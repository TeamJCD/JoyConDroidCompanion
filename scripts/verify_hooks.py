#!/usr/bin/env python3
"""
verify_hooks.py — Static scanner for Hook 1 (CoD), Hook 2 (Bond) and
Hook 3 (Mode-Change) patterns.

Usage:
    python3 scripts/verify_hooks.py <libbluetooth*.so> [...]
    python3 scripts/verify_hooks.py          # auto-scans scripts/libs/**

Multiple library paths can be given; each is scanned independently.
The script prints the found function addresses and bond_type_ptr, and exits
non-zero if any library yields no match for a hook.
"""

import struct
import sys

# ── ELF helpers ─────────────────────────────────────────────────────────────

def parse_exec_segment(path):
    """Return (words, vaddr, exec_sz) for the first executable PT_LOAD segment."""
    with open(path, 'rb') as f:
        data = f.read()
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    for i in range(e_phnum):
        ph = data[e_phoff + i * 56: e_phoff + (i + 1) * 56]
        p_type, p_flags = struct.unpack_from('<II', ph, 0)
        if p_type == 1 and (p_flags & 1):   # PT_LOAD + PF_X
            foff  = struct.unpack_from('<Q', ph, 8)[0]
            vaddr = struct.unpack_from('<Q', ph, 16)[0]
            sz    = struct.unpack_from('<Q', ph, 32)[0]
            raw   = data[foff: foff + sz]
            words = struct.unpack_from('<' + 'I' * (len(raw) // 4), raw)
            return words, vaddr, sz
    raise ValueError("no executable PT_LOAD segment found")

# ── Hook 1: btsnd_hcic_write_dev_class (CoD) ────────────────────────────────
#
# Pattern: MOVZ wX, #0x0C24  (HCI opcode Write_Class_of_Device)
# Anchor:  walk back to SCS_SAVE (str x30, [x18], #8)
#
# Samsung ships up to 3 independent functions with this pattern; all are
# hooked at runtime (MAX_COD_HOOKS=4).  The scanner returns every unique
# function found so the caller can report / validate all of them.
#
# Some Qualcomm QTI stacks (Xiaomi 2210132C, "nuwa") use a different calling
# convention: x0 is a pointer to a 3-byte dev_class array rather than a
# packed raw value.  Fingerprint: three LDRB loads from the same base
# register at byte offsets 0/1/2 (the array-unpacking loop) — see
# cod_fn_takes_ptr_arg() in src/cod.c for the runtime-identical check.

MOVZ_HCI_COD_MASK   = 0xFFFFFFE0
MOVZ_HCI_COD_VAL    = 0x52818480
SCS_SAVE_INSN       = 0xf800865e
MAX_COD_HOOKS       = 4
MAX_COD_PTR_HOOKS   = 2
COD_PTR_SCAN_WINDOW = 200
LDRB_IMM_MASK       = 0xFFC00000
LDRB_IMM_VAL        = 0x39400000

def _cod_fn_takes_raw_value(ws, fn_idx, movz_idx):
    """
    Return True if x0 is used as a raw uint32_t CoD value (not a pointer).
    Functions with  ADD X*, X0, #imm12  where imm12 >= 64 before the MOVZ
    treat x0 as a structure pointer and must be skipped (different calling
    convention — passing cod=0x082500 would crash on first dereference).
    """
    ADD_X0_MASK = 0xFF8003E0
    ADD_X0_VAL  = 0x91000000
    for k in range(fn_idx, movz_idx):
        if (ws[k] & ADD_X0_MASK) == ADD_X0_VAL:
            imm12 = (ws[k] >> 10) & 0xFFF
            if imm12 >= 64:
                return False
    return True

def _cod_fn_takes_ptr_arg(ws, fn_idx):
    """Return True if x0 is a pointer to a 3-byte dev_class array (QTI variant)."""
    n = len(ws)
    fn_end = min(fn_idx + COD_PTR_SCAN_WINDOW, n)
    for q in range(fn_idx + 1, fn_end):
        if ws[q] == SCS_SAVE_INSN:
            fn_end = q
            break
    offset_mask = [0] * 32
    for p in range(fn_idx, fn_end):
        if (ws[p] & LDRB_IMM_MASK) != LDRB_IMM_VAL:
            continue
        rn  = (ws[p] >> 5) & 0x1F
        imm = (ws[p] >> 10) & 0xFFF
        if imm > 2 or rn == 31:
            continue
        offset_mask[rn] |= (1 << imm)
        if offset_mask[rn] == 0x7:
            return True
    return False

def find_cod_fns(ws, vaddr):
    """Return list of (fn_va, distance_in_words, kind) for all CoD-hook candidates.
    kind is one of 'raw', 'ptr', 'skip'."""
    n = len(ws)
    results = []
    seen = set()
    for i in range(n):
        if (ws[i] & MOVZ_HCI_COD_MASK) != MOVZ_HCI_COD_VAL:
            continue
        for j in range(i, max(i - 256, -1), -1):
            if ws[j] == SCS_SAVE_INSN:
                fn_va = vaddr + j * 4
                if fn_va not in seen:
                    seen.add(fn_va)
                    if _cod_fn_takes_ptr_arg(ws, j):
                        kind = "ptr"
                    elif _cod_fn_takes_raw_value(ws, j, i):
                        kind = "raw"
                    else:
                        kind = "skip"
                    results.append((fn_va, i - j, kind))
                break
    return results

# ── Hook 2: btm_set_bond_type_dev (Bond) ────────────────────────────────────
#
# Anchor:  LDRB triple accessing consecutive byte offsets N/N+1/N+2 from the
#          same base register (just_works/loc_auth_req/rmt_auth_req in
#          tBTA_DM_SP_CFM_REQ).  Off0 >= BD_NAME_LEN=248 (field lies after
#          the 248-byte bd_name array, so offset is always >248 in any build).
# Filter1: BL preceded by STRB within 2 insns (writes bond_type before call).
# Filter2: bond_type_ptr decoded via ADRP+ADD must be in data/BSS (>= exec_end).
# Filter3: BL target must not have another BL in its first 8 insns (not a wrapper).

LDRB_ANY_MASK = 0xFFC00000
LDRB_ANY_VAL  = 0x39400000
BL_MASK       = 0xFC000000
BL_VAL        = 0x94000000
STRB_MASK     = 0xFFC00000
STRB_VAL      = 0x39000000
ADRP_MASK     = 0x9F000000
ADRP_VAL      = 0x90000000
ADD_IMM_MASK  = 0xFFC00000
ADD_IMM_VAL   = 0x91000000
BD_NAME_LEN   = 248

def _decode_adrp_add(ws, a, vaddr):
    insn   = ws[a]
    immlo  = (insn >> 29) & 0x3
    immhi  = (insn >> 5)  & 0x7FFFF
    imm21u = (immhi << 2) | immlo
    imm21s = imm21u - (1 << 21) if imm21u & (1 << 20) else imm21u
    pc     = vaddr + a * 4
    page   = (pc & ~0xFFF) + (imm21s << 12)
    add    = ws[a + 1]
    imm12  = (add >> 10) & 0xFFF
    if add & (1 << 22):
        imm12 <<= 12
    return (page + imm12) & 0xFFFFFFFFFFFFFFFF

def _reg_from_local_adrp(ws, wl, i, rn):
    """True if register `rn` is ever the destination of an ADRP within
    [wl, i) — i.e. its value likely comes from a static/global address
    rather than a genuine function-parameter struct pointer."""
    for a in range(wl, i):
        if (ws[a] & ADRP_MASK) == ADRP_VAL and (ws[a] & 0x1F) == rn:
            return True
    return False

# ── Hook 2 strategy 2: setter-shape scan (src/bond_setter_scan.c) ──────────
#
# Mirrors bond_setter_scan.c: scans for btm_set_bond_type_dev's own shape
# (two lookup calls to the same target, a third distinct "resolve" call,
# then a byte-store through x0 using a register forwarded from w1 near the
# function's start) instead of anchoring on its caller. See that file's
# header for the full rationale and verification notes.

BL_MASK_SETTER  = 0xFC000000
BL_VAL_SETTER   = 0x94000000
MOV_W1_MASK     = 0xFFFFFFE0
MOV_W1_VAL      = 0x2A0103E0
STRB_MASK_SETTER = 0xFFC00000
STRB_VAL_SETTER  = 0x39000000

SETTER_SCAN_WINDOW   = 64
SETTER_FWD_WINDOW    = 12
SETTER_STRB_AFTER_BL = 4

def _bl_target(ws, idx, vaddr):
    imm26 = ws[idx] & 0x03FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    return (vaddr + idx * 4 + imm26 * 4) & 0xFFFFFFFFFFFFFFFF

def _check_setter_candidate(ws, p, n, vaddr):
    fwin_hi = min(p + SETTER_FWD_WINDOW, n)
    fwd_regs = [ws[q] & 0x1F for q in range(p, fwin_hi) if (ws[q] & MOV_W1_MASK) == MOV_W1_VAL]
    if not fwd_regs:
        return None

    win_hi = min(p + SETTER_SCAN_WINDOW, n)
    bl_targets = []
    have_repeat = False
    repeat_target = None

    for q in range(p, win_hi):
        if (ws[q] & BL_MASK_SETTER) != BL_VAL_SETTER:
            continue
        tgt = _bl_target(ws, q, vaddr)

        if not have_repeat:
            if tgt in bl_targets:
                have_repeat = True
                repeat_target = tgt
            bl_targets.append(tgt)
            continue
        if tgt == repeat_target:
            continue

        strb_hi = min(q + 1 + SETTER_STRB_AFTER_BL, win_hi)
        for s in range(q + 1, strb_hi):
            if (ws[s] & STRB_MASK_SETTER) != STRB_VAL_SETTER:
                continue
            rt = ws[s] & 0x1F
            rn = (ws[s] >> 5) & 0x1F
            if rn != 0:
                continue
            if rt in fwd_regs:
                return p
    return None

def find_bond_fn_by_setter_shape(ws, vaddr):
    n = len(ws)
    matches = [p for p in range(n - SETTER_SCAN_WINDOW)
               if ws[p] == SCS_SAVE_INSN and _check_setter_candidate(ws, p, n, vaddr) is not None]
    if len(matches) != 1:
        return None
    return vaddr + matches[0] * 4

def find_bond_fn(ws, vaddr, exec_sz):
    exec_end = vaddr + exec_sz
    n = len(ws)

    for i in range(n - 128):
        if (ws[i] & LDRB_ANY_MASK) != LDRB_ANY_VAL:
            continue
        off0 = (ws[i] >> 10) & 0xFFF
        if off0 < BD_NAME_LEN:
            continue
        rn0  = (ws[i] >> 5) & 0x1F

        wl = max(0, i - 16)
        if _reg_from_local_adrp(ws, wl, i, rn0):
            continue
        wh = min(n, i + 32)
        n1 = n2 = 0
        for q in range(wl, wh):
            if (ws[q] & LDRB_ANY_MASK) != LDRB_ANY_VAL:
                continue
            if (ws[q] >> 5) & 0x1F != rn0:
                continue
            off = (ws[q] >> 10) & 0xFFF
            if off == off0 + 1:
                n1 = 1
            if off == off0 + 2:
                n2 = 1
        if not n1 or not n2:
            continue

        for q in range(i, min(i + 256, n)):
            if (ws[q] & BL_MASK) != BL_VAL:
                continue
            strb_idx = None
            if q >= 1 and (ws[q - 1] & STRB_MASK) == STRB_VAL:
                strb_idx = q - 1
            elif q >= 2 and (ws[q - 2] & STRB_MASK) == STRB_VAL:
                strb_idx = q - 2
            if strb_idx is None:
                continue
            strb_rn = (ws[strb_idx] >> 5) & 0x1F

            imm26 = ws[q] & 0x03FFFFFF
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            bl_tgt = (vaddr + q * 4 + imm26 * 4) & 0xFFFFFFFFFFFFFFFF

            # ADRP+ADD's destination register must match the STRB's base
            # register — otherwise this pair isn't the one feeding that STRB.
            bond_ptr = None
            for a in range(max(i, q - 16), q - 1):
                if ((ws[a] & ADRP_MASK) == ADRP_VAL and
                        (ws[a + 1] & ADD_IMM_MASK) == ADD_IMM_VAL and
                        (ws[a] & 0x1F) == strb_rn):
                    bond_ptr = _decode_adrp_add(ws, a, vaddr)
                    break

            if not bond_ptr or bond_ptr < exec_end:
                continue

            if vaddr <= bl_tgt < vaddr + exec_sz:
                fn_idx = (bl_tgt - vaddr) // 4
                if any((ws[fn_idx + k] & BL_MASK) == BL_VAL
                       for k in range(8) if fn_idx + k < n):
                    continue  # wrapper/bridge — skip

            return bl_tgt, bond_ptr, off0

    return None, None, None

# ── Hook 3: btm_pm_proc_mode_change (Mode-Change) ───────────────────────────
#
# Observational hook — publishes the current BT link power mode to
# /dev/btlinkmode, never alters behavior. Mirrors src/mode_change.c
# (strategy 1: caller byte-unpack fingerprint) and
# src/mode_change_shape_scan.c (strategy 2: callee shape scan).

BTI_C_INSN = 0xd503245f

# Strategy 1: LDRB/LDURH/LDRH loads at fixed offsets 0/1/3/4 from the same
# base register — the raw 6-byte HCI Mode Change event being unpacked by the
# caller (Status@0, Connection_Handle@1-2, Current_Mode@3, Interval@4-5).
LDRB_OFF0_MASK  = 0xFFFFFC00
LDRB_OFF0_VAL   = 0x39400000   # LDRB  Wt,[Xn,#0]  (status)
LDURH_OFF1_MASK = 0xFFFFFC00
LDURH_OFF1_VAL  = 0x78401000   # LDURH Wt,[Xn,#1]  (handle)
LDRH_OFF4_MASK  = 0xFFFFFC00
LDRH_OFF4_VAL   = 0x79400800   # LDRH  Wt,[Xn,#4]  (interval)
LDRB_OFF3_MASK  = 0xFFFFFC00
LDRB_OFF3_VAL   = 0x39400c00   # LDRB  Wt,[Xn,#3]  (mode)

MOV_REG_MASK = 0xFFE0FFE0      # MOV Wd,Wm (ORR Wd,WZR,Wm alias)
MOV_REG_VAL  = 0x2A0003E0

UNPACK_SCAN_WINDOW = 8
SIM_FORWARD_MAX    = 64

F_NONE, F_STATUS, F_HANDLE, F_MODE, F_INTERVAL = range(5)

def _mc_target_has_scs_prologue(ws, idx, n):
    if idx < 0 or idx + 1 >= n:
        return False
    if ws[idx] == SCS_SAVE_INSN:
        return True
    if ws[idx] == BTI_C_INSN and ws[idx + 1] == SCS_SAVE_INSN:
        return True
    return False

def _mc_simulate_to_call(ws, start, n, r_status, r_handle, r_mode, r_interval):
    holds = [F_NONE] * 32
    holds[r_status], holds[r_handle] = F_STATUS, F_HANDLE
    holds[r_mode], holds[r_interval] = F_MODE, F_INTERVAL

    win_hi = min(start + SIM_FORWARD_MAX, n)
    for q in range(start, win_hi):
        w = ws[q]
        if (w & MOV_REG_MASK) == MOV_REG_VAL:
            rd, rm = w & 0x1F, (w >> 16) & 0x1F
            holds[rd] = holds[rm]
            continue
        is_bl = (w & BL_MASK) == BL_VAL
        is_b  = (w & 0xFC000000) == 0x14000000
        if is_bl or is_b:
            if holds[0] == F_STATUS and holds[1] == F_HANDLE and \
               holds[2] == F_MODE and holds[3] == F_INTERVAL:
                imm26 = w & 0x03FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= (1 << 26)
                tgt_idx = q + imm26
                if _mc_target_has_scs_prologue(ws, tgt_idx, n):
                    return tgt_idx
            if is_b:
                break
            holds[0] = holds[1] = holds[2] = holds[3] = F_NONE
            continue
        rd_generic = w & 0x1F
        if rd_generic < 4 and holds[rd_generic] != F_NONE:
            holds[rd_generic] = F_NONE
    return None

def find_mode_change_fn(ws, vaddr):
    n = len(ws)
    match = None
    n_matches = 0

    for p in range(n - UNPACK_SCAN_WINDOW):
        win_hi = p + UNPACK_SCAN_WINDOW
        i_status = i_handle = i_mode = i_interval = None
        for q in range(p, win_hi):
            w = ws[q]
            if i_status is None and (w & LDRB_OFF0_MASK) == LDRB_OFF0_VAL: i_status = q
            if i_handle is None and (w & LDURH_OFF1_MASK) == LDURH_OFF1_VAL: i_handle = q
            if i_mode is None and (w & LDRB_OFF3_MASK) == LDRB_OFF3_VAL: i_mode = q
            if i_interval is None and (w & LDRH_OFF4_MASK) == LDRH_OFF4_VAL: i_interval = q
        if None in (i_status, i_handle, i_mode, i_interval):
            continue

        rn = lambda idx: (ws[idx] >> 5) & 0x1F
        if not (rn(i_status) == rn(i_handle) == rn(i_mode) == rn(i_interval)):
            continue

        rt = lambda idx: ws[idx] & 0x1F
        r_status, r_handle, r_mode, r_interval = rt(i_status), rt(i_handle), rt(i_mode), rt(i_interval)
        if len({r_status, r_handle, r_mode, r_interval}) != 4:
            continue

        last = max(i_status, i_handle, i_mode, i_interval)
        tgt_idx = _mc_simulate_to_call(ws, last + 1, n, r_status, r_handle, r_mode, r_interval)
        if tgt_idx is None:
            continue

        if match is None:
            match, n_matches = tgt_idx, 1
        elif tgt_idx != match:
            n_matches += 1

    if n_matches != 1:
        return None
    return vaddr + match * 4

# Strategy 2: whole-binary scan for btm_pm_proc_mode_change's own shape —
# SCS_SAVE(+BTI) prologue, then AND X1,#0xffff + STRH W1,[SP,#imm] (masks and
# stashes the handle arg) bracketed by an ADRP+LDR pair before it and a CBZ
# after it (a global-lookup-and-bail idiom every verified instance has).

AND_X1_FFFF_MASK = 0xFFFFFFE0
AND_X1_FFFF_VAL  = 0x92403C20
STRH_W1_SP_MASK  = 0xFFC003FF
STRH_W1_SP_VAL   = 0x790003E1
LDR_X_IMM_MASK   = 0xFFC00000
LDR_X_IMM_VAL    = 0xF9400000
CBZ_X_MASK       = 0xFF000000
CBZ_X_VAL        = 0xB4000000

SHAPE_SCAN_WINDOW = 18
AND_STRH_MAX_GAP  = 3
ADRP_LOOKBACK     = 4
CBZ_LOOKAHEAD     = 4

def find_mode_change_fn_by_shape(ws, vaddr):
    n = len(ws)
    match = None
    n_matches = 0

    for p in range(n):
        if ws[p] == SCS_SAVE_INSN:
            prologue = p
        elif ws[p] == BTI_C_INSN and p + 1 < n and ws[p + 1] == SCS_SAVE_INSN:
            prologue = p + 1
        else:
            continue

        win_hi = min(prologue + SHAPE_SCAN_WINDOW, n)
        and_idx = strh_idx = None
        for q in range(prologue, win_hi):
            if and_idx is None and (ws[q] & AND_X1_FFFF_MASK) == AND_X1_FFFF_VAL:
                and_idx = q
            if strh_idx is None and (ws[q] & STRH_W1_SP_MASK) == STRH_W1_SP_VAL:
                strh_idx = q
        if and_idx is None or strh_idx is None:
            continue
        if not (0 <= strh_idx - and_idx <= AND_STRH_MAX_GAP):
            continue

        adrp_lo = max(0, and_idx - ADRP_LOOKBACK)
        has_adrp_ldr = any(
            (ws[a] & ADRP_MASK) == ADRP_VAL and (ws[a + 1] & LDR_X_IMM_MASK) == LDR_X_IMM_VAL
            for a in range(adrp_lo, and_idx)
        )
        if not has_adrp_ldr:
            continue

        cbz_hi = min(strh_idx + 1 + CBZ_LOOKAHEAD, n)
        has_cbz = any((ws[c] & CBZ_X_MASK) == CBZ_X_VAL for c in range(strh_idx, cbz_hi))
        if not has_cbz:
            continue

        if match is None:
            match, n_matches = prologue, 1
        elif prologue != match:
            n_matches += 1

    if n_matches != 1:
        return None
    return vaddr + match * 4

# ── Main ─────────────────────────────────────────────────────────────────────

def verify(path):
    print(f"\n{'=' * 70}")
    print(f"  {path}")
    print(f"{'=' * 70}")
    try:
        ws, vaddr, exec_sz = parse_exec_segment(path)
    except Exception as e:
        print(f"  ERROR: {e}")
        return False

    exec_end = vaddr + exec_sz
    print(f"  Exec segment: 0x{vaddr:08x} – 0x{exec_end:08x}  ({exec_sz // 1024} KiB)")

    ok = True

    # Hook 1 — may match multiple functions on Samsung
    cod_fns = find_cod_fns(ws, vaddr)
    raw     = [(va, d) for va, d, k in cod_fns if k == "raw"]
    ptr     = [(va, d) for va, d, k in cod_fns if k == "ptr"]
    skipped = [(va, d) for va, d, k in cod_fns if k == "skip"]
    if raw or ptr:
        for idx, (fn_va, dist) in enumerate(raw):
            tag = "✅" if idx == 0 else "  "
            suffix = f"  (slot {idx})" if idx > 0 else ""
            print(f"  Hook 1 (CoD):  fn=0x{fn_va:08x}  (+{dist * 4} bytes to MOVZ)  {tag}{suffix}")
        for idx, (fn_va, dist) in enumerate(ptr):
            print(f"  Hook 1 (CoD):  fn=0x{fn_va:08x}  (+{dist * 4} bytes to MOVZ)  ✅  (pointer-arg variant, slot {idx})")
        for fn_va, dist in skipped:
            print(f"  Hook 1 (CoD):  fn=0x{fn_va:08x}  (+{dist * 4} bytes to MOVZ)  ⏭  (x0=pointer, skipped)")
        if len(raw) > MAX_COD_HOOKS:
            print(f"  Hook 1 (CoD):  WARNING: {len(raw)} raw hookable > MAX_COD_HOOKS={MAX_COD_HOOKS}, excess will be skipped")
        if len(ptr) > MAX_COD_PTR_HOOKS:
            print(f"  Hook 1 (CoD):  WARNING: {len(ptr)} pointer-arg hookable > MAX_COD_PTR_HOOKS={MAX_COD_PTR_HOOKS}, excess will be skipped")
    else:
        print(f"  Hook 1 (CoD):  NOT FOUND  ❌")
        ok = False

    # Hook 2
    fn_va, bond_ptr, off0 = find_bond_fn(ws, vaddr, exec_sz)
    if fn_va is not None:
        print(f"  Hook 2 (Bond): fn=0x{fn_va:08x}  bond_type_ptr=0x{bond_ptr:08x}"
              f"  offs={off0}/{off0+1}/{off0+2}  ✅")
        fn_idx = (fn_va - vaddr) // 4
        first4 = [f"0x{ws[fn_idx+k]:08x}" for k in range(4) if fn_idx+k < len(ws)]
        print(f"             first 4 insns: {' '.join(first4)}")
        if ws[fn_idx] == SCS_SAVE_INSN:
            print(f"             prologue: SCS_SAVE (standard)")
        elif (ws[fn_idx] & ADRP_MASK) == ADRP_VAL:
            print(f"             prologue: ADRP x{ws[fn_idx] & 0x1f} (Samsung-style early-exit preamble)")
    elif (setter_va := find_bond_fn_by_setter_shape(ws, vaddr)) is not None:
        print(f"  Hook 2 (Bond): generic scanner found nothing, but setter-shape scan"
              f"  ✅  (bond_setter_scan.c, fn=0x{setter_va:08x})")
    else:
        print(f"  Hook 2 (Bond): NOT FOUND  ❌")
        ok = False

    # Hook 3
    mc_va = find_mode_change_fn(ws, vaddr)
    if mc_va is not None:
        print(f"  Hook 3 (Mode-Change): fn=0x{mc_va:08x}  ✅")
    elif (mc_shape_va := find_mode_change_fn_by_shape(ws, vaddr)) is not None:
        print(f"  Hook 3 (Mode-Change): generic scanner found nothing, but shape scan"
              f"  ✅  (mode_change_shape_scan.c, fn=0x{mc_shape_va:08x})")
    else:
        print(f"  Hook 3 (Mode-Change): NOT FOUND  ❌")
        ok = False

    return ok

if __name__ == "__main__":
    paths = sys.argv[1:]
    if not paths:
        # default: scan all known device libs
        import glob, os
        root = os.path.join(os.path.dirname(__file__), "libs")
        paths = sorted(glob.glob(
            os.path.join(root, "**/libbluetooth*.so"), recursive=True
        ))
        if not paths:
            print(f"Usage: {sys.argv[0]} <libbluetooth*.so> [...]")
            sys.exit(1)

    all_ok = True
    for p in paths:
        if not verify(p):
            all_ok = False

    sys.exit(0 if all_ok else 1)
