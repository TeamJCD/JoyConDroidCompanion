#!/usr/bin/env python3
"""
verify_hooks.py — Static scanner for Hook 1 (CoD) and Hook 2 (Bond) patterns.

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

MOVZ_HCI_COD_MASK = 0xFFFFFFE0
MOVZ_HCI_COD_VAL  = 0x52818480
SCS_SAVE_INSN     = 0xf800865e

def find_cod_fn(ws, vaddr):
    n = len(ws)
    for i in range(n):
        if (ws[i] & MOVZ_HCI_COD_MASK) != MOVZ_HCI_COD_VAL:
            continue
        for j in range(i, max(i - 256, -1), -1):
            if ws[j] == SCS_SAVE_INSN:
                return vaddr + j * 4, i - j  # (fn_va, distance_to_movz)
    return None, None

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
            has_strb = (
                (q >= 1 and (ws[q - 1] & STRB_MASK) == STRB_VAL) or
                (q >= 2 and (ws[q - 2] & STRB_MASK) == STRB_VAL)
            )
            if not has_strb:
                continue

            imm26 = ws[q] & 0x03FFFFFF
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            bl_tgt = (vaddr + q * 4 + imm26 * 4) & 0xFFFFFFFFFFFFFFFF

            bond_ptr = None
            for a in range(max(i, q - 16), q - 1):
                if (ws[a] & ADRP_MASK) == ADRP_VAL and (ws[a + 1] & ADD_IMM_MASK) == ADD_IMM_VAL:
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

    # Hook 1
    fn_va, dist = find_cod_fn(ws, vaddr)
    if fn_va is not None:
        print(f"  Hook 1 (CoD):  fn=0x{fn_va:08x}  (+{dist * 4} bytes to MOVZ)  ✅")
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
    else:
        print(f"  Hook 2 (Bond): NOT FOUND  ❌")
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