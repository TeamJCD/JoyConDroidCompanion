/*
 * bond_setter_scan.c — pattern scan for btm_set_bond_type_dev itself, for BT
 * stacks where bond.c's caller-anchored LDRB-triple scan finds nothing
 * because the caller (btif_dm_ssp_cfm_req_evt or its equivalent) has been
 * restructured beyond recognition (confirmed on Samsung's Android 16
 * "Gabeldorsche" stack, e.g. Galaxy Z Fold SM-F946B).
 *
 * Instead of anchoring on the caller, this scans for the setter's own,
 * fairly distinctive shape (confirmed via Ghidra decompile of
 * btm_set_bond_type_dev on Galaxy Z Fold SM-F946B, 2026-07-27):
 *
 *   btm_set_bond_type_dev(void *addr, tBTM_BOND_TYPE value):
 *     mov wD, w1                 ; value argument forwarded into a
 *                                 ; register that survives the calls below
 *     bl  lookup(key1, addr)     ; primary key
 *     cbnz x0, resolve
 *     bl  lookup(key2, addr)     ; fallback key — SAME target as above
 *     cbz  x0, fail
 *   resolve:
 *     bl  resolve(x0)            ; a third, DIFFERENT call
 *     cbz  x0, fail
 *     strb wD, [x0, #imm]        ; the actual bond_type store, through the
 *                                 ; resolve call's fresh return value
 *     ...
 *
 * Verified against all 4 reference libraries in scripts/libs/ (2026-07-29):
 * finds exactly the known-correct address on SM-F946B (0x8ed088, matched by
 * static analysis against the live-confirmed btm_set_bond_type_dev) *and*
 * independently rediscovers the exact address bond.c's caller-anchored scan
 * already finds on the Sony XZ2 Compact AOSP-style stack (0x830f14) — two
 * independent methods agreeing is a strong correctness signal. On both
 * Samsung A05 libraries (SM-A055M/F) it correctly finds nothing:
 * btm_set_bond_type_dev there is a plain leaf store with no calls at all, so
 * this shape-based scan simply doesn't apply — bond.c's scan already covers
 * those devices anyway.
 *
 * Two properties make this specific enough to trust:
 *   - the two lookup calls share an identical target address (only the
 *     ADR-loaded key argument differs) — a rare fingerprint that random
 *     unrelated setters elsewhere in a 10+ MB binary are very unlikely to
 *     share by chance (confirmed: 0 false matches across all 4 references);
 *   - the store's base register must be x0 itself, i.e. the *fresh* return
 *     value of the third (resolve) call, not some long-lived register that
 *     merely happens to sit near an unrelated pair of repeated calls. This
 *     filter alone eliminated every non-bond_type candidate found on the
 *     two Samsung A05 libraries during verification.
 *
 * If more than one candidate survives both filters in a given library, this
 * refuses to guess and reports not-found rather than patching the wrong
 * function — the whole point of scanning instead of trusting a hardcoded
 * address is that an ambiguous result should mean "no hook", not "best
 * guess".
 *
 * Because the offset is decoded from the STRB instruction itself rather
 * than assumed ahead of time, this should survive firmware updates that
 * recompile this same source function at a different address, as long as
 * this exact shape is preserved.
 */

#include "shim.h"
#include <string.h>

#define BL_MASK  0xFC000000u
#define BL_VAL   0x94000000u

/* "mov Wd, W1" (ORR Wd, WZR, W1 alias) — forwards the value argument. */
#define MOV_W1_MASK 0xFFFFFFE0u
#define MOV_W1_VAL  0x2A0103E0u

/* STRB Wt, [Xn, #imm12] (unsigned offset) */
#define STRB_MASK 0xFFC00000u
#define STRB_VAL  0x39000000u

#define BOND_TYPE_PERSISTENT 1u
#define BOND_TYPE_TEMPORARY  2u

#define SCAN_WINDOW    64u  /* words to scan forward from each SCS_SAVE candidate */
#define FWD_WINDOW     12u  /* how early "mov wD,w1" must appear after prologue */
#define STRB_AFTER_BL   4u  /* STRB must land within this many insns after a BL */
#define MAX_FWD_REGS     4
#define MAX_BL_TARGETS  16

typedef uint64_t (*set_bond_type_fn)(uint64_t, uint64_t);
static set_bond_type_fn g_orig_stub;

static uint64_t hook_bond(uint64_t ctx, uint64_t value)
{
    if (value == BOND_TYPE_TEMPORARY) {
        LOGI("hook_bond_setter_scan: TEMPORARY -> PERSISTENT");
        value = BOND_TYPE_PERSISTENT;
    }
    return g_orig_stub ? g_orig_stub(ctx, value) : 0;
}

static uintptr_t bl_target(const uint32_t *insn_ptr)
{
    int32_t imm26 = (int32_t)((*insn_ptr & 0x03FFFFFFu) << 6) >> 6;
    return (uintptr_t)insn_ptr + (int64_t)imm26 * 4;
}

/* Checks one SCS_SAVE-anchored candidate function starting at `p` for the
 * shape described in the file header. Returns `p` on a match, NULL otherwise. */
static uint8_t *check_candidate(uint32_t *p, uint32_t *end)
{
    uint32_t *fwin_hi = (p + FWD_WINDOW < end) ? p + FWD_WINDOW : end;
    int fwd_regs[MAX_FWD_REGS]; int n_fwd = 0;
    for (uint32_t *q = p; q < fwin_hi && n_fwd < MAX_FWD_REGS; q++)
        if ((*q & MOV_W1_MASK) == MOV_W1_VAL)
            fwd_regs[n_fwd++] = (int)(*q & 0x1Fu);
    if (n_fwd == 0) return NULL;

    uint32_t *win_hi = (p + SCAN_WINDOW < end) ? p + SCAN_WINDOW : end;
    uintptr_t bl_targets[MAX_BL_TARGETS]; int n_bl = 0;
    int have_repeat = 0;
    uintptr_t repeat_target = 0;

    for (uint32_t *q = p; q < win_hi; q++) {
        if ((*q & BL_MASK) != BL_VAL) continue;
        uintptr_t tgt = bl_target(q);

        if (!have_repeat) {
            for (int i = 0; i < n_bl; i++) {
                if (bl_targets[i] == tgt) { have_repeat = 1; repeat_target = tgt; break; }
            }
            if (n_bl < MAX_BL_TARGETS) bl_targets[n_bl++] = tgt;
            continue;
        }
        if (tgt == repeat_target) continue; /* still part of the repeated-call group */

        /* `tgt` is a third, distinct call — the candidate "resolve" step. */
        uint32_t *strb_hi = (q + 1 + STRB_AFTER_BL < win_hi) ? q + 1 + STRB_AFTER_BL : win_hi;
        for (uint32_t *s = q + 1; s < strb_hi; s++) {
            if ((*s & STRB_MASK) != STRB_VAL) continue;
            uint32_t rt = *s & 0x1Fu;
            uint32_t rn = (*s >> 5) & 0x1Fu;
            if (rn != 0) continue; /* must store through x0 — the resolve call's fresh return value */
            for (int i = 0; i < n_fwd; i++)
                if (fwd_regs[i] == (int)rt) return (uint8_t *)p;
        }
    }
    return NULL;
}

static uint8_t *find_bond_fn_by_setter_shape(const char *libname)
{
    size_t exec_size = 0;
    uint32_t *exec = (uint32_t *)get_lib_exec_range(libname, &exec_size);
    if (!exec) return NULL;
    uint32_t *end = (uint32_t *)((uint8_t *)exec + exec_size);

    uint8_t *match = NULL;
    int n_matches = 0;

    for (uint32_t *p = exec; p + SCAN_WINDOW < end; p++) {
        if (*p != SCS_SAVE_INSN) continue;
        uint8_t *cand = check_candidate(p, end);
        if (!cand) continue;
        n_matches++;
        if (n_matches == 1) match = cand;
        else LOGI("find_bond_fn_by_setter_shape: additional candidate @ %p (ambiguous)", (void *)cand);
    }

    if (n_matches != 1) {
        if (n_matches > 1)
            LOGE("find_bond_fn_by_setter_shape: %d ambiguous candidates, refusing to guess", n_matches);
        return NULL;
    }
    return match;
}

int install_bond_hook_setter_scan(const char *libname)
{
    uint8_t *fn = find_bond_fn_by_setter_shape(libname);
    if (!fn) return 0;
    if (install_hook(fn, (void *)hook_bond, (void **)&g_orig_stub) != 0) {
        LOGE("install_bond_hook_setter_scan: failed to install hook @ %p", (void *)fn);
        return 0;
    }
    LOGI("install_bond_hook_setter_scan: hooked @ %p", (void *)fn);
    return 1;
}
