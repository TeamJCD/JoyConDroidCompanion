/*
 * mode_change_shape_scan.c — Mode-Change Hook, Strategy 2: whole-binary shape
 * scan for btm_pm_proc_mode_change itself, for BT stacks where
 * mode_change.c's caller-anchored byte-unpack scan finds nothing because the
 * caller doesn't unpack the raw HCI event bytes locally — it's already
 * called with pre-parsed arguments, the unpacking having happened further up
 * the dispatch chain (confirmed on Samsung's A05 stack, SM-A055F/SM-A055M).
 *
 * Instead of anchoring on the caller, this scans for the callee's own shape
 * (confirmed identical across Sony XZ2 Compact, Samsung SM-F946B and both
 * Samsung A05 libraries via .gnu_debugdata, 2026-08-20):
 *
 *   btm_pm_proc_mode_change(status, handle, mode, interval):
 *     <SCS_SAVE prologue, optionally preceded by a BTI landing pad>
 *     <register spill, stack canary setup>
 *     adrp x8, ...
 *     ldr  x9, [x8, #imm]   ; load some pm-control-block global pointer
 *     and  x8, x1, #0xffff  ; mask the handle arg (x1) to 16 bits
 *     strh w1, [sp, #imm]   ; stash the handle on the stack
 *     cbz  x9, fail         ; bail if the loaded global is null
 *     ...
 *
 * The `AND X1,#0xffff` + `STRH W1,[SP,#imm]` pair alone is too common to be a
 * standalone fingerprint — any function taking a uint16_t handle as its 2nd
 * argument tends to do exactly this. Requiring the ADRP+LDR pair shortly
 * before and the CBZ shortly after (the lookup-and-bail idiom) eliminates
 * every false positive observed during verification, leaving exactly one
 * match per binary.
 *
 * Verified 2026-08-20 against all 5 reference libraries: unique, exact match
 * (cross-checked against .gnu_debugdata symbols) on Sony XZ2 Compact,
 * Samsung SM-F946B, SM-A055F and SM-A055M. Sony and F946B are independently
 * found by mode_change.c's caller-anchored scan too, and both agree exactly
 * — the same two-independent-methods correctness signal used to validate
 * Hook 2's bond_setter_scan.c. Finds nothing on Xiaomi's libbluetooth_qti.so
 * (its btm_pm_proc_mode_change calls a helper before doing anything else,
 * a differently-shaped body) — mode_change.c already covers that device.
 *
 * If more than one candidate survives every filter, this refuses to guess
 * and reports not-found rather than patching the wrong function, matching
 * bond_setter_scan.c's philosophy.
 */

#include "shim.h"
#include "btlinkmode.h"

#define SCS_SAVE  SCS_SAVE_INSN
#define BTI_C_INSN 0xd503245fu

/* AND Xd, X1, #0xffff — bitmask-immediate form, fixed except Rd (bits[4:0]). */
#define AND_X1_FFFF_MASK 0xFFFFFFE0u
#define AND_X1_FFFF_VAL  0x92403C20u

/* STRH W1, [SP, #imm] — unsigned-offset halfword store, Rn=SP(31) and Rt=1
 * (w1) fixed, only the imm12 field (bits[21:10]) varies. */
#define STRH_W1_SP_MASK 0xFFC003FFu
#define STRH_W1_SP_VAL  0x790003E1u

#define ADRP_MASK 0x9F000000u
#define ADRP_VAL  0x90000000u

/* LDR Xt, [Xn, #imm] — unsigned-offset 64-bit load. */
#define LDR_X_IMM_MASK 0xFFC00000u
#define LDR_X_IMM_VAL  0xF9400000u

/* CBZ Xt, label — 64-bit compare-and-branch-if-zero. */
#define CBZ_X_MASK 0xFF000000u
#define CBZ_X_VAL  0xB4000000u

#define SHAPE_SCAN_WINDOW 18u  /* words after prologue the AND/STRH pair must fall within */
#define AND_STRH_MAX_GAP   3u  /* max instructions between the AND and the STRH */
#define ADRP_LOOKBACK       4u /* how far before the AND to look for ADRP+LDR */
#define CBZ_LOOKAHEAD       4u /* how far after the STRH to look for the CBZ */

typedef void (*mode_change_fn_t)(uint32_t, uint32_t, uint32_t, uint32_t);
static mode_change_fn_t g_orig_stub;

static void hook_mode_change(uint32_t status, uint32_t handle, uint32_t mode, uint32_t interval)
{
    LOGI("hook_mode_change_shape: status=0x%02x handle=0x%04x mode=%u interval=%u",
         status, handle, mode, interval);
    mode_change_publish(mode);
    if (g_orig_stub)
        g_orig_stub(status, handle, mode, interval);
}

static uint8_t *find_mode_change_fn_by_shape(const char *libname)
{
    size_t exec_size = 0;
    uint32_t *exec = (uint32_t *)get_lib_exec_range(libname, &exec_size);
    if (!exec) return NULL;
    uint32_t *end = exec + exec_size / 4;

    uint8_t *match = NULL;
    int n_matches = 0;

    for (uint32_t *p = exec; p < end; p++) {
        uint32_t *prologue = NULL;
        if (*p == SCS_SAVE) {
            prologue = p;
        } else if (*p == BTI_C_INSN && p + 1 < end && *(p + 1) == SCS_SAVE) {
            prologue = p + 1;
        } else {
            continue;
        }

        uint32_t *win_hi = prologue + SHAPE_SCAN_WINDOW;
        if (win_hi > end) win_hi = end;

        uint32_t *and_insn = NULL, *strh_insn = NULL;
        for (uint32_t *q = prologue; q < win_hi; q++) {
            if (!and_insn && (*q & AND_X1_FFFF_MASK) == AND_X1_FFFF_VAL) and_insn = q;
            if (!strh_insn && (*q & STRH_W1_SP_MASK) == STRH_W1_SP_VAL) strh_insn = q;
        }
        if (!and_insn || !strh_insn) continue;
        long gap = strh_insn - and_insn;
        if (gap < 0 || gap > (long)AND_STRH_MAX_GAP) continue;

        uint32_t *adrp_lo = and_insn - ADRP_LOOKBACK;
        if (adrp_lo < exec) adrp_lo = exec;
        int has_adrp_ldr = 0;
        for (uint32_t *a = adrp_lo; a < and_insn; a++) {
            if ((*a & ADRP_MASK) != ADRP_VAL) continue;
            if ((*(a + 1) & LDR_X_IMM_MASK) == LDR_X_IMM_VAL) {
                has_adrp_ldr = 1;
                break;
            }
        }
        if (!has_adrp_ldr) continue;

        uint32_t *cbz_hi = strh_insn + 1 + CBZ_LOOKAHEAD;
        if (cbz_hi > end) cbz_hi = end;
        int has_cbz = 0;
        for (uint32_t *c = strh_insn; c < cbz_hi; c++) {
            if ((*c & CBZ_X_MASK) == CBZ_X_VAL) { has_cbz = 1; break; }
        }
        if (!has_cbz) continue;

        uint8_t *cand = (uint8_t *)prologue;
        if (!match) {
            match = cand;
            n_matches = 1;
        } else if (cand != match) {
            n_matches++;
            LOGI("find_mode_change_fn_by_shape: additional candidate @ %p (ambiguous)", (void *)cand);
        }
    }

    if (n_matches != 1) {
        if (n_matches > 1)
            LOGE("find_mode_change_fn_by_shape: %d ambiguous candidates, refusing to guess", n_matches);
        return NULL;
    }
    return match;
}

int install_mode_change_hook_shape_scan(const char *libname)
{
    uint8_t *fn = find_mode_change_fn_by_shape(libname);
    if (!fn) return 0;
    if (install_hook(fn, (void *)hook_mode_change, (void **)&g_orig_stub) != 0) {
        LOGE("install_mode_change_hook_shape_scan: failed to install hook @ %p", (void *)fn);
        return 0;
    }
    LOGI("install_mode_change_hook_shape_scan: hooked @ %p", (void *)fn);
    return 1;
}
