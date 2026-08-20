/*
 * mode_change.c — Mode-Change Hook, Strategy 1: btm_pm_proc_mode_change
 *
 * Observational hook (unlike Hooks 1/2, never alters arguments or return
 * values): publishes the Bluetooth link's current power mode (Active/Sniff/
 * Hold/Park) to /dev/btlinkmode so JCD can avoid sending HID reports while
 * BTM is mid-negotiation of a Sniff Mode transition — a report landing
 * inside that negotiation window makes the Switch disconnect.
 *
 * Target: btm_pm_proc_mode_change(tHCI_ERROR_CODE status, uint16_t handle,
 * tHCI_MODE mode, uint16_t interval), confirmed via .gnu_debugdata symbols
 * against all 5 reference libraries in scripts/libs/. It receives the
 * already-parsed HCI Mode Change Event fields directly in w0..w3 — no byte
 * parsing needed in the hook itself, same as Hooks 1/2.
 *
 * Strategy 1 (this file): anchor on the caller (btu_hcif_mode_change_evt,
 * inlined or standalone depending on build) unpacking the raw 6-byte event
 * via 4 loads at fixed offsets from the same base register:
 *   LDRB  [Xn,#0]  status
 *   LDURH [Xn,#1]  handle
 *   LDRB  [Xn,#3]  mode
 *   LDRH  [Xn,#4]  interval
 * (per the Mode Change event layout: Status@0, Connection_Handle@1-2,
 * Current_Mode@3, Interval@4-5). From there, a small forward register-
 * dataflow simulation tracks which field each register holds — propagating
 * through MOV, and treating any BL as clobbering w0-3 per AAPCS64
 * caller-saved semantics — until it finds a BL/B where w0=status, w1=handle,
 * w2=mode, w3=interval lands on a target beginning with the shim's
 * SCS_SAVE prologue (optionally preceded by a BTI landing pad, seen on
 * newer builds).
 *
 * Verified 2026-08-20 against all 5 reference libraries: unique, exact match
 * (cross-checked against .gnu_debugdata symbols) on Sony XZ2 Compact,
 * Samsung SM-F946B, and Xiaomi libbluetooth_qti.so. Finds nothing on the two
 * Samsung A05 libraries — their compiled caller doesn't unpack the raw event
 * bytes itself (already called with pre-parsed arguments), so there is no
 * local byte-unpack fingerprint to anchor on. See mode_change_shape_scan.c
 * for the fallback strategy that covers those two.
 */

#include "shim.h"
#include "btlinkmode.h"

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

/* LDRB Wt,[Xn,#imm] / LDURH Wt,[Xn,#imm] / LDRH Wt,[Xn,#imm] (unsigned
 * offset for LDRB/LDRH, unscaled for LDURH) with both Rn and the immediate
 * fixed — only Rt (bits[4:0]) varies. */
#define LDRB_OFF0_MASK  0xFFFFFC00u
#define LDRB_OFF0_VAL   0x39400000u   /* LDRB  Wt,[Xn,#0] */
#define LDURH_OFF1_MASK 0xFFFFFC00u
#define LDURH_OFF1_VAL  0x78401000u   /* LDURH Wt,[Xn,#1] */
#define LDRH_OFF4_MASK  0xFFFFFC00u
#define LDRH_OFF4_VAL   0x79400800u   /* LDRH  Wt,[Xn,#4] */
#define LDRB_OFF3_MASK  0xFFFFFC00u
#define LDRB_OFF3_VAL   0x39400c00u   /* LDRB  Wt,[Xn,#3] */

#define LD_RN(w) (((w) >> 5) & 0x1Fu)
#define LD_RT(w) ((w) & 0x1Fu)

/* MOV Wd,Wm (ORR Wd,WZR,Wm alias) — Rn fixed to WZR(31), Rd/Rm vary. */
#define MOV_REG_MASK 0xFFE0FFE0u
#define MOV_REG_VAL  0x2A0003E0u
#define MOV_RD(w) ((w) & 0x1Fu)
#define MOV_RM(w) (((w) >> 16) & 0x1Fu)

#define BL_MASK 0xFC000000u
#define BL_VAL  0x94000000u
#define B_MASK  0xFC000000u
#define B_VAL   0x14000000u

/* bti c */
#define BTI_C_INSN 0xd503245fu

#define UNPACK_SCAN_WINDOW 8u   /* words the 4 unpack loads must fall within */
#define SIM_FORWARD_MAX   64u   /* words to simulate forward before giving up */

typedef void (*mode_change_fn_t)(uint32_t, uint32_t, uint32_t, uint32_t);
static mode_change_fn_t g_orig_stub;

static int g_linkmode_fd = -1;

static const char *mode_name(uint32_t mode)
{
    switch (mode) {
        case BT_LINK_MODE_ACTIVE: return "Active";
        case BT_LINK_MODE_HOLD:   return "Hold";
        case BT_LINK_MODE_SNIFF:  return "Sniff";
        case BT_LINK_MODE_PARK:   return "Park";
        default:                  return "?";
    }
}

void mode_change_publish(uint32_t mode)
{
    if (g_linkmode_fd < 0) {
        g_linkmode_fd = open(BTLINKMODE_PATH, O_WRONLY);
        if (g_linkmode_fd < 0) {
            LOGE("mode_change_publish: open(%s) failed (errno=%d)", BTLINKMODE_PATH, errno);
            return;
        }
    }
    char buf[2] = { (char)('0' + (mode & 0x3u)), '\n' };
    if (pwrite(g_linkmode_fd, buf, sizeof(buf), 0) != (ssize_t)sizeof(buf)) {
        LOGE("mode_change_publish: pwrite failed (errno=%d)", errno);
    }
}

static void hook_mode_change(uint32_t status, uint32_t handle, uint32_t mode, uint32_t interval)
{
    LOGI("hook_mode_change: status=0x%02x handle=0x%04x mode=%s(%u) interval=%u",
         status, handle, mode_name(mode), mode, interval);
    mode_change_publish(mode);
    if (g_orig_stub)
        g_orig_stub(status, handle, mode, interval);
}

static int target_has_scs_prologue(const uint32_t *tgt, const uint32_t *exec, const uint32_t *end)
{
    if (tgt < exec || tgt + 1 >= end) return 0;
    if (*tgt == SCS_SAVE_INSN) return 1;
    if (*tgt == BTI_C_INSN && *(tgt + 1) == SCS_SAVE_INSN) return 1;
    return 0;
}

/* Field tags tracked per register during the forward simulation. */
enum { F_NONE = 0, F_STATUS, F_HANDLE, F_MODE, F_INTERVAL };

/*
 * Simulates forward from just after the unpack quad, tracking which field
 * (if any) each register holds. Returns the call target once w0..w3 line up
 * as (status,handle,mode,interval) and the target has an SCS_SAVE prologue,
 * or NULL if nothing qualifies within SIM_FORWARD_MAX instructions.
 */
static uint32_t *simulate_to_call(uint32_t *start, uint32_t *end, const uint32_t *exec,
                                   uint32_t r_status, uint32_t r_handle,
                                   uint32_t r_mode, uint32_t r_interval)
{
    uint8_t holds[32] = {0};
    holds[r_status]   = F_STATUS;
    holds[r_handle]   = F_HANDLE;
    holds[r_mode]     = F_MODE;
    holds[r_interval] = F_INTERVAL;

    uint32_t *win_hi = start + SIM_FORWARD_MAX;
    if (win_hi > end) win_hi = end;

    for (uint32_t *q = start; q < win_hi; q++) {
        uint32_t w = *q;
        if ((w & MOV_REG_MASK) == MOV_REG_VAL) {
            uint32_t rd = MOV_RD(w), rm = MOV_RM(w);
            holds[rd] = holds[rm];
            continue;
        }
        int is_bl = (w & BL_MASK) == BL_VAL;
        int is_b  = (w & B_MASK)  == B_VAL;
        if (is_bl || is_b) {
            if (holds[0] == F_STATUS && holds[1] == F_HANDLE &&
                holds[2] == F_MODE   && holds[3] == F_INTERVAL) {
                int32_t imm26 = (int32_t)((w & 0x03FFFFFFu) << 6) >> 6;
                uint32_t *tgt = q + imm26;
                if (target_has_scs_prologue(tgt, exec, end))
                    return tgt;
            }
            if (is_b) break; /* unconditional branch ends this basic block */
            holds[0] = holds[1] = holds[2] = holds[3] = F_NONE; /* BL clobbers x0-x18 */
            continue;
        }
        /* Any other instruction writing directly to a tracked low register
         * (w0-3) outside of the unpack loads themselves invalidates it. */
        uint32_t rd_generic = w & 0x1Fu;
        if (rd_generic < 4 && holds[rd_generic] != F_NONE)
            holds[rd_generic] = F_NONE;
    }
    return NULL;
}

static uint8_t *find_mode_change_fn(const char *libname)
{
    size_t exec_size = 0;
    uint32_t *exec = (uint32_t *)get_lib_exec_range(libname, &exec_size);
    if (!exec) return NULL;
    uint32_t *end = exec + exec_size / 4;

    uint8_t *match = NULL;
    int n_matches = 0;

    for (uint32_t *p = exec; p + UNPACK_SCAN_WINDOW < end; p++) {
        uint32_t *win_hi = p + UNPACK_SCAN_WINDOW;

        uint32_t *i_status = NULL, *i_handle = NULL, *i_mode = NULL, *i_interval = NULL;
        for (uint32_t *q = p; q < win_hi; q++) {
            if (!i_status   && (*q & LDRB_OFF0_MASK)  == LDRB_OFF0_VAL)  i_status = q;
            if (!i_handle   && (*q & LDURH_OFF1_MASK) == LDURH_OFF1_VAL) i_handle = q;
            if (!i_mode     && (*q & LDRB_OFF3_MASK)  == LDRB_OFF3_VAL)  i_mode = q;
            if (!i_interval && (*q & LDRH_OFF4_MASK)  == LDRH_OFF4_VAL)  i_interval = q;
        }
        if (!i_status || !i_handle || !i_mode || !i_interval) continue;
        if (LD_RN(*i_status) != LD_RN(*i_handle) ||
            LD_RN(*i_status) != LD_RN(*i_mode) ||
            LD_RN(*i_status) != LD_RN(*i_interval))
            continue;

        uint32_t r_status = LD_RT(*i_status), r_handle = LD_RT(*i_handle);
        uint32_t r_mode = LD_RT(*i_mode), r_interval = LD_RT(*i_interval);
        if (r_status == r_handle || r_status == r_mode || r_status == r_interval ||
            r_handle == r_mode   || r_handle == r_interval || r_mode == r_interval)
            continue; /* the four fields must land in four distinct registers */

        uint32_t *last = i_status;
        if (i_handle > last) last = i_handle;
        if (i_mode > last) last = i_mode;
        if (i_interval > last) last = i_interval;

        uint32_t *tgt = simulate_to_call(last + 1, end, exec, r_status, r_handle, r_mode, r_interval);
        if (!tgt) continue;

        if (!match) {
            match = (uint8_t *)tgt;
            n_matches = 1;
        } else if ((uint8_t *)tgt != match) {
            n_matches++;
            LOGI("find_mode_change_fn: additional candidate @ %p (ambiguous)", (void *)tgt);
        }
    }

    if (n_matches != 1) {
        if (n_matches > 1)
            LOGE("find_mode_change_fn: %d ambiguous candidates, refusing to guess", n_matches);
        return NULL;
    }
    return match;
}

int install_mode_change_hook(const char *libname)
{
    uint8_t *fn = find_mode_change_fn(libname);
    if (!fn) return 0;
    if (install_hook(fn, (void *)hook_mode_change, (void **)&g_orig_stub) != 0) {
        LOGE("install_mode_change_hook: failed to install hook @ %p", (void *)fn);
        return 0;
    }
    LOGI("install_mode_change_hook: hooked @ %p", (void *)fn);
    return 1;
}
