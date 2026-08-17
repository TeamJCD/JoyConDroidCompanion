/*
 * cod.c — Hook 1: btsnd_hcic_write_dev_class
 *
 * Forces the CoD argument to 0x002508 (Peripheral/Gamepad, no service-class
 * bits) on every HCI Write_Class_of_Device command.  Identified by the unique
 * `movz wX, #0x0C24` instruction (HCI opcode), disambiguated by walking back
 * to the shadow-call-stack prologue.
 *
 * Samsung's BT stack ships up to 3 independent functions that encode this
 * opcode (fn1/fn2/fn3).  All are hooked; on non-Samsung builds only fn1
 * exists and fn2/fn3 slots are silently skipped.
 *
 * CoD 0x002508 in packed form (as passed to the function):
 *   dev_class[0]=0x08 (low), dev_class[1]=0x25, dev_class[2]=0x00 (high)
 *   arg = (0x08<<16)|(0x25<<8)|0x00 = 0x082500
 */

#include "shim.h"

/* movz wX, #0x0C24  (HCI opcode Write_Class_of_Device = OGF 0x03 | OCF 0x024) */
#define MOVZ_HCI_COD_MASK  0xFFFFFFE0u
#define MOVZ_HCI_COD_VAL   0x52818480u

#define MAX_COD_HOOKS 4

typedef void (*cod_fn_t)(uint32_t);

static cod_fn_t g_orig_stubs[MAX_COD_HOOKS];

static void cod_hook_impl(uint32_t cod, int idx)
{
    uint32_t cod_hr = ((cod & 0xFFu) << 16) | (cod & 0xFF00u) | ((cod >> 16) & 0xFFu);
    LOGI("hook_cod[%d]: CoD=0x%06x -> forcing 0x002508", idx, cod_hr);
    if (g_orig_stubs[idx])
        g_orig_stubs[idx](0x082500u);
    on_stack_ready();
}

static void hook_cod_0(uint32_t cod) { cod_hook_impl(cod, 0); }
static void hook_cod_1(uint32_t cod) { cod_hook_impl(cod, 1); }
static void hook_cod_2(uint32_t cod) { cod_hook_impl(cod, 2); }
static void hook_cod_3(uint32_t cod) { cod_hook_impl(cod, 3); }

static cod_fn_t const g_hook_fns[MAX_COD_HOOKS] = {
    hook_cod_0, hook_cod_1, hook_cod_2, hook_cod_3
};

/*
 * Returns 1 if the function treats x0 as a raw uint32_t CoD value, 0 if it
 * treats x0 as a structure pointer.
 *
 * Detection: an instruction of the form  ADD X*, X0, #imm12  with imm12 >= 64
 * before the MOVZ indicates x0 is used as a pointer base.  btsnd_hcic_write_dev_class
 * and compact variants never do this — they save, shift, or pass x0 directly.
 */
static int cod_fn_takes_raw_value(uint32_t *fn_start, uint32_t *movz_pos)
{
    /* ADD X*, X0, #imm12 — 64-bit, no flags, Rn=X0 */
    const uint32_t ADD_X0_MASK = 0xFF8003E0u; /* sf=1 opc=0 S=0 100001 * Rn=0 */
    const uint32_t ADD_X0_VAL  = 0x91000000u;
    for (uint32_t *q = fn_start; q < movz_pos; q++) {
        if ((*q & ADD_X0_MASK) == ADD_X0_VAL) {
            uint32_t imm12 = (*q >> 10) & 0xFFFu;
            if (imm12 >= 64u) return 0;
        }
    }
    return 1;
}

int install_cod_hook(const char *libname)
{
    size_t exec_size = 0;
    uint32_t *exec = (uint32_t *)get_lib_exec_range(libname, &exec_size);
    if (!exec) return 0;
    uint32_t *end = exec + exec_size / 4;

    int n_installed = 0;
    uint8_t *seen_fns[MAX_COD_HOOKS] = {NULL};

    for (uint32_t *p = exec; p < end && n_installed < MAX_COD_HOOKS; p++) {
        if ((*p & MOVZ_HCI_COD_MASK) != MOVZ_HCI_COD_VAL)
            continue;

        /* Walk back to the nearest SCS_SAVE — function entry point. */
        uint8_t *fn = NULL;
        for (uint32_t *q = p; q >= exec && (p - q) < 256; q--) {
            if (*q == SCS_SAVE_INSN) {
                fn = (uint8_t *)q;
                break;
            }
        }
        if (!fn) continue;

        /* Skip if this function was already hooked (multiple MOVZ in one fn). */
        int dup = 0;
        for (int i = 0; i < n_installed; i++) {
            if (seen_fns[i] == fn) { dup = 1; break; }
        }
        if (dup) continue;

        /*
         * Skip functions that treat x0 as a structure pointer rather than a
         * raw CoD value.  Such wrappers have a different calling convention:
         * calling them with cod=0x082500 would crash on the first pointer
         * dereference.
         */
        if (!cod_fn_takes_raw_value((uint32_t *)fn, p)) {
            LOGI("find_cod: fn=%p skipped (x0 is pointer, not raw CoD)", fn);
            continue;
        }

        seen_fns[n_installed] = fn;
        LOGI("find_cod: fn=%p (+%u bytes to MOVZ)", fn,
             (unsigned)((p - (uint32_t *)fn) * 4));

        install_hook(fn, (void *)g_hook_fns[n_installed],
                     (void **)&g_orig_stubs[n_installed]);
        n_installed++;
    }

    if (n_installed == 0)
        LOGE("install_cod_hook: btsnd_hcic_write_dev_class not found — CoD fix disabled");
    else
        LOGI("install_cod_hook: %d hook(s) installed", n_installed);
    return n_installed;
}
