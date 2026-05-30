/*
 * cod.c — Hook 1: btsnd_hcic_write_dev_class
 *
 * Forces the CoD argument to 0x002508 (Peripheral/Gamepad, no service-class
 * bits) on every HCI Write_Class_of_Device command.  Identified by the unique
 * `movz wX, #0x0C24` instruction (HCI opcode), disambiguated by walking back
 * to the shadow-call-stack prologue.
 *
 * CoD 0x002508 in packed form (as passed to the function):
 *   dev_class[0]=0x08 (low), dev_class[1]=0x25, dev_class[2]=0x00 (high)
 *   arg = (0x08<<16)|(0x25<<8)|0x00 = 0x082500
 */

#include "shim.h"

/* movz wX, #0x0C24  (HCI opcode Write_Class_of_Device = OGF 0x03 | OCF 0x024) */
#define MOVZ_HCI_COD_MASK  0xFFFFFFE0u
#define MOVZ_HCI_COD_VAL   0x52818480u

static void (*g_orig_stub)(uint32_t cod);

static void hook_cod(uint32_t cod)
{
    uint32_t cod_hr = ((cod & 0xFFu) << 16) | (cod & 0xFF00u) | ((cod >> 16) & 0xFFu);
    LOGI("hook_cod: CoD=0x%06x -> forcing 0x002508", cod_hr);
    if (g_orig_stub)
        g_orig_stub(0x082500u);
    on_stack_ready();
}

static uint8_t *find_cod_fn(const char *libname)
{
    size_t exec_size = 0;
    uint32_t *exec = (uint32_t *)get_lib_exec_range(libname, &exec_size);
    if (!exec) return NULL;
    uint32_t *end = exec + exec_size / 4;

    for (uint32_t *p = exec; p < end; p++) {
        if ((*p & MOVZ_HCI_COD_MASK) != MOVZ_HCI_COD_VAL)
            continue;

        for (uint32_t *q = p; q >= exec && (p - q) < 256; q--) {
            if (*q == SCS_SAVE_INSN) {
                LOGI("find_cod: fn=%p (+%u bytes)", q, (unsigned)((p - q) * 4));
                return (uint8_t *)q;
            }
        }
    }
    return NULL;
}

void install_cod_hook(const char *libname)
{
    uint8_t *fn = find_cod_fn(libname);
    if (fn)
        install_hook(fn, hook_cod, (void **)&g_orig_stub);
    else
        LOGE("install_cod_hook: btsnd_hcic_write_dev_class not found — CoD fix disabled");
}