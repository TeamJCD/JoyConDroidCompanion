#pragma once

#include <stdint.h>
#include <stddef.h>
#include <android/log.h>
#include <jni.h>

#define LOG_TAG "jcdshim"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* str x30, [x18], #8 — shadow-call-stack save, first insn of every SCS function. */
#define SCS_SAVE_INSN  0xf800865eu

/*
 * Function boundaries on stacks without shadow call stack.
 *
 * Older stacks (e.g. Android 9 builds) have no SCS_SAVE prologue and use
 * Clang CFI: direct calls land on a jump-table slot that is a single
 * unconditional B to the real body. A plain function start is a frame-setup
 * instruction right after an unconditional end of control flow (RET/B/BR) or
 * UDF padding. Mirrored in scripts/verify_hooks.py.
 */
#define RET_INSN 0xd65f03c0u

static inline int insn_is_uncond_b(uint32_t w)
{
    return (w & 0xFC000000u) == 0x14000000u;
}

static inline int insn_is_terminator(uint32_t w)
{
    return w == RET_INSN || w == 0u || insn_is_uncond_b(w)
        || (w & 0xFFFFFC1Fu) == 0xD61F0000u;            /* BR Xn */
}

static inline int insn_is_frame_prologue(uint32_t w)
{
    if ((w & 0xFFC003E0u) == 0xA98003E0u && ((w >> 21) & 1u))  /* STP Xa,Xb,[SP,#-n]! */
        return 1;
    if ((w & 0xFFE00FE0u) == 0xF8000FE0u && ((w >> 20) & 1u))  /* STR Xt,[SP,#-n]! */
        return 1;
    return (w & 0xFF8003FFu) == 0xD10003FFu;                   /* SUB SP,SP,#n */
}

/* p must not be the first word of the exec range (caller guarantees p > start). */
static inline int is_plain_fn_start(const uint32_t *p)
{
    return insn_is_terminator(p[-1]) && insn_is_frame_prologue(p[0]);
}

/* Follow a CFI jump-table slot (single B) to the real body, staying in range. */
static inline uint32_t *resolve_cfi_slot(uint32_t *p, uint32_t *start, uint32_t *end)
{
    if (p < start || p >= end || !insn_is_uncond_b(*p))
        return p;
    int32_t imm26 = (int32_t)(*p & 0x03FFFFFFu);
    if (imm26 & (1 << 25))
        imm26 -= (1 << 26);
    uint32_t *t = p + imm26;
    return (t >= start && t < end) ? t : p;
}

extern JavaVM *g_jvm;

void *get_lib_exec_range(const char *name, size_t *size_out);
int   install_hook(uint8_t *fn, void *hook_fn, void **orig_stub_out);

int  install_cod_hook(const char *libname);
int  install_bond_hook(const char *libname);
int  install_bond_hook_setter_scan(const char *libname);
int  install_mode_change_hook(const char *libname);
int  install_mode_change_hook_shape_scan(const char *libname);

void btaddr_init(JNIEnv *env);
void on_stack_ready(void);
