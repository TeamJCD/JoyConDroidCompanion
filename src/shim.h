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

extern JavaVM *g_jvm;

void *get_lib_exec_range(const char *name, size_t *size_out);
int   install_hook(uint8_t *fn, void *hook_fn, void **orig_stub_out);

int  install_cod_hook(const char *libname);
int  install_bond_hook(const char *libname);
int  install_bond_hook_setter_scan(const char *libname);

void btaddr_init(JNIEnv *env);
void on_stack_ready(void);
