/*
 * shim.c — libbluetooth_jni.so replacement for the BT process.
 *
 * Loaded instead of the real library via APEX bind-mount overlay.
 * DT_NEEDED: libbluetooth_jni_orig.so (SONAME patched to .sx) loads the real
 * 13 MB library alongside and provides libc symbols transitively.
 *
 * Two inline trampoline hooks (see cod.c, bond.c):
 *   cod.c  — btsnd_hcic_write_dev_class   forces CoD to 0x002508
 *   bond.c — btm_set_bond_type_dev        forces BOND_TYPE_PERSISTENT
 *
 * SELinux requirements (sepolicy.rule):
 *   allow bluetooth self:process execmem
 *
 * execmod is NOT needed: mprotect(RWX) on a currently-RX page does not set
 * VM_WRITE, so the kernel skips the execmod check.
 */

#include "shim.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>

/* ── ELF helpers ── */

static uint32_t gnu_hash_fn(const char *s)
{
    uint32_t h = 5381;
    for (unsigned char c; (c = (unsigned char)*s) != '\0'; s++)
        h = (h << 5) + h + c;
    return h;
}

static uint32_t sysv_hash_fn(const char *s)
{
    unsigned long h = 0, g;
    while (*s) {
        h = (h << 4) + (unsigned char)*s++;
        g = h & 0xF0000000UL;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return (uint32_t)h;
}

static void *get_lib_base(const char *name)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return NULL;
    char line[512];
    uintptr_t base = (uintptr_t)-1;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, name)) continue;
        uintptr_t a = (uintptr_t)strtoul(line, NULL, 16);
        if (a < base) base = a;
    }
    fclose(f);
    if (base == (uintptr_t)-1) {
        LOGE("get_lib_base: '%s' not found", name);
        return NULL;
    }
    return (void *)base;
}

void *get_lib_exec_range(const char *name, size_t *size_out)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return NULL;
    char line[512];
    uintptr_t lo = (uintptr_t)-1, hi = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, name)) continue;
        if (!strstr(line, "r-xp")) continue;
        uintptr_t a, b;
        if (sscanf(line, "%lx-%lx", &a, &b) == 2) {
            if (a < lo) lo = a;
            if (b > hi) hi = b;
        }
    }
    fclose(f);
    if (lo == (uintptr_t)-1 || hi <= lo) {
        LOGE("get_lib_exec_range: no exec region for '%s'", name);
        return NULL;
    }
    *size_out = hi - lo;
    return (void *)lo;
}

static void *find_exported_sym(const char *libname, const char *sym)
{
    uint8_t *b = (uint8_t *)get_lib_base(libname);
    if (!b) return NULL;

    uint64_t phoff = *(uint64_t *)(b + 0x20);
    uint16_t phnum = *(uint16_t *)(b + 0x38);

    uint8_t *dyn = NULL;
    for (int i = 0; i < phnum; i++) {
        uint8_t *ph = b + phoff + (uint64_t)i * 56;
        if (*(uint32_t *)ph == 2u) { dyn = b + *(uint64_t *)(ph + 16); break; }
    }
    if (!dyn) return NULL;

    uint8_t *strtab = NULL, *symtab = NULL;
    uint8_t *gnu_hash = NULL, *sysv_hash = NULL;
    for (int64_t *e = (int64_t *)dyn; e[0]; e += 2) {
        if (e[0] == 5)             strtab    = b + e[1];
        if (e[0] == 6)             symtab    = b + e[1];
        if (e[0] == 0x6ffffef5LL)  gnu_hash  = b + e[1];
        if (e[0] == 4)             sysv_hash = b + e[1];
    }
    if (!strtab || !symtab) return NULL;

    if (gnu_hash) {
        uint32_t nbuckets = *(uint32_t *)(gnu_hash +  0);
        uint32_t symndx   = *(uint32_t *)(gnu_hash +  4);
        uint32_t maskwords= *(uint32_t *)(gnu_hash +  8);
        uint32_t shift2   = *(uint32_t *)(gnu_hash + 12);
        uint64_t *bloom   = (uint64_t  *)(gnu_hash + 16);
        uint32_t *buckets = (uint32_t  *)(gnu_hash + 16 + (uint64_t)maskwords * 8);
        uint32_t *chains  = buckets + nbuckets;

        uint32_t h = gnu_hash_fn(sym);
        uint64_t bword = bloom[(h / 64u) % maskwords];
        if (!((bword >> (h % 64u)) & 1u) ||
            !((bword >> ((h >> shift2) % 64u)) & 1u))
            goto try_sysv;
        uint32_t bucket = buckets[h % nbuckets];
        if (!bucket) goto try_sysv;

        for (uint32_t si = bucket; ; si++) {
            uint32_t c = chains[si - symndx];
            if ((c & ~1u) == (h & ~1u)) {
                uint8_t *entry = symtab + (uint64_t)si * 24;
                uint32_t name_off = *(uint32_t *)entry;
                if (strcmp((const char *)(strtab + name_off), sym) == 0) {
                    uint16_t st_shndx = *(uint16_t *)(entry + 6);
                    if (st_shndx) return b + *(uint64_t *)(entry + 8);
                }
            }
            if (c & 1u) break;
        }
    }

try_sysv:
    if (sysv_hash) {
        uint32_t nbucket = *(uint32_t *)(sysv_hash + 0);
        uint32_t nchain  = *(uint32_t *)(sysv_hash + 4);
        uint32_t *bucket = (uint32_t *)(sysv_hash + 8);
        uint32_t *chain  = bucket + nbucket;

        uint32_t h = sysv_hash_fn(sym);
        for (uint32_t si = bucket[h % nbucket]; si && si < nchain; si = chain[si]) {
            uint8_t *entry = symtab + (uint64_t)si * 24;
            uint32_t name_off = *(uint32_t *)entry;
            if (strcmp((const char *)(strtab + name_off), sym) == 0) {
                uint16_t st_shndx = *(uint16_t *)(entry + 6);
                if (st_shndx) return b + *(uint64_t *)(entry + 8);
            }
        }
    }
    return NULL;
}

/* ── Cache flush ── */

static void flush_icache(void *start, size_t len)
{
    uintptr_t p   = (uintptr_t)start & ~63UL;
    uintptr_t end = (uintptr_t)start + len;
    for (uintptr_t a = p; a < end; a += 64)
        __asm__ volatile("dc cvau, %0" :: "r"(a) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    for (uintptr_t a = p; a < end; a += 64)
        __asm__ volatile("ic ivau, %0" :: "r"(a) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    __asm__ volatile("isb" ::: "memory");
}

/* ARM64 trampoline: ldr x17,[pc,#8]; br x17; .8byte <target> — 16 bytes. */
#define TRAMP_LDR_X17  0x58000051u
#define TRAMP_BR_X17   0xd61f0220u

/* ── Hook infrastructure ── */

static void *alloc_orig_stub(uint8_t *fn)
{
    uint8_t *stub = mmap(NULL, 64,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stub == MAP_FAILED) {
        LOGE("alloc_orig_stub: mmap failed (errno=%d)", errno);
        return NULL;
    }
    memcpy(stub, fn, 16);
    ((uint32_t *)stub)[4] = TRAMP_LDR_X17;
    ((uint32_t *)stub)[5] = TRAMP_BR_X17;
    uint64_t cont = (uint64_t)(fn + 16);
    memcpy(stub + 24, &cont, 8);
    flush_icache(stub, 32);
    return stub;
}

static int patch_fn(uint8_t *fn, void *hook_fn)
{
    uintptr_t page = (uintptr_t)fn & ~(uintptr_t)0xFFFu;
    /* Round fn+16 up to next page boundary to handle page-spanning trampolines. */
    size_t len = (((uintptr_t)fn & 0xFFFu) + 16u + 0xFFFu) & ~(size_t)0xFFFu;
    if (mprotect((void *)page, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("patch_fn: mprotect RWX failed (errno=%d)", errno);
        return -1;
    }
    ((uint32_t *)fn)[0] = TRAMP_LDR_X17;
    ((uint32_t *)fn)[1] = TRAMP_BR_X17;
    uint64_t h = (uint64_t)hook_fn;
    memcpy(fn + 8, &h, 8);
    flush_icache(fn, 16);
    LOGI("patch_fn: hooked %p -> %p", fn, hook_fn);
    return 0;
}

int install_hook(uint8_t *fn, void *hook_fn, void **orig_stub_out)
{
    void *stub = alloc_orig_stub(fn);
    if (!stub) return -1;
    if (patch_fn(fn, hook_fn) != 0) {
        munmap(stub, 64);
        return -1;
    }
    *orig_stub_out = stub;
    return 0;
}

/* ── BT stack ready notification ── */

void write_bt_addr(void);  /* defined in btaddr.c */

JavaVM *g_jvm = NULL;

void on_stack_ready(void)
{
    static int fired = 0;
    if (fired) return;
    fired = 1;
    write_bt_addr();
}

/* ── Entry point ── */

static const char * const ORIG_LIB_CANDIDATES[] = {
    "libbluetooth_jni_orig.so",   /* APEX-based Bluetooth (Mainline module) */
    "libbluetooth_orig.so",       /* non-APEX Bluetooth (/system or /vendor) */
    "libbluetooth_qti_orig.so",   /* Qualcomm non-APEX */
    NULL
};

static const char *find_orig_lib(void)
{
    for (int i = 0; ORIG_LIB_CANDIDATES[i]; i++)
        if (find_exported_sym(ORIG_LIB_CANDIDATES[i], "JNI_OnLoad"))
            return ORIG_LIB_CANDIDATES[i];
    return NULL;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    LOGI("JNI_OnLoad: shim loaded");
    g_jvm = vm;

    JNIEnv *env = NULL;
    (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    if (!env) { LOGE("JNI_OnLoad: GetEnv failed"); return -1; }

    const char *orig_lib = find_orig_lib();
    if (!orig_lib) { LOGE("JNI_OnLoad: orig BT library not found"); return -1; }
    LOGI("JNI_OnLoad: orig lib = %s", orig_lib);

    typedef jint (*jni_onload_fn)(JavaVM *, void *);
    jni_onload_fn orig =
        (jni_onload_fn)find_exported_sym(orig_lib, "JNI_OnLoad");
    if (!orig) { LOGE("JNI_OnLoad: orig JNI_OnLoad not found"); return -1; }

    jint version = orig(vm, reserved);

    static int installed = 0;
    if (!installed) {
        btaddr_init(env);
        install_cod_hook(orig_lib);
        install_bond_hook(orig_lib);
        installed = 1;
    }

    LOGI("JNI_OnLoad: done");
    return version;
}