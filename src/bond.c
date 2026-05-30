/*
 * bond.c — Hook 3: btm_set_bond_type_dev
 *
 * Forces BOND_TYPE_PERSISTENT (1) when the stack would otherwise choose
 * BOND_TYPE_TEMPORARY (2) during JustWorks SSP without bonding bits.
 * A temporary bond causes btif_dm_auth_cmpl_evt to skip storing the link
 * key, resulting in an L2CAP Security_Block on the subsequent HID connect.
 *
 * Both the function argument and the pairing_cb.bond_type global are
 * overridden: the argument fixes the BTM device record; the global fixes
 * btif_dm_auth_cmpl_evt's decision to persist the link key.
 *
 * Identified by the unique LDRB triple accessing tBTA_DM_SP_CFM_REQ fields
 * just_works/loc_auth_req/rmt_auth_req at struct offsets 264/265/266.
 * The call to btm_set_bond_type_dev is then pinpointed by the STRB that
 * immediately precedes it (writing bond_type into pairing_cb.bond_type).
 * The pairing_cb.bond_type address is decoded from the ADRP+ADD pair that
 * loads it at the same call site.
 */

#include "shim.h"

/*
 * LDRB wT,[xN,#imm] (unsigned offset): bits[31:10] encode the type+imm12.
 * Mask 0xFFFFFC00 isolates those bits, freeing the register fields.
 *
 * tBTA_DM_SP_CFM_REQ layout (verified against LineageOS source):
 *   +264  bool     just_works
 *   +265  uint8_t  loc_auth_req
 *   +266  uint8_t  rmt_auth_req
 */
#define LDRB_MASK            0xFFFFFC00u
#define LDRB_JUST_WORKS_VAL  (0x39400000u | (264u << 10u))  /* 0x39442000 */
#define LDRB_LOC_AUTH_VAL    (0x39400000u | (265u << 10u))  /* 0x39442400 */
#define LDRB_RMT_AUTH_VAL    (0x39400000u | (266u << 10u))  /* 0x39442800 */

/* BL label: bits[31:26] = 100101 */
#define BL_INSN_MASK  0xFC000000u
#define BL_INSN_VAL   0x94000000u

/* ADRP: bit31=1, bits[28:24]=10000 */
#define ADRP_MASK  0x9F000000u
#define ADRP_VAL   0x90000000u

/* ADD Xd,Xn,#imm12 (no shift): bits[31:22] = 1001000100 */
#define ADD_IMM_MASK  0xFFC00000u
#define ADD_IMM_VAL   0x91000000u

/* STRB wN,[xM,#imm] (unsigned offset): bits[31:22] = 0011100100 */
#define STRB_MASK  0xFFC00000u
#define STRB_VAL   0x39000000u

#define BOND_TYPE_PERSISTENT  1u
#define BOND_TYPE_TEMPORARY   2u

static void (*g_orig_stub)(const void *bd_addr, uint32_t bond_type);
static volatile uint8_t *g_pairing_cb_bond_type = NULL;

static void hook_bond(const void *bd_addr, uint32_t bond_type)
{
    LOGI("hook_bond_type: bond_type=%u", bond_type);
    if (bond_type == BOND_TYPE_TEMPORARY) {
        bond_type = BOND_TYPE_PERSISTENT;
        LOGI("hook_bond_type: TEMPORARY -> PERSISTENT");
        if (g_pairing_cb_bond_type) {
            *g_pairing_cb_bond_type = (uint8_t)BOND_TYPE_PERSISTENT;
        } else {
            LOGE("hook_bond_type: pairing_cb.bond_type ptr unknown");
        }
    }
    if (g_orig_stub)
        g_orig_stub(bd_addr, bond_type);
}

/*
 * Decode ADRP+ADD pair at instruction `a` to a runtime pointer.
 *
 * ADRP imm21 = (immhi[18:0] << 2) | immlo[1:0]   from bits [23:5] and [30:29]
 * page_off   = SignExtend(imm21, 21) << 12
 * result     = (PC_of_ADRP & ~0xFFF) + page_off + ADD_imm12
 */
static volatile uint8_t *decode_adrp_add(const uint32_t *a)
{
    uint32_t immlo    = (*a >> 29) & 0x3u;
    uint32_t immhi    = (*a >> 5)  & 0x7FFFFu;
    uint32_t imm21    = (immhi << 2) | immlo;
    int64_t  page_off = (int64_t)((int32_t)(imm21 << 11) >> 11) << 12;
    uintptr_t page    = ((uintptr_t)a & ~(uintptr_t)0xFFFu) + (uintptr_t)page_off;

    uint32_t add_insn = *(a + 1);
    uint32_t imm12    = (add_insn >> 10) & 0xFFFu;
    if (add_insn & (1u << 22)) imm12 <<= 12;  /* LSL #12 shift */

    return (volatile uint8_t *)(page + imm12);
}

static uint8_t *find_bond_fn(const char *libname)
{
    size_t exec_size = 0;
    uint32_t *exec = (uint32_t *)get_lib_exec_range(libname, &exec_size);
    if (!exec) return NULL;
    uint32_t *end = exec + exec_size / 4;

    for (uint32_t *p = exec; p + 128 < end; p++) {
        if ((*p & LDRB_MASK) != LDRB_JUST_WORKS_VAL) continue;

        /* Require loc_auth_req (265) and rmt_auth_req (266) within ±16 insns. */
        uint32_t *win_lo = (p > exec + 16) ? p - 16 : exec;
        uint32_t *win_hi = (p + 32 < end)  ? p + 32 : end;
        int has265 = 0, has266 = 0;
        for (uint32_t *q = win_lo; q < win_hi; q++) {
            if ((*q & LDRB_MASK) == LDRB_LOC_AUTH_VAL) has265 = 1;
            if ((*q & LDRB_MASK) == LDRB_RMT_AUTH_VAL) has266 = 1;
        }
        if (!has265 || !has266) continue;

        /*
         * Scan forward for the first BL preceded by a STRB within 2 insns.
         * The STRB writes bond_type into pairing_cb.bond_type immediately
         * before calling btm_set_bond_type_dev — this combination is unique
         * and rejects unrelated BLs in the same large dispatcher function.
         */
        for (uint32_t *q = p; q < p + 256 && q < end; q++) {
            if ((*q & BL_INSN_MASK) != BL_INSN_VAL) continue;

            int has_strb = 0;
            if (q >= p + 1 && ((*(q - 1) & STRB_MASK) == STRB_VAL)) has_strb = 1;
            if (q >= p + 2 && ((*(q - 2) & STRB_MASK) == STRB_VAL)) has_strb = 1;
            if (!has_strb) continue;

            int32_t   imm26  = (int32_t)((*q & 0x03FFFFFFu) << 6) >> 6;
            uintptr_t bl_tgt = (uintptr_t)q + (int64_t)imm26 * 4;

            /* Decode ADRP+ADD within 16 insns before this BL. */
            uint32_t *adrp_lo = (q > p + 16) ? q - 16 : p;
            volatile uint8_t *cand = NULL;
            for (uint32_t *a = adrp_lo; a + 1 < q; a++) {
                if ((*a & ADRP_MASK) != ADRP_VAL) continue;
                if ((*(a + 1) & ADD_IMM_MASK) != ADD_IMM_VAL) continue;
                cand = decode_adrp_add(a);
                break;
            }

            /* Sanity: bond_type_ptr must be outside the exec region (i.e. in .bss). */
            if (!cand || ((uint8_t *)cand >= (uint8_t *)exec &&
                          (uint8_t *)cand <  (uint8_t *)exec + exec_size)) {
                LOGE("find_bond: decoded bond_type_ptr=%p looks invalid, ignoring",
                     (void *)cand);
                cand = NULL;
            }
            g_pairing_cb_bond_type = cand;
            LOGI("find_bond: btm_set_bond_type_dev=%p  bond_type_ptr=%p",
                (void *)bl_tgt, (void *)cand);
            return (uint8_t *)bl_tgt;
        }
    }

    return NULL;
}

void install_bond_hook(const char *libname)
{
    uint8_t *fn = find_bond_fn(libname);
    if (fn)
        install_hook(fn, hook_bond, (void **)&g_orig_stub);
    else
        LOGE("install_bond_hook: btm_set_bond_type_dev not found — persistent bond fix disabled");
}