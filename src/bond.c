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
 * Identified by a LDRB triple accessing three consecutive byte offsets
 * (N, N+1, N+2) from the same base register in tBTA_DM_SP_CFM_REQ
 * (just_works / loc_auth_req / rmt_auth_req — offsets vary by vendor build).
 * The call to btm_set_bond_type_dev is then pinpointed by the STRB that
 * immediately precedes it (writing bond_type into pairing_cb.bond_type).
 * The pairing_cb.bond_type address is decoded from the ADRP+ADD pair that
 * loads it at the same call site.
 */

#include "shim.h"

/*
 * LDRB wT,[xN,#imm] unsigned-offset: bits[31:22] = 0011 1001 01.
 * We scan for ANY three consecutive byte-offsets (N, N+1, N+2) from the
 * same base register rather than hard-coding the tBTA_DM_SP_CFM_REQ layout.
 * This makes the scan resilient to vendor struct padding differences.
 */
#define LDRB_ANY_MASK  0xFFC00000u
#define LDRB_ANY_VAL   0x39400000u
#define LDRB_OFF(w)    (((w) >> 10) & 0xFFFu)
#define LDRB_RN(w)     (((w) >>  5) & 0x01Fu)

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
        if ((*p & LDRB_ANY_MASK) != LDRB_ANY_VAL) continue;

        uint32_t off0 = LDRB_OFF(*p);
        /* just_works follows bd_name[BD_NAME_LEN=248] in tBTA_DM_SP_CFM_REQ,
         * so the offset is always > 248 regardless of vendor struct padding. */
        if (off0 < 248u) continue;
        uint32_t rn0  = LDRB_RN(*p);

        /* Require loads at off0+1 and off0+2 with the same base register. */
        uint32_t *win_lo = (p > exec + 16) ? p - 16 : exec;
        uint32_t *win_hi = (p + 32 < end)  ? p + 32 : end;
        int has_n1 = 0, has_n2 = 0;
        for (uint32_t *q = win_lo; q < win_hi; q++) {
            if ((*q & LDRB_ANY_MASK) != LDRB_ANY_VAL) continue;
            if (LDRB_RN(*q) != rn0) continue;
            uint32_t off = LDRB_OFF(*q);
            if (off == off0 + 1) has_n1 = 1;
            if (off == off0 + 2) has_n2 = 1;
        }
        if (!has_n1 || !has_n2) continue;

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

            /* bond_type_ptr must lie past the exec region (in data/BSS).
             * Pointers into the R-- header or exec itself are false positives;
             * skip this BL and keep scanning rather than returning a bad hook. */
            if (!cand || (uint8_t *)cand < (uint8_t *)exec + exec_size) {
                LOGI("find_bond: bond_type_ptr=%p not in data/BSS, skipping BL@%p",
                     (void *)cand, (void *)q);
                continue;
            }

            /* btm_set_bond_type_dev is a simple setter — it does not call
             * other functions in its prologue.  Reject BL targets that have
             * another BL within their first 8 instructions (wrapper/bridge). */
            {
                uint32_t *tgt = (uint32_t *)bl_tgt;
                int is_wrapper = 0;
                for (int k = 0; k < 8 && tgt + k < end; k++) {
                    if ((tgt[k] & BL_INSN_MASK) == BL_INSN_VAL) { is_wrapper = 1; break; }
                }
                if (is_wrapper) {
                    LOGI("find_bond: BL target %p looks like a wrapper, skipping",
                         (void *)bl_tgt);
                    continue;
                }
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
