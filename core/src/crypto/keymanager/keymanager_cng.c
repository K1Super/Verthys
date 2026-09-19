/*
 * keymanager_cng.c — V3 密钥组 CNG 内核托管生命周期实现
 *
 * 批量导入流程：
 *   MEK 明文（用户态栈帧唯一暴露点）→ BCryptGenerateSymmetricKey 导入内核
 *   → 立即清零 → 用 MEK 内核句柄逐角色解包 wrapped 子密钥（解密在内核态，
 *   解包输出为栈上 32B + 立即导入 + 立即清零）→ KERNEL_RESIDENT。
 *
 * 失败原子性：任一步失败 → 销毁本次已导入的全部句柄 → 状态回 UNINITIALIZED，
 * 不留半导入态（与 vsb_txn 回滚语义对齐）。
 */
#include "keymanager_cng.h"
#include "verthys_internal.h"  /* verthys_secure_zero */
#include "verthys_crypto.h"    /* verthys_random_bytes（密钥组生成） */

#include <string.h>

/* ---------- 进程级句柄总量（defense_closure MEM_DUMP 判据） ----------
 * 全部 VerthysCngKeyManager 实例的活跃内核句柄之和，Interlocked 原子维护。
 * > 0 ⇒ 密钥组已进入 CNG 内核托管（V3 目标态）。 */
static volatile LONG s_kernel_handle_total = 0;

/* ---------- V3 域分离标签（与 V2 标签严格隔离） ---------- */

/* wrapped 子密钥 AAD 前缀："verthys/wrap-v3"（16 字节数组：15 字符 + NUL 填充） */
static const uint8_t WRAP_AAD_PREFIX[16] = {
    'v', 'e', 'r', 't', 'h', 'y', 's',
    '/', 'w', 'r', 'a', 'p', '-', 'v', '3'
};

/*
 * 构造 wrapped 子密钥 AAD：前缀(16B) + 角色字节(1B)。
 * 域分离保证：同一密钥组内 A/B/C 的 wrapped 数据不可互换（角色绑定）。
 */
static void build_wrap_aad(uint8_t aad[17], uint8_t role)
{
    memcpy(aad, WRAP_AAD_PREFIX, sizeof(WRAP_AAD_PREFIX));
    aad[16] = role;
}

/* 角色固定的非敏感 key_id（诊断/轮换追踪；恒定内容，不含密钥信息） */
static const uint8_t ROLE_KEY_ID[VERTHYS_CNG_KEY_COUNT][VERTHYS_CNG_KEY_ID_BYTES] = {
    { 'v', 'e', 'r', 't', 'h', 'y', 's', ':', 'm', 'e', 'k', ':', 'v', '3', 0 },
    { 'v', 'e', 'r', 't', 'h', 'y', 's', ':', 'k', 'e', 'y', 'a', ':', 'v', '3' },
    { 'v', 'e', 'r', 't', 'h', 'y', 's', ':', 'k', 'e', 'y', 'b', ':', 'v', '3' },
    { 'v', 'e', 'r', 't', 'h', 'y', 's', ':', 'k', 'e', 'y', 'c', ':', 'v', '3' },
};

/* ---------- 公共接口 ---------- */

VerthysResult verthys_cng_km_init(VerthysCngKeyManager *km)
{
    if (km == NULL) return VERTHYS_ERR_INVALID;

    /* 预创建共享 AES-GCM 算法提供者（幂等） */
    VerthysResult r = verthys_cng_init_once();
    if (r != VERTHYS_OK) return r;

    memset(km, 0, sizeof(*km));
    km->state         = VERTHYS_CNG_KM_UNINITIALIZED;
    km->handle_count  = 0;
    return VERTHYS_OK;
}

/*
 * 单角色内核态解包 + 导入：
 *   wrapped（60B）→ MEK 内核句柄解密（AAD=角色绑定标签）→ 栈上明文
 *   → 导入角色上下文 → 清零栈明文。
 * 失败返回 VERTHYS_ERR_AUTH / VERTHYS_ERR_INVALID，且不留句柄。
 */
static VerthysResult import_wrapped_role(VerthysCngKeyManager *km,
                                       VerthysCngKeyRole role,
                                       const uint8_t *wrapped,
                                       uint32_t wrapped_len)
{
    /* ★ 红线：解包输出缓冲栈上分配 + 导入后立即清零 */
    uint8_t key_material[VERTHYS_CNG_KEY_BYTES];
    size_t  key_len = sizeof(key_material);
    uint8_t aad[17];
    VerthysResult r;

    if (wrapped == NULL || wrapped_len != VERTHYS_CNG_WRAPPED_BYTES) {
        return VERTHYS_ERR_INVALID;
    }

    build_wrap_aad(aad, (uint8_t)role);

    /* wrapped 布局：[12B nonce || 32B ct || 16B tag]，解密在内核态完成 */
    r = verthys_cng_aead_decrypt(&km->keys[VERTHYS_CNG_KEY_MEK],
                               wrapped + VERTHYS_CNG_NONCE_BYTES,
                               wrapped_len - VERTHYS_CNG_NONCE_BYTES,
                               aad, sizeof(aad),
                               wrapped,
                               key_material, &key_len);
    if (r != VERTHYS_OK) {
        verthys_secure_zero(key_material, sizeof(key_material));
        return r;
    }
    if (key_len != VERTHYS_CNG_KEY_BYTES) {
        verthys_secure_zero(key_material, sizeof(key_material));
        return VERTHYS_ERR_CORRUPT;
    }

    /* 导入内核（import 内部清零 key_material，const 契约同 verthys_crypto_cng.h） */
    r = verthys_cng_aead_import_key(&km->keys[role], key_material,
                                  ROLE_KEY_ID[role]);
    verthys_secure_zero(key_material, sizeof(key_material));
    if (r != VERTHYS_OK) return r;

    km->handle_count++;
    InterlockedIncrement(&s_kernel_handle_total);
    return VERTHYS_OK;
}

/* 销毁全部已导入句柄（不改变调用方期望的最终状态） */
static void destroy_all_handles(VerthysCngKeyManager *km)
{
    /* 进程级总量同步递减（与 km->handle_count 严格配对） */
    if (km->handle_count > 0) {
        InterlockedAdd(&s_kernel_handle_total, -(LONG)km->handle_count);
    }
    for (int r = 0; r < (int)VERTHYS_CNG_KEY_COUNT; r++) {
        if (verthys_cng_aead_is_imported(&km->keys[r])) {
            verthys_cng_aead_destroy(&km->keys[r]);
        }
    }
    km->handle_count = 0;
}

VerthysResult verthys_cng_km_import_batch(
    VerthysCngKeyManager *km,
    const uint8_t mek[VERTHYS_CNG_KEY_BYTES],
    const uint8_t *wrapped_a, uint32_t wrapped_a_len,
    const uint8_t *wrapped_b, uint32_t wrapped_b_len,
    const uint8_t *wrapped_c, uint32_t wrapped_c_len)
{
    VerthysResult r;

    if (km == NULL || mek == NULL) return VERTHYS_ERR_INVALID;

    /* 状态机守卫：仅接受初始态或已初始化态（重入导入 = 解锁重入）；
     * DESTROYED 为终态，须 verthys_cng_km_init 方可重新导入 */
    if (km->state == VERTHYS_CNG_KM_REKEYING) return VERTHYS_ERR_LOCKED;
    if (km->state == VERTHYS_CNG_KM_DERIVED)  return VERTHYS_ERR_LOCKED;
    if (km->state == VERTHYS_CNG_KM_DESTROYED) return VERTHYS_ERR_INVALID;

    /* 重入：先销毁旧句柄（旧密钥组整体退场，不留混合态） */
    if (km->state == VERTHYS_CNG_KM_KERNEL_RESIDENT ||
        km->handle_count > 0) {
        destroy_all_handles(km);
    }
    km->state = VERTHYS_CNG_KM_DERIVED;

    /* 句柄预算校验（4 把密钥 ≤ 16 上限） */
    if (VERTHYS_CNG_KEY_COUNT > VERTHYS_CNG_MAX_HANDLES) {
        km->state = VERTHYS_CNG_KM_UNINITIALIZED;
        return VERTHYS_ERR_INTERNAL;
    }

    /* 1. 导入 MEK——密钥组唯一用户态明文暴露点（导入后立即清零） */
    r = verthys_cng_aead_import_key(&km->keys[VERTHYS_CNG_KEY_MEK],
                                  mek, ROLE_KEY_ID[VERTHYS_CNG_KEY_MEK]);
    if (r != VERTHYS_OK) {
        km->state = VERTHYS_CNG_KM_UNINITIALIZED;
        return r;
    }
    km->handle_count = 1;
    InterlockedIncrement(&s_kernel_handle_total);

    /* 2/3. 逐角色内核态解包导入（失败即整体回滚） */
    r = import_wrapped_role(km, VERTHYS_CNG_KEY_A, wrapped_a, wrapped_a_len);
    if (r != VERTHYS_OK) goto fail;
    r = import_wrapped_role(km, VERTHYS_CNG_KEY_B, wrapped_b, wrapped_b_len);
    if (r != VERTHYS_OK) goto fail;
    r = import_wrapped_role(km, VERTHYS_CNG_KEY_C, wrapped_c, wrapped_c_len);
    if (r != VERTHYS_OK) goto fail;

    km->state = VERTHYS_CNG_KM_KERNEL_RESIDENT;
    return VERTHYS_OK;

fail:
    /* 失败原子性：销毁本次全部已导入句柄，状态回初始 */
    destroy_all_handles(km);
    km->state = VERTHYS_CNG_KM_UNINITIALIZED;
    return r;
}

VerthysResult verthys_cng_km_wrap_key(
    VerthysCngKeyManager *km,
    VerthysCngKeyRole role,
    const uint8_t key[VERTHYS_CNG_KEY_BYTES],
    uint8_t *wrapped_out, uint32_t wrapped_out_cap)
{
    uint8_t aad[17];
    uint8_t nonce[VERTHYS_CNG_NONCE_BYTES];
    size_t ct_len = VERTHYS_CNG_KEY_BYTES + VERTHYS_CNG_TAG_BYTES;
    VerthysResult r;

    if (km == NULL || key == NULL || wrapped_out == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (role != VERTHYS_CNG_KEY_A && role != VERTHYS_CNG_KEY_B &&
        role != VERTHYS_CNG_KEY_C) {
        return VERTHYS_ERR_INVALID;
    }
    if (wrapped_out_cap < VERTHYS_CNG_WRAPPED_BYTES) {
        return VERTHYS_ERR_INVALID;
    }
    /* 前置：MEK 已导入（创建路径：先导入 MEK 语境后调用） */
    if (!verthys_cng_aead_is_imported(&km->keys[VERTHYS_CNG_KEY_MEK])) {
        return VERTHYS_ERR_LOCKED;
    }

    build_wrap_aad(aad, (uint8_t)role);

    /* wrapped 布局：[12B nonce || 32B ct || 16B tag]；加密在内核态完成 */
    r = verthys_cng_aead_encrypt(&km->keys[VERTHYS_CNG_KEY_MEK],
                               key, VERTHYS_CNG_KEY_BYTES,
                               aad, sizeof(aad),
                               wrapped_out + VERTHYS_CNG_NONCE_BYTES,
                               &ct_len, nonce);
    if (r != VERTHYS_OK) {
        verthys_secure_zero((void *)key, VERTHYS_CNG_KEY_BYTES);
        return r;
    }
    if (ct_len != VERTHYS_CNG_KEY_BYTES + VERTHYS_CNG_TAG_BYTES) {
        verthys_secure_zero((void *)key, VERTHYS_CNG_KEY_BYTES);
        return VERTHYS_ERR_INTERNAL;
    }
    memcpy(wrapped_out, nonce, VERTHYS_CNG_NONCE_BYTES);
    verthys_secure_zero(nonce, sizeof(nonce));

    /* 红线：子密钥明文仅本栈帧瞬态，返回前清零（const 契约同 import） */
    verthys_secure_zero((void *)key, VERTHYS_CNG_KEY_BYTES);
    return VERTHYS_OK;
}

VerthysCngAead *verthys_cng_km_get(VerthysCngKeyManager *km, VerthysCngKeyRole role)
{
    if (km == NULL || role < 0 || role >= VERTHYS_CNG_KEY_COUNT) return NULL;
    if (km->state != VERTHYS_CNG_KM_KERNEL_RESIDENT) return NULL;
    if (!verthys_cng_aead_is_imported(&km->keys[role])) return NULL;
    return &km->keys[role];
}

/*
 * ChangePassword V3：旧口令派生 MEK 的包裹验证。
 * candidate MEK 临时导入（唯一句柄，用后即毁）→ 对 wrapped_probe 做内核态
 * 解包试探：AEAD 认证通过 = 口令正确；AUTH 失败 = 口令错误。
 * 解包输出为栈上 32B 瞬态，验证后清零。
 * import_key 的 const 契约：mek 入参在导入完成后被清零。
 */
VerthysResult verthys_cng_km_verify_mek(
    const uint8_t mek[VERTHYS_CNG_KEY_BYTES],
    const uint8_t *wrapped_probe, uint32_t wrapped_probe_len)
{
    VerthysCngAead probe;
    uint8_t key_material[VERTHYS_CNG_KEY_BYTES];
    size_t key_len = sizeof(key_material);
    uint8_t aad[17];
    VerthysResult r;

    if (mek == NULL || wrapped_probe == NULL ||
        wrapped_probe_len != VERTHYS_CNG_WRAPPED_BYTES) {
        return VERTHYS_ERR_INVALID;
    }

    r = verthys_cng_init_once();
    if (r != VERTHYS_OK) return r;

    build_wrap_aad(aad, (uint8_t)VERTHYS_CNG_KEY_A);  /* 探针角色与调用方约定一致 */

    r = verthys_cng_aead_init(&probe);
    if (r != VERTHYS_OK) {
        verthys_secure_zero(key_material, sizeof(key_material));
        return r;
    }
    r = verthys_cng_aead_import_key(&probe, mek, ROLE_KEY_ID[VERTHYS_CNG_KEY_MEK]);
    if (r != VERTHYS_OK) {
        /* mek 已被 import_key 内部清零（const 契约），无需再清 */
        verthys_secure_zero(key_material, sizeof(key_material));
        return r;
    }

    r = verthys_cng_aead_decrypt(&probe,
                               wrapped_probe + VERTHYS_CNG_NONCE_BYTES,
                               wrapped_probe_len - VERTHYS_CNG_NONCE_BYTES,
                               aad, sizeof(aad),
                               wrapped_probe,
                               key_material, &key_len);
    verthys_cng_aead_destroy(&probe);
    verthys_secure_zero(key_material, sizeof(key_material));
    /* VERTHYS_OK = 口令正确；VERTHYS_ERR_AUTH = 口令错误；其余透传 */
    return r;
}

/*
 * ChangePassword V3：单角色重包裹（rekey 内部步骤）。
 * 旧 MEK（km 驻留句柄）解包 wrapped（超级块现值）→ 栈上 32B 瞬态 →
 * 新 MEK 临时句柄（new_mek_aead）内核态加密 → new_wrapped_out。
 * 明文在函数返回前清零。
 */
static VerthysResult rekey_one_role(VerthysCngKeyManager *km,
                                  VerthysCngAead *new_mek_aead,
                                  VerthysCngKeyRole role,
                                  const uint8_t *wrapped, uint32_t wrapped_len,
                                  uint8_t *wrapped_out, uint32_t wrapped_out_cap)
{
    uint8_t key_material[VERTHYS_CNG_KEY_BYTES];
    size_t key_len = sizeof(key_material);
    uint8_t aad[17];
    uint8_t nonce[VERTHYS_CNG_NONCE_BYTES];
    size_t ct_len = VERTHYS_CNG_KEY_BYTES + VERTHYS_CNG_TAG_BYTES;
    VerthysResult r;

    if (wrapped == NULL || wrapped_len != VERTHYS_CNG_WRAPPED_BYTES) {
        return VERTHYS_ERR_INVALID;
    }
    if (wrapped_out == NULL || wrapped_out_cap < VERTHYS_CNG_WRAPPED_BYTES) {
        return VERTHYS_ERR_INVALID;
    }

    build_wrap_aad(aad, (uint8_t)role);

    /* 1. 旧 MEK 解包（解密在内核态完成，输出栈上 32B） */
    r = verthys_cng_aead_decrypt(&km->keys[VERTHYS_CNG_KEY_MEK],
                               wrapped + VERTHYS_CNG_NONCE_BYTES,
                               wrapped_len - VERTHYS_CNG_NONCE_BYTES,
                               aad, sizeof(aad),
                               wrapped,
                               key_material, &key_len);
    if (r != VERTHYS_OK) {
        verthys_secure_zero(key_material, sizeof(key_material));
        return r;   /* AUTH = wrapped 与 km 旧 MEK 不匹配（状态交叉异常） */
    }
    if (key_len != VERTHYS_CNG_KEY_BYTES) {
        verthys_secure_zero(key_material, sizeof(key_material));
        return VERTHYS_ERR_CORRUPT;
    }

    /* 2. 新 MEK 重新包裹（内核态加密，nonce 内部计数器生成） */
    r = verthys_cng_aead_encrypt(new_mek_aead, key_material, VERTHYS_CNG_KEY_BYTES,
                               aad, sizeof(aad),
                               wrapped_out + VERTHYS_CNG_NONCE_BYTES,
                               &ct_len, nonce);
    verthys_secure_zero(key_material, sizeof(key_material));  /* 红线：明文仅本栈帧 */
    if (r != VERTHYS_OK) return r;
    if (ct_len != VERTHYS_CNG_KEY_BYTES + VERTHYS_CNG_TAG_BYTES) {
        return VERTHYS_ERR_INTERNAL;
    }
    memcpy(wrapped_out, nonce, VERTHYS_CNG_NONCE_BYTES);
    verthys_secure_zero(nonce, sizeof(nonce));
    return VERTHYS_OK;
}

VerthysResult verthys_cng_km_rekey(
    VerthysCngKeyManager *km,
    const uint8_t new_mek[VERTHYS_CNG_KEY_BYTES],
    const uint8_t *wrapped_a, uint32_t wrapped_a_len,
    const uint8_t *wrapped_b, uint32_t wrapped_b_len,
    const uint8_t *wrapped_c, uint32_t wrapped_c_len,
    uint8_t *new_wrapped_a_out, uint32_t new_wrapped_a_cap,
    uint8_t *new_wrapped_b_out, uint32_t new_wrapped_b_cap,
    uint8_t *new_wrapped_c_out, uint32_t new_wrapped_c_cap)
{
    VerthysCngAead new_mek_ctx;
    VerthysResult r;

    if (km == NULL || new_mek == NULL ||
        wrapped_a == NULL || wrapped_b == NULL || wrapped_c == NULL ||
        new_wrapped_a_out == NULL || new_wrapped_b_out == NULL ||
        new_wrapped_c_out == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (wrapped_a_len != VERTHYS_CNG_WRAPPED_BYTES ||
        wrapped_b_len != VERTHYS_CNG_WRAPPED_BYTES ||
        wrapped_c_len != VERTHYS_CNG_WRAPPED_BYTES) {
        return VERTHYS_ERR_INVALID;
    }
    if (new_wrapped_a_cap < VERTHYS_CNG_WRAPPED_BYTES ||
        new_wrapped_b_cap < VERTHYS_CNG_WRAPPED_BYTES ||
        new_wrapped_c_cap < VERTHYS_CNG_WRAPPED_BYTES) {
        return VERTHYS_ERR_INVALID;
    }
    /* 前置：KERNEL_RESIDENT（旧 MEK 可用于解包现值 wrapped） */
    if (km->state != VERTHYS_CNG_KM_KERNEL_RESIDENT) return VERTHYS_ERR_LOCKED;
    if (!verthys_cng_aead_is_imported(&km->keys[VERTHYS_CNG_KEY_MEK])) {
        return VERTHYS_ERR_LOCKED;
    }

    /* 新 MEK 临时句柄（导入 + 三角色重包裹 + 销毁，全在本栈帧内） */
    r = verthys_cng_aead_init(&new_mek_ctx);
    if (r != VERTHYS_OK) return r;
    r = verthys_cng_aead_import_key(&new_mek_ctx, new_mek,
                                 ROLE_KEY_ID[VERTHYS_CNG_KEY_MEK]);
    if (r != VERTHYS_OK) {
        /* new_mek 已被 import_key 内部清零（const 契约） */
        return r;
    }

    r = rekey_one_role(km, &new_mek_ctx, VERTHYS_CNG_KEY_A,
                       wrapped_a, wrapped_a_len,
                       new_wrapped_a_out, new_wrapped_a_cap);
    if (r != VERTHYS_OK) goto out;
    r = rekey_one_role(km, &new_mek_ctx, VERTHYS_CNG_KEY_B,
                       wrapped_b, wrapped_b_len,
                       new_wrapped_b_out, new_wrapped_b_cap);
    if (r != VERTHYS_OK) goto out;
    r = rekey_one_role(km, &new_mek_ctx, VERTHYS_CNG_KEY_C,
                       wrapped_c, wrapped_c_len,
                       new_wrapped_c_out, new_wrapped_c_cap);

out:
    verthys_cng_aead_destroy(&new_mek_ctx);
    /* km 状态零变更（旧 MEK + A/B/C 原样驻留）；失败产物由调用方丢弃 */
    return r;
}

VerthysResult verthys_cng_km_rotate_mek(
    VerthysCngKeyManager *km,
    const uint8_t new_mek[VERTHYS_CNG_KEY_BYTES])
{
    VerthysResult r;

    if (km == NULL || new_mek == NULL) return VERTHYS_ERR_INVALID;
    if (km->state != VERTHYS_CNG_KM_KERNEL_RESIDENT) return VERTHYS_ERR_LOCKED;
    if (!verthys_cng_aead_is_imported(&km->keys[VERTHYS_CNG_KEY_MEK])) {
        return VERTHYS_ERR_LOCKED;
    }

    /* 销毁旧 → 导入新（顺序保证任何时刻 MEK 槽位至多一把句柄；
     * 导入失败 = MEK 角色空缺，A/B/C 运行态不受影响，错误上抛） */
    verthys_cng_aead_destroy(&km->keys[VERTHYS_CNG_KEY_MEK]);
    km->handle_count--;
    InterlockedDecrement(&s_kernel_handle_total);

    r = verthys_cng_aead_import_key(&km->keys[VERTHYS_CNG_KEY_MEK], new_mek,
                                 ROLE_KEY_ID[VERTHYS_CNG_KEY_MEK]);
    if (r != VERTHYS_OK) return r;
    km->handle_count++;
    InterlockedIncrement(&s_kernel_handle_total);
    return VERTHYS_OK;
}

VerthysResult verthys_cng_km_rotate_abc(
    VerthysCngKeyManager *km,
    VerthysCngAead *new_a,
    VerthysCngAead *new_b,
    VerthysCngAead *new_c)
{
    int destroyed = 0;
    int role;

    if (km == NULL || new_a == NULL || new_b == NULL || new_c == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (km->state != VERTHYS_CNG_KM_KERNEL_RESIDENT) {
        verthys_cng_aead_destroy(new_a);   /* 消耗语义：失败同样接管 */
        verthys_cng_aead_destroy(new_b);
        verthys_cng_aead_destroy(new_c);
        return VERTHYS_ERR_LOCKED;
    }
    if (!verthys_cng_aead_is_imported(new_a) ||
        !verthys_cng_aead_is_imported(new_b) ||
        !verthys_cng_aead_is_imported(new_c)) {
        verthys_cng_aead_destroy(new_a);
        verthys_cng_aead_destroy(new_b);
        verthys_cng_aead_destroy(new_c);
        return VERTHYS_ERR_INVALID;
    }

    /* 1. 销毁旧 A/B/C（MEK 不动；槽位地址不变是借用指针续期的前提） */
    for (role = (int)VERTHYS_CNG_KEY_A; role <= (int)VERTHYS_CNG_KEY_C; role++) {
        if (verthys_cng_aead_is_imported(&km->keys[role])) {
            verthys_cng_aead_destroy(&km->keys[role]);
            destroyed++;
        }
    }
    if (destroyed > 0) {
        km->handle_count -= destroyed;
        InterlockedAdd(&s_kernel_handle_total, -(LONG)destroyed);
    }

    /* 2. 原位移交：结构拷贝（POD：句柄 + nonce 计数器 + key_id）+
     *    调用方栈结构清零防双重销毁 */
    km->keys[VERTHYS_CNG_KEY_A] = *new_a;
    km->keys[VERTHYS_CNG_KEY_B] = *new_b;
    km->keys[VERTHYS_CNG_KEY_C] = *new_c;
    memset(new_a, 0, sizeof(*new_a));
    memset(new_b, 0, sizeof(*new_b));
    memset(new_c, 0, sizeof(*new_c));

    /* 3. 计数配对（销毁 destroyed + 移交 3；new_* 由调用方直接 import，
     *    未曾计入——此处在 km/全局两侧补记，维持"总量 = 实际句柄数"） */
    km->handle_count += 3;
    InterlockedAdd(&s_kernel_handle_total, 3);
    return VERTHYS_OK;
}

VerthysResult verthys_cng_km_generate_keyset(
    VerthysCngKeyManager *km,
    const uint8_t mek[VERTHYS_CNG_KEY_BYTES],
    uint8_t *wrapped_a_out, uint32_t wrapped_a_cap,
    uint8_t *wrapped_b_out, uint32_t wrapped_b_cap,
    uint8_t *wrapped_c_out, uint32_t wrapped_c_cap)
{
    /* A/B/C 明文仅本栈帧瞬态（wrap 后由 wrap_key 清零，红线） */
    uint8_t key_a[VERTHYS_CNG_KEY_BYTES];
    uint8_t key_b[VERTHYS_CNG_KEY_BYTES];
    uint8_t key_c[VERTHYS_CNG_KEY_BYTES];
    VerthysResult r;

    if (km == NULL || mek == NULL ||
        wrapped_a_out == NULL || wrapped_b_out == NULL || wrapped_c_out == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (wrapped_a_cap < VERTHYS_CNG_WRAPPED_BYTES ||
        wrapped_b_cap < VERTHYS_CNG_WRAPPED_BYTES ||
        wrapped_c_cap < VERTHYS_CNG_WRAPPED_BYTES) {
        return VERTHYS_ERR_INVALID;
    }
    /* 状态机守卫：创建路径专用——REKEYING 中途禁止；DESTROYED 须先 init */
    if (km->state == VERTHYS_CNG_KM_REKEYING) return VERTHYS_ERR_LOCKED;
    if (km->state == VERTHYS_CNG_KM_DERIVED)  return VERTHYS_ERR_LOCKED;
    if (km->state == VERTHYS_CNG_KM_DESTROYED) return VERTHYS_ERR_INVALID;

    /* 重生成：旧密钥组整体退场（不留混合态） */
    if (km->state == VERTHYS_CNG_KM_KERNEL_RESIDENT || km->handle_count > 0) {
        destroy_all_handles(km);
    }
    km->state = VERTHYS_CNG_KM_DERIVED;

    /* 1. MEK 临时代入（wrap 语境；产物销毁后状态归还 UNINITIALIZED） */
    r = verthys_cng_aead_import_key(&km->keys[VERTHYS_CNG_KEY_MEK],
                                  mek, ROLE_KEY_ID[VERTHYS_CNG_KEY_MEK]);
    if (r != VERTHYS_OK) {
        km->state = VERTHYS_CNG_KM_UNINITIALIZED;
        return r;
    }
    km->handle_count = 1;
    InterlockedIncrement(&s_kernel_handle_total);

    /* 2. A/B/C 随机生成 + 内核态 wrap（wrap_key 内部清零明文） */
    verthys_random_bytes(key_a, sizeof(key_a));
    verthys_random_bytes(key_b, sizeof(key_b));
    verthys_random_bytes(key_c, sizeof(key_c));

    r = verthys_cng_km_wrap_key(km, VERTHYS_CNG_KEY_A, key_a,
                              wrapped_a_out, wrapped_a_cap);
    if (r != VERTHYS_OK) goto fail;
    r = verthys_cng_km_wrap_key(km, VERTHYS_CNG_KEY_B, key_b,
                              wrapped_b_out, wrapped_b_cap);
    if (r != VERTHYS_OK) goto fail;
    r = verthys_cng_km_wrap_key(km, VERTHYS_CNG_KEY_C, key_c,
                              wrapped_c_out, wrapped_c_cap);
    if (r != VERTHYS_OK) goto fail;

    /* 3. 临时 MEK 退场：正式导入交由 import_batch（调用方持久化后执行） */
    destroy_all_handles(km);
    km->state = VERTHYS_CNG_KM_UNINITIALIZED;
    /* 防御性清零（wrap_key 已清零；覆盖编译器优化差异） */
    verthys_secure_zero(key_a, sizeof(key_a));
    verthys_secure_zero(key_b, sizeof(key_b));
    verthys_secure_zero(key_c, sizeof(key_c));
    return VERTHYS_OK;

fail:
    verthys_secure_zero(key_a, sizeof(key_a));
    verthys_secure_zero(key_b, sizeof(key_b));
    verthys_secure_zero(key_c, sizeof(key_c));
    destroy_all_handles(km);
    km->state = VERTHYS_CNG_KM_UNINITIALIZED;
    return r;
}

int verthys_cng_km_any_installed(const VerthysCngKeyManager *km)
{
    if (km == NULL) return 0;
    for (int r = 0; r < (int)VERTHYS_CNG_KEY_COUNT; r++) {
        if (verthys_cng_aead_is_imported(&km->keys[r])) return 1;
    }
    return 0;
}

int verthys_cng_km_handle_count(const VerthysCngKeyManager *km)
{
    return (km == NULL) ? 0 : km->handle_count;
}

int verthys_cng_km_global_handle_total(void)
{
    return (int)s_kernel_handle_total;
}

VerthysCngKmState verthys_cng_km_state(const VerthysCngKeyManager *km)
{
    return (km == NULL) ? VERTHYS_CNG_KM_DESTROYED : km->state;
}

void verthys_cng_km_destroy_all(VerthysCngKeyManager *km)
{
    if (km == NULL) return;

    destroy_all_handles(km);
    km->state = VERTHYS_CNG_KM_DESTROYED;
}
