/*
 * keymanager.c — 四级密钥体系实现
 *
 * 实现要点：
 *   - 胡椒托管：通过 verthys_pepper 模块统一管理生命周期（统一接
 *     口封装，避免密钥材料散落多处），支持 OS 密钥存储托管 + Shamir
 *     恢复卡 + 编译内嵌兜底。
 *   - L2 派生密钥材料：Argon2id(password || pepper, salt) → 32B（瞬时变量，
 *     用后 verthys_secure_zero 擦除）
 *   - L3 MEK：HKDF-Expand(L2, "verthys/master-key-v1") → 32B
 *   - L4 DEK：随机 32B；wrap = XChaCha20-Poly1305(MEK, random nonce, AD=label)
 *   - 记录级：HKDF-Expand(DEK, "verthys/record-v1" || record_id) → 32B
 *
 * 域分离：所有 HKDF info 与 AEAD AD 均带版本后缀 -v1，便于未来算法迁移。
 */
#include "keymanager.h"
#include "verthys_internal.h"  /* verthys_secure_zero */
#include "verthys_pepper.h"    /* 胡椒托管框架 */

#include <stdlib.h>
#include <string.h>

/* ---------- 域分离标签（HKDF info / AEAD AD） ---------- */
static const char INFO_MASTER_KEY[] = "verthys/master-key-v1";
static const char INFO_RECORD_KEY[] = "verthys/record-v1";
static const char AD_DEK_WRAP[]     = "verthys/dek-wrap-v1";

int keymanager_derive_master(uint8_t master_key[VERTHYS_KEY_BYTES],
                             const uint8_t *password, size_t pw_len,
                             const uint8_t salt[VERTHYS_SALT_BYTES])
{
    if (master_key == NULL || salt == NULL) return -1;
    if (password == NULL && pw_len != 0) return -1;

    /* ★ 胡椒托管框架：从 verthys_pepper 模块获取当前生效的胡椒
     *（优先级：注入 > OS 托管(CNG/TPM) > 编译内嵌兜底）
     * 胡椒模块在 Verthys_Init 时初始化，此处保证已就绪。 */
    /* 返回码约定：0 成功 / -1 通用失败 / -2 pepper 来源错误，
     * 上层据此映射 VERTHYS_ERR_PEPPER_SOURCE（区别于密码错误）。 */
    if (verthys_pepper_init() != 0) {
        if (verthys_pepper_source_error()) return -2;
        return -1;
    }
    const uint8_t *pepper = verthys_pepper_get();
    if (pepper == NULL) return -1;

    /* L2：Argon2id(password || pepper, salt) → 派生密钥材料（瞬时） */
    uint8_t dkm[VERTHYS_KEY_BYTES];
    if (verthys_argon2id_derive(dkm, password, pw_len, salt, pepper) != 0) {
        return -1;
    }

    /* L3：HKDF-Expand(DKM, "verthys/master-key-v1") → MEK */
    int rc = verthys_hkdf_expand(master_key, dkm,
                               (const uint8_t *)INFO_MASTER_KEY,
                               sizeof(INFO_MASTER_KEY) - 1);

    verthys_secure_zero(dkm, sizeof dkm);
    return rc;
}

/* ★ 企业级优化：完全参数化的主密钥派生
 *
 * 与 keymanager_derive_master 相同，但 Argon2id 参数由调用方传入，
 * 支持从超级块读取实际参数（BALANCED 32MiB/2/1 / SECURE 64MiB/3/1）。
 *
 * 安全下限兜底：防止损坏的超级块触发 DoS（参数过小或过大）。
 *   - mem_kib: 8 KiB ≤ mem_kib ≤ 4 GiB（Argon2id 规范范围）
 *   - iters:   iters ≥ 1
 *   - parallel: 1 ≤ parallel ≤ 64
 * 越界参数返回 -1，不调用 libsodium。
 */
int keymanager_derive_master_ex(uint8_t master_key[VERTHYS_KEY_BYTES],
                                const uint8_t *password, size_t pw_len,
                                const uint8_t salt[VERTHYS_SALT_BYTES],
                                uint32_t mem_kib,
                                uint32_t iters,
                                uint32_t parallel)
{
    if (master_key == NULL || salt == NULL) return -1;
    if (password == NULL && pw_len != 0) return -1;

    /* 安全下限校验（OWASP 2023 推荐 + Argon2id 规范范围） */
    if (mem_kib < 8u || mem_kib > 4u * 1024u * 1024u) return -1;
    if (iters < 1u) return -1;
    if (parallel < 1u || parallel > 64u) return -1;

    /* ★ 胡椒托管框架：与 keymanager_derive_master 共用 */
    /* 返回码约定：0 成功 / -1 通用失败 / -2 pepper 来源错误，
     * 上层据此映射 VERTHYS_ERR_PEPPER_SOURCE（区别于密码错误）。 */
    if (verthys_pepper_init() != 0) {
        if (verthys_pepper_source_error()) return -2;
        return -1;
    }
    const uint8_t *pepper = verthys_pepper_get();
    if (pepper == NULL) return -1;

    /* L2：Argon2id(password || pepper, salt, mem_kib, iters, parallel) → 派生密钥材料 */
    uint8_t dkm[VERTHYS_KEY_BYTES];
    if (verthys_argon2id_derive_ex(dkm, password, pw_len, salt, pepper,
                                  mem_kib, iters, parallel) != 0) {
        return -1;
    }

    /* L3：HKDF-Expand(DKM, "verthys/master-key-v1") → MEK */
    int rc = verthys_hkdf_expand(master_key, dkm,
                               (const uint8_t *)INFO_MASTER_KEY,
                               sizeof(INFO_MASTER_KEY) - 1);

    verthys_secure_zero(dkm, sizeof dkm);
    return rc;
}

int keymanager_derive_master_export(uint8_t master_key[VERTHYS_KEY_BYTES],
                                    const uint8_t *password, size_t pw_len,
                                    const uint8_t salt[VERTHYS_SALT_BYTES])
{
    if (master_key == NULL || salt == NULL) return -1;
    if (password == NULL && pw_len != 0) return -1;

    /* L2：Argon2id(password, salt) → 派生密钥材料（无胡椒） */
    uint8_t dkm[VERTHYS_KEY_BYTES];
    if (verthys_argon2id_derive_raw(dkm, password, pw_len, salt) != 0) {
        return -1;
    }

    /* L3：HKDF-Expand(DKM, "verthys/master-key-v1") → MEK */
    int rc = verthys_hkdf_expand(master_key, dkm,
                               (const uint8_t *)INFO_MASTER_KEY,
                               sizeof(INFO_MASTER_KEY) - 1);

    verthys_secure_zero(dkm, sizeof dkm);
    return rc;
}

void keymanager_generate_dek(uint8_t dek[VERTHYS_KEY_BYTES])
{
    if (dek == NULL) return;
    verthys_random_bytes(dek, VERTHYS_KEY_BYTES);
}

int keymanager_wrap_dek(uint8_t wrapped[VERTHYS_DEK_WRAPPED_BYTES],
                        uint8_t nonce_out[VERTHYS_AEAD_NONCE_BYTES],
                        const uint8_t dek[VERTHYS_KEY_BYTES],
                        const uint8_t master_key[VERTHYS_KEY_BYTES])
{
    if (wrapped == NULL || nonce_out == NULL || dek == NULL || master_key == NULL) {
        return -1;
    }

    /* 随机 nonce（XChaCha20 24B nonce 重复概率可忽略） */
    verthys_random_bytes(nonce_out, VERTHYS_AEAD_NONCE_BYTES);

    /* AEAD 加密：AD = "verthys/dek-wrap-v1"（域分离，防与其他 AEAD 块互换） */
    size_t ct_len = 0;
    if (verthys_aead_encrypt(master_key, nonce_out,
                           (const uint8_t *)AD_DEK_WRAP, sizeof(AD_DEK_WRAP) - 1,
                           dek, VERTHYS_KEY_BYTES,
                           wrapped, &ct_len) != 0) {
        return -1;
    }
    if (ct_len != VERTHYS_DEK_WRAPPED_BYTES) {
        verthys_secure_zero(wrapped, ct_len);
        verthys_secure_zero(nonce_out, VERTHYS_AEAD_NONCE_BYTES);
        return -1;
    }
    return 0;
}

int keymanager_unwrap_dek(uint8_t dek_out[VERTHYS_KEY_BYTES],
                          const uint8_t wrapped[VERTHYS_DEK_WRAPPED_BYTES],
                          const uint8_t nonce[VERTHYS_AEAD_NONCE_BYTES],
                          const uint8_t master_key[VERTHYS_KEY_BYTES])
{
    if (dek_out == NULL || wrapped == NULL || nonce == NULL || master_key == NULL) {
        return -1;
    }

    size_t pt_len = 0;
    if (verthys_aead_decrypt(master_key, nonce,
                           (const uint8_t *)AD_DEK_WRAP, sizeof(AD_DEK_WRAP) - 1,
                           wrapped, VERTHYS_DEK_WRAPPED_BYTES,
                           dek_out, &pt_len) != 0) {
        return -1;  /* 认证失败 = 主密码错误 或 wrapped 被篡改 */
    }
    if (pt_len != VERTHYS_KEY_BYTES) {
        verthys_secure_zero(dek_out, pt_len);
        return -1;
    }
    return 0;
}

int keymanager_derive_record_key(uint8_t record_key[VERTHYS_KEY_BYTES],
                                 const uint8_t dek[VERTHYS_KEY_BYTES],
                                 const uint8_t *record_id, size_t id_len)
{
    if (record_key == NULL || dek == NULL) return -1;
    if (record_id == NULL && id_len != 0) return -1;

    /* info = "verthys/record-v1" || record_id（前缀域分离 + 记录 ID） */
    const size_t prefix_len = sizeof(INFO_RECORD_KEY) - 1;
    const size_t info_len = prefix_len + id_len;
    uint8_t *info = (uint8_t *)malloc(info_len);
    if (info == NULL) return -1;

    memcpy(info, INFO_RECORD_KEY, prefix_len);
    if (id_len != 0) {
        memcpy(info + prefix_len, record_id, id_len);
    }

    int rc = verthys_hkdf_expand(record_key, dek, info, info_len);
    verthys_secure_zero(info, info_len);
    free(info);
    return rc;
}

/* ===================================================================== *
 *                     三密钥分立实现                                     *
 * ===================================================================== */

/* 三密钥域分离标签 */
static const char INFO_KEY_A[] = "verthys/key-a-index-v2";
static const char INFO_KEY_B[] = "verthys/key-b-data-v2";
static const char INFO_KEY_C[] = "verthys/key-c-superblock-v2";

int keymanager_derive_key_a(uint8_t key_a[VERTHYS_KEY_BYTES],
                            const uint8_t master_key[VERTHYS_KEY_BYTES])
{
    if (key_a == NULL || master_key == NULL) return -1;
    return verthys_hkdf_expand(key_a, master_key,
                             (const uint8_t *)INFO_KEY_A,
                             sizeof(INFO_KEY_A) - 1);
}

int keymanager_derive_key_b(uint8_t key_b[VERTHYS_KEY_BYTES],
                            const uint8_t master_key[VERTHYS_KEY_BYTES])
{
    if (key_b == NULL || master_key == NULL) return -1;
    return verthys_hkdf_expand(key_b, master_key,
                             (const uint8_t *)INFO_KEY_B,
                             sizeof(INFO_KEY_B) - 1);
}

int keymanager_derive_key_c(uint8_t key_c[VERTHYS_KEY_BYTES],
                            const uint8_t master_key[VERTHYS_KEY_BYTES])
{
    if (key_c == NULL || master_key == NULL) return -1;
    return verthys_hkdf_expand(key_c, master_key,
                             (const uint8_t *)INFO_KEY_C,
                             sizeof(INFO_KEY_C) - 1);
}

int keymanager_derive_three_keys(uint8_t key_a[VERTHYS_KEY_BYTES],
                                 uint8_t key_b[VERTHYS_KEY_BYTES],
                                 uint8_t key_c[VERTHYS_KEY_BYTES],
                                 const uint8_t master_key[VERTHYS_KEY_BYTES])
{
    if (key_a == NULL || key_b == NULL || key_c == NULL || master_key == NULL) return -1;
    if (keymanager_derive_key_a(key_a, master_key) != 0) return -1;
    if (keymanager_derive_key_b(key_b, master_key) != 0) {
        verthys_secure_zero(key_a, VERTHYS_KEY_BYTES);
        return -1;
    }
    if (keymanager_derive_key_c(key_c, master_key) != 0) {
        verthys_secure_zero(key_a, VERTHYS_KEY_BYTES);
        verthys_secure_zero(key_b, VERTHYS_KEY_BYTES);
        return -1;
    }
    return 0;
}

void keymanager_generate_mount_salt(uint8_t mount_salt[VERTHYS_KEY_BYTES])
{
    if (mount_salt == NULL) return;
    verthys_random_bytes(mount_salt, VERTHYS_KEY_BYTES);
}

/* ===================================================================== *
 * V3 域分离派生实现（解锁流水线 S2）                                     *
 * ===================================================================== */

/* V3 域分离标签（与 V1/V2 严格隔离） */
static const char INFO_MASTER_KEY_V3[]     = "verthys/master-key-v3";
static const char INFO_INTEGRITY_KEY_V3[]  = "verthys/integrity-key-v3";

int keymanager_derive_master_v3(uint8_t master_key[VERTHYS_KEY_BYTES],
                                const uint8_t *password, size_t pw_len,
                                const uint8_t salt[VERTHYS_SALT_BYTES],
                                uint32_t mem_kib,
                                uint32_t iters,
                                uint32_t parallel)
{
    if (master_key == NULL || salt == NULL) return -1;
    if (password == NULL && pw_len != 0) return -1;

    /* Argon2id 参数范围校验（与 derive_master_ex 同口径，防损坏超块 DoS） */
    if (mem_kib < 8u || mem_kib > 4u * 1024u * 1024u) return -1;
    if (iters < 1u) return -1;
    if (parallel < 1u || parallel > 64u) return -1;

    /* 胡椒托管框架（S0 pepper 快速失败由调用方前置；此处兜底） */
    if (verthys_pepper_init() != 0) {
        if (verthys_pepper_source_error()) return -2;
        return -1;
    }
    const uint8_t *pepper = verthys_pepper_get();
    if (pepper == NULL) return -1;

    /* L2：Argon2id(password ‖ pepper, salt, 超级块参数) → DKM（瞬时） */
    uint8_t dkm[VERTHYS_KEY_BYTES];
    if (verthys_argon2id_derive_ex(dkm, password, pw_len, salt, pepper,
                                  mem_kib, iters, parallel) != 0) {
        return -1;
    }

    /* L3：HKDF-Expand(DKM, "verthys/master-key-v3") → MEK */
    int rc = verthys_hkdf_expand(master_key, dkm,
                               (const uint8_t *)INFO_MASTER_KEY_V3,
                               sizeof(INFO_MASTER_KEY_V3) - 1);

    verthys_secure_zero(dkm, sizeof dkm);
    return rc;
}

int keymanager_derive_integrity_key_v3(uint8_t out[VERTHYS_KEY_BYTES],
                                       const uint8_t master_key[VERTHYS_KEY_BYTES])
{
    if (out == NULL || master_key == NULL) return -1;
    return verthys_hkdf_expand(out, master_key,
                             (const uint8_t *)INFO_INTEGRITY_KEY_V3,
                             sizeof(INFO_INTEGRITY_KEY_V3) - 1);
}
