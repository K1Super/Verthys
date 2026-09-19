/*
 * verthys_crypto.c — 密码学原语实现（基于 libsodium）
 */
#include "verthys_crypto.h"
#include "verthys_internal.h"  /* verthys_secure_zero */
#include "verthys_api_utils.h" /* verthys_monotonic_ms（校准计时） */

#include <sodium.h>
#include <string.h>   /* memcpy（sodium.h 不保证传递性暴露） */

int verthys_crypto_init(void)
{
    /* sodium_init: 0=首次初始化成功, 1=已初始化, -1=失败；均视为可用 */
    return sodium_init() < 0 ? -1 : 0;
}

void verthys_random_bytes(uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) return;
    randombytes_buf(buf, len);
}

int verthys_aead_encrypt(const uint8_t *key,
                       const uint8_t *nonce,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext, size_t *ct_len)
{
    unsigned long long clen = 0;
    if (key == NULL || nonce == NULL || ciphertext == NULL || ct_len == NULL) {
        return -1;
    }
    if (plaintext == NULL && pt_len != 0) return -1;
    if (ad == NULL && ad_len != 0) return -1;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext, &clen,
            plaintext, (unsigned long long)pt_len,
            ad, (unsigned long long)ad_len,
            NULL, nonce, key) != 0) {
        return -1;
    }
    *ct_len = (size_t)clen;
    return 0;
}

int verthys_aead_decrypt(const uint8_t *key,
                       const uint8_t *nonce,
                       const uint8_t *ad, size_t ad_len,
                       const uint8_t *ciphertext, size_t ct_len,
                       uint8_t *plaintext, size_t *pt_len)
{
    unsigned long long mlen = 0;
    if (key == NULL || nonce == NULL || plaintext == NULL || pt_len == NULL) {
        return -1;
    }
    if (ciphertext == NULL && ct_len != 0) return -1;
    if (ad == NULL && ad_len != 0) return -1;
    /* 密文至少含 MAC */
    if (ct_len < VERTHYS_AEAD_MAC_BYTES) return -1;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext, &mlen,
            NULL,
            ciphertext, (unsigned long long)ct_len,
            ad, (unsigned long long)ad_len,
            nonce, key) != 0) {
        return -1;
    }
    *pt_len = (size_t)mlen;
    return 0;
}

/* ================================================================== *
 * 完全参数化的密钥派生接口
 *                                                                    *
 * 接收全部 Argon2id 参数，由调用方从超级块获取后传入，               *
 * 彻底解耦代码与固定强度。兼容旧接口（verthys_argon2id_derive /         *
 * verthys_argon2id_derive_raw）内部委托本函数。                         *
 *                                                                    *
 * 安全约束校验：                                                      *
 *   - mem_kib 须 ≥ 8（Argon2id 最小 8 KiB），≤ 4*1024*1024（4 GiB）  *
 *   - iters    须 ≥ 1                                                *
 *   - parallel  须 ≥ 1 且 ≤ 64                                       *
 *   - 越界参数返回 -1，不调用 libsodium（防止 DoS：超大内存分配）     *
 * ================================================================== */
int verthys_argon2id_derive_ex(uint8_t out[VERTHYS_KEY_BYTES],
                             const uint8_t *password, size_t pw_len,
                             const uint8_t salt[VERTHYS_SALT_BYTES],
                             const uint8_t pepper[VERTHYS_KEY_BYTES],
                             uint32_t mem_kib,
                             uint32_t iters,
                             uint32_t parallel)
{
    if (out == NULL || salt == NULL) return -1;
    if (password == NULL && pw_len != 0) return -1;

    /* ★ 参数合理性校验：防止恶意/损坏的超级块触发超大内存分配（DoS 防护） */
    if (mem_kib < 8u) return -1;                          /* Argon2id 最小 8 KiB */
    if (mem_kib > (4u * 1024u * 1024u)) return -1;        /* 上限 4 GiB */
    if (iters < 1u) return -1;                            /* 至少 1 次迭代 */
    if (parallel < 1u || parallel > 64u) return -1;       /* 并行度 1..64 */

    /* 拼接 password||pepper 作为 Argon2id 口令输入（pepper 直拼）
     * pepper == NULL 时不混入胡椒（用于导出/导入独立解密场景） */
    uint8_t *combined = NULL;
    size_t combined_len;
    const uint8_t *pwd_ptr;
    size_t pwd_len;

    if (pepper != NULL) {
        combined_len = pw_len + VERTHYS_KEY_BYTES;
        combined = (uint8_t *)malloc(combined_len);
        if (combined == NULL) return -1;
        if (pw_len != 0) {
            memcpy(combined, password, pw_len);
        }
        memcpy(combined + pw_len, pepper, VERTHYS_KEY_BYTES);
        pwd_ptr = combined;
        pwd_len = combined_len;
    } else {
        /* 无胡椒：直接用 password 作为口令输入 */
        pwd_ptr = password;
        pwd_len = pw_len;
    }

    /* libsodium crypto_pwhash_argon2id：
     *   opslimit  = 时间代价（迭代次数相关，这里直接用 iters）
     *   memlimit  = 内存字节数 = mem_kib * 1024
     *
     * 注意：libsodium 的 opslimit 与 Argon2id 的 t（iterations）参数对应，
     *       memlimit 与 m（memory）参数对应（单位字节）。
     *       Argon2id 规范要求 parallelism ≤ lanes，libsodium 固定 lanes=1，
     *       因此 parallel>1 时实际并行度仍受限，但参数透传保留语义正确性。 */
    int rc = crypto_pwhash_argon2id(
        out, VERTHYS_KEY_BYTES,
        (const char *)pwd_ptr, (unsigned long long)pwd_len,
        salt,
        (unsigned long long)iters,                /* opslimit = 迭代次数 */
        (size_t)mem_kib * 1024u,                  /* memlimit = 内存字节数 */
        crypto_pwhash_argon2id_ALG_ARGON2ID13);

    if (combined != NULL) {
        verthys_secure_zero(combined, combined_len);
        free(combined);
    }
    return rc != 0 ? -1 : 0;
}

int verthys_argon2id_derive(uint8_t out[VERTHYS_KEY_BYTES],
                          const uint8_t *password, size_t pw_len,
                          const uint8_t salt[VERTHYS_SALT_BYTES],
                          const uint8_t pepper[VERTHYS_KEY_BYTES])
{
    /* ★ 兼容封装：委托 verthys_argon2id_derive_ex 并传入默认硬编码参数
     *（VERTHYS_ARGON2_MEM_KIB / VERTHYS_ARGON2_ITERS / VERTHYS_ARGON2_PARALLEL）
     * 新代码应直接调用 verthys_argon2id_derive_ex，从超级块读取实际参数。 */
    return verthys_argon2id_derive_ex(out, password, pw_len, salt, pepper,
                                    VERTHYS_ARGON2_MEM_KIB,
                                    VERTHYS_ARGON2_ITERS,
                                    VERTHYS_ARGON2_PARALLEL);
}

int verthys_argon2id_derive_raw(uint8_t out[VERTHYS_KEY_BYTES],
                              const uint8_t *password, size_t pw_len,
                              const uint8_t salt[VERTHYS_SALT_BYTES])
{
    /* ★ 兼容封装：委托 verthys_argon2id_derive_ex，pepper=NULL（不混入胡椒） */
    return verthys_argon2id_derive_ex(out, password, pw_len, salt, NULL,
                                    VERTHYS_ARGON2_MEM_KIB,
                                    VERTHYS_ARGON2_ITERS,
                                    VERTHYS_ARGON2_PARALLEL);
}

/* ================================================================== *
 * 独立完整性密钥派生
 *                                                                    *
 * integrity_key = HKDF-SHA256(master_key, "verthys/integrity-key") *
 *                                                                    *
 * 与 DEK 完全隔离：即使 DEK 泄露，历史文件的 HMAC 完整性验证          *
 * 仍然有效（integrity_key 由 master_key 派生，独立于数据加密密钥）。   *
 *                                                                    *
 * 用途：                                                              *
 *   - 超级块偏移量 MAC（offset_mac）                                  *
 *   - 状态链防回滚哈希（state_chain）                                 *
 *   - 累积写入 HMAC（write_hmac）                                     *
 *   - 尾部日志哈希指针（tail_log_head_hash）                          *
 * ================================================================== */
int verthys_derive_integrity_key(uint8_t out[VERTHYS_KEY_BYTES],
                               const uint8_t master_key[VERTHYS_KEY_BYTES])
{
    static const char info[] = VERTHYS_INTEGRITY_KEY_INFO;
    return verthys_hkdf_expand(out, master_key,
                             (const uint8_t *)info, sizeof(info) - 1);
}

int verthys_hkdf_expand(uint8_t out[VERTHYS_KEY_BYTES],
                      const uint8_t prk[VERTHYS_KEY_BYTES],
                      const uint8_t *info, size_t info_len)
{
    if (out == NULL || prk == NULL) return -1;
    if (info == NULL && info_len != 0) return -1;
    /* libsodium 1.0.20 签名：expand(out, out_len, ctx, ctx_len, prk)
     * PRK 长度隐式为 crypto_kdf_hkdf_sha256_KEYBYTES(32)；
     * ctx 为域分离标签（本项目用 "verthys/..." 前缀，非空可打印 ASCII）。 */
    if (crypto_kdf_hkdf_sha256_expand(
            out, VERTHYS_KEY_BYTES,
            (const char *)info, info_len,
            prk) != 0) {
        return -1;
    }
    return 0;
}

int verthys_hmac_sha256(uint8_t out[VERTHYS_HMAC_BYTES],
                      const uint8_t key[VERTHYS_KEY_BYTES],
                      const uint8_t *data, size_t data_len)
{
    if (out == NULL || key == NULL) return -1;
    if (data == NULL && data_len != 0) return -1;
    if (crypto_auth_hmacsha256(out, data, (unsigned long long)data_len, key) != 0) {
        return -1;
    }
    return 0;
}

/* ================================================================== *
 * BLAKE2b-256 通用哈希封装
 *                                                                    *
 * 内容寻址（Extent）哈希专用：libsodium crypto_generichash 即         *
 * BLAKE2b-256（32B digest，无密钥模式）。                             *
 * 输出经 Verthys 内部敏感数据处理纪律约束：哈希非密钥材料，无需清零。    *
 * ================================================================== */
int verthys_generichash(uint8_t out[VERTHYS_GENERICHASH_BYTES],
                      const uint8_t *data, size_t data_len)
{
    if (out == NULL) return -1;
    if (data == NULL && data_len != 0) return -1;
    if (crypto_generichash(out, VERTHYS_GENERICHASH_BYTES,
                           data, (unsigned long long)data_len,
                           NULL, 0) != 0) {
        return -1;
    }
    return 0;
}


/* ================================================================== *
 * Argon2id 动态校准实现
 * ================================================================== *
 * 两段式探测（总开销 = 2 次派生）：
 *   1. 初始测量：以 min_iters 派生一次，得 t_probe；
 *   2. 线性换算：iters_scaled = min_iters * target / t_probe，钳制到
 *      [min_iters, max_iters]；
 *   3. 确认测量：以换算结果派生一次，若换算误差 ≥ 1 迭代则二次修正
 *      （仅修正，不再测量——误差来源主要是固定开销项，一次修正足够）。
 * 全程不落任何密钥材料（派生输出即算即弃）。
 */
int verthys_argon2_calibrate(const uint8_t *password, size_t pw_len,
                           const uint8_t salt[VERTHYS_SALT_BYTES],
                           const uint8_t pepper[VERTHYS_KEY_BYTES],
                           uint32_t mem_kib,
                           uint32_t target_ms,
                           uint32_t min_iters, uint32_t max_iters,
                           uint32_t *out_iters)
{
    if (out_iters == NULL || salt == NULL) return -1;
    if (password == NULL && pw_len != 0) return -1;
    if (min_iters < 1u || max_iters < min_iters) return -1;
    if (target_ms == 0) return -1;
    if (mem_kib < 8u || mem_kib > 4u * 1024u * 1024u) return -1;

    uint8_t scratch[VERTHYS_KEY_BYTES];

    /* 1. 初始测量 */
    uint64_t t0 = verthys_monotonic_ms();
    if (verthys_argon2id_derive_ex(scratch, password, pw_len, salt, pepper,
                                 mem_kib, min_iters, 1u) != 0) {
        verthys_secure_zero(scratch, sizeof scratch);
        return -1;
    }
    uint64_t t_probe = verthys_monotonic_ms() - t0;
    verthys_secure_zero(scratch, sizeof scratch);
    if (t_probe == 0) t_probe = 1;  /* 防除零（时钟粒度粗于单次派生时） */

    /* 2. 线性换算 + 钳制 */
    uint64_t scaled = ((uint64_t)min_iters * (uint64_t)target_ms + t_probe - 1) / t_probe;
    if (scaled < min_iters) scaled = min_iters;
    if (scaled > max_iters) scaled = max_iters;

    /* 3. 确认测量（换算结果的派生同时充当创建基准的一次采样） */
    t0 = verthys_monotonic_ms();
    if (verthys_argon2id_derive_ex(scratch, password, pw_len, salt, pepper,
                                 mem_kib, (uint32_t)scaled, 1u) != 0) {
        verthys_secure_zero(scratch, sizeof scratch);
        return -1;
    }
    uint64_t t_confirm = verthys_monotonic_ms() - t0;
    verthys_secure_zero(scratch, sizeof scratch);
    if (t_confirm == 0) t_confirm = 1;

    /* 二次修正：确认耗时偏离目标时按同一比例修正一次（不再测量） */
    uint64_t refined = ((uint64_t)scaled * (uint64_t)target_ms + t_confirm - 1) / t_confirm;
    if (refined < min_iters) refined = min_iters;
    if (refined > max_iters) refined = max_iters;

    *out_iters = (uint32_t)refined;
    return 0;
}
