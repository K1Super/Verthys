/*
 * state_crypto.h — 服务端密码学原语（SHA-256 / HMAC / ECDSA P-256 / CSPRNG）
 *
 * 约束：
 *   - 只使用 CNG（BCrypt）标准实现，不自创算法。
 *   - 私钥只以 BCRYPT_ECCPRIVATE_BLOB 形式在内存与 SYSTEM 可读文件中流转。
 *   - 所有密钥材料在使用后立即安全清零，不写日志、不进入错误文本。
 */
#ifndef VTY_STATE_CRYPTO_H
#define VTY_STATE_CRYPTO_H

#include <windows.h>
#include <bcrypt.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_HASH_BYTES 32u
#define VTY_ECC_SIGNATURE_BYTES 64u
#define VTY_ECC_BLOB_MAX 256u

/* 计算 SHA-256。返回 0 成功，非 0 失败。 */
int vty_sha256(const uint8_t *data, size_t len, uint8_t out[VTY_HASH_BYTES]);

/* 计算 HMAC-SHA256。key 必须为 32 字节。返回 0 成功。 */
int vty_hmac_sha256(const uint8_t key[32], const uint8_t *data, size_t len,
                    uint8_t out[VTY_HASH_BYTES]);

/* 生成密码学随机字节。返回 0 成功。 */
int vty_random_bytes(uint8_t *out, size_t len);

/*
 * 生成 ECDSA P-256 密钥对并导出 blob。
 * priv_cap/pub_cap 为调用方缓冲区容量；成功时回填实际长度。
 * 失败时清零并返回非 0。
 */
int vty_ecc_generate_keypair(uint8_t *priv_blob, DWORD *priv_len, DWORD priv_cap,
                             uint8_t *pub_blob, DWORD *pub_len, DWORD pub_cap);

/* 从私钥 blob 导入 CNG 句柄。成功后调用方负责 vty_ecc_free_key。 */
int vty_ecc_load_private(const uint8_t *priv_blob, DWORD priv_len,
                         BCRYPT_KEY_HANDLE *key_out);

/* 从私钥 blob 导出公钥 blob。 */
int vty_ecc_public_from_private(const uint8_t *priv_blob, DWORD priv_len,
                                uint8_t *pub_blob, DWORD *pub_len, DWORD pub_cap);

/* 对 32 字节哈希做 ECDSA P-256 签名，输出 raw r||s（64 字节）。 */
int vty_ecc_sign(BCRYPT_KEY_HANDLE key, const uint8_t hash[VTY_HASH_BYTES],
                 uint8_t signature[VTY_ECC_SIGNATURE_BYTES]);

/* 用公钥 blob 验签。成功返回 0，失败返回非 0。 */
int vty_ecc_verify(const uint8_t *pub_blob, DWORD pub_len,
                   const uint8_t hash[VTY_HASH_BYTES],
                   const uint8_t signature[VTY_ECC_SIGNATURE_BYTES]);

/* 导入公钥 blob，用于批量验签场景。 */
int vty_ecc_load_public(const uint8_t *pub_blob, DWORD pub_len,
                        BCRYPT_KEY_HANDLE *key_out);

/* 用已导入公钥句柄验签。 */
int vty_ecc_verify_with_key(BCRYPT_KEY_HANDLE key,
                            const uint8_t hash[VTY_HASH_BYTES],
                            const uint8_t signature[VTY_ECC_SIGNATURE_BYTES]);

void vty_ecc_free_key(BCRYPT_KEY_HANDLE *key);

/* 常量时间比较；用于 HMAC 等秘密相关比较。 */
int vty_const_time_equal(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VTY_STATE_CRYPTO_H */
