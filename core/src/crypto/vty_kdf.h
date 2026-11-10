/*
 * vty_kdf.h — 密码学原语封装（内部，不导出）
 *
 * 统一约束：密钥材料只在栈上短暂出现，返回前清零；参数下限在
 * 本层强制，避免上层遗漏导致弱参数被接受。
 */
#ifndef VTY_KDF_H
#define VTY_KDF_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 参数区间校验：在 VTY_ARGON2_* 允许区间内返回 VTY_OK，否则 VTY_E_KDF_WEAK */
int vty_kdf_params_valid(uint32_t mem_kib, uint32_t iters, uint32_t parallel);

/* 槽位 KDF：32B 盐，输出 32B；参数低于下限拒绝（VTY_E_KDF_WEAK） */
int vty_kdf_argon2id(uint8_t out[VTY_KEY_BYTES],
                     const uint8_t *pwd, size_t pwd_len,
                     const uint8_t salt[VTY_SALT_BYTES],
                     uint32_t mem_kib, uint32_t iters, uint32_t parallel);

/* HKDF-SHA256-Expand：prk 32B，info 为域分离标签（可拼接定位字段） */
int vty_hkdf_expand(uint8_t out[VTY_KEY_BYTES],
                    const uint8_t prk[VTY_KEY_BYTES],
                    const uint8_t *info, size_t info_len);

/* HMAC-SHA256；key 为任意长度（由调用方保证为派生密钥） */
int vty_hmac_sha256(uint8_t out[VTY_HASH_BYTES],
                    const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len);

/* SHA-256（恢复码校验位等非密钥摘要） */
int vty_sha256(uint8_t out[VTY_HASH_BYTES], const uint8_t *data, size_t len);

/* XChaCha20-Poly1305：输出 [密文 || 16B tag] */
int vty_aead_seal(const uint8_t key[VTY_KEY_BYTES],
                  const uint8_t nonce[VTY_NONCE_BYTES],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *pt, size_t pt_len,
                  uint8_t *ct, size_t ct_cap, size_t *ct_len);

int vty_aead_open(const uint8_t key[VTY_KEY_BYTES],
                  const uint8_t nonce[VTY_NONCE_BYTES],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *ct, size_t ct_len,
                  uint8_t *pt, size_t pt_cap, size_t *pt_len);

/* 用 32B KEK 包裹 32B 密钥：nonce 由本函数生成，密文长度固定 48 */
int vty_wrap_key32(const uint8_t kek[VTY_KEY_BYTES],
                   const uint8_t key[VTY_KEY_BYTES],
                   const uint8_t *aad, size_t aad_len,
                   uint8_t nonce_out[VTY_NONCE_BYTES],
                   uint8_t ct_out[VTY_KEY_BYTES + VTY_TAG_BYTES]);

int vty_unwrap_key32(const uint8_t kek[VTY_KEY_BYTES],
                     const uint8_t nonce[VTY_NONCE_BYTES],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t ct_len,
                     uint8_t key_out[VTY_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* VTY_KDF_H */
