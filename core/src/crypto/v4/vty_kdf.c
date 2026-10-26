/*
 * vty_kdf.c — v4 密码学原语封装实现
 */
#include "vty_kdf.h"
#include "vty_util.h"
#include "verthys_crypto.h"

#include <sodium.h>
#include <string.h>

/* 32B 盐 → libsodium 需要 16B 盐：用域分离摘要取前 16 字节。
 * 这样保留了 32B 存储熵，同时不改变标准算法实现。 */
static const char SALT_DERIVE_LABEL[] = "verthys/v4/kdf-salt";

int vty_kdf_params_valid(uint32_t mem_kib, uint32_t iters, uint32_t parallel)
{
    if (mem_kib < VTY_ARGON2_MEM_KIB_MIN) return VTY_E_KDF_WEAK;
    if (mem_kib > VTY_ARGON2_MEM_KIB_MAX) return VTY_E_KDF_WEAK;
    if (iters < VTY_ARGON2_ITERS_MIN) return VTY_E_KDF_WEAK;
    if (parallel < VTY_ARGON2_PARALLEL_MIN || parallel > VTY_ARGON2_PARALLEL_MAX) {
        return VTY_E_KDF_WEAK;
    }
    return VTY_OK;
}

static void derive_salt16(const uint8_t salt32[VTY_SALT_BYTES], uint8_t out16[16])
{
    uint8_t buf[sizeof(SALT_DERIVE_LABEL) - 1 + VTY_SALT_BYTES];
    uint8_t digest[32];
    size_t label_len = sizeof(SALT_DERIVE_LABEL) - 1;

    memcpy(buf, SALT_DERIVE_LABEL, label_len);
    memcpy(buf + label_len, salt32, VTY_SALT_BYTES);
    (void)crypto_hash_sha256(digest, buf, (unsigned long long)sizeof(buf));
    memcpy(out16, digest, 16);
    vty_secure_zero(buf, sizeof(buf));
    vty_secure_zero(digest, sizeof(digest));
}

static int argon2id_call(uint8_t out[VTY_KEY_BYTES],
                         const uint8_t *pwd, size_t pwd_len,
                         const uint8_t salt16[16],
                         uint32_t mem_kib, uint32_t iters, uint32_t parallel)
{
    if (out == NULL || salt16 == NULL) return VTY_E_INVALID;
    if (pwd == NULL && pwd_len != 0) return VTY_E_INVALID;
    if (pwd_len > 0xFFFFFFFFu) return VTY_E_INVALID;
    if (mem_kib < 8u || mem_kib > VTY_ARGON2_MEM_KIB_MAX) return VTY_E_INVALID;
    if (iters < 1u) return VTY_E_INVALID;
    if (parallel < 1u || parallel > 64u) return VTY_E_INVALID;

    /* libsodium 的并行度固定为 1；parallel 仅用于参数合法性记录，
     * 实际内存代价由 mem_kib 与 iters 决定。 */
    if (crypto_pwhash_argon2id(out, VTY_KEY_BYTES,
                               (const char *)(pwd != NULL ? pwd : (const uint8_t *)""),
                               (unsigned long long)pwd_len,
                               salt16,
                               (unsigned long long)iters,
                               (size_t)mem_kib * 1024u,
                               crypto_pwhash_argon2id_ALG_ARGON2ID13) != 0) {
        return VTY_E_RESOURCE;
    }
    return VTY_OK;
}

int vty_kdf_argon2id(uint8_t out[VTY_KEY_BYTES],
                     const uint8_t *pwd, size_t pwd_len,
                     const uint8_t salt[VTY_SALT_BYTES],
                     uint32_t mem_kib, uint32_t iters, uint32_t parallel)
{
    uint8_t salt16[16];
    int rc;

    if (salt == NULL) return VTY_E_INVALID;
    rc = vty_kdf_params_valid(mem_kib, iters, parallel);
    if (rc != VTY_OK) return rc;

    derive_salt16(salt, salt16);
    rc = argon2id_call(out, pwd, pwd_len, salt16, mem_kib, iters, parallel);
    vty_secure_zero(salt16, sizeof(salt16));
    return rc;
}

int vty_kdf_argon2id_raw16(uint8_t out[VTY_KEY_BYTES],
                           const uint8_t *pwd, size_t pwd_len,
                           const uint8_t salt16[16],
                           uint32_t mem_kib, uint32_t iters, uint32_t parallel)
{
    return argon2id_call(out, pwd, pwd_len, salt16, mem_kib, iters, parallel);
}

int vty_hkdf_expand(uint8_t out[VTY_KEY_BYTES],
                    const uint8_t prk[VTY_KEY_BYTES],
                    const uint8_t *info, size_t info_len)
{
    if (out == NULL || prk == NULL) return VTY_E_INVALID;
    if (info == NULL && info_len != 0) return VTY_E_INVALID;
    if (crypto_kdf_hkdf_sha256_expand(out, VTY_KEY_BYTES,
                                      (const char *)info, info_len,
                                      prk) != 0) {
        return VTY_E_INVALID;
    }
    return VTY_OK;
}

int vty_hmac_sha256(uint8_t out[VTY_HASH_BYTES],
                    const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len)
{
    if (out == NULL || key == NULL) return VTY_E_INVALID;
    if (key_len != crypto_auth_hmacsha256_KEYBYTES) return VTY_E_INVALID;
    if (data == NULL && data_len != 0) return VTY_E_INVALID;
    if (crypto_auth_hmacsha256(out, data, (unsigned long long)data_len, key) != 0) {
        return VTY_E_INVALID;
    }
    return VTY_OK;
}

int vty_sha256(uint8_t out[VTY_HASH_BYTES], const uint8_t *data, size_t len)
{
    if (out == NULL) return VTY_E_INVALID;
    if (data == NULL && len != 0) return VTY_E_INVALID;
    if (crypto_hash_sha256(out, data, (unsigned long long)len) != 0) {
        return VTY_E_INVALID;
    }
    return VTY_OK;
}

int vty_aead_seal(const uint8_t key[VTY_KEY_BYTES],
                  const uint8_t nonce[VTY_NONCE_BYTES],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *pt, size_t pt_len,
                  uint8_t *ct, size_t ct_cap, size_t *ct_len)
{
    size_t out_len = 0;

    if (key == NULL || nonce == NULL || ct == NULL || ct_len == NULL) {
        return VTY_E_INVALID;
    }
    if (pt == NULL && pt_len != 0) return VTY_E_INVALID;
    if (pt_len > SIZE_MAX - VTY_TAG_BYTES) return VTY_E_INVALID;
    if (ct_cap < pt_len + VTY_TAG_BYTES) return VTY_E_INVALID;

    if (verthys_aead_encrypt(key, nonce, aad, aad_len, pt, pt_len, ct, &out_len) != 0) {
        return VTY_E_AEAD;
    }
    if (out_len != pt_len + VTY_TAG_BYTES) {
        vty_secure_zero(ct, out_len);
        return VTY_E_AEAD;
    }
    *ct_len = out_len;
    return VTY_OK;
}

int vty_aead_open(const uint8_t key[VTY_KEY_BYTES],
                  const uint8_t nonce[VTY_NONCE_BYTES],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *ct, size_t ct_len,
                  uint8_t *pt, size_t pt_cap, size_t *pt_len)
{
    size_t out_len = 0;

    if (key == NULL || nonce == NULL || pt == NULL || pt_len == NULL) {
        return VTY_E_INVALID;
    }
    if (ct == NULL && ct_len != 0) return VTY_E_INVALID;
    if (ct_len < VTY_TAG_BYTES) return VTY_E_AEAD;
    if (pt_cap < ct_len - VTY_TAG_BYTES) return VTY_E_INVALID;

    if (verthys_aead_decrypt(key, nonce, aad, aad_len, ct, ct_len, pt, &out_len) != 0) {
        /* 认证失败：不区分标签错、密钥错、AAD 错 */
        return VTY_E_KEY_INVALID;
    }
    *pt_len = out_len;
    return VTY_OK;
}

int vty_wrap_key32(const uint8_t kek[VTY_KEY_BYTES],
                   const uint8_t key[VTY_KEY_BYTES],
                   const uint8_t *aad, size_t aad_len,
                   uint8_t nonce_out[VTY_NONCE_BYTES],
                   uint8_t ct_out[VTY_KEY_BYTES + VTY_TAG_BYTES])
{
    size_t ct_len = 0;

    if (kek == NULL || key == NULL || nonce_out == NULL || ct_out == NULL) {
        return VTY_E_INVALID;
    }
    vty_random(nonce_out, VTY_NONCE_BYTES);
    if (vty_aead_seal(kek, nonce_out, aad, aad_len,
                      key, VTY_KEY_BYTES,
                      ct_out, VTY_KEY_BYTES + VTY_TAG_BYTES, &ct_len) != VTY_OK) {
        vty_secure_zero(ct_out, VTY_KEY_BYTES + VTY_TAG_BYTES);
        return VTY_E_AEAD;
    }
    return VTY_OK;
}

int vty_unwrap_key32(const uint8_t kek[VTY_KEY_BYTES],
                     const uint8_t nonce[VTY_NONCE_BYTES],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t ct_len,
                     uint8_t key_out[VTY_KEY_BYTES])
{
    size_t pt_len = 0;
    int rc;

    if (kek == NULL || nonce == NULL || key_out == NULL) return VTY_E_INVALID;
    if (ct_len != VTY_KEY_BYTES + VTY_TAG_BYTES) return VTY_E_KEY_INVALID;

    rc = vty_aead_open(kek, nonce, aad, aad_len, ct, ct_len,
                       key_out, VTY_KEY_BYTES, &pt_len);
    if (rc != VTY_OK) {
        vty_secure_zero(key_out, VTY_KEY_BYTES);
        return rc;
    }
    if (pt_len != VTY_KEY_BYTES) {
        vty_secure_zero(key_out, VTY_KEY_BYTES);
        return VTY_E_KEY_INVALID;
    }
    return VTY_OK;
}
