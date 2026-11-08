/*
 * state_crypto.c — CNG 实现（SHA-256 / HMAC-SHA256 / ECDSA P-256 / CSPRNG）
 *
 * 所有失败路径都清零中间缓冲区；任何密钥材料都不进入返回值或日志。
 */
#include "state_crypto.h"

#include <string.h>

#pragma comment(lib, "bcrypt.lib")

static void vty_wipe(void *p, size_t n)
{
    if (p != NULL && n > 0) {
        SecureZeroMemory(p, n);
    }
}

int vty_sha256(const uint8_t *data, size_t len, uint8_t out[VTY_HASH_BYTES])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status;
    int rc = -1;

    if (out == NULL || (data == NULL && len != 0) ||
        len > 0xFFFFFFFFu) {
        return -1;
    }
    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    if (len != 0) {
        status = BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0);
        if (!BCRYPT_SUCCESS(status)) goto done;
    }
    status = BCryptFinishHash(hash, out, VTY_HASH_BYTES, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    rc = 0;

done:
    if (hash != NULL) {
        BCryptDestroyHash(hash);
    }
    if (alg != NULL) {
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    if (rc != 0) {
        vty_wipe(out, VTY_HASH_BYTES);
    }
    return rc;
}

int vty_hmac_sha256(const uint8_t key[32], const uint8_t *data, size_t len,
                    uint8_t out[VTY_HASH_BYTES])
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status;
    int rc = -1;

    if (key == NULL || out == NULL || (data == NULL && len != 0) ||
        len > 0xFFFFFFFFu) {
        return -1;
    }
    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                         BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptCreateHash(alg, &hash, NULL, 0, (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    if (len != 0) {
        status = BCryptHashData(hash, (PUCHAR)data, (ULONG)len, 0);
        if (!BCRYPT_SUCCESS(status)) goto done;
    }
    status = BCryptFinishHash(hash, out, VTY_HASH_BYTES, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    rc = 0;

done:
    if (hash != NULL) {
        BCryptDestroyHash(hash);
    }
    if (alg != NULL) {
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    if (rc != 0) {
        vty_wipe(out, VTY_HASH_BYTES);
    }
    return rc;
}

int vty_random_bytes(uint8_t *out, size_t len)
{
    if (out == NULL || len == 0 || len > 0xFFFFFFFFu) {
        return -1;
    }
    return BCRYPT_SUCCESS(BCryptGenRandom(NULL, out, (ULONG)len,
                                         BCRYPT_USE_SYSTEM_PREFERRED_RNG))
               ? 0
               : -1;
}

int vty_ecc_generate_keypair(uint8_t *priv_blob, DWORD *priv_len, DWORD priv_cap,
                             uint8_t *pub_blob, DWORD *pub_len, DWORD pub_cap)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS status;
    DWORD local_priv = 0;
    DWORD local_pub = 0;
    int rc = -1;

    if (priv_blob == NULL || priv_len == NULL || pub_blob == NULL ||
        pub_len == NULL || priv_cap == 0 || pub_cap == 0) {
        return -1;
    }
    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM,
                                         NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptGenerateKeyPair(alg, &key, 256, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptFinalizeKeyPair(key, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB,
                             priv_blob, priv_cap, &local_priv, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB,
                             pub_blob, pub_cap, &local_pub, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    *priv_len = local_priv;
    *pub_len = local_pub;
    rc = 0;

done:
    if (rc != 0) {
        vty_wipe(priv_blob, priv_cap);
        vty_wipe(pub_blob, pub_cap);
        if (priv_len != NULL) *priv_len = 0;
        if (pub_len != NULL) *pub_len = 0;
    }
    if (key != NULL) {
        BCryptDestroyKey(key);
    }
    if (alg != NULL) {
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return rc;
}

int vty_ecc_load_private(const uint8_t *priv_blob, DWORD priv_len,
                         BCRYPT_KEY_HANDLE *key_out)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS status;
    int rc = -1;

    if (priv_blob == NULL || priv_len == 0 || key_out == NULL) {
        return -1;
    }
    *key_out = NULL;
    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM,
                                         NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPRIVATE_BLOB, &key,
                                 (PUCHAR)priv_blob, priv_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    *key_out = key;
    key = NULL;
    rc = 0;

done:
    if (key != NULL) {
        BCryptDestroyKey(key);
    }
    if (alg != NULL) {
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return rc;
}

int vty_ecc_load_public(const uint8_t *pub_blob, DWORD pub_len,
                        BCRYPT_KEY_HANDLE *key_out)
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS status;
    int rc = -1;

    if (pub_blob == NULL || pub_len == 0 || key_out == NULL) {
        return -1;
    }
    *key_out = NULL;
    status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM,
                                         NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    status = BCryptImportKeyPair(alg, NULL, BCRYPT_ECCPUBLIC_BLOB, &key,
                                 (PUCHAR)pub_blob, pub_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto done;
    *key_out = key;
    key = NULL;
    rc = 0;

done:
    if (key != NULL) {
        BCryptDestroyKey(key);
    }
    if (alg != NULL) {
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return rc;
}

int vty_ecc_public_from_private(const uint8_t *priv_blob, DWORD priv_len,
                                uint8_t *pub_blob, DWORD *pub_len, DWORD pub_cap)
{
    BCRYPT_KEY_HANDLE key = NULL;
    DWORD local_len = 0;
    int rc = -1;

    if (pub_blob == NULL || pub_len == NULL || pub_cap == 0) {
        return -1;
    }
    if (vty_ecc_load_private(priv_blob, priv_len, &key) != 0) {
        return -1;
    }
    if (BCRYPT_SUCCESS(BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                       pub_blob, pub_cap, &local_len, 0))) {
        *pub_len = local_len;
        rc = 0;
    }
    vty_ecc_free_key(&key);
    if (rc != 0) {
        vty_wipe(pub_blob, pub_cap);
        *pub_len = 0;
    }
    return rc;
}

int vty_ecc_sign(BCRYPT_KEY_HANDLE key, const uint8_t hash[VTY_HASH_BYTES],
                 uint8_t signature[VTY_ECC_SIGNATURE_BYTES])
{
    DWORD sig_len = 0;
    NTSTATUS status;

    if (key == NULL || hash == NULL || signature == NULL) {
        return -1;
    }
    memset(signature, 0, VTY_ECC_SIGNATURE_BYTES);
    status = BCryptSignHash(key, NULL, (PUCHAR)hash, VTY_HASH_BYTES,
                            signature, VTY_ECC_SIGNATURE_BYTES, &sig_len, 0);
    if (!BCRYPT_SUCCESS(status) || sig_len != VTY_ECC_SIGNATURE_BYTES) {
        vty_wipe(signature, VTY_ECC_SIGNATURE_BYTES);
        return -1;
    }
    return 0;
}

int vty_ecc_verify_with_key(BCRYPT_KEY_HANDLE key,
                            const uint8_t hash[VTY_HASH_BYTES],
                            const uint8_t signature[VTY_ECC_SIGNATURE_BYTES])
{
    NTSTATUS status;

    if (key == NULL || hash == NULL || signature == NULL) {
        return -1;
    }
    status = BCryptVerifySignature(key, NULL, (PUCHAR)hash, VTY_HASH_BYTES,
                                   (PUCHAR)signature, VTY_ECC_SIGNATURE_BYTES, 0);
    return BCRYPT_SUCCESS(status) ? 0 : -1;
}

int vty_ecc_verify(const uint8_t *pub_blob, DWORD pub_len,
                   const uint8_t hash[VTY_HASH_BYTES],
                   const uint8_t signature[VTY_ECC_SIGNATURE_BYTES])
{
    BCRYPT_KEY_HANDLE key = NULL;
    int rc;

    if (vty_ecc_load_public(pub_blob, pub_len, &key) != 0) {
        return -1;
    }
    rc = vty_ecc_verify_with_key(key, hash, signature);
    vty_ecc_free_key(&key);
    return rc;
}

void vty_ecc_free_key(BCRYPT_KEY_HANDLE *key)
{
    if (key != NULL && *key != NULL) {
        BCryptDestroyKey(*key);
        *key = NULL;
    }
}

int vty_const_time_equal(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    size_t i;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    return diff == 0 ? 1 : 0;
}
