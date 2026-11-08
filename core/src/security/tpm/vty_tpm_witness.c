/*
 * vty_tpm_witness.c — TPM 持久化密钥见证实现
 *
 * 为什么用 ECC P-256：RSA-2048 在 PTT 上单次建键约 2 秒，无法承受每次
 * 保存都轮换；ECC 约 0.4 秒，且只需要导出公钥计算指纹。对称密钥不被
 * PCP 支持（HMAC 定稿失败、AES 建键被拒），因此 ECC 是当前可行且
 * 足够强的选择。
 *
 * 指纹 = SHA-256(导出的 ECC 公钥 BLOB)。旧密钥被覆盖后无法重建同一
 * 公钥，故旧状态文件无法伪造指纹。
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include "vty_tpm_witness.h"
#include "vty_util.h"
#include "vty_kdf.h"

#include <string.h>

#define WIT_PUB_MAX 512u
#define WIT_NAME_CHARS 64u

static int not_found_status(SECURITY_STATUS st)
{
    uint32_t code = (uint32_t)st;
    /* CNG/PCP 对“容器/键不存在”使用不同的 NTE 码 */
    return code == 0x80090011u || code == 0x80090016u || code == 0x80090026u;
}

static void wit_name(const uint8_t id[VTY_UUID_BYTES], uint8_t slot,
                     wchar_t out[WIT_NAME_CHARS])
{
    static const wchar_t hex[] = L"0123456789ABCDEF";
    size_t i;

    for (i = 0; i < 11; i++) out[i] = L"VerthysWit_"[i];
    for (i = 0; i < VTY_UUID_BYTES; i++) {
        out[11 + i * 2] = hex[(id[i] >> 4) & 0x0Fu];
        out[12 + i * 2] = hex[id[i] & 0x0Fu];
    }
    out[11 + VTY_UUID_BYTES * 2] = L'_';
    out[12 + VTY_UUID_BYTES * 2] = (slot == 0) ? L'A' : L'B';
    out[13 + VTY_UUID_BYTES * 2] = L'\0';
}

int vty_tpm_witness_available(void)
{
    NCRYPT_PROV_HANDLE prov = 0;

    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        return 0;
    }
    NCryptFreeObject(prov);
    return 1;
}

/* 导出当前公钥并计算指纹；失败返回 E_TPM */
static int witness_fp(NCRYPT_KEY_HANDLE key,
                      uint8_t fp[VTY_TPM_WITNESS_FP_BYTES])
{
    uint8_t pub[WIT_PUB_MAX];
    DWORD pub_len = sizeof(pub);
    int rc = VTY_E_TPM;

    if (NCryptExportKey(key, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
                        pub, sizeof(pub), &pub_len, 0) == 0 &&
        pub_len > 0 &&
        vty_sha256(fp, pub, pub_len) == VTY_OK) {
        rc = VTY_OK;
    }
    vty_secure_zero(pub, sizeof(pub));
    return rc;
}

int vty_tpm_witness_create(const uint8_t id[VTY_UUID_BYTES], uint8_t slot,
                           uint8_t fp[VTY_TPM_WITNESS_FP_BYTES])
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    wchar_t name[WIT_NAME_CHARS];
    DWORD usage = NCRYPT_PCP_SIGNATURE_KEY;
    int rc = VTY_E_TPM;

    if (id == NULL || fp == NULL || slot >= VTY_TPM_WITNESS_SLOTS) {
        return VTY_E_INVALID;
    }
    wit_name(id, slot, name);
    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        return VTY_E_TPM;
    }

    if (NCryptCreatePersistedKey(prov, &key, BCRYPT_ECDSA_P256_ALGORITHM,
                                 name, 0, NCRYPT_OVERWRITE_KEY_FLAG) == 0) {
        if (NCryptSetProperty(key, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                              (PBYTE)&usage, sizeof(usage), 0) == 0 &&
            NCryptFinalizeKey(key, 0) == 0) {
            rc = witness_fp(key, fp);
        }
    }
    if (key != 0) {
        if (rc != VTY_OK) {
            (void)NCryptDeleteKey(key, 0);
            vty_secure_zero(fp, VTY_TPM_WITNESS_FP_BYTES);
        } else {
            NCryptFreeObject(key);
        }
    }
    NCryptFreeObject(prov);
    return rc;
}

int vty_tpm_witness_verify(const uint8_t id[VTY_UUID_BYTES], uint8_t slot,
                           const uint8_t expected[VTY_TPM_WITNESS_FP_BYTES])
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    wchar_t name[WIT_NAME_CHARS];
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
    int rc = VTY_E_TPM;

    if (id == NULL || expected == NULL || slot >= VTY_TPM_WITNESS_SLOTS) {
        return VTY_E_INVALID;
    }
    wit_name(id, slot, name);
    memset(fp, 0, sizeof(fp));
    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        return VTY_E_TPM;
    }
    if (NCryptOpenKey(prov, &key, name, 0, 0) == 0) {
        if (witness_fp(key, fp) == VTY_OK &&
            vty_ct_equal(fp, expected, VTY_TPM_WITNESS_FP_BYTES) == 0) {
            rc = VTY_OK;
        }
        NCryptFreeObject(key);
    }
    NCryptFreeObject(prov);
    vty_secure_zero(fp, sizeof(fp));
    return rc;
}

int vty_tpm_witness_delete(const uint8_t id[VTY_UUID_BYTES], uint8_t slot)
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    wchar_t name[WIT_NAME_CHARS];
    SECURITY_STATUS st;

    if (id == NULL || slot >= VTY_TPM_WITNESS_SLOTS) return VTY_E_INVALID;
    wit_name(id, slot, name);
    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        return VTY_E_TPM;
    }
    st = NCryptOpenKey(prov, &key, name, 0, 0);
    if (st != 0) {
        NCryptFreeObject(prov);
        return not_found_status(st) ? VTY_OK : VTY_E_TPM;
    }
    if (NCryptDeleteKey(key, 0) == 0) {
        /* NCryptDeleteKey 删除持久化键但不释放调用方持有的 key 句柄，
         * 必须显式 NCryptFreeObject，否则每次轮换泄漏一个句柄（N5）。 */
        NCryptFreeObject(key);
        NCryptFreeObject(prov);
        return VTY_OK;
    }
    NCryptFreeObject(key);
    NCryptFreeObject(prov);
    return VTY_E_TPM;
}

int vty_tpm_witness_any(const uint8_t id[VTY_UUID_BYTES])
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    wchar_t name[WIT_NAME_CHARS];
    uint8_t slot;
    int found = 0;

    if (id == NULL) return -1;
    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        return -1;
    }
    for (slot = 0; slot < VTY_TPM_WITNESS_SLOTS; slot++) {
        SECURITY_STATUS st;
        wit_name(id, slot, name);
        st = NCryptOpenKey(prov, &key, name, 0, 0);
        if (st == 0) {
            NCryptFreeObject(key);
            found = 1;
            break;
        }
        if (!not_found_status(st)) {
            NCryptFreeObject(prov);
            return -1;
        }
    }
    NCryptFreeObject(prov);
    return found;
}

int vty_tpm_witness_delete_all(const uint8_t id[VTY_UUID_BYTES])
{
    int a, b;
    a = vty_tpm_witness_delete(id, 0);
    b = vty_tpm_witness_delete(id, 1);
    if (a != VTY_OK || b != VTY_OK) return VTY_E_TPM;
    return VTY_OK;
}

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
int vty_tpm_witness_id_from_string(const char *text,
                                   uint8_t id[VTY_UUID_BYTES])
{
    uint8_t digest[VTY_HASH_BYTES];

    if (text == NULL || id == NULL) return VTY_E_INVALID;
    if (vty_sha256(digest, text, strlen(text)) != VTY_OK) return VTY_E_TPM;
    memcpy(id, digest, VTY_UUID_BYTES);
    vty_secure_zero(digest, sizeof(digest));
    return VTY_OK;
}
#endif
