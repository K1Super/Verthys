/*
 * vty_tpm_pcr.c — TPM 2.0 PCR 读取与 PCR 绑定密钥实现
 *
 * 实现要点：
 *   1. PCR 读取走 TBS 的 TPM2_PCR_Read（无授权命令），只请求 SHA-256 银行；
 *   2. PCR 摘要按 TPM2_PolicyPCR 语义计算：按 PCR 索引升序拼接各 PCR 值后
 *      再做 SHA-256；
 *   3. PCR 绑定密钥由 Windows Platform Crypto Provider 在 TPM 内生成，
 *      公钥导出后用于软件侧 RSA 加封，私钥只在 PCR 匹配时才能解密。
 *
 * 为什么不用 TBS 直接发密封/解封命令：本机 Windows TPM 驱动拒绝所有
 * 带授权区的 TPM 2.0 命令（含空会话与 HMAC 会话），PCP 是系统提供的
 * 受支持路径，且其 PCR 绑定语义与 TPM2_PolicyPCR 一致。
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
#include <tbs.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include "vty_tpm_pcr.h"
#include "vty_util.h"
#include "vty_kdf.h"

#include <string.h>

#define TPM_ST_NO_SESSIONS 0x8001u
#define TPM_CC_PCR_READ    0x0000017Eu
#define TPM_ALG_SHA256_ID  0x000Bu
#define TPM_RC_SUCCESS     0x000u

#define TPM_CMD_MAX  64u
#define TPM_RESP_MAX 1024u
#define RSA_PUB_MAX  1024u

static void be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t rd_be16(const uint8_t *p)
{
    return ((uint32_t)p[0] << 8) | p[1];
}

static uint32_t rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint32_t popcount32(uint32_t v)
{
    uint32_t n = 0;
    while (v != 0) {
        n += v & 1u;
        v >>= 1;
    }
    return n;
}

/* 密钥名由库 UUID 派生：同名键在重密封时被覆盖，旧私钥随之失效，
 * 从而让“旧槽位 + 旧副本”无法继续通过 PCR 门。 */
static void pcr_key_name(const uint8_t uuid[VTY_UUID_BYTES], wchar_t out[64])
{
    static const wchar_t hex[] = L"0123456789ABCDEF";
    size_t i;

    for (i = 0; i < 11; i++) out[i] = L"VerthysPCR_"[i];
    for (i = 0; i < VTY_UUID_BYTES; i++) {
        out[11 + i * 2] = hex[(uuid[i] >> 4) & 0x0Fu];
        out[12 + i * 2] = hex[uuid[i] & 0x0Fu];
    }
    out[11 + VTY_UUID_BYTES * 2] = L'\0';
}

int vty_tpm_pcr_select_valid(uint32_t select)
{
    if (select == 0) return VTY_E_INVALID;
    if ((select & ~VTY_TPM_PCR_SELECT_MASK) != 0) return VTY_E_INVALID;
    return VTY_OK;
}

int vty_tpm_pcr_measure(uint32_t select, uint8_t digest[VTY_HASH_BYTES])
{
    TBS_CONTEXT_PARAMS2 params;
    TBS_HCONTEXT ctx = NULL;
    TBS_RESULT tr;
    uint8_t cmd[TPM_CMD_MAX];
    uint8_t resp[TPM_RESP_MAX];
    size_t clen = 0;
    size_t rlen = sizeof(resp);
    size_t off = 10;
    uint32_t need;
    uint32_t sel_count;
    uint32_t digest_count;
    uint32_t i;
    uint8_t cat[VTY_TPM_PCR_TABLE_BYTES];
    size_t cat_len = 0;
    int rc = VTY_E_TPM;
    UINT32 out_len;

    if (digest == NULL) return VTY_E_INVALID;
    if (vty_tpm_pcr_select_valid(select) != VTY_OK) return VTY_E_INVALID;

    memset(&params, 0, sizeof(params));
    params.version = TBS_CONTEXT_VERSION_TWO;
    params.includeTpm20 = 1;
    tr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &ctx);
    if (tr != TBS_SUCCESS) return VTY_E_TPM;

    be16(cmd, TPM_ST_NO_SESSIONS);
    be32(cmd + 2, 0);                       /* 长度回填 */
    be32(cmd + 6, TPM_CC_PCR_READ);
    clen = 10;
    be32(cmd + clen, 1);                    /* TPML_PCR_SELECTION 项数 */
    clen += 4;
    be16(cmd + clen, TPM_ALG_SHA256_ID);
    clen += 2;
    cmd[clen++] = 3;                        /* sizeofSelect：PCR0–23 */
    cmd[clen++] = (uint8_t)(select & 0xFFu);
    cmd[clen++] = (uint8_t)((select >> 8) & 0xFFu);
    cmd[clen++] = (uint8_t)((select >> 16) & 0xFFu);
    be32(cmd + 2, (uint32_t)clen);

    out_len = (UINT32)rlen;
    tr = Tbsip_Submit_Command(ctx, TBS_COMMAND_LOCALITY_ZERO,
                              TBS_COMMAND_PRIORITY_NORMAL,
                              cmd, (UINT32)clen, resp, &out_len);
    Tbsip_Context_Close(ctx);
    rlen = (size_t)out_len;
    if (tr != TBS_SUCCESS) goto out;
    if (rlen < 10 || rd_be16(resp) != TPM_ST_NO_SESSIONS) goto out;
    if (rd_be32(resp + 2) != rlen) goto out;
    if (rd_be32(resp + 6) != TPM_RC_SUCCESS) goto out;

    off += 4;                               /* pcrUpdateCounter */
    if (off + 4 > rlen) goto out;
    sel_count = rd_be32(resp + off);
    off += 4;
    if (sel_count != 1) goto out;
    for (i = 0; i < sel_count; i++) {
        uint32_t bytes;
        if (off + 3 > rlen) goto out;
        if (rd_be16(resp + off) != TPM_ALG_SHA256_ID) goto out;
        bytes = resp[off + 2];
        off += 3;
        if (bytes != 3 || off + bytes > rlen) goto out;
        /* 响应必须回显实际读取的 PCR 集合，否则不能把摘要用于策略比对 */
        if (resp[off] != (uint8_t)(select & 0xFFu) ||
            resp[off + 1] != (uint8_t)((select >> 8) & 0xFFu) ||
            resp[off + 2] != (uint8_t)((select >> 16) & 0xFFu)) {
            goto out;
        }
        off += bytes;
    }
    if (off + 4 > rlen) goto out;
    digest_count = rd_be32(resp + off);
    off += 4;
    need = popcount32(select);
    if (digest_count != need || need == 0) goto out;

    for (i = 0; i < digest_count; i++) {
        uint32_t n;
        if (off + 2 > rlen) goto out;
        n = rd_be16(resp + off);
        off += 2;
        if (n != VTY_HASH_BYTES || off + n > rlen) goto out;
        if (cat_len + n > sizeof(cat)) goto out;
        memcpy(cat + cat_len, resp + off, n);
        cat_len += n;
        off += n;
    }
    if (vty_sha256(digest, cat, cat_len) != VTY_OK) goto out;
    rc = VTY_OK;

out:
    vty_secure_zero(cat, sizeof(cat));
    vty_secure_zero(resp, sizeof(resp));
    return rc;
}

int vty_tpm_pcr_available(void)
{
    NCRYPT_PROV_HANDLE prov = 0;
    uint8_t digest[VTY_HASH_BYTES];
    int ok;

    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        return 0;
    }
    NCryptFreeObject(prov);
    ok = (vty_tpm_pcr_measure(VTY_TPM_PCR_SELECT_DEFAULT, digest) == VTY_OK);
    vty_secure_zero(digest, sizeof(digest));
    return ok;
}

int vty_tpm_pcr_key_create(const uint8_t vault_uuid[VTY_UUID_BYTES],
                           uint32_t select,
                           const uint8_t *expected24, size_t expected_len)
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    wchar_t name[64];
    DWORD usage = NCRYPT_PCP_ENCRYPTION_KEY;
    uint8_t mask3[3];
    uint16_t alg = TPM_ALG_SHA256_ID;
    int rc = VTY_E_TPM;
    int created = 0;

    if (vault_uuid == NULL) return VTY_E_INVALID;
    if (vty_tpm_pcr_select_valid(select) != VTY_OK) return VTY_E_INVALID;
    if (expected24 == NULL && expected_len != 0) return VTY_E_INVALID;
    if (expected24 != NULL && expected_len != VTY_TPM_PCR_TABLE_BYTES) {
        return VTY_E_INVALID;
    }

    pcr_key_name(vault_uuid, name);
    mask3[0] = (uint8_t)(select & 0xFFu);
    mask3[1] = (uint8_t)((select >> 8) & 0xFFu);
    mask3[2] = (uint8_t)((select >> 16) & 0xFFu);

    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        return VTY_E_TPM;
    }

    if (NCryptCreatePersistedKey(prov, &key, NCRYPT_RSA_ALGORITHM, name, 0,
                                 NCRYPT_OVERWRITE_KEY_FLAG) == 0) {
        created = 1;
        if (NCryptSetProperty(key, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                              (PBYTE)&usage, sizeof(usage), 0) == 0 &&
            NCryptSetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRMASK_PROPERTY,
                              (PBYTE)mask3, sizeof(mask3), 0) == 0 &&
            NCryptSetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRALGID_PROPERTY,
                              (PBYTE)&alg, sizeof(alg), 0) == 0 &&
            (expected24 == NULL ||
             NCryptSetProperty(key, NCRYPT_PCP_PLATFORM_BINDING_PCRDIGESTLIST_PROPERTY,
                               (PBYTE)expected24, (DWORD)expected_len, 0) == 0) &&
            NCryptFinalizeKey(key, 0) == 0) {
            rc = VTY_OK;
        }
    }
    if (key != 0) {
        if (rc != VTY_OK && created) {
            /* 半成品键不能被后续解封误用 */
            (void)NCryptDeleteKey(key, 0);
        } else {
            NCryptFreeObject(key);
        }
    }
    NCryptFreeObject(prov);
    return rc;
}

int vty_tpm_pcr_key_delete(const uint8_t vault_uuid[VTY_UUID_BYTES])
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    wchar_t name[64];
    SECURITY_STATUS st;

    if (vault_uuid == NULL) return VTY_E_INVALID;
    pcr_key_name(vault_uuid, name);
    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        return VTY_E_TPM;
    }
    st = NCryptOpenKey(prov, &key, name, 0, 0);
    if (st != 0) {
        uint32_t code = (uint32_t)st;
        NCryptFreeObject(prov);
        /* 仅“键不存在”视为已删除；权限/设备故障必须向上报告 */
        if (code == 0x80090011u || code == 0x80090016u || code == 0x80090026u) {
            return VTY_OK;
        }
        return VTY_E_TPM;
    }
    if (NCryptDeleteKey(key, 0) == 0) {
        NCryptFreeObject(prov);
        return VTY_OK;
    }
    NCryptFreeObject(key);
    NCryptFreeObject(prov);
    return VTY_E_TPM;
}

int vty_tpm_pcr_seal(const uint8_t vault_uuid[VTY_UUID_BYTES],
                     const uint8_t key_data[VTY_KEY_BYTES],
                     uint8_t ct[VTY_TPM_PCR_CT_BYTES])
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE nkey = 0;
    BCRYPT_ALG_HANDLE rsa = NULL;
    BCRYPT_KEY_HANDLE pub = NULL;
    wchar_t name[64];
    uint8_t pubblob[RSA_PUB_MAX];
    DWORD pub_len = sizeof(pubblob);
    DWORD ct_len = VTY_TPM_PCR_CT_BYTES;
    BCRYPT_OAEP_PADDING_INFO oaep;
    NTSTATUS bs;
    int rc = VTY_E_TPM;

    if (vault_uuid == NULL || key_data == NULL || ct == NULL) return VTY_E_INVALID;
    pcr_key_name(vault_uuid, name);
    memset(&oaep, 0, sizeof(oaep));
    oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        return VTY_E_TPM;
    }
    if (NCryptOpenKey(prov, &nkey, name, 0, 0) != 0) goto out;
    if (NCryptExportKey(nkey, 0, BCRYPT_RSAPUBLIC_BLOB, NULL,
                        pubblob, sizeof(pubblob), &pub_len, 0) != 0) {
        goto out;
    }
    bs = BCryptOpenAlgorithmProvider(&rsa, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (bs != 0) goto out;
    bs = BCryptImportKeyPair(rsa, NULL, BCRYPT_RSAPUBLIC_BLOB, &pub,
                             pubblob, pub_len, 0);
    if (bs != 0) goto out;
    bs = BCryptEncrypt(pub, (PUCHAR)key_data, VTY_KEY_BYTES, &oaep, NULL, 0,
                       ct, ct_len, &ct_len, BCRYPT_PAD_OAEP);
    if (bs == 0 && ct_len == VTY_TPM_PCR_CT_BYTES) {
        rc = VTY_OK;
    }

out:
    if (rc != VTY_OK && ct != NULL) vty_secure_zero(ct, VTY_TPM_PCR_CT_BYTES);
    if (pub != NULL) BCryptDestroyKey(pub);
    if (rsa != NULL) BCryptCloseAlgorithmProvider(rsa, 0);
    if (nkey != 0) NCryptFreeObject(nkey);
    NCryptFreeObject(prov);
    vty_secure_zero(pubblob, sizeof(pubblob));
    return rc;
}

int vty_tpm_pcr_unseal(const uint8_t vault_uuid[VTY_UUID_BYTES],
                       const uint8_t ct[VTY_TPM_PCR_CT_BYTES],
                       uint8_t key_out[VTY_KEY_BYTES])
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE nkey = 0;
    wchar_t name[64];
    uint8_t plain[VTY_KEY_BYTES];
    DWORD plain_len = sizeof(plain);
    BCRYPT_OAEP_PADDING_INFO oaep;
    int rc = VTY_E_TPM;

    if (vault_uuid == NULL || ct == NULL || key_out == NULL) return VTY_E_INVALID;
    pcr_key_name(vault_uuid, name);
    memset(&oaep, 0, sizeof(oaep));
    oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != 0) {
        return VTY_E_TPM;
    }
    if (NCryptOpenKey(prov, &nkey, name, 0, 0) == 0) {
        if (NCryptDecrypt(nkey, (PBYTE)ct, VTY_TPM_PCR_CT_BYTES, &oaep,
                          plain, sizeof(plain), &plain_len, BCRYPT_PAD_OAEP) == 0 &&
            plain_len == VTY_KEY_BYTES) {
            memcpy(key_out, plain, VTY_KEY_BYTES);
            rc = VTY_OK;
        }
        NCryptFreeObject(nkey);
    }
    NCryptFreeObject(prov);
    if (rc != VTY_OK) vty_secure_zero(key_out, VTY_KEY_BYTES);
    vty_secure_zero(plain, sizeof(plain));
    return rc;
}
