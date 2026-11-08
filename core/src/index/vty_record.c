/*
 * vty_record.c — 记录与名称加密实现
 */
#include "vty_record.h"
#include "vty_kdf.h"
#include "vty_util.h"

#include <windows.h>
#include <stdlib.h>
#include <string.h>

#define RECORD_PREFIX_BYTES (8u + VTY_UUID_BYTES + 8u + 2u)  /* id|uuid|epoch|name_len */

static size_t pad_to(size_t n, size_t bucket)
{
    return (n + bucket - 1u) / bucket * bucket;
}

static int derive_key(const uint8_t mdek[VTY_KEY_BYTES],
                      const char *label,
                      const uint8_t module_uuid[VTY_UUID_BYTES],
                      const uint8_t *tail, size_t tail_len,
                      uint8_t out[VTY_KEY_BYTES])
{
    uint8_t info[64];
    size_t label_len = strlen(label);
    size_t need = label_len + VTY_UUID_BYTES + tail_len;

    if (need > sizeof(info)) return VTY_E_INVALID;
    memcpy(info, label, label_len);
    memcpy(info + label_len, module_uuid, VTY_UUID_BYTES);
    if (tail_len != 0) memcpy(info + label_len + VTY_UUID_BYTES, tail, tail_len);
    return vty_hkdf_expand(out, mdek, info, need);
}

static int name_aad(const uint8_t module_uuid[VTY_UUID_BYTES],
                    uint64_t record_id, uint64_t epoch,
                    uint8_t out[64], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_NAME;
    size_t dlen = strlen(domain);

    memcpy(out, domain, dlen);
    memcpy(out + dlen, module_uuid, VTY_UUID_BYTES);
    vty_put_u64(out + dlen + VTY_UUID_BYTES, record_id);
    vty_put_u64(out + dlen + VTY_UUID_BYTES + 8u, epoch);
    *out_len = dlen + VTY_UUID_BYTES + 16u;
    return VTY_OK;
}

static int record_aad(const uint8_t module_uuid[VTY_UUID_BYTES],
                      uint64_t record_id, uint64_t epoch, uint16_t name_len,
                      uint8_t out[64], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_RECORD;
    size_t dlen = strlen(domain);

    memcpy(out, domain, dlen);
    memcpy(out + dlen, module_uuid, VTY_UUID_BYTES);
    vty_put_u64(out + dlen + VTY_UUID_BYTES, record_id);
    vty_put_u64(out + dlen + VTY_UUID_BYTES + 8u, epoch);
    vty_put_u16(out + dlen + VTY_UUID_BYTES + 16u, name_len);
    *out_len = dlen + VTY_UUID_BYTES + 18u;
    return VTY_OK;
}

int vty_record_seal(const uint8_t mdek[VTY_KEY_BYTES],
                    const uint8_t module_uuid[VTY_UUID_BYTES],
                    uint64_t record_id, uint64_t epoch,
                    const uint8_t *name, size_t name_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t **out, size_t *out_len)
{
    uint8_t nk[VTY_KEY_BYTES];
    uint8_t dk[VTY_KEY_BYTES];
    uint8_t nonce[VTY_NONCE_BYTES];
    uint8_t aad[64];
    size_t aad_len = 0;
    size_t name_plain, data_plain;
    size_t name_ct_len, data_ct_len;
    size_t total, off;
    uint8_t *buf = NULL;
    uint8_t tail[16];
    int rc = VTY_OK;

    if (mdek == NULL || module_uuid == NULL || out == NULL || out_len == NULL) {
        return VTY_E_INVALID;
    }
    if (name == NULL && name_len != 0) return VTY_E_INVALID;
    if (data == NULL && data_len != 0) return VTY_E_INVALID;
    if (name_len > VTY_RECORD_MAX_NAME) return VTY_E_INVALID;
    if (data_len > VTY_RECORD_MAX_DATA) return VTY_E_INVALID;

    name_plain = pad_to(2u + name_len, VTY_RECORD_NAME_BUCKET);
    data_plain = pad_to(4u + data_len, VTY_RECORD_DATA_BUCKET);
    if (name_plain > 0xFFFFu - VTY_TAG_BYTES) return VTY_E_INVALID;
    if (data_plain > 0xFFFFFFFFu - VTY_TAG_BYTES) return VTY_E_INVALID;
    name_ct_len = name_plain + VTY_TAG_BYTES;
    data_ct_len = data_plain + VTY_TAG_BYTES;
    total = RECORD_PREFIX_BYTES + name_ct_len + 4u + VTY_NONCE_BYTES + data_ct_len;

    buf = (uint8_t *)vty_alloc(total);
    if (buf == NULL) return VTY_E_RESOURCE;

    /* 名称与数据的 nonce 值相同但密钥不同（NK/DK），因此不构成 nonce 复用 */
    vty_random(nonce, sizeof(nonce));

    vty_put_u64(tail, record_id);
    vty_put_u64(tail + 8, epoch);
    rc = derive_key(mdek, VTY_DOMAIN_NAME, module_uuid, tail, 16, nk);
    if (rc != VTY_OK) goto done;
    {
        uint8_t tail2[16];
        vty_put_u64(tail2, record_id);
        vty_put_u64(tail2 + 8, epoch);
        rc = derive_key(mdek, VTY_DOMAIN_RECORD, module_uuid, tail2, 16, dk);
        vty_secure_zero(tail2, sizeof(tail2));
    }
    if (rc != VTY_OK) goto done;

    vty_put_u64(buf + 0, record_id);
    memcpy(buf + 8, module_uuid, VTY_UUID_BYTES);
    vty_put_u64(buf + 24, epoch);
    vty_put_u16(buf + 32, (uint16_t)name_ct_len);

    /* 名称明文：u16 实长 || 名称 || 零填充 */
    {
        uint8_t *np = (uint8_t *)vty_alloc(name_plain);
        size_t np_len = 0;
        if (np == NULL) { rc = VTY_E_RESOURCE; goto done; }
        vty_put_u16(np, (uint16_t)name_len);
        if (name_len != 0) memcpy(np + 2, name, name_len);
        name_aad(module_uuid, record_id, epoch, aad, &aad_len);
        rc = vty_aead_seal(nk, nonce, aad, aad_len, np, name_plain,
                           buf + RECORD_PREFIX_BYTES, name_ct_len, &np_len);
        vty_free(np, name_plain);
        if (rc != VTY_OK) goto done;
        if (np_len != name_ct_len) { rc = VTY_E_AEAD; goto done; }
    }

    off = RECORD_PREFIX_BYTES + name_ct_len;
    vty_put_u32(buf + off, (uint32_t)data_ct_len);
    off += 4;
    memcpy(buf + off, nonce, VTY_NONCE_BYTES);
    off += VTY_NONCE_BYTES;

    {
        uint8_t *dp = (uint8_t *)vty_alloc(data_plain);
        size_t dp_len = 0;
        if (dp == NULL) { rc = VTY_E_RESOURCE; goto done; }
        vty_put_u32(dp, (uint32_t)data_len);
        if (data_len != 0) memcpy(dp + 4, data, data_len);
        record_aad(module_uuid, record_id, epoch, (uint16_t)name_ct_len,
                   aad, &aad_len);
        rc = vty_aead_seal(dk, nonce, aad, aad_len, dp, data_plain,
                           buf + off, data_ct_len, &dp_len);
        vty_free(dp, data_plain);
        if (rc != VTY_OK) goto done;
        if (dp_len != data_ct_len) { rc = VTY_E_AEAD; goto done; }
    }

    *out = buf;
    *out_len = total;
    buf = NULL;

done:
    if (buf != NULL) vty_free(buf, total);
    vty_secure_zero(nk, sizeof(nk));
    vty_secure_zero(dk, sizeof(dk));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

int vty_record_open(const uint8_t mdek[VTY_KEY_BYTES],
                    const uint8_t module_uuid[VTY_UUID_BYTES],
                    uint64_t epoch,
                    const uint8_t *in, size_t in_len,
                    uint8_t **name, size_t *name_len,
                    uint8_t **data, size_t *data_len)
{
    uint8_t nk[VTY_KEY_BYTES];
    uint8_t dk[VTY_KEY_BYTES];
    uint8_t nonce[VTY_NONCE_BYTES];
    uint8_t aad[64];
    size_t aad_len = 0;
    uint64_t record_id;
    uint64_t stored_epoch;
    uint16_t name_ct_len;
    uint32_t data_ct_len;
    size_t name_plain, data_plain;
    size_t off;
    uint8_t *name_pt = NULL;
    uint8_t *data_pt = NULL;
    uint8_t *name_out = NULL;
    uint8_t *data_out = NULL;
    size_t name_out_len = 0;
    size_t data_out_len = 0;
    size_t pt_len = 0;
    uint32_t actual;
    int rc = VTY_OK;

    if (mdek == NULL || module_uuid == NULL || in == NULL ||
        name == NULL || name_len == NULL || data == NULL || data_len == NULL) {
        return VTY_E_INVALID;
    }
    *name = NULL; *name_len = 0; *data = NULL; *data_len = 0;

    if (in_len < RECORD_PREFIX_BYTES + 4u + VTY_NONCE_BYTES) return VTY_E_INVALID;
    record_id = vty_get_u64(in + 0);
    if (memcmp(in + 8, module_uuid, VTY_UUID_BYTES) != 0) return VTY_E_KEY_INVALID;
    stored_epoch = vty_get_u64(in + 24);
    if (stored_epoch != epoch) return VTY_E_KEY_INVALID;
    name_ct_len = vty_get_u16(in + 32);

    if (name_ct_len < VTY_TAG_BYTES + 2u) return VTY_E_INVALID;
    if ((name_ct_len - VTY_TAG_BYTES) % VTY_RECORD_NAME_BUCKET != 0) return VTY_E_INVALID;
    name_plain = (size_t)name_ct_len - VTY_TAG_BYTES;
    if (in_len < (size_t)RECORD_PREFIX_BYTES + name_ct_len + 4u + VTY_NONCE_BYTES) {
        return VTY_E_INVALID;
    }

    off = RECORD_PREFIX_BYTES + name_ct_len;
    data_ct_len = vty_get_u32(in + off); off += 4;
    memcpy(nonce, in + off, VTY_NONCE_BYTES); off += VTY_NONCE_BYTES;
    if (data_ct_len < VTY_TAG_BYTES + 4u) return VTY_E_INVALID;
    if ((data_ct_len - VTY_TAG_BYTES) % VTY_RECORD_DATA_BUCKET != 0) return VTY_E_INVALID;
    if (in_len != off + data_ct_len) return VTY_E_INVALID;
    data_plain = (size_t)data_ct_len - VTY_TAG_BYTES;

    {
        uint8_t tail[16];
        vty_put_u64(tail, record_id);
        vty_put_u64(tail + 8, epoch);
        rc = derive_key(mdek, VTY_DOMAIN_NAME, module_uuid, tail, 16, nk);
        if (rc == VTY_OK) {
            rc = derive_key(mdek, VTY_DOMAIN_RECORD, module_uuid, tail, 16, dk);
        }
        vty_secure_zero(tail, sizeof(tail));
    }
    if (rc != VTY_OK) goto done;

    name_pt = (uint8_t *)vty_alloc(name_plain);
    if (name_pt == NULL) { rc = VTY_E_RESOURCE; goto done; }
    name_aad(module_uuid, record_id, epoch, aad, &aad_len);
    rc = vty_aead_open(nk, nonce, aad, aad_len,
                       in + RECORD_PREFIX_BYTES, name_ct_len,
                       name_pt, name_plain, &pt_len);
    if (rc != VTY_OK) goto done;
    if (pt_len != name_plain) { rc = VTY_E_INVALID; goto done; }

    actual = vty_get_u16(name_pt);
    if (actual > name_plain - 2u) { rc = VTY_E_INVALID; goto done; }
    name_out = (uint8_t *)vty_alloc(actual != 0 ? actual : 1u);
    if (name_out == NULL) { rc = VTY_E_RESOURCE; goto done; }
    name_out_len = actual != 0 ? actual : 1u;
    if (actual != 0) memcpy(name_out, name_pt + 2, actual);

    data_pt = (uint8_t *)vty_alloc(data_plain);
    if (data_pt == NULL) { rc = VTY_E_RESOURCE; goto done; }
    record_aad(module_uuid, record_id, epoch, name_ct_len, aad, &aad_len);
    rc = vty_aead_open(dk, nonce, aad, aad_len,
                       in + off, data_ct_len,
                       data_pt, data_plain, &pt_len);
    if (rc != VTY_OK) goto done;
    if (pt_len != data_plain) { rc = VTY_E_INVALID; goto done; }

    actual = vty_get_u32(data_pt);
    if ((size_t)actual > data_plain - 4u) { rc = VTY_E_INVALID; goto done; }
    data_out = (uint8_t *)vty_alloc(actual != 0 ? actual : 1u);
    if (data_out == NULL) { rc = VTY_E_RESOURCE; goto done; }
    data_out_len = actual != 0 ? actual : 1u;
    if (actual != 0) memcpy(data_out, data_pt + 4, actual);

    *name = name_out;
    *name_len = vty_get_u16(name_pt);
    *data = data_out;
    *data_len = vty_get_u32(data_pt);
    name_out = NULL;
    data_out = NULL;

done:
    /* 明文暂存区（名称/数据）必须清零后释放：vty_free 不保证擦除。
     * 输出缓冲区仅在失败路径尚未移交所有权时清零（成功路径置 NULL）。 */
    if (name_pt != NULL) {
        vty_secure_zero(name_pt, name_plain);
        vty_free(name_pt, name_plain);
    }
    if (data_pt != NULL) {
        vty_secure_zero(data_pt, data_plain);
        vty_free(data_pt, data_plain);
    }
    if (name_out != NULL) {
        vty_secure_zero(name_out, name_out_len);
        vty_free(name_out, name_out_len);
    }
    if (data_out != NULL) {
        vty_secure_zero(data_out, data_out_len);
        vty_free(data_out, data_out_len);
    }
    vty_secure_zero(nk, sizeof(nk));
    vty_secure_zero(dk, sizeof(dk));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

int vty_record_open_name(const uint8_t mdek[VTY_KEY_BYTES],
                         const uint8_t module_uuid[VTY_UUID_BYTES],
                         uint64_t epoch,
                         const uint8_t *in, size_t in_len,
                         uint8_t **name, size_t *name_len)
{
    uint8_t nk[VTY_KEY_BYTES];
    uint8_t nonce[VTY_NONCE_BYTES];
    uint8_t aad[64];
    size_t aad_len = 0;
    uint64_t record_id;
    uint16_t name_ct_len;
    uint32_t data_ct_len;
    size_t name_plain;
    size_t off;
    size_t name_alloc = 0;
    uint8_t *name_pt = NULL;
    uint8_t *name_out = NULL;
    size_t pt_len = 0;
    uint32_t actual;
    int rc = VTY_OK;

    if (mdek == NULL || module_uuid == NULL || in == NULL ||
        name == NULL || name_len == NULL) {
        return VTY_E_INVALID;
    }
    *name = NULL;
    *name_len = 0;

    if (in_len < RECORD_PREFIX_BYTES + 4u + VTY_NONCE_BYTES) return VTY_E_INVALID;
    record_id = vty_get_u64(in + 0);
    if (memcmp(in + 8, module_uuid, VTY_UUID_BYTES) != 0) return VTY_E_KEY_INVALID;
    if (vty_get_u64(in + 24) != epoch) return VTY_E_KEY_INVALID;
    name_ct_len = vty_get_u16(in + 32);
    if (name_ct_len < VTY_TAG_BYTES + 2u) return VTY_E_INVALID;
    if ((name_ct_len - VTY_TAG_BYTES) % VTY_RECORD_NAME_BUCKET != 0) return VTY_E_INVALID;
    name_plain = (size_t)name_ct_len - VTY_TAG_BYTES;
    if (in_len < (size_t)RECORD_PREFIX_BYTES + name_ct_len + 4u + VTY_NONCE_BYTES) {
        return VTY_E_INVALID;
    }

    /* 名称与数据用同一随机 nonce（密钥不同，不构成复用），存储位置在
     * 数据密文之前；摘要路径只借用它解密名称，不读取数据密文。 */
    off = (size_t)RECORD_PREFIX_BYTES + name_ct_len;
    data_ct_len = vty_get_u32(in + off); off += 4;
    memcpy(nonce, in + off, VTY_NONCE_BYTES); off += VTY_NONCE_BYTES;
    if (data_ct_len < VTY_TAG_BYTES + 4u) return VTY_E_INVALID;
    if ((data_ct_len - VTY_TAG_BYTES) % VTY_RECORD_DATA_BUCKET != 0) return VTY_E_INVALID;
    if (in_len != off + data_ct_len) return VTY_E_INVALID;

    {
        uint8_t tail[16];
        vty_put_u64(tail, record_id);
        vty_put_u64(tail + 8, epoch);
        rc = derive_key(mdek, VTY_DOMAIN_NAME, module_uuid, tail, 16, nk);
        vty_secure_zero(tail, sizeof(tail));
    }
    if (rc != VTY_OK) goto done;

    name_pt = (uint8_t *)vty_alloc(name_plain);
    if (name_pt == NULL) { rc = VTY_E_RESOURCE; goto done; }
    name_aad(module_uuid, record_id, epoch, aad, &aad_len);
    rc = vty_aead_open(nk, nonce, aad, aad_len,
                       in + RECORD_PREFIX_BYTES, name_ct_len,
                       name_pt, name_plain, &pt_len);
    if (rc != VTY_OK) goto done;
    if (pt_len != name_plain) { rc = VTY_E_INVALID; goto done; }

    actual = vty_get_u16(name_pt);
    if (actual > name_plain - 2u) { rc = VTY_E_INVALID; goto done; }
    name_alloc = actual != 0 ? actual : 1u;
    name_out = (uint8_t *)vty_alloc(name_alloc);
    if (name_out == NULL) { rc = VTY_E_RESOURCE; goto done; }
    if (actual != 0) memcpy(name_out, name_pt + 2, actual);

    *name = name_out;
    *name_len = actual;
    name_out = NULL;

done:
    if (name_pt != NULL) {
        vty_secure_zero(name_pt, name_plain);
        vty_free(name_pt, name_plain);
    }
    if (name_out != NULL) {
        vty_secure_zero(name_out, name_alloc);
        vty_free(name_out, name_alloc);
    }
    vty_secure_zero(nk, sizeof(nk));
    vty_secure_zero(nonce, sizeof(nonce));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

int vty_type_token(const uint8_t mdek[VTY_KEY_BYTES],
                   const uint8_t module_uuid[VTY_UUID_BYTES],
                   uint64_t epoch, uint8_t type,
                   uint8_t out[VTY_HASH_BYTES])
{
    uint8_t tk[VTY_KEY_BYTES];
    uint8_t tail[8];
    int rc;

    if (mdek == NULL || module_uuid == NULL || out == NULL) return VTY_E_INVALID;
    vty_put_u64(tail, epoch);
    rc = derive_key(mdek, VTY_DOMAIN_TYPE_INDEX, module_uuid, tail, sizeof(tail), tk);
    if (rc == VTY_OK) {
        rc = vty_hmac_sha256(out, tk, VTY_KEY_BYTES, &type, 1u);
    }
    vty_secure_zero(tk, sizeof(tk));
    vty_secure_zero(tail, sizeof(tail));
    return rc;
}

int vty_record_reject_plaintext(int encrypted_flag)
{
    return encrypted_flag != 0 ? VTY_OK : VTY_E_PLAINTEXT_FORBIDDEN;
}

/* NFKC 归一化后再做盲索引，避免同义写法产生不同索引 */
static int nfkc(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len)
{
    int wlen, nlen, u8len;
    wchar_t *wsrc = NULL;
    wchar_t *wdst = NULL;
    uint8_t *dst = NULL;

    *out = NULL; *out_len = 0;
    if (in == NULL && in_len != 0) return VTY_E_INVALID;
    if (in_len > 0x7FFFFFFFu) return VTY_E_INVALID;
    if (in_len == 0) return VTY_OK;

    wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                               (const char *)in, (int)in_len, NULL, 0);
    if (wlen <= 0) return VTY_E_INVALID;
    wsrc = (wchar_t *)malloc(((size_t)wlen + 1u) * sizeof(wchar_t));
    if (wsrc == NULL) return VTY_E_RESOURCE;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            (const char *)in, (int)in_len, wsrc, wlen) != wlen) {
        free(wsrc);
        return VTY_E_INVALID;
    }

    /* 查询返回的是“上界估计”，实际归一化结果可以更短（全角→半角会缩短），
     * 因此只能要求 0 < 结果 <= 估计容量，不能要求相等。 */
    nlen = NormalizeString(NormalizationKC, wsrc, wlen, NULL, 0);
    if (nlen <= 0) {
        free(wsrc);
        return VTY_E_INVALID;
    }
    wdst = (wchar_t *)malloc(((size_t)nlen + 1u) * sizeof(wchar_t));
    if (wdst == NULL) {
        free(wsrc);
        return VTY_E_RESOURCE;
    }
    nlen = NormalizeString(NormalizationKC, wsrc, wlen, wdst, nlen);
    if (nlen <= 0) {
        free(wsrc); free(wdst);
        return VTY_E_INVALID;
    }
    free(wsrc);

    u8len = WideCharToMultiByte(CP_UTF8, 0, wdst, nlen, NULL, 0, NULL, NULL);
    if (u8len <= 0) {
        free(wdst);
        return VTY_E_INVALID;
    }
    dst = (uint8_t *)malloc((size_t)u8len);
    if (dst == NULL) {
        free(wdst);
        return VTY_E_RESOURCE;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, wdst, nlen, (char *)dst, u8len,
                            NULL, NULL) != u8len) {
        free(wdst); free(dst);
        return VTY_E_INVALID;
    }
    free(wdst);

    *out = dst;
    *out_len = (size_t)u8len;
    return VTY_OK;
}

int vty_name_index(const uint8_t mdek[VTY_KEY_BYTES],
                   const uint8_t module_uuid[VTY_UUID_BYTES],
                   const uint8_t *name, size_t name_len,
                   uint8_t out[VTY_HASH_BYTES])
{
    uint8_t info[64];
    size_t label_len = strlen(VTY_DOMAIN_NAME_INDEX);
    uint8_t ik[VTY_KEY_BYTES];
    uint8_t *norm = NULL;
    size_t norm_len = 0;
    int rc;

    if (mdek == NULL || module_uuid == NULL || name == NULL || out == NULL) {
        return VTY_E_INVALID;
    }
    if (label_len + VTY_UUID_BYTES > sizeof(info)) return VTY_E_INVALID;

    memcpy(info, VTY_DOMAIN_NAME_INDEX, label_len);
    memcpy(info + label_len, module_uuid, VTY_UUID_BYTES);
    rc = vty_hkdf_expand(ik, mdek, info, label_len + VTY_UUID_BYTES);
    if (rc != VTY_OK) {
        vty_secure_zero(ik, sizeof(ik));
        return rc;
    }

    rc = nfkc(name, name_len, &norm, &norm_len);
    if (rc == VTY_OK) {
        rc = vty_hmac_sha256(out, ik, VTY_KEY_BYTES, norm, norm_len);
    }

    if (norm != NULL) free(norm);
    vty_secure_zero(ik, sizeof(ik));
    vty_secure_zero(info, sizeof(info));
    return rc;
}
