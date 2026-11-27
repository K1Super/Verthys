/*
 * vty_chunk.c — 分片与文件清单加密实现
 */
#include "vty_chunk.h"
#include "vty_kdf.h"
#include "vty_util.h"

#include <sodium.h>
#include <string.h>

#define CHUNK_PREFIX (VTY_UUID_BYTES + 4u + 4u + 4u)

static int derive(const uint8_t mdek[VTY_KEY_BYTES], const char *label,
                  const uint8_t *tail, size_t tail_len,
                  uint8_t out[VTY_KEY_BYTES])
{
    uint8_t info[64];
    size_t llen = strlen(label);
    if (llen + tail_len > sizeof(info)) return VTY_E_INVALID;
    memcpy(info, label, llen);
    if (tail_len != 0) memcpy(info + llen, tail, tail_len);
    return vty_hkdf_expand(out, mdek, info, llen + tail_len);
}

static int chunk_aad(const uint8_t file_uuid[VTY_UUID_BYTES],
                     uint32_t seq, uint32_t total, uint32_t pt_len,
                     uint8_t out[64], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_CHUNK;
    size_t dlen = strlen(domain);

    memcpy(out, domain, dlen);
    memcpy(out + dlen, file_uuid, VTY_UUID_BYTES);
    vty_put_u32(out + dlen + VTY_UUID_BYTES, seq);
    vty_put_u32(out + dlen + VTY_UUID_BYTES + 4u, total);
    vty_put_u32(out + dlen + VTY_UUID_BYTES + 8u, pt_len);
    *out_len = dlen + VTY_UUID_BYTES + 12u;
    return VTY_OK;
}

int vty_chunk_seal(const uint8_t mdek[VTY_KEY_BYTES],
                   const uint8_t file_uuid[VTY_UUID_BYTES],
                   uint32_t seq, uint32_t total, uint64_t epoch,
                   const uint8_t *pt, size_t pt_len,
                   uint8_t **out, size_t *out_len)
{
    uint8_t ck[VTY_KEY_BYTES];
    uint8_t tail[VTY_UUID_BYTES + 12u];
    uint8_t aad[64];
    size_t aad_len = 0;
    size_t total_len;
    uint8_t *buf;
    size_t ct_len = 0;
    int rc;

    if (mdek == NULL || file_uuid == NULL || out == NULL || out_len == NULL) {
        return VTY_E_INVALID;
    }
    if (pt == NULL && pt_len != 0) return VTY_E_INVALID;
    if (pt_len > VTY_CHUNK_MAX_PT) return VTY_E_INVALID;
    if (total == 0 || seq >= total) return VTY_E_INVALID;

    memcpy(tail, file_uuid, VTY_UUID_BYTES);
    vty_put_u32(tail + VTY_UUID_BYTES, seq);
    vty_put_u64(tail + VTY_UUID_BYTES + 4u, epoch);
    rc = derive(mdek, VTY_DOMAIN_CHUNK, tail, sizeof(tail), ck);
    if (rc != VTY_OK) {
        vty_secure_zero(ck, sizeof(ck));
        return rc;
    }

    total_len = CHUNK_PREFIX + VTY_NONCE_BYTES + pt_len + VTY_TAG_BYTES;
    buf = (uint8_t *)vty_alloc(total_len);
    if (buf == NULL) {
        vty_secure_zero(ck, sizeof(ck));
        return VTY_E_RESOURCE;
    }

    memcpy(buf, file_uuid, VTY_UUID_BYTES);
    vty_put_u32(buf + VTY_UUID_BYTES, seq);
    vty_put_u32(buf + VTY_UUID_BYTES + 4u, total);
    vty_put_u32(buf + VTY_UUID_BYTES + 8u, (uint32_t)pt_len);
    vty_random(buf + CHUNK_PREFIX, VTY_NONCE_BYTES);

    chunk_aad(file_uuid, seq, total, (uint32_t)pt_len, aad, &aad_len);
    rc = vty_aead_seal(ck, buf + CHUNK_PREFIX, aad, aad_len, pt, pt_len,
                       buf + CHUNK_PREFIX + VTY_NONCE_BYTES,
                       total_len - CHUNK_PREFIX - VTY_NONCE_BYTES, &ct_len);
    if (rc == VTY_OK && ct_len == pt_len + VTY_TAG_BYTES) {
        *out = buf;
        *out_len = total_len;
        buf = NULL;
    } else if (rc == VTY_OK) {
        rc = VTY_E_AEAD;
    }

    if (buf != NULL) vty_free(buf, total_len);
    vty_secure_zero(ck, sizeof(ck));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

int vty_chunk_open(const uint8_t mdek[VTY_KEY_BYTES],
                   const uint8_t file_uuid[VTY_UUID_BYTES],
                   uint32_t seq, uint32_t total, uint64_t epoch,
                   const uint8_t *in, size_t in_len,
                   uint8_t **pt, size_t *pt_len)
{
    uint8_t ck[VTY_KEY_BYTES];
    uint8_t tail[VTY_UUID_BYTES + 12u];
    uint8_t aad[64];
    size_t aad_len = 0;
    uint32_t stored_seq, stored_total, stored_len;
    uint8_t *buf;
    size_t out_len = 0;
    int rc;

    if (mdek == NULL || file_uuid == NULL || in == NULL || pt == NULL || pt_len == NULL) {
        return VTY_E_INVALID;
    }
    *pt = NULL; *pt_len = 0;
    if (in_len < CHUNK_PREFIX + VTY_NONCE_BYTES + VTY_TAG_BYTES) return VTY_E_INVALID;

    if (memcmp(in, file_uuid, VTY_UUID_BYTES) != 0) return VTY_E_KEY_INVALID;
    stored_seq = vty_get_u32(in + VTY_UUID_BYTES);
    stored_total = vty_get_u32(in + VTY_UUID_BYTES + 4u);
    stored_len = vty_get_u32(in + VTY_UUID_BYTES + 8u);
    if (stored_seq != seq || stored_total != total) return VTY_E_KEY_INVALID;
    if (stored_len > VTY_CHUNK_MAX_PT) return VTY_E_INVALID;
    if (in_len != (size_t)CHUNK_PREFIX + VTY_NONCE_BYTES + stored_len + VTY_TAG_BYTES) {
        return VTY_E_INVALID;
    }

    memcpy(tail, file_uuid, VTY_UUID_BYTES);
    vty_put_u32(tail + VTY_UUID_BYTES, seq);
    vty_put_u64(tail + VTY_UUID_BYTES + 4u, epoch);
    rc = derive(mdek, VTY_DOMAIN_CHUNK, tail, sizeof(tail), ck);
    if (rc != VTY_OK) {
        vty_secure_zero(ck, sizeof(ck));
        return rc;
    }

    buf = (uint8_t *)vty_alloc(stored_len != 0 ? stored_len : 1u);
    if (buf == NULL) {
        vty_secure_zero(ck, sizeof(ck));
        return VTY_E_RESOURCE;
    }

    chunk_aad(file_uuid, seq, total, stored_len, aad, &aad_len);
    rc = vty_aead_open(ck, in + CHUNK_PREFIX, aad, aad_len,
                       in + CHUNK_PREFIX + VTY_NONCE_BYTES,
                       in_len - CHUNK_PREFIX - VTY_NONCE_BYTES,
                       buf, stored_len, &out_len);
    if (rc == VTY_OK && out_len == stored_len) {
        *pt = buf;
        *pt_len = stored_len;
        buf = NULL;
    } else if (rc == VTY_OK) {
        rc = VTY_E_INVALID;
    }

    if (buf != NULL) vty_free(buf, stored_len != 0 ? stored_len : 1u);
    vty_secure_zero(ck, sizeof(ck));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

/* 内联分片的最小 base64 长度：信封最短 68B → base64 92 字符；留出余量。 */
#define VTY_EMBEDDED_MIN_B64 64u
#define VTY_EMBEDDED_MARKER "\"chunkDataB64\""

static int embedded_b64_char(uint8_t c)
{
    return (c >= (uint8_t)'A' && c <= (uint8_t)'Z')
        || (c >= (uint8_t)'a' && c <= (uint8_t)'z')
        || (c >= (uint8_t)'0' && c <= (uint8_t)'9')
        || c == (uint8_t)'+' || c == (uint8_t)'/' || c == (uint8_t)'=';
}

/* 定位 "chunkDataB64":[ ... ] 的数组区间；只在该区间内扫描 base64，
 * 避免对缩略图/密钥材料等其它字段做无谓的解码与认证尝试。 */
static int embedded_array_bounds(const uint8_t *json, size_t n,
                                 size_t *start, size_t *end)
{
    const size_t mlen = sizeof(VTY_EMBEDDED_MARKER) - 1u;
    size_t i;
    if (n < mlen) return 0;
    for (i = 0; i + mlen <= n; i++) {
        size_t j;
        if (memcmp(json + i, VTY_EMBEDDED_MARKER, mlen) != 0) continue;
        j = i + mlen;
        while (j < n && (json[j] == ' ' || json[j] == '\t'
                         || json[j] == '\r' || json[j] == '\n')) {
            j++;
        }
        if (j >= n || json[j] != ':') continue;
        j++;
        while (j < n && (json[j] == ' ' || json[j] == '\t'
                         || json[j] == '\r' || json[j] == '\n')) {
            j++;
        }
        if (j >= n || json[j] != '[') continue;
        j++;
        *start = j;
        while (j < n && json[j] != ']') j++;
        if (j >= n) return 0;
        *end = j;
        return 1;
    }
    return 0;
}

int vty_chunk_rewrap_embedded(const uint8_t old_mdek[VTY_KEY_BYTES],
                              const uint8_t new_mdek[VTY_KEY_BYTES],
                              uint64_t old_epoch,
                              uint64_t new_epoch,
                              const uint8_t *json, size_t json_len,
                              uint8_t **out, size_t *out_len,
                              int *rewrapped)
{
    uint8_t *dst = NULL;
    size_t copied = 0;
    size_t i = 0;
    size_t array_end = 0;
    int rc = VTY_OK;

    /* 循环内失败清理统一走 out：这些缓冲必须在函数作用域声明。 */
    uint8_t *bin = NULL;
    size_t bin_cap = 0;
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    uint8_t *sealed = NULL;
    size_t sealed_len = 0;
    char *enc = NULL;
    size_t enc_cap = 0;

    if (old_mdek == NULL || new_mdek == NULL || json == NULL
        || out == NULL || out_len == NULL || rewrapped == NULL) {
        return VTY_E_INVALID;
    }
    *out = NULL;
    *out_len = 0;
    *rewrapped = 0;
    if (json_len < 2u || json[0] != (uint8_t)'{') return VTY_OK;
    if (!embedded_array_bounds(json, json_len, &i, &array_end)) return VTY_OK;

    while (i < array_end) {
        size_t start, run_len, bin_len = 0, enc_len;
        uint8_t file_uuid[VTY_UUID_BYTES];
        uint32_t seq, total, stored_len;

        if (!embedded_b64_char(json[i])) { i++; continue; }
        start = i;
        while (i < array_end && embedded_b64_char(json[i])) i++;
        run_len = i - start;
        if (run_len < VTY_EMBEDDED_MIN_B64) continue;

        bin_cap = (run_len / 4u + 1u) * 3u;
        bin = (uint8_t *)vty_alloc(bin_cap);
        if (bin == NULL) { rc = VTY_E_RESOURCE; goto out; }
        if (sodium_base642bin(bin, bin_cap, (const char *)(json + start), run_len,
                              NULL, &bin_len, NULL,
                              sodium_base64_VARIANT_ORIGINAL) != 0) {
            vty_free(bin, bin_cap);
            bin = NULL;
            continue;
        }
        if (bin_len < CHUNK_PREFIX + VTY_NONCE_BYTES + VTY_TAG_BYTES) {
            vty_free(bin, bin_cap);
            bin = NULL;
            continue;
        }
        seq = vty_get_u32(bin + VTY_UUID_BYTES);
        total = vty_get_u32(bin + VTY_UUID_BYTES + 4u);
        stored_len = vty_get_u32(bin + VTY_UUID_BYTES + 8u);
        if (total == 0u || seq >= total || (size_t)stored_len > VTY_CHUNK_MAX_PT
            || bin_len != (size_t)CHUNK_PREFIX + VTY_NONCE_BYTES + stored_len
                              + VTY_TAG_BYTES) {
            vty_free(bin, bin_cap);
            bin = NULL;
            continue;
        }
        memcpy(file_uuid, bin, VTY_UUID_BYTES);

        /* 只换封能以旧 MDEK 认证的内联分片：缩略图、v2 口令分片等
         * 认证失败后原样保留，不改变其字节。 */
        rc = vty_chunk_open(old_mdek, file_uuid, seq, total, old_epoch, bin, bin_len,
                            &pt, &pt_len);
        if (rc != VTY_OK) {
            vty_free(bin, bin_cap);
            bin = NULL;
            if (rc == VTY_E_RESOURCE) goto out;
            rc = VTY_OK;
            continue;
        }
        vty_free(bin, bin_cap);
        bin = NULL;

        rc = vty_chunk_seal(new_mdek, file_uuid, seq, total, new_epoch,
                            pt, pt_len, &sealed, &sealed_len);
        vty_secure_zero(pt, pt_len != 0 ? pt_len : 1u);
        vty_free(pt, pt_len != 0 ? pt_len : 1u);
        pt = NULL;
        if (rc != VTY_OK) goto out;

        enc_cap = sodium_base64_encoded_len(sealed_len, sodium_base64_VARIANT_ORIGINAL);
        enc = (char *)vty_alloc(enc_cap);
        if (enc == NULL) { rc = VTY_E_RESOURCE; goto out; }
        if (sodium_bin2base64(enc, enc_cap, sealed, sealed_len,
                              sodium_base64_VARIANT_ORIGINAL) == NULL) {
            rc = VTY_E_INVALID;
            goto out;
        }
        enc_len = strlen(enc);
        vty_secure_zero(sealed, sealed_len);
        vty_free(sealed, sealed_len);
        sealed = NULL;
        if (enc_len != run_len) {
            /* 信封换封不改变明文长度，base64 长度理论恒定；异常则不改写。 */
            vty_free(enc, enc_cap);
            enc = NULL;
            continue;
        }

        if (dst == NULL) {
            dst = (uint8_t *)vty_alloc(json_len);
            if (dst == NULL) { rc = VTY_E_RESOURCE; goto out; }
            memcpy(dst, json, start);
            copied = start;
        } else if (start > copied) {
            memcpy(dst + copied, json + copied, start - copied);
        }
        memcpy(dst + start, enc, enc_len);
        copied = start + run_len;
        vty_free(enc, enc_cap);
        enc = NULL;
    }

    if (dst == NULL) return VTY_OK;
    if (copied < json_len) {
        memcpy(dst + copied, json + copied, json_len - copied);
    }
    *out = dst;
    *out_len = json_len;
    *rewrapped = 1;
    return VTY_OK;

out:
    if (bin != NULL) vty_free(bin, bin_cap);
    if (pt != NULL) vty_free(pt, pt_len != 0 ? pt_len : 1u);
    if (sealed != NULL) vty_free(sealed, sealed_len != 0 ? sealed_len : 1u);
    if (enc != NULL) vty_free(enc, enc_cap);
    if (dst != NULL) vty_free(dst, json_len);
    return rc;
}

int vty_chunk_id(const uint8_t mdek[VTY_KEY_BYTES],
                 const uint8_t file_uuid[VTY_UUID_BYTES],
                 uint32_t seq, uint8_t out[VTY_HASH_BYTES])
{
    uint8_t ik[VTY_KEY_BYTES];
    uint8_t info[64];
    size_t llen = strlen(VTY_DOMAIN_CHUNK_ID);
    uint8_t msg[VTY_UUID_BYTES + 4u];
    int rc;

    if (mdek == NULL || file_uuid == NULL || out == NULL) return VTY_E_INVALID;
    if (llen + VTY_UUID_BYTES > sizeof(info)) return VTY_E_INVALID;

    memcpy(info, VTY_DOMAIN_CHUNK_ID, llen);
    memcpy(info + llen, file_uuid, VTY_UUID_BYTES);
    rc = vty_hkdf_expand(ik, mdek, info, llen + VTY_UUID_BYTES);
    if (rc != VTY_OK) {
        vty_secure_zero(ik, sizeof(ik));
        return rc;
    }
    memcpy(msg, file_uuid, VTY_UUID_BYTES);
    vty_put_u32(msg + VTY_UUID_BYTES, seq);
    rc = vty_hmac_sha256(out, ik, VTY_KEY_BYTES, msg, sizeof(msg));

    vty_secure_zero(ik, sizeof(ik));
    vty_secure_zero(info, sizeof(info));
    return rc;
}

static int manifest_aad(const uint8_t file_uuid[VTY_UUID_BYTES], uint64_t epoch,
                        uint8_t out[48], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_MANIFEST;
    size_t dlen = strlen(domain);

    memcpy(out, domain, dlen);
    memcpy(out + dlen, file_uuid, VTY_UUID_BYTES);
    vty_put_u64(out + dlen + VTY_UUID_BYTES, epoch);
    *out_len = dlen + VTY_UUID_BYTES + 8u;
    return VTY_OK;
}

int vty_manifest_seal(const uint8_t mdek[VTY_KEY_BYTES],
                      const uint8_t file_uuid[VTY_UUID_BYTES],
                      uint64_t epoch,
                      const uint8_t pt_hash[VTY_HASH_BYTES],
                      uint32_t total,
                      const uint8_t *chunk_ids,
                      uint8_t **out, size_t *out_len)
{
    uint8_t mk[VTY_KEY_BYTES];
    uint8_t aad[48];
    size_t aad_len = 0;
    uint8_t *plain = NULL;
    uint8_t *buf = NULL;
    size_t plain_len;
    size_t ct_len = 0;
    uint8_t tail[VTY_UUID_BYTES + 8u];
    int rc;

    if (mdek == NULL || file_uuid == NULL || pt_hash == NULL ||
        out == NULL || out_len == NULL) {
        return VTY_E_INVALID;
    }
    if (total == 0 || total > VTY_MANIFEST_MAX_CHUNKS) return VTY_E_INVALID;
    if (chunk_ids == NULL) return VTY_E_INVALID;

    memcpy(tail, file_uuid, VTY_UUID_BYTES);
    vty_put_u64(tail + VTY_UUID_BYTES, epoch);
    rc = derive(mdek, VTY_DOMAIN_MANIFEST, tail, sizeof(tail), mk);
    if (rc != VTY_OK) {
        vty_secure_zero(mk, sizeof(mk));
        return rc;
    }

    plain_len = VTY_UUID_BYTES + VTY_HASH_BYTES + 4u + (size_t)total * VTY_HASH_BYTES;
    plain = (uint8_t *)vty_alloc(plain_len);
    buf = (uint8_t *)vty_alloc(VTY_NONCE_BYTES + plain_len + VTY_TAG_BYTES);
    if (plain == NULL || buf == NULL) {
        rc = VTY_E_RESOURCE;
        goto done;
    }

    memcpy(plain, file_uuid, VTY_UUID_BYTES);
    memcpy(plain + VTY_UUID_BYTES, pt_hash, VTY_HASH_BYTES);
    vty_put_u32(plain + VTY_UUID_BYTES + VTY_HASH_BYTES, total);
    memcpy(plain + VTY_UUID_BYTES + VTY_HASH_BYTES + 4u,
           chunk_ids, (size_t)total * VTY_HASH_BYTES);

    vty_random(buf, VTY_NONCE_BYTES);
    manifest_aad(file_uuid, epoch, aad, &aad_len);
    rc = vty_aead_seal(mk, buf, aad, aad_len, plain, plain_len,
                       buf + VTY_NONCE_BYTES, plain_len + VTY_TAG_BYTES, &ct_len);
    if (rc == VTY_OK && ct_len == plain_len + VTY_TAG_BYTES) {
        *out = buf;
        *out_len = VTY_NONCE_BYTES + plain_len + VTY_TAG_BYTES;
        buf = NULL;
    } else if (rc == VTY_OK) {
        rc = VTY_E_AEAD;
    }

done:
    if (plain != NULL) vty_free(plain, plain_len);
    if (buf != NULL) vty_free(buf, VTY_NONCE_BYTES + plain_len + VTY_TAG_BYTES);
    vty_secure_zero(mk, sizeof(mk));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

int vty_manifest_open(const uint8_t mdek[VTY_KEY_BYTES],
                      const uint8_t file_uuid[VTY_UUID_BYTES],
                      uint64_t epoch,
                      const uint8_t *in, size_t in_len,
                      uint8_t pt_hash[VTY_HASH_BYTES],
                      uint32_t *total,
                      uint8_t **chunk_ids)
{
    uint8_t mk[VTY_KEY_BYTES];
    uint8_t aad[48];
    size_t aad_len = 0;
    uint8_t *plain = NULL;
    uint8_t *ids = NULL;
    uint8_t tail[VTY_UUID_BYTES + 8u];
    size_t plain_len, pt_len = 0;
    uint32_t n = 0;
    int rc;

    if (mdek == NULL || file_uuid == NULL || in == NULL ||
        pt_hash == NULL || total == NULL || chunk_ids == NULL) {
        return VTY_E_INVALID;
    }
    *total = 0;
    *chunk_ids = NULL;
    if (in_len < VTY_NONCE_BYTES + VTY_UUID_BYTES + VTY_HASH_BYTES + 4u + VTY_TAG_BYTES) {
        return VTY_E_INVALID;
    }

    plain_len = in_len - VTY_NONCE_BYTES - VTY_TAG_BYTES;
    if (plain_len < VTY_UUID_BYTES + VTY_HASH_BYTES + 4u) return VTY_E_INVALID;
    /* 明文长度上限按清单最大值推导，避免伪造超长输入触发巨量分配 */
    if (plain_len > VTY_UUID_BYTES + VTY_HASH_BYTES + 4u +
                    (size_t)VTY_MANIFEST_MAX_CHUNKS * VTY_HASH_BYTES) {
        return VTY_E_INVALID;
    }

    memcpy(tail, file_uuid, VTY_UUID_BYTES);
    vty_put_u64(tail + VTY_UUID_BYTES, epoch);
    rc = derive(mdek, VTY_DOMAIN_MANIFEST, tail, sizeof(tail), mk);
    if (rc != VTY_OK) {
        vty_secure_zero(mk, sizeof(mk));
        return rc;
    }

    plain = (uint8_t *)vty_alloc(plain_len);
    if (plain == NULL) {
        vty_secure_zero(mk, sizeof(mk));
        return VTY_E_RESOURCE;
    }

    manifest_aad(file_uuid, epoch, aad, &aad_len);
    rc = vty_aead_open(mk, in, aad, aad_len,
                       in + VTY_NONCE_BYTES, in_len - VTY_NONCE_BYTES,
                       plain, plain_len, &pt_len);
    if (rc == VTY_OK) {
        if (pt_len != plain_len ||
            memcmp(plain, file_uuid, VTY_UUID_BYTES) != 0) {
            rc = VTY_E_KEY_INVALID;
        }
    }
    if (rc == VTY_OK) {
        n = vty_get_u32(plain + VTY_UUID_BYTES + VTY_HASH_BYTES);
        if (n == 0 || n > VTY_MANIFEST_MAX_CHUNKS) {
            rc = VTY_E_INVALID;
        } else if (plain_len != VTY_UUID_BYTES + VTY_HASH_BYTES + 4u +
                               (size_t)n * VTY_HASH_BYTES) {
            rc = VTY_E_INVALID;
        } else {
            ids = (uint8_t *)vty_alloc((size_t)n * VTY_HASH_BYTES);
            if (ids == NULL) {
                rc = VTY_E_RESOURCE;
            } else {
                memcpy(pt_hash, plain + VTY_UUID_BYTES, VTY_HASH_BYTES);
                memcpy(ids, plain + VTY_UUID_BYTES + VTY_HASH_BYTES + 4u,
                       (size_t)n * VTY_HASH_BYTES);
                *total = n;
                *chunk_ids = ids;
                ids = NULL;
            }
        }
    }

    if (ids != NULL) vty_free(ids, (size_t)n * VTY_HASH_BYTES);
    if (plain != NULL) vty_free(plain, plain_len);
    vty_secure_zero(mk, sizeof(mk));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}
