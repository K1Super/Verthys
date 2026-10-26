/*
 * vty_chunk_v4.c — v4 分片与文件清单加密实现
 */
#include "vty_chunk_v4.h"
#include "vty_kdf.h"
#include "vty_util.h"

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
