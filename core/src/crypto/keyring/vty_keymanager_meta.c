/*
 * vty_keymanager_meta.c — A/B 元数据副本编解码、Keyring DataRoot 与载入
 */

#include "vty_keymanager_internal.h"

#define VTY_BODY_AAD_MAX 128u
#define VTY_BODY_NONCE VTY_NONCE_BYTES


/* body AAD = 域串 || uuid || epoch || generation || keyring_len || header_digest。
 * header_digest 绑定固定头与整段槽区，使“删槽/清标志/换 minor”无法
 * 只改明文头就生效。 */
static void body_aad(const uint8_t uuid[VTY_UUID_BYTES], uint64_t epoch,
                     uint64_t generation, uint32_t keyring_len,
                     const uint8_t digest[VTY_HASH_BYTES],
                     uint8_t out[VTY_BODY_AAD_MAX], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_KEYRING;
    size_t dlen = strlen(domain);
    size_t off = dlen;

    memcpy(out, domain, dlen);
    memcpy(out + off, uuid, VTY_UUID_BYTES); off += VTY_UUID_BYTES;
    vty_put_u64(out + off, epoch); off += 8u;
    vty_put_u64(out + off, generation); off += 8u;
    vty_put_u32(out + off, keyring_len); off += 4u;
    memcpy(out + off, digest, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    *out_len = off;
}

int vty_km_keyring_set_data_root(VtyKeyring *kr,
                                 const uint8_t hash[VTY_HASH_BYTES],
                                 const VtyDataRootLocator *loc)
{
    uint8_t enc[VTY_DATA_ROOT_BYTES];
    uint32_t i;
    int rc;

    rc = vty_data_root_encode(loc, enc);
    if (rc != VTY_OK) return rc;

    for (i = 0; i < kr->count; i++) {
        if (kr->entries[i].kind == VTY_KEYKIND_DATA_ROOT) {
            kr->entries[i].id_len = VTY_DATA_ROOT_BYTES;
            memcpy(kr->entries[i].id, enc, VTY_DATA_ROOT_BYTES);
            memcpy(kr->entries[i].key, hash, VTY_HASH_BYTES);
            return VTY_OK;
        }
    }
    if (kr->count >= VTY_KEYRING_MAX_ENTRIES) return VTY_E_RESOURCE;
    memset(&kr->entries[kr->count], 0, sizeof(kr->entries[0]));
    kr->entries[kr->count].kind = VTY_KEYKIND_DATA_ROOT;
    kr->entries[kr->count].id_len = VTY_DATA_ROOT_BYTES;
    memcpy(kr->entries[kr->count].id, enc, VTY_DATA_ROOT_BYTES);
    memcpy(kr->entries[kr->count].key, hash, VTY_HASH_BYTES);
    kr->count++;
    return VTY_OK;
}

int vty_km_keyring_take_data_root(const VtyKeyring *kr,
                                  const uint8_t uuid[VTY_UUID_BYTES], uint64_t epoch,
                                  VtyDataRootLocator *loc,
                                  uint8_t hash[VTY_HASH_BYTES])
{
    VtyKeyEntry e;
    uint8_t expect[VTY_HASH_BYTES];
    int rc;

    memset(&e, 0, sizeof(e));
    rc = vty_keyring_find_entry(kr, VTY_KEYKIND_DATA_ROOT, NULL, 0, &e);
    if (rc != VTY_OK) return VTY_E_CORRUPT;
    if (e.id_len != VTY_DATA_ROOT_BYTES) return VTY_E_CORRUPT;
    rc = vty_data_root_decode(e.id, loc);
    if (rc != VTY_OK) return rc;
    memcpy(hash, e.key, VTY_HASH_BYTES);

    if (loc->root_node_id == 0u) {
        uint8_t empty[VTY_HASH_BYTES];
        rc = vty_store_empty_root(uuid, epoch, empty);
        if (rc != VTY_OK) return rc;
        rc = vty_store_data_root(uuid, epoch, empty, expect);
        if (rc != VTY_OK) return rc;
        if (vty_ct_equal(expect, hash, VTY_HASH_BYTES) != 0) return VTY_E_CORRUPT;
    }
    return VTY_OK;
}

/* 构建一份完整 meta copy（header+slots+body），用于创建或保存。 */
int vty_km_build_meta_copy(const VtyVault *v, uint8_t *copy, size_t *body_len_out)
{
    uint8_t plain[VTY_KEYRING_MAX_BYTES];
    uint8_t aad[VTY_BODY_AAD_MAX];
    uint8_t digest[VTY_HASH_BYTES];
    size_t plain_len = 0;
    size_t slots_len = 0;
    size_t header_len;
    size_t body_len;
    size_t aad_len = 0;
    size_t ct_len = 0;
    uint32_t i;
    int rc;

    if (v == NULL || copy == NULL || body_len_out == NULL) return VTY_E_INVALID;

    rc = vty_keyring_serialize(&v->keyring, plain, sizeof(plain), &plain_len);
    if (rc != VTY_OK) return rc;
    for (i = 0; i < v->slot_count; i++) {
        slots_len += vty_slot_serialized_len(&v->slots[i]);
    }
    header_len = VTY_HEADER_FIXED_BYTES + slots_len + VTY_HEADER_HASH_BYTES;
    body_len = VTY_BODY_NONCE + plain_len + VTY_TAG_BYTES;
    if (header_len > VTY_META_COPY_BYTES ||
        header_len + body_len > VTY_META_COPY_BYTES) {
        vty_secure_zero(plain, sizeof(plain));
        return VTY_E_RESOURCE;
    }

    memset(copy, 0, VTY_META_COPY_BYTES);
    {
        VtyHeader h = v->header;
        h.header_len = (uint16_t)header_len;
        h.slot_count = (uint16_t)v->slot_count;
        h.keyring_len = (uint32_t)plain_len;
        rc = vty_header_write_fixed(&h, copy, VTY_META_COPY_BYTES);
        if (rc != VTY_OK) goto out;
    }

    {
        size_t off = VTY_HEADER_FIXED_BYTES;
        for (i = 0; i < v->slot_count; i++) {
            size_t w = 0;
            rc = vty_slot_write(&v->slots[i], i, &v->header, copy + off,
                                header_len - off, &w);
            if (rc != VTY_OK) goto out;
            off += w;
        }
    }

    rc = vty_header_finalize(copy, header_len);
    if (rc != VTY_OK) goto out;
    rc = vty_header_digest(copy, header_len, digest);
    if (rc != VTY_OK) goto out;

    body_aad(v->header.vault_uuid, v->header.epoch, v->header.generation,
             (uint32_t)plain_len, digest, aad, &aad_len);
    vty_random(copy + header_len, VTY_BODY_NONCE);
    rc = vty_aead_seal(v->kc, copy + header_len, aad, aad_len, plain, plain_len,
                       copy + header_len + VTY_BODY_NONCE,
                       VTY_META_COPY_BYTES - header_len - VTY_BODY_NONCE,
                       &ct_len);
    if (rc == VTY_OK) {
        if (ct_len != plain_len + VTY_TAG_BYTES) rc = VTY_E_CORRUPT;
        else *body_len_out = VTY_BODY_NONCE + ct_len;
    }

out:
    vty_secure_zero(plain, sizeof(plain));
    vty_secure_zero(aad, sizeof(aad));
    vty_secure_zero(digest, sizeof(digest));
    return rc;
}

int vty_km_parse_meta_copy(uint8_t *header_buf, uint32_t index, VtyMetaCopy *out)
{
    VtyMetaCopy c;
    size_t body_len;
    int rc;

    if (header_buf == NULL || out == NULL) return VTY_E_INVALID;
    memset(&c, 0, sizeof(c));
    c.index = index;
    c.header_buf = header_buf;

    rc = vty_header_parse(header_buf, VTY_META_COPY_BYTES, &c.h);
    if (rc != VTY_OK) return rc;
    if (c.h.keyring_len == 0u) return VTY_E_CORRUPT;

    body_len = VTY_BODY_NONCE + (size_t)c.h.keyring_len + VTY_TAG_BYTES;
    if ((size_t)c.h.header_len + body_len > VTY_META_COPY_BYTES) {
        return VTY_E_CORRUPT;
    }

    rc = vty_slots_parse_all(header_buf, c.h.header_len, &c.h,
                             c.slots, VTY_MAX_SLOTS, &c.slot_count);
    if (rc != VTY_OK) return rc;
    if (c.slot_count != c.h.slot_count) return VTY_E_CORRUPT;

    rc = vty_header_digest(header_buf, c.h.header_len, c.digest);
    if (rc != VTY_OK) return rc;

    c.body = header_buf + c.h.header_len;
    c.body_len = body_len;
    c.valid = 1;
    *out = c;
    return VTY_OK;
}

int vty_km_open_body_copy(const VtyHeader *h, const uint8_t digest[VTY_HASH_BYTES],
                          const uint8_t *body, size_t body_len,
                          const uint8_t kc[VTY_KEY_BYTES], VtyKeyring *out)
{
    uint8_t plain[VTY_KEYRING_MAX_BYTES];
    uint8_t aad[VTY_BODY_AAD_MAX];
    uint8_t check[VTY_KEY_BYTES];
    size_t aad_len = 0;
    size_t plain_len = 0;
    int rc;

    if (h == NULL || digest == NULL || body == NULL || out == NULL || kc == NULL) {
        return VTY_E_INVALID;
    }
    if (body_len != VTY_BODY_NONCE + (size_t)h->keyring_len + VTY_TAG_BYTES) {
        return VTY_E_CORRUPT;
    }

    body_aad(h->vault_uuid, h->epoch, h->generation, h->keyring_len,
             digest, aad, &aad_len);
    rc = vty_aead_open(kc, body, aad, aad_len,
                       body + VTY_BODY_NONCE, body_len - VTY_BODY_NONCE,
                       plain, sizeof(plain), &plain_len);
    if (rc == VTY_OK) {
        rc = vty_keyring_parse(plain, plain_len, out);
    }
    if (rc == VTY_OK) {
        memset(check, 0, sizeof(check));
        rc = vty_keyring_find(out, VTY_KEYKIND_KC, NULL, 0, check);
        if (rc == VTY_OK) {
            if (vty_ct_equal(check, kc, VTY_KEY_BYTES) != 0) rc = VTY_E_KEY_INVALID;
        }
        vty_secure_zero(check, sizeof(check));
    }

    vty_secure_zero(plain, sizeof(plain));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

int vty_km_load_meta(const char *path, uint8_t **meta_out, uint64_t *file_size,
                     VtyMetaCopy copies[VTY_META_COPIES])
{
    uint8_t *meta;
    uint32_t i;
    int first_error = VTY_OK;
    int valid_count = 0;

    if (path == NULL || meta_out == NULL || file_size == NULL || copies == NULL) {
        return VTY_E_INVALID;
    }
    *meta_out = NULL;
    memset(copies, 0, sizeof(VtyMetaCopy) * VTY_META_COPIES);

    meta = (uint8_t *)vty_alloc(VTY_DATA_OFFSET);
    if (meta == NULL) return VTY_E_RESOURCE;
    if (vty_km_read_range(path, 0, meta, VTY_DATA_OFFSET, file_size) != VTY_OK) {
        vty_free(meta, VTY_DATA_OFFSET);
        return VTY_E_INVALID;
    }

    for (i = 0; i < VTY_META_COPIES; i++) {
        int rc = vty_km_parse_meta_copy(meta + (size_t)i * VTY_META_COPY_BYTES, i,
                                 &copies[i]);
        if (rc == VTY_OK) {
            valid_count++;
        } else if (first_error == VTY_OK) {
            first_error = rc;
        }
    }
    if (valid_count == 0) {
        vty_free(meta, VTY_DATA_OFFSET);
        return first_error == VTY_OK ? VTY_E_CORRUPT : first_error;
    }

    /* 同代不同内容意味着两份副本被分叉写入；无法判断哪份是真实提交，
     * 只能拒绝，不能按“看起来更新”的一方继续。 */
    if (copies[0].valid && copies[1].valid &&
        copies[0].h.generation == copies[1].h.generation) {
        if (memcmp(copies[0].digest, copies[1].digest, VTY_HASH_BYTES) != 0 ||
            copies[0].body_len != copies[1].body_len ||
            memcmp(copies[0].body, copies[1].body, copies[0].body_len) != 0) {
            /* 同代分叉：头/槽或 body 任一不同都无法判定真实提交。 */
            vty_free(meta, VTY_DATA_OFFSET);
            return VTY_E_CORRUPT;
        }
    }

    if (copies[1].valid &&
        (!copies[0].valid || copies[1].h.generation > copies[0].h.generation)) {
        VtyMetaCopy tmp = copies[0];
        copies[0] = copies[1];
        copies[1] = tmp;
    }

    *meta_out = meta;
    return VTY_OK;
}
