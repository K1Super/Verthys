/*
 * vty_store_node.c — 目录节点编解码与加密节点读写
 */

#include "vty_store_internal.h"


void vty_st_node_free(VtyMemNode *n)
{
    uint32_t i;
    if (n == NULL) return;
    for (i = 0; i < n->n && i < VTY_STORE_ENTRY_MAX; i++) {
        if (n->e[i].val != NULL) {
            vty_secure_zero(n->e[i].val, n->e[i].val_len);
            vty_free(n->e[i].val, n->e[i].val_len);
            n->e[i].val = NULL;
        }
    }
    memset(n, 0, sizeof(*n));
}

int vty_st_node_plain_size(const VtyMemNode *n, size_t *out)
{
    size_t total = VTY_NODE_HDR_BYTES;
    uint32_t i;

    if (n == NULL || out == NULL) return VTY_E_INVALID;
    if (n->n == 0 || n->n > VTY_STORE_ENTRY_MAX) return VTY_E_INVALID;
    for (i = 0; i < n->n; i++) {
        if (n->e[i].key_len == 0 || n->e[i].key_len > VTY_STORE_KEY_MAX) {
            return VTY_E_CORRUPT;
        }
        if (n->type == VTY_NODE_LEAF) {
            total += 4u + n->e[i].key_len + n->e[i].val_len;
        } else {
            total += 2u + n->e[i].key_len + 8u + VTY_HASH_BYTES;
        }
    }
    *out = total;
    return total <= VTY_STORE_NODE_BYTES ? VTY_OK : VTY_E_RESOURCE;
}

static int node_serialize(const VtyMemNode *n, uint8_t *buf, size_t cap, size_t *out_len)
{
    size_t need;
    size_t off = 0;
    uint32_t i;
    int rc;

    rc = vty_st_node_plain_size(n, &need);
    if (rc != VTY_OK) return rc;
    if (need > cap) return VTY_E_INVALID;

    buf[off++] = VTY_NODE_VERSION;
    buf[off++] = n->level;
    buf[off++] = n->type;
    buf[off++] = 0;
    vty_put_u16(buf + off, n->n); off += 2;
    vty_put_u16(buf + off, 0); off += 2;
    vty_put_u64(buf + off, 0); off += 8;

    for (i = 0; i < n->n; i++) {
        const VtyMemEntry *e = &n->e[i];
        vty_put_u16(buf + off, e->key_len); off += 2;
        if (n->type == VTY_NODE_LEAF) {
            vty_put_u16(buf + off, (uint16_t)e->val_len); off += 2;
            memcpy(buf + off, e->key, e->key_len); off += e->key_len;
            if (e->val_len != 0) {
                memcpy(buf + off, e->val, e->val_len);
                off += e->val_len;
            }
        } else {
            vty_put_u64(buf + off, e->child_id); off += 8;
            memcpy(buf + off, e->child_hash, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
            memcpy(buf + off, e->key, e->key_len); off += e->key_len;
        }
    }
    if (off != need) return VTY_E_CORRUPT;
    *out_len = off;
    return VTY_OK;
}

int vty_st_key_cmp(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    size_t n = alen < blen ? alen : blen;
    int c = n != 0 ? memcmp(a, b, n) : 0;
    if (c != 0) return c;
    if (alen < blen) return -1;
    if (alen > blen) return 1;
    return 0;
}

static int node_parse(const uint8_t *buf, size_t len, uint8_t expected_level,
                      VtyMemNode *out)
{
    VtyMemNode n;
    size_t off = 0;
    uint16_t count;
    uint32_t i;

    if (buf == NULL || out == NULL) return VTY_E_INVALID;
    if (len < VTY_NODE_HDR_BYTES) return VTY_E_CORRUPT;
    memset(&n, 0, sizeof(n));
    if (buf[off++] != VTY_NODE_VERSION) return VTY_E_CORRUPT;
    n.level = buf[off++];
    n.type = buf[off++];
    if (buf[off++] != 0) return VTY_E_CORRUPT;
    count = vty_get_u16(buf + off); off += 2;
    if (vty_get_u16(buf + off) != 0) return VTY_E_CORRUPT;
    off += 2;
    if (vty_get_u64(buf + off) != 0) return VTY_E_CORRUPT;
    off += 8;

    if (n.level != expected_level) return VTY_E_CORRUPT;
    if (n.type != VTY_NODE_LEAF && n.type != VTY_NODE_INTERNAL) return VTY_E_CORRUPT;
    if (count == 0 || count > VTY_STORE_ENTRY_MAX) return VTY_E_CORRUPT;
    n.n = count;

    for (i = 0; i < count; i++) {
        VtyMemEntry *e = &n.e[i];
        uint16_t klen;
        if (off + 2 > len) goto corrupt;
        klen = vty_get_u16(buf + off); off += 2;
        if (klen == 0 || klen > VTY_STORE_KEY_MAX) goto corrupt;
        e->key_len = klen;

        if (n.type == VTY_NODE_LEAF) {
            uint16_t vlen;
            if (off + 2 > len) goto corrupt;
            vlen = vty_get_u16(buf + off); off += 2;
            if (off + klen + vlen > len) goto corrupt;
            memcpy(e->key, buf + off, klen); off += klen;
            e->val_len = vlen;
            if (vlen != 0) {
                e->val = (uint8_t *)vty_alloc(vlen);
                if (e->val == NULL) goto corrupt;
                memcpy(e->val, buf + off, vlen);
            }
            off += vlen;
        } else {
            if (off + 8 + VTY_HASH_BYTES + klen > len) goto corrupt;
            e->child_id = vty_get_u64(buf + off); off += 8;
            memcpy(e->child_hash, buf + off, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
            memcpy(e->key, buf + off, klen); off += klen;
        }

        if (i > 0 && vty_st_key_cmp(n.e[i - 1].key, n.e[i - 1].key_len,
                              e->key, e->key_len) >= 0) {
            goto corrupt;
        }
    }
    if (off != len) goto corrupt;
    *out = n;
    return VTY_OK;

corrupt:
    vty_st_node_free(&n);
    return VTY_E_CORRUPT;
}

static void dir_aad(uint64_t node_id, uint8_t level, uint32_t payload_len,
                    uint8_t out[128], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_DIR;
    size_t dlen = strlen(domain);
    size_t off = dlen;

    memcpy(out, domain, dlen);
    /* 数据区结构统一大端，避免跨平台解析差异。 */
    out[off++] = (uint8_t)(node_id >> 56);
    out[off++] = (uint8_t)(node_id >> 48);
    out[off++] = (uint8_t)(node_id >> 40);
    out[off++] = (uint8_t)(node_id >> 32);
    out[off++] = (uint8_t)(node_id >> 24);
    out[off++] = (uint8_t)(node_id >> 16);
    out[off++] = (uint8_t)(node_id >> 8);
    out[off++] = (uint8_t)node_id;
    out[off++] = level;
    out[off++] = (uint8_t)(payload_len >> 24);
    out[off++] = (uint8_t)(payload_len >> 16);
    out[off++] = (uint8_t)(payload_len >> 8);
    out[off++] = (uint8_t)payload_len;
    *out_len = off;
}

int vty_st_node_write(VtyStore *s, const VtyMemNode *n, VtyNodeRef *ref)
{
    uint8_t plain[VTY_STORE_NODE_BYTES];
    uint8_t aad[128];
    uint8_t *seg;
    uint8_t hash[VTY_HASH_BYTES];
    size_t plain_len = 0;
    size_t aad_len = 0;
    size_t ct_len = 0;
    size_t payload_len;
    size_t total;
    uint64_t id;
    VtySegmentHeader sh;
    int rc;

    if (s == NULL || n == NULL || ref == NULL) return VTY_E_INVALID;
    rc = node_serialize(n, plain, sizeof(plain), &plain_len);
    if (rc != VTY_OK) return rc;

    ct_len = plain_len + VTY_TAG_BYTES;
    payload_len = VTY_NONCE_BYTES + ct_len;
    total = VTY_SEG_HEADER_BYTES + payload_len;
    id = s->loc.data_end;

    seg = (uint8_t *)vty_alloc(total);
    if (seg == NULL) {
        vty_secure_zero(plain, sizeof(plain));
        return VTY_E_RESOURCE;
    }

    memset(&sh, 0, sizeof(sh));
    sh.type = VTY_SEG_DIR;
    sh.flags = 0;
    sh.payload_len = (uint32_t)payload_len;
    sh.seq = id;
    sh.id = n->level;
    rc = vty_segment_header_write(&sh, seg);
    if (rc != VTY_OK) goto out;

    vty_random(seg + VTY_SEG_HEADER_BYTES, VTY_NONCE_BYTES);
    dir_aad(id, n->level, (uint32_t)payload_len, aad, &aad_len);
    rc = vty_aead_seal(s->kdir, seg + VTY_SEG_HEADER_BYTES, aad, aad_len,
                       plain, plain_len,
                       seg + VTY_SEG_HEADER_BYTES + VTY_NONCE_BYTES,
                       total - VTY_SEG_HEADER_BYTES - VTY_NONCE_BYTES, &ct_len);
    if (rc != VTY_OK) goto out;
    if (ct_len != plain_len + VTY_TAG_BYTES) { rc = VTY_E_CORRUPT; goto out; }

    rc = vty_blake3_32(seg, total, hash);
    if (rc != VTY_OK) goto out;
    rc = vty_st_write_at(s->h, id, seg, total);
    if (rc != VTY_OK) goto out;

    s->loc.data_end = id + total;
    s->dirty = 1;

    memset(ref, 0, sizeof(*ref));
    ref->id = id;
    ref->level = n->level;
    memcpy(ref->hash, hash, VTY_HASH_BYTES);
    memcpy(ref->max_key, n->e[n->n - 1].key, n->e[n->n - 1].key_len);
    ref->max_len = n->e[n->n - 1].key_len;

out:
    vty_secure_zero(plain, sizeof(plain));
    vty_secure_zero(aad, sizeof(aad));
    vty_free(seg, total);
    return rc;
}

int vty_st_node_read(VtyStore *s, uint64_t id, uint8_t expected_level,
                     VtyMemNode *out, uint8_t hash_out[VTY_HASH_BYTES])
{
    uint8_t shbuf[VTY_SEG_HEADER_BYTES];
    VtySegmentHeader sh;
    uint8_t *seg = NULL;
    uint8_t plain[VTY_STORE_NODE_BYTES];
    uint8_t aad[128];
    uint8_t hash[VTY_HASH_BYTES];
    size_t aad_len = 0;
    size_t plain_len = 0;
    size_t total;
    int rc;

    if (s == NULL || out == NULL) return VTY_E_INVALID;
    if (id < VTY_DATA_OFFSET || id >= s->loc.data_end) return VTY_E_CORRUPT;
    if (s->loc.data_end - id < VTY_SEG_HEADER_BYTES) return VTY_E_CORRUPT;

    rc = vty_st_read_at(s->h, id, shbuf, sizeof(shbuf));
    if (rc != VTY_OK) return VTY_E_IO;
    rc = vty_segment_header_parse(shbuf, &sh);
    if (rc != VTY_OK) return rc;
    if (sh.type != VTY_SEG_DIR) return VTY_E_CORRUPT;
    if (sh.seq != id || sh.id != expected_level) return VTY_E_CORRUPT;
    total = VTY_SEG_HEADER_BYTES + (size_t)sh.payload_len;
    if (total > s->loc.data_end - id) return VTY_E_CORRUPT;

    seg = (uint8_t *)vty_alloc(total);
    if (seg == NULL) return VTY_E_RESOURCE;
    rc = vty_st_read_at(s->h, id, seg, total);
    if (rc != VTY_OK) goto out;
    rc = vty_blake3_32(seg, total, hash);
    if (rc != VTY_OK) goto out;

    dir_aad(id, expected_level, sh.payload_len, aad, &aad_len);
    rc = vty_aead_open(s->kdir, seg + VTY_SEG_HEADER_BYTES, aad, aad_len,
                       seg + VTY_SEG_HEADER_BYTES + VTY_NONCE_BYTES,
                       (size_t)sh.payload_len - VTY_NONCE_BYTES,
                       plain, sizeof(plain), &plain_len);
    if (rc != VTY_OK) goto out;
    rc = node_parse(plain, plain_len, expected_level, out);
    if (rc == VTY_OK && hash_out != NULL) memcpy(hash_out, hash, VTY_HASH_BYTES);

out:
    vty_secure_zero(plain, sizeof(plain));
    vty_secure_zero(aad, sizeof(aad));
    if (seg != NULL) vty_free(seg, total);
    return rc;
}
