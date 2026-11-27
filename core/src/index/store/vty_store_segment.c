/*
 * vty_store_segment.c — 追加段读写与擦除
 */

#include "vty_store_internal.h"


/* ------------------------------------------------------------------ *
 * 追加段（记录/分片）
 *
 * 段本身不再叠加 AEAD：记录/分片的机密性由各自的内层 AEAD 提供，
 * 完整性由 BLAKE3(段头+payload) 绑定到加密目录叶——若段被替换或
 * 搬移，叶中的 hash 必然失配。
 * ------------------------------------------------------------------ */
int vty_store_append_segment(VtyStore *s, uint8_t type, uint64_t seq, uint64_t id,
                             const uint8_t *payload, size_t payload_len,
                             VtySegmentLocator *out)
{
    uint8_t *seg = NULL;
    uint8_t hash[VTY_HASH_BYTES];
    size_t total;
    uint64_t offset;
    int rc;

    if (s == NULL || out == NULL) return VTY_E_INVALID;
    if (type != VTY_SEG_RECORD && type != VTY_SEG_CHUNK) return VTY_E_INVALID;
    if (payload == NULL && payload_len != 0) return VTY_E_INVALID;
    /* total_len 是 u32 字段：payload 必须给 32B 段头留出空间，否则
     * 写盘长度会被截断，目录引用到错误边界。 */
    if (payload_len > 0xFFFFFFFFu - VTY_SEG_HEADER_BYTES) return VTY_E_INVALID;
    total = VTY_SEG_HEADER_BYTES + payload_len;

    seg = (uint8_t *)vty_alloc(total);
    if (seg == NULL) return VTY_E_RESOURCE;
    {
        VtySegmentHeader sh;
        memset(&sh, 0, sizeof(sh));
        sh.type = type;
        sh.flags = 0;
        sh.payload_len = (uint32_t)payload_len;
        sh.seq = seq;
        sh.id = id;
        rc = vty_segment_header_write(&sh, seg);
        if (rc != VTY_OK) goto out;
    }
    if (payload_len != 0) memcpy(seg + VTY_SEG_HEADER_BYTES, payload, payload_len);
    rc = vty_blake3_32(seg, total, hash);
    if (rc != VTY_OK) goto out;

    /* 优先复用已删除段留下的空闲区；无可用区时由分配器追加。 */
    rc = vty_store_space_alloc(s, (uint64_t)total, &offset);
    if (rc != VTY_OK) goto out;
    rc = vty_st_write_at(s->h, offset, seg, total);
    if (rc != VTY_OK) goto out;

    s->dirty = 1;

    memset(out, 0, sizeof(*out));
    out->type = type;
    out->seq = seq;
    out->id = id;
    out->offset = offset;
    out->total_len = (uint32_t)total;
    memcpy(out->hash, hash, VTY_HASH_BYTES);

out:
    if (seg != NULL) vty_free(seg, total);
    return rc;
}

int vty_store_read_segment(VtyStore *s, const VtySegmentLocator *loc,
                           uint8_t **payload, size_t *payload_len)
{
    uint8_t shbuf[VTY_SEG_HEADER_BYTES];
    VtySegmentHeader sh;
    uint8_t *seg = NULL;
    uint8_t hash[VTY_HASH_BYTES];
    size_t total;
    int rc;

    if (s == NULL || loc == NULL || payload == NULL || payload_len == NULL) {
        return VTY_E_INVALID;
    }
    *payload = NULL;
    *payload_len = 0;
    if (loc->offset < VTY_DATA_OFFSET || loc->offset >= s->loc.data_end) {
        return VTY_E_CORRUPT;
    }
    if (loc->total_len < VTY_SEG_HEADER_BYTES ||
        loc->total_len > s->loc.data_end - loc->offset) {
        return VTY_E_CORRUPT;
    }
    total = loc->total_len;

    rc = vty_st_read_at(s->h, loc->offset, shbuf, sizeof(shbuf));
    if (rc != VTY_OK) return rc;
    rc = vty_segment_header_parse(shbuf, &sh);
    if (rc != VTY_OK) return rc;
    if (sh.type != loc->type || sh.seq != loc->seq || sh.id != loc->id) {
        return VTY_E_CORRUPT;
    }
    if (VTY_SEG_HEADER_BYTES + (size_t)sh.payload_len != total) {
        return VTY_E_CORRUPT;
    }

    seg = (uint8_t *)vty_alloc(total);
    if (seg == NULL) return VTY_E_RESOURCE;
    rc = vty_st_read_at(s->h, loc->offset, seg, total);
    if (rc == VTY_OK) rc = vty_blake3_32(seg, total, hash);
    if (rc == VTY_OK &&
        vty_ct_equal(hash, loc->hash, VTY_HASH_BYTES) != 0) {
        rc = VTY_E_CORRUPT;
    }
    if (rc != VTY_OK) {
        vty_free(seg, total);
        return rc;
    }

    if (sh.payload_len != 0) {
        uint8_t *out = (uint8_t *)vty_alloc(sh.payload_len);
        if (out == NULL) {
            vty_free(seg, total);
            return VTY_E_RESOURCE;
        }
        memcpy(out, seg + VTY_SEG_HEADER_BYTES, sh.payload_len);
        *payload = out;
        *payload_len = sh.payload_len;
    }
    vty_free(seg, total);
    return VTY_OK;
}

int vty_store_read_raw(VtyStore *s, uint64_t offset, uint8_t *buf, size_t len)
{
    if (s == NULL || buf == NULL || len == 0u) return VTY_E_INVALID;
    if (offset < VTY_DATA_OFFSET || offset >= s->loc.data_end) {
        return VTY_E_CORRUPT;
    }
    if ((uint64_t)len > s->loc.data_end - offset) return VTY_E_CORRUPT;
    return vty_st_read_at(s->h, offset, buf, len);
}

static int scrub_zero_at(VtyStore *s, uint64_t pos, uint64_t len)
{
    uint8_t *zeros;
    size_t zero_len = 64u * 1024u;
    uint64_t end = pos + len;
    int rc = VTY_OK;

    zeros = (uint8_t *)vty_alloc(zero_len);
    if (zeros == NULL) return VTY_E_RESOURCE;
    memset(zeros, 0, zero_len);
    while (pos < end) {
        size_t chunk = (size_t)((end - pos) < (uint64_t)zero_len
                                    ? (end - pos)
                                    : (uint64_t)zero_len);
        rc = vty_st_write_at(s->h, pos, zeros, chunk);
        if (rc != VTY_OK) break;
        pos += chunk;
    }
    vty_secure_zero(zeros, zero_len);
    vty_free(zeros, zero_len);
    if (rc == VTY_OK) s->dirty = 1;
    return rc;
}

int vty_store_scrub_range(VtyStore *s, uint64_t seg_off, uint32_t seg_len,
                          uint32_t part_off, uint32_t part_len)
{
    uint8_t shbuf[VTY_SEG_HEADER_BYTES];
    VtySegmentHeader sh;
    int rc;

    if (s == NULL) return VTY_E_INVALID;
    if (seg_off < VTY_DATA_OFFSET || seg_off >= s->loc.data_end) {
        return VTY_E_CORRUPT;
    }
    if ((uint64_t)seg_len > s->loc.data_end - seg_off ||
        seg_len < VTY_SEG_HEADER_BYTES) {
        return VTY_E_CORRUPT;
    }
    rc = vty_st_read_at(s->h, seg_off, shbuf, sizeof(shbuf));
    if (rc != VTY_OK) return rc;
    rc = vty_segment_header_parse(shbuf, &sh);
    if (rc != VTY_OK) return rc;
    if (sh.type != VTY_SEG_RECORD && sh.type != VTY_SEG_CHUNK) {
        return VTY_E_CORRUPT;
    }
    if ((uint64_t)VTY_SEG_HEADER_BYTES + (uint64_t)sh.payload_len !=
        (uint64_t)seg_len) {
        return VTY_E_CORRUPT;
    }
    if ((uint64_t)part_off + (uint64_t)part_len > (uint64_t)seg_len ||
        part_len == 0u) {
        return VTY_E_CORRUPT;
    }
    return scrub_zero_at(s, seg_off + part_off, part_len);
}

int vty_store_scrub_raw(VtyStore *s, uint64_t offset, uint32_t len)
{
    if (s == NULL || len == 0u) return VTY_E_INVALID;
    if (offset < VTY_DATA_OFFSET || offset >= s->loc.data_end) {
        return VTY_E_CORRUPT;
    }
    if ((uint64_t)len > s->loc.data_end - offset) return VTY_E_CORRUPT;
    return scrub_zero_at(s, offset, len);
}

int vty_store_flush(VtyStore *s)
{
    if (s == NULL || s->h == INVALID_HANDLE_VALUE) return VTY_E_INVALID;
    if (!FlushFileBuffers(s->h)) return VTY_E_IO;
    s->dirty = 0;
    return VTY_OK;
}
