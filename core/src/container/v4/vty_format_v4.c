/*
 * vty_format_v4.c — v4 容器明文头部、DataRoot locator 与段头编解码
 */
#include "vty_format_v4.h"
#include "vty_util.h"
#include "vty_blake3.h"

#include <string.h>

static void put_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void put_u64_be(uint8_t *p, uint64_t v)
{
    put_u32_be(p, (uint32_t)(v >> 32));
    put_u32_be(p + 4, (uint32_t)v);
}

static uint32_t get_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t get_u64_be(const uint8_t *p)
{
    return ((uint64_t)get_u32_be(p) << 32) | (uint64_t)get_u32_be(p + 4);
}

static int header_min_len(void)
{
    return (int)(VTY_V4_HEADER_FIXED_BYTES + VTY_V4_HEADER_HASH_BYTES);
}

int vty_v4_header_write_fixed(const VtyV4Header *h, uint8_t *buf, size_t cap)
{
    if (h == NULL || buf == NULL) return VTY_E_INVALID;
    if (cap < VTY_V4_HEADER_FIXED_BYTES) return VTY_E_INVALID;
    if (h->slot_count > VTY_V4_MAX_SLOTS) return VTY_E_INVALID;
    if (h->version_major != VTY_V4_VERSION_MAJOR ||
        h->version_minor != VTY_V4_VERSION_MINOR) {
        return VTY_E_VERSION;
    }

    vty_put_u32(buf + 0, VTY_V4_MAGIC);
    vty_put_u16(buf + 4, VTY_V4_VERSION_MAJOR);
    vty_put_u16(buf + 6, VTY_V4_VERSION_MINOR);
    vty_put_u16(buf + 8, h->header_len);
    vty_put_u16(buf + 10, h->flags);
    memcpy(buf + 12, h->vault_uuid, VTY_UUID_BYTES);
    vty_put_u64(buf + 28, h->epoch);
    vty_put_u16(buf + 36, h->slot_count);
    vty_put_u16(buf + 38, h->reserved0);
    vty_put_u32(buf + 40, h->keyring_len);
    /* 固定头 44..76 共 32B：先清零再写 generation。保留区必须全零，
     * 否则未来语义会被旧解析器当成“未知但可继续”带进认证范围。 */
    memset(buf + VTY_V4_GENERATION_OFFSET, 0,
           VTY_V4_RESERVED_TAIL_BYTES + 8u);
    vty_put_u64(buf + VTY_V4_GENERATION_OFFSET, h->generation);
    return VTY_OK;
}

int vty_v4_header_finalize(uint8_t *buf, size_t header_len)
{
    uint8_t hash[VTY_HASH_BYTES];
    size_t hashed_len;
    int rc;

    if (buf == NULL || header_len < (size_t)header_min_len()) return VTY_E_INVALID;
    hashed_len = header_len - VTY_V4_HEADER_HASH_BYTES;

    rc = vty_blake3_32(buf, hashed_len, hash);
    if (rc != VTY_OK) return rc;
    memcpy(buf + hashed_len, hash, VTY_HASH_BYTES);
    return VTY_OK;
}

int vty_v4_header_parse(const uint8_t *buf, size_t len, VtyV4Header *out)
{
    VtyV4Header h;
    uint8_t hash[VTY_HASH_BYTES];
    size_t hashed_len;
    size_t slot_bytes;

    if (buf == NULL || out == NULL) return VTY_E_INVALID;
    if (len < (size_t)header_min_len()) return VTY_E_INVALID;

    h.magic = vty_get_u32(buf + 0);
    if (h.magic != VTY_V4_MAGIC) return VTY_E_VERSION;

    h.version_major = vty_get_u16(buf + 4);
    if (h.version_major != VTY_V4_VERSION_MAJOR) return VTY_E_VERSION;

    h.version_minor = vty_get_u16(buf + 6);
    if (h.version_minor != VTY_V4_VERSION_MINOR) return VTY_E_VERSION;

    h.header_len = vty_get_u16(buf + 8);
    h.flags = vty_get_u16(buf + 10);
    memcpy(h.vault_uuid, buf + 12, VTY_UUID_BYTES);
    h.epoch = vty_get_u64(buf + 28);
    h.slot_count = vty_get_u16(buf + 36);
    h.reserved0 = vty_get_u16(buf + 38);
    h.keyring_len = vty_get_u32(buf + 40);
    h.generation = vty_get_u64(buf + VTY_V4_GENERATION_OFFSET);
    memcpy(h.reserved1_tail, buf + VTY_V4_GENERATION_OFFSET + 8u,
           VTY_V4_RESERVED_TAIL_BYTES);

    /* 保留位非零意味着未来格式或伪造数据：按未知槽/未知标志拒绝，
     * 不能带着未定义语义继续解密。 */
    {
        size_t i;
        for (i = 0; i < VTY_V4_RESERVED_TAIL_BYTES; i++) {
            if (h.reserved1_tail[i] != 0) return VTY_E_SLOT_UNKNOWN;
        }
    }

    if ((h.flags & (uint16_t)~VTY_FLAG_KNOWN_MASK) != 0) return VTY_E_SLOT_UNKNOWN;
    if (h.slot_count == 0 || h.slot_count > VTY_V4_MAX_SLOTS) return VTY_E_INVALID;
    if (h.reserved0 != 0) return VTY_E_SLOT_UNKNOWN;
    if (h.header_len > len) return VTY_E_INVALID;
    if (h.header_len < (uint16_t)header_min_len()) return VTY_E_INVALID;
    if (h.header_len > VTY_V4_META_COPY_BYTES) return VTY_E_INVALID;

    slot_bytes = (size_t)h.header_len - VTY_V4_HEADER_FIXED_BYTES - VTY_V4_HEADER_HASH_BYTES;
    if (slot_bytes > (size_t)VTY_V4_MAX_SLOTS * 400u) return VTY_E_INVALID;

    hashed_len = (size_t)h.header_len - VTY_V4_HEADER_HASH_BYTES;
    if (vty_blake3_32(buf, hashed_len, hash) != VTY_OK) return VTY_E_INVALID;
    if (vty_ct_equal(hash, buf + hashed_len, VTY_HASH_BYTES) != 0) return VTY_E_CORRUPT;

    *out = h;
    return VTY_OK;
}

const uint8_t *vty_v4_header_slots(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len < VTY_V4_HEADER_FIXED_BYTES) return NULL;
    return buf + VTY_V4_HEADER_FIXED_BYTES;
}

size_t vty_v4_header_slots_len(const VtyV4Header *h)
{
    if (h == NULL) return 0;
    if (h->header_len < VTY_V4_HEADER_FIXED_BYTES + VTY_V4_HEADER_HASH_BYTES) return 0;
    return (size_t)h->header_len - VTY_V4_HEADER_FIXED_BYTES - VTY_V4_HEADER_HASH_BYTES;
}

uint64_t vty_v4_header_generation(const VtyV4Header *h)
{
    if (h == NULL) return 0;
    return h->generation;
}

int vty_v4_header_digest(const uint8_t *header, size_t header_len,
                         uint8_t out[VTY_HASH_BYTES])
{
    const char *domain = VTY_DOMAIN_HEADER;
    size_t dlen = strlen(domain);
    size_t hashed_len;
    uint8_t *buf;
    int rc;

    if (header == NULL || out == NULL) return VTY_E_INVALID;
    if (header_len < (size_t)header_min_len()) return VTY_E_INVALID;
    if (header_len > VTY_V4_META_COPY_BYTES) return VTY_E_INVALID;
    hashed_len = header_len - VTY_V4_HEADER_HASH_BYTES;

    buf = (uint8_t *)vty_alloc(dlen + hashed_len);
    if (buf == NULL) return VTY_E_RESOURCE;
    memcpy(buf, domain, dlen);
    memcpy(buf + dlen, header, hashed_len);
    rc = vty_blake3_32(buf, dlen + hashed_len, out);
    vty_free(buf, dlen + hashed_len);
    return rc;
}

int vty_data_root_encode(const VtyDataRootLocator *loc, uint8_t out[VTY_DATA_ROOT_BYTES])
{
    size_t off = 0;

    if (loc == NULL || out == NULL) return VTY_E_INVALID;
    if (loc->version != 1u || loc->flags != 0u || loc->pad != 0u) return VTY_E_INVALID;
    if (loc->data_end < VTY_V4_DATA_OFFSET) return VTY_E_INVALID;
    if (loc->level > 8u) return VTY_E_INVALID;

    memset(out, 0, VTY_DATA_ROOT_BYTES);
    out[off++] = loc->version;
    out[off++] = loc->flags;
    put_u64_be(out + off, loc->root_node_id); off += 8;
    put_u64_be(out + off, loc->root_offset); off += 8;
    put_u32_be(out + off, loc->root_len); off += 4;
    out[off++] = loc->level;
    put_u64_be(out + off, loc->data_end); off += 8;
    out[off++] = loc->pad;
    return VTY_OK;
}

int vty_data_root_decode(const uint8_t in[VTY_DATA_ROOT_BYTES], VtyDataRootLocator *out)
{
    size_t off = 0;

    if (in == NULL || out == NULL) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    out->version = in[off++];
    out->flags = in[off++];
    out->root_node_id = get_u64_be(in + off); off += 8;
    out->root_offset = get_u64_be(in + off); off += 8;
    out->root_len = get_u32_be(in + off); off += 4;
    out->level = in[off++];
    out->data_end = get_u64_be(in + off); off += 8;
    out->pad = in[off++];

    if (out->version != 1u || out->flags != 0u || out->pad != 0u) return VTY_E_CORRUPT;
    if (out->data_end < VTY_V4_DATA_OFFSET) return VTY_E_CORRUPT;
    if (out->level > 8u) return VTY_E_CORRUPT;
    if (out->root_node_id == 0u) {
        if (out->root_offset != 0u || out->root_len != 0u || out->level != 0u) {
            return VTY_E_CORRUPT;
        }
    } else if (out->root_len < VTY_SEG_HEADER_BYTES + VTY_NONCE_BYTES + VTY_TAG_BYTES) {
        return VTY_E_CORRUPT;
    }
    return VTY_OK;
}

int vty_segment_header_write(const VtySegmentHeader *h, uint8_t out[VTY_SEG_HEADER_BYTES])
{
    if (h == NULL || out == NULL) return VTY_E_INVALID;
    if (h->type < VTY_SEG_RECORD || h->type > VTY_SEG_DIR) return VTY_E_INVALID;
    if (h->flags != 0u || h->payload_len == 0u) return VTY_E_INVALID;

    memset(out, 0, VTY_SEG_HEADER_BYTES);
    put_u32_be(out + 0, VTY_SEG_MAGIC);
    out[4] = h->type;
    out[5] = h->flags;
    /* 6..8 reserved，28..32 pad：保持零，解析时强制校验 */
    put_u32_be(out + 8, h->payload_len);
    put_u64_be(out + 12, h->seq);
    put_u64_be(out + 20, h->id);
    return VTY_OK;
}

int vty_segment_header_parse(const uint8_t in[VTY_SEG_HEADER_BYTES], VtySegmentHeader *out)
{
    if (in == NULL || out == NULL) return VTY_E_INVALID;
    if (get_u32_be(in + 0) != VTY_SEG_MAGIC) return VTY_E_CORRUPT;
    out->type = in[4];
    out->flags = in[5];
    out->payload_len = get_u32_be(in + 8);
    out->seq = get_u64_be(in + 12);
    out->id = get_u64_be(in + 20);

    if (out->type < VTY_SEG_RECORD || out->type > VTY_SEG_DIR) return VTY_E_CORRUPT;
    if (out->flags != 0u) return VTY_E_CORRUPT;
    if (vty_get_u16(in + 6) != 0u || get_u32_be(in + 28) != 0u) return VTY_E_CORRUPT;
    if (out->payload_len == 0u) return VTY_E_CORRUPT;
    return VTY_OK;
}
