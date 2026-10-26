/*
 * vty_format_v4.c — v4 容器明文头部编解码
 */
#include "vty_format_v4.h"
#include "vty_util.h"
#include "vty_blake3.h"

#include <string.h>

static int header_min_len(void)
{
    return (int)(VTY_V4_HEADER_FIXED_BYTES + VTY_V4_HEADER_HASH_BYTES);
}

int vty_v4_header_write_fixed(const VtyV4Header *h, uint8_t *buf, size_t cap)
{
    if (h == NULL || buf == NULL) return VTY_E_INVALID;
    if (cap < VTY_V4_HEADER_FIXED_BYTES) return VTY_E_INVALID;
    if (h->slot_count > VTY_V4_MAX_SLOTS) return VTY_E_INVALID;

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
    /* 只落版本计数器；其余保留位保持零，避免把未定义内容写进公开头 */
    memset(buf + 44, 0, 32);
    vty_put_u64(buf + 44, vty_get_u64(h->reserved1));
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
    h.header_len = vty_get_u16(buf + 8);
    h.flags = vty_get_u16(buf + 10);
    memcpy(h.vault_uuid, buf + 12, VTY_UUID_BYTES);
    h.epoch = vty_get_u64(buf + 28);
    h.slot_count = vty_get_u16(buf + 36);
    h.reserved0 = vty_get_u16(buf + 38);
    h.keyring_len = vty_get_u32(buf + 40);
    memcpy(h.reserved1, buf + 44, 32);
    /* 保留区非零意味着未来格式或伪造数据：按未知槽/未知标志拒绝，
     * 不能带着未定义语义继续解密 */
    {
        size_t i;
        for (i = 8; i < 32; i++) {
            if (h.reserved1[i] != 0) return VTY_E_SLOT_UNKNOWN;
        }
    }

    if ((h.flags & (uint16_t)~VTY_FLAG_KNOWN_MASK) != 0) return VTY_E_SLOT_UNKNOWN;
    if (h.slot_count == 0 || h.slot_count > VTY_V4_MAX_SLOTS) return VTY_E_INVALID;
    if (h.reserved0 != 0) return VTY_E_SLOT_UNKNOWN;
    if (h.header_len > len) return VTY_E_INVALID;
    if (h.header_len < (uint16_t)header_min_len()) return VTY_E_INVALID;

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
    return vty_get_u64(h->reserved1);
}

void vty_v4_header_set_generation(VtyV4Header *h, uint64_t generation)
{
    if (h == NULL) return;
    vty_put_u64(h->reserved1, generation);
}
