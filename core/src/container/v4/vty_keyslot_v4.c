/*
 * vty_keyslot_v4.c — v4 密钥槽编解码与包裹实现
 */
#include "vty_keyslot_v4.h"
#include "vty_kdf.h"
#include "vty_util.h"

#include <string.h>

#define SLOT_BASE_FIELDS 6u
#define SLOT_TAIL_FIELDS 2u   /* ct_len */

static int is_known_slot_type(uint8_t t)
{
    return t >= VTY_SLOT_USER_PASSWORD && t <= VTY_SLOT_FIDO2;
}

int vty_slot_build_aad(const uint8_t vault_uuid[VTY_UUID_BYTES], uint64_t epoch,
                       uint8_t slot_index, uint8_t slot_type,
                       uint8_t out[VTY_SLOT_AAD_MAX], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_SLOT;
    size_t dlen = strlen(domain);
    size_t need = dlen + VTY_UUID_BYTES + 8u + 1u + 1u;

    if (vault_uuid == NULL || out == NULL || out_len == NULL) return VTY_E_INVALID;
    if (need > VTY_SLOT_AAD_MAX) return VTY_E_INVALID;

    memcpy(out, domain, dlen);
    memcpy(out + dlen, vault_uuid, VTY_UUID_BYTES);
    vty_put_u64(out + dlen + VTY_UUID_BYTES, epoch);
    out[dlen + VTY_UUID_BYTES + 8u] = slot_index;
    out[dlen + VTY_UUID_BYTES + 8u + 1u] = slot_type;
    *out_len = need;
    return VTY_OK;
}

size_t vty_slot_serialized_len(const VtySlot *s)
{
    if (s == NULL) return 0;
    return (size_t)SLOT_BASE_FIELDS + s->params_len + VTY_SALT_BYTES +
           VTY_NONCE_BYTES + SLOT_TAIL_FIELDS + s->ct_len;
}

int vty_slot_write(const VtySlot *s, uint32_t index, const VtyV4Header *h,
                   uint8_t *buf, size_t cap, size_t *written)
{
    size_t need;
    size_t off = 0;

    if (s == NULL || h == NULL || buf == NULL || written == NULL) return VTY_E_INVALID;
    if (index >= VTY_V4_MAX_SLOTS) return VTY_E_INVALID;
    if (!is_known_slot_type(s->slot_type)) return VTY_E_SLOT_UNKNOWN;
    if (s->ct_len > VTY_SLOT_CT_MAX) return VTY_E_INVALID;
    if (s->params_len != 0 && s->params_len != 12 &&
        s->params_len != VTY_SLOT_PARAMS_PCR) {
        return VTY_E_INVALID;
    }
    if (s->params_len == VTY_SLOT_PARAMS_PCR && s->slot_type != VTY_SLOT_DEVICE_PCR) {
        return VTY_E_SLOT_UNKNOWN;
    }
    if (s->params_len == VTY_SLOT_PARAMS_PCR) {
        /* 写路径也校验，避免把逻辑上不可解析的槽落盘 */
        if (s->pcr_select == 0 ||
            (s->pcr_select & ~0x00FFFFFFu) != 0 ||
            s->ct_len != VTY_SLOT_PCR_CT_BYTES) {
            return VTY_E_INVALID;
        }
    }

    need = vty_slot_serialized_len(s);
    if (need > cap) return VTY_E_INVALID;

    buf[0] = s->slot_type;
    buf[1] = s->slot_flags;
    buf[2] = s->kdf_id;
    buf[3] = s->wrap_alg;
    vty_put_u16(buf + 4, s->params_len);
    off = SLOT_BASE_FIELDS;

    if (s->params_len == 12u) {
        vty_put_u32(buf + off, s->m_cost); off += 4;
        vty_put_u32(buf + off, s->t_cost); off += 4;
        vty_put_u32(buf + off, s->p_cost); off += 4;
    } else if (s->params_len == VTY_SLOT_PARAMS_PCR) {
        vty_put_u32(buf + off, s->pcr_select); off += 4;
        memcpy(buf + off, s->pcr_digest, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    }
    memcpy(buf + off, s->salt, VTY_SALT_BYTES); off += VTY_SALT_BYTES;
    memcpy(buf + off, s->nonce, VTY_NONCE_BYTES); off += VTY_NONCE_BYTES;
    vty_put_u16(buf + off, s->ct_len); off += SLOT_TAIL_FIELDS;
    if (s->ct_len != 0) {
        memcpy(buf + off, s->ct, s->ct_len); off += s->ct_len;
    }

    *written = off;
    return VTY_OK;
}

int vty_slot_parse_at(const uint8_t *buf, size_t len, size_t offset,
                      uint32_t index, const VtyV4Header *h,
                      VtySlot *out, size_t *consumed)
{
    VtySlot s;
    size_t off;
    uint16_t params_len;
    uint16_t ct_len;

    if (buf == NULL || h == NULL || out == NULL || consumed == NULL) return VTY_E_INVALID;
    if (offset > len) return VTY_E_INVALID;
    if (len - offset < SLOT_BASE_FIELDS) return VTY_E_INVALID;

    memset(&s, 0, sizeof(s));
    s.slot_type = buf[offset + 0];
    s.slot_flags = buf[offset + 1];
    s.kdf_id = buf[offset + 2];
    s.wrap_alg = buf[offset + 3];
    params_len = vty_get_u16(buf + offset + 4);
    s.params_len = params_len;

    if (!is_known_slot_type(s.slot_type)) return VTY_E_SLOT_UNKNOWN;
    if ((s.slot_flags & (uint8_t)~0x03u) != 0) return VTY_E_SLOT_UNKNOWN;
    if (params_len != 0 && params_len != 12 &&
        params_len != VTY_SLOT_PARAMS_PCR) {
        return VTY_E_INVALID;
    }
    if (params_len == VTY_SLOT_PARAMS_PCR && s.slot_type != VTY_SLOT_DEVICE_PCR) {
        return VTY_E_SLOT_UNKNOWN;
    }

    off = offset + SLOT_BASE_FIELDS;
    if (len - off < (size_t)params_len) return VTY_E_INVALID;

    if (params_len == 12u) {
        s.m_cost = vty_get_u32(buf + off); off += 4;
        s.t_cost = vty_get_u32(buf + off); off += 4;
        s.p_cost = vty_get_u32(buf + off); off += 4;
    } else if (params_len == VTY_SLOT_PARAMS_PCR) {
        s.pcr_select = vty_get_u32(buf + off); off += 4;
        memcpy(s.pcr_digest, buf + off, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    }

    if (len - off < VTY_SALT_BYTES + VTY_NONCE_BYTES + SLOT_TAIL_FIELDS) {
        return VTY_E_INVALID;
    }
    memcpy(s.salt, buf + off, VTY_SALT_BYTES); off += VTY_SALT_BYTES;
    memcpy(s.nonce, buf + off, VTY_NONCE_BYTES); off += VTY_NONCE_BYTES;
    ct_len = vty_get_u16(buf + off); off += SLOT_TAIL_FIELDS;
    if (ct_len > VTY_SLOT_CT_MAX) return VTY_E_INVALID;
    if (len - off < (size_t)ct_len) return VTY_E_INVALID;

    s.ct_len = ct_len;
    if (ct_len != 0) {
        memcpy(s.ct, buf + off, ct_len);
        off += ct_len;
    }

    /* KDF / 包裹算法组合必须自洽，防止“设备槽塞口令密文”这类混淆 */
    if (s.kdf_id == VTY_KDF_ARGON2ID) {
        if (s.wrap_alg != VTY_WRAP_XCHACHA && s.wrap_alg != VTY_WRAP_AESGCM) {
            return VTY_E_SLOT_UNKNOWN;
        }
        if (params_len != 12u) return VTY_E_INVALID;
        /* PCR 槽不使用口令 KDF */
        if (s.slot_type == VTY_SLOT_DEVICE_PCR) return VTY_E_SLOT_UNKNOWN;
        /* 口令/模块槽恰好包裹一个 32B 密钥；恢复槽承载变长 Keyring */
        if (s.slot_type == VTY_SLOT_RECOVERY) {
            if (s.ct_len <= VTY_TAG_BYTES) return VTY_E_INVALID;
        } else {
            if (s.ct_len != VTY_KEY_BYTES + VTY_TAG_BYTES) return VTY_E_INVALID;
        }
    } else if (s.kdf_id == VTY_KDF_NONE) {
        if (s.wrap_alg != VTY_WRAP_RSAOAEP) return VTY_E_SLOT_UNKNOWN;
        if (s.slot_type == VTY_SLOT_DEVICE_PCR) {
            /* PCR 槽：32B 策略摘要 + 固定长度 RSA 密文，位图仅允许 PCR0–23 */
            if (params_len != VTY_SLOT_PARAMS_PCR) return VTY_E_INVALID;
            if (s.pcr_select == 0 ||
                (s.pcr_select & ~0x00FFFFFFu) != 0) {
                return VTY_E_INVALID;
            }
            if (s.ct_len != VTY_SLOT_PCR_CT_BYTES) return VTY_E_INVALID;
        } else if (params_len != 0) {
            return VTY_E_INVALID;
        }
    } else {
        return VTY_E_SLOT_UNKNOWN;
    }

    *out = s;
    *consumed = off - offset;
    return VTY_OK;
}

int vty_slots_parse_all(const uint8_t *buf, size_t len,
                        const VtyV4Header *h,
                        VtySlot *out, uint32_t cap, uint32_t *out_count)
{
    const uint8_t *slots;
    size_t slots_len;
    size_t off = 0;
    uint32_t i;

    if (buf == NULL || h == NULL || out == NULL || out_count == NULL) return VTY_E_INVALID;
    if (h->slot_count > cap) return VTY_E_INVALID;

    slots = vty_v4_header_slots(buf, len);
    slots_len = vty_v4_header_slots_len(h);
    if (slots == NULL) return VTY_E_INVALID;
    if (VTY_V4_HEADER_FIXED_BYTES + slots_len + VTY_V4_HEADER_HASH_BYTES !=
        (size_t)h->header_len) {
        return VTY_E_INVALID;
    }

    for (i = 0; i < h->slot_count; i++) {
        size_t consumed = 0;
        int rc = vty_slot_parse_at(slots, slots_len, off, i, h, &out[i], &consumed);
        if (rc != VTY_OK) return rc;
        if (consumed == 0) return VTY_E_INVALID;
        off += consumed;
    }

    *out_count = h->slot_count;
    return VTY_OK;
}

int vty_slot_seal_argon2id(VtySlot *s, uint8_t slot_type, uint8_t slot_flags,
                           const uint8_t *secret, size_t secret_len,
                           const uint8_t key[VTY_KEY_BYTES],
                           const VtyV4Header *h, uint32_t index,
                           uint32_t mem_kib, uint32_t iters, uint32_t parallel)
{
    uint8_t kek[VTY_KEY_BYTES];
    uint8_t aad[VTY_SLOT_AAD_MAX];
    size_t aad_len = 0;
    size_t ct_len = 0;
    int rc;

    if (s == NULL || key == NULL || h == NULL) return VTY_E_INVALID;
    if (secret == NULL && secret_len != 0) return VTY_E_INVALID;
    if (index >= VTY_V4_MAX_SLOTS) return VTY_E_INVALID;

    rc = vty_kdf_params_valid(mem_kib, iters, parallel);
    if (rc != VTY_OK) return rc;

    memset(s, 0, sizeof(*s));
    s->slot_type = slot_type;
    s->slot_flags = slot_flags;
    s->kdf_id = VTY_KDF_ARGON2ID;
    s->wrap_alg = VTY_WRAP_XCHACHA;
    s->params_len = 12u;
    s->m_cost = mem_kib;
    s->t_cost = iters;
    s->p_cost = parallel;
    vty_random(s->salt, VTY_SALT_BYTES);

    rc = vty_kdf_argon2id(kek, secret, secret_len, s->salt, mem_kib, iters, parallel);
    if (rc != VTY_OK) {
        vty_secure_zero(kek, sizeof(kek));
        return rc;
    }

    rc = vty_slot_build_aad(h->vault_uuid, h->epoch, (uint8_t)index, slot_type,
                            aad, &aad_len);
    if (rc == VTY_OK) {
        rc = vty_wrap_key32(kek, key, aad, aad_len, s->nonce, s->ct);
        if (rc == VTY_OK) {
            ct_len = VTY_KEY_BYTES + VTY_TAG_BYTES;
            s->ct_len = (uint16_t)ct_len;
        }
    }

    vty_secure_zero(kek, sizeof(kek));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

int vty_slot_open_argon2id(const VtySlot *s,
                           const uint8_t *secret, size_t secret_len,
                           const VtyV4Header *h, uint32_t index,
                           uint8_t key_out[VTY_KEY_BYTES])
{
    uint8_t kek[VTY_KEY_BYTES];
    uint8_t aad[VTY_SLOT_AAD_MAX];
    size_t aad_len = 0;
    int rc;

    if (s == NULL || key_out == NULL || h == NULL) return VTY_E_INVALID;
    if (secret == NULL && secret_len != 0) return VTY_E_INVALID;
    if (s->kdf_id != VTY_KDF_ARGON2ID) return VTY_E_SLOT_UNKNOWN;

    rc = vty_kdf_params_valid(s->m_cost, s->t_cost, s->p_cost);
    if (rc != VTY_OK) {
        /* 存储参数低于下限：拒绝解锁，不提供兼容降低 */
        return rc;
    }

    rc = vty_kdf_argon2id(kek, secret, secret_len, s->salt,
                          s->m_cost, s->t_cost, s->p_cost);
    if (rc != VTY_OK) {
        vty_secure_zero(kek, sizeof(kek));
        return rc;
    }

    rc = vty_slot_build_aad(h->vault_uuid, h->epoch, (uint8_t)index, s->slot_type,
                            aad, &aad_len);
    if (rc == VTY_OK) {
        rc = vty_unwrap_key32(kek, s->nonce, aad, aad_len, s->ct, s->ct_len, key_out);
    }

    vty_secure_zero(kek, sizeof(kek));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

int vty_slot_seal_device(VtySlot *s, uint8_t slot_flags,
                         const uint8_t key[VTY_KEY_BYTES],
                         const VtyV4Header *h, uint32_t index)
{
    size_t blob_len = VTY_SLOT_CT_MAX;
    int rc;

    /* 设备槽走 RSA-OAEP 直接包裹，不参与头部/槽序 AAD，故 header 允许为空 */
    (void)h;
    if (s == NULL || key == NULL) return VTY_E_INVALID;
    if (index >= VTY_V4_MAX_SLOTS) return VTY_E_INVALID;

    memset(s, 0, sizeof(*s));
    s->slot_type = VTY_SLOT_DEVICE_ROOT;
    s->slot_flags = slot_flags;
    s->kdf_id = VTY_KDF_NONE;
    s->wrap_alg = VTY_WRAP_RSAOAEP;
    s->params_len = 0;

    rc = vty_device_key_seal(key, s->ct, &blob_len);
    if (rc != VTY_OK) return rc;
    s->ct_len = (uint16_t)blob_len;
    return VTY_OK;
}

int vty_slot_open_device(const VtySlot *s, const VtyV4Header *h, uint32_t index,
                         uint8_t key_out[VTY_KEY_BYTES])
{
    (void)h;
    (void)index;
    if (s == NULL || key_out == NULL) return VTY_E_INVALID;
    if (s->slot_type != VTY_SLOT_DEVICE_ROOT) return VTY_E_SLOT_UNKNOWN;
    if (s->kdf_id != VTY_KDF_NONE || s->wrap_alg != VTY_WRAP_RSAOAEP) {
        return VTY_E_SLOT_UNKNOWN;
    }
    return vty_device_key_unseal(s->ct, s->ct_len, key_out);
}

int vty_slot_find(const VtySlot *slots, uint32_t count, uint8_t slot_type)
{
    uint32_t i;
    if (slots == NULL) return -1;
    for (i = 0; i < count; i++) {
        if (slots[i].slot_type == slot_type) return (int)i;
    }
    return -1;
}

int vty_slot_policy_check(const VtySlot *slots, uint32_t count, uint16_t flags)
{
    uint32_t i;
    uint32_t pcr_slots = 0;

    if (slots == NULL || count == 0) return VTY_E_SLOT_MISSING;
    for (i = 0; i < count; i++) {
        if (slots[i].slot_type == VTY_SLOT_DEVICE_PCR) pcr_slots++;
    }

    if (vty_slot_find(slots, count, VTY_SLOT_USER_PASSWORD) < 0) return VTY_E_SLOT_MISSING;
    if (vty_slot_find(slots, count, VTY_SLOT_DEVICE_ROOT) < 0) return VTY_E_SLOT_MISSING;

    /* 恢复槽一旦声明存在，就必须真的存在——声明与实体不一致视为损坏 */
    if ((flags & VTY_FLAG_RECOVERY) != 0 &&
        vty_slot_find(slots, count, VTY_SLOT_RECOVERY) < 0) {
        return VTY_E_SLOT_MISSING;
    }

    /* PCR 槽同理：声明与实体必须一致，且最多一个 */
    if ((flags & VTY_FLAG_PCR) != 0) {
        if (pcr_slots != 1) return VTY_E_SLOT_MISSING;
    } else if (pcr_slots != 0) {
        return VTY_E_SLOT_UNKNOWN;
    }

    /* D3 keyfile 是用户槽 KDF 第二输入，不写独立槽；若出现 type 5 槽，
     * 说明文件来自未批准的旧设计或伪造，直接拒绝。 */
    if (vty_slot_find(slots, count, VTY_SLOT_KEYFILE) >= 0) {
        return VTY_E_SLOT_UNKNOWN;
    }

    if ((flags & VTY_FLAG_HIGH_SECURITY) != 0) {
        if ((flags & VTY_FLAG_KEYFILE) == 0 && pcr_slots == 0) {
            return VTY_E_SLOT_MISSING;
        }
    }
    return VTY_OK;
}
