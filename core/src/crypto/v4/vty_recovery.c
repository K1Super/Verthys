/*
 * vty_recovery.c — 恢复码与 RecoveryKeyring 实现
 */
#include "vty_recovery.h"
#include "vty_kdf.h"
#include "vty_util.h"

#include <string.h>

static const char B32_ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
static const char CHECKSUM_LABEL[] = "verthys/v4/recovery-checksum";

static int b32_value(char c)
{
    int i;
    if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    /* 易混字符按规范归一：I/L→1，O→0 */
    if (c == 'I' || c == 'L') c = '1';
    if (c == 'O') c = '0';
    for (i = 0; i < 32; i++) {
        if (B32_ALPHABET[i] == c) return i;
    }
    return -1;
}

static void b32_encode(const uint8_t *in, size_t in_len, char *out, size_t out_chars)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t i, oi = 0;

    for (i = 0; i < in_len; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5 && oi < out_chars) {
            out[oi++] = B32_ALPHABET[(acc >> (bits - 5)) & 0x1Fu];
            bits -= 5;
        }
    }
    if (bits > 0 && oi < out_chars) {
        out[oi++] = B32_ALPHABET[(acc << (5 - bits)) & 0x1Fu];
    }
    while (oi < out_chars) {
        out[oi++] = B32_ALPHABET[0];
    }
}

/* 返回 1=成功；尾部多余位必须为 0，否则视为非规范输入 */
static int b32_decode(const char *s, size_t n, uint8_t *out, size_t out_len)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t i, oi = 0;

    for (i = 0; i < n; i++) {
        int v = b32_value(s[i]);
        if (v < 0) return 0;
        acc = (acc << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8 && oi < out_len) {
            out[oi++] = (uint8_t)(acc >> (bits - 8));
            bits -= 8;
        }
    }
    if (oi != out_len) return 0;
    if (bits > 0) {
        uint32_t mask = (1u << bits) - 1u;
        if ((acc & mask) != 0) return 0;
    }
    return 1;
}

static int compute_checksum(const uint8_t code[VTY_RECOVERY_CODE_BYTES],
                            uint8_t out[2])
{
    uint8_t buf[sizeof(CHECKSUM_LABEL) - 1 + VTY_RECOVERY_CODE_BYTES];
    uint8_t digest[32];
    size_t label_len = sizeof(CHECKSUM_LABEL) - 1;

    memcpy(buf, CHECKSUM_LABEL, label_len);
    memcpy(buf + label_len, code, VTY_RECOVERY_CODE_BYTES);
    if (vty_sha256(digest, buf, sizeof(buf)) != VTY_OK) {
        vty_secure_zero(buf, sizeof(buf));
        return VTY_E_INVALID;
    }
    out[0] = digest[0];
    out[1] = digest[1];
    vty_secure_zero(buf, sizeof(buf));
    vty_secure_zero(digest, sizeof(digest));
    return VTY_OK;
}

static int format_with_checksum(const uint8_t code[VTY_RECOVERY_CODE_BYTES],
                                char *text, size_t text_cap)
{
    char raw[VTY_RECOVERY_CHARS];
    uint8_t sum[2];
    size_t i, oi = 0;
    int group;

    if (text == NULL) return VTY_E_INVALID;
    if (text_cap < VTY_RECOVERY_TEXT_BUF) return VTY_E_INVALID;
    if (compute_checksum(code, sum) != VTY_OK) return VTY_E_INVALID;

    b32_encode(code, VTY_RECOVERY_CODE_BYTES, raw, VTY_RECOVERY_DATA_CHARS);
    b32_encode(sum, sizeof(sum), raw + VTY_RECOVERY_DATA_CHARS, VTY_RECOVERY_SUM_CHARS);

    for (group = 0; group < 14; group++) {
        if (group != 0) text[oi++] = '-';
        for (i = 0; i < 4; i++) {
            text[oi++] = raw[group * 4u + i];
        }
    }
    text[oi] = '\0';
    vty_secure_zero(raw, sizeof(raw));
    return VTY_OK;
}

int vty_recovery_format(const uint8_t code[VTY_RECOVERY_CODE_BYTES],
                        char *text, size_t text_cap)
{
    return format_with_checksum(code, text, text_cap);
}

int vty_recovery_generate(uint8_t code[VTY_RECOVERY_CODE_BYTES],
                          char *text, size_t text_cap)
{
    if (code == NULL) return VTY_E_INVALID;
    vty_random(code, VTY_RECOVERY_CODE_BYTES);
    return format_with_checksum(code, text, text_cap);
}

int vty_recovery_verify(const char *text)
{
    uint8_t code[VTY_RECOVERY_CODE_BYTES];
    int rc = vty_recovery_decode(text, code);
    vty_secure_zero(code, sizeof(code));
    return rc;
}

int vty_recovery_decode(const char *text,
                        uint8_t code[VTY_RECOVERY_CODE_BYTES])
{
    char norm[VTY_RECOVERY_CHARS];
    size_t n = 0;
    size_t i;
    uint8_t sum[2];
    uint8_t provided[2];

    if (text == NULL || code == NULL) return VTY_E_INVALID;

    /* 去除分组分隔符；其它字符一律交给字母表校验拒绝。
     * 超出长度的非分隔字符必须立即拒绝——若在此截断，尾部多写的字符
     * 会被静默忽略，等于接受任意后缀。 */
    for (i = 0; text[i] != '\0'; i++) {
        char c = text[i];
        if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (n >= sizeof(norm)) return VTY_E_INVALID;
        norm[n++] = c;
    }
    if (n != VTY_RECOVERY_CHARS) return VTY_E_INVALID;

    if (!b32_decode(norm, VTY_RECOVERY_DATA_CHARS, code, VTY_RECOVERY_CODE_BYTES)) {
        vty_secure_zero(code, VTY_RECOVERY_CODE_BYTES);
        return VTY_E_INVALID;
    }
    if (!b32_decode(norm + VTY_RECOVERY_DATA_CHARS, VTY_RECOVERY_SUM_CHARS,
                    provided, sizeof(provided))) {
        vty_secure_zero(code, VTY_RECOVERY_CODE_BYTES);
        return VTY_E_INVALID;
    }
    if (compute_checksum(code, sum) != VTY_OK) {
        vty_secure_zero(code, VTY_RECOVERY_CODE_BYTES);
        return VTY_E_INVALID;
    }
    if (vty_ct_equal(sum, provided, sizeof(sum)) != 0) {
        vty_secure_zero(code, VTY_RECOVERY_CODE_BYTES);
        return VTY_E_INVALID;
    }

    vty_secure_zero(norm, sizeof(norm));
    vty_secure_zero(sum, sizeof(sum));
    vty_secure_zero(provided, sizeof(provided));
    return VTY_OK;
}

int vty_keyring_serialize(const VtyKeyring *kr, uint8_t *buf, size_t cap,
                          size_t *out_len)
{
    size_t off = 1;
    uint32_t i;

    if (kr == NULL || buf == NULL || out_len == NULL) return VTY_E_INVALID;
    if (kr->count == 0 || kr->count > VTY_KEYRING_MAX_ENTRIES) return VTY_E_INVALID;
    if (cap < 1) return VTY_E_INVALID;

    buf[0] = kr->count;
    for (i = 0; i < kr->count; i++) {
        const VtyKeyEntry *e = &kr->entries[i];
        size_t need = 1u + 2u + e->module_uuid_len + 1u + VTY_KEY_BYTES;
        if (e->kind < VTY_KEYKIND_KC || e->kind > VTY_KEYKIND_MDEK) return VTY_E_INVALID;
        if (e->module_uuid_len != 0 && e->module_uuid_len != VTY_KEYRING_MODULE_ID_MAX) {
            return VTY_E_INVALID;
        }
        if (e->kind == VTY_KEYKIND_MDEK && e->module_uuid_len != VTY_KEYRING_MODULE_ID_MAX) {
            return VTY_E_INVALID;
        }
        if (e->kind != VTY_KEYKIND_MDEK && e->module_uuid_len != 0) return VTY_E_INVALID;
        if (off + need > cap || off + need > VTY_KEYRING_MAX_BYTES) return VTY_E_INVALID;

        buf[off++] = e->kind;
        vty_put_u16(buf + off, (uint16_t)e->module_uuid_len); off += 2;
        if (e->module_uuid_len != 0) {
            memcpy(buf + off, e->module_uuid, e->module_uuid_len);
            off += e->module_uuid_len;
        }
        buf[off++] = VTY_KEY_BYTES;
        memcpy(buf + off, e->key, VTY_KEY_BYTES);
        off += VTY_KEY_BYTES;
    }
    *out_len = off;
    return VTY_OK;
}

int vty_keyring_parse(const uint8_t *buf, size_t len, VtyKeyring *out)
{
    size_t off = 1;
    uint32_t i, j;

    if (buf == NULL || out == NULL || len < 1) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    out->count = buf[0];
    if (out->count == 0 || out->count > VTY_KEYRING_MAX_ENTRIES) return VTY_E_INVALID;

    for (i = 0; i < out->count; i++) {
        VtyKeyEntry *e = &out->entries[i];
        uint16_t id_len;

        if (off + 3 > len) return VTY_E_INVALID;
        e->kind = buf[off++];
        id_len = vty_get_u16(buf + off); off += 2;
        if (e->kind < VTY_KEYKIND_KC || e->kind > VTY_KEYKIND_MDEK) return VTY_E_INVALID;
        if (id_len > VTY_KEYRING_MODULE_ID_MAX) return VTY_E_INVALID;
        if (e->kind == VTY_KEYKIND_MDEK && id_len != VTY_KEYRING_MODULE_ID_MAX) {
            return VTY_E_INVALID;
        }
        if (e->kind != VTY_KEYKIND_MDEK && id_len != 0) return VTY_E_INVALID;

        if (off + id_len + 1u + VTY_KEY_BYTES > len) return VTY_E_INVALID;
        e->module_uuid_len = (uint8_t)id_len;
        if (id_len != 0) {
            memcpy(e->module_uuid, buf + off, id_len);
            off += id_len;
        }
        if (buf[off++] != VTY_KEY_BYTES) return VTY_E_INVALID;
        memcpy(e->key, buf + off, VTY_KEY_BYTES);
        off += VTY_KEY_BYTES;

        for (j = 0; j < i; j++) {
            if (out->entries[j].kind == e->kind &&
                out->entries[j].module_uuid_len == e->module_uuid_len &&
                memcmp(out->entries[j].module_uuid, e->module_uuid,
                       e->module_uuid_len) == 0) {
                return VTY_E_INVALID;
            }
        }
    }

    if (off != len) return VTY_E_INVALID;
    return VTY_OK;
}

int vty_keyring_find(const VtyKeyring *kr, uint8_t kind,
                     const uint8_t *module_uuid, size_t module_uuid_len,
                     uint8_t key_out[VTY_KEY_BYTES])
{
    uint32_t i;

    if (kr == NULL || key_out == NULL) return VTY_E_INVALID;
    if (module_uuid == NULL && module_uuid_len != 0) return VTY_E_INVALID;
    if (module_uuid_len != 0 && module_uuid_len != VTY_KEYRING_MODULE_ID_MAX) {
        return VTY_E_INVALID;
    }

    for (i = 0; i < kr->count; i++) {
        const VtyKeyEntry *e = &kr->entries[i];
        if (e->kind != kind) continue;
        if (e->module_uuid_len != module_uuid_len) continue;
        if (module_uuid_len != 0 && memcmp(e->module_uuid, module_uuid, module_uuid_len) != 0) {
            continue;
        }
        memcpy(key_out, e->key, VTY_KEY_BYTES);
        return VTY_OK;
    }
    return VTY_E_KEY_INVALID;
}

static void recovery_aad(const uint8_t vault_uuid[VTY_UUID_BYTES], uint64_t epoch,
                         uint32_t keyring_len,
                         uint8_t out[64], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_RECOVERY;
    size_t dlen = strlen(domain);

    memcpy(out, domain, dlen);
    memcpy(out + dlen, vault_uuid, VTY_UUID_BYTES);
    vty_put_u64(out + dlen + VTY_UUID_BYTES, epoch);
    vty_put_u32(out + dlen + VTY_UUID_BYTES + 8u, keyring_len);
    *out_len = dlen + VTY_UUID_BYTES + 8u + 4u;
}

int vty_recovery_slot_seal(VtySlot *s, const VtyKeyring *kr,
                           const uint8_t code[VTY_RECOVERY_CODE_BYTES],
                           const VtyV4Header *h, uint32_t index,
                           uint32_t mem_kib, uint32_t iters, uint32_t parallel)
{
    uint8_t plain[VTY_KEYRING_MAX_BYTES];
    uint8_t kek[VTY_KEY_BYTES];
    uint8_t aad[64];
    size_t plain_len = 0;
    size_t aad_len = 0;
    size_t ct_len = 0;
    int rc;

    if (s == NULL || kr == NULL || code == NULL || h == NULL) return VTY_E_INVALID;
    if (index >= VTY_V4_MAX_SLOTS) return VTY_E_INVALID;

    rc = vty_kdf_params_valid(mem_kib, iters, parallel);
    if (rc != VTY_OK) return rc;

    rc = vty_keyring_serialize(kr, plain, sizeof(plain), &plain_len);
    if (rc != VTY_OK) return rc;

    memset(s, 0, sizeof(*s));
    s->slot_type = VTY_SLOT_RECOVERY;
    s->slot_flags = VTY_SLOT_FLAG_REQUIRED | VTY_SLOT_FLAG_ROTATABLE;
    s->kdf_id = VTY_KDF_ARGON2ID;
    s->wrap_alg = VTY_WRAP_XCHACHA;
    s->params_len = 12u;
    s->m_cost = mem_kib;
    s->t_cost = iters;
    s->p_cost = parallel;
    vty_random(s->salt, VTY_SALT_BYTES);
    vty_random(s->nonce, VTY_NONCE_BYTES);

    rc = vty_kdf_argon2id(kek, code, VTY_RECOVERY_CODE_BYTES, s->salt,
                          mem_kib, iters, parallel);
    if (rc == VTY_OK) {
        recovery_aad(h->vault_uuid, h->epoch, (uint32_t)plain_len, aad, &aad_len);
        rc = vty_aead_seal(kek, s->nonce, aad, aad_len, plain, plain_len,
                           s->ct, VTY_SLOT_CT_MAX, &ct_len);
        if (rc == VTY_OK) s->ct_len = (uint16_t)ct_len;
    }

    vty_secure_zero(plain, sizeof(plain));
    vty_secure_zero(kek, sizeof(kek));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

int vty_recovery_slot_open(const VtySlot *s, const char *text,
                           const VtyV4Header *h, uint32_t index,
                           VtyKeyring *out)
{
    uint8_t code[VTY_RECOVERY_CODE_BYTES];
    uint8_t plain[VTY_KEYRING_MAX_BYTES];
    uint8_t kek[VTY_KEY_BYTES];
    uint8_t aad[64];
    size_t aad_len = 0;
    size_t plain_len = 0;
    int rc;

    (void)index;
    if (s == NULL || text == NULL || h == NULL || out == NULL) return VTY_E_INVALID;
    if (s->slot_type != VTY_SLOT_RECOVERY) return VTY_E_SLOT_UNKNOWN;
    if (s->kdf_id != VTY_KDF_ARGON2ID) return VTY_E_SLOT_UNKNOWN;
    if (s->ct_len <= VTY_TAG_BYTES || s->ct_len > VTY_SLOT_CT_MAX) return VTY_E_INVALID;

    rc = vty_recovery_decode(text, code);
    if (rc != VTY_OK) return rc;

    rc = vty_kdf_params_valid(s->m_cost, s->t_cost, s->p_cost);
    if (rc == VTY_OK) {
        rc = vty_kdf_argon2id(kek, code, VTY_RECOVERY_CODE_BYTES, s->salt,
                              s->m_cost, s->t_cost, s->p_cost);
    }
    if (rc == VTY_OK) {
        uint32_t keyring_len = (uint32_t)s->ct_len - VTY_TAG_BYTES;
        recovery_aad(h->vault_uuid, h->epoch, keyring_len, aad, &aad_len);
        rc = vty_aead_open(kek, s->nonce, aad, aad_len, s->ct, s->ct_len,
                           plain, sizeof(plain), &plain_len);
    }
    if (rc == VTY_OK) {
        rc = vty_keyring_parse(plain, plain_len, out);
    }

    vty_secure_zero(code, sizeof(code));
    vty_secure_zero(kek, sizeof(kek));
    vty_secure_zero(aad, sizeof(aad));
    vty_secure_zero(plain, sizeof(plain));
    return rc;
}
