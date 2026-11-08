/*
 * vty_module.c — 模块 M1 模块表与密钥生命周期
 *
 * 模块表存放在目录 keyspace 5。未启用模块的 MDEK 仍在 body Keyring；
 * 启用后 MDEK 移出 Keyring，只以 share_u/share_d 形式存于描述符槽。
 * 因此启用后仅持有 K_c 无法取得 MDEK，模块口令与设备根构成真实边界。
 *
 * 事务边界：所有写操作先写数据区（COW），再提交一次数据区，最后
 * 写一次元数据。提交前的失败恢复 store checkpoint；元数据提交失败
 * 一律锁定会话，避免代际不确定时继续写。
 */
#include "vty_module.h"
#include "vty_repo.h"
#include "vty_keyslot.h"
#include "vty_kdf.h"
#include "vty_util.h"
#include "vty_blake3.h"
#include "vty_device_root.h"
#include "vty_lockout.h"
#include "vty_machine_limiter.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MOD_DESC_VER 1u
#define MOD_REC_VER  1u
#define MOD_REC_CT   (VTY_KEY_BYTES + VTY_TAG_BYTES)

#define MOD_DESC_OFF_VER        0u
#define MOD_DESC_OFF_FLAGS      1u
#define MOD_DESC_OFF_INDEX      2u
#define MOD_DESC_OFF_RESERVED   3u
#define MOD_DESC_OFF_UUID       4u
#define MOD_DESC_OFF_EPOCH      20u
#define MOD_DESC_OFF_VERIFIER   28u
#define MOD_DESC_OFF_SLOT_COUNT 60u
#define MOD_DESC_OFF_RESERVED2  61u
#define MOD_DESC_OFF_SLOTS      64u

typedef struct {
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t enabled;
    uint8_t deleted;
    uint8_t has_recovery;
    uint64_t module_epoch;
    uint8_t verifier[VTY_HASH_BYTES];
    VtySlot user;
    VtySlot device;
    uint8_t rec_nonce[VTY_NONCE_BYTES];
    uint8_t rec_ct[MOD_REC_CT];
} ModuleDesc;

static int all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

static void desc_clear(ModuleDesc *d)
{
    if (d != NULL) vty_secure_zero(d, sizeof(*d));
}

static int module_aad(const VtyVault *v, const ModuleDesc *d,
                      uint8_t slot_index, uint8_t slot_type,
                      uint8_t out[96], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_MODULE;
    size_t dlen = strlen(domain);

    memcpy(out, domain, dlen);
    memcpy(out + dlen, v->header.vault_uuid, VTY_UUID_BYTES);
    memcpy(out + dlen + VTY_UUID_BYTES, d->uuid, VTY_UUID_BYTES);
    vty_put_u64(out + dlen + VTY_UUID_BYTES * 2u, d->module_epoch);
    out[dlen + VTY_UUID_BYTES * 2u + 8u] = slot_index;
    out[dlen + VTY_UUID_BYTES * 2u + 8u + 1u] = slot_type;
    *out_len = dlen + VTY_UUID_BYTES * 2u + 8u + 2u;
    return VTY_OK;
}

static int module_rec_aad(const VtyVault *v, const ModuleDesc *d,
                          uint8_t out[96], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_MODULE_RECOVERY;
    size_t dlen = strlen(domain);

    memcpy(out, domain, dlen);
    memcpy(out + dlen, v->header.vault_uuid, VTY_UUID_BYTES);
    memcpy(out + dlen + VTY_UUID_BYTES, d->uuid, VTY_UUID_BYTES);
    vty_put_u64(out + dlen + VTY_UUID_BYTES * 2u, d->module_epoch);
    out[dlen + VTY_UUID_BYTES * 2u + 8u] = (uint8_t)VTY_MODULE_SLOT_RECOVERY;
    out[dlen + VTY_UUID_BYTES * 2u + 8u + 1u] = (uint8_t)VTY_SLOT_RECOVERY;
    *out_len = dlen + VTY_UUID_BYTES * 2u + 8u + 2u;
    return VTY_OK;
}

/* K_mod_rec = HKDF(K_recovery, "module-recovery"|vault_uuid|module_uuid|epoch) */
static int module_rec_key(const VtyVault *v, const ModuleDesc *d,
                          const uint8_t krec[VTY_KEY_BYTES],
                          uint8_t out[VTY_KEY_BYTES])
{
    const char *domain = VTY_DOMAIN_MODULE_RECOVERY;
    uint8_t info[64];
    size_t dlen = strlen(domain);
    int rc;

    if (dlen + VTY_UUID_BYTES + 8u > sizeof(info)) return VTY_E_INVALID;
    memcpy(info, domain, dlen);
    memcpy(info + dlen, d->uuid, VTY_UUID_BYTES);
    vty_put_u64(info + dlen + VTY_UUID_BYTES, d->module_epoch);
    rc = vty_hkdf_expand(out, krec, info, dlen + VTY_UUID_BYTES + 8u);
    vty_secure_zero(info, sizeof(info));
    return rc;
}

static int module_verifier(const uint8_t mdek[VTY_KEY_BYTES],
                           const uint8_t module_uuid[VTY_UUID_BYTES],
                           uint8_t out[VTY_HASH_BYTES])
{
    uint8_t info[64];
    size_t llen = strlen(VTY_DOMAIN_MODULE);
    uint8_t vk[VTY_KEY_BYTES];
    int rc;

    memcpy(info, VTY_DOMAIN_MODULE, llen);
    memcpy(info + llen, module_uuid, VTY_UUID_BYTES);
    rc = vty_hkdf_expand(vk, mdek, info, llen + VTY_UUID_BYTES);
    if (rc == VTY_OK) {
        rc = vty_hmac_sha256(out, vk, VTY_KEY_BYTES,
                             (const uint8_t *)"verify", 6);
    }
    vty_secure_zero(vk, sizeof(vk));
    vty_secure_zero(info, sizeof(info));
    return rc;
}

static void desc_init_disabled(ModuleDesc *d,
                               const uint8_t uuid[VTY_UUID_BYTES])
{
    memset(d, 0, sizeof(*d));
    memcpy(d->uuid, uuid, VTY_UUID_BYTES);
    d->enabled = 0u;
    d->deleted = 0u;
    d->has_recovery = 0u;
    d->module_epoch = VTY_MODULE_EPOCH_DISABLED;
}

static void desc_init_deleted(ModuleDesc *d,
                              const uint8_t uuid[VTY_UUID_BYTES])
{
    memset(d, 0, sizeof(*d));
    memcpy(d->uuid, uuid, VTY_UUID_BYTES);
    d->enabled = 0u;
    d->deleted = 1u;
    d->has_recovery = 0u;
    d->module_epoch = VTY_MODULE_EPOCH_DISABLED;
}

static int desc_serialize(const ModuleDesc *d, uint32_t index,
                          uint8_t **out, size_t *out_len)
{
    uint8_t *buf;
    size_t total = MOD_DESC_OFF_SLOTS;
    size_t off;
    uint32_t slot_count;
    VtyHeader fake;
    int rc;

    if (d == NULL || out == NULL || out_len == NULL) return VTY_E_INVALID;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (d->enabled && d->deleted) return VTY_E_INVALID;
    if (d->enabled && d->module_epoch != VTY_MODULE_EPOCH_ENABLED) {
        return VTY_E_INVALID;
    }
    if (!d->enabled) {
        total = MOD_DESC_OFF_SLOTS;
    } else {
        total += vty_slot_serialized_len(&d->user);
        total += vty_slot_serialized_len(&d->device);
        if (d->has_recovery) total += VTY_MODULE_RECOVERY_BYTES;
    }
    if (total > VTY_MODULE_DESC_MAX) return VTY_E_INVALID;

    buf = (uint8_t *)vty_alloc(total);
    if (buf == NULL) return VTY_E_RESOURCE;

    buf[MOD_DESC_OFF_VER] = MOD_DESC_VER;
    buf[MOD_DESC_OFF_FLAGS] = d->enabled ? VTY_MODULE_FLAG_ENABLED :
                              (d->deleted ? VTY_MODULE_FLAG_DELETED : 0u);
    buf[MOD_DESC_OFF_INDEX] = (uint8_t)index;
    buf[MOD_DESC_OFF_RESERVED] = 0u;
    memcpy(buf + MOD_DESC_OFF_UUID, d->uuid, VTY_UUID_BYTES);
    vty_put_u64(buf + MOD_DESC_OFF_EPOCH, d->module_epoch);
    if (d->enabled) {
        memcpy(buf + MOD_DESC_OFF_VERIFIER, d->verifier, VTY_HASH_BYTES);
    }
    slot_count = d->enabled ? (d->has_recovery ? 3u : 2u) : 0u;
    buf[MOD_DESC_OFF_SLOT_COUNT] = (uint8_t)slot_count;
    memset(buf + MOD_DESC_OFF_RESERVED2, 0, 3u);

    if (!d->enabled) {
        *out = buf;
        *out_len = total;
        return VTY_OK;
    }

    memset(&fake, 0, sizeof(fake));
    off = MOD_DESC_OFF_SLOTS;
    {
        size_t w = 0;
        rc = vty_slot_write(&d->user, VTY_MODULE_SLOT_USER, &fake, buf + off,
                            total - off, &w);
        if (rc != VTY_OK) { vty_free(buf, total); return rc; }
        off += w;
        rc = vty_slot_write(&d->device, VTY_MODULE_SLOT_DEVICE, &fake, buf + off,
                            total - off, &w);
        if (rc != VTY_OK) { vty_free(buf, total); return rc; }
        off += w;
    }
    if (d->has_recovery) {
        if (total - off != VTY_MODULE_RECOVERY_BYTES) {
            vty_free(buf, total);
            return VTY_E_INVALID;
        }
        buf[off] = MOD_REC_VER;
        buf[off + 1u] = 0u;
        buf[off + 2u] = 0u;
        buf[off + 3u] = 0u;
        memcpy(buf + off + 4u, d->rec_nonce, VTY_NONCE_BYTES);
        memcpy(buf + off + 4u + VTY_NONCE_BYTES, d->rec_ct, MOD_REC_CT);
        off += VTY_MODULE_RECOVERY_BYTES;
    }
    if (off != total) { vty_free(buf, total); return VTY_E_INVALID; }

    *out = buf;
    *out_len = total;
    return VTY_OK;
}

static int desc_parse(const uint8_t *buf, size_t len, uint32_t expected_index,
                      ModuleDesc *out)
{
    VtyHeader fake;
    uint8_t slot_count;
    size_t off;
    int rc;

    if (buf == NULL || out == NULL || len < MOD_DESC_OFF_SLOTS) {
        return VTY_E_INVALID;
    }
    if (buf[MOD_DESC_OFF_VER] != MOD_DESC_VER) return VTY_E_VERSION;
    if ((buf[MOD_DESC_OFF_FLAGS] & (uint8_t)~0x03u) != 0) return VTY_E_SLOT_UNKNOWN;
    if (buf[MOD_DESC_OFF_INDEX] != (uint8_t)expected_index) return VTY_E_CORRUPT;
    if (buf[MOD_DESC_OFF_RESERVED] != 0) return VTY_E_CORRUPT;
    if (buf[MOD_DESC_OFF_RESERVED2] != 0 ||
        buf[MOD_DESC_OFF_RESERVED2 + 1u] != 0 ||
        buf[MOD_DESC_OFF_RESERVED2 + 2u] != 0) {
        return VTY_E_CORRUPT;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->uuid, buf + MOD_DESC_OFF_UUID, VTY_UUID_BYTES);
    if (all_zero(out->uuid, VTY_UUID_BYTES)) return VTY_E_CORRUPT;
    out->enabled = (uint8_t)(buf[MOD_DESC_OFF_FLAGS] & VTY_MODULE_FLAG_ENABLED);
    out->deleted = (uint8_t)((buf[MOD_DESC_OFF_FLAGS] & VTY_MODULE_FLAG_DELETED) != 0);
    if (out->enabled && out->deleted) {
        desc_clear(out);
        return VTY_E_CORRUPT;
    }
    out->module_epoch = vty_get_u64(buf + MOD_DESC_OFF_EPOCH);
    memcpy(out->verifier, buf + MOD_DESC_OFF_VERIFIER, VTY_HASH_BYTES);
    slot_count = buf[MOD_DESC_OFF_SLOT_COUNT];

    if (!out->enabled) {
        if (len != MOD_DESC_OFF_SLOTS || slot_count != 0u ||
            out->module_epoch != VTY_MODULE_EPOCH_DISABLED ||
            !all_zero(out->verifier, VTY_HASH_BYTES)) {
            desc_clear(out);
            return VTY_E_CORRUPT;
        }
        return VTY_OK;
    }

    if (out->module_epoch != VTY_MODULE_EPOCH_ENABLED) {
        desc_clear(out);
        return VTY_E_CORRUPT;
    }
    if (slot_count != 2u && slot_count != 3u) {
        desc_clear(out);
        return VTY_E_CORRUPT;
    }
    if (all_zero(out->verifier, VTY_HASH_BYTES)) {
        desc_clear(out);
        return VTY_E_CORRUPT;
    }

    memset(&fake, 0, sizeof(fake));
    off = MOD_DESC_OFF_SLOTS;
    {
        size_t consumed = 0;
        rc = vty_slot_parse_at(buf, len, off, VTY_MODULE_SLOT_USER, &fake,
                               &out->user, &consumed);
        if (rc != VTY_OK) { desc_clear(out); return rc; }
        off += consumed;
        if (out->user.slot_type != VTY_SLOT_USER_PASSWORD ||
            out->user.kdf_id != VTY_KDF_ARGON2ID ||
            out->user.wrap_alg != VTY_WRAP_XCHACHA ||
            (out->user.slot_flags & VTY_SLOT_FLAG_REQUIRED) == 0 ||
            vty_kdf_params_valid(out->user.m_cost, out->user.t_cost,
                                 out->user.p_cost) != VTY_OK) {
            desc_clear(out);
            return VTY_E_SLOT_UNKNOWN;
        }
        rc = vty_slot_parse_at(buf, len, off, VTY_MODULE_SLOT_DEVICE, &fake,
                               &out->device, &consumed);
        if (rc != VTY_OK) { desc_clear(out); return rc; }
        off += consumed;
        if (out->device.slot_type != VTY_SLOT_DEVICE_ROOT ||
            out->device.kdf_id != VTY_KDF_NONE ||
            out->device.wrap_alg != VTY_WRAP_RSAOAEP) {
            desc_clear(out);
            return VTY_E_SLOT_UNKNOWN;
        }
    }

    if (slot_count == 3u) {
        size_t rec_len = VTY_MODULE_RECOVERY_BYTES;
        if (len - off != rec_len) { desc_clear(out); return VTY_E_CORRUPT; }
        if (buf[off] != MOD_REC_VER || buf[off + 1u] != 0u ||
            buf[off + 2u] != 0u || buf[off + 3u] != 0u) {
            desc_clear(out);
            return VTY_E_CORRUPT;
        }
        memcpy(out->rec_nonce, buf + off + 4u, VTY_NONCE_BYTES);
        memcpy(out->rec_ct, buf + off + 4u + VTY_NONCE_BYTES, MOD_REC_CT);
        out->has_recovery = 1u;
        off += rec_len;
    } else {
        out->has_recovery = 0u;
    }
    if (off != len) { desc_clear(out); return VTY_E_CORRUPT; }
    return VTY_OK;
}

static int desc_load(VtyVault *v, uint32_t index, ModuleDesc *out)
{
    uint8_t key = (uint8_t)index;
    uint8_t *value = NULL;
    size_t value_len = 0;
    int rc;

    if (v == NULL || v->store == NULL || out == NULL) return VTY_E_INVALID;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;

    rc = vty_store_get(v->store, VTY_KS_MODULE, &key, 1u, &value, &value_len);
    if (rc != VTY_OK) return VTY_E_CORRUPT;
    rc = desc_parse(value, value_len, index, out);
    if (value != NULL) vty_free(value, value_len);
    return rc;
}

static int desc_store(VtyVault *v, uint32_t index, const ModuleDesc *d)
{
    uint8_t key = (uint8_t)index;
    uint8_t *buf = NULL;
    size_t len = 0;
    int rc;

    if (v == NULL || v->store == NULL || d == NULL) return VTY_E_INVALID;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;

    rc = desc_serialize(d, index, &buf, &len);
    if (rc != VTY_OK) return rc;
    rc = vty_store_put(v->store, VTY_KS_MODULE, &key, 1u, buf, len);
    vty_free(buf, len);
    return rc;
}

static int desc_seal_user(VtyVault *v, ModuleDesc *d, const char *password,
                          const uint8_t share_u[VTY_KEY_BYTES])
{
    uint8_t kek[VTY_KEY_BYTES];
    uint8_t aad[96];
    size_t aad_len = 0;
    int rc;

    if (password == NULL) return VTY_E_INVALID;
    memset(&d->user, 0, sizeof(d->user));
    d->user.slot_type = VTY_SLOT_USER_PASSWORD;
    d->user.slot_flags = VTY_SLOT_FLAG_REQUIRED | VTY_SLOT_FLAG_ROTATABLE;
    d->user.kdf_id = VTY_KDF_ARGON2ID;
    d->user.wrap_alg = VTY_WRAP_XCHACHA;
    d->user.params_len = 12u;
    d->user.m_cost = v->mem_kib;
    d->user.t_cost = v->iters;
    d->user.p_cost = v->parallel;
    vty_random(d->user.salt, VTY_SALT_BYTES);

    rc = vty_kdf_argon2id(kek, (const uint8_t *)password, strlen(password),
                          d->user.salt, v->mem_kib, v->iters, v->parallel);
    if (rc != VTY_OK) { vty_secure_zero(kek, sizeof(kek)); return rc; }

    module_aad(v, d, VTY_MODULE_SLOT_USER, VTY_SLOT_USER_PASSWORD, aad, &aad_len);
    rc = vty_wrap_key32(kek, share_u, aad, aad_len, d->user.nonce, d->user.ct);
    vty_secure_zero(kek, sizeof(kek));
    vty_secure_zero(aad, sizeof(aad));
    if (rc == VTY_OK) d->user.ct_len = MOD_REC_CT;
    return rc;
}

static int desc_seal_device(VtyVault *v, ModuleDesc *d,
                            const uint8_t share_d[VTY_KEY_BYTES])
{
    (void)v;
    return vty_slot_seal_device(&d->device, VTY_SLOT_FLAG_REQUIRED, share_d,
                                NULL, VTY_MODULE_SLOT_DEVICE);
}

static int desc_seal_recovery(VtyVault *v, ModuleDesc *d,
                              const uint8_t krec[VTY_KEY_BYTES],
                              const uint8_t share_d[VTY_KEY_BYTES])
{
    uint8_t krec_mod[VTY_KEY_BYTES];
    uint8_t aad[96];
    size_t aad_len = 0;
    int rc;

    rc = module_rec_key(v, d, krec, krec_mod);
    if (rc != VTY_OK) return rc;
    module_rec_aad(v, d, aad, &aad_len);
    rc = vty_wrap_key32(krec_mod, share_d, aad, aad_len,
                        d->rec_nonce, d->rec_ct);
    vty_secure_zero(krec_mod, sizeof(krec_mod));
    vty_secure_zero(aad, sizeof(aad));
    if (rc == VTY_OK) d->has_recovery = 1u;
    return rc;
}

static int desc_open_user(VtyVault *v, const ModuleDesc *d,
                          const char *password,
                          uint8_t share_u[VTY_KEY_BYTES])
{
    uint8_t kek[VTY_KEY_BYTES];
    uint8_t aad[96];
    size_t aad_len = 0;
    int rc;

    if (password == NULL || password[0] == '\0') return VTY_E_INVALID;
    if (vty_kdf_params_valid(d->user.m_cost, d->user.t_cost,
                             d->user.p_cost) != VTY_OK) {
        return VTY_E_KDF_WEAK;
    }
    rc = vty_kdf_argon2id(kek, (const uint8_t *)password, strlen(password),
                          d->user.salt, d->user.m_cost, d->user.t_cost,
                          d->user.p_cost);
    if (rc != VTY_OK) { vty_secure_zero(kek, sizeof(kek)); return rc; }

    module_aad(v, d, VTY_MODULE_SLOT_USER, VTY_SLOT_USER_PASSWORD, aad, &aad_len);
    rc = vty_unwrap_key32(kek, d->user.nonce, aad, aad_len,
                          d->user.ct, d->user.ct_len, share_u);
    vty_secure_zero(kek, sizeof(kek));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

static int desc_open_recovery(VtyVault *v, const ModuleDesc *d,
                              uint8_t share_d[VTY_KEY_BYTES])
{
    uint8_t krec_mod[VTY_KEY_BYTES];
    uint8_t aad[96];
    size_t aad_len = 0;
    int rc;

    if (!d->has_recovery) return VTY_E_SLOT_MISSING;
    if (all_zero(v->k_recovery, VTY_KEY_BYTES)) return VTY_E_POLICY;
    rc = module_rec_key(v, d, v->k_recovery, krec_mod);
    if (rc != VTY_OK) return rc;
    module_rec_aad(v, d, aad, &aad_len);
    rc = vty_unwrap_key32(krec_mod, d->rec_nonce, aad, aad_len,
                          d->rec_ct, MOD_REC_CT, share_d);
    vty_secure_zero(krec_mod, sizeof(krec_mod));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

/* 解出 share_u/share_d 并校验 verifier。
 *
 * 口令失败只计入模块锁（按 vault_uuid + module_index 区分作用域），
 * 不污染库级熔断；成功后只重置本模块作用域。 */
static int desc_open_shares(VtyVault *v, uint32_t module_index,
                            const ModuleDesc *d, const char *password,
                            uint8_t share_u[VTY_KEY_BYTES],
                            uint8_t share_d[VTY_KEY_BYTES],
                            uint8_t mdek[VTY_KEY_BYTES])
{
    uint8_t verifier[VTY_HASH_BYTES];
    const uint8_t *vault_uuid = v->header.vault_uuid;
    int rc;
    size_t i;

    if (vty_machine_limiter_check() != VTY_OK) return VTY_E_LOCKED;
    if (vty_lockout_enabled()) {
        if (vty_lockout_init() != VTY_OK) return VTY_E_MODULE_LOCKED;
        if (vty_lockout_module_begin_attempt(vault_uuid, module_index) != VTY_OK) {
            return VTY_E_MODULE_LOCKED;
        }
    }

    rc = desc_open_user(v, d, password, share_u);
    if (rc != VTY_OK) {
        if (rc == VTY_E_KEY_INVALID) {
            if (vty_lockout_enabled()) {
                (void)vty_lockout_module_record_failure(vault_uuid, module_index);
            }
            (void)vty_machine_limiter_record_failure();
        }
        return rc;
    }

    rc = vty_slot_open_device(&d->device, NULL, VTY_MODULE_SLOT_DEVICE, share_d);
    if (rc != VTY_OK && v->recovery_mode && d->has_recovery) {
        int rrc = desc_open_recovery(v, d, share_d);
        if (rrc != VTY_OK) rc = rrc;
        else rc = VTY_OK;
    }
    if (rc != VTY_OK) return rc;

    for (i = 0; i < VTY_KEY_BYTES; i++) mdek[i] = (uint8_t)(share_u[i] ^ share_d[i]);
    memset(verifier, 0, sizeof(verifier));
    rc = module_verifier(mdek, d->uuid, verifier);
    if (rc == VTY_OK && vty_ct_equal(verifier, d->verifier, VTY_HASH_BYTES) != 0) {
        rc = VTY_E_KEY_INVALID;
    }
    vty_secure_zero(verifier, sizeof(verifier));
    if (rc != VTY_OK) {
        vty_secure_zero(mdek, VTY_KEY_BYTES);
        if (rc == VTY_E_KEY_INVALID) {
            if (vty_lockout_enabled()) {
                (void)vty_lockout_module_record_failure(vault_uuid, module_index);
            }
            (void)vty_machine_limiter_record_failure();
        }
    } else {
        /* 成功只重置本模块作用域；库锁不受影响 */
        if (vty_lockout_enabled()) {
            (void)vty_lockout_module_reset(vault_uuid, module_index);
        }
        (void)vty_machine_limiter_reset();
    }
    return rc;
}

/* 用恢复码验证并派生 K_recovery；K_c 必须与会话一致。 */
static int krec_from_code(VtyVault *v, const char *recovery_text,
                          uint8_t krec_out[VTY_KEY_BYTES])
{
    int idx;
    VtyKeyring kr;
    uint8_t kc[VTY_KEY_BYTES];
    int rc;

    if (recovery_text == NULL || recovery_text[0] == '\0') return VTY_E_INVALID;
    idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_RECOVERY);
    if (idx < 0) return VTY_E_SLOT_MISSING;

    memset(&kr, 0, sizeof(kr));
    memset(kc, 0, sizeof(kc));
    rc = vty_recovery_slot_open(&v->slots[idx], recovery_text, &v->header,
                                (uint32_t)idx, &kr, krec_out);
    if (rc == VTY_OK) {
        rc = vty_keyring_find(&kr, VTY_KEYKIND_KC, NULL, 0, kc);
    }
    if (rc == VTY_OK && vty_ct_equal(kc, v->kc, VTY_KEY_BYTES) != 0) {
        rc = VTY_E_KEY_INVALID;
    }
    vty_secure_zero(&kr, sizeof(kr));
    vty_secure_zero(kc, sizeof(kc));
    if (rc != VTY_OK) vty_secure_zero(krec_out, VTY_KEY_BYTES);
    return rc;
}

static int keyring_find_mdek(const VtyKeyring *kr,
                             const uint8_t uuid[VTY_UUID_BYTES],
                             uint8_t out[VTY_KEY_BYTES])
{
    return vty_keyring_find(kr, VTY_KEYKIND_MDEK, uuid, VTY_UUID_BYTES, out);
}

static int keyring_remove_mdek(VtyKeyring *kr,
                               const uint8_t uuid[VTY_UUID_BYTES])
{
    uint32_t i;
    for (i = 0; i < kr->count; i++) {
        VtyKeyEntry *e = &kr->entries[i];
        if (e->kind != VTY_KEYKIND_MDEK) continue;
        if (e->id_len != VTY_UUID_BYTES ||
            memcmp(e->id, uuid, VTY_UUID_BYTES) != 0) continue;
        if (i + 1u < kr->count) {
            memmove(&kr->entries[i], &kr->entries[i + 1u],
                    (kr->count - i - 1u) * sizeof(kr->entries[0]));
        }
        kr->count--;
        vty_secure_zero(&kr->entries[kr->count], sizeof(kr->entries[0]));
        return VTY_OK;
    }
    return VTY_E_INVALID;
}

static int keyring_add_mdek(VtyKeyring *kr,
                            const uint8_t uuid[VTY_UUID_BYTES],
                            const uint8_t mdek[VTY_KEY_BYTES])
{
    VtyKeyEntry *e;
    uint8_t existing[VTY_KEY_BYTES];

    if (keyring_find_mdek(kr, uuid, existing) == VTY_OK) return VTY_E_INVALID;
    if (kr->count >= VTY_KEYRING_MAX_ENTRIES) return VTY_E_RESOURCE;
    e = &kr->entries[kr->count];
    memset(e, 0, sizeof(*e));
    e->kind = VTY_KEYKIND_MDEK;
    e->id_len = VTY_UUID_BYTES;
    memcpy(e->id, uuid, VTY_UUID_BYTES);
    memcpy(e->key, mdek, VTY_KEY_BYTES);
    kr->count++;
    return VTY_OK;
}

/* 卷剩余空间必须覆盖模块重写追加量与余量；不足时在写盘前拒绝。 */
static int module_free_space_ok(const VtyVault *v, uint64_t need)
{
    wchar_t wpath[1024];
    wchar_t volume[1024];
    ULARGE_INTEGER free_bytes;
    int n;
    uint64_t required;

    if (v->path[0] == '\0') return VTY_E_INVALID;
    n = MultiByteToWideChar(CP_UTF8, 0, v->path, -1, wpath,
                            (int)(sizeof(wpath) / sizeof(wpath[0])));
    if (n <= 0) return VTY_E_INVALID;
    if (!GetVolumePathNameW(wpath, volume,
                            (DWORD)(sizeof(volume) / sizeof(volume[0])))) {
        return VTY_E_IO;
    }
    if (!GetDiskFreeSpaceExW(volume, &free_bytes, NULL, NULL)) return VTY_E_IO;
    if (need > UINT64_MAX - (1024u * 1024u)) return VTY_E_RESOURCE;
    required = need + need / 10u + (1024u * 1024u);
    return (free_bytes.QuadPart >= required) ? VTY_OK : VTY_E_RESOURCE;
}

uint32_t vty_module_index_for_type(uint8_t type)
{
    switch (type) {
    case 0x02: case 0x03: case 0x0A: case 0x20:
        return 1u; /* accounts */
    case 0x04: case 0x08:
        return 2u; /* fileverthys */
    default:
        return 0u; /* photo / 未知 */
    }
}

int vty_module_table_init(VtyVault *v)
{
    uint32_t i, n = 0;
    ModuleDesc d;
    int rc;

    if (v == NULL || v->store == NULL || !v->unlocked) return VTY_E_POLICY;

    memset(v->modules, 0, sizeof(v->modules));
    for (i = 0; i < v->keyring.count; i++) {
        VtyKeyEntry *e = &v->keyring.entries[i];
        if (e->kind != VTY_KEYKIND_MDEK) continue;
        if (n >= VTY_MODULE_COUNT) return VTY_E_CORRUPT;
        desc_init_disabled(&d, e->id);
        rc = desc_store(v, n, &d);
        desc_clear(&d);
        if (rc != VTY_OK) return rc;
        memcpy(v->modules[n].uuid, e->id, VTY_UUID_BYTES);
        n++;
    }
    if (n != VTY_MODULE_COUNT) return VTY_E_CORRUPT;
    /* 模块表使新库目录非空；同时建立记录分配器，避免首次 Add
     * 把“目录非空但没有分配器”误判为 E_CORRUPT。 */
    rc = vty_repo_init_allocator(v);
    if (rc != VTY_OK) return rc;
    return vty_vault_commit_store(v);
}

int vty_module_table_load(VtyVault *v)
{
    ModuleDesc descs[VTY_MODULE_COUNT];
    uint32_t i, j, disabled_count = 0, enabled_count = 0;
    int rc;

    if (v == NULL || v->store == NULL || !v->unlocked) return VTY_E_POLICY;

    memset(descs, 0, sizeof(descs));
    memset(v->modules, 0, sizeof(v->modules));

    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        rc = desc_load(v, i, &descs[i]);
        if (rc != VTY_OK) goto fail;
        if (descs[i].enabled) enabled_count++;
        else if (!descs[i].deleted) disabled_count++;
        memcpy(v->modules[i].uuid, descs[i].uuid, VTY_UUID_BYTES);
        v->modules[i].enabled = descs[i].enabled;
        v->modules[i].deleted = descs[i].deleted;
        v->modules[i].has_recovery = descs[i].has_recovery;
        v->modules[i].unlocked = 0u;
        vty_secure_zero(v->modules[i].mdek, VTY_KEY_BYTES);
        for (j = 0; j < i; j++) {
            if (memcmp(descs[j].uuid, descs[i].uuid, VTY_UUID_BYTES) == 0) {
                rc = VTY_E_CORRUPT;
                goto fail;
            }
        }
    }

    if (((v->header.flags & VTY_FLAG_MODULE_M1) != 0) != (enabled_count != 0)) {
        rc = VTY_E_CORRUPT;
        goto fail;
    }

    {
        uint32_t kind3 = 0;
        for (i = 0; i < v->keyring.count; i++) {
            VtyKeyEntry *e = &v->keyring.entries[i];
            int found = 0;
            if (e->kind != VTY_KEYKIND_MDEK) continue;
            kind3++;
            for (j = 0; j < VTY_MODULE_COUNT; j++) {
                if (e->id_len == VTY_UUID_BYTES &&
                    memcmp(e->id, descs[j].uuid, VTY_UUID_BYTES) == 0) {
                    found = 1;
                    if (descs[j].enabled || descs[j].deleted ||
                        all_zero(e->key, VTY_KEY_BYTES)) {
                        rc = VTY_E_CORRUPT;
                        goto fail;
                    }
                    break;
                }
            }
            if (!found) { rc = VTY_E_CORRUPT; goto fail; }
        }
        if (kind3 != disabled_count) { rc = VTY_E_CORRUPT; goto fail; }
    }

    for (i = 0; i < VTY_MODULE_COUNT; i++) desc_clear(&descs[i]);
    return VTY_OK;

fail:
    for (i = 0; i < VTY_MODULE_COUNT; i++) desc_clear(&descs[i]);
    memset(v->modules, 0, sizeof(v->modules));
    return rc;
}

int vty_module_enable(VtyVault *v, uint32_t index, const char *password,
                      const char *recovery_code)
{
    ModuleDesc desc;
    ModuleDesc new_desc;
    VtyStoreCheckpoint cp;
    VtyKeyring old_kr;
    VtyKeyring new_kr;
    VtyModuleState old_state;
    uint16_t old_flags;
    uint8_t old_mdek[VTY_KEY_BYTES];
    uint8_t new_mdek[VTY_KEY_BYTES];
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t krec[VTY_KEY_BYTES];
    uint64_t need = 0;
    int have_krec = 0;
    int rc;
    size_t i;

    memset(&desc, 0, sizeof(desc));
    memset(&new_desc, 0, sizeof(new_desc));
    memset(old_mdek, 0, sizeof(old_mdek));
    memset(new_mdek, 0, sizeof(new_mdek));
    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    memset(krec, 0, sizeof(krec));
    memset(&old_kr, 0, sizeof(old_kr));
    memset(&new_kr, 0, sizeof(new_kr));
    memset(&old_state, 0, sizeof(old_state));

    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (password == NULL || password[0] == '\0' ||
        strlen(password) > VTY_MODULE_PASSWORD_MAX) {
        return VTY_E_INVALID;
    }
    /* 已启用不可重复启用；deleted 允许重建空模块。 */
    if (v->modules[index].enabled) return VTY_E_POLICY;

    rc = desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (desc.enabled || memcmp(desc.uuid, v->modules[index].uuid,
                               VTY_UUID_BYTES) != 0) {
        desc_clear(&desc);
        return VTY_E_CORRUPT;
    }
    if (!desc.deleted) {
        rc = keyring_find_mdek(&v->keyring, desc.uuid, old_mdek);
        if (rc != VTY_OK) { desc_clear(&desc); return VTY_E_CORRUPT; }
    }
    if (vty_kdf_params_valid(v->mem_kib, v->iters, v->parallel) != VTY_OK) {
        desc_clear(&desc);
        return VTY_E_KDF_WEAK;
    }

    if (recovery_code != NULL) {
        rc = krec_from_code(v, recovery_code, krec);
        if (rc != VTY_OK) {
            desc_clear(&desc);
            return rc;
        }
        have_krec = 1;
    }

    if (!desc.deleted) {
        rc = vty_repo_module_rekey_bytes(v, index, &need);
        if (rc == VTY_OK) rc = module_free_space_ok(v, need);
        if (rc != VTY_OK) {
            desc_clear(&desc);
            vty_secure_zero(krec, sizeof(krec));
            return rc;
        }
    }

    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) {
        desc_clear(&desc);
        vty_secure_zero(krec, sizeof(krec));
        return rc;
    }
    old_kr = v->keyring;
    old_state = v->modules[index];
    old_flags = v->header.flags;

    vty_random(new_mdek, VTY_KEY_BYTES);
    vty_random(share_u, VTY_KEY_BYTES);
    for (i = 0; i < VTY_KEY_BYTES; i++) {
        share_d[i] = (uint8_t)(new_mdek[i] ^ share_u[i]);
    }

    memset(&new_desc, 0, sizeof(new_desc));
    memcpy(new_desc.uuid, desc.uuid, VTY_UUID_BYTES);
    new_desc.enabled = 1u;
    new_desc.module_epoch = VTY_MODULE_EPOCH_ENABLED;
    rc = module_verifier(new_mdek, new_desc.uuid, new_desc.verifier);
    if (rc == VTY_OK) {
        rc = desc_seal_user(v, &new_desc, password, share_u);
    }
    if (rc == VTY_OK) rc = desc_seal_device(v, &new_desc, share_d);
    if (rc == VTY_OK && have_krec) {
        rc = desc_seal_recovery(v, &new_desc, krec, share_d);
    }
    if (rc == VTY_OK && !desc.deleted) {
        rc = vty_repo_module_rekey(v, index, old_mdek, new_mdek);
    }
    if (rc == VTY_OK) rc = desc_store(v, index, &new_desc);
    if (rc == VTY_OK) {
        new_kr = v->keyring;
        if (!desc.deleted) rc = keyring_remove_mdek(&new_kr, new_desc.uuid);
    }
    if (rc == VTY_OK) rc = vty_vault_commit_store(v);
    if (rc != VTY_OK) {
        (void)vty_store_restore(v->store, &cp);
        goto fail;
    }

    v->keyring = new_kr;
    v->header.flags = (uint16_t)(v->header.flags | VTY_FLAG_MODULE_M1);
    v->modules[index].enabled = 1u;
    v->modules[index].deleted = 0u;
    v->modules[index].unlocked = 1u;
    v->modules[index].has_recovery = new_desc.has_recovery;
    memcpy(v->modules[index].mdek, new_mdek, VTY_KEY_BYTES);

    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        goto fail;
    }

    desc_clear(&desc);
    desc_clear(&new_desc);
    vty_secure_zero(&old_kr, sizeof(old_kr));
    vty_secure_zero(&new_kr, sizeof(new_kr));
    vty_secure_zero(&old_state, sizeof(old_state));
    vty_secure_zero(old_mdek, sizeof(old_mdek));
    vty_secure_zero(new_mdek, sizeof(new_mdek));
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(krec, sizeof(krec));
    return VTY_OK;

fail:
    v->keyring = old_kr;
    v->header.flags = old_flags;
    v->modules[index] = old_state;
    desc_clear(&desc);
    desc_clear(&new_desc);
    vty_secure_zero(&old_kr, sizeof(old_kr));
    vty_secure_zero(&new_kr, sizeof(new_kr));
    vty_secure_zero(&old_state, sizeof(old_state));
    vty_secure_zero(old_mdek, sizeof(old_mdek));
    vty_secure_zero(new_mdek, sizeof(new_mdek));
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(krec, sizeof(krec));
    return rc;
}

int vty_module_delete(VtyVault *v, uint32_t index,
                      const char *password, const char *confirm)
{
    ModuleDesc desc;
    ModuleDesc deleted_desc;
    VtyStoreCheckpoint cp;
    VtyKeyring old_kr;
    VtyKeyring new_kr;
    VtyModuleState old_state;
    uint16_t old_flags;
    uint8_t old_uuid[VTY_UUID_BYTES];
    uint8_t new_uuid[VTY_UUID_BYTES];
    uint8_t check_key[VTY_KEY_BYTES];
    uint64_t records = 0, files = 0, chunks = 0;
    uint32_t i;
    int any_enabled = 0;
    int rc;

    memset(&desc, 0, sizeof(desc));
    memset(&deleted_desc, 0, sizeof(deleted_desc));
    memset(&old_kr, 0, sizeof(old_kr));
    memset(&new_kr, 0, sizeof(new_kr));
    memset(&old_state, 0, sizeof(old_state));
    memset(old_uuid, 0, sizeof(old_uuid));
    memset(new_uuid, 0, sizeof(new_uuid));
    memset(check_key, 0, sizeof(check_key));

    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (confirm == NULL || strcmp(confirm, "DELETE") != 0) return VTY_E_INVALID;

    /* 普通会话必须重新验证容器口令；恢复会话已由恢复码根认证，
     * 允许空口令，但提供了口令时仍必须正确。 */
    if (password != NULL && password[0] != '\0') {
        rc = vty_vault_verify_user_password(v, password);
        if (rc != VTY_OK) return rc;
    } else if (!v->recovery_mode) {
        return VTY_E_INVALID;
    }

    rc = desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (desc.deleted) {
        desc_clear(&desc);
        return VTY_E_POLICY;
    }
    if (memcmp(desc.uuid, v->modules[index].uuid, VTY_UUID_BYTES) != 0) {
        desc_clear(&desc);
        return VTY_E_CORRUPT;
    }
    memcpy(old_uuid, desc.uuid, VTY_UUID_BYTES);

    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) { desc_clear(&desc); return rc; }
    old_kr = v->keyring;
    old_state = v->modules[index];
    old_flags = v->header.flags;

    rc = vty_repo_module_purge(v, index, old_uuid, &records, &files, &chunks);
    if (rc != VTY_OK) goto fail;

    do {
        vty_random(new_uuid, VTY_UUID_BYTES);
    } while (all_zero(new_uuid, VTY_UUID_BYTES));
    desc_init_deleted(&deleted_desc, new_uuid);
    rc = desc_store(v, index, &deleted_desc);
    if (rc != VTY_OK) goto fail;

    /* 销毁旧 MDEK：未启用模块必须存在 kind 3；已启用模块应当不存在。
     * 若存在则一并删除，确保任何残留副本都不再可解。 */
    new_kr = v->keyring;
    rc = keyring_find_mdek(&new_kr, old_uuid, check_key);
    if (rc == VTY_OK) {
        rc = keyring_remove_mdek(&new_kr, old_uuid);
        if (rc != VTY_OK) goto fail;
    } else if (!old_state.enabled) {
        /* 未启用状态缺失 MDEK 说明库已不一致 */
        rc = VTY_E_CORRUPT;
        goto fail;
    } else {
        rc = VTY_OK;
    }
    vty_secure_zero(check_key, sizeof(check_key));

    rc = vty_vault_commit_store(v);
    if (rc != VTY_OK) goto fail;

    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        if (i != index && v->modules[i].enabled) any_enabled = 1;
    }
    v->keyring = new_kr;
    v->header.flags = any_enabled
                          ? (uint16_t)(v->header.flags | VTY_FLAG_MODULE_M1)
                          : (uint16_t)(v->header.flags & ~VTY_FLAG_MODULE_M1);
    memset(&v->modules[index], 0, sizeof(v->modules[index]));
    memcpy(v->modules[index].uuid, new_uuid, VTY_UUID_BYTES);
    v->modules[index].deleted = 1u;

    /* 第一次写新代；第二次覆盖另一副本，移除仍含旧 MDEK 的低代副本。 */
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) goto fail;
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) goto fail;

    desc_clear(&desc);
    desc_clear(&deleted_desc);
    vty_secure_zero(&old_kr, sizeof(old_kr));
    vty_secure_zero(&new_kr, sizeof(new_kr));
    vty_secure_zero(&old_state, sizeof(old_state));
    vty_secure_zero(old_uuid, sizeof(old_uuid));
    vty_secure_zero(new_uuid, sizeof(new_uuid));
    vty_secure_zero(check_key, sizeof(check_key));
    (void)records; (void)files; (void)chunks;
    return VTY_OK;

fail:
    (void)vty_store_restore(v->store, &cp);
    v->keyring = old_kr;
    v->header.flags = old_flags;
    v->modules[index] = old_state;
    desc_clear(&desc);
    desc_clear(&deleted_desc);
    vty_secure_zero(&old_kr, sizeof(old_kr));
    vty_secure_zero(&new_kr, sizeof(new_kr));
    vty_secure_zero(&old_state, sizeof(old_state));
    vty_secure_zero(old_uuid, sizeof(old_uuid));
    vty_secure_zero(new_uuid, sizeof(new_uuid));
    vty_secure_zero(check_key, sizeof(check_key));
    if (rc != VTY_OK && v->unlocked == 0) return rc;
    return rc;
}

int vty_module_unlock(VtyVault *v, uint32_t index, const char *password)
{
    ModuleDesc desc;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    int rc;

    memset(&desc, 0, sizeof(desc));
    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    memset(mdek, 0, sizeof(mdek));

    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (!v->modules[index].enabled) return VTY_E_POLICY;
    if (password == NULL || password[0] == '\0' ||
        strlen(password) > VTY_MODULE_PASSWORD_MAX) {
        return VTY_E_INVALID;
    }

    rc = desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (!desc.enabled || memcmp(desc.uuid, v->modules[index].uuid,
                                VTY_UUID_BYTES) != 0) {
        desc_clear(&desc);
        return VTY_E_CORRUPT;
    }

    rc = desc_open_shares(v, index, &desc, password, share_u, share_d, mdek);
    if (rc != VTY_OK) {
        desc_clear(&desc);
        vty_secure_zero(share_u, sizeof(share_u));
        vty_secure_zero(share_d, sizeof(share_d));
        vty_secure_zero(mdek, sizeof(mdek));
        return rc;
    }

    memcpy(v->modules[index].mdek, mdek, VTY_KEY_BYTES);
    v->modules[index].unlocked = 1u;
    v->modules[index].has_recovery = desc.has_recovery;

    desc_clear(&desc);
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(mdek, sizeof(mdek));
    return VTY_OK;
}

void vty_module_lock(VtyVault *v, uint32_t index)
{
    uint32_t i;

    if (v == NULL) return;
    if (index == VTY_MODULE_ALL) {
        for (i = 0; i < VTY_MODULE_COUNT; i++) {
            v->modules[i].unlocked = 0u;
            vty_secure_zero(v->modules[i].mdek, VTY_KEY_BYTES);
        }
        return;
    }
    if (index >= VTY_MODULE_COUNT) return;
    v->modules[index].unlocked = 0u;
    vty_secure_zero(v->modules[index].mdek, VTY_KEY_BYTES);
}

int vty_module_status(const VtyVault *v, uint32_t index, VtyModuleStatus *out)
{
    if (v == NULL || out == NULL) return VTY_E_INVALID;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    out->enabled = v->modules[index].enabled;
    out->unlocked = v->modules[index].unlocked;
    out->has_recovery = v->modules[index].has_recovery;
    out->deleted = v->modules[index].deleted;
    return VTY_OK;
}

int vty_module_rotate_password(VtyVault *v, uint32_t index,
                               const char *old_password,
                               const char *new_password)
{
    ModuleDesc desc;
    VtyStoreCheckpoint cp;
    VtyModuleState old_state;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    int rc;

    memset(&desc, 0, sizeof(desc));
    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    memset(mdek, 0, sizeof(mdek));
    memset(&old_state, 0, sizeof(old_state));

    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (!v->modules[index].enabled) return VTY_E_POLICY;
    if (new_password == NULL || new_password[0] == '\0' ||
        strlen(new_password) > VTY_MODULE_PASSWORD_MAX) {
        return VTY_E_INVALID;
    }

    rc = desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (!desc.enabled) { desc_clear(&desc); return VTY_E_POLICY; }

    rc = desc_open_shares(v, index, &desc, old_password, share_u, share_d, mdek);
    if (rc != VTY_OK) goto out;

    rc = desc_seal_user(v, &desc, new_password, share_u);
    if (rc != VTY_OK) goto out;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) goto out;
    old_state = v->modules[index];
    rc = desc_store(v, index, &desc);
    if (rc == VTY_OK) rc = vty_vault_commit_store(v);
    if (rc != VTY_OK) {
        (void)vty_store_restore(v->store, &cp);
        v->modules[index] = old_state;
        goto out;
    }
    v->modules[index].unlocked = 1u;
    v->modules[index].has_recovery = desc.has_recovery;
    memcpy(v->modules[index].mdek, mdek, VTY_KEY_BYTES);
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) v->unlocked = 0;

out:
    desc_clear(&desc);
    vty_secure_zero(&old_state, sizeof(old_state));
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(mdek, sizeof(mdek));
    return rc;
}

int vty_module_disable(VtyVault *v, uint32_t index, const char *password)
{
    ModuleDesc desc;
    ModuleDesc disabled;
    VtyStoreCheckpoint cp;
    VtyKeyring old_kr;
    VtyKeyring new_kr;
    VtyModuleState old_state;
    uint16_t old_flags;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    uint32_t i;
    int any_enabled = 0;
    int rc;

    memset(&desc, 0, sizeof(desc));
    memset(&disabled, 0, sizeof(disabled));
    memset(&old_kr, 0, sizeof(old_kr));
    memset(&new_kr, 0, sizeof(new_kr));
    memset(&old_state, 0, sizeof(old_state));
    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    memset(mdek, 0, sizeof(mdek));

    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (!v->modules[index].enabled) return VTY_E_POLICY;

    rc = desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (!desc.enabled) { desc_clear(&desc); return VTY_E_POLICY; }

    rc = desc_open_shares(v, index, &desc, password, share_u, share_d, mdek);
    if (rc != VTY_OK) goto out;

    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) goto out;
    old_kr = v->keyring;
    old_state = v->modules[index];
    old_flags = v->header.flags;

    desc_init_disabled(&disabled, desc.uuid);
    rc = desc_store(v, index, &disabled);
    if (rc == VTY_OK) {
        new_kr = v->keyring;
        rc = keyring_add_mdek(&new_kr, desc.uuid, mdek);
    }
    if (rc == VTY_OK) rc = vty_vault_commit_store(v);
    if (rc != VTY_OK) {
        (void)vty_store_restore(v->store, &cp);
        v->keyring = old_kr;
        v->header.flags = old_flags;
        v->modules[index] = old_state;
        goto out;
    }

    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        if (i != index && v->modules[i].enabled) any_enabled = 1;
    }
    v->keyring = new_kr;
    if (!any_enabled) {
        v->header.flags = (uint16_t)(v->header.flags & ~VTY_FLAG_MODULE_M1);
    }
    v->modules[index].enabled = 0u;
    v->modules[index].unlocked = 0u;
    v->modules[index].has_recovery = 0u;
    vty_secure_zero(v->modules[index].mdek, VTY_KEY_BYTES);

    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) v->unlocked = 0;

out:
    desc_clear(&desc);
    desc_clear(&disabled);
    vty_secure_zero(&old_kr, sizeof(old_kr));
    vty_secure_zero(&new_kr, sizeof(new_kr));
    vty_secure_zero(&old_state, sizeof(old_state));
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(mdek, sizeof(mdek));
    return rc;
}

int vty_module_bind_recovery(VtyVault *v, uint32_t index,
                             const char *password, const char *recovery_code)
{
    ModuleDesc desc;
    VtyStoreCheckpoint cp;
    VtyModuleState old_state;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t krec[VTY_KEY_BYTES];
    int rc;

    memset(&desc, 0, sizeof(desc));
    memset(&old_state, 0, sizeof(old_state));
    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    memset(mdek, 0, sizeof(mdek));
    memset(krec, 0, sizeof(krec));

    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (!v->modules[index].enabled) return VTY_E_POLICY;
    if (recovery_code == NULL) return VTY_E_INVALID;

    rc = desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (!desc.enabled) { desc_clear(&desc); return VTY_E_POLICY; }

    rc = desc_open_shares(v, index, &desc, password, share_u, share_d, mdek);
    if (rc != VTY_OK) goto out;
    rc = krec_from_code(v, recovery_code, krec);
    if (rc != VTY_OK) goto out;

    rc = desc_seal_recovery(v, &desc, krec, share_d);
    if (rc != VTY_OK) goto out;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) goto out;
    old_state = v->modules[index];
    rc = desc_store(v, index, &desc);
    if (rc == VTY_OK) rc = vty_vault_commit_store(v);
    if (rc != VTY_OK) {
        (void)vty_store_restore(v->store, &cp);
        v->modules[index] = old_state;
        goto out;
    }
    v->modules[index].unlocked = 1u;
    v->modules[index].has_recovery = 1u;
    memcpy(v->modules[index].mdek, mdek, VTY_KEY_BYTES);
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) v->unlocked = 0;

out:
    desc_clear(&desc);
    vty_secure_zero(&old_state, sizeof(old_state));
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(mdek, sizeof(mdek));
    vty_secure_zero(krec, sizeof(krec));
    return rc;
}

int vty_module_reseal_device(VtyVault *v, uint32_t index, const char *password)
{
    ModuleDesc desc;
    VtyStoreCheckpoint cp;
    VtyModuleState old_state;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    int rc;

    memset(&desc, 0, sizeof(desc));
    memset(&old_state, 0, sizeof(old_state));
    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    memset(mdek, 0, sizeof(mdek));

    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (!v->recovery_mode) return VTY_E_POLICY;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (!v->modules[index].enabled) return VTY_E_POLICY;

    rc = desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (!desc.enabled) { desc_clear(&desc); return VTY_E_POLICY; }

    rc = desc_open_shares(v, index, &desc, password, share_u, share_d, mdek);
    if (rc != VTY_OK) goto out;

    rc = desc_seal_device(v, &desc, share_d);
    if (rc != VTY_OK) goto out;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) goto out;
    old_state = v->modules[index];
    rc = desc_store(v, index, &desc);
    if (rc == VTY_OK) rc = vty_vault_commit_store(v);
    if (rc != VTY_OK) {
        (void)vty_store_restore(v->store, &cp);
        v->modules[index] = old_state;
        goto out;
    }
    v->modules[index].unlocked = 1u;
    v->modules[index].has_recovery = desc.has_recovery;
    memcpy(v->modules[index].mdek, mdek, VTY_KEY_BYTES);
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) v->unlocked = 0;

out:
    desc_clear(&desc);
    vty_secure_zero(&old_state, sizeof(old_state));
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(mdek, sizeof(mdek));
    return rc;
}

int vty_module_recovery_seal(VtyVault *v, uint32_t index,
                             const uint8_t k_recovery[VTY_KEY_BYTES])
{
    ModuleDesc desc;
    uint8_t share_d[VTY_KEY_BYTES];
    int rc;

    memset(&desc, 0, sizeof(desc));
    memset(share_d, 0, sizeof(share_d));

    if (v == NULL || k_recovery == NULL) return VTY_E_INVALID;
    if (!v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (!v->modules[index].enabled) return VTY_E_POLICY;

    rc = desc_load(v, index, &desc);
    if (rc != VTY_OK) goto out;
    if (!desc.enabled) { rc = VTY_E_CORRUPT; goto out; }
    if (desc.has_recovery) { rc = VTY_E_POLICY; goto out; }

    rc = vty_slot_open_device(&desc.device, NULL, VTY_MODULE_SLOT_DEVICE,
                              share_d);
    if (rc == VTY_OK) {
        rc = desc_seal_recovery(v, &desc, k_recovery, share_d);
    }
    if (rc == VTY_OK) rc = desc_store(v, index, &desc);
    if (rc == VTY_OK) v->modules[index].has_recovery = 1u;

out:
    desc_clear(&desc);
    vty_secure_zero(share_d, sizeof(share_d));
    return rc;
}

int vty_module_recovery_reseal_all(VtyVault *v,
                                   const uint8_t k_recovery_old[VTY_KEY_BYTES],
                                   const uint8_t k_recovery_new[VTY_KEY_BYTES])
{
    uint32_t i;
    int rc = VTY_OK;

    if (v == NULL || k_recovery_old == NULL || k_recovery_new == NULL ||
        !v->unlocked) {
        return VTY_E_POLICY;
    }
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;

    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        ModuleDesc desc;
        uint8_t share_d[VTY_KEY_BYTES];
        uint8_t krec_old_mod[VTY_KEY_BYTES];
        uint8_t aad[96];
        size_t aad_len = 0;

        if (!v->modules[i].enabled || !v->modules[i].has_recovery) continue;

        memset(&desc, 0, sizeof(desc));
        memset(share_d, 0, sizeof(share_d));
        memset(krec_old_mod, 0, sizeof(krec_old_mod));
        rc = desc_load(v, i, &desc);
        if (rc == VTY_OK && !desc.has_recovery) rc = VTY_E_CORRUPT;
        if (rc == VTY_OK) {
            rc = module_rec_key(v, &desc, k_recovery_old, krec_old_mod);
        }
        if (rc == VTY_OK) {
            module_rec_aad(v, &desc, aad, &aad_len);
            rc = vty_unwrap_key32(krec_old_mod, desc.rec_nonce, aad, aad_len,
                                  desc.rec_ct, MOD_REC_CT, share_d);
        }
        if (rc == VTY_OK) {
            rc = desc_seal_recovery(v, &desc, k_recovery_new, share_d);
        }
        if (rc == VTY_OK) rc = desc_store(v, i, &desc);
        desc_clear(&desc);
        vty_secure_zero(share_d, sizeof(share_d));
        vty_secure_zero(krec_old_mod, sizeof(krec_old_mod));
        vty_secure_zero(aad, sizeof(aad));
        if (rc != VTY_OK) return rc;
    }
    return VTY_OK;
}
