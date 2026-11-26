/*
 * vty_module_seal.c — 模块槽封装与解封策略
 *
 * 构造 AAD、派生 K_mod_rec 与 verifier，完成 user/device/recovery 槽的
 * 封包与解包；口令失败只计入模块锁作用域，不污染库级熔断。
 */
#include "vty_module_internal.h"

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

int vty_mod_rec_aad(const VtyVault *v, const ModuleDesc *d,
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
int vty_mod_rec_key(const VtyVault *v, const ModuleDesc *d,
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

int vty_mod_verifier(const uint8_t mdek[VTY_KEY_BYTES],
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

int vty_mod_desc_seal_user(VtyVault *v, ModuleDesc *d, const char *password,
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

int vty_mod_desc_seal_recovery(VtyVault *v, ModuleDesc *d,
                               const uint8_t krec[VTY_KEY_BYTES],
                               const uint8_t share_d[VTY_KEY_BYTES])
{
    uint8_t krec_mod[VTY_KEY_BYTES];
    uint8_t aad[96];
    size_t aad_len = 0;
    int rc;

    rc = vty_mod_rec_key(v, d, krec, krec_mod);
    if (rc != VTY_OK) return rc;
    vty_mod_rec_aad(v, d, aad, &aad_len);
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
    if (vty_mod_all_zero(v->k_recovery, VTY_KEY_BYTES)) return VTY_E_POLICY;
    rc = vty_mod_rec_key(v, d, v->k_recovery, krec_mod);
    if (rc != VTY_OK) return rc;
    vty_mod_rec_aad(v, d, aad, &aad_len);
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
int vty_mod_desc_open_shares(VtyVault *v, uint32_t module_index,
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
    rc = vty_mod_verifier(mdek, d->uuid, verifier);
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
int vty_mod_krec_from_code(VtyVault *v, const char *recovery_text,
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

    rc = vty_mod_desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (!desc.enabled || memcmp(desc.uuid, v->modules[index].uuid,
                                VTY_UUID_BYTES) != 0) {
        vty_mod_desc_clear(&desc);
        return VTY_E_CORRUPT;
    }

    rc = vty_mod_desc_open_shares(v, index, &desc, password, share_u, share_d, mdek);
    if (rc != VTY_OK) {
        vty_mod_desc_clear(&desc);
        vty_secure_zero(share_u, sizeof(share_u));
        vty_secure_zero(share_d, sizeof(share_d));
        vty_secure_zero(mdek, sizeof(mdek));
        return rc;
    }

    memcpy(v->modules[index].mdek, mdek, VTY_KEY_BYTES);
    v->modules[index].unlocked = 1u;
    v->modules[index].has_recovery = desc.has_recovery;

    /* 模块解锁后立即补做该模块遗留的待擦记录：解锁前维护无法取得
     * MDEK，不能把“暂时拿不到密钥”当作已完成擦除。失败不阻断解锁。 */
    (void)vty_repo_maintain_pending_scrub(v, 4096u, NULL, NULL);

    vty_mod_desc_clear(&desc);
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(mdek, sizeof(mdek));
    return VTY_OK;
}

