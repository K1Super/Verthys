/*
 * vty_module_enable.c — 模块启用、禁用、改密与设备重封
 *
 * 这些操作都会改写描述符并提交元数据，统一走 checkpoint → 数据区提交
 * → 元数据写入；失败按 checkpoint 回滚 Keyring、flags 与模块状态。
 */
#include "vty_module_internal.h"

static int desc_seal_device(VtyVault *v, ModuleDesc *d,
                            const uint8_t share_d[VTY_KEY_BYTES])
{
    (void)v;
    return vty_slot_seal_device(&d->device, VTY_SLOT_FLAG_REQUIRED, share_d,
                                NULL, VTY_MODULE_SLOT_DEVICE);
}

int vty_mod_keyring_find_mdek(const VtyKeyring *kr,
                              const uint8_t uuid[VTY_UUID_BYTES],
                              uint8_t out[VTY_KEY_BYTES])
{
    return vty_keyring_find(kr, VTY_KEYKIND_MDEK, uuid, VTY_UUID_BYTES, out);
}

int vty_mod_keyring_remove_mdek(VtyKeyring *kr,
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

    if (vty_mod_keyring_find_mdek(kr, uuid, existing) == VTY_OK) return VTY_E_INVALID;
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

    rc = vty_mod_desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (desc.enabled || memcmp(desc.uuid, v->modules[index].uuid,
                               VTY_UUID_BYTES) != 0) {
        vty_mod_desc_clear(&desc);
        return VTY_E_CORRUPT;
    }
    if (!desc.deleted) {
        rc = vty_mod_keyring_find_mdek(&v->keyring, desc.uuid, old_mdek);
        if (rc != VTY_OK) { vty_mod_desc_clear(&desc); return VTY_E_CORRUPT; }
    }
    if (vty_kdf_params_valid(v->mem_kib, v->iters, v->parallel) != VTY_OK) {
        vty_mod_desc_clear(&desc);
        return VTY_E_KDF_WEAK;
    }

    if (recovery_code != NULL) {
        rc = vty_mod_krec_from_code(v, recovery_code, krec);
        if (rc != VTY_OK) {
            vty_mod_desc_clear(&desc);
            return rc;
        }
        have_krec = 1;
    }

    if (!desc.deleted) {
        rc = vty_repo_module_rekey_bytes(v, index, &need);
        if (rc == VTY_OK) rc = vty_mod_free_space_ok(v, need);
        if (rc != VTY_OK) {
            vty_mod_desc_clear(&desc);
            vty_secure_zero(krec, sizeof(krec));
            return rc;
        }
    }

    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) {
        vty_mod_desc_clear(&desc);
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
    rc = vty_mod_verifier(new_mdek, new_desc.uuid, new_desc.verifier);
    if (rc == VTY_OK) {
        rc = vty_mod_desc_seal_user(v, &new_desc, password, share_u);
    }
    if (rc == VTY_OK) rc = desc_seal_device(v, &new_desc, share_d);
    if (rc == VTY_OK && have_krec) {
        rc = vty_mod_desc_seal_recovery(v, &new_desc, krec, share_d);
    }
    if (rc == VTY_OK && !desc.deleted) {
        rc = vty_repo_module_rekey(v, index, old_mdek, new_mdek);
    }
    if (rc == VTY_OK) rc = vty_mod_desc_store(v, index, &new_desc);
    if (rc == VTY_OK) {
        new_kr = v->keyring;
        if (!desc.deleted) rc = vty_mod_keyring_remove_mdek(&new_kr, new_desc.uuid);
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
    /* 第二次写覆盖另一副本：旧 MDEK 已从 Keyring 移除，若旧代元数据仍
     * 保留其包裹密文，重封前的历史段会被重新解封。两次落盘确保两份
     * 元数据副本都不再含旧 MDEK。 */
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        goto fail;
    }

    vty_mod_desc_clear(&desc);
    vty_mod_desc_clear(&new_desc);
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
    vty_mod_desc_clear(&desc);
    vty_mod_desc_clear(&new_desc);
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

    rc = vty_mod_desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (!desc.enabled) { vty_mod_desc_clear(&desc); return VTY_E_POLICY; }

    rc = vty_mod_desc_open_shares(v, index, &desc, old_password, share_u, share_d, mdek);
    if (rc != VTY_OK) goto out;

    rc = vty_mod_desc_seal_user(v, &desc, new_password, share_u);
    if (rc != VTY_OK) goto out;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) goto out;
    old_state = v->modules[index];
    rc = vty_mod_desc_store(v, index, &desc);
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
    vty_mod_desc_clear(&desc);
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

    rc = vty_mod_desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (!desc.enabled) { vty_mod_desc_clear(&desc); return VTY_E_POLICY; }

    rc = vty_mod_desc_open_shares(v, index, &desc, password, share_u, share_d, mdek);
    if (rc != VTY_OK) goto out;

    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) goto out;
    old_kr = v->keyring;
    old_state = v->modules[index];
    old_flags = v->header.flags;

    vty_mod_desc_init_disabled(&disabled, desc.uuid);
    rc = vty_mod_desc_store(v, index, &disabled);
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
    vty_mod_desc_clear(&desc);
    vty_mod_desc_clear(&disabled);
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

    rc = vty_mod_desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (!desc.enabled) { vty_mod_desc_clear(&desc); return VTY_E_POLICY; }

    rc = vty_mod_desc_open_shares(v, index, &desc, password, share_u, share_d, mdek);
    if (rc != VTY_OK) goto out;
    rc = vty_mod_krec_from_code(v, recovery_code, krec);
    if (rc != VTY_OK) goto out;

    rc = vty_mod_desc_seal_recovery(v, &desc, krec, share_d);
    if (rc != VTY_OK) goto out;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) goto out;
    old_state = v->modules[index];
    rc = vty_mod_desc_store(v, index, &desc);
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
    vty_mod_desc_clear(&desc);
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

    rc = vty_mod_desc_load(v, index, &desc);
    if (rc != VTY_OK) return rc;
    if (!desc.enabled) { vty_mod_desc_clear(&desc); return VTY_E_POLICY; }

    rc = vty_mod_desc_open_shares(v, index, &desc, password, share_u, share_d, mdek);
    if (rc != VTY_OK) goto out;

    rc = desc_seal_device(v, &desc, share_d);
    if (rc != VTY_OK) goto out;
    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) goto out;
    old_state = v->modules[index];
    rc = vty_mod_desc_store(v, index, &desc);
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
    vty_mod_desc_clear(&desc);
    vty_secure_zero(&old_state, sizeof(old_state));
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(mdek, sizeof(mdek));
    return rc;
}

