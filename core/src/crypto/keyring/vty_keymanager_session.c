/*
 * vty_keymanager_session.c — PCR 槽位、模块密钥访问与生命周期
 */

#include "vty_keymanager_internal.h"


int vty_vault_pcr_slot_prepare(VtyVault *v, uint32_t select, VtySlot *slot)
{
    int rc;

    memset(slot, 0, sizeof(*slot));
    rc = vty_tpm_pcr_select_valid(select);
    if (rc != VTY_OK) return rc;
    rc = vty_tpm_pcr_key_create(v->header.vault_uuid, select, NULL, 0);
    if (rc != VTY_OK) return rc;

    slot->slot_type = VTY_SLOT_DEVICE_PCR;
    slot->slot_flags = VTY_SLOT_FLAG_REQUIRED;
    slot->kdf_id = VTY_KDF_NONE;
    slot->wrap_alg = VTY_WRAP_RSAOAEP;
    slot->params_len = VTY_SLOT_PARAMS_PCR;
    slot->pcr_select = select;
    rc = vty_tpm_pcr_measure(select, slot->pcr_digest);
    if (rc == VTY_OK) {
        rc = vty_tpm_pcr_seal(v->header.vault_uuid, v->kc, slot->ct);
    }
    if (rc != VTY_OK) {
        (void)vty_tpm_pcr_key_delete(v->header.vault_uuid);
        memset(slot, 0, sizeof(*slot));
        return VTY_E_TPM;
    }
    slot->ct_len = VTY_SLOT_PCR_CT_BYTES;
    return VTY_OK;
}

int vty_vault_pcr_enable(VtyVault *v, uint32_t pcr_select)
{
    VtySlot slot;
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR) >= 0) {
        return VTY_E_POLICY;
    }
    if (v->slot_count >= VTY_MAX_SLOTS) return VTY_E_RESOURCE;
    if (!vty_tpm_pcr_available()) return VTY_E_TPM;

    rc = vty_vault_pcr_slot_prepare(v, pcr_select, &slot);
    if (rc != VTY_OK) return rc;

    v->slots[v->slot_count] = slot;
    v->slot_count++;
    v->header.flags |= VTY_FLAG_PCR;
    rc = vty_vault_save(v);
    if (rc != VTY_OK) v->unlocked = 0;
    return rc;
}

int vty_vault_pcr_disable(VtyVault *v)
{
    int p_idx;
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    p_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    if (p_idx < 0) return VTY_E_POLICY;
    if ((uint32_t)p_idx != v->slot_count - 1u) return VTY_E_CORRUPT;
    if ((v->header.flags & VTY_FLAG_HIGH_SECURITY) != 0 &&
        (v->header.flags & VTY_FLAG_KEYFILE) == 0) {
        return VTY_E_POLICY;
    }

    v->slot_count--;
    v->header.flags &= (uint16_t)~VTY_FLAG_PCR;
    rc = vty_vault_save(v);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        return rc;
    }
    (void)vty_tpm_pcr_key_delete(v->header.vault_uuid);
    return VTY_OK;
}

int vty_vault_pcr_reseal(VtyVault *v)
{
    int p_idx;
    uint8_t digest[VTY_HASH_BYTES];
    uint8_t ct[VTY_TPM_PCR_CT_BYTES];
    uint8_t check[VTY_KEY_BYTES];
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    p_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    if (p_idx < 0) return VTY_E_POLICY;
    if (!vty_tpm_pcr_available()) return VTY_E_TPM;

    memset(digest, 0, sizeof(digest));
    memset(ct, 0, sizeof(ct));
    vty_secure_zero(check, sizeof(check));

    rc = vty_tpm_pcr_key_create(v->header.vault_uuid,
                                v->slots[p_idx].pcr_select, NULL, 0);
    if (rc != VTY_OK) return rc;
    rc = vty_tpm_pcr_measure(v->slots[p_idx].pcr_select, digest);
    if (rc == VTY_OK) {
        rc = vty_tpm_pcr_seal(v->header.vault_uuid, v->kc, ct);
    }
    if (rc == VTY_OK) {
        rc = vty_tpm_pcr_unseal(v->header.vault_uuid, ct, check);
    }
    if (rc == VTY_OK && vty_ct_equal(check, v->kc, VTY_KEY_BYTES) != 0) {
        rc = VTY_E_TPM;
    }
    vty_secure_zero(check, sizeof(check));
    if (rc != VTY_OK) {
        vty_secure_zero(digest, sizeof(digest));
        vty_secure_zero(ct, sizeof(ct));
        return VTY_E_TPM;
    }

    memcpy(v->slots[p_idx].pcr_digest, digest, VTY_HASH_BYTES);
    memcpy(v->slots[p_idx].ct, ct, VTY_TPM_PCR_CT_BYTES);
    vty_secure_zero(digest, sizeof(digest));
    vty_secure_zero(ct, sizeof(ct));
    rc = vty_vault_save(v);
    if (rc != VTY_OK) v->unlocked = 0;
    return rc;
}

int vty_vault_system_key(const VtyVault *v, uint8_t key_out[VTY_KEY_BYTES])
{
    if (v == NULL || key_out == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    /* K_c 已由容器解锁认证；派生只做域分离，不引入新因子。 */
    return vty_hkdf_expand(key_out, v->kc,
                           (const uint8_t *)VTY_DOMAIN_SYSTEM_RECORD,
                           strlen(VTY_DOMAIN_SYSTEM_RECORD));
}

int vty_vault_module_key_index(const VtyVault *v, uint32_t index,
                               uint8_t key_out[VTY_KEY_BYTES])
{
    if (v == NULL || key_out == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;

    if (v->modules[index].deleted) return VTY_E_POLICY;
    if (v->modules[index].enabled) {
        /* 启用后 MDEK 不再存在于 Keyring；未解锁即策略拒绝，
         * 绝不回退到 Keyring 或描述符包裹密文。 */
        if (!v->modules[index].unlocked) return VTY_E_POLICY;
        memcpy(key_out, v->modules[index].mdek, VTY_KEY_BYTES);
        return VTY_OK;
    }
    return vty_keyring_find(&v->keyring, VTY_KEYKIND_MDEK,
                            v->modules[index].uuid, VTY_UUID_BYTES, key_out);
}

int vty_vault_module_key(const VtyVault *v, const uint8_t module_uuid[VTY_UUID_BYTES],
                         uint8_t key_out[VTY_KEY_BYTES])
{
    uint32_t i;

    if (v == NULL || module_uuid == NULL || key_out == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    /* 系统记录域不属于任何模块：按 K_c 派生，不受模块锁定影响。 */
    if (memcmp(module_uuid, vty_system_module_uuid, VTY_UUID_BYTES) == 0) {
        return vty_vault_system_key(v, key_out);
    }
    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        if (memcmp(v->modules[i].uuid, module_uuid, VTY_UUID_BYTES) == 0) {
            return vty_vault_module_key_index(v, i, key_out);
        }
    }
    /* 记录叶引用了模块表中不存在的 UUID：目录/记录交叉损坏 */
    return VTY_E_CORRUPT;
}

int vty_vault_module_uuid(const VtyVault *v, uint32_t index,
                          uint8_t out[VTY_UUID_BYTES])
{
    if (v == NULL || out == NULL) return VTY_E_INVALID;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    memcpy(out, v->modules[index].uuid, VTY_UUID_BYTES);
    return VTY_OK;
}

void vty_vault_lock(VtyVault *v)
{
    if (v == NULL) return;
    /* 先关闭数据区会话（flush 未提交段），再清零密钥；反序会让
     * store 在密钥已为零时执行 flush/关闭。 */
    if (v->store != NULL) {
        vty_store_close(v->store);
        v->store = NULL;
    }
    vty_secure_zero(v->kc, sizeof(v->kc));
    vty_secure_zero(&v->keyring, sizeof(v->keyring));
    vty_secure_zero(&v->data_root, sizeof(v->data_root));
    vty_secure_zero(v->data_root_hash, sizeof(v->data_root_hash));
    vty_secure_zero(v->modules, sizeof(v->modules));
    vty_secure_zero(v->k_recovery, sizeof(v->k_recovery));
    vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
    v->keyfile_digest_set = 0;
    v->recovery_mode = 0;
    v->no_rollback_anchor = 0;
    v->rotate_pending = 0;
    v->defer_anchor = 0;
    v->anchor_floor_gen = 0;
    v->anchor_defer_since_ms = 0;
    v->unlocked = 0;
    /* Keyring 的 32 字节条目会被编译器溢出到栈槽位，缓冲区清零无法覆盖 */
    vty_wipe_stack();
}

void vty_vault_free(VtyVault *v)
{
    if (v == NULL) return;
    vty_vault_lock(v);
    vty_secure_free(v);
}

int vty_vault_binding_info(const VtyVault *v, VtyVaultBindingInfo *out)
{
    int device_idx;
    int pcr_idx;

    if (out == NULL) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    if (v == NULL) return VTY_E_INVALID;

    out->unlocked = v->unlocked ? 1u : 0u;
    device_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    pcr_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    out->device_bound = (device_idx >= 0) ? 1u : 0u;
    out->pcr_bound = (pcr_idx >= 0) ? 1u : 0u;
    return VTY_OK;
}
