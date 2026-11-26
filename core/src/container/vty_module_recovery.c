/*
 * vty_module_recovery.c — 恢复码绑定与轮换重封
 *
 * 只改写数据区中的 recovery 槽，不提交元数据；K_recovery 轮换由调用方
 * 负责 checkpoint 与提交。
 */
#include "vty_module_internal.h"

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

    rc = vty_mod_desc_load(v, index, &desc);
    if (rc != VTY_OK) goto out;
    if (!desc.enabled) { rc = VTY_E_CORRUPT; goto out; }
    if (desc.has_recovery) { rc = VTY_E_POLICY; goto out; }

    rc = vty_slot_open_device(&desc.device, NULL, VTY_MODULE_SLOT_DEVICE,
                              share_d);
    if (rc == VTY_OK) {
        rc = vty_mod_desc_seal_recovery(v, &desc, k_recovery, share_d);
    }
    if (rc == VTY_OK) rc = vty_mod_desc_store(v, index, &desc);
    if (rc == VTY_OK) v->modules[index].has_recovery = 1u;

out:
    vty_mod_desc_clear(&desc);
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
        rc = vty_mod_desc_load(v, i, &desc);
        if (rc == VTY_OK && !desc.has_recovery) rc = VTY_E_CORRUPT;
        if (rc == VTY_OK) {
            rc = vty_mod_rec_key(v, &desc, k_recovery_old, krec_old_mod);
        }
        if (rc == VTY_OK) {
            vty_mod_rec_aad(v, &desc, aad, &aad_len);
            rc = vty_unwrap_key32(krec_old_mod, desc.rec_nonce, aad, aad_len,
                                  desc.rec_ct, MOD_REC_CT, share_d);
        }
        if (rc == VTY_OK) {
            rc = vty_mod_desc_seal_recovery(v, &desc, k_recovery_new, share_d);
        }
        if (rc == VTY_OK) rc = vty_mod_desc_store(v, i, &desc);
        vty_mod_desc_clear(&desc);
        vty_secure_zero(share_d, sizeof(share_d));
        vty_secure_zero(krec_old_mod, sizeof(krec_old_mod));
        vty_secure_zero(aad, sizeof(aad));
        if (rc != VTY_OK) return rc;
    }
    return VTY_OK;
}
