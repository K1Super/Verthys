/*
 * vty_keymanager_factor.c — keyfile 因子、设备重封与恢复码轮换
 */

#include "vty_keymanager_internal.h"


/* 重新生成 share_u/share_d 并按指定 keyfile 摘要重封用户槽与设备槽。
 * 只改槽，不重写数据；失败由调用方锁定会话。 */
static int reseal_user_device_slots(VtyVault *v, const char *password,
                                    const uint8_t *keyfile_digest)
{
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    int u_idx, d_idx;
    int rc;
    size_t i;

    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    if (u_idx < 0 || d_idx < 0) return VTY_E_SLOT_MISSING;

    vty_random(share_u, VTY_KEY_BYTES);
    for (i = 0; i < VTY_KEY_BYTES; i++) {
        share_d[i] = (uint8_t)(v->kc[i] ^ share_u[i]);
    }
    rc = vty_km_seal_user_slot(&v->slots[u_idx], VTY_SLOT_USER_PASSWORD,
                        VTY_SLOT_FLAG_REQUIRED, password, keyfile_digest,
                        share_u, &v->header, (uint32_t)u_idx,
                        v->mem_kib, v->iters, v->parallel);
    if (rc == VTY_OK) {
        rc = vty_slot_seal_device(&v->slots[d_idx], VTY_SLOT_FLAG_REQUIRED,
                                  share_d, &v->header, (uint32_t)d_idx);
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    return rc;
}

int vty_vault_reseal_device(VtyVault *v, const char *password,
                            const uint8_t *keyfile_digest_or_null)
{
    uint8_t digest[VTY_KEY_BYTES];
    int has_keyfile;
    int rc;

    memset(digest, 0, sizeof(digest));
    if (v == NULL || password == NULL || password[0] == '\0') {
        return VTY_E_INVALID;
    }
    if (!v->unlocked || !v->recovery_mode) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (strlen(v->path) == 0) return VTY_E_INVALID;

    has_keyfile = (v->header.flags & VTY_FLAG_KEYFILE) != 0;
    if (has_keyfile && keyfile_digest_or_null == NULL) {
        return VTY_E_KEYFILE_REQUIRED;
    }
    if (!has_keyfile && keyfile_digest_or_null != NULL) {
        return VTY_E_INVALID;
    }
    if (has_keyfile) {
        memcpy(digest, keyfile_digest_or_null, VTY_KEY_BYTES);
    }

    rc = reseal_user_device_slots(v, password, has_keyfile ? digest : NULL);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        goto out;
    }
    if (has_keyfile) {
        memcpy(v->keyfile_digest, digest, VTY_KEY_BYTES);
        v->keyfile_digest_set = 1;
    }

    /* 新槽必须能用当前口令（及 keyfile 摘要）自检还原 K_c；失败即锁定
     * 会话，避免把半套槽位继续用于写入。 */
    rc = vty_vault_verify_password(v, password);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        if (has_keyfile) {
            v->keyfile_digest_set = 0;
            vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
        }
        goto out;
    }

    /* 只写元数据副本，不提交数据区：槽重绑不改变记录/分片。 */
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        if (has_keyfile) {
            v->keyfile_digest_set = 0;
            vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
        }
    }

out:
    vty_secure_zero(digest, sizeof(digest));
    return rc;
}

int vty_vault_reseal_device_file(VtyVault *v, const char *password,
                                 const char *keyfile_path)
{
    uint8_t digest[VTY_KEY_BYTES];
    int rc;

    memset(digest, 0, sizeof(digest));
    if (v == NULL || password == NULL || password[0] == '\0') {
        return VTY_E_INVALID;
    }
    if (!v->unlocked || !v->recovery_mode) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;

    if ((v->header.flags & VTY_FLAG_KEYFILE) != 0) {
        if (keyfile_path == NULL || keyfile_path[0] == '\0') {
            return VTY_E_KEYFILE_REQUIRED;
        }
        rc = vty_km_load_keyfile_digest(keyfile_path, digest);
        if (rc != VTY_OK) {
            vty_secure_zero(digest, sizeof(digest));
            return rc;
        }
        rc = vty_vault_reseal_device(v, password, digest);
    } else {
        rc = vty_vault_reseal_device(v, password, NULL);
    }

    vty_secure_zero(digest, sizeof(digest));
    return rc;
}

int vty_vault_keyfile_enable(VtyVault *v, const char *password,
                             const uint8_t *new_blob, size_t new_len)
{
    uint8_t secret[VTY_KEYFILE_SECRET_BYTES];
    uint8_t digest[VTY_KEY_BYTES];
    int was_keyfile;
    int recovery_rebind;
    int rc;

    memset(secret, 0, sizeof(secret));
    memset(digest, 0, sizeof(digest));
    if (v == NULL || password == NULL || password[0] == '\0' ||
        new_blob == NULL || new_len != VTY_KEYFILE_BLOB_BYTES) {
        return new_blob == NULL || new_len != VTY_KEYFILE_BLOB_BYTES
            ? VTY_E_KEYFILE_INVALID : VTY_E_INVALID;
    }
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (strlen(v->path) == 0) return VTY_E_INVALID;

    was_keyfile = (v->header.flags & VTY_FLAG_KEYFILE) != 0;
    /* 恢复会话没有旧 keyfile 摘要：这是“keyfile 丢失”的唯一逃生路径。
     * 恢复码已认证根访问，允许用当前口令直接重封；重封后立即自检。 */
    recovery_rebind = v->recovery_mode && !v->keyfile_digest_set;
    if (was_keyfile && !v->keyfile_digest_set && !recovery_rebind) {
        return VTY_E_KEYFILE_REQUIRED;
    }

    rc = vty_keyfile_parse(new_blob, new_len, secret);
    if (rc == VTY_OK) rc = vty_keyfile_digest(secret, digest);
    if (rc != VTY_OK) goto out;

    /* 先验证当前口令；启用/轮换都必须知道当前口令。恢复会话无法验证
     * 旧用户槽（缺旧 keyfile 摘要），由恢复码承担认证，重封后自检。 */
    if (!recovery_rebind) {
        rc = vty_vault_verify_password(v, password);
        if (rc != VTY_OK) goto out;
    }

    rc = reseal_user_device_slots(v, password, digest);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        goto out;
    }

    v->header.flags |= VTY_FLAG_KEYFILE;
    memcpy(v->keyfile_digest, digest, VTY_KEY_BYTES);
    v->keyfile_digest_set = 1;
    if (recovery_rebind) {
        /* 新槽自检：用“口令 + 新摘要”必须能解开并还原 K_c。 */
        rc = vty_vault_verify_password(v, password);
        if (rc != VTY_OK) {
            v->unlocked = 0;
            v->keyfile_digest_set = 0;
            vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
            goto out;
        }
    }
    rc = vty_vault_save(v);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        v->keyfile_digest_set = 0;
        vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
    }

out:
    vty_secure_zero(secret, sizeof(secret));
    vty_secure_zero(digest, sizeof(digest));
    return rc;
}

int vty_vault_keyfile_enable_file(VtyVault *v, const char *password,
                                  const char *new_keyfile_path)
{
    uint8_t blob[VTY_KEYFILE_BLOB_BYTES];
    int rc;

    memset(blob, 0, sizeof(blob));
    if (new_keyfile_path == NULL) return VTY_E_KEYFILE_REQUIRED;
    if (v == NULL || password == NULL) return VTY_E_INVALID;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    rc = vty_keyfile_generate(blob);
    if (rc == VTY_OK) {
        rc = vty_km_write_keyfile_file(new_keyfile_path, blob, sizeof(blob));
    }
    if (rc == VTY_OK) {
        rc = vty_vault_keyfile_enable(v, password, blob, sizeof(blob));
        /* 重封失败时新文件尚未被库接受，删除以免用户拿它去解一个
         * 仍按旧因子封装的库。 */
        if (rc != VTY_OK) vty_km_delete_file_utf8(new_keyfile_path);
    }
    vty_secure_zero(blob, sizeof(blob));
    return rc;
}

int vty_vault_keyfile_disable(VtyVault *v, const char *password,
                              const char *keyfile_path)
{
    uint8_t digest[VTY_KEY_BYTES];
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t kc[VTY_KEY_BYTES];
    int u_idx, d_idx;
    int rc;

    memset(digest, 0, sizeof(digest));
    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    memset(kc, 0, sizeof(kc));
    if (v == NULL || password == NULL || password[0] == '\0') {
        return VTY_E_KEYFILE_REQUIRED;
    }
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if ((v->header.flags & VTY_FLAG_KEYFILE) == 0) return VTY_E_POLICY;
    /* 高安全模式必须有第二因子：没有 PCR 槽时不得关闭 keyfile，否则
     * 落盘后的库立即违反 vty_slot_policy_check，普通解锁被拒。 */
    if ((v->header.flags & VTY_FLAG_HIGH_SECURITY) != 0 &&
        vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR) < 0) {
        return VTY_E_POLICY;
    }

    if (keyfile_path == NULL || keyfile_path[0] == '\0') {
        /* 空路径只在恢复会话有意义：keyfile 丢失后无法校验旧文件，
         * 由恢复码承担认证；重封后立即用“仅口令”自检。 */
        if (!v->recovery_mode) {
            rc = VTY_E_KEYFILE_REQUIRED;
            goto out;
        }
        rc = reseal_user_device_slots(v, password, NULL);
        if (rc != VTY_OK) {
            v->unlocked = 0;
            goto out;
        }
        v->header.flags &= (uint16_t)~VTY_FLAG_KEYFILE;
        v->keyfile_digest_set = 0;
        vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
        rc = vty_vault_verify_password(v, password);
        if (rc != VTY_OK) {
            v->unlocked = 0;
            goto out;
        }
        rc = vty_vault_save(v);
        if (rc != VTY_OK) v->unlocked = 0;
        goto out;
    }

    rc = vty_km_load_keyfile_digest(keyfile_path, digest);
    if (rc != VTY_OK) goto out;
    /* 用用户提供的 keyfile 重新计算摘要并验证口令；错误的文件会在
     * 用户槽解包时统一失败，不泄露“文件对/错”。 */
    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    if (u_idx < 0 || d_idx < 0) { rc = VTY_E_SLOT_MISSING; goto out; }
    rc = vty_km_open_user_slot(&v->slots[u_idx], password, digest,
                        &v->header, (uint32_t)u_idx, share_u);
    if (rc == VTY_OK) {
        rc = vty_slot_open_device(&v->slots[d_idx], &v->header,
                                  (uint32_t)d_idx, share_d);
    }
    if (rc == VTY_OK) {
        size_t i;
        for (i = 0; i < VTY_KEY_BYTES; i++) {
            kc[i] = (uint8_t)(share_u[i] ^ share_d[i]);
        }
        if (vty_ct_equal(kc, v->kc, VTY_KEY_BYTES) != 0) rc = VTY_E_KEY_INVALID;
    }
    if (rc != VTY_OK) goto out;

    rc = reseal_user_device_slots(v, password, NULL);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        goto out;
    }

    v->header.flags &= (uint16_t)~VTY_FLAG_KEYFILE;
    v->keyfile_digest_set = 0;
    vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
    rc = vty_vault_save(v);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        v->keyfile_digest_set = 0;
        vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
    }

out:
    vty_secure_zero(digest, sizeof(digest));
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(kc, sizeof(kc));
    return rc;
}

int vty_vault_recovery_rotate(VtyVault *v,
                              const char *password,
                              const char *old_recovery_text,
                              char *new_text, size_t new_cap)
{
    uint8_t code[VTY_RECOVERY_CODE_BYTES];
    uint8_t krec_old[VTY_KEY_BYTES];
    uint8_t krec_new[VTY_KEY_BYTES];
    uint8_t kc[VTY_KEY_BYTES];
    VtySlot new_slot;
    VtySlot old_slot;
    VtyKeyring rk;
    VtyStoreCheckpoint cp;
    int r_idx;
    int committed = 0;
    int rc;

    memset(code, 0, sizeof(code));
    memset(krec_old, 0, sizeof(krec_old));
    memset(krec_new, 0, sizeof(krec_new));
    memset(kc, 0, sizeof(kc));
    memset(&new_slot, 0, sizeof(new_slot));
    memset(&old_slot, 0, sizeof(old_slot));
    memset(&rk, 0, sizeof(rk));

    if (v == NULL || password == NULL || old_recovery_text == NULL ||
        new_text == NULL) {
        return VTY_E_INVALID;
    }
    if (new_cap < VTY_RECOVERY_TEXT_BUF) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (strlen(v->path) == 0) return VTY_E_INVALID;

    r_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_RECOVERY);
    if (r_idx < 0) return VTY_E_SLOT_MISSING;

    rc = vty_vault_verify_user_password(v, password);
    if (rc != VTY_OK) return rc;

    rc = vty_recovery_slot_open(&v->slots[r_idx], old_recovery_text,
                                &v->header, (uint32_t)r_idx, &rk, krec_old);
    if (rc == VTY_OK) {
        rc = vty_keyring_find(&rk, VTY_KEYKIND_KC, NULL, 0, kc);
    }
    if (rc == VTY_OK && vty_ct_equal(kc, v->kc, VTY_KEY_BYTES) != 0) {
        rc = VTY_E_KEY_INVALID;
    }
    if (rc != VTY_OK) goto out;

    rc = vty_recovery_generate(code, new_text, new_cap);
    if (rc != VTY_OK) goto out;
    rc = vty_recovery_slot_seal(&new_slot, v->kc, code, &v->header,
                                (uint32_t)r_idx, v->mem_kib, v->iters,
                                v->parallel, krec_new);
    if (rc != VTY_OK) goto out;

    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) goto out;
    rc = vty_module_recovery_reseal_all(v, krec_old, krec_new);
    if (rc == VTY_OK) rc = vty_vault_commit_store(v);
    if (rc != VTY_OK) {
        (void)vty_store_restore(v->store, &cp);
        goto out;
    }
    committed = 1;

    old_slot = v->slots[r_idx];
    v->slots[r_idx] = new_slot;
    if (v->recovery_mode) memcpy(v->k_recovery, krec_new, VTY_KEY_BYTES);
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) {
        v->slots[r_idx] = old_slot;
        v->unlocked = 0;
    }

out:
    if (rc != VTY_OK) {
        if (committed) (void)vty_store_restore(v->store, &cp);
        /* 新码只在完整成功后才允许交付；失败必须擦除输出缓冲，
         * 否则调用方会拿到一个磁盘上不存在的恢复码。 */
        vty_secure_zero(new_text, new_cap);
    }
    vty_secure_zero(code, sizeof(code));
    vty_secure_zero(krec_old, sizeof(krec_old));
    vty_secure_zero(krec_new, sizeof(krec_new));
    vty_secure_zero(kc, sizeof(kc));
    vty_secure_zero(&new_slot, sizeof(new_slot));
    vty_secure_zero(&old_slot, sizeof(old_slot));
    vty_secure_zero(&rk, sizeof(rk));
    return rc;
}
