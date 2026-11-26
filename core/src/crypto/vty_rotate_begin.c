/*
 * vty_rotate_begin.c — 轮换作业的启动检查与新库创建
 *
 * 校验源会话资格、口令、同卷与空间，决定 PCR 绑定去留，按源库模块
 * 策略创建新容器；并登记各已启用模块的口令，供后续复制使用。
 */

#include "vty_rotate_internal.h"

int vty_rotate_begin(VtyVault *old, const char *new_path, const char *password,
                     uint32_t flags, VtyRotateJob **out)
{
    VtyRotateJob *job = NULL;
    VtyVault *newv = NULL;
    uint8_t kc[VTY_KEY_BYTES];
    uint16_t new_flags;
    const uint8_t *kfd = NULL;
    int p_idx;
    int rc;

    if (out != NULL) *out = NULL;
    if (old == NULL || new_path == NULL || password == NULL || out == NULL) {
        return VTY_E_INVALID;
    }
    if (!old->unlocked || old->store == NULL || !old->recovery_mode) {
        return VTY_E_POLICY;
    }
    if (old->rotate_pending) return VTY_E_ROTATE_PENDING;
    if ((flags & ~VTY_ROTATE_FLAG_DROP_PCR) != 0u) return VTY_E_INVALID;
    if (password[0] == '\0') return VTY_E_INVALID;
    if (new_path[0] == '\0') return VTY_E_INVALID;
    if (strlen(old->path) >= VTY_ROTATE_PATH_MAX ||
        strlen(new_path) >= VTY_ROTATE_PATH_MAX) {
        return VTY_E_INVALID;
    }
    if ((old->header.flags & VTY_FLAG_KEYFILE) != 0 &&
        !old->keyfile_digest_set) {
        /* 恢复会话不携带 keyfile 摘要；无法在不破坏 keyfile 因子的前提
         * 下重封用户槽。 */
        return VTY_E_POLICY;
    }

    rc = vty_vault_verify_user_password(old, password);
    if (rc != VTY_OK) return rc;

    if (vty_rot_file_exists(new_path)) return VTY_E_EXISTS;
    if (!vty_rot_same_directory(old->path, new_path)) return VTY_E_INVALID;
    rc = vty_rot_space_ok(old->path);
    if (rc != VTY_OK) return rc;

    p_idx = vty_slot_find(old->slots, old->slot_count, VTY_SLOT_DEVICE_PCR);
    if (p_idx >= 0 && (old->header.flags & VTY_FLAG_PCR) == 0) {
        return VTY_E_CORRUPT;
    }
    if (p_idx < 0 && (old->header.flags & VTY_FLAG_PCR) != 0) {
        return VTY_E_CORRUPT;
    }
    if (p_idx >= 0) {
        if (!vty_tpm_pcr_available()) {
            if ((flags & VTY_ROTATE_FLAG_DROP_PCR) == 0u) return VTY_E_TPM;
            /* 与 pcr_disable 同策略：高安全模式没有 keyfile 时不允许
             * 失去第二因子。 */
            if ((old->header.flags & VTY_FLAG_HIGH_SECURITY) != 0 &&
                (old->header.flags & VTY_FLAG_KEYFILE) == 0) {
                return VTY_E_POLICY;
            }
        }
    }

    job = (VtyRotateJob *)vty_alloc(sizeof(*job));
    if (job == NULL) return VTY_E_RESOURCE;
    job->old = old;
    vty_rot_set_stage(job, VTY_ROTATE_STAGE_BEGUN);
    memcpy(job->old_path, old->path, strlen(old->path) + 1);
    memcpy(job->new_path, new_path, strlen(new_path) + 1);
    rc = vty_repo_next_id(old, &job->source_next_id);
    if (rc != VTY_OK) {
        vty_rotate_free(job);
        return rc;
    }
    if (p_idx >= 0) {
        job->has_pcr = 1;
        job->pcr_select = old->slots[p_idx].pcr_select;
        job->pcr_drop = !vty_tpm_pcr_available();
    }

    new_flags = (uint16_t)(old->header.flags &
                           (uint16_t)~(VTY_FLAG_PCR | VTY_FLAG_MODULE_M1));
    if ((new_flags & VTY_FLAG_KEYFILE) != 0) {
        kfd = old->keyfile_digest;
    }

    vty_random(kc, VTY_KEY_BYTES);
    rc = vty_vault_create_from_kc(old, new_path, password, kc, new_flags,
                                  kfd, &newv);
    vty_secure_zero(kc, sizeof(kc));
    if (rc != VTY_OK) {
        vty_rotate_free(job);
        return rc;
    }

    job->newv = newv;
    old->rotate_pending = 1u;
    *out = job;
    return VTY_OK;
}

int vty_rotate_unlock_module(VtyRotateJob *job, uint32_t index,
                             const char *password, const char *recovery_code)
{
    char *copy;
    int rc;

    if (job == NULL || job->old == NULL) return VTY_E_INVALID;
    if (job->stage != VTY_ROTATE_STAGE_BEGUN) return VTY_E_POLICY;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    if (!job->old->modules[index].enabled) return VTY_E_POLICY;
    if (password == NULL || password[0] == '\0' ||
        strlen(password) > VTY_MODULE_PASSWORD_MAX) {
        return VTY_E_INVALID;
    }
    if (recovery_code != NULL && recovery_code[0] != '\0') {
        rc = vty_vault_verify_recovery(job->old, recovery_code);
        if (rc != VTY_OK) return rc;
    }

    rc = vty_module_unlock(job->old, index, password);
    if (rc != VTY_OK) return rc;

    copy = (char *)vty_secure_alloc(strlen(password) + 1u, "module_pw");
    if (copy == NULL) return VTY_E_RESOURCE;
    memcpy(copy, password, strlen(password) + 1u);
    if (job->module_pw[index] != NULL) {
        vty_secure_free(job->module_pw[index]);
    }
    job->module_pw[index] = copy;
    job->module_pw_len[index] = strlen(password);
    return VTY_OK;
}
