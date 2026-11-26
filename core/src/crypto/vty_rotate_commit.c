/*
 * vty_rotate_commit.c — 提交、原子替换与失败回滚
 *
 * 提交前重封 PCR 并落盘恢复日志；关闭数据区后单次原子替换源路径，
 * 推进回退锚点，按策略清理备份与旧 PCR 密钥。任一步失败恢复源库绑定
 * 与会话；磁盘状态不确定时保持会话锁定。
 */

#include "vty_rotate_internal.h"

static int rot_reopen_store(VtyVault *v)
{
    if (v->store != NULL) {
        vty_store_close(v->store);
        v->store = NULL;
    }
    return vty_store_open(v->path, v->kc, v->header.vault_uuid,
                          v->header.epoch, &v->data_root,
                          v->data_root_hash, &v->store);
}

/* 重开失败意味着源会话已不可写；锁定会话，避免带着空 store 继续操作。 */
static void rot_reopen_or_lock(VtyVault *v)
{
    if (rot_reopen_store(v) != VTY_OK) v->unlocked = 0;
}

/* PCR 密钥名由库 UUID 派生，重封会覆盖旧私钥。提交前若已调用 prepare，
 * 失败路径必须重建源库绑定，否则源库普通解锁会 fail-closed。返回
 * VTY_OK 表示源库绑定已恢复；否则保留恢复日志供下次解锁兜底。 */
static int rot_restore_old_pcr(VtyRotateJob *job)
{
    int saved;
    int rc;

    if (job == NULL || job->old == NULL || !job->pcr_sealed) return VTY_OK;
    saved = job->old->rotate_pending;
    job->old->rotate_pending = 0;
    rc = vty_vault_pcr_reseal(job->old);
    if (rc != VTY_OK) job->old->unlocked = 0;
    job->old->rotate_pending = saved;
    job->pcr_sealed = 0;
    return (rc == VTY_OK) ? VTY_OK : VTY_E_TPM;
}

/* 源库绑定已恢复时才删除日志；恢复失败则保留，下次口令解锁用它重封。 */
static void rot_journal_end_after_restore(VtyRotateJob *job, int restored)
{
    if (job == NULL || job->journal == NULL) return;
    vty_vault_rotate_journal_end(&job->journal, restored);
}

/* 把已安装的新文件退回临时路径、恢复备份并重开源库会话。
 * 回滚同样使用 ReplaceFileW 单次原子替换，避免出现“源路径暂时消失”的
 * 窗口；任一步失败都意味着磁盘状态不确定：源会话保持锁定，等待用户用
 * 恢复码重新打开。 */
static int rot_restore_after_failed_swap(VtyRotateJob *job)
{
    int rc = VTY_OK;
    int orc;

    if (job->new_installed) {
        /* 原子回滚：target=源路径（当前是新库内容），replacement=备份
         * （旧库内容），backup=临时路径（接收新库内容）。成功后源路径恢复
         * 旧库、临时路径回到新库，全程不需要中间态。 */
        if (!vty_rot_file_exists(job->backup_path)) {
            job->old->unlocked = 0;
            return VTY_E_IO;
        }
        rc = vty_rot_replace(job->old_path, job->backup_path, job->new_path);
        if (rc != VTY_OK) {
            /* 源路径仍是完整新库、备份仍是完整旧库：不删除任何文件，
             * 交由恢复码路径处理；PCR 重封不能执行（TPM 密钥已指向新库）。 */
            job->old->unlocked = 0;
            return VTY_E_IO;
        }
        job->new_installed = 0;
        job->backup_created = 0;
    } else if (job->backup_created) {
        rc = vty_rot_move(job->backup_path, job->old_path);
        if (rc != VTY_OK) {
            job->old->unlocked = 0;
            return VTY_E_IO;
        }
        job->backup_created = 0;
    }
    orc = rot_reopen_store(job->old);
    if (orc != VTY_OK) {
        job->old->unlocked = 0;
        rc = VTY_E_IO;
    }
    rot_journal_end_after_restore(job, rot_restore_old_pcr(job) == VTY_OK);
    return rc;
}

static void rot_zero_pw(VtyRotateJob *job, uint32_t index)
{
    if (job->module_pw[index] != NULL) {
        vty_secure_free(job->module_pw[index]);
        job->module_pw[index] = NULL;
        job->module_pw_len[index] = 0;
    }
}

int vty_rotate_commit(VtyRotateJob *job, int keep_old, VtyVault **out_new)
{
    VtyVault *old;
    VtyVault *newv;
    uint32_t i;
    int jrc;
    int rc;

    if (out_new != NULL) *out_new = NULL;
    if (job == NULL || job->old == NULL || job->newv == NULL) {
        return VTY_E_INVALID;
    }
    if (job->stage != VTY_ROTATE_STAGE_COPIED) return VTY_E_POLICY;
    old = job->old;
    newv = job->newv;
    if (!newv->unlocked || newv->store == NULL) return VTY_E_POLICY;

    /* PCR：旧库有槽且 TPM 可用时，在替换前重封新库；密钥名同 UUID，
     * 会覆盖旧私钥，因此失败路径必须恢复源库绑定。覆盖前先落盘恢复
     * 日志：若进程在重封后、替换前被杀，下次口令解锁据此重封源库。 */
    if (job->has_pcr && !job->pcr_drop) {
        VtySlot slot;
        if (newv->slot_count >= VTY_MAX_SLOTS) {
            vty_rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
            return VTY_E_RESOURCE;
        }
        rc = vty_vault_rotate_journal_start(old, &job->journal);
        if (rc != VTY_OK) {
            vty_rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
            return rc;
        }
        job->pcr_sealed = 1u;
        rc = vty_vault_pcr_slot_prepare(newv, job->pcr_select, &slot);
        if (rc != VTY_OK) {
            jrc = rot_restore_old_pcr(job);
            rot_journal_end_after_restore(job, jrc == VTY_OK);
            vty_rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
            return rc;
        }
        newv->slots[newv->slot_count] = slot;
        newv->slot_count++;
        newv->header.flags |= VTY_FLAG_PCR;
        rc = vty_vault_save_meta(newv);
        if (rc != VTY_OK) {
            jrc = rot_restore_old_pcr(job);
            rot_journal_end_after_restore(job, jrc == VTY_OK);
            vty_rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
            return rc;
        }
    }

    /* 关闭两个数据区句柄，ReplaceFileW 才能在同一卷内完成替换。 */
    if (newv->store != NULL) {
        vty_store_close(newv->store);
        newv->store = NULL;
    }
    if (old->store != NULL) {
        vty_store_close(old->store);
        old->store = NULL;
    }

    rc = vty_rot_make_backup_path(job->old_path, job->backup_path);
    if (rc != VTY_OK) {
        rot_reopen_or_lock(old);
        jrc = rot_restore_old_pcr(job);
        rot_journal_end_after_restore(job, jrc == VTY_OK);
        vty_rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
        return rc;
    }

    /* 单次原子替换：源路径在任何时刻都存在且内容完整（旧库或新库），
     * 旧库内容落到 backup，不存在“源路径先消失”的窗口。 */
    rc = vty_rot_replace(job->old_path, job->new_path, job->backup_path);
    if (rc != VTY_OK) {
        /* 失败后源库通常仍在；若源路径缺失而备份已生成，先把备份放回
         * 源路径，再重开源会话。 */
        if (!vty_rot_file_exists(job->old_path)) {
            if (vty_rot_file_exists(job->backup_path) &&
                vty_rot_move(job->backup_path, job->old_path) == VTY_OK) {
                job->backup_created = 0u;
            } else {
                job->old->unlocked = 0;
            }
        }
        if (vty_rot_file_exists(job->backup_path)) job->backup_created = 1u;
        rot_reopen_or_lock(old);
        jrc = rot_restore_old_pcr(job);
        rot_journal_end_after_restore(job, jrc == VTY_OK);
        vty_rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
        return rc;
    }
    job->new_installed = 1u;
    job->backup_created = 1u;

    memcpy(newv->path, job->old_path, strlen(job->old_path) + 1);
    rc = rot_reopen_store(newv);
    if (rc != VTY_OK) {
        (void)rot_restore_after_failed_swap(job);
        vty_rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
        return rc;
    }

    /* 文件已就位，推进回退锚点到新库代。新库代严格大于源库锚点
     * （Begin 时取 source generation + 1 起步），因此用 commit 而非
     * reset_anchor，保持单调防回滚。 */
    if (vty_rollback_enabled()) {
        rc = vty_rollback_commit(newv->header.vault_uuid,
                                 newv->header.generation);
        if (rc != VTY_OK) {
            vty_store_close(newv->store);
            newv->store = NULL;
            (void)rot_restore_after_failed_swap(job);
            vty_rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
            return rc;
        }
    }

    newv->no_rollback_anchor = 0u;
    newv->recovery_mode = 0u;
    old->rotate_pending = 0u;

    /* PCR 重封与原子替换均已越过崩溃窗口：恢复日志不再需要。 */
    vty_vault_rotate_journal_end(&job->journal, 1);

    if (!keep_old) {
        if (vty_rot_delete(job->backup_path)) {
            job->backup_created = 0u;
        }
        /* 删除失败时保留备份文件：提交已经成功，不回滚也不把失败伪装成
         * 成功；残留的加密备份不泄露明文。 */
    }

    /* 新库不再有 PCR 槽时，旧 PCR 密钥只保护已退役的旧 K_c；
     * 不保留旧备份时一并删除，避免残留可解封的旧容器密钥。 */
    if (job->has_pcr && job->pcr_drop && !keep_old) {
        (void)vty_tpm_pcr_key_delete(old->header.vault_uuid);
    }

    vty_rot_set_stage(job, VTY_ROTATE_STAGE_COMMITTED);
    for (i = 0; i < VTY_MODULE_COUNT; i++) rot_zero_pw(job, i);

    *out_new = newv;
    job->newv = NULL;
    job->old = NULL;
    vty_vault_free(old);
    vty_rotate_free(job);
    return VTY_OK;
}
