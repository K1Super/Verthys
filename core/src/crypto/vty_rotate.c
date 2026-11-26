/*
 * vty_rotate.c — 全库 DEK 轮换作业实现
 *
 * 设计要点：
 *   - 仅恢复码会话可作为源库；Begin 要求重新输入容器口令用于重封
 *     user/device 槽，恢复槽复用会话缓存的 KEK 与旧 salt，因此旧恢复码
 *     继续有效。
 *   - 新库先以独立文件全量重建，构建期间不推进回退锚点；Commit 时才
 *     原子替换并推进锚点，保证中止/失败不会让源库被锚点拒绝。
 *   - 源库在作业期间只读（rotate_pending），避免复制快照之外的写入
 *     在提交时被静默丢弃。
 *   - PCR 密钥名只由 UUID 派生，重封会覆盖旧私钥（反回滚语义）。覆盖前
 *     先落盘恢复日志，使“重封后、替换前”崩溃的源库仍能用口令解锁；
 *     日志只在源库绑定已恢复或提交完成时删除。
 */

#include "vty_rotate_internal.h"

void vty_rot_set_stage(VtyRotateJob *job, uint32_t stage)
{
    job->stage = stage;
    job->stats.stage = stage;
}

void vty_rotate_free(VtyRotateJob *job)
{
    uint32_t i;

    if (job == NULL) return;
    /* 未显式收尾的日志保留在盘上：重封失败的源库只能靠它恢复口令解锁。 */
    vty_vault_rotate_journal_end(&job->journal, 0);
    if (job->newv != NULL) {
        vty_vault_free(job->newv);
        job->newv = NULL;
    }
    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        if (job->module_pw[i] != NULL) {
            vty_secure_free(job->module_pw[i]);
            job->module_pw[i] = NULL;
            job->module_pw_len[i] = 0;
        }
    }
    vty_free(job, sizeof(*job));
}

/* 中止作业：释放作业并尽力删除临时库。返回 VTY_OK 表示临时库已不存在；
 * 删除失败返回 VTY_E_IO（作业仍被释放，调用方应提示残留文件）。 */
int vty_rotate_abort(VtyRotateJob *job)
{
    int safe_to_delete;
    int rc = VTY_OK;

    if (job == NULL) return VTY_OK;
    safe_to_delete = (job->new_installed == 0 && job->backup_created == 0);
    if (job->old != NULL) job->old->rotate_pending = 0;
    /* 必须先释放新会话（关闭数据区句柄），否则 Windows 上删除会失败。 */
    if (job->newv != NULL) {
        vty_vault_free(job->newv);
        job->newv = NULL;
    }
    /* 提交失败且自动恢复未完成时不动任何文件，保留现场给恢复码路径。 */
    if (safe_to_delete && !vty_rot_delete(job->new_path)) rc = VTY_E_IO;
    vty_rotate_free(job);
    return rc;
}

const VtyRotateStats *vty_rotate_stats(const VtyRotateJob *job)
{
    return (job != NULL) ? &job->stats : NULL;
}

int vty_rot_progress(VtyRotateJob *job, VtyRotateProgressFn cb, void *user)
{
    if (cb == NULL) return VTY_OK;
    return cb(user, &job->stats) != 0 ? VTY_E_POLICY : VTY_OK;
}
