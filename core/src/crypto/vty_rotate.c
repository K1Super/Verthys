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
#include "vty_rotate.h"
#include "vty_repo.h"
#include "vty_store.h"
#include "vty_module.h"
#include "vty_tpm_pcr.h"
#include "vty_rollback.h"
#include "vty_util.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

#define VTY_ROTATE_PATH_MAX 1024u
#define VTY_ROTATE_BACKUP_MAX 1100u
#define VTY_ROTATE_SPACE_MARGIN (16u * 1024u * 1024u)

struct VtyRotateJob {
    VtyVault *old;                  /* 借用源会话 */
    VtyVault *newv;                 /* 作业拥有的新会话 */
    char old_path[VTY_ROTATE_PATH_MAX];
    char new_path[VTY_ROTATE_PATH_MAX];
    char backup_path[VTY_ROTATE_BACKUP_MAX];
    uint32_t stage;
    char *module_pw[VTY_MODULE_COUNT];
    size_t module_pw_len[VTY_MODULE_COUNT];
    uint8_t has_pcr;
    uint8_t pcr_drop;
    uint8_t pcr_sealed;             /* PCR 密钥已被覆盖，失败时需恢复源库 */
    void *journal;                  /* PCR 重封期间持有的恢复日志句柄 */
    uint8_t backup_created;
    uint8_t new_installed;
    uint32_t pcr_select;
    uint64_t expected_chunks;
    uint64_t source_next_id;        /* 源库 ID 分配器水位（轮换保真） */
    VtyRotateStats stats;
};

static void rot_set_stage(VtyRotateJob *job, uint32_t stage)
{
    job->stage = stage;
    job->stats.stage = stage;
}

static wchar_t *rot_utf8_to_wide(const char *s)
{
    int n;
    wchar_t *w;

    if (s == NULL) return NULL;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (w == NULL) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

static int rot_file_exists(const char *path)
{
    wchar_t *w = rot_utf8_to_wide(path);
    DWORD attrs;
    int exists;

    if (w == NULL) return 0;
    attrs = GetFileAttributesW(w);
    exists = (attrs != INVALID_FILE_ATTRIBUTES);
    free(w);
    return exists;
}

static int rot_move(const char *from, const char *to)
{
    wchar_t *wf = rot_utf8_to_wide(from);
    wchar_t *wt = rot_utf8_to_wide(to);
    int rc = VTY_OK;

    if (wf == NULL || wt == NULL) {
        free(wf);
        free(wt);
        return VTY_E_INVALID;
    }
    if (!MoveFileExW(wf, wt, MOVEFILE_WRITE_THROUGH)) rc = VTY_E_IO;
    free(wf);
    free(wt);
    return rc;
}

/* 原子替换：target 被 replacement 替换，原 target 内容落到 backup（backup
 * 必须不存在）；成功返回时 replacement 路径不再存在。Windows ReplaceFileW
 * 保证单次调用内完成“替换 + 备份”，不存在“源路径先消失”的窗口。 */
static int rot_replace(const char *target, const char *replacement,
                       const char *backup)
{
    wchar_t *wt;
    wchar_t *wr;
    wchar_t *wb = NULL;
    int rc = VTY_OK;

    if (target == NULL || replacement == NULL || backup == NULL) {
        return VTY_E_INVALID;
    }
    wt = rot_utf8_to_wide(target);
    wr = rot_utf8_to_wide(replacement);
    wb = rot_utf8_to_wide(backup);
    if (wt == NULL || wr == NULL || wb == NULL) {
        free(wt);
        free(wr);
        free(wb);
        return VTY_E_INVALID;
    }
    if (!ReplaceFileW(wt, wr, wb, REPLACEFILE_WRITE_THROUGH, NULL, NULL)) {
        rc = VTY_E_IO;
    }
    free(wt);
    free(wr);
    free(wb);
    return rc;
}

/* 清理失败不应伪装成成功：删除失败时重试有限次数，并返回是否真正删除。 */
static int rot_delete(const char *path)
{
    wchar_t *w;
    uint32_t attempt;

    if (path == NULL || path[0] == '\0') return 1;
    w = rot_utf8_to_wide(path);
    if (w == NULL) return 0;
    for (attempt = 0; attempt < 3u; attempt++) {
        if (DeleteFileW(w)) {
            free(w);
            return 1;
        }
        Sleep(20u);
    }
    free(w);
    return !rot_file_exists(path);
}

/* 同目录（同卷）判定：跨卷 MoveFileExW 不是原子替换，必须在 Begin
 * 阶段就拒绝，而不是等临时库建完再失败。 */
static int rot_full_path(const char *path, wchar_t out[2048])
{
    wchar_t *w = rot_utf8_to_wide(path);
    DWORD n;

    if (w == NULL) return 0;
    n = GetFullPathNameW(w, 2048, out, NULL);
    free(w);
    return n > 0 && n < 2048;
}

static int rot_same_directory(const char *a, const char *b)
{
    wchar_t wa[2048];
    wchar_t wb[2048];
    wchar_t *pa, *pb;
    int rc;

    if (!rot_full_path(a, wa) || !rot_full_path(b, wb)) return 0;
    pa = wcsrchr(wa, L'\\');
    pb = wcsrchr(wb, L'\\');
    if (pa == NULL || pb == NULL) return 0;
    *pa = L'\0';
    *pb = L'\0';
    rc = _wcsicmp(wa, wb);
    vty_secure_zero(wa, sizeof(wa));
    vty_secure_zero(wb, sizeof(wb));
    return rc == 0;
}

/* 粗粒度空间预检：新库只保留存活记录/分片，正常不会超过旧文件大小；
 * 用旧文件大小 + 余量作为下界，空间不足时尽早返回 NO_SPACE。查询失败
 * （路径/卷信息不可得）不阻断，交给实际写入报 IO/NO_SPACE。 */
static int rot_space_ok(const char *old_path)
{
    wchar_t wold[2048];
    wchar_t volume[2048];
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULARGE_INTEGER free_bytes;
    uint64_t size;
    uint64_t required;

    if (!rot_full_path(old_path, wold)) return VTY_E_INVALID;
    if (!GetFileAttributesExW(wold, GetFileExInfoStandard, &fad)) {
        return VTY_OK;
    }
    size = ((uint64_t)fad.nFileSizeHigh << 32) | (uint64_t)fad.nFileSizeLow;
    if (size > UINT64_MAX - (uint64_t)VTY_ROTATE_SPACE_MARGIN) {
        return VTY_E_NO_SPACE;
    }
    required = size + (uint64_t)VTY_ROTATE_SPACE_MARGIN;

    if (!GetVolumePathNameW(wold, volume,
                            (DWORD)(sizeof(volume) / sizeof(volume[0]))) ||
        !GetDiskFreeSpaceExW(volume, &free_bytes, NULL, NULL)) {
        return VTY_OK;
    }
    return ((uint64_t)free_bytes.QuadPart >= required) ? VTY_OK
                                                       : VTY_E_NO_SPACE;
}

static int rot_make_backup_path(const char *old_path,
                                char out[VTY_ROTATE_BACKUP_MAX])
{
    uint32_t attempt;

    for (attempt = 0; attempt < 8u; attempt++) {
        uint32_t rnd = 0;
        vty_random((uint8_t *)&rnd, sizeof(rnd));
        if (sprintf_s(out, VTY_ROTATE_BACKUP_MAX, "%s.old-%08lx-%08lx",
                      old_path, (unsigned long)GetTickCount64(),
                      (unsigned long)rnd) < 0) {
            return VTY_E_RESOURCE;
        }
        if (!rot_file_exists(out)) return VTY_OK;
    }
    return VTY_E_IO;
}

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
        if (!rot_file_exists(job->backup_path)) {
            job->old->unlocked = 0;
            return VTY_E_IO;
        }
        rc = rot_replace(job->old_path, job->backup_path, job->new_path);
        if (rc != VTY_OK) {
            /* 源路径仍是完整新库、备份仍是完整旧库：不删除任何文件，
             * 交由恢复码路径处理；PCR 重封不能执行（TPM 密钥已指向新库）。 */
            job->old->unlocked = 0;
            return VTY_E_IO;
        }
        job->new_installed = 0;
        job->backup_created = 0;
    } else if (job->backup_created) {
        rc = rot_move(job->backup_path, job->old_path);
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
    if (safe_to_delete && !rot_delete(job->new_path)) rc = VTY_E_IO;
    vty_rotate_free(job);
    return rc;
}

const VtyRotateStats *vty_rotate_stats(const VtyRotateJob *job)
{
    return (job != NULL) ? &job->stats : NULL;
}

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

    if (rot_file_exists(new_path)) return VTY_E_EXISTS;
    if (!rot_same_directory(old->path, new_path)) return VTY_E_INVALID;
    rc = rot_space_ok(old->path);
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
    rot_set_stage(job, VTY_ROTATE_STAGE_BEGUN);
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

static int rot_progress(VtyRotateJob *job, VtyRotateProgressFn cb, void *user)
{
    if (cb == NULL) return VTY_OK;
    return cb(user, &job->stats) != 0 ? VTY_E_POLICY : VTY_OK;
}

static int rot_records_equal(const VtyRepoRecord *a, const VtyRepoRecord *b)
{
    if (a->type != b->type || a->name_len != b->name_len ||
        a->data_len != b->data_len) {
        return 0;
    }
    if (a->name_len != 0u &&
        memcmp(a->name, b->name, a->name_len) != 0) {
        return 0;
    }
    if (a->data_len != 0u &&
        memcmp(a->data, b->data, a->data_len) != 0) {
        return 0;
    }
    return 1;
}

static void rot_free_record(VtyRepoRecord *rec)
{
    if (rec->name != NULL) {
        vty_secure_zero(rec->name, rec->name_len != 0 ? rec->name_len : 1u);
        vty_free(rec->name, rec->name_len != 0 ? rec->name_len : 1u);
        rec->name = NULL;
    }
    if (rec->data != NULL) {
        vty_secure_zero(rec->data, rec->data_len != 0 ? rec->data_len : 1u);
        vty_free(rec->data, rec->data_len != 0 ? rec->data_len : 1u);
        rec->data = NULL;
    }
}

static int rot_copy_records(VtyRotateJob *job, VtyRotateProgressFn cb,
                            void *user)
{
    VtyRepoIter *it = NULL;
    int rc;

    rc = vty_repo_iter_open(job->old, 0u, &it);
    if (rc != VTY_OK) return rc;

    for (;;) {
        VtyRepoLeaf leaf;
        VtyRepoRecord rec;
        VtyRepoRecord check;
        uint64_t new_id = 0;
        int done = 0;

        memset(&leaf, 0, sizeof(leaf));
        memset(&rec, 0, sizeof(rec));
        memset(&check, 0, sizeof(check));
        rc = vty_repo_iter_next(it, &leaf, &done);
        if (rc != VTY_OK || done) break;

        rc = vty_repo_read(job->old, &leaf, &rec);
        if (rc == VTY_OK) {
            rc = vty_repo_add_ex(job->newv, rec.type, rec.name, rec.name_len,
                                 rec.data, rec.data_len, leaf.record_id,
                                 leaf.created_time, &new_id);
        }
        if (rc != VTY_OK) {
            rot_free_record(&rec);
            break;
        }
        if (new_id != leaf.record_id) {
            rot_free_record(&rec);
            rc = VTY_E_VERIFY;
            break;
        }
        /* 逐条回读新库：提交前证明“复制出的内容与源库逐字节一致”，
         * 而不是只相信计数。 */
        rc = vty_repo_get(job->newv, new_id, &check);
        if (rc == VTY_OK && !rot_records_equal(&rec, &check)) {
            rc = VTY_E_VERIFY;
        }
        rot_free_record(&check);
        if (rc != VTY_OK) {
            rot_free_record(&rec);
            break;
        }

        job->stats.records++;
        job->stats.bytes += (uint64_t)rec.name_len + (uint64_t)rec.data_len;
        rot_free_record(&rec);
        rc = rot_progress(job, cb, user);
        if (rc != VTY_OK) break;
    }

    vty_repo_iter_close(it);
    return rc;
}

typedef struct {
    VtyRotateJob *job;
    VtyRotateProgressFn cb;
    void *user;
} RotFileCtx;

static int rot_copy_file(void *user, const uint8_t file_uuid[VTY_UUID_BYTES],
                         const VtyRepoFile *file)
{
    RotFileCtx *ctx = (RotFileCtx *)user;
    VtyRotateJob *job = ctx->job;
    VtyRepoFile check_file;
    uint32_t seq;
    int rc;

    rc = vty_repo_file_put_ex(job->newv, file_uuid, file->pt_hash,
                              file->total, file->created_time);
    if (rc != VTY_OK) return rc;
    memset(&check_file, 0, sizeof(check_file));
    rc = vty_repo_file_get(job->newv, file_uuid, &check_file);
    if (rc == VTY_OK &&
        (check_file.total != file->total ||
         check_file.created_time != file->created_time ||
         memcmp(check_file.pt_hash, file->pt_hash, VTY_HASH_BYTES) != 0)) {
        rc = VTY_E_VERIFY;
    }
    if (rc != VTY_OK) return rc;
    job->expected_chunks += (uint64_t)file->total;

    for (seq = 0; seq < file->total; seq++) {
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        uint8_t *rt = NULL;
        size_t rt_len = 0;

        rc = vty_repo_chunk_get(job->old, file_uuid, seq, &pt, &pt_len);
        if (rc == VTY_OK) {
            rc = vty_repo_chunk_add(job->newv, file_uuid, seq, pt, pt_len);
        }
        if (rc == VTY_OK) {
            rc = vty_repo_chunk_get(job->newv, file_uuid, seq, &rt, &rt_len);
            if (rc == VTY_OK &&
                (rt_len != pt_len || memcmp(rt, pt, pt_len) != 0)) {
                rc = VTY_E_VERIFY;
            }
        }
        if (rt != NULL) {
            vty_secure_zero(rt, rt_len != 0 ? rt_len : 1u);
            vty_free(rt, rt_len != 0 ? rt_len : 1u);
        }
        if (pt != NULL) {
            vty_secure_zero(pt, pt_len != 0 ? pt_len : 1u);
            vty_free(pt, pt_len != 0 ? pt_len : 1u);
        }
        if (rc != VTY_OK) return rc;
        job->stats.chunks++;
        /* 分片级回调：大文件复制期间也能在下一分片边界响应取消请求。 */
        rc = rot_progress(job, ctx->cb, ctx->user);
        if (rc != VTY_OK) return rc;
    }

    job->stats.files++;
    return rot_progress(job, ctx->cb, ctx->user);
}

static int rot_verify(VtyRotateJob *job)
{
    uint64_t old_count = 0;
    uint64_t new_count = 0;
    uint64_t old_files = 0;
    uint64_t new_files = 0;
    int rc;

    rc = vty_repo_count(job->old, &old_count);
    if (rc != VTY_OK) return rc;
    rc = vty_repo_count(job->newv, &new_count);
    if (rc != VTY_OK) return rc;
    if (old_count != new_count || new_count != job->stats.records) {
        return VTY_E_VERIFY;
    }

    if (job->old->modules[2].deleted) {
        /* fileverthys 已删除：键空间只剩墓碑，不依赖模块密钥统计存活文件；
         * 若仍存在存活文件叶，说明删除未清空数据，必须 fail-closed。 */
        uint64_t live = 0;
        rc = vty_repo_file_count_live(job->old, &live);
        if (rc != VTY_OK) return rc;
        if (live != 0) return VTY_E_CORRUPT;
        old_files = 0;
    } else {
        rc = vty_repo_file_list(job->old, NULL, NULL, &old_files);
        if (rc != VTY_OK) return rc;
    }
    rc = vty_repo_file_list(job->newv, NULL, NULL, &new_files);
    if (rc != VTY_OK) return rc;
    if (old_files != new_files || new_files != job->stats.files) {
        return VTY_E_VERIFY;
    }
    if (job->stats.chunks != job->expected_chunks) return VTY_E_VERIFY;
    return VTY_OK;
}

int vty_rotate_run(VtyRotateJob *job, VtyRotateProgressFn cb, void *user)
{
    uint32_t i;
    int rc;

    if (job == NULL || job->newv == NULL || job->old == NULL) {
        return VTY_E_INVALID;
    }
    if (job->stage != VTY_ROTATE_STAGE_BEGUN) return VTY_E_POLICY;

    /* 所有已启用模块必须具备口令与已解锁的源 MDEK，否则复制出的记录
     * 无法解密。 */
    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        if (!job->old->modules[i].enabled) continue;
        if (job->module_pw[i] == NULL || !job->old->modules[i].unlocked) {
            return VTY_E_MODULE_LOCKED;
        }
    }

    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        if (!job->old->modules[i].enabled) continue;
        rc = vty_module_enable(job->newv, i, job->module_pw[i], NULL);
        if (rc != VTY_OK) goto fail;
        if (job->old->modules[i].has_recovery) {
            rc = vty_module_recovery_seal(job->newv, i, job->old->k_recovery);
            if (rc != VTY_OK) goto fail;
        }
        job->stats.modules_ready++;
        rc = rot_progress(job, cb, user);
        if (rc != VTY_OK) goto fail;
    }

    rc = rot_copy_records(job, cb, user);
    if (rc != VTY_OK) goto fail;

    {
        RotFileCtx ctx;
        ctx.job = job;
        ctx.cb = cb;
        ctx.user = user;
        if (job->old->modules[2].deleted) {
            /* 文件模块已删除：只验证键空间无存活文件，不执行复制。 */
            uint64_t live = 0;
            rc = vty_repo_file_count_live(job->old, &live);
            if (rc != VTY_OK) goto fail;
            if (live != 0) { rc = VTY_E_CORRUPT; goto fail; }
        } else {
            rc = vty_repo_file_list(job->old, rot_copy_file, &ctx, NULL);
            if (rc != VTY_OK) goto fail;
        }
    }

    /* 保留源库 ID 水位：新库不得复用源库已分配过的 ID（含已删除记录）。 */
    if (job->source_next_id != 0u) {
        uint64_t new_next = 0;
        rc = vty_repo_next_id(job->newv, &new_next);
        if (rc != VTY_OK) goto fail;
        if (job->source_next_id > new_next) {
            rc = vty_repo_set_next_id(job->newv, job->source_next_id);
            if (rc != VTY_OK) goto fail;
        }
    }

    rc = vty_store_verify(job->newv->store);
    if (rc != VTY_OK) goto fail;
    rc = rot_verify(job);
    if (rc != VTY_OK) goto fail;

    /* 最后一次落盘：提交数据区并写元数据；锚点仍被抑制。 */
    rc = vty_vault_save(job->newv);
    if (rc != VTY_OK) goto fail;

    rot_set_stage(job, VTY_ROTATE_STAGE_COPIED);
    return VTY_OK;

fail:
    rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
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
            rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
            return VTY_E_RESOURCE;
        }
        rc = vty_vault_rotate_journal_start(old, &job->journal);
        if (rc != VTY_OK) {
            rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
            return rc;
        }
        job->pcr_sealed = 1u;
        rc = vty_vault_pcr_slot_prepare(newv, job->pcr_select, &slot);
        if (rc != VTY_OK) {
            jrc = rot_restore_old_pcr(job);
            rot_journal_end_after_restore(job, jrc == VTY_OK);
            rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
            return rc;
        }
        newv->slots[newv->slot_count] = slot;
        newv->slot_count++;
        newv->header.flags |= VTY_FLAG_PCR;
        rc = vty_vault_save_meta(newv);
        if (rc != VTY_OK) {
            jrc = rot_restore_old_pcr(job);
            rot_journal_end_after_restore(job, jrc == VTY_OK);
            rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
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

    rc = rot_make_backup_path(job->old_path, job->backup_path);
    if (rc != VTY_OK) {
        rot_reopen_or_lock(old);
        jrc = rot_restore_old_pcr(job);
        rot_journal_end_after_restore(job, jrc == VTY_OK);
        rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
        return rc;
    }

    /* 单次原子替换：源路径在任何时刻都存在且内容完整（旧库或新库），
     * 旧库内容落到 backup，不存在“源路径先消失”的窗口。 */
    rc = rot_replace(job->old_path, job->new_path, job->backup_path);
    if (rc != VTY_OK) {
        /* 失败后源库通常仍在；若源路径缺失而备份已生成，先把备份放回
         * 源路径，再重开源会话。 */
        if (!rot_file_exists(job->old_path)) {
            if (rot_file_exists(job->backup_path) &&
                rot_move(job->backup_path, job->old_path) == VTY_OK) {
                job->backup_created = 0u;
            } else {
                job->old->unlocked = 0;
            }
        }
        if (rot_file_exists(job->backup_path)) job->backup_created = 1u;
        rot_reopen_or_lock(old);
        jrc = rot_restore_old_pcr(job);
        rot_journal_end_after_restore(job, jrc == VTY_OK);
        rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
        return rc;
    }
    job->new_installed = 1u;
    job->backup_created = 1u;

    memcpy(newv->path, job->old_path, strlen(job->old_path) + 1);
    rc = rot_reopen_store(newv);
    if (rc != VTY_OK) {
        (void)rot_restore_after_failed_swap(job);
        rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
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
            rot_set_stage(job, VTY_ROTATE_STAGE_FAILED);
            return rc;
        }
    }

    newv->no_rollback_anchor = 0u;
    newv->recovery_mode = 0u;
    old->rotate_pending = 0u;

    /* PCR 重封与原子替换均已越过崩溃窗口：恢复日志不再需要。 */
    vty_vault_rotate_journal_end(&job->journal, 1);

    if (!keep_old) {
        if (rot_delete(job->backup_path)) {
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

    rot_set_stage(job, VTY_ROTATE_STAGE_COMMITTED);
    for (i = 0; i < VTY_MODULE_COUNT; i++) rot_zero_pw(job, i);

    *out_new = newv;
    job->newv = NULL;
    job->old = NULL;
    vty_vault_free(old);
    vty_rotate_free(job);
    return VTY_OK;
}
