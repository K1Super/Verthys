/*
 * vty_compact.c — 容器空间压缩作业实现
 *
 * 安全边界：只搬运已加密的记录/分片段，不接触明文与模块密钥；目录树用
 * 当前会话 K_dir 重建，slots/keyring/epoch 原样继承。替换使用
 * ReplaceFileW(WRITE_THROUGH) + 同目录备份，失败保留原库。
 */
#include "vty_compact.h"
#include "vty_secure_delete.h"
#include "vty_repo.h"
#include "vty_store.h"
#include "vty_rollback.h"
#include "vty_util.h"

#include <windows.h>
#include <stdlib.h>
#include <string.h>

#define VTY_COMPACT_PATH_MAX 1400u
#define VTY_COMPACT_TMP_SUFFIX ".vtycompact.tmp"
#define VTY_COMPACT_BAK_SUFFIX ".vtycompact.bak"

struct VtyCompactJob {
    VtyVault *src;
    VtyVault *dst;
    char src_path[VTY_COMPACT_PATH_MAX];
    char tmp_path[VTY_COMPACT_PATH_MAX];
    char backup_path[VTY_COMPACT_PATH_MAX];
    VtyCompactStats stats;
};

static wchar_t *compact_utf8_to_wide(const char *s)
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

static int compact_derive_path(const char *base, const char *suffix,
                               char out[VTY_COMPACT_PATH_MAX])
{
    size_t blen, slen;

    if (base == NULL || suffix == NULL || out == NULL) return VTY_E_INVALID;
    blen = strlen(base);
    slen = strlen(suffix);
    if (blen + slen + 1u > VTY_COMPACT_PATH_MAX) return VTY_E_INVALID;
    memcpy(out, base, blen);
    memcpy(out + blen, suffix, slen + 1u);
    return VTY_OK;
}

static int compact_path_exists(const char *path)
{
    wchar_t *w;
    DWORD attrs;

    if (path == NULL) return 0;
    w = compact_utf8_to_wide(path);
    if (w == NULL) return 0;
    attrs = GetFileAttributesW(w);
    free(w);
    return attrs != INVALID_FILE_ATTRIBUTES;
}

static int compact_delete_path(const char *path, int missing_ok)
{
    int rc;

    (void)missing_ok;
    if (path == NULL) return VTY_E_INVALID;
    /* 旧库/临时库与源库同密钥；先整文件零写再删除，避免密文留在
     * 空闲空间仍可被口令解封。 */
    rc = vty_secure_delete_file(path);
    return rc;
}

/* 同目录替换：备份名不得预先存在；ReplaceFileW 失败时目标文件保持原样。 */
static int compact_replace_file(const char *target, const char *replacement,
                                const char *backup)
{
    wchar_t *wt = NULL, *wr = NULL, *wb = NULL;
    BOOL ok;
    int rc = VTY_E_IO;

    if (target == NULL || replacement == NULL || backup == NULL) {
        return VTY_E_INVALID;
    }
    if (compact_delete_path(backup, 1) != VTY_OK) return VTY_E_IO;

    wt = compact_utf8_to_wide(target);
    wr = compact_utf8_to_wide(replacement);
    wb = compact_utf8_to_wide(backup);
    if (wt == NULL || wr == NULL || wb == NULL) goto out;
    ok = ReplaceFileW(wt, wr, wb, REPLACEFILE_WRITE_THROUGH, NULL, NULL);
    if (ok) rc = VTY_OK;

out:
    if (wt != NULL) free(wt);
    if (wr != NULL) free(wr);
    if (wb != NULL) free(wb);
    return rc;
}

static int compact_move_replace(const char *from, const char *to)
{
    wchar_t *wf = NULL, *wt = NULL;
    BOOL ok;
    int rc = VTY_E_IO;

    if (from == NULL || to == NULL) return VTY_E_INVALID;
    wf = compact_utf8_to_wide(from);
    wt = compact_utf8_to_wide(to);
    if (wf == NULL || wt == NULL) goto out;
    ok = MoveFileExW(wf, wt, MOVEFILE_REPLACE_EXISTING |
                                 MOVEFILE_WRITE_THROUGH);
    if (ok) rc = VTY_OK;

out:
    if (wf != NULL) free(wf);
    if (wt != NULL) free(wt);
    return rc;
}

static int compact_dir_free_bytes(const char *container_path, uint64_t *out)
{
    char dir[VTY_COMPACT_PATH_MAX];
    wchar_t *w = NULL;
    ULARGE_INTEGER free_bytes;
    size_t len, i;
    int found_sep = 0;

    if (container_path == NULL || out == NULL) return VTY_E_INVALID;
    len = strlen(container_path);
    if (len + 1u > sizeof(dir)) return VTY_E_INVALID;
    memcpy(dir, container_path, len + 1u);
    for (i = len; i > 0u; i--) {
        if (dir[i - 1u] == '\\' || dir[i - 1u] == '/') {
            dir[i - 1u] = '\0';
            found_sep = 1;
            break;
        }
    }
    if (!found_sep) {
        /* 相对文件名：当前目录就是目标卷目录。 */
        memcpy(dir, ".", 2u);
    } else {
        len = strlen(dir);
        if (len == 0u) {
            /* 根目录 "\\" / "/"：保留原始分隔符作为卷根。 */
            dir[0] = container_path[0];
            dir[1] = '\0';
        } else if (len == 2u && dir[1] == ':') {
            /* "C:" 表示该盘当前目录，必须补根分隔符才是卷根。 */
            dir[2] = '\\';
            dir[3] = '\0';
        }
    }

    w = compact_utf8_to_wide(dir);
    if (w == NULL) return VTY_E_INVALID;
    if (!GetDiskFreeSpaceExW(w, NULL, &free_bytes, NULL)) {
        free(w);
        return VTY_E_IO;
    }
    free(w);
    *out = (uint64_t)free_bytes.QuadPart;
    return VTY_OK;
}

static int compact_space_ok(const char *container_path, uint64_t live_bytes)
{
    uint64_t free_bytes = 0;
    uint64_t need;
    uint64_t margin;
    int rc;

    rc = compact_dir_free_bytes(container_path, &free_bytes);
    if (rc != VTY_OK) return rc;
    if (live_bytes > UINT64_MAX - VTY_DATA_OFFSET) return VTY_E_NO_SPACE;
    need = live_bytes + VTY_DATA_OFFSET;
    margin = live_bytes / 20u;
    if (margin < 16u * 1024u * 1024u) margin = 16u * 1024u * 1024u;
    if (need > UINT64_MAX - margin) return VTY_E_NO_SPACE;
    need += margin;
    return (free_bytes >= need) ? VTY_OK : VTY_E_NO_SPACE;
}

static int compact_reopen_store(VtyVault *v)
{
    if (v == NULL) return VTY_E_INVALID;
    if (v->store != NULL) {
        vty_store_close(v->store);
        v->store = NULL;
    }
    return vty_store_open(v->path, v->kc, v->header.vault_uuid,
                          v->header.epoch, &v->data_root,
                          v->data_root_hash, &v->store);
}

typedef struct {
    VtyCompactJob *job;
    VtyCompactProgressFn cb;
    void *user;
} CompactBridge;

static int compact_progress_bridge(void *user, uint64_t records,
                                   uint64_t chunks, uint64_t bytes)
{
    CompactBridge *bridge = (CompactBridge *)user;

    if (bridge == NULL || bridge->job == NULL) return 0;
    bridge->job->stats.records = records;
    bridge->job->stats.chunks = chunks;
    bridge->job->stats.bytes = bytes;
    if (bridge->cb != NULL) {
        return bridge->cb(bridge->user, &bridge->job->stats);
    }
    return 0;
}

int vty_compact_begin(VtyVault *src, const char *tmp_path,
                      VtyCompactJob **out)
{
    VtyCompactJob *job = NULL;
    VtyStorageStats stats;
    int rc;

    if (out != NULL) *out = NULL;
    if (src == NULL || tmp_path == NULL || out == NULL) return VTY_E_INVALID;
    if (!src->unlocked || src->store == NULL) return VTY_E_POLICY;
    if (src->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (src->defer_anchor) return VTY_E_POLICY;
    if (strlen(src->path) + 1u > VTY_COMPACT_PATH_MAX ||
        strlen(tmp_path) + 1u > VTY_COMPACT_PATH_MAX) {
        return VTY_E_INVALID;
    }
    if (compact_path_exists(tmp_path)) {
        rc = compact_delete_path(tmp_path, 1);
        if (rc != VTY_OK) return rc;
    }

    rc = vty_repo_storage_stats(src, &stats);
    if (rc != VTY_OK) return rc;
    rc = compact_space_ok(src->path, stats.live_bytes);
    if (rc != VTY_OK) return rc;

    job = (VtyCompactJob *)vty_alloc(sizeof(*job));
    if (job == NULL) return VTY_E_RESOURCE;
    memset(job, 0, sizeof(*job));
    job->src = src;
    memcpy(job->src_path, src->path, strlen(src->path) + 1u);
    memcpy(job->tmp_path, tmp_path, strlen(tmp_path) + 1u);
    rc = compact_derive_path(job->src_path, VTY_COMPACT_BAK_SUFFIX,
                             job->backup_path);
    if (rc != VTY_OK) {
        vty_free(job, sizeof(*job));
        return rc;
    }
    job->stats.before_bytes = stats.file_size;
    job->stats.live_bytes = stats.live_bytes;
    job->stats.stage = VTY_COMPACT_STAGE_BEGUN;

    rc = vty_vault_clone_for_compaction(src, tmp_path, &job->dst);
    if (rc != VTY_OK) {
        vty_free(job, sizeof(*job));
        return rc;
    }
    *out = job;
    return VTY_OK;
}

int vty_compact_run(VtyCompactJob *job, VtyCompactProgressFn cb, void *user)
{
    CompactBridge bridge;
    VtyStorageStats s1, s2;
    VtyStoreStats st;
    uint64_t src_next = 0, dst_next = 0;
    uint64_t records = 0, chunks = 0, bytes = 0;
    uint64_t file_size = 0;
    uint64_t mtime = 0;
    int rc;

    if (job == NULL || job->src == NULL || job->dst == NULL) {
        return VTY_E_INVALID;
    }
    if (job->stats.stage != VTY_COMPACT_STAGE_BEGUN) return VTY_E_POLICY;

    job->stats.stage = VTY_COMPACT_STAGE_COPIED;
    bridge.job = job;
    bridge.cb = cb;
    bridge.user = user;

    rc = vty_repo_compact_copy(job->src, job->dst,
                               compact_progress_bridge, &bridge,
                               &records, &chunks, &bytes);
    if (rc != VTY_OK) goto fail;
    job->stats.records = records;
    job->stats.chunks = chunks;
    job->stats.bytes = bytes;

    rc = vty_store_verify(job->dst->store);
    if (rc != VTY_OK) goto fail;
    rc = vty_vault_commit_store(job->dst);
    if (rc != VTY_OK) goto fail;
    rc = vty_vault_save_meta(job->dst);
    if (rc != VTY_OK) goto fail;
    rc = vty_store_verify_data_root(job->dst->store, &job->dst->data_root,
                                    job->dst->data_root_hash, &file_size,
                                    &mtime);
    if (rc != VTY_OK) goto fail;

    rc = vty_repo_storage_stats(job->src, &s1);
    if (rc != VTY_OK) goto fail;
    rc = vty_repo_storage_stats(job->dst, &s2);
    if (rc != VTY_OK) goto fail;
    if (s1.live_segment_bytes != s2.live_segment_bytes ||
        s1.record_count != s2.record_count ||
        s1.file_count != s2.file_count ||
        s1.chunk_count != s2.chunk_count) {
        rc = VTY_E_VERIFY;
        goto fail;
    }
    rc = vty_repo_next_id(job->src, &src_next);
    if (rc == VTY_OK) rc = vty_repo_next_id(job->dst, &dst_next);
    if (rc != VTY_OK) goto fail;
    if (src_next != dst_next) {
        rc = VTY_E_VERIFY;
        goto fail;
    }
    rc = vty_store_storage_stats(job->dst->store, &st);
    if (rc != VTY_OK) goto fail;
    if (st.file_size > job->stats.before_bytes) {
        rc = VTY_E_VERIFY;
        goto fail;
    }
    job->stats.after_bytes = st.file_size;
    job->stats.reclaimed_bytes =
        job->stats.before_bytes - job->stats.after_bytes;
    job->stats.stage = VTY_COMPACT_STAGE_COPIED;
    if (cb != NULL && cb(user, &job->stats) != 0) {
        rc = VTY_E_POLICY;
        goto fail;
    }
    return VTY_OK;

fail:
    job->stats.stage = VTY_COMPACT_STAGE_FAILED;
    return rc;
}

/* 替换后失败：把备份放回源路径并重开源库。返回 VTY_E_IO 表示连回滚
 * 都失败，调用方应锁定容器并要求人工介入。 */
static int compact_restore_backup(VtyCompactJob *job)
{
    int rc;

    if (job->dst != NULL && job->dst->store != NULL) {
        vty_store_close(job->dst->store);
        job->dst->store = NULL;
    }
    rc = compact_move_replace(job->backup_path, job->src_path);
    if (rc != VTY_OK) return rc;
    return compact_reopen_store(job->src);
}

int vty_compact_commit(VtyCompactJob *job, VtyVault **out_new)
{
    VtyVault *src;
    VtyVault *dst;
    int rc;
    int replaced = 0;

    if (out_new != NULL) *out_new = NULL;
    if (job == NULL || job->src == NULL || job->dst == NULL ||
        out_new == NULL) {
        return VTY_E_INVALID;
    }
    if (job->stats.stage != VTY_COMPACT_STAGE_COPIED) return VTY_E_POLICY;
    src = job->src;
    dst = job->dst;

    /* 关闭两个数据区句柄，ReplaceFileW 才能完成同卷替换。 */
    if (dst->store != NULL) {
        vty_store_close(dst->store);
        dst->store = NULL;
    }
    if (src->store != NULL) {
        vty_store_close(src->store);
        src->store = NULL;
    }

    rc = compact_replace_file(job->src_path, job->tmp_path,
                              job->backup_path);
    if (rc != VTY_OK) {
        (void)compact_reopen_store(src);
        job->stats.stage = VTY_COMPACT_STAGE_FAILED;
        return rc;
    }
    replaced = 1;

    memcpy(dst->path, job->src_path, strlen(job->src_path) + 1u);
    rc = compact_reopen_store(dst);
    if (rc == VTY_OK) rc = vty_store_verify(dst->store);
    if (rc != VTY_OK) {
        if (replaced) (void)compact_restore_backup(job);
        job->stats.stage = VTY_COMPACT_STAGE_FAILED;
        return rc;
    }

    /* 新文件已落盘且可读；推进回退锚点后再删除旧库备份。 */
    if (vty_rollback_enabled()) {
        rc = vty_rollback_commit(dst->header.vault_uuid,
                                 dst->header.generation);
        if (rc != VTY_OK) {
            (void)compact_restore_backup(job);
            job->stats.stage = VTY_COMPACT_STAGE_FAILED;
            return rc;
        }
    }
    dst->no_rollback_anchor = 0;
    (void)compact_delete_path(job->backup_path, 1);

    job->stats.stage = VTY_COMPACT_STAGE_COMMITTED;
    *out_new = dst;
    job->src = NULL;
    job->dst = NULL;
    vty_vault_free(src);
    vty_compact_free(job);
    return VTY_OK;
}

int vty_compact_abort(VtyCompactJob *job)
{
    int rc = VTY_OK;

    if (job == NULL) return VTY_OK;
    if (job->dst != NULL) {
        vty_vault_free(job->dst);
        job->dst = NULL;
    }
    if (job->tmp_path[0] != '\0' && compact_path_exists(job->tmp_path)) {
        rc = compact_delete_path(job->tmp_path, 1);
    }
    vty_compact_free(job);
    return rc;
}

void vty_compact_free(VtyCompactJob *job)
{
    if (job == NULL) return;
    vty_secure_zero(job, sizeof(*job));
    vty_free(job, sizeof(*job));
}

const VtyCompactStats *vty_compact_stats(const VtyCompactJob *job)
{
    return (job != NULL) ? &job->stats : NULL;
}

int vty_compact_cleanup_stale(const char *container_path)
{
    char tmp[VTY_COMPACT_PATH_MAX];
    int rc;

    rc = compact_derive_path(container_path, VTY_COMPACT_TMP_SUFFIX, tmp);
    if (rc != VTY_OK) return rc;
    if (!compact_path_exists(tmp)) return VTY_OK;
    return compact_delete_path(tmp, 1);
}

int vty_compact_drop_backup(const char *container_path)
{
    char bak[VTY_COMPACT_PATH_MAX];
    int rc;

    rc = compact_derive_path(container_path, VTY_COMPACT_BAK_SUFFIX, bak);
    if (rc != VTY_OK) return rc;
    if (!compact_path_exists(bak)) return VTY_OK;
    return compact_delete_path(bak, 1);
}
