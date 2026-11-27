/*
 * vty_rotate_internal.h — 轮换作业跨文件内部契约（不导出）
 *
 * 作业对象、路径上限与空间余量只有这一处定义；阶段推进、进度回调与
 * 文件系统原语在实现文件间共享，任何文件都不得另行复制状态。
 */

#ifndef VTY_ROTATE_INTERNAL_H
#define VTY_ROTATE_INTERNAL_H

#include "vty_rotate.h"
#include "vty_repo.h"
#include "vty_store.h"
#include "vty_module.h"
#include "vty_tpm_pcr.h"
#include "vty_rollback.h"
#include "vty_secure_delete.h"
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

typedef struct {
    VtyRotateJob *job;
    VtyRotateProgressFn cb;
    void *user;
} RotFileCtx;

/* 阶段推进与进度回调 */
void vty_rot_set_stage(VtyRotateJob *job, uint32_t stage);
int vty_rot_progress(VtyRotateJob *job, VtyRotateProgressFn cb, void *user);

/* 路径与文件系统原语 */
int vty_rot_file_exists(const char *path);
int vty_rot_move(const char *from, const char *to);
int vty_rot_replace(const char *target, const char *replacement,
                    const char *backup);
int vty_rot_delete(const char *path);
/* 覆盖式重命名：把删除失败的备份转存为确定性的 .vtysdel 待删文件。 */
int vty_rot_rename_over(const char *from, const char *to);
int vty_rot_same_directory(const char *a, const char *b);
int vty_rot_space_ok(const char *old_path);
int vty_rot_make_backup_path(const char *old_path,
                             char out[VTY_ROTATE_BACKUP_MAX]);

#endif /* VTY_ROTATE_INTERNAL_H */
