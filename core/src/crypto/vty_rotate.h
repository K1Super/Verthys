/*
 * vty_rotate.h — 全库 DEK 轮换作业（内部，不导出）
 *
 * 恢复码会话不持有容器口令与恢复码明文，因此轮换采用“新文件全量重建 +
 * 原子替换”：保留 vault_uuid，生成新 K_c，epoch+1，用会话缓存的恢复 KEK
 * 重封恢复槽，旧恢复码继续有效。临时库构建期间不推进回退锚点。
 */
#ifndef VTY_ROTATE_H
#define VTY_ROTATE_H

#include "vty_types.h"
#include "vty_keymanager.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Begin flags：TPM/PCR 不可用时显式允许移除 PCR 绑定；
 * 未置位时返回 VTY_E_TPM（fail-closed）。 */
#define VTY_ROTATE_FLAG_DROP_PCR 0x01u

#define VTY_ROTATE_STAGE_BEGUN     1u
#define VTY_ROTATE_STAGE_COPIED    2u
#define VTY_ROTATE_STAGE_COMMITTED 3u
#define VTY_ROTATE_STAGE_FAILED    4u

typedef struct {
    uint32_t stage;          /* VTY_ROTATE_STAGE_* */
    uint32_t modules_ready;  /* 已登记口令的已启用模块数 */
    uint64_t records;        /* 已复制记录数 */
    uint64_t files;          /* 已复制文件数 */
    uint64_t chunks;         /* 已复制分片数 */
    uint64_t bytes;          /* 已复制记录明文（名称+数据）字节数 */
} VtyRotateStats;

/* 进度回调：返回非 0 取消本次 Run（作业进入失败态，仅可 Abort）。 */
typedef int (*VtyRotateProgressFn)(void *user, const VtyRotateStats *stats);

typedef struct VtyRotateJob VtyRotateJob;

/* 前置：old 已解锁且为恢复码会话；password 是当前容器口令；new_path
 * 必须不存在且与源库同目录（同卷原子替换）。成功返回作业并置
 * old->rotate_pending=1，源库进入只读态。 */
int vty_rotate_begin(VtyVault *old, const char *new_path, const char *password,
                     uint32_t flags, VtyRotateJob **out);

/* 登记一个已启用模块的口令并解锁源模块。所有已启用模块都必须在 Run
 * 前登记；recovery_code 非空时先校验当前恢复码（可选二次确认）。 */
int vty_rotate_unlock_module(VtyRotateJob *job, uint32_t index,
                             const char *password, const char *recovery_code);

/* 全量重建：启用新库模块 → 复制记录/文件/分片 → 完整性复核。
 * 成功进入 COPIED；任一失败进入 FAILED，只能 Abort。 */
int vty_rotate_run(VtyRotateJob *job, VtyRotateProgressFn cb, void *user);

/* 原子替换并推进回退锚点。成功时返回新会话（*out_new），作业被释放，
 * 源库实例被释放；调用方负责把 *out_new 接管到句柄。 */
int vty_rotate_commit(VtyRotateJob *job, int keep_old, VtyVault **out_new);

/* 丢弃临时库并释放作业；成功提交后不可调用。返回 VTY_OK 表示临时库
 * 已不存在；删除失败返回 VTY_E_IO（作业仍被释放）。 */
int vty_rotate_abort(VtyRotateJob *job);

/* 仅释放作业（不删除临时文件）；供失败路径内部使用。 */
void vty_rotate_free(VtyRotateJob *job);

const VtyRotateStats *vty_rotate_stats(const VtyRotateJob *job);

#ifdef __cplusplus
}
#endif

#endif /* VTY_ROTATE_H */
