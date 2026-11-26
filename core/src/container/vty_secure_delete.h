/*
 * vty_secure_delete.h — 代际文件安全删除（内部，不导出）
 *
 * 压缩/轮换产生的临时库、旧库与备份都持有同一把 MDEK 下的完整密文。
 * 仅 DeleteFileW 会把密文留在空闲空间，持有容器口令的人仍可恢复；
 * 因此这些派生文件必须先整文件零写并刷盘，再删除。
 *
 * 只用于应用自己派生的容器文件；不做任意路径删除。
 */
#ifndef VTY_SECURE_DELETE_H
#define VTY_SECURE_DELETE_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 零写 + FlushFileBuffers + 删除。文件不存在视为成功。
 * 拒绝目录、重解析点与多硬链接文件（防止误毁链接目标）。 */
int vty_secure_delete_file(const char *path);

/* 解锁/启动维护：清理容器同目录的压缩临时/备份与轮换备份
 * （<base>.vtycompact.tmp/.bak、<base>.old-XXXXXXXX-XXXXXXXX）。
 * 失败项保留，下次解锁重试；不阻断解锁。 */
int vty_secure_delete_maintain(const char *container_path,
                               uint64_t *out_deleted,
                               uint64_t *out_failed);

#ifdef __cplusplus
}
#endif

#endif /* VTY_SECURE_DELETE_H */
