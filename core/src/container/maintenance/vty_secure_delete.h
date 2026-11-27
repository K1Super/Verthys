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

/* 带截止时间的版本：预算内未完成时 *out_deferred=1，文件保留待下次
 * 重试；维护路径用它保证解锁延迟有界。deadline_ms=0 表示不设上限。 */
int vty_secure_delete_file_budget(const char *path, uint64_t deadline_ms,
                                  int *out_deferred);

/* 解锁/启动维护：清理容器同目录的压缩临时/备份与轮换失败转存的
 * .vtysdel 待删文件。整轮共享时间预算，未完成项下次解锁继续。 */
int vty_secure_delete_maintain(const char *container_path,
                               uint64_t *out_deleted,
                               uint64_t *out_failed);

#ifdef __cplusplus
}
#endif

#endif /* VTY_SECURE_DELETE_H */
