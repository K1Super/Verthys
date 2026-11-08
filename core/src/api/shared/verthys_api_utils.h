/*
 * verthys_api_utils.h — 共享工具模块头（从 verthys_api.c 拆分）
 *
 * 收录从 verthys_api.c 抽离的纯工具/辅助函数原型、宏与全局变量声明，
 * 供 verthys_api.c 及其他内部翻译单元复用。
 *
 */
#ifndef VERTHYS_API_UTILS_H
#define VERTHYS_API_UTILS_H

#include "verthys_internal.h"
#include <stdint.h>
#include <stddef.h>

/* ---------- 宏定义（自 verthys_api.c 迁移） ---------- */
#define VERTHYS_READ_FILE_MAX_BYTES ((size_t)4u * 1024u * 1024u * 1024u)

/* 工作线程汇合超时（毫秒）：Deinit/Lock 等待后台线程退出（预热/进度消费）
 * 的有界上限。超时后放弃等待并继续生命周期流程，残存线程由进程退出统一
 * 回收——避免阻塞点被外部卡死时 Deinit/Lock 永久挂起。 */
#define VERTHYS_JOIN_TIMEOUT_MS 3000u

/* ---------- 全局变量（自 verthys_api.c 迁移） ---------- */
extern int g_has_avx2;

/* ---------- 单调时钟 ---------- */
uint64_t verthys_monotonic_ms(void);

/* ---------- 工作线程有界汇合 ----------
 * 以 VERTHYS_JOIN_TIMEOUT_MS 为上限等待线程退出。
 * 返回 WaitForSingleObject 的结果：WAIT_OBJECT_0=已退出；WAIT_TIMEOUT=
 * 超时放弃等待（线程残存，由进程退出回收）；WAIT_FAILED=等待异常（同样不
 * 阻断生命周期）。不关闭句柄（句柄回收由调用方决定）。 */
#ifdef _WIN32
DWORD verthys_join_thread_bounded(HANDLE thread);
#endif

/* ---------- 文件 I/O 辅助 ---------- */
int read_file(const char *path, uint8_t **out_buf, size_t *out_size);
int write_file(const char *path, const uint8_t *buf, size_t size);
char *dup_string(const char *s);

/* 释放 GetRecord 借用指针缓存（安全清零 + 释放） */
void ctx_free_getrecord_cache(struct VerthysContext *ctx);

/* ---------- 会话生命周期（进程级原子计数） ----------
 * ctx->vault 的赋值/释放必须统一经以下辅助函数，禁止散落手动释放与赋值：
 *   attach                       NULL→v 计数 +1；替换非 NULL 旧值时释放旧值、
 *                                计数不变（先释放后赋值）。
 *   detach                       v→NULL 释放并计数 −1。
 *   replace_externally_freed     仅用于 Verthys_V4RotateCommit：vty_rotate_commit
 *                                已释放旧库并返回新库，只赋值、计数不变。
 * 计数口径 = 进程内持有存活 会话的上下文数，供防御状态查询读取；
 * 不遍历上下文、不读裸指针。 */
void vault_session_attach(struct VerthysContext *ctx, struct VtyVault *v);
void vault_session_detach(struct VerthysContext *ctx);
void vault_session_replace_externally_freed(struct VerthysContext *ctx,
                                         struct VtyVault *v);
uint32_t vault_session_resident_count(void);

/* 清除上下文中的所有敏感材料（会话 + 借用缓存），不动 file_path。
 * 退避记账为进程级模块全局，与上下文生命周期无关。 */
void ctx_zero_sensitive(struct VerthysContext *ctx);

/* ---------- 格式检测 ----------
 * 读取文件头 8 字节判断格式：仅识别 固定头 "VRTY"。
 * 未知格式返回 VERTHYS_FMT_NONE，由调用方拒绝。 */
VerthysContainerVersion detect_format(const uint8_t *buf, size_t size);

int verthys_check_avx2_support(void);

#endif /* VERTHYS_API_UTILS_H */
