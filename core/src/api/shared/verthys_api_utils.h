/*
 * verthys_api_utils.h — 共享工具模块头（从 verthys_api.c 拆分，V3-only）
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
#define VERTHYS_BACKOFF_MAX_SECS 3600u
#define VERTHYS_READ_FILE_MAX_BYTES ((size_t)4u * 1024u * 1024u * 1024u)

/* 工作线程汇合超时（毫秒）：Deinit/Lock 等待后台线程退出（预热/进度消费）
 * 的有界上限。超时后放弃等待并继续生命周期流程，残存线程由进程退出统一
 * 回收——避免阻塞点被外部卡死时 Deinit/Lock 永久挂起。 */
#define VERTHYS_JOIN_TIMEOUT_MS 3000u

/* ---------- 全局变量（自 verthys_api.c 迁移） ---------- */
extern int g_has_avx2;

/* ---------- 暴力破解退避 ----------
 * 进程级聚合记账（模块级原子全局）：任一句柄的解锁口令失败均计入
 * 同一计数，指数退避（2^k 秒，封顶 VERTHYS_BACKOFF_MAX_SECS）拦截
 * 同进程内全部句柄的后续解锁尝试。仅 AUTH 失败记账，RATE 早退与
 * 成功路径不递增；成功解锁由调用方触发 reset 清零。 */
uint64_t verthys_monotonic_ms(void);
uint64_t verthys_backoff_remaining_ms(void);
void verthys_backoff_record_failure(void);
void verthys_backoff_reset(void);

/* ---------- 工作线程有界汇合 ----------
 * 以 VERTHYS_JOIN_TIMEOUT_MS 为上限等待线程退出。
 * 返回 WaitForSingleObject 的结果：WAIT_OBJECT_0=已退出；WAIT_TIMEOUT=
 * 超时放弃等待（线程残存，由进程退出回收）；WAIT_FAILED=等待异常（同样不
 * 阻断生命周期）。不关闭句柄（句柄回收由调用方决定）。 */
#ifdef _WIN32
DWORD verthys_join_thread_bounded(HANDLE thread);
#endif

/* ---------- 小端序读取（用于索引区长度前缀） ---------- */
uint64_t verthys_get_u64le(const uint8_t *p);

/* ---------- 文件 I/O 辅助 ---------- */
int read_file(const char *path, uint8_t **out_buf, size_t *out_size);
int write_file(const char *path, const uint8_t *buf, size_t size);
char *dup_string(const char *s);

/* 释放 GetRecord 借用指针缓存（安全清零 + 释放） */
void ctx_free_getrecord_cache(struct VerthysContext *ctx);

/* 清除上下文中的所有敏感材料（CNG 内核密钥组 + 借用缓存），不动 file_path。
 * 前置条件：调用方已先行收口 V3 子系统（verthys_v3_ctx_subsystems_close——
 * 后台线程汇合后内核句柄方可安全销毁）。退避记账为进程级模块全局，
 * 与上下文生命周期无关。 */
void ctx_zero_sensitive(struct VerthysContext *ctx);

/* ---------- 格式检测（V3-only）----------
 * 读取文件头 8 字节判断格式：V3 超级块首副本帧头 magic "V3RP"。
 * 非 V3 一律返回 VERTHYS_ERR_FORMAT。 */
VerthysContainerVersion detect_format(const uint8_t *buf, size_t size);

int verthys_check_avx2_support(void);

#endif /* VERTHYS_API_UTILS_H */
