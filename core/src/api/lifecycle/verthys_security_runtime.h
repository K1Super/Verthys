/*
 * verthys_security_runtime.h — 进程级安全运行时（内部，不导出）
 *
 * 承载与句柄无关的进程级状态：周期巡检定时器、活动句柄注册表、
 * 应急 DEGRADE 降级处理器。生命周期门面只通过本头文件访问。
 */
#ifndef VERTHYS_SECURITY_RUNTIME_H
#define VERTHYS_SECURITY_RUNTIME_H

#include "verthys_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 活动句柄注册表 ---------- */

void verthys_ctx_registry_add(struct VerthysContext *ctx);
int verthys_ctx_registry_remove(struct VerthysContext *ctx);
int verthys_ctx_registry_contains(struct VerthysContext *ctx);
int verthys_ctx_registry_has_capacity(void);
int verthys_ctx_registry_empty(void);

/* 固定句柄：取得注册表共享锁并确认句柄在册，成功返回 1 且锁由调用方
 * 持有，必须同线程配对调用 unpin。用于“先确认存活、再读取上下文”的
 * 查询路径，防止 Deinit 在复制期间释放上下文。
 *
 * 锁序：registry → ctx->api_mutex。持有注册表锁期间禁止再取注册表
 * 独占锁（同线程会阻塞在自身已持有的共享锁上）。 */
int verthys_ctx_registry_pin(struct VerthysContext *ctx);
void verthys_ctx_registry_unpin(void);

/* ---------- 周期安全巡检 ----------
 * 反调试每 60s 执行；反注入每 5 拍（300s）执行一次。回调在独立定时器
 * 线程运行，不持有任何句柄锁；启动失败只降级，不阻断 BOOT。 */
void verthys_security_periodic_start(void);
void verthys_security_periodic_stop(void);

/* ---------- 应急 DEGRADE 降级处理器 ----------
 * 对全部已解锁句柄执行“密钥与明文立即清零 + 状态置 LOCKED”，进程保持
 * 存活，不执行任何磁盘写入。恢复方式为用户正常重新解锁。 */
void verthys_emergency_lock_all(void);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_SECURITY_RUNTIME_H */
