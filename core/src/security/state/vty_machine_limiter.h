/*
 * vty_machine_limiter.h — 机器级速率限制扩展点（内部，不导出）
 *
 * 语义契约（特权服务实现必须保持）：
 *   - check：返回 VTY_E_LOCKED 表示机器级尝试预算耗尽；VTY_OK 放行。
 *   - record_failure：记录一次失败尝试；不得清零累计计数。
 *   - reset：仅在成功解锁后调用；不得重置累计审计计数。
 *
 * 本模块只通过命名管道请求特权服务，不在本地保存预算；服务未安装、
 * 不可达、超时或应答验签失败一律映射为 VTY_E_LOCKED，不降级为放行。
 */
#ifndef VTY_MACHINE_LIMITER_H
#define VTY_MACHINE_LIMITER_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int vty_machine_limiter_check(void);
int vty_machine_limiter_record_failure(void);
int vty_machine_limiter_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* VTY_MACHINE_LIMITER_H */
