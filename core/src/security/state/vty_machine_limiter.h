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
#include "vty_svc_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VtyKernelStatus {
    uint32_t state;
    uint32_t reason;
    uint32_t capabilities;
    uint16_t protocol_major;
    uint16_t protocol_minor;
} VtyKernelStatus;

int vty_machine_limiter_check(void);
int vty_machine_limiter_record_failure(void);
int vty_machine_limiter_reset(void);

/*
 * 查询服务侧内核加固状态。
 * 返回 VTY_OK 表示状态已确定（含未安装/不可用）；VTY_E_INVALID 仅表示 out 为空。
 */
int vty_machine_limiter_kernel_status(VtyKernelStatus *out);

/*
 * 内核防护生命周期（进程级）：
 *   - apply_preset：SECURE 时 ARM 并登记本进程，其他档位释放；
 *   - release：解除本进程保护（锁定路径调用）。
 * 失败不阻断既有用户态解锁（SECURE = preferred），状态由查询接口如实反映。
 * 仅当前进程是 Verthys worker 时服务才接受；其他进程调用只会失败。
 */
void vty_machine_limiter_kernel_guard_apply_preset(void);
void vty_machine_limiter_kernel_guard_release(void);

/* 单步命令；成功返回 VTY_OK。仅供本模块与定向测试使用。 */
int vty_machine_limiter_kernel_arm(void);
int vty_machine_limiter_kernel_register(void);
int vty_machine_limiter_kernel_disarm(void);

#ifdef __cplusplus
}
#endif

#endif /* VTY_MACHINE_LIMITER_H */
