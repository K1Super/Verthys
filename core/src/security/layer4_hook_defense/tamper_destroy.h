/*
 * tamper_destroy.h — 篡改联动销毁策略（内部模块，不导出）
 *
 * ★ 销毁链简化。

 * 原实现缺陷：
 *   - 清零注册密钥页后调用 key_drift_force_migrate（已被删除），
 *     会把零页复制到新分配——制造新分配、无安全意义；
 *   - emergency_trigger() 内部 TerminateProcess 之后的
 *     job_isolation_break()/FatalExit 实际不可达；
 *   - Nonce/密钥页注册表零调用点，注册表恒空，"联动销毁"没有武器。
 *
 * 简化后的销毁链（每一步真实可达）：
 *   1. key_separation_purge_all() —— 销毁 CNG 内核密钥句柄
 *      （唯一密钥存放位置，内核释放密钥材料）；
 *   2. emergency_trigger() —— 内存绝育（memory_guard 注册区清零）
 *      + 匿名故障码上报看门狗 + TerminateProcess。
 */
#ifndef VERTHYS_TAMPER_DESTROY_H
#define VERTHYS_TAMPER_DESTROY_H

#include <stdint.h>
#include <stddef.h>

/*
 * 初始化篡改联动销毁模块（幂等）。
 * 返回 0 成功，非 0 失败。
 */
int tamper_destroy_init(void);

/*
 * 触发篡改联动销毁（不可逆，调用后进程在毫秒内终止）。
 * 幂等：进程终止性操作，重复触发被 emergency 闩锁拦截。
 */
void tamper_destroy_trigger(void);

#endif /* VERTHYS_TAMPER_DESTROY_H */
