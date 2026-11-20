/*
 * vty_witness_pool.h — TPM 见证密钥预置池
 *
 * 前提：每次提交同步创建一把 TPM 持久化 ECDSA 密钥约 400–640ms，
 * 且该成本发生在跨进程回滚互斥量内。本模块在后台预创建“下一把”
 * 密钥，把建键成本移出提交关键路径。
 *
 * 约束：
 *   - 只服务 rollback.c 内部；不属于公共 ABI。
 *   - 池按见证 ID（设备根 + 容器 UUID）分区，两槽中只预置非当前槽。
 *   - 后台建键必须持有跨进程 RollbackState 互斥量：否则两个进程可能
 *     同时对同名 TPM 键做 OVERWRITE，后写者会让先写者的状态指纹失配，
 *     甚至删除对方仍在引用的键。
 *   - 调度的前提是状态中已存在该库条目（首次提交完成前不得预置）。
 *   - 池内只保存公开指纹，不接触私钥材料。
 *
 * 锁顺序：RollbackState → pool lock。调用方在持有状态锁时只能调用
 * schedule/take/return/invalidate；wait_idle 与 shutdown 必须在
 * 释放状态锁之后调用。
 */
#ifndef VTY_WITNESS_POOL_H
#define VTY_WITNESS_POOL_H

#include "vty_types.h"
#include "vty_tpm_witness.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 启动后台线程（幂等）。返回 VTY_OK 或 VTY_E_RESOURCE。 */
int vty_witness_pool_start(void);

/* 停止并回收后台线程。不得在持有状态锁时调用。 */
void vty_witness_pool_shutdown(void);

/* 声明当前槽并请求补齐非当前槽的预置键。持有状态锁调用。
 * 仅应在状态中已存在该库条目、且当前见证已验证后调用。 */
void vty_witness_pool_schedule(const uint8_t wid[VTY_UUID_BYTES],
                               int current_slot);

/* 取预置键：只返回非当前槽、且指纹经 TPM 重新校验通过的键。
 * 成功时槽位标记为空，调用方负责写入状态。
 * 返回 VTY_E_POLICY 表示后台正在建键；返回 VTY_E_TPM 表示无可用预置。
 * 持有状态锁调用。 */
int vty_witness_pool_take(const uint8_t wid[VTY_UUID_BYTES], int current_slot,
                          int *slot,
                          uint8_t fp[VTY_TPM_WITNESS_FP_BYTES]);

/* 状态写入失败时归还刚取出的预置键。持有状态锁调用。 */
void vty_witness_pool_return(const uint8_t wid[VTY_UUID_BYTES], int slot,
                             const uint8_t fp[VTY_TPM_WITNESS_FP_BYTES]);

/* 同步建键前调用：放弃该槽的预置登记（不删除密钥，调用方随后覆盖）。 */
void vty_witness_pool_invalidate(const uint8_t wid[VTY_UUID_BYTES], int slot);

/* 等待该库的后台建键结束（成功或失败）。不得持有状态锁调用。
 * 返回 VTY_OK 表示不再处于 CREATING，VTY_E_TPM 表示超时。 */
int vty_witness_pool_wait_idle(const uint8_t wid[VTY_UUID_BYTES],
                               unsigned timeout_ms);

/* 等待预置键就绪（测试用；成功返回 1，超时或失败返回 0）。 */
int vty_witness_pool_test_wait_ready(const uint8_t wid[VTY_UUID_BYTES],
                                     unsigned timeout_ms);

/* 池行为计数（测试用）：命中、同步回退、等待。 */
void vty_witness_pool_test_stats(unsigned *hits, unsigned *fallbacks,
                                 unsigned *waits);
void vty_witness_pool_test_reset_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* VTY_WITNESS_POOL_H */
