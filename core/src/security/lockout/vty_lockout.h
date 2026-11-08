/*
 * vty_lockout.h — 持久化失败计数与熔断（内部，不导出）
 *
 * 状态文件固定落在 KnownFolder\Verthys\Security，只接受当前布局。
 * 其它尺寸/旧格式一律按损坏 fail-closed：不读取、不迁移、不为旧应用
 * 版本提供反向兼容。状态带设备根 MAC：拷到其它机器或任意篡改都会被视为
 * 锁定，而不是“重置为 0 次”。计数在成功解锁后才清零，重启不清零。
 * 状态缺失但当前见证仍存在、状态损坏、机器不匹配、见证不可用一律
 * fail-closed。
 */
#ifndef VTY_LOCKOUT_H
#define VTY_LOCKOUT_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_LOCKOUT_MAX_FAILURES 5u

/* 必须在使用前调用一次；返回 VTY_OK 或 VTY_E_TPM */
int vty_lockout_init(void);

/* 测试注入：指定状态文件路径；生产环境固定使用 KnownFolder 安全目录，
 * 禁止任何生产路径调用。 */
int vty_lockout_set_path_for_test(const char *path);

/* 熔断开关（默认 1）。单元测试进程启动时关闭，避免错误口令用例
 * 写入真实用户状态文件；专用用例再显式开启并注入沙箱路径。 */
void vty_lockout_set_enabled(int enabled);
int vty_lockout_enabled(void);

/* 是否处于锁定；损坏 / 机器不匹配 / 见证缺失或不符一律返回 VTY_E_LOCKED。
 * 达到阈值后按失败次数指数退避（2^failures 秒，上限 1 小时）：窗口内
 * 返回 E_LOCKED，窗口满允许重试；计数只有成功解锁才清零。
 * 纯查询语义：不消耗尝试额度，不更新时间戳。 */
int vty_lockout_check(void);

/* 认证前尝试门禁：在 check 语义之上增加 1 秒最小尝试间隔（纵深防御）。
 * 只在真正发起口令校验前调用；纯查询请用 vty_lockout_check。 */
int vty_lockout_begin_attempt(void);

/* 库锁剩余秒数（纯查询）。返回 VTY_E_LOCKED 表示当前应拒绝且 *out>0；
 * VTY_OK 表示可尝试。 */
int vty_lockout_remaining_secs(uint32_t *out);

/* 记录一次失败；达到阈值或见证/状态写入失败返回 VTY_E_LOCKED。
 * 阈值后计数继续累加（32 封顶）并刷新退避时间戳。 */
int vty_lockout_record_failure(void);

/* 库解锁 / 恢复码解锁成功后清零；模块解锁成功不清库（否则可用已知模块
 * 口令反复洗掉库口令失败次数）。失败重试不影响计数（只读）。
 * 状态损坏时允许在成功解锁后重建；计数已为 0 且见证有效时跳过轮换。 */
int vty_lockout_reset(void);

uint32_t vty_lockout_failures(void);

/* 模块锁：按 SHA-256(vault_uuid || module_index) 前 16 字节区分作用域。
 * 模块失败不污染库锁；库成功不清模块锁；模块成功只重置自身作用域。 */
int vty_lockout_module_begin_attempt(
    const uint8_t vault_uuid[VTY_UUID_BYTES], uint32_t module_index);
int vty_lockout_module_remaining_secs(
    const uint8_t vault_uuid[VTY_UUID_BYTES], uint32_t module_index,
    uint32_t *out);
int vty_lockout_module_record_failure(
    const uint8_t vault_uuid[VTY_UUID_BYTES], uint32_t module_index);
int vty_lockout_module_reset(
    const uint8_t vault_uuid[VTY_UUID_BYTES], uint32_t module_index);
uint32_t vty_lockout_module_failures(
    const uint8_t vault_uuid[VTY_UUID_BYTES], uint32_t module_index);

/* 阈值后的退避窗口（秒）：2^failures，上限 3600。
 * 与进程内退避公式一致，供测试与诊断使用。 */
uint32_t vty_lockout_backoff_secs(uint32_t failures);

/* 测试注入：覆写当前 UTC 秒；0 = 使用系统时间。生产路径不得调用。 */
int vty_lockout_set_test_clock(uint64_t now_secs);

#ifdef __cplusplus
}
#endif

#endif /* VTY_LOCKOUT_H */
