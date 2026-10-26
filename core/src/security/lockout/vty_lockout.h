/*
 * vty_lockout.h — 持久化失败计数与熔断（内部，不导出）
 *
 * 状态文件带机器绑定 MAC：拷到其它机器或任意篡改都会被视为锁定，
 * 而不是“重置为 0 次”。计数在成功解锁后才清零，重启不清零。
 * v2 起追加 TPM 持久化密钥指纹见证：还原旧状态、删除状态文件、删除
 * 见证密钥均 fail-closed；见证不可用时同样锁定。
 */
#ifndef VTY_LOCKOUT_H
#define VTY_LOCKOUT_H

#include "vty_v4_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_LOCKOUT_MAX_FAILURES 5u

/* 必须在使用前调用一次；返回 VTY_OK 或 VTY_E_TPM */
int vty_lockout_init(void);

/* 测试注入：指定状态文件路径；生产环境使用默认用户目录 */
int vty_lockout_set_path(const char *path);

/* 熔断开关（默认 1）。单元测试进程启动时关闭，避免错误口令用例
 * 写入真实用户状态文件；专用用例再显式开启并注入沙箱路径。 */
void vty_lockout_set_enabled(int enabled);
int vty_lockout_enabled(void);

/* 是否处于锁定；损坏 / 机器不匹配 / 见证缺失或不符一律返回 VTY_E_LOCKED */
int vty_lockout_check(void);

/* 记录一次失败；达到阈值或见证/状态写入失败返回 VTY_E_LOCKED */
int vty_lockout_record_failure(void);

/* 库解锁 / 恢复码解锁成功后清零；模块解锁成功不清零（否则可用已知模块
 * 口令反复洗掉库口令失败次数）。失败重试不影响计数（只读）。
 * 状态损坏时允许在成功解锁后重建；计数已为 0 且见证有效时跳过轮换。 */
int vty_lockout_reset(void);

uint32_t vty_lockout_failures(void);

#ifdef __cplusplus
}
#endif

#endif /* VTY_LOCKOUT_H */
