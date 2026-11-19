/*
 * vty_rollback.h — 库文件版本回退检测（内部，不导出）
 *
 * 容器头内的版本计数器由 K_c 通过 body AAD 认证；本模块在同一台机器上
 * 维护每个库已见过的最大版本，作为外部锚点。整体还原旧库文件时版本
 * 低于锚点，直接拒绝——否则攻击者可用“旧密文 + 旧口令”覆盖新库，
 * 让已删除的数据复活。
 *
 * 锚点文件带机器绑定 MAC：篡改或挪到其它机器一律 fail-closed（拒绝打开），
 * 而不是被当作“首次运行”。见证身份为“设备根哈希 + 容器 UUID”，与状态
 * 文件路径无关。状态缺失时，任一见证仍存在或容器 generation >= 2（已建立
 * 锚点）均 fail-closed，只有状态、见证都不存在且容器 generation < 2 才视为
 * 首次运行。见证不可用时同样 fail-closed。旧布局与旧路径不再支持，按损坏
 * 拒绝。
 */
#ifndef VTY_ROLLBACK_H
#define VTY_ROLLBACK_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_ROLLBACK_MAX_ENTRIES 64u

/* 必须在使用前调用一次；返回 VTY_OK 或 VTY_E_TPM */
int vty_rollback_init(void);

/* 测试注入：指定状态文件路径；生产环境固定使用 KnownFolder 安全目录，
 * 禁止任何生产路径调用。 */
int vty_rollback_set_path_for_test(const char *path);

/* 开关（默认 1）。单元测试进程启动时关闭，避免普通用例写真实用户状态；
 * 专用用例显式开启并注入沙箱路径。 */
void vty_rollback_set_enabled(int enabled);
int vty_rollback_enabled(void);

/* 打开前检查：generation 低于已记录锚点返回 VTY_E_ROLLBACK。
 * 状态损坏 / 机器不匹配 / 设备根不可用 / 见证指纹缺失或不符一律
 * 按回退拒绝（fail-closed）。 */
int vty_rollback_check(const uint8_t vault_uuid[VTY_UUID_BYTES], uint64_t generation);

/* 解锁成功后推进锚点；版本增大时轮换见证并落盘。
 * 见证建键或状态写入失败返回 VTY_E_ROLLBACK，不静默降级。 */
int vty_rollback_commit(const uint8_t vault_uuid[VTY_UUID_BYTES], uint64_t generation);

/* 恢复码解锁后重设锚点（允许回退并轮换见证）：恢复码是用户显式选择的
 * 逃生通道，若继续保持旧锚点，被回滚的库将永远无法再用恢复码修复。 */
int vty_rollback_reset_anchor(const uint8_t vault_uuid[VTY_UUID_BYTES],
                              uint64_t generation);

#if defined(VERTHYS_G0A_PROTOTYPE) && VERTHYS_G0A_PROTOTYPE
/* G0-A 隔离原型：停止后台预置线程、清空已验证条目缓存与脏锚点标记。
 * 由核心 Deinit 在最后一个上下文注销后调用；可重复调用。 */
void vty_rollback_shutdown(void);

/* 跨进程 RollbackState 互斥量：供预置池后台建键与提交串行化。
 * 调用方必须按 RollbackState → pool lock 顺序加锁。 */
void *vty_rollback_lock_state(void);
void vty_rollback_unlock_state(void *mutex);
#endif

#if defined(VERTHYS_G0A_PROTOTYPE) && VERTHYS_G0A_PROTOTYPE && \
    defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
/* 崩溃注入：在指定提交阶段直接 TerminateProcess，模拟断电/进程被杀。
 * 仅隔离原型 + 测试钩子构建提供；进程退出码为 0xC0DE0000 | point。 */
enum {
    VTY_RB_CRASH_COMMIT_ENTER = 1,   /* 已加载状态、尚未取/建新键 */
    VTY_RB_CRASH_AFTER_NEW_KEY = 2,  /* 新键已存在、状态未写 */
    VTY_RB_CRASH_AFTER_STORE = 3,    /* 状态已写、旧键未退役 */
    VTY_RB_CRASH_AFTER_RETIRE = 4    /* 旧键已退役、未补池 */
};
void vty_rollback_set_crash_point_for_test(int point);
#endif

#ifdef __cplusplus
}
#endif

#endif /* VTY_ROLLBACK_H */
