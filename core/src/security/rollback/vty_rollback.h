/*
 * vty_rollback.h — 库文件版本回退检测（内部，不导出）
 *
 * 容器头内的版本计数器由 K_c 通过 body AAD 认证；本模块在同一台机器上
 * 维护每个库已见过的最大版本，作为外部锚点。整体还原旧库文件时版本
 * 低于锚点，直接拒绝——否则攻击者可用“旧密文 + 旧口令”覆盖新库，
 * 让已删除的数据复活。
 *
 * 锚点文件带机器绑定 MAC：篡改或挪到其它机器一律 fail-closed（拒绝打开），
 * 而不是被当作“首次运行”。v2 起追加 TPM 持久化密钥指纹见证：还原旧状态、
 * 删除状态文件、删除见证密钥均 fail-closed；只有状态与两槽见证密钥同时
 * 不存在才视为首次运行（残余删除向量）。见证不可用时同样 fail-closed。
 */
#ifndef VTY_ROLLBACK_H
#define VTY_ROLLBACK_H

#include "vty_v4_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_ROLLBACK_MAX_ENTRIES 64u

/* 必须在使用前调用一次；返回 VTY_OK 或 VTY_E_TPM */
int vty_rollback_init(void);

/* 测试注入：指定状态文件路径；生产环境使用默认用户目录 */
int vty_rollback_set_path(const char *path);

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

#ifdef __cplusplus
}
#endif

#endif /* VTY_ROLLBACK_H */
