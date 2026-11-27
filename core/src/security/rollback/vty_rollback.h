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

/* 测试注入：指定状态文件路径；仅测试构建生效。生产构建保留同名桩并
 * 返回 VTY_E_POLICY，生产运行期不能改写状态目录。 */
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
 * 逃生通道，若继续保持旧锚点，被回滚的库将永远无法再用恢复码修复。
 *
 * 见证缺失（DEAD）或指纹不符（TAMPERED）时同样允许重设：此时旧见证
 * 已无法证明任何东西，拒绝重设等于让持有恢复码的用户永久失去访问权。
 * 重设成功后清除脏标记并清理非当前槽的残留键。 */
int vty_rollback_reset_anchor(const uint8_t vault_uuid[VTY_UUID_BYTES],
                              uint64_t generation);

/* ------------------------------------------------------------------ *
 * 锚点生命周期维护（内部）
 *
 * 状态判定只用于展示与“可证明失效”的回收：ACTIVE/TAMPERED/UNKNOWN
 * 一律保留。DEAD 仅当引用的见证槽确定不存在（exists==0）时成立；
 * 平台错误（-1）保持 UNKNOWN。释放必须显式置位 CONFIRM。
 * ------------------------------------------------------------------ */
typedef enum {
    VTY_ANCHOR_ABSENT   = 0,
    VTY_ANCHOR_ACTIVE   = 1,
    VTY_ANCHOR_DEAD     = 2,
    VTY_ANCHOR_TAMPERED = 3,
    VTY_ANCHOR_UNKNOWN  = 4
} VtyAnchorState;

typedef struct {
    uint8_t  uuid[VTY_UUID_BYTES];
    uint64_t generation;
    uint32_t state;              /* VtyAnchorState */
} VtyAnchorInfo;

typedef struct {
    uint8_t  uuid[VTY_UUID_BYTES];
    uint32_t released;
    uint32_t cleanup_failed;
} VtyAnchorReleaseResult;

#define VTY_ROLLBACK_ANCHOR_CONFIRM 0x00000001u

/* 列出锚点快照。out_state_missing=1 表示状态文件不存在（首次运行或被
 * 删除）；状态文件损坏返回 VTY_E_CORRUPT。capacity 不足返回
 * VTY_E_RESOURCE，并仍写出总条数。 */
int vty_rollback_anchor_list(VtyAnchorInfo *out, uint32_t capacity,
                             uint32_t *out_count, int *out_state_missing);

/* 释放指定 UUID 的锚点并删除两槽见证。flags 必须含 CONFIRM。
 * 条目不存在时仍幂等清理两槽见证；状态写失败返回 VTY_E_IO 且不删见证。
 * out_cleanup_failed=1 表示状态已释放但见证删除失败；调用方在保留 UUID
 * 的前提下可重试释放。 */
int vty_rollback_anchor_release(const uint8_t vault_uuid[VTY_UUID_BYTES],
                                uint32_t flags, uint32_t *out_released,
                                uint32_t *out_cleanup_failed);

/* 批量释放指定 UUID 集合。flags 必须含 CONFIRM；count 1..64，重复或全零
 * UUID 拒绝。一次状态锁、一次认证加载、一次压缩落盘；状态写失败返回
 * VTY_E_IO 且不删除任何见证。条目不存在时仍幂等清理两槽见证，逐条结果
 * 写入 out_results。 */
int vty_rollback_anchor_release_batch(const uint8_t *uuids, uint32_t count,
                                      uint32_t flags,
                                      VtyAnchorReleaseResult *out_results,
                                      uint32_t capacity, uint32_t *out_count);

/* 提交快路径：维护 A/B 两个预置见证槽，后台线程提前建键；提交时切换
 * 已就绪的键，把 NCryptFinalizeKey 的约 400ms 移出关键路径。预置池空时
 * 同步建键，不关闭回退保护。 */
void vty_rollback_shutdown(void);

/* 跨进程 RollbackState 互斥量：供预置池后台建键与提交串行化。
 * 调用方必须按 RollbackState → pool lock 顺序加锁。 */
void *vty_rollback_lock_state(void);
void vty_rollback_unlock_state(void *mutex);

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
/* 崩溃注入：在指定提交阶段直接 TerminateProcess，模拟断电/进程被杀。
 * 仅测试钩子构建提供；进程退出码为 0xC0DE0000 | point。 */
enum {
    VTY_RB_CRASH_COMMIT_ENTER = 1,   /* 已加载状态、尚未取/建新键 */
    VTY_RB_CRASH_AFTER_NEW_KEY = 2,  /* 新键已存在、状态未写 */
    VTY_RB_CRASH_AFTER_STORE = 3,    /* 状态已写、旧键未退役 */
    VTY_RB_CRASH_AFTER_RETIRE = 4    /* 旧键已退役、未补池 */
};
void vty_rollback_set_crash_point_for_test(int point);

/* 逻辑容量注入：仅缩小“可登记条目数”上限，物理布局仍为 64 条。
 * 用于在少量真实 TPM 键下确定性地覆盖容量/回收分支。 */
void vty_rollback_set_max_entries_for_test(uint32_t max_entries);

/* 状态落盘故障注入：接下来 count 次维护写入返回 VTY_E_IO。
 * 用于验证“状态未落盘时不得删除任何见证键”。 */
void vty_rb_set_store_fail_for_test(int count);

/* 重置路径解析状态：允许测试重新验证“缺少隔离目录必须拒绝初始化”。 */
void vty_rollback_reset_path_for_test(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* VTY_ROLLBACK_H */
