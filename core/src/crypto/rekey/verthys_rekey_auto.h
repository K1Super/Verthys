/*
 * verthys_rekey_auto.h — 自动密钥轮换状态机（内部模块，不导出）
 *
 * 轮换语义（适配 V3 落地架构）：
 *   - MEK 口令派生不变（轮换非改密，integrity_key / salt / 温缓存
 *     HMAC 语境全部不变）；轮换对象 = L4 子密钥组 A/B/C：
 *       1. 新 key_a'/b'/c' 随机生成（BCryptGenRandom 语境，
 *          verthys_random_bytes）；
 *       2. 新 wrapped 形态经 MEK 内核态加密（verthys_cng_km_wrap_key，
 *          与解锁 S3 import_batch 互逆）；
 *       3. CNG 内核态"旧解密 → 新加密"重包装：分区密钥明文仅在本
 *          函数栈帧瞬态（红线），分区密钥本身不变 → Extent/LSM/
 *          审计分区数据零重写（"数据"在 V3 落地
 *          架构中即 key_a 保护域——分区表帧 + 分区密钥包装形态）；
 *       4. 超级块 VsbTxnV3 法定人数原子提交（wrapped_a/b/c + key_id
 *          + 分区表槽位 + TLV 轮换状态；复用 change_password 的
 *          vsb_txn 保护模式）；
 *       5. 旧句柄销毁 → 新句柄原位激活（verthys_cng_km_rotate_abc，
 *          km->keys[] 原位替换——wal/txn 借用的 VerthysCngAead 指针
 *          续期有效，即原子指针切换句柄落地形态）。
 *
 * 崩溃一致性（跨结构原子性，ping-pong 槽位协议）：
 *   分区表帧（key_a' 重包装）与超级块（key_a' wrapped 形态）分属两个
 *   磁盘结构，无法单次原子提交。协议：
 *     1. 新分区表帧先写入备用槽位（默认 1MB ↔ 2MB 交替，均在
 *        [1MB,4MB) 分区表区内互不覆盖）+ fsync；
 *     2. 超级块法定人数提交（partition_table_offset 指向新槽位）。
 *   崩溃窗口分析（任一时刻断电）：
 *     - 提交前崩溃：盘面 sb 仍指旧槽位 + 旧 key_a 语境 → 旧帧完整
 *       （ping-pong 保证不被覆写）→ 解锁走旧密钥，新帧为无害孤儿；
 *     - 提交后崩溃：盘面 sb 指新槽位 + 新 wrapped 密钥 → 新帧已
 *       fsync → 解锁走新密钥闭环；
 *     - 提交中撕裂（1-2 副本新）：读侧法定人数取 ≥2 一致者，两个
 *       版本各自自洽（对应各自的完整分区表帧）。
 *
 * DEGRADE 强制触发（异常触发）：
 *   应急 DEGRADE 处理器（verthys_api.c verthys_emergency_lock_all）在
 *   清钥前调用 verthys_rekey_auto_note_degrade 将强制轮换标志持久化
 *   于超级块 TLV（tag 0x02 flags bit0）——DEGRADE 后进程内解锁被
 *   S0 熔断门控拒绝（恢复语义 = 进程重启），标志必须落盘才能在下次
 *   解锁时兑现强制轮换（密钥可能已随内存泄露，旧 wrapped 形态
 *   继续有效即继续暴露）。轮换提交时清除标志。
 *
 * TLV 轮换状态（超级块 extensions，tag 0x02，与预设 tag 0x01 共存）：
 *   [u64le last_rekey_ft][u64le last_rekey_txid][u8 flags] = 17B
 *     last_rekey_ft   上次轮换 FILETIME（缺省 = sb.created_at）
 *     last_rekey_txid 上次轮换时 sb.txid（写事务单调计数代理
 *                     ops_since_rekey——零额外磁盘写，跨会话精确）
 *     flags           bit0 = DEGRADE 强制轮换待兑现
 */
#ifndef VERTHYS_REKEY_AUTO_H
#define VERTHYS_REKEY_AUTO_H

#include <stdint.h>
#include <stddef.h>
#include "verthys.h"
#include "verthys_container_v3.h"     /* VerthysSuperBlockV3 */
#include "verthys_v3_lifecycle.h"     /* VerthysContextV3 */
#include "verthys_transaction_v3.h"   /* VerthysTxnV3State（终态守卫） */

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 策略常量 ---------- */

#define VERTHYS_REKEY_INTERVAL_DAYS        90u    /* 时间触发阈值 */
#define VERTHYS_REKEY_OPS_THRESHOLD       10000u /* 写事务触发阈值（txid 增量） */
#define VERTHYS_REKEY_MIN_INTERVAL_HOURS  24u    /* 防震荡最小间隔 */

/* FILETIME 100ns 单位换算（绕开月份/年份浮点，纯常量） */
#define VERTHYS_REKEY_FT_PER_DAY  \
    UINT64_C(864000000000)      /* 24h × 3600s × 10^7 */
#define VERTHYS_REKEY_FT_PER_HOUR \
    UINT64_C(36000000000)       /* 3600s × 10^7 */

/* ---------- TLV 轮换状态 ---------- */

#define VERTHYS_V3_TLV_TAG_REKEY   0x02u
#define VERTHYS_REKEY_TLV_BYTES   17u    /* 8 + 8 + 1 */
#define VERTHYS_REKEY_FLAG_FORCE  0x01u  /* DEGRADE 强制轮换待兑现 */

typedef struct VerthysRekeyState {
    uint64_t last_rekey_ft;     /* 上次轮换 FILETIME（缺省 = created_at） */
    uint64_t last_rekey_txid;   /* 上次轮换时 sb.txid（缺省 0） */
    uint8_t  flags;             /* VERTHYS_REKEY_FLAG_FORCE 位域 */
} VerthysRekeyState;

/* ---------- 触发原因 ---------- */

typedef enum VerthysRekeyTrigger {
    VERTHYS_REKEY_TRIGGER_NONE    = 0,
    VERTHYS_REKEY_TRIGGER_TIME    = 1u << 0,  /* 距上次轮换 ≥ 90 天 */
    VERTHYS_REKEY_TRIGGER_OPS     = 1u << 1,  /* 写事务增量 ≥ 10,000 */
    VERTHYS_REKEY_TRIGGER_DEGRADE = 1u << 2   /* DEGRADE 强制（旁路防震荡） */
} VerthysRekeyTrigger;

/* ---------- 查询 / 编排 ---------- */

/*
 * 评估轮换触发条件（纯查询，无副作用）：
 *   - TLV 状态缺省（无 tag 0x02）：last_rekey_ft = sb.created_at，
 *     last_rekey_txid = 0，flags = 0（新容器不触发）；
 *   - TIME：now_ft - last_rekey_ft ≥ 90 天（无符号比较，时钟回拨
 *     拨回创建前视为不触发——触发只会推迟不会误报）；
 *   - OPS：sb.txid - last_rekey_txid ≥ 10,000（单调计数代理写操作数，
 *     每 AddRecord/Update/Delete/Import 事务恰 +1）；
 *   - DEGRADE：TLV flags bit0（note_degrade 持久化的强制标志）。
 * 返回触发位掩码；ctx3 非法 / 未解锁返回 NONE。
 */
uint32_t verthys_rekey_auto_check(const VerthysContextV3 *ctx3);

/*
 * 执行密钥轮换（核心）。
 *   force：1 = 旁路 24h 防震荡（DEGRADE / 手动场景）；0 = 遵守防震荡。
 *   out_rotated（可 NULL）：1 = 已完成轮换；0 = 防震荡拒绝（非错误）。
 * 前置：subsystems_open + km KERNEL_RESIDENT + 事务终态
 *   （ACTIVE/PREPARED → INTERNAL 编排缺陷；COMMITTED → 幂等补
 *   confirm 后继续，同 change_password 惯例）。
 * 返回：VERTHYS_OK（含防震荡拒绝）/ VERTHYS_ERR_LOCKED / VERTHYS_ERR_IO
 *   （法定人数不满足）/ VERTHYS_ERR_CNG_UNAVAILABLE / 各子系统错误透传。
 * 失败原子性：km 句柄零变更；盘面仅可能残留备用槽位孤儿帧（无害，
 * 下次轮换覆写）。
 */
__declspec(noinline) VerthysResult verthys_rekey_auto_rotate(VerthysContextV3 *ctx3, int force,
                                     int *out_rotated);

/*
 * 编排入口（verthys_v3_open_existing 解锁成功后接线）：
 *   check → 任一触发 → rotate（DEGRADE 位强制旁路防震荡）。
 *   未触发：out_rotated=0 直接返回。
 *   轮换为 best-effort 深化：失败不影响已成功解锁（调用方吞错，
 *   下次解锁重试）——本函数自身错误仍如实返回供编排方决策。
 */
VerthysResult verthys_rekey_auto_maybe_rotate(VerthysContextV3 *ctx3,
                                          int *out_rotated);

/*
 * DEGRADE 标志持久化（应急降级处理器清钥前调用，best-effort）：
 *   TLV flags 置 VERTHYS_REKEY_FLAG_FORCE + vsb_txn 法定人数提交。
 *   仅提交非敏感 HMAC 元数据（不违背降级路径"敏感数据不落盘"红线；
 *   时延代价 ~ms 级 3 副本写，为"强制轮换跨进程重启兑现"的必要代价）。
 *   失败静默（轮换属纵深防御层，降级锁库语义不受影响）。
 */
VerthysResult verthys_rekey_auto_note_degrade(VerthysContextV3 *ctx3);

/* ---------- TLV 状态读写（rotate 内部复用 + 测试白盒注入） ---------- */

/*
 * 读 TLV 轮换状态（缺省值语义同 verthys_rekey_auto_check）。
 * sb 非法结构（TLV 头截断/长度越界）按缺省处理——超级块整体已经
 * 法定人数 + HMAC 认证，本层不再重复拒绝。
 */
void verthys_rekey_auto_state_get(const VerthysSuperBlockV3 *sb,
                                VerthysRekeyState *out);

/*
 * 写 TLV 轮换状态：保留既有非 0x02 TLV（预设等），替换/追加 0x02。
 * 容量溢出（extensions 256B 上限）返回 VERTHYS_ERR_INVALID。
 * 仅改内存态 sb——持久化由调用方 vsb_txn 提交（rotate/note_degrade）。
 */
VerthysResult verthys_rekey_auto_state_set(VerthysSuperBlockV3 *sb,
                                       const VerthysRekeyState *st);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_REKEY_AUTO_H */
