/*
 * verthys_transaction_v3.h — V3 六阶段事务（WAL + 法定人数提交）
 *
 * 六阶段协议（单写者纪律）：
 *   BEGIN         txid = sb->txid + 1；WAL BEGIN 记录；
 *                         LSM flush 抑制开启（未提交条目不入 SSTable）
 *   WRITE_EXTENT  verthys_extent_put（内容寻址 + CNG 加密追加）
 *                         + WAL EXTENT 记录（含 nonce，重放重注册必需）
 *   UPDATE_INDEX  verthys_lsm_put / delete + WAL INDEX 记录
 *   PREPARE       计算超级块候选快照（merkle_root / 分区 used）
 *                         + WAL PREPARE 记录
 *   COMMIT        超级块法定人数提交（≥2/3 副本）→ Extent 索引
 *                         持久化 → 分区表持久化 → WAL COMMIT 记录
 *   CONFIRM       法定人数读回验证 txid + Extent 抽样解密验证
 *                         + WAL 截断复位 + 解除 flush 抑制
 *
 * 崩溃窗口语义（与 verthys_wal.h 回放规则一一对应）：
 *   - COMMIT 前崩溃（含 PREPARE 后）：组无 COMMIT 记录且 sb_txid < txid
 *     → 恢复回滚（LSM MemTable 剔除 + Extent 追加块成孤儿交 GC）；
 *   - 超块法定人数提交后、Extent 索引/分区表落盘前崩溃：sb_txid ≥ txid
 *     且组仅 PREPARE → 恢复重放（幂等收尾：重注册 Extent + 重放 LSM +
 *     重存索引/分区表 + 超块补 wal_committed_txid）；
 *   - WAL COMMIT 记录撕裂：同上（COMMIT 在法定人数成功后落笔）。
 *
 * 运行时回滚（verthys_txn_v3_rollback）：仅限 PREPARE 前后、COMMIT 前调用；
 * 依赖 flush 抑制纪律（BEGIN 阶段开启），LSM 条目仅存在于 MemTable 与
 * LSM WAL 尾部，经 verthys_lsm_rollback_txid 精确撤销。
 *
 * merkle_root 计算口径（V3 过渡实现）：BLAKE2b-256(全部 Extent 哈希按
 * 索引序拼接 ‖ u64le(next_offset))——确定性由重放重建同序索引保证。
 *
 * 线程安全性：非线程安全——单写者纪律（FFI 单线程事务流水线）。
 * 本模块不拥有任何子系统（FILE/WAL/LSM/Extent/分区均为借用）。
 */
#ifndef VERTHYS_TXN_V3_H
#define VERTHYS_TXN_V3_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "verthys.h"
#include "verthys_wal.h"
#include "verthys_container_v3.h"
#include "verthys_lsm.h"
#include "verthys_extent.h"
#include "verthys_partition.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 事务状态机 ---------- */

typedef enum {
    VERTHYS_TXN_V3_IDLE      = 0,   /* init 后 / confirm 后 */
    VERTHYS_TXN_V3_ACTIVE    = 1,   /* BEGIN 完成（写入阶段进行中） */
    VERTHYS_TXN_V3_PREPARED  = 2,   /* PREPARE 完成（COMMIT 待执行） */
    VERTHYS_TXN_V3_COMMITTED = 3,   /* COMMIT 完成（CONFIRM 待执行） */
    VERTHYS_TXN_V3_CONFIRMED = 4,   /* CONFIRM 完成（终态） */
    VERTHYS_TXN_V3_ABORTED   = 5,   /* 回滚终态 */
} VerthysTxnV3State;

/*
 * 事务上下文（栈或嵌入上层 ctx；全部子系统引用为借用）。
 * integrity_key 为超级块 HMAC 密钥的内存拷贝（Lock/Deinit 由上层
 * 统一清理本结构：verthys_txn_v3_deinit 安全清零）。
 */
typedef struct VerthysTxnV3 {
    /* 借用引用 */
    FILE                   *f;             /* 容器文件（"r+b"） */
    VerthysWal               *wal;           /* 事务 WAL（已 open） */
    VerthysSuperBlockV3      *sb;            /* 超级块内存态（commit 时变更） */
    VerthysLsm               *lsm;           /* LSM 索引（已 open） */
    VerthysExtentIndex       *ext_idx;       /* Extent 索引内存态 */
    VerthysPartition         *extent_part;   /* Extent 分区（ptable 实条目） */
    VerthysPartitionTable    *ptable;        /* 分区表（含内核句柄） */
    VerthysCngAead           *table_aead;    /* 分区表 AEAD（wrapping 语境） */
    uint8_t                 integrity_key[VERTHYS_KEY_BYTES];

    /* 事务状态 */
    uint64_t              txid;            /* 本事务 ID（BEGIN 分配） */
    VerthysTxnV3State       state;
    uint64_t              lsm_wal_base;    /* BEGIN 时 LSM WAL 游标快照 */
    size_t                extent_ops;      /* Extent 写入记录数 */
    size_t                index_ops;       /* 索引更新记录数 */
    int                   has_prepare;     /* PREPARE 快照有效标志 */
    VerthysWalPreparePayload prepare;        /* 候选快照 */
    int                   persist_done;    /* COMMIT 步骤 3/4 成功标志
                                              （CONFIRM 幂等补存依据） */

    /*
     * Extent 引用变动账本（回滚精确还原）：
     * 写入阶段记 +1（新块创建与去重命中同价），删除阶段对现值
     * 记 -1；同哈希净额聚合。回滚按净额反向调整（净额为零 = 无操作，
     * 精确覆盖"本事务先写后删同一内容"的复合场景——顺序施加逆操作会
     * 因 ref_count 下限截断出偏差）。COMMIT 成功即弃置（已提交不可
     * 回滚）。模块自管理堆，deinit/rollback/begin 释放。
     */
    struct VerthysTxnExtRef *ext_refs;       /* 账本数组（NULL = 空） */
    size_t                ext_ref_count;
    size_t                ext_ref_cap;
} VerthysTxnV3;

/* ---------- 生命周期 ---------- */

/*
 * 绑定子系统并置 IDLE。全部参数须非 NULL（ext_idx 可为已 init 的空索引）。
 * integrity_key 拷贝入上下文（32B，VERTHYS_KEY_BYTES）。
 */
VerthysResult verthys_txn_v3_init(VerthysTxnV3 *t, FILE *f, VerthysWal *wal,
                              VerthysSuperBlockV3 *sb, VerthysLsm *lsm,
                              VerthysExtentIndex *ext_idx,
                              VerthysPartition *extent_part,
                              VerthysPartitionTable *ptable,
                              VerthysCngAead *table_aead,
                              const uint8_t integrity_key[VERTHYS_KEY_BYTES]);

/* 安全清零（密钥擦除）；幂等（NULL 直接返回）。不触碰借用子系统。 */
void verthys_txn_v3_deinit(VerthysTxnV3 *t);

/* ---------- 六阶段事务 ---------- */

/*
 * BEGIN：txid = sb->txid + 1；WAL BEGIN；LSM flush 抑制开启；
 * 快照 LSM WAL 游标（回滚截断基准）。
 * 前置：state == IDLE。
 */
__declspec(noinline) VerthysResult verthys_txn_v3_begin(VerthysTxnV3 *t);

/*
 * WRITE_EXTENT：verthys_extent_put（查重/加密/追加/fsync）
 * + WAL EXTENT 记录（哈希/偏移/尺寸/nonce 全量）。
 * 前置：state == ACTIVE。hash_out/stored 可为 NULL（语义同 extent_put）。
 */
VerthysResult verthys_txn_v3_write_extent(VerthysTxnV3 *t,
                                      const uint8_t *pt, size_t pt_len,
                                      uint8_t hash_out[VERTHYS_EXTENT_HASH_BYTES],
                                      int *stored);

/*
 * UPDATE_INDEX：verthys_lsm_put + WAL INDEX 记录。
 * e->created_txid 由本函数统一置为事务 txid（调用方无须设置）；
 * e->tombstone 强制清零（删除走 verthys_txn_v3_delete）。
 */
VerthysResult verthys_txn_v3_update_index(VerthysTxnV3 *t, const VerthysLsmEntry *e);

/*
 * DELETE：查找现值 → Extent 引用释放（ref_count--）→
 * verthys_lsm_delete（墓碑）+ WAL INDEX 记录（墓碑条目）。
 * 键不存在亦写墓碑（LSM 幂等语义）。
 */
VerthysResult verthys_txn_v3_delete(VerthysTxnV3 *t, uint64_t lid);

/*
 * PREPARE：计算候选快照（merkle_root / extent_used / index_used /
 * audit_used，取自当前分区表条目）+ WAL PREPARE。
 * 前置：state == ACTIVE。
 */
VerthysResult verthys_txn_v3_prepare(VerthysTxnV3 *t);

/*
 * COMMIT（原子性由 WAL + 法定人数语义保证）：
 *   1. 超块候选字段写入（txid / updated_at / wal 状态 / merkle_root）；
 *   2. 法定人数提交（vsb_txn_v3 备份保护，失败内存回滚）；
 *   3. Extent 索引持久化（帧覆写 + fsync）；
 *   4. 分区表持久化（帧覆写 + fsync）；
 *   5. WAL COMMIT 记录；
 *   6. 解除 flush 抑制 + MemTable 达阈值则 flush（失败不影响提交
 *      语义——数据已提交，flush 为持久化优化，下次 put/close 重试）。
 * 前置：state == PREPARED。成功 → COMMITTED。
 * 步骤 2 后失败：超块已持久含 txid，恢复路径按 PREPARE-only 组重放收尾。
 */
__declspec(noinline) VerthysResult verthys_txn_v3_commit(VerthysTxnV3 *t);

/*
 * CONFIRM：
 *   1. 法定人数读回验证 sb.txid == 事务 txid；
 *   2. Extent 随机抽样解密 + 内容哈希校验（1 条，无条目则跳过）；
 *   3. WAL 截断复位（reset）。
 * 前置：state == COMMITTED。成功 → CONFIRMED。
 */
__declspec(noinline) VerthysResult verthys_txn_v3_confirm(VerthysTxnV3 *t);

/*
 * 运行时回滚：LSM MemTable/WAL 尾部精确撤销（flush 抑制纪律）+
 * Extent 引用还原（本事务新增引用释放）→ ABORTED。
 * 仅限 ACTIVE / PREPARED（COMMIT 后不可回滚——法定人数已持久）。
 * 盘面 Extent 追加块成为孤儿（索引不可达），由 GC 回收。
 */
__declspec(noinline) VerthysResult verthys_txn_v3_rollback(VerthysTxnV3 *t);

/* ---------- 崩溃恢复（open 后、首个事务前调用一次） ---------- */

/*
 * 崩溃恢复：
 *   1. verthys_wal_replay_ex：重放组（COMMIT 在场 / PREPARE-only 且
 *      sb_txid ≥ txid）逐记录重应用——EXTENT 重注册（缺则补、
 *      命中则 ref_count++，方向安全：只多不少）、INDEX 重放 LSM；
 *      丢弃组（未提交）收集 txid → LSM MemTable 剔除（运行态清理）；
 *   2. 存在重放组：重算 next_offset → Extent 索引重存 → 分区表重存 →
 *      超块 wal_committed_txid = sb->txid 法定人数补提交；
 *   3. MemTable 非空 → flush（恢复后持久快照，LSM WAL 随之复位）；
 *   4. WAL 截断复位。
 * out_replayed / out_discarded 可为 NULL。
 * 返回：VERTHYS_OK / 各子系统错误透传 / VERTHYS_ERR_INTERNAL。
 */
__declspec(noinline) VerthysResult verthys_txn_v3_recover(VerthysTxnV3 *t,
                                 uint64_t *out_replayed,
                                 uint64_t *out_discarded);

/* ---------- 查询 ---------- */

/* 当前事务 txid（IDLE 返回 0） */
uint64_t verthys_txn_v3_txid(const VerthysTxnV3 *t);

/* 状态机查询 */
VerthysTxnV3State verthys_txn_v3_state(const VerthysTxnV3 *t);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_TXN_V3_H */
