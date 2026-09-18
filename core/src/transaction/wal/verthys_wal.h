/*
 * verthys_wal.h — V3 事务 WAL（环形 480KB×2 预写日志）
 *
 * 设计依据：
 *   - docs/TARGET_ARCHITECTURE_V5.md §6.2（WAL 区布局）/ §10.1（事务协议与
 *     崩溃恢复回放规则）
 *   - docs/V3_UPGRADE_PLAYBOOK.md WP-5（WAL 环形双半区；记录类型
 *     BEGIN/EXTENT/INDEX/PREPARE/COMMIT；恢复按 v5.0 §10.1 回放规则）
 *
 * 区域布局（容器绝对偏移 VERTHYS_V3_WAL_REGION_OFFSET = 0x10000 起，共
 * 960KB = VERTHYS_V3_WAL_REGION_END - OFFSET，容量自容器布局边界推导）：
 *   [半区 0：480KB][半区 1：480KB]
 *   半区布局：[HalfHeader 24B][WAL 帧 0][WAL 帧 1]... append-only
 *   HalfHeader = [u32 magic 'V3WH'][u32 version][u64 half_seq][u64 reserved=0]
 *
 * 环形语义（480KB×2）：
 *   - 单一活跃半区顺序追加；剩余空间不足以容纳下一帧 → 换区：
 *     旧活跃半区整体转为备份（数据保留，恢复回放仍可读取），
 *     新活跃半区写入递增 half_seq 头后从头追加；
 *   - half_seq 单调递增 → 崩溃后打开时据此判定活跃半区；
 *     撕裂的新半区头（换区瞬间崩溃）→ 回退旧半区为活跃，
 *     进行中的未提交事务自然回滚（§10.1 回放规则兜底）；
 *   - verthys_wal_reset（CONFIRM 后截断）：双半区清零重建，seq 续接。
 *
 * 帧布局（复用 verthys_lsm_frame_write/read_decrypt，WP-4 帧惯例）：
 *   [u32 magic 'V3WA'][u32 ct_len][AEAD 密文 ct_len 字节（含 16B tag）][12B nonce]
 *   AEAD 密钥 = C 角色密钥语境（V2 惯例延续：C 密钥用于超级块与事务日志；
 *   V3 中 C 角色 VerthysCngAead 上下文由本模块独占推进 nonce 计数器）。
 *   域分离 AAD = "verthys/wal-txn-v3"（与 LSM WAL "verthys/lsm-wal-v3"
 *   严格隔离）。
 *
 * 记录明文布局（手工小端编码，与 WP-4 LSM WAL 条目编码惯例一致）：
 *   公共头：[u8 type][u64le txid]
 *   BEGIN  (1)：+ u64le timestamp
 *   EXTENT (2)：+ hash[32] + u64le offset + u32le size + u32le plaintext_size
 *               + nonce[12]（数据块 AEAD nonce——崩溃重放重注册索引条目
 *               必需，缺此字段则恢复后 Extent 不可解密）
 *   INDEX  (3)：+ verthys_lsm_entry_encode 编码条目（78B 定长头 + name，
 *               全字段可重放入 LSM MemTable）
 *   PREPARE(4)：+ merkle_root[32] + u64le extent_used + u64le index_used
 *               + u64le audit_used（超级块候选状态快照）
 *   COMMIT (5)：+ u64le timestamp
 *
 * 崩溃恢复回放规则（v5.0 §10.1，verthys_wal_replay）：
 *   1. 双半区顺序扫描（低 seq 半区在前，帧序拼接）；
 *      撕裂尾部帧/解密失败帧静默截断（计数上报）；
 *   2. 记录按 txid 分组（单写者顺序事务，组天然连续）；
 *   3. txid ≤ committed_txid（= 超级块 wal_committed_txid）→ 已提交确认，
 *      跳过；
 *   4. 组内含 COMMIT 记录 → 提交已过法定人数（COMMIT 记录在法定人数
 *      提交成功之后落笔）→ 整组经回调重放（调用方 redrive：重应用索引 +
 *      超级块补提交）；
 *   5. 仅 PREPARE（无 COMMIT）且 sb_txid ≥ txid → 法定人数提交已完成、
 *      COMMIT 记录撕裂 → 整组经回调重放（幂等收尾）；
 *   6. 仅 BEGIN/EXTENT/INDEX（或 PREPARE 但 sb_txid < txid）→ 未提交，
 *      回滚丢弃（Extent 追加块成为孤儿，由 GC 回收；内存索引不动）。
 *
 * nonce 纪律（红线级）：打开时扫描全部有效帧的 nonce 计数器，恢复至
 * max(盘面计数) + 安全裕量（防回退，E-7/R-5）。
 *
 * 线程安全性：本模块非线程安全——单写者纪律（FFI 单线程事务流水线），
 * 与 WP-2/WP-3 模块一致；并发由上层事务层（WP-5）串行化。
 * 本模块不拥有 FILE 句柄与 AEAD 上下文（借用，调用方管理生命周期）。
 */
#ifndef VERTHYS_WAL_H
#define VERTHYS_WAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "verthys.h"
#include "verthys_crypto_cng.h"
#include "verthys_container_v3.h"  /* WAL 区边界（容量单一事实源） */
#include "verthys_lsm.h"          /* VerthysLsmEntry（INDEX 记录载荷） */

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 常量 ---------- */

/* 区域容量自容器布局边界推导（verthys_container_v3.h 单一事实源，防漂移
 * 红线）：[0x10000, 0x100000) = 960KB → 双 480KB 半区。曾因 512KB×2
 * 与布局边界矛盾导致 verthys_wal_reset 整区清零越界 64KB、覆写分区表
 * 区首帧（解锁 S4 magic=0 回归），故本模块不得独立复述区域尺寸。 */
#define VERTHYS_WAL_REGION_BYTES          VERTHYS_V3_WAL_REGION_BYTES
#define VERTHYS_WAL_HALF_BYTES            (VERTHYS_V3_WAL_REGION_BYTES / 2u)
#define VERTHYS_WAL_FRAME_MAGIC         UINT32_C(0x41573356)    /* 'V3WA' */
#define VERTHYS_WAL_HALF_MAGIC          UINT32_C(0x48573356)    /* 'V3WH' */
#define VERTHYS_WAL_VERSION             3u
#define VERTHYS_WAL_HALF_HEADER_BYTES   24u
#define VERTHYS_WAL_NONCE_RESTORE_MARGIN 64u  /* nonce 恢复安全裕量（R-5） */
#define VERTHYS_WAL_MAX_RECORD_BYTES    8192u /* 明文记录编码容量上限 */

/* 域分离标签（与 LSM WAL / 分区表 / 超级块严格隔离） */
#define VERTHYS_WAL_AAD                 "verthys/wal-txn-v3"

/* ---------- 记录类型（§10.1 六 Phase 映射） ---------- */

typedef enum {
    VERTHYS_WAL_REC_BEGIN   = 1,  /* Phase 1：事务开始 */
    VERTHYS_WAL_REC_EXTENT  = 2,  /* Phase 2：Extent 写入 */
    VERTHYS_WAL_REC_INDEX   = 3,  /* Phase 3：LSM 索引更新 */
    VERTHYS_WAL_REC_PREPARE = 4,  /* Phase 4：全部变更已持久化，超级块候选态 */
    VERTHYS_WAL_REC_COMMIT  = 5,  /* Phase 5：法定人数提交成功 */
} VerthysWalRecType;

/* EXTENT 记录载荷（Phase 2 重放信息） */
typedef struct VerthysWalExtentPayload {
    uint8_t  hash[32];          /* BLAKE2b-256 内容寻址哈希 */
    uint64_t offset;            /* Extent 分区数据区相对偏移 */
    uint32_t size;              /* 密文长度（含 16B tag） */
    uint32_t plaintext_size;    /* 明文长度 */
    uint8_t  nonce[12];         /* 数据块 AEAD nonce（重注册必需） */
} VerthysWalExtentPayload;

/* PREPARE 记录载荷（Phase 4 超级块候选状态快照） */
typedef struct VerthysWalPreparePayload {
    uint8_t  merkle_root[32];   /* 新 Merkle 根 */
    uint64_t extent_used;       /* Extent 分区已用字节 */
    uint64_t index_used;        /* 索引分区已用字节 */
    uint64_t audit_used;        /* 审计分区已用字节 */
} VerthysWalPreparePayload;

/*
 * WAL 记录（解码后的内存态）。
 * INDEX 记录：entry.name 在解码态指向 rec->u.index.name 内部缓冲；
 * 编码态（append）由调用方设置 entry.name 借用指针（name_len ≤
 * VERTHYS_LSM_NAME_MAX_BYTES）。
 */
typedef struct VerthysWalRecord {
    uint8_t  type;              /* VerthysWalRecType */
    uint64_t txid;              /* 所属事务 ID */
    union {
        struct { uint64_t timestamp; } begin;
        VerthysWalExtentPayload extent;
        struct {
            VerthysLsmEntry entry;
            uint8_t name[VERTHYS_LSM_NAME_MAX_BYTES];
        } index;
        VerthysWalPreparePayload prepare;
        struct { uint64_t timestamp; } commit;
    } u;
} VerthysWalRecord;

/* WAL 上下文（不透明；内部结构见 verthys_wal.c） */
typedef struct VerthysWal VerthysWal;

/*
 * ★ WP-5（verthys_v3_lifecycle 接线）：堆分配 + 零初始化 WAL 上下文。
 * 结构体对翻译单元外不透明，调用方（VerthysContextV3.wal）经本对函数
 * 管理生命周期。返回 NULL = 内存耗尽。
 */
VerthysWal *verthys_wal_create(void);

/*
 * ★ WP-5：close（内存态安全清零）+ free。幂等（NULL 直接返回）。
 * 不触碰盘面（与 verthys_wal_close 语义一致）。
 */
void verthys_wal_destroy(VerthysWal *w);

/* ---------- 生命周期 ---------- */

/*
 * 打开（或初始化）WAL。
 *
 * [in,out] w             WAL 上下文（须非 NULL）
 * [in]     f             容器文件（已打开，"r+b"，借用不拥有）
 * [in]     region_offset WAL 区域起始绝对偏移（= VERTHYS_V3_WAL_REGION_OFFSET）
 * [in]     aead          C 角色 AEAD 上下文（已导入密钥；借用不拥有；
 *                        本模块独占推进其 nonce 计数器）
 * [out]    out_frames    可为 NULL；非 NULL 回传双半区有效帧总数
 * [out]    out_torn      可为 NULL；非 NULL 回传撕裂/损坏帧计数
 *
 * 行为：扫描双半区（头有效性 + 帧结构 + nonce 计数器），确定活跃半区
 * （有效头中 half_seq 最大者；均为空 → 初始化半区 0，seq=1）；游标 =
 * 活跃半区最后有效帧之后；nonce 计数器恢复至 max(盘面) + 裕量（防回退）。
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_LOCKED（aead 未导入）/
 * VERTHYS_ERR_IO / VERTHYS_ERR_INTERNAL。
 */
VerthysResult verthys_wal_open(VerthysWal *w, FILE *f, uint64_t region_offset,
                           VerthysCngAead *aead,
                           uint64_t *out_frames, uint64_t *out_torn);

/* 关闭：清零内存态（不触碰盘面）。幂等（NULL 直接返回）。 */
VerthysResult verthys_wal_close(VerthysWal *w);

/* ---------- 追加 ---------- */

/*
 * 追加记录：明文编码 → AEAD 帧 → 活跃半区追加 → fflush + _commit。
 * 活跃半区剩余空间不足 → 换区（旧区转备份，新区 seq+1 头写入）后追加。
 * 单帧超出半区容量（记录过大）→ VERTHYS_ERR_INVALID。
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_LOCKED /
 * VERTHYS_ERR_IO / VERTHYS_ERR_INTERNAL。
 */
__declspec(noinline) VerthysResult verthys_wal_append(VerthysWal *w, const VerthysWalRecord *rec);

/* ---------- 崩溃恢复回放（v5.0 §10.1） ---------- */

/*
 * 回放回调：按原始记录序投递需重放（redrive）的记录。
 * 返回 VERTHYS_OK 继续；非 VERTHYS_OK 中止回放并透传该错误。
 * INDEX 记录的 entry.name 指向记录内部缓冲，仅在回调返回前有效。
 */
typedef VerthysResult (*VerthysWalReplayFn)(void *user, const VerthysWalRecord *rec);

/*
 * 崩溃恢复回放：
 *   双半区顺序扫描 → 按 txid 分组 → 按 §10.1 规则分类（见文件头）→
 *   需重放的事务组经 fn 逐记录投递（升 txid、组内原始序）。
 *
 * [in]  w               WAL 上下文（须已 open）
 * [in]  committed_txid  超级块 wal_committed_txid（已提交确认水位）
 * [in]  sb_txid         超级块当前 txid（PREPARE-only 组判定）
 * [in]  fn              重放回调（重放组非空时须非 NULL）
 * [in]  user            回调透传
 * [out] out_frames      可为 NULL；有效帧总数
 * [out] out_replayed    可为 NULL；经回调投递的记录数
 * [out] out_discarded   可为 NULL；丢弃记录数（回滚 + 已提交跳过）
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_IO /
 * VERTHYS_ERR_FORMAT（记录载荷结构非法）/ 回调错误透传 /
 * VERTHYS_ERR_INTERNAL。
 */
VerthysResult verthys_wal_replay(VerthysWal *w, uint64_t committed_txid,
                             uint64_t sb_txid,
                             VerthysWalReplayFn fn, void *user,
                             uint64_t *out_frames,
                             uint64_t *out_replayed,
                             uint64_t *out_discarded);

/*
 * 扩展回放（事务层恢复用）：与 verthys_wal_replay 相同的 §10.1 分类规则，
 * 但被丢弃（回滚/已提交跳过）的组经 fn_discard 逐记录投递——上层事务层
 * 据此清理内存态（如 LSM MemTable 中未提交事务的条目）。
 * fn_discard 可为 NULL（等同 verthys_wal_replay）；fn_replay 在存在重放组时
 * 须非 NULL。丢弃组投递序 = 原始记录序。
 */
__declspec(noinline) VerthysResult verthys_wal_replay_ex(VerthysWal *w, uint64_t committed_txid,
                                uint64_t sb_txid,
                                VerthysWalReplayFn fn_replay, void *user_replay,
                                VerthysWalReplayFn fn_discard, void *user_discard,
                                uint64_t *out_frames,
                                uint64_t *out_replayed,
                                uint64_t *out_discarded);

/*
 * 截断复位（Phase 6 CONFIRM 后调用）：
 * 双半区清零 → 半区 0 写入 seq+1 头 → fsync。之后盘面无任何可回放记录。
 */
VerthysResult verthys_wal_reset(VerthysWal *w);

/* ---------- 统计（测试/诊断） ---------- */

/* 活跃半区当前帧数 */
uint64_t verthys_wal_frame_count(const VerthysWal *w);

/* 活跃半区 half_seq */
uint64_t verthys_wal_half_seq(const VerthysWal *w);

/* 活跃半区索引（0/1；未 open 返回 2） */
unsigned verthys_wal_active_half(const VerthysWal *w);

/* 活跃半区游标（字节，相对半区起始；含半区头） */
uint64_t verthys_wal_cursor(const VerthysWal *w);

/* 活跃半区首帧绝对偏移（= 区域偏移 + 活跃半区 × 512KB + 半区头）。
 * 超级块 wal_head_offset 候选值（Phase 5 COMMIT 写入）。未 open 返回 0。 */
uint64_t verthys_wal_head_offset(const VerthysWal *w);

/* 活跃半区追加游标绝对偏移（= 区域偏移 + 活跃半区 × 512KB + cursor）。
 * 超级块 wal_tail_offset 候选值（Phase 5 COMMIT 写入）。未 open 返回 0。 */
uint64_t verthys_wal_tail_offset(const VerthysWal *w);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_WAL_H */
