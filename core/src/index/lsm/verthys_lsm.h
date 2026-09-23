/*
 * verthys_lsm.h — V3 LSM 索引（MemTable 跳表 + 分级 SSTable + 后台 Compaction）
 *
 * 结构：
 *   MemTable（跳表，内存）
 *     ↓ flush（阈值：10,000 条 / 64MB）
 *   SSTable Level 0（可能重叠，seq 新旧排序）
 *     ↓ compaction（后台线程 BELOW_NORMAL，空闲触发 CPU<30%，单次 ≤64MB）
 *   SSTable Level 1+（层内不重叠，容量逐级 ×10，基数 64MB）
 *
 * 写入路径：MemTable 插入 → WAL 先行 → 阈值 flush
 * 读取路径：MemTable → L0（新→旧）→ L1 → ... → 命中即返回
 * 删除路径：Tombstone 标记 → compaction 至最底层时物理删除
 * 查找加速：Bloom Filter（每 SSTable，xxHash64 双重哈希，FPR 0.1%）
 *
 * SSTable 磁盘布局（schema/sstable.fbs）：
 *   [Data Block 0..N-1][Index Block][Bloom Filter][Footer][Trailer]
 *   Data/Index/Footer = 分区 AEAD 帧；Bloom 位图明文存储、完整性由
 *   Footer 内 BLAKE2b-256 锚定；Trailer = 明文定位锚。
 *
 * 并发纪律：
 *   - MemTable 单写者（FFI 单线程）：put/delete/flush/compact 持 SRWLOCK 独占；
 *   - 读者快照：get 持 SRWLOCK 共享，读取期间视图稳定；
 *   - compaction 后台线程与提交互斥：同一 SRWLOCK 独占模式。
 *
 * LSM 区域布局（容器文件内，region_offset 基准）：
 *   [Manifest 帧区 1MB][WAL 区 68MB][SSTable 数据区 append-only]
 *
 * nonce 纪律：全部帧（WAL/SSTable/Manifest）经 Index 分区 AEAD 计数器
 * 生成 nonce（唯一性硬保证）；Manifest 持久化"保存后值"快照（区别于
 * extent 的保存前值），重载 restore 后绝不复用帧自身 nonce。
 *
 * 线程安全性：公开 API 全部线程安全（内部 SRWLOCK）；单写者纪律由
 * 锁串行化保证。本模块不拥有 FILE 句柄与分区（借用，调用方管理生命周期）。
 */
#ifndef VERTHYS_LSM_H
#define VERTHYS_LSM_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "verthys.h"
#include "verthys_partition.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 常量 ---------- */

#define VERTHYS_LSM_VERSION                  3u

/* MemTable 阈值 */
#define VERTHYS_LSM_MEMTABLE_MAX_ENTRIES     10000u  /* 条目上限（触发 flush） */
#define VERTHYS_LSM_MEMTABLE_MAX_BYTES       (64u * 1024u * 1024u) /* 字节上限 */

/* 层级与 Compaction */
#define VERTHYS_LSM_MAX_LEVELS               7u    /* V3_LSM_MAX_LEVELS */
#define VERTHYS_LSM_L0_COMPACTION_TRIGGER    4u    /* L0 表数触发合并 */
#define VERTHYS_LSM_LEVEL_BASE_BYTES         (64u * 1024u * 1024u) /* L1 容量基数 */
#define VERTHYS_LSM_COMPACTION_MAX_RUN_BYTES (64u * 1024u * 1024u) /* 单次 ≤64MB */
#define VERTHYS_LSM_COMPACTION_IDLE_CPU_PCT  30u   /* 空闲触发 CPU 阈值 */
#define VERTHYS_LSM_MAX_TABLES               128u  /* Manifest 在册表上限 */

/* 区域布局 */
#define VERTHYS_LSM_MANIFEST_REGION_BYTES    (1u * 1024u * 1024u)   /* Manifest 帧区 */
#define VERTHYS_LSM_WAL_REGION_BYTES         (68u * 1024u * 1024u)  /* WAL 区（≥ MemTable 上限 + 帧开销） */

/* SSTable 结构参数 */
#define VERTHYS_LSM_SSTABLE_BLOCK_BYTES      4096u /* 数据块明文目标大小 */
#define VERTHYS_LSM_SSTABLE_TRAILER_BYTES    24u   /* [u64 footer 偏移][u64 txid][u32 magic][u32 保留] */
#define VERTHYS_LSM_BLOOM_BITS_PER_KEY       15u   /* FPR ≈ 0.074% ≤ 0.1% */
#define VERTHYS_LSM_BLOOM_HASH_COUNT         10u   /* 双重哈希迭代次数 k */

/* 条目约束 */
#define VERTHYS_LSM_NAME_MAX_BYTES           4096u /* 记录名上限 */

/* ---------- 类型 ---------- */

/*
 * LSM 索引条目（内存态）。
 * 键 = lid（全局唯一逻辑记录 ID）；内容寻址哈希定位 Extent 数据块。
 * name 为借用指针：put 时借用调用方缓冲（内部拷贝）；get 时拷入调用方
 * name_buf（避免跨 SSTable 生命周期借用）。
 */
typedef struct VerthysLsmEntry {
    uint64_t lid;             /* 键：逻辑记录 ID */
    uint8_t  type;            /* 记录业务类型 */
    uint8_t  tombstone;       /* 1 = 删除墓碑（compaction 至最底层物理删除） */
    uint8_t  slot_state;      /* 槽位生命周期状态 */
    uint16_t name_len;        /* UTF8 名称字节长度 */
    const uint8_t *name;      /* 变长名称（借用指针） */
    uint64_t data_size;       /* 原始明文字节大小 */
    uint32_t plaintext_size;  /* Extent 明文长度 */
    uint32_t extent_size;     /* Extent 密文长度（含 16B tag） */
    uint8_t  hash[32];        /* BLAKE2b-256 内容寻址哈希（Extent 键） */
    uint64_t created_txid;    /* 创建/最近更新事务 ID */
    uint64_t created_time;    /* 创建 Unix 时间戳（前端排序） */
} VerthysLsmEntry;

/* LSM 树（不透明；内部结构位于 verthys_lsm_internal.h） */
typedef struct VerthysLsm VerthysLsm;

/* ---------- 生命周期 ---------- */

/*
 * verthys_v3_lifecycle 接线：堆分配 + 零初始化 LSM 上下文。
 * 结构体对翻译单元外不透明，调用方（VerthysContextV3.lsm）经本对函数
 * 管理生命周期。返回 NULL = 内存耗尽。
 */
VerthysLsm *verthys_lsm_create(void);

/*
 * 关闭：close（后台线程汇合 + flush + Manifest 保存 + 内存全释放）
 * + 安全清零 + free。幂等（NULL 直接返回）。
 * 返回 close 的结果码：非 VERTHYS_OK 即"非干净关闭"（WAL 未复位，
 * 下次 open 重放重建），调用方据此记录诊断；数据安全由 WAL 兜底。
 */
VerthysResult verthys_lsm_destroy(VerthysLsm *lsm);

/*
 * v3_lifecycle 失败路径：中止式关闭——不 flush、不存 Manifest、
 * 不复位 WAL（盘面 LSM WAL 帧原样保留，下次 open 重放后由事务层 recover
 * 裁决）。解锁失败重试路径专用：未提交 MemTable 条目（open 重放产物）
 * 落入 SSTable 将不可剔除（rebuild_excluding 仅 MemTable），为红线级数据泄漏。
 */
VerthysResult verthys_lsm_abort(VerthysLsm *lsm);

/* abort + 安全清零 + free（堆实例；幂等）。 */
void verthys_lsm_destroy_abort(VerthysLsm *lsm);

/*
 * 打开（或创建）LSM 索引。
 *
 * [in,out] lsm            LSM 上下文（须非 NULL；重复 open 前须先 close）
 * [in]     f              容器文件（已打开，"r+b"，借用不拥有）
 * [in]     part           Index 分区（已导入密钥；借用不拥有）
 * [in]     region_offset  LSM 区域起始偏移（容器绝对偏移）
 * [in]     region_size    LSM 区域字节容量（≥ Manifest+WAL 区 + 数据区）
 * [in]     enable_bg      1 = 启动后台 compaction 线程（BELOW_NORMAL，
 *                         空闲触发）；0 = 仅同步模式（测试/维护）
 *
 * 行为：Manifest 加载（区域为空 → 初始化并保存首帧，nonce 快照为
 * 保存后值）；WAL 重放（崩溃恢复：撕裂尾部帧静默截断）。重放条目
 * 留在 MemTable（修订：不自动 flush——未提交条目须保持可剔除，
 * 由事务层 recover() 裁决后统一 flush；阈值触发移交 put 路径）；
 * bg=1 时启动后台线程。
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_LOCKED（分区未导入）/
 * VERTHYS_ERR_AUTH（Manifest 篡改）/ VERTHYS_ERR_FORMAT（结构非法）/
 * VERTHYS_ERR_IO / VERTHYS_ERR_INTERNAL。
 */
VerthysResult verthys_lsm_open(VerthysLsm *lsm, FILE *f, VerthysPartition *part,
                           uint64_t region_offset, uint64_t region_size,
                           int enable_bg);

/*
 * 关闭：停止后台线程 → MemTable flush → Manifest 保存 → WAL 复位 →
 * 释放全部内存态（含 SSTable 惰性缓存）。幂等（NULL 直接返回）。
 *
 * dirty 语义（契约）：flush 或 Manifest 保存失败时返回对应错误码，
 * 内存态仍全部释放，但本次关闭必须视为"非干净关闭"——WAL 未复位，
 * 全部条目仍在 WAL 帧中；下次 open 重放重建（幂等）。调用方不得
 * 把错误返回当作干净关闭忽略（数据由 WAL 兜底，但语义必须显式）。
 */
VerthysResult verthys_lsm_close(VerthysLsm *lsm);

/* ---------- 数据路径 ---------- */

/*
 * 写入条目：WAL 先行 → MemTable 插入（同键覆盖）→ 达阈值自动 flush
 * （冻结当前表 → 落盘 L0 SSTable → Manifest 提交 → WAL 复位）。
 *
 * [in] lsm   LSM 上下文
 * [in] txid  当前事务 ID（记账 created_txid）
 * [in] e     条目（须非 NULL；name 借用，name_len ≤ NAME_MAX；
 *            tombstone 强制置 0——删除走 verthys_lsm_delete）
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_LOCKED /
 * VERTHYS_ERR_RESOURCE_LIMIT（WAL/Manifest 容量耗尽）/ VERTHYS_ERR_IO /
 * VERTHYS_ERR_INTERNAL。
 */
__declspec(noinline) VerthysResult verthys_lsm_put(VerthysLsm *lsm, uint64_t txid, const VerthysLsmEntry *e);

/*
 * 查找：MemTable → L0（新→旧）→ L1..（键域/Bloom 过滤 + 块二分）。
 * 命中墓碑（任意层）→ VERTHYS_ERR_NOTFOUND（新版本遮蔽旧值，立即返回）。
 *
 * [out] out          命中条目拷贝（可为 NULL=仅探测存在性）
 * [out] name_buf     名称输出缓冲（可为 NULL，仅当 out 为 NULL 或
 *                    条目 name_len==0）
 * [in]  name_cap     name_buf 容量（< name_len 返回 VERTHYS_ERR_INVALID）
 * [out] name_len_out 可为 NULL；非 NULL 回传实际名称长度
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_NOTFOUND / VERTHYS_ERR_INVALID /
 * VERTHYS_ERR_AUTH（帧篡改）/ VERTHYS_ERR_CORRUPT（Bloom 位图哈希不符）/
 * VERTHYS_ERR_FORMAT / VERTHYS_ERR_IO / VERTHYS_ERR_INTERNAL。
 */
__declspec(noinline) VerthysResult verthys_lsm_get(VerthysLsm *lsm, uint64_t lid,
                          VerthysLsmEntry *out,
                          uint8_t *name_buf, size_t name_cap,
                          size_t *name_len_out);

/*
 * 删除：写入墓碑条目（WAL 先行 + MemTable 插入，同 put 路径）。
 * 键不存在亦写入墓碑（LSM 标准语义，幂等）。
 */
VerthysResult verthys_lsm_delete(VerthysLsm *lsm, uint64_t txid, uint64_t lid);

/* ---------- 维护路径 ---------- */

/*
 * 强制 flush：冻结并落盘当前 MemTable（空表为 no-op）。
 * 调用方持独占锁语义（内部自持）。
 */
__declspec(noinline) VerthysResult verthys_lsm_flush(VerthysLsm *lsm);

/*
 * 同步执行单次 compaction 运行（测试/维护入口；生产路径为后台线程
 * 空闲触发）。策略：自 L0 起首个超限层级 → 主选集 ≤64MB（L0 取全部
 * 重叠表，L≥1 按键序取表）→ 并入 L+1 重叠表 → k 路归并（层级小者新、
 * 同层 seq 大者新）→ 墓碑至最底层物理删除 → 产出 L+1 非重叠 SSTable →
 * Manifest 原子提交（覆写帧）。
 * 无超限层级 → VERTHYS_OK（no-op）。
 */
__declspec(noinline) VerthysResult verthys_lsm_compact(VerthysLsm *lsm);

/* 是否存在超限层级（L0 表数 ≥ 触发值，或 L≥1 字节超容量 ×10 逐级） */
int verthys_lsm_needs_compaction(const VerthysLsm *lsm);

/* ---------- 事务层配合接口 ---------- */

/*
 * 抑制/恢复 MemTable 阈值自动 flush。
 * 事务进行中（transaction_v3）必须抑制：未提交条目不得进入 SSTable，
 * 否则运行时回滚与崩溃回滚均无法撤销（flush 后条目持久于 L0 表）。
 * 抑制期间 MemTable 字节上限仍受 WAL 区容量约束（RESOURCE_LIMIT）。
 * 抑制解除后由调用方按需 verthys_lsm_flush。
 */
void verthys_lsm_set_flush_suppress(VerthysLsm *lsm, int suppress);

/* 当前 WAL 追加游标（相对 WAL 区；事务 BEGIN 时快照，回滚截断基准） */
uint64_t verthys_lsm_wal_cursor(const VerthysLsm *lsm);

/*
 * 按 txid 回滚（transaction_v3 运行时回滚 / 崩溃恢复清理共用）：
 *   1. WAL 截断：失效化 wal_cursor_base 起始帧头（回放链断开）+ fsync；
 *   2. MemTable 重放重建：自偏移 0 重放（止于断链点）并剔除
 *      created_txid == txid 残留帧（防御纵深）。
 *
 * 回滚重建（重放式重建取代过滤式剔除）：事务 DELETE 墓碑
 * 在 MemTable 已按新者胜覆写原始条目，过滤式剔除墓碑将连带丢失被
 * 覆写的原始条目（已提交数据丢失，红线级）；WAL 保有全部历史帧
 * （WAL 先行 + flush 复位不变式），重放跳过本事务帧即完整复原。
 *
 * 前置（红线）：事务期间抑制自动 flush，且单写者纪律保证
 * [wal_cursor_base, 当前游标) 区间帧全部归属本事务；
 * 若当前游标 < wal_cursor_base（事务中途发生过 flush）返回
 * VERTHYS_ERR_INVALID（条目已入 SSTable，运行时回滚不可行）。
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_IO / VERTHYS_ERR_INTERNAL。
 */
VerthysResult verthys_lsm_rollback_txid(VerthysLsm *lsm, uint64_t txid,
                                    uint64_t wal_cursor_base);

/*
 * 过滤重放重建（transaction_v3 崩溃恢复丢弃组清理）：
 * MemTable 自 LSM WAL 偏移 0 重放重建，exclude_txids 命中帧（丢弃组
 * 写入/墓碑）不入表；不截断 WAL（恢复路径中已提交/未提交帧交错，
 * 截断即丢已提交数据；恢复末尾统一 flush 使 WAL 复位；全帧皆属丢弃
 * 组时由 rollback_txid(base=0) 截断）。
 *
 * 修复说明（与上方同型根因）：丢弃组墓碑在 MemTable 已覆写
 * 原始条目，过滤式剔除（旧 purge_txid）将同时丢失墓碑与被覆写条目
 * （已提交数据丢失，红线级）；重放跳过丢弃组帧即完整复原原始条目。
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_INTERNAL。
 */
VerthysResult verthys_lsm_rebuild_excluding(VerthysLsm *lsm,
                                        const uint64_t *exclude_txids,
                                        size_t exclude_count);

/* ---------- 温启动缓存接口（全量预热） ---------- */

/*
 * 温缓存表记录段编码（export_warm 产出 / open_warm 消费；warmcache_v3
 * 的 sstable_meta 段载荷）：
 *
 *   [u32le table_count]
 *   [table_count × 表记录：
 *      u64le seq                 （Manifest 匹配键，全局唯一）
 *      u64le index_block_offset  （Footer 惰性字段，三件套之一）
 *      u64le bloom_offset
 *      u32le bloom_bytes
 *      u8    bloom_k
 *      u8    reserved[3]         （零填充）
 *      32B   bloom_hash          （BLAKE2b-256(bloom)，Footer 锚定值）
 *      u32le block_count
 *      block_count × [u64le first_key][u64le offset]
 *                     [u32le frame_len][u32le entry_count]
 *      bloom_bytes × bloom 位图]
 *
 * 权威性设计（红线级）：段内不含 Manifest 载荷——温启动的 Manifest
 * 始终从盘面帧加载（单帧读 + 解密 ≈ 亚毫秒，且为唯一权威），缓存仅
 * 承载重建昂贵的惰性缓存内容（Footer 字段 + Bloom 位图 + 块索引）。
 * 由此缓存过期（导出后发生过 flush/compaction）不构成任何覆写/误读
 * 风险：seq 不匹配的记录静默跳过，盘面新表退化为惰性加载。
 */

/*
 * 导出温缓存原料（Lock 同步时机 / 事务提交后异步防抖时机）：
 *   - *out_tables_pt：上表编码的表记录段（heap 副本，调用方
 *     verthys_secure_zero + free）；
 *   - *out_memtable_pt：MemTable 快照编码流（[u32le count][count × 条目
 *     编码]，与 LSM WAL 帧明文同构；heap 副本，调用方 zero + free）。
 *
 * 行为：先逐表预热（verthys_lsm_sstable_preheat，幂等——确保惰性缓存
 * 完整可导出），再两遍编码（MemTable 测长 + 写入）。全程持独占锁
 * （单写者纪律保证两遍间快照稳定）。
 *
 * 调用方纪律（Lock 时机）：先 verthys_lsm_flush（快照 = 刷盘后空
 * MemTable），后本函数，再 verthys_lsm_close——close 自身的 flush 为
 * no-op。异步时机（事务提交后）：本函数自身持锁快照，事务边界外
 * 调用即可。
 */
VerthysResult verthys_lsm_export_warm(VerthysLsm *lsm,
                                  uint8_t **out_tables_pt, size_t *out_tables_len,
                                  uint8_t **out_memtable_pt, size_t *out_memtable_len);

/*
 * 温启动打开（S5 温缓存命中路径）：与 verthys_lsm_open 相同的区域布局、
 * 崩溃恢复与生命周期语义（Manifest 盘面加载 → WAL 重放 → nonce 下限
 * 推定），另做两步加速：
 *   1. 表记录段安装：seq 匹配的 Manifest 表直接填充惰性缓存（Footer
 *      字段 + Bloom 位图 + 块索引），后续 get/preheat 零表 IO；seq 不
 *      匹配（缓存过期）静默跳过；
 *   2. MemTable 快照先解码入表，随后 WAL 重放——重放条目新于快照
 *      （同键覆盖 = 时序正确）。txid 门控由 warmcache 层承担（快照
 *      过期时传 NULL），本层不重复校验。
 *
 * tables_pt / memtable_pt 可为 NULL/0（对应段缺失）。
 * 解码失败（结构非法）返回 VERTHYS_ERR_FORMAT——调用方据此回退冷启动
 * （verthys_lsm_open 重入安全：nonce restore 单调向前，无回退副作用）。
 */
VerthysResult verthys_lsm_open_warm(VerthysLsm *lsm, FILE *f, VerthysPartition *part,
                                uint64_t region_offset, uint64_t region_size,
                                int enable_bg,
                                const uint8_t *tables_pt, size_t tables_len,
                                const uint8_t *memtable_pt, size_t memtable_len);

/*
 * 全量索引预热（完全解锁 S6 / MINIMAL_FIRST 后台预热线程）：
 * 逐表强制加载 Footer + Bloom 位图 + Index Block（惰性缓存填充），
 * 后续 get 路径元数据零 IO。幂等（缓存已在时 no-op）。
 */
VerthysResult verthys_lsm_preheat_full(VerthysLsm *lsm);

/* ---------- 统计（测试/诊断） ---------- */

/* Manifest 在册 SSTable 总数 */
size_t verthys_lsm_table_count(const VerthysLsm *lsm);

/* ---------- 全量扫描迭代器（API 层 Scan/摘要/计数 接线） ---------- */

/*
 * 全量快照迭代器（lid 升序；跨层归并去重——同 lid 取最新版本；墓碑跳过）：
 *   - MemTable：open 时编码流深拷贝（快照后写者 put/flush 不影响迭代器）；
 *   - SSTable：open 时在册表深拷贝元数据（惰性缓存私有重载）+ 顺序块
 *     迭代器（快照后新 flush 的表不在视野内）；表区域 append-only，
 *     compaction 移除不复用偏移，已打开迭代器安全；
 *   - f/part 借用（生命周期由调用方契约保证：close 先于 lsm destroy）。
 *
 * 新旧判定：MemTable 最新；SSTable 层级小者新；同层 seq 大者新。
 *
 * 线程安全性：open/next 持 lsm 独占锁（块定位读 vio_pread64 非原子，
 * 须与 get/preheat/flush 等全部 f 使用者互斥；next 每步推进后即释放，
 * 长扫描不长时间阻塞写者）；close 无锁（纯自有状态）。
 */
typedef struct VerthysLsmScanIter VerthysLsmScanIter;

/*
 * 打开快照迭代器。*out 为堆实例（scan_close 释放）。
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_INTERNAL（内存）/
 * 各表迭代器打开错误透传（AUTH/FORMAT/IO）。
 */
VerthysResult verthys_lsm_scan_open(VerthysLsm *lsm, VerthysLsmScanIter **out);

/*
 * 取下一条有效条目（跳过墓碑）。返回 VERTHYS_OK；耗尽返回 VERTHYS_ERR_NOTFOUND
 * （幂等，重复调用持续 NOTFOUND）；name_buf 容量不足返回 VERTHYS_ERR_INVALID
 * （本条未消费，携更大缓冲重试得同一条目）；块读取/解码失败收敛
 * VERTHYS_ERR_INTERNAL（迭代器失效，须 close）。
 * out/name 语义同 verthys_lsm_get（拷贝出参，name 拷入 name_buf）。
 */
VerthysResult verthys_lsm_scan_next(VerthysLsmScanIter *it, VerthysLsmEntry *out,
                                uint8_t *name_buf, size_t name_cap,
                                size_t *name_len_out);

/* 释放迭代器（幂等）。 */
void verthys_lsm_scan_close(VerthysLsmScanIter *it);

/*
 * 有效记录数估算（摘要计数；O(表数 + MemTable 条目)）：
 * Σ(表 entry_count - tombstone_count) + MemTable 非墓碑条目数。
 * 同 lid 多版本未 compaction 时略偏高（V3 语义：Add 恒新 lid，仅
 * 崩溃恢复重放窗口内可能出现瞬时偏差，commit 后收敛）。
 */
uint64_t verthys_lsm_estimate_records(const VerthysLsm *lsm);

/* 指定层级在册表数（level ≥ MAX_LEVELS 返回 0） */
size_t verthys_lsm_level_table_count(const VerthysLsm *lsm, unsigned level);

/* 指定层级总字节（在册 SSTable 区域大小求和） */
uint64_t verthys_lsm_level_bytes(const VerthysLsm *lsm, unsigned level);

/* 活跃 MemTable 条目数（未 flush） */
size_t verthys_lsm_memtable_count(const VerthysLsm *lsm);

/*
 * 全局最大已见 lid（LID 顺序分配基准）。
 * put/delete 单调推高；open 时由 Manifest max_key ∪ MemTable 尾值
 * 合并初始化；rollback/purge 重建 MemTable 后不回退（LID 永不复用，
 * 红线语义——避免与孤儿 Extent / 已写 WAL 帧的旧键产生关联混淆）。
 * AddRecord 经 max_lid + 1 分配新键。空库返回 0。
 */
uint64_t verthys_lsm_max_lid(const VerthysLsm *lsm);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_LSM_H */
