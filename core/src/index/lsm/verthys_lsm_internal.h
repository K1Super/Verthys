/*
 * verthys_lsm_internal.h — LSM 模块内部契约（verthys_lsm.c / memtable /
 * sstable / compaction 共享；测试直接链接对象消费）
 *
 * 本头不属于公共 ABI：条目编解码、MemTable 跳表、Bloom、SSTable 读写、
 * Manifest 内存态等跨翻译单元细节在此声明。
 *
 * 帧惯例：
 *   [u32 magic][u32 ct_len][AEAD 密文 ct_len 字节（含 16B tag）][12B nonce]
 *   ct_len ≥ 16（空明文合法）。
 *
 * 域分离 AAD（经 verthys_cng_aead_encrypt 显式传入，Index 分区密钥）：
 *   WAL 帧        : "verthys/lsm-wal-v3"
 *   Manifest 帧   : "verthys/lsm-manifest-v3"
 *   数据块 i      : "verthys/lsm-sstable-v3" ‖ u64le(seq) ‖ u32le(i)
 *   Index Block   : "verthys/lsm-index-v3" ‖ u64le(seq)
 *   Footer        : "verthys/lsm-footer-v3" ‖ u64le(seq)
 * 块级 AAD 绑定 seq + 块号：密文块搬运至其他 SSTable/槽位 → 认证失败。
 */
#ifndef VERTHYS_LSM_INTERNAL_H
#define VERTHYS_LSM_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "verthys_lsm.h"
#include "verthys_partition.h"
#include "verthys_io.h"
#include "verthys_extent.h"     /* verthys_extent_hash = BLAKE2b-256（Bloom 锚定） */

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 帧与魔数 ---------- */

#define VERTHYS_LSM_WAL_MAGIC        UINT32_C(0x574C3356) /* 'V3LW' */
#define VERTHYS_LSM_MANIFEST_MAGIC   UINT32_C(0x4D4C3356) /* 'V3LM' */
#define VERTHYS_LSM_SSTABLE_MAGIC    UINT32_C(0x53533356) /* 'V3SS' */
#define VERTHYS_LSM_BLOCK_MAGIC      UINT32_C(0x4B423356) /* 'V3BK'（数据块帧） */
#define VERTHYS_LSM_INDEX_MAGIC      UINT32_C(0x49533356) /* 'V3SI'（Index Block） */
#define VERTHYS_LSM_FRAME_HEADER_BYTES 8u                 /* [magic][ct_len] */
#define VERTHYS_LSM_FRAME_TAIL_BYTES   12u                /* nonce */

/* 域分离标签 */
#define VERTHYS_LSM_AAD_WAL       "verthys/lsm-wal-v3"
#define VERTHYS_LSM_AAD_MANIFEST  "verthys/lsm-manifest-v3"
#define VERTHYS_LSM_AAD_SSTABLE   "verthys/lsm-sstable-v3"
#define VERTHYS_LSM_AAD_INDEX     "verthys/lsm-index-v3"
#define VERTHYS_LSM_AAD_FOOTER    "verthys/lsm-footer-v3"

/* ---------- 条目编解码（verthys_lsm_memtable.c） ---------- */

/* 定长头 78B + name；与 WAL 帧/数据块明文共用 */
#define VERTHYS_LSM_ENTRY_HEADER_BYTES 78u

/* 编码长度（含 name） */
size_t verthys_lsm_entry_encoded_len(const VerthysLsmEntry *e);

/*
 * 编码条目到 buf。
 * 返回 0 成功 / -1 失败（容量不足或参数非法）。
 */
int verthys_lsm_entry_encode(uint8_t *buf, size_t cap, const VerthysLsmEntry *e);

/*
 * 从 buf 解码（返回消费字节数，0=失败）。
 * out->name 指向 buf 内部（借用：buf 生存期内有效）；调用方校验
 * name_len 合法性与总长一致性。
 */
size_t verthys_lsm_entry_decode(const uint8_t *buf, size_t len, VerthysLsmEntry *out);

/* ---------- MemTable 跳表（verthys_lsm_memtable.c） ---------- */

#define VERTHYS_LSM_MEMTABLE_MAX_HEIGHT 16u

typedef struct VerthysLsmMemTable VerthysLsmMemTable;

VerthysLsmMemTable *verthys_lsm_memtable_create(void);
void verthys_lsm_memtable_destroy(VerthysLsmMemTable *mt);

/* 冻结：置 frozen 标志（文档化单写者纪律；冻结后插入返回 INVALID） */
void verthys_lsm_memtable_freeze(VerthysLsmMemTable *mt);
int verthys_lsm_memtable_frozen(const VerthysLsmMemTable *mt);

/*
 * 插入/同键覆盖（跳表 O(log n)）。
 * e 深拷贝（name 独立分配）；字节记账按编码长度。
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID（NULL、frozen、name 非法）/
 * VERTHYS_ERR_INTERNAL（内存耗尽）。
 */
VerthysResult verthys_lsm_memtable_insert(VerthysLsmMemTable *mt, const VerthysLsmEntry *e);

/* 查找：返回借用指针（mt 持有所有权；未命中返回 NULL） */
const VerthysLsmEntry *verthys_lsm_memtable_find(const VerthysLsmMemTable *mt, uint64_t lid);

/* 阈值判定：条目数 ≥ 10,000 或字节 ≥ 64MB */
int verthys_lsm_memtable_needs_flush(const VerthysLsmMemTable *mt);

size_t verthys_lsm_memtable_entry_count(const VerthysLsmMemTable *mt);
size_t verthys_lsm_memtable_bytes(const VerthysLsmMemTable *mt);

/*
 * API 接线：本表当前最大 lid（O(1) 字段读；插入单调推高，
 * 重建后随内容收缩）。上层 VerthysLsm.max_lid 承担"永不复用"单调性。
 */
uint64_t verthys_lsm_memtable_max_lid(const VerthysLsmMemTable *mt);

/* 升序遍历：cb 返回非 0 停止；返回已遍历条目数 */
typedef int (*VerthysLsmEntryCallback)(const VerthysLsmEntry *e, void *user_data);
size_t verthys_lsm_memtable_iterate(const VerthysLsmMemTable *mt,
                                  VerthysLsmEntryCallback cb, void *user_data);

/* ---------- Bloom Filter（verthys_lsm_sstable.c，xxHash64 双重哈希） ---------- */

typedef struct VerthysLsmBloom {
    uint8_t *bits;       /* 位图（byte[]） */
    uint32_t bytes;      /* 位图字节数 */
    uint8_t  k;          /* 双重哈希迭代次数 */
} VerthysLsmBloom;

/* n 个键所需位图字节数（向上取整到字节；n=0 → 1） */
uint32_t verthys_lsm_bloom_bytes_for(size_t n);

VerthysResult verthys_lsm_bloom_init(VerthysLsmBloom *b, size_t n); /* 分配 + 清零 */
void verthys_lsm_bloom_free(VerthysLsmBloom *b);                  /* 释放 + 置零 */
void verthys_lsm_bloom_add(VerthysLsmBloom *b, uint64_t key);
int verthys_lsm_bloom_may_contain(const VerthysLsmBloom *b, uint64_t key); /* 1=可能 0=必无 */

/* ---------- SSTable 元数据（内存态 Manifest 条目 + 惰性缓存） ---------- */

typedef struct VerthysLsmBlockIdx {
    uint64_t first_key;    /* 块内最小 lid */
    uint64_t offset;       /* 块帧起始（容器绝对偏移） */
    uint32_t frame_len;    /* 帧字节数 */
    uint32_t entry_count;  /* 块内条目数（含墓碑） */
} VerthysLsmBlockIdx;

typedef struct VerthysLsmTableMeta {
    /* Manifest 持久化字段 */
    uint64_t seq;
    uint8_t  level;
    uint64_t offset;           /* SSTable 区域起始（容器绝对偏移） */
    uint32_t size;             /* 区域字节数（含 Trailer） */
    uint32_t entry_count;      /* 含墓碑 */
    uint32_t tombstone_count;
    uint64_t min_key;
    uint64_t max_key;
    uint64_t created_txid;
    /* Footer 惰性加载字段（首次访问填充） */
    int footer_loaded;
    uint64_t index_block_offset;
    uint64_t bloom_offset;
    uint32_t bloom_bytes;
    uint8_t  bloom_k;
    uint8_t  bloom_hash[32];   /* BLAKE2b-256(bloom bits) */
    /* 惰性缓存（SSTable 移除时释放） */
    uint8_t *bloom_bits;       /* 校验通过后缓存的位图 */
    VerthysLsmBlockIdx *blocks;  /* Index Block 解析结果 */
    size_t block_count;
} VerthysLsmTableMeta;

typedef struct VerthysLsmManifest {
    VerthysLsmTableMeta tables[VERTHYS_LSM_MAX_TABLES];
    size_t count;
    uint64_t txid;             /* 快照事务 ID */
    uint64_t next_seq;         /* SSTable 序号分配器 */
    uint64_t next_data_offset; /* 数据区追加游标（相对数据区基址） */
    uint64_t nonce_snapshot;   /* 加载侧回填：盘面 nonce 快照（保存后值）；
                                   open 据此 + WAL 帧数 + 裕量推计数器下限 */
} VerthysLsmManifest;

/* ---------- AEAD 帧助手（verthys_lsm_sstable.c 提供，全模块共用） ---------- */

/*
 * 帧写入：[u32 magic][u32 ct_len][ct||tag][12B nonce] → abs_off。
 * 密文布局 [ct‖tag]，容量 = pt_len + 16B；nonce 由分区计数器生成（唯一性）。
 * out_frame_len 可为 NULL。
 */
VerthysResult verthys_lsm_frame_write(FILE *f, uint64_t abs_off, uint32_t magic,
                                  VerthysCngAead *aead,
                                  const uint8_t *aad, size_t aad_len,
                                  const uint8_t *pt, size_t pt_len,
                                  uint32_t *out_frame_len);

/*
 * 帧读取 + 解密：返回堆分配明文（调用方 free）。
 * max_ct：密文长度上限（容量防护，含 tag）；frame_len_out 可为 NULL。
 * 认证失败 → VERTHYS_ERR_AUTH；结构非法 → VERTHYS_ERR_FORMAT。
 */
VerthysResult verthys_lsm_frame_read_decrypt(FILE *f, uint64_t abs_off,
                                         uint32_t magic,
                                         const VerthysCngAead *aead,
                                         const uint8_t *aad, size_t aad_len,
                                         size_t max_ct,
                                         uint8_t **pt_out, size_t *pt_len_out,
                                         uint32_t *frame_len_out);

/* ---------- 有序条目迭代器（SSTable 写入的统一输入源） ---------- */

typedef struct VerthysLsmEntryIter {
    /*
     * 推进：返回 1 = *out 填充借用条目（须立即消费）；0 = 结束；-1 = 错误。
     * 条目须按 lid 升序（SSTable 数据块有序性契约）。
     */
    int (*next)(struct VerthysLsmEntryIter *it, const VerthysLsmEntry **out);
    void *ctx;
} VerthysLsmEntryIter;

/* MemTable 升序迭代器（next 回调实现，ctx = memtable 迭代游标堆分配） */
typedef struct VerthysLsmMemIter VerthysLsmMemIter;
VerthysResult verthys_lsm_memtable_iter_start(const VerthysLsmMemTable *mt,
                                          VerthysLsmEntryIter *it, VerthysLsmMemIter **out);
void verthys_lsm_memtable_iter_end(VerthysLsmMemIter *mi);

/* ---------- SSTable 读写（verthys_lsm_sstable.c） ---------- */

/*
 * 写入 SSTable：消费升序迭代器 → 数据块（AEAD 帧，块级 AAD 绑定
 * seq+块号）→ Bloom 位图 → Index Block 帧 → Footer 帧 → Trailer。
 *
 * [in]     f            容器文件
 * [in]     part         Index 分区（已导入；加密推进 nonce 计数器）
 * [in]     it           升序条目迭代器（本函数逐条消费）
 * [in]     total_hint   条目数上界（Bloom 容量预估）
 * [in]     txid         flush/compaction 事务 ID
 * [in]     seq          SSTable 序号（Manifest 分配）
 * [in]     level        目标层级
 * [in]     data_base    数据区基址（容器绝对偏移）
 * [in,out] rel_cursor   [in] 追加游标（相对数据区）/ [out] 写入后推进
 * [in]     data_limit   数据区字节容量（越界 → RESOURCE_LIMIT）
 * [out]    meta         写入结果元数据（footer 字段一并填充）
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_LOCKED /
 * VERTHYS_ERR_RESOURCE_LIMIT（数据区耗尽）/ VERTHYS_ERR_IO / VERTHYS_ERR_INTERNAL。
 */
VerthysResult verthys_lsm_sstable_write(FILE *f, VerthysPartition *part,
                                    VerthysLsmEntryIter *it, size_t total_hint,
                                    uint64_t txid, uint64_t seq, uint8_t level,
                                    uint64_t data_base,
                                    uint64_t *rel_cursor, uint64_t data_limit,
                                    VerthysLsmTableMeta *meta);

/*
 * 单表查找（惰性加载 Footer/Bloom/块索引并缓存）。
 * 返回：VERTHYS_OK（键定位成功：out 拷贝，out->tombstone 指示墓碑）/
 * VERTHYS_ERR_NOTFOUND（本表无此键——调用方继续下一表）/
 * VERTHYS_ERR_AUTH / VERTHYS_ERR_CORRUPT（Bloom 哈希不符）/ VERTHYS_ERR_FORMAT /
 * VERTHYS_ERR_IO / VERTHYS_ERR_INTERNAL。
 */
VerthysResult verthys_lsm_sstable_find(FILE *f, VerthysPartition *part,
                                   VerthysLsmTableMeta *meta, uint64_t lid,
                                   VerthysLsmEntry *out,
                                   uint8_t *name_buf, size_t name_cap,
                                   size_t *name_len_out);

/* 释放 meta 惰性缓存（Manifest 移除/关闭时调用；持久化字段保留） */
void verthys_lsm_sstable_meta_release(VerthysLsmTableMeta *meta);

/*
 * 单表全量预热——强制加载
 * Footer + Bloom 位图 + Index Block（ensure_* 链的公开内部门面，
 * verthys_lsm_preheat_full 逐表调用）。幂等（缓存已在时 no-op）。
 */
VerthysResult verthys_lsm_sstable_preheat(FILE *f, VerthysPartition *part,
                                      VerthysLsmTableMeta *meta);

/* ---------- SSTable 顺序迭代（compaction 输入） ---------- */

typedef struct VerthysLsmSstIter VerthysLsmSstIter;

/*
 * 打开整表升序迭代器（逐块惰性读取解密；块级 AAD 校验）。
 * 返回 VERTHYS_OK / 错误码（同 find）。
 */
VerthysResult verthys_lsm_sstable_iter_open(FILE *f, VerthysPartition *part,
                                        VerthysLsmTableMeta *meta,
                                        VerthysLsmEntryIter *it,
                                        VerthysLsmSstIter **out);
void verthys_lsm_sstable_iter_close(VerthysLsmSstIter *si);

/* ---------- Manifest 持久化（verthys_lsm.c） ---------- */

/*
 * Manifest 保存：flatcc 序列化（nonce_counter 快照 = 当前计数器 + 1，
 * ★保存后值约定）→ Index 分区密钥 AEAD → 帧区整帧覆写 + fsync。
 */
VerthysResult verthys_lsm_manifest_save(FILE *f, uint64_t region_offset,
                                    const VerthysLsmManifest *m,
                                    VerthysPartition *part);

/*
 * 有序插入（查找序：level 升序、同层 seq 降序；容量满返回 -1）。
 * flush（verthys_lsm.c）与 compaction（verthys_lsm_compaction.c）共用。
 */
int manifest_insert_sorted(VerthysLsmManifest *m, const VerthysLsmTableMeta *t);

/*
 * Manifest 加载：帧读取 → AEAD 解密验证 → verifier + 字段校验 →
 * 内存态重建 + nonce 计数器 restore（保存后值；快照 < 当前值拒绝）。
 * 区域为空/无有效帧 → VERTHYS_ERR_FORMAT（调用方据此初始化新 Manifest）。
 */
VerthysResult verthys_lsm_manifest_load(FILE *f, uint64_t region_offset,
                                    VerthysPartition *part,
                                    VerthysLsmManifest *m);

/*
 * Manifest 明文帧解析（对齐 vsb_v3_parse_unverified
 * 分层模式）：flatcc verifier → magic/version → 字段提取 → 逐表元数据
 * 边界校验（level < MAX_LEVELS、size 非零、min_key ≤ max_key）→ 有序
 * 重建 m。不含 nonce 计数器 restore（生产路径由 manifest_load 在解析
 * 成功后执行；restore 依赖 CNG 分区句柄，与解析层解耦）。
 * 安全边界：产物不构成信任输入——生产路径仅在 AEAD 认证通过后调用。
 */
VerthysResult verthys_lsm_manifest_parse_unverified(const uint8_t *pt, size_t pt_len,
                                                VerthysLsmManifest *m);

/* ---------- LSM 树内部结构（verthys_lsm.c） ---------- */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

struct VerthysLsm {
    FILE *f;                    /* 借用 */
    VerthysPartition *part;       /* 借用（Index 分区） */
    uint64_t region_offset;
    uint64_t region_size;
    uint64_t wal_region_offset;   /* = region_offset + MANIFEST_REGION（绝对） */
    uint64_t data_region_offset;  /* = wal_region_offset + WAL_REGION（绝对） */
    SRWLOCK lock;                 /* 写独占 / 读共享 */
    VerthysLsmMemTable *memtable;   /* 活跃表 */
    VerthysLsmManifest manifest;
    uint64_t wal_cursor;          /* WAL 追加游标（相对 WAL 区） */
    /* 事务层配合：事务进行中抑制 MemTable 阈值自动 flush——
     * 未提交条目绝不进入 SSTable（否则运行时回滚/崩溃回滚均无法撤销）。
     * 事务提交边界由 transaction_v3 解除抑制并按需 flush。 */
    int suppress_flush;
    /*
     * API 接线：全局最大已见 lid（put/delete 单调推高，open
     * 时由 Manifest 各表 max_key + MemTable 尾值合并初始化）。
     * 红线语义：LID 永不复用——rollback/purge 重建 MemTable 后本字段
     * 不回退，AddRecord 分配 max_lid+1 保证跨事务唯一性。
     */
    uint64_t max_lid;
    /* 后台 compaction 线程 */
    int bg_enabled;
    HANDLE bg_thread;
    volatile LONG bg_shutdown;
};

/*
 * 内部：flush 冻结表（调用方持独占锁）。
 * 流程：sstable_write(L0) → Manifest 追加 → manifest_save → WAL 复位。
 * txid 取 manifest.txid + 1（成功后回写）。
 */
VerthysResult verthys_lsm_flush_locked(VerthysLsm *lsm);

/* 内部：compaction 单次运行（调用方持独占锁；verthys_lsm_compaction.c） */
VerthysResult verthys_lsm_compact_locked(VerthysLsm *lsm);

/* 内部：超限层级判定（无锁读，调用方持任意锁） */
int verthys_lsm_needs_compaction_locked(const VerthysLsm *lsm);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_LSM_INTERNAL_H */
