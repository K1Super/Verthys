/*
 * verthys_lsm_compaction.c — LSM Compaction：分级合并策略
 *
 * 策略（leveled）：
 *   1. 自 L0 起首个超限层级（L0 表数 ≥ 触发值 4；L≥1 字节超容量，
 *      L1 基数 64MB 逐级 ×10）；
 *   2. 主选集 ≤64MB：L0 取全部表（层内可重叠——部分选取会破坏
 *      "L0 新值遮蔽"查找序，正确性优先）；L≥1 层内不重叠，按 min_key
 *      键序取前缀（至少 1 表）；
 *   3. 并入 L+1 层与选集键域重叠的全部表（区间扩张循环重扫——
 *      被并入表可能扩展键域引入新重叠表）；
 *   4. k 路归并：同 lid 胜者判定——层级小者新（L0 最新），同层
 *      seq 大者新；败者版本即时丢弃；
 *   5. 墓碑至最底层（target == MAX_LEVELS-1）物理删除——最底层
 *      无更深层数据，遮蔽使命完成；
 *   6. 产出单个 L+1 SSTable（升序流 → sstable_write）；全墓碑输出
 *      → 零表产出（仅摘除输入 + Manifest 提交）；
 *   7. Manifest 原子提交（覆写帧 + fsync）；保存失败回滚内存态
 *      （盘面 Manifest 仍引用旧表 → 数据零丢失，新表沦为脏区覆写）。
 *
 * 崩溃一致性：输入 SSTable 永不原地改写；新表先 _commit 落盘，
 * Manifest 覆写为唯一提交点。任意时刻崩溃：盘面 Manifest 引用的
 * 表集合完整有效（旧表或新表二选一）。
 *
 * 并发纪律：调用方（verthys_lsm.c bg_thread_main / verthys_lsm_compact）
 * 持 SRWLOCK 独占；本翻译单元不加锁。
 */
#include "verthys_lsm_internal.h"
#include "verthys_internal.h"     /* verthys_secure_zero */

#include <stdlib.h>
#include <string.h>

/* ================== 层级超限判定 ================== */

/* 首个超限层级（L0 表数 ≥ 触发值 / L≥1 字节超容量 ×10 逐级）；-1 = 无 */
static int pick_overlimit_level(const VerthysLsm *lsm)
{
    size_t l0 = 0;
    uint64_t level_bytes[VERTHYS_LSM_MAX_LEVELS];
    uint64_t limit = VERTHYS_LSM_LEVEL_BASE_BYTES;

    memset(level_bytes, 0, sizeof(level_bytes));
    for (size_t i = 0; i < lsm->manifest.count; i++) {
        const VerthysLsmTableMeta *t = &lsm->manifest.tables[i];
        if (t->level == 0) l0++;
        if (t->level < VERTHYS_LSM_MAX_LEVELS) {
            level_bytes[t->level] += t->size;
        }
    }

    if (l0 >= VERTHYS_LSM_L0_COMPACTION_TRIGGER) return 0;

    for (unsigned lvl = 1; lvl < VERTHYS_LSM_MAX_LEVELS; lvl++) {
        if (level_bytes[lvl] > limit) return (int)lvl;
        if (limit > UINT64_MAX / 10u) break;   /* 溢出防护：上限即无穷 */
        limit *= 10u;
    }
    return -1;
}

/* ================== 输入选集 ================== */

typedef struct CompactionInputs {
    size_t   idx[VERTHYS_LSM_MAX_TABLES];   /* Manifest 表索引 */
    size_t   n;
    uint64_t min_key;
    uint64_t max_key;
    uint64_t total_bytes;
} CompactionInputs;

/*
 * Manifest 影子事务（compact 提交边界）：
 *   - tables：数组浅拷贝（惰性缓存指针与内存 Manifest 共享）；
 *   - 备份必须在摘除输入表 / 释放其缓存之前——此后 abort 恢复的
 *     数组仍持有未释放的输入表，其缓存可继续服务 get/scan；
 *   - removed_idx/removed_n：被摘除表索引，commit（save 成功后）
 *     依此释放在备份副本上的惰性缓存；
 *   - abort 只恢复数组与元数据，绝不释放输入表资源。
 */
typedef struct ManifestShadowTxn {
    VerthysLsmTableMeta tables[VERTHYS_LSM_MAX_TABLES];
    size_t count;
    uint64_t txid, next_seq, next_data_offset;
    size_t removed_idx[VERTHYS_LSM_MAX_TABLES];
    size_t removed_n;
} ManifestShadowTxn;

static void inputs_add(CompactionInputs *in, const VerthysLsmManifest *m, size_t i)
{
    const VerthysLsmTableMeta *t = &m->tables[i];

    in->idx[in->n] = i;
    in->n++;
    if (in->n == 1 || t->min_key < in->min_key) in->min_key = t->min_key;
    if (in->n == 1 || t->max_key > in->max_key) in->max_key = t->max_key;
    in->total_bytes += t->size;
}

/*
 * 主选集：
 *   L0  → 全部 L0 表（层内可重叠，部分选取破坏查找序）；
 *   L≥1 → 层内按 min_key 键序取前缀，累计 ≤64MB（至少 1 表）。
 */
static void select_seeds(CompactionInputs *in, const VerthysLsmManifest *m,
                         unsigned level)
{
    if (level == 0) {
        for (size_t i = 0; i < m->count; i++) {
            if (m->tables[i].level == 0) inputs_add(in, m, i);
        }
        return;
    }

    /* 收集同层索引 → 按 min_key 升序（层内不重叠 → 等价键序） */
    {
        size_t order[VERTHYS_LSM_MAX_TABLES];
        size_t n = 0;

        for (size_t i = 0; i < m->count; i++) {
            if (m->tables[i].level == level) order[n++] = i;
        }
        for (size_t i = 1; i < n; i++) {         /* 插入排序（n ≤ 128） */
            size_t k = order[i], j = i;
            while (j > 0 && m->tables[order[j - 1]].min_key > m->tables[k].min_key) {
                order[j] = order[j - 1];
                j--;
            }
            order[j] = k;
        }
        for (size_t i = 0; i < n; i++) {
            const VerthysLsmTableMeta *t = &m->tables[order[i]];
            if (in->n != 0 &&
                in->total_bytes + t->size > VERTHYS_LSM_COMPACTION_MAX_RUN_BYTES) {
                break;
            }
            inputs_add(in, m, order[i]);
        }
    }
}

/*
 * 并入 target_level 与选集键域重叠的全部表。
 * 被并入表可能扩展键域 → 引入新重叠表 → 循环重扫至收敛
 * （层内不重叠保证有限轮收敛）。
 */
static void add_overlapping(CompactionInputs *in, const VerthysLsmManifest *m,
                            unsigned target_level)
{
    int changed = 1;

    while (changed) {
        changed = 0;
        for (size_t i = 0; i < m->count; i++) {
            const VerthysLsmTableMeta *t = &m->tables[i];
            int already = 0;

            if (t->level != target_level) continue;
            for (size_t j = 0; j < in->n; j++) {
                if (in->idx[j] == i) { already = 1; break; }
            }
            if (already) continue;
            if (t->min_key <= in->max_key && t->max_key >= in->min_key) {
                inputs_add(in, m, i);
                changed = 1;
            }
        }
    }
}

/* Manifest 摘除输入表（保留相对有序性） */
static void manifest_remove_inputs(VerthysLsmManifest *m,
                                   const CompactionInputs *in)
{
    size_t w = 0;

    for (size_t i = 0; i < m->count; i++) {
        int drop = 0;
        for (size_t j = 0; j < in->n; j++) {
            if (in->idx[j] == i) { drop = 1; break; }
        }
        if (drop) continue;
        m->tables[w++] = m->tables[i];
    }
    m->count = w;
}

/* ================== k 路归并迭代器 ================== */

typedef struct MergeSource {
    VerthysLsmEntryIter   it;      /* sstable_iter_open 填充 */
    VerthysLsmSstIter    *si;
    const VerthysLsmEntry *cur;    /* 当前就绪条目（NULL = 待推进/耗尽） */
    unsigned            level;
    uint64_t            seq;
} MergeSource;

typedef struct MergeIter {
    MergeSource    *srcs;
    size_t          n;
    int             drop_tombstones;  /* target == 最底层 */
    VerthysLsmEntry   out;              /* 稳定拷贝（name 借用 name_buf） */
    uint8_t         name_buf[VERTHYS_LSM_NAME_MAX_BYTES];
} MergeIter;

/* 推进单源至就绪/耗尽；返回 0 成功 / -1 错误 */
static int source_advance(MergeSource *s)
{
    const VerthysLsmEntry *e = NULL;
    int rc;

    if (s->cur != NULL) return 0;
    if (s->it.next == NULL) return -1;
    rc = s->it.next(&s->it, &e);
    if (rc < 0) return -1;
    s->cur = (rc == 1) ? e : NULL;
    return 0;
}

/* 新旧判定：a 比 b 新 → 1（层级小者新；同层 seq 大者新） */
static int source_newer(const MergeSource *a, const MergeSource *b)
{
    if (a->level != b->level) return a->level < b->level;
    return a->seq > b->seq;
}

/*
 * 归并推进：全源就绪 → 取最小 lid（同 lid 取最新）→ 胜者拷贝至
 * 稳定缓冲 → 消费全部同 lid 源 → 墓碑至最底层跳过（物理删除）。
 */
static int merge_iter_next(VerthysLsmEntryIter *it, const VerthysLsmEntry **out)
{
    MergeIter *mi = (MergeIter *)it->ctx;

    if (mi == NULL || out == NULL) return -1;

    for (;;) {
        size_t best = 0;
        int have = 0;
        uint64_t lid;

        for (size_t i = 0; i < mi->n; i++) {
            if (source_advance(&mi->srcs[i]) != 0) return -1;
        }

        for (size_t i = 0; i < mi->n; i++) {
            const MergeSource *s = &mi->srcs[i];
            if (s->cur == NULL) continue;
            if (!have) {
                best = i;
                have = 1;
                continue;
            }
            if (s->cur->lid < mi->srcs[best].cur->lid ||
                (s->cur->lid == mi->srcs[best].cur->lid &&
                 source_newer(s, &mi->srcs[best]))) {
                best = i;
            }
        }
        if (!have) return 0;    /* 全源耗尽 */

        lid = mi->srcs[best].cur->lid;

        /* 胜者拷贝（后续推进会使借用指针失效） */
        {
            const VerthysLsmEntry *w = mi->srcs[best].cur;
            mi->out = *w;
            if (w->name_len != 0) {
                memcpy(mi->name_buf, w->name, w->name_len);
                mi->out.name = mi->name_buf;
            } else {
                mi->out.name = NULL;
            }
        }

        /* 消费全部同 lid 源（含胜者；败者版本丢弃） */
        for (size_t i = 0; i < mi->n; i++) {
            MergeSource *s = &mi->srcs[i];
            if (s->cur != NULL && s->cur->lid == lid) s->cur = NULL;
        }

        /* 墓碑至最底层 → 物理删除（不产出，继续归并） */
        if (mi->out.tombstone && mi->drop_tombstones) continue;

        *out = &mi->out;
        return 1;
    }
}

/*
 * 预取包装迭代器：首条已由 merge_iter_next 预取（空输出探测），
 * 产出 stash 后透传归并迭代器。
 */
typedef struct CompactionOutIter {
    VerthysLsmEntryIter *src;
    int                stash_valid;
    VerthysLsmEntry      stash;
    uint8_t            stash_name[VERTHYS_LSM_NAME_MAX_BYTES];
} CompactionOutIter;

static int out_iter_next(VerthysLsmEntryIter *it, const VerthysLsmEntry **out)
{
    CompactionOutIter *oi = (CompactionOutIter *)it->ctx;

    if (oi == NULL || out == NULL) return -1;
    if (oi->stash_valid) {
        oi->stash_valid = 0;
        *out = &oi->stash;
        return 1;
    }
    return oi->src->next(oi->src, out);
}

/* ================== 单次 compaction 运行 ================== */

VerthysResult verthys_lsm_compact_locked(VerthysLsm *lsm)
{
    VerthysResult r;
    int level = pick_overlimit_level(lsm);
    unsigned target_level;
    CompactionInputs in;
    MergeSource *srcs = NULL;
    MergeIter mi;
    VerthysLsmEntryIter merge_it;
    CompactionOutIter oi;
    memset(&oi, 0, sizeof(oi));
    size_t opened = 0;
    size_t total_entries = 0;
    uint64_t seq, txid;
    uint64_t cursor = 0;
    VerthysLsmTableMeta meta;
    int wrote_table = 0;
    int have_output = 0;
    /* Manifest 影子事务（见结构注释：先备份后摘除，save 失败可完整回滚） */
    ManifestShadowTxn txn;
    uint64_t data_limit;

    if (lsm == NULL) return VERTHYS_ERR_INVALID;
    if (level < 0) return VERTHYS_OK;    /* 无超限层级：no-op */

    /* ---- 1. 输入选集 ---- */
    memset(&in, 0, sizeof(in));
    select_seeds(&in, &lsm->manifest, (unsigned)level);
    if (in.n == 0) return VERTHYS_OK;

    target_level = ((unsigned)level + 1 < VERTHYS_LSM_MAX_LEVELS)
                       ? (unsigned)level + 1
                       : (unsigned)level;   /* 最层内自并（墓碑可物理删除） */
    if (target_level != (unsigned)level) {
        add_overlapping(&in, &lsm->manifest, target_level);
    }

    /* ---- 2. 打开全部输入迭代器 ---- */
    srcs = (MergeSource *)calloc(in.n, sizeof(*srcs));
    if (srcs == NULL) return VERTHYS_ERR_INTERNAL;
    for (size_t i = 0; i < in.n; i++) {
        VerthysLsmTableMeta *t = &lsm->manifest.tables[in.idx[i]];
        srcs[i].level = t->level;
        srcs[i].seq = t->seq;
        r = verthys_lsm_sstable_iter_open(lsm->f, lsm->part, t,
                                        &srcs[i].it, &srcs[i].si);
        if (r != VERTHYS_OK) goto fail_iter;
        opened++;
        total_entries += t->entry_count;
    }

    memset(&mi, 0, sizeof(mi));
    mi.srcs = srcs;
    mi.n = in.n;
    mi.drop_tombstones = (target_level == VERTHYS_LSM_MAX_LEVELS - 1);

    merge_it.next = merge_iter_next;
    merge_it.ctx = &mi;

    /* ---- 3. 空输出探测（首条预取）---- */
    {
        const VerthysLsmEntry *first = NULL;
        int rc = merge_iter_next(&merge_it, &first);

        if (rc < 0) { r = VERTHYS_ERR_INTERNAL; goto fail_iter; }
        if (rc == 1) {
            have_output = 1;
            memset(&oi, 0, sizeof(oi));
            oi.src = &merge_it;
            oi.stash_valid = 1;
            oi.stash = *first;
            if (first->name_len != 0) {
                memcpy(oi.stash_name, first->name, first->name_len);
                oi.stash.name = oi.stash_name;
            } else {
                oi.stash.name = NULL;
            }
        }
        /* rc == 0：全墓碑至最底层 → 零表产出 */
    }

    /* ---- 4. 产出 SSTable（先于 Manifest 变更落盘 + _commit）---- */
    seq = lsm->manifest.next_seq;
    txid = lsm->manifest.txid + 1;
    cursor = lsm->manifest.next_data_offset;
    data_limit = lsm->region_size -
                 (lsm->data_region_offset - lsm->region_offset);

    if (have_output) {
        VerthysLsmEntryIter out_it;

        out_it.next = out_iter_next;
        out_it.ctx = &oi;

        r = verthys_lsm_sstable_write(lsm->f, lsm->part, &out_it,
                                    total_entries, txid, seq,
                                    (uint8_t)target_level,
                                    lsm->data_region_offset,
                                    &cursor, data_limit, &meta);
        if (r != VERTHYS_OK) goto fail_iter;
        wrote_table = 1;
    }

    /* ---- 5. Manifest 影子事务：先备份中间态（输入表缓存未释放、
     * 拷贝共享指针仍有效）再摘除输入表。 ---- */
    txn.count = lsm->manifest.count;
    memcpy(txn.tables, lsm->manifest.tables,
           txn.count * sizeof(txn.tables[0]));
    txn.txid = lsm->manifest.txid;
    txn.next_seq = lsm->manifest.next_seq;
    txn.next_data_offset = lsm->manifest.next_data_offset;
    memcpy(txn.removed_idx, in.idx, in.n * sizeof(in.idx[0]));
    txn.removed_n = in.n;

    /* 内存态应用：只动数组与元数据，不触碰被摘除表资源 */
    manifest_remove_inputs(&lsm->manifest, &in);
    lsm->manifest.txid = txid;
    if (wrote_table) {
        /* 摘除 ≥1 表 → 插入必有余量（容量不可能失败） */
        if (manifest_insert_sorted(&lsm->manifest, &meta) != 0) {
            r = VERTHYS_ERR_INTERNAL;
            goto fail_rollback;
        }
        lsm->manifest.next_seq = seq + 1;
        lsm->manifest.next_data_offset = cursor;
    }

    /* ---- 6. Manifest 持久化（唯一提交点）---- */
    r = verthys_lsm_manifest_save(lsm->f, lsm->region_offset,
                                &lsm->manifest, lsm->part);
    if (r != VERTHYS_OK) goto fail_rollback;

    /* ---- 7. 提交：盘面已引用新表集合，被摘除输入表的
     * 惰性缓存至此使命完成，统一释放（经备份副本指针）。 ---- */
    for (size_t i = 0; i < txn.removed_n; i++) {
        verthys_lsm_sstable_meta_release(&txn.tables[txn.removed_idx[i]]);
    }

    /* ---- 收尾：关闭迭代器 ---- */
    for (size_t i = 0; i < opened; i++) {
        verthys_lsm_sstable_iter_close(srcs[i].si);
    }
    free(srcs);
    return VERTHYS_OK;

fail_rollback:
    /* abort：恢复备份。输入表回归数组且其惰性缓存未被释放（save 前
     * 零释放）——当前进程 get/scan 立即可达；盘面 Manifest 仍引用
     * 旧表集合，新表数据区由游标回退覆写回收（沦为脏区）。 */
    memcpy(lsm->manifest.tables, txn.tables,
           txn.count * sizeof(lsm->manifest.tables[0]));
    lsm->manifest.count = txn.count;
    lsm->manifest.txid = txn.txid;
    lsm->manifest.next_seq = txn.next_seq;
    lsm->manifest.next_data_offset = txn.next_data_offset;

fail_iter:
    for (size_t i = 0; i < opened; i++) {
        verthys_lsm_sstable_iter_close(srcs[i].si);
    }
    free(srcs);
    return r;
}
