/*
 * verthys_transaction_v3.c — V3 六 Phase 事务实现
 *
 * 设计契约见 verthys_transaction_v3.h 文件头。实现要点：
 *   - 全部子系统（FILE/WAL/超块/LSM/Extent/分区表）均为借用引用，
 *     本模块零拥有权（integrity_key 拷贝除外，deinit 清零）；
 *   - 单写者纪律：非线程安全，FFI 单线程事务流水线串行化；
 *   - COMMIT 原子性 = WAL（§10.1 回放）+ 超级块法定人数（§6.3）：
 *     法定人数成功后的任何失败等价于该点崩溃，恢复路径按
 *     PREPARE-only 组重放收尾（confirm 幂等补存兜底）；
 *   - merkle_root 口径（V3 过渡实现，见头注）：BLAKE2b-256(全部
 *     Extent 哈希按索引序拼接 ‖ u64le(next_offset))。
 *
 * wal_committed_txid 水位语义（关键决策，防"已提交未收尾"组被
 * §10.1 规则 3 误跳过）：
 *   - 正常路径 COMMIT 不推进该水位（若在法定人数写入中一并推进，
 *     崩溃于"法定人数后、Extent 索引/分区表落盘前"的组将命中
 *     规则 3 被跳过——索引快照停留在提交前，已提交数据不可达）；
 *   - 水位推进仅两处：崩溃恢复收尾（sb->wal_committed_txid = sb->txid
 *     法定人数补提交）。CONFIRM 后 WAL 已复位，盘面无组可跳，
 *     水位滞后无害（下次 COMMIT 候选快照原样携带）。
 */
#include "verthys_transaction_v3.h"
#include "verthys_crypto.h"      /* verthys_generichash */
#include "verthys_internal.h"    /* verthys_secure_zero */

#include <stdlib.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>           /* GetSystemTimeAsFileTime */

/* ================== 内部工具 ================== */

static void txn_put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
}

/* 当前 FILETIME（超块 updated_at 口径，§6.3） */
static uint64_t txn_now_filetime(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

/* Unix 毫秒时间戳（WAL BEGIN/COMMIT 记账，非安全敏感） */
static uint64_t txn_now_unix_ms(void)
{
    return (txn_now_filetime() - 116444736000000000ULL) / 10000ULL;
}

/* Extent 索引内按哈希定位条目（与 verthys_extent.c 同款线性扫描；
 * 本模块需就地修改条目（重放 ref_count++），故不复用只读接口） */
static size_t txn_extent_find_slot(const VerthysExtentIndex *idx,
                                   const uint8_t hash[VERTHYS_EXTENT_HASH_BYTES])
{
    for (size_t i = 0; i < idx->count; i++) {
        if (memcmp(idx->entries[i].hash, hash, VERTHYS_EXTENT_HASH_BYTES) == 0) {
            return i;
        }
    }
    return SIZE_MAX;
}

/* ================== Extent 引用变动账本 ================== */

struct VerthysTxnExtRef {
    uint8_t  hash[VERTHYS_EXTENT_HASH_BYTES];
    int64_t  net;                 /* 本事务净引用变动（+写 / -删） */
};

static void txn_ledger_clear(VerthysTxnV3 *t)
{
    if (t->ext_refs != NULL) {
        free(t->ext_refs);
        t->ext_refs = NULL;
    }
    t->ext_ref_count = 0;
    t->ext_ref_cap = 0;
}

static VerthysResult txn_ledger_record(VerthysTxnV3 *t,
                                     const uint8_t hash[VERTHYS_EXTENT_HASH_BYTES],
                                     int64_t delta)
{
    /* 同哈希净额聚合（先写后删同内容 → 净额 0，回滚零操作） */
    for (size_t i = 0; i < t->ext_ref_count; i++) {
        if (memcmp(t->ext_refs[i].hash, hash, VERTHYS_EXTENT_HASH_BYTES) == 0) {
            t->ext_refs[i].net += delta;
            return VERTHYS_OK;
        }
    }
    if (t->ext_ref_count == t->ext_ref_cap) {
        size_t ncap = t->ext_ref_cap == 0 ? 8u : t->ext_ref_cap * 2u;
        struct VerthysTxnExtRef *nr =
            (struct VerthysTxnExtRef *)realloc(t->ext_refs,
                                             ncap * sizeof(*nr));
        if (nr == NULL) return VERTHYS_ERR_INTERNAL;
        t->ext_refs = nr;
        t->ext_ref_cap = ncap;
    }
    memcpy(t->ext_refs[t->ext_ref_count].hash, hash, VERTHYS_EXTENT_HASH_BYTES);
    t->ext_refs[t->ext_ref_count].net = delta;
    t->ext_ref_count++;
    return VERTHYS_OK;
}

/*
 * 按净额反向调整（回滚）：
 *   net > 0 → 释放 net 次引用（verthys_extent_release，下限 0；
 *             本事务新建块归 ref=0，GC 可回收——盘面追加块为孤儿）；
 *   net < 0 → 归还 |net| 次引用（删除时释放的引用还原）。
 * 净额为零的哈希无账目（见 txn_ledger_record 聚合）。
 */
static void txn_ledger_apply_rollback(VerthysTxnV3 *t)
{
    for (size_t i = 0; i < t->ext_ref_count; i++) {
        const struct VerthysTxnExtRef *ref = &t->ext_refs[i];

        if (ref->net > 0) {
            for (int64_t k = 0; k < ref->net; k++) {
                (void)verthys_extent_release(t->ext_idx, ref->hash, t->txid, NULL);
            }
        } else if (ref->net < 0) {
            size_t slot = txn_extent_find_slot(t->ext_idx, ref->hash);
            if (slot != SIZE_MAX) {
                VerthysExtent *e = &t->ext_idx->entries[slot];
                uint64_t add = (uint64_t)(-ref->net);
                if ((uint64_t)e->ref_count + add > UINT32_MAX) {
                    e->ref_count = UINT32_MAX;
                } else {
                    e->ref_count += (uint32_t)add;
                }
                e->last_ref_txid = t->txid;
            }
            /* 未命中（理论不可达：删除时条目必在索引）→ 防御性跳过，
             * 引用计数为 GC 建议值，方向安全（只多不少）。 */
        }
    }
}

/* ================== 生命周期 ================== */

VerthysResult verthys_txn_v3_init(VerthysTxnV3 *t, FILE *f, VerthysWal *wal,
                              VerthysSuperBlockV3 *sb, VerthysLsm *lsm,
                              VerthysExtentIndex *ext_idx,
                              VerthysPartition *extent_part,
                              VerthysPartitionTable *ptable,
                              VerthysCngAead *table_aead,
                              const uint8_t integrity_key[VERTHYS_KEY_BYTES])
{
    if (t == NULL || f == NULL || wal == NULL || sb == NULL || lsm == NULL ||
        ext_idx == NULL || extent_part == NULL || ptable == NULL ||
        table_aead == NULL || integrity_key == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    memset(t, 0, sizeof(*t));
    t->f = f;
    t->wal = wal;
    t->sb = sb;
    t->lsm = lsm;
    t->ext_idx = ext_idx;
    t->extent_part = extent_part;
    t->ptable = ptable;
    t->table_aead = table_aead;
    memcpy(t->integrity_key, integrity_key, VERTHYS_KEY_BYTES);
    t->state = VERTHYS_TXN_V3_IDLE;
    return VERTHYS_OK;
}

void verthys_txn_v3_deinit(VerthysTxnV3 *t)
{
    if (t == NULL) return;
    txn_ledger_clear(t);
    verthys_secure_zero(t, sizeof(*t));
}

/* ================== Phase 1 BEGIN ================== */

VerthysResult verthys_txn_v3_begin(VerthysTxnV3 *t)
{
    VerthysWalRecord rec;
    VerthysResult r;

    if (t == NULL) return VERTHYS_ERR_INVALID;
    if (t->state != VERTHYS_TXN_V3_IDLE && t->state != VERTHYS_TXN_V3_CONFIRMED &&
        t->state != VERTHYS_TXN_V3_ABORTED) {
        return VERTHYS_ERR_INVALID;       /* 事务进行中/已提交待确认 */
    }

    memset(&rec, 0, sizeof(rec));
    rec.type = VERTHYS_WAL_REC_BEGIN;
    rec.txid = t->sb->txid + 1;
    rec.u.begin.timestamp = txn_now_unix_ms();

    r = verthys_wal_append(t->wal, &rec);
    if (r != VERTHYS_OK) return r;        /* IDLE 保持，可重试/放弃 */

    t->txid = rec.txid;
    t->lsm_wal_base = verthys_lsm_wal_cursor(t->lsm);
    t->extent_ops = 0;
    t->index_ops = 0;
    t->has_prepare = 0;
    t->persist_done = 0;
    memset(&t->prepare, 0, sizeof(t->prepare));
    txn_ledger_clear(t);                /* 终态复用时弃置残账（防御） */

    verthys_lsm_set_flush_suppress(t->lsm, 1);   /* 未提交条目禁入 SSTable */
    t->state = VERTHYS_TXN_V3_ACTIVE;
    return VERTHYS_OK;
}

/* ================== Phase 2 WRITE_EXTENT ================== */

VerthysResult verthys_txn_v3_write_extent(VerthysTxnV3 *t,
                                      const uint8_t *pt, size_t pt_len,
                                      uint8_t hash_out[VERTHYS_EXTENT_HASH_BYTES],
                                      int *stored)
{
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    VerthysExtent ent;
    VerthysWalRecord rec;
    VerthysResult r;
    int was_stored = 0;

    if (t == NULL) return VERTHYS_ERR_INVALID;
    if (t->state != VERTHYS_TXN_V3_ACTIVE) return VERTHYS_ERR_INVALID;

    r = verthys_extent_put(t->f, t->extent_part, t->ext_idx, t->txid,
                         pt, pt_len, hash, &was_stored);
    if (r != VERTHYS_OK) return r;

    /* 账本：新块创建（ref 0→1）与去重命中（ref++）同为 +1 */
    r = txn_ledger_record(t, hash, +1);
    if (r != VERTHYS_OK) return r;

    /* 索引条目现值（含数据块 nonce——重放重注册必需） */
    r = verthys_extent_index_find(t->ext_idx, hash, &ent);
    if (r != VERTHYS_OK) return r;        /* 刚写入必命中，理论不可达 */

    memset(&rec, 0, sizeof(rec));
    rec.type = VERTHYS_WAL_REC_EXTENT;
    rec.txid = t->txid;
    memcpy(rec.u.extent.hash, ent.hash, VERTHYS_EXTENT_HASH_BYTES);
    rec.u.extent.offset = ent.offset;
    rec.u.extent.size = ent.size;
    rec.u.extent.plaintext_size = ent.plaintext_size;
    memcpy(rec.u.extent.nonce, ent.nonce, VERTHYS_EXTENT_NONCE_BYTES);

    r = verthys_wal_append(t->wal, &rec);
    if (r != VERTHYS_OK) return r;        /* 数据块已落盘：恢复时为孤儿或
                                           由组回放/丢弃裁决（§10.1） */

    if (hash_out != NULL) {
        memcpy(hash_out, hash, VERTHYS_EXTENT_HASH_BYTES);
    }
    if (stored != NULL) {
        *stored = was_stored;
    }
    t->extent_ops++;
    return VERTHYS_OK;
}

/* ================== Phase 3 UPDATE_INDEX / DELETE ================== */

VerthysResult verthys_txn_v3_update_index(VerthysTxnV3 *t, const VerthysLsmEntry *e)
{
    VerthysLsmEntry clean;
    VerthysWalRecord rec;
    VerthysResult r;

    if (t == NULL || e == NULL) return VERTHYS_ERR_INVALID;
    if (t->state != VERTHYS_TXN_V3_ACTIVE) return VERTHYS_ERR_INVALID;
    if (e->name_len > VERTHYS_LSM_NAME_MAX_BYTES) return VERTHYS_ERR_INVALID;
    if (e->name == NULL && e->name_len != 0) return VERTHYS_ERR_INVALID;

    clean = *e;
    clean.tombstone = 0;                /* 删除走 verthys_txn_v3_delete */
    clean.created_txid = t->txid;       /* 事务记账统一置位 */

    r = verthys_lsm_put(t->lsm, t->txid, &clean);
    if (r != VERTHYS_OK) return r;

    memset(&rec, 0, sizeof(rec));
    rec.type = VERTHYS_WAL_REC_INDEX;
    rec.txid = t->txid;
    rec.u.index.entry = clean;          /* name 借用调用方缓冲（同步编码） */

    r = verthys_wal_append(t->wal, &rec);
    if (r != VERTHYS_OK) return r;
    t->index_ops++;
    return VERTHYS_OK;
}

VerthysResult verthys_txn_v3_delete(VerthysTxnV3 *t, uint64_t lid)
{
    VerthysLsmEntry cur;
    uint8_t name_buf[VERTHYS_LSM_NAME_MAX_BYTES];
    VerthysWalRecord rec;
    VerthysResult r;

    if (t == NULL) return VERTHYS_ERR_INVALID;
    if (t->state != VERTHYS_TXN_V3_ACTIVE) return VERTHYS_ERR_INVALID;

    /* 查找现值 → Extent 引用释放（不存在亦写墓碑，LSM 幂等语义） */
    memset(&cur, 0, sizeof(cur));
    r = verthys_lsm_get(t->lsm, lid, &cur, name_buf, sizeof(name_buf), NULL);
    if (r == VERTHYS_OK) {
        r = txn_ledger_record(t, cur.hash, -1);
        if (r != VERTHYS_OK) return r;
        r = verthys_extent_release(t->ext_idx, cur.hash, t->txid, NULL);
        if (r != VERTHYS_OK) return r;
    } else if (r != VERTHYS_ERR_NOTFOUND) {
        return r;
    }

    r = verthys_lsm_delete(t->lsm, t->txid, lid);
    if (r != VERTHYS_OK) return r;

    /* WAL INDEX 记录 = 墓碑条目（与 verthys_lsm_delete 内部构造同形：
     * lid + tombstone + created_txid；重放走 verthys_lsm_delete 等价路径） */
    memset(&rec, 0, sizeof(rec));
    rec.type = VERTHYS_WAL_REC_INDEX;
    rec.txid = t->txid;
    rec.u.index.entry.lid = lid;
    rec.u.index.entry.tombstone = 1;
    rec.u.index.entry.created_txid = t->txid;

    r = verthys_wal_append(t->wal, &rec);
    if (r != VERTHYS_OK) return r;
    t->index_ops++;
    return VERTHYS_OK;
}

/* ================== Phase 4 PREPARE ================== */

/* merkle_root 过渡口径：BLAKE2b-256(哈希按索引序拼接 ‖ u64le(next_offset)) */
static VerthysResult txn_compute_merkle_root(const VerthysExtentIndex *idx,
                                           uint8_t root[VERTHYS_V3_MERKLE_ROOT_BYTES])
{
    size_t len = idx->count * VERTHYS_EXTENT_HASH_BYTES + 8u;
    uint8_t *buf;
    int rc;

    buf = (uint8_t *)malloc(len);
    if (buf == NULL) return VERTHYS_ERR_INTERNAL;
    for (size_t i = 0; i < idx->count; i++) {
        memcpy(buf + i * VERTHYS_EXTENT_HASH_BYTES,
               idx->entries[i].hash, VERTHYS_EXTENT_HASH_BYTES);
    }
    txn_put_u64le(buf + idx->count * VERTHYS_EXTENT_HASH_BYTES,
                  idx->next_offset);
    rc = verthys_generichash(root, buf, len);
    free(buf);
    return (rc == 0) ? VERTHYS_OK : VERTHYS_ERR_INTERNAL;
}

static const VerthysPartition *txn_ptable_find(const VerthysPartitionTable *pt,
                                             VerthysPartitionType type)
{
    for (size_t i = 0; i < pt->count; i++) {
        if (pt->entries[i].type == type) {
            return &pt->entries[i];
        }
    }
    return NULL;
}

VerthysResult verthys_txn_v3_prepare(VerthysTxnV3 *t)
{
    const VerthysPartition *ip, *ap;
    VerthysWalRecord rec;
    VerthysResult r;

    if (t == NULL) return VERTHYS_ERR_INVALID;
    if (t->state != VERTHYS_TXN_V3_ACTIVE) return VERTHYS_ERR_INVALID;

    r = txn_compute_merkle_root(t->ext_idx, t->prepare.merkle_root);
    if (r != VERTHYS_OK) return r;

    /* 分区用量快照（Extent 条目为 ptable 实条目，used 已随写推进） */
    t->prepare.extent_used = t->extent_part->used;
    ip = txn_ptable_find(t->ptable, VERTHYS_PARTITION_INDEX);
    t->prepare.index_used = (ip != NULL) ? ip->used : 0;
    ap = txn_ptable_find(t->ptable, VERTHYS_PARTITION_AUDIT);
    t->prepare.audit_used = (ap != NULL) ? ap->used : 0;

    memset(&rec, 0, sizeof(rec));
    rec.type = VERTHYS_WAL_REC_PREPARE;
    rec.txid = t->txid;
    rec.u.prepare = t->prepare;

    r = verthys_wal_append(t->wal, &rec);
    if (r != VERTHYS_OK) return r;

    t->has_prepare = 1;
    t->state = VERTHYS_TXN_V3_PREPARED;
    return VERTHYS_OK;
}

/* ================== Phase 5 COMMIT ================== */

VerthysResult verthys_txn_v3_commit(VerthysTxnV3 *t)
{
    VsbTxnV3 vtxn;
    VerthysResult r;
    uint64_t need;

    if (t == NULL) return VERTHYS_ERR_INVALID;
    if (t->state != VERTHYS_TXN_V3_PREPARED) return VERTHYS_ERR_INVALID;

    /* ---- 0. Extent 分区扩展决策（§6.4 2x 策略；须在超块候选写入前，
     *        使 sb->extent_partition_size 与分区表一致持久） ---- */
    need = (uint64_t)VERTHYS_EXTENT_INDEX_REGION_BYTES + t->ext_idx->next_offset;
    if (need > t->extent_part->size) {
        r = verthys_partition_grow(t->extent_part, need - t->extent_part->size);
        if (r != VERTHYS_OK) return r;
        t->sb->extent_partition_size = t->extent_part->size;
    }

    /* ---- 1/2. 超块候选字段 + 法定人数提交（vsb_txn 备份保护） ---- */
    r = vsb_txn_v3_begin(&vtxn, t->sb);     /* 失败内存回滚基准 */
    if (r != VERTHYS_OK) return r;

    t->sb->txid = t->txid;
    t->sb->updated_at = txn_now_filetime();
    t->sb->wal_head_offset = verthys_wal_head_offset(t->wal);
    t->sb->wal_tail_offset = verthys_wal_tail_offset(t->wal);
    memcpy(t->sb->merkle_root, t->prepare.merkle_root, VERTHYS_V3_MERKLE_ROOT_BYTES);
    /* wal_committed_txid 不在此推进（见文件头水位语义注记） */

    r = vsb_txn_v3_commit(&vtxn, t->sb, t->f, t->integrity_key);
    if (r != VERTHYS_OK) {
        (void)vsb_txn_v3_rollback(&vtxn, t->sb);   /* 内存态还原 */
        return r;                           /* 组无 COMMIT：恢复按未提交丢弃 */
    }

    /* 法定人数已持久含 txid：此后失败 ≡ 该点崩溃（恢复重放收尾），
     * 状态先行 COMMITTED——回滚通道永久关闭（数据已提交）。 */
    t->state = VERTHYS_TXN_V3_COMMITTED;

    /* ---- 3. Extent 索引持久化 ---- */
    t->ext_idx->txid = t->txid;
    r = verthys_extent_index_save(t->f, t->extent_part->offset,
                                t->ext_idx, t->extent_part);
    if (r != VERTHYS_OK) return r;

    /* ---- 4. 分区表持久化 ---- */
    t->ptable->txid = t->txid;
    r = verthys_partition_table_save(t->f, VERTHYS_V3_PARTITION_TABLE_OFFSET,
                                   t->ptable, t->table_aead);
    if (r != VERTHYS_OK) return r;
    t->persist_done = 1;

    /* ---- 5. WAL COMMIT 记录（法定人数成功之后落笔，§10.1 规则 4 锚点） ---- */
    {
        VerthysWalRecord rec;
        memset(&rec, 0, sizeof(rec));
        rec.type = VERTHYS_WAL_REC_COMMIT;
        rec.txid = t->txid;
        rec.u.commit.timestamp = txn_now_unix_ms();
        r = verthys_wal_append(t->wal, &rec);
        if (r != VERTHYS_OK) return r;    /* 组 PREPARE-only + sb_txid ≥ txid：
                                           恢复按规则 5 重放收尾 */
    }

    /* ---- 6. 解除 flush 抑制 + 达阈值 flush（失败不影响提交语义） ---- */
    txn_ledger_clear(t);                /* 已提交：引用账本使命完成 */
    verthys_lsm_set_flush_suppress(t->lsm, 0);
    if (verthys_lsm_memtable_count(t->lsm) >= VERTHYS_LSM_MEMTABLE_MAX_ENTRIES) {
        (void)verthys_lsm_flush(t->lsm);  /* 持久化优化，put/close 重试 */
    }
    return VERTHYS_OK;
}

/* ================== Phase 6 CONFIRM ================== */

VerthysResult verthys_txn_v3_confirm(VerthysTxnV3 *t)
{
    VerthysSuperBlockV3 disk_sb;
    VerthysResult r;

    if (t == NULL) return VERTHYS_ERR_INVALID;
    if (t->state != VERTHYS_TXN_V3_COMMITTED) return VERTHYS_ERR_INVALID;

    /* 1. 法定人数读回验证 txid */
    memset(&disk_sb, 0, sizeof(disk_sb));
    r = vsb_v3_read_quorum(t->f, t->integrity_key, &disk_sb, NULL);
    if (r != VERTHYS_OK) return r;
    if (disk_sb.txid != t->txid) return VERTHYS_ERR_CORRUPT;

    /* 2. Extent 抽样解密 + 内容哈希校验（1 条：最新写入块；无条目跳过） */
    if (t->ext_idx->count > 0) {
        const VerthysExtent *e = &t->ext_idx->entries[t->ext_idx->count - 1];
        uint8_t *pt = (uint8_t *)malloc(e->plaintext_size == 0
                                        ? 1u : e->plaintext_size);
        size_t pt_len = e->plaintext_size;
        if (pt == NULL) return VERTHYS_ERR_INTERNAL;
        r = verthys_extent_get(t->f, t->extent_part, t->ext_idx, e->hash,
                             pt, &pt_len);
        verthys_secure_zero(pt, pt_len);
        free(pt);
        if (r != VERTHYS_OK) return r;    /* AUTH/CORRUPT 透传（读路径校验） */
    }

    /* 3. 幂等补存：COMMIT 步骤 3/4 失败后直达 CONFIRM 的兜底
     *    （内容不变重写，WAL 复位前补齐索引/分区表盘面快照）。 */
    if (!t->persist_done) {
        r = verthys_extent_index_save(t->f, t->extent_part->offset,
                                    t->ext_idx, t->extent_part);
        if (r != VERTHYS_OK) return r;
        r = verthys_partition_table_save(t->f, VERTHYS_V3_PARTITION_TABLE_OFFSET,
                                       t->ptable, t->table_aead);
        if (r != VERTHYS_OK) return r;
        t->persist_done = 1;
    }

    /* 4. WAL 截断复位（此后盘面无任何可回放记录） */
    r = verthys_wal_reset(t->wal);
    if (r != VERTHYS_OK) return r;

    t->state = VERTHYS_TXN_V3_CONFIRMED;
    return VERTHYS_OK;
}

/* ================== 运行时回滚 ================== */

VerthysResult verthys_txn_v3_rollback(VerthysTxnV3 *t)
{
    VerthysResult r;

    if (t == NULL) return VERTHYS_ERR_INVALID;
    if (t->state != VERTHYS_TXN_V3_ACTIVE && t->state != VERTHYS_TXN_V3_PREPARED) {
        return VERTHYS_ERR_INVALID;       /* COMMIT 后不可回滚（法定人数已持久） */
    }

    /* 1. LSM 精确撤销：WAL 截断至 BEGIN 快照 + MemTable 重放重建
     *    （flush 抑制纪律保证条目仅在 MemTable 与 LSM WAL 尾部；
     *    本事务墓碑覆写的原始条目经重放复原，★ WP-12 缺陷②）。 */
    r = verthys_lsm_rollback_txid(t->lsm, t->txid, t->lsm_wal_base);
    if (r != VERTHYS_OK) {
        /* 撤销失败（IO/游标回绕）：状态保持，调用方可重试；
         * 不切换 ABORTED——半撤销态下重试是唯一一致路径。 */
        return r;
    }

    /* 2. Extent 引用净额还原（本事务新建块 → ref 0，孤儿块交 GC）。
     *    账本先弃置再复位 WAL：复位失败的重试路径不得二次反向调整。 */
    txn_ledger_apply_rollback(t);
    txn_ledger_clear(t);

    /* 3. 事务 WAL 复位（★ WP-12 属性测试发现的复活窗口修复）：
     *    回滚组的 BEGIN/EXTENT/INDEX 帧若残留 WAL，且 begin 复用
     *    txid = sb->txid + 1 —— 后续同 txid 组 COMMIT 后、CONFIRM
     *    复位前崩溃，重放按"txid 变更才开新组"合并两组，废弃记录
     *    被复活（违反回滚耐久性契约：已向调用方返回失败的操作在
     *    崩溃恢复后不得可见）。此处全量复位安全：回滚时刻 WAL 内
     *    不可能存在未决已提交组（COMMITTED 阻塞 begin；abort 对
     *    COMMITTED 走 confirm 补收尾；confirm/recover 均以复位收口），
     *    在册帧全部为同 txid 废弃帧（本组 + 此前累积回滚组）。
     *    失败保持原状态可重试：LSM 截断与引用还原均已生效且幂等
     *    （重试仅重复 WAL 复位），账本已清零不会二次调整。 */
    r = verthys_wal_reset(t->wal);
    if (r != VERTHYS_OK) return r;

    /* 4. 解除 flush 抑制。 */
    verthys_lsm_set_flush_suppress(t->lsm, 0);

    t->state = VERTHYS_TXN_V3_ABORTED;
    return VERTHYS_OK;
}

/* ================== 崩溃恢复 ================== */

typedef struct TxnRecoverCtx {
    VerthysTxnV3 *t;
    uint64_t committed_txid;    /* 超块已提交确认水位（规则 3 组勿剔除） */
    int has_replay;             /* 存在重放组 */
    /* 未提交（规则 6）丢弃组 txid 收集：组内 txid 连续，变更即新组 */
    uint64_t *discard_txids;
    size_t   discard_count, discard_cap;
    uint64_t last_discard_txid;
} TxnRecoverCtx;

/* 重放组回调：EXTENT 幂等重注册 + INDEX 重放 LSM（§10.1 redrive） */
static VerthysResult txn_recover_replay_cb(void *user, const VerthysWalRecord *rec)
{
    TxnRecoverCtx *c = (TxnRecoverCtx *)user;
    VerthysTxnV3 *t = c->t;
    VerthysResult r;

    switch (rec->type) {
    case VERTHYS_WAL_REC_BEGIN:
    case VERTHYS_WAL_REC_COMMIT:
        break;                                  /* 簿记记录：无副作用 */

    case VERTHYS_WAL_REC_EXTENT: {
        size_t slot = txn_extent_find_slot(t->ext_idx, rec->u.extent.hash);
        if (slot != SIZE_MAX) {
            /* 命中 → ref_count++（方向安全：只多不少；崩溃点晚于索引
             * 落盘时计数偏大，空间泄漏换数据安全，GC 周期收敛） */
            VerthysExtent *e = &t->ext_idx->entries[slot];
            if (e->ref_count < UINT32_MAX) e->ref_count++;
            e->last_ref_txid = rec->txid;
        } else {
            /* 缺失（崩溃点早于索引落盘）→ 补注册（nonce 随记录重放） */
            VerthysExtent *e;
            if (t->ext_idx->count >= VERTHYS_EXTENT_INDEX_MAX) {
                return VERTHYS_ERR_RESOURCE_LIMIT;
            }
            e = &t->ext_idx->entries[t->ext_idx->count];
            memset(e, 0, sizeof(*e));
            memcpy(e->hash, rec->u.extent.hash, VERTHYS_EXTENT_HASH_BYTES);
            memcpy(e->nonce, rec->u.extent.nonce, VERTHYS_EXTENT_NONCE_BYTES);
            e->offset = rec->u.extent.offset;
            e->size = rec->u.extent.size;
            e->plaintext_size = rec->u.extent.plaintext_size;
            e->ref_count = 1;
            e->created_txid = rec->txid;
            e->last_ref_txid = rec->txid;
            t->ext_idx->count++;
        }
        /* next_offset 重算：覆盖一切可见条目的数据区游标下限 */
        {
            uint64_t end = rec->u.extent.offset + rec->u.extent.size;
            if (end > t->ext_idx->next_offset) {
                t->ext_idx->next_offset = end;
            }
        }
        break;
    }

    case VERTHYS_WAL_REC_INDEX: {
        const VerthysLsmEntry *e = &rec->u.index.entry;
        /* 墓碑经 delete 内部通道（put 强制清墓碑标志的对策）；
         * entry.name 指向记录内联缓冲，回调内同步消费有效 */
        if (e->tombstone) {
            r = verthys_lsm_delete(t->lsm, rec->txid, e->lid);
        } else {
            r = verthys_lsm_put(t->lsm, rec->txid, e);
        }
        if (r != VERTHYS_OK) return r;
        break;
    }

    case VERTHYS_WAL_REC_PREPARE:
        break;      /* 候选快照：超块盘面为权威（法定人数已含 merkle_root） */

    default:
        return VERTHYS_ERR_FORMAT;
    }
    c->has_replay = 1;
    return VERTHYS_OK;
}

/* 丢弃组回调：未提交组收集 txid → MemTable 剔除；
 * 已提交确认组（规则 3）条目合法，勿剔除。 */
static VerthysResult txn_recover_discard_cb(void *user, const VerthysWalRecord *rec)
{
    TxnRecoverCtx *c = (TxnRecoverCtx *)user;

    if (rec->txid == 0 || rec->txid <= c->committed_txid) {
        return VERTHYS_OK;                /* 已提交确认水位内：合法数据 */
    }
    if (c->discard_count > 0 && c->last_discard_txid == rec->txid) {
        return VERTHYS_OK;                /* 同组续记录 */
    }
    if (c->discard_count == c->discard_cap) {
        size_t ncap = c->discard_cap == 0 ? 4u : c->discard_cap * 2u;
        uint64_t *na = (uint64_t *)realloc(c->discard_txids,
                                           ncap * sizeof(*na));
        if (na == NULL) return VERTHYS_ERR_INTERNAL;
        c->discard_txids = na;
        c->discard_cap = ncap;
    }
    c->discard_txids[c->discard_count++] = rec->txid;
    c->last_discard_txid = rec->txid;
    return VERTHYS_OK;
}

VerthysResult verthys_txn_v3_recover(VerthysTxnV3 *t,
                                 uint64_t *out_replayed,
                                 uint64_t *out_discarded)
{
    TxnRecoverCtx c;
    uint64_t replayed = 0, discarded = 0;
    VerthysResult r;

    if (t == NULL) return VERTHYS_ERR_INVALID;
    if (t->state != VERTHYS_TXN_V3_IDLE) return VERTHYS_ERR_INVALID;

    memset(&c, 0, sizeof(c));
    c.t = t;
    c.committed_txid = t->sb->wal_committed_txid;

    /* 抑制自动 flush：重放/剔除期间 MemTable 不得部分持久化 */
    verthys_lsm_set_flush_suppress(t->lsm, 1);

    r = verthys_wal_replay_ex(t->wal, t->sb->wal_committed_txid, t->sb->txid,
                            txn_recover_replay_cb, &c,
                            txn_recover_discard_cb, &c,
                            NULL, &replayed, &discarded);
    if (r == VERTHYS_OK && c.discard_count > 0) {
        /* 丢弃组（未提交）过滤重放重建（★ WP-12 缺陷②b）：跳过丢弃组
         * 帧，被其墓碑覆写的已提交原始条目经重放复原（过滤式剔除将
         * 连同墓碑一起丢失被覆写条目 → 已提交数据丢失，红线级）。 */
        r = verthys_lsm_rebuild_excluding(t->lsm, c.discard_txids,
                                        c.discard_count);
    }
    if (r == VERTHYS_OK && c.has_replay) {
        /* next_offset 已随 EXTENT 重注册维护；
         * Extent 分区 used 下限推定（索引区 + 数据区游标）。 */
        {
            uint64_t used_floor = (uint64_t)VERTHYS_EXTENT_INDEX_REGION_BYTES +
                                  t->ext_idx->next_offset;
            if (used_floor > t->extent_part->used) {
                t->extent_part->used = used_floor;
            }
        }
        t->ext_idx->txid = t->sb->txid;
        r = verthys_extent_index_save(t->f, t->extent_part->offset,
                                    t->ext_idx, t->extent_part);
    }
    if (r == VERTHYS_OK && c.has_replay) {
        t->ptable->txid = t->sb->txid;
        r = verthys_partition_table_save(t->f, VERTHYS_V3_PARTITION_TABLE_OFFSET,
                                       t->ptable, t->table_aead);
    }
    if (r == VERTHYS_OK && c.has_replay) {
        /* 水位推进（正常路径外的唯一一处）：恢复收尾后组使命完成 */
        t->sb->wal_committed_txid = t->sb->txid;
        r = vsb_v3_commit_quorum(t->f, t->sb, t->integrity_key);
    }
    if (r == VERTHYS_OK) {
        if (verthys_lsm_memtable_count(t->lsm) > 0) {
            r = verthys_lsm_flush(t->lsm);    /* 恢复后持久快照 + LSM WAL 复位 */
        } else if (c.discard_count > 0 &&
                   verthys_lsm_wal_cursor(t->lsm) > 0) {
            /* MemTable 空 + LSM WAL 有帧：全部帧属丢弃组（重放条目
             * 必在 MemTable，空表 ⟹ 无重放条目 ⟹ 帧皆未提交）。
             * rollback_txid(base=0) 截断整条 LSM WAL（帧头失效化）+
             * 幂等剔除——否则残留帧重开复活未提交条目。 */
            r = verthys_lsm_rollback_txid(t->lsm, c.discard_txids[0], 0);
        }
    }

    verthys_lsm_set_flush_suppress(t->lsm, 0);
    if (r == VERTHYS_OK) {
        r = verthys_wal_reset(t->wal);        /* 盘面无任何可回放记录 */
    }

    free(c.discard_txids);
    if (r != VERTHYS_OK) return r;            /* 幂等可重试：重放方向安全 */

    if (out_replayed != NULL) *out_replayed = replayed;
    if (out_discarded != NULL) *out_discarded = discarded;
    return VERTHYS_OK;
}

/* ================== 查询 ================== */

uint64_t verthys_txn_v3_txid(const VerthysTxnV3 *t)
{
    return (t != NULL) ? t->txid : 0;
}

VerthysTxnV3State verthys_txn_v3_state(const VerthysTxnV3 *t)
{
    return (t != NULL) ? t->state : VERTHYS_TXN_V3_IDLE;
}
