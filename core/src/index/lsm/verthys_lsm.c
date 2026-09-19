/*
 * verthys_lsm.c — V3 LSM 索引主模块：生命周期 / WAL / Manifest / 数据路径
 *
 * LSM 区域布局（region_offset 基准）：
 *   [Manifest 帧区 1MB][WAL 区 68MB][SSTable 数据区 append-only]
 *
 * WAL（Write-Ahead Log）：
 *   - 帧格式同分区帧惯例：[u32 'V3LW'][u32 ct_len][AEAD 密文][12B nonce]，
 *     明文 = 单条条目编码（78B 头 + name），AAD = "verthys/lsm-wal-v3"；
 *   - put/delete 先追加 WAL 帧再插入 MemTable（WAL 先行）；
 *   - flush 持久化 SSTable + Manifest 提交后 WAL 复位（游标归零 +
 *     首帧头清零失效化，杜绝复位后旧帧重放）；
 *   - 崩溃恢复：open 时顺序重放，撕裂尾部帧（解密/结构失败）静默截断。
 *
 * Manifest（LSM 元数据，帧区整帧覆写）：
 *   - 明文 = LSMManifestV3（schema/sstable.fbs）；
 *   - nonce 快照采用"保存后值"约定（区别于 extent 的保存前值）：
 *     序列化时取分区计数器 + 1 = 保存帧自身消耗的计数器值；重载
 *     restore 后下一次加密绝不复用保存帧 nonce（红线级防重用）；
 *   - open 重放后计数器下限推定：max(当前值, 盘面快照 + WAL 重放帧数
 *     + 安全裕量)——WAL 帧在保存后各自消耗一个 nonce，撕裂帧亦可能
 *     已消耗，裕量覆盖。
 *
 * 并发纪律：
 *   - put/delete/flush/compact/open/close 持 SRWLOCK 独占（单写者）；
 *   - get 持独占而非共享：SSTable 元数据惰性加载（Footer/Bloom/块索引）
 *     会修改 Manifest 内存态，SRWLOCK 共享模式下并发惰性初始化存在
 *     数据竞争；FFI 单线程纪律下独占读取与读者快照语义等价（无并发
 *     读者），结构上仍沿用同一 SRWLOCK 互斥模式。
 *
 * 后台 compaction 线程（enable_bg=1）：
 *   - BELOW_NORMAL 优先级；空闲触发（CPU < 30%，GetSystemTimes 采样）；
 *   - 单次运行 ≤ 64MB（verthys_lsm_compaction.c）；
 *   - 关停：原子标志 + WaitForSingleObject 汇合（close 路径）。
 */
#include "sstable_builder.h"
#include "sstable_verifier.h"
#include "sstable_reader.h"

#include "verthys_lsm_internal.h"
#include "verthys_internal.h"     /* verthys_secure_zero */

#include <io.h>                 /* _commit / _fileno */
#include <stdlib.h>
#include <string.h>

/* nonce 恢复安全裕量（覆盖撕裂帧已消耗但不可数的 nonce） */
#define VERTHYS_LSM_NONCE_RESTORE_MARGIN 64u

/* 后台线程空闲采样/轮询间隔 */
#define VERTHYS_LSM_BG_POLL_MS 1000u

/* ================== 小端读写 ================== */

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

static void put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
}

/* ================== Manifest 持久化 ================== */

/*
 * Manifest FlatBuffer 明文序列化（帧写入共用路径）。
 * nonce 快照 = 当前计数器 + 1（保存后值约定，同 manifest_save 注释）。
 * 产物为 flatcc 对齐缓冲——调用方须 flatcc_builder_aligned_free 归还。
 */
static VerthysResult manifest_serialize_pt(const VerthysLsmManifest *m,
                                         const VerthysPartition *part,
                                         uint8_t **out_pt, size_t *out_len)
{
    flatcc_builder_t builder;
    uint8_t *pt = NULL;
    size_t pt_len = 0;
    int build_ok = 0;
    uint64_t nonce_snapshot = verthys_cng_aead_nonce_counter(&part->aead) + 1u;

    if (m == NULL || part == NULL || out_pt == NULL || out_len == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (m->count > VERTHYS_LSM_MAX_TABLES) return VERTHYS_ERR_INVALID;

    if (flatcc_builder_init(&builder) != 0) return VERTHYS_ERR_INTERNAL;
    do {
        if (LSMManifestV3_start_as_root(&builder) != 0) break;
        if (LSMManifestV3_magic_add(&builder, VERTHYS_LSM_MANIFEST_MAGIC) != 0) break;
        if (LSMManifestV3_version_add(&builder, VERTHYS_LSM_VERSION) != 0) break;
        if (LSMManifestV3_txid_add(&builder, m->txid) != 0) break;
        if (LSMManifestV3_next_seq_add(&builder, m->next_seq) != 0) break;
        if (LSMManifestV3_next_data_offset_add(&builder, m->next_data_offset) != 0) break;
        if (LSMManifestV3_nonce_counter_add(&builder, nonce_snapshot) != 0) break;

        if (m->count != 0) {
            int vec_ok = 1;
            if (LSMTableMetaV3_vec_start(&builder) != 0) break;
            for (size_t i = 0; i < m->count; i++) {
                const VerthysLsmTableMeta *t = &m->tables[i];
                LSMTableMetaV3_ref_t ref;
                if (LSMTableMetaV3_start(&builder) != 0) { vec_ok = 0; break; }
                if (LSMTableMetaV3_seq_add(&builder, t->seq) != 0 ||
                    LSMTableMetaV3_level_add(&builder, t->level) != 0 ||
                    LSMTableMetaV3_offset_add(&builder, t->offset) != 0 ||
                    LSMTableMetaV3_size_add(&builder, t->size) != 0 ||
                    LSMTableMetaV3_entry_count_add(&builder, t->entry_count) != 0 ||
                    LSMTableMetaV3_tombstone_count_add(&builder, t->tombstone_count) != 0 ||
                    LSMTableMetaV3_min_key_add(&builder, t->min_key) != 0 ||
                    LSMTableMetaV3_max_key_add(&builder, t->max_key) != 0 ||
                    LSMTableMetaV3_created_txid_add(&builder, t->created_txid) != 0) {
                    vec_ok = 0;
                    break;
                }
                ref = LSMTableMetaV3_end(&builder);
                if (ref == 0 || LSMTableMetaV3_vec_push(&builder, ref) == NULL) {
                    vec_ok = 0;
                    break;
                }
            }
            if (!vec_ok) break;
            {
                LSMTableMetaV3_vec_ref_t vec = LSMTableMetaV3_vec_end(&builder);
                if (vec == 0 || LSMManifestV3_tables_add(&builder, vec) != 0) break;
            }
        }

        if (LSMManifestV3_end_as_root(&builder) == 0) break;
        pt = flatcc_builder_finalize_aligned_buffer(&builder, &pt_len);
        if (pt == NULL || pt_len == 0) break;
        build_ok = 1;
    } while (0);

    flatcc_builder_clear(&builder);
    if (!build_ok) {
        if (pt != NULL) flatcc_builder_aligned_free(pt);
        return VERTHYS_ERR_INTERNAL;
    }
    *out_pt = pt;
    *out_len = pt_len;
    return VERTHYS_OK;
}

VerthysResult verthys_lsm_manifest_save(FILE *f, uint64_t region_offset,
                                    const VerthysLsmManifest *m,
                                    VerthysPartition *part)
{
    VerthysResult r;
    uint8_t *pt = NULL;
    size_t pt_len = 0;

    if (f == NULL || part == NULL) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(&part->aead)) return VERTHYS_ERR_LOCKED;

    /* ★保存后值约定：序列化快照 = 当前计数器 + 1（保存帧自身消耗值）；
     * restore 后下一次加密为快照 +1，绝不复用保存帧 nonce。 */
    r = manifest_serialize_pt(m, part, &pt, &pt_len);
    if (r != VERTHYS_OK) return r;

    r = verthys_lsm_frame_write(f, region_offset, VERTHYS_LSM_MANIFEST_MAGIC,
                              &part->aead,
                              (const uint8_t *)VERTHYS_LSM_AAD_MANIFEST,
                              strlen(VERTHYS_LSM_AAD_MANIFEST),
                              pt, pt_len, NULL);
    flatcc_builder_aligned_free(pt);
    if (r != VERTHYS_OK) return r;

    /* 物理落盘（Manifest 是提交点，必须先于后续数据引用持久化） */
    if (fflush(f) != 0 || _commit(_fileno(f)) != 0) return VERTHYS_ERR_IO;
    return VERTHYS_OK;
}

/* Manifest 表排序比较：level 升序，同层 seq 降序（L0 新→旧优先查找） */
static int table_meta_before(const VerthysLsmTableMeta *a,
                             const VerthysLsmTableMeta *b)
{
    if (a->level != b->level) return a->level < b->level;
    return a->seq > b->seq;
}

/* 有序插入（查找序维护；容量满返回 -1）。compaction 模块共用 → 非 static */
int manifest_insert_sorted(VerthysLsmManifest *m,
                           const VerthysLsmTableMeta *t)
{
    size_t pos;
    if (m->count >= VERTHYS_LSM_MAX_TABLES) return -1;
    for (pos = 0; pos < m->count; pos++) {
        if (table_meta_before(t, &m->tables[pos])) break;
    }
    memmove(&m->tables[pos + 1], &m->tables[pos],
            (m->count - pos) * sizeof(m->tables[0]));
    m->tables[pos] = *t;
    m->count++;
    return 0;
}

/*
 * Manifest 明文帧纯缓冲解析（对齐 vsb_v3_parse_unverified
 * 分层模式）：flatcc verifier → magic/version → 字段提取 → 逐表元数据边界
 * 校验（level < MAX_LEVELS、size 非零、min_key ≤ max_key）→ 有序重建 m
 * （含 nonce_snapshot 回填）。不含 CNG restore——计数器回推依赖分区句柄，
 * 由 manifest_parse_pt 在解析成功后执行，与解析层解耦。
 * 安全边界：产物不构成信任输入——生产路径仅在 AEAD 认证通过后调用。
 * 失败时逐表释放惰性缓存并清零 *m。
 */
VerthysResult verthys_lsm_manifest_parse_unverified(const uint8_t *pt, size_t pt_len,
                                                VerthysLsmManifest *m)
{
    VerthysResult r;
    LSMManifestV3_table_t t;
    LSMTableMetaV3_vec_t vec;
    size_t count, i;

    if (pt == NULL || pt_len == 0 || m == NULL) {
        return VERTHYS_ERR_INVALID;
    }

    memset(m, 0, sizeof(*m));

    /* ★ r 须先置 OK——内层表循环全部成功时不设置 r，
     * 若未初始化，"if (r != VERTHYS_OK) break" 将读栈残留垃圾值，
     * 导致正常 Manifest 被误判失败（reopen 概率性返回垃圾错误码）。 */
    r = VERTHYS_OK;

    do {
        if (LSMManifestV3_verify_as_root(pt, pt_len) != flatcc_verify_ok) {
            r = VERTHYS_ERR_FORMAT;
            break;
        }
        t = LSMManifestV3_as_root(pt);
        if (t == NULL ||
            LSMManifestV3_magic(t) != VERTHYS_LSM_MANIFEST_MAGIC ||
            LSMManifestV3_version(t) != VERTHYS_LSM_VERSION) {
            r = VERTHYS_ERR_FORMAT;
            break;
        }

        m->txid = LSMManifestV3_txid(t);
        m->next_seq = LSMManifestV3_next_seq(t);
        m->next_data_offset = LSMManifestV3_next_data_offset(t);
        m->nonce_snapshot = LSMManifestV3_nonce_counter(t);

        vec = LSMManifestV3_tables(t);
        count = (vec == NULL) ? 0 : LSMTableMetaV3_vec_len(vec);
        if (count > VERTHYS_LSM_MAX_TABLES) {
            r = VERTHYS_ERR_FORMAT;
            break;
        }
        for (i = 0; i < count; i++) {
            LSMTableMetaV3_table_t mt = LSMTableMetaV3_vec_at(vec, i);
            VerthysLsmTableMeta tm;
            if (mt == NULL) {
                r = VERTHYS_ERR_FORMAT;
                break;
            }
            memset(&tm, 0, sizeof(tm));
            tm.seq = LSMTableMetaV3_seq(mt);
            tm.level = LSMTableMetaV3_level(mt);
            tm.offset = LSMTableMetaV3_offset(mt);
            tm.size = LSMTableMetaV3_size(mt);
            tm.entry_count = LSMTableMetaV3_entry_count(mt);
            tm.tombstone_count = LSMTableMetaV3_tombstone_count(mt);
            tm.min_key = LSMTableMetaV3_min_key(mt);
            tm.max_key = LSMTableMetaV3_max_key(mt);
            tm.created_txid = LSMTableMetaV3_created_txid(mt);
            if (tm.level >= VERTHYS_LSM_MAX_LEVELS || tm.size == 0 ||
                tm.min_key > tm.max_key) {
                r = VERTHYS_ERR_FORMAT;
                break;
            }
            if (manifest_insert_sorted(m, &tm) != 0) {
                r = VERTHYS_ERR_FORMAT;
                break;
            }
        }
    } while (0);

    if (r != VERTHYS_OK) {
        for (size_t j = 0; j < m->count; j++) {
            verthys_lsm_sstable_meta_release(&m->tables[j]);
        }
        memset(m, 0, sizeof(*m));
    }
    return r;
}

/*
 * Manifest 明文帧解析 + nonce 计数器 restore
 * （快照 > 当前值才前推，防回退语义保留）。失败时 *m 清零。
 */
static VerthysResult manifest_parse_pt(const uint8_t *pt, size_t pt_len,
                                     VerthysPartition *part,
                                     VerthysLsmManifest *m)
{
    VerthysResult r;

    if (pt == NULL || pt_len == 0 || part == NULL || m == NULL) {
        return VERTHYS_ERR_INVALID;
    }

    r = verthys_lsm_manifest_parse_unverified(pt, pt_len, m);
    if (r != VERTHYS_OK) {
        return r;
    }

    if (m->nonce_snapshot > verthys_cng_aead_nonce_counter(&part->aead)) {
        if (verthys_cng_aead_restore_nonce_counter(&part->aead,
                                                 m->nonce_snapshot) != VERTHYS_OK) {
            for (size_t j = 0; j < m->count; j++) {
                verthys_lsm_sstable_meta_release(&m->tables[j]);
            }
            memset(m, 0, sizeof(*m));
            return VERTHYS_ERR_INTERNAL;
        }
    }
    return VERTHYS_OK;
}

VerthysResult verthys_lsm_manifest_load(FILE *f, uint64_t region_offset,
                                    VerthysPartition *part,
                                    VerthysLsmManifest *m)
{
    VerthysResult r;
    uint8_t *pt = NULL;
    size_t pt_len = 0;

    if (f == NULL || part == NULL || m == NULL) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(&part->aead)) return VERTHYS_ERR_LOCKED;

    r = verthys_lsm_frame_read_decrypt(f, region_offset, VERTHYS_LSM_MANIFEST_MAGIC,
                                     &part->aead,
                                     (const uint8_t *)VERTHYS_LSM_AAD_MANIFEST,
                                     strlen(VERTHYS_LSM_AAD_MANIFEST),
                                     VERTHYS_LSM_MANIFEST_REGION_BYTES,
                                     &pt, &pt_len, NULL);
    if (r != VERTHYS_OK) {
        return (r == VERTHYS_ERR_FORMAT) ? VERTHYS_ERR_FORMAT : r;
    }

    r = manifest_parse_pt(pt, pt_len, part, m);
    verthys_secure_zero(pt, pt_len);
    free(pt);
    return r;
}

/* ================== WAL ================== */

/*
 * WAL 帧追加：WAL 先行（先于 MemTable 插入）。
 * 仅 fflush（进程崩溃可恢复）；_commit 留给 flush/Manifest 提交边界。
 */
static VerthysResult wal_append(VerthysLsm *lsm, const VerthysLsmEntry *e)
{
    uint8_t pt[VERTHYS_LSM_ENTRY_HEADER_BYTES + VERTHYS_LSM_NAME_MAX_BYTES];
    size_t pt_len = verthys_lsm_entry_encoded_len(e);
    uint32_t frame_len = 0;
    VerthysResult r;

    if (pt_len == 0 || pt_len > sizeof(pt)) return VERTHYS_ERR_INVALID;
    if (verthys_lsm_entry_encode(pt, sizeof(pt), e) != 0) return VERTHYS_ERR_INTERNAL;

    /* 容量校验（WAL 区 68MB > MemTable 64MB 上限 + 帧开销） */
    if (lsm->wal_cursor + VERTHYS_LSM_FRAME_HEADER_BYTES + pt_len +
            VERTHYS_CNG_TAG_BYTES + VERTHYS_LSM_FRAME_TAIL_BYTES >
        VERTHYS_LSM_WAL_REGION_BYTES) {
        return VERTHYS_ERR_RESOURCE_LIMIT;
    }

    r = verthys_lsm_frame_write(lsm->f, lsm->wal_region_offset + lsm->wal_cursor,
                              VERTHYS_LSM_WAL_MAGIC, &lsm->part->aead,
                              (const uint8_t *)VERTHYS_LSM_AAD_WAL,
                              strlen(VERTHYS_LSM_AAD_WAL),
                              pt, pt_len, &frame_len);
    if (r != VERTHYS_OK) return r;
    if (fflush(lsm->f) != 0) return VERTHYS_ERR_IO;

    lsm->wal_cursor += frame_len;
    return VERTHYS_OK;
}

/*
 * WAL 复位：游标归零 + 首帧头 8B 清零（旧帧失效化——杜绝复位后
 * 旧帧被下一次 open 重放）+ _commit（提交边界）。
 */
static VerthysResult wal_reset(VerthysLsm *lsm)
{
    static const uint8_t zeros[VERTHYS_LSM_FRAME_HEADER_BYTES] = {0};

    lsm->wal_cursor = 0;
    if (vio_pwrite64(lsm->f, lsm->wal_region_offset, zeros, sizeof(zeros)) != 0) {
        return VERTHYS_ERR_IO;
    }
    if (fflush(lsm->f) != 0 || _commit(_fileno(lsm->f)) != 0) {
        return VERTHYS_ERR_IO;
    }
    return VERTHYS_OK;
}

/*
 * WAL 重放（崩溃恢复 / 回滚重建共用）：
 *   自偏移 0 顺序解帧 → 条目插入 MemTable → 撕裂尾部（读取短/结构/
 *   解密失败）静默截断（wal_cursor 停在最后有效帧尾）。
 * exclude_txids（非 NULL 时）：跳过 created_txid 命中列表的帧（条目
 *   不入 MemTable，游标照常推进）——崩溃恢复丢弃组过滤重建用：跳过
 *   未提交组的写入/墓碑帧，保留更早的已提交原始帧。
 * 返回重放帧数（*frames_out，含跳过帧），错误仅限 MemTable 插入失败
 * （INTERNAL）。
 */
static VerthysResult wal_replay_impl(VerthysLsm *lsm, uint64_t *frames_out,
                                   const uint64_t *exclude_txids,
                                   size_t exclude_count)
{
    uint64_t cursor = 0;
    uint64_t frames = 0;

    *frames_out = 0;
    for (;;) {
        uint8_t header[VERTHYS_LSM_FRAME_HEADER_BYTES];
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        uint32_t frame_len = 0;
        VerthysLsmEntry e;
        size_t used;
        int excluded = 0;
        VerthysResult r;

        if (vio_pread64(lsm->f, lsm->wal_region_offset + cursor,
                        header, sizeof(header)) != 0) {
            break;      /* 区尾/短读：正常终止 */
        }
        if (get_u32le(header) != VERTHYS_LSM_WAL_MAGIC) break;   /* 旧帧失效化标记 */
        {
            uint32_t ct_len = get_u32le(header + 4);
            if (ct_len < VERTHYS_CNG_TAG_BYTES ||
                ct_len > VERTHYS_LSM_ENTRY_HEADER_BYTES +
                         VERTHYS_LSM_NAME_MAX_BYTES + VERTHYS_CNG_TAG_BYTES) {
                break;  /* 结构非法：撕裂尾部 */
            }
        }

        r = verthys_lsm_frame_read_decrypt(
                lsm->f, lsm->wal_region_offset + cursor, VERTHYS_LSM_WAL_MAGIC,
                &lsm->part->aead,
                (const uint8_t *)VERTHYS_LSM_AAD_WAL,
                strlen(VERTHYS_LSM_AAD_WAL),
                VERTHYS_LSM_ENTRY_HEADER_BYTES + VERTHYS_LSM_NAME_MAX_BYTES +
                VERTHYS_CNG_TAG_BYTES,
                &pt, &pt_len, &frame_len);
        if (r != VERTHYS_OK) break;       /* 撕裂尾部：静默截断 */

        used = verthys_lsm_entry_decode(pt, pt_len, &e);
        if (used == 0 || used != pt_len) {
            verthys_secure_zero(pt, pt_len);
            free(pt);
            break;                      /* 结构非法：撕裂尾部 */
        }
        for (size_t k = 0; k < exclude_count; k++) {
            if (e.created_txid == exclude_txids[k]) {
                excluded = 1;
                break;
            }
        }
        if (!excluded) {
            r = verthys_lsm_memtable_insert(lsm->memtable, &e);
            if (r != VERTHYS_OK) {
                verthys_secure_zero(pt, pt_len);
                free(pt);
                return r;               /* 插入失败：真实错误 */
            }
        }
        verthys_secure_zero(pt, pt_len);
        free(pt);

        cursor += frame_len;
        frames++;
    }

    lsm->wal_cursor = cursor;
    *frames_out = frames;
    return VERTHYS_OK;
}

static VerthysResult wal_replay(VerthysLsm *lsm, uint64_t *frames_out)
{
    return wal_replay_impl(lsm, frames_out, NULL, 0);
}

/* ================== flush ================== */

VerthysResult verthys_lsm_flush_locked(VerthysLsm *lsm)
{
    VerthysResult r;
    uint64_t seq, txid;
    VerthysLsmTableMeta meta;
    VerthysLsmEntryIter it;
    VerthysLsmMemIter *mi = NULL;
    VerthysLsmMemTable *fresh = NULL;
    size_t count;

    if (lsm == NULL) return VERTHYS_ERR_INVALID;
    count = verthys_lsm_memtable_entry_count(lsm->memtable);
    if (count == 0) return VERTHYS_OK;    /* 空表 no-op */

    seq = lsm->manifest.next_seq;
    txid = lsm->manifest.txid + 1;

    r = verthys_lsm_memtable_iter_start(lsm->memtable, &it, &mi);
    if (r != VERTHYS_OK) return r;

    r = verthys_lsm_sstable_write(lsm->f, lsm->part, &it, count,
                                txid, seq, 0,
                                lsm->data_region_offset,
                                &lsm->manifest.next_data_offset,
                                lsm->region_size -
                                (lsm->data_region_offset - lsm->region_offset),
                                &meta);
    verthys_lsm_memtable_iter_end(mi);
    if (r != VERTHYS_OK) return r;

    /* Manifest 提交：序号推进 + 有序插入 + 保存（提交点） */
    lsm->manifest.next_seq = seq + 1;
    lsm->manifest.txid = txid;
    if (manifest_insert_sorted(&lsm->manifest, &meta) != 0) {
        /* 回滚（SSTable 已落盘但未在册 → 脏区，后续覆写） */
        lsm->manifest.next_seq = seq;
        lsm->manifest.txid = txid - 1;
        lsm->manifest.next_data_offset -= meta.size;
        return VERTHYS_ERR_RESOURCE_LIMIT;
    }
    r = verthys_lsm_manifest_save(lsm->f, lsm->region_offset,
                                &lsm->manifest, lsm->part);
    if (r != VERTHYS_OK) {
        /* Manifest 保存失败：从内存态摘除（盘面 Manifest 仍为旧态） */
        for (size_t i = 0; i < lsm->manifest.count; i++) {
            if (lsm->manifest.tables[i].seq == seq) {
                memmove(&lsm->manifest.tables[i],
                        &lsm->manifest.tables[i + 1],
                        (lsm->manifest.count - i - 1) *
                        sizeof(lsm->manifest.tables[0]));
                break;
            }
        }
        lsm->manifest.count--;
        lsm->manifest.next_seq = seq;
        lsm->manifest.txid = txid - 1;
        lsm->manifest.next_data_offset -= meta.size;
        return r;
    }

    /* 新活跃表替换（旧表生命周期至此结束，条目已持久化） */
    fresh = verthys_lsm_memtable_create();
    if (fresh == NULL) {
        /* 内存耗尽：数据安全（已持久化），仅无法继续接受写入 */
        return VERTHYS_ERR_INTERNAL;
    }
    verthys_lsm_memtable_destroy(lsm->memtable);
    lsm->memtable = fresh;

    /* WAL 复位（SSTable + Manifest 已 _commit，WAL 帧使命完成） */
    r = wal_reset(lsm);
    if (r != VERTHYS_OK) return r;    /* 数据安全；WAL 旧帧将重放幂等覆盖 */
    return VERTHYS_OK;
}

/* ================== 后台 compaction 线程 ================== */

/* CPU 空闲率采样（GetSystemTimes，间隔 500ms 双采样） */
static int cpu_idle_below(unsigned threshold_pct)
{
    FILETIME idle1, kernel1, user1, idle2, kernel2, user2;
    uint64_t i1, k1, u1, i2, k2, u2;
    uint64_t d_total, d_busy;

    if (!GetSystemTimes(&idle1, &kernel1, &user1)) return 0;
    Sleep(500);
    if (!GetSystemTimes(&idle2, &kernel2, &user2)) return 0;

    i1 = ((uint64_t)idle1.dwHighDateTime << 32) | idle1.dwLowDateTime;
    k1 = ((uint64_t)kernel1.dwHighDateTime << 32) | kernel1.dwLowDateTime;
    u1 = ((uint64_t)user1.dwHighDateTime << 32) | user1.dwLowDateTime;
    i2 = ((uint64_t)idle2.dwHighDateTime << 32) | idle2.dwLowDateTime;
    k2 = ((uint64_t)kernel2.dwHighDateTime << 32) | kernel2.dwLowDateTime;
    u2 = ((uint64_t)user2.dwHighDateTime << 32) | user2.dwLowDateTime;

    d_total = (k2 - k1) + (u2 - u1);
    if (d_total == 0) return 0;
    d_busy = d_total - (i2 - i1);
    return (d_busy * 100u) / d_total < (uint64_t)threshold_pct;
}

static DWORD WINAPI bg_thread_main(LPVOID param)
{
    VerthysLsm *lsm = (VerthysLsm *)param;

    /* BELOW_NORMAL：后台维护任务不与前台交互/IO 竞争 CPU */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

    while (InterlockedCompareExchange(&lsm->bg_shutdown, 0, 0) == 0) {
        int did_work = 0;

        if (cpu_idle_below(VERTHYS_LSM_COMPACTION_IDLE_CPU_PCT)) {
            AcquireSRWLockExclusive(&lsm->lock);
            if (InterlockedCompareExchange(&lsm->bg_shutdown, 0, 0) == 0 &&
                verthys_lsm_needs_compaction_locked(lsm)) {
                verthys_lsm_compact_locked(lsm);
                did_work = 1;
            }
            ReleaseSRWLockExclusive(&lsm->lock);
        }
        if (!did_work) Sleep(VERTHYS_LSM_BG_POLL_MS);
    }
    return 0;
}

/* ================== 温启动缓存 ================== */

/*
 * 编码契约位于 verthys_lsm.h（温缓存表记录段）。权威性设计：Manifest 始终
 * 从盘面帧加载，缓存段仅承载惰性缓存内容（Footer 字段 + Bloom 位图 +
 * 块索引）——缓存过期（seq 不匹配）静默跳过，无覆写/误读风险。
 */

/* 表记录定长头：seq/ibo/bo(8×3) + bloom_bytes(4) + bloom_k(1) + rsv(3)
 * + bloom_hash(32) + block_count(4) */
#define WARM_TABLE_FIXED_BYTES 68u
#define WARM_BLOCK_BYTES       24u

/* MemTable 快照两遍编码：测量回调（第一遍） */
typedef struct {
    size_t total;
    int    failed;
} warm_measure_ctx;

static int warm_mt_measure_cb(const VerthysLsmEntry *e, void *user)
{
    warm_measure_ctx *c = (warm_measure_ctx *)user;
    size_t n = verthys_lsm_entry_encoded_len(e);
    if (n == 0) { c->failed = 1; return 1; }
    c->total += n;
    return 0;
}

/* MemTable 快照两遍编码：写入回调（第二遍） */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   pos;
    int      failed;
} warm_encode_ctx;

static int warm_mt_encode_cb(const VerthysLsmEntry *e, void *user)
{
    warm_encode_ctx *c = (warm_encode_ctx *)user;
    size_t n = verthys_lsm_entry_encoded_len(e);
    if (n == 0 || n > c->cap - c->pos ||
        verthys_lsm_entry_encode(c->buf + c->pos, n, e) != 0) {
        c->failed = 1;
        return 1;
    }
    c->pos += n;
    return 0;
}

/*
 * MemTable 快照编码：[u32le count][count × 条目编码]（升序迭代，
 * 与 WAL 帧明文同构）。调用方持独占锁（两遍间快照稳定）。
 */
static VerthysResult warm_memtable_encode(const VerthysLsmMemTable *mt,
                                        uint8_t **out_pt, size_t *out_len)
{
    warm_measure_ctx mc;
    warm_encode_ctx ec;
    uint8_t *pt;
    size_t len;

    memset(&mc, 0, sizeof(mc));
    verthys_lsm_memtable_iterate(mt, warm_mt_measure_cb, &mc);
    if (mc.failed) return VERTHYS_ERR_INTERNAL;

    len = 4 + mc.total;
    pt = (uint8_t *)malloc(len);
    if (pt == NULL) return VERTHYS_ERR_INTERNAL;
    put_u32le(pt, (uint32_t)verthys_lsm_memtable_entry_count(mt));

    ec.buf = pt + 4;
    ec.cap = mc.total;
    ec.pos = 0;
    ec.failed = 0;
    verthys_lsm_memtable_iterate(mt, warm_mt_encode_cb, &ec);
    if (ec.failed || ec.pos != mc.total) {
        verthys_secure_zero(pt, len);
        free(pt);
        return VERTHYS_ERR_INTERNAL;
    }
    *out_pt = pt;
    *out_len = len;
    return VERTHYS_OK;
}

/*
 * 表记录段编码（两遍：测长 + 写入）。前置（红线）：全部表已完成
 * preheat（footer_loaded=1 且惰性缓存完整），否则返回 INTERNAL——
 * 调用方（export_warm）保证。
 */
static VerthysResult warm_tables_encode(const VerthysLsm *lsm,
                                      uint8_t **out_pt, size_t *out_len)
{
    const VerthysLsmManifest *m = &lsm->manifest;
    size_t total = 4;
    uint8_t *pt;
    size_t pos;

    for (size_t i = 0; i < m->count; i++) {
        const VerthysLsmTableMeta *t = &m->tables[i];
        if (!t->footer_loaded ||
            (t->bloom_bytes != 0 && t->bloom_bits == NULL) ||
            (t->block_count != 0 && t->blocks == NULL)) {
            return VERTHYS_ERR_INTERNAL;
        }
        total += WARM_TABLE_FIXED_BYTES +
                 (size_t)t->block_count * WARM_BLOCK_BYTES + t->bloom_bytes;
    }
    pt = (uint8_t *)malloc(total);
    if (pt == NULL) return VERTHYS_ERR_INTERNAL;

    put_u32le(pt, (uint32_t)m->count);
    pos = 4;
    for (size_t i = 0; i < m->count; i++) {
        const VerthysLsmTableMeta *t = &m->tables[i];
        put_u64le(pt + pos, t->seq);                    pos += 8;
        put_u64le(pt + pos, t->index_block_offset);     pos += 8;
        put_u64le(pt + pos, t->bloom_offset);           pos += 8;
        put_u32le(pt + pos, t->bloom_bytes);            pos += 4;
        pt[pos] = t->bloom_k;                           pos += 1;
        memset(pt + pos, 0, 3);                         pos += 3;
        memcpy(pt + pos, t->bloom_hash, 32);            pos += 32;
        put_u32le(pt + pos, (uint32_t)t->block_count);  pos += 4;
        for (size_t b = 0; b < t->block_count; b++) {
            const VerthysLsmBlockIdx *bi = &t->blocks[b];
            put_u64le(pt + pos, bi->first_key);   pos += 8;
            put_u64le(pt + pos, bi->offset);      pos += 8;
            put_u32le(pt + pos, bi->frame_len);   pos += 4;
            put_u32le(pt + pos, bi->entry_count); pos += 4;
        }
        if (t->bloom_bytes != 0) {
            memcpy(pt + pos, t->bloom_bits, t->bloom_bytes);
            pos += t->bloom_bytes;
        }
    }
    if (pos != total) {     /* 同源两遍必然相等；防御性校验 */
        verthys_secure_zero(pt, total);
        free(pt);
        return VERTHYS_ERR_INTERNAL;
    }
    *out_pt = pt;
    *out_len = total;
    return VERTHYS_OK;
}

/*
 * 表记录段安装（open_warm 专用，Manifest 加载后调用）：
 * 逐记录严格游标有界解析 → 独立堆副本（位图 + 块索引）→ seq 匹配
 * Manifest 表 → 填充惰性缓存（footer_loaded=1）。seq 不匹配（缓存
 * 过期）或已安装（重复记录）→ 释放副本静默跳过。
 */
static VerthysResult warm_tables_install(VerthysLsm *lsm,
                                       const uint8_t *pt, size_t len)
{
    VerthysLsmManifest *m = &lsm->manifest;
    size_t count, pos;

    if (len < 4) return VERTHYS_ERR_FORMAT;
    count = get_u32le(pt);
    pos = 4;
    for (size_t i = 0; i < count; i++) {
        uint64_t seq, ibo, bo;
        uint32_t bbytes, bcount;
        uint8_t bk;
        const uint8_t *hashp;
        VerthysLsmTableMeta *meta = NULL;
        uint8_t *bits = NULL;
        VerthysLsmBlockIdx *blocks = NULL;

        if (len - pos < WARM_TABLE_FIXED_BYTES) return VERTHYS_ERR_FORMAT;
        seq     = get_u64le(pt + pos);
        ibo     = get_u64le(pt + pos + 8);
        bo      = get_u64le(pt + pos + 16);
        bbytes  = get_u32le(pt + pos + 24);
        bk      = pt[pos + 28];
        hashp   = pt + pos + 32;
        bcount  = get_u32le(pt + pos + 64);
        pos += WARM_TABLE_FIXED_BYTES;
        if (len - pos < (size_t)bcount * WARM_BLOCK_BYTES + bbytes) {
            return VERTHYS_ERR_FORMAT;
        }
        if (bbytes != 0) {
            bits = (uint8_t *)malloc(bbytes);
            if (bits == NULL) return VERTHYS_ERR_INTERNAL;
            memcpy(bits, pt + pos + (size_t)bcount * WARM_BLOCK_BYTES, bbytes);
        }
        if (bcount != 0) {
            blocks = (VerthysLsmBlockIdx *)malloc((size_t)bcount * sizeof(*blocks));
            if (blocks == NULL) {
                free(bits);
                return VERTHYS_ERR_INTERNAL;
            }
            for (size_t b = 0; b < bcount; b++) {
                const uint8_t *bp = pt + pos + b * WARM_BLOCK_BYTES;
                blocks[b].first_key   = get_u64le(bp);
                blocks[b].offset      = get_u64le(bp + 8);
                blocks[b].frame_len   = get_u32le(bp + 16);
                blocks[b].entry_count = get_u32le(bp + 20);
            }
        }
        pos += (size_t)bcount * WARM_BLOCK_BYTES + bbytes;

        for (size_t j = 0; j < m->count; j++) {
            if (m->tables[j].seq == seq) { meta = &m->tables[j]; break; }
        }
        if (meta != NULL && !meta->footer_loaded) {
            meta->footer_loaded = 1;
            meta->index_block_offset = ibo;
            meta->bloom_offset = bo;
            meta->bloom_bytes = bbytes;
            meta->bloom_k = bk;
            memcpy(meta->bloom_hash, hashp, sizeof(meta->bloom_hash));
            meta->bloom_bits = bits;
            meta->blocks = blocks;
            meta->block_count = bcount;
        } else {
            free(bits);
            free(blocks);
        }
    }
    if (pos != len) return VERTHYS_ERR_FORMAT;
    return VERTHYS_OK;
}

/*
 * MemTable 快照播种（open_warm 专用，WAL 重放前调用——重放条目
 * 新于快照，同键覆盖 = 新者胜）。严格游标有界解析 + 总长一致性校验；
 * 条目合法性由 memtable_insert 把关（name 深拷贝）。
 */
static VerthysResult warm_memtable_seed(VerthysLsm *lsm,
                                      const uint8_t *pt, size_t len)
{
    size_t count, pos;

    if (len < 4) return VERTHYS_ERR_FORMAT;
    count = get_u32le(pt);
    if (count > (len - 4) / VERTHYS_LSM_ENTRY_HEADER_BYTES) {
        return VERTHYS_ERR_FORMAT;    /* 容量防护：count 与缓冲不符 */
    }
    pos = 4;
    for (size_t i = 0; i < count; i++) {
        VerthysLsmEntry e;
        size_t used = verthys_lsm_entry_decode(pt + pos, len - pos, &e);
        VerthysResult r;
        if (used == 0) return VERTHYS_ERR_FORMAT;
        r = verthys_lsm_memtable_insert(lsm->memtable, &e);
        if (r != VERTHYS_OK) return r;
        pos += used;
    }
    if (pos != len) return VERTHYS_ERR_FORMAT;
    return VERTHYS_OK;
}

/* ================== 生命周期 ================== */

/* Manifest 区首 8 字节全零 = 从未写入（区分"空区"与"损坏帧"） */
static int manifest_region_empty(FILE *f, uint64_t region_offset)
{
    uint8_t header[VERTHYS_LSM_FRAME_HEADER_BYTES];
    uint32_t i;

    if (vio_pread64(f, region_offset, header, sizeof(header)) != 0) return 1;
    for (i = 0; i < sizeof(header); i++) {
        if (header[i] != 0) return 0;
    }
    return 1;
}

/*
 * 打开共用内核（冷启动 verthys_lsm_open / 温启动 verthys_lsm_open_warm）。
 * 温路径插入步骤（Manifest 加载后、WAL 重放前，时序红线）：
 *   1. warm_tables_install：seq 匹配表安装惰性缓存（过期记录跳过）；
 *   2. warm_memtable_seed：快照条目先入表——WAL 重放条目后入，
 *      同键覆盖 = 新者胜（重放帧时序上晚于快照导出点）。
 */
static VerthysResult lsm_open_internal(VerthysLsm *lsm, FILE *f, VerthysPartition *part,
                                     uint64_t region_offset, uint64_t region_size,
                                     int enable_bg,
                                     const uint8_t *warm_tables_pt, size_t warm_tables_len,
                                     const uint8_t *memtable_pt, size_t memtable_len)
{
    VerthysResult r;
    uint64_t wal_frames = 0;
    uint64_t counter_floor;

    if (lsm == NULL || f == NULL || part == NULL) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(&part->aead)) return VERTHYS_ERR_LOCKED;
    if (region_size < VERTHYS_LSM_MANIFEST_REGION_BYTES +
                      VERTHYS_LSM_WAL_REGION_BYTES + VERTHYS_LSM_SSTABLE_BLOCK_BYTES) {
        return VERTHYS_ERR_INVALID;
    }

    memset(lsm, 0, sizeof(*lsm));
    lsm->f = f;
    lsm->part = part;
    lsm->region_offset = region_offset;
    lsm->region_size = region_size;
    lsm->wal_region_offset = region_offset + VERTHYS_LSM_MANIFEST_REGION_BYTES;
    lsm->data_region_offset = lsm->wal_region_offset + VERTHYS_LSM_WAL_REGION_BYTES;
    InitializeSRWLock(&lsm->lock);

    lsm->memtable = verthys_lsm_memtable_create();
    if (lsm->memtable == NULL) {
        memset(lsm, 0, sizeof(*lsm));
        return VERTHYS_ERR_INTERNAL;
    }

    AcquireSRWLockExclusive(&lsm->lock);

    /* ---- Manifest：加载或初始化（盘面帧为唯一权威） ---- */
    if (manifest_region_empty(f, region_offset)) {
        memset(&lsm->manifest, 0, sizeof(lsm->manifest));
        lsm->manifest.next_seq = 1;
        r = verthys_lsm_manifest_save(f, region_offset, &lsm->manifest, part);
        if (r != VERTHYS_OK) goto fail;
        /* 首帧已消耗计数器 1；nonce_snapshot 回填（保存后值） */
        lsm->manifest.nonce_snapshot =
            verthys_cng_aead_nonce_counter(&part->aead);
    } else {
        r = verthys_lsm_manifest_load(f, region_offset, part, &lsm->manifest);
        if (r != VERTHYS_OK) goto fail;
    }

    /* ---- 温缓存表记录安装（open_warm 专用） ---- */
    if (warm_tables_pt != NULL) {
        r = warm_tables_install(lsm, warm_tables_pt, warm_tables_len);
        if (r != VERTHYS_OK) goto fail;
    }

    /* ---- MemTable 快照播种（open_warm 专用；先于 WAL 重放） ---- */
    if (memtable_pt != NULL) {
        r = warm_memtable_seed(lsm, memtable_pt, memtable_len);
        if (r != VERTHYS_OK) goto fail;
    }

    /* ---- WAL 重放（崩溃恢复）---- */
    r = wal_replay(lsm, &wal_frames);
    if (r != VERTHYS_OK) goto fail;

    /* ---- max-lid 初值合并（API 接线：LID 分配基准） ----
     * Manifest 各表 max_key（覆盖 SSTable 全部历史版本）∪ 当前
     * MemTable 尾值（温缓存播种 + WAL 重放产物，insert 已推高表内
     * max_lid）。语义同 verthys_lsm_internal.h：本字段单调不回退。 */
    for (size_t i = 0; i < lsm->manifest.count; i++) {
        if (lsm->manifest.tables[i].max_key > lsm->max_lid) {
            lsm->max_lid = lsm->manifest.tables[i].max_key;
        }
    }
    {
        uint64_t mt_max = verthys_lsm_memtable_max_lid(lsm->memtable);
        if (mt_max > lsm->max_lid) lsm->max_lid = mt_max;
    }

    /* ---- nonce 计数器下限推定（防 WAL 帧 nonce 重用） ---- */
    counter_floor = lsm->manifest.nonce_snapshot + wal_frames +
                    VERTHYS_LSM_NONCE_RESTORE_MARGIN;
    if (counter_floor > verthys_cng_aead_nonce_counter(&part->aead)) {
        r = verthys_cng_aead_restore_nonce_counter(&part->aead, counter_floor);
        if (r != VERTHYS_OK) {
            r = VERTHYS_ERR_INTERNAL;
            goto fail;
        }
    }

    /* ---- 修订：不再"重放后达阈值立即 flush" ----
     * 原行为会将崩溃会话遗留的未提交条目（LSM WAL 重放产物）持久化
     * 进 SSTable，令 transaction_v3 崩溃恢复的 MemTable 过滤重建
     * （verthys_lsm_rebuild_excluding）失效——未提交数据永久可见
     * （红线级）。重放条目一律留在 MemTable，由事务层 recover() 统一
     * 裁决后 flush（阈值触发移交 put 路径的 suppress_flush 检查，
     * 语义不变）。 */

    ReleaseSRWLockExclusive(&lsm->lock);

    /* ---- 后台 compaction 线程 ---- */
    if (enable_bg) {
        lsm->bg_enabled = 1;
        lsm->bg_shutdown = 0;
        lsm->bg_thread = CreateThread(NULL, 0, bg_thread_main, lsm, 0, NULL);
        if (lsm->bg_thread == NULL) {
            lsm->bg_enabled = 0;
            verthys_lsm_close(lsm);
            return VERTHYS_ERR_INTERNAL;
        }
    }
    return VERTHYS_OK;

fail:
    ReleaseSRWLockExclusive(&lsm->lock);
    for (size_t i = 0; i < lsm->manifest.count; i++) {
        verthys_lsm_sstable_meta_release(&lsm->manifest.tables[i]);
    }
    verthys_lsm_memtable_destroy(lsm->memtable);
    memset(lsm, 0, sizeof(*lsm));
    return r;
}

VerthysResult verthys_lsm_open(VerthysLsm *lsm, FILE *f, VerthysPartition *part,
                           uint64_t region_offset, uint64_t region_size,
                           int enable_bg)
{
    return lsm_open_internal(lsm, f, part, region_offset, region_size,
                             enable_bg, NULL, 0, NULL, 0);
}

VerthysResult verthys_lsm_open_warm(VerthysLsm *lsm, FILE *f, VerthysPartition *part,
                                uint64_t region_offset, uint64_t region_size,
                                int enable_bg,
                                const uint8_t *tables_pt, size_t tables_len,
                                const uint8_t *memtable_pt, size_t memtable_len)
{
    if (lsm == NULL || f == NULL || part == NULL) return VERTHYS_ERR_INVALID;
    if (tables_pt == NULL && tables_len != 0) return VERTHYS_ERR_INVALID;
    if (memtable_pt == NULL && memtable_len != 0) return VERTHYS_ERR_INVALID;
    if (tables_pt == NULL && memtable_pt == NULL) {
        return VERTHYS_ERR_INVALID;   /* 无加速载荷 = 调用方误用 */
    }
    return lsm_open_internal(lsm, f, part, region_offset, region_size,
                             enable_bg, tables_pt, tables_len,
                             memtable_pt, memtable_len);
}

VerthysResult verthys_lsm_close(VerthysLsm *lsm)
{
    VerthysResult r = VERTHYS_OK;

    if (lsm == NULL) return VERTHYS_OK;

    /* 停后台线程（汇合后再动共享态） */
    if (lsm->bg_thread != NULL) {
        InterlockedExchange(&lsm->bg_shutdown, 1);
        WaitForSingleObject(lsm->bg_thread, INFINITE);
        CloseHandle(lsm->bg_thread);
        lsm->bg_thread = NULL;
    }
    lsm->bg_enabled = 0;

    AcquireSRWLockExclusive(&lsm->lock);

    /* MemTable flush（空表 no-op）+ Manifest 终态保存（nonce 快照下限） */
    if (lsm->f != NULL && lsm->part != NULL) {
        r = verthys_lsm_flush_locked(lsm);
        if (r == VERTHYS_OK) {
            r = verthys_lsm_manifest_save(lsm->f, lsm->region_offset,
                                        &lsm->manifest, lsm->part);
        }
    }

    verthys_lsm_memtable_destroy(lsm->memtable);
    lsm->memtable = NULL;
    for (size_t i = 0; i < lsm->manifest.count; i++) {
        verthys_lsm_sstable_meta_release(&lsm->manifest.tables[i]);
    }
    ReleaseSRWLockExclusive(&lsm->lock);
    memset(lsm, 0, sizeof(*lsm));
    return r;
}

/* ================== 生命周期（堆分配） ================== */

/* 结构体对外不透明（verthys_lsm_internal.h），经本对函数管理堆生命周期 */
VerthysLsm *verthys_lsm_create(void)
{
    VerthysLsm *lsm = (VerthysLsm *)calloc(1, sizeof(*lsm));
    return lsm;
}

void verthys_lsm_destroy(VerthysLsm *lsm)
{
    if (lsm == NULL) return;
    verthys_lsm_close(lsm);          /* 幂等；close 尾部已 memset 清零 */
    verthys_secure_zero(lsm, sizeof(*lsm));
    free(lsm);
}

/*
 * v3_lifecycle 失败路径：中止式关闭——不 flush、不存 Manifest、
 * 不复位 WAL。盘面 LSM WAL 帧保持原样：下次 open 重放回 MemTable 后由
 * 事务层 recover 裁决（丢弃组剔除 / 重放组收尾）。
 * 红线：解锁失败路径若 flush，未提交条目（open 重放产物）将落入 SSTable
 * 且 LSM WAL 被复位——rebuild_excluding 仅作用于 MemTable，未提交数据
 * 将永久可见。唯一例外：recover 已完成的会话（unlock 成功后）MemTable
 * 仅含已提交条目——但该场景走 Lock 路径（close 正常 flush），不走本函数。
 */
VerthysResult verthys_lsm_abort(VerthysLsm *lsm)
{
    if (lsm == NULL) return VERTHYS_OK;

    /* 停后台线程（汇合后再动共享态；后台线程只读 + 惰性加载预热线程） */
    if (lsm->bg_thread != NULL) {
        InterlockedExchange(&lsm->bg_shutdown, 1);
        WaitForSingleObject(lsm->bg_thread, INFINITE);
        CloseHandle(lsm->bg_thread);
        lsm->bg_thread = NULL;
    }
    lsm->bg_enabled = 0;

    AcquireSRWLockExclusive(&lsm->lock);
    verthys_lsm_memtable_destroy(lsm->memtable);
    lsm->memtable = NULL;
    for (size_t i = 0; i < lsm->manifest.count; i++) {
        verthys_lsm_sstable_meta_release(&lsm->manifest.tables[i]);
    }
    ReleaseSRWLockExclusive(&lsm->lock);
    memset(lsm, 0, sizeof(*lsm));
    return VERTHYS_OK;
}

void verthys_lsm_destroy_abort(VerthysLsm *lsm)
{
    if (lsm == NULL) return;
    verthys_lsm_abort(lsm);
    verthys_secure_zero(lsm, sizeof(*lsm));
    free(lsm);
}

/* ================== 数据路径 ================== */

/*
 * 写入内部通道：
 *   is_tombstone=0（外部 put）——tombstone 强制清零（删除专走 delete）；
 *   is_tombstone=1（delete 内部）——保留墓碑标志（遮蔽语义依赖）。
 * 此前 delete 复用外部 put 路径 → 墓碑被强制清零 → get 旧值复活
 * （红线级缺陷，测试 v3lsm_delete_tombstone 捕获）。
 */
static VerthysResult verthys_lsm_put_internal(VerthysLsm *lsm, uint64_t txid,
                                          const VerthysLsmEntry *e,
                                          int is_tombstone)
{
    VerthysResult r;
    VerthysLsmEntry clean;

    if (lsm == NULL || e == NULL) return VERTHYS_ERR_INVALID;
    if (e->name_len > VERTHYS_LSM_NAME_MAX_BYTES) return VERTHYS_ERR_INVALID;
    if (e->name == NULL && e->name_len != 0) return VERTHYS_ERR_INVALID;

    clean = *e;
    if (!is_tombstone) clean.tombstone = 0;
    clean.created_txid = txid;

    AcquireSRWLockExclusive(&lsm->lock);
    r = wal_append(lsm, &clean);            /* WAL 先行 */
    if (r == VERTHYS_OK) {
        r = verthys_lsm_memtable_insert(lsm->memtable, &clean);
        if (r == VERTHYS_OK) {
            /* API 接线：LID 永不复用——单调推高，回滚/剔除不回退 */
            if (e->lid > lsm->max_lid) lsm->max_lid = e->lid;
            if (!lsm->suppress_flush &&
                    verthys_lsm_memtable_needs_flush(lsm->memtable)) {
                r = verthys_lsm_flush_locked(lsm);    /* 阈值自动 flush */
            }
        }
    }
    ReleaseSRWLockExclusive(&lsm->lock);
    return r;
}

VerthysResult verthys_lsm_put(VerthysLsm *lsm, uint64_t txid, const VerthysLsmEntry *e)
{
    return verthys_lsm_put_internal(lsm, txid, e, 0);
}

VerthysResult verthys_lsm_get(VerthysLsm *lsm, uint64_t lid,
                          VerthysLsmEntry *out,
                          uint8_t *name_buf, size_t name_cap,
                          size_t *name_len_out)
{
    VerthysResult r = VERTHYS_ERR_NOTFOUND;
    const VerthysLsmEntry *me;

    if (lsm == NULL) return VERTHYS_ERR_INVALID;

    /* 独占锁（非共享）：SSTable 元数据惰性加载修改 Manifest 内存态，
     * SRWLOCK 共享模式下并发惰性初始化存在数据竞争；FFI 单线程纪律
     * 下与读者快照语义等价。 */
    AcquireSRWLockExclusive(&lsm->lock);

    /* 1. MemTable */
    me = verthys_lsm_memtable_find(lsm->memtable, lid);
    if (me != NULL) {
        if (me->tombstone) {
            ReleaseSRWLockExclusive(&lsm->lock);
            return VERTHYS_ERR_NOTFOUND;
        }
        if (out != NULL) {
            *out = *me;
            if (me->name_len != 0) {
                if (name_buf == NULL || name_cap < me->name_len) {
                    ReleaseSRWLockExclusive(&lsm->lock);
                    return VERTHYS_ERR_INVALID;
                }
                memcpy(name_buf, me->name, me->name_len);
                out->name = name_buf;
            } else {
                out->name = NULL;
            }
        }
        if (name_len_out != NULL) *name_len_out = me->name_len;
        ReleaseSRWLockExclusive(&lsm->lock);
        return VERTHYS_OK;
    }

    /* 2. SSTable：L0 新→旧 → L1..（tables 已按 level 升序/seq 降序）。
     * out == NULL 探测形态修复（存在性检查，公共 API
     *   delete/delete_many 在用）此前依赖 out->tombstone 判墓碑——探测
     *   形态无落点，SSTable 命中墓碑被误报 OK（MemTable 分支无此问题：
     *   墓碑先行判定不依赖 out）。修复：本地落点 + 名字暂存，探测与
     *   取值两形态同构判定。 */
    if (out == NULL) {
        VerthysLsmEntry probe;
        uint8_t probe_name[VERTHYS_LSM_NAME_MAX_BYTES];

        for (size_t i = 0; i < lsm->manifest.count; i++) {
            VerthysLsmTableMeta *meta = &lsm->manifest.tables[i];

            if (lid < meta->min_key || lid > meta->max_key) continue;

            r = verthys_lsm_sstable_find(lsm->f, lsm->part, meta, lid,
                                       &probe, probe_name,
                                       sizeof(probe_name), NULL);
            if (r == VERTHYS_OK) {
                ReleaseSRWLockExclusive(&lsm->lock);
                return probe.tombstone ? VERTHYS_ERR_NOTFOUND : VERTHYS_OK;
            }
            if (r != VERTHYS_ERR_NOTFOUND) break;    /* 真实错误上抛 */
        }
        ReleaseSRWLockExclusive(&lsm->lock);
        return (r == VERTHYS_OK) ? VERTHYS_ERR_NOTFOUND : r;
    }

    for (size_t i = 0; i < lsm->manifest.count; i++) {
        VerthysLsmTableMeta *meta = &lsm->manifest.tables[i];

        if (lid < meta->min_key || lid > meta->max_key) continue;  /* 键域排除 */

        r = verthys_lsm_sstable_find(lsm->f, lsm->part, meta, lid,
                                   out, name_buf, name_cap, name_len_out);
        if (r == VERTHYS_OK) {
            if (out->tombstone) {
                ReleaseSRWLockExclusive(&lsm->lock);
                return VERTHYS_ERR_NOTFOUND;     /* 墓碑遮蔽旧值 */
            }
            ReleaseSRWLockExclusive(&lsm->lock);
            return VERTHYS_OK;
        }
        if (r != VERTHYS_ERR_NOTFOUND) break;    /* 真实错误上抛 */
    }

    ReleaseSRWLockExclusive(&lsm->lock);
    return (r == VERTHYS_OK) ? VERTHYS_ERR_NOTFOUND : r;
}

VerthysResult verthys_lsm_delete(VerthysLsm *lsm, uint64_t txid, uint64_t lid)
{
    VerthysLsmEntry tomb;

    if (lsm == NULL) return VERTHYS_ERR_INVALID;

    memset(&tomb, 0, sizeof(tomb));
    tomb.lid = lid;
    tomb.tombstone = 1;
    tomb.created_txid = txid;

    return verthys_lsm_put_internal(lsm, txid, &tomb, 1);   /* 墓碑内部通道 */
}

/* ================== 事务层配合接口 ================== */

void verthys_lsm_set_flush_suppress(VerthysLsm *lsm, int suppress)
{
    if (lsm == NULL) return;
    AcquireSRWLockExclusive(&lsm->lock);
    lsm->suppress_flush = suppress ? 1 : 0;
    ReleaseSRWLockExclusive(&lsm->lock);
}

uint64_t verthys_lsm_wal_cursor(const VerthysLsm *lsm)
{
    uint64_t cur;
    if (lsm == NULL) return 0;
    AcquireSRWLockShared((SRWLOCK *)&lsm->lock);   /* const 视图锁访问（C4090 惯例强转） */
    cur = lsm->wal_cursor;
    ReleaseSRWLockShared((SRWLOCK *)&lsm->lock);
    return cur;
}

/*
 * MemTable 过滤重放重建内核（rollback_txid / rebuild_excluding 共用，
 * 回滚重建：重放式取代过滤式剔除）。

 * 为什么重放而非过滤式剔除（缺陷根因）：丢弃组的 DELETE 墓碑在
 * MemTable 中已按新者胜覆写原始条目——过滤式剔除墓碑后，被覆写的
 * 原始条目无从找回（已提交数据丢失，红线级）。WAL 先行 + flush 复位
 * 不变式（MemTable ≡ 重放 [0, wal_cursor)）保证 LSM WAL 保有全部
 * 历史帧：自偏移 0 重放并跳过命中 exclude_txids 的帧，即完整复原
 * 被墓碑遮蔽的原始条目。
 *
 * 换入语义：重放成功才销毁旧表（原子切换）；失败复原旧表，调用方
 * 重试幂等（rollback 路径 WAL 已先行截断，重放产物确定一致）。
 * wal_cursor 由 wal_replay_impl 收敛至重放终止点（rollback 场景 =
 * 截断点；rebuild 场景 = 原游标，撕裂尾只会前移收紧）。
 */
static VerthysResult memtable_rebuild_locked(VerthysLsm *lsm,
                                           const uint64_t *exclude_txids,
                                           size_t exclude_count)
{
    VerthysResult r;
    uint64_t frames;
    VerthysLsmMemTable *nm, *old;

    nm = verthys_lsm_memtable_create();
    if (nm == NULL) return VERTHYS_ERR_INTERNAL;

    old = lsm->memtable;
    lsm->memtable = nm;
    r = wal_replay_impl(lsm, &frames, exclude_txids, exclude_count);
    if (r != VERTHYS_OK) {
        lsm->memtable = old;      /* 复原：失败路径可重试 */
        verthys_lsm_memtable_destroy(nm);
        return r;
    }
    verthys_lsm_memtable_destroy(old);
    return VERTHYS_OK;
}

VerthysResult verthys_lsm_rollback_txid(VerthysLsm *lsm, uint64_t txid,
                                    uint64_t wal_cursor_base)
{
    static const uint8_t zeros[VERTHYS_LSM_FRAME_HEADER_BYTES] = {0};
    VerthysResult r;

    if (lsm == NULL || txid == 0) return VERTHYS_ERR_INVALID;

    AcquireSRWLockExclusive(&lsm->lock);

    /* 前置：事务期间未发生 flush（suppress_flush 纪律保证）。发生即
     * 游标回绕——运行时回滚不可行（条目已入 SSTable），返回 INVALID。 */
    if (lsm->wal_cursor < wal_cursor_base) {
        ReleaseSRWLockExclusive(&lsm->lock);
        return VERTHYS_ERR_INVALID;
    }

    /* 1. WAL 截断：失效化 base 起始帧头（回放链在 base 处断开）+ 提交。
     * 截断先行——即便后续 MemTable 重建失败（内存态残留），重开后
     * 回滚语义仍然成立（重放止于断链点，本事务帧不可达）。 */
    if (lsm->wal_cursor > wal_cursor_base) {
        if (vio_pwrite64(lsm->f, lsm->wal_region_offset + wal_cursor_base,
                         zeros, sizeof(zeros)) != 0) {
            ReleaseSRWLockExclusive(&lsm->lock);
            return VERTHYS_ERR_IO;
        }
        if (fflush(lsm->f) != 0 || _commit(_fileno(lsm->f)) != 0) {
            ReleaseSRWLockExclusive(&lsm->lock);
            return VERTHYS_ERR_IO;
        }
        lsm->wal_cursor = wal_cursor_base;
    }

    /* 2. MemTable 重放重建（★ 缺陷②修复：过滤式剔除 → 重放式重建）：
     *    自偏移 0 重放（止于断链点），剔除 created_txid == txid 残留帧
     *    （防御纵深：正常时序下本事务帧已被截断，命中仅发生于历史
     *    txid 复用残留）。本事务墓碑覆写的原始条目经重放完整复原。 */
    r = memtable_rebuild_locked(lsm, &txid, 1);
    if (r != VERTHYS_OK) {
        ReleaseSRWLockExclusive(&lsm->lock);
        return r;
    }

    ReleaseSRWLockExclusive(&lsm->lock);
    return VERTHYS_OK;
}

VerthysResult verthys_lsm_rebuild_excluding(VerthysLsm *lsm,
                                        const uint64_t *exclude_txids,
                                        size_t exclude_count)
{
    VerthysResult r;

    if (lsm == NULL) return VERTHYS_ERR_INVALID;
    if (exclude_txids == NULL && exclude_count != 0) return VERTHYS_ERR_INVALID;

    AcquireSRWLockExclusive(&lsm->lock);
    r = memtable_rebuild_locked(lsm, exclude_txids, exclude_count);
    ReleaseSRWLockExclusive(&lsm->lock);
    return r;
}

/* ================== 维护路径 ================== */

VerthysResult verthys_lsm_flush(VerthysLsm *lsm)
{
    VerthysResult r;

    if (lsm == NULL) return VERTHYS_ERR_INVALID;
    AcquireSRWLockExclusive(&lsm->lock);
    r = verthys_lsm_flush_locked(lsm);
    ReleaseSRWLockExclusive(&lsm->lock);
    return r;
}

/* .rhat 保护单元保留（runtime_hash.h X 清单）：生产 DLL 内 compaction 由
 * 后台线程经持锁态 verthys_lsm_compact_locked 触发，本公开入口（维护/测试
 * 薄壳）在 Release /OPT:REF 下无调用者会被丢弃——/include 强制保留，
 * 保住 .rhat 清单全命中（禁静默降级）与维护入口的分发可用性。 */
#if defined(_MSC_VER)
#pragma comment(linker, "/include:verthys_lsm_compact")
#endif

VerthysResult verthys_lsm_compact(VerthysLsm *lsm)
{
    VerthysResult r;

    if (lsm == NULL) return VERTHYS_ERR_INVALID;
    AcquireSRWLockExclusive(&lsm->lock);
    r = verthys_lsm_compact_locked(lsm);
    ReleaseSRWLockExclusive(&lsm->lock);
    return r;
}

/* ---------- 温启动缓存公开门面 ---------- */

VerthysResult verthys_lsm_export_warm(VerthysLsm *lsm,
                                  uint8_t **out_tables_pt, size_t *out_tables_len,
                                  uint8_t **out_memtable_pt, size_t *out_memtable_len)
{
    VerthysResult r;
    uint8_t *tpt = NULL, *mpt = NULL;
    size_t tpt_len = 0, mpt_len = 0;

    if (lsm == NULL || out_tables_pt == NULL || out_tables_len == NULL ||
        out_memtable_pt == NULL || out_memtable_len == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    *out_tables_pt = NULL;
    *out_tables_len = 0;
    *out_memtable_pt = NULL;
    *out_memtable_len = 0;

    if (lsm->f == NULL || lsm->part == NULL) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(&lsm->part->aead)) return VERTHYS_ERR_LOCKED;

    AcquireSRWLockExclusive(&lsm->lock);

    /* 逐表预热（幂等）：确保惰性缓存完整可导出 */
    for (size_t i = 0; i < lsm->manifest.count; i++) {
        r = verthys_lsm_sstable_preheat(lsm->f, lsm->part,
                                      &lsm->manifest.tables[i]);
        if (r != VERTHYS_OK) goto fail;
    }

    r = warm_tables_encode(lsm, &tpt, &tpt_len);
    if (r != VERTHYS_OK) goto fail;
    r = warm_memtable_encode(lsm->memtable, &mpt, &mpt_len);
    if (r != VERTHYS_OK) goto fail;

    ReleaseSRWLockExclusive(&lsm->lock);

    *out_tables_pt = tpt;
    *out_tables_len = tpt_len;
    *out_memtable_pt = mpt;
    *out_memtable_len = mpt_len;
    return VERTHYS_OK;

fail:
    ReleaseSRWLockExclusive(&lsm->lock);
    if (tpt != NULL) { verthys_secure_zero(tpt, tpt_len); free(tpt); }
    if (mpt != NULL) { verthys_secure_zero(mpt, mpt_len); free(mpt); }
    return r;
}

VerthysResult verthys_lsm_preheat_full(VerthysLsm *lsm)
{
    VerthysResult r;

    if (lsm == NULL) return VERTHYS_ERR_INVALID;
    if (lsm->f == NULL || lsm->part == NULL) return VERTHYS_ERR_INVALID;

    /* 独占锁：惰性加载修改 Manifest 内存态（与 get 路径同一纪律） */
    AcquireSRWLockExclusive(&lsm->lock);
    for (size_t i = 0; i < lsm->manifest.count; i++) {
        r = verthys_lsm_sstable_preheat(lsm->f, lsm->part,
                                      &lsm->manifest.tables[i]);
        if (r != VERTHYS_OK) {
            ReleaseSRWLockExclusive(&lsm->lock);
            return r;
        }
    }
    ReleaseSRWLockExclusive(&lsm->lock);
    return VERTHYS_OK;
}

/* ================== 统计与判定 ================== */

int verthys_lsm_needs_compaction_locked(const VerthysLsm *lsm)
{
    size_t l0 = 0;
    uint64_t level_bytes[VERTHYS_LSM_MAX_LEVELS];
    uint64_t limit = VERTHYS_LSM_LEVEL_BASE_BYTES;

    if (lsm == NULL) return 0;

    memset(level_bytes, 0, sizeof(level_bytes));
    for (size_t i = 0; i < lsm->manifest.count; i++) {
        const VerthysLsmTableMeta *t = &lsm->manifest.tables[i];
        if (t->level == 0) l0++;
        if (t->level < VERTHYS_LSM_MAX_LEVELS) {
            level_bytes[t->level] += t->size;
        }
    }

    /* L0：表数 ≥ 触发值 */
    if (l0 >= VERTHYS_LSM_L0_COMPACTION_TRIGGER) return 1;

    /* L1+：字节超容量（L1 基数 64MB，逐级 ×10） */
    for (unsigned lvl = 1; lvl < VERTHYS_LSM_MAX_LEVELS; lvl++) {
        if (level_bytes[lvl] > limit) return 1;
        if (limit > UINT64_MAX / 10u) break;   /* 溢出防护：上限即无穷 */
        limit *= 10u;
    }
    return 0;
}

int verthys_lsm_needs_compaction(const VerthysLsm *lsm)
{
    return verthys_lsm_needs_compaction_locked(lsm);
}

size_t verthys_lsm_table_count(const VerthysLsm *lsm)
{
    return (lsm != NULL) ? lsm->manifest.count : 0;
}

size_t verthys_lsm_level_table_count(const VerthysLsm *lsm, unsigned level)
{
    size_t n = 0;

    if (lsm == NULL || level >= VERTHYS_LSM_MAX_LEVELS) return 0;
    for (size_t i = 0; i < lsm->manifest.count; i++) {
        if (lsm->manifest.tables[i].level == level) n++;
    }
    return n;
}

uint64_t verthys_lsm_level_bytes(const VerthysLsm *lsm, unsigned level)
{
    uint64_t bytes = 0;

    if (lsm == NULL || level >= VERTHYS_LSM_MAX_LEVELS) return 0;
    for (size_t i = 0; i < lsm->manifest.count; i++) {
        if (lsm->manifest.tables[i].level == level) {
            bytes += lsm->manifest.tables[i].size;
        }
    }
    return bytes;
}

size_t verthys_lsm_memtable_count(const VerthysLsm *lsm)
{
    return (lsm != NULL && lsm->memtable != NULL)
               ? verthys_lsm_memtable_entry_count(lsm->memtable)
               : 0;
}

uint64_t verthys_lsm_max_lid(const VerthysLsm *lsm)
{
    uint64_t v;

    if (lsm == NULL) return 0;
    AcquireSRWLockShared((SRWLOCK *)&lsm->lock);   /* const 视图锁访问（C4090 惯例强转） */
    v = lsm->max_lid;
    ReleaseSRWLockShared((SRWLOCK *)&lsm->lock);
    return v;
}

/* ================== 全量扫描迭代器（API 层 Scan/摘要/计数 接线） ================== */

/*
 * SSTable 扫描源：在册表元数据深拷贝 + 顺序块迭代器。
 * 惰性缓存指针不共享（拷贝后置零 → 迭代器私有重载）：快照后
 * compaction 释放 Manifest 共享缓存不影响已打开迭代器；close 时
 * meta_release 仅释放私有副本。
 */
typedef struct ScanSstSrc {
    VerthysLsmTableMeta    meta;    /* 深拷贝（持久化字段；惰性缓存私有） */
    VerthysLsmEntryIter    it;
    VerthysLsmSstIter     *si;
    const VerthysLsmEntry *cur;     /* 当前就绪条目（NULL = 待推进/耗尽） */
} ScanSstSrc;

struct VerthysLsmScanIter {
    VerthysLsm      *lsm;           /* 借用（next 持 lsm 独占锁串行化 f 定位读） */
    /* MemTable 快照（open 深拷贝编码流，与 warm 导出同构） */
    uint8_t       *mem_buf;       /* [u32le count][count × 条目编码] */
    size_t         mem_len;
    size_t         mem_pos;       /* 解码游标（= 4 起步，越过 count 前缀） */
    int            mem_valid;     /* 1 = mem_cur 就绪 */
    int            mem_done;      /* 1 = 耗尽 */
    VerthysLsmEntry  mem_cur;       /* 当前条目（name 借用 mem_buf，快照稳定） */
    /* SSTable 源（Manifest 序：level 升序/同层 seq 降序 = 新→旧；序小者新） */
    ScanSstSrc    *sst;
    size_t         sst_count;
    int            failed;        /* 1 = 错误失效（后续 next 返回 INTERNAL） */
};

/* MemTable 快照源推进：mem_valid 置位或 mem_done。返回 0 成功 / -1 结构非法。 */
static int scan_mem_advance(VerthysLsmScanIter *sc)
{
    size_t used;

    if (sc->mem_valid || sc->mem_done) return 0;
    if (sc->mem_pos >= sc->mem_len) {
        sc->mem_done = 1;
        return 0;
    }
    used = verthys_lsm_entry_decode(sc->mem_buf + sc->mem_pos,
                                  sc->mem_len - sc->mem_pos, &sc->mem_cur);
    if (used == 0 || sc->mem_pos + used > sc->mem_len) return -1;
    sc->mem_pos += used;
    sc->mem_valid = 1;
    return 0;
}

/* SSTable 源推进（同 compaction source_advance；块读取/解码失败收敛 INTERNAL） */
static VerthysResult scan_sst_advance(ScanSstSrc *s)
{
    const VerthysLsmEntry *e = NULL;
    int rc;

    if (s->cur != NULL) return VERTHYS_OK;
    rc = s->it.next(&s->it, &e);
    if (rc < 0) return VERTHYS_ERR_INTERNAL;
    s->cur = (rc == 1) ? e : NULL;
    return VERTHYS_OK;
}

VerthysResult verthys_lsm_scan_open(VerthysLsm *lsm, VerthysLsmScanIter **out)
{
    VerthysResult r;
    VerthysLsmScanIter *sc;
    uint8_t *mpt = NULL;
    size_t mpt_len = 0;

    if (lsm == NULL || out == NULL) return VERTHYS_ERR_INVALID;
    if (lsm->f == NULL || lsm->part == NULL) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(&lsm->part->aead)) return VERTHYS_ERR_LOCKED;
    *out = NULL;

    sc = (VerthysLsmScanIter *)calloc(1, sizeof(*sc));
    if (sc == NULL) return VERTHYS_ERR_INTERNAL;
    sc->lsm = lsm;

    AcquireSRWLockExclusive(&lsm->lock);

    /* 1. MemTable 快照深拷贝（独占锁下两遍编码快照稳定） */
    r = warm_memtable_encode(lsm->memtable, &mpt, &mpt_len);
    if (r != VERTHYS_OK) goto fail;
    sc->mem_buf = mpt;
    sc->mem_len = mpt_len;
    sc->mem_pos = 4;                  /* 越过 [u32le count] 前缀 */
    mpt = NULL;

    /* 2. SSTable 源：Manifest 序深拷贝元数据 + 顺序块迭代器打开
     *    （惰性加载 IO 在私有副本上完成，不触碰共享 Manifest 内存态） */
    if (lsm->manifest.count != 0) {
        sc->sst = (ScanSstSrc *)calloc(lsm->manifest.count, sizeof(*sc->sst));
        if (sc->sst == NULL) { r = VERTHYS_ERR_INTERNAL; goto fail; }
        sc->sst_count = lsm->manifest.count;
    }
    for (size_t i = 0; i < sc->sst_count; i++) {
        ScanSstSrc *s = &sc->sst[i];

        s->meta = lsm->manifest.tables[i];    /* 持久化字段拷贝 */
        s->meta.footer_loaded = 0;            /* 惰性缓存不共享：私有重载 */
        s->meta.bloom_bits = NULL;
        s->meta.blocks = NULL;
        s->meta.block_count = 0;

        r = verthys_lsm_sstable_iter_open(lsm->f, lsm->part, &s->meta,
                                        &s->it, &s->si);
        if (r != VERTHYS_OK) goto fail;
    }

    ReleaseSRWLockExclusive(&lsm->lock);
    *out = sc;
    return VERTHYS_OK;

fail:
    ReleaseSRWLockExclusive(&lsm->lock);
    if (mpt != NULL) { verthys_secure_zero(mpt, mpt_len); free(mpt); }
    if (sc->sst != NULL) {
        for (size_t i = 0; i < sc->sst_count; i++) {
            verthys_lsm_sstable_iter_close(sc->sst[i].si);
            verthys_lsm_sstable_meta_release(&sc->sst[i].meta);
        }
        free(sc->sst);
    }
    if (sc->mem_buf != NULL) {
        verthys_secure_zero(sc->mem_buf, sc->mem_len);
        free(sc->mem_buf);
    }
    verthys_secure_zero(sc, sizeof(*sc));
    free(sc);
    return r;
}

VerthysResult verthys_lsm_scan_next(VerthysLsmScanIter *it, VerthysLsmEntry *out,
                                uint8_t *name_buf, size_t name_cap,
                                size_t *name_len_out)
{
    VerthysResult r;

    if (it == NULL) return VERTHYS_ERR_INVALID;
    if (it->failed) return VERTHYS_ERR_INTERNAL;

    /* 独占锁：块读取经 vio_pread64（fseek+fread 非原子定位），须与全部
     * f 使用者互斥（get/preheat/flush 同一纪律）；每步推进后即释放，
     * 长扫描不长时间阻塞写者。 */
    AcquireSRWLockExclusive(&it->lsm->lock);

    for (;;) {
        const VerthysLsmEntry *w = NULL;
        int best_is_mem = 0;
        size_t best_sst = 0;
        uint64_t lid = 0;
        int have = 0;

        /* 1. 全源推进至就绪/耗尽 */
        if (scan_mem_advance(it) != 0) { r = VERTHYS_ERR_INTERNAL; goto fail; }
        for (size_t i = 0; i < it->sst_count; i++) {
            r = scan_sst_advance(&it->sst[i]);
            if (r != VERTHYS_OK) goto fail;
        }

        /* 2. 最小 lid + 胜者（MemTable 最新；SSTable Manifest 序小者新：
         *    仅严格小于才替换 → 同 lid 首见源（最新）胜出） */
        if (it->mem_valid) {
            w = &it->mem_cur;
            lid = it->mem_cur.lid;
            have = 1;
            best_is_mem = 1;
        }
        for (size_t i = 0; i < it->sst_count; i++) {
            const VerthysLsmEntry *c = it->sst[i].cur;
            if (c == NULL) continue;
            if (!have || c->lid < lid) {
                w = c;
                lid = c->lid;
                have = 1;
                best_is_mem = 0;
                best_sst = i;
            }
        }
        if (!have) {
            ReleaseSRWLockExclusive(&it->lsm->lock);
            return VERTHYS_ERR_NOTFOUND;         /* 全源耗尽 */
        }
        (void)best_is_mem; (void)best_sst;     /* 胜者指针已定，辅助量不消费 */

        /* 3. 墓碑遮蔽 → 消费同 lid 全源，继续归并 */
        if (w->tombstone) {
            if (it->mem_valid && it->mem_cur.lid == lid) it->mem_valid = 0;
            for (size_t i = 0; i < it->sst_count; i++) {
                ScanSstSrc *s = &it->sst[i];
                if (s->cur != NULL && s->cur->lid == lid) s->cur = NULL;
            }
            continue;
        }

        /* 4. 出参容量校验（未消费——同条目可携更大缓冲重试） */
        if (out != NULL && w->name_len != 0 &&
            (name_buf == NULL || name_cap < w->name_len)) {
            ReleaseSRWLockExclusive(&it->lsm->lock);
            return VERTHYS_ERR_INVALID;
        }

        /* 5. 拷贝出参（借用条目随后续推进失效——立即拷贝） */
        if (out != NULL) {
            *out = *w;
            if (w->name_len != 0) {
                memcpy(name_buf, w->name, w->name_len);
                out->name = name_buf;
            } else {
                out->name = NULL;
            }
        }
        if (name_len_out != NULL) *name_len_out = w->name_len;

        /* 6. 消费同 lid 全源（含胜者；败者旧版本丢弃） */
        if (it->mem_valid && it->mem_cur.lid == lid) it->mem_valid = 0;
        for (size_t i = 0; i < it->sst_count; i++) {
            ScanSstSrc *s = &it->sst[i];
            if (s->cur != NULL && s->cur->lid == lid) s->cur = NULL;
        }

        ReleaseSRWLockExclusive(&it->lsm->lock);
        return VERTHYS_OK;
    }

fail:
    ReleaseSRWLockExclusive(&it->lsm->lock);
    it->failed = 1;
    return r;
}

void verthys_lsm_scan_close(VerthysLsmScanIter *it)
{
    if (it == NULL) return;

    if (it->sst != NULL) {
        for (size_t i = 0; i < it->sst_count; i++) {
            verthys_lsm_sstable_iter_close(it->sst[i].si);
            verthys_lsm_sstable_meta_release(&it->sst[i].meta);
        }
        free(it->sst);
    }
    if (it->mem_buf != NULL) {
        verthys_secure_zero(it->mem_buf, it->mem_len);
        free(it->mem_buf);
    }
    verthys_secure_zero(it, sizeof(*it));
    free(it);
}

/* MemTable 非墓碑计数回调（estimate_records） */
static int scan_count_live_cb(const VerthysLsmEntry *e, void *ud)
{
    if (!e->tombstone) (*(uint64_t *)ud)++;
    return 0;
}

uint64_t verthys_lsm_estimate_records(const VerthysLsm *lsm)
{
    uint64_t total = 0;

    if (lsm == NULL) return 0;

    AcquireSRWLockShared((SRWLOCK *)&lsm->lock);   /* const 视图锁访问（C4090 惯例强转） */
    for (size_t i = 0; i < lsm->manifest.count; i++) {
        const VerthysLsmTableMeta *t = &lsm->manifest.tables[i];
        total += (t->entry_count >= t->tombstone_count)
                     ? (uint64_t)(t->entry_count - t->tombstone_count)
                     : 0;    /* 防御：不变量破坏不致下溢 */
    }
    verthys_lsm_memtable_iterate(lsm->memtable, scan_count_live_cb, &total);
    ReleaseSRWLockShared((SRWLOCK *)&lsm->lock);
    return total;
}
