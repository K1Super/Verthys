/*
 * verthys_wal.c — V3 事务 WAL 实现（环形 512KB×2 回放）
 *
 * 设计契约位于 verthys_wal.h 文件头。实现要点：
 *   - 帧读写复用 verthys_lsm_frame_write / verthys_lsm_frame_read_decrypt
 *     （帧惯例：[magic][ct_len][ct||tag][nonce]）；
 *   - 打开即全量解密校验扫描（撕裂尾部精确定位，游标绝不落在撕裂帧之后，
 *     保证后续追加记录在回放中可达）；
 *   - 回放按"低 seq 半区在前"拼接帧序，组缓冲存明文 heap 拷贝（内存
 *     有界：<= 区域字节数），投递时解码（栈上记录 + name 内联缓冲）。
 */
#include "verthys_wal.h"
#include "verthys_lsm_internal.h"  /* 帧助手 + 条目编解码 */
#include "verthys_io.h"
#include "verthys_internal.h"      /* verthys_secure_zero */

#include <io.h>                  /* _commit / _fileno */
#include <stdlib.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

/* ---------- 小端读写（与 LSM 模块同款惯例） ---------- */

static void wal_put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t wal_get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wal_put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
}

static uint64_t wal_get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

/* ---------- 小端读写（与 LSM 模块同款惯例） ---------- */

/* Unix 毫秒时间戳（BEGIN/COMMIT 记账，非安全敏感） */
static uint64_t wal_now_unix_ms(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (u.QuadPart - 116444736000000000ULL) / 10000ULL;
}

static VerthysResult wal_fsync(FILE *f)
{
    if (fflush(f) != 0) return VERTHYS_ERR_IO;
    if (_commit(_fileno(f)) != 0) return VERTHYS_ERR_IO;
    return VERTHYS_OK;
}

/* ---------- 内部结构 ---------- */

struct VerthysWal {
    FILE *f;                    /* 借用 */
    VerthysCngAead *aead;         /* 借用（C 角色密钥语境） */
    uint64_t region_offset;     /* WAL 区域绝对起始偏移 */
    unsigned active_half;       /* 0/1 */
    uint64_t half_seq;          /* 活跃半区 seq */
    uint64_t cursor;            /* 活跃半区游标（相对半区起始，含头） */
    uint64_t frame_count;       /* 活跃半区帧数 */
    int half_valid[2];          /* 盘面头有效性（open 扫描结果） */
    uint64_t half_seq_disk[2];  /* 盘面各半区 seq（回放排序依据） */
    int opened;
};

/* ---------- 记录编解码 ---------- */

/* 编码：返回明文字节长度；0 = 失败（参数非法/容量不足） */
static size_t wal_encode_record(uint8_t *buf, size_t cap,
                                const VerthysWalRecord *rec)
{
    if (rec == NULL) return 0;
    if (rec->type < VERTHYS_WAL_REC_BEGIN || rec->type > VERTHYS_WAL_REC_COMMIT) {
        return 0;
    }
    if (cap < 17u) return 0;
    buf[0] = rec->type;
    wal_put_u64le(buf + 1, rec->txid);

    switch (rec->type) {
    case VERTHYS_WAL_REC_BEGIN:
        wal_put_u64le(buf + 9, rec->u.begin.timestamp);
        return 17u;

    case VERTHYS_WAL_REC_EXTENT:
        if (cap < 69u) return 0;
        memcpy(buf + 9, rec->u.extent.hash, 32);
        wal_put_u64le(buf + 41, rec->u.extent.offset);
        wal_put_u32le(buf + 49, rec->u.extent.size);
        wal_put_u32le(buf + 53, rec->u.extent.plaintext_size);
        memcpy(buf + 57, rec->u.extent.nonce, 12);
        return 69u;

    case VERTHYS_WAL_REC_INDEX: {
        size_t el = verthys_lsm_entry_encoded_len(&rec->u.index.entry);
        if (el == 0 || 9u + el > cap) return 0;
        if (verthys_lsm_entry_encode(buf + 9, cap - 9u,
                                   &rec->u.index.entry) != 0) {
            return 0;
        }
        return 9u + el;
    }

    case VERTHYS_WAL_REC_PREPARE:
        if (cap < 65u) return 0;
        memcpy(buf + 9, rec->u.prepare.merkle_root, 32);
        wal_put_u64le(buf + 41, rec->u.prepare.extent_used);
        wal_put_u64le(buf + 49, rec->u.prepare.index_used);
        wal_put_u64le(buf + 57, rec->u.prepare.audit_used);
        return 65u;

    case VERTHYS_WAL_REC_COMMIT:
        wal_put_u64le(buf + 9, rec->u.commit.timestamp);
        return 17u;

    default:
        return 0;
    }
}

/* 解码：结构非法返回 VERTHYS_ERR_FORMAT。
 * INDEX：entry.name 指向 out->u.index.name 内联缓冲（4KB，栈安全）。 */
static VerthysResult wal_decode_record(const uint8_t *pt, size_t len,
                                     VerthysWalRecord *out)
{
    const uint8_t *p;
    size_t rem;

    if (pt == NULL || out == NULL || len < 9u) return VERTHYS_ERR_FORMAT;
    memset(out, 0, sizeof(*out));
    out->type = pt[0];
    out->txid = wal_get_u64le(pt + 1);
    p = pt + 9;
    rem = len - 9u;

    switch (out->type) {
    case VERTHYS_WAL_REC_BEGIN:
        if (rem < 8u) return VERTHYS_ERR_FORMAT;
        out->u.begin.timestamp = wal_get_u64le(p);
        return VERTHYS_OK;

    case VERTHYS_WAL_REC_EXTENT:
        if (rem < 60u) return VERTHYS_ERR_FORMAT;
        memcpy(out->u.extent.hash, p, 32);
        out->u.extent.offset = wal_get_u64le(p + 32);
        out->u.extent.size = wal_get_u32le(p + 40);
        out->u.extent.plaintext_size = wal_get_u32le(p + 44);
        memcpy(out->u.extent.nonce, p + 48, 12);
        return VERTHYS_OK;

    case VERTHYS_WAL_REC_INDEX: {
        size_t used = verthys_lsm_entry_decode(p, rem, &out->u.index.entry);
        if (used == 0 || used != rem) return VERTHYS_ERR_FORMAT;
        if (out->u.index.entry.name_len > VERTHYS_LSM_NAME_MAX_BYTES) {
            return VERTHYS_ERR_FORMAT;
        }
        if (out->u.index.entry.name_len > 0) {
            memcpy(out->u.index.name, out->u.index.entry.name,
                   out->u.index.entry.name_len);
        }
        out->u.index.entry.name = out->u.index.name;
        return VERTHYS_OK;
    }

    case VERTHYS_WAL_REC_PREPARE:
        if (rem < 56u) return VERTHYS_ERR_FORMAT;
        memcpy(out->u.prepare.merkle_root, p, 32);
        out->u.prepare.extent_used = wal_get_u64le(p + 32);
        out->u.prepare.index_used = wal_get_u64le(p + 40);
        out->u.prepare.audit_used = wal_get_u64le(p + 48);
        return VERTHYS_OK;

    case VERTHYS_WAL_REC_COMMIT:
        if (rem < 8u) return VERTHYS_ERR_FORMAT;
        out->u.commit.timestamp = wal_get_u64le(p);
        return VERTHYS_OK;

    default:
        return VERTHYS_ERR_FORMAT;
    }
}

/* ---------- 半区头与帧遍历 ---------- */

static uint64_t wal_half_base(const VerthysWal *w, unsigned half)
{
    return w->region_offset + (uint64_t)half * VERTHYS_WAL_HALF_BYTES;
}

static VerthysResult wal_write_half_header(VerthysWal *w, unsigned half,
                                         uint64_t seq)
{
    uint8_t hdr[VERTHYS_WAL_HALF_HEADER_BYTES];
    wal_put_u32le(hdr, VERTHYS_WAL_HALF_MAGIC);
    wal_put_u32le(hdr + 4, VERTHYS_WAL_VERSION);
    wal_put_u64le(hdr + 8, seq);
    wal_put_u64le(hdr + 16, 0);          /* reserved */
    if (vio_pwrite64(w->f, wal_half_base(w, half), hdr, sizeof(hdr)) != 0) {
        return VERTHYS_ERR_IO;
    }
    return wal_fsync(w->f);
}

/*
 * 换区清零：目标半区数据区（头之后至半区尾）全零覆写 + fsync。
 * 双半区环形复用下，第三圈起换入的半区数据区残留上一轮旧帧——
 * 残留帧在当前密钥语境下仍是合法 AEAD 帧（nonce 帧内记录），重开
 * 扫描按"自半区头逐帧解、magic 不符才停"会把残留当当前链续上。
 * 清零先行保证换入半区只有新头与新链；清零成功后崩溃（头未写）：
 * 头 seq 仍旧值、数据区全零，magic 不符即停，无残留链可解。
 * 只清被换入的一半；被换出半区数据保持不动（未 flush 事务帧仍
 * 靠它重放，"旧区转备份（数据保留）"语义）。
 * 失败直接返回，active_half 不切换（调用方保持旧区仍为活动区，
 * 可重试换区或继续在旧区尾部之后——单帧超半区已在上游拒绝，
 * 实际可重试路径为上层整事务重试）。
 */
static VerthysResult wal_clear_half_data(VerthysWal *w, unsigned half)
{
    uint8_t *zero;
    const uint64_t data_off =
        wal_half_base(w, half) + VERTHYS_WAL_HALF_HEADER_BYTES;
    const size_t data_bytes =
        (size_t)VERTHYS_WAL_HALF_BYTES - VERTHYS_WAL_HALF_HEADER_BYTES;

    zero = (uint8_t *)calloc(1, data_bytes);
    if (zero == NULL) return VERTHYS_ERR_INTERNAL;
    if (vio_pwrite64(w->f, data_off, zero, data_bytes) != 0) {
        free(zero);
        return VERTHYS_ERR_IO;
    }
    free(zero);
    return wal_fsync(w->f);
}

/*
 * 帧遍历：自半区头后逐帧解密校验，明文交 fn（可为 NULL = 仅结构扫描）。
 * 终止条件（撕裂静默截断）：
 *   - 帧头 magic 不符（空白/垃圾）-> 正常结束（不计撕裂）；
 *   - ct_len 越界 / 解密认证失败 / 记录解码失败 -> 撕裂计数 +1 并停止。
 * out_frames/out_torn/out_cursor/out_max_nonce 可为 NULL。
 */
typedef VerthysResult (*WalPtFn)(void *user, const uint8_t *pt, size_t pt_len);

static VerthysResult wal_foreach_frame(VerthysWal *w, unsigned half,
                                     WalPtFn fn, void *user,
                                     uint64_t *out_frames,
                                     uint64_t *out_torn,
                                     uint64_t *out_cursor,
                                     uint64_t *out_max_nonce)
{
    uint64_t base = wal_half_base(w, half);
    uint64_t cur = VERTHYS_WAL_HALF_HEADER_BYTES;
    uint64_t frames = 0, torn = 0, max_nonce = 0;
    uint8_t hdr[VERTHYS_WAL_HALF_HEADER_BYTES];
    VerthysResult r;

    if (vio_pread64(w->f, base, hdr, sizeof(hdr)) != 0) return VERTHYS_ERR_IO;
    if (wal_get_u32le(hdr) != VERTHYS_WAL_HALF_MAGIC ||
        wal_get_u32le(hdr + 4) != VERTHYS_WAL_VERSION) {
        /* 无有效头 -> 空半区 */
        if (out_frames) *out_frames = 0;
        if (out_torn) *out_torn = 0;
        if (out_cursor) *out_cursor = VERTHYS_WAL_HALF_HEADER_BYTES;
        if (out_max_nonce) *out_max_nonce = 0;
        return VERTHYS_OK;
    }

    for (;;) {
        uint8_t fh[VERTHYS_LSM_FRAME_HEADER_BYTES];
        uint32_t ct_len;
        uint64_t frame_len;
        uint8_t *pt = NULL;
        size_t pt_len = 0;
        uint8_t nonce[VERTHYS_CNG_NONCE_BYTES];
        uint64_t ctr;

        if (cur + VERTHYS_LSM_FRAME_HEADER_BYTES > VERTHYS_WAL_HALF_BYTES) break;
        if (vio_pread64(w->f, base + cur, fh, sizeof(fh)) != 0) {
            torn++;
            break;
        }
        if (wal_get_u32le(fh) != VERTHYS_WAL_FRAME_MAGIC) break; /* 空白区 */
        ct_len = wal_get_u32le(fh + 4);
        frame_len = VERTHYS_LSM_FRAME_HEADER_BYTES + (uint64_t)ct_len +
                    VERTHYS_LSM_FRAME_TAIL_BYTES;
        if (ct_len < VERTHYS_CNG_TAG_BYTES ||
            cur + frame_len > VERTHYS_WAL_HALF_BYTES) {
            torn++;
            break;
        }

        r = verthys_lsm_frame_read_decrypt(w->f, base + cur,
                                         VERTHYS_WAL_FRAME_MAGIC,
                                         w->aead,
                                         (const uint8_t *)VERTHYS_WAL_AAD,
                                         strlen(VERTHYS_WAL_AAD),
                                         VERTHYS_WAL_HALF_BYTES,
                                         &pt, &pt_len, NULL);
        if (r != VERTHYS_OK) {
            torn++;
            break;
        }

        /* nonce 计数器提取（帧尾 12B 明文 nonce） */
        if (vio_pread64(w->f,
                        base + cur + VERTHYS_LSM_FRAME_HEADER_BYTES + ct_len,
                        nonce, sizeof(nonce)) != 0) {
            free(pt);
            torn++;
            break;
        }
        ctr = verthys_cng_nonce_decode_counter(nonce);
        if (ctr > max_nonce) max_nonce = ctr;

        if (fn != NULL) {
            r = fn(user, pt, pt_len);
            if (r != VERTHYS_OK) {
                free(pt);
                return r;   /* 回调错误透传 */
            }
        }
        free(pt);
        frames++;
        cur += frame_len;
    }

    if (out_frames) *out_frames = frames;
    if (out_torn) *out_torn = torn;
    if (out_cursor) *out_cursor = cur;
    if (out_max_nonce) *out_max_nonce = max_nonce;
    return VERTHYS_OK;
}

/* ---------- 生命周期 ---------- */

/* verthys_v3_lifecycle 接线：结构体对外不透明，经本对函数管理堆生命周期 */
VerthysWal *verthys_wal_create(void)
{
    VerthysWal *w = (VerthysWal *)calloc(1, sizeof(*w));
    return w;
}

void verthys_wal_destroy(VerthysWal *w)
{
    if (w == NULL) return;
    verthys_wal_close(w);
    verthys_secure_zero(w, sizeof(*w));
    free(w);
}

VerthysResult verthys_wal_open(VerthysWal *w, FILE *f, uint64_t region_offset,
                           VerthysCngAead *aead,
                           uint64_t *out_frames, uint64_t *out_torn)
{
    uint64_t frames[2] = {0, 0}, torns[2] = {0, 0};
    uint64_t cursors[2] = {0, 0}, nonces[2] = {0, 0};
    uint8_t hdr[VERTHYS_WAL_HALF_HEADER_BYTES];
    unsigned active;
    VerthysResult r;
    uint64_t max_nonce, target, cur_ctr;

    if (w == NULL || f == NULL || aead == NULL) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(aead)) return VERTHYS_ERR_LOCKED;

    memset(w, 0, sizeof(*w));
    w->f = f;
    w->aead = aead;
    w->region_offset = region_offset;
    active = 2u;  /* 未决 */

    for (unsigned h = 0; h < 2u; h++) {
        r = wal_foreach_frame(w, h, NULL, NULL, &frames[h], &torns[h],
                              &cursors[h], &nonces[h]);
        if (r != VERTHYS_OK) return r;
        /* 半区头有效性（独立读头判断） */
        if (vio_pread64(f, wal_half_base(w, h), hdr, sizeof(hdr)) != 0) {
            return VERTHYS_ERR_IO;
        }
        w->half_valid[h] = (wal_get_u32le(hdr) == VERTHYS_WAL_HALF_MAGIC &&
                            wal_get_u32le(hdr + 4) == VERTHYS_WAL_VERSION) ? 1 : 0;
        w->half_seq_disk[h] = w->half_valid[h] ? wal_get_u64le(hdr + 8) : 0;
    }

    if (!w->half_valid[0] && !w->half_valid[1]) {
        /* 全新区域：半区 0 初始化（seq=1），半区 1 头清零防陈旧垃圾 */
        uint8_t zero[VERTHYS_WAL_HALF_HEADER_BYTES];
        memset(zero, 0, sizeof(zero));
        r = wal_write_half_header(w, 0, 1);
        if (r != VERTHYS_OK) return r;
        if (vio_pwrite64(f, wal_half_base(w, 1), zero, sizeof(zero)) != 0) {
            return VERTHYS_ERR_IO;
        }
        r = wal_fsync(f);
        if (r != VERTHYS_OK) return r;
        w->half_valid[0] = 1;
        w->half_seq_disk[0] = 1;
        w->half_valid[1] = 0;
        w->half_seq_disk[1] = 0;
        active = 0;
        w->half_seq = 1;
        w->cursor = VERTHYS_WAL_HALF_HEADER_BYTES;
        w->frame_count = 0;
    } else {
        /* 活跃半区 = 有效头中 seq 较大者；seq 相同（异常态）取游标大者 */
        if (w->half_valid[0] && w->half_valid[1]) {
            if (w->half_seq_disk[0] > w->half_seq_disk[1]) active = 0;
            else if (w->half_seq_disk[1] > w->half_seq_disk[0]) active = 1;
            else active = (cursors[0] >= cursors[1]) ? 0u : 1u;
        } else if (w->half_valid[0]) {
            active = 0;
        } else {
            active = 1;
        }
        w->half_seq = w->half_seq_disk[active];
        w->cursor = cursors[active];
        w->frame_count = frames[active];
    }

    w->active_half = active;
    w->opened = 1;

    /* nonce 计数器恢复（红线：防回退，保留裕量） */
    max_nonce = (nonces[0] > nonces[1]) ? nonces[0] : nonces[1];
    if (max_nonce > 0) {
        /* 加裕量防回绕：接近 2^64 钳制上限（加密侧对回绕拒绝） */
        target = (max_nonce > UINT64_MAX - VERTHYS_WAL_NONCE_RESTORE_MARGIN)
                     ? UINT64_MAX
                     : max_nonce + VERTHYS_WAL_NONCE_RESTORE_MARGIN;
        cur_ctr = verthys_cng_aead_nonce_counter(aead);
        if (target > cur_ctr) {
            r = verthys_cng_aead_restore_nonce_counter(aead, target);
            if (r != VERTHYS_OK) return r;
        }
    }

    if (out_frames) *out_frames = frames[0] + frames[1];
    if (out_torn) *out_torn = torns[0] + torns[1];
    return VERTHYS_OK;
}

VerthysResult verthys_wal_close(VerthysWal *w)
{
    if (w == NULL) return VERTHYS_OK;
    verthys_secure_zero(w, sizeof(*w));
    return VERTHYS_OK;
}

/* ---------- 追加 ---------- */

VerthysResult verthys_wal_append(VerthysWal *w, const VerthysWalRecord *rec)
{
    uint8_t pt[VERTHYS_WAL_MAX_RECORD_BYTES];
    size_t pt_len;
    uint64_t frame_len;
    uint32_t flen = 0;
    uint64_t base;
    VerthysResult r;

    if (w == NULL || rec == NULL || !w->opened) return VERTHYS_ERR_INVALID;
    if (!verthys_cng_aead_is_imported(w->aead)) return VERTHYS_ERR_LOCKED;

    pt_len = wal_encode_record(pt, sizeof(pt), rec);
    if (pt_len == 0) return VERTHYS_ERR_INVALID;

    frame_len = VERTHYS_LSM_FRAME_HEADER_BYTES + (uint64_t)pt_len +
                VERTHYS_CNG_TAG_BYTES + VERTHYS_LSM_FRAME_TAIL_BYTES;
    if (frame_len > VERTHYS_WAL_HALF_BYTES - VERTHYS_WAL_HALF_HEADER_BYTES) {
        return VERTHYS_ERR_INVALID;   /* 单帧超半区容量 */
    }

    if (w->cursor + frame_len > VERTHYS_WAL_HALF_BYTES) {
        /* 换区：旧区转备份（数据保留），新区 seq+1。
         * 清零先行（残留旧帧不可被续链回放，见 wal_clear_half_data），
         * 失败不切换 active_half（保持旧区活动，上层重试）。 */
        unsigned nh = 1u - w->active_half;
        uint64_t nseq = w->half_seq + 1;
        r = wal_clear_half_data(w, nh);
        if (r != VERTHYS_OK) return r;
        r = wal_write_half_header(w, nh, nseq);
        if (r != VERTHYS_OK) return r;
        w->active_half = nh;
        w->half_seq = nseq;
        w->half_valid[nh] = 1;
        w->half_seq_disk[nh] = nseq;
        w->cursor = VERTHYS_WAL_HALF_HEADER_BYTES;
        w->frame_count = 0;
    }

    base = wal_half_base(w, w->active_half);
    r = verthys_lsm_frame_write(w->f, base + w->cursor, VERTHYS_WAL_FRAME_MAGIC,
                              w->aead,
                              (const uint8_t *)VERTHYS_WAL_AAD,
                              strlen(VERTHYS_WAL_AAD),
                              pt, pt_len, &flen);
    if (r != VERTHYS_OK) return r;
    r = wal_fsync(w->f);
    if (r != VERTHYS_OK) return r;

    w->cursor += flen;
    w->frame_count++;
    return VERTHYS_OK;
}

/* ---------- 回放 ---------- */

/* 事务组缓冲：存帧明文 heap 拷贝（内存 <= 区域字节数） */
typedef struct WalGroupBuf {
    uint8_t **pts;
    size_t *lens;
    size_t count, cap;
    uint64_t txid;
    int has_prepare, has_commit;
    int open;
} WalGroupBuf;

static void wal_group_reset(WalGroupBuf *g)
{
    if (g->pts != NULL) {
        for (size_t i = 0; i < g->count; i++) {
            if (g->pts[i] != NULL) {
                free(g->pts[i]);
                g->pts[i] = NULL;
            }
        }
    }
    g->count = 0;
    g->txid = 0;
    g->has_prepare = 0;
    g->has_commit = 0;
    g->open = 0;
}

static void wal_group_free(WalGroupBuf *g)
{
    wal_group_reset(g);
    free(g->pts);
    free(g->lens);
    g->pts = NULL;
    g->lens = NULL;
    g->cap = 0;
}

static VerthysResult wal_group_push(WalGroupBuf *g, const uint8_t *pt,
                                  size_t pt_len, uint8_t type, uint64_t txid)
{
    if (g->count == g->cap) {
        size_t ncap = g->cap == 0 ? 16u : g->cap * 2u;
        uint8_t **npts = (uint8_t **)realloc(g->pts, ncap * sizeof(*npts));
        size_t *nlens;
        if (npts == NULL) return VERTHYS_ERR_INTERNAL;
        g->pts = npts;
        nlens = (size_t *)realloc(g->lens, ncap * sizeof(*nlens));
        if (nlens == NULL) return VERTHYS_ERR_INTERNAL;
        g->lens = nlens;
        g->cap = ncap;
    }
    g->pts[g->count] = (uint8_t *)malloc(pt_len);
    if (g->pts[g->count] == NULL) return VERTHYS_ERR_INTERNAL;
    memcpy(g->pts[g->count], pt, pt_len);
    g->lens[g->count] = pt_len;
    g->count++;
    g->txid = txid;
    g->open = 1;
    if (type == VERTHYS_WAL_REC_PREPARE) g->has_prepare = 1;
    if (type == VERTHYS_WAL_REC_COMMIT) g->has_commit = 1;
    return VERTHYS_OK;
}

typedef struct WalReplayCtx {
    uint64_t committed_txid;
    uint64_t sb_txid;
    VerthysWalReplayFn fn;            /* 重放组回调 */
    void *user;
    VerthysWalReplayFn fn_discard;    /* 丢弃组回调（可 NULL） */
    void *user_discard;
    WalGroupBuf group;
    uint64_t replayed, discarded;
    int fn_failed;      /* fn == NULL 且存在重放组 */
} WalReplayCtx;

/* 逐记录解码投递到 fn（重放/丢弃共用） */
static VerthysResult wal_group_deliver(WalGroupBuf *g, VerthysWalReplayFn fn,
                                     void *user)
{
    VerthysResult r = VERTHYS_OK;

    for (size_t i = 0; i < g->count; i++) {
        VerthysWalRecord rec;    /* 栈记录：name 指向内联缓冲，占用随结构体声明而定 */
        r = wal_decode_record(g->pts[i], g->lens[i], &rec);
        if (r != VERTHYS_OK) break;
        r = fn(user, &rec);
        if (r != VERTHYS_OK) break;
    }
    return r;
}

/* 组分类终结：redrive -> 逐记录解码投递；否则丢弃（可选投递） */
static VerthysResult wal_group_finalize(WalReplayCtx *c)
{
    VerthysResult r = VERTHYS_OK;

    if (!c->group.open) return VERTHYS_OK;

    if (c->group.txid != 0 && c->group.txid <= c->committed_txid) {
        /* 已提交确认 -> 跳过 */
        c->discarded += c->group.count;
        if (c->fn_discard != NULL) {
            r = wal_group_deliver(&c->group, c->fn_discard, c->user_discard);
        }
    } else if (c->group.has_commit ||
               (c->group.has_prepare && c->sb_txid >= c->group.txid)) {
        /* COMMIT 在法定人数提交成功后落笔 -> 重放；
         * PREPARE-only 且超块已含该 txid -> 提交完成、COMMIT 撕裂 -> 重放收尾 */
        if (c->fn == NULL) {
            c->fn_failed = 1;
            wal_group_reset(&c->group);
            return VERTHYS_ERR_INVALID;
        }
        r = wal_group_deliver(&c->group, c->fn, c->user);
        c->replayed += c->group.count;
    } else {
        /* 未提交（BEGIN/EXTENT/INDEX 或 PREPARE 未达超块）-> 回滚丢弃 */
        c->discarded += c->group.count;
        if (c->fn_discard != NULL) {
            r = wal_group_deliver(&c->group, c->fn_discard, c->user_discard);
        }
    }

    wal_group_reset(&c->group);
    return r;
}

/* 帧明文回调：提取记录头 -> 组缓冲管理 */
static VerthysResult wal_replay_frame(void *user, const uint8_t *pt,
                                    size_t pt_len)
{
    WalReplayCtx *c = (WalReplayCtx *)user;
    uint64_t txid;
    VerthysResult r;

    if (pt_len < 9u) return VERTHYS_ERR_FORMAT;
    txid = wal_get_u64le(pt + 1);

    if (c->group.open && txid != c->group.txid) {
        r = wal_group_finalize(c);
        if (r != VERTHYS_OK) return r;
    }
    return wal_group_push(&c->group, pt, pt_len, pt[0], txid);
}

VerthysResult verthys_wal_replay(VerthysWal *w, uint64_t committed_txid,
                             uint64_t sb_txid,
                             VerthysWalReplayFn fn, void *user,
                             uint64_t *out_frames,
                             uint64_t *out_replayed,
                             uint64_t *out_discarded)
{
    return verthys_wal_replay_ex(w, committed_txid, sb_txid,
                               fn, user, NULL, NULL,
                               out_frames, out_replayed, out_discarded);
}

VerthysResult verthys_wal_replay_ex(VerthysWal *w, uint64_t committed_txid,
                                uint64_t sb_txid,
                                VerthysWalReplayFn fn_replay, void *user_replay,
                                VerthysWalReplayFn fn_discard, void *user_discard,
                                uint64_t *out_frames,
                                uint64_t *out_replayed,
                                uint64_t *out_discarded)
{
    WalReplayCtx ctx;
    unsigned order[2];
    uint64_t frames_total = 0, frames, torn;
    VerthysResult r;

    if (w == NULL || !w->opened) return VERTHYS_ERR_INVALID;

    memset(&ctx, 0, sizeof(ctx));
    ctx.committed_txid = committed_txid;
    ctx.sb_txid = sb_txid;
    ctx.fn = fn_replay;
    ctx.user = user_replay;
    ctx.fn_discard = fn_discard;
    ctx.user_discard = user_discard;

    /* 低 seq 半区在前（帧序拼接；单写者下时间序保持） */
    if (w->half_valid[0] && w->half_valid[1]) {
        if (w->half_seq_disk[0] <= w->half_seq_disk[1]) {
            order[0] = 0; order[1] = 1;
        } else {
            order[0] = 1; order[1] = 0;
        }
    } else if (w->half_valid[0]) {
        order[0] = 0; order[1] = 2;   /* 2 = 跳过 */
    } else if (w->half_valid[1]) {
        order[0] = 1; order[1] = 2;
    } else {
        order[0] = 2; order[1] = 2;
    }

    for (int i = 0; i < 2; i++) {
        if (order[i] == 2u) continue;
        r = wal_foreach_frame(w, order[i], wal_replay_frame, &ctx,
                              &frames, &torn, NULL, NULL);
        if (r != VERTHYS_OK) {
            wal_group_free(&ctx.group);
            return r;
        }
        frames_total += frames;
    }

    r = wal_group_finalize(&ctx);   /* 末组终结 */
    if (r == VERTHYS_OK && ctx.fn_failed) r = VERTHYS_ERR_INVALID;
    wal_group_free(&ctx.group);

    if (out_frames) *out_frames = frames_total;
    if (out_replayed) *out_replayed = ctx.replayed;
    if (out_discarded) *out_discarded = ctx.discarded;
    return r;
}

/* ---------- 截断复位 ---------- */

VerthysResult verthys_wal_reset(VerthysWal *w)
{
    uint8_t dead_hdr[VERTHYS_WAL_HALF_HEADER_BYTES];
    uint64_t nseq;
    VerthysResult r;

    if (w == NULL || !w->opened) return VERTHYS_ERR_INVALID;

    /* 截断复位：新链落半区 0。只清半区 0 数据区（复用换区清零机制）
     * 并将半区 1 头失活，替代全量 960KB 清零——半区 1 数据区不动，
     * 它未来再被换入时同样会先清零。崩溃序次安全：任一中间点崩溃后
     * 重开的数据视图均为 reset 前语义或 reset 后语义，无凭空丢失。 */
    r = wal_clear_half_data(w, 0);
    if (r != VERTHYS_OK) return r;

    nseq = w->half_seq + 1;
    r = wal_write_half_header(w, 0, nseq);
    if (r != VERTHYS_OK) return r;

    /* 半区 1 头失活（无 magic 即空半区），旧链不再参与重开重放 */
    memset(dead_hdr, 0, sizeof(dead_hdr));
    if (vio_pwrite64(w->f, wal_half_base(w, 1), dead_hdr,
                     sizeof(dead_hdr)) != 0) {
        return VERTHYS_ERR_IO;
    }
    r = wal_fsync(w->f);
    if (r != VERTHYS_OK) return r;

    w->active_half = 0;
    w->half_seq = nseq;
    w->half_valid[0] = 1;
    w->half_seq_disk[0] = nseq;
    w->half_valid[1] = 0;
    w->half_seq_disk[1] = 0;
    w->cursor = VERTHYS_WAL_HALF_HEADER_BYTES;
    w->frame_count = 0;
    return VERTHYS_OK;
}

/* ---------- 统计 ---------- */

uint64_t verthys_wal_frame_count(const VerthysWal *w)
{
    return (w != NULL && w->opened) ? w->frame_count : 0;
}

uint64_t verthys_wal_half_seq(const VerthysWal *w)
{
    return (w != NULL && w->opened) ? w->half_seq : 0;
}

unsigned verthys_wal_active_half(const VerthysWal *w)
{
    return (w != NULL && w->opened) ? w->active_half : 2u;
}

uint64_t verthys_wal_cursor(const VerthysWal *w)
{
    return (w != NULL && w->opened) ? w->cursor : 0;
}

uint64_t verthys_wal_head_offset(const VerthysWal *w)
{
    if (w == NULL || !w->opened) return 0;
    return w->region_offset + (uint64_t)w->active_half * VERTHYS_WAL_HALF_BYTES +
           VERTHYS_WAL_HALF_HEADER_BYTES;
}

uint64_t verthys_wal_tail_offset(const VerthysWal *w)
{
    if (w == NULL || !w->opened) return 0;
    return w->region_offset + (uint64_t)w->active_half * VERTHYS_WAL_HALF_BYTES +
           w->cursor;
}
