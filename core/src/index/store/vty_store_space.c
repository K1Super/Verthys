/*
 * vty_store_space.c — 数据区空闲区分配与回收
 *
 * 区间表只存在于内存：DataRoot 是唯一事实源，解锁期从根可达范围重建，
 * 因此崩溃不会留下「空闲标记指向仍被引用数据」的持久化不一致。
 *
 * 关键不变量：
 *   - LIVE 区间始终被当前 DataRoot（目录节点或目录叶引用的记录/分片段）
 *     引用；FREE 区间只来自已提交事务的退役。
 *   - 退役区间在提交前保持 LIVE，事务内后续写入不得复用，否则回退后
 *     旧根仍引用的数据会被覆盖。
 *   - 有游标打开时，退役区间转入 deferred，全部游标关闭后才释放：
 *     游标按节点 id 重新读盘，复用其快照路径上的旧节点会直接读坏。
 */

#include "vty_store_internal.h"

#include <winioctl.h>

/* ------------------------------------------------------------------ *
 * 容量管理
 * ------------------------------------------------------------------ */

static int grow_ranges(VtyStore *s, size_t need)
{
    VtySpaceRange *p;
    size_t cap;

    if (need <= s->range_cap) return VTY_OK;
    cap = s->range_cap != 0 ? s->range_cap : 64u;
    while (cap < need) {
        if (cap > ((size_t)-1) / 2u) return VTY_E_RESOURCE;
        cap *= 2u;
    }
    p = (VtySpaceRange *)vty_alloc(cap * sizeof(*p));
    if (p == NULL) return VTY_E_RESOURCE;
    if (s->range_n != 0) {
        memcpy(p, s->ranges, s->range_n * sizeof(*p));
    }
    if (s->ranges != NULL) {
        vty_free(s->ranges, s->range_cap * sizeof(*s->ranges));
    }
    s->ranges = p;
    s->range_cap = cap;
    return VTY_OK;
}

static int grow_extents(VtySpaceExtent **arr, size_t *cap, size_t need)
{
    VtySpaceExtent *p;
    size_t new_cap;

    if (need <= *cap) return VTY_OK;
    new_cap = *cap != 0 ? *cap : 64u;
    while (new_cap < need) {
        if (new_cap > ((size_t)-1) / 2u) return VTY_E_RESOURCE;
        new_cap *= 2u;
    }
    p = (VtySpaceExtent *)vty_alloc(new_cap * sizeof(*p));
    if (p == NULL) return VTY_E_RESOURCE;
    if (*arr != NULL) {
        if (*cap != 0) memcpy(p, *arr, (*cap < need ? *cap : need) * sizeof(*p));
        vty_free(*arr, *cap * sizeof(**arr));
    }
    *arr = p;
    *cap = new_cap;
    return VTY_OK;
}

static void extents_free(VtySpaceExtent **arr, size_t *cap, size_t *n)
{
    if (*arr != NULL) {
        vty_free(*arr, *cap * sizeof(**arr));
        *arr = NULL;
    }
    *cap = 0;
    *n = 0;
}

static void space_reset(VtyStore *s)
{
    s->range_n = 0;
    s->free_bytes = 0;
    s->retired_n = 0;
    s->deferred_n = 0;
    s->space_ready = 0;
    s->space_overflow = 0;
    /* reader_n 由游标生命周期维护：禁用复用不得打乱仍在打开的游标计数。 */
}

void vty_store_space_disable(VtyStore *s)
{
    if (s == NULL) return;
    space_reset(s);
}

/* ------------------------------------------------------------------ *
 * 区间查找与失效保护
 * ------------------------------------------------------------------ */

/* 返回第一个 end > off 的区间下标；调用方必须自行校验包含关系。 */
static size_t range_floor(const VtyStore *s, uint64_t off)
{
    size_t lo = 0, hi = s->range_n;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        const VtySpaceRange *r = &s->ranges[mid];
        if (r->off + r->len <= off) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo;
}

static void shrink_tail(VtyStore *s)
{
    while (s->range_n != 0u) {
        VtySpaceRange *last = &s->ranges[s->range_n - 1u];
        if (last->state != VTY_SPACE_FREE) break;
        if (last->len > s->loc.data_end) break;
        s->loc.data_end -= last->len;
        s->free_bytes -= last->len;
        s->range_n--;
    }
}

/* 把 [off, off+len) 由 LIVE 改为 FREE，并与相邻 FREE 合并。
 * 只接受仍处于 LIVE 的已登记区间；任何不匹配都按 BOOKKEEPING 错误
 * 处理，由调用方关闭复用，绝不猜测。 */
static int space_mark_free(VtyStore *s, uint64_t off, uint64_t len)
{
    size_t i;
    VtySpaceRange r;
    uint64_t end;
    uint64_t foff;
    uint64_t flen;
    int left;
    int right;
    size_t parts;
    size_t extra;
    size_t pos;
    size_t fi;
    int rc;

    if (len == 0u) return VTY_OK;
    if (off < VTY_DATA_OFFSET || off + len < off ||
        off + len > s->loc.data_end) {
        return VTY_E_CORRUPT;
    }
    i = range_floor(s, off);
    if (i >= s->range_n) return VTY_E_CORRUPT;
    r = s->ranges[i];
    if (r.state != VTY_SPACE_LIVE) return VTY_E_CORRUPT;
    if (off < r.off || off + len > r.off + r.len) return VTY_E_CORRUPT;

    end = r.off + r.len;
    foff = off;
    flen = len;
    left = (foff > r.off) ? 1 : 0;
    right = (foff + flen < end) ? 1 : 0;
    parts = (size_t)(1 + left + right);
    extra = parts - 1u;

    if (extra != 0u) {
        rc = grow_ranges(s, s->range_n + extra);
        if (rc != VTY_OK) return rc;
        memmove(&s->ranges[i + parts], &s->ranges[i + 1u],
                (s->range_n - i - 1u) * sizeof(VtySpaceRange));
        s->range_n += extra;
    }

    pos = i;
    if (left) {
        s->ranges[pos].off = r.off;
        s->ranges[pos].len = foff - r.off;
        s->ranges[pos].state = VTY_SPACE_LIVE;
        pos++;
    }
    fi = pos;
    s->ranges[pos].off = foff;
    s->ranges[pos].len = flen;
    s->ranges[pos].state = VTY_SPACE_FREE;
    pos++;
    if (right) {
        s->ranges[pos].off = foff + flen;
        s->ranges[pos].len = end - (foff + flen);
        s->ranges[pos].state = VTY_SPACE_LIVE;
        pos++;
    }
    s->free_bytes += flen;

    /* 与后邻合并 */
    if (fi + 1u < s->range_n &&
        s->ranges[fi + 1u].state == VTY_SPACE_FREE) {
        s->ranges[fi].len += s->ranges[fi + 1u].len;
        memmove(&s->ranges[fi + 1u], &s->ranges[fi + 2u],
                (s->range_n - fi - 2u) * sizeof(VtySpaceRange));
        s->range_n--;
    }
    /* 与前邻合并 */
    if (fi > 0u && s->ranges[fi - 1u].state == VTY_SPACE_FREE) {
        s->ranges[fi - 1u].len += s->ranges[fi].len;
        memmove(&s->ranges[fi], &s->ranges[fi + 1u],
                (s->range_n - fi - 1u) * sizeof(VtySpaceRange));
        s->range_n--;
    }
    return VTY_OK;
}

/* ------------------------------------------------------------------ *
 * 分配
 * ------------------------------------------------------------------ */

static int space_append(VtyStore *s, uint64_t len, uint64_t *out_off)
{
    int rc;

    if (s->loc.data_end > UINT64_MAX - len) return VTY_E_NO_SPACE;
    if (s->space_ready) {
        if (s->range_n != 0u) {
            VtySpaceRange *last = &s->ranges[s->range_n - 1u];
            if (last->off + last->len != s->loc.data_end) return VTY_E_CORRUPT;
        } else if (s->loc.data_end != VTY_DATA_OFFSET) {
            return VTY_E_CORRUPT;
        }
        rc = grow_ranges(s, s->range_n + 1u);
        if (rc != VTY_OK) return rc;
        s->ranges[s->range_n].off = s->loc.data_end;
        s->ranges[s->range_n].len = len;
        s->ranges[s->range_n].state = VTY_SPACE_LIVE;
        s->range_n++;
    }
    *out_off = s->loc.data_end;
    s->loc.data_end += len;
    return VTY_OK;
}

int vty_store_space_alloc(VtyStore *s, uint64_t len, uint64_t *out_off)
{
    size_t i;
    int rc;

    if (s == NULL || out_off == NULL || len == 0u) return VTY_E_INVALID;
    if (!s->space_ready) return space_append(s, len, out_off);

    if (s->free_bytes >= len) {
        for (i = 0; i < s->range_n; i++) {
            VtySpaceRange *r = &s->ranges[i];
            if (r->state != VTY_SPACE_FREE || r->len < len) continue;
            if (r->len - len < VTY_SPACE_SPLIT_MIN) {
                /* 剩余不足以形成可用区间：整段交付，避免碎片。 */
                *out_off = r->off;
                s->free_bytes -= r->len;
                r->state = VTY_SPACE_LIVE;
                return VTY_OK;
            }
            /* 前段 LIVE，后段继续 FREE；插入一个新的 LIVE 区间。
             * 注意先保存原区间边界：写入 ranges[i] 后同一指针读到的
             * 已是新长度，直接用会把后半段长度算成 0。 */
            uint64_t old_off = r->off;
            uint64_t old_len = r->len;

            rc = grow_ranges(s, s->range_n + 1u);
            if (rc != VTY_OK) return rc;
            memmove(&s->ranges[i + 1u], &s->ranges[i],
                    (s->range_n - i) * sizeof(VtySpaceRange));
            s->range_n++;
            s->ranges[i].off = old_off;
            s->ranges[i].len = len;
            s->ranges[i].state = VTY_SPACE_LIVE;
            s->ranges[i + 1u].off = old_off + len;
            s->ranges[i + 1u].len = old_len - len;
            s->free_bytes -= len;
            *out_off = old_off;
            return VTY_OK;
        }
    }
    return space_append(s, len, out_off);
}

/* ------------------------------------------------------------------ *
 * 退役与提交
 * ------------------------------------------------------------------ */

void vty_store_space_retire(VtyStore *s, uint64_t off, uint64_t len)
{
    if (s == NULL || !s->space_ready || len == 0u) return;
    if (s->space_overflow) return;
    if (s->retired_n >= VTY_SPACE_RETIRED_MAX) {
        /* 超大批量事务：放弃本轮精确回收，解锁期重建兜底。 */
        s->space_overflow = 1;
        s->retired_n = 0;
        return;
    }
    if (grow_extents(&s->retired, &s->retired_cap,
                     s->retired_n + 1u) != VTY_OK) {
        s->space_overflow = 1;
        s->retired_n = 0;
        return;
    }
    s->retired[s->retired_n].off = off;
    s->retired[s->retired_n].len = len;
    s->retired_n++;
}

void vty_store_retire_segment(VtyStore *s, uint64_t off, uint32_t len)
{
    if (len < VTY_SEG_HEADER_BYTES) return;
    vty_store_space_retire(s, off, (uint64_t)len);
}

static void release_deferred(VtyStore *s)
{
    size_t i;

    if (!s->space_ready || s->deferred_n == 0u) return;
    for (i = 0; i < s->deferred_n; i++) {
        if (space_mark_free(s, s->deferred[i].off,
                            s->deferred[i].len) != VTY_OK) {
            /* 账本异常：立即停止复用，保留数据可读性。 */
            vty_store_space_disable(s);
            return;
        }
    }
    s->deferred_n = 0;
    shrink_tail(s);
}

int vty_store_space_commit(VtyStore *s)
{
    size_t i;

    if (s == NULL) return VTY_E_INVALID;
    if (!s->space_ready) {
        s->retired_n = 0;
        return VTY_OK;
    }
    if (s->space_overflow) {
        /* 本事务未完整登记退役区间：不能只释放一部分，关闭复用。 */
        s->retired_n = 0;
        s->deferred_n = 0;
        vty_store_space_disable(s);
        return VTY_OK;
    }

    if (s->reader_n != 0u) {
        for (i = 0; i < s->retired_n; i++) {
            if (grow_extents(&s->deferred, &s->deferred_cap,
                             s->deferred_n + 1u) != VTY_OK) {
                s->retired_n = 0;
                vty_store_space_disable(s);
                return VTY_OK;
            }
            s->deferred[s->deferred_n] = s->retired[i];
            s->deferred_n++;
        }
        s->retired_n = 0;
        return VTY_OK;
    }

    for (i = 0; i < s->retired_n; i++) {
        if (space_mark_free(s, s->retired[i].off,
                            s->retired[i].len) != VTY_OK) {
            s->retired_n = 0;
            vty_store_space_disable(s);
            return VTY_OK;
        }
    }
    s->retired_n = 0;
    shrink_tail(s);
    return VTY_OK;
}

void vty_store_space_restore(VtyStore *s, const VtyStoreCheckpoint *cp)
{
    if (s == NULL || cp == NULL) return;
    if (!s->space_ready) {
        s->retired_n = 0;
        return;
    }
    if (!cp->space_ready) {
        vty_store_space_disable(s);
        return;
    }

    /* 事务内新分配的区间允许泄漏到下次解锁重建，但区间表必须裁回
     * 检查点的 data_end，避免把回退后仍被引用的尾部当成空闲。 */
    while (s->range_n != 0u &&
           s->ranges[s->range_n - 1u].off >= s->loc.data_end) {
        s->range_n--;
    }
    if (s->range_n != 0u) {
        VtySpaceRange *last = &s->ranges[s->range_n - 1u];
        uint64_t end = last->off + last->len;
        if (end > s->loc.data_end) {
            last->len -= end - s->loc.data_end;
        }
        if (last->len == 0u) s->range_n--;
    }
    s->retired_n = (cp->retired_n <= s->retired_n) ? cp->retired_n : 0u;
    s->space_overflow = 0;
    s->free_bytes = 0;
    {
        size_t i;
        for (i = 0; i < s->range_n; i++) {
            if (s->ranges[i].state == VTY_SPACE_FREE) {
                s->free_bytes += s->ranges[i].len;
            }
        }
    }
}

void vty_store_space_reader_enter(VtyStore *s)
{
    if (s == NULL) return;
    s->reader_n++;
}

void vty_store_space_reader_leave(VtyStore *s)
{
    if (s == NULL) return;
    if (s->reader_n != 0u) s->reader_n--;
    if (s->reader_n == 0u) release_deferred(s);
}

/* ------------------------------------------------------------------ *
 * 解锁期重建
 * ------------------------------------------------------------------ */

int vty_store_space_begin(VtyStore *s)
{
    if (s == NULL) return VTY_E_INVALID;
    space_reset(s);
    /* 重建只发生在解锁维护阶段，此时不应有任何游标。 */
    s->reader_n = 0;
    return VTY_OK;
}

int vty_store_space_reserve(VtyStore *s, uint64_t off, uint64_t len)
{
    int rc;

    if (s == NULL) return VTY_E_INVALID;
    if (len == 0u) return VTY_E_INVALID;
    if (off < VTY_DATA_OFFSET || off + len < off ||
        off + len > s->loc.data_end) {
        return VTY_E_CORRUPT;
    }
    rc = grow_ranges(s, s->range_n + 1u);
    if (rc != VTY_OK) return rc;
    s->ranges[s->range_n].off = off;
    s->ranges[s->range_n].len = len;
    s->ranges[s->range_n].state = VTY_SPACE_LIVE;
    s->range_n++;
    return VTY_OK;
}

static int range_cmp(const void *a, const void *b)
{
    const VtySpaceRange *ra = (const VtySpaceRange *)a;
    const VtySpaceRange *rb = (const VtySpaceRange *)b;

    if (ra->off < rb->off) return -1;
    if (ra->off > rb->off) return 1;
    return 0;
}

int vty_store_space_finish(VtyStore *s)
{
    VtySpaceRange *out;
    size_t out_cap;
    size_t pos = 0;
    size_t i;
    uint64_t cursor;
    int rc = VTY_OK;

    if (s == NULL) return VTY_E_INVALID;
    if (s->range_n != 0u) {
        qsort(s->ranges, s->range_n, sizeof(*s->ranges), range_cmp);
    }

    out_cap = s->range_n * 2u + 1u;
    out = (VtySpaceRange *)vty_alloc(out_cap * sizeof(*out));
    if (out == NULL) return VTY_E_RESOURCE;

    cursor = VTY_DATA_OFFSET;
    for (i = 0; i < s->range_n; i++) {
        VtySpaceRange r = s->ranges[i];
        if (r.off < cursor || r.off + r.len < r.off ||
            r.off + r.len > s->loc.data_end) {
            rc = VTY_E_CORRUPT;
            break;
        }
        if (r.off > cursor) {
            out[pos].off = cursor;
            out[pos].len = r.off - cursor;
            out[pos].state = VTY_SPACE_FREE;
            pos++;
        }
        out[pos].off = r.off;
        out[pos].len = r.len;
        out[pos].state = VTY_SPACE_LIVE;
        pos++;
        cursor = r.off + r.len;
    }
    if (rc == VTY_OK && cursor < s->loc.data_end) {
        out[pos].off = cursor;
        out[pos].len = s->loc.data_end - cursor;
        out[pos].state = VTY_SPACE_FREE;
        pos++;
    }
    if (rc != VTY_OK) {
        vty_free(out, out_cap * sizeof(*out));
        return rc;
    }

    if (s->ranges != NULL) {
        vty_free(s->ranges, s->range_cap * sizeof(*s->ranges));
    }
    s->ranges = out;
    s->range_cap = out_cap;
    s->range_n = pos;
    s->free_bytes = 0;
    for (i = 0; i < pos; i++) {
        if (s->ranges[i].state == VTY_SPACE_FREE) {
            s->free_bytes += s->ranges[i].len;
        }
    }
    s->retired_n = 0;
    s->deferred_n = 0;
    s->space_overflow = 0;
    s->space_ready = 1;
    shrink_tail(s);
    return VTY_OK;
}

/* ------------------------------------------------------------------ *
 * 目录树节点登记
 * ------------------------------------------------------------------ */

static int scan_node(VtyStore *s, uint64_t id, uint8_t level,
                     const uint8_t expected_hash[VTY_HASH_BYTES],
                     uint8_t depth)
{
    VtyMemNode n;
    uint8_t actual[VTY_HASH_BYTES];
    uint32_t i;
    int rc;

    if (depth > VTY_STORE_MAX_LEVEL) return VTY_E_CORRUPT;
    memset(&n, 0, sizeof(n));
    rc = vty_st_node_read(s, id, level, &n, actual);
    if (rc != VTY_OK) return rc;
    if (expected_hash != NULL &&
        vty_ct_equal(actual, expected_hash, VTY_HASH_BYTES) != 0) {
        vty_st_node_free(&n);
        return VTY_E_CORRUPT;
    }
    rc = vty_store_space_reserve(s, id, n.total_len);
    if (rc == VTY_OK && n.type == VTY_NODE_INTERNAL) {
        for (i = 0; i < n.n; i++) {
            rc = scan_node(s, n.e[i].child_id,
                           (uint8_t)(level > 0u ? level - 1u : 0u),
                           n.e[i].child_hash, (uint8_t)(depth + 1u));
            if (rc != VTY_OK) break;
        }
    }
    vty_st_node_free(&n);
    return rc;
}

int vty_store_space_scan_nodes(VtyStore *s)
{
    if (s == NULL) return VTY_E_INVALID;
    if (s->loc.root_node_id == 0u) return VTY_OK;
    return scan_node(s, s->loc.root_node_id, s->loc.level, s->root_hash, 0u);
}

/* ------------------------------------------------------------------ *
 * 物理截断
 * ------------------------------------------------------------------ */

int vty_store_trim_tail(VtyStore *s, uint64_t durable_end)
{
    uint64_t size = 0;
    FILE_ZERO_DATA_INFORMATION zd;
    FILE_END_OF_FILE_INFO eof;
    DWORD got = 0;
    int rc;

    if (s == NULL || s->h == INVALID_HANDLE_VALUE || s->h == NULL) {
        return VTY_E_INVALID;
    }
    /* 只截断持久化高水位与当前数据区高水位一致的情况：若存在尚未提交
     * 的追加写入，截断会删掉后续提交要引用的段。 */
    if (durable_end != s->loc.data_end) return VTY_OK;
    rc = vty_st_file_size_of(s->h, &size);
    if (rc != VTY_OK) return rc;
    if (size <= durable_end) return VTY_OK;

    /* 先零化再截断：被截掉的区间可能仍含密文，零化避免其以簇残留
     * 形式留在文件系统里。FSCTL 不支持时退回直接截断（内容已无密钥）。 */
    memset(&zd, 0, sizeof(zd));
    zd.FileOffset.QuadPart = (LONGLONG)durable_end;
    zd.BeyondFinalZero.QuadPart = (LONGLONG)size;
    (void)DeviceIoControl(s->h, FSCTL_SET_ZERO_DATA, &zd, sizeof(zd),
                          NULL, 0, &got, NULL);

    memset(&eof, 0, sizeof(eof));
    eof.EndOfFile.QuadPart = (LONGLONG)durable_end;
    if (!SetFileInformationByHandle(s->h, FileEndOfFileInfo, &eof,
                                    sizeof(eof))) {
        return VTY_E_IO;
    }
    return VTY_OK;
}
