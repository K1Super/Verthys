/*
 * verthys_lsm_memtable.c — LSM MemTable：跳表 + 条目编解码
 *
 * 跳表：概率均衡（p=1/4，最大塔高 16），插入/查找 O(log n)。
 * 单写者纪律：本翻译单元不加锁——并发由 VerthysLsm 的 SRWLOCK 串行化
 * （put/delete 独占，get 共享只读）。
 *
 * 冻结语义：达阈值后由上层 freeze（只读化），新写入路由到新活跃表。
 *
 * 条目编解码：定长头 78B + 变长 name（LE），WAL 帧与 SSTable 数据块
 * 明文共用同一编码。
 */
#include "verthys_lsm_internal.h"
#include "verthys_internal.h"   /* verthys_secure_zero */

#include <stdlib.h>
#include <string.h>

/* ================== 条目编解码 ================== */

size_t verthys_lsm_entry_encoded_len(const VerthysLsmEntry *e)
{
    if (e == NULL) return 0;
    return VERTHYS_LSM_ENTRY_HEADER_BYTES + (size_t)e->name_len;
}

static void put_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static uint16_t get_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

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

static void put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
    }
}

static uint64_t get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | (uint64_t)p[i];
    }
    return v;
}

int verthys_lsm_entry_encode(uint8_t *buf, size_t cap, const VerthysLsmEntry *e)
{
    size_t need;

    if (buf == NULL || e == NULL) return -1;
    if (e->name_len > VERTHYS_LSM_NAME_MAX_BYTES) return -1;
    if (e->name == NULL && e->name_len != 0) return -1;

    need = verthys_lsm_entry_encoded_len(e);
    if (cap < need) return -1;

    put_u64le(buf + 0, e->lid);
    buf[8]  = e->type;
    buf[9]  = e->tombstone;
    buf[10] = e->slot_state;
    buf[11] = 0;                       /* 保留 */
    put_u16le(buf + 12, e->name_len);
    put_u64le(buf + 14, e->data_size);
    put_u32le(buf + 22, e->plaintext_size);
    put_u32le(buf + 26, e->extent_size);
    memcpy(buf + 30, e->hash, 32);
    put_u64le(buf + 62, e->created_txid);
    put_u64le(buf + 70, e->created_time);
    if (e->name_len != 0) {
        memcpy(buf + VERTHYS_LSM_ENTRY_HEADER_BYTES, e->name, e->name_len);
    }
    return 0;
}

size_t verthys_lsm_entry_decode(const uint8_t *buf, size_t len, VerthysLsmEntry *out)
{
    uint16_t name_len;
    size_t total;

    if (buf == NULL || out == NULL || len < VERTHYS_LSM_ENTRY_HEADER_BYTES) return 0;

    name_len = get_u16le(buf + 12);
    if (name_len > VERTHYS_LSM_NAME_MAX_BYTES) return 0;
    total = VERTHYS_LSM_ENTRY_HEADER_BYTES + (size_t)name_len;
    if (len < total) return 0;

    memset(out, 0, sizeof(*out));
    out->lid            = get_u64le(buf + 0);
    out->type           = buf[8];
    out->tombstone      = buf[9];
    out->slot_state     = buf[10];
    out->name_len       = name_len;
    out->data_size      = get_u64le(buf + 14);
    out->plaintext_size = get_u32le(buf + 22);
    out->extent_size    = get_u32le(buf + 26);
    memcpy(out->hash, buf + 30, 32);
    out->created_txid   = get_u64le(buf + 62);
    out->created_time   = get_u64le(buf + 70);
    out->name           = (name_len != 0) ? (buf + VERTHYS_LSM_ENTRY_HEADER_BYTES) : NULL;
    return total;
}

/* ================== 跳表 MemTable ================== */

/* 节点：变长塔（next[height]）+ 条目（name 堆分配独立持有） */
typedef struct VerthysLsmMemNode {
    uint64_t lid;
    uint8_t  height;
    VerthysLsmEntry entry;        /* entry.name 指向 name_buf */
    uint8_t *name_buf;          /* name_len==0 时 NULL */
    struct VerthysLsmMemNode *next[1];
} VerthysLsmMemNode;

struct VerthysLsmMemTable {
    VerthysLsmMemNode *head;      /* 哨兵（塔高 MAX_HEIGHT） */
    unsigned level;             /* 当前最高有效层 */
    size_t count;
    size_t bytes;               /* 编码长度记账 */
    int frozen;
    uint32_t rng;               /* 塔高随机源（xorshift32，单写者） */
    /*
     * API 接线：本表当前最大 lid（O(1) 维护，插入时单调推高）。
     * 语义：仅反映本表内容——重建（rollback/purge）后随新表内容收缩。
     * "LID 永不复用"的单调性由上层 VerthysLsm.max_lid 承担（内存态不回退），
     * 本字段仅为 open/重放后初值合并提供 O(1) 数据源。
     */
    uint64_t max_lid;
};

/* 测试白盒：强制后续 memtable_create 返回 NULL（分配失败注入；
 * 仅 verthys_tests.exe 对象直链调用，不在 DLL 导出清单中） */
static int s_test_force_alloc_fail = 0;

void verthys_lsm_memtable_test_force_alloc_fail(int enabled)
{
    s_test_force_alloc_fail = enabled ? 1 : 0;
}

VerthysLsmMemTable *verthys_lsm_memtable_create(void)
{
    VerthysLsmMemTable *mt;

    if (s_test_force_alloc_fail) return NULL;
    mt = (VerthysLsmMemTable *)calloc(1, sizeof(*mt));
    if (mt == NULL) return NULL;

    /* 哨兵节点：塔高 MAX_HEIGHT，lid 语义无效（查找以比较结果走向） */
    mt->head = (VerthysLsmMemNode *)calloc(
        1, offsetof(VerthysLsmMemNode, next) +
               VERTHYS_LSM_MEMTABLE_MAX_HEIGHT * sizeof(VerthysLsmMemNode *));
    if (mt->head == NULL) {
        free(mt);
        return NULL;
    }
    mt->head->height = (uint8_t)VERTHYS_LSM_MEMTABLE_MAX_HEIGHT;
    mt->level = 1;
    mt->rng = 0x9E3779B9u;      /* 固定种子：行为可复现 */
    return mt;
}

static void memnode_chain_destroy(VerthysLsmMemNode *n)
{
    while (n != NULL) {
        VerthysLsmMemNode *next = n->next[0];
        if (n->name_buf != NULL) {
            verthys_secure_zero(n->name_buf, n->entry.name_len);
            free(n->name_buf);
        }
        free(n);
        n = next;
    }
}

void verthys_lsm_memtable_destroy(VerthysLsmMemTable *mt)
{
    if (mt == NULL) return;
    if (mt->head != NULL) {
        memnode_chain_destroy(mt->head->next[0]);
        free(mt->head);
    }
    free(mt);
}

void verthys_lsm_memtable_freeze(VerthysLsmMemTable *mt)
{
    if (mt != NULL) mt->frozen = 1;
}

int verthys_lsm_memtable_frozen(const VerthysLsmMemTable *mt)
{
    return (mt != NULL) ? mt->frozen : 0;
}

/* xorshift32 塔高采样：p=1/4 逐层晋升 */
static unsigned random_height(VerthysLsmMemTable *mt)
{
    unsigned h = 1;
    while (h < VERTHYS_LSM_MEMTABLE_MAX_HEIGHT && (mt->rng & 3u) == 0) {
        h++;
    }
    mt->rng ^= mt->rng << 13;
    mt->rng ^= mt->rng >> 17;
    mt->rng ^= mt->rng << 5;
    return h;
}

VerthysResult verthys_lsm_memtable_insert(VerthysLsmMemTable *mt, const VerthysLsmEntry *e)
{
    VerthysLsmMemNode *update[VERTHYS_LSM_MEMTABLE_MAX_HEIGHT];
    VerthysLsmMemNode *x;
    unsigned i;

    if (mt == NULL || e == NULL) return VERTHYS_ERR_INVALID;
    if (mt->frozen) return VERTHYS_ERR_INVALID;
    if (e->name_len > VERTHYS_LSM_NAME_MAX_BYTES) return VERTHYS_ERR_INVALID;
    if (e->name == NULL && e->name_len != 0) return VERTHYS_ERR_INVALID;

    /* 定位：记录每层前驱 */
    x = mt->head;
    for (i = mt->level; i >= 1; i--) {
        while (x->next[i - 1] != NULL && x->next[i - 1]->lid < e->lid) {
            x = x->next[i - 1];
        }
        update[i - 1] = x;
    }
    x = x->next[0];

    /* 同键覆盖：原地替换条目（RoW 语义），记账按前后编码长度差修正 */
    if (x != NULL && x->lid == e->lid) {
        size_t old_len = verthys_lsm_entry_encoded_len(&x->entry);
        size_t new_len = verthys_lsm_entry_encoded_len(e);
        uint8_t *nb = NULL;

        if (e->name_len != 0) {
            nb = (uint8_t *)malloc(e->name_len);
            if (nb == NULL) return VERTHYS_ERR_INTERNAL;
            memcpy(nb, e->name, e->name_len);
        }
        if (x->name_buf != NULL) {
            verthys_secure_zero(x->name_buf, x->entry.name_len);
            free(x->name_buf);
        }
        x->name_buf = nb;
        x->entry = *e;
        x->entry.name = nb;
        mt->bytes += new_len;
        mt->bytes -= old_len;
        if (e->lid > mt->max_lid) mt->max_lid = e->lid;   /* 覆盖亦可能推高 */
        return VERTHYS_OK;
    }

    {
        unsigned h = random_height(mt);
        VerthysLsmMemNode *n;
        uint8_t *nb = NULL;

        if (h > mt->level) {
            for (i = mt->level + 1; i <= h; i++) {
                update[i - 1] = mt->head;
            }
            mt->level = h;
        }

        if (e->name_len != 0) {
            nb = (uint8_t *)malloc(e->name_len);
            if (nb == NULL) return VERTHYS_ERR_INTERNAL;
            memcpy(nb, e->name, e->name_len);
        }

        n = (VerthysLsmMemNode *)malloc(
            offsetof(VerthysLsmMemNode, next) + h * sizeof(VerthysLsmMemNode *));
        if (n == NULL) {
            if (nb != NULL) free(nb);
            return VERTHYS_ERR_INTERNAL;
        }
        n->lid = e->lid;
        n->height = (uint8_t)h;
        n->name_buf = nb;
        n->entry = *e;
        n->entry.name = nb;

        for (i = 1; i <= h; i++) {
            n->next[i - 1] = update[i - 1]->next[i - 1];
            update[i - 1]->next[i - 1] = n;
        }
        mt->count++;
        mt->bytes += verthys_lsm_entry_encoded_len(e);
        if (e->lid > mt->max_lid) mt->max_lid = e->lid;
    }
    return VERTHYS_OK;
}

/* 本表当前最大 lid（空表返回 0；重建后随内容收缩——见结构体注释） */
uint64_t verthys_lsm_memtable_max_lid(const VerthysLsmMemTable *mt)
{
    return (mt != NULL) ? mt->max_lid : 0;
}

const VerthysLsmEntry *verthys_lsm_memtable_find(const VerthysLsmMemTable *mt, uint64_t lid)
{
    const VerthysLsmMemNode *x;
    unsigned i;

    if (mt == NULL) return NULL;
    x = mt->head;
    for (i = mt->level; i >= 1; i--) {
        while (x->next[i - 1] != NULL && x->next[i - 1]->lid < lid) {
            x = x->next[i - 1];
        }
    }
    x = x->next[0];
    if (x != NULL && x->lid == lid) return &x->entry;
    return NULL;
}

int verthys_lsm_memtable_needs_flush(const VerthysLsmMemTable *mt)
{
    if (mt == NULL) return 0;
    return (mt->count >= VERTHYS_LSM_MEMTABLE_MAX_ENTRIES ||
            mt->bytes >= VERTHYS_LSM_MEMTABLE_MAX_BYTES) ? 1 : 0;
}

size_t verthys_lsm_memtable_entry_count(const VerthysLsmMemTable *mt)
{
    return (mt != NULL) ? mt->count : 0;
}

size_t verthys_lsm_memtable_bytes(const VerthysLsmMemTable *mt)
{
    return (mt != NULL) ? mt->bytes : 0;
}

size_t verthys_lsm_memtable_iterate(const VerthysLsmMemTable *mt,
                                  VerthysLsmEntryCallback cb, void *user_data)
{
    size_t n = 0;
    const VerthysLsmMemNode *x;

    if (mt == NULL || cb == NULL) return 0;
    for (x = mt->head->next[0]; x != NULL; x = x->next[0]) {
        n++;
        if (cb(&x->entry, user_data) != 0) break;
    }
    return n;
}

/* ================== MemTable 升序迭代器（SSTable 写入输入源） ================== */

struct VerthysLsmMemIter {
    const VerthysLsmMemNode *cur;    /* 下一个待产出节点 */
};

static int memtable_iter_next(VerthysLsmEntryIter *it, const VerthysLsmEntry **out)
{
    VerthysLsmMemIter *mi = (VerthysLsmMemIter *)it->ctx;

    if (mi == NULL || out == NULL) return -1;
    if (mi->cur == NULL) return 0;
    *out = &mi->cur->entry;
    mi->cur = mi->cur->next[0];
    return 1;
}

VerthysResult verthys_lsm_memtable_iter_start(const VerthysLsmMemTable *mt,
                                          VerthysLsmEntryIter *it, VerthysLsmMemIter **out)
{
    VerthysLsmMemIter *mi;

    if (mt == NULL || it == NULL || out == NULL) return VERTHYS_ERR_INVALID;
    mi = (VerthysLsmMemIter *)calloc(1, sizeof(*mi));
    if (mi == NULL) return VERTHYS_ERR_INTERNAL;
    mi->cur = mt->head->next[0];
    it->next = memtable_iter_next;
    it->ctx = mi;
    *out = mi;
    return VERTHYS_OK;
}

void verthys_lsm_memtable_iter_end(VerthysLsmMemIter *mi)
{
    free(mi);
}
