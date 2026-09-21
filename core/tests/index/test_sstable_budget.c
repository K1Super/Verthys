/*
 * test_sstable_budget.c — SSTable 写前预算回归
 *
 * 覆盖：
 *   1. 紧容量场景：flush 产物超出数据区剩余容量时，必须在任何越界
 *      字节物理落盘之前拒绝；数据区边界之后的内容（真实容器中紧邻
 *      extent 数据区的密文）不得被覆写，游标不推进、meta 不登记。
 *   2. 充足容量场景：正常写入路径行为不变（成功返回、游标推进、
 *      产物可经查找路径读回）。
 */
#include "verthys_test.h"
#include "verthys_lsm_internal.h"
#include "verthys_partition.h"
#include "verthys_crypto.h"
#include "verthys_internal.h"
#include "verthys_io.h"

#include <string.h>
#include <stdlib.h>

#define SSTB_TMP         "test_sstable_budget.tmp"
#define SSTB_KEY_BYTES   VERTHYS_CNG_KEY_BYTES
#define SSTB_PART_ID     11u
#define SSTB_REGION_SIZE (2u * 1024u * 1024u)
#define SSTB_DATA_BASE   0u
/* 小于单块帧长（帧头 8 + 定长头 78 + 名称 + tag 16 + 帧尾 12），
 * 迫使首个数据块即越界 */
#define SSTB_TIGHT_LIMIT 64u
#define SSTB_ROOMY_LIMIT (64u * 1024u)
#define SSTB_SENTINEL_BYTES 512u

static void sstb_cleanup(void) { remove(SSTB_TMP); }

/* 脚手架：新建容器文件 + 随机 wrapping 密钥 + Index 分区 */
static int sstb_setup(VerthysCngAead *wrap, uint8_t wk[SSTB_KEY_BYTES],
                      VerthysPartition *part, FILE **fout)
{
    FILE *f = NULL;

    sstb_cleanup();
    if (verthys_cng_aead_init(wrap) != VERTHYS_OK) return -1;
    verthys_random_bytes(wk, SSTB_KEY_BYTES);
    {
        uint8_t copy[SSTB_KEY_BYTES];
        memcpy(copy, wk, SSTB_KEY_BYTES);
        if (verthys_cng_aead_import_key(wrap, copy, NULL) != VERTHYS_OK) return -1;
    }
    if (verthys_partition_create(part, SSTB_PART_ID, VERTHYS_PARTITION_INDEX,
                               0, SSTB_REGION_SIZE, 1, wrap) != VERTHYS_OK) {
        return -1;
    }
    fopen_s(&f, SSTB_TMP, "w+b");
    if (f == NULL) return -1;
    *fout = f;
    return 0;
}

static void sstb_teardown(VerthysPartition *part, VerthysCngAead *wrap,
                          uint8_t wk[SSTB_KEY_BYTES], FILE *f)
{
    if (f != NULL) fclose(f);
    verthys_partition_destroy(part);
    verthys_cng_aead_destroy(wrap);
    verthys_secure_zero(wk, SSTB_KEY_BYTES);
    sstb_cleanup();
}

/* 数据区边界之后预埋哨兵字节（模拟紧邻 extent 数据区内容） */
static int sstb_fill_sentinel(FILE *f, uint64_t start, size_t bytes)
{
    uint8_t *pat = (uint8_t *)malloc(bytes);
    int ok;

    if (pat == NULL) return -1;
    memset(pat, 0xA5, bytes);
    ok = (vio_pwrite64(f, start, pat, bytes) == 0);
    free(pat);
    return ok ? 0 : -1;
}

static int sstb_sentinel_intact(FILE *f, uint64_t start, size_t bytes)
{
    uint8_t *pat = (uint8_t *)malloc(bytes);
    int ok = 1;

    if (pat == NULL) return 0;
    if (vio_pread64(f, start, pat, bytes) != 0) {
        free(pat);
        return 0;
    }
    for (size_t i = 0; i < bytes; i++) {
        if (pat[i] != 0xA5) { ok = 0; break; }
    }
    free(pat);
    return ok;
}

static VerthysResult sstb_insert_entry(VerthysLsmMemTable *mt, uint64_t lid,
                                       const char *name, uint64_t txid)
{
    VerthysLsmEntry e;

    memset(&e, 0, sizeof(e));
    e.lid = lid;
    e.type = 2;
    e.slot_state = 1;
    e.name = (const uint8_t *)name;
    e.name_len = (uint16_t)strlen(name);
    e.data_size = 128;
    e.plaintext_size = 128;
    e.extent_size = 144;
    e.created_txid = txid;
    e.created_time = 1700000000u;
    return verthys_lsm_memtable_insert(mt, &e);
}

/* ---------- 1. 紧容量：越界字节不得落盘 ---------- */

TEST(sstb_budget_rejects_before_physical_write)
{
    VerthysCngAead wrap;
    uint8_t wk[SSTB_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsmMemTable *mt = NULL;
    VerthysLsmEntryIter it;
    VerthysLsmMemIter *mi = NULL;
    VerthysLsmTableMeta meta;
    uint64_t rel = 0;
    VerthysResult r_write;
    int sentinel_ok;

    CHECK(sstb_setup(&wrap, wk, &part, &f) == 0);
    mt = verthys_lsm_memtable_create();
    CHECK(mt != NULL);
    CHECK(sstb_insert_entry(mt, 1, "budget-entry-one", 5) == VERTHYS_OK);
    CHECK(sstb_insert_entry(mt, 2, "budget-entry-two", 5) == VERTHYS_OK);
    CHECK(verthys_lsm_memtable_iter_start(mt, &it, &mi) == VERTHYS_OK);

    CHECK(sstb_fill_sentinel(f, SSTB_DATA_BASE + SSTB_TIGHT_LIMIT,
                             SSTB_SENTINEL_BYTES) == 0);

    /* 先完成全部操作与资源清理，再统一断言（断言失败立即返回
     * 不跳过清理，避免单用例失败污染后续用例） */
    memset(&meta, 0, sizeof(meta));
    r_write = verthys_lsm_sstable_write(f, &part, &it, 2, 5, 1, 0,
                                       SSTB_DATA_BASE, &rel, SSTB_TIGHT_LIMIT,
                                       &meta);
    sentinel_ok = sstb_sentinel_intact(f, SSTB_DATA_BASE + SSTB_TIGHT_LIMIT,
                                       SSTB_SENTINEL_BYTES);
    verthys_lsm_memtable_iter_end(mi);
    verthys_lsm_memtable_destroy(mt);
    sstb_teardown(&part, &wrap, wk, f);

    CHECK(r_write == VERTHYS_ERR_RESOURCE_LIMIT);
    CHECK(rel == 0);        /* 游标不推进 */
    CHECK(meta.size == 0);  /* meta 未登记 */
    /* 核心断言：数据区边界之后的内容一个字节都不许动 */
    CHECK(sentinel_ok);
    return 0;
}

/* ---------- 2. 充足容量：正常路径行为不变 ---------- */

TEST(sstb_budget_normal_write_unaffected)
{
    VerthysCngAead wrap;
    uint8_t wk[SSTB_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsmMemTable *mt = NULL;
    VerthysLsmEntryIter it;
    VerthysLsmMemIter *mi = NULL;
    VerthysLsmTableMeta meta;
    VerthysLsmEntry out;
    uint8_t name_buf[64];
    uint64_t rel = 0;
    VerthysResult r_write;
    VerthysResult r_find;
    int sentinel_ok;

    CHECK(sstb_setup(&wrap, wk, &part, &f) == 0);
    mt = verthys_lsm_memtable_create();
    CHECK(mt != NULL);
    CHECK(sstb_insert_entry(mt, 1, "budget-entry-one", 5) == VERTHYS_OK);
    CHECK(sstb_insert_entry(mt, 2, "budget-entry-two", 5) == VERTHYS_OK);
    CHECK(verthys_lsm_memtable_iter_start(mt, &it, &mi) == VERTHYS_OK);

    CHECK(sstb_fill_sentinel(f, SSTB_DATA_BASE + SSTB_ROOMY_LIMIT,
                             SSTB_SENTINEL_BYTES) == 0);

    memset(&meta, 0, sizeof(meta));
    r_write = verthys_lsm_sstable_write(f, &part, &it, 2, 5, 1, 0,
                                       SSTB_DATA_BASE, &rel, SSTB_ROOMY_LIMIT,
                                       &meta);
    sentinel_ok = sstb_sentinel_intact(f, SSTB_DATA_BASE + SSTB_ROOMY_LIMIT,
                                       SSTB_SENTINEL_BYTES);

    /* 产物可读：查找路径命中（Footer/Bloom/块索引全链路有效） */
    memset(&out, 0, sizeof(out));
    r_find = (r_write == VERTHYS_OK)
        ? verthys_lsm_sstable_find(f, &part, &meta, 1, &out,
                                   name_buf, sizeof(name_buf), NULL)
        : VERTHYS_ERR_INTERNAL;

    verthys_lsm_sstable_meta_release(&meta);
    verthys_lsm_memtable_iter_end(mi);
    verthys_lsm_memtable_destroy(mt);
    sstb_teardown(&part, &wrap, wk, f);

    CHECK(r_write == VERTHYS_OK);
    CHECK(rel > 0);
    CHECK(meta.size == (uint32_t)rel);
    CHECK(meta.entry_count == 2);
    CHECK(sentinel_ok);
    CHECK(r_find == VERTHYS_OK);
    CHECK(out.lid == 1);
    CHECK(out.name_len == strlen("budget-entry-one"));
    CHECK(memcmp(name_buf, "budget-entry-one", strlen("budget-entry-one")) == 0);
    return 0;
}
