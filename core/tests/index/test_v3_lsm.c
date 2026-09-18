/*
 * test_v3_lsm.c — WP-4 验收：V3 LSM 索引（MemTable + SSTable + Compaction）
 *
 * 覆盖（PLAYBOOK WP-4 步骤 + 验收标准）：
 *   1. 生命周期：空区域 open 初始化 Manifest → 统计全 0 → close 幂等
 *   2. put/get roundtrip：全字段逐项校验 + 变长名称 roundtrip +
 *      name_len_out 回传
 *   3. 同键覆盖：后写胜出（created_txid/名称/大小更新）
 *   4. 删除墓碑：get NOTFOUND（遮蔽）+ 不存在键删除幂等 + 复活写
 *   5. flush：MemTable → L0 SSTable（统计断言 + get 走盘路径仍命中）
 *   6. 重启持久化：close → 重新 open → Manifest/数据完整恢复
 *   7. WAL 崩溃恢复：未 flush 即崩溃（跳过 close）→ 重开重放 → 命中
 *   8. Compaction 触发与 L0 归并：4 表触发 → compact → L0=0/L1=1 →
 *      全键命中（k 路归并 + Bloom + 块索引读取路径）
 *   9. Compaction 版本归并：跨表同键 → 新版本胜出
 *  10. Compaction 墓碑遮蔽：delete 后 compact → NOTFOUND
 *  11. Manifest 帧篡改 → open 拒绝（AUTH）
 *  12. 查找边界：未存在键 NOTFOUND、name 容量不足 INVALID
 *  13. 全 API NULL 参数校验
 */
#include "verthys_test.h"
#include "verthys_lsm.h"
#include "verthys_lsm_internal.h"
#include "verthys_partition.h"
#include "verthys_crypto.h"
#include "verthys_internal.h"
#include "verthys_io.h"

#include <string.h>
#include <stdlib.h>

#define V3L_TMP        "test_v3_lsm.tmp"
#define V3L_KEY_BYTES  VERTHYS_CNG_KEY_BYTES
#define V3L_PART_ID    9u
#define V3L_REGION_OFFSET 0u
#define V3L_REGION_SIZE   (80u * 1024u * 1024u)  /* Manifest 1MB + WAL 68MB + 数据区 */

static void v3l_cleanup(void) { remove(V3L_TMP); }

/* 测试脚手架：新建容器文件 + 随机 wrapping 密钥 + Index 分区 */
static int v3l_setup(VerthysCngAead *wrap, uint8_t wk[V3L_KEY_BYTES],
                     VerthysPartition *part, FILE **fout)
{
    FILE *f = NULL;

    v3l_cleanup();
    if (verthys_cng_aead_init(wrap) != VERTHYS_OK) return -1;
    verthys_random_bytes(wk, V3L_KEY_BYTES);
    {
        uint8_t copy[V3L_KEY_BYTES];
        memcpy(copy, wk, V3L_KEY_BYTES);
        if (verthys_cng_aead_import_key(wrap, copy, NULL) != VERTHYS_OK) return -1;
    }
    if (verthys_partition_create(part, V3L_PART_ID, VERTHYS_PARTITION_INDEX,
                               0, V3L_REGION_SIZE, 1, wrap) != VERTHYS_OK) {
        return -1;
    }
    fopen_s(&f, V3L_TMP, "w+b");
    if (f == NULL) return -1;
    *fout = f;
    return 0;
}

static void v3l_teardown(VerthysPartition *part, VerthysCngAead *wrap,
                         uint8_t wk[V3L_KEY_BYTES], FILE *f)
{
    if (f != NULL) fclose(f);
    verthys_partition_destroy(part);
    verthys_cng_aead_destroy(wrap);
    verthys_secure_zero(wk, V3L_KEY_BYTES);
    v3l_cleanup();
}

/* 确定性条目构造（seed 区分内容字段） */
static void v3l_make_entry(VerthysLsmEntry *e, uint64_t lid, const char *name,
                           uint64_t txid, uint8_t seed)
{
    memset(e, 0, sizeof(*e));
    e->lid = lid;
    e->type = (uint8_t)(seed % 8u);
    e->tombstone = 0;
    e->slot_state = 1;
    e->name_len = (uint16_t)strlen(name);
    e->name = (const uint8_t *)name;
    e->data_size = 100u + seed;
    e->plaintext_size = 100u + seed;
    e->extent_size = 100u + seed + 16u;
    for (int i = 0; i < 32; i++) e->hash[i] = (uint8_t)(seed + i);
    e->created_txid = txid;
    e->created_time = 1700000000u + seed;
}

/* 全字段比对（out.name 已拷入 name_buf → 指针不同，逐字段断言） */
static int v3l_entry_equals(const VerthysLsmEntry *a, const VerthysLsmEntry *b)
{
    if (a->lid != b->lid) return 0;
    if (a->type != b->type) return 0;
    if (a->tombstone != b->tombstone) return 0;
    if (a->slot_state != b->slot_state) return 0;
    if (a->name_len != b->name_len) return 0;
    if (a->name_len != 0 && memcmp(a->name, b->name, a->name_len) != 0) return 0;
    if (a->data_size != b->data_size) return 0;
    if (a->plaintext_size != b->plaintext_size) return 0;
    if (a->extent_size != b->extent_size) return 0;
    if (memcmp(a->hash, b->hash, 32) != 0) return 0;
    if (a->created_txid != b->created_txid) return 0;
    if (a->created_time != b->created_time) return 0;
    return 1;
}

/* ---------- 1. 生命周期 ---------- */

TEST(v3lsm_open_close_roundtrip)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    CHECK(verthys_lsm_table_count(&lsm) == 0);
    CHECK(verthys_lsm_level_table_count(&lsm, 0) == 0);
    CHECK(verthys_lsm_level_table_count(&lsm, 1) == 0);
    CHECK(verthys_lsm_level_bytes(&lsm, 0) == 0);
    CHECK(verthys_lsm_memtable_count(&lsm) == 0);
    CHECK(verthys_lsm_needs_compaction(&lsm) == 0);
    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    CHECK(verthys_lsm_close(NULL) == VERTHYS_OK);   /* 幂等 */
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}

/* ---------- 2. put/get roundtrip ---------- */

TEST(v3lsm_put_get_roundtrip)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry in, out;
    uint8_t name_buf[64];
    size_t name_len = 0;

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    v3l_make_entry(&in, 42, "record-forty-two", 7, 3u);
    CHECK(verthys_lsm_put(&lsm, 7, &in) == VERTHYS_OK);
    CHECK(verthys_lsm_memtable_count(&lsm) == 1);

    memset(&out, 0, sizeof(out));
    CHECK(verthys_lsm_get(&lsm, 42, &out, name_buf, sizeof(name_buf), &name_len)
          == VERTHYS_OK);
    CHECK(v3l_entry_equals(&in, &out));
    CHECK(name_len == strlen("record-forty-two"));
    CHECK(memcmp(name_buf, "record-forty-two", name_len) == 0);

    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}

/* ---------- 3. 同键覆盖 ---------- */

TEST(v3lsm_put_overwrite)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry v1, v2, out;
    uint8_t name_buf[64];

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    v3l_make_entry(&v1, 100, "version-one", 1, 10u);
    v3l_make_entry(&v2, 100, "version-two", 2, 20u);
    CHECK(verthys_lsm_put(&lsm, 1, &v1) == VERTHYS_OK);
    CHECK(verthys_lsm_put(&lsm, 2, &v2) == VERTHYS_OK);
    CHECK(verthys_lsm_memtable_count(&lsm) == 1);   /* 覆盖非新增 */

    memset(&out, 0, sizeof(out));
    CHECK(verthys_lsm_get(&lsm, 100, &out, name_buf, sizeof(name_buf), NULL)
          == VERTHYS_OK);
    CHECK(v3l_entry_equals(&v2, &out));
    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}

/* ---------- 4. 删除墓碑 ---------- */

TEST(v3lsm_delete_tombstone)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry in, out;
    uint8_t name_buf[64];

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    v3l_make_entry(&in, 7, "doomed", 1, 5u);
    CHECK(verthys_lsm_put(&lsm, 1, &in) == VERTHYS_OK);
    CHECK(verthys_lsm_get(&lsm, 7, &out, name_buf, sizeof(name_buf), NULL)
          == VERTHYS_OK);
    CHECK(verthys_lsm_delete(&lsm, 2, 7) == VERTHYS_OK);
    CHECK(verthys_lsm_get(&lsm, 7, &out, name_buf, sizeof(name_buf), NULL)
          == VERTHYS_ERR_NOTFOUND);
    /* 不存在键删除幂等 */
    CHECK(verthys_lsm_delete(&lsm, 3, 999) == VERTHYS_OK);
    /* 复活写：新版本覆盖墓碑 */
    v3l_make_entry(&in, 7, "revived", 4, 6u);
    CHECK(verthys_lsm_put(&lsm, 4, &in) == VERTHYS_OK);
    memset(&out, 0, sizeof(out));
    CHECK(verthys_lsm_get(&lsm, 7, &out, name_buf, sizeof(name_buf), NULL)
          == VERTHYS_OK);
    CHECK(v3l_entry_equals(&in, &out));
    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}
/* ---------- 5. flush → L0 SSTable ---------- */

TEST(v3lsm_flush_to_sstable)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry in[3], out;
    uint8_t name_buf[64];
    uint64_t lids[3] = { 11, 22, 33 };

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    char names[3][32];
    for (int i = 0; i < 3; i++) {
        sprintf_s(names[i], sizeof(names[i]), "flush-entry-%d", i);
        v3l_make_entry(&in[i], lids[i], names[i], 1, (uint8_t)(10 + i));
        CHECK(verthys_lsm_put(&lsm, 1, &in[i]) == VERTHYS_OK);
    }
    CHECK(verthys_lsm_memtable_count(&lsm) == 3);
    CHECK(verthys_lsm_table_count(&lsm) == 0);

    CHECK(verthys_lsm_flush(&lsm) == VERTHYS_OK);
    CHECK(verthys_lsm_memtable_count(&lsm) == 0);
    CHECK(verthys_lsm_table_count(&lsm) == 1);
    CHECK(verthys_lsm_level_table_count(&lsm, 0) == 1);
    CHECK(verthys_lsm_level_bytes(&lsm, 0) > 0);
    CHECK(verthys_lsm_needs_compaction(&lsm) == 0);   /* 1 表 < 触发值 4 */

    /* get 走 SSTable 盘路径（MemTable 已空）——全部命中 */
    for (int i = 0; i < 3; i++) {
        memset(&out, 0, sizeof(out));
        CHECK(verthys_lsm_get(&lsm, lids[i], &out, name_buf, sizeof(name_buf), NULL)
              == VERTHYS_OK);
        CHECK(v3l_entry_equals(&in[i], &out));
    }

    /* 空 MemTable flush = no-op */
    CHECK(verthys_lsm_flush(&lsm) == VERTHYS_OK);
    CHECK(verthys_lsm_table_count(&lsm) == 1);
    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}

/* ---------- 6. 重启持久化 ---------- */

TEST(v3lsm_reopen_persistence)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry in, out;
    uint8_t name_buf[64];

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    v3l_make_entry(&in, 555, "persist-me", 9, 42u);
    CHECK(verthys_lsm_put(&lsm, 9, &in) == VERTHYS_OK);
    CHECK(verthys_lsm_flush(&lsm) == VERTHYS_OK);
    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);   /* close 保存 Manifest */

    /* 重开：Manifest 加载 + SSTable 读取路径 */
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    CHECK(verthys_lsm_table_count(&lsm) == 1);
    CHECK(verthys_lsm_level_table_count(&lsm, 0) == 1);
    memset(&out, 0, sizeof(out));
    CHECK(verthys_lsm_get(&lsm, 555, &out, name_buf, sizeof(name_buf), NULL)
          == VERTHYS_OK);
    CHECK(v3l_entry_equals(&in, &out));
    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}

/* ---------- 7. WAL 崩溃恢复 ---------- */

TEST(v3lsm_wal_crash_recovery)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry in, out;
    uint8_t name_buf[64];

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    v3l_make_entry(&in, 777, "wal-only-entry", 3, 17u);
    CHECK(verthys_lsm_put(&lsm, 3, &in) == VERTHYS_OK);
    CHECK(verthys_lsm_memtable_count(&lsm) == 1);

    /* 模拟崩溃：跳过 verthys_lsm_close（WAL 未复位、MemTable 未落盘），
     * 直接 fclose 丢弃全部内存态——恢复完全依赖 WAL 重放 */
    fclose(f);
    f = NULL;

    fopen_s(&f, V3L_TMP, "r+b");
    CHECK(f != NULL);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    memset(&out, 0, sizeof(out));
    CHECK(verthys_lsm_get(&lsm, 777, &out, name_buf, sizeof(name_buf), NULL)
          == VERTHYS_OK);
    CHECK(v3l_entry_equals(&in, &out));
    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}

/* ---------- 8. Compaction：L0 触发与归并 ---------- */

TEST(v3lsm_compaction_l0_merge)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry in[8], out;
    uint8_t name_buf[64];
    uint64_t lids[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);

    /* 4 组 put+flush → 4 个 L0 表（≥ 触发值） */
    char names[4][32];
    for (int i = 0; i < 4; i++) {
        sprintf_s(names[i], sizeof(names[i]), "l0-table-%d", i);
        v3l_make_entry(&in[i], lids[i], names[i], 1, (uint8_t)(20 + i));
        CHECK(verthys_lsm_put(&lsm, 1, &in[i]) == VERTHYS_OK);
        CHECK(verthys_lsm_flush(&lsm) == VERTHYS_OK);
    }
    CHECK(verthys_lsm_level_table_count(&lsm, 0) == 4);
    CHECK(verthys_lsm_needs_compaction(&lsm) == 1);

    CHECK(verthys_lsm_compact(&lsm) == VERTHYS_OK);
    CHECK(verthys_lsm_level_table_count(&lsm, 0) == 0);
    CHECK(verthys_lsm_level_table_count(&lsm, 1) == 1);
    CHECK(verthys_lsm_needs_compaction(&lsm) == 0);

    /* 归并后全键命中（Bloom + 块索引 + L1 读取路径） */
    for (int i = 0; i < 4; i++) {
        memset(&out, 0, sizeof(out));
        CHECK(verthys_lsm_get(&lsm, lids[i], &out, name_buf, sizeof(name_buf), NULL)
              == VERTHYS_OK);
        CHECK(v3l_entry_equals(&in[i], &out));
    }

    /* 归并后再写入新表（L1 之上 L0 查找序优先） */
    v3l_make_entry(&in[4], lids[4], "post-compaction", 2, 30u);
    CHECK(verthys_lsm_put(&lsm, 2, &in[4]) == VERTHYS_OK);
    memset(&out, 0, sizeof(out));
    CHECK(verthys_lsm_get(&lsm, lids[4], &out, name_buf, sizeof(name_buf), NULL)
          == VERTHYS_OK);
    CHECK(v3l_entry_equals(&in[4], &out));

    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}

/* ---------- 9. Compaction：跨表同键版本归并 ---------- */

TEST(v3lsm_compaction_shadowing)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry old_v, new_v, out;
    uint8_t name_buf[64];
    int i;

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);

    /* 填充 3 表 + 旧版本表（共 4 表触发） */
    for (i = 0; i < 3; i++) {
        char name[32];
        sprintf_s(name, sizeof(name), "filler-%d", i);
        v3l_make_entry(&old_v, 900 + i, name, 1, 40u);
        CHECK(verthys_lsm_put(&lsm, 1, &old_v) == VERTHYS_OK);
        CHECK(verthys_lsm_flush(&lsm) == VERTHYS_OK);
    }
    /* 旧版本（表 seq 较小）→ 新版本（表 seq 较大）：同 lid=500 */
    v3l_make_entry(&old_v, 500, "old-version", 1, 41u);
    CHECK(verthys_lsm_put(&lsm, 1, &old_v) == VERTHYS_OK);
    CHECK(verthys_lsm_flush(&lsm) == VERTHYS_OK);
    v3l_make_entry(&new_v, 500, "new-version", 2, 42u);
    CHECK(verthys_lsm_put(&lsm, 2, &new_v) == VERTHYS_OK);
    CHECK(verthys_lsm_flush(&lsm) == VERTHYS_OK);   /* 第 5 表：触发 */

    CHECK(verthys_lsm_needs_compaction(&lsm) == 1);
    CHECK(verthys_lsm_compact(&lsm) == VERTHYS_OK);
    CHECK(verthys_lsm_level_table_count(&lsm, 0) == 0);
    CHECK(verthys_lsm_level_table_count(&lsm, 1) == 1);

    /* 新版本胜出（同层 seq 大者新 → k 路归并胜者判定） */
    memset(&out, 0, sizeof(out));
    CHECK(verthys_lsm_get(&lsm, 500, &out, name_buf, sizeof(name_buf), NULL)
          == VERTHYS_OK);
    CHECK(v3l_entry_equals(&new_v, &out));

    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}
/* ---------- 10. Compaction：墓碑遮蔽 ---------- */

TEST(v3lsm_compaction_tombstone)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry in, out;
    uint8_t name_buf[64];
    int i;

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);

    /* 值表（lid=600 存活）+ 填充 2 表 + 墓碑表 = 4 表触发 */
    v3l_make_entry(&in, 600, "alive", 1, 50u);
    CHECK(verthys_lsm_put(&lsm, 1, &in) == VERTHYS_OK);
    CHECK(verthys_lsm_flush(&lsm) == VERTHYS_OK);
    for (i = 0; i < 2; i++) {
        char name[32];
        sprintf_s(name, sizeof(name), "filler-%d", i);
        v3l_make_entry(&in, 910 + i, name, 1, 51u);
        CHECK(verthys_lsm_put(&lsm, 1, &in) == VERTHYS_OK);
        CHECK(verthys_lsm_flush(&lsm) == VERTHYS_OK);
    }
    CHECK(verthys_lsm_delete(&lsm, 2, 600) == VERTHYS_OK);
    CHECK(verthys_lsm_flush(&lsm) == VERTHYS_OK);   /* 墓碑随 MemTable 落 L0 */

    CHECK(verthys_lsm_needs_compaction(&lsm) == 1);
    CHECK(verthys_lsm_compact(&lsm) == VERTHYS_OK);
    CHECK(verthys_lsm_level_table_count(&lsm, 1) == 1);

    /* 墓碑归并进 L1 → 继续遮蔽旧值 */
    CHECK(verthys_lsm_get(&lsm, 600, &out, name_buf, sizeof(name_buf), NULL)
          == VERTHYS_ERR_NOTFOUND);
    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}

/* ---------- 11. Manifest 帧篡改 ---------- */

TEST(v3lsm_manifest_tamper_rejected)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry in;
    uint8_t byte;
    VerthysResult r;

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    v3l_make_entry(&in, 888, "tamper-target", 1, 60u);
    CHECK(verthys_lsm_put(&lsm, 1, &in) == VERTHYS_OK);
    CHECK(verthys_lsm_flush(&lsm) == VERTHYS_OK);
    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);

    /* 翻转 Manifest 帧密文区 1 字节（帧头 8B 之后）→ AEAD 认证失败 */
    CHECK(vio_pread64(f, V3L_REGION_OFFSET + 16, &byte, 1) == 0);
    byte ^= 0xFF;
    CHECK(vio_pwrite64(f, V3L_REGION_OFFSET + 16, &byte, 1) == 0);
    fclose(f);
    f = NULL;

    fopen_s(&f, V3L_TMP, "r+b");
    CHECK(f != NULL);
    r = verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0);
    CHECK(r == VERTHYS_ERR_AUTH || r == VERTHYS_ERR_FORMAT);
    /* open 失败不持资源 → 仅关文件 */
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}

/* ---------- 12. 查找边界 ---------- */

TEST(v3lsm_get_notfound_and_invalid)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry in, out;
    uint8_t name_buf[64];
    uint8_t tiny_buf[2];

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    v3l_make_entry(&in, 1234, "a-rather-long-name", 1, 70u);
    CHECK(verthys_lsm_put(&lsm, 1, &in) == VERTHYS_OK);

    /* 未存在键 */
    CHECK(verthys_lsm_get(&lsm, 4321, &out, name_buf, sizeof(name_buf), NULL)
          == VERTHYS_ERR_NOTFOUND);
    /* 探测模式（out/name_buf NULL） */
    CHECK(verthys_lsm_get(&lsm, 1234, NULL, NULL, 0, NULL) == VERTHYS_OK);
    CHECK(verthys_lsm_get(&lsm, 4321, NULL, NULL, 0, NULL) == VERTHYS_ERR_NOTFOUND);
    /* 名称容量不足 */
    CHECK(verthys_lsm_get(&lsm, 1234, &out, tiny_buf, sizeof(tiny_buf), NULL)
          == VERTHYS_ERR_INVALID);
    /* put NULL 条目 / tombstone 置位强制清零 */
    CHECK(verthys_lsm_put(&lsm, 1, NULL) == VERTHYS_ERR_INVALID);
    in.tombstone = 1;
    CHECK(verthys_lsm_put(&lsm, 1, &in) == VERTHYS_OK);   /* 强制清零路径 */
    in.tombstone = 0;
    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}

/* ---------- 13. 全 API NULL 参数校验 ---------- */

TEST(v3lsm_null_params_rejected)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry in;

    v3l_make_entry(&in, 1, "x", 1, 1u);
    CHECK(verthys_lsm_open(NULL, NULL, NULL, 0, 0, 0) == VERTHYS_ERR_INVALID);
    CHECK(verthys_lsm_put(NULL, 1, &in) == VERTHYS_ERR_INVALID);
    CHECK(verthys_lsm_get(NULL, 1, NULL, NULL, 0, NULL) == VERTHYS_ERR_INVALID);
    CHECK(verthys_lsm_delete(NULL, 1, 1) == VERTHYS_ERR_INVALID);
    CHECK(verthys_lsm_flush(NULL) == VERTHYS_ERR_INVALID);
    CHECK(verthys_lsm_compact(NULL) == VERTHYS_ERR_INVALID);
    CHECK(verthys_lsm_needs_compaction(NULL) == 0);
    CHECK(verthys_lsm_table_count(NULL) == 0);
    CHECK(verthys_lsm_level_table_count(NULL, 0) == 0);
    CHECK(verthys_lsm_level_bytes(NULL, 0) == 0);
    CHECK(verthys_lsm_memtable_count(NULL) == 0);

    /* 正常 open 后传入无效 region 参数。
     * open 校验失败即未接管资源（无副作用）→ 不得调用 close
     * （lsm 为未初始化栈存储，close 操作垃圾指针 = 未定义行为） */
    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    CHECK(verthys_lsm_open(&lsm, NULL, &part, 0, V3L_REGION_SIZE, 0)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_lsm_open(&lsm, f, NULL, 0, V3L_REGION_SIZE, 0)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_lsm_open(&lsm, f, &part, 0, 0, 0) == VERTHYS_ERR_INVALID);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}
/* ---------- 14. 大规模插入 + 全量查找 ----------
 * PLAYBOOK WP-4 验收：>=50,000 条插入 + 全量 find（复用
 * repair_btree_large_insert 模式）。乱序键（Fisher-Yates 洗牌）覆盖
 * 跳表/多表 flush/compaction 归并/Bloom/块索引全路径。
 */

TEST(v3lsm_large_insert_find)
{
    VerthysCngAead wrap;
    uint8_t wk[V3L_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm lsm;
    VerthysLsmEntry in, out;
    uint8_t name_buf[64];
    const uint32_t N = 50000u;
    uint64_t *lids = NULL;
    char (*names)[24] = NULL;
    uint32_t rng = 0x12345678u;
    int tables_before;

    CHECK(v3l_setup(&wrap, wk, &part, &f) == 0);
    lids = (uint64_t *)malloc((size_t)N * sizeof(*lids));
    names = (char (*)[24])malloc((size_t)N * sizeof(*names));
    if (lids == NULL || names == NULL) {
        free(lids); free(names);
        v3l_teardown(&part, &wrap, wk, f);
        return 1;
    }

    /* 确定性乱序键（xorshift32 驱动 Fisher-Yates；键空间 1..99999 奇数） */
    for (uint32_t i = 0; i < N; i++) lids[i] = (uint64_t)i * 2u + 1u;
    for (uint32_t i = N - 1; i > 0; i--) {
        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
        {
            uint32_t j = rng % (i + 1u);
            uint64_t t = lids[i]; lids[i] = lids[j]; lids[j] = t;
        }
    }

    CHECK(verthys_lsm_open(&lsm, f, &part, V3L_REGION_OFFSET, V3L_REGION_SIZE, 0)
          == VERTHYS_OK);
    for (uint32_t i = 0; i < N; i++) {
        sprintf_s(names[i], sizeof(names[i]), "entry-%08llu",
                  (unsigned long long)(lids[i] / 2u));
        v3l_make_entry(&in, lids[i], names[i], 1, (uint8_t)(lids[i] % 200u));
        if (verthys_lsm_put(&lsm, 1, &in) != VERTHYS_OK) {
            printf("  [FAIL] put i=%u lid=%llu\n", i, (unsigned long long)lids[i]);
            return 1;
        }
    }
    /* 阈值 10,000 条/表自动 flush x5 → L0 >= 4 表（compaction 触发值） */
    if (verthys_lsm_table_count(&lsm) < 4 ||
        verthys_lsm_needs_compaction(&lsm) != 1) {
        printf("  [FAIL] tables=%zu needs=%d\n",
               verthys_lsm_table_count(&lsm), verthys_lsm_needs_compaction(&lsm));
        return 1;
    }

    tables_before = (int)verthys_lsm_table_count(&lsm);
    CHECK(verthys_lsm_compact(&lsm) == VERTHYS_OK);
    if ((int)verthys_lsm_table_count(&lsm) > tables_before) {
        printf("  [FAIL] table count grew: %d -> %zu\n", tables_before,
               verthys_lsm_table_count(&lsm));
        return 1;
    }

    /* 全量 find：50,000 条全部命中且全字段一致 */
    for (uint32_t i = 0; i < N; i++) {
        v3l_make_entry(&in, lids[i], names[i], 1, (uint8_t)(lids[i] % 200u));
        memset(&out, 0, sizeof(out));
        if (verthys_lsm_get(&lsm, lids[i], &out, name_buf, sizeof(name_buf),
                          NULL) != VERTHYS_OK ||
            !v3l_entry_equals(&in, &out)) {
            printf("  [FAIL] find i=%u lid=%llu\n", i,
                   (unsigned long long)lids[i]);
            return 1;
        }
    }
    /* 未写入键（偶数键）不得命中 */
    CHECK(verthys_lsm_get(&lsm, 100u, NULL, NULL, 0, NULL) == VERTHYS_ERR_NOTFOUND);

    CHECK(verthys_lsm_close(&lsm) == VERTHYS_OK);
    free(lids);
    free(names);
    v3l_teardown(&part, &wrap, wk, f);
    return 0;
}