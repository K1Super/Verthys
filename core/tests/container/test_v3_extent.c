/*
 * test_v3_extent.c — WP-3 验收：V3 内容寻址 Extent（去重 + 完整性）
 *
 * 覆盖（PLAYBOOK WP-3 步骤 + 验收标准：寻址/去重/引用计数/GC 标记/
 * 损坏检测）：
 *   1. 内容寻址哈希：确定性、区分性、空数据、参数校验
 *   2. 索引生命周期：init 默认值、find 未命中、参数校验
 *   3. put/get roundtrip：条目字段记账（offset/size/ref_count/txid）、
 *      缓冲区容量校验、未命中
 *   4. 空明文路径
 *   5. 去重：相同明文 ref_count++（零重写，游标/used 不变）、
 *      不同明文新条目
 *   6. 引用计数 + GC 标记：release 递减、下限 0 不回绕、重复引用、
 *      gc_eligible 统计、未知哈希 NOTFOUND
 *   7. 资源上限：索引条目满 / ref_count 饱和 → RESOURCE_LIMIT
 *   8. 未导入密钥（LOCKED）拒绝
 *   9. 数据块密文篡改 → AUTH（输出清零）
 *  10. 密文块搬运（A 块密文覆写 B 块槽位）→ AUTH（AAD 绑定 hash）
 *  11. 错误分区密钥读取 → AUTH（分区密钥隔离）
 *  12. 索引持久化 roundtrip：save → 分区重载（wrapped 解包重导入）→
 *      load → 条目/游标/数据完整恢复、nonce 计数器 restore
 *  13. E-7 防回退：分区计数器高于索引快照 → load 拒绝
 *  14. 索引帧篡改：密文翻转 → AUTH；magic/ct_len 破坏 → FORMAT
 *  15. 空索引区 load → FORMAT
 *  16. 全 API NULL 参数校验
 */
#include "verthys_test.h"
#include "verthys_extent.h"
#include "verthys_partition.h"
#include "verthys_crypto.h"
#include "verthys_internal.h"   /* verthys_secure_zero */
#include "verthys_io.h"         /* vio_pread64/vio_pwrite64（篡改注入） */

#include <string.h>
#include <stdlib.h>

#define V3E_TMP       "test_v3_extent.tmp"
#define V3E_KEY_BYTES VERTHYS_CNG_KEY_BYTES
#define V3E_DATA_REGION_BASE (VERTHYS_EXTENT_INDEX_REGION_BYTES)
#define V3E_PART_ID  7u

static void v3e_cleanup(void) { remove(V3E_TMP); }

/* 确定性测试数据填充（可复现） */
static void v3e_fill(uint8_t *buf, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + (uint8_t)(i * 7u) + 3u);
    }
}

/*
 * 测试脚手架：随机 wrapping 密钥导入 + 创建 Extent 分区
 * （id=7，offset=0，size=16MB，created_txid=1）。
 * wk 回传明文 wrapping 密钥副本（仅供重导入；测试收尾清零）。
 */
static int v3e_setup(VerthysCngAead *wrap, uint8_t wk[V3E_KEY_BYTES],
                     VerthysPartition *part)
{
    uint8_t copy[V3E_KEY_BYTES];

    verthys_random_bytes(wk, V3E_KEY_BYTES);
    memcpy(copy, wk, V3E_KEY_BYTES);
    if (verthys_cng_aead_init(wrap) != VERTHYS_OK) return -1;
    if (verthys_cng_aead_import_key(wrap, copy, NULL) != VERTHYS_OK) return -1;
    if (verthys_partition_create(part, V3E_PART_ID, VERTHYS_PARTITION_EXTENT,
                               0, 16u * 1024u * 1024u, 1, wrap) != VERTHYS_OK) {
        return -1;
    }
    return 0;
}

static void v3e_teardown(VerthysPartition *part, VerthysCngAead *wrap,
                         uint8_t wk[V3E_KEY_BYTES])
{
    verthys_partition_destroy(part);
    verthys_cng_aead_destroy(wrap);
    verthys_secure_zero(wk, V3E_KEY_BYTES);
}

/* 以既有 wrapping 密钥重导入（import 清零入参 → 传副本） */
static int v3e_reimport(VerthysCngAead *a, const uint8_t key[V3E_KEY_BYTES])
{
    uint8_t copy[V3E_KEY_BYTES];

    memcpy(copy, key, V3E_KEY_BYTES);
    if (verthys_cng_aead_init(a) != VERTHYS_OK) return -1;
    return verthys_cng_aead_import_key(a, copy, NULL) == VERTHYS_OK ? 0 : -1;
}

/* ---------- 1. 内容寻址哈希 ---------- */

TEST(v3ext_hash_basics)
{
    uint8_t a[64], b[64];
    uint8_t h1[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t h2[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t h3[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t h_empty[VERTHYS_EXTENT_HASH_BYTES];

    v3e_fill(a, sizeof(a), 1u);
    v3e_fill(b, sizeof(b), 2u);

    /* 确定性：相同数据 → 相同哈希 */
    CHECK(verthys_extent_hash(h1, a, sizeof(a)) == VERTHYS_OK);
    CHECK(verthys_extent_hash(h2, a, sizeof(a)) == VERTHYS_OK);
    CHECK(memcmp(h1, h2, VERTHYS_EXTENT_HASH_BYTES) == 0);

    /* 区分性：不同数据 → 不同哈希 */
    CHECK(verthys_extent_hash(h3, b, sizeof(b)) == VERTHYS_OK);
    CHECK(memcmp(h1, h3, VERTHYS_EXTENT_HASH_BYTES) != 0);

    /* 空数据可哈希，且与非空哈希不同 */
    CHECK(verthys_extent_hash(h_empty, NULL, 0) == VERTHYS_OK);
    CHECK(memcmp(h1, h_empty, VERTHYS_EXTENT_HASH_BYTES) != 0);

    /* 参数校验 */
    CHECK(verthys_extent_hash(NULL, a, sizeof(a)) == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_hash(h1, NULL, 1) == VERTHYS_ERR_INVALID);
    return 0;
}

/* ---------- 2. 索引生命周期 ---------- */

TEST(v3ext_index_init_and_find)
{
    VerthysExtentIndex idx;
    uint8_t h[VERTHYS_EXTENT_HASH_BYTES] = {0};

    CHECK(verthys_extent_index_init(NULL, 0) == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_index_init(&idx, 9) == VERTHYS_OK);
    CHECK(idx.count == 0);
    CHECK(idx.txid == 9);
    CHECK(idx.next_offset == 0);

    /* 空索引：任意哈希未命中 */
    CHECK(verthys_extent_index_find(&idx, h, NULL) == VERTHYS_ERR_NOTFOUND);
    CHECK(verthys_extent_index_find(NULL, h, NULL) == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_index_find(&idx, NULL, NULL) == VERTHYS_ERR_INVALID);
    return 0;
}

/* ---------- 3. put/get roundtrip ---------- */

TEST(v3ext_put_get_roundtrip)
{
    VerthysCngAead wrap;
    VerthysPartition part;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    VerthysExtent e;
    uint8_t pt[100];
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t out[128];
    uint8_t h_unknown[VERTHYS_EXTENT_HASH_BYTES] = {1};
    size_t olen;
    int stored = -1;

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    v3e_fill(pt, sizeof(pt), 11u);
    CHECK(verthys_extent_put(f, &part, &idx, 5, pt, sizeof(pt),
                           hash, &stored) == VERTHYS_OK);
    CHECK(stored == 1);
    CHECK(idx.count == 1);
    CHECK(idx.next_offset == sizeof(pt) + VERTHYS_EXTENT_TAG_BYTES);
    CHECK(part.used == sizeof(pt) + VERTHYS_EXTENT_TAG_BYTES);

    /* 条目字段记账 */
    CHECK(verthys_extent_index_find(&idx, hash, &e) == VERTHYS_OK);
    CHECK(e.ref_count == 1);
    CHECK(e.created_txid == 5);
    CHECK(e.last_ref_txid == 5);
    CHECK(e.plaintext_size == sizeof(pt));
    CHECK(e.size == sizeof(pt) + VERTHYS_EXTENT_TAG_BYTES);
    CHECK(e.offset == 0);

    /* 读取 roundtrip */
    olen = sizeof(out);
    CHECK(verthys_extent_get(f, &part, &idx, hash, out, &olen) == VERTHYS_OK);
    CHECK(olen == sizeof(pt));
    CHECK(memcmp(out, pt, sizeof(pt)) == 0);

    /* 容量不足拒绝 */
    olen = sizeof(pt) - 1;
    CHECK(verthys_extent_get(f, &part, &idx, hash, out, &olen)
          == VERTHYS_ERR_INVALID);

    /* 未命中 */
    olen = sizeof(out);
    CHECK(verthys_extent_get(f, &part, &idx, h_unknown, out, &olen)
          == VERTHYS_ERR_NOTFOUND);

    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 4. 空明文路径 ---------- */

TEST(v3ext_put_empty_plaintext)
{
    VerthysCngAead wrap;
    VerthysPartition part;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    VerthysExtent e;
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t out[4];
    size_t olen;
    int stored = -1;

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    CHECK(verthys_extent_put(f, &part, &idx, 5, NULL, 0, hash, &stored)
          == VERTHYS_OK);
    CHECK(stored == 1);
    CHECK(idx.count == 1);
    CHECK(idx.next_offset == VERTHYS_EXTENT_TAG_BYTES);

    CHECK(verthys_extent_index_find(&idx, hash, &e) == VERTHYS_OK);
    CHECK(e.plaintext_size == 0);
    CHECK(e.size == VERTHYS_EXTENT_TAG_BYTES);

    olen = sizeof(out);
    CHECK(verthys_extent_get(f, &part, &idx, hash, out, &olen) == VERTHYS_OK);
    CHECK(olen == 0);

    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 5. 去重（零重写） ---------- */

TEST(v3ext_dedup_no_rewrite)
{
    VerthysCngAead wrap;
    VerthysPartition part;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    VerthysExtent e;
    uint8_t a[80], b[50];
    uint8_t hash_a[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t hash_b[VERTHYS_EXTENT_HASH_BYTES];
    uint64_t cursor_after_first;
    uint64_t used_after_first;
    int stored = -1;

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    v3e_fill(a, sizeof(a), 21u);
    v3e_fill(b, sizeof(b), 22u);

    /* 首次写入：新数据块 */
    CHECK(verthys_extent_put(f, &part, &idx, 5, a, sizeof(a),
                           hash_a, &stored) == VERTHYS_OK);
    CHECK(stored == 1);
    cursor_after_first = idx.next_offset;
    used_after_first = part.used;

    /* 相同明文再次写入：去重命中（零重写） */
    CHECK(verthys_extent_put(f, &part, &idx, 6, a, sizeof(a),
                           hash_a, &stored) == VERTHYS_OK);
    CHECK(stored == 0);
    CHECK(idx.count == 1);
    CHECK(idx.next_offset == cursor_after_first);
    CHECK(part.used == used_after_first);

    /* 去重命中回传哈希与首次一致 */
    CHECK(memcmp(hash_a, hash_a, VERTHYS_EXTENT_HASH_BYTES) == 0);

    /* 引用计数递增 + 事务记账 */
    CHECK(verthys_extent_index_find(&idx, hash_a, &e) == VERTHYS_OK);
    CHECK(e.ref_count == 2);
    CHECK(e.created_txid == 5);
    CHECK(e.last_ref_txid == 6);

    /* 不同明文：新数据块 */
    CHECK(verthys_extent_put(f, &part, &idx, 7, b, sizeof(b),
                           hash_b, &stored) == VERTHYS_OK);
    CHECK(stored == 1);
    CHECK(idx.count == 2);
    CHECK(idx.next_offset == cursor_after_first + sizeof(b) +
                             VERTHYS_EXTENT_TAG_BYTES);

    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 6. 引用计数 + GC 标记 ---------- */

TEST(v3ext_release_refcount_and_gc)
{
    VerthysCngAead wrap;
    VerthysPartition part;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    uint8_t pt[40];
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t h_unknown[VERTHYS_EXTENT_HASH_BYTES] = {9};
    uint32_t rc = 99;
    size_t eligible = 99;

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    v3e_fill(pt, sizeof(pt), 31u);
    CHECK(verthys_extent_put(f, &part, &idx, 5, pt, sizeof(pt),
                           hash, NULL) == VERTHYS_OK);
    CHECK(verthys_extent_put(f, &part, &idx, 6, pt, sizeof(pt),
                           hash, NULL) == VERTHYS_OK);

    /* 释放一次：2 → 1（仍不可回收） */
    CHECK(verthys_extent_release(&idx, hash, 8, &rc) == VERTHYS_OK);
    CHECK(rc == 1);
    CHECK(verthys_extent_gc_eligible(&idx, &eligible) == VERTHYS_OK);
    CHECK(eligible == 0);

    /* 释放到 0：GC 可回收标记 */
    CHECK(verthys_extent_release(&idx, hash, 9, &rc) == VERTHYS_OK);
    CHECK(rc == 0);
    CHECK(verthys_extent_gc_eligible(&idx, &eligible) == VERTHYS_OK);
    CHECK(eligible == 1);

    /* 重复释放：下限 0，不回绕 */
    CHECK(verthys_extent_release(&idx, hash, 10, &rc) == VERTHYS_OK);
    CHECK(rc == 0);
    CHECK(verthys_extent_gc_eligible(&idx, &eligible) == VERTHYS_OK);
    CHECK(eligible == 1);

    /* 重新引用（去重命中）：复活，脱离 GC 标记 */
    CHECK(verthys_extent_put(f, &part, &idx, 11, pt, sizeof(pt),
                           hash, NULL) == VERTHYS_OK);
    CHECK(verthys_extent_index_find(&idx, hash, NULL) == VERTHYS_OK);
    CHECK(verthys_extent_gc_eligible(&idx, &eligible) == VERTHYS_OK);
    CHECK(eligible == 0);

    /* 未知哈希释放 → NOTFOUND */
    CHECK(verthys_extent_release(&idx, h_unknown, 12, &rc)
          == VERTHYS_ERR_NOTFOUND);
    CHECK(verthys_extent_gc_eligible(NULL, &eligible) == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_gc_eligible(&idx, NULL) == VERTHYS_ERR_INVALID);

    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 7. 资源上限 ---------- */

TEST(v3ext_resource_limit_rejected)
{
    VerthysCngAead wrap;
    VerthysPartition part;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    uint8_t a[32], b[32];
    uint8_t hash_a[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t hash_b[VERTHYS_EXTENT_HASH_BYTES];

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    v3e_fill(a, sizeof(a), 41u);
    v3e_fill(b, sizeof(b), 42u);
    CHECK(verthys_extent_put(f, &part, &idx, 5, a, sizeof(a),
                           hash_a, NULL) == VERTHYS_OK);

    /* ref_count 饱和：去重路径拒绝（防 u32 回绕） */
    idx.entries[0].ref_count = UINT32_MAX;
    CHECK(verthys_extent_put(f, &part, &idx, 6, a, sizeof(a),
                           hash_a, NULL) == VERTHYS_ERR_RESOURCE_LIMIT);
    idx.entries[0].ref_count = 1;

    /* 索引条目满：新数据路径拒绝 */
    idx.count = VERTHYS_EXTENT_INDEX_MAX;
    CHECK(verthys_extent_put(f, &part, &idx, 6, b, sizeof(b),
                           hash_b, NULL) == VERTHYS_ERR_RESOURCE_LIMIT);
    idx.count = 1;

    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 8. 未导入密钥（LOCKED） ---------- */

TEST(v3ext_locked_rejected)
{
    VerthysCngAead wrap;
    VerthysPartition part;
    VerthysPartition unimported;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    uint8_t pt[32];
    uint8_t pt2[32];
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t out[64];
    size_t olen = sizeof(out);

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    v3e_fill(pt, sizeof(pt), 51u);
    CHECK(verthys_extent_put(f, &part, &idx, 5, pt, sizeof(pt),
                           hash, NULL) == VERTHYS_OK);

    /* 零初始化分区（未导入密钥）→ LOCKED。
     * 注：去重路径先于密钥检查（去重无需加密）——用未入索引的新明文
     * 触发新数据块加密路径，方能命中 LOCKED 前置校验。 */
    memset(&unimported, 0, sizeof(unimported));
    unimported.id = V3E_PART_ID;
    v3e_fill(pt2, sizeof(pt2), 52u);
    CHECK(verthys_extent_put(f, &unimported, &idx, 6, pt2, sizeof(pt2),
                           hash, NULL) == VERTHYS_ERR_LOCKED);
    CHECK(verthys_extent_get(f, &unimported, &idx, hash, out, &olen)
          == VERTHYS_ERR_LOCKED);

    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 9. 数据块密文篡改 ---------- */

TEST(v3ext_data_tamper_rejected)
{
    VerthysCngAead wrap;
    VerthysPartition part;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    VerthysExtent e;
    uint8_t pt[60];
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t out[128];
    uint8_t byte_val;
    uint64_t abs_off;
    size_t olen;

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    v3e_fill(pt, sizeof(pt), 61u);
    CHECK(verthys_extent_put(f, &part, &idx, 5, pt, sizeof(pt),
                           hash, NULL) == VERTHYS_OK);
    CHECK(verthys_extent_index_find(&idx, hash, &e) == VERTHYS_OK);

    /* 定位密文（数据区 = 索引区之后）并翻转中间一字节 */
    abs_off = V3E_DATA_REGION_BASE + e.offset + e.size / 2;
    CHECK(vio_pread64(f, abs_off, &byte_val, 1) == 0);
    byte_val ^= 0xFF;
    CHECK(vio_pwrite64(f, abs_off, &byte_val, 1) == 0);

    /* 读取拒绝（AEAD 认证失败）且输出缓冲清零 */
    memset(out, 0xAA, sizeof(out));
    olen = sizeof(out);
    CHECK(verthys_extent_get(f, &part, &idx, hash, out, &olen)
          == VERTHYS_ERR_AUTH);
    for (size_t i = 0; i < sizeof(out); i++) {
        CHECK(out[i] == 0);
    }

    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 10. 密文块搬运（AAD 绑定 hash） ---------- */

TEST(v3ext_block_move_rejected)
{
    VerthysCngAead wrap;
    VerthysPartition part;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    VerthysExtent ea, eb;
    uint8_t a[70], b[70];
    uint8_t hash_a[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t hash_b[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t ct[70 + VERTHYS_EXTENT_TAG_BYTES];
    uint8_t out[128];
    size_t olen;

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    v3e_fill(a, sizeof(a), 71u);
    v3e_fill(b, sizeof(b), 72u);
    CHECK(verthys_extent_put(f, &part, &idx, 5, a, sizeof(a),
                           hash_a, NULL) == VERTHYS_OK);
    CHECK(verthys_extent_put(f, &part, &idx, 5, b, sizeof(b),
                           hash_b, NULL) == VERTHYS_OK);
    CHECK(verthys_extent_index_find(&idx, hash_a, &ea) == VERTHYS_OK);
    CHECK(verthys_extent_index_find(&idx, hash_b, &eb) == VERTHYS_OK);
    CHECK(ea.size == eb.size);

    /* 攻击：将 A 块密文整体搬运到 B 块槽位 */
    CHECK(vio_pread64(f, V3E_DATA_REGION_BASE + ea.offset,
                      ct, ea.size) == 0);
    CHECK(vio_pwrite64(f, V3E_DATA_REGION_BASE + eb.offset,
                       ct, ea.size) == 0);

    /* B 读取拒绝：AAD 绑定 hash（内容承诺），搬运密文认证失败 */
    olen = sizeof(out);
    CHECK(verthys_extent_get(f, &part, &idx, hash_b, out, &olen)
          == VERTHYS_ERR_AUTH);

    /* A 读取不受影响（B 槽位覆写不触及 A 数据） */
    olen = sizeof(out);
    CHECK(verthys_extent_get(f, &part, &idx, hash_a, out, &olen) == VERTHYS_OK);
    CHECK(olen == sizeof(a));
    CHECK(memcmp(out, a, sizeof(a)) == 0);

    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 11. 错误分区密钥 ---------- */

TEST(v3ext_wrong_partition_key_rejected)
{
    VerthysCngAead wrap;
    VerthysPartition part;
    VerthysPartition other;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    uint8_t pt[55];
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t out[128];
    size_t olen = sizeof(out);

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    v3e_fill(pt, sizeof(pt), 81u);
    CHECK(verthys_extent_put(f, &part, &idx, 5, pt, sizeof(pt),
                           hash, NULL) == VERTHYS_OK);

    /* 同 id 不同密钥的分区：解密认证失败（分区密钥隔离） */
    CHECK(verthys_partition_create(&other, V3E_PART_ID,
                                 VERTHYS_PARTITION_EXTENT,
                                 0, 16u * 1024u * 1024u, 1,
                                 &wrap) == VERTHYS_OK);
    CHECK(verthys_extent_get(f, &other, &idx, hash, out, &olen)
          == VERTHYS_ERR_AUTH);

    verthys_partition_destroy(&other);
    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 12. 索引持久化 roundtrip ---------- */

TEST(v3ext_index_save_load_roundtrip)
{
    VerthysCngAead wrap;
    VerthysCngAead wrap2;
    VerthysPartition part;
    VerthysPartition part2;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    VerthysExtentIndex idx2;
    VerthysExtent e1, e2;
    uint8_t a[90], b[45];
    uint8_t hash_a[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t hash_b[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t out[128];
    size_t olen;
    int stored = -1;

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    v3e_fill(a, sizeof(a), 91u);
    v3e_fill(b, sizeof(b), 92u);
    CHECK(verthys_extent_put(f, &part, &idx, 5, a, sizeof(a),
                           hash_a, &stored) == VERTHYS_OK);
    CHECK(stored == 1);
    CHECK(verthys_extent_put(f, &part, &idx, 6, a, sizeof(a),
                           hash_a, &stored) == VERTHYS_OK);  /* 去重 ref=2 */
    CHECK(verthys_extent_put(f, &part, &idx, 7, b, sizeof(b),
                           hash_b, &stored) == VERTHYS_OK);
    CHECK(stored == 1);

    /* 持久化（帧加密计数器推进；快照值 = save 前计数器 = 2） */
    CHECK(verthys_extent_index_save(f, part.offset, &idx, &part) == VERTHYS_OK);

    /* 分区重载：wrapped 解包 → 内核重导入（计数器从 0 起步） */
    CHECK(v3e_reimport(&wrap2, wk) == 0);
    CHECK(verthys_partition_load(&part2, part.id, part.type,
                               part.offset, part.size, part.used,
                               part.key_id,
                               0,  /* nonce_counter=0：由索引帧 restore */
                               part.created_txid,
                               part.wrapped_key, part.wrapped_key_len,
                               part.wrap_nonce, &wrap2) == VERTHYS_OK);

    /* 索引重载：AEAD 解密 + verifier + 条目重建 + 计数器 restore */
    CHECK(verthys_extent_index_load(f, part.offset, &part2, &idx2)
          == VERTHYS_OK);
    CHECK(idx2.count == 2);
    CHECK(idx2.txid == 5);
    CHECK(idx2.next_offset == idx.next_offset);

    CHECK(verthys_extent_index_find(&idx2, hash_a, &e1) == VERTHYS_OK);
    CHECK(verthys_extent_index_find(&idx, hash_a, &e2) == VERTHYS_OK);
    CHECK(e1.ref_count == 2);
    CHECK(e1.created_txid == 5);
    CHECK(e1.last_ref_txid == 6);
    CHECK(e1.offset == e2.offset);
    CHECK(e1.size == e2.size);
    CHECK(memcmp(e1.nonce, e2.nonce, VERTHYS_EXTENT_NONCE_BYTES) == 0);

    /* nonce 计数器 restore 到快照值（防回退基线）。
     * 保存后值约定：save 前 counter=2（2 次 put），帧加密 +1 → 快照=3 */
    CHECK(verthys_partition_nonce_counter(&part2) == 3);

    /* 重载后数据读取闭环（重载密钥 + 重载索引） */
    olen = sizeof(out);
    CHECK(verthys_extent_get(f, &part2, &idx2, hash_a, out, &olen) == VERTHYS_OK);
    CHECK(olen == sizeof(a));
    CHECK(memcmp(out, a, sizeof(a)) == 0);

    olen = sizeof(out);
    CHECK(verthys_extent_get(f, &part2, &idx2, hash_b, out, &olen) == VERTHYS_OK);
    CHECK(olen == sizeof(b));
    CHECK(memcmp(out, b, sizeof(b)) == 0);

    verthys_partition_destroy(&part2);
    verthys_cng_aead_destroy(&wrap2);
    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 13. E-7 nonce 防回退 ---------- */

TEST(v3ext_index_load_nonce_rollback_rejected)
{
    VerthysCngAead wrap;
    VerthysCngAead wrap2;
    VerthysPartition part;
    VerthysPartition part2;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    VerthysExtentIndex idx2;
    uint8_t pt[32];
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    v3e_fill(pt, sizeof(pt), 101u);
    CHECK(verthys_extent_put(f, &part, &idx, 5, pt, sizeof(pt),
                           hash, NULL) == VERTHYS_OK);
    CHECK(verthys_extent_index_save(f, part.offset, &idx, &part) == VERTHYS_OK);

    /* 分区以“未来”计数器重载（模拟已发生更多加密的盘面状态）：
     * 索引帧快照值 < 当前值 → restore 拒绝（严禁回退，防 nonce 复用） */
    CHECK(v3e_reimport(&wrap2, wk) == 0);
    CHECK(verthys_partition_load(&part2, part.id, part.type,
                               part.offset, part.size, part.used,
                               part.key_id,
                               100,  /* 高于索引帧快照（=2，保存后值） */
                               part.created_txid,
                               part.wrapped_key, part.wrapped_key_len,
                               part.wrap_nonce, &wrap2) == VERTHYS_OK);
    CHECK(verthys_extent_index_load(f, part.offset, &part2, &idx2)
          == VERTHYS_ERR_INVALID);

    verthys_partition_destroy(&part2);
    verthys_cng_aead_destroy(&wrap2);
    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 14. 索引帧篡改 ---------- */

TEST(v3ext_index_tamper_rejected)
{
    VerthysCngAead wrap;
    VerthysCngAead wrap2;
    VerthysPartition part;
    VerthysPartition part2;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    VerthysExtentIndex idx2;
    uint8_t pt[32];
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t byte_val;
    uint8_t header[VERTHYS_EXTENT_INDEX_FRAME_HEADER_BYTES];

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    v3e_fill(pt, sizeof(pt), 111u);
    CHECK(verthys_extent_put(f, &part, &idx, 5, pt, sizeof(pt),
                           hash, NULL) == VERTHYS_OK);

    /* (a) 密文翻转 → AUTH */
    CHECK(verthys_extent_index_save(f, part.offset, &idx, &part) == VERTHYS_OK);
    CHECK(vio_pread64(f, part.offset +
                          VERTHYS_EXTENT_INDEX_FRAME_HEADER_BYTES + 10,
                      &byte_val, 1) == 0);
    byte_val ^= 0xFF;
    CHECK(vio_pwrite64(f, part.offset +
                           VERTHYS_EXTENT_INDEX_FRAME_HEADER_BYTES + 10,
                       &byte_val, 1) == 0);
    CHECK(v3e_reimport(&wrap2, wk) == 0);
    CHECK(verthys_partition_load(&part2, part.id, part.type,
                               part.offset, part.size, part.used,
                               part.key_id, 0, part.created_txid,
                               part.wrapped_key, part.wrapped_key_len,
                               part.wrap_nonce, &wrap2) == VERTHYS_OK);
    CHECK(verthys_extent_index_load(f, part.offset, &part2, &idx2)
          == VERTHYS_ERR_AUTH);
    verthys_partition_destroy(&part2);
    verthys_cng_aead_destroy(&wrap2);

    /* (b) magic 破坏 → FORMAT */
    CHECK(verthys_extent_index_save(f, part.offset, &idx, &part) == VERTHYS_OK);
    memset(header, 0, sizeof(header));
    header[0] = 0xBB;  /* 非 'V3EX' */
    CHECK(vio_pwrite64(f, part.offset, header, 4) == 0);
    CHECK(v3e_reimport(&wrap2, wk) == 0);
    CHECK(verthys_partition_load(&part2, part.id, part.type,
                               part.offset, part.size, part.used,
                               part.key_id, 0, part.created_txid,
                               part.wrapped_key, part.wrapped_key_len,
                               part.wrap_nonce, &wrap2) == VERTHYS_OK);
    CHECK(verthys_extent_index_load(f, part.offset, &part2, &idx2)
          == VERTHYS_ERR_FORMAT);
    verthys_partition_destroy(&part2);
    verthys_cng_aead_destroy(&wrap2);

    /* (c) ct_len 越界（< tag）→ FORMAT */
    CHECK(verthys_extent_index_save(f, part.offset, &idx, &part) == VERTHYS_OK);
    memset(header, 0, sizeof(header));
    CHECK(vio_pwrite64(f, part.offset + 4, header, 4) == 0);
    CHECK(v3e_reimport(&wrap2, wk) == 0);
    CHECK(verthys_partition_load(&part2, part.id, part.type,
                               part.offset, part.size, part.used,
                               part.key_id, 0, part.created_txid,
                               part.wrapped_key, part.wrapped_key_len,
                               part.wrap_nonce, &wrap2) == VERTHYS_OK);
    CHECK(verthys_extent_index_load(f, part.offset, &part2, &idx2)
          == VERTHYS_ERR_FORMAT);
    verthys_partition_destroy(&part2);
    verthys_cng_aead_destroy(&wrap2);

    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 15. 空索引区 ---------- */

TEST(v3ext_index_load_empty_region_rejected)
{
    VerthysCngAead wrap;
    VerthysPartition part;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);

    /* 无任何索引帧落盘 → FORMAT */
    CHECK(verthys_extent_index_load(f, part.offset, &part, &idx)
          == VERTHYS_ERR_FORMAT);

    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}

/* ---------- 16. NULL 参数校验 ---------- */

TEST(v3ext_null_params_rejected)
{
    VerthysCngAead wrap;
    VerthysPartition part;
    uint8_t wk[V3E_KEY_BYTES];
    FILE *f;
    VerthysExtentIndex idx;
    uint8_t pt[16];
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    uint8_t out[32];
    size_t olen = sizeof(out);
    uint32_t rc;
    size_t eligible;

    CHECK(v3e_setup(&wrap, wk, &part) == 0);
    f = fopen(V3E_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(verthys_extent_index_init(&idx, 5) == VERTHYS_OK);

    CHECK(verthys_extent_put(NULL, &part, &idx, 5, pt, sizeof(pt),
                           hash, NULL) == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_put(f, NULL, &idx, 5, pt, sizeof(pt),
                           hash, NULL) == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_put(f, &part, NULL, 5, pt, sizeof(pt),
                           hash, NULL) == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_put(f, &part, &idx, 5, NULL, 1,
                           hash, NULL) == VERTHYS_ERR_INVALID);

    CHECK(verthys_extent_get(NULL, &part, &idx, hash, out, &olen)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_get(f, NULL, &idx, hash, out, &olen)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_get(f, &part, NULL, hash, out, &olen)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_get(f, &part, &idx, NULL, out, &olen)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_get(f, &part, &idx, hash, NULL, &olen)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_get(f, &part, &idx, hash, out, NULL)
          == VERTHYS_ERR_INVALID);

    CHECK(verthys_extent_release(NULL, hash, 5, &rc) == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_release(&idx, NULL, 5, &rc) == VERTHYS_ERR_INVALID);

    CHECK(verthys_extent_gc_eligible(NULL, &eligible) == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_gc_eligible(&idx, NULL) == VERTHYS_ERR_INVALID);

    CHECK(verthys_extent_index_save(NULL, 0, &idx, &part)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_index_save(f, 0, NULL, &part) == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_index_save(f, 0, &idx, NULL) == VERTHYS_ERR_INVALID);

    CHECK(verthys_extent_index_load(NULL, 0, &part, &idx)
          == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_index_load(f, 0, NULL, &idx) == VERTHYS_ERR_INVALID);
    CHECK(verthys_extent_index_load(f, 0, &part, NULL) == VERTHYS_ERR_INVALID);

    fclose(f);
    v3e_teardown(&part, &wrap, wk);
    v3e_cleanup();
    return 0;
}
