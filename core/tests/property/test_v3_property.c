/*
 * test_v3_property.c — 属性测试（自研 harness，无外部框架）
 *
 * 随机序列 + 不变式断言，覆盖三大不变式族：
 *
 *   1. LSM 插入/删除/查找（"插入后必可找到"）：
 *      随机 put/delete/get/flush/compact 序列 vs 影子模型（lid → 条目/墓碑），
 *      周期性全键扫描断言"存活键必可找到且字段逐项一致、死亡键必 NOTFOUND"，
 *      收尾 close → reopen 持久化不变式复验。
 *
 *   2. Extent 引用计数守恒：
 *      随机 put/release 序列 vs 引用模型（内容 → 期望计数），
 *      断言实际计数 ≡ 模型计数（逐内容 + 总量守恒）、条目不可变性
 *      （offset/size/nonce 首写后不变）、去重零重写（stored 标志）、
 *      next_offset 单调不减、gc_eligible ≡ 零引用条目数、
 *      存活内容抽样解密 roundtrip。
 *
 *   3. 事务 commit/rollback 后超级块与 WAL 一致：
 *      随机白盒六阶段事务（add/delete × commit|rollback）vs 模型，
 *      断言 sb.txid 当且仅当 commit 推进（内存态 ≡ 法定人数盘面态）、
 *      CONFIRM 后 WAL 帧清零、回滚后 WAL 帧清零且记录不可见、
 *      LID 水位单调（含回滚烧毁 + 墓碑占位）、Extent 引用守恒、
 *      公共 API 可见性 ≡ 模型。
 *
 *   4. 回滚耐久性（复活窗口回归，属性测试发现缺陷的验收）：
 *      回滚事务 → 同 txid 再提交 → COMMITTED 后崩溃（CONFIRM 前）→
 *      重开恢复：已回滚记录不得复活、已提交记录必须可见、LID 不复用。
 *
 *   5. 定向回归（回滚/崩溃丢弃后原始条目复原的验收，修复前必失败）：
 *      事务内 DELETE 墓碑按新者胜覆写 MemTable 原始条目——回滚/崩溃
 *      恢复丢弃该事务时，原始条目必须经重放重建完整复原（过滤式剔除
 *      会连同墓碑一起丢失被覆写条目 = 已提交数据丢失，红线级）。
 *      运行时回滚路径 + Lock/重开持久化复验 + 已提交删除对照组；
 *      PREPARED 崩溃 → 恢复丢弃组路径 + 恢复收尾 WAL 清零。
 *
 * 可复现性：固定种子 + PROP_CHECK 失败上下文（种子/步号/操作名）打印。
 * 失败防级联：PROP_CHECK 跳转各测试尾部 prop_fail 清理标签（句柄/
 * 文件不释放将阻塞后续测试的 remove()/fopen()）。
 */
#include "verthys_test.h"
#include "verthys_lsm.h"
#include "verthys_extent.h"
#include "verthys_partition.h"
#include "verthys_crypto.h"
#include "verthys_internal.h"
#include "verthys_v3_lifecycle.h"    /* VerthysContextV3 / add_record_in_txn */
#include "verthys_wal.h"             /* verthys_wal_frame_count */
#include "verthys_container_v3.h"    /* vsb_v3_read_quorum */
#include "verthys.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ================== harness 核心：确定性 PRNG + 失败上下文 ================== */

/*
 * splitmix64：确定性随机流（种子 → 全序列可复现）。
 * 属性测试要求失败可重放：种子固定编译入测试，失败时 PROP_CHECK
 * 打印步号与操作名，重跑同一种子必得同一序列。
 */
static uint64_t prng_next(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

/* [0, n) 均匀取值（n > 0；模偏置对属性测试可忽略） */
static unsigned prng_range(uint64_t *state, unsigned n)
{
    return (unsigned)(prng_next(state) % n);
}

static uint64_t g_prop_seed;
static unsigned g_prop_step;
static const char *g_prop_op;

/*
 * PROP_CHECK：TEST 体内断言——失败打印重放上下文后跳转各测试尾部的
 * prop_fail 标签（清理 + return 1）。防级联：TEST 失败后 runner 继续
 * 跑后续测试，句柄/文件未释放将在 Windows 下阻塞 remove()/fopen()
 * （打开文件不可删除），令无关测试连坐失败。
 * 辅助函数（p1_scan_all）无标签语境，用 PROP_CHECK_RET（返回语义，
 * 调用方收到非零后自行 goto prop_fail）。
 */
#define PROP_CHECK(cond) do { \
    if (!(cond)) { \
        printf("  [PROP FAIL] seed=0x%016llx step=%u op=%s: %s @ %s:%d\n", \
               (unsigned long long)g_prop_seed, g_prop_step, \
               (g_prop_op != NULL) ? g_prop_op : "?", #cond, __FILE__, __LINE__); \
        goto prop_fail; \
    } \
} while (0)

/* 辅助函数版：失败返回 1（清理责任在调用方） */
#define PROP_CHECK_RET(cond) do { \
    if (!(cond)) { \
        printf("  [PROP FAIL] seed=0x%016llx step=%u op=%s: %s @ %s:%d\n", \
               (unsigned long long)g_prop_seed, g_prop_step, \
               (g_prop_op != NULL) ? g_prop_op : "?", #cond, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

/* 步进（每步 = 一次随机操作；失败时 g_prop_step 即重放定位符） */
#define PROP_STEP() do { g_prop_step++; } while (0)

/* ================== 属性 1：LSM 插入/删除/查找 ================== */

#define P1_TMP          "test_v3_prop_lsm.tmp"
#define P1_KEY_BYTES    VERTHYS_CNG_KEY_BYTES
#define P1_PART_ID      21u
#define P1_REGION_SIZE  (80u * 1024u * 1024u)
#define P1_SLOTS        64u    /* 键空间（lid = 1..P1_SLOTS） */
#define P1_OPS          2000u
#define P1_SCAN_EVERY   128u   /* 周期性全键扫描间隔 */
#define P1_NAME_MAX     24u

/* 影子模型槽位：ABSENT（从未写/等价墓碑遮蔽后）或 LIVE（最新值快照） */
typedef struct P1Slot {
    int      live;
    VerthysLsmEntry e;                 /* name 拷贝存 name_buf */
    uint8_t  name_buf[P1_NAME_MAX];
} P1Slot;

static void p1_cleanup(void) { remove(P1_TMP); }

/* 失败路径自清理（调用方以返回 -1 判定"零资源残留"，直接 return 1） */
static int p1_setup(VerthysCngAead *wrap, uint8_t wk[P1_KEY_BYTES],
                    VerthysPartition *part, FILE **fout)
{
    FILE *f = NULL;
    uint8_t copy[P1_KEY_BYTES];

    p1_cleanup();
    *fout = NULL;
    if (verthys_cng_aead_init(wrap) != VERTHYS_OK) return -1;
    verthys_random_bytes(wk, P1_KEY_BYTES);
    memcpy(copy, wk, P1_KEY_BYTES);
    if (verthys_cng_aead_import_key(wrap, copy, NULL) != VERTHYS_OK) {
        verthys_cng_aead_destroy(wrap);
        return -1;
    }
    if (verthys_partition_create(part, P1_PART_ID, VERTHYS_PARTITION_INDEX,
                               0, P1_REGION_SIZE, 1, wrap) != VERTHYS_OK) {
        verthys_cng_aead_destroy(wrap);
        return -1;
    }
    fopen_s(&f, P1_TMP, "w+b");
    if (f == NULL) {
        verthys_partition_destroy(part);
        verthys_cng_aead_destroy(wrap);
        return -1;
    }
    *fout = f;
    return 0;
}

static void p1_teardown(VerthysPartition *part, VerthysCngAead *wrap,
                        uint8_t wk[P1_KEY_BYTES], FILE *f)
{
    if (f != NULL) fclose(f);
    verthys_partition_destroy(part);
    verthys_cng_aead_destroy(wrap);
    verthys_secure_zero(wk, P1_KEY_BYTES);
    p1_cleanup();
}

/* 随机条目生成（内容确定性派生自 PRNG，供模型快照与 get 比对） */
static void p1_make_random(P1Slot *slot, uint64_t lid, uint64_t txid,
                           uint64_t *rng)
{
    uint16_t name_len = (uint16_t)prng_range(rng, P1_NAME_MAX + 1u);
    uint8_t seed = (uint8_t)prng_next(rng);
    size_t i;

    memset(slot, 0, sizeof(*slot));
    slot->live = 1;
    slot->e.lid = lid;
    slot->e.type = (uint8_t)prng_range(rng, 8u);
    slot->e.tombstone = 0;
    slot->e.slot_state = 1;
    slot->e.name_len = name_len;
    slot->e.name = slot->name_buf;              /* put 内部拷贝（借用） */
    for (i = 0; i < name_len; i++) {
        slot->name_buf[i] = (uint8_t)('a' + prng_range(rng, 26u));
    }
    slot->e.data_size = prng_next(rng) % 100000u;
    slot->e.plaintext_size = (uint32_t)(prng_next(rng) % 5000u);
    slot->e.extent_size = slot->e.plaintext_size + 16u
                          + (uint32_t)(prng_next(rng) % 64u);
    for (i = 0; i < 32; i++) slot->e.hash[i] = (uint8_t)prng_next(rng);
    slot->e.created_txid = txid;
    slot->e.created_time = 1700000000u + seed;
}

/* 全键扫描断言：存活键逐字段一致、死亡键 NOTFOUND、水位覆盖存活键 */
static int p1_scan_all(VerthysLsm *lsm, P1Slot model[], const char *phase)
{
    uint64_t max_live_lid = 0;
    size_t name_len = 0;
    VerthysLsmEntry out;
    uint8_t name_buf[P1_NAME_MAX];
    uint64_t lid;

    g_prop_op = phase;
    for (lid = 1; lid <= P1_SLOTS; lid++) {
        const P1Slot *m = &model[lid - 1];
        memset(&out, 0, sizeof(out));
        if (m->live) {
            PROP_CHECK_RET(verthys_lsm_get(lsm, lid, &out, name_buf,
                                         sizeof(name_buf), &name_len) == VERTHYS_OK);
            PROP_CHECK_RET(out.lid == m->e.lid);
            PROP_CHECK_RET(out.type == m->e.type);
            PROP_CHECK_RET(out.tombstone == 0);
            PROP_CHECK_RET(out.slot_state == m->e.slot_state);
            PROP_CHECK_RET(out.name_len == m->e.name_len);
            PROP_CHECK_RET(out.name_len == 0 ||
                       memcmp(name_buf, m->name_buf, out.name_len) == 0);
            PROP_CHECK_RET(out.data_size == m->e.data_size);
            PROP_CHECK_RET(out.plaintext_size == m->e.plaintext_size);
            PROP_CHECK_RET(out.extent_size == m->e.extent_size);
            PROP_CHECK_RET(memcmp(out.hash, m->e.hash, 32) == 0);
            PROP_CHECK_RET(out.created_txid == m->e.created_txid);
            PROP_CHECK_RET(out.created_time == m->e.created_time);
            if (lid > max_live_lid) max_live_lid = lid;
        } else {
            PROP_CHECK_RET(verthys_lsm_get(lsm, lid, NULL, NULL, 0, NULL)
                       == VERTHYS_ERR_NOTFOUND);
        }
    }
    PROP_CHECK_RET(verthys_lsm_max_lid(lsm) >= max_live_lid);
    return 0;
}

/*
 * 随机操作流 vs 影子模型：
 *   put 40% / delete 20% / get 31% / flush 4% / compact 5%
 *   （flush 后按需 compact——镜像生产后台线程，控制 L0 表数有界）。
 */
TEST(prop_lsm_insert_find_delete)
{
    VerthysCngAead wrap;
    uint8_t wk[P1_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysLsm *lsm;
    P1Slot model[P1_SLOTS];
    uint64_t rng = UINT64_C(0x5EED00011AA70001);
    unsigned op;

    g_prop_seed = rng;
    g_prop_step = 0;
    g_prop_op = "setup";
    printf("[prop] lsm: seed=0x%016llx ops=%u slots=%u\n",
           (unsigned long long)rng, P1_OPS, P1_SLOTS);

    if (p1_setup(&wrap, wk, &part, &f) != 0) {
        printf("  [PROP FAIL] op=setup: p1_setup @ %s:%d\n",
               __FILE__, __LINE__);
        return 1;               /* setup 失败路径已内部自清理 */
    }
    lsm = verthys_lsm_create();
    PROP_CHECK(lsm != NULL);
    PROP_CHECK(verthys_lsm_open(lsm, f, &part, 0, P1_REGION_SIZE, 0) == VERTHYS_OK);

    memset(model, 0, sizeof(model));
    for (op = 1; op <= P1_OPS; op++) {
        uint64_t lid = 1u + prng_range(&rng, P1_SLOTS);
        unsigned dice = (unsigned)(prng_next(&rng) % 100u);
        P1Slot *m = &model[lid - 1];

        PROP_STEP();
        if (dice < 40u) {                        /* put：模型快照 + 写入 */
            g_prop_op = "put";
            p1_make_random(m, lid, op, &rng);
            PROP_CHECK(verthys_lsm_put(lsm, op, &m->e) == VERTHYS_OK);
        } else if (dice < 60u) {                 /* delete：墓碑（幂等） */
            g_prop_op = "delete";
            m->live = 0;
            memset(&m->e, 0, sizeof(m->e));
            PROP_CHECK(verthys_lsm_delete(lsm, op, lid) == VERTHYS_OK);
        } else if (dice < 91u) {                 /* get：即时可见性 */
            VerthysLsmEntry out;
            uint8_t name_buf[P1_NAME_MAX];
            size_t name_len = 0;

            g_prop_op = "get";
            memset(&out, 0, sizeof(out));
            if (m->live) {
                PROP_CHECK(verthys_lsm_get(lsm, lid, &out, name_buf,
                                         sizeof(name_buf), &name_len)
                           == VERTHYS_OK);
                PROP_CHECK(out.name_len == m->e.name_len);
                PROP_CHECK(out.data_size == m->e.data_size);
                PROP_CHECK(out.plaintext_size == m->e.plaintext_size);
                PROP_CHECK(memcmp(out.hash, m->e.hash, 32) == 0);
                PROP_CHECK(out.created_txid == m->e.created_txid);
            } else {
                PROP_CHECK(verthys_lsm_get(lsm, lid, &out, name_buf,
                                         sizeof(name_buf), &name_len)
                           == VERTHYS_ERR_NOTFOUND);
            }
        } else if (dice < 95u) {                 /* flush → 按需 compact */
            g_prop_op = "flush";
            PROP_CHECK(verthys_lsm_flush(lsm) == VERTHYS_OK);
            if (verthys_lsm_needs_compaction(lsm)) {
                PROP_CHECK(verthys_lsm_compact(lsm) == VERTHYS_OK);
            }
        } else {                                 /* compact（多数 no-op） */
            g_prop_op = "compact";
            PROP_CHECK(verthys_lsm_compact(lsm) == VERTHYS_OK);
        }

        if (op % P1_SCAN_EVERY == 0) {
            if (p1_scan_all(lsm, model, "scan") != 0) goto prop_fail;
        }
    }

    /* 持久化不变式：close（flush + Manifest 保存）→ reopen → 全键复验 */
    g_prop_op = "close-reopen";
    PROP_CHECK(verthys_lsm_close(lsm) == VERTHYS_OK);
    PROP_CHECK(verthys_lsm_open(lsm, f, &part, 0, P1_REGION_SIZE, 0) == VERTHYS_OK);
    if (p1_scan_all(lsm, model, "scan-after-reopen") != 0) goto prop_fail;
    PROP_CHECK(verthys_lsm_close(lsm) == VERTHYS_OK);
    verthys_lsm_destroy(lsm);
    p1_teardown(&part, &wrap, wk, f);
    printf("[prop] lsm: %u 步全部不变式成立\n", P1_OPS);
    return 0;

prop_fail:
    verthys_lsm_destroy(lsm);     /* NULL 安全；close 后零置态/半开态均安全 */
    p1_teardown(&part, &wrap, wk, f);
    return 1;
}

/* ================== 属性 2：Extent 引用计数守恒 ================== */

#define P2_TMP         "test_v3_prop_ext.tmp"
#define P2_KEY_BYTES   VERTHYS_CNG_KEY_BYTES
#define P2_PART_ID     22u
#define P2_PART_SIZE   (16u * 1024u * 1024u)
#define P2_CONTENTS    16u
#define P2_OPS         1200u
#define P2_CHECK_EVERY 64u
#define P2_DATA_MAX    64u

static void p2_cleanup(void) { remove(P2_TMP); }

/* 失败路径自清理（语义同 p1_setup：返回 -1 = 零资源残留） */
static int p2_setup(VerthysCngAead *wrap, uint8_t wk[P2_KEY_BYTES],
                    VerthysPartition *part, FILE **fout)
{
    FILE *f = NULL;
    uint8_t copy[P2_KEY_BYTES];

    p2_cleanup();
    *fout = NULL;
    if (verthys_cng_aead_init(wrap) != VERTHYS_OK) return -1;
    verthys_random_bytes(wk, P2_KEY_BYTES);
    memcpy(copy, wk, P2_KEY_BYTES);
    if (verthys_cng_aead_import_key(wrap, copy, NULL) != VERTHYS_OK) {
        verthys_cng_aead_destroy(wrap);
        return -1;
    }
    if (verthys_partition_create(part, P2_PART_ID, VERTHYS_PARTITION_EXTENT,
                               0, P2_PART_SIZE, 1, wrap) != VERTHYS_OK) {
        verthys_cng_aead_destroy(wrap);
        return -1;
    }
    fopen_s(&f, P2_TMP, "w+b");
    if (f == NULL) {
        verthys_partition_destroy(part);
        verthys_cng_aead_destroy(wrap);
        return -1;
    }
    *fout = f;
    return 0;
}

static void p2_teardown(VerthysPartition *part, VerthysCngAead *wrap,
                        uint8_t wk[P2_KEY_BYTES], FILE *f)
{
    if (f != NULL) fclose(f);
    verthys_partition_destroy(part);
    verthys_cng_aead_destroy(wrap);
    verthys_secure_zero(wk, P2_KEY_BYTES);
    p2_cleanup();
}

/*
 * 随机 put/release 流 vs 引用模型：
 *   put 60%（去重命中 ref++ 零重写 / 新内容 ref=1）
 *   release 32%（下限 0 不回绕）/ release 未知哈希 8%（NOTFOUND）
 * 守恒断言：实际 ≡ 模型（逐内容 + 总量）、条目不可变、
 * next_offset 单调、gc_eligible ≡ 零引用数、抽样解密一致。
 */
TEST(prop_extent_refcount_conservation)
{
    VerthysCngAead wrap;
    uint8_t wk[P2_KEY_BYTES];
    VerthysPartition part;
    FILE *f = NULL;
    VerthysExtentIndex idx;
    uint8_t data[P2_CONTENTS][P2_DATA_MAX];
    uint8_t hash[P2_CONTENTS][VERTHYS_EXTENT_HASH_BYTES];
    uint8_t hash_unknown[VERTHYS_EXTENT_HASH_BYTES];
    uint64_t model_ref[P2_CONTENTS];      /* 期望引用计数 */
    uint64_t model_sum = 0;               /* Σ模型（守恒总量） */
    int inserted[P2_CONTENTS];
    uint64_t first_offset[P2_CONTENTS];   /* 条目不可变性基准 */
    uint32_t first_size[P2_CONTENTS];
    uint8_t first_nonce[P2_CONTENTS][VERTHYS_EXTENT_NONCE_BYTES];
    uint64_t last_next_offset = 0;
    uint64_t rng = UINT64_C(0x5EED0002E27E1172);
    unsigned op, c;
    size_t i;

    g_prop_seed = rng;
    g_prop_step = 0;
    g_prop_op = "setup";
    printf("[prop] extent: seed=0x%016llx ops=%u contents=%u\n",
           (unsigned long long)rng, P2_OPS, P2_CONTENTS);

    /* 内容池：确定性派生（全 64 字节；gcd(131,256)=1 保证互异） */
    for (c = 0; c < P2_CONTENTS; c++) {
        for (i = 0; i < P2_DATA_MAX; i++) {
            data[c][i] = (uint8_t)(c * 131u + i * 7u + 5u);
        }
        model_ref[c] = 0;
        inserted[c] = 0;
        first_offset[c] = 0;
        first_size[c] = 0;
    }
    memset(hash_unknown, 0xA5, sizeof(hash_unknown));
    hash_unknown[0] = 0x5A;               /* 与池内容哈希实际不可碰撞 */

    if (p2_setup(&wrap, wk, &part, &f) != 0) {
        printf("  [PROP FAIL] op=setup: p2_setup @ %s:%d\n",
               __FILE__, __LINE__);
        return 1;               /* setup 失败路径已内部自清理 */
    }
    PROP_CHECK(verthys_extent_index_init(&idx, 1) == VERTHYS_OK);

    /* 内容哈希预计算（模型寻址键） */
    for (c = 0; c < P2_CONTENTS; c++) {
        PROP_CHECK(verthys_extent_hash(hash[c], data[c], P2_DATA_MAX) == VERTHYS_OK);
    }

    for (op = 1; op <= P2_OPS; op++) {
        unsigned dice = (unsigned)(prng_next(&rng) % 100u);
        unsigned ci = prng_range(&rng, P2_CONTENTS);

        PROP_STEP();
        if (dice < 60u) {                        /* put：守恒 + 去重语义 */
            uint8_t h_out[VERTHYS_EXTENT_HASH_BYTES];
            int stored = -1;
            VerthysExtent e;

            g_prop_op = "put";
            PROP_CHECK(verthys_extent_put(f, &part, &idx, op,
                                        data[ci], P2_DATA_MAX,
                                        h_out, &stored) == VERTHYS_OK);
            PROP_CHECK(memcmp(h_out, hash[ci], VERTHYS_EXTENT_HASH_BYTES) == 0);
            /* 去重零重写：首写 stored=1，其后必 stored=0 */
            PROP_CHECK(stored == (inserted[ci] ? 0 : 1));
            if (!inserted[ci]) {
                inserted[ci] = 1;
                PROP_CHECK(verthys_extent_index_find(&idx, hash[ci], &e)
                           == VERTHYS_OK);
                first_offset[ci] = e.offset;
                first_size[ci] = e.size;
                memcpy(first_nonce[ci], e.nonce, VERTHYS_EXTENT_NONCE_BYTES);
                PROP_CHECK(e.ref_count == 1);
            }
            model_ref[ci]++;
            model_sum++;
            PROP_CHECK(verthys_extent_index_find(&idx, hash[ci], &e) == VERTHYS_OK);
            PROP_CHECK(e.ref_count == model_ref[ci]);
        } else if (dice < 92u) {                 /* release：下限 0 */
            uint32_t out_rc = 9999u;

            g_prop_op = "release";
            if (inserted[ci]) {
                PROP_CHECK(verthys_extent_release(&idx, hash[ci], op, &out_rc)
                           == VERTHYS_OK);
                /* 模型同语义递减：计数 > 0 才减（下限 0 不回绕） */
                if (model_ref[ci] > 0) {
                    model_ref[ci]--;
                    model_sum--;
                }
                PROP_CHECK(out_rc == model_ref[ci]);
            } else {
                PROP_CHECK(verthys_extent_release(&idx, hash[ci], op, &out_rc)
                           == VERTHYS_ERR_NOTFOUND);
            }
        } else {                                 /* release 未知哈希 */
            g_prop_op = "release-unknown";
            PROP_CHECK(verthys_extent_release(&idx, hash_unknown, op, NULL)
                       == VERTHYS_ERR_NOTFOUND);
        }

        if (op % P2_CHECK_EVERY == 0) {
            uint64_t sum = 0;
            size_t gc = 0, expect_gc = 0;

            g_prop_op = "conservation-check";
            for (c = 0; c < P2_CONTENTS; c++) {
                VerthysExtent e;
                if (inserted[c]) {
                    PROP_CHECK(verthys_extent_index_find(&idx, hash[c], &e)
                               == VERTHYS_OK);
                    PROP_CHECK(e.ref_count == model_ref[c]);
                    /* 条目不可变：首写定位三元组不随引用变动漂移 */
                    PROP_CHECK(e.offset == first_offset[c]);
                    PROP_CHECK(e.size == first_size[c]);
                    PROP_CHECK(memcmp(e.nonce, first_nonce[c],
                                      VERTHYS_EXTENT_NONCE_BYTES) == 0);
                    sum += e.ref_count;
                    if (model_ref[c] == 0) expect_gc++;
                } else {
                    PROP_CHECK(verthys_extent_index_find(&idx, hash[c], NULL)
                               == VERTHYS_ERR_NOTFOUND);
                }
            }
            /* 守恒：Σ实际 ≡ Σ模型 */
            PROP_CHECK(sum == model_sum);
            PROP_CHECK(verthys_extent_gc_eligible(&idx, &gc) == VERTHYS_OK);
            PROP_CHECK(gc == expect_gc);
            /* 追加游标单调不减 */
            PROP_CHECK(idx.next_offset >= last_next_offset);
            last_next_offset = idx.next_offset;
        }
    }

    /* 存活内容抽样完整性：全部非零引用内容解密 roundtrip */
    g_prop_op = "integrity-sample";
    for (c = 0; c < P2_CONTENTS; c++) {
        uint8_t out[P2_DATA_MAX];
        size_t out_len = sizeof(out);

        if (!inserted[c] || model_ref[c] == 0) continue;
        PROP_CHECK(verthys_extent_get(f, &part, &idx, hash[c], out, &out_len)
                   == VERTHYS_OK);
        PROP_CHECK(out_len == P2_DATA_MAX);
        PROP_CHECK(memcmp(out, data[c], P2_DATA_MAX) == 0);
    }

    p2_teardown(&part, &wrap, wk, f);
    printf("[prop] extent: %u 步引用计数守恒成立\n", P2_OPS);
    return 0;

prop_fail:
    p2_teardown(&part, &wrap, wk, f);
    return 1;
}

/* ================== 属性 3：事务 commit/rollback 超级块与 WAL 一致 ================== */

#define P3_VERTHYS     "test_v3_prop_txn.verthys"
#define P3_CACHE     "test_v3_prop_txn.verthys.idx_cache"
#define P3_PW        "prop-txn-pass"
#define P3_PW_LEN    12
#define P3_CONTENTS  8u
#define P3_DATA_MAX  48u
#define P3_TXNS      48u
#define P3_MAX_LIDS  192u

static void p3_cleanup(void)
{
    remove(P3_VERTHYS);
    remove(P3_CACHE);
}

/* 造一个已锁定的空 V3 容器（PERFORMANCE 预设，固定 Argon2id 参数） */
static int p3_make_locked(const char *path)
{
    VerthysHandle h;

    p3_cleanup();
    if (Verthys_Init(&h) != VERTHYS_OK) return -1;
    if (Verthys_CreateWithPreset(h, path, P3_PW, P3_PW_LEN,
                               VERTHYS_PRESET_PERFORMANCE) != VERTHYS_OK) {
        Verthys_Deinit(h);
        return -1;
    }
    if (Verthys_Lock(h) != VERTHYS_OK) {
        Verthys_Deinit(h);
        return -1;
    }
    Verthys_Deinit(h);
    return 0;
}

/* 崩溃模拟（与 test_v3_lifecycle 同语义）：中止式拆除，盘面 WAL 保留 */
static void p3_crash_abort(struct VerthysContext *ctx)
{
    VerthysContextV3 *v3 = ctx->v3;
    FILE *f = v3->f;

    ctx->v3 = NULL;
    ctx->state = VERTHYS_STATE_LOCKED;
    verthys_v3_ctx_destroy(v3);
    if (f != NULL) fclose(f);
}

/* Deinit + 句柄置空：prop_fail 标签以 h != NULL 判定是否补销毁，
 * 正常路径 Deinit 后立即置空，杜绝失败路径双重 Deinit（双重释放）。 */
static VerthysResult p3_deinit(VerthysHandle *ph)
{
    VerthysResult r = Verthys_Deinit(*ph);
    *ph = NULL;
    return r;
}

/*
 * 随机白盒事务流 vs 模型：
 *   每事务 = begin → {add ×1..2 | delete ×0..1} → commit|rollback（抛硬币）
 *   add：LID = 模型水位 + 1（断言，含回滚烧毁 + 墓碑占位的水位记账）
 *   delete：70% 存活键 / 30% 任意键（墓碑占位，LID 水位推高）
 * 不变式（每事务后全量断言）：
 *   I1 sb.txid 当且仅当 commit +1（内存 ≡ 法定人数盘面读回）
 *   I2 CONFIRM 后 WAL 帧清零；回滚后 WAL 帧清零（复活窗口修复）
 *   I3 回滚记录不可见（LSM 直查 + 公共 API 双路径）
 *   I4 LID 水位单调（下一 add 恰为水位 + 1）
 *   I5 Extent 引用守恒（实际 ≡ 存活记录按内容计数）
 *   I6 可见性 ≡ 模型（公共 API 读全部水位内 LID）
 */
TEST(prop_txn_commit_rollback_consistency)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    uint8_t data[P3_CONTENTS][P3_DATA_MAX];
    uint8_t hash[P3_CONTENTS][VERTHYS_EXTENT_HASH_BYTES];
    size_t data_len[P3_CONTENTS];
    /* 模型：LID 槽位（live + 内容索引 + 名序号）+ 水位 + txid 期望 */
    struct {
        uint8_t live;
        uint8_t content;
        uint32_t name_seq;
    } slot[P3_MAX_LIDS + 1];
    int ever_inserted[P3_CONTENTS];
    uint64_t watermark = 0;      /* LID 水位（一切写入/墓碑触达的最大 lid） */
    uint64_t expect_txid = 0;    /* 期望 sb.txid（仅 commit 推进） */
    uint32_t name_seq = 0;
    uint64_t rng = UINT64_C(0x5EED00037A980003);
    unsigned t, c;
    size_t i;

    g_prop_seed = rng;
    g_prop_step = 0;
    g_prop_op = "setup";
    printf("[prop] txn: seed=0x%016llx txns=%u\n",
           (unsigned long long)rng, P3_TXNS);

    /* 内容池（尺寸相异：1..48 字节；含 1 字节最小明文路径） */
    for (c = 0; c < P3_CONTENTS; c++) {
        data_len[c] = 1u + ((size_t)c * 6u + 5u) % P3_DATA_MAX;
        for (i = 0; i < data_len[c]; i++) {
            data[c][i] = (uint8_t)(c * 197u + i * 13u + 11u);
        }
        memset(data[c] + data_len[c], 0, P3_DATA_MAX - data_len[c]);
        PROP_CHECK(verthys_extent_hash(hash[c], data[c], data_len[c]) == VERTHYS_OK);
        ever_inserted[c] = 0;
    }
    memset(slot, 0, sizeof(slot));

    PROP_CHECK(p3_make_locked(P3_VERTHYS) == 0);
    PROP_CHECK(Verthys_Init(&h) == VERTHYS_OK);
    PROP_CHECK(Verthys_Unlock(h, P3_VERTHYS, P3_PW, P3_PW_LEN, 0) == VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    PROP_CHECK(v3 != NULL && v3->subsystems_open == 1);
    PROP_CHECK(v3->sb.txid == 0);           /* 创建首版 txid=0 */
    PROP_CHECK(verthys_wal_frame_count(v3->wal) == 0);

    for (t = 1; t <= P3_TXNS; t++) {
        unsigned n_adds = 1u + prng_range(&rng, 2u);
        unsigned n_dels = (prng_range(&rng, 3u) == 0u) ? 1u : 0u;
        unsigned add_lids[2] = {0, 0};
        unsigned add_cnt[2] = {0, 0};
        unsigned n_adds_real = 0;
        unsigned del_lid = 0;
        int do_commit;
        unsigned k;

        PROP_STEP();
        g_prop_op = "begin";
        PROP_CHECK(verthys_txn_v3_begin(&v3->txn) == VERTHYS_OK);
        PROP_CHECK(verthys_txn_v3_txid(&v3->txn) == expect_txid + 1);

        /* 写入与索引更新：add × n（预算护栏：水位越界即提前收束） */
        for (k = 0; k < n_adds && watermark + 1 < P3_MAX_LIDS; k++) {
            uint8_t name[16];
            int nlen;
            uint64_t lid = 0;
            unsigned ci = prng_range(&rng, P3_CONTENTS);

            g_prop_op = "add-in-txn";
            name_seq++;
            nlen = sprintf_s((char *)name, sizeof(name), "p3n-%u", name_seq);
            PROP_CHECK(nlen > 0);
            /* I4：LID 恰为模型水位 + 1（含回滚烧毁/墓碑占位记账） */
            PROP_CHECK(verthys_v3_add_record_in_txn(v3, VERTHYS_RECORD_ACCOUNT,
                                                  name, (size_t)nlen,
                                                  data[ci], data_len[ci],
                                                  &lid) == VERTHYS_OK);
            PROP_CHECK(lid == watermark + 1);
            watermark = lid;
            ever_inserted[ci] = 1;
            add_lids[k] = (unsigned)lid;
            add_cnt[k] = ci;
            n_adds_real++;
        }

        /* 删除（70% 存活键 / 30% 任意键占位） */
        if (n_dels > 0) {
            uint64_t lids[P3_MAX_LIDS];
            size_t live_cnt = 0;
            uint64_t lid;

            g_prop_op = "delete-in-txn";
            for (lid = 1; lid <= watermark; lid++) {
                if (slot[lid].live) lids[live_cnt++] = lid;
            }
            if (live_cnt > 0 && prng_range(&rng, 10u) < 7u) {
                del_lid = (unsigned)lids[prng_range(&rng, (unsigned)live_cnt)];
            } else {
                del_lid = 1u + prng_range(&rng, P3_MAX_LIDS - 1u);
                if ((uint64_t)del_lid > watermark) {
                    watermark = del_lid;     /* 墓碑占位：LID 水位推高 */
                }
            }
            PROP_CHECK(verthys_txn_v3_delete(&v3->txn, del_lid) == VERTHYS_OK);
        }

        /* 收口或回滚（抛硬币） */
        do_commit = (prng_next(&rng) & 1u) != 0u;
        if (do_commit) {
            g_prop_op = "commit";
            PROP_CHECK(verthys_txn_v3_prepare(&v3->txn) == VERTHYS_OK);
            PROP_CHECK(verthys_txn_v3_commit(&v3->txn) == VERTHYS_OK);
            PROP_CHECK(verthys_txn_v3_confirm(&v3->txn) == VERTHYS_OK);
            PROP_CHECK(verthys_txn_v3_state(&v3->txn) == VERTHYS_TXN_V3_CONFIRMED);
            expect_txid++;
            /* I1：内存 sb ≡ 期望 ≡ 法定人数盘面读回 */
            PROP_CHECK(v3->sb.txid == expect_txid);
            {
                VerthysSuperBlockV3 disk_sb;
                memset(&disk_sb, 0, sizeof(disk_sb));
                PROP_CHECK(vsb_v3_read_quorum(v3->f, v3->integrity_key,
                                              &disk_sb, NULL) == VERTHYS_OK);
                PROP_CHECK(disk_sb.txid == expect_txid);
            }
            /* I2：CONFIRM 后 WAL 帧清零 */
            PROP_CHECK(verthys_wal_frame_count(v3->wal) == 0);
            /* 模型施加：add 置活、delete 置亡 */
            for (k = 0; k < n_adds_real; k++) {
                slot[add_lids[k]].live = 1;
                slot[add_lids[k]].content = (uint8_t)add_cnt[k];
                slot[add_lids[k]].name_seq = name_seq - n_adds_real + k + 1u;
            }
            if (n_dels > 0) slot[del_lid].live = 0;
        } else {
            g_prop_op = "rollback";
            PROP_CHECK(verthys_txn_v3_rollback(&v3->txn) == VERTHYS_OK);
            PROP_CHECK(verthys_txn_v3_state(&v3->txn) == VERTHYS_TXN_V3_ABORTED);
            /* I1：sb.txid 不推进 */
            PROP_CHECK(v3->sb.txid == expect_txid);
            /* I2：回滚后 WAL 帧清零（废弃组不得残留——复活窗口修复） */
            PROP_CHECK(verthys_wal_frame_count(v3->wal) == 0);
            /* I3：回滚记录不可见（LSM 直查） */
            for (k = 0; k < n_adds_real; k++) {
                PROP_CHECK(verthys_lsm_get(v3->lsm, add_lids[k],
                                         NULL, NULL, 0, NULL)
                           == VERTHYS_ERR_NOTFOUND);
            }
            /* 模型不变（回滚零效果）；水位保留（LID 永不复用） */
        }

        /* I5：Extent 引用守恒（实际 ≡ 存活记录按内容计数） */
        g_prop_op = "extent-conservation";
        {
            uint64_t expect_ref[P3_CONTENTS];
            uint64_t lid;

            for (c = 0; c < P3_CONTENTS; c++) expect_ref[c] = 0;
            for (lid = 1; lid <= watermark; lid++) {
                if (slot[lid].live) expect_ref[slot[lid].content]++;
            }
            for (c = 0; c < P3_CONTENTS; c++) {
                VerthysExtent e;
                if (ever_inserted[c]) {
                    PROP_CHECK(verthys_extent_index_find(v3->ext_idx, hash[c],
                                                       &e) == VERTHYS_OK);
                    PROP_CHECK(e.ref_count == expect_ref[c]);
                }
            }
        }

        /* I6：可见性 ≡ 模型（公共 API 全水位扫描） */
        g_prop_op = "visibility";
        {
            uint64_t lid;

            for (lid = 1; lid <= watermark; lid++) {
                VerthysRecord out;
                char expect_name[16];
                unsigned seq;
                int nlen;

                if (slot[lid].live) {
                    PROP_CHECK(Verthys_GetRecord(h, lid, &out) == VERTHYS_OK);
                    PROP_CHECK(out.type == VERTHYS_RECORD_ACCOUNT);
                    PROP_CHECK(out.data_len == data_len[slot[lid].content]);
                    PROP_CHECK(memcmp(out.data, data[slot[lid].content],
                                      out.data_len) == 0);
                    seq = slot[lid].name_seq;
                    nlen = sprintf_s(expect_name, sizeof(expect_name),
                                     "p3n-%u", seq);
                    PROP_CHECK(nlen > 0);
                    PROP_CHECK(out.name_len == (size_t)nlen);
                    PROP_CHECK(memcmp(out.name, expect_name, out.name_len) == 0);
                } else {
                    PROP_CHECK(Verthys_GetRecord(h, lid, &out)
                               == VERTHYS_ERR_NOTFOUND);
                }
            }
        }
    }

    PROP_CHECK(Verthys_Lock(h) == VERTHYS_OK);
    PROP_CHECK(p3_deinit(&h) == VERTHYS_OK);
    p3_cleanup();
    printf("[prop] txn: %u 事务（commit/rollback 混合）超级块与 WAL 一致\n",
           P3_TXNS);
    return 0;

prop_fail:
    /* 未锁会话走完整 Lock 收尾（事务收尾 + flush），已拆除壳安全销毁；
     * 失败亦不阻断——清理路径不产生新失败 */
    if (h != NULL) (void)Verthys_Deinit(h);
    p3_cleanup();
    return 1;
}

/* ================== 属性 4：回滚耐久性（复活窗口回归） ================== */

/*
 * 属性推演发现的回滚复活缺陷验收（verthys_txn_v3_rollback 现已复位
 * 事务 WAL——修复前该测试必失败）：
 *   1. 回滚事务 T1（txid=N，记录 R2）→ 废弃组帧残留 WAL；
 *   2. 同 txid 事务 T2（begin 复用 txid=N，记录 R3）→ commit →
 *      崩溃于 CONFIRM 前（法定人数已持久 + WAL COMMIT 在场）；
 *   3. 重开恢复：重放组合并（同 txid 相邻组）→ R2 被复活（缺陷）；
 *      修复后：回滚即清 WAL，恢复仅重放 T2 → R2 不可见、R3 可见。
 */
TEST(prop_txn_crash_no_resurrection)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRecord out;
    uint64_t lid_r1 = 0, lid_r2 = 0, lid_r3 = 0, lid_next = 0;
    const uint8_t content_r1[] = "baseline-record";
    const uint8_t content_r2[] = "rolled-back-record";
    const uint8_t content_r3[] = "committed-record";
    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "base", 4,
                      content_r1, sizeof(content_r1) - 1};
    uint64_t sb_txid_before = 0;
    uint64_t rng = UINT64_C(0x5EED0004DEADBEEF);

    g_prop_seed = rng;
    g_prop_step = 0;
    g_prop_op = "setup";
    printf("[prop] crash-resurrection: seed=0x%016llx\n",
           (unsigned long long)rng);

    /* 基线容器：1 条记录（lid=1，sb.txid=1） */
    p3_cleanup();
    PROP_CHECK(Verthys_Init(&h) == VERTHYS_OK);
    PROP_CHECK(Verthys_CreateWithPreset(h, P3_VERTHYS, P3_PW, P3_PW_LEN,
                                      VERTHYS_PRESET_PERFORMANCE) == VERTHYS_OK);
    PROP_CHECK(Verthys_AddRecord(h, &r1, &lid_r1) == VERTHYS_OK);
    PROP_CHECK(lid_r1 == 1);
    PROP_CHECK(Verthys_Lock(h) == VERTHYS_OK);
    PROP_CHECK(p3_deinit(&h) == VERTHYS_OK);

    /* 解锁 → 白盒驱动：T1 回滚（R2）→ T2 提交（R3）→ 崩溃于 CONFIRM 前 */
    PROP_CHECK(Verthys_Init(&h) == VERTHYS_OK);
    PROP_CHECK(Verthys_Unlock(h, P3_VERTHYS, P3_PW, P3_PW_LEN, 0) == VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    PROP_CHECK(v3 != NULL && v3->subsystems_open == 1);
    PROP_CHECK(v3->sb.txid == 1);
    sb_txid_before = v3->sb.txid;

    /* T1：begin → add R2 → 回滚（修复后 WAL 复位，帧清零） */
    g_prop_op = "t1-rollback";
    PROP_CHECK(verthys_txn_v3_begin(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_txid(&v3->txn) == sb_txid_before + 1);
    PROP_CHECK(verthys_v3_add_record_in_txn(v3, VERTHYS_RECORD_ACCOUNT,
                                          (const uint8_t *)"rb", 2,
                                          content_r2, sizeof(content_r2) - 1,
                                          &lid_r2) == VERTHYS_OK);
    PROP_CHECK(lid_r2 == 2);                    /* LID 烧毁起点 */
    PROP_CHECK(verthys_txn_v3_rollback(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_state(&v3->txn) == VERTHYS_TXN_V3_ABORTED);
    PROP_CHECK(verthys_wal_frame_count(v3->wal) == 0);   /* 修复核心断言 */
    PROP_CHECK(v3->sb.txid == sb_txid_before);          /* 回滚不推进 txid */

    /* T2：同 txid 再开 → add R3 → 提交 → 崩溃于 CONFIRM 前 */
    g_prop_op = "t2-commit-crash";
    PROP_CHECK(verthys_txn_v3_begin(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_txid(&v3->txn) == sb_txid_before + 1);  /* txid 复用 */
    PROP_CHECK(verthys_v3_add_record_in_txn(v3, VERTHYS_RECORD_ACCOUNT,
                                          (const uint8_t *)"ok", 2,
                                          content_r3, sizeof(content_r3) - 1,
                                          &lid_r3) == VERTHYS_OK);
    PROP_CHECK(lid_r3 == 3);                    /* LID 永不复用（lid 2 已烧） */
    PROP_CHECK(verthys_txn_v3_prepare(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_commit(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(v3->sb.txid == sb_txid_before + 1);
    p3_crash_abort(ctx);                        /* COMMITTED 态崩溃 */
    PROP_CHECK(p3_deinit(&h) == VERTHYS_OK);

    /* 重开恢复（COMMIT 在场组重放收尾） */
    PROP_CHECK(Verthys_Init(&h) == VERTHYS_OK);
    PROP_CHECK(Verthys_Unlock(h, P3_VERTHYS, P3_PW, P3_PW_LEN, 0) == VERTHYS_OK);

    g_prop_op = "post-recovery";
    /* 基线 + 已提交记录可见 */
    PROP_CHECK(Verthys_GetRecord(h, lid_r1, &out) == VERTHYS_OK);
    PROP_CHECK(memcmp(out.data, content_r1, sizeof(content_r1) - 1) == 0);
    PROP_CHECK(Verthys_GetRecord(h, lid_r3, &out) == VERTHYS_OK);
    PROP_CHECK(out.data_len == sizeof(content_r3) - 1);
    PROP_CHECK(memcmp(out.data, content_r3, sizeof(content_r3) - 1) == 0);
    /* 已回滚记录不得复活（缺陷核心断言） */
    PROP_CHECK(Verthys_GetRecord(h, lid_r2, &out) == VERTHYS_ERR_NOTFOUND);

    /* LID 不复用：恢复后新写入越过烧毁位 */
    {
        VerthysRecord r4 = {VERTHYS_RECORD_ACCOUNT, "post", 4,
                          (const uint8_t *)"post-recovery", 13};
        PROP_CHECK(Verthys_AddRecord(h, &r4, &lid_next) == VERTHYS_OK);
        PROP_CHECK(lid_next == lid_r3 + 1);
    }

    PROP_CHECK(Verthys_Lock(h) == VERTHYS_OK);
    PROP_CHECK(p3_deinit(&h) == VERTHYS_OK);
    p3_cleanup();
    printf("[prop] crash-resurrection: 回滚耐久性成立（无复活）\n");
    return 0;

prop_fail:
    if (h != NULL) (void)Verthys_Deinit(h);
    p3_cleanup();
    return 1;
}

/* ================== 定向回归：回滚/崩溃丢弃后原始条目复原 ================== */

/*
 * 定向回归-运行时回滚（回滚墓碑覆写数据丢失，修复前必失败）：
 *   R1 提交后驻留 MemTable（单记录远未达 flush 阈值、未 Lock）→
 *   事务内 DELETE R1（墓碑按新者胜覆写 MemTable 原始条目）→ 回滚。
 *   修复前：回滚走过滤式剔除——墓碑与被覆写的 R1 一同消失
 *   （GetRecord NOTFOUND，已提交数据丢失，红线级）；
 *   修复后：WAL 重放重建完整复原 R1。
 *   对照组：回滚修复不得破坏正向删除语义（已提交 DELETE 维持删除）、
 *   不存在 LID 的墓碑回滚后仍不存在（不凭空造数）。
 */
TEST(prop_txn_rollback_delete_restores_original)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRecord out;
    uint64_t lid_r1 = 0;
    const uint8_t content_r1[] = "original-committed-record";
    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "reg", 3,
                      content_r1, sizeof(content_r1) - 1};
    uint64_t sb_txid_before;

    g_prop_seed = UINT64_C(0x5EED000500000002);
    g_prop_step = 0;
    g_prop_op = "setup";
    printf("[prop] rollback-delete-restore: 定向回归（缺陷②验收）\n");

    p3_cleanup();
    PROP_CHECK(Verthys_Init(&h) == VERTHYS_OK);
    PROP_CHECK(Verthys_CreateWithPreset(h, P3_VERTHYS, P3_PW, P3_PW_LEN,
                                      VERTHYS_PRESET_PERFORMANCE) == VERTHYS_OK);
    PROP_CHECK(Verthys_AddRecord(h, &r1, &lid_r1) == VERTHYS_OK);
    PROP_CHECK(lid_r1 == 1);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    PROP_CHECK(v3 != NULL && v3->subsystems_open == 1);
    sb_txid_before = v3->sb.txid;

    /* 事务内 DELETE R1 → 回滚：R1 必须完整复原（缺陷核心断言） */
    g_prop_op = "delete-rollback";
    PROP_CHECK(verthys_txn_v3_begin(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_delete(&v3->txn, lid_r1) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_rollback(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_state(&v3->txn) == VERTHYS_TXN_V3_ABORTED);
    PROP_CHECK(v3->sb.txid == sb_txid_before);
    PROP_CHECK(Verthys_GetRecord(h, lid_r1, &out) == VERTHYS_OK);
    PROP_CHECK(out.data_len == sizeof(content_r1) - 1);
    PROP_CHECK(memcmp(out.data, content_r1, sizeof(content_r1) - 1) == 0);
    PROP_CHECK(verthys_lsm_get(v3->lsm, lid_r1, NULL, NULL, 0, NULL)
               == VERTHYS_OK);

    /* 不存在 LID 的墓碑回滚：仍不存在（不凭空造数） */
    g_prop_op = "absent-tomb-rollback";
    PROP_CHECK(verthys_txn_v3_begin(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_delete(&v3->txn, 999) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_rollback(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_lsm_get(v3->lsm, 999, NULL, NULL, 0, NULL)
               == VERTHYS_ERR_NOTFOUND);

    /* 复原的 R1 经 Lock → 重开持久化复验（复原条目落 SSTable 存活） */
    g_prop_op = "persist-recheck";
    PROP_CHECK(Verthys_Lock(h) == VERTHYS_OK);
    PROP_CHECK(p3_deinit(&h) == VERTHYS_OK);
    PROP_CHECK(Verthys_Init(&h) == VERTHYS_OK);
    PROP_CHECK(Verthys_Unlock(h, P3_VERTHYS, P3_PW, P3_PW_LEN, 0) == VERTHYS_OK);
    PROP_CHECK(Verthys_GetRecord(h, lid_r1, &out) == VERTHYS_OK);
    PROP_CHECK(memcmp(out.data, content_r1, sizeof(content_r1) - 1) == 0);

    /* 对照组：已提交 DELETE 维持删除语义 */
    g_prop_op = "delete-commit";
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    PROP_CHECK(verthys_txn_v3_begin(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_delete(&v3->txn, lid_r1) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_prepare(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_commit(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_confirm(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(Verthys_GetRecord(h, lid_r1, &out) == VERTHYS_ERR_NOTFOUND);

    PROP_CHECK(Verthys_Lock(h) == VERTHYS_OK);
    PROP_CHECK(p3_deinit(&h) == VERTHYS_OK);
    p3_cleanup();
    printf("[prop] rollback-delete-restore: 回滚墓碑数据复原成立\n");
    return 0;

prop_fail:
    if (h != NULL) (void)Verthys_Deinit(h);
    p3_cleanup();
    return 1;
}

/*
 * 定向回归-崩溃恢复（恢复丢弃组墓碑覆写数据丢失，修复前必失败）：
 *   R1 提交后驻留 MemTable → 事务内 DELETE R1 → PREPARE 后崩溃
 *   （WAL 无 COMMIT 记录 → 丢弃该未提交组）→ 重开恢复。
 *   修复前：恢复对丢弃组走过滤式剔除——R1 随墓碑一同消失（已提交
 *   数据丢失，红线级）；修复后：过滤重放重建（排除丢弃组帧）复原 R1。
 */
TEST(prop_txn_crash_discard_delete_restores_original)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRecord out;
    uint64_t lid_r1 = 0;
    const uint8_t content_r1[] = "survivor-committed-record";
    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "sur", 3,
                      content_r1, sizeof(content_r1) - 1};

    g_prop_seed = UINT64_C(0x5EED00060000000B);
    g_prop_step = 0;
    g_prop_op = "setup";
    printf("[prop] crash-discard-restore: 定向回归（缺陷②b验收）\n");

    p3_cleanup();
    PROP_CHECK(Verthys_Init(&h) == VERTHYS_OK);
    PROP_CHECK(Verthys_CreateWithPreset(h, P3_VERTHYS, P3_PW, P3_PW_LEN,
                                      VERTHYS_PRESET_PERFORMANCE) == VERTHYS_OK);
    PROP_CHECK(Verthys_AddRecord(h, &r1, &lid_r1) == VERTHYS_OK);
    PROP_CHECK(lid_r1 == 1);

    /* 同会话内开事务 DELETE R1 → PREPARE → 崩溃（无 COMMIT 记录） */
    g_prop_op = "delete-prepare-crash";
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    PROP_CHECK(v3 != NULL && v3->subsystems_open == 1);
    PROP_CHECK(verthys_txn_v3_begin(&v3->txn) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_delete(&v3->txn, lid_r1) == VERTHYS_OK);
    PROP_CHECK(verthys_txn_v3_prepare(&v3->txn) == VERTHYS_OK);
    p3_crash_abort(ctx);            /* PREPARED 态崩溃 → 恢复丢弃该组 */
    PROP_CHECK(p3_deinit(&h) == VERTHYS_OK);

    /* 重开恢复：丢弃组剔除不得殃及被墓碑覆写的已提交 R1（缺陷核心） */
    g_prop_op = "post-recovery";
    PROP_CHECK(Verthys_Init(&h) == VERTHYS_OK);
    PROP_CHECK(Verthys_Unlock(h, P3_VERTHYS, P3_PW, P3_PW_LEN, 0) == VERTHYS_OK);
    PROP_CHECK(Verthys_GetRecord(h, lid_r1, &out) == VERTHYS_OK);
    PROP_CHECK(out.data_len == sizeof(content_r1) - 1);
    PROP_CHECK(memcmp(out.data, content_r1, sizeof(content_r1) - 1) == 0);

    /* 恢复收尾：事务 WAL 清零（无残留可回放记录） */
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    PROP_CHECK(verthys_wal_frame_count(v3->wal) == 0);

    PROP_CHECK(Verthys_Lock(h) == VERTHYS_OK);
    PROP_CHECK(p3_deinit(&h) == VERTHYS_OK);
    p3_cleanup();
    printf("[prop] crash-discard-restore: 恢复丢弃组数据复原成立\n");
    return 0;

prop_fail:
    if (h != NULL) (void)Verthys_Deinit(h);
    p3_cleanup();
    return 1;
}
