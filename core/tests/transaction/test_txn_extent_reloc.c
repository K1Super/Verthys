/*
 * test_txn_extent_reloc.c — Extent 容量三级链审计搬迁集成验收
 *
 * 验收对象：事务写入路径的容量保障链（紧凑化 → 常规 2x 扩展 →
 * 审计分区后移搬迁）。覆盖历史故障的两处根因：
 *   1. 审计搬迁的容量计算未计入追加游标跳洞抬升量——抬升后游标
 *      越过 2x 新容量，单块写入被 put 容量守卫拒绝（容量告罄风暴）；
 *   2. 紧凑化不变量校验含死块条目——搬迁轮次后死块保留陈旧偏移，
 *      二次紧凑化必失败。
 *
 * 测试场景：
 *   A. 公共 API 路径：连续单记录事务写入，跨过初代 16MiB 与二代
 *      32MiB 数据区容量，观测两次审计搬迁（超级块审计偏移与数据区
 *      容量各推进两次），全程写入成功、逐字节读回一致，锁定重开后
 *      搬迁结果随分区表持久存活；
 *   B. 手动事务路径：同事务内先触发首次审计搬迁，随后制造死块并
 *      连续写入至再触发紧凑化——验证紧凑化在搬迁之后照常回收死块
 *      （死块陈旧偏移不参与不变量校验），且紧凑化后的追加游标
 *      恒不低于本事务跳洞地板（旧审计区在元数据持久化前不可覆盖）。
 *
 * 数据量纪律：单块 2MiB（内容寻址去重域内每块内容唯一），单事务
 * 最多 9 块；全测试密文总量约 34MiB，IO 与内存驻留受控。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"          /* VerthysContext / VerthysState */
#include "verthys_v3_lifecycle.h"       /* VerthysContextV3 / 事务共享骨架 */
#include "verthys_transaction_v3.h"     /* VerthysTxnV3 / 状态机 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define RELOC_VERTHYS  "test_txn_extent_reloc.verthys"
#define RELOC_PW       "extent-reloc-pass"
#define RELOC_PW_LEN   17

/* 单块明文长度：2MiB（预留审计标签长度，容量边界按整数块推进） */
#define RELOC_BLOCK_BYTES   (2u * 1024u * 1024u)
/* 初代/二代数据区容量（与容器默认布局一致） */
#define RELOC_EXTENT_1ST    (16u * 1024u * 1024u)
#define RELOC_EXTENT_2ND    (32u * 1024u * 1024u)
#define RELOC_EXTENT_3RD    (64u * 1024u * 1024u)

static void reloc_cleanup(void) { remove(RELOC_VERTHYS); }

/* 唯块模式填充：内容寻址下每块必须互异，否则去重合并会掩盖搬运缺陷 */
static void reloc_fill(uint8_t *buf, size_t len, unsigned seed)
{
    for (size_t j = 0; j < len; j++) {
        buf[j] = (uint8_t)((j * 31u + seed) & 0xFFu);
    }
}

static int reloc_verify(const uint8_t *buf, size_t len, unsigned seed)
{
    for (size_t j = 0; j < len; j++) {
        uint8_t expect = (uint8_t)((j * 31u + seed) & 0xFFu);
        if (buf[j] != expect) return 0;
    }
    return 1;
}

/* ================== 场景 A：公共 API 两轮搬迁 + 重开持久 ================== */

TEST(txn_extent_reloc_chain_two_rounds)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    uint8_t *block = NULL;
    VerthysRecord out;

    /* 预写块（公共 API 单记录事务，7 块 × 2MiB = 14MiB） */
    uint64_t ids[16] = {0};
    uint64_t ext_off0 = 0;
    uint64_t audit_after_a = 0, audit_after_i = 0;
    uint64_t size_after_a = 0, size_after_i = 0;
    uint64_t floor_after_a = 0, floor_after_i = 0;
    uint64_t audit_reopen = 0;
    int write_ok = 1;
    int verify_all_ok = 0;
    int reopen_ok = 0;

    reloc_cleanup();
    block = (uint8_t *)malloc(RELOC_BLOCK_BYTES);
    if (block == NULL) { reloc_cleanup(); return 1; }
    if (Verthys_Init(&h) != VERTHYS_OK) { free(block); reloc_cleanup(); return 1; }
    if (Verthys_CreateWithPreset(h, RELOC_VERTHYS, RELOC_PW, RELOC_PW_LEN,
                                 VERTHYS_PRESET_PERFORMANCE) != VERTHYS_OK) {
        (void)Verthys_Deinit(h); free(block); reloc_cleanup(); return 1;
    }
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    if (v3 == NULL || v3->subsystems_open != 1) {
        (void)Verthys_Deinit(h); free(block); reloc_cleanup(); return 1;
    }

    ext_off0 = v3->txn.extent_part->offset;

    /* 预写 7 块至 14MiB（容量 1MiB 索引头 + 14MiB 数据 + 2MiB 即越界，
     * 第 8 块起进入保障链） */
    for (unsigned i = 0; i < 7; i++) {
        char name[32];
        VerthysRecord r;
        int n = sprintf_s(name, sizeof(name), "reloc-%u", i);
        reloc_fill(block, RELOC_BLOCK_BYTES, i);
        r.type = VERTHYS_RECORD_ACCOUNT;
        r.name = name;
        r.name_len = (size_t)n;
        r.data = block;
        r.data_len = RELOC_BLOCK_BYTES;
        if (Verthys_AddRecord(h, &r, &ids[i]) != VERTHYS_OK) write_ok = 0;
    }

    /* 手动事务：第 8 块触发首次审计搬迁，续写至跨过二代容量触发
     * 第二次搬迁（一次事务内完成，覆盖搬迁后同事务连续写入） */
    if (write_ok) {
        if (verthys_txn_v3_begin(&v3->txn) != VERTHYS_OK) {
            verthys_v3_txn_abort(v3);
            write_ok = 0;
        }
    }
    if (write_ok) {
        for (unsigned i = 7; i < 16; i++) {
            char name[32];
            uint64_t lid = 0;
            int n = sprintf_s(name, sizeof(name), "reloc-%u", i);
            reloc_fill(block, RELOC_BLOCK_BYTES, i);
            if (verthys_v3_add_record_in_txn(v3, VERTHYS_RECORD_ACCOUNT,
                                             name, (size_t)n, block,
                                             RELOC_BLOCK_BYTES, &lid) != VERTHYS_OK) {
                write_ok = 0;
                break;
            }
            ids[i] = lid;
            if (i == 7) {
                audit_after_a = v3->sb.audit_partition_offset;
                size_after_a = v3->txn.extent_part->size;
                floor_after_a = v3->txn.reloc_hole_floor;
            }
            if (i == 15) {
                audit_after_i = v3->sb.audit_partition_offset;
                size_after_i = v3->txn.extent_part->size;
                floor_after_i = v3->txn.reloc_hole_floor;
            }
        }
    }
    if (write_ok && verthys_v3_txn_finish(v3) != VERTHYS_OK) write_ok = 0;

    /* 逐字节读回校验（搬迁密文原样搬移不重加密的端到端证据） */
    if (write_ok) {
        verify_all_ok = 1;
        for (unsigned i = 0; i < 16 && verify_all_ok; i++) {
            if (Verthys_GetRecord(h, ids[i], &out) != VERTHYS_OK ||
                out.data_len != RELOC_BLOCK_BYTES ||
                !reloc_verify(out.data, RELOC_BLOCK_BYTES, i)) {
                verify_all_ok = 0;
            }
        }
    }

    /* 锁定重开：搬迁结果随分区表持久存活 + 数据完好 */
    if (verify_all_ok) {
        if (Verthys_Lock(h) != VERTHYS_OK) { (void)Verthys_Deinit(h); free(block); reloc_cleanup(); return 1; }
        (void)Verthys_Deinit(h);
        if (Verthys_Init(&h) != VERTHYS_OK) { free(block); reloc_cleanup(); return 1; }
        if (Verthys_Unlock(h, RELOC_VERTHYS, RELOC_PW, RELOC_PW_LEN, 0) != VERTHYS_OK) {
            (void)Verthys_Deinit(h); free(block); reloc_cleanup(); return 1;
        }
        ctx = (struct VerthysContext *)h;
        v3 = ctx->v3;
        if (v3 != NULL && v3->subsystems_open == 1) {
            audit_reopen = v3->sb.audit_partition_offset;
        }
        reopen_ok = (v3 != NULL && v3->subsystems_open == 1 &&
                     Verthys_GetRecord(h, ids[15], &out) == VERTHYS_OK &&
                     out.data_len == RELOC_BLOCK_BYTES &&
                     reloc_verify(out.data, RELOC_BLOCK_BYTES, 15));
    }

    (void)Verthys_Deinit(h);
    free(block);
    reloc_cleanup();

    CHECK(write_ok);

    /* 首轮搬迁：审计偏移推进至 32MiB 处新起点，数据区翻倍至 32MiB，
     * 跳洞地板 = 旧审计区间终点相对数据区高度（16MiB） */
    CHECK((audit_after_a - ext_off0) == RELOC_EXTENT_2ND);
    CHECK_EQ(size_after_a, (uint64_t)RELOC_EXTENT_2ND);
    CHECK_EQ(floor_after_a, (uint64_t)RELOC_EXTENT_1ST);

    /* 次轮搬迁：审计偏移推进至 64MiB 处，数据区再翻倍，地板抬升至 32MiB */
    CHECK((audit_after_i - ext_off0) == RELOC_EXTENT_3RD);
    CHECK_EQ(size_after_i, (uint64_t)RELOC_EXTENT_3RD);
    CHECK_EQ(floor_after_i, (uint64_t)RELOC_EXTENT_2ND);

    CHECK(verify_all_ok);
    CHECK(reopen_ok);
    CHECK((audit_reopen - ext_off0) == RELOC_EXTENT_3RD);
    return 0;
}

/* ================== 场景 B：同事务搬迁后紧凑化 + 地板守卫 ================== */

TEST(txn_extent_reloc_same_txn_compact_floor)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    uint8_t *block = NULL;
    VerthysRecord out;

    uint64_t ids[16] = {0};
    uint64_t next_after_h = 0;
    uint64_t next_after_j = 0;
    int write_ok = 1;
    int floor_respected = 1;

    reloc_cleanup();
    block = (uint8_t *)malloc(RELOC_BLOCK_BYTES);
    if (block == NULL) { reloc_cleanup(); return 1; }

    if (Verthys_Init(&h) != VERTHYS_OK) { free(block); reloc_cleanup(); return 1; }
    if (Verthys_CreateWithPreset(h, RELOC_VERTHYS, RELOC_PW, RELOC_PW_LEN,
                                 VERTHYS_PRESET_PERFORMANCE) != VERTHYS_OK) {
        (void)Verthys_Deinit(h); free(block); reloc_cleanup(); return 1;
    }
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    if (v3 == NULL || v3->subsystems_open != 1) {
        (void)Verthys_Deinit(h); free(block); reloc_cleanup(); return 1;
    }

    /* 预写 7 块（14MiB） */
    for (unsigned i = 0; i < 7; i++) {
        char name[32];
        VerthysRecord r;
        int n = sprintf_s(name, sizeof(name), "reloc-%u", i);
        reloc_fill(block, RELOC_BLOCK_BYTES, i);
        r.type = VERTHYS_RECORD_ACCOUNT;
        r.name = name;
        r.name_len = (size_t)n;
        r.data = block;
        r.data_len = RELOC_BLOCK_BYTES;
        if (Verthys_AddRecord(h, &r, &ids[i]) != VERTHYS_OK) write_ok = 0;
    }
    /* 手动事务：A 触发首次搬迁；删除预写块制造死块；续写至触发
     * 紧凑化（死块回收）；再删一块并续写至二次紧凑化 */
    if (write_ok && verthys_txn_v3_begin(&v3->txn) != VERTHYS_OK) {
        verthys_v3_txn_abort(v3);
        write_ok = 0;
    }
    if (write_ok) {
        char name[32];
        uint64_t lid = 0;
        int n;

        /* 块 A：触发首次审计搬迁（地板 16MiB，游标抬升后写入） */
        n = sprintf_s(name, sizeof(name), "reloc-A");
        reloc_fill(block, RELOC_BLOCK_BYTES, 0xAAu);
        if (verthys_v3_add_record_in_txn(v3, VERTHYS_RECORD_ACCOUNT,
                                         name, (size_t)n, block,
                                         RELOC_BLOCK_BYTES, &lid) != VERTHYS_OK) {
            write_ok = 0;
        }
        ids[7] = lid;
        if (v3->txn.reloc_hole_floor != RELOC_EXTENT_1ST) write_ok = 0;

        /* 死块 1：删除预写块（同事务引用释放，条目 ref 归零） */
        if (write_ok && verthys_txn_v3_delete(&v3->txn, ids[2]) != VERTHYS_OK) {
            write_ok = 0;
        }

        /* 块 B..H：推进游标越过二代容量边界触发紧凑化（死块回收后
         * 落回可用空间，不再触发二次搬迁） */
        for (unsigned k = 0; k < 7 && write_ok; k++) {
            n = sprintf_s(name, sizeof(name), "reloc-B%u", k);
            reloc_fill(block, RELOC_BLOCK_BYTES, 0xB0u + k);
            if (verthys_v3_add_record_in_txn(v3, VERTHYS_RECORD_ACCOUNT,
                                             name, (size_t)n, block,
                                             RELOC_BLOCK_BYTES, &lid) != VERTHYS_OK) {
                write_ok = 0;
                break;
            }
            ids[8 + k] = lid;
            if (k == 6) next_after_h = v3->txn.ext_idx->next_offset;
            if (v3->txn.ext_idx->next_offset < v3->txn.reloc_hole_floor) {
                floor_respected = 0;
            }
        }

        /* 死块 2：再删一块新写块，续写两块触发二次紧凑化 */
        if (write_ok && verthys_txn_v3_delete(&v3->txn, ids[8]) != VERTHYS_OK) {
            write_ok = 0;
        }
        for (unsigned k = 0; k < 2 && write_ok; k++) {
            n = sprintf_s(name, sizeof(name), "reloc-C%u", k);
            reloc_fill(block, RELOC_BLOCK_BYTES, 0xC0u + k);
            if (verthys_v3_add_record_in_txn(v3, VERTHYS_RECORD_ACCOUNT,
                                             name, (size_t)n, block,
                                             RELOC_BLOCK_BYTES, &lid) != VERTHYS_OK) {
                write_ok = 0;
                break;
            }
            ids[15] = lid;
            if (k == 1) next_after_j = v3->txn.ext_idx->next_offset;
            if (v3->txn.ext_idx->next_offset < v3->txn.reloc_hole_floor) {
                floor_respected = 0;
            }
        }
    }
    if (write_ok && verthys_v3_txn_finish(v3) != VERTHYS_OK) write_ok = 0;

    /* 幸存块读回校验（死块对应的两条 LID 应 NOTFOUND） */
    if (write_ok) {
        /* 块 0（未删除）与 A 数据完整 */
        if (Verthys_GetRecord(h, ids[0], &out) != VERTHYS_OK ||
            !reloc_verify(out.data, RELOC_BLOCK_BYTES, 0)) write_ok = 0;
        if (Verthys_GetRecord(h, ids[7], &out) != VERTHYS_OK ||
            !reloc_verify(out.data, RELOC_BLOCK_BYTES, 0xAAu)) write_ok = 0;
        if (Verthys_GetRecord(h, ids[2], &out) != VERTHYS_ERR_NOTFOUND) write_ok = 0;
        if (Verthys_GetRecord(h, ids[8], &out) != VERTHYS_ERR_NOTFOUND) write_ok = 0;
    }

    (void)Verthys_Deinit(h);
    free(block);
    reloc_cleanup();

    CHECK(write_ok);
    /* 紧凑化游标收缩与跳洞地板纪律：活跃块前向搬移覆盖死块空洞，
     * 两轮紧凑化全程游标不低于本事务地板（16MiB） */
    CHECK(floor_respected);
    /* 首轮紧凑化（死块 2MiB 被活跃块前向搬移覆盖）：活跃 14 块，
     * 每块占位 = 明文长度 + AEAD 标签（VERTHYS_EXTENT_TAG_BYTES） */
    CHECK_EQ(next_after_h,
             (uint64_t)(14u * (RELOC_BLOCK_BYTES + VERTHYS_EXTENT_TAG_BYTES)));
    /* 二次紧凑化：活跃 15 块（死块回收不产生数据区回落） */
    CHECK_EQ(next_after_j,
             (uint64_t)(15u * (RELOC_BLOCK_BYTES + VERTHYS_EXTENT_TAG_BYTES)));
    return 0;
}
