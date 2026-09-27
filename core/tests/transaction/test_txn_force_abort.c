/*
 * test_txn_force_abort.c — 配套测试：写入失败后的会话级恢复
 *
 * 场景：MemTable 换表分配失败（LSM 只读态置位）→ 事务内 LSM 写入失败
 * （RESOURCE_LIMIT）→ 常规回滚因重建分配同样失败 → 强制复位兜底
 * （force_abort）。
 *
 * 行为契约：
 *   1. 失败事务的返回值如实传回 RESOURCE_LIMIT（不吞错误、不虚报成功）；
 *   2. 强制复位后事务状态归位 ABORTED：后续 begin 可再次进入。历史缺陷
 *      为常规回滚失败被忽略时状态滞留 ACTIVE，后续全部写入永久 INVALID
 *      ——单点瞬时故障瘫痪整个会话，用户侧表现为"部分记录写入失败"
 *      后同一批照片连带全部失败；
 *   3. 瞬时压力消退后（分配恢复），下一条写入经 LSM 只读态自愈
 *      （一次性重放重建）原地成功，无需重开容器；
 *   4. 既有数据与新写入数据均完整可读。
 *
 * 失败防残留：操作序列只记录观测值，资源清理先行，断言统一收尾
 * （CHECK 失败立即返回——中途断言会跳过清理，句柄泄漏将阻塞后续
 * 测试的 remove()）。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "verthys_v3_lifecycle.h"     /* VerthysContextV3 */
#include "verthys_transaction_v3.h"   /* VerthysTxnV3State */
#include "verthys_lsm.h"              /* verthys_lsm_flush */
#include "verthys_lsm_internal.h"     /* verthys_lsm_memtable_test_force_alloc_fail */

#include <string.h>
#include <stdio.h>

#define FA_VERTHYS  "test_txn_force_abort.verthys"
#define FA_PW       "force-abort-pass"
#define FA_PW_LEN   16

static void fa_cleanup(void) { remove(FA_VERTHYS); }

TEST(txn_add_failure_session_recovery)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "fa-first", 8,
                       (const uint8_t *)"first-record-payload", 20};
    VerthysRecord r3 = {VERTHYS_RECORD_ACCOUNT, "fa-recover", 10,
                       (const uint8_t *)"recovered-record-payload", 23};
    VerthysRecord out;
    uint64_t lid_r1 = 0, lid_r3 = 0;
    VerthysResult r_flush = VERTHYS_OK;
    VerthysResult r2 = VERTHYS_OK;
    VerthysResult r3r = VERTHYS_OK;
    int state_after_fail = -1;
    int get_r1_ok = 0, get_r3_ok = 0, r1_payload_ok = 0, r3_payload_ok = 0;
    int seq_ok = 1;

    fa_cleanup();

    /* --- 序列执行（观测值记录，不中途断言） --- */
    if (Verthys_Init(&h) != VERTHYS_OK) { fa_cleanup(); return 1; }
    if (Verthys_CreateWithPreset(h, FA_VERTHYS, FA_PW, FA_PW_LEN,
                                 VERTHYS_PRESET_PERFORMANCE) != VERTHYS_OK) {
        (void)Verthys_Deinit(h); fa_cleanup(); return 1;
    }
    if (Verthys_AddRecord(h, &r1, &lid_r1) != VERTHYS_OK || lid_r1 != 1) {
        (void)Verthys_Deinit(h); fa_cleanup(); return 1;
    }

    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    if (v3 == NULL || v3->subsystems_open != 1) {
        (void)Verthys_Deinit(h); fa_cleanup(); return 1;
    }

    /* 注入换表分配失败 → flush 在重建处失败（条目已持久化入 SSTable、
     * 旧表已销毁，LSM 只读态置位——同生产瞬时内存压力形态）。
     * 注入保持开启：此后事务写入与回滚重建均将瞬时失败。 */
    verthys_lsm_memtable_test_force_alloc_fail(1);
    r_flush = verthys_lsm_flush(v3->lsm);

    /* 失败写入：事务内 LSM put 经只读态自愈尝试（重建首步分配即失败）
     * 返回 RESOURCE_LIMIT；内部 abort 的常规回滚重建同样失败 → 走
     * force_abort 兜底归位。 */
    r2 = Verthys_AddRecord(h, &r3, &lid_r3);
    state_after_fail = (int)v3->txn.state;

    /* 复位注入（瞬时压力消退） */
    verthys_lsm_memtable_test_force_alloc_fail(0);

    /* 恢复写入：begin 需可再次进入（历史缺陷此处永久 INVALID），
     * LSM 只读态经一次性重放重建自愈，写能力原地恢复 */
    r3r = Verthys_AddRecord(h, &r3, &lid_r3);

    /* 数据完好性验证（r1 与本次恢复写入均完整可读） */
    if (Verthys_GetRecord(h, lid_r1, &out) == VERTHYS_OK) {
        get_r1_ok = 1;
        r1_payload_ok = (out.data_len == 20 &&
            memcmp(out.data, "first-record-payload", 20) == 0);
    }
    if (Verthys_GetRecord(h, lid_r3, &out) == VERTHYS_OK) {
        get_r3_ok = 1;
        r3_payload_ok = (out.data_len == 23 &&
            memcmp(out.data, "recovered-record-payload", 23) == 0);
    }

    /* --- 资源清理先行（后续断言失败不产生句柄/文件残留） --- */
    if (Verthys_Lock(h) != VERTHYS_OK) {
        (void)Verthys_Deinit(h); fa_cleanup(); return 1;
    }
    (void)Verthys_Deinit(h);
    fa_cleanup();

    /* --- 统一断言（观测值一并打印，红态可直接定位） --- */
    printf("[txn-force-abort] obs: flush=%d r2=%d state_after=%d r3=%d "
           "lid3=%llu get1=%d p1=%d get3=%d p3=%d seq=%d\n",
           (int)r_flush, (int)r2, state_after_fail, (int)r3r,
           (unsigned long long)lid_r3, get_r1_ok, r1_payload_ok,
           get_r3_ok, r3_payload_ok, seq_ok);

    CHECK(seq_ok == 1);                                  /* 前序序列完整 */
    CHECK(r_flush == VERTHYS_ERR_RESOURCE_LIMIT);        /* 注入生效：flush 失败 */
    CHECK(r2 == VERTHYS_ERR_RESOURCE_LIMIT);             /* 失败如实传回 */
    CHECK(state_after_fail == (int)VERTHYS_TXN_V3_ABORTED); /* 兜底归位 */
    CHECK(r3r == VERTHYS_OK);                            /* 核心：写入恢复 */
    CHECK(lid_r3 == 2);                                  /* lid 与索引一致 */
    CHECK(get_r1_ok == 1 && r1_payload_ok == 1);         /* 既有数据完好 */
    CHECK(get_r3_ok == 1 && r3_payload_ok == 1);         /* 新写入数据完好 */

    printf("[txn-force-abort] 写入失败会话级恢复契约成立\n");
    return 0;
}