/*
 * test_txn_delete_retry.c — 配套测试：DELETE 中途失败的引用完好性
 *
 * 场景：事务内删除的 LSM 墓碑写入失败（冻结活跃 MemTable 注入——
 * 墓碑的 WAL 帧已落盘、跳表插入被拒，确定性触发"删除半程"）。
 *
 * 行为契约：
 *   1. 失败瞬间零副作用：Extent 引用计数不变（仍 1）、事务账本未
 *      记账、被删记录仍可读。若引用先于墓碑清零，失败与回滚之间的
 *      任何持久化都会落盘"索引存活但引用已清零"的悬挂状态——该
 *      状态会被 GC 判定为可回收，物理删除仍被引用的数据块；
 *   2. 回滚复原：失败事务回滚后引用计数与记录可见性复原；
 *   3. 正向语义不变：完整提交路径的删除仍生效（引用归零、记录
 *      不可见、账本弃置）。
 *
 * 失败防残留：操作序列只记录观测值，资源清理先行，断言统一收尾
 * （CHECK 失败立即返回——中途断言会跳过清理，句柄泄漏将阻塞后续
 * 测试的 remove()）。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "verthys_v3_lifecycle.h"     /* VerthysContextV3 */
#include "verthys_transaction_v3.h"   /* verthys_txn_v3_* */
#include "verthys_extent.h"           /* verthys_extent_index_find */
#include "verthys_lsm.h"              /* verthys_lsm_get */
#include "verthys_lsm_internal.h"     /* verthys_lsm_memtable_freeze */

#include <string.h>
#include <stdio.h>

#define DR_VERTHYS  "test_txn_del_retry.verthys"
#define DR_PW       "del-retry-pass"
#define DR_PW_LEN   14

static void dr_cleanup(void) { remove(DR_VERTHYS); }

TEST(txn_delete_failure_keeps_extent_ref)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRecord out;
    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "del-retry", 9,
                       (const uint8_t *)"delete-retry-payload", 20};
    uint64_t lid_r1 = 0;
    uint8_t hash[VERTHYS_EXTENT_HASH_BYTES];
    VerthysExtent ent;
    VerthysResult r_del = VERTHYS_OK;
    uint32_t ref_after_fail = 0xFFFFFFFFu;
    uint32_t ref_after_rollback = 0xFFFFFFFFu;
    uint32_t ref_after_commit = 0xFFFFFFFFu;
    size_t ledger_after_fail = 0xFFFFFFFFu;
    size_t ledger_after_commit = 0xFFFFFFFFu;
    int lsm_alive_after_fail = 0;
    int record_ok_after_rollback = 0;
    int record_gone_after_commit = 0;
    int seq_ok = 1;

    dr_cleanup();

    /* --- 序列执行（观测值记录，不中途断言） --- */
    if (Verthys_Init(&h) != VERTHYS_OK) { dr_cleanup(); return 1; }
    if (Verthys_CreateWithPreset(h, DR_VERTHYS, DR_PW, DR_PW_LEN,
                                 VERTHYS_PRESET_PERFORMANCE) != VERTHYS_OK) {
        (void)Verthys_Deinit(h); dr_cleanup(); return 1;
    }
    if (Verthys_AddRecord(h, &r1, &lid_r1) != VERTHYS_OK || lid_r1 != 1) {
        (void)Verthys_Deinit(h); dr_cleanup(); return 1;
    }

    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    if (v3 == NULL || v3->subsystems_open != 1 ||
        v3->ext_idx->count != 1) {
        (void)Verthys_Deinit(h); dr_cleanup(); return 1;
    }
    memcpy(hash, v3->ext_idx->entries[0].hash, VERTHYS_EXTENT_HASH_BYTES);

    /* 失败注入：冻结活跃 MemTable → 事务内 DELETE 的墓碑跳表插入被拒
     *（墓碑 WAL 帧先行已落盘——恰好构成"删除半程"故障点） */
    if (verthys_txn_v3_begin(&v3->txn) != VERTHYS_OK) {
        seq_ok = 0;
    } else {
        verthys_lsm_memtable_freeze(v3->lsm->memtable);
        r_del = verthys_txn_v3_delete(&v3->txn, lid_r1);

        /* 失败瞬间观测（核心窗口） */
        if (verthys_extent_index_find(v3->ext_idx, hash, &ent) == VERTHYS_OK) {
            ref_after_fail = ent.ref_count;
        }
        ledger_after_fail = v3->txn.ext_ref_count;
        lsm_alive_after_fail =
            (verthys_lsm_get(v3->lsm, lid_r1, NULL, NULL, 0, NULL) == VERTHYS_OK);

        /* 回滚复原（重建的 MemTable 解冻，后续操作恢复正常） */
        if (verthys_txn_v3_rollback(&v3->txn) != VERTHYS_OK) seq_ok = 0;
        if (verthys_extent_index_find(v3->ext_idx, hash, &ent) == VERTHYS_OK) {
            ref_after_rollback = ent.ref_count;
        }
        record_ok_after_rollback =
            (Verthys_GetRecord(h, lid_r1, &out) == VERTHYS_OK);
    }

    /* 正向全链：新事务完整删除（顺序重排不得破坏正常提交语义） */
    if (verthys_txn_v3_begin(&v3->txn) != VERTHYS_OK ||
        verthys_txn_v3_delete(&v3->txn, lid_r1) != VERTHYS_OK ||
        verthys_txn_v3_prepare(&v3->txn) != VERTHYS_OK ||
        verthys_txn_v3_commit(&v3->txn) != VERTHYS_OK ||
        verthys_txn_v3_confirm(&v3->txn) != VERTHYS_OK) {
        seq_ok = 0;
    }
    if (verthys_extent_index_find(v3->ext_idx, hash, &ent) == VERTHYS_OK) {
        ref_after_commit = ent.ref_count;
    }
    ledger_after_commit = v3->txn.ext_ref_count;
    record_gone_after_commit =
        (Verthys_GetRecord(h, lid_r1, &out) == VERTHYS_ERR_NOTFOUND);

    /* --- 资源清理先行（后续断言失败不产生句柄/文件残留） --- */
    if (Verthys_Lock(h) != VERTHYS_OK) {
        (void)Verthys_Deinit(h); dr_cleanup(); return 1;
    }
    (void)Verthys_Deinit(h);
    dr_cleanup();

    /* --- 统一断言（观测值一并打印，红态可直接定位） --- */
    printf("[txn-del-retry] obs: r_del=%d seq=%d ref_fail=%u ledger_fail=%zu "
           "alive=%d ref_rb=%u rec_rb=%d ref_cmt=%u rec_gone=%d ledger_cmt=%zu\n",
           (int)r_del, seq_ok, ref_after_fail, ledger_after_fail,
           lsm_alive_after_fail, ref_after_rollback, record_ok_after_rollback,
           ref_after_commit, record_gone_after_commit, ledger_after_commit);

    CHECK(r_del != VERTHYS_OK);            /* 注入生效：DELETE 确实失败 */
    CHECK(seq_ok == 1);                    /* 回滚与正向序列全部成功 */
    CHECK(ref_after_fail == 1);            /* 失败瞬间引用完好 */
    CHECK(ledger_after_fail == 0);         /* 失败瞬间账本未记账 */
    CHECK(lsm_alive_after_fail == 1);      /* 被删记录仍存活 */
    CHECK(ref_after_rollback == 1);        /* 回滚后引用复原 */
    CHECK(record_ok_after_rollback == 1);  /* 回滚后记录可读 */
    CHECK(ref_after_commit == 0);          /* 正向删除引用归零 */
    CHECK(record_gone_after_commit == 1);  /* 正向删除后不可见 */
    CHECK(ledger_after_commit == 0);        /* 提交后账本弃置 */

    printf("[txn-del-retry] DELETE 中途失败引用完好性契约成立\n");
    return 0;
}
