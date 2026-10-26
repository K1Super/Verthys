/*
 * test_v4_lockout_pipeline.c — 熔断接入解锁流水线验收
 *
 * 验证目标：
 *   - 解锁口令失败（AUTH）会写入持久化计数（跨重启语义）
 *   - 达到阈值后，即使进程内退避为 0，Unlock 仍返回 RATE（不可绕过）
 *   - 重新 init 状态模块（等价重启）后仍锁定
 *   - 显式 reset（运维恢复路径）后正确口令恢复
 *
 * 持久化默认指向真实用户目录，本进程由 test_runner 关闭；
 * 本用例显式开启并注入沙箱状态文件，结束时无论成败都恢复原状。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_api_utils.h"
#include "vty_lockout.h"
#include "vty_tpm_witness.h"

#include <stdio.h>
#include <string.h>

#define LP_VAULT "v4_lockout_pipeline.verthys"
#define LP_STATE "v4_lockout_pipeline.state"
#define LP_PW    "pipeline-pass"
#define LP_PW_LEN 13u
#define LP_BAD   "pipeline-wrong"
#define LP_BAD_LEN 14u

static void lp_clean_witness(void)
{
    uint8_t id[VTY_UUID_BYTES];
    if (vty_tpm_witness_id_from_string(LP_STATE, id) == VTY_OK) {
        (void)vty_tpm_witness_delete_all(id);
    }
}

TEST(v4_lockout_pipeline_persistent)
{
    VerthysHandle h = NULL;
    int failed = 0;
    int rc;
    uint32_t i;

    remove(LP_VAULT);
    remove(LP_STATE);
    lp_clean_witness();

    verthys_backoff_set_persistent(1);
    if (vty_lockout_set_path(LP_STATE) != VTY_OK ||
        vty_lockout_init() != VTY_OK ||
        vty_lockout_reset() != VTY_OK) {
        printf("  [FAIL] lockout sandbox init\n");
        failed = 1;
        goto done;
    }
    /* 清掉前序用例可能残留的进程内退避 */
    verthys_backoff_reset();

    if (Verthys_Init(&h) != VERTHYS_OK) {
        printf("  [FAIL] init\n");
        failed = 1;
        goto done;
    }
    if (Verthys_CreateWithPreset(h, LP_VAULT, LP_PW, LP_PW_LEN,
                                 VERTHYS_PRESET_PERFORMANCE) != VERTHYS_OK) {
        printf("  [FAIL] create\n");
        failed = 1;
        goto done;
    }
    if (Verthys_Lock(h) != VERTHYS_OK) {
        printf("  [FAIL] lock\n");
        failed = 1;
        goto done;
    }

    /* 1. 失败计入 → 持久化计数 +1 */
    rc = (int)Verthys_Unlock(h, LP_VAULT, LP_BAD, LP_BAD_LEN, 0);
    if (rc != VERTHYS_ERR_AUTH) {
        printf("  [FAIL] expect AUTH, got %d\n", rc);
        failed = 1;
        goto done;
    }
    if (vty_lockout_failures() != 1) {
        printf("  [FAIL] persistent failures=%u, expect 1\n",
               vty_lockout_failures());
        failed = 1;
        goto done;
    }

    /* 2. 清零（同时清进程内退避与持久化），再注入 5 次持久化失败 */
    verthys_backoff_reset();
    if (vty_lockout_failures() != 0) {
        printf("  [FAIL] reset should clear persistent counter\n");
        failed = 1;
        goto done;
    }
    for (i = 0; i < VTY_LOCKOUT_MAX_FAILURES; i++) {
        rc = vty_lockout_record_failure();
        if (i + 1u < VTY_LOCKOUT_MAX_FAILURES && rc != VTY_OK) {
            printf("  [FAIL] record %u rc=%d\n", i, rc);
            failed = 1;
            goto done;
        }
    }
    if (vty_lockout_failures() != VTY_LOCKOUT_MAX_FAILURES) {
        printf("  [FAIL] failures=%u, expect %u\n", vty_lockout_failures(),
               VTY_LOCKOUT_MAX_FAILURES);
        failed = 1;
        goto done;
    }

    /* 3. 进程内退避为 0 时，正确口令仍必须被持久化熔断拦截 */
    rc = (int)Verthys_Unlock(h, LP_VAULT, LP_PW, LP_PW_LEN, 0);
    if (rc != VERTHYS_ERR_RATE) {
        printf("  [FAIL] locked vault must return RATE, got %d\n", rc);
        failed = 1;
        goto done;
    }

    /* 4. 等价重启：重新 init 后仍锁定 */
    if (vty_lockout_init() != VTY_OK || vty_lockout_check() != VTY_E_LOCKED) {
        printf("  [FAIL] lockout did not survive restart\n");
        failed = 1;
        goto done;
    }

    /* 5. 运维恢复（reset）后正确口令可解锁 */
    verthys_backoff_reset();
    rc = (int)Verthys_Unlock(h, LP_VAULT, LP_PW, LP_PW_LEN, 0);
    if (rc != VERTHYS_OK) {
        printf("  [FAIL] unlock after reset rc=%d\n", rc);
        failed = 1;
        goto done;
    }

done:
    if (h != NULL) Verthys_Deinit(h);
    verthys_backoff_reset();
    verthys_backoff_set_persistent(0);
    remove(LP_VAULT);
    remove(LP_STATE);
    lp_clean_witness();
    return failed ? 1 : 0;
}
