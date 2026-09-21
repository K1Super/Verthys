/*
 * test_backoff_process_wide.c — 暴力破解退避进程级聚合语义测试
 *
 * 验证目标：口令失败记账为进程级聚合——任一句柄上的失败解锁
 * 开启的指数退避窗口，必须拦截同进程内其他独立句柄的解锁尝试，
 * 杜绝"关闭重开句柄即清零计数"的绕过路径。
 *
 * 语义时序：
 *   1. 句柄 A 以错误口令解锁 → AUTH（记账 1 次，2 秒退避窗口开启）；
 *   2. 独立句柄 B 以正确口令解锁同一容器 → 必须被 RATE 拦截
 *      （退避门禁位于口令派生之前，拦截不产生新的失败记账）；
 *   3. 记账清零后句柄 B 正常解锁 → OK（拦截非永久锁死）。
 *
 * 断言后置：错误码先累计到局部标记，全部操作与句柄清理完成后
 * 统一裁决（避免断言中途 return 跳过清理）。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "verthys_api_utils.h"

#include <string.h>
#include <stdio.h>

#define BW_PATH  "test_backoff_pw.verthys"
#define BW_PW    "backoff-pass"
#define BW_PW_LEN 12
#define BW_WRONG "wrong-pass-xx"
#define BW_WRONG_LEN 14

static void bw_cleanup(void) { remove(BW_PATH); }

TEST(backoff_process_wide_aggregation)
{
    VerthysHandle ha = NULL;
    VerthysHandle hb = NULL;
    VerthysResult rc;
    int failed = 0;

    bw_cleanup();
    /* 防御前序测试残留的进程级退避记账（自含测试理论上已清零，
     * 此处显式复位保证本测试时序确定性） */
    verthys_backoff_reset();

    if (Verthys_Init(&ha) != VERTHYS_OK) {
        printf("  [FAIL] init A failed\n");
        return 1;
    }
    if (Verthys_Init(&hb) != VERTHYS_OK) {
        printf("  [FAIL] init B failed\n");
        Verthys_Deinit(ha);
        bw_cleanup();
        return 1;
    }
    if (Verthys_CreateWithPreset(ha, BW_PATH, BW_PW, BW_PW_LEN,
                                 VERTHYS_PRESET_PERFORMANCE) != VERTHYS_OK) {
        printf("  [FAIL] create failed\n");
        goto done;
    }
    if (Verthys_Lock(ha) != VERTHYS_OK) {
        printf("  [FAIL] lock A failed\n");
        goto done;
    }

    /* 1. 句柄 A 错误口令 → AUTH（退避记账 1 次，2 秒窗口开启） */
    rc = Verthys_Unlock(ha, BW_PATH, BW_WRONG, BW_WRONG_LEN, 0);
    if (rc != VERTHYS_ERR_AUTH) {
        printf("  [FAIL] expect AUTH on wrong password, got %ld\n", (long)rc);
        failed = 1;
        goto done;
    }

    /* 2. 独立句柄 B 正确口令 → 进程级聚合下必须 RATE 拦截 */
    rc = Verthys_Unlock(hb, BW_PATH, BW_PW, BW_PW_LEN, 0);
    if (rc != VERTHYS_ERR_RATE) {
        printf("  [FAIL] independent handle bypasses backoff: "
               "expect RATE, got %ld\n", (long)rc);
        failed = 1;
        goto done;
    }

    /* 3. 记账清零 → B 正常解锁（拦截非永久锁死） */
    verthys_backoff_reset();
    rc = Verthys_Unlock(hb, BW_PATH, BW_PW, BW_PW_LEN, 0);
    if (rc != VERTHYS_OK) {
        printf("  [FAIL] unlock after reset should succeed, got %ld\n",
               (long)rc);
        failed = 1;
        goto done;
    }

done:
    Verthys_Deinit(ha);
    Verthys_Deinit(hb);
    bw_cleanup();
    return failed ? 1 : 0;
}
