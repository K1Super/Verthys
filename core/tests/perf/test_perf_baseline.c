/*
 * test_perf_baseline.c — 方案 §8.3：性能基准与回归
 *
 * 度量项（解锁耗时 / 写入吞吐 / 批量读取吞吐），输出到 stdout 供 CI
 * 采集与阈值报警；断言仅做宽松健全性校验（避免环境噪声导致假失败）：
 *   - 解锁总耗时 < 5s（BALANCED 校准目标 1.2s 的 4 倍上界）
 *   - 写入/读取吞吐 > 0
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "verthys_api_utils.h"
#include <string.h>

#define BASE_VERTHYS "test_perf_baseline_tmp.verthys"

static void base_cleanup(void) { remove(BASE_VERTHYS); }

TEST(perf_baseline_unlock_write_read)
{
    base_cleanup();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, BASE_VERTHYS, "perf-pass", 9,
                                    VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    /* 1. 解锁耗时（第二次解锁：温缓存热路径） */
    Verthys_Lock(h);
    uint64_t t0 = verthys_monotonic_ms();
    CHECK_EQ(Verthys_Unlock(h, BASE_VERTHYS, "perf-pass", 9, 0), VERTHYS_OK);
    uint64_t unlock_ms = verthys_monotonic_ms() - t0;

    /* 2. 写入吞吐：50 条记录（含事务提交与缓存异步写） */
    const uint32_t N = 50;
    uint64_t t1 = verthys_monotonic_ms();
    for (uint32_t i = 0; i < N; i++) {
        VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "perf", 4,
                         (const uint8_t *)"payload-bytes-for-baseline", 26};
        uint64_t id = 0;
        CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);
    }
    uint64_t write_ms = verthys_monotonic_ms() - t1;

    /* 3. 批量读取吞吐：50 条逐条借用读取 */
    uint64_t t2 = verthys_monotonic_ms();
    for (uint64_t id = 1; id <= N; id++) {
        VerthysRecord out;
        CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    }
    uint64_t read_ms = verthys_monotonic_ms() - t2;

    VerthysDiagnostics diag;
    CHECK_EQ(Verthys_GetDiagnostics(h, &diag), VERTHYS_OK);

    printf("  [PERF-BASELINE] unlock=%llu ms derive=%llu ms write=%u rec in %llu ms (%.1f rec/s) read=%u rec in %llu ms\n",
           (unsigned long long)unlock_ms,
           (unsigned long long)diag.unlock_derive_ms,
           N, (unsigned long long)write_ms,
           write_ms > 0 ? (double)N * 1000.0 / (double)write_ms : 0.0,
           N, (unsigned long long)read_ms);

    /* 宽松健全性断言（CI 阈值报警在此基础上另行配置）。
     * 注：50 条借用指针读取可快于 QPC 时钟粒度（read_ms==0 合法），
     * 读取吞吐不做时间断言，正确性由上方逐条 CHECK 保证。 */
    CHECK(unlock_ms < 5000);
    CHECK(write_ms > 0);

    Verthys_Lock(h);
    Verthys_Deinit(h);
    base_cleanup();
    return 0;
}
