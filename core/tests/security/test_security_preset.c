/*
 * test_security_preset.c — 三档预设配置、特性位投影与快照读取
 *
 * 覆盖：
 *   - 特性位投影与档位矩阵逐位一致（跨层特性契约的唯一权威输出）
 *   - 切档后活跃档位读回一致、重复切档幂等、非法入参拒绝
 *   - 并发快照压力：切换与读取并发时快照恒为完整档位
 *     （无全零、无跨档字段混合、无撕裂）
 *
 * 全局状态纪律：本文件切换运行时档位后必须复位为平衡档，
 * 避免影响依赖平衡档行为的其他用例。
 */
#include "verthys_test.h"
#include "security_preset.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

/* 三档特性位期望值（11 位契约逐位核算产物） */
#define EXPECT_BITS_BALANCED     0x6FFu
#define EXPECT_BITS_SECURE       0x7FFu
#define EXPECT_BITS_PERFORMANCE  0x073u

/* 应用侧策略位期望值（平衡档基线 / 高安全档附加剪贴板防护 / 性能档仅空闲锁定） */
#define APP_BITS_BALANCED    (SEC_FEAT_INTEGRITY_CHECK | SEC_FEAT_SESSION_LOCK_IDLE | \
                              SEC_FEAT_MODULE_PATROL | SEC_FEAT_USB_CLONE_DETECT | \
                              SEC_FEAT_TRACE_CLEANUP)
#define APP_BITS_SECURE      (APP_BITS_BALANCED | SEC_FEAT_CLIPBOARD_GUARD)
#define APP_BITS_PERFORMANCE (SEC_FEAT_SESSION_LOCK_IDLE)

/* 判定快照是否为某个完整档位（逐字段一致性校验）
 * 任一字段组合不属于已知档位（含全零、跨档混合）即返回 0。 */
static int snapshot_is_valid_matrix(const SecurityConfig *c)
{
    switch (c->preset) {
    case SEC_PRESET_BALANCED:
        return c->anti_debug == 1 && c->anti_debug_aggressive == 0 &&
               c->memory_lock == 1 && c->anti_dump == 1 && c->anti_inject == 1 &&
               c->app_features == APP_BITS_BALANCED;
    case SEC_PRESET_SECURE:
        return c->anti_debug == 1 && c->anti_debug_aggressive == 1 &&
               c->memory_lock == 1 && c->anti_dump == 1 && c->anti_inject == 1 &&
               c->app_features == APP_BITS_SECURE;
    case SEC_PRESET_PERFORMANCE:
        return c->anti_debug == 1 && c->anti_debug_aggressive == 0 &&
               c->memory_lock == 0 && c->anti_dump == 0 && c->anti_inject == 1 &&
               c->app_features == APP_BITS_PERFORMANCE;
    default:
        return 0;
    }
}

/* ====================================================================== *
 * 测试1：特性位投影与矩阵逐位一致 + 非法入参拒绝
 * ====================================================================== */
TEST(preset_feature_bits_matrix)
{
    uint32_t bits = 0;

    CHECK_EQ(security_preset_feature_bits(SEC_PRESET_BALANCED, &bits), 0);
    CHECK_EQ(bits, EXPECT_BITS_BALANCED);

    CHECK_EQ(security_preset_feature_bits(SEC_PRESET_SECURE, &bits), 0);
    CHECK_EQ(bits, EXPECT_BITS_SECURE);

    CHECK_EQ(security_preset_feature_bits(SEC_PRESET_PERFORMANCE, &bits), 0);
    CHECK_EQ(bits, EXPECT_BITS_PERFORMANCE);

    /* 非法档位与空指针必须显式拒绝，不得返回未定义位值 */
    CHECK_EQ(security_preset_feature_bits((SecurityPreset)9, &bits), -1);
    CHECK_EQ(security_preset_feature_bits(SEC_PRESET_BALANCED, NULL), -1);

    /* 投影结果始终落在合法掩码内 */
    CHECK_EQ((EXPECT_BITS_BALANCED | EXPECT_BITS_SECURE | EXPECT_BITS_PERFORMANCE)
                 & ~SEC_FEAT_VALID_MASK, 0u);
    return 0;
}

/* ====================================================================== *
 * 测试2：切档后读回一致 + 重复切档幂等 + 快照字段随档位收敛
 * ====================================================================== */
TEST(preset_switch_readback_idempotent)
{
    CHECK_EQ(security_preset_init(SEC_PRESET_BALANCED), 0);

    SecurityPreset sp = (SecurityPreset)9;
    CHECK_EQ(security_active_preset(&sp), 0);
    CHECK_EQ(sp, SEC_PRESET_BALANCED);

    SecurityConfig c;
    CHECK_EQ(security_config_snapshot(&c), 0);
    CHECK_EQ(c.preset, SEC_PRESET_BALANCED);
    CHECK(snapshot_is_valid_matrix(&c));

    /* 切高安全档：读回一致且激进退出位开启 */
    CHECK_EQ(security_preset_switch(SEC_PRESET_SECURE), 0);
    CHECK_EQ(security_active_preset(&sp), 0);
    CHECK_EQ(sp, SEC_PRESET_SECURE);
    CHECK_EQ(security_config_snapshot(&c), 0);
    CHECK_EQ(c.anti_debug_aggressive, 1);
    CHECK(snapshot_is_valid_matrix(&c));

    /* 幂等：重复切到当前档仍成功，档位不变 */
    CHECK_EQ(security_preset_switch(SEC_PRESET_SECURE), 0);
    CHECK_EQ(security_runtime_preset(), SEC_PRESET_SECURE);

    /* 切性能档：锁页/防转储关闭，调试检测保持开启（红线能力） */
    CHECK_EQ(security_preset_switch(SEC_PRESET_PERFORMANCE), 0);
    CHECK_EQ(security_config_snapshot(&c), 0);
    CHECK_EQ(c.memory_lock, 0);
    CHECK_EQ(c.anti_dump, 0);
    CHECK_EQ(c.anti_debug, 1);
    CHECK(snapshot_is_valid_matrix(&c));

    /* 复位全局状态：后续用例依赖平衡档行为 */
    CHECK_EQ(security_preset_switch(SEC_PRESET_BALANCED), 0);
    CHECK_EQ(security_active_preset(&sp), 0);
    CHECK_EQ(sp, SEC_PRESET_BALANCED);
    return 0;
}

/* ====================================================================== *
 * 测试3：并发快照压力（写线程持续切档 × 4 读线程持续取快照）
 *
 * 断言：任一成功快照都必须是某个完整档位——无全零、无跨档字段混合。
 * 该用例覆盖双缓冲 + 发布世代号的一致性契约。
 * ====================================================================== */
typedef struct SnapshotStressCtx {
    volatile LONG stop;
    volatile LONG invalid;
    volatile LONG iterations;
} SnapshotStressCtx;

static DWORD WINAPI snapshot_reader_thread(LPVOID param)
{
    SnapshotStressCtx *ctx = (SnapshotStressCtx *)param;
    while (InterlockedCompareExchange(&ctx->stop, 0, 0) == 0) {
        SecurityConfig c;
        if (security_config_snapshot(&c) == 0) {
            if (!snapshot_is_valid_matrix(&c)) {
                InterlockedIncrement(&ctx->invalid);
            }
        }
        InterlockedIncrement(&ctx->iterations);
    }
    return 0;
}

TEST(preset_snapshot_concurrent_stress)
{
    SnapshotStressCtx ctx;
    memset(&ctx, 0, sizeof(ctx));

    HANDLE readers[4];
    for (int i = 0; i < 4; i++) {
        readers[i] = CreateThread(NULL, 0, snapshot_reader_thread, &ctx, 0, NULL);
        CHECK(readers[i] != NULL);
    }

    const SecurityPreset seq[3] = {
        SEC_PRESET_BALANCED, SEC_PRESET_SECURE, SEC_PRESET_PERFORMANCE
    };
    for (int i = 0; i < 200000; i++) {
        CHECK_EQ(security_preset_switch(seq[i % 3]), 0);
    }

    InterlockedExchange(&ctx.stop, 1);
    DWORD wait_rc = WaitForMultipleObjects(4, readers, TRUE, 10000);
    CHECK_EQ(wait_rc, WAIT_OBJECT_0);
    for (int i = 0; i < 4; i++) {
        CloseHandle(readers[i]);
    }

    CHECK_EQ((int)ctx.invalid, 0);   /* 任一快照必须是完整档位 */
    CHECK((int)ctx.iterations > 0);  /* 读线程确实执行过快照 */

    /* 复位全局状态 */
    CHECK_EQ(security_preset_switch(SEC_PRESET_BALANCED), 0);
    return 0;
}