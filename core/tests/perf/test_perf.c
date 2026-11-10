/*
 * test_perf.c — 密钥体系性能基准
 *
 * 度量并输出：
 *   - 分片封装/解封吞吐（4MiB 分片、64MiB 总量）
 *   - 库解锁耗时（含 Argon2id 口令派生 + 设备根解封）
 *   - 模块切换耗时（模块口令派生 + 设备根解封 + MDEK 校验）
 *
 * 断言采用宽松上界：仅在明显退化时失败；精确阈值由持续集成
 * 采集 stdout 后判定。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_keymanager.h"
#include "vty_module.h"
#include "vty_chunk.h"
#include "vty_util.h"
#include "verthys_api_utils.h"

#include <stdio.h>
#include <string.h>

#define PERF_CHUNK (4u * 1024u * 1024u)
#define PERF_CHUNKS 16u
#define PERF_VAULT "perf.verthys"
#define PERF_MODULE "perf_mod.bin"

TEST(perf_chunk_throughput)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t *pt = (uint8_t *)vty_alloc(PERF_CHUNK);
    uint64_t t0, elapsed;
    uint32_t i;
    uint64_t total = 0;

    CHECK(pt != NULL);
    memset(pt, 0x3c, PERF_CHUNK);
    memset(mdek, 0x41, sizeof(mdek));
    memset(uuid, 0x42, sizeof(uuid));

    t0 = verthys_monotonic_ms();
    for (i = 0; i < PERF_CHUNKS; i++) {
        uint8_t *ct = NULL;
        uint8_t *back = NULL;
        size_t ct_len = 0;
        size_t back_len = 0;

        CHECK_EQ(vty_chunk_seal(mdek, uuid, i, PERF_CHUNKS, 1, pt, PERF_CHUNK,
                                &ct, &ct_len), VTY_OK);
        CHECK_EQ(vty_chunk_open(mdek, uuid, i, PERF_CHUNKS, 1, ct, ct_len,
                                &back, &back_len), VTY_OK);
        CHECK_EQ(back_len, PERF_CHUNK);
        CHECK_EQ(memcmp(back, pt, PERF_CHUNK), 0);
        total += (uint64_t)PERF_CHUNK * 2u;
        vty_free(back, back_len);
        vty_free(ct, ct_len);
    }
    elapsed = verthys_monotonic_ms() - t0;
    vty_free(pt, PERF_CHUNK);

    printf("  [PERF] chunk seal+open %llu MiB in %llu ms (%.1f MiB/s)\n",
           (unsigned long long)(total >> 20), (unsigned long long)elapsed,
           elapsed > 0 ? (double)total / (1024.0 * 1024.0) /
                             ((double)elapsed / 1000.0)
                       : 0.0);
    /* 64MiB 双程至少应达到 100MiB/s；低于此值说明 AEAD/BLAKE3 路径退化 */
    if (elapsed > 0) {
        CHECK((double)total / (1024.0 * 1024.0) /
                  ((double)elapsed / 1000.0) > 100.0);
    }
    return 0;
}

TEST(perf_vault_unlock_latency)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint64_t max_ms = 0;
    uint32_t i;

    remove(PERF_VAULT);
    CHECK_EQ(vty_vault_create(PERF_VAULT, "perf-pass", &v, code, sizeof(code)),
             VTY_OK);
    vty_vault_free(v);

    for (i = 0; i < 5; i++) {
        uint64_t t0 = verthys_monotonic_ms();
        v = NULL;
        CHECK_EQ(vty_vault_open(PERF_VAULT, "perf-pass", &v), VTY_OK);
        {
            uint64_t ms = verthys_monotonic_ms() - t0;
            if (ms > max_ms) max_ms = ms;
        }
        vty_vault_free(v);
    }

    printf("  [PERF] vault open max=%llu ms over 5 runs\n",
           (unsigned long long)max_ms);
    /* 性能目标 p95 <= 1.5s；这里用 5 次的最大值近似上界 */
    CHECK(max_ms < 1500);
    remove(PERF_VAULT);
    return 0;
}

TEST(perf_module_switch_latency)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint64_t max_ms = 0;
    uint32_t i;

    remove(PERF_VAULT);
    remove(PERF_MODULE);
    CHECK_EQ(vty_vault_create(PERF_VAULT, "perf-pass", &v, code, sizeof(code)),
             VTY_OK);
    /* 模块槽在容器内：启用一次后测重复解锁（口令 KDF 路径） */
    CHECK_EQ(vty_module_enable(v, 0u, "mod-pass", NULL), VTY_OK);

    for (i = 0; i < 5; i++) {
        uint64_t t0 = verthys_monotonic_ms();
        vty_module_lock(v, 0u);
        CHECK_EQ(vty_module_unlock(v, 0u, "mod-pass"), VTY_OK);
        {
            uint64_t ms = verthys_monotonic_ms() - t0;
            if (ms > max_ms) max_ms = ms;
        }
    }

    printf("  [PERF] module switch max=%llu ms over 5 runs\n",
           (unsigned long long)max_ms);
    /* 性能目标 <=200ms；给出 2 倍环境余量，精确阈值由持续集成采集判定 */
    CHECK(max_ms < 400);

    vty_vault_free(v);
    remove(PERF_VAULT);
    remove(PERF_MODULE);
    return 0;
}
