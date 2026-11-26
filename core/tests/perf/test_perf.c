/*
 * test_perf.c — 密钥体系性能基准
 *
 * 度量并输出：
 *   - 分片封装/解封吞吐（结构分片大小、可配置轮数）
 *   - 库解锁耗时（含 Argon2id 口令派生 + 设备根解封）
 *   - 模块切换耗时（模块口令派生 + 设备根解封 + MDEK 校验）
 *   - 导入提交路径：块批提交、元数据保存、meta 记录提交、BLAKE3 吞吐
 *
 * 断言采用宽松下界/上界：仅在明显退化时失败；精确阈值由持续集成
 * 采集 stdout 后判定。基准规模一律来自环境变量或结构常量，
 * 不以任何示例数据总量作为判据。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_keymanager.h"
#include "vty_module.h"
#include "vty_chunk.h"
#include "vty_repo.h"
#include "vty_blake3.h"
#include "vty_util.h"
#include "verthys_api_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PERF_CHUNK (4u * 1024u * 1024u)
#define PERF_CHUNKS 16u
#define PERF_VAULT "perf.verthys"
#define PERF_MODULE "perf_mod.bin"
#define PERF_IMPORT_VAULT "perf_import.verthys"

/* 基准规模读取：无效/缺失时使用结构默认值，不绑定任何示例总量。 */
static unsigned perf_env_u32(const char *name, unsigned fallback)
{
    const char *raw = getenv(name);
    unsigned long value;
    if (raw == NULL || raw[0] == '\0') return fallback;
    value = strtoul(raw, NULL, 10);
    if (value == 0ul || value > 65536ul) return fallback;
    return (unsigned)value;
}

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
    /* 性能目标 <=200ms；本地保留 2 倍余量。共享 CI runner 受邻居负载与
     * 实时扫描影响，采用与库解锁一致的 1.5s 上界，只拦截明显退化。 */
    {
        const char *ci = getenv("CI");
        uint64_t budget_ms =
            (ci != NULL && strcmp(ci, "true") == 0) ? 1500u : 400u;
        CHECK(max_ms < budget_ms);
    }

    vty_vault_free(v);
    remove(PERF_VAULT);
    remove(PERF_MODULE);
    return 0;
}

TEST(perf_blake3_throughput)
{
    unsigned mib = perf_env_u32("VERTHYS_PERF_BLAKE3_MIB", 16u);
    unsigned rounds = perf_env_u32("VERTHYS_PERF_BLAKE3_ROUNDS", 8u);
    size_t bytes = (size_t)mib * 1024u * 1024u;
    uint8_t *buf;
    uint8_t out[VTY_HASH_BYTES];
    uint64_t t0;
    uint64_t elapsed;
    double mib_per_s;
    unsigned i;
    size_t off;

    buf = (uint8_t *)vty_alloc(bytes);
    CHECK(buf != NULL);
    for (off = 0; off < bytes; off++) {
        buf[off] = (uint8_t)(off * 131u + 17u);
    }

    t0 = verthys_monotonic_ms();
    for (i = 0; i < rounds; i++) {
        CHECK_EQ(vty_blake3_32(buf, bytes, out), VTY_OK);
    }
    elapsed = verthys_monotonic_ms() - t0;
    if (elapsed == 0) elapsed = 1;
    mib_per_s = ((double)mib * (double)rounds) / ((double)elapsed / 1000.0);
    printf("  [PERF] blake3 %u MiB x %u rounds in %llu ms (%.1f MiB/s)\n",
           mib, rounds, (unsigned long long)elapsed, mib_per_s);
    /* 便携实现下界；加速实现应显著高于此值。 */
    CHECK(mib_per_s > 50.0);

    vty_free(buf, bytes);
    return 0;
}

TEST(perf_import_commit_path)
{
    unsigned chunks = perf_env_u32("VERTHYS_PERF_COMMIT_CHUNKS", 8u);
    unsigned meta_saves = perf_env_u32("VERTHYS_PERF_META_SAVES", 8u);
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t *data = NULL;
    VtyRepoInput *inputs = NULL;
    uint64_t *ids = NULL;
    char (*names)[40] = NULL;
    uint64_t t0;
    uint64_t add_ms;
    uint64_t meta_ms;
    uint64_t meta_record_ms;
    double mib;
    double mib_per_s;
    unsigned i;

    remove(PERF_IMPORT_VAULT);
    CHECK_EQ(vty_vault_create(PERF_IMPORT_VAULT, "perf-import-pass", &v, code,
                              sizeof(code)),
             VTY_OK);
    CHECK_EQ(vty_vault_bulk_begin(v), VTY_OK);

    data = (uint8_t *)vty_alloc(PERF_CHUNK);
    inputs = (VtyRepoInput *)calloc(chunks, sizeof(*inputs));
    ids = (uint64_t *)calloc(chunks, sizeof(*ids));
    names = (char (*)[40])calloc(chunks, 40u);
    CHECK(data != NULL && inputs != NULL && ids != NULL && names != NULL);
    for (i = 0; i < PERF_CHUNK; i++) {
        data[i] = (uint8_t)(i * 197u + 31u);
    }
    for (i = 0; i < chunks; i++) {
        snprintf(names[i], sizeof(names[i]), "chunk_perf_%08x", i);
        inputs[i].type = 5u;
        inputs[i].name = (const uint8_t *)names[i];
        inputs[i].name_len = strlen(names[i]);
        inputs[i].data = data;
        inputs[i].data_len = PERF_CHUNK;
    }

    t0 = verthys_monotonic_ms();
    CHECK_EQ(vty_repo_add_many(v, inputs, chunks, ids), VTY_OK);
    add_ms = verthys_monotonic_ms() - t0;
    if (add_ms == 0) add_ms = 1;
    /* 导入会话的锚点推迟必须在块提交后仍然有效；否则每批都会触发
     * 回退锚点提交，性能与 TPM 交互都会被放大。 */
    CHECK_EQ(vty_vault_bulk_active(v), 1);
    mib = ((double)chunks * (double)PERF_CHUNK) / (1024.0 * 1024.0);
    mib_per_s = mib / ((double)add_ms / 1000.0);
    printf("  [PERF] import block batch chunks=%u in %llu ms (%.1f MiB/s)\n",
           chunks, (unsigned long long)add_ms, mib_per_s);
    CHECK(mib_per_s > 5.0);

    t0 = verthys_monotonic_ms();
    for (i = 0; i < meta_saves; i++) {
        CHECK_EQ(vty_vault_save_meta(v), VTY_OK);
    }
    meta_ms = verthys_monotonic_ms() - t0;
    printf("  [PERF] meta save %u runs in %llu ms (avg %.2f ms)\n",
           meta_saves, (unsigned long long)meta_ms,
           (double)meta_ms / (double)meta_saves);

    {
        VtyRepoInput meta_input;
        uint64_t meta_id = 0;
        const char *meta_name = "meta_perf_record";
        const char *meta_body = "{\"name\":\"perf\",\"size\":0}";

        memset(&meta_input, 0, sizeof(meta_input));
        meta_input.type = 1u;
        meta_input.name = (const uint8_t *)meta_name;
        meta_input.name_len = strlen(meta_name);
        meta_input.data = (const uint8_t *)meta_body;
        meta_input.data_len = strlen(meta_body);

        t0 = verthys_monotonic_ms();
        CHECK_EQ(vty_repo_add_many(v, &meta_input, 1u, &meta_id), VTY_OK);
        meta_record_ms = verthys_monotonic_ms() - t0;
        printf("  [PERF] meta record commit in %llu ms\n",
               (unsigned long long)meta_record_ms);
        /* 仅拦截病态退化；绝对阈值由 CI 采集 stdout 判定。 */
        CHECK(meta_record_ms < 5000u);
    }

    CHECK_EQ(vty_vault_bulk_commit(v), VTY_OK);
    vty_vault_free(v);
    free(inputs);
    free(ids);
    free(names);
    vty_free(data, PERF_CHUNK);
    remove(PERF_IMPORT_VAULT);
    return 0;
}
