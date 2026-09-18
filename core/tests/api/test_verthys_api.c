/*
 * test_verthys_api.c — Verthys 公共 API 全链路行为测试（TDD 垂直切片）
 *
 * 通过 verthys.h 公共接口验证：
 *   - 创建新 verthys → 增 → 查 → 锁 → 解锁 → 查（持久化往返）
 *   - 删 → 查返回 NOTFOUND
 *   - 错误密码 → AUTH
 *   - 未解锁时操作 → LOCKED
 *   - 参数校验 → INVALID
 *
 * 注意：Unlock 含 Argon2id 64MiB/3iter，每次约 0.5–1s，测试尽量减少 Unlock 次数。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>  /* Sleep */
#endif

#define TMP_VERTHYS "test_verthys_tmp.verthys"

/* 跨平台睡眠（毫秒） */
static void test_sleep_ms(unsigned ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

static void cleanup_tmp(void) { remove(TMP_VERTHYS); }

/* 创建新 verthys → 增 → 查 → 锁 → 重新解锁 → 查（验证持久化） */
TEST(api_full_roundtrip)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 文件不存在 → 用 Verthys_CreateWithPreset 创建新 verthys */
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "password", 8, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    /* 增记录 */
    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "gmail", 5, (const uint8_t *)"pass123", 7};
    VerthysRecord r2 = {VERTHYS_RECORD_ACCOUNT, "bank", 4, (const uint8_t *)"secret99", 8};
    uint64_t id1 = 0, id2 = 0;
    CHECK_EQ(Verthys_AddRecord(h, &r1, &id1), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &r2, &id2), VERTHYS_OK);
    CHECK(id1 != id2);
    CHECK(id1 > 0);

    /* 查记录 */
    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK_EQ(out.type, VERTHYS_RECORD_ACCOUNT);
    CHECK_EQ(out.name_len, 5u);
    CHECK(memcmp(out.name, "gmail", 5) == 0);
    CHECK_EQ(out.data_len, 7u);
    CHECK(memcmp(out.data, "pass123", 7) == 0);

    /* 锁定（写文件） */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 重新解锁（读文件） */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "password", 8, 0), VERTHYS_OK);

    /* 验证记录持久化 */
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK_EQ(out.name_len, 5u);
    CHECK(memcmp(out.name, "gmail", 5) == 0);
    CHECK_EQ(out.data_len, 7u);
    CHECK(memcmp(out.data, "pass123", 7) == 0);

    CHECK_EQ(Verthys_GetRecord(h, id2, &out), VERTHYS_OK);
    CHECK_EQ(out.name_len, 4u);
    CHECK(memcmp(out.name, "bank", 4) == 0);
    CHECK_EQ(out.data_len, 8u);
    CHECK(memcmp(out.data, "secret99", 8) == 0);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 删除记录 → 查返回 NOTFOUND */
TEST(api_delete_record)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "test", 4, (const uint8_t *)"data", 4};
    uint64_t id = 0;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);

    CHECK_EQ(Verthys_DeleteRecord(h, id), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_ERR_NOTFOUND);

    /* 再删一次 → NOTFOUND */
    CHECK_EQ(Verthys_DeleteRecord(h, id), VERTHYS_ERR_NOTFOUND);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 查不存在记录 → NOTFOUND */
TEST(api_get_not_found)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, 999, &out), VERTHYS_ERR_NOTFOUND);
    CHECK_EQ(Verthys_GetRecord(h, 1, &out), VERTHYS_ERR_NOTFOUND);  /* 空表 */

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 错误密码 → AUTH；连续错误触发指数退避 → RATE；冷却后正确密码可解锁 */
TEST(api_wrong_password)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 创建 */
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "correct", 7, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"y", 1};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 错误密码解锁 → AUTH（第 1 次失败，触发 2^1=2s 冷却） */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "WRONG!!", 7, 0), VERTHYS_ERR_AUTH);

    /* 冷却窗口内立即重试 → RATE（project.md 5.3 指数退避） */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "correct", 7, 0), VERTHYS_ERR_RATE);

    /* 等待 2.1 秒让冷却窗口过期 */
    test_sleep_ms(2100);

    /* 正确密码可解锁 */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "correct", 7, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &r), VERTHYS_OK);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 暴力破解指数退避：连续失败后等待时间指数增长（project.md 5.3） */
TEST(api_rate_limit_exponential)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 创建 verthys */
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "correct", 7, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 第 1 次错误 → AUTH，冷却 2^1=2s */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "wrong1", 6, 0), VERTHYS_ERR_AUTH);

    /* 冷却内立即重试（即使是错误密码）→ RATE */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "wrong2", 6, 0), VERTHYS_ERR_RATE);

    /* 等待 2.1s 让 2^1 冷却过期 */
    test_sleep_ms(2100);

    /* 第 2 次错误 → AUTH，冷却 2^2=4s */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "wrong2", 6, 0), VERTHYS_ERR_AUTH);

    /* 冷却内立即重试 → RATE */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "correct", 7, 0), VERTHYS_ERR_RATE);

    /* 等待 4.1s 让 2^2 冷却过期 */
    test_sleep_ms(4100);

    /* 正确密码可解锁（成功重置退避计数） */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "correct", 7, 0), VERTHYS_OK);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 未解锁时操作 → LOCKED */
TEST(api_operations_require_unlock)
{
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"y", 1};
    uint64_t id;
    VerthysRecord out;

    /* UNINIT 状态 */
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_ERR_LOCKED);
    CHECK_EQ(Verthys_GetRecord(h, 1, &out), VERTHYS_ERR_LOCKED);
    CHECK_EQ(Verthys_DeleteRecord(h, 1), VERTHYS_ERR_LOCKED);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_ERR_LOCKED);

    Verthys_Deinit(h);
    return 0;
}

/* 锁定后操作 → LOCKED */
TEST(api_locked_after_lock)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"y", 1};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_ERR_LOCKED);
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_ERR_LOCKED);
    CHECK_EQ(Verthys_DeleteRecord(h, id), VERTHYS_ERR_LOCKED);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 参数校验 → INVALID */
TEST(api_invalid_params)
{
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(NULL), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_Deinit(NULL), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"y", 1};
    uint64_t id;

    CHECK_EQ(Verthys_Unlock(NULL, TMP_VERTHYS, "pw", 2, 0), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_Unlock(h, NULL, "pw", 2, 0), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, NULL, 5, 0), VERTHYS_ERR_INVALID);

    CHECK_EQ(Verthys_AddRecord(h, NULL, &id), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_AddRecord(h, &r, NULL), VERTHYS_ERR_INVALID);

    /* Unlock 后才能测 AddRecord 的参数校验 */
    cleanup_tmp();
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, NULL, &id), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_AddRecord(h, &r, NULL), VERTHYS_ERR_INVALID);

    /* NULL name 或 data（非零长度时） */
    VerthysRecord bad = {VERTHYS_RECORD_ACCOUNT, NULL, 5, (const uint8_t *)"y", 1};
    CHECK_EQ(Verthys_AddRecord(h, &bad, &id), VERTHYS_ERR_INVALID);
    bad.name = "x"; bad.name_len = 1; bad.data = NULL; bad.data_len = 5;
    CHECK_EQ(Verthys_AddRecord(h, &bad, &id), VERTHYS_ERR_INVALID);

    /* GetRecord NULL */
    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, 1, NULL), VERTHYS_ERR_INVALID);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 增删增循环：ID 不复用，表内容正确 */
TEST(api_add_delete_add_cycle)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "a", 1, (const uint8_t *)"1", 1};
    VerthysRecord r2 = {VERTHYS_RECORD_ACCOUNT, "b", 1, (const uint8_t *)"2", 1};
    VerthysRecord r3 = {VERTHYS_RECORD_ACCOUNT, "c", 1, (const uint8_t *)"3", 1};
    uint64_t id1, id2, id3;

    CHECK_EQ(Verthys_AddRecord(h, &r1, &id1), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &r2, &id2), VERTHYS_OK);
    CHECK_EQ(Verthys_DeleteRecord(h, id1), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &r3, &id3), VERTHYS_OK);

    /* id3 不应等于 id1（ID 不复用） */
    CHECK(id3 != id1);
    CHECK(id3 > id2);

    /* id2 和 id3 仍可查 */
    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id2, &out), VERTHYS_OK);
    CHECK(memcmp(out.name, "b", 1) == 0);
    CHECK_EQ(Verthys_GetRecord(h, id3, &out), VERTHYS_OK);
    CHECK(memcmp(out.name, "c", 1) == 0);

    /* id1 已删 */
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_ERR_NOTFOUND);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 空密码应允许（不报错） */
TEST(api_empty_password)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    /* 空密码 + 0 长度 */
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "", 0, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"y", 1};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 重新解锁 */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "", 0, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &r), VERTHYS_OK);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 锁定后重新解锁同一文件，dirty 状态正确 */
TEST(api_lock_unlock_same_file)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    /* 锁定空 verthys（应能写入空文件） */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "pw", 2, 0), VERTHYS_OK);

    /* 添加记录后锁定再解锁 */
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "rec", 3, (const uint8_t *)"data", 4};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "pw", 2, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &r), VERTHYS_OK);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* ===== Verthys_CreateWithPreset 测试 ===== */

#define TMP_VERTHYS_CP "test_verthys_cp_tmp.verthys"

static void cleanup_cp(void) { remove(TMP_VERTHYS_CP); }

/* CreateWithPreset + BALANCED：创建 → 增 → 锁 → 解锁 → 查（验证预设往返） */
TEST(api_create_with_preset_balanced)
{
    cleanup_cp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 文件不存在 → 创建新 verthys（BALANCED 预设） */
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS_CP, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    /* 白盒校验：preset 字段正确（★ V3：新建一律 V3，Playbook WP-5） */
    struct VerthysContext *ctx = (struct VerthysContext *)h;
    CHECK_EQ(ctx->preset, VERTHYS_PRESET_BALANCED);
    CHECK_EQ(ctx->warm_cache_enabled, 1);  /* BALANCED 启用温启动缓存 */
    CHECK_EQ(ctx->fmt_version, VERTHYS_FMT_V3);

    /* 增记录 */
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "test", 4, (const uint8_t *)"data", 4};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    /* 锁定 → 重新解锁 → 验证预设持久化 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS_CP, "pw", 2, 0), VERTHYS_OK);

    /* 白盒校验：解锁后预设从扩展 TLV 恢复（V3） */
    CHECK_EQ(ctx->preset, VERTHYS_PRESET_BALANCED);
    CHECK_EQ(ctx->warm_cache_enabled, 1);

    /* 记录持久化 */
    CHECK_EQ(Verthys_GetRecord(h, id, &r), VERTHYS_OK);
    CHECK(memcmp(r.name, "test", 4) == 0);

    Verthys_Deinit(h);
    cleanup_cp();
    return 0;
}

/* CreateWithPreset + SECURE：创建 → 增 → 锁 → 解锁 → 查（验证 SECURE 预设往返） */
TEST(api_create_with_preset_secure)
{
    cleanup_cp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 创建新 verthys（SECURE 预设） */
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS_CP, "pw", 2, VERTHYS_PRESET_SECURE), VERTHYS_OK);

    /* 白盒校验：preset 字段正确（★ V3：新建一律 V3，Playbook WP-5） */
    struct VerthysContext *ctx = (struct VerthysContext *)h;
    CHECK_EQ(ctx->preset, VERTHYS_PRESET_SECURE);
    CHECK_EQ(ctx->warm_cache_enabled, 0);  /* SECURE 禁用温启动缓存 */
    CHECK_EQ(ctx->fmt_version, VERTHYS_FMT_V3);

    /* 增记录 */
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "secret", 6, (const uint8_t *)"classified", 10};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    /* 锁定 → 重新解锁 → 验证 SECURE 预设持久化 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS_CP, "pw", 2, 0), VERTHYS_OK);

    /* 白盒校验：解锁后预设从扩展 TLV 恢复为 SECURE（V3） */
    CHECK_EQ(ctx->preset, VERTHYS_PRESET_SECURE);
    CHECK_EQ(ctx->warm_cache_enabled, 0);  /* SECURE 持久禁用温启动缓存 */

    /* 记录持久化 */
    CHECK_EQ(Verthys_GetRecord(h, id, &r), VERTHYS_OK);
    CHECK(memcmp(r.name, "secret", 6) == 0);
    CHECK_EQ(r.data_len, 10u);
    CHECK(memcmp(r.data, "classified", 10) == 0);

    Verthys_Deinit(h);
    cleanup_cp();
    return 0;
}

/* CreateWithPreset 在已存在文件上 → EXISTS */
TEST(api_create_with_preset_exists)
{
    cleanup_cp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 第一次创建成功 */
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS_CP, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 文件已存在 → EXISTS */
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS_CP, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_ERR_EXISTS);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS_CP, "pw", 2, VERTHYS_PRESET_SECURE), VERTHYS_ERR_EXISTS);

    Verthys_Deinit(h);
    cleanup_cp();
    return 0;
}

/* CreateWithPreset 参数校验 → INVALID */
TEST(api_create_with_preset_invalid)
{
    cleanup_cp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* NULL 句柄 */
    CHECK_EQ(Verthys_CreateWithPreset(NULL, TMP_VERTHYS_CP, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_ERR_INVALID);
    /* NULL 路径 */
    CHECK_EQ(Verthys_CreateWithPreset(h, NULL, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_ERR_INVALID);
    /* 非法预设值（99, 0xFFFFFFFF）——★ V3：PERFORMANCE(2) 已为合法三档
     * 之一（API 层校验 BALANCED/SECURE/PERFORMANCE），不再属非法域 */
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS_CP, "pw", 2, (VerthysPreset)99), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS_CP, "pw", 2, (VerthysPreset)0xFFFFFFFF), VERTHYS_ERR_INVALID);

    Verthys_Deinit(h);
    cleanup_cp();
    return 0;
}

/* CreateWithPreset 后修改密码 → 预设不变 */
TEST(api_create_with_preset_survives_cp)
{
    cleanup_cp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 创建 SECURE verthys */
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS_CP, "old", 3, VERTHYS_PRESET_SECURE), VERTHYS_OK);
    struct VerthysContext *ctx = (struct VerthysContext *)h;
    CHECK_EQ(ctx->preset, VERTHYS_PRESET_SECURE);

    /* 修改密码 */
    CHECK_EQ(Verthys_ChangePassword(h, "old", 3, "new", 3), VERTHYS_OK);

    /* 锁定 → 用新密码解锁 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS_CP, "new", 3, 0), VERTHYS_OK);

    /* 预设仍为 SECURE（密码更改不影响预设） */
    CHECK_EQ(ctx->preset, VERTHYS_PRESET_SECURE);
    CHECK_EQ(ctx->warm_cache_enabled, 0);

    Verthys_Deinit(h);
    cleanup_cp();
    return 0;
}
