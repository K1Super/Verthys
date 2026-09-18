/*
 * test_memory_safety.c — 内存安全测试（Phase 1.11）
 *
 * 验证 project.md 6 内存安全环节（§1.4 V2 退役后 V3 语义）：
 *   - Lock 后密钥不可达（CNG 内核句柄全部销毁 + VerthysContextV3 归零）
 *   - Lock 后记录明文释放（LSM/Extent 上下文随 v3 实例销毁）
 *   - Lock 后 file_path 保留（供重新解锁）
 *   - 失败的 Unlock 不污染上下文（状态不变、无密钥残留）
 *   - Deinit 从各状态安全退出
 *
 * ★ P0 缺陷1企业级方案 — UAF 回归测试（查询→修改→旧指针失效）
 *   - GetRecord 填充借用缓存（last_getrecord_data != NULL，out.data 借用之）
 *   - 全部 6 个写操作（Add/Delete/DeleteRecords/Import/ChangePassword/Flush）
 *     调用后缓存立即失效（last_getrecord_data == NULL），消除 UAF 窗口
 *     （原第 7 项 RebuildMerkle 随 §1.4 V2 退役删除）
 *   - 二次 GetRecord 返回全新借用指针（单次有效原则）
 *
 * 通过 verthys_internal.h 直接检查 VerthysContext 内部字段。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "verthys_v3_lifecycle.h"    /* VerthysContextV3（fmt_version==V3 白盒） */
#include "verthys_lsm.h"             /* verthys_lsm_estimate_records（V3 记账） */
#include <string.h>

#ifdef _WIN32
#include <windows.h>  /* Sleep */
#endif

#define TMP_VERTHYS "test_mem_tmp.verthys"
#define TMP_EXPORT "test_mem_export.verthys"

static void cleanup_tmp(void) { remove(TMP_VERTHYS); remove(TMP_EXPORT); }

/* 跨平台睡眠（毫秒） */
static void mem_sleep_ms(unsigned ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

/* Lock 后密钥不可达（CNG 内核句柄销毁 + V3 上下文归零） */
TEST(mem_lock_zeroes_keys)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"y", 1};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    /* Lock 前 sanity（★ V3：密钥全程 CNG 内核态驻留，用户态零密钥数组——
     * KERNEL_RESIDENT 红线的白盒判据 = 四角色句柄全部在位 + 状态机
     * 处于 KERNEL_RESIDENT） */
    struct VerthysContext *ctx = (struct VerthysContext *)h;
    CHECK_EQ(ctx->fmt_version, VERTHYS_FMT_V3);
    CHECK_EQ(verthys_cng_km_state(&ctx->cng_keys), VERTHYS_CNG_KM_KERNEL_RESIDENT);
    CHECK_EQ(verthys_cng_km_handle_count(&ctx->cng_keys), 4);
    CHECK(verthys_cng_km_any_installed(&ctx->cng_keys) == 1);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* Lock 后密钥不可达：BCryptDestroyKey 全组销毁（内核态材料不可恢复，
     * 状态机 DESTROYED / 句柄计数 0）+ VerthysContextV3 整体归零 */
    CHECK_EQ(verthys_cng_km_state(&ctx->cng_keys), VERTHYS_CNG_KM_DESTROYED);
    CHECK_EQ(verthys_cng_km_handle_count(&ctx->cng_keys), 0);
    CHECK(verthys_cng_km_any_installed(&ctx->cng_keys) == 0);
    CHECK(ctx->v3 == NULL);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* Lock 后记录释放（V3：LSM/Extent 随 v3 实例销毁，无内存记录驻留） */
TEST(mem_lock_frees_records)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "a", 1, (const uint8_t *)"1", 1};
    VerthysRecord r2 = {VERTHYS_RECORD_PHOTO, "b", 1, (const uint8_t *)"2", 1};
    uint64_t id1, id2;
    CHECK_EQ(Verthys_AddRecord(h, &r1, &id1), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &r2, &id2), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;
    CHECK_EQ(ctx->fmt_version, VERTHYS_FMT_V3);
    /* v3：记录存储在 LSM 索引（MemTable/SSTable；无内存记录数组） */
    CHECK(ctx->v3 != NULL);
    CHECK(ctx->v3->lsm != NULL);
    CHECK_EQ(verthys_lsm_estimate_records(ctx->v3->lsm), 2ull);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* Lock 后记录释放：Verthys_Lock 销毁整个 VerthysContextV3（verthys_v3_lock
     * 事务收尾 + LSM flush/温缓存写 → ctx_destroy → ctx->v3 = NULL）。
     * 整个 V3 上下文归零是最强内存安全保证——记录明文（MemTable/SSTable
     * 缓冲）与密钥（subsystems_close 清零）随销毁彻底释放，无残留驻留。 */
    CHECK(ctx->v3 == NULL);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* Lock 后 file_path 保留（供重新解锁使用） */
TEST(mem_lock_retains_file_path)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"y", 1};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;
    CHECK(ctx->file_path != NULL);
    CHECK(strcmp(ctx->file_path, TMP_VERTHYS) == 0);
    CHECK_EQ(ctx->state, VERTHYS_STATE_LOCKED);

    /* 重新解锁验证 file_path 仍可用 */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "pw", 2, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &r), VERTHYS_OK);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 失败的 Unlock（错误密码）不污染上下文 */
TEST(mem_failed_unlock_keeps_locked)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "correct", 7, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"y", 1};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 错误密码解锁 → AUTH（触发 2^1=2s 冷却） */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "WRONG", 5, 0), VERTHYS_ERR_AUTH);

    /* 上下文仍为 LOCKED，无密钥残留（V3 判据：v3 实例未建立 +
     * CNG 句柄计数 0——解锁失败路径不得遗留任何内核句柄） */
    struct VerthysContext *ctx = (struct VerthysContext *)h;
    CHECK_EQ(ctx->state, VERTHYS_STATE_LOCKED);
    CHECK(ctx->v3 == NULL);
    CHECK_EQ(verthys_cng_km_handle_count(&ctx->cng_keys), 0);

    /* 冷却窗口内立即重试 → RATE */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "correct", 7, 0), VERTHYS_ERR_RATE);

    /* 等待 2.1s 让冷却过期 */
    mem_sleep_ms(2100);

    /* 正确密码仍可解锁 */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "correct", 7, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &r), VERTHYS_OK);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 失败的 Unlock（格式错误）不污染上下文 */
TEST(mem_failed_unlock_bad_format)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 覆写文件为垃圾数据 */
    FILE *f = fopen(TMP_VERTHYS, "wb");
    CHECK(f != NULL);
    fwrite("GARBAGE", 1, 7, f);
    fclose(f);

    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "pw", 2, 0), VERTHYS_ERR_FORMAT);

    struct VerthysContext *ctx = (struct VerthysContext *)h;
    CHECK_EQ(ctx->state, VERTHYS_STATE_LOCKED);
    CHECK(ctx->v3 == NULL);
    CHECK_EQ(verthys_cng_km_handle_count(&ctx->cng_keys), 0);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* Deinit 从 UNLOCKED 状态安全退出 */
TEST(mem_deinit_from_unlocked)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"y", 1};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    /* 直接 Deinit（不 Lock），应安全清理密钥与记录 */
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);

    cleanup_tmp();
    return 0;
}

/* Deinit 从 LOCKED 状态安全退出 */
TEST(mem_deinit_from_locked)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    cleanup_tmp();
    return 0;
}

/* Deinit 从 UNINIT 状态安全退出 */
TEST(mem_deinit_from_uninit)
{
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    return 0;
}

/* ====================================================================== *
 * ★ P0 缺陷1企业级方案 — UAF 回归测试
 *
 * 验证场景：查询 → 修改 → 旧借用指针失效（防止 Use-After-Free）
 *
 * 原缺陷：查询接口对外暴露内部缓存裸指针，写入操作未失效缓存，GC 回收
 * 旧数据块后外部指针变野指针，引发 UAF。
 *
 * 根治方案：所有写操作入口统一调用 ctx_free_getrecord_cache(ctx)，
 * 写操作提交前强制清空历史查询缓存。
 *
 * 测试策略（白盒）：
 *   1. GetRecord 后 ctx->last_getrecord_data != NULL，out.data 借用之
 *   2. 写操作后 ctx->last_getrecord_data == NULL（缓存已失效）
 *   3. 二次 GetRecord 返回全新借用指针
 * ====================================================================== */

/* GetRecord 填充借用缓存：out.data 指向 ctx->last_getrecord_data */
TEST(mem_uaf_getrecord_populates_borrow_cache)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "acct", 4, (const uint8_t *)"secret", 6};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;

    /* 写操作前缓存应为空（AddRecord 已失效） */
    CHECK(ctx->last_getrecord_data == NULL);

    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);

    /* GetRecord 后缓存填充，out.data 借用缓存指针 */
    CHECK(ctx->last_getrecord_data != NULL);
    CHECK(out.data == ctx->last_getrecord_data);  /* 借用语义 */
    CHECK(out.name == (const char *)ctx->last_getrecord_name);
    CHECK_EQ(out.data_len, 6u);
    CHECK(memcmp(out.data, "secret", 6) == 0);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* AddRecord 失效借用缓存（UAF 防护） */
TEST(mem_uaf_addrecord_invalidates_cache)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "a", 1, (const uint8_t *)"d1", 2};
    uint64_t id1;
    CHECK_EQ(Verthys_AddRecord(h, &r1, &id1), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;

    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);
    const uint8_t *old_ptr = out.data;  /* 模拟上层持有的旧借用指针 */

    /* AddRecord 后缓存立即失效，old_ptr 不再可用 */
    VerthysRecord r2 = {VERTHYS_RECORD_ACCOUNT, "b", 1, (const uint8_t *)"d2", 2};
    uint64_t id2;
    CHECK_EQ(Verthys_AddRecord(h, &r2, &id2), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data == NULL);  /* 缓存已失效，old_ptr 悬空 */

    /* 二次 GetRecord 返回全新借用指针（单次有效原则） */
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);
    CHECK(out.data == ctx->last_getrecord_data);
    /* ★ 断言语义修正：UAF 防护的真实判据是"失效先于复用"——由上方
     * ctx->last_getrecord_data == NULL 断言保证；二次 GetRecord 的地址
     * 是否复用旧块由分配器决定（同尺寸先释放后分配可能返回同一地址），
     * 不构成借用语义的一部分。改为校验新借用指针承载正确数据。 */
    (void)old_ptr;
    CHECK(out.data_len == 2);
    CHECK(out.data[0] == 'd' && out.data[1] == '1');

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* DeleteRecord 失效借用缓存（UAF 防护） */
TEST(mem_uaf_deleterecord_invalidates_cache)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "keep", 4, (const uint8_t *)"d1", 2};
    VerthysRecord r2 = {VERTHYS_RECORD_ACCOUNT, "kill", 4, (const uint8_t *)"d2", 2};
    uint64_t id1, id2;
    CHECK_EQ(Verthys_AddRecord(h, &r1, &id1), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &r2, &id2), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;

    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);

    /* DeleteRecord 后缓存失效（即使删除的是另一条记录） */
    CHECK_EQ(Verthys_DeleteRecord(h, id2), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data == NULL);

    /* id1 仍可查，返回新借用指针 */
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* DeleteRecords 批量删除失效借用缓存（UAF 防护） */
TEST(mem_uaf_deleterecords_invalidates_cache)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "keep", 4, (const uint8_t *)"d1", 2};
    uint64_t id1, id2, id3;
    CHECK_EQ(Verthys_AddRecord(h, &r1, &id1), VERTHYS_OK);
    VerthysRecord r2 = {VERTHYS_RECORD_ACCOUNT, "k2", 2, (const uint8_t *)"d2", 2};
    CHECK_EQ(Verthys_AddRecord(h, &r2, &id2), VERTHYS_OK);
    VerthysRecord r3 = {VERTHYS_RECORD_ACCOUNT, "k3", 2, (const uint8_t *)"d3", 2};
    CHECK_EQ(Verthys_AddRecord(h, &r3, &id3), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;

    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);

    /* 批量删除 id2, id3 后缓存失效 */
    uint64_t ids[2] = {id2, id3};
    CHECK_EQ(Verthys_DeleteRecords(h, ids, 2), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data == NULL);

    /* id1 仍可查 */
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* Flush 显式刷盘失效借用缓存（UAF 防护） */
TEST(mem_uaf_flush_invalidates_cache)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"data", 4};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;

    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);

    /* Flush 后缓存失效 */
    CHECK_EQ(Verthys_Flush(h), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data == NULL);

    /* 二次查询返回新借用指针 */
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* Import 导入失效借用缓存（UAF 防护） */
TEST(mem_uaf_import_invalidates_cache)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "orig", 4, (const uint8_t *)"d1", 2};
    VerthysRecord r2 = {VERTHYS_RECORD_ACCOUNT, "exp", 3, (const uint8_t *)"d2", 2};
    uint64_t id1, id2;
    CHECK_EQ(Verthys_AddRecord(h, &r1, &id1), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &r2, &id2), VERTHYS_OK);

    /* 导出当前容器到独立文件 */
    CHECK_EQ(Verthys_Export(h, TMP_EXPORT, "exppw", 5), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;

    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);

    /* Import 后缓存失效（导入操作触发写事务） */
    CHECK_EQ(Verthys_Import(h, TMP_EXPORT, "exppw", 5), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data == NULL);

    /* 原记录仍可查，返回新借用指针 */
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* ChangePassword 改密失效借用缓存（UAF 防护） */
TEST(mem_uaf_changepassword_invalidates_cache)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "oldpw", 5, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "acct", 4, (const uint8_t *)"secret", 6};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;

    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);

    /* ChangePassword 后缓存失效（改密重新加密超级块 DEK 密文） */
    CHECK_EQ(Verthys_ChangePassword(h, "oldpw", 5, "newpw", 5), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data == NULL);

    /* 改密后记录仍可查，返回新借用指针（KEK+DEK 双层：数据块未重加密） */
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);
    CHECK_EQ(out.data_len, 6u);
    CHECK(memcmp(out.data, "secret", 6) == 0);

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}

/* 二次 GetRecord 覆盖旧借用缓存（单次有效原则） */
TEST(mem_uaf_getrecord_overwrites_previous_borrow)
{
    cleanup_tmp();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "a", 1, (const uint8_t *)"d1", 2};
    VerthysRecord r2 = {VERTHYS_RECORD_ACCOUNT, "b", 1, (const uint8_t *)"d2", 2};
    uint64_t id1, id2;
    CHECK_EQ(Verthys_AddRecord(h, &r1, &id1), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &r2, &id2), VERTHYS_OK);

    struct VerthysContext *ctx = (struct VerthysContext *)h;

    /* 第一次查询 id1 */
    VerthysRecord out1;
    CHECK_EQ(Verthys_GetRecord(h, id1, &out1), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);
    const uint8_t *ptr1 = ctx->last_getrecord_data;

    /* 第二次查询 id2 — 旧借用指针（out1.data）立即失效 */
    VerthysRecord out2;
    CHECK_EQ(Verthys_GetRecord(h, id2, &out2), VERTHYS_OK);
    CHECK(ctx->last_getrecord_data != NULL);
    /* out1.data 现已悬空（缓存被 out2 数据覆盖），仅 out2.data 有效 */
    CHECK(out2.data == ctx->last_getrecord_data);

    /* 同一时刻最多一组借用指针有效（单次有效原则） */
    (void)ptr1;  /* ptr1 已失效，禁止解引用 */

    Verthys_Deinit(h);
    cleanup_tmp();
    return 0;
}
