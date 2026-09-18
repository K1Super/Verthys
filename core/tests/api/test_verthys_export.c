/*
 * test_verthys_export.c — Export/Import/ChangePassword 行为测试（TDD 垂直切片）
 *
 * 验证：
 *   - ChangePassword：旧密码校验、新密码可解锁、旧密码失效、记录保留
 *   - Export：生成独立 .verthys 文件，使用独立密码（无胡椒派生）
 *   - Import：合并记录到当前加密库，错误密码/坏文件拒绝
 *   - 参数校验与状态机
 *
 * 注意：含 Argon2id 64MiB/3iter，每次约 0.5–1s。
 */
#include "verthys_test.h"
#include "verthys.h"
#include <string.h>

#define TMP_VERTHYS  "test_verthys_tmp.verthys"
#define TMP_VERTHYS2 "test_verthys2_tmp.verthys"
#define TMP_EXPORT "test_export_tmp.verthys"

static void cleanup_all(void) {
    remove(TMP_VERTHYS);
    remove(TMP_VERTHYS2);
    remove(TMP_EXPORT);
}

/* =================== ChangePassword =================== */

/* 改密码后新密码可解锁，旧密码失效 */
TEST(cp_then_unlock_new)
{
    cleanup_all();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "oldpw", 5, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "rec", 3, (const uint8_t *)"data", 4};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    CHECK_EQ(Verthys_ChangePassword(h, "oldpw", 5, "newpw", 5), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 新密码可解锁 */
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "newpw", 5, 0), VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &r), VERTHYS_OK);

    /* 旧密码失效 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "oldpw", 5, 0), VERTHYS_ERR_AUTH);

    Verthys_Deinit(h);
    cleanup_all();
    return 0;
}

/* 旧密码错误 → AUTH */
TEST(cp_wrong_old)
{
    cleanup_all();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "correct", 7, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    CHECK_EQ(Verthys_ChangePassword(h, "WRONG", 5, "new", 3), VERTHYS_ERR_AUTH);

    /* 原密码仍可用 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "correct", 7, 0), VERTHYS_OK);

    Verthys_Deinit(h);
    cleanup_all();
    return 0;
}

/* 改密码后记录完整保留 */
TEST(cp_preserves_records)
{
    cleanup_all();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "a1", 2, (const uint8_t *)"d1", 2};
    VerthysRecord r2 = {VERTHYS_RECORD_PHOTO, "p1", 2, (const uint8_t *)"d2", 2};
    uint64_t id1, id2;
    CHECK_EQ(Verthys_AddRecord(h, &r1, &id1), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &r2, &id2), VERTHYS_OK);

    CHECK_EQ(Verthys_ChangePassword(h, "pw", 2, "newpw", 5), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, TMP_VERTHYS, "newpw", 5, 0), VERTHYS_OK);

    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, id1, &out), VERTHYS_OK);
    CHECK_EQ(out.type, VERTHYS_RECORD_ACCOUNT);
    CHECK(memcmp(out.name, "a1", 2) == 0);
    CHECK(memcmp(out.data, "d1", 2) == 0);

    CHECK_EQ(Verthys_GetRecord(h, id2, &out), VERTHYS_OK);
    CHECK_EQ(out.type, VERTHYS_RECORD_PHOTO);
    CHECK(memcmp(out.name, "p1", 2) == 0);

    Verthys_Deinit(h);
    cleanup_all();
    return 0;
}

/* 参数校验 → INVALID */
TEST(cp_invalid_params)
{
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    CHECK_EQ(Verthys_ChangePassword(NULL, "a", 1, "b", 1), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_ChangePassword(h, NULL, 5, "b", 1), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_ChangePassword(h, "a", 1, NULL, 5), VERTHYS_ERR_INVALID);

    Verthys_Deinit(h);
    return 0;
}

/* 未解锁时改密码 → LOCKED */
TEST(cp_requires_unlock)
{
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_ChangePassword(h, "a", 1, "b", 1), VERTHYS_ERR_LOCKED);
    Verthys_Deinit(h);
    return 0;
}

/* =================== Export =================== */

/* 导出后导入往返：记录完整 */
TEST(export_import_roundtrip)
{
    cleanup_all();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "gmail", 5, (const uint8_t *)"pass123", 7};
    VerthysRecord r2 = {VERTHYS_RECORD_PHOTO, "pic", 3, (const uint8_t *)"\x89PNG\x00", 5};
    uint64_t id1, id2;
    CHECK_EQ(Verthys_AddRecord(h, &r1, &id1), VERTHYS_OK);
    CHECK_EQ(Verthys_AddRecord(h, &r2, &id2), VERTHYS_OK);

    /* 导出（独立密码，无胡椒） */
    CHECK_EQ(Verthys_Export(h, TMP_EXPORT, "epw", 3), VERTHYS_OK);
    Verthys_Deinit(h);

    /* 导入到新 verthys */
    VerthysHandle h2;
    CHECK_EQ(Verthys_Init(&h2), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h2, TMP_VERTHYS2, "pw2", 3, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    CHECK_EQ(Verthys_Import(h2, TMP_EXPORT, "epw", 3), VERTHYS_OK);

    /* 验证导入的记录（ID 从 1 开始重新分配） */
    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h2, 1, &out), VERTHYS_OK);
    CHECK_EQ(out.type, VERTHYS_RECORD_ACCOUNT);
    CHECK_EQ(out.name_len, 5u);
    CHECK(memcmp(out.name, "gmail", 5) == 0);
    CHECK_EQ(out.data_len, 7u);
    CHECK(memcmp(out.data, "pass123", 7) == 0);

    CHECK_EQ(Verthys_GetRecord(h2, 2, &out), VERTHYS_OK);
    CHECK_EQ(out.type, VERTHYS_RECORD_PHOTO);
    CHECK_EQ(out.name_len, 3u);
    CHECK(memcmp(out.name, "pic", 3) == 0);
    CHECK_EQ(out.data_len, 5u);
    CHECK(memcmp(out.data, "\x89PNG\x00", 5) == 0);

    Verthys_Deinit(h2);
    cleanup_all();
    return 0;
}

/* 导出使用与主密码不同的密码 */
TEST(export_separate_password)
{
    cleanup_all();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "mainpw", 6, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"y", 1};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);

    /* 导出密码与主密码不同 */
    CHECK_EQ(Verthys_Export(h, TMP_EXPORT, "exportpw", 8), VERTHYS_OK);
    Verthys_Deinit(h);

    /* 用导出密码导入 */
    VerthysHandle h2;
    CHECK_EQ(Verthys_Init(&h2), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h2, TMP_VERTHYS2, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    CHECK_EQ(Verthys_Import(h2, TMP_EXPORT, "exportpw", 8), VERTHYS_OK);

    /* 错误的导出密码导入失败 */
    CHECK_EQ(Verthys_Import(h2, TMP_EXPORT, "WRONG", 5), VERTHYS_ERR_AUTH);

    Verthys_Deinit(h2);
    cleanup_all();
    return 0;
}

/* 导出参数校验 → INVALID */
TEST(export_invalid_params)
{
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    CHECK_EQ(Verthys_Export(NULL, TMP_EXPORT, "pw", 2), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_Export(h, NULL, "pw", 2), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_Export(h, TMP_EXPORT, NULL, 5), VERTHYS_ERR_INVALID);

    Verthys_Deinit(h);
    return 0;
}

/* 未解锁时导出 → LOCKED */
TEST(export_requires_unlock)
{
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Export(h, TMP_EXPORT, "pw", 2), VERTHYS_ERR_LOCKED);
    Verthys_Deinit(h);
    return 0;
}

/* =================== Import =================== */

/* 导入合并到已有记录的 verthys */
TEST(import_merges_records)
{
    cleanup_all();
    VerthysHandle h1;
    CHECK_EQ(Verthys_Init(&h1), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h1, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    VerthysRecord r1 = {VERTHYS_RECORD_ACCOUNT, "src", 3, (const uint8_t *)"d1", 2};
    uint64_t id1;
    CHECK_EQ(Verthys_AddRecord(h1, &r1, &id1), VERTHYS_OK);
    CHECK_EQ(Verthys_Export(h1, TMP_EXPORT, "epw", 3), VERTHYS_OK);
    Verthys_Deinit(h1);

    VerthysHandle h2;
    CHECK_EQ(Verthys_Init(&h2), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h2, TMP_VERTHYS2, "pw2", 3, VERTHYS_PRESET_BALANCED), VERTHYS_OK);

    /* 目标 verthys 先有 1 条记录 */
    VerthysRecord r2 = {VERTHYS_RECORD_ACCOUNT, "dst", 3, (const uint8_t *)"d2", 2};
    uint64_t id2;
    CHECK_EQ(Verthys_AddRecord(h2, &r2, &id2), VERTHYS_OK);
    CHECK_EQ(id2, 1u);

    /* 导入 1 条 */
    CHECK_EQ(Verthys_Import(h2, TMP_EXPORT, "epw", 3), VERTHYS_OK);

    /* 原 1 条 + 导入 1 条 = 2 条 */
    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h2, 1, &out), VERTHYS_OK);  /* 原有 */
    CHECK(memcmp(out.name, "dst", 3) == 0);
    CHECK_EQ(Verthys_GetRecord(h2, 2, &out), VERTHYS_OK);  /* 导入 */
    CHECK(memcmp(out.name, "src", 3) == 0);

    Verthys_Deinit(h2);
    cleanup_all();
    return 0;
}

/* 导入错误密码 → AUTH */
TEST(import_wrong_password)
{
    cleanup_all();
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "x", 1, (const uint8_t *)"y", 1};
    uint64_t id;
    CHECK_EQ(Verthys_AddRecord(h, &r, &id), VERTHYS_OK);
    CHECK_EQ(Verthys_Export(h, TMP_EXPORT, "correct", 7), VERTHYS_OK);

    /* 错误密码导入 */
    CHECK_EQ(Verthys_Import(h, TMP_EXPORT, "WRONG", 5), VERTHYS_ERR_AUTH);

    Verthys_Deinit(h);
    cleanup_all();
    return 0;
}

/* 导入非 .verthys 文件 → FORMAT */
TEST(import_bad_file)
{
    cleanup_all();
    /* 写入垃圾数据 */
    FILE *f = fopen(TMP_EXPORT, "wb");
    CHECK(f != NULL);
    const char *garbage = "NOT A VERTHYS FILE";
    fwrite(garbage, 1, strlen(garbage), f);
    fclose(f);

    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_CreateWithPreset(h, TMP_VERTHYS, "pw", 2, VERTHYS_PRESET_BALANCED), VERTHYS_OK);
    CHECK_EQ(Verthys_Import(h, TMP_EXPORT, "pw", 2), VERTHYS_ERR_FORMAT);

    Verthys_Deinit(h);
    cleanup_all();
    return 0;
}

/* 导入参数校验 → INVALID */
TEST(import_invalid_params)
{
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    CHECK_EQ(Verthys_Import(NULL, TMP_EXPORT, "pw", 2), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_Import(h, NULL, "pw", 2), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_Import(h, TMP_EXPORT, NULL, 5), VERTHYS_ERR_INVALID);

    Verthys_Deinit(h);
    return 0;
}

/* 未解锁时导入 → LOCKED */
TEST(import_requires_unlock)
{
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Import(h, TMP_EXPORT, "pw", 2), VERTHYS_ERR_LOCKED);
    Verthys_Deinit(h);
    return 0;
}
