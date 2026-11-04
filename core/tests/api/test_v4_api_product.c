/*
 * test_v4_api_product.c — v4 产品链端到端（公共 API）
 *
 * 覆盖：创建（返回恢复码）→ 记录写入 → 模块启用 → 保存/锁定/口令解锁 →
 * 模块解锁后读取 → 导出 → 新库导入 → 恢复码解锁。全部走公共 C API，
 * 不直接调用内部仓库/密钥管理器。
 */
#include "verthys_test.h"
#include "verthys.h"

#include <stdio.h>
#include <string.h>

#define E2E_PATH_A "v4_product_a.vty"
#define E2E_PATH_B "v4_product_b.vty"
#define E2E_EXPORT "v4_product_export.bin"
#define E2E_PW     "v4-product-pw"
#define E2E_MOD_PW "v4-product-mod-pw"

static VerthysResult e2e_add(VerthysHandle h, VerthysRecordType type,
                             const char *name, const char *data)
{
    VerthysRecord r;
    uint64_t id = 0;

    memset(&r, 0, sizeof(r));
    r.type = type;
    r.name = name;
    r.name_len = strlen(name);
    r.data = (const uint8_t *)data;
    r.data_len = strlen(data);
    return Verthys_AddRecord(h, &r, &id);
}

TEST(v4_api_product_e2e)
{
    VerthysHandle a = NULL;
    VerthysHandle b = NULL;
    char code[80];
    uint64_t count_before = 0, count_after = 0;
    uint8_t found = 0;

    remove(E2E_PATH_A);
    remove(E2E_PATH_B);
    remove(E2E_EXPORT);

    CHECK_EQ(Verthys_Init(&a), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(a, E2E_PATH_A, E2E_PW, strlen(E2E_PW),
                              code, sizeof(code)), VERTHYS_OK);
    CHECK(strlen(code) > 20);
    CHECK_EQ(e2e_add(a, VERTHYS_RECORD_ACCOUNT, "acct", "account-data"),
             VERTHYS_OK);
    CHECK_EQ(e2e_add(a, VERTHYS_RECORD_PHOTO, "photo", "photo-data"),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleEnable(a, VERTHYS_MODULE_PHOTO,
                                    E2E_MOD_PW, strlen(E2E_MOD_PW), NULL),
             VERTHYS_OK);
    CHECK_EQ(Verthys_Flush(a), VERTHYS_OK);

    CHECK_EQ(Verthys_Lock(a), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(a, E2E_PATH_A, E2E_PW, strlen(E2E_PW)),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleUnlock(a, VERTHYS_MODULE_PHOTO,
                                    E2E_MOD_PW, strlen(E2E_MOD_PW)),
             VERTHYS_OK);
    CHECK_EQ(Verthys_GetSummaryCount(a, &count_before), VERTHYS_OK);
    CHECK_EQ(count_before, 2u);

    CHECK_EQ(Verthys_Export(a, E2E_EXPORT, "export-pw", 9), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(a), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(a), VERTHYS_OK);

    CHECK_EQ(Verthys_Init(&b), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(b, E2E_PATH_B, "other-pw", 8,
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_Import(b, E2E_EXPORT, "export-pw", 9), VERTHYS_OK);
    CHECK_EQ(Verthys_GetSummaryCount(b, &count_after), VERTHYS_OK);
    CHECK_EQ(count_after, 2u);
    CHECK_EQ(Verthys_HasRecordByType(b, VERTHYS_RECORD_ACCOUNT, &found),
             VERTHYS_OK);
    CHECK_EQ(found, 1u);

    /* 恢复码解锁路径也必须在同一产品链上可用 */
    CHECK_EQ(Verthys_Lock(b), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(b, E2E_PATH_B, code), VERTHYS_OK);
    CHECK_EQ(Verthys_GetSummaryCount(b, &count_after), VERTHYS_OK);
    CHECK_EQ(count_after, 2u);

    CHECK_EQ(Verthys_Lock(b), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(b), VERTHYS_OK);

    remove(E2E_PATH_A);
    remove(E2E_PATH_B);
    remove(E2E_EXPORT);
    return 0;
}
