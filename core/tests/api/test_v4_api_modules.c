/*
 * test_v4_api_modules.c — v4 模块 M1 公共 API 验收
 *
 * 覆盖：启用/状态/解锁/锁定/口令轮换/绑定恢复码/禁用、策略错误码、
 * 恢复码轮换与恢复解锁。验证对外错误类别与“模块锁定只影响本模块”。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "vty_v4_types.h"
#include "vty_recovery.h"
#include "vty_lockout.h"

#include <stdio.h>
#include <string.h>

#define V4_MOD_PATH "v4_api_modules.vty"
#define V4_MOD_PW   "v4-mod-pw"
#define V4_MOD_PW2  "v4-mod-pw-2"

static VerthysResult mod_add(VerthysHandle h, uint8_t type,
                             const char *name, const char *data, uint64_t *id)
{
    VerthysRecord r;

    memset(&r, 0, sizeof(r));
    r.type = (VerthysRecordType)type;
    r.name = name;
    r.name_len = strlen(name);
    r.data = (const uint8_t *)data;
    r.data_len = strlen(data);
    return Verthys_AddRecord(h, &r, id);
}

static int mod_record_equals(VerthysHandle h, uint64_t id, const char *data)
{
    VerthysRecord rec;

    memset(&rec, 0, sizeof(rec));
    if (Verthys_GetRecord(h, id, &rec) != VERTHYS_OK) return 0;
    return rec.data_len == strlen(data) &&
           memcmp(rec.data, data, rec.data_len) == 0;
}

TEST(v4_api_modules_roundtrip_and_policy)
{
    VerthysHandle h = NULL;
    VerthysModuleStatus st;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint64_t photo_id = 0, acct_id = 0;

    vty_lockout_set_enabled(0);
    remove(V4_MOD_PATH);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, V4_MOD_PATH, V4_MOD_PW, strlen(V4_MOD_PW),
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(mod_add(h, VERTHYS_RECORD_PHOTO, "photo", "p-data", &photo_id),
             VERTHYS_OK);
    CHECK_EQ(mod_add(h, VERTHYS_RECORD_ACCOUNT, "acct", "a-data", &acct_id),
             VERTHYS_OK);

    memset(&st, 0, sizeof(st));
    CHECK_EQ(Verthys_V4ModuleStatus(h, VERTHYS_MODULE_PHOTO, &st), VERTHYS_OK);
    CHECK_EQ(st.enabled, 0u);
    CHECK_EQ(st.unlocked, 0u);
    CHECK_EQ(st.has_recovery, 0u);

    /* 未启用时解锁按策略拒绝 */
    CHECK_EQ(Verthys_V4ModuleUnlock(h, VERTHYS_MODULE_PHOTO,
                                    "mpw", 3), VERTHYS_ERR_POLICY);

    CHECK_EQ(Verthys_V4ModuleEnable(h, VERTHYS_MODULE_PHOTO,
                                    "mpw", 3, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleStatus(h, VERTHYS_MODULE_PHOTO, &st), VERTHYS_OK);
    CHECK_EQ(st.enabled, 1u);
    CHECK_EQ(st.unlocked, 1u);
    CHECK_EQ(st.has_recovery, 0u);
    CHECK(mod_record_equals(h, photo_id, "p-data"));
    CHECK(mod_record_equals(h, acct_id, "a-data"));

    /* 锁定 photo：photo 读取返回 POLICY，account 不受影响 */
    CHECK_EQ(Verthys_V4ModuleLock(h, VERTHYS_MODULE_PHOTO), VERTHYS_OK);
    {
        VerthysRecord tmp;
        memset(&tmp, 0, sizeof(tmp));
        CHECK_EQ(Verthys_GetRecord(h, photo_id, &tmp), VERTHYS_ERR_POLICY);
    }
    CHECK(mod_record_equals(h, acct_id, "a-data"));
    CHECK_EQ(Verthys_V4ModuleUnlock(h, VERTHYS_MODULE_PHOTO,
                                    "wrong", 5), VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_V4ModuleUnlock(h, VERTHYS_MODULE_PHOTO,
                                    "mpw", 3), VERTHYS_OK);
    CHECK(mod_record_equals(h, photo_id, "p-data"));

    /* 口令轮换：旧口令失败、新口令成功；数据不变 */
    CHECK_EQ(Verthys_V4ModuleRotatePassword(h, VERTHYS_MODULE_PHOTO,
                                             "mpw", 3, "mpw2", 4), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleLock(h, VERTHYS_MODULE_PHOTO), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleUnlock(h, VERTHYS_MODULE_PHOTO,
                                    "mpw", 3), VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_V4ModuleUnlock(h, VERTHYS_MODULE_PHOTO,
                                    "mpw2", 4), VERTHYS_OK);
    CHECK(mod_record_equals(h, photo_id, "p-data"));

    /* 绑定恢复码：需要模块口令 + 当前容器恢复码 */
    CHECK_EQ(Verthys_V4ModuleBindRecovery(h, VERTHYS_MODULE_PHOTO,
                                          "mpw2", 4, code), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleStatus(h, VERTHYS_MODULE_PHOTO, &st), VERTHYS_OK);
    CHECK_EQ(st.has_recovery, 1u);

    /* 禁用：MDEK 回到 Keyring，读取不再要求模块解锁 */
    CHECK_EQ(Verthys_V4ModuleDisable(h, VERTHYS_MODULE_PHOTO,
                                     "mpw2", 4), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleStatus(h, VERTHYS_MODULE_PHOTO, &st), VERTHYS_OK);
    CHECK_EQ(st.enabled, 0u);
    CHECK_EQ(st.unlocked, 0u);
    CHECK(mod_record_equals(h, photo_id, "p-data"));

    /* 非法模块索引 */
    CHECK_EQ(Verthys_V4ModuleStatus(h, 3, &st), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_V4ModuleUnlock(h, 3, "x", 1), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_V4ModuleLock(h, VERTHYS_MODULE_ALL), VERTHYS_OK);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(V4_MOD_PATH);
    return 0;
}

TEST(v4_api_module_delete)
{
    VerthysHandle h = NULL;
    VerthysModuleStatus st;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint64_t photo_id = 0, acct_id = 0;
    VerthysRecord tmp;

    vty_lockout_set_enabled(0);
    remove(V4_MOD_PATH);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, V4_MOD_PATH, V4_MOD_PW, strlen(V4_MOD_PW),
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(mod_add(h, VERTHYS_RECORD_PHOTO, "photo", "p-data", &photo_id),
             VERTHYS_OK);
    CHECK_EQ(mod_add(h, VERTHYS_RECORD_ACCOUNT, "acct", "a-data", &acct_id),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleEnable(h, VERTHYS_MODULE_PHOTO,
                                    "mpw", 3, NULL), VERTHYS_OK);

    CHECK_EQ(Verthys_V4ModuleDelete(h, VERTHYS_MODULE_PHOTO,
                                     V4_MOD_PW, strlen(V4_MOD_PW), "delete"),
             VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_V4ModuleDelete(h, VERTHYS_MODULE_PHOTO,
                                     "wrong", 5, "DELETE"), VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_V4ModuleDelete(h, VERTHYS_MODULE_PHOTO,
                                     V4_MOD_PW, strlen(V4_MOD_PW), "DELETE"),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleStatus(h, VERTHYS_MODULE_PHOTO, &st), VERTHYS_OK);
    CHECK_EQ(st.deleted, 1u);
    CHECK_EQ(st.enabled, 0u);

    memset(&tmp, 0, sizeof(tmp));
    CHECK_EQ(Verthys_GetRecord(h, photo_id, &tmp), VERTHYS_ERR_NOTFOUND);
    CHECK(mod_record_equals(h, acct_id, "a-data"));
    CHECK_EQ(mod_add(h, VERTHYS_RECORD_PHOTO, "new", "n-data", &photo_id),
             VERTHYS_ERR_POLICY);

    /* 重建空模块后旧记录仍不可读，新记录可写 */
    CHECK_EQ(Verthys_V4ModuleEnable(h, VERTHYS_MODULE_PHOTO,
                                    "mpw", 3, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleStatus(h, VERTHYS_MODULE_PHOTO, &st), VERTHYS_OK);
    CHECK_EQ(st.deleted, 0u);
    CHECK_EQ(Verthys_GetRecord(h, photo_id, &tmp), VERTHYS_ERR_NOTFOUND);
    CHECK_EQ(mod_add(h, VERTHYS_RECORD_PHOTO, "new", "n-data", &photo_id),
             VERTHYS_OK);
    CHECK(mod_record_equals(h, photo_id, "n-data"));

    /* 恢复会话：已由恢复码根认证，可免口令删除 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, V4_MOD_PATH, code), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleDelete(h, VERTHYS_MODULE_PHOTO,
                                     NULL, 0, "DELETE"), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleStatus(h, VERTHYS_MODULE_PHOTO, &st), VERTHYS_OK);
    CHECK_EQ(st.deleted, 1u);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(V4_MOD_PATH);
    return 0;
}

TEST(v4_api_recovery_rotate)
{
    VerthysHandle h = NULL;
    VerthysModuleStatus st;
    char code[VTY_RECOVERY_TEXT_BUF];
    char new_code[VTY_RECOVERY_TEXT_BUF];
    uint64_t photo_id = 0;

    vty_lockout_set_enabled(0);
    remove(V4_MOD_PATH);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, V4_MOD_PATH, V4_MOD_PW, strlen(V4_MOD_PW),
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(mod_add(h, VERTHYS_RECORD_PHOTO, "photo", "p-data", &photo_id),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleEnable(h, VERTHYS_MODULE_PHOTO,
                                    "mpw", 3, code), VERTHYS_OK);

    /* 恢复码轮换：错误口令拒绝；成功后旧码失效、新码可用 */
    memset(new_code, 0, sizeof(new_code));
    CHECK_EQ(Verthys_V4RecoveryRotate(h, "wrong", 5, code,
                                      new_code, sizeof(new_code)),
             VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_V4RecoveryRotate(h, V4_MOD_PW, strlen(V4_MOD_PW), code,
                                      new_code, sizeof(new_code)), VERTHYS_OK);
    CHECK(new_code[0] != '\0');
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    CHECK(vty_lockout_enabled() == 0);
    CHECK(Verthys_V4UnlockRecovery(h, V4_MOD_PATH, code) != VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, V4_MOD_PATH, new_code), VERTHYS_OK);
    CHECK_EQ(Verthys_V4ModuleUnlock(h, VERTHYS_MODULE_PHOTO,
                                    "mpw", 3), VERTHYS_OK);
    CHECK(mod_record_equals(h, photo_id, "p-data"));
    CHECK_EQ(Verthys_V4ModuleStatus(h, VERTHYS_MODULE_PHOTO, &st), VERTHYS_OK);
    CHECK_EQ(st.has_recovery, 1u);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(V4_MOD_PATH);
    return 0;
}
