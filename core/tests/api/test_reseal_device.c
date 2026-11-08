/*
 * test_reseal_device.c — 恢复会话容器 user/device 槽重绑验收
 *
 * 覆盖换机恢复后的日常解锁恢复：恢复码会话重封 user/device 槽后，
 * 新本机口令可普通解锁，旧口令失效；keyfile 启用时缺文件必须拒绝。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "vty_types.h"
#include "vty_recovery.h"

#include <stdio.h>
#include <string.h>

#define RESEAL_PATH "reseal.vty"
#define RESEAL_KF_PATH "reseal_kf.vty"
#define RESEAL_KF_FILE "reseal.key"
#define RESEAL_PW_A "reseal-pass-A"
#define RESEAL_PW_B "reseal-pass-B"

static void reseal_cleanup(void)
{
    remove(RESEAL_PATH);
    remove(RESEAL_KF_PATH);
    remove(RESEAL_KF_FILE);
}

TEST(reseal_device_roundtrip_restores_normal_unlock)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];

    reseal_cleanup();
    memset(code, 0, sizeof(code));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, RESEAL_PATH, RESEAL_PW_A,
                              strlen(RESEAL_PW_A), code, sizeof(code)),
             VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, RESEAL_PATH, code), VERTHYS_OK);

    /* 换机后本机口令为 B：恢复会话重绑容器槽。 */
    CHECK_EQ(Verthys_V4ResealDevice(h, RESEAL_PW_B, strlen(RESEAL_PW_B), NULL),
             VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 新口令普通解锁成功；旧口令必须失效。 */
    CHECK_EQ(Verthys_V4Unlock(h, RESEAL_PATH, RESEAL_PW_B,
                              strlen(RESEAL_PW_B)), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(h, RESEAL_PATH, RESEAL_PW_A,
                              strlen(RESEAL_PW_A)), VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    reseal_cleanup();
    return 0;
}

TEST(reseal_device_rejects_normal_session)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];

    reseal_cleanup();
    memset(code, 0, sizeof(code));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, RESEAL_PATH, RESEAL_PW_A,
                              strlen(RESEAL_PW_A), code, sizeof(code)),
             VERTHYS_OK);
    /* V4Create 返回后会话仍是解锁态且非恢复会话。 */
    CHECK_EQ(Verthys_V4ResealDevice(h, RESEAL_PW_B, strlen(RESEAL_PW_B), NULL),
             VERTHYS_ERR_POLICY);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    reseal_cleanup();
    return 0;
}

TEST(reseal_device_keyfile_required_and_roundtrip)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];

    reseal_cleanup();
    memset(code, 0, sizeof(code));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4CreateKeyfile(h, RESEAL_KF_PATH, RESEAL_PW_A,
                                     strlen(RESEAL_PW_A), RESEAL_KF_FILE,
                                     code, sizeof(code)),
             VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    /* 恢复码通道不携带 keyfile 摘要。 */
    CHECK_EQ(Verthys_V4UnlockRecovery(h, RESEAL_KF_PATH, code), VERTHYS_OK);

    /* 启用 keyfile 却未提供文件：不得静默降级为仅口令。 */
    CHECK_EQ(Verthys_V4ResealDevice(h, RESEAL_PW_B, strlen(RESEAL_PW_B), NULL),
             VERTHYS_ERR_KEYFILE_REQUIRED);
    /* 提供正确 keyfile 后重绑成功。 */
    CHECK_EQ(Verthys_V4ResealDevice(h, RESEAL_PW_B, strlen(RESEAL_PW_B),
                                    RESEAL_KF_FILE),
             VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    CHECK_EQ(Verthys_V4UnlockKeyfile(h, RESEAL_KF_PATH, RESEAL_PW_B,
                                     strlen(RESEAL_PW_B), RESEAL_KF_FILE),
             VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    /* 缺 keyfile 必须拒绝，而不是退回仅口令解锁。 */
    CHECK_EQ(Verthys_V4Unlock(h, RESEAL_KF_PATH, RESEAL_PW_B,
                              strlen(RESEAL_PW_B)),
             VERTHYS_ERR_KEYFILE_REQUIRED);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    reseal_cleanup();
    return 0;
}
