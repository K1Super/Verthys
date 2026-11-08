/*
 * test_api.c — 公共会话入口验收
 *
 * 覆盖：V4Create/Unlock/Lock/Save 往返、恢复码解锁、主 Unlock 的
 * 格式分发与 ContainerInfo。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "vty_types.h"
#include "vty_recovery.h"

#include <stdio.h>
#include <string.h>

#define API_PATH "api.vty"
#define API_PW "api-pass"
#define API_KF_PATH "api_kf.vty"
#define API_KF_FILE "api_kf.key"
#define API_KF_FILE2 "api_kf2.key"

static long api_file_size(const char *path)
{
    FILE *f = fopen(path, "rb");
    long n;

    if (f == NULL) return -1;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fclose(f);
    return n;
}

static int api_write_bytes(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) return 1;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return 1; }
    fclose(f);
    return 0;
}

TEST(api_create_save_lock_unlock_roundtrip)
{
    VerthysHandle h = NULL;
    VerthysContainerInfo info;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint64_t gen1 = 0, gen2 = 0;

    remove(API_PATH);
    memset(code, 0, sizeof(code));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, API_PATH, API_PW, strlen(API_PW),
                              code, sizeof(code)), VERTHYS_OK);
    CHECK(strlen(code) == VTY_RECOVERY_CHARS + 13u);

    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.fmt_version, VERTHYS_FMT_CONTAINER);
    gen1 = info.txid;

    CHECK_EQ(Verthys_Flush(h), VERTHYS_OK);
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    gen2 = info.txid;
    CHECK(gen2 > gen1);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.fmt_version, VERTHYS_FMT_CONTAINER);
    CHECK_EQ(info.record_count, 0u);

    /* 主 Unlock 必须按 magic 分发到容器会话路径 */
    CHECK_EQ(Verthys_V4Unlock(h, API_PATH, API_PW, strlen(API_PW)),
             VERTHYS_OK);
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.fmt_version, VERTHYS_FMT_CONTAINER);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);

    remove(API_PATH);
    return 0;
}

TEST(api_recovery_unlock_roundtrip)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    VerthysContainerInfo info;

    remove(API_PATH);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, API_PATH, API_PW, strlen(API_PW),
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_Flush(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    CHECK_EQ(Verthys_V4UnlockRecovery(h, API_PATH, code), VERTHYS_OK);
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.fmt_version, VERTHYS_FMT_CONTAINER);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(API_PATH);
    return 0;
}

TEST(api_keyfile_create_unlock_disable_roundtrip)
{
    VerthysHandle h = NULL;
    VerthysContainerInfo info;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint32_t enabled = 0;
    uint32_t recovery_mode = 0;
    uint8_t bad[72];

    remove(API_KF_PATH);
    remove(API_KF_FILE);
    remove(API_KF_FILE2);
    memset(code, 0, sizeof(code));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4CreateKeyfile(h, API_KF_PATH, API_PW,
                                     strlen(API_PW), API_KF_FILE,
                                     code, sizeof(code)), VERTHYS_OK);
    /* VKFL v1 固定 72B，创建成功后必须已经落盘。 */
    CHECK_EQ(api_file_size(API_KF_FILE), 72);

    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.has_keyfile, 1u);
    CHECK_EQ(Verthys_V4KeyfileStatus(h, &enabled, &recovery_mode), VERTHYS_OK);
    CHECK_EQ(enabled, 1u);
    CHECK_EQ(recovery_mode, 0u);

    /* 同一 keyfile 路径已存在：独占新建必须拒绝，且不破坏原文件。 */
    CHECK_EQ(Verthys_V4KeyfileEnable(h, API_PW, strlen(API_PW),
                                     API_KF_FILE), VERTHYS_ERR_EXISTS);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    /* 标准解锁（无 keyfile）必须显式要求 keyfile，而不是报口令错。 */
    CHECK_EQ(Verthys_V4Unlock(h, API_KF_PATH, API_PW,
                              strlen(API_PW)), VERTHYS_ERR_KEYFILE_REQUIRED);
    /* 路径不存在 / 内容不是 VKFL：格式错误。 */
    CHECK_EQ(Verthys_V4UnlockKeyfile(h, API_KF_PATH, API_PW,
                                     strlen(API_PW), "api_missing.key"),
             VERTHYS_ERR_KEYFILE_INVALID);
    memset(bad, 0xAA, sizeof(bad));
    CHECK_EQ(api_write_bytes(API_KF_FILE2, bad, sizeof(bad)), 0);
    CHECK_EQ(Verthys_V4UnlockKeyfile(h, API_KF_PATH, API_PW,
                                     strlen(API_PW), API_KF_FILE2),
             VERTHYS_ERR_KEYFILE_INVALID);

    CHECK_EQ(Verthys_V4UnlockKeyfile(h, API_KF_PATH, API_PW,
                                     strlen(API_PW), API_KF_FILE),
             VERTHYS_OK);
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.has_keyfile, 1u);

    /* 关闭 keyfile 需要当前口令 + 当前 keyfile；口令错必须拒绝。 */
    CHECK_EQ(Verthys_V4KeyfileDisable(h, "wrong-pw", strlen("wrong-pw"),
                                      API_KF_FILE), VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_V4KeyfileDisable(h, API_PW, strlen(API_PW),
                                      API_KF_FILE), VERTHYS_OK);
    CHECK_EQ(Verthys_V4KeyfileStatus(h, &enabled, &recovery_mode), VERTHYS_OK);
    CHECK_EQ(enabled, 0u);
    CHECK_EQ(recovery_mode, 0u);
    remove(API_KF_FILE2);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(h, API_KF_PATH, API_PW,
                              strlen(API_PW)), VERTHYS_OK);
    CHECK_EQ(Verthys_GetContainerInfo(h, &info), VERTHYS_OK);
    CHECK_EQ(info.has_keyfile, 0u);

    /* 非 keyfile 库传 keyfile 路径按标准口令路径处理（忽略多余因子）。 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4UnlockKeyfile(h, API_KF_PATH, API_PW,
                                     strlen(API_PW), "api_missing.key"),
             VERTHYS_OK);

    /* 已解锁会话重新启用 keyfile：生成新文件并重封用户槽。 */
    remove(API_KF_FILE2);
    CHECK_EQ(Verthys_V4KeyfileEnable(h, API_PW, strlen(API_PW),
                                     API_KF_FILE2), VERTHYS_OK);
    CHECK_EQ(api_file_size(API_KF_FILE2), 72);
    CHECK_EQ(Verthys_V4KeyfileStatus(h, &enabled, &recovery_mode), VERTHYS_OK);
    CHECK_EQ(enabled, 1u);
    CHECK_EQ(recovery_mode, 0u);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(h, API_KF_PATH, API_PW,
                              strlen(API_PW)), VERTHYS_ERR_KEYFILE_REQUIRED);
    CHECK_EQ(Verthys_V4UnlockKeyfile(h, API_KF_PATH, API_PW,
                                     strlen(API_PW), API_KF_FILE2),
             VERTHYS_OK);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(API_KF_PATH);
    remove(API_KF_FILE);
    remove(API_KF_FILE2);
    return 0;
}

TEST(api_keyfile_recovery_rebind)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint32_t enabled = 0;
    uint32_t recovery_mode = 0;

    remove(API_KF_PATH);
    remove(API_KF_FILE);
    remove(API_KF_FILE2);
    memset(code, 0, sizeof(code));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4CreateKeyfile(h, API_KF_PATH, API_PW,
                                     strlen(API_PW), API_KF_FILE,
                                     code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 恢复码解锁：进入恢复会话 */
    CHECK_EQ(Verthys_V4UnlockRecovery(h, API_KF_PATH, code), VERTHYS_OK);
    CHECK_EQ(Verthys_V4KeyfileStatus(h, &enabled, &recovery_mode), VERTHYS_OK);
    CHECK_EQ(enabled, 1u);
    CHECK_EQ(recovery_mode, 1u);

    /* keyfile 丢失逃生：恢复会话中用当前口令生成新 keyfile 并重绑 */
    remove(API_KF_FILE2);
    CHECK_EQ(Verthys_V4KeyfileEnable(h, API_PW, strlen(API_PW),
                                     API_KF_FILE2), VERTHYS_OK);
    CHECK_EQ(api_file_size(API_KF_FILE2), 72);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 旧 keyfile 必须失效，新 keyfile 可解锁 */
    CHECK_EQ(Verthys_V4Unlock(h, API_KF_PATH, API_PW,
                              strlen(API_PW)), VERTHYS_ERR_KEYFILE_REQUIRED);
    CHECK_EQ(Verthys_V4UnlockKeyfile(h, API_KF_PATH, API_PW,
                                     strlen(API_PW), API_KF_FILE),
             VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_V4UnlockKeyfile(h, API_KF_PATH, API_PW,
                                     strlen(API_PW), API_KF_FILE2),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4KeyfileStatus(h, &enabled, &recovery_mode), VERTHYS_OK);
    CHECK_EQ(enabled, 1u);
    CHECK_EQ(recovery_mode, 0u);

    /* 普通会话不允许空路径关闭 keyfile（必须提供当前 keyfile） */
    CHECK_EQ(Verthys_V4KeyfileDisable(h, API_PW, strlen(API_PW), ""),
             VERTHYS_ERR_KEYFILE_REQUIRED);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 恢复会话空路径关闭 keyfile：回到“仅口令” */
    CHECK_EQ(Verthys_V4UnlockRecovery(h, API_KF_PATH, code), VERTHYS_OK);
    CHECK_EQ(Verthys_V4KeyfileDisable(h, API_PW, strlen(API_PW), ""),
             VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(h, API_KF_PATH, API_PW,
                              strlen(API_PW)), VERTHYS_OK);
    CHECK_EQ(Verthys_V4KeyfileStatus(h, &enabled, &recovery_mode), VERTHYS_OK);
    CHECK_EQ(enabled, 0u);
    CHECK_EQ(recovery_mode, 0u);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(API_KF_PATH);
    remove(API_KF_FILE);
    remove(API_KF_FILE2);
    return 0;
}

TEST(api_keyfile_create_rejects_existing_targets)
{
    VerthysHandle h = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    uint8_t junk[8];

    remove(API_KF_PATH);
    remove(API_KF_FILE);
    memset(junk, 0, sizeof(junk));
    CHECK_EQ(api_write_bytes(API_KF_FILE, junk, sizeof(junk)), 0);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    /* keyfile 目标已存在（哪怕内容不是 VKFL）：不覆盖，报 EXISTS，且
     * 不创建库文件。 */
    CHECK_EQ(Verthys_V4CreateKeyfile(h, API_KF_PATH, API_PW,
                                     strlen(API_PW), API_KF_FILE,
                                     code, sizeof(code)), VERTHYS_ERR_EXISTS);
    CHECK_EQ(api_file_size(API_KF_PATH), -1);
    CHECK_EQ(api_file_size(API_KF_FILE), 8);

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(API_KF_PATH);
    remove(API_KF_FILE);
    return 0;
}
