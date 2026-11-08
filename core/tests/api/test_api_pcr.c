/*
 * test_api_pcr.c — PCR 策略公共 API 验收
 *
 * 覆盖：状态查询、恢复码二次认证、启用/关闭/重密封、重复操作策略拒绝、
 * PCR 门失败时公共错误码为 TPM、恢复会话免恢复码重密封后普通解锁恢复。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "vty_types.h"
#include "vty_keymanager.h"
#include "vty_recovery.h"
#include "vty_tpm_pcr.h"
#include "vty_lockout.h"

#include <stdio.h>
#include <string.h>

#define PCR_PATH "api_pcr.vty"
#define PCR_PW   "pcr-api-pw"

TEST(api_pcr_policy_roundtrip)
{
    VerthysHandle h = NULL;
    struct VerthysContext *ctx;
    char code[VTY_RECOVERY_TEXT_BUF];
    char other[VTY_RECOVERY_TEXT_BUF];
    uint8_t other_code[VTY_RECOVERY_CODE_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint32_t enabled = 0xFFFFFFFFu;
    uint32_t select = 0xFFFFFFFFu;

    if (!vty_tpm_pcr_available()) {
        printf("  [SKIP] TPM/PCP 不可用\n");
        return 0;
    }
    vty_lockout_set_enabled(0);
    remove(PCR_PATH);
    memset(code, 0, sizeof(code));
    memset(other, 0, sizeof(other));
    memset(other_code, 0, sizeof(other_code));
    memset(uuid, 0, sizeof(uuid));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, PCR_PATH, PCR_PW, strlen(PCR_PW),
                              code, sizeof(code)), VERTHYS_OK);

    CHECK_EQ(Verthys_V4PcrStatus(h, &enabled, &select), VERTHYS_OK);
    CHECK_EQ(enabled, 0u);
    CHECK_EQ(select, 0u);

    /* 未启用时先校验位图；非 PCR0–23 位一律 INVALID */
    CHECK_EQ(Verthys_V4PcrEnable(h, 0x01000000u, code), VERTHYS_ERR_INVALID);

    /* 普通会话未提供恢复码：拒绝，且不改变策略 */
    CHECK_EQ(Verthys_V4PcrEnable(h, VTY_TPM_PCR_SELECT_DEFAULT, NULL),
             VERTHYS_ERR_INVALID);

    /* 格式合法但不是当前恢复码：AUTH，不泄露细分原因 */
    CHECK_EQ(vty_recovery_generate(other_code, other, sizeof(other)), VTY_OK);
    CHECK_EQ(Verthys_V4PcrEnable(h, VTY_TPM_PCR_SELECT_DEFAULT, other),
             VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_V4PcrStatus(h, &enabled, &select), VERTHYS_OK);
    CHECK_EQ(enabled, 0u);

    CHECK_EQ(Verthys_V4PcrEnable(h, VTY_TPM_PCR_SELECT_DEFAULT, code),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4PcrStatus(h, &enabled, &select), VERTHYS_OK);
    CHECK_EQ(enabled, 1u);
    CHECK_EQ(select, (uint32_t)VTY_TPM_PCR_SELECT_DEFAULT);
    CHECK_EQ(Verthys_V4PcrEnable(h, VTY_TPM_PCR_SELECT_DEFAULT, code),
             VERTHYS_ERR_POLICY);

    CHECK_EQ(Verthys_V4PcrDisable(h, other), VERTHYS_ERR_AUTH);
    CHECK_EQ(Verthys_V4PcrDisable(h, code), VERTHYS_OK);
    CHECK_EQ(Verthys_V4PcrStatus(h, &enabled, &select), VERTHYS_OK);
    CHECK_EQ(enabled, 0u);
    CHECK_EQ(Verthys_V4PcrDisable(h, code), VERTHYS_ERR_POLICY);

    CHECK_EQ(Verthys_V4PcrEnable(h, VTY_TPM_PCR_SELECT_DEFAULT, code),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4PcrReseal(h, code), VERTHYS_OK);

    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->vault != NULL);
    memcpy(uuid, ctx->vault->header.vault_uuid, VTY_UUID_BYTES);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4PcrStatus(h, &enabled, &select), VERTHYS_ERR_LOCKED);
    CHECK_EQ(Verthys_V4Unlock(h, PCR_PATH, PCR_PW, strlen(PCR_PW)),
             VERTHYS_OK);

    /* 设备侧 PCR 密钥丢失：普通解锁必须 fail-closed，恢复码仍可用 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    CHECK_EQ(Verthys_V4Unlock(h, PCR_PATH, PCR_PW, strlen(PCR_PW)),
             VERTHYS_ERR_TPM);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, PCR_PATH, code), VERTHYS_OK);

    /* 恢复会话已由恢复码认证，允许空恢复码重密封 */
    CHECK_EQ(Verthys_V4PcrReseal(h, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Unlock(h, PCR_PATH, PCR_PW, strlen(PCR_PW)),
             VERTHYS_OK);
    CHECK_EQ(Verthys_V4PcrStatus(h, &enabled, &select), VERTHYS_OK);
    CHECK_EQ(enabled, 1u);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    CHECK_EQ(vty_tpm_pcr_key_delete(uuid), VTY_OK);
    remove(PCR_PATH);
    return 0;
}
