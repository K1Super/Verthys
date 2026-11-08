/*
 * test_witness.c — TPM 持久化密钥见证模块验收
 *
 * 覆盖：
 *   - A/B 双槽轮换与公钥指纹变化
 *   - 旧指纹在轮换后校验失败（旧状态不可重放）
 *   - 删除幂等、两槽存在性查询
 *   - 见证域 id 由稳定字符串派生且可区分
 *
 * 需要 Platform Crypto Provider；环境不具备时打印 SKIP。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_tpm_witness.h"
#include "vty_util.h"

#include <stdio.h>
#include <string.h>

TEST(witness_rotation_and_verify)
{
    uint8_t id[VTY_UUID_BYTES];
    uint8_t fp0[VTY_TPM_WITNESS_FP_BYTES];
    uint8_t fp1[VTY_TPM_WITNESS_FP_BYTES];
    uint8_t fp2[VTY_TPM_WITNESS_FP_BYTES];

    if (!vty_tpm_witness_available()) {
        printf("  [SKIP] PCP 不可用\n");
        return 0;
    }
    memset(id, 0x5A, sizeof(id));
    memset(fp0, 0, sizeof(fp0));
    memset(fp1, 0, sizeof(fp1));
    memset(fp2, 0, sizeof(fp2));

    CHECK_EQ(vty_tpm_witness_delete_all(id), VTY_OK);
    CHECK_EQ(vty_tpm_witness_any(id), 0);

    CHECK_EQ(vty_tpm_witness_create(id, 0, fp0), VTY_OK);
    CHECK_EQ(vty_tpm_witness_verify(id, 0, fp0), VTY_OK);
    CHECK_EQ(vty_tpm_witness_any(id), 1);

    /* 覆盖同槽：公钥指纹必须变化，旧指纹不可再验证 */
    CHECK_EQ(vty_tpm_witness_create(id, 0, fp2), VTY_OK);
    CHECK(memcmp(fp0, fp2, sizeof(fp0)) != 0);
    CHECK_EQ(vty_tpm_witness_verify(id, 0, fp0), VTY_E_TPM);
    CHECK_EQ(vty_tpm_witness_verify(id, 0, fp2), VTY_OK);

    /* 另一槽独立 */
    CHECK_EQ(vty_tpm_witness_create(id, 1, fp1), VTY_OK);
    CHECK(memcmp(fp1, fp2, sizeof(fp1)) != 0);
    CHECK_EQ(vty_tpm_witness_verify(id, 1, fp1), VTY_OK);
    CHECK_EQ(vty_tpm_witness_verify(id, 1, fp2), VTY_E_TPM);

    /* 删除幂等 */
    CHECK_EQ(vty_tpm_witness_delete(id, 0), VTY_OK);
    CHECK_EQ(vty_tpm_witness_delete(id, 0), VTY_OK);
    CHECK_EQ(vty_tpm_witness_verify(id, 0, fp2), VTY_E_TPM);
    CHECK_EQ(vty_tpm_witness_any(id), 1);
    CHECK_EQ(vty_tpm_witness_delete_all(id), VTY_OK);
    CHECK_EQ(vty_tpm_witness_any(id), 0);

    /* 见证域 id 派生稳定且可区分（仅测试钩子构建提供该派生函数） */
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    {
        uint8_t id2[VTY_UUID_BYTES];
        CHECK_EQ(vty_tpm_witness_id_from_string("lockout-a", id2), VTY_OK);
        CHECK(memcmp(id, id2, sizeof(id)) != 0);
    }
#endif
    return 0;
}
