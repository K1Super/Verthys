/*
 * test_integrity_verify.c — 配套测试：构建期签名验签
 *
 * 覆盖：
 *   - 开发/测试构建（.vsec 全零未配置）：integrity_verify_startup 空操作通过
 *   - integrity_init 幂等就绪（defense_closure HOOK 路径判据）
 *
 * Release 构建的 .vsec 注入由 build_core.release.ps1 完成并在生产链路
 * 验证（Verthys_Unlock 入口）；测试进程的 .vsec 恒为未配置态，验签必须
 * 返回 0（跳过），此行为本身即是契约的一部分。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "integrity.h"

TEST(integrity_verify_unconfigured_passes)
{
    /* 测试构建无基准注入 → 跳过校验返回 0（不得误报） */
    CHECK_EQ(integrity_verify_startup(), 0);
    return 0;
}

TEST(integrity_init_idempotent)
{
    CHECK_EQ(integrity_init(), 0);
    CHECK_EQ(integrity_init(), 0);  /* 幂等 */
    return 0;
}
