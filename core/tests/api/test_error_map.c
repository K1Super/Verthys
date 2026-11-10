/*
 * test_error_map.c — 内部错误码到公共返回码的映射验收
 *
 * 覆盖轮换相关的 20–23 码：必须映射到独立的公共码，
 * 不得折叠为 INVALID（否则调用方无法按码分流）。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "api/verthys_api_container.h"
#include "vty_types.h"

TEST(error_map_d9_codes_are_distinct)
{
    CHECK_EQ(verthys_api_container_map(VTY_E_ROTATE_PENDING),
             VERTHYS_ERR_ROTATE_PENDING);
    CHECK_EQ(verthys_api_container_map(VTY_E_MODULE_LOCKED),
             VERTHYS_ERR_MODULE_LOCKED);
    CHECK_EQ(verthys_api_container_map(VTY_E_NO_SPACE),
             VERTHYS_ERR_NO_SPACE);
    CHECK_EQ(verthys_api_container_map(VTY_E_VERIFY),
             VERTHYS_ERR_VERIFY);

    /* 不得回落到默认 INVALID */
    CHECK(verthys_api_container_map(VTY_E_ROTATE_PENDING) != VERTHYS_ERR_INVALID);
    CHECK(verthys_api_container_map(VTY_E_MODULE_LOCKED) != VERTHYS_ERR_INVALID);
    CHECK(verthys_api_container_map(VTY_E_NO_SPACE) != VERTHYS_ERR_INVALID);
    CHECK(verthys_api_container_map(VTY_E_VERIFY) != VERTHYS_ERR_INVALID);

    /* 公共错误码值固定为 0x1C–0x1F（ABI 契约） */
    CHECK_EQ((unsigned)VERTHYS_ERR_ROTATE_PENDING, 0x1Cu);
    CHECK_EQ((unsigned)VERTHYS_ERR_MODULE_LOCKED, 0x1Du);
    CHECK_EQ((unsigned)VERTHYS_ERR_NO_SPACE, 0x1Eu);
    CHECK_EQ((unsigned)VERTHYS_ERR_VERIFY, 0x1Fu);
    return 0;
}

TEST(error_map_r10_slot_errors_lock_format_policy)
{
    /* 结构类错误统一 FORMAT，便于诊断；口令错误走 AUTH。
     * 此处锁定该映射，防止实现漂移。 */
    CHECK_EQ(verthys_api_container_map(VTY_E_SLOT_MISSING), VERTHYS_ERR_FORMAT);
    CHECK_EQ(verthys_api_container_map(VTY_E_SLOT_UNKNOWN), VERTHYS_ERR_FORMAT);
    CHECK_EQ(verthys_api_container_map(VTY_E_KDF_WEAK), VERTHYS_ERR_FORMAT);
    CHECK_EQ(verthys_api_container_map(VTY_E_KEY_INVALID), VERTHYS_ERR_AUTH);
    CHECK_EQ(verthys_api_container_map(VTY_E_AEAD), VERTHYS_ERR_AUTH);
    return 0;
}
