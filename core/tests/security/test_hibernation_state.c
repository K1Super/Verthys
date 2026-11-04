/*
 * test_hibernation_state.c — 系统休眠状态三态映射与真实查询
 *
 * 覆盖：
 *   - 纯解析：缺失 → 未知；0 → 禁用；非 0 → 启用
 *   - 真实注册表查询返回值域合法（0/1/2），失败不得伪装成禁用
 */
#include "verthys_test.h"
#include "hibernation_state.h"

#include <stdint.h>

TEST(hibernation_state_parse_map)
{
    CHECK_EQ(hibernation_state_parse(0, 0u), HIBERNATION_STATE_UNKNOWN);
    CHECK_EQ(hibernation_state_parse(0, 1u), HIBERNATION_STATE_UNKNOWN);
    CHECK_EQ(hibernation_state_parse(1, 0u), HIBERNATION_STATE_DISABLED);
    CHECK_EQ(hibernation_state_parse(1, 1u), HIBERNATION_STATE_ENABLED);
    /* Windows 对 HibernateEnabled 按非零即启用解释 */
    CHECK_EQ(hibernation_state_parse(1, 2u), HIBERNATION_STATE_ENABLED);
    return 0;
}

TEST(hibernation_state_query_real)
{
    uint32_t state = hibernation_state_query();
    TEST_LOG("[hibernation] current state=%u (0=disabled 1=enabled 2=unknown)\n",
             (unsigned)state);
    CHECK(state <= HIBERNATION_STATE_UNKNOWN);
    return 0;
}
