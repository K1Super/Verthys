/*
 * test_init.c — Phase 1.3 追踪弹：验证 Init/Deinit 行为
 *
 * 这是端到端验证构建链路的第一个测试（RED→GREEN）。
 * 仅通过 verthys.h 公共接口验证，不触碰内部结构。
 */
#include "verthys_test.h"
#include "verthys.h"

/* Init + Deinit 正常往返，句柄非空 */
TEST(init_deinit_roundtrip)
{
    VerthysHandle h = NULL;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK(h != NULL);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    return 0;
}

/* Init 拒绝空 out_handle */
TEST(init_rejects_null)
{
    CHECK_EQ(Verthys_Init(NULL), VERTHYS_ERR_INVALID);
    return 0;
}

/* Deinit 拒绝空句柄 */
TEST(deinit_rejects_null)
{
    CHECK_EQ(Verthys_Deinit(NULL), VERTHYS_ERR_INVALID);
    return 0;
}

/* 多次 Init 产生独立句柄 */
TEST(init_independent_handles)
{
    VerthysHandle a = NULL, b = NULL;
    CHECK_EQ(Verthys_Init(&a), VERTHYS_OK);
    CHECK_EQ(Verthys_Init(&b), VERTHYS_OK);
    CHECK(a != b);
    CHECK_EQ(Verthys_Deinit(a), VERTHYS_OK);
    CHECK_EQ(Verthys_Deinit(b), VERTHYS_OK);
    return 0;
}
