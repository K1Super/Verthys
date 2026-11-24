#include "vtg_protocol.h"

#include <stdio.h>

/*
 * 协议布局冒烟测试。
 *
 * 该测试不加载驱动，只验证服务与驱动共享的定长结构与常量；
 * 任何布局变化都必须在这里显式失败，避免跨层二进制契约漂移。
 */

#define VTG_CHECK(condition)                                                   \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "FAIL: %s\n", #condition);                         \
            return 1;                                                          \
        }                                                                      \
    } while (0)

int
main(void)
{
    VTG_CHECK(VTG_PROTOCOL_MAJOR == 1u);
    VTG_CHECK(VTG_PROTOCOL_MINOR == 0u);
    VTG_CHECK(VTG_MAX_IMAGE_PATH_CHARS == 520u);
    VTG_CHECK(sizeof(VTG_WCHAR) == 2u);
    VTG_CHECK(sizeof(VTG_HEADER) == 32u);
    VTG_CHECK(sizeof(VTG_PROCESS_IDENTITY) == 1056u);
    VTG_CHECK(sizeof(VTG_ARM_IN) == 2136u);
    VTG_CHECK(sizeof(VTG_REGISTER_IN) == 1096u);
    VTG_CHECK(sizeof(VTG_STATUS_OUT) == 72u);

    VTG_CHECK(VTG_CMD_PING == 1);
    VTG_CHECK(VTG_CMD_ARM == 2);
    VTG_CHECK(VTG_CMD_DISARM == 3);
    VTG_CHECK(VTG_CMD_REGISTER_PROCESS == 4);
    VTG_CHECK(VTG_CMD_UNREGISTER_PROCESS == 5);
    VTG_CHECK(VTG_CMD_QUERY_STATUS == 6);
    VTG_CHECK(VTG_CMD_QUERY_STATS == 7);
    VTG_CHECK(VTG_CMD_QUERY_EVENTS == 8);

    VTG_CHECK(VTG_STATE_UNARMED == 0);
    VTG_CHECK(VTG_STATE_ACTIVE == 2);
    VTG_CHECK(VTG_REASON_NONE == 0);
    VTG_CHECK(VTG_STATUS_OK == 0);
    VTG_CHECK(VTG_STATUS_NOT_SUPPORTED == 8);
    VTG_CHECK(VTG_CAP_QUERY_STATUS == 0x00000001u);
    VTG_CHECK(VTG_CAP_PROTECT_PROCESS == 0x00000002u);
    VTG_CHECK(VTG_CAP_EVENTS == 0x00000004u);

    printf("VTG protocol tests passed\n");
    return 0;
}
