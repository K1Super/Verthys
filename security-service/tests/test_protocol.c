/*
 * test_protocol.c — 协议编码/解码与非法输入拒绝
 */
#include "test_common.h"
#include "kernel_guard.h"
#include "vty_svc_protocol.h"

#include <string.h>

static void test_valid_request(void)
{
    uint8_t raw[VTY_SVC_REQUEST_BYTES];
    VtySvcRequestFields fields;

    vty_svc_request_encode(raw, (uint16_t)VTY_SVC_CMD_CHECK, 0x11223344u,
                           0x0102030405060708ULL, 0x1112131415161718ULL);
    CHECK_EQ_INT(vty_svc_request_decode(raw, sizeof(raw), &fields),
                 VTY_SVC_STATUS_OK);
    CHECK_EQ_INT(fields.command, VTY_SVC_CMD_CHECK);
    CHECK_EQ_U64(fields.request_id, 0x11223344u);
    CHECK_EQ_U64(fields.nonce_lo, 0x0102030405060708ULL);
    CHECK_EQ_U64(fields.nonce_hi, 0x1112131415161718ULL);
    CHECK(vty_svc_reserved_zero(raw + 32, 32));
}

static void test_invalid_requests(void)
{
    uint8_t raw[VTY_SVC_REQUEST_BYTES];
    uint8_t copy[VTY_SVC_REQUEST_BYTES];
    VtySvcRequestFields fields;

    vty_svc_request_encode(raw, (uint16_t)VTY_SVC_CMD_CHECK, 1u, 2u, 3u);

    memcpy(copy, raw, sizeof(copy));
    copy[0] ^= 0xFFu;
    CHECK_EQ_INT(vty_svc_request_decode(copy, sizeof(copy), &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    vty_svc_put_u16le(copy + 4, 2u);
    CHECK_EQ_INT(vty_svc_request_decode(copy, sizeof(copy), &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    vty_svc_put_u16le(copy + 6, 0u);
    CHECK_EQ_INT(vty_svc_request_decode(copy, sizeof(copy), &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    vty_svc_put_u16le(copy + 6, 9u);
    CHECK_EQ_INT(vty_svc_request_decode(copy, sizeof(copy), &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    CHECK(vty_svc_command_valid((uint16_t)VTY_SVC_CMD_KERNEL_STATUS));
    CHECK(vty_svc_command_valid((uint16_t)VTY_SVC_CMD_KERNEL_ARM));
    CHECK(vty_svc_command_valid((uint16_t)VTY_SVC_CMD_KERNEL_REGISTER));
    CHECK(vty_svc_command_valid((uint16_t)VTY_SVC_CMD_KERNEL_DISARM));
    CHECK(!vty_svc_command_valid(9u));

    /* 内核生命周期命令仍是无载荷的 64 字节请求，保留区必须全 0。 */
    vty_svc_request_encode(raw, (uint16_t)VTY_SVC_CMD_KERNEL_ARM, 4u, 5u, 6u);
    CHECK_EQ_INT(vty_svc_request_decode(raw, sizeof(raw), &fields),
                 VTY_SVC_STATUS_OK);
    CHECK_EQ_INT(fields.command, VTY_SVC_CMD_KERNEL_ARM);
    CHECK(vty_svc_reserved_zero(raw + 32, 32));

    memcpy(copy, raw, sizeof(copy));
    copy[12] = 1u;
    CHECK_EQ_INT(vty_svc_request_decode(copy, sizeof(copy), &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    copy[32] = 1u;
    CHECK_EQ_INT(vty_svc_request_decode(copy, sizeof(copy), &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    CHECK_EQ_INT(vty_svc_request_decode(raw, sizeof(raw) - 1u, &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_svc_request_decode(raw, sizeof(raw) + 1u, &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_svc_request_decode(NULL, sizeof(raw), &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);
}

static void test_kernel_request_payload(void)
{
    uint8_t raw[VTY_SVC_REQUEST_BYTES];
    uint8_t copy[VTY_SVC_REQUEST_BYTES];
    VtySvcRequestFields fields;
    VtySvcKernelPayload payload;

    /* 宿主预 ARM：mode=1，selector=1。 */
    memset(&payload, 0, sizeof(payload));
    payload.mode = VTY_SVC_ARM_MODE_HOST_PREARM;
    payload.worker_image = VTY_SVC_WORKER_IMAGE_SIDECAR;
    vty_svc_request_encode_kernel(raw, (uint16_t)VTY_SVC_CMD_KERNEL_ARM,
                                  0x0A0B0C0Du, 11u, 12u, &payload);
    CHECK_EQ_U64(vty_svc_get_u32le(raw + 32), VTY_SVC_ARM_MODE_HOST_PREARM);
    CHECK_EQ_U64(vty_svc_get_u32le(raw + 36),
                 VTY_SVC_WORKER_IMAGE_SIDECAR);
    /* 通用解码要求载荷区全 0，必须拒绝；内核解码接受。 */
    CHECK_EQ_INT(vty_svc_request_decode(raw, sizeof(raw), &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);
    memset(&payload, 0xFF, sizeof(payload));
    CHECK_EQ_INT(vty_svc_request_decode_kernel(raw, sizeof(raw), &fields,
                                               &payload),
                 VTY_SVC_STATUS_OK);
    CHECK_EQ_INT(fields.command, VTY_SVC_CMD_KERNEL_ARM);
    CHECK_EQ_U64(fields.request_id, 0x0A0B0C0Du);
    CHECK_EQ_INT(payload.mode, VTY_SVC_ARM_MODE_HOST_PREARM);
    CHECK_EQ_INT(payload.worker_image, VTY_SVC_WORKER_IMAGE_SIDECAR);

    /* 非法 mode / self 模式携带 selector / 未使用区非 0。 */
    memcpy(copy, raw, sizeof(copy));
    vty_svc_put_u32le(copy + 32, 2u);
    CHECK_EQ_INT(vty_svc_request_decode_kernel(copy, sizeof(copy), &fields,
                                               &payload),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    vty_svc_put_u32le(copy + 32, 0u);
    CHECK_EQ_INT(vty_svc_request_decode_kernel(copy, sizeof(copy), &fields,
                                               &payload),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    vty_svc_put_u32le(copy + 36, 9u);
    CHECK_EQ_INT(vty_svc_request_decode_kernel(copy, sizeof(copy), &fields,
                                               &payload),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    copy[40] = 1u;
    CHECK_EQ_INT(vty_svc_request_decode_kernel(copy, sizeof(copy), &fields,
                                               &payload),
                 VTY_SVC_STATUS_BAD_REQUEST);

    /* 旧请求（载荷全 0）仍按 worker self 接受。 */
    vty_svc_request_encode_kernel(raw, (uint16_t)VTY_SVC_CMD_KERNEL_ARM, 1u,
                                  2u, 3u, NULL);
    CHECK_EQ_INT(vty_svc_request_decode_kernel(raw, sizeof(raw), &fields,
                                               &payload),
                 VTY_SVC_STATUS_OK);
    CHECK_EQ_INT(payload.mode, VTY_SVC_ARM_MODE_WORKER_SELF);
    CHECK_EQ_INT(payload.worker_image, VTY_SVC_WORKER_IMAGE_DEFAULT);

    /* REGISTER：PID 与创建时间定长布局。 */
    memset(&payload, 0, sizeof(payload));
    payload.target_pid = 0x1234u;
    payload.target_creation = 0x0102030405060708ULL;
    vty_svc_request_encode_kernel(raw, (uint16_t)VTY_SVC_CMD_KERNEL_REGISTER,
                                  7u, 8u, 9u, &payload);
    CHECK_EQ_U64(vty_svc_get_u32le(raw + 32), 0x1234u);
    CHECK_EQ_U64(vty_svc_get_u64le(raw + 36), 0x0102030405060708ULL);
    CHECK_EQ_INT(vty_svc_request_decode_kernel(raw, sizeof(raw), &fields,
                                               &payload),
                 VTY_SVC_STATUS_OK);
    CHECK_EQ_U64(payload.target_pid, 0x1234u);
    CHECK_EQ_U64(payload.target_creation, 0x0102030405060708ULL);

    memcpy(copy, raw, sizeof(copy));
    vty_svc_put_u32le(copy + 32, 0u);
    CHECK_EQ_INT(vty_svc_request_decode_kernel(copy, sizeof(copy), &fields,
                                               &payload),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    copy[44] = 1u;
    CHECK_EQ_INT(vty_svc_request_decode_kernel(copy, sizeof(copy), &fields,
                                               &payload),
                 VTY_SVC_STATUS_BAD_REQUEST);

    /* DISARM 不允许载荷。 */
    vty_svc_request_encode(raw, (uint16_t)VTY_SVC_CMD_KERNEL_DISARM, 4u, 5u,
                           6u);
    CHECK_EQ_INT(vty_svc_request_decode_kernel(raw, sizeof(raw), &fields,
                                               &payload),
                 VTY_SVC_STATUS_OK);
    memcpy(copy, raw, sizeof(copy));
    copy[32] = 1u;
    CHECK_EQ_INT(vty_svc_request_decode_kernel(copy, sizeof(copy), &fields,
                                               &payload),
                 VTY_SVC_STATUS_BAD_REQUEST);

    /* 非内核命令不接受内核解码器。 */
    vty_svc_request_encode(raw, (uint16_t)VTY_SVC_CMD_CHECK, 1u, 2u, 3u);
    CHECK_EQ_INT(vty_svc_request_decode_kernel(raw, sizeof(raw), &fields,
                                               &payload),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_svc_request_decode_kernel(raw, sizeof(raw) - 1u, &fields,
                                               &payload),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_svc_request_decode_kernel(NULL, sizeof(raw), &fields,
                                               &payload),
                 VTY_SVC_STATUS_BAD_REQUEST);
}

static void test_valid_response(void)
{
    uint8_t raw[VTY_SVC_RESPONSE_BYTES];
    VtySvcResponseFields fields;

    vty_svc_response_encode(raw, (uint16_t)VTY_SVC_STATUS_LOCKED, 0x55667788u,
                            42u, 0xAABBCCDDEEFF0011ULL,
                            0x1122334455667788ULL, 3u, 1700000000ULL);
    CHECK_EQ_INT(vty_svc_response_decode(raw, sizeof(raw), 0x55667788u,
                                         0xAABBCCDDEEFF0011ULL,
                                         0x1122334455667788ULL, &fields),
                 VTY_SVC_STATUS_OK);
    CHECK_EQ_INT(fields.status, VTY_SVC_STATUS_LOCKED);
    CHECK_EQ_U64(fields.request_id, 0x55667788u);
    CHECK_EQ_U64(fields.retry_after_sec, 42u);
    CHECK_EQ_U64(fields.remaining_tokens, 3u);
    CHECK_EQ_U64(fields.server_time_sec, 1700000000ULL);
    CHECK(vty_svc_reserved_zero(raw + 48, 16));
}

static void test_kernel_response(void)
{
    uint8_t raw[VTY_SVC_RESPONSE_BYTES];
    VtySvcResponseFields fields;

    vty_svc_response_encode_kernel(
        raw, (uint16_t)VTY_SVC_STATUS_OK, 0x55667788u, 0u,
        0xAABBCCDDEEFF0011ULL, 0x1122334455667788ULL, 0u, 1700000000ULL,
        (uint32_t)VTY_KERNEL_STATE_NOT_INSTALLED,
        (uint32_t)VTY_KERNEL_REASON_NOT_INSTALLED, 0x3u, 1u, 0u);

    CHECK_EQ_INT(vty_svc_response_decode_kernel(
                     raw, sizeof(raw), 0x55667788u, 0xAABBCCDDEEFF0011ULL,
                     0x1122334455667788ULL, &fields),
                 VTY_SVC_STATUS_OK);
    CHECK_EQ_INT(fields.kernel_state, VTY_KERNEL_STATE_NOT_INSTALLED);
    CHECK_EQ_INT(fields.kernel_reason, VTY_KERNEL_REASON_NOT_INSTALLED);
    CHECK_EQ_INT(fields.kernel_capabilities, 0x3u);
    CHECK_EQ_INT(fields.kernel_protocol_major, 1u);
    CHECK_EQ_INT(fields.kernel_protocol_minor, 0u);

    /* 普通响应的 48..63 必须是全 0；KernelStatus 专用解码才允许非 0。 */
    CHECK_EQ_INT(vty_svc_response_decode(raw, sizeof(raw), 0x55667788u,
                                         0xAABBCCDDEEFF0011ULL,
                                         0x1122334455667788ULL, &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_svc_response_decode_kernel(raw, sizeof(raw), 1u,
                                                 0xAABBCCDDEEFF0011ULL,
                                                 0x1122334455667788ULL,
                                                 &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);
}

static void test_invalid_responses(void)
{
    uint8_t raw[VTY_SVC_RESPONSE_BYTES];
    uint8_t copy[VTY_SVC_RESPONSE_BYTES];
    VtySvcResponseFields fields;

    vty_svc_response_encode(raw, (uint16_t)VTY_SVC_STATUS_OK, 7u, 0u, 8u, 9u,
                            10u, 11u);

    CHECK_EQ_INT(vty_svc_response_decode(raw, sizeof(raw), 8u, 8u, 9u, &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_svc_response_decode(raw, sizeof(raw), 7u, 9u, 9u, &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_svc_response_decode(raw, sizeof(raw), 7u, 8u, 10u, &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    copy[0] ^= 0xFFu;
    CHECK_EQ_INT(vty_svc_response_decode(copy, sizeof(copy), 7u, 8u, 9u,
                                         &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    vty_svc_put_u16le(copy + 4, 2u);
    CHECK_EQ_INT(vty_svc_response_decode(copy, sizeof(copy), 7u, 8u, 9u,
                                         &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    vty_svc_put_u16le(copy + 6, 6u);
    CHECK_EQ_INT(vty_svc_response_decode(copy, sizeof(copy), 7u, 8u, 9u,
                                         &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    copy[36] = 1u;
    CHECK_EQ_INT(vty_svc_response_decode(copy, sizeof(copy), 7u, 8u, 9u,
                                         &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    memcpy(copy, raw, sizeof(copy));
    copy[48] = 1u;
    CHECK_EQ_INT(vty_svc_response_decode(copy, sizeof(copy), 7u, 8u, 9u,
                                         &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

    CHECK_EQ_INT(vty_svc_response_decode(raw, sizeof(raw) - 1u, 7u, 8u, 9u,
                                         &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);
}

int test_protocol_run(void)
{
    printf("[ U1 ] protocol encode/decode\n");
    test_valid_request();
    test_invalid_requests();
    test_kernel_request_payload();
    test_valid_response();
    test_kernel_response();
    test_invalid_responses();
    return g_test_failures;
}
