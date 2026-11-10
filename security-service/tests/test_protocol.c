/*
 * test_protocol.c — 协议编码/解码与非法输入拒绝
 */
#include "test_common.h"
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
    vty_svc_put_u16le(copy + 6, 5u);
    CHECK_EQ_INT(vty_svc_request_decode(copy, sizeof(copy), &fields),
                 VTY_SVC_STATUS_BAD_REQUEST);

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
    test_valid_response();
    test_invalid_responses();
    return g_test_failures;
}
