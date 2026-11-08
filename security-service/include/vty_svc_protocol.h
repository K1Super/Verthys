/*
 * vty_svc_protocol.h — 安全服务 IPC 协议 v1 契约（服务端与 core 客户端共享）
 *
 * 设计约束：
 *   - 全定长、小端、无字符串、无变长字段，避免解析器成为攻击面。
 *   - 请求 64 字节、响应 128 字节；响应前 64 字节为签名覆盖范围。
 *   - 协议版本、魔法数、命令与状态码只在本头定义，其它模块只引用。
 *
 * 该头同时被 core/src/security/state/vty_machine_limiter.c 包含，
 * 因此不得依赖 windows.h 或任何 CNG 类型。
 */
#ifndef VTY_SVC_PROTOCOL_H
#define VTY_SVC_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 请求魔法：字节序列 'V','T','S','Q'，按小端 u32 书写。 */
#define VTY_SVC_REQUEST_MAGIC 0x51535456u
/* 响应魔法：字节序列 'V','T','S','R'。 */
#define VTY_SVC_RESPONSE_MAGIC 0x52535456u

#define VTY_SVC_PROTOCOL_VERSION 1u
#define VTY_SVC_REQUEST_BYTES 64u
#define VTY_SVC_RESPONSE_BYTES 128u
#define VTY_SVC_RESPONSE_HEADER_BYTES 64u
#define VTY_SVC_SIGNATURE_BYTES 64u

#define VTY_SVC_PIPE_NAME L"\\\\.\\pipe\\VerthysSecuritySvc.v1"
#define VTY_SVC_REGISTRY_KEY L"SOFTWARE\\Verthys\\SecurityService"
#define VTY_SVC_SERVICE_NAME L"VerthysSecuritySvc"
#define VTY_SVC_EVENT_SOURCE L"VerthysSecuritySvc"

/* 注册表值名：服务、安装器与 core 客户端共享同一契约。 */
#define VTY_SVC_REG_INSTALLED L"Installed"
#define VTY_SVC_REG_VERSION L"Version"
#define VTY_SVC_REG_INSTALL_PATH L"InstallPath"
#define VTY_SVC_REG_STATE_INITIALIZED L"StateInitialized"
#define VTY_SVC_REG_STATE_GENERATION L"StateGeneration"
#define VTY_SVC_REG_STATE_CREATED L"StateCreatedUtc"
#define VTY_SVC_REG_SERVER_PUBKEY L"ServerPubKey"
#define VTY_SVC_REG_PROTOCOL_VERSION L"ProtocolVersion"

#define VTY_SVC_CLIENT_CONNECT_TIMEOUT_MS 250u
#define VTY_SVC_CLIENT_REPLY_TIMEOUT_MS 1000u
#define VTY_SVC_SERVER_READ_TIMEOUT_MS 1000u
#define VTY_SVC_SERVER_WRITE_TIMEOUT_MS 2000u
#define VTY_SVC_MAX_PIPE_INSTANCES 8u
#define VTY_SVC_MAX_MESSAGE_BYTES 512u

/* 命令白名单。数值是协议契约，不得改动既有含义。 */
typedef enum VtySvcCommand {
    VTY_SVC_CMD_CHECK = 1,
    VTY_SVC_CMD_RECORD_FAILURE = 2,
    VTY_SVC_CMD_RESET = 3,
    VTY_SVC_CMD_PING = 4
} VtySvcCommand;

/* 响应状态。客户端只对 OK 放行，其余一律 fail-closed。 */
typedef enum VtySvcStatus {
    VTY_SVC_STATUS_OK = 0,
    VTY_SVC_STATUS_LOCKED = 1,
    VTY_SVC_STATUS_DENIED = 2,
    VTY_SVC_STATUS_BAD_REQUEST = 3,
    VTY_SVC_STATUS_INTERNAL = 4,
    VTY_SVC_STATUS_UNAVAILABLE = 5
} VtySvcStatus;

/* 解码后的请求字段（主机序）。 */
typedef struct VtySvcRequestFields {
    uint16_t command;
    uint32_t request_id;
    uint64_t nonce_lo;
    uint64_t nonce_hi;
} VtySvcRequestFields;

/* 解码后的响应字段（主机序）。 */
typedef struct VtySvcResponseFields {
    uint16_t status;
    uint32_t request_id;
    uint32_t retry_after_sec;
    uint64_t nonce_lo;
    uint64_t nonce_hi;
    uint32_t remaining_tokens;
    uint64_t server_time_sec;
} VtySvcResponseFields;

static inline uint16_t vty_svc_get_u16le(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t vty_svc_get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint64_t vty_svc_get_u64le(const uint8_t *p)
{
    return (uint64_t)vty_svc_get_u32le(p) |
           ((uint64_t)vty_svc_get_u32le(p + 4) << 32);
}

static inline void vty_svc_put_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static inline void vty_svc_put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static inline void vty_svc_put_u64le(uint8_t *p, uint64_t v)
{
    vty_svc_put_u32le(p, (uint32_t)(v & 0xFFFFFFFFu));
    vty_svc_put_u32le(p + 4, (uint32_t)((v >> 32) & 0xFFFFFFFFu));
}

/* 校验命令是否在白名单内。 */
static inline int vty_svc_command_valid(uint16_t command)
{
    return command == (uint16_t)VTY_SVC_CMD_CHECK ||
           command == (uint16_t)VTY_SVC_CMD_RECORD_FAILURE ||
           command == (uint16_t)VTY_SVC_CMD_RESET ||
           command == (uint16_t)VTY_SVC_CMD_PING;
}

/* 校验状态码是否在已定义范围内。 */
static inline int vty_svc_status_valid(uint16_t status)
{
    return status <= (uint16_t)VTY_SVC_STATUS_UNAVAILABLE;
}

/* 校验响应保留区是否为全 0。 */
static inline int vty_svc_reserved_zero(const uint8_t *p, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        if (p[i] != 0) return 0;
    }
    return 1;
}

/*
 * 构造 64 字节请求。调用方必须保证 raw 指向至少 64 字节可写缓冲区。
 * reserved0 与 reserved1 一律写 0，不接受调用方自定义。
 */
static inline void vty_svc_request_encode(uint8_t raw[VTY_SVC_REQUEST_BYTES],
                                          uint16_t command,
                                          uint32_t request_id,
                                          uint64_t nonce_lo,
                                          uint64_t nonce_hi)
{
    memset(raw, 0, VTY_SVC_REQUEST_BYTES);
    vty_svc_put_u32le(raw + 0, VTY_SVC_REQUEST_MAGIC);
    vty_svc_put_u16le(raw + 4, (uint16_t)VTY_SVC_PROTOCOL_VERSION);
    vty_svc_put_u16le(raw + 6, command);
    vty_svc_put_u32le(raw + 8, request_id);
    vty_svc_put_u32le(raw + 12, 0);
    vty_svc_put_u64le(raw + 16, nonce_lo);
    vty_svc_put_u64le(raw + 24, nonce_hi);
}

/*
 * 解析并校验 64 字节请求。
 * 返回 VTY_SVC_STATUS_OK 表示合法；否则返回 VTY_SVC_STATUS_BAD_REQUEST。
 * 校验项：magic、version、command 白名单、reserved 全 0、缓冲长度恰为 64。
 */
static inline uint16_t vty_svc_request_decode(const uint8_t *raw,
                                              size_t len,
                                              VtySvcRequestFields *out)
{
    if (raw == NULL || out == NULL ||
        len != VTY_SVC_REQUEST_BYTES) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (vty_svc_get_u32le(raw + 0) != VTY_SVC_REQUEST_MAGIC) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (vty_svc_get_u16le(raw + 4) != (uint16_t)VTY_SVC_PROTOCOL_VERSION) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (!vty_svc_command_valid(vty_svc_get_u16le(raw + 6))) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (vty_svc_get_u32le(raw + 12) != 0 ||
        !vty_svc_reserved_zero(raw + 32, 32)) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    out->command = vty_svc_get_u16le(raw + 6);
    out->request_id = vty_svc_get_u32le(raw + 8);
    out->nonce_lo = vty_svc_get_u64le(raw + 16);
    out->nonce_hi = vty_svc_get_u64le(raw + 24);
    return (uint16_t)VTY_SVC_STATUS_OK;
}

/*
 * 构造 128 字节响应。前 64 字节为签名覆盖范围，signature 区写 0，
 * 由调用方随后填入 ECDSA 签名。
 */
static inline void vty_svc_response_encode(uint8_t raw[VTY_SVC_RESPONSE_BYTES],
                                           uint16_t status,
                                           uint32_t request_id,
                                           uint32_t retry_after_sec,
                                           uint64_t nonce_lo,
                                           uint64_t nonce_hi,
                                           uint32_t remaining_tokens,
                                           uint64_t server_time_sec)
{
    memset(raw, 0, VTY_SVC_RESPONSE_BYTES);
    vty_svc_put_u32le(raw + 0, VTY_SVC_RESPONSE_MAGIC);
    vty_svc_put_u16le(raw + 4, (uint16_t)VTY_SVC_PROTOCOL_VERSION);
    vty_svc_put_u16le(raw + 6, status);
    vty_svc_put_u32le(raw + 8, request_id);
    vty_svc_put_u32le(raw + 12, retry_after_sec);
    vty_svc_put_u64le(raw + 16, nonce_lo);
    vty_svc_put_u64le(raw + 24, nonce_hi);
    vty_svc_put_u32le(raw + 32, remaining_tokens);
    vty_svc_put_u32le(raw + 36, 0);
    vty_svc_put_u64le(raw + 40, server_time_sec);
}

/*
 * 校验响应头（不含签名字节），并回填字段。
 * 返回 VTY_SVC_STATUS_OK 表示头部合法；否则返回 BAD_REQUEST。
 * 签名校验由调用方在 CNG 层完成；本函数不做任何密码学运算。
 */
static inline uint16_t vty_svc_response_decode(const uint8_t *raw,
                                               size_t len,
                                               uint32_t expected_request_id,
                                               uint64_t expected_nonce_lo,
                                               uint64_t expected_nonce_hi,
                                               VtySvcResponseFields *out)
{
    if (raw == NULL || out == NULL ||
        len != VTY_SVC_RESPONSE_BYTES) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (vty_svc_get_u32le(raw + 0) != VTY_SVC_RESPONSE_MAGIC) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (vty_svc_get_u16le(raw + 4) != (uint16_t)VTY_SVC_PROTOCOL_VERSION) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (!vty_svc_status_valid(vty_svc_get_u16le(raw + 6))) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (vty_svc_get_u32le(raw + 8) != expected_request_id ||
        vty_svc_get_u64le(raw + 16) != expected_nonce_lo ||
        vty_svc_get_u64le(raw + 24) != expected_nonce_hi ||
        vty_svc_get_u32le(raw + 36) != 0 ||
        !vty_svc_reserved_zero(raw + 48, 16)) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    out->status = vty_svc_get_u16le(raw + 6);
    out->request_id = vty_svc_get_u32le(raw + 8);
    out->retry_after_sec = vty_svc_get_u32le(raw + 12);
    out->nonce_lo = vty_svc_get_u64le(raw + 16);
    out->nonce_hi = vty_svc_get_u64le(raw + 24);
    out->remaining_tokens = vty_svc_get_u32le(raw + 32);
    out->server_time_sec = vty_svc_get_u64le(raw + 40);
    return (uint16_t)VTY_SVC_STATUS_OK;
}

#if defined(__cplusplus)
static_assert(sizeof(uint16_t) == 2 && sizeof(uint32_t) == 4 &&
                  sizeof(uint64_t) == 8,
              "protocol header requires fixed-width integers");
#else
_Static_assert(sizeof(uint16_t) == 2 && sizeof(uint32_t) == 4 &&
                   sizeof(uint64_t) == 8,
               "protocol header requires fixed-width integers");
#endif

#ifdef __cplusplus
}
#endif

#endif /* VTY_SVC_PROTOCOL_H */
