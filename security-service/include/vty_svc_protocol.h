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
    VTY_SVC_CMD_PING = 4,
    /* status=OK 只表示查询已应答；内核是否可用看响应 48..63 区。 */
    VTY_SVC_CMD_KERNEL_STATUS = 5,
    /*
     * 内核防护生命周期命令。请求仍为 64 字节且无载荷：服务以已认证的
     * 管道客户端进程身份作为唯一输入，拒绝客户端指定受保护路径。
     */
    VTY_SVC_CMD_KERNEL_ARM = 6,
    VTY_SVC_CMD_KERNEL_REGISTER = 7,
    VTY_SVC_CMD_KERNEL_DISARM = 8
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

/* KernelStatus 跨服务/核心共享状态；数值是协议契约，只增不改。 */
typedef enum VtyKernelState {
    VTY_KERNEL_STATE_UNKNOWN = 0,
    VTY_KERNEL_STATE_UNARMED = 1,
    VTY_KERNEL_STATE_ARMED = 2,
    VTY_KERNEL_STATE_ACTIVE = 3,
    VTY_KERNEL_STATE_DEGRADED = 4,
    VTY_KERNEL_STATE_LOST = 5,
    VTY_KERNEL_STATE_NOT_INSTALLED = 6,
    VTY_KERNEL_STATE_STOPPED = 7,
    VTY_KERNEL_STATE_VERSION_MISMATCH = 8,
    VTY_KERNEL_STATE_UNHEALTHY = 9,
    VTY_KERNEL_STATE_UNSUPPORTED = 10
} VtyKernelState;

typedef enum VtyKernelReason {
    VTY_KERNEL_REASON_NONE = 0,
    VTY_KERNEL_REASON_NOT_INSTALLED = 1,
    VTY_KERNEL_REASON_STOPPED = 2,
    VTY_KERNEL_REASON_VERSION_MISMATCH = 3,
    VTY_KERNEL_REASON_UNSUPPORTED = 4,
    VTY_KERNEL_REASON_REGISTER_FAILED = 5,
    VTY_KERNEL_REASON_PROCESS_EXITED = 6,
    VTY_KERNEL_REASON_DRIVER_UNLOADED = 7,
    VTY_KERNEL_REASON_INTERNAL = 8,
    VTY_KERNEL_REASON_ACCESS_DENIED = 9,
    VTY_KERNEL_REASON_TIMEOUT = 10,
    VTY_KERNEL_REASON_BAD_RESPONSE = 11
} VtyKernelReason;

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
    uint32_t kernel_state;
    uint32_t kernel_reason;
    uint32_t kernel_capabilities;
    uint16_t kernel_protocol_major;
    uint16_t kernel_protocol_minor;
} VtySvcResponseFields;

/* KernelStatus 使用响应头 48..63 的保留区；既有命令仍要求该区全 0。 */
#define VTY_SVC_RESPONSE_KERNEL_STATE_OFF 48u
#define VTY_SVC_RESPONSE_KERNEL_REASON_OFF 52u
#define VTY_SVC_RESPONSE_KERNEL_CAPS_OFF 56u
#define VTY_SVC_RESPONSE_KERNEL_PROTOCOL_OFF 60u

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

/*
 * 内核生命周期命令载荷区（请求 32..63）。
 *
 * ARM 与 REGISTER 需要固定宽度载荷；DISARM 与非内核命令仍要求该区全 0。
 * 载荷只描述“已认证客户端希望保护哪个本地 worker”，受保护路径仍由服务
 * 从客户端映像目录派生，客户端不能提交任意路径。
 */
#define VTY_SVC_REQUEST_PAYLOAD_OFF 32u

#define VTY_SVC_ARM_MODE_WORKER_SELF 0u
#define VTY_SVC_ARM_MODE_HOST_PREARM 1u

#define VTY_SVC_WORKER_IMAGE_DEFAULT 0u
#define VTY_SVC_WORKER_IMAGE_SIDECAR 1u

typedef struct VtySvcKernelPayload {
    uint32_t mode;
    uint32_t worker_image;
    uint32_t target_pid;
    uint64_t target_creation;
} VtySvcKernelPayload;

/* 校验命令是否在白名单内。 */
static inline int vty_svc_command_valid(uint16_t command)
{
    return command == (uint16_t)VTY_SVC_CMD_CHECK ||
           command == (uint16_t)VTY_SVC_CMD_RECORD_FAILURE ||
           command == (uint16_t)VTY_SVC_CMD_RESET ||
           command == (uint16_t)VTY_SVC_CMD_PING ||
           command == (uint16_t)VTY_SVC_CMD_KERNEL_STATUS ||
           command == (uint16_t)VTY_SVC_CMD_KERNEL_ARM ||
           command == (uint16_t)VTY_SVC_CMD_KERNEL_REGISTER ||
           command == (uint16_t)VTY_SVC_CMD_KERNEL_DISARM;
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
 * 构造带内核载荷的 64 字节请求。payload 为 NULL 时载荷区全 0，
 * 对应 worker 自身 ARM 与 self REGISTER 的既有语义。
 */
static inline void vty_svc_request_encode_kernel(
    uint8_t raw[VTY_SVC_REQUEST_BYTES],
    uint16_t command,
    uint32_t request_id,
    uint64_t nonce_lo,
    uint64_t nonce_hi,
    const VtySvcKernelPayload *payload)
{
    vty_svc_request_encode(raw, command, request_id, nonce_lo, nonce_hi);
    if (payload == NULL) return;
    if (command == (uint16_t)VTY_SVC_CMD_KERNEL_ARM) {
        vty_svc_put_u32le(raw + VTY_SVC_REQUEST_PAYLOAD_OFF, payload->mode);
        vty_svc_put_u32le(raw + VTY_SVC_REQUEST_PAYLOAD_OFF + 4u,
                          payload->worker_image);
    } else if (command == (uint16_t)VTY_SVC_CMD_KERNEL_REGISTER) {
        vty_svc_put_u32le(raw + VTY_SVC_REQUEST_PAYLOAD_OFF,
                          payload->target_pid);
        vty_svc_put_u64le(raw + VTY_SVC_REQUEST_PAYLOAD_OFF + 4u,
                          payload->target_creation);
    }
}

/*
 * 解析并校验内核生命周期请求（命令 6/7/8）。
 * 与通用解码的差异：命令 6/7 允许 32..63 区的固定宽度载荷，
 * 但各命令的未使用字节必须为 0。返回前回填主机序字段与载荷。
 */
static inline uint16_t vty_svc_request_decode_kernel(
    const uint8_t *raw,
    size_t len,
    VtySvcRequestFields *out,
    VtySvcKernelPayload *payload)
{
    uint16_t command;

    if (raw == NULL || out == NULL || payload == NULL ||
        len != VTY_SVC_REQUEST_BYTES) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (vty_svc_get_u32le(raw + 0) != VTY_SVC_REQUEST_MAGIC) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (vty_svc_get_u16le(raw + 4) != (uint16_t)VTY_SVC_PROTOCOL_VERSION) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    command = vty_svc_get_u16le(raw + 6);
    if (command != (uint16_t)VTY_SVC_CMD_KERNEL_ARM &&
        command != (uint16_t)VTY_SVC_CMD_KERNEL_REGISTER &&
        command != (uint16_t)VTY_SVC_CMD_KERNEL_DISARM) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (vty_svc_get_u32le(raw + 12) != 0) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }

    memset(payload, 0, sizeof(*payload));
    if (command == (uint16_t)VTY_SVC_CMD_KERNEL_ARM) {
        payload->mode = vty_svc_get_u32le(raw + VTY_SVC_REQUEST_PAYLOAD_OFF);
        payload->worker_image = vty_svc_get_u32le(
            raw + VTY_SVC_REQUEST_PAYLOAD_OFF + 4u);
        if (payload->mode > VTY_SVC_ARM_MODE_HOST_PREARM ||
            payload->worker_image > VTY_SVC_WORKER_IMAGE_SIDECAR) {
            return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
        }
        if (payload->mode == VTY_SVC_ARM_MODE_WORKER_SELF &&
            payload->worker_image != VTY_SVC_WORKER_IMAGE_DEFAULT) {
            return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
        }
        if (!vty_svc_reserved_zero(raw + VTY_SVC_REQUEST_PAYLOAD_OFF + 8u, 24u)) {
            return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
        }
    } else if (command == (uint16_t)VTY_SVC_CMD_KERNEL_REGISTER) {
        payload->target_pid = vty_svc_get_u32le(raw + VTY_SVC_REQUEST_PAYLOAD_OFF);
        payload->target_creation = vty_svc_get_u64le(
            raw + VTY_SVC_REQUEST_PAYLOAD_OFF + 4u);
        if (!vty_svc_reserved_zero(raw + VTY_SVC_REQUEST_PAYLOAD_OFF + 12u, 20u)) {
            return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
        }
        if (payload->target_pid == 0 && payload->target_creation != 0) {
            return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
        }
    } else {
        if (!vty_svc_reserved_zero(raw + VTY_SVC_REQUEST_PAYLOAD_OFF, 32u)) {
            return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
        }
    }

    out->command = command;
    out->request_id = vty_svc_get_u32le(raw + 8);
    out->nonce_lo = vty_svc_get_u64le(raw + 16);
    out->nonce_hi = vty_svc_get_u64le(raw + 24);
    return (uint16_t)VTY_SVC_STATUS_OK;
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
 * 构造 KernelStatus 响应：在标准 128 字节响应头的 48..63 区写入内核状态。
 * 这些字段仍在前 64 字节签名覆盖范围内。
 */
static inline void vty_svc_response_encode_kernel(
    uint8_t raw[VTY_SVC_RESPONSE_BYTES],
    uint16_t status,
    uint32_t request_id,
    uint32_t retry_after_sec,
    uint64_t nonce_lo,
    uint64_t nonce_hi,
    uint32_t remaining_tokens,
    uint64_t server_time_sec,
    uint32_t kernel_state,
    uint32_t kernel_reason,
    uint32_t kernel_capabilities,
    uint16_t kernel_protocol_major,
    uint16_t kernel_protocol_minor)
{
    vty_svc_response_encode(raw, status, request_id, retry_after_sec,
                            nonce_lo, nonce_hi, remaining_tokens,
                            server_time_sec);
    vty_svc_put_u32le(raw + VTY_SVC_RESPONSE_KERNEL_STATE_OFF, kernel_state);
    vty_svc_put_u32le(raw + VTY_SVC_RESPONSE_KERNEL_REASON_OFF, kernel_reason);
    vty_svc_put_u32le(raw + VTY_SVC_RESPONSE_KERNEL_CAPS_OFF,
                      kernel_capabilities);
    vty_svc_put_u16le(raw + VTY_SVC_RESPONSE_KERNEL_PROTOCOL_OFF,
                      kernel_protocol_major);
    vty_svc_put_u16le(raw + VTY_SVC_RESPONSE_KERNEL_PROTOCOL_OFF + 2u,
                      kernel_protocol_minor);
}


/*
 * 校验标准响应头（不含签名字节），并回填字段。
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
    out->kernel_state = 0;
    out->kernel_reason = 0;
    out->kernel_capabilities = 0;
    out->kernel_protocol_major = 0;
    out->kernel_protocol_minor = 0;
    return (uint16_t)VTY_SVC_STATUS_OK;
}

/*
 * 校验 KernelStatus 响应头。与标准解码的差异只在 48..63 区：
 * 该区承载内核状态，必须由调用方按签名覆盖范围一并校验签名。
 */
static inline uint16_t vty_svc_response_decode_kernel(
    const uint8_t *raw,
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
        vty_svc_get_u32le(raw + 36) != 0) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    out->status = vty_svc_get_u16le(raw + 6);
    out->request_id = vty_svc_get_u32le(raw + 8);
    out->retry_after_sec = vty_svc_get_u32le(raw + 12);
    out->nonce_lo = vty_svc_get_u64le(raw + 16);
    out->nonce_hi = vty_svc_get_u64le(raw + 24);
    out->remaining_tokens = vty_svc_get_u32le(raw + 32);
    out->server_time_sec = vty_svc_get_u64le(raw + 40);
    out->kernel_state =
        vty_svc_get_u32le(raw + VTY_SVC_RESPONSE_KERNEL_STATE_OFF);
    out->kernel_reason =
        vty_svc_get_u32le(raw + VTY_SVC_RESPONSE_KERNEL_REASON_OFF);
    out->kernel_capabilities =
        vty_svc_get_u32le(raw + VTY_SVC_RESPONSE_KERNEL_CAPS_OFF);
    out->kernel_protocol_major =
        vty_svc_get_u16le(raw + VTY_SVC_RESPONSE_KERNEL_PROTOCOL_OFF);
    out->kernel_protocol_minor =
        vty_svc_get_u16le(raw + VTY_SVC_RESPONSE_KERNEL_PROTOCOL_OFF + 2u);
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
