#ifndef VTG_PROTOCOL_H
#define VTG_PROTOCOL_H

/*
 * 内核防护驱动的共享协议定义。
 *
 * 约束：
 * - 所有结构定长，禁止嵌入指针；
 * - 字段布局是服务与驱动的二进制契约，修改必须同步版本号；
 * - 本文件不得依赖用户态或内核态专属头文件，测试与服务客户端共用。
 */

#if defined(_KERNEL_MODE) || defined(_NTDDK_) || defined(_NTIFS_)
typedef UINT16 VTG_U16;
typedef UINT32 VTG_U32;
typedef UINT64 VTG_U64;
typedef WCHAR VTG_WCHAR;
#else
#include <stdint.h>
typedef uint16_t VTG_U16;
typedef uint32_t VTG_U32;
typedef uint64_t VTG_U64;
typedef wchar_t VTG_WCHAR;
#endif

#define VTG_PROTOCOL_MAJOR 1u
#define VTG_PROTOCOL_MINOR 0u

#define VTG_MAX_IMAGE_PATH_CHARS 520u
#define VTG_MAX_PROTECTED_PROCESSES 8u
#define VTG_MAX_EVENTS 64u

typedef enum _VTG_COMMAND {
    VTG_CMD_PING = 1,
    VTG_CMD_ARM = 2,
    VTG_CMD_DISARM = 3,
    VTG_CMD_REGISTER_PROCESS = 4,
    VTG_CMD_UNREGISTER_PROCESS = 5,
    VTG_CMD_QUERY_STATUS = 6,
    VTG_CMD_QUERY_STATS = 7,
    VTG_CMD_QUERY_EVENTS = 8
} VTG_COMMAND;

typedef enum _VTG_STATE {
    VTG_STATE_UNARMED = 0,
    VTG_STATE_ARMED = 1,
    VTG_STATE_ACTIVE = 2,
    VTG_STATE_DEGRADED = 3,
    VTG_STATE_LOST = 4
} VTG_STATE;

typedef enum _VTG_REASON {
    VTG_REASON_NONE = 0,
    VTG_REASON_NOT_INSTALLED = 1,
    VTG_REASON_STOPPED = 2,
    VTG_REASON_VERSION_MISMATCH = 3,
    VTG_REASON_UNSUPPORTED = 4,
    VTG_REASON_REGISTER_FAILED = 5,
    VTG_REASON_PROCESS_EXITED = 6,
    VTG_REASON_DRIVER_UNLOADED = 7,
    VTG_REASON_INTERNAL = 8
} VTG_REASON;

typedef enum _VTG_STATUS {
    VTG_STATUS_OK = 0,
    VTG_STATUS_INVALID_REQUEST = 1,
    VTG_STATUS_VERSION_MISMATCH = 2,
    VTG_STATUS_ACCESS_DENIED = 3,
    VTG_STATUS_NOT_ARMED = 4,
    VTG_STATUS_CAPACITY_EXCEEDED = 5,
    VTG_STATUS_PROCESS_NOT_FOUND = 6,
    VTG_STATUS_IDENTITY_MISMATCH = 7,
    VTG_STATUS_NOT_SUPPORTED = 8,
    VTG_STATUS_INTERNAL = 9
} VTG_STATUS;

typedef enum _VTG_CAPABILITY {
    VTG_CAP_QUERY_STATUS = 0x00000001u,
    VTG_CAP_PROTECT_PROCESS = 0x00000002u,
    VTG_CAP_EVENTS = 0x00000004u
} VTG_CAPABILITY;

#pragma pack(push, 8)

typedef struct _VTG_HEADER {
    VTG_U32 Size;
    VTG_U16 Major;
    VTG_U16 Minor;
    VTG_U32 Command;
    VTG_U32 Flags;
    VTG_U64 RequestId;
    VTG_U32 Status;
    VTG_U32 Reserved;
} VTG_HEADER;

typedef struct _VTG_PROCESS_IDENTITY {
    VTG_U32 ProcessId;
    VTG_U32 Reserved;
    VTG_U64 CreationTime;
    VTG_WCHAR ImagePath[VTG_MAX_IMAGE_PATH_CHARS];
} VTG_PROCESS_IDENTITY;

typedef struct _VTG_ARM_IN {
    VTG_HEADER Header;
    VTG_U32 Policy;
    VTG_U32 Flags;
    VTG_PROCESS_IDENTITY Service;
    VTG_WCHAR ProtectedImagePath[VTG_MAX_IMAGE_PATH_CHARS];
} VTG_ARM_IN;

typedef struct _VTG_REGISTER_IN {
    VTG_HEADER Header;
    VTG_PROCESS_IDENTITY Process;
    VTG_U32 Flags;
    VTG_U32 Reserved;
} VTG_REGISTER_IN;

typedef struct _VTG_STATUS_OUT {
    VTG_HEADER Header;
    VTG_U32 State;
    VTG_U32 Reason;
    VTG_U16 ProtocolMajor;
    VTG_U16 ProtocolMinor;
    VTG_U32 Capabilities;
    VTG_U32 ProtectedCount;
    VTG_U64 ActiveSince;
    VTG_U32 LastError;
    VTG_U32 Reserved;
} VTG_STATUS_OUT;

#pragma pack(pop)

#endif /* VTG_PROTOCOL_H */
