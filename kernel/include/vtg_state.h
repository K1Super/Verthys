#ifndef VTG_STATE_H
#define VTG_STATE_H

#include <ntifs.h>

#include "vtg_protocol.h"

/*
 * 受保护进程表与内核防护状态。
 *
 * 并发契约：
 * - 所有公开函数可以在 PASSIVE_LEVEL 调用；
 * - Ob 回调只调用查询函数，不在回调中分配、等待或做文件 I/O；
 * - 进程对象引用由表项持有，进程退出或 DISARM 时释放。
 */

NTSTATUS VtgStateInit(VOID);
VOID VtgStateUninit(VOID);

NTSTATUS VtgStateArm(_In_ const VTG_ARM_IN *Arm);
VOID VtgStateDisarm(VOID);

NTSTATUS VtgStateRegisterProcess(_In_ const VTG_REGISTER_IN *Register);
NTSTATUS VtgStateUnregisterProcess(_In_ const VTG_REGISTER_IN *Register);

VOID VtgStateQueryStatus(
    _Out_ VTG_STATE *State,
    _Out_ VTG_REASON *Reason,
    _Out_ ULONG *ProtectedCount,
    _Out_ ULONGLONG *ActiveSince,
    _Out_ ULONG *LastError);

BOOLEAN VtgStateIsProtected(_In_ PEPROCESS Process);
BOOLEAN VtgStateIsTrustedService(_In_ PEPROCESS Process);
BOOLEAN VtgStateAllowBootstrap(
    _In_ PEPROCESS Process,
    _In_ PEPROCESS CallerProcess);

BOOLEAN VtgStateAcquireCallbackProtection(VOID);
VOID VtgStateReleaseCallbackProtection(VOID);

VOID VtgStateOnProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath);

VOID VtgStateOnProcessExit(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId);

#endif /* VTG_STATE_H */
