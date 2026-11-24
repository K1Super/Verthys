#include <ntifs.h>

#include "vtg_state.h"

/*
 * 受保护进程表与 ARM 状态。
 *
 * 设计约束：
 * - 进程身份由 PID、创建时间和映像路径共同校验，PID 不能单独作为键；
 * - 表项持有进程对象引用，进程退出或 DISARM 时释放；
 * - 查询路径只做短扫描，不在 Ob 回调中分配或等待。
 */

/*
 * 父进程完成 Job/DACL/REGISTER 的 bootstrap 窗口。
 * 5 秒按 100ns 计时；窗口只对 bootstrap 表项的父进程生效，外部进程
 * 始终使用完整剥离掩码，因此不会扩大攻击面。
 */
#define VTG_BOOTSTRAP_TIMEOUT_100NS (5ull * 1000ull * 1000ull * 10ull)

typedef struct _VTG_PROTECTED_ENTRY {
    PEPROCESS Process;
    PEPROCESS ParentProcess;
    ULONG ParentProcessId;
    ULONGLONG BootstrapDeadline;
    BOOLEAN Confirmed;
    BOOLEAN InUse;
} VTG_PROTECTED_ENTRY;

static EX_PUSH_LOCK g_Lock;
static EX_RUNDOWN_REF g_CallbackRundown;
static VTG_PROTECTED_ENTRY g_Entries[VTG_MAX_PROTECTED_PROCESSES];
static WCHAR g_ProtectedImagePath[VTG_MAX_IMAGE_PATH_CHARS];
static USHORT g_ProtectedImagePathLength;

static VTG_STATE g_State;
static VTG_REASON g_Reason;
static ULONG g_ProtectedCount;
static ULONGLONG g_ActiveSince;
static ULONG g_LastError;

static PEPROCESS g_ServiceProcess;

static NTSTATUS
VtgBuildUnicodeString(
    _In_reads_(VTG_MAX_IMAGE_PATH_CHARS) const WCHAR *Text,
    _Out_ UNICODE_STRING *Value
    )
{
    USHORT length = 0;

    if (Text == NULL || Value == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    while (length < VTG_MAX_IMAGE_PATH_CHARS && Text[length] != L'\0') {
        length++;
    }
    if (length == 0 || length >= VTG_MAX_IMAGE_PATH_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }

    Value->Length = (USHORT)(length * sizeof(WCHAR));
    Value->MaximumLength = (USHORT)((length + 1) * sizeof(WCHAR));
    Value->Buffer = (PWCH)Text;
    return STATUS_SUCCESS;
}

static VOID
VtgBuildProtectedPathLocked(
    _Out_ UNICODE_STRING *Value
    )
{
    Value->Length = g_ProtectedImagePathLength;
    Value->MaximumLength = (USHORT)(g_ProtectedImagePathLength + sizeof(WCHAR));
    Value->Buffer = g_ProtectedImagePath;
}

static NTSTATUS
VtgValidateIdentity(
    _In_ const VTG_PROCESS_IDENTITY *Identity,
    _In_opt_ PCUNICODE_STRING ExpectedImage,
    _Out_ PEPROCESS *Process
    )
{
    NTSTATUS status;
    UNICODE_STRING identityPath;
    PUNICODE_STRING imageName = NULL;

    if (Identity == NULL || Process == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Process = NULL;

    status = VtgBuildUnicodeString(Identity->ImagePath, &identityPath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)Identity->ProcessId,
        Process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if ((ULONGLONG)PsGetProcessCreateTimeQuadPart(*Process) !=
        Identity->CreationTime) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    status = SeLocateProcessImageName(*Process, &imageName);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    if (!RtlEqualUnicodeString(&identityPath, imageName, TRUE)) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    if (ExpectedImage != NULL &&
        !RtlEqualUnicodeString(ExpectedImage, imageName, TRUE)) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    status = STATUS_SUCCESS;

Exit:
    if (imageName != NULL) {
        ExFreePool(imageName);
    }
    if (!NT_SUCCESS(status) && *Process != NULL) {
        ObDereferenceObject(*Process);
        *Process = NULL;
    }
    return status;
}

static NTSTATUS
VtgAddEntryLocked(
    _In_ PEPROCESS Process,
    _In_opt_ PEPROCESS ParentProcess,
    _In_ ULONG ParentProcessId,
    _In_ BOOLEAN Confirmed
    )
{
    ULONG index;
    ULONG freeIndex = VTG_MAX_PROTECTED_PROCESSES;

    for (index = 0; index < VTG_MAX_PROTECTED_PROCESSES; index++) {
        if (g_Entries[index].InUse && g_Entries[index].Process == Process) {
            if (Confirmed) {
                g_Entries[index].Confirmed = TRUE;
            }
            if (ParentProcessId != 0) {
                g_Entries[index].ParentProcessId = ParentProcessId;
            }
            return STATUS_SUCCESS;
        }
        if (!g_Entries[index].InUse && freeIndex == VTG_MAX_PROTECTED_PROCESSES) {
            freeIndex = index;
        }
    }

    if (freeIndex == VTG_MAX_PROTECTED_PROCESSES) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ObReferenceObject(Process);
    g_Entries[freeIndex].Process = Process;
    g_Entries[freeIndex].ParentProcess = NULL;
    g_Entries[freeIndex].ParentProcessId = ParentProcessId;
    if (ParentProcess != NULL) {
        ObReferenceObject(ParentProcess);
        g_Entries[freeIndex].ParentProcess = ParentProcess;
    }
    g_Entries[freeIndex].BootstrapDeadline =
        KeQueryInterruptTime() + VTG_BOOTSTRAP_TIMEOUT_100NS;
    g_Entries[freeIndex].Confirmed = Confirmed;
    g_Entries[freeIndex].InUse = TRUE;

    g_ProtectedCount++;
    if (g_ActiveSince == 0) {
        g_ActiveSince = KeQueryInterruptTime();
    }
    g_State = VTG_STATE_ACTIVE;
    g_Reason = VTG_REASON_NONE;
    return STATUS_SUCCESS;
}

NTSTATUS
VtgStateInit(VOID)
{
    ExInitializePushLock(&g_Lock);
    ExInitializeRundownProtection(&g_CallbackRundown);
    RtlZeroMemory(g_Entries, sizeof(g_Entries));
    RtlZeroMemory(g_ProtectedImagePath, sizeof(g_ProtectedImagePath));
    g_ProtectedImagePathLength = 0;
    g_State = VTG_STATE_UNARMED;
    g_Reason = VTG_REASON_NONE;
    g_ProtectedCount = 0;
    g_ActiveSince = 0;
    g_LastError = 0;
    g_ServiceProcess = NULL;
    return STATUS_SUCCESS;
}

VOID
VtgStateDisarm(VOID)
{
    ULONG index;
    ULONG releaseCount = 0;
    PEPROCESS toRelease[VTG_MAX_PROTECTED_PROCESSES];
    PEPROCESS parentsToRelease[VTG_MAX_PROTECTED_PROCESSES];
    PEPROCESS serviceToRelease = NULL;

    ExAcquirePushLockExclusive(&g_Lock);

    for (index = 0; index < VTG_MAX_PROTECTED_PROCESSES; index++) {
        if (g_Entries[index].InUse) {
            toRelease[releaseCount] = g_Entries[index].Process;
            parentsToRelease[releaseCount] = g_Entries[index].ParentProcess;
            releaseCount++;
            RtlZeroMemory(&g_Entries[index], sizeof(g_Entries[index]));
        }
    }
    if (g_ServiceProcess != NULL) {
        serviceToRelease = g_ServiceProcess;
        g_ServiceProcess = NULL;
    }

    RtlZeroMemory(g_ProtectedImagePath, sizeof(g_ProtectedImagePath));
    g_ProtectedImagePathLength = 0;
    g_State = VTG_STATE_UNARMED;
    g_Reason = VTG_REASON_NONE;
    g_ProtectedCount = 0;
    g_ActiveSince = 0;
    g_LastError = 0;

    ExReleasePushLockExclusive(&g_Lock);

    for (index = 0; index < releaseCount; index++) {
        ObDereferenceObject(toRelease[index]);
        if (parentsToRelease[index] != NULL) {
            ObDereferenceObject(parentsToRelease[index]);
        }
    }
    if (serviceToRelease != NULL) {
        ObDereferenceObject(serviceToRelease);
    }
}

VOID
VtgStateUninit(VOID)
{
    /*
     * 回调注销后仍可能有在途 Ob 回调；先等待 rundown 归零，
     * 再释放进程引用，避免卸载与回调并发。
     */
    ExWaitForRundownProtectionRelease(&g_CallbackRundown);
    VtgStateDisarm();
}

NTSTATUS
VtgStateArm(
    _In_ const VTG_ARM_IN *Arm
    )
{
    NTSTATUS status;
    UNICODE_STRING protectedPath;
    PEPROCESS serviceProcess = NULL;

    if (Arm == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = VtgBuildUnicodeString(Arm->ProtectedImagePath, &protectedPath);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = VtgValidateIdentity(&Arm->Service, NULL, &serviceProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    VtgStateDisarm();

    ExAcquirePushLockExclusive(&g_Lock);
    RtlCopyMemory(
        g_ProtectedImagePath,
        protectedPath.Buffer,
        protectedPath.Length + sizeof(WCHAR));
    g_ProtectedImagePathLength = protectedPath.Length;
    g_ServiceProcess = serviceProcess;
    g_State = VTG_STATE_ARMED;
    g_Reason = VTG_REASON_NONE;
    g_ProtectedCount = 0;
    g_ActiveSince = 0;
    g_LastError = 0;
    ExReleasePushLockExclusive(&g_Lock);

    return STATUS_SUCCESS;
}

NTSTATUS
VtgStateRegisterProcess(
    _In_ const VTG_REGISTER_IN *Register
    )
{
    NTSTATUS status;
    UNICODE_STRING expectedPath;
    WCHAR expectedBuffer[VTG_MAX_IMAGE_PATH_CHARS];
    PEPROCESS process = NULL;

    if (Register == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ExAcquirePushLockShared(&g_Lock);
    if (g_State != VTG_STATE_ARMED && g_State != VTG_STATE_ACTIVE) {
        ExReleasePushLockShared(&g_Lock);
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlCopyMemory(
        expectedBuffer,
        g_ProtectedImagePath,
        g_ProtectedImagePathLength + sizeof(WCHAR));
    expectedPath.Length = g_ProtectedImagePathLength;
    expectedPath.MaximumLength =
        (USHORT)(g_ProtectedImagePathLength + sizeof(WCHAR));
    expectedPath.Buffer = expectedBuffer;
    ExReleasePushLockShared(&g_Lock);

    status = VtgValidateIdentity(&Register->Process, &expectedPath, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ExAcquirePushLockExclusive(&g_Lock);
    if (g_State != VTG_STATE_ARMED && g_State != VTG_STATE_ACTIVE) {
        status = STATUS_INVALID_DEVICE_STATE;
    } else {
        status = VtgAddEntryLocked(
            process,
            NULL,
            0,
            TRUE);
        if (!NT_SUCCESS(status)) {
            g_State = VTG_STATE_DEGRADED;
            g_Reason = VTG_REASON_REGISTER_FAILED;
            g_LastError = (ULONG)status;
        }
    }
    ExReleasePushLockExclusive(&g_Lock);

    ObDereferenceObject(process);
    return status;
}

NTSTATUS
VtgStateUnregisterProcess(
    _In_ const VTG_REGISTER_IN *Register
    )
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PEPROCESS entryProcess = NULL;
    PEPROCESS entryParent = NULL;
    ULONG index;
    BOOLEAN found = FALSE;

    if (Register == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = VtgValidateIdentity(&Register->Process, NULL, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ExAcquirePushLockExclusive(&g_Lock);
    for (index = 0; index < VTG_MAX_PROTECTED_PROCESSES; index++) {
        if (g_Entries[index].InUse && g_Entries[index].Process == process) {
            entryProcess = g_Entries[index].Process;
            entryParent = g_Entries[index].ParentProcess;
            RtlZeroMemory(&g_Entries[index], sizeof(g_Entries[index]));
            if (g_ProtectedCount > 0) {
                g_ProtectedCount--;
            }
            found = TRUE;
            break;
        }
    }
    if (found && g_ProtectedCount == 0) {
        g_State = VTG_STATE_ARMED;
        g_ActiveSince = 0;
    }
    ExReleasePushLockExclusive(&g_Lock);

    if (entryProcess != NULL) {
        ObDereferenceObject(entryProcess);
    }
    if (entryParent != NULL) {
        ObDereferenceObject(entryParent);
    }
    ObDereferenceObject(process);
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

VOID
VtgStateQueryStatus(
    _Out_ VTG_STATE *State,
    _Out_ VTG_REASON *Reason,
    _Out_ ULONG *ProtectedCount,
    _Out_ ULONGLONG *ActiveSince,
    _Out_ ULONG *LastError
    )
{
    ExAcquirePushLockShared(&g_Lock);
    if (State != NULL) {
        *State = g_State;
    }
    if (Reason != NULL) {
        *Reason = g_Reason;
    }
    if (ProtectedCount != NULL) {
        *ProtectedCount = g_ProtectedCount;
    }
    if (ActiveSince != NULL) {
        *ActiveSince = g_ActiveSince;
    }
    if (LastError != NULL) {
        *LastError = g_LastError;
    }
    ExReleasePushLockShared(&g_Lock);
}

BOOLEAN
VtgStateAcquireCallbackProtection(VOID)
{
    return ExAcquireRundownProtection(&g_CallbackRundown);
}

VOID
VtgStateReleaseCallbackProtection(VOID)
{
    ExReleaseRundownProtection(&g_CallbackRundown);
}

BOOLEAN
VtgStateIsProtected(
    _In_ PEPROCESS Process
    )
{
    ULONG index;
    BOOLEAN protected = FALSE;

    ExAcquirePushLockShared(&g_Lock);
    for (index = 0; index < VTG_MAX_PROTECTED_PROCESSES; index++) {
        if (g_Entries[index].InUse && g_Entries[index].Process == Process) {
            protected = TRUE;
            break;
        }
    }
    ExReleasePushLockShared(&g_Lock);
    return protected;
}

BOOLEAN
VtgStateIsTrustedService(
    _In_ PEPROCESS Process
    )
{
    BOOLEAN trusted;

    ExAcquirePushLockShared(&g_Lock);
    trusted = (g_ServiceProcess != NULL && g_ServiceProcess == Process);
    ExReleasePushLockShared(&g_Lock);
    return trusted;
}

BOOLEAN
VtgStateAllowBootstrap(
    _In_ PEPROCESS Process,
    _In_ PEPROCESS CallerProcess
    )
{
    ULONG index;
    BOOLEAN allowed = FALSE;
    ULONGLONG now = KeQueryInterruptTime();
    ULONG callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    ExAcquirePushLockShared(&g_Lock);
    for (index = 0; index < VTG_MAX_PROTECTED_PROCESSES; index++) {
        if (g_Entries[index].InUse &&
            g_Entries[index].Process == Process &&
            !g_Entries[index].Confirmed &&
            (g_Entries[index].ParentProcess == CallerProcess ||
             (g_Entries[index].ParentProcessId != 0 &&
              g_Entries[index].ParentProcessId == callerPid)) &&
            now <= g_Entries[index].BootstrapDeadline) {
            allowed = TRUE;
            break;
        }
    }
    ExReleasePushLockShared(&g_Lock);
    return allowed;
}

static BOOLEAN
VtgBaseNameEquals(
    _In_ PCUNICODE_STRING Left,
    _In_ PCUNICODE_STRING Right
    )
{
    USHORT leftIndex = 0;
    USHORT rightIndex = 0;
    USHORT index;
    UNICODE_STRING leftBase;
    UNICODE_STRING rightBase;

    if (Left == NULL || Right == NULL ||
        Left->Buffer == NULL || Right->Buffer == NULL) {
        return FALSE;
    }

    for (index = 0; index < Left->Length / sizeof(WCHAR); index++) {
        if (Left->Buffer[index] == L'\\') {
            leftIndex = (USHORT)(index + 1);
        }
    }
    for (index = 0; index < Right->Length / sizeof(WCHAR); index++) {
        if (Right->Buffer[index] == L'\\') {
            rightIndex = (USHORT)(index + 1);
        }
    }

    leftBase.Length = (USHORT)(Left->Length - leftIndex * sizeof(WCHAR));
    leftBase.MaximumLength = leftBase.Length;
    leftBase.Buffer = Left->Buffer + leftIndex;
    rightBase.Length = (USHORT)(Right->Length - rightIndex * sizeof(WCHAR));
    rightBase.MaximumLength = rightBase.Length;
    rightBase.Buffer = Right->Buffer + rightIndex;

    if (leftBase.Length == 0 || rightBase.Length == 0) {
        return FALSE;
    }
    return RtlEqualUnicodeString(&leftBase, &rightBase, TRUE);
}

VOID
VtgStateOnProcessCreate(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ParentProcessId,
    _In_opt_ PCUNICODE_STRING ImagePath
    )
{
    NTSTATUS status;
    UNICODE_STRING expectedPath;
    PUNICODE_STRING imageName = NULL;
    PEPROCESS parentProcess = NULL;
    BOOLEAN fullMatch = FALSE;
    BOOLEAN sameBase = FALSE;
    BOOLEAN matches = FALSE;
    BOOLEAN armed;

    if (Process == NULL || ImagePath == NULL) {
        return;
    }

    UNREFERENCED_PARAMETER(ProcessId);

    ExAcquirePushLockShared(&g_Lock);
    armed = (g_State == VTG_STATE_ARMED || g_State == VTG_STATE_ACTIVE);
    if (armed) {
        VtgBuildProtectedPathLocked(&expectedPath);
        fullMatch = RtlEqualUnicodeString(&expectedPath, ImagePath, TRUE);
        if (!fullMatch) {
            sameBase = VtgBaseNameEquals(&expectedPath, ImagePath);
        }
    }
    ExReleasePushLockShared(&g_Lock);
    if (!armed || (!fullMatch && !sameBase)) {
        return;
    }

    if (!fullMatch) {
        status = SeLocateProcessImageName(Process, &imageName);
        if (!NT_SUCCESS(status)) {
            return;
        }

        ExAcquirePushLockShared(&g_Lock);
        if (g_State == VTG_STATE_ARMED || g_State == VTG_STATE_ACTIVE) {
            VtgBuildProtectedPathLocked(&expectedPath);
            matches = RtlEqualUnicodeString(&expectedPath, imageName, TRUE);
        }
        ExReleasePushLockShared(&g_Lock);
        ExFreePool(imageName);
        if (!matches) {
            return;
        }
    }

    if (ParentProcessId != NULL) {
        (VOID)PsLookupProcessByProcessId(ParentProcessId, &parentProcess);
    }

    ExAcquirePushLockExclusive(&g_Lock);
    if (g_State == VTG_STATE_ARMED || g_State == VTG_STATE_ACTIVE) {
        status = VtgAddEntryLocked(
            Process,
            parentProcess,
            (ULONG)(ULONG_PTR)ParentProcessId,
            FALSE);
        if (!NT_SUCCESS(status)) {
            g_State = VTG_STATE_DEGRADED;
            g_Reason = VTG_REASON_REGISTER_FAILED;
            g_LastError = (ULONG)status;
        }
    }
    ExReleasePushLockExclusive(&g_Lock);

    if (parentProcess != NULL) {
        ObDereferenceObject(parentProcess);
    }
}

VOID
VtgStateOnProcessExit(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId
    )
{
    ULONG index;
    PEPROCESS entryProcess = NULL;
    PEPROCESS entryParent = NULL;
    PEPROCESS serviceProcess = NULL;

    UNREFERENCED_PARAMETER(ProcessId);

    ExAcquirePushLockExclusive(&g_Lock);

    for (index = 0; index < VTG_MAX_PROTECTED_PROCESSES; index++) {
        if (g_Entries[index].InUse && g_Entries[index].Process == Process) {
            entryProcess = g_Entries[index].Process;
            entryParent = g_Entries[index].ParentProcess;
            RtlZeroMemory(&g_Entries[index], sizeof(g_Entries[index]));
            if (g_ProtectedCount > 0) {
                g_ProtectedCount--;
            }
            break;
        }
    }

    if (g_ServiceProcess != NULL && g_ServiceProcess == Process) {
        serviceProcess = g_ServiceProcess;
        g_ServiceProcess = NULL;
        g_State = VTG_STATE_DEGRADED;
        g_Reason = VTG_REASON_PROCESS_EXITED;
    }

    if (g_ProtectedCount == 0 && g_State == VTG_STATE_ACTIVE) {
        g_State = VTG_STATE_ARMED;
        g_ActiveSince = 0;
    }

    ExReleasePushLockExclusive(&g_Lock);

    if (entryProcess != NULL) {
        ObDereferenceObject(entryProcess);
    }
    if (entryParent != NULL) {
        ObDereferenceObject(entryParent);
    }
    if (serviceProcess != NULL) {
        ObDereferenceObject(serviceProcess);
    }
}
