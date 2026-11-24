#include <ntifs.h>

#include "vtg_ob.h"
#include "vtg_state.h"

/*
 * 内核头不提供 winnt.h 的进程/线程访问位，这里按稳定 ABI 值定义；
 * 这些位与用户态 OpenProcess/OpenThread 的访问掩码一致。
 */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE 0x0040
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA 0x0100
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE 0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION 0x0020
#endif

/*
 * 进程/线程句柄权限剥离。
 *
 * 驱动加载即注册回调；未 ARM 时表为空，回调直接放行。
 * 回调内不做分配、等待、文件 I/O 或用户态访问。
 */

/*
 * bootstrap 阶段父进程需要完整句柄权限：CreateProcess 在创建挂起态
 * worker 时要用 PROCESS_VM_WRITE / PROCESS_VM_OPERATION 初始化地址空间，
 * 并用线程句柄完成初始线程设置。父进程是刚发起 ARM 的宿主，属于信任
 * 边界内；外部进程仍走完整剥离，REGISTER 后父进程的新句柄也恢复完整
 * 剥离。窗口由 VtgStateAllowBootstrap 的 deadline 与 Confirmed 共同限制。
 */
#define VTG_PROCESS_STRIP_MASK (                    \
    PROCESS_VM_READ |                               \
    PROCESS_VM_WRITE |                              \
    PROCESS_VM_OPERATION |                          \
    PROCESS_CREATE_THREAD |                         \
    PROCESS_SUSPEND_RESUME |                        \
    PROCESS_TERMINATE |                             \
    PROCESS_DUP_HANDLE |                            \
    PROCESS_SET_QUOTA)

#define VTG_THREAD_STRIP_MASK (                     \
    THREAD_SET_CONTEXT |                            \
    THREAD_SUSPEND_RESUME |                         \
    THREAD_TERMINATE |                              \
    THREAD_SET_INFORMATION)

static PVOID g_ObRegistration = NULL;

/*
 * 受保护进程在初始化阶段需要 csrss.exe/lsass.exe 等 LocalSystem 调用者
 * 保留完整进程/线程访问：CreateProcess 初始句柄、DLL 加载与激活上下文
 * 创建都经由这些调用者。SYSTEM 不在威胁模型内；外部同用户进程仍按完整
 * 掩码剥离，REGISTER 前后一致。
 */
static BOOLEAN
VtgIsSystemCaller(VOID)
{
    PEPROCESS caller = PsGetCurrentProcess();
    PACCESS_TOKEN token;
    PVOID info = NULL;
    PTOKEN_USER user;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    UCHAR sidBuffer[SECURITY_MAX_SID_SIZE];
    PSID systemSid = (PSID)sidBuffer;
    BOOLEAN isSystem = FALSE;
    NTSTATUS status;

    if (PsGetProcessId(caller) == (HANDLE)(ULONG_PTR)4) {
        return TRUE;
    }
    token = PsReferencePrimaryToken(caller);
    if (token == NULL) {
        return FALSE;
    }
    status = SeQueryInformationToken(token, TokenUser, &info);
    PsDereferencePrimaryToken(token);
    if (!NT_SUCCESS(status) || info == NULL) {
        return FALSE;
    }
    user = (PTOKEN_USER)info;
    if (NT_SUCCESS(RtlInitializeSid(systemSid, &authority, 1))) {
        *RtlSubAuthoritySid(systemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;
        isSystem = RtlEqualSid(user->User.Sid, systemSid);
    }
    ExFreePool(info);
    return isSystem;
}

static PACCESS_MASK
VtgGetDesiredAccess(
    _In_ POB_PRE_OPERATION_INFORMATION Info
    )
{
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        return &Info->Parameters->CreateHandleInformation.DesiredAccess;
    }
    if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        return &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    }
    return NULL;
}

static OB_PREOP_CALLBACK_STATUS
VtgProcessPreOperation(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION Info
    )
{
    PEPROCESS target;
    PEPROCESS caller;
    PACCESS_MASK desired;

    UNREFERENCED_PARAMETER(RegistrationContext);

    target = (PEPROCESS)Info->Object;
    caller = PsGetCurrentProcess();
    desired = VtgGetDesiredAccess(Info);
    if (desired == NULL) {
        return OB_PREOP_SUCCESS;
    }
    if (!VtgStateAcquireCallbackProtection()) {
        return OB_PREOP_SUCCESS;
    }
    if (!VtgStateIsProtected(target)) {
        VtgStateReleaseCallbackProtection();
        return OB_PREOP_SUCCESS;
    }
    if (target == caller || VtgStateIsTrustedService(caller)) {
        VtgStateReleaseCallbackProtection();
        return OB_PREOP_SUCCESS;
    }

    if (VtgStateAllowBootstrap(target, caller) || VtgIsSystemCaller()) {
        /*
         * 父进程处于 bootstrap 阶段，或 LocalSystem 调用者正在初始化/加载
         * 受保护进程。SYSTEM 属于信任边界内；外部同用户进程不命中此分支。
         */
        VtgStateReleaseCallbackProtection();
        return OB_PREOP_SUCCESS;
    }

    *desired &= ~VTG_PROCESS_STRIP_MASK;
    VtgStateReleaseCallbackProtection();
    return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS
VtgThreadPreOperation(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION Info
    )
{
    PETHREAD target;
    PEPROCESS targetProcess;
    PEPROCESS caller;
    PACCESS_MASK desired;

    UNREFERENCED_PARAMETER(RegistrationContext);

    target = (PETHREAD)Info->Object;
    targetProcess = IoThreadToProcess(target);
    caller = PsGetCurrentProcess();
    desired = VtgGetDesiredAccess(Info);
    if (desired == NULL) {
        return OB_PREOP_SUCCESS;
    }
    if (!VtgStateAcquireCallbackProtection()) {
        return OB_PREOP_SUCCESS;
    }
    if (!VtgStateIsProtected(targetProcess)) {
        VtgStateReleaseCallbackProtection();
        return OB_PREOP_SUCCESS;
    }
    if (targetProcess == caller || VtgStateIsTrustedService(caller)) {
        VtgStateReleaseCallbackProtection();
        return OB_PREOP_SUCCESS;
    }

    if (VtgStateAllowBootstrap(targetProcess, caller) || VtgIsSystemCaller()) {
        VtgStateReleaseCallbackProtection();
        return OB_PREOP_SUCCESS;
    }

    *desired &= ~VTG_THREAD_STRIP_MASK;
    VtgStateReleaseCallbackProtection();
    return OB_PREOP_SUCCESS;
}

NTSTATUS
VtgObInit(VOID)
{
    UNICODE_STRING altitude;
    OB_OPERATION_REGISTRATION operations[2];
    OB_CALLBACK_REGISTRATION registration;

    RtlInitUnicodeString(&altitude, L"321000");

    RtlZeroMemory(operations, sizeof(operations));
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = VtgProcessPreOperation;
    operations[0].PostOperation = NULL;

    operations[1].ObjectType = PsThreadType;
    operations[1].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = VtgThreadPreOperation;
    operations[1].PostOperation = NULL;

    RtlZeroMemory(&registration, sizeof(registration));
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 2;
    registration.Altitude = altitude;
    registration.RegistrationContext = NULL;
    registration.OperationRegistration = operations;

    return ObRegisterCallbacks(&registration, &g_ObRegistration);
}

VOID
VtgObUninit(VOID)
{
    if (g_ObRegistration != NULL) {
        ObUnRegisterCallbacks(g_ObRegistration);
        g_ObRegistration = NULL;
    }
}
