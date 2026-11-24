#include <ntifs.h>

#include "vtg_notify.h"
#include "vtg_state.h"

/*
 * 进程创建/退出通知。
 *
 * 创建通知只做映像路径匹配与表项添加；退出通知释放进程引用。
 * 通知类能力不能阻断进程创建，也不在此处终止进程。
 */

static VOID
VtgProcessNotify(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    /*
     * 卸载路径先注销通知再等待 rundown。这里获取保护引用，避免
     * 通知回调与 VtgStateUninit 并发释放状态。
     */
    if (!VtgStateAcquireCallbackProtection()) {
        return;
    }

    if (CreateInfo != NULL) {
        VtgStateOnProcessCreate(
            Process,
            ProcessId,
            CreateInfo->ParentProcessId,
            CreateInfo->ImageFileName);
    } else {
        VtgStateOnProcessExit(Process, ProcessId);
    }

    VtgStateReleaseCallbackProtection();
}

NTSTATUS
VtgNotifyInit(VOID)
{
    return PsSetCreateProcessNotifyRoutineEx(VtgProcessNotify, FALSE);
}

VOID
VtgNotifyUninit(VOID)
{
    (VOID)PsSetCreateProcessNotifyRoutineEx(VtgProcessNotify, TRUE);
}
