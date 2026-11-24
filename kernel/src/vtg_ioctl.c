#include <ntifs.h>
#include <wdf.h>

#include "vtg_ioctl.h"
#include "vtg_state.h"

/*
 * IOCTL 面：Ping、QueryStatus、ARM、DISARM、Register、Unregister。
 *
 * 所有命令都返回定长状态响应，服务据此更新状态机；
 * 未实现的统计/事件命令返回 STATUS_NOT_SUPPORTED。
 */

static VTG_STATUS
VtgMapStatus(
    _In_ NTSTATUS Status
    )
{
    switch (Status) {
    case STATUS_SUCCESS:
        return VTG_STATUS_OK;
    case STATUS_INVALID_PARAMETER:
        return VTG_STATUS_INVALID_REQUEST;
    case STATUS_INVALID_DEVICE_STATE:
        return VTG_STATUS_NOT_ARMED;
    case STATUS_NOT_FOUND:
        return VTG_STATUS_PROCESS_NOT_FOUND;
    case STATUS_INSUFFICIENT_RESOURCES:
        return VTG_STATUS_CAPACITY_EXCEEDED;
    case STATUS_ACCESS_DENIED:
        return VTG_STATUS_ACCESS_DENIED;
    default:
        return VTG_STATUS_INTERNAL;
    }
}

static BOOLEAN
VtgValidateHeader(
    _In_ const VTG_HEADER *Header,
    _In_ size_t ExpectedSize
    )
{
    if (Header->Size != (VTG_U32)ExpectedSize) {
        return FALSE;
    }
    if (Header->Major != VTG_PROTOCOL_MAJOR ||
        Header->Minor != VTG_PROTOCOL_MINOR) {
        return FALSE;
    }
    if (Header->Flags != 0 || Header->Reserved != 0 || Header->Status != 0) {
        return FALSE;
    }
    return TRUE;
}

static VOID
VtgCompleteStatus(
    _In_ WDFREQUEST Request,
    _In_ const VTG_HEADER *RequestHeader,
    _In_ VTG_STATUS ResultStatus
    )
{
    NTSTATUS status;
    PVOID output = NULL;
    size_t outputSize = 0;
    VTG_STATUS_OUT *response = NULL;
    VTG_STATE state = VTG_STATE_UNARMED;
    VTG_REASON reason = VTG_REASON_NONE;
    ULONG protectedCount = 0;
    ULONGLONG activeSince = 0;
    ULONG lastError = 0;
    VTG_U32 requestCommand;
    VTG_U64 requestId;

    if (RequestHeader == NULL) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    /*
     * METHOD_BUFFERED 下输入与输出可能共用同一系统缓冲。必须在
     * RetrieveOutputBuffer/清零之前保存请求头字段，否则 Command 与
     * RequestId 会被一起清零，服务侧响应校验恒失败。
     */
    requestCommand = RequestHeader->Command;
    requestId = RequestHeader->RequestId;

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(VTG_STATUS_OUT),
        &output,
        &outputSize);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
        return;
    }

    VtgStateQueryStatus(
        &state,
        &reason,
        &protectedCount,
        &activeSince,
        &lastError);

    RtlZeroMemory(output, sizeof(VTG_STATUS_OUT));
    response = (VTG_STATUS_OUT *)output;
    response->Header.Size = sizeof(VTG_STATUS_OUT);
    response->Header.Major = VTG_PROTOCOL_MAJOR;
    response->Header.Minor = VTG_PROTOCOL_MINOR;
    response->Header.Command = requestCommand;
    response->Header.RequestId = requestId;
    response->Header.Status = (VTG_U32)ResultStatus;
    response->State = (VTG_U32)state;
    response->Reason = (VTG_U32)reason;
    response->ProtocolMajor = VTG_PROTOCOL_MAJOR;
    response->ProtocolMinor = VTG_PROTOCOL_MINOR;
    response->Capabilities =
        VTG_CAP_QUERY_STATUS | VTG_CAP_PROTECT_PROCESS;
    response->ProtectedCount = protectedCount;
    response->ActiveSince = activeSince;
    response->LastError = lastError;

    WdfRequestCompleteWithInformation(
        Request,
        STATUS_SUCCESS,
        (ULONG_PTR)sizeof(VTG_STATUS_OUT));
}

static size_t
VtgExpectedInputSize(
    _In_ ULONG IoControlCode
    )
{
    switch (IoControlCode) {
    case VTG_IOCTL_ARM:
        return sizeof(VTG_ARM_IN);
    case VTG_IOCTL_REGISTER_PROCESS:
    case VTG_IOCTL_UNREGISTER_PROCESS:
        return sizeof(VTG_REGISTER_IN);
    default:
        return sizeof(VTG_HEADER);
    }
}

static BOOLEAN
VtgCommandMatches(
    _In_ ULONG IoControlCode,
    _In_ const VTG_HEADER *Header
    )
{
    switch (IoControlCode) {
    case VTG_IOCTL_PING:
        return Header->Command == VTG_CMD_PING;
    case VTG_IOCTL_ARM:
        return Header->Command == VTG_CMD_ARM;
    case VTG_IOCTL_DISARM:
        return Header->Command == VTG_CMD_DISARM;
    case VTG_IOCTL_REGISTER_PROCESS:
        return Header->Command == VTG_CMD_REGISTER_PROCESS;
    case VTG_IOCTL_UNREGISTER_PROCESS:
        return Header->Command == VTG_CMD_UNREGISTER_PROCESS;
    case VTG_IOCTL_QUERY_STATUS:
        return Header->Command == VTG_CMD_QUERY_STATUS;
    default:
        return TRUE;
    }
}

VOID
VtgEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    NTSTATUS status;
    PVOID input = NULL;
    size_t inputSize = 0;
    size_t expectedSize;
    const VTG_HEADER *header = NULL;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    expectedSize = VtgExpectedInputSize(IoControlCode);
    status = WdfRequestRetrieveInputBuffer(
        Request,
        expectedSize,
        &input,
        &inputSize);
    if (!NT_SUCCESS(status) || inputSize < expectedSize) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    header = (const VTG_HEADER *)input;
    if (!VtgValidateHeader(header, expectedSize) ||
        !VtgCommandMatches(IoControlCode, header)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    switch (IoControlCode) {
    case VTG_IOCTL_PING:
    case VTG_IOCTL_QUERY_STATUS:
        VtgCompleteStatus(Request, header, VTG_STATUS_OK);
        break;

    case VTG_IOCTL_ARM:
        status = VtgStateArm((const VTG_ARM_IN *)header);
        VtgCompleteStatus(Request, header, VtgMapStatus(status));
        break;

    case VTG_IOCTL_DISARM:
        VtgStateDisarm();
        VtgCompleteStatus(Request, header, VTG_STATUS_OK);
        break;

    case VTG_IOCTL_REGISTER_PROCESS:
        status = VtgStateRegisterProcess((const VTG_REGISTER_IN *)header);
        VtgCompleteStatus(Request, header, VtgMapStatus(status));
        break;

    case VTG_IOCTL_UNREGISTER_PROCESS:
        status = VtgStateUnregisterProcess((const VTG_REGISTER_IN *)header);
        VtgCompleteStatus(Request, header, VtgMapStatus(status));
        break;

    default:
        WdfRequestComplete(Request, STATUS_NOT_SUPPORTED);
        break;
    }
}
