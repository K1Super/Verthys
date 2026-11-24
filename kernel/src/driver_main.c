#include <ntifs.h>
#include <wdf.h>

#include "vtg_ioctl.h"
#include "vtg_notify.h"
#include "vtg_ob.h"
#include "vtg_state.h"

/*
 * VerthysGuard 驱动入口与设备生命周期。
 *
 * Round 1 只建立非 PnP 设备、IOCTL 队列与只读状态查询；
 * 不注册进程回调、不剥离句柄、不接触文件或密钥。
 */

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD VtgEvtDriverUnload;

static NTSTATUS
VtgCreateDevice(
    _In_ WDFDRIVER Driver
    )
{
    NTSTATUS status;
    WDFDEVICE device = NULL;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDF_IO_QUEUE_CONFIG queueConfig;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLinkName;
    UNICODE_STRING sddl;

    RtlInitUnicodeString(&sddl, VTG_DEVICE_SDDL);
    deviceInit = WdfControlDeviceInitAllocate(Driver, &sddl);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);

    RtlInitUnicodeString(&deviceName, VTG_DEVICE_NAME);
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    RtlInitUnicodeString(&symLinkName, VTG_SYMLINK_NAME);
    status = WdfDeviceCreateSymbolicLink(device, &symLinkName);
    if (!NT_SUCCESS(status)) {
        WdfObjectDelete(device);
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = VtgEvtIoDeviceControl;

    status = WdfIoQueueCreate(
        device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        WdfObjectDelete(device);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver = NULL;

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = VtgEvtDriverUnload;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        &driver);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = VtgStateInit();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = VtgNotifyInit();
    if (!NT_SUCCESS(status)) {
        VtgStateUninit();
        return status;
    }

    status = VtgObInit();
    if (!NT_SUCCESS(status)) {
        VtgNotifyUninit();
        VtgStateUninit();
        return status;
    }

    status = VtgCreateDevice(driver);
    if (!NT_SUCCESS(status)) {
        VtgObUninit();
        VtgNotifyUninit();
        VtgStateUninit();
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
VtgEvtDriverUnload(
    _In_ WDFDRIVER Driver
    )
{
    /*
     * 设备、符号链接与队列都由 WDF 作为驱动子对象管理；
     * 卸载时 WDF 会在队列排空后删除它们。
     * 回调与进程通知必须先注销，再释放受保护进程表引用。
     */
    UNREFERENCED_PARAMETER(Driver);
    VtgObUninit();
    VtgNotifyUninit();
    VtgStateUninit();
}
