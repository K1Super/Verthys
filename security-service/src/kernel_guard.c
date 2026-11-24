/*
 * kernel_guard.c — 服务侧内核防护状态查询与生命周期命令
 *
 * 安全约束：
 *   - 只打开 SYSTEM-only 设备；ARM/REGISTER 的对象只能是已认证客户端进程；
 *   - 客户端路径先转换为 SeLocateProcessImageName 使用的 NT 设备路径，
 *     避免用户态 DOS 路径与内核返回值形式不一致导致身份校验失败；
 *   - 所有设备 I/O 都有上界，超时后取消，不阻塞服务工作线程；
 *   - 驱动缺失/未运行映射为显式状态，不抛出异常，不影响 P2 既有命令。
 */
#include "kernel_guard.h"

#include <windows.h>
#include <winioctl.h>
#include <string.h>
#include <wchar.h>

#include "service_util.h"
#include "vtg_ioctl.h"
#include "vtg_protocol.h"

#define VTY_KG_IO_TIMEOUT_MS 250u
#define VTY_KG_LIFECYCLE_TIMEOUT_MS 500u
#define VTY_KG_DEFAULT_DEVICE L"\\\\.\\VerthysGuard"

#define VTY_KG_MODE_NONE 0u
#define VTY_KG_MODE_WORKER_SELF 1u
#define VTY_KG_MODE_HOST_PREARM 2u

static SRWLOCK g_kg_lock = SRWLOCK_INIT;
static DWORD g_mode = VTY_KG_MODE_NONE;
static DWORD g_owner_pid;
static ULONGLONG g_owner_creation;
static DWORD g_bound_pid;
static ULONGLONG g_bound_creation;
static WCHAR g_armed_path[VTG_MAX_IMAGE_PATH_CHARS];
static volatile LONG g_request_seq;

static void kg_clear_state_locked(void)
{
    g_mode = VTY_KG_MODE_NONE;
    g_owner_pid = 0;
    g_owner_creation = 0;
    g_bound_pid = 0;
    g_bound_creation = 0;
    memset(g_armed_path, 0, sizeof(g_armed_path));
}

static void kg_set_unavailable(VtyKernelGuardStatus *out, uint32_t state,
                               uint32_t reason)
{
    out->state = state;
    out->reason = reason;
    out->capabilities = 0;
    out->protocol_major = 0;
    out->protocol_minor = 0;
}

static uint32_t kg_map_driver_state(uint32_t state)
{
    switch (state) {
    case VTG_STATE_UNARMED:
        return VTY_KERNEL_STATE_UNARMED;
    case VTG_STATE_ARMED:
        return VTY_KERNEL_STATE_ARMED;
    case VTG_STATE_ACTIVE:
        return VTY_KERNEL_STATE_ACTIVE;
    case VTG_STATE_DEGRADED:
        return VTY_KERNEL_STATE_DEGRADED;
    case VTG_STATE_LOST:
        return VTY_KERNEL_STATE_LOST;
    default:
        return VTY_KERNEL_STATE_UNKNOWN;
    }
}

static uint16_t kg_map_driver_result(uint32_t status)
{
    switch (status) {
    case VTG_STATUS_OK:
        return (uint16_t)VTY_SVC_STATUS_OK;
    case VTG_STATUS_INVALID_REQUEST:
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    case VTG_STATUS_ACCESS_DENIED:
    case VTG_STATUS_IDENTITY_MISMATCH:
        return (uint16_t)VTY_SVC_STATUS_DENIED;
    case VTG_STATUS_VERSION_MISMATCH:
    case VTG_STATUS_NOT_ARMED:
    case VTG_STATUS_CAPACITY_EXCEEDED:
    case VTG_STATUS_PROCESS_NOT_FOUND:
    case VTG_STATUS_NOT_SUPPORTED:
        return (uint16_t)VTY_SVC_STATUS_UNAVAILABLE;
    default:
        return (uint16_t)VTY_SVC_STATUS_INTERNAL;
    }
}

static void kg_fill_status(const VTG_STATUS_OUT *response,
                           VtyKernelGuardStatus *out)
{
    out->state = kg_map_driver_state(response->State);
    out->reason = response->Reason;
    out->capabilities = response->Capabilities;
    out->protocol_major = response->ProtocolMajor;
    out->protocol_minor = response->ProtocolMinor;
}

int vty_kernel_guard_dos_to_nt_path(const wchar_t *dos_path, wchar_t *out,
                                    size_t cap)
{
    wchar_t drive[3];
    wchar_t device[VTY_PATH_MAX];
    size_t device_len;
    size_t suffix_len;

    if (dos_path == NULL || out == NULL || cap == 0) return -1;
    if (wcslen(dos_path) < 3u) return -1;
    if (!((dos_path[0] >= L'A' && dos_path[0] <= L'Z') ||
          (dos_path[0] >= L'a' && dos_path[0] <= L'z'))) {
        return -1;
    }
    if (dos_path[1] != L':' ||
        (dos_path[2] != L'\\' && dos_path[2] != L'/')) {
        return -1;
    }

    drive[0] = dos_path[0];
    drive[1] = L':';
    drive[2] = L'\0';
    memset(device, 0, sizeof(device));
    if (QueryDosDeviceW(drive, device, VTY_PATH_MAX) == 0) return -1;
    device_len = wcslen(device);
    if (device_len == 0) return -1;

    suffix_len = wcslen(dos_path + 2);
    if (device_len + suffix_len + 1u > cap) return -1;
    memcpy(out, device, device_len * sizeof(wchar_t));
    memcpy(out + device_len, dos_path + 2,
           (suffix_len + 1u) * sizeof(wchar_t));
    return 0;
}

int vty_kernel_guard_is_worker_image(const wchar_t *image_path)
{
    const wchar_t *base;

    if (image_path == NULL || image_path[0] == L'\0') return 0;
    base = wcsrchr(image_path, L'\\');
    base = (base != NULL) ? base + 1 : image_path;
    return _wcsicmp(base, L"verthys-worker.exe") == 0 ||
           _wcsicmp(base, L"verthys-worker-x86_64-pc-windows-msvc.exe") == 0;
}

int vty_kernel_guard_is_host_image(const wchar_t *image_path)
{
    const wchar_t *base;

    if (image_path == NULL || image_path[0] == L'\0') return 0;
    base = wcsrchr(image_path, L'\\');
    base = (base != NULL) ? base + 1 : image_path;
    return _wcsicmp(base, L"verthys.exe") == 0;
}

int vty_kernel_guard_worker_basename(uint32_t selector, wchar_t *out,
                                     size_t cap)
{
    const wchar_t *name;

    if (out == NULL || cap == 0) return -1;
    out[0] = L'\0';
    if (selector == VTY_SVC_WORKER_IMAGE_DEFAULT) {
        name = L"verthys-worker.exe";
    } else if (selector == VTY_SVC_WORKER_IMAGE_SIDECAR) {
        name = L"verthys-worker-x86_64-pc-windows-msvc.exe";
    } else {
        return -1;
    }
    if (wcslen(name) + 1u > cap) return -1;
    memcpy(out, name, (wcslen(name) + 1u) * sizeof(wchar_t));
    return 0;
}

int vty_kernel_guard_build_sibling_path(const wchar_t *host_image,
                                        uint32_t selector, wchar_t *out,
                                        size_t cap)
{
    const wchar_t *separator;
    size_t dir_len;
    wchar_t worker[VTY_PATH_MAX];
    size_t worker_len;

    if (host_image == NULL || out == NULL || cap == 0) return -1;
    out[0] = L'\0';
    if (vty_kernel_guard_worker_basename(selector, worker,
                                         VTY_PATH_MAX) != 0) {
        return -1;
    }

    separator = wcsrchr(host_image, L'\\');
    if (separator == NULL) return -1;
    dir_len = (size_t)(separator - host_image);
    if (dir_len == 0) return -1;

    worker_len = wcslen(worker);
    if (dir_len + 1u + worker_len + 1u > cap) return -1;
    memcpy(out, host_image, dir_len * sizeof(wchar_t));
    out[dir_len] = L'\\';
    memcpy(out + dir_len + 1u, worker, (worker_len + 1u) * sizeof(wchar_t));
    return 0;
}

static int kg_pid_alive(DWORD pid);

static int kg_identity_is(DWORD pid, ULONGLONG creation, DWORD other_pid,
                          ULONGLONG other_creation)
{
    return pid != 0 && pid == other_pid && creation == other_creation;
}

static int kg_any_live_owner_locked(void)
{
    if (g_mode == VTY_KG_MODE_NONE) return 0;
    if (g_bound_pid != 0 && kg_pid_alive(g_bound_pid)) return 1;
    if (g_owner_pid != 0 && kg_pid_alive(g_owner_pid)) return 1;
    return 0;
}

static int kg_worker_file_exists(const wchar_t *dos_path)
{
    DWORD attrs;

    if (dos_path == NULL || dos_path[0] == L'\0') return 0;
    attrs = GetFileAttributesW(dos_path);
    if (attrs == INVALID_FILE_ATTRIBUTES) return 0;
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static HANDLE kg_open_device(const wchar_t *device_path,
                             VtyKernelGuardStatus *out)
{
    HANDLE device;
    DWORD error;

    device = CreateFileW(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL);
    if (device != INVALID_HANDLE_VALUE) return device;

    error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
        kg_set_unavailable(out, VTY_KERNEL_STATE_NOT_INSTALLED,
                           VTY_KERNEL_REASON_NOT_INSTALLED);
    } else if (error == ERROR_ACCESS_DENIED) {
        kg_set_unavailable(out, VTY_KERNEL_STATE_UNHEALTHY,
                           VTY_KERNEL_REASON_ACCESS_DENIED);
    } else {
        kg_set_unavailable(out, VTY_KERNEL_STATE_STOPPED,
                           VTY_KERNEL_REASON_STOPPED);
    }
    return INVALID_HANDLE_VALUE;
}

typedef struct _VTY_KG_IO_CONTEXT {
    OVERLAPPED ov;
    HANDLE event;
    VTG_STATUS_OUT response;
} VTY_KG_IO_CONTEXT;

/*
 * 发送一次设备 IO。返回：
 *   0   完成且输出长度正确
 *   -1  参数/资源/驱动错误
 *   -2  超时（已 CancelIoEx）
 *
 * 安全约束：OVERLAPPED 与响应缓冲必须在堆上。若取消后 IRP 仍未完成，
 * 内核仍可能写入这两个缓冲区；此时有意保留上下文不释放，宁可泄漏
 * 几十字节，也不能让内核写已释放的栈内存导致蓝屏。
 */
static int kg_device_ioctl(HANDLE device, ULONG ioctl, const void *input,
                           DWORD input_len, VTG_STATUS_OUT *response,
                           DWORD timeout_ms)
{
    VTY_KG_IO_CONTEXT *ctx;
    DWORD bytes = 0;
    DWORD error;
    DWORD wait_result;
    BOOL ok;

    if (device == INVALID_HANDLE_VALUE || response == NULL) return -1;
    memset(response, 0, sizeof(*response));
    ctx = (VTY_KG_IO_CONTEXT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                         sizeof(*ctx));
    if (ctx == NULL) return -1;
    ctx->event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ctx->event == NULL) {
        HeapFree(GetProcessHeap(), 0, ctx);
        return -1;
    }
    ctx->ov.hEvent = ctx->event;

    ok = DeviceIoControl(device, ioctl, (LPVOID)input, input_len,
                         &ctx->response, (DWORD)sizeof(ctx->response), &bytes,
                         &ctx->ov);
    if (!ok) {
        error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            CloseHandle(ctx->event);
            HeapFree(GetProcessHeap(), 0, ctx);
            return -1;
        }
        wait_result = WaitForSingleObject(ctx->event, timeout_ms);
        if (wait_result != WAIT_OBJECT_0) {
            (void)CancelIoEx(device, &ctx->ov);
            /*
             * 取消是异步的；最多再等 5 秒。仍未完成则保留上下文与事件，
             * 由后续 IRP 完成写入或进程退出时回收，绝不提前释放。
             */
            if (WaitForSingleObject(ctx->event, 5000u) != WAIT_OBJECT_0) {
                return -2;
            }
            (void)GetOverlappedResult(device, &ctx->ov, &bytes, FALSE);
            CloseHandle(ctx->event);
            HeapFree(GetProcessHeap(), 0, ctx);
            return -2;
        }
        if (!GetOverlappedResult(device, &ctx->ov, &bytes, FALSE)) {
            CloseHandle(ctx->event);
            HeapFree(GetProcessHeap(), 0, ctx);
            return -1;
        }
    }

    if (bytes == (DWORD)sizeof(ctx->response)) {
        *response = ctx->response;
    }
    CloseHandle(ctx->event);
    HeapFree(GetProcessHeap(), 0, ctx);
    return (bytes == (DWORD)sizeof(*response)) ? 0 : -1;
}

static int kg_response_valid(const VTG_STATUS_OUT *response,
                             uint32_t expected_command, uint64_t request_id)
{
    return response->Header.Size == (VTG_U32)sizeof(VTG_STATUS_OUT) &&
           response->Header.Major == VTG_PROTOCOL_MAJOR &&
           response->Header.Minor == VTG_PROTOCOL_MINOR &&
           response->Header.Command == expected_command &&
           response->Header.RequestId == request_id &&
           response->ProtocolMajor == VTG_PROTOCOL_MAJOR &&
           response->ProtocolMinor == VTG_PROTOCOL_MINOR;
}

static uint64_t kg_filetime_quad(FILETIME value)
{
    ULARGE_INTEGER quad;

    quad.LowPart = value.dwLowDateTime;
    quad.HighPart = value.dwHighDateTime;
    return (uint64_t)quad.QuadPart;
}

static int kg_build_process_identity(HANDLE process, DWORD pid,
                                     VTG_PROCESS_IDENTITY *out,
                                     uint64_t *creation_time)
{
    FILETIME creation;
    FILETIME exit_time;
    FILETIME kernel_time;
    FILETIME user_time;
    wchar_t dos_path[VTY_PATH_MAX];
    wchar_t nt_path[VTG_MAX_IMAGE_PATH_CHARS];

    if (process == NULL || out == NULL || creation_time == NULL) return -1;
    memset(out, 0, sizeof(*out));
    memset(dos_path, 0, sizeof(dos_path));
    memset(nt_path, 0, sizeof(nt_path));

    if (!GetProcessTimes(process, &creation, &exit_time, &kernel_time,
                         &user_time)) {
        return -1;
    }
    if (vty_get_process_image_path(process, dos_path, VTY_PATH_MAX) != 0) {
        return -1;
    }
    if (vty_kernel_guard_dos_to_nt_path(dos_path, nt_path,
                                        VTG_MAX_IMAGE_PATH_CHARS) != 0) {
        return -1;
    }

    out->ProcessId = pid;
    out->CreationTime = kg_filetime_quad(creation);
    if (vty_wide_copy(out->ImagePath, VTG_MAX_IMAGE_PATH_CHARS, nt_path) != 0) {
        return -1;
    }
    *creation_time = out->CreationTime;
    return 0;
}

static int kg_build_self_identity(VTG_PROCESS_IDENTITY *out)
{
    uint64_t creation = 0;
    return kg_build_process_identity(GetCurrentProcess(), GetCurrentProcessId(),
                                     out, &creation);
}

static int kg_pid_alive(DWORD pid)
{
    HANDLE process;
    DWORD wait_result;

    if (pid == 0) return 0;
    process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                          FALSE, pid);
    if (process == NULL) {
        /* 只有明确的“无此进程”才视为已退出；其余按存活处理（fail-safe）。 */
        return GetLastError() != ERROR_INVALID_PARAMETER;
    }
    wait_result = WaitForSingleObject(process, 0);
    CloseHandle(process);
    return wait_result == WAIT_TIMEOUT;
}

uint16_t vty_kernel_guard_arm(DWORD client_pid, HANDLE client_process,
                              uint32_t mode, uint32_t worker_image,
                              VtyKernelGuardStatus *out)
{
    VTG_ARM_IN arm;
    VTG_STATUS_OUT response;
    VTG_PROCESS_IDENTITY service_identity;
    VTG_PROCESS_IDENTITY client_identity;
    uint64_t client_creation = 0;
    wchar_t host_dos[VTY_PATH_MAX];
    wchar_t worker_dos[VTY_PATH_MAX];
    wchar_t worker_nt[VTG_MAX_IMAGE_PATH_CHARS];
    const wchar_t *protected_path;
    HANDLE device;
    uint16_t result = (uint16_t)VTY_SVC_STATUS_INTERNAL;
    int io_rc;

    if (out == NULL || client_process == NULL || client_pid == 0) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (mode != VTY_SVC_ARM_MODE_WORKER_SELF &&
        mode != VTY_SVC_ARM_MODE_HOST_PREARM) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    if (mode == VTY_SVC_ARM_MODE_WORKER_SELF &&
        worker_image != VTY_SVC_WORKER_IMAGE_DEFAULT) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    kg_set_unavailable(out, VTY_KERNEL_STATE_UNKNOWN,
                       VTY_KERNEL_REASON_INTERNAL);

    if (kg_build_process_identity(client_process, client_pid, &client_identity,
                                  &client_creation) != 0) {
        return (uint16_t)VTY_SVC_STATUS_DENIED;
    }

    memset(host_dos, 0, sizeof(host_dos));
    memset(worker_dos, 0, sizeof(worker_dos));
    memset(worker_nt, 0, sizeof(worker_nt));

    if (mode == VTY_SVC_ARM_MODE_HOST_PREARM) {
        if (!vty_kernel_guard_is_host_image(client_identity.ImagePath)) {
            return (uint16_t)VTY_SVC_STATUS_DENIED;
        }
        if (vty_get_process_image_path(client_process, host_dos,
                                       VTY_PATH_MAX) != 0) {
            return (uint16_t)VTY_SVC_STATUS_DENIED;
        }
        if (vty_kernel_guard_build_sibling_path(host_dos, worker_image,
                                                worker_dos, VTY_PATH_MAX) != 0) {
            return (uint16_t)VTY_SVC_STATUS_DENIED;
        }
        if (!kg_worker_file_exists(worker_dos)) {
            return (uint16_t)VTY_SVC_STATUS_DENIED;
        }
        if (vty_kernel_guard_dos_to_nt_path(worker_dos, worker_nt,
                                            VTG_MAX_IMAGE_PATH_CHARS) != 0) {
            return (uint16_t)VTY_SVC_STATUS_DENIED;
        }
        protected_path = worker_nt;
    } else {
        if (!vty_kernel_guard_is_worker_image(client_identity.ImagePath)) {
            return (uint16_t)VTY_SVC_STATUS_DENIED;
        }
        protected_path = client_identity.ImagePath;
    }

    if (kg_build_self_identity(&service_identity) != 0) {
        return (uint16_t)VTY_SVC_STATUS_INTERNAL;
    }

    AcquireSRWLockExclusive(&g_kg_lock);
    if (g_mode != VTY_KG_MODE_NONE && kg_any_live_owner_locked()) {
        int same_owner = kg_identity_is(client_pid, client_creation, g_owner_pid,
                                        g_owner_creation);
        int host_takeover =
            mode == VTY_SVC_ARM_MODE_WORKER_SELF &&
            g_mode == VTY_KG_MODE_HOST_PREARM &&
            _wcsicmp(g_armed_path, client_identity.ImagePath) == 0 &&
            kg_pid_alive(g_owner_pid);
        int bound_alive =
            g_bound_pid != 0 && kg_pid_alive(g_bound_pid) &&
            !kg_identity_is(g_bound_pid, g_bound_creation, client_pid,
                            client_creation);
        if ((!same_owner && !host_takeover) || bound_alive) {
            ReleaseSRWLockExclusive(&g_kg_lock);
            return (uint16_t)VTY_SVC_STATUS_DENIED;
        }
    }

    device = kg_open_device(VTY_KG_DEFAULT_DEVICE, out);
    if (device == INVALID_HANDLE_VALUE) {
        ReleaseSRWLockExclusive(&g_kg_lock);
        return (uint16_t)VTY_SVC_STATUS_UNAVAILABLE;
    }

    memset(&arm, 0, sizeof(arm));
    arm.Header.Size = (VTG_U32)sizeof(arm);
    arm.Header.Major = VTG_PROTOCOL_MAJOR;
    arm.Header.Minor = VTG_PROTOCOL_MINOR;
    arm.Header.Command = VTG_CMD_ARM;
    arm.Header.RequestId =
        (VTG_U64)(ULONG)InterlockedIncrement(&g_request_seq);
    arm.Service = service_identity;
    if (vty_wide_copy(arm.ProtectedImagePath, VTG_MAX_IMAGE_PATH_CHARS,
                      protected_path) != 0) {
        CloseHandle(device);
        ReleaseSRWLockExclusive(&g_kg_lock);
        return (uint16_t)VTY_SVC_STATUS_INTERNAL;
    }

    io_rc = kg_device_ioctl(device, VTG_IOCTL_ARM, &arm, (DWORD)sizeof(arm),
                            &response, VTY_KG_LIFECYCLE_TIMEOUT_MS);
    CloseHandle(device);
    if (io_rc != 0 ||
        !kg_response_valid(&response, VTG_CMD_ARM, arm.Header.RequestId)) {
        kg_set_unavailable(out, VTY_KERNEL_STATE_UNHEALTHY,
                           io_rc == -2 ? VTY_KERNEL_REASON_TIMEOUT
                                       : VTY_KERNEL_REASON_BAD_RESPONSE);
        kg_clear_state_locked();
        ReleaseSRWLockExclusive(&g_kg_lock);
        return (uint16_t)VTY_SVC_STATUS_UNAVAILABLE;
    }

    kg_fill_status(&response, out);
    result = kg_map_driver_result(response.Header.Status);
    if (result == (uint16_t)VTY_SVC_STATUS_OK) {
        g_owner_pid = client_pid;
        g_owner_creation = client_creation;
        g_bound_pid = 0;
        g_bound_creation = 0;
        if (mode == VTY_SVC_ARM_MODE_HOST_PREARM) {
            g_mode = VTY_KG_MODE_HOST_PREARM;
            memset(g_armed_path, 0, sizeof(g_armed_path));
            (void)vty_wide_copy(g_armed_path, VTG_MAX_IMAGE_PATH_CHARS,
                                protected_path);
        } else {
            g_mode = VTY_KG_MODE_WORKER_SELF;
            memset(g_armed_path, 0, sizeof(g_armed_path));
            (void)vty_wide_copy(g_armed_path, VTG_MAX_IMAGE_PATH_CHARS,
                                protected_path);
        }
    } else {
        kg_clear_state_locked();
    }
    ReleaseSRWLockExclusive(&g_kg_lock);
    return result;
}

uint16_t vty_kernel_guard_register(DWORD client_pid, HANDLE client_process,
                                   uint32_t target_pid,
                                   uint64_t target_creation,
                                   VtyKernelGuardStatus *out)
{
    VTG_REGISTER_IN register_in;
    VTG_STATUS_OUT response;
    VTG_PROCESS_IDENTITY client_identity;
    VTG_PROCESS_IDENTITY target_identity;
    uint64_t client_creation = 0;
    uint64_t opened_creation = 0;
    HANDLE target_process = NULL;
    HANDLE device;
    uint16_t result = (uint16_t)VTY_SVC_STATUS_INTERNAL;
    int io_rc = 0;

    if (out == NULL || client_process == NULL || client_pid == 0) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    kg_set_unavailable(out, VTY_KERNEL_STATE_UNKNOWN,
                       VTY_KERNEL_REASON_INTERNAL);

    if (kg_build_process_identity(client_process, client_pid, &client_identity,
                                  &client_creation) != 0) {
        return (uint16_t)VTY_SVC_STATUS_DENIED;
    }
    memset(&target_identity, 0, sizeof(target_identity));

    AcquireSRWLockExclusive(&g_kg_lock);
    if (g_mode == VTY_KG_MODE_NONE) {
        ReleaseSRWLockExclusive(&g_kg_lock);
        return (uint16_t)VTY_SVC_STATUS_LOCKED;
    }

    {
        int is_owner = kg_identity_is(client_pid, client_creation, g_owner_pid,
                                      g_owner_creation);
        int is_bound = kg_identity_is(client_pid, client_creation, g_bound_pid,
                                      g_bound_creation);

        if (g_mode == VTY_KG_MODE_WORKER_SELF) {
            if (!is_owner || target_pid != 0 || target_creation != 0) {
                ReleaseSRWLockExclusive(&g_kg_lock);
                return is_owner ? (uint16_t)VTY_SVC_STATUS_BAD_REQUEST
                                : (uint16_t)VTY_SVC_STATUS_DENIED;
            }
            target_identity = client_identity;
        } else if (is_bound) {
            if (target_pid != 0 || target_creation != 0) {
                ReleaseSRWLockExclusive(&g_kg_lock);
                return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
            }
            target_identity = client_identity;
        } else if (is_owner) {
            if (target_pid == 0 || target_creation == 0) {
                ReleaseSRWLockExclusive(&g_kg_lock);
                return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
            }
            target_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                         FALSE, target_pid);
            if (target_process == NULL) {
                ReleaseSRWLockExclusive(&g_kg_lock);
                return (uint16_t)VTY_SVC_STATUS_UNAVAILABLE;
            }
            if (kg_build_process_identity(target_process, target_pid,
                                          &target_identity,
                                          &opened_creation) != 0 ||
                opened_creation != target_creation ||
                !vty_kernel_guard_is_worker_image(target_identity.ImagePath) ||
                _wcsicmp(target_identity.ImagePath, g_armed_path) != 0) {
                CloseHandle(target_process);
                ReleaseSRWLockExclusive(&g_kg_lock);
                return (uint16_t)VTY_SVC_STATUS_DENIED;
            }
        } else {
            ReleaseSRWLockExclusive(&g_kg_lock);
            return (uint16_t)VTY_SVC_STATUS_DENIED;
        }
    }

    device = kg_open_device(VTY_KG_DEFAULT_DEVICE, out);
    if (device == INVALID_HANDLE_VALUE) {
        if (target_process != NULL) CloseHandle(target_process);
        ReleaseSRWLockExclusive(&g_kg_lock);
        return (uint16_t)VTY_SVC_STATUS_UNAVAILABLE;
    }

    memset(&register_in, 0, sizeof(register_in));
    register_in.Header.Size = (VTG_U32)sizeof(register_in);
    register_in.Header.Major = VTG_PROTOCOL_MAJOR;
    register_in.Header.Minor = VTG_PROTOCOL_MINOR;
    register_in.Header.Command = VTG_CMD_REGISTER_PROCESS;
    register_in.Header.RequestId =
        (VTG_U64)(ULONG)InterlockedIncrement(&g_request_seq);
    register_in.Process = target_identity;

    io_rc = kg_device_ioctl(device, VTG_IOCTL_REGISTER_PROCESS, &register_in,
                            (DWORD)sizeof(register_in), &response,
                            VTY_KG_LIFECYCLE_TIMEOUT_MS);
    CloseHandle(device);
    if (target_process != NULL) CloseHandle(target_process);
    if (io_rc != 0 ||
        !kg_response_valid(&response, VTG_CMD_REGISTER_PROCESS,
                           register_in.Header.RequestId)) {
        kg_set_unavailable(out, VTY_KERNEL_STATE_UNHEALTHY,
                           io_rc == -2 ? VTY_KERNEL_REASON_TIMEOUT
                                       : VTY_KERNEL_REASON_BAD_RESPONSE);
        ReleaseSRWLockExclusive(&g_kg_lock);
        return (uint16_t)VTY_SVC_STATUS_UNAVAILABLE;
    }

    kg_fill_status(&response, out);
    result = kg_map_driver_result(response.Header.Status);
    if (result == (uint16_t)VTY_SVC_STATUS_OK) {
        g_bound_pid = target_identity.ProcessId;
        g_bound_creation = target_identity.CreationTime;
    }
    ReleaseSRWLockExclusive(&g_kg_lock);
    return result;
}

uint16_t vty_kernel_guard_disarm(DWORD client_pid, HANDLE client_process,
                                 VtyKernelGuardStatus *out)
{
    VTG_HEADER request;
    VTG_STATUS_OUT response;
    VTG_PROCESS_IDENTITY client_identity;
    uint64_t client_creation = 0;
    HANDLE device;
    uint16_t result = (uint16_t)VTY_SVC_STATUS_INTERNAL;
    int io_rc;

    if (out == NULL || client_process == NULL || client_pid == 0) {
        return (uint16_t)VTY_SVC_STATUS_BAD_REQUEST;
    }
    kg_set_unavailable(out, VTY_KERNEL_STATE_UNKNOWN,
                       VTY_KERNEL_REASON_INTERNAL);

    if (kg_build_process_identity(client_process, client_pid, &client_identity,
                                  &client_creation) != 0) {
        return (uint16_t)VTY_SVC_STATUS_DENIED;
    }
    if (!vty_kernel_guard_is_worker_image(client_identity.ImagePath) &&
        !vty_kernel_guard_is_host_image(client_identity.ImagePath)) {
        return (uint16_t)VTY_SVC_STATUS_DENIED;
    }

    AcquireSRWLockExclusive(&g_kg_lock);
    if (g_mode != VTY_KG_MODE_NONE) {
        int allowed =
            kg_identity_is(client_pid, client_creation, g_owner_pid,
                           g_owner_creation) ||
            kg_identity_is(client_pid, client_creation, g_bound_pid,
                           g_bound_creation);
        if (!allowed && kg_any_live_owner_locked()) {
            ReleaseSRWLockExclusive(&g_kg_lock);
            return (uint16_t)VTY_SVC_STATUS_DENIED;
        }
    }

    device = kg_open_device(VTY_KG_DEFAULT_DEVICE, out);
    if (device == INVALID_HANDLE_VALUE) {
        kg_clear_state_locked();
        ReleaseSRWLockExclusive(&g_kg_lock);
        return (uint16_t)VTY_SVC_STATUS_UNAVAILABLE;
    }

    memset(&request, 0, sizeof(request));
    request.Size = (VTG_U32)sizeof(request);
    request.Major = VTG_PROTOCOL_MAJOR;
    request.Minor = VTG_PROTOCOL_MINOR;
    request.Command = VTG_CMD_DISARM;
    request.RequestId = (VTG_U64)(ULONG)InterlockedIncrement(&g_request_seq);

    io_rc = kg_device_ioctl(device, VTG_IOCTL_DISARM, &request,
                            (DWORD)sizeof(request), &response,
                            VTY_KG_LIFECYCLE_TIMEOUT_MS);
    CloseHandle(device);
    if (io_rc != 0 ||
        !kg_response_valid(&response, VTG_CMD_DISARM, request.RequestId)) {
        kg_set_unavailable(out, VTY_KERNEL_STATE_UNHEALTHY,
                           io_rc == -2 ? VTY_KERNEL_REASON_TIMEOUT
                                       : VTY_KERNEL_REASON_BAD_RESPONSE);
        ReleaseSRWLockExclusive(&g_kg_lock);
        return (uint16_t)VTY_SVC_STATUS_UNAVAILABLE;
    }

    kg_fill_status(&response, out);
    if (response.Header.Status == VTG_STATUS_OK ||
        response.Header.Status == VTG_STATUS_NOT_ARMED) {
        kg_clear_state_locked();
        result = (uint16_t)VTY_SVC_STATUS_OK;
    } else {
        result = kg_map_driver_result(response.Header.Status);
    }
    ReleaseSRWLockExclusive(&g_kg_lock);
    return result;
}

int vty_kernel_guard_query_path(const wchar_t *device_path,
                                VtyKernelGuardStatus *out)
{
    HANDLE device;
    VTG_HEADER request;
    VTG_STATUS_OUT response;
    int rc = -1;
    int io_rc;

    if (out == NULL) return -1;
    kg_set_unavailable(out, VTY_KERNEL_STATE_UNKNOWN,
                       VTY_KERNEL_REASON_INTERNAL);
    if (device_path == NULL || device_path[0] == L'\0') return -1;

    device = kg_open_device(device_path, out);
    if (device == INVALID_HANDLE_VALUE) {
        return 0;
    }

    memset(&request, 0, sizeof(request));
    request.Size = (VTG_U32)sizeof(request);
    request.Major = VTG_PROTOCOL_MAJOR;
    request.Minor = VTG_PROTOCOL_MINOR;
    request.Command = VTG_CMD_QUERY_STATUS;

    io_rc = kg_device_ioctl(device, VTG_IOCTL_QUERY_STATUS, &request,
                            (DWORD)sizeof(request), &response,
                            VTY_KG_IO_TIMEOUT_MS);
    if (io_rc != 0) {
        kg_set_unavailable(out, VTY_KERNEL_STATE_UNHEALTHY,
                           io_rc == -2 ? VTY_KERNEL_REASON_TIMEOUT
                                       : VTY_KERNEL_REASON_INTERNAL);
        goto done;
    }
    if (!kg_response_valid(&response, VTG_CMD_QUERY_STATUS,
                           request.RequestId) ||
        response.Header.Status != VTG_STATUS_OK) {
        kg_set_unavailable(out, VTY_KERNEL_STATE_UNHEALTHY,
                           VTY_KERNEL_REASON_BAD_RESPONSE);
        goto done;
    }

    kg_fill_status(&response, out);
    rc = 0;

done:
    CloseHandle(device);
    return rc;
}

int vty_kernel_guard_query(VtyKernelGuardStatus *out)
{
    return vty_kernel_guard_query_path(VTY_KG_DEFAULT_DEVICE, out);
}
