/*
 * test_kernel_guard.c — 服务侧内核防护映射与生命周期命令边界
 *
 * 不加载驱动；用不存在的设备路径验证 NOT_INSTALLED 映射，
 * 避免测试依赖开发机是否安装测试驱动。
 */
#include "test_common.h"
#include "kernel_guard.h"

#include <string.h>
#include <wchar.h>

static void test_missing_device(void)
{
    VtyKernelGuardStatus status;
    int rc;

    memset(&status, 0xFF, sizeof(status));
    rc = vty_kernel_guard_query_path(L"\\\\.\\VerthysGuardMissingForTest",
                                     &status);
    CHECK_EQ_INT(rc, 0);
    CHECK_EQ_INT(status.state, VTY_KERNEL_STATE_NOT_INSTALLED);
    CHECK_EQ_INT(status.reason, VTY_KERNEL_REASON_NOT_INSTALLED);
    CHECK_EQ_INT(status.capabilities, 0u);
    CHECK_EQ_INT(status.protocol_major, 0u);
    CHECK_EQ_INT(status.protocol_minor, 0u);
}

static void test_invalid_arguments(void)
{
    VtyKernelGuardStatus status;

    CHECK_EQ_INT(vty_kernel_guard_query_path(NULL, &status), -1);
    CHECK_EQ_INT(vty_kernel_guard_query_path(L"", &status), -1);
    CHECK_EQ_INT(vty_kernel_guard_query_path(L"\\\\.\\Missing", NULL), -1);
}

static void test_dos_to_nt_path(void)
{
    wchar_t dos[256];
    wchar_t nt[520];

    memset(dos, 0, sizeof(dos));
    memset(nt, 0, sizeof(nt));
    if (GetWindowsDirectoryW(dos, 256) == 0) {
        CHECK(0);
        return;
    }

    CHECK_EQ_INT(vty_kernel_guard_dos_to_nt_path(dos, nt, 520), 0);
    CHECK(wcsncmp(nt, L"\\Device\\", 8) == 0);
    CHECK(wcslen(nt) >= wcslen(dos) - 2u);
    CHECK(_wcsicmp(nt + wcslen(nt) - (wcslen(dos) - 2u), dos + 2) == 0);

    CHECK_EQ_INT(vty_kernel_guard_dos_to_nt_path(L"Windows", nt, 520), -1);
    CHECK_EQ_INT(vty_kernel_guard_dos_to_nt_path(L"C:", nt, 520), -1);
    CHECK_EQ_INT(vty_kernel_guard_dos_to_nt_path(NULL, nt, 520), -1);
    CHECK_EQ_INT(vty_kernel_guard_dos_to_nt_path(dos, NULL, 520), -1);
    CHECK_EQ_INT(vty_kernel_guard_dos_to_nt_path(dos, nt, 4), -1);
}

static void test_worker_image_names(void)
{
    CHECK(vty_kernel_guard_is_worker_image(
        L"\\Device\\HarddiskVolume3\\Program Files\\Verthys\\verthys-worker.exe"));
    CHECK(vty_kernel_guard_is_worker_image(
        L"\\Device\\HarddiskVolume3\\Verthys\\"
        L"verthys-worker-x86_64-pc-windows-msvc.exe"));
    CHECK(!vty_kernel_guard_is_worker_image(
        L"\\Device\\HarddiskVolume3\\Program Files\\Verthys\\Verthys.exe"));
    CHECK(!vty_kernel_guard_is_worker_image(
        L"\\Device\\HarddiskVolume3\\Temp\\verthys-worker-other.exe"));
    CHECK(!vty_kernel_guard_is_worker_image(NULL));
    CHECK(!vty_kernel_guard_is_worker_image(L""));
}

static void test_host_image_names(void)
{
    CHECK(vty_kernel_guard_is_host_image(
        L"\\Device\\HarddiskVolume3\\Program Files\\Verthys\\Verthys.exe"));
    CHECK(vty_kernel_guard_is_host_image(
        L"\\Device\\HarddiskVolume3\\Program Files\\Verthys\\verthys.exe"));
    CHECK(!vty_kernel_guard_is_host_image(
        L"\\Device\\HarddiskVolume3\\Program Files\\Verthys\\verthys-worker.exe"));
    CHECK(!vty_kernel_guard_is_host_image(NULL));
    CHECK(!vty_kernel_guard_is_host_image(L""));
}

static void test_worker_basename_and_sibling(void)
{
    wchar_t out[520];

    memset(out, 0, sizeof(out));
    CHECK_EQ_INT(vty_kernel_guard_worker_basename(0u, out, 520), 0);
    CHECK(_wcsicmp(out, L"verthys-worker.exe") == 0);
    CHECK_EQ_INT(vty_kernel_guard_worker_basename(1u, out, 520), 0);
    CHECK(_wcsicmp(out, L"verthys-worker-x86_64-pc-windows-msvc.exe") == 0);
    CHECK_EQ_INT(vty_kernel_guard_worker_basename(2u, out, 520), -1);
    CHECK_EQ_INT(vty_kernel_guard_worker_basename(0u, NULL, 520), -1);
    CHECK_EQ_INT(vty_kernel_guard_worker_basename(0u, out, 4), -1);

    memset(out, 0, sizeof(out));
    CHECK_EQ_INT(vty_kernel_guard_build_sibling_path(
                     L"C:\\Program Files\\Verthys\\Verthys.exe", 0u, out,
                     520),
                 0);
    CHECK(_wcsicmp(out, L"C:\\Program Files\\Verthys\\verthys-worker.exe") == 0);
    CHECK_EQ_INT(vty_kernel_guard_build_sibling_path(
                     L"C:\\Program Files\\Verthys\\Verthys.exe", 1u, out,
                     520),
                 0);
    CHECK(_wcsicmp(out,
                   L"C:\\Program Files\\Verthys\\"
                   L"verthys-worker-x86_64-pc-windows-msvc.exe") == 0);

    CHECK_EQ_INT(vty_kernel_guard_build_sibling_path(L"Verthys.exe", 0u, out,
                                                     520),
                 -1);
    CHECK_EQ_INT(vty_kernel_guard_build_sibling_path(L"\\Verthys.exe", 0u, out,
                                                     520),
                 -1);
    CHECK_EQ_INT(vty_kernel_guard_build_sibling_path(
                     L"C:\\Program Files\\Verthys\\Verthys.exe", 0u, out, 8),
                 -1);
}

static void test_lifecycle_boundaries(void)
{
    VtyKernelGuardStatus status;
    HANDLE process = GetCurrentProcess();
    DWORD pid = GetCurrentProcessId();

    memset(&status, 0, sizeof(status));
    CHECK_EQ_INT(vty_kernel_guard_arm(0, process, 0u, 0u, &status),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_kernel_guard_arm(pid, NULL, 0u, 0u, &status),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_kernel_guard_arm(pid, process, 2u, 0u, &status),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_kernel_guard_arm(pid, process, 0u, 1u, &status),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_kernel_guard_register(0, process, 0u, 0u, &status),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_kernel_guard_disarm(0, process, &status),
                 VTY_SVC_STATUS_BAD_REQUEST);
    CHECK_EQ_INT(vty_kernel_guard_disarm(pid, NULL, &status),
                 VTY_SVC_STATUS_BAD_REQUEST);

    /* 测试进程不是 worker/宿主映像：必须在触达驱动前拒绝。 */
    CHECK_EQ_INT(vty_kernel_guard_arm(pid, process, 0u, 0u, &status),
                 VTY_SVC_STATUS_DENIED);
    CHECK_EQ_INT(vty_kernel_guard_arm(pid, process, 1u, 0u, &status),
                 VTY_SVC_STATUS_DENIED);
    /* REGISTER 先判定“服务侧尚无 ARM 状态”，再判定调用方映像。 */
    CHECK_EQ_INT(vty_kernel_guard_register(pid, process, 0u, 0u, &status),
                 VTY_SVC_STATUS_LOCKED);
    CHECK_EQ_INT(vty_kernel_guard_disarm(pid, process, &status),
                 VTY_SVC_STATUS_DENIED);
}

int test_kernel_guard_run(void)
{
    printf("[ U2 ] kernel guard query and lifecycle mapping\n");
    test_missing_device();
    test_invalid_arguments();
    test_dos_to_nt_path();
    test_worker_image_names();
    test_host_image_names();
    test_worker_basename_and_sibling();
    test_lifecycle_boundaries();
    return g_test_failures;
}
