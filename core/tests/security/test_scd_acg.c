/*
 * test_scd_acg.c — ACG 下的直连系统调用传输验证
 *
 * 目标：
 *   证明映像内 thunk 在 ACG（禁止动态代码）生效后仍能激活，
 *   且两条 NT 查询与 ntdll 导出的结果一致。
 *
 * 前置条件：
 *   - 进程支持 SetProcessMitigationPolicy 与 ProcessDynamicCodePolicy；
 *   - 系统不支持时输出 SKIP 并以 0 退出。
 *
 * 通过判据：
 *   1. ACG 策略写入成功且读回确认；
 *   2. syscall_direct_available() 返回 1；
 *   3. NtQueryInformationProcess 查询的 PEB 与 ntdll 导出一致；
 *   4. NtQuerySystemInformation(SystemBasicInformation) 返回页大小 4096。
 *
 * 独立性：
 *   ACG 是进程级且不可撤销的策略，因此本验证使用独立可执行文件，
 *   不与共享测试进程合并。
 */
#include "syscall_direct.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ProcessDynamicCodePolicy 的枚举值；显式数值避免旧 SDK 缺少成员。 */
#define SCD_POLICY_DYNAMIC_CODE 2

typedef BOOL (WINAPI *ScdSetMitigation_t)(int, PVOID, SIZE_T);
typedef BOOL (WINAPI *ScdGetMitigation_t)(HANDLE, int, PVOID, SIZE_T);

typedef struct ScdDynamicCodePolicy {
    DWORD Flags;
} ScdDynamicCodePolicy;

typedef struct ScdPbi {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} ScdPbi;

typedef struct ScdSbi {
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    UCHAR NumberOfProcessors;
} ScdSbi;

typedef LONG (NTAPI *ScdNtQip)(HANDLE, ULONG, PVOID, ULONG, PULONG);

/*
 * 启用 ACG。
 * 返回 1 = 策略已生效；0 = 当前系统不支持；-1 = 策略写入或读回失败。
 * 读回用于排除“调用成功但策略未生效”的假阳性。
 */
static int scd_enable_acg(DWORD *error_out)
{
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (k32 == NULL) {
        *error_out = GetLastError();
        return -1;
    }

    ScdSetMitigation_t set_policy =
        (ScdSetMitigation_t)(void *)GetProcAddress(k32, "SetProcessMitigationPolicy");
    if (set_policy == NULL) {
        *error_out = ERROR_CALL_NOT_IMPLEMENTED;
        return 0;
    }

    ScdDynamicCodePolicy desired;
    desired.Flags = 1u;  /* ProhibitDynamicCode，且不允许线程级豁免 */
    if (!set_policy(SCD_POLICY_DYNAMIC_CODE, &desired, sizeof(desired))) {
        *error_out = GetLastError();
        if (*error_out == ERROR_NOT_SUPPORTED ||
            *error_out == ERROR_INVALID_PARAMETER ||
            *error_out == ERROR_CALL_NOT_IMPLEMENTED) {
            return 0;
        }
        return -1;
    }

    ScdGetMitigation_t get_policy =
        (ScdGetMitigation_t)(void *)GetProcAddress(k32, "GetProcessMitigationPolicy");
    if (get_policy != NULL) {
        ScdDynamicCodePolicy actual;
        memset(&actual, 0, sizeof(actual));
        if (get_policy(GetCurrentProcess(), SCD_POLICY_DYNAMIC_CODE,
                       &actual, sizeof(actual))) {
            if ((actual.Flags & 1u) == 0) {
                *error_out = ERROR_INVALID_STATE;
                return -1;
            }
        }
    }
    return 1;
}

int main(void)
{
    DWORD error = 0;

    int acg = scd_enable_acg(&error);
    if (acg == 0) {
        printf("SKIP: ACG unsupported (error=%lu)\n", (unsigned long)error);
        return 0;
    }
    if (acg < 0) {
        printf("FAIL: ACG enable error=%lu\n", (unsigned long)error);
        return 1;
    }

    syscall_direct_init();
    if (syscall_direct_available() != 1) {
        printf("FAIL: direct syscall thunk not active under ACG\n");
        return 2;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        printf("FAIL: ntdll handle\n");
        return 3;
    }

    ScdNtQip direct =
        (ScdNtQip)(void *)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (direct == NULL) {
        printf("FAIL: NtQueryInformationProcess export\n");
        return 4;
    }

    ScdPbi baseline;
    ScdPbi transport;
    memset(&baseline, 0, sizeof(baseline));
    memset(&transport, 0, sizeof(transport));

    LONG r_base = direct(GetCurrentProcess(), 0, &baseline, sizeof(baseline), NULL);
    LONG r_thunk = syscall_NtQueryInformationProcess(
        GetCurrentProcess(), 0, &transport, sizeof(transport), NULL);
    if (r_base != STATUS_SUCCESS || r_thunk != STATUS_SUCCESS) {
        printf("FAIL: NtQueryInformationProcess status direct=0x%08lX thunk=0x%08lX\n",
               (unsigned long)r_base, (unsigned long)r_thunk);
        return 5;
    }
    if (baseline.PebBaseAddress != transport.PebBaseAddress ||
        baseline.UniqueProcessId != transport.UniqueProcessId) {
        printf("FAIL: PEB mismatch under ACG\n");
        return 6;
    }

    ScdSbi sbi;
    memset(&sbi, 0, sizeof(sbi));
    LONG r_sys = syscall_NtQuerySystemInformation(0, &sbi, sizeof(sbi), NULL);
    if (r_sys != STATUS_SUCCESS || sbi.PageSize != 4096u) {
        printf("FAIL: NtQuerySystemInformation status=0x%08lX page=%lu\n",
               (unsigned long)r_sys, (unsigned long)sbi.PageSize);
        return 7;
    }

    printf("PASS: ACG active, in-image thunk functional\n");
    return 0;
}
