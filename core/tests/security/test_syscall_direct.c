/*
 * test_syscall_direct.c — ★ V3 升级 WP-9：直接系统调用传输测试
 *
 * 验证维度（环境自适应：激活/降级两态均须通过——测试断言的是
 * "传输语义与 ntdll 导出一致"，激活与否取决于运行环境 SSN 提取结果）：
 *   1. 初始化幂等 + available() 结果稳定（同一进程内两次调用一致）
 *   2. NtQueryInformationProcess 经包装查询 PEB：与 GetProcAddress
 *      直连 ntdll 的结果逐字节一致（stub 与内核真理的一致性证明）
 *   3. NtQuerySystemInformation(SystemBasicInformation) 成功且字段合理
 *   4. 错误码穿透：零长缓冲返回 STATUS_INFO_LENGTH_MISMATCH
 *      （证明 NTSTATUS 完整经过 stub RAX 返回，无吞没/改写）
 *   5. 检测器接线回归：anti_debug_v2 / memory_guard 经新传输在
 *      干净环境下零误报（既有测试自动覆盖，此处补直接断言）
 */
#include "verthys_test.h"
#include "syscall_direct.h"
#include "anti_debug_v2.h"
#include "memory_guard.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)
#endif

/* ProcessBasicInformation 输出结构（与 memory_guard 内定义等价） */
typedef struct _T_PBI {
    PVOID     Reserved1;
    PVOID     PebBaseAddress;
    PVOID     Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} T_PBI;

/* SystemBasicInformation（信息类 0）输出结构 */
typedef struct _T_SBI {
    ULONG     Reserved;
    ULONG     TimerResolution;
    ULONG     PageSize;
    ULONG     NumberOfPhysicalPages;
    ULONG     LowestPhysicalPageNumber;
    ULONG     HighestPhysicalPageNumber;
    ULONG     AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    UCHAR     NumberOfProcessors;
} T_SBI;

/* 直连 ntdll 导出的 NtQueryInformationProcess（对照组） */
typedef LONG (NTAPI *T_NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);

/* 初始化幂等 + available() 稳定 */
TEST(scd_init_idempotent)
{
    CHECK_EQ(syscall_direct_init(), 0);
    CHECK_EQ(syscall_direct_init(), 0);

    int a1 = syscall_direct_available();
    int a2 = syscall_direct_available();
    CHECK(a1 == 0 || a1 == 1);
    CHECK_EQ(a1, a2);   /* 同进程内结论稳定（InitOnce 缓存） */
    TEST_LOG("[scd] direct stub %s\n", a1 ? "ACTIVE" : "DEGRADED");
    return 0;
}

/* 包装查询 PEB 与直连 ntdll 结果一致（stub/回退两态均须等价） */
TEST(scd_process_query_matches_ntdll)
{
    /* 对照组：直连导出 */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    CHECK(ntdll != NULL);
    T_NtQIP direct = (T_NtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
    CHECK(direct != NULL);

    T_PBI via_direct = { 0 }, via_wrapper = { 0 };
    HANDLE proc = GetCurrentProcess();

    CHECK_EQ(direct(proc, 0, &via_direct, sizeof(via_direct), NULL),
             STATUS_SUCCESS);
    CHECK_EQ(syscall_NtQueryInformationProcess(
                 proc, 0, &via_wrapper, sizeof(via_wrapper), NULL),
             STATUS_SUCCESS);

    /* 内核真理唯一：两条传输路径读到的必须是同一个 PEB */
    CHECK(via_direct.PebBaseAddress != NULL);
    CHECK_EQ((long)(via_wrapper.PebBaseAddress ==
                    via_direct.PebBaseAddress), 1);
    CHECK_EQ((long)via_wrapper.UniqueProcessId, (long)via_direct.UniqueProcessId);
    return 0;
}

/* SystemBasicInformation 查询成功且字段合理 */
TEST(scd_system_query_basic_info)
{
    T_SBI sbi;
    memset(&sbi, 0, sizeof(sbi));
    CHECK_EQ(syscall_NtQuerySystemInformation(
                 0 /* SystemBasicInformation */, &sbi, sizeof(sbi), NULL),
             STATUS_SUCCESS);

    CHECK(sbi.PageSize == 4096);              /* x64 Windows 页大小恒定 */
    CHECK(sbi.NumberOfPhysicalPages > 0);
    CHECK(sbi.AllocationGranularity == 65536); /* 分配粒度恒定 64 KiB */
    CHECK(sbi.NumberOfProcessors > 0 && sbi.NumberOfProcessors <= 64);
    return 0;
}

/* 错误码穿透：零长缓冲 → STATUS_INFO_LENGTH_MISMATCH */
TEST(scd_error_code_passthrough)
{
    LONG st = syscall_NtQueryInformationProcess(
        GetCurrentProcess(), 0, NULL, 0, NULL);
    CHECK_EQ(st, STATUS_INFO_LENGTH_MISMATCH);

    LONG st2 = syscall_NtQuerySystemInformation(0, NULL, 0, NULL);
    CHECK_EQ(st2, STATUS_INFO_LENGTH_MISMATCH);
    return 0;
}

/* 检测器接线回归：新传输下干净环境零误报 */
TEST(scd_detector_wiring_clean)
{
    CHECK_EQ(anti_debug_v2_init(), 0);
    CHECK_EQ(anti_debug_v2_check(), DBG_THREAT_NONE);
    CHECK_EQ(anti_debug_v2_is_punish_mode(), 0);

    /* memory_guard 句柄表扫描经直接系统调用（干净环境返回 0；
     * test_memory_safety.c 亦有覆盖，此处从 WP-9 传输视角复验） */
    CHECK_EQ(memory_guard_init(), 0);
    CHECK_EQ(memory_guard_check_remote_read(), 0);
    return 0;
}
