/*
 * test_anti_inject.c — 防注入线程基线重采样（白名单）单元验证
 *
 * 覆盖（APC 线程增长检测的内部线程白名单判定）：
 *   - 本库自身模块（verthys.dll / 测试 exe）内地址的线程入口 → 判定为内部线程，
 *     不计入可疑增长计数
 *   - 外部 DLL 函数入口（ntdll 导出）→ 判定为外部线程，计入可疑增长计数
 *   - 未落任何模块的内存（VirtualAlloc）→ 判定为外部线程，计入可疑增长计数
 *
 * 背景：原 APC 增长检测按"进程线程总数"与基线比较，解锁期合法内部线程
 *（preheat / 进度消费）增长超过 2× 即误报。修复后仅统计自身模块外的线程。
 */
#include "verthys_test.h"
#include "anti_inject.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* 模块内地址样本：本测试翻译单元内函数入口（与 verthys core 同落 am / exe） */
static void ai_internal_probe(void) {}

TEST(ai_thread_internal_address_in_own_module)
{
    int r = anti_inject_thread_in_own_module((const void *)&ai_internal_probe);
    CHECK_EQ(r, 1);
    return 0;
}

TEST(ai_thread_external_dll_address_not_in_own_module)
{
    /* ntdll 导出函数入口：外部 DLL，不在本库自身模块内 */
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const void *ext = (ntdll != NULL)
        ? (const void *)GetProcAddress(ntdll, "NtQueryInformationThread")
        : NULL;
    CHECK(ext != NULL);
    CHECK_EQ(anti_inject_thread_in_own_module(ext), 0);
    return 0;
}

TEST(ai_thread_unmapped_address_not_in_own_module)
{
    /* 非模块内存：堆式执行内存，GetModuleHandleExW 无法定位归属 */
    void *mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    int r = anti_inject_thread_in_own_module((const void *)mem);
    if (mem != NULL) {
        VirtualFree(mem, 0, MEM_RELEASE);
    }
    CHECK(mem != NULL);
    CHECK_EQ(r, 0);
    return 0;
}