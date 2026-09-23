/*
 * test_system32_loader.c — System32 加载位置校验（分隔符边界）
 *
 * 验证目标：加载位置校验的前缀比较必须带分隔符边界——与 System32 目录
 * 字符串同前缀但非其子目录的旁路路径（"…\System32Malware\evil.dll"）必须
 * 被判定为不在 System32；真实 System32 子路径、大小写变体与目录本身
 * （尾分隔符/结尾边界）必须通过。修复前 _wcsnicmp 纯前缀比较会使旁路
 * 路径误通过（该路径加载的 DLL 被当作可信 System32 模块接受）。
 *
 * 测试经 system32_loader_dir_prefix_test 白盒直取判定函数（初始化后），
 * 并辅以真实 system32_loader_load 完整链路（真实 System32 DLL 加载通过、
 * 路径校验不误拒）。
 */
#include "verthys_test.h"
#include "system32_loader.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wchar.h>
#include <stdio.h>

TEST(sys32_prefix_boundary_rejects_sibling)
{
    wchar_t sysdir[MAX_PATH];
    wchar_t real[MAX_PATH];
    wchar_t sibling[2 * MAX_PATH];
    wchar_t tail[MAX_PATH];
    wchar_t mixed[MAX_PATH];
    wchar_t truncated[MAX_PATH];
    int r_real, r_sibling, r_tail, r_upper, r_trunc, r_empty, r_null;

    CHECK_EQ(system32_loader_init(), 0);
    CHECK(GetSystemDirectoryW(sysdir, MAX_PATH) > 0);

    /* 真实 System32 子路径（尾随文件名） */
    swprintf_s(real, MAX_PATH, L"%s\\kernel32.dll", sysdir);

    /* 同前缀旁路目录：System32Malware\evil.dll（判别缺陷的核心用例） */
    swprintf_s(sibling, 2 * MAX_PATH, L"%sMalware\\evil.dll", sysdir);

    /* 目录本身多一个尾分隔符（前缀后紧跟分隔符边界） */
    swprintf_s(tail, MAX_PATH, L"%s\\", sysdir);

    /* 大小写变体（判定应大小写不敏感） */
    swprintf_s(mixed, MAX_PATH, L"%s\\KERNEL32.DLL", sysdir);

    /* 截断前缀（去掉末两字符，如 "System3"）：不构成前缀 */
    swprintf_s(truncated, MAX_PATH, L"%s", sysdir);
    truncated[wcslen(truncated) - 2] = L'\0';

    /* ---- 先完成全部判定采集，再统一断言 ---- */
    r_real    = system32_loader_dir_prefix_test(real);
    r_sibling = system32_loader_dir_prefix_test(sibling);
    r_tail    = system32_loader_dir_prefix_test(tail);
    r_upper   = system32_loader_dir_prefix_test(mixed);
    r_trunc   = system32_loader_dir_prefix_test(truncated);
    r_empty   = system32_loader_dir_prefix_test(L"");
    r_null    = system32_loader_dir_prefix_test(NULL);

    CHECK_EQ(r_real, 1);      /* 真实子路径：通过 */
    CHECK_EQ(r_sibling, 0);   /* 旁路目录：拒绝（修复点） */
    CHECK_EQ(r_tail, 1);      /* 尾分隔符：通过 */
    CHECK_EQ(r_upper, 1);     /* 大小写变体：通过 */
    CHECK_EQ(r_trunc, 0);     /* 截断前缀：拒绝 */
    CHECK_EQ(r_empty, 0);     /* 空串：拒绝 */
    CHECK_EQ(r_null, 0);      /* NULL：拒绝 */
    return 0;
}

/* 完整加载链路：真实 System32 DLL 经 system32_loader_load 通过（校验不误拒） */
TEST(sys32_load_real_system32_dll)
{
    void *h = NULL;
    int rc = -1;

    CHECK_EQ(system32_loader_init(), 0);

    /* advapi32 已由进程加载：LoadLibraryEx 返回既有句柄，路径校验走全链路 */
    rc = system32_loader_load(L"advapi32.dll", &h);
    CHECK_EQ(rc, 0);
    if (h != NULL) FreeLibrary((HMODULE)h);
    return 0;
}

/* 非法参数：路径分隔符 / NULL 显式拒绝（既有契约回归） */
TEST(sys32_load_rejects_path_and_null)
{
    CHECK_EQ(system32_loader_init(), 0);
    CHECK(system32_loader_load(L"..\\evil.dll", NULL) != 0);
    CHECK(system32_loader_load(NULL, NULL) != 0);
    return 0;
}