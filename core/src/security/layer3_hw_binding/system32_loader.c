/*
 * system32_loader.c — System32 优先加载与 cnghwassist.sys 冲突解决实现
 */
#include "system32_loader.h"
#include "verthys_internal.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlwapi.h>
#include <string.h>
#include <stdio.h>   /* swprintf_s 是 <stdio.h>/<wchar.h> 中的内联包装函数，
                       * 实际调用 __stdio_common_vswprintf_s（ucrt.lib）。
                       * 不包含此头文件会导致隐式声明，链接器找不到 swprintf_s。 */

/* LOAD_LIBRARY_SEARCH_SYSTEM32 常量 */
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif

#ifndef LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
#define LOAD_LIBRARY_SEARCH_DEFAULT_DIRS 0x00001000
#endif

/* ---------- 模块状态 ---------- */

static SysLoaderMode s_mode = SYSLOADER_MODE_HW_ASSIST;
static int s_initialized = 0;
static wchar_t s_system32_dir[MAX_PATH];
static wchar_t s_module_dir[MAX_PATH];

/* ---------- 检测 cnghwassist.sys ---------- */

static int driver_exists(const wchar_t *driver_name)
{
    wchar_t path[MAX_PATH];
    if (GetSystemDirectoryW(s_system32_dir, MAX_PATH) == 0) {
        return 0;
    }
    /* drivers 子目录 */
    swprintf_s(path, MAX_PATH, L"%s\\drivers\\%s", s_system32_dir, driver_name);
    return PathFileExistsW(path) ? 1 : 0;
}

/* System32 目录前缀匹配（带分隔符边界）。
 *
 * 原缺陷：_wcsnicmp(path, dir, wcslen(dir)) 无分隔符边界——
 * 与 System32 同前缀的旁路目录（如 "C:\Windows\System32Malware\evil.dll"）
 * 也能通过前缀检查。修复：前缀一致后，path 中紧随前缀的字符必须是路径
 * 分隔符或字符串结尾。dir 以 GetSystemDirectoryW 结果为准（无尾部
 * 分隔符），大小写不敏感（_wcsnicmp）。
 */
static int system32_dir_prefix(const wchar_t *path)
{
    size_t dlen;

    if (path == NULL) return 0;
    dlen = wcslen(s_system32_dir);
    if (dlen == 0) return 0;
    if (_wcsnicmp(path, s_system32_dir, dlen) != 0) return 0;
    return (path[dlen] == L'\0' || path[dlen] == L'\\' || path[dlen] == L'/');
}

/* 测试白盒：暴露前缀边界判定（仅 test 对象直链调用，不入 DLL 导出清单） */
int system32_loader_dir_prefix_test(const wchar_t *path)
{
    return system32_dir_prefix(path);
}

/* ---------- 公共接口 ---------- */

int system32_loader_init(void)
{
    if (s_initialized) return 0;
    s_initialized = 1;

    /* 1. 获取 System32 目录 */
    if (GetSystemDirectoryW(s_system32_dir, MAX_PATH) == 0) {
        return -1;
    }

    /* 2. 获取当前模块所在目录 */
    HMODULE hSelf = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&system32_loader_init, &hSelf);
    if (hSelf && GetModuleFileNameW(hSelf, s_module_dir, MAX_PATH) > 0) {
        /* 截断到目录路径 */
        wchar_t *p = wcsrchr(s_module_dir, L'\\');
        if (p) *p = L'\0';
    }

    /* 3. 设置默认 DLL 搜索路径：System32 优先 */
    /*    SetDefaultDllDirectories 等价于 IMAGE_LOAD_PREFER_SYSTEM32 */
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
        typedef BOOL (WINAPI *pSetDefaultDllDirectories_t)(DWORD);
        pSetDefaultDllDirectories_t pSetDefaultDllDirectories =
            (pSetDefaultDllDirectories_t)GetProcAddress(
                hKernel32, "SetDefaultDllDirectories");
        if (pSetDefaultDllDirectories) {
            pSetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                       LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        }
    }

    /* 4. 检测 cnghwassist.sys */
    if (driver_exists(L"cnghwassist.sys")) {
        s_mode = SYSLOADER_MODE_HW_ASSIST;
    } else {
        s_mode = SYSLOADER_MODE_PURE_SOFT;
    }

    return 0;
}

SysLoaderMode system32_loader_get_mode(void)
{
    return s_mode;
}

int system32_loader_load(const wchar_t *dll_name, void **out_handle)
{
    if (!s_initialized || dll_name == NULL || out_handle == NULL) return -1;

    /* 1. 仅允许文件名（禁止路径分隔符） */
    if (wcschr(dll_name, L'\\') || wcschr(dll_name, L'/')) {
        return -2;  /* 拒绝路径，仅允许文件名 */
    }

    /* 2. 优先从 System32 加载（带 LOAD_LIBRARY_SEARCH_SYSTEM32） */
    HMODULE hMod = LoadLibraryExW(dll_name, NULL,
                                    LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (hMod) {
        /* 验证加载位置确实是 System32 */
        wchar_t loaded_path[MAX_PATH] = {0};
        if (GetModuleFileNameW(hMod, loaded_path, MAX_PATH) > 0) {
            if (!system32_dir_prefix(loaded_path)) {
                /* 不是从 System32 加载，拒绝 */
                FreeLibrary(hMod);
                return -3;
            }
        }
        *out_handle = (void *)hMod;
        return 0;
    }

    /* 3. System32 加载失败，尝试从当前模块目录 */
    if (s_module_dir[0] != L'\0') {
        wchar_t full_path[MAX_PATH];
        swprintf_s(full_path, MAX_PATH, L"%s\\%s", s_module_dir, dll_name);
        hMod = LoadLibraryExW(full_path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (hMod) {
            *out_handle = (void *)hMod;
            return 0;
        }
    }

    /* 4. 捕获 STATUS_IMAGE_NOT_FOUND（错误码映射到 HRESULT 0xC0000225） */
    DWORD err = GetLastError();
    if (err == ERROR_MOD_NOT_FOUND) {
        /* 驱动或依赖 DLL 缺失，返回特定错误码供上层降级 */
        return -100;
    }
    return -4;
}
