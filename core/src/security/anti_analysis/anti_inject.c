/*
 * anti_inject.c — 深度防注入与模块认证实现
 *
 * 用户需求（二.3 深度防注入与模块认证）：
 *   1. 入口基因修复（anti_inject_harden_search_path）：
 *      - SetDllDirectoryW(L"") 移除当前工作目录在 DLL 搜索顺序中的优先级
 *      - SetSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE) 强制安全搜索
 *      - 必须在反注入模块加载前执行，杜绝“当前目录投毒”型 DLL 劫持
 *   2. 远程线程注入检测（anti_inject_check_remote_thread）：
 *      - 遍历当前进程线程，NtQueryInformationThread(9) 获取线程起始地址
 *      - 起始地址不在任何已加载模块范围内 → 疑似 CreateRemoteThread 注入
 *   3. APC 注入检测（anti_inject_check_apc）：
 *      - NtQueryInformationThread(0) 获取 TEB，检查线程初始化标志位异常
 *      - 注入线程通常跳过 DLL_THREAD_ATTACH / Loader 初始化（SameTebFlags）
 *   4. 窗口钩子注入检测（anti_inject_check_window_hook）：
 *      - 检测 SetWindowsHookEx 全局钩子（WH_CBT/WH_GETMESSAGE/WH_KEYBOARD/WH_MOUSE/WH_DEBUG）
 *      - 遍历线程 Win32ThreadInfo 钩子链 + 已知 hook 库模块扫描
 *   5. 模块白名单巡检（anti_inject_check_modules）：
 *      - CreateToolhelp32Snapshot 遍历已加载模块
 *      - 路径必须在安装目录 / System32 / SysWOW64 / 受信任白名单下
 *      - 非系统模块必须具有有效 Authenticode 数字签名（WinVerifyTrust）
 *
 * 安全策略：
 *   - 模块状态 static 变量，幂等初始化
 *   - 受信任路径白名单 static 数组存储（最大 64 路径）
 *   - 所有临时缓冲区用毕 verthys_secure_zero 清零
 *   - 检测到威胁时上报 emergency_report 触发连锁应急响应
 *   - 性能模式（anti_inject=1）下仍执行模块巡检
 */
#include "anti_inject.h"
#include "verthys_internal.h"   /* verthys_secure_zero */
#include "verthys_crypto.h"     /* verthys_crypto_init */
#include "security_preset.h"  /* security_get_config */
#include "emergency.h"        /* emergency_report */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <wctype.h>   /* towupper */

/* ---------- 链接库声明（MSVC 通过源码内 #pragma 指定链接依赖） ---------- */
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shlwapi.lib")

/* ---------- SetSearchPathMode 相关常量（来自 shlwapi.h） ----------
 * 函数原型已在 winbase.h 中声明（现代 Windows SDK），此处仅补充常量定义。
 * shlwapi.lib 已通过下方 #pragma 链接。
 */
#ifndef BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE
#define BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE 0x00000001
#endif

/* WinVerifyTrust 头文件（softpub.h 提供 WINTRUST_ACTION_GENERIC_VERIFY_V2） */
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

/* ===================================================================== *
 *                           NT API 动态加载                              *
 * ===================================================================== */

#ifndef NTAPI
#define NTAPI __stdcall
#endif

#define MY_STATUS_SUCCESS ((LONG)0x00000000)

/* NtQueryInformationThread 信息类（注意：与下方结构体 typedef 命名分离，避免冲突） */
#define MY_THREAD_BASIC_INFO_CLASS      0
#define MY_THREAD_STARTADDR_INFO_CLASS  9

/* NtQueryInformationThread 函数原型 */
typedef LONG (NTAPI *NtQueryInformationThread_t)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

/*
 * THREAD_BASIC_INFORMATION（NtQueryInformationThread 信息类 0 的输出）。
 * winternl.h 中声明，但为避免引入额外依赖，此处自定义等价结构。
 */
/* CLIENT_ID 在 winnt.h 中可能未直接可用（受 NTDDI 宏保护），自定义等价 */
typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MY_CLIENT_ID;

typedef struct _MY_THREAD_BASIC_INFORMATION {
    LONG          ExitStatus;
    PVOID         TebBaseAddress;
    MY_CLIENT_ID  ClientId;
    ULONG_PTR     Affinity;
    LONG          Priority;
    LONG          BasePriority;
} MY_THREAD_BASIC_INFORMATION;

/* ---------- TEB 关键字段偏移量（Windows 10+） ----------
 * SameTebFlags：包含线程初始化标志，注入线程会跳过 Loader/Thread 初始化
 *   - SkipThreadAttach (bit 3)：线程未接收 DLL_THREAD_ATTACH
 *   - SkipLoaderInit   (bit 14)：线程跳过 Loader 初始化
 *   注：Alertable 状态实际驻留内核 ETHREAD，TEB 中 SameTebFlags 的跳过
 *   初始化标志是用户态可观测的最强 APC/远程线程注入信号。
 * Win32ThreadInfo：指向 W32THREAD 结构，含消息钩子链表头。
 */
#if defined(_WIN64)
#define TEB_SAME_TEB_FLAGS_OFFSET   0x17EEu
#define TEB_WIN32_THREAD_INFO_OFFSET 0x078u
#define TEB_SAME_FLAGS_SIZE         2u
#else
#define TEB_SAME_TEB_FLAGS_OFFSET   0x0FCAu
#define TEB_WIN32_THREAD_INFO_OFFSET 0x040u
#define TEB_SAME_FLAGS_SIZE         2u
#endif

#define TEB_FLAG_SKIP_THREAD_ATTACH  0x0008u  /* bit 3 */
#define TEB_FLAG_SKIP_LOADER_INIT    0x4000u  /* bit 14 */

/* ---------- 模块状态 ---------- */

#define MAX_TRUSTED_PATHS 64

static int s_initialized = 0;

/* 受信任路径白名单（宽字符，规范化为大写、无尾部分隔符） */
static wchar_t s_trusted_paths[MAX_TRUSTED_PATHS][MAX_PATH];
static int s_trusted_path_count = 0;

/* 初始化时记录的基线线程数，用于 APC 注入的线程数异常比较 */
static int s_baseline_thread_count = 0;

/* ===================================================================== *
 *                              辅助函数                                  *
 * ===================================================================== */

/* 获取 NtQueryInformationThread 函数指针（ntdll.dll 必然已加载） */
static NtQueryInformationThread_t get_ntquery_thread(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) return NULL;
    return (NtQueryInformationThread_t)GetProcAddress(
        ntdll, "NtQueryInformationThread");
}

/*
 * 判断地址是否落在任意已加载模块的地址范围内。
 * 利用 GetModuleHandleExW(FROM_ADDRESS) —— 文档化 API，比手动遍历
 * 模块列表更可靠且线程安全。
 * 返回 1=在某个模块内，0=不在任何模块（疑似分配的可执行内存）。
 */
static int address_in_any_module(const void *addr)
{
    if (addr == NULL) return 0;
    HMODULE hMod = NULL;
    BOOL ok = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)addr,
        &hMod);
    if (!ok || hMod == NULL) return 0;
    return 1;
}

/*
 * 判断地址是否落在受信任模块（安装目录或系统目录下的模块）内。
 * 用于钩子链扫描：钩子过程地址若指向非受信任模块 → 疑似钩子注入。
 */
static int address_in_trusted_module(const void *addr,
                                     const wchar_t *install_dir,
                                     const wchar_t *system32_dir,
                                     const wchar_t *syswow64_dir)
{
    HMODULE hMod = NULL;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)addr, &hMod) || hMod == NULL) {
        return 0;  /* 不在任何模块 → 非受信任 */
    }

    wchar_t mod_path[MAX_PATH];
    DWORD n = GetModuleFileNameW(hMod, mod_path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return 0;

    /* 转大写做前缀比较 */
    wchar_t upper_path[MAX_PATH];
    memcpy(upper_path, mod_path, sizeof(upper_path));
    for (int i = 0; upper_path[i]; i++) {
        upper_path[i] = (wchar_t)towupper(upper_path[i]);
    }

    int trusted = 0;
    if (install_dir != NULL && _wcsnicmp(upper_path, install_dir, wcslen(install_dir)) == 0) {
        trusted = 1;
    } else if (system32_dir != NULL && _wcsnicmp(upper_path, system32_dir, wcslen(system32_dir)) == 0) {
        trusted = 1;
    } else if (syswow64_dir != NULL && _wcsnicmp(upper_path, syswow64_dir, wcslen(syswow64_dir)) == 0) {
        trusted = 1;
    }

    /* 检查受信任路径白名单 */
    if (!trusted) {
        for (int i = 0; i < s_trusted_path_count; i++) {
            if (_wcsnicmp(upper_path, s_trusted_paths[i],
                          wcslen(s_trusted_paths[i])) == 0) {
                trusted = 1;
                break;
            }
        }
    }

    verthys_secure_zero(upper_path, sizeof(upper_path));
    verthys_secure_zero(mod_path, sizeof(mod_path));
    return trusted;
}

/* 安全读取指定进程内内存（TEB 等），失败返回 0 */
static int safe_read_memory(const void *addr, void *buf, size_t len)
{
    if (addr == NULL || buf == NULL || len == 0) return 0;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & PAGE_NOACCESS) return 0;

    __try {
        memcpy(buf, addr, len);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

/*
 * ★ 方案 §6.2.2（P1-N 修复）：目录前缀匹配（带分隔符边界）。
 *
 * 原缺陷：_wcsnicmp(path, dir, wcslen(dir)) 无分隔符边界——
 * "C:\Windows\System32Malware\evil.dll" 也能通过 System32 前缀检查。
 * 修复：前缀一致后，path 中紧随前缀的字符必须是路径分隔符或字符串结尾。
 * dir 传入前已规范化为大写、无尾部分隔符。
 */
static int dir_prefix_matches(const wchar_t *dir, const wchar_t *path)
{
    if (dir == NULL || path == NULL) return 0;
    size_t dlen = wcslen(dir);
    if (dlen == 0) return 0;
    if (_wcsnicmp(path, dir, dlen) != 0) return 0;
    wchar_t next = path[dlen];
    return (next == L'\0' || next == L'\\' || next == L'/');
}

/* 路径转大写并去除尾部路径分隔符（原地修改） */
static void normalize_path_upper(wchar_t *path)
{
    if (path == NULL) return;
    size_t len = wcslen(path);
    while (len > 0 && (path[len - 1] == L'\\' || path[len - 1] == L'/')) {
        path[--len] = L'\0';
    }
    for (size_t i = 0; i < len; i++) {
        path[i] = (wchar_t)towupper(path[i]);
    }
}

/* 获取安装目录（主 EXE 所在目录），成功返回 1 */
static int get_install_dir(wchar_t *out, size_t cap)
{
    wchar_t exe_path[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, exe_path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return 0;

    /* 截取到最后一个路径分隔符 */
    wchar_t *p = wcsrchr(exe_path, L'\\');
    if (p == NULL) {
        p = wcsrchr(exe_path, L'/');
    }
    if (p == NULL) return 0;
    *p = L'\0';

    normalize_path_upper(exe_path);
    wcscpy_s(out, cap, exe_path);
    verthys_secure_zero(exe_path, sizeof(exe_path));
    return 1;
}

/* 获取系统目录（System32），成功返回 1 */
static int get_system32_dir(wchar_t *out, size_t cap)
{
    UINT n = GetSystemDirectoryW(out, (UINT)cap);
    if (n == 0 || n >= cap) return 0;
    normalize_path_upper(out);
    return 1;
}

/* 获取 SysWOW64 目录（System32 同级），成功返回 1 */
static int get_syswow64_dir(wchar_t *out, size_t cap)
{
    wchar_t sys_dir[MAX_PATH];
    UINT n = GetSystemDirectoryW(sys_dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return 0;

    /* System32 通常为 C:\Windows\System32，SysWOW64 为同级 \SysWOW64 */
    wchar_t *p = wcsrchr(sys_dir, L'\\');
    if (p == NULL) return 0;
    *p = L'\0';

    if (wcscat_s(sys_dir, MAX_PATH, L"\\SysWOW64") != 0) return 0;
    normalize_path_upper(sys_dir);
    wcscpy_s(out, cap, sys_dir);
    verthys_secure_zero(sys_dir, sizeof(sys_dir));
    return 1;
}

/*
 * 通过 WinVerifyTrust 验证文件的 Authenticode 数字签名。
 * 返回 1=签名有效，0=无签名或验证失败。
 * 使用 WTD_REVOKE_NONE 跳过吊销检查（离线可用，避免网络延迟）。
 */
static int verify_module_signature(const wchar_t *file_path)
{
    if (file_path == NULL) return 0;

    WINTRUST_FILE_INFO file_info;
    memset(&file_info, 0, sizeof(file_info));
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = file_path;
    file_info.hFile = NULL;
    file_info.pgKnownSubject = NULL;

    WINTRUST_DATA trust_data;
    memset(&trust_data, 0, sizeof(trust_data));
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.pPolicyCallbackData = NULL;
    trust_data.pSIPClientData = NULL;
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.hWVTStateData = NULL;
    trust_data.pwszURLReference = NULL;
    trust_data.dwProvFlags = 0;
    trust_data.dwUIContext = 0;

    /* Authenticode 策略 GUID */
    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG result = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policy_guid, &trust_data);

    /* 清理状态（必须调用，避免资源泄漏） */
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policy_guid, &trust_data);

    return (result == 0) ? 1 : 0;
}

/*
 * 统计当前进程的线程数量。
 * 返回线程数（包含主线程），失败返回 -1。
 */
static int count_process_threads(DWORD pid, DWORD *out_main_tid)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return -1;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int count = 0;

    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                count++;
                if (out_main_tid != NULL && te.th32ThreadID == GetCurrentThreadId()) {
                    *out_main_tid = te.th32ThreadID;
                }
            }
        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);
    return count;
}

/* ===================================================================== *
 *                       1. 远程线程注入检测                              *
 * ===================================================================== */

/*
 * 遍历当前进程所有线程，对非主线程查询其 Win32 起始地址。
 * 若起始地址不在任何已加载模块范围内 → 疑似远程线程注入
 *（CreateRemoteThread 的线程起始地址通常指向 VirtualAllocEx 分配的内存）。
 */
int anti_inject_check_remote_thread(void)
{
    const SecurityConfig *cfg = security_get_config();
    if (cfg == NULL || !cfg->anti_inject) return 0;

    NtQueryInformationThread_t pNtQuery = get_ntquery_thread();
    if (pNtQuery == NULL) return 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    DWORD pid = GetCurrentProcessId();
    DWORD main_tid = GetCurrentThreadId();
    int threat = 0;

    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == main_tid) continue;  /* 排除主线程 */

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
                                        FALSE, te.th32ThreadID);
            if (hThread == NULL) continue;

            PVOID start_addr = NULL;
            ULONG ret_len = 0;
            LONG status = pNtQuery(hThread,
                                   MY_THREAD_STARTADDR_INFO_CLASS,
                                   &start_addr,
                                   sizeof(start_addr),
                                   &ret_len);
            CloseHandle(hThread);

            if (status != MY_STATUS_SUCCESS) continue;

            /* 起始地址不在任何已加载模块 → 疑似远程线程注入 */
            if (!address_in_any_module(start_addr)) {
                threat |= INJECT_THREAT_REMOTE_THREAD;
                emergency_report(EMERG_LEVEL_TELEMETRY, EMERG_SIG_HOOK_DETECTED);
            }
        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);
    return threat;
}

/* ===================================================================== *
 *                          2. APC 注入检测                               *
 * ===================================================================== */

/*
 * 检测 APC 注入：遍历当前进程线程，通过 NtQueryInformationThread
 *（ThreadBasicInformation）获取 TEB，检查 SameTebFlags 中的线程
 * 初始化跳过标志。注入线程（CreateRemoteThread / QueueUserAPC 触发）
 * 通常跳过 DLL_THREAD_ATTACH 与 Loader 初始化，这些标志位是用户态
 * 可观测的最强注入信号。
 *
 * 辅助信号：线程数相比基线显著增加 → 疑似注入线程。
 */
int anti_inject_check_apc(void)
{
    const SecurityConfig *cfg = security_get_config();
    if (cfg == NULL || !cfg->anti_inject) return 0;

    NtQueryInformationThread_t pNtQuery = get_ntquery_thread();
    if (pNtQuery == NULL) return 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    DWORD pid = GetCurrentProcessId();
    DWORD main_tid = GetCurrentThreadId();
    int threat = 0;

    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == main_tid) continue;  /* 排除主线程 */

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
                                        FALSE, te.th32ThreadID);
            if (hThread == NULL) continue;

            MY_THREAD_BASIC_INFORMATION tbi;
            memset(&tbi, 0, sizeof(tbi));
            ULONG ret_len = 0;
            LONG status = pNtQuery(hThread,
                                   MY_THREAD_BASIC_INFO_CLASS,
                                   &tbi,
                                   sizeof(tbi),
                                   &ret_len);
            CloseHandle(hThread);

            if (status != MY_STATUS_SUCCESS) continue;
            if (tbi.TebBaseAddress == NULL) continue;

            /* 安全读取 TEB 的 SameTebFlags 字段 */
            unsigned char flags_buf[TEB_SAME_FLAGS_SIZE];
            memset(flags_buf, 0, sizeof(flags_buf));
            const void *flags_addr =
                (const void *)((const unsigned char *)tbi.TebBaseAddress +
                               TEB_SAME_TEB_FLAGS_OFFSET);

            if (safe_read_memory(flags_addr, flags_buf, sizeof(flags_buf))) {
                unsigned short flags =
                    (unsigned short)(flags_buf[0] |
                                     (flags_buf[1] << 8));
                /* 注入线程跳过 Thread 初始化或 Loader 初始化 */
                if ((flags & TEB_FLAG_SKIP_THREAD_ATTACH) ||
                    (flags & TEB_FLAG_SKIP_LOADER_INIT)) {
                    threat |= INJECT_THREAT_APC;
                    emergency_report(EMERG_LEVEL_TELEMETRY, EMERG_SIG_HOOK_DETECTED);
                }
            }
        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);

    /* 辅助信号：线程数相比基线显著增加（>2倍） → 疑似注入 */
    if (s_baseline_thread_count > 0) {
        DWORD main_tid_dummy = 0;
        int current = count_process_threads(pid, &main_tid_dummy);
        if (current > 0 && current >= s_baseline_thread_count * 2) {
            threat |= INJECT_THREAT_APC;
        }
    }

    return threat;
}

/* ===================================================================== *
 *                       3. 窗口钩子注入检测                              *
 * ===================================================================== */

/* 已知 hook 注入库 DLL 名称（GetModuleHandleW 大小写不敏感，可省略扩展名） */
static const wchar_t *s_known_hook_dlls[] = {
    L"easyhook32",
    L"easyhook64",
    L"minhook.x86",
    L"minhook.x64",
    L"detoured",
    L"mhook",
    L"hooklib",
    L"api_log",
};

/* 检查是否加载了已知 hook 库 */
static int check_known_hook_dlls(void)
{
    for (int i = 0;
         i < (int)(sizeof(s_known_hook_dlls) / sizeof(s_known_hook_dlls[0]));
         i++) {
        if (GetModuleHandleW(s_known_hook_dlls[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

/*
 * 检查线程的消息钩子链：读取 TEB->Win32ThreadInfo 指向的 W32THREAD
 * 结构，扫描其中指针是否指向非受信任模块（钩子过程地址）。
 * W32THREAD 结构布局未文档化，采用扫描前 256 字节中的指针值，
 * 判断是否落在非系统/非安装目录模块内。
 */
static int check_thread_hook_chain(const wchar_t *install_dir,
                                   const wchar_t *system32_dir,
                                   const wchar_t *syswow64_dir)
{
    NtQueryInformationThread_t pNtQuery = get_ntquery_thread();
    if (pNtQuery == NULL) return 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    DWORD pid = GetCurrentProcessId();
    int found_hook = 0;

    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION,
                                        FALSE, te.th32ThreadID);
            if (hThread == NULL) continue;

            MY_THREAD_BASIC_INFORMATION tbi;
            memset(&tbi, 0, sizeof(tbi));
            ULONG ret_len = 0;
            LONG status = pNtQuery(hThread,
                                   MY_THREAD_BASIC_INFO_CLASS,
                                   &tbi,
                                   sizeof(tbi),
                                   &ret_len);
            CloseHandle(hThread);

            if (status != MY_STATUS_SUCCESS) continue;
            if (tbi.TebBaseAddress == NULL) continue;

            /* 读取 TEB->Win32ThreadInfo 指针 */
            PVOID win32_thread_info = NULL;
            const void *wti_addr =
                (const void *)((const unsigned char *)tbi.TebBaseAddress +
                               TEB_WIN32_THREAD_INFO_OFFSET);
            if (!safe_read_memory(wti_addr, &win32_thread_info,
                                  sizeof(win32_thread_info))) {
                continue;
            }
            if (win32_thread_info == NULL) continue;  /* 无 GUI 线程，跳过 */

            /* 扫描 W32THREAD 结构前 256 字节中的指针 */
            unsigned char w32_buf[256];
            memset(w32_buf, 0, sizeof(w32_buf));
            if (!safe_read_memory(win32_thread_info, w32_buf, sizeof(w32_buf))) {
                continue;
            }

            size_t ptr_size = sizeof(void *);
            for (size_t off = 0;
                 off + ptr_size <= sizeof(w32_buf);
                 off += ptr_size) {
                PVOID val = NULL;
                memcpy(&val, w32_buf + off, ptr_size);
                if (val == NULL) continue;

                /* 指针指向非受信任模块 → 疑似钩子过程 */
                if (!address_in_trusted_module(val, install_dir,
                                               system32_dir, syswow64_dir)) {
                    /* 确认指针确实落在某个模块内（排除随机值） */
                    if (address_in_any_module(val)) {
                        found_hook = 1;
                        break;
                    }
                }
            }

            verthys_secure_zero(w32_buf, sizeof(w32_buf));
            if (found_hook) break;
        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);
    return found_hook;
}

/*
 * 检测窗口钩子注入：综合已知 hook 库扫描 + 线程消息钩子链检查。
 * 检测 SetWindowsHookEx 安装的全局钩子（WH_CBT/WH_GETMESSAGE 等）。
 */
int anti_inject_check_window_hook(void)
{
    const SecurityConfig *cfg = security_get_config();
    if (cfg == NULL || !cfg->anti_inject) return 0;

    int threat = 0;

    /* 1. 已知 hook 库模块扫描 */
    if (check_known_hook_dlls()) {
        threat |= INJECT_THREAT_WINDOW_HOOK;
    }

    /* 2. 线程消息钩子链检查 */
    wchar_t install_dir[MAX_PATH];
    wchar_t system32_dir[MAX_PATH];
    wchar_t syswow64_dir[MAX_PATH];
    int got_paths = 0;

    if (get_install_dir(install_dir, MAX_PATH) &&
        get_system32_dir(system32_dir, MAX_PATH) &&
        get_syswow64_dir(syswow64_dir, MAX_PATH)) {
        got_paths = 1;
    }

    if (got_paths) {
        if (check_thread_hook_chain(install_dir, system32_dir, syswow64_dir)) {
            threat |= INJECT_THREAT_WINDOW_HOOK;
        }
        verthys_secure_zero(install_dir, sizeof(install_dir));
        verthys_secure_zero(system32_dir, sizeof(system32_dir));
        verthys_secure_zero(syswow64_dir, sizeof(syswow64_dir));
    }

    if (threat & INJECT_THREAT_WINDOW_HOOK) {
        emergency_report(EMERG_LEVEL_TELEMETRY, EMERG_SIG_HOOK_DETECTED);
    }

    return threat;
}

/* ===================================================================== *
 *                       4. 模块白名单巡检                                *
 * ===================================================================== */

/*
 * 遍历当前进程已加载模块，验证模块信任（方案 §6.2.2 信任模型）：
 *   a) 有效 Authenticode 签名（WinVerifyTrust）→ 信任（签名优先）；
 *   b) 无签名但位于 System32 / SysWOW64 / 安装目录 / 白名单路径 →
 *      按位置信任（系统目录模块使用目录签名/catalog，非内嵌 Authenticode）；
 *   c) 其余（无签名且路径不受信任）→ TELEMETRY 上报 UNKNOWN_DLL。
 *
 * 与原实现的差异：
 *   - 签名优先于位置：第三方合法签名 DLL 不再因安装目录外而误报；
 *   - 目录前缀匹配带分隔符边界（dir_prefix_matches，P1-N 修复）；
 *   - 威胁上报统一为 TELEMETRY 级（低置信度启发式，方案 §6.1）。
 */
int anti_inject_check_modules(void)
{
    const SecurityConfig *cfg = security_get_config();
    /* 性能模式（anti_inject=1）下仍执行模块巡检 */
    if (cfg == NULL || !cfg->anti_inject) return 0;

    wchar_t install_dir[MAX_PATH];
    wchar_t system32_dir[MAX_PATH];
    wchar_t syswow64_dir[MAX_PATH];

    if (!get_install_dir(install_dir, MAX_PATH) ||
        !get_system32_dir(system32_dir, MAX_PATH) ||
        !get_syswow64_dir(syswow64_dir, MAX_PATH)) {
        return 0;  /* 路径获取失败，不阻断 */
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        verthys_secure_zero(install_dir, sizeof(install_dir));
        verthys_secure_zero(system32_dir, sizeof(system32_dir));
        verthys_secure_zero(syswow64_dir, sizeof(syswow64_dir));
        return 0;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    int threat = 0;

    if (Module32FirstW(snapshot, &me)) {
        do {
            const wchar_t *mod_path = me.szExePath;
            if (mod_path == NULL || mod_path[0] == L'\0') continue;

            /* 路径转大写副本用于前缀比较 */
            wchar_t upper_path[MAX_PATH];
            wcscpy_s(upper_path, MAX_PATH, mod_path);
            normalize_path_upper(upper_path);

            /* a) 签名优先：有效 Authenticode 签名即信任 */
            if (verify_module_signature(mod_path)) {
                verthys_secure_zero(upper_path, sizeof(upper_path));
                continue;
            }

            /* b) 无签名：按位置信任（System32 / SysWOW64 / 安装目录 / 白名单） */
            int in_trusted_location =
                dir_prefix_matches(install_dir, upper_path) ||
                dir_prefix_matches(system32_dir, upper_path) ||
                dir_prefix_matches(syswow64_dir, upper_path);
            if (!in_trusted_location) {
                for (int i = 0; i < s_trusted_path_count; i++) {
                    if (dir_prefix_matches(s_trusted_paths[i], upper_path)) {
                        in_trusted_location = 1;
                        break;
                    }
                }
            }

            if (!in_trusted_location) {
                /* c) 无签名且路径不受信任 → 未知第三方 DLL（TELEMETRY） */
                threat |= INJECT_THREAT_UNKNOWN_DLL;
                emergency_report(EMERG_LEVEL_TELEMETRY, EMERG_SIG_UNKNOWN_DLL);
            }

            verthys_secure_zero(upper_path, sizeof(upper_path));
        } while (Module32NextW(snapshot, &me));
    }

    CloseHandle(snapshot);
    verthys_secure_zero(install_dir, sizeof(install_dir));
    verthys_secure_zero(system32_dir, sizeof(system32_dir));
    verthys_secure_zero(syswow64_dir, sizeof(syswow64_dir));

    return threat;
}

/* ===================================================================== *
 *                       5. 综合检测                                      *
 * ===================================================================== */

int anti_inject_check_all(void)
{
    int threat = 0;
    threat |= anti_inject_check_remote_thread();
    threat |= anti_inject_check_apc();
    threat |= anti_inject_check_window_hook();
    threat |= anti_inject_check_modules();
    return threat;
}

/* ===================================================================== *
 *                       初始化与配置接口                                  *
 * ===================================================================== */

/*
 * 执行入口基因修复（DLL 搜索顺序加固）。
 * 必须在程序入口点最早执行（在加载任何其他 DLL 之前）。
 * Windows: SetDllDirectoryW(L"") + SetSearchPathMode
 * Linux/Mac: 无操作（Unix 系统不依赖搜索路径）
 */
int anti_inject_harden_search_path(void)
{
    /*
     * SetDllDirectoryW(L"")：从 DLL 搜索顺序中移除当前工作目录，
     * 防止攻击者在工作目录放置恶意 DLL 实施劫持。
     */
    SetDllDirectoryW(L"");

    /*
     * SetSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE)：
     * 强制安全搜索模式，系统目录始终优先于当前目录。
     */
    SetSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE);

    return 0;
}

/*
 * 添加受信任模块路径（白名单）。
 * 用于注册已知安全的第三方 DLL（如 Tauri 运行时依赖）。
 * 路径以 UTF-8 传入，内部转为宽字符并规范化（大写、去尾部分隔符）。
 */
int anti_inject_add_trusted_path(const char *path)
{
    if (path == NULL) return -1;
    if (s_trusted_path_count >= MAX_TRUSTED_PATHS) return -1;

    wchar_t wpath[MAX_PATH];
    int len = MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, MAX_PATH);
    if (len == 0) return -1;

    normalize_path_upper(wpath);

    /* 检查重复 */
    for (int i = 0; i < s_trusted_path_count; i++) {
        if (_wcsicmp(wpath, s_trusted_paths[i]) == 0) {
            verthys_secure_zero(wpath, sizeof(wpath));
            return 0;  /* 已存在，幂等返回 */
        }
    }

    wcscpy_s(s_trusted_paths[s_trusted_path_count], MAX_PATH, wpath);
    s_trusted_path_count++;

    verthys_secure_zero(wpath, sizeof(wpath));
    return 0;
}

/*
 * 初始化防注入模块（幂等）。
 * 执行 DLL 搜索顺序加固，记录基线线程数。
 * 返回 0 成功，非 0 失败。
 */
int anti_inject_init(void)
{
    if (s_initialized) return 0;

    /* 确保密码库可用（模块依赖初始化链） */
    if (verthys_crypto_init() != 0) {
        return -1;
    }

    /* 执行入口基因修复（即使重复调用也是幂等安全的） */
    anti_inject_harden_search_path();

    /* 记录基线线程数（用于 APC 注入的线程数异常比较） */
    DWORD main_tid = 0;
    int tc = count_process_threads(GetCurrentProcessId(), &main_tid);
    s_baseline_thread_count = (tc > 0) ? tc : 0;

    s_initialized = 1;
    return 0;
}
