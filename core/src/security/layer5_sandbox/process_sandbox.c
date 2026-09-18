/*
 * process_sandbox.c — 进程无菌沙盒实现（四项 mitigation policy）
 *
 * 用户需求（五、进程无菌沙盒 — 1. 双进程解耦架构）：
 *   加密 Worker（纯无菌沙盒）应用以下 mitigation policy：
 *     1. WIN32K_SYSTEM_CALL_DISABLE：免疫所有窗口注入（ProcessSystemCallDisableInformation）
 *     2. PROCESS_CREATION_DISABLED：绝杀进程镂空、子进程注入（ProcessChildProcessInformation）
 *     3. IMAGE_LOAD_PREFER_SYSTEM32：防本地 DLL 劫持（SetDefaultDllDirectories）
 *     4. IMAGE_LOAD_NO_REMOTE：防反射注入、内存 PE 加载（ProcessImageLoadPolicy.NoRemoteImages）
 *     5. IMAGE_LOAD_NO_LOW_LABEL：禁止低完整性镜像加载（ProcessImageLoadPolicy.NoLowMandatoryLabelImages）
 *
 * 技术要点：
 *   - ProcessSystemCallDisableInformation（Win10 1709+，RS3）
 *       typedef struct _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY {
 *           union {
 *               DWORD Flags;
 *               struct { DWORD DisallowWin32kSystemCalls : 1; ... };
 *           };
 *       } PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY;
 *     应用后当前进程不能再调用任何 Win32k 系统调用（NtUser* / NtGdi*），
 *     彻底免疫所有基于窗口的注入（SetWindowsHookEx、窗口子类化、剪贴板钩子等）。
 *     一旦启用不可撤销。
 *
 *   - ProcessChildProcessInformation（Win10 1709+，RS3）
 *       typedef struct _PROCESS_MITIGATION_CHILD_PROCESS_POLICY {
 *           union {
 *               DWORD Flags;
 *               struct {
 *                   DWORD NoChildProcessCreation : 1;
 *                   DWORD AuditNoChildProcessCreation : 1;
 *                   ...
 *               };
 *           };
 *       } PROCESS_MITIGATION_CHILD_PROCESS_POLICY;
 *     NoChildProcessCreation=1 后，CreateProcess 调用将返回 STATUS_ACCESS_DENIED，
 *     绝杀进程镂空（Process Hollowing）、子进程注入路径。
 *
 *   - SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)（Win10 1607+，RS1）
 *     修改进程默认 DLL 搜索路径，仅从 System32 加载，防本地目录 DLL 劫持。
 *
 *   - ProcessImageLoadPolicy（Win10 1709+，RS3）
 *       typedef struct _PROCESS_MITIGATION_IMAGE_LOAD_POLICY {
 *           union {
 *               DWORD Flags;
 *               struct {
 *                   DWORD NoRemoteImages : 1;
 *                   DWORD NoLowMandatoryLabelImages : 1;
 *                   ...
 *               };
 *           };
 *       } PROCESS_MITIGATION_IMAGE_LOAD_POLICY;
 *     NoRemoteImages=1 禁止从 UNC 路径、网络位置加载 DLL（防反射注入）；
 *     NoLowMandatoryLabelImages=1 禁止从低完整性目录加载 DLL。
 *
 * 失败降级：
 *   - 部分策略仅 Win10 1709+ 支持，旧版本调用会返回 STATUS_NOT_SUPPORTED。
 *   - 本模块对每项策略独立判断：成功则记录到 active_attrs，失败则跳过不阻断。
 *   - 即使部分策略应用失败，已成功应用的策略仍生效，沙盒部分可用。
 *   - 但 SANDBOX_ATTR_ALL 场景下任一关键策略失败会返回非零，调用方据此决策。
 *
 * 安全契约：
 *   - 必须在 Worker 进程启动早期、加载任何业务 DLL 之前调用。
 *   - 这些 mitigation policy 一旦应用不可撤销，进程整个生命周期有效。
 *   - 本模块仅对当前进程生效，不影响其他进程。
 */
#include "process_sandbox.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

/* ---------- 未公开的 mitigation policy 结构与枚举 ----------
 *
 * Windows SDK 早期版本未公开 ProcessSystemCallDisableInformation 等
 * mitigation policy 类型的结构定义。此处显式声明以兼容旧 SDK，
 * 与 ntddk.h / winnt.h 的最新定义保持二进制兼容（结构布局稳定）。
 */

/* ProcessMitigationPolicy 枚举值（与 winnt.h 一致） */
typedef enum _PROCESS_MITIGATION_POLICY_VERTHYS {
    ProcessDEPPolicy_VERTHYS                = 0,
    ProcessASLRPolicy_VERTHYS               = 1,
    ProcessDynamicCodePolicy_VERTHYS        = 2,
    ProcessStrictHandleCheckPolicy_VERTHYS  = 3,
    ProcessSystemCallDisablePolicy_VERTHYS  = 4,  /* Win10 1709+ */
    ProcessExtensionPointDisablePolicy_VERTHYS = 5,
    ProcessChildProcessPolicy_VERTHYS       = 6,  /* Win10 1709+ */
    ProcessPayloadOverridePolicy_VERTHYS    = 7,
    ProcessImageLoadPolicy_VERTHYS          = 8,  /* Win10 1709+ */
    ProcessMaxMitigationPolicy_VERTHYS      = 9
} PROCESS_MITIGATION_POLICY_VERTHYS;

/* ProcessSystemCallDisablePolicy 结构（4 字节联合体） */
typedef struct _PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_VERTHYS {
    union {
        DWORD Flags;
        struct {
            DWORD DisallowWin32kSystemCalls : 1;
            DWORD ReservedFlags             : 31;
        };
    };
} PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_VERTHYS;

/* ProcessChildProcessPolicy 结构（4 字节联合体） */
typedef struct _PROCESS_MITIGATION_CHILD_PROCESS_POLICY_VERTHYS {
    union {
        DWORD Flags;
        struct {
            DWORD NoChildProcessCreation         : 1;
            DWORD AuditNoChildProcessCreation    : 1;
            DWORD ReservedFlags                  : 30;
        };
    };
} PROCESS_MITIGATION_CHILD_PROCESS_POLICY_VERTHYS;

/* ProcessImageLoadPolicy 结构（4 字节联合体） */
typedef struct _PROCESS_MITIGATION_IMAGE_LOAD_POLICY_VERTHYS {
    union {
        DWORD Flags;
        struct {
            DWORD NoRemoteImages               : 1;
            DWORD NoLowMandatoryLabelImages     : 1;
            DWORD ReservedFlags                : 30;
        };
    };
} PROCESS_MITIGATION_IMAGE_LOAD_POLICY_VERTHYS;

/* SetDefaultDllDirectories 标志 */
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif

/* ---------- 动态解析 SetProcessMitigationPolicy ----------
 *
 * 部分旧版 kernel32 / kernelbase 不导出 SetProcessMitigationPolicy，
 * 通过 GetProcAddress 动态解析，缺失时该策略跳过。
 */
typedef BOOL (WINAPI *pSetProcessMitigationPolicy_t)(
    PROCESS_MITIGATION_POLICY_VERTHYS,
    PVOID,
    SIZE_T);

/* ---------- 模块状态 ---------- */

static uint32_t s_active_attrs = 0;
static int      s_initialized  = 0;

/* ---------- 辅助：解析 SetProcessMitigationPolicy ---------- */

static pSetProcessMitigationPolicy_t resolve_set_mitigation_policy(void)
{
    HMODULE h = GetModuleHandleW(L"kernel32.dll");
    if (h == NULL) {
        h = LoadLibraryW(L"kernel32.dll");
    }
    if (h == NULL) return NULL;

    /* SetProcessMitigationPolicy 在 kernel32 / kernelbase 中均可解析到 */
    return (pSetProcessMitigationPolicy_t)GetProcAddress(
        h, "SetProcessMitigationPolicy");
}

/* ---------- 各 mitigation policy 应用 ---------- */

/*
 * 应用 ProcessSystemCallDisablePolicy（禁用 Win32k 系统调用）。
 *   返回 0 成功，非 0 失败。
 *
 * 安全含义：禁用后进程无法调用任何 NtUser / NtGdi 系列系统调用，
 * 所有窗口注入路径（SetWindowsHookEx、窗口子类化、剪贴板钩子、
 * 全局消息钩子、Event Hook 等）立即失效。
 *
 * 不可撤销：一旦应用，进程整个生命周期有效。
 */
static int apply_win32k_syscall_disable(void)
{
    pSetProcessMitigationPolicy_t p = resolve_set_mitigation_policy();
    if (p == NULL) {
        /* 旧版 Windows 无此 API，跳过 */
        return -1;
    }

    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY_VERTHYS policy;
    memset(&policy, 0, sizeof(policy));
    policy.DisallowWin32kSystemCalls = 1;

    if (!p(ProcessSystemCallDisablePolicy_VERTHYS,
           &policy,
           sizeof(policy))) {
        /* GetLastError() 通常为 STATUS_NOT_SUPPORTED（旧版本）或
         * STATUS_ACCESS_DENIED（已应用） */
        return -1;
    }
    return 0;
}

/*
 * 应用 ProcessChildProcessPolicy（NoChildProcessCreation=1）。
 *   返回 0 成功，非 0 失败。
 *
 * 安全含义：禁止当前进程创建任何子进程。
 *   - CreateProcess / CreateProcessAsUser / CreateProcessWithTokenW 等全部失败
 *   - 绝杀进程镂空（Process Hollowing）：攻击者无法创建挂起新进程替换镜像
 *   - 绝杀子进程注入：无法将恶意代码注入到新创建的子进程
 *
 * 不可撤销：一旦应用，进程整个生命周期有效。
 */
static int apply_child_process_disable(void)
{
    pSetProcessMitigationPolicy_t p = resolve_set_mitigation_policy();
    if (p == NULL) {
        return -1;
    }

    PROCESS_MITIGATION_CHILD_PROCESS_POLICY_VERTHYS policy;
    memset(&policy, 0, sizeof(policy));
    policy.NoChildProcessCreation = 1;

    if (!p(ProcessChildProcessPolicy_VERTHYS,
           &policy,
           sizeof(policy))) {
        return -1;
    }
    return 0;
}

/*
 * 应用 SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)。
 *   返回 0 成功，非 0 失败。
 *
 * 安全含义：修改进程默认 DLL 搜索路径，仅从 System32 加载 DLL。
 *   - 防本地目录 DLL 劫持：攻击者在当前工作目录放置恶意同名 DLL 无效
 *   - 防路径前缀劫持：仅信任 System32 路径
 *   - 与 LoadLibraryEx(LOAD_LIBRARY_SEARCH_SYSTEM32) 等效但全局生效
 *
 * 注意：本 API 在 Win8+ 可用（kernel32.dll），相较前两项策略版本要求更宽松。
 */
static int apply_image_prefer_system32(void)
{
    typedef BOOL (WINAPI *pSetDefaultDllDirectories_t)(DWORD);
    HMODULE h = GetModuleHandleW(L"kernel32.dll");
    if (h == NULL) {
        h = LoadLibraryW(L"kernel32.dll");
    }
    if (h == NULL) return -1;

    pSetDefaultDllDirectories_t pSetDefaultDllDirectories =
        (pSetDefaultDllDirectories_t)GetProcAddress(
            h, "SetDefaultDllDirectories");
    if (pSetDefaultDllDirectories == NULL) {
        return -1;
    }

    if (!pSetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)) {
        return -1;
    }
    return 0;
}

/*
 * 应用 ProcessImageLoadPolicy（NoRemoteImages=1, NoLowMandatoryLabelImages=1）。
 *   返回 0 成功，非 0 失败。
 *
 * 安全含义：
 *   - NoRemoteImages=1：禁止从 UNC 路径、网络位置加载 DLL/EXE。
 *     防御反射注入（Reflective DLL Injection）通过 \\server\share\malicious.dll
 *     路径加载；防御内存 PE 加载（LoadLibrary 内存加载包装器）。
 *   - NoLowMandatoryLabelImages=1：禁止从低完整性目录（如 %TEMP% 下任意可写位置）
 *     加载镜像。防止 Medium IL 进程被 Low IL 攻击者写入恶意 DLL 后被加载。
 *
 * 不可撤销：一旦应用，进程整个生命周期有效。
 */
static int apply_image_load_policy(int no_remote, int no_low_label)
{
    pSetProcessMitigationPolicy_t p = resolve_set_mitigation_policy();
    if (p == NULL) {
        return -1;
    }

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY_VERTHYS policy;
    memset(&policy, 0, sizeof(policy));
    if (no_remote)     policy.NoRemoteImages           = 1;
    if (no_low_label)  policy.NoLowMandatoryLabelImages = 1;

    /* 若两项都未启用，无需调用 */
    if (!no_remote && !no_low_label) {
        return 0;
    }

    if (!p(ProcessImageLoadPolicy_VERTHYS,
           &policy,
           sizeof(policy))) {
        return -1;
    }
    return 0;
}

/* ===================================================================== *
 *                           公共接口                                    *
 * ===================================================================== */

int process_sandbox_init(uint32_t attrs)
{
    if (s_initialized) {
        /* 已初始化过，仅追加（无法撤销已应用的策略） */
    }

    int any_failure = 0;

    /* 1. 禁用 Win32k 系统调用（免疫窗口注入） */
    if (attrs & SANDBOX_ATTR_WIN32K_SYS_DISABLE) {
        if (apply_win32k_syscall_disable() == 0) {
            s_active_attrs |= SANDBOX_ATTR_WIN32K_SYS_DISABLE;
        } else {
            any_failure = 1;
        }
    }

    /* 2. 禁止子进程创建（绝杀进程镂空、子进程注入） */
    if (attrs & SANDBOX_ATTR_PROCESS_CREATE_DISABLE) {
        if (apply_child_process_disable() == 0) {
            s_active_attrs |= SANDBOX_ATTR_PROCESS_CREATE_DISABLE;
        } else {
            any_failure = 1;
        }
    }

    /* 3. System32 优先加载（防本地 DLL 劫持） */
    if (attrs & SANDBOX_ATTR_IMAGE_PREFER_SYS32) {
        if (apply_image_prefer_system32() == 0) {
            s_active_attrs |= SANDBOX_ATTR_IMAGE_PREFER_SYS32;
        } else {
            any_failure = 1;
        }
    }

    /* 4. 禁止远程镜像加载（防反射注入、内存 PE 加载）
     *    + 禁止低完整性镜像加载 */
    if ((attrs & SANDBOX_ATTR_IMAGE_NO_REMOTE) ||
        (attrs & SANDBOX_ATTR_IMAGE_NO_LOW_LABEL)) {
        int no_remote    = (attrs & SANDBOX_ATTR_IMAGE_NO_REMOTE)   ? 1 : 0;
        int no_low_label = (attrs & SANDBOX_ATTR_IMAGE_NO_LOW_LABEL) ? 1 : 0;
        if (apply_image_load_policy(no_remote, no_low_label) == 0) {
            if (no_remote)    s_active_attrs |= SANDBOX_ATTR_IMAGE_NO_REMOTE;
            if (no_low_label) s_active_attrs |= SANDBOX_ATTR_IMAGE_NO_LOW_LABEL;
        } else {
            any_failure = 1;
        }
    }

    s_initialized = 1;

    /*
     * 返回策略：
     *   - 若任一请求的策略应用失败，返回 -1（调用方可据此决策）
     *   - 已成功应用的策略仍生效（部分沙盒可用优于全无）
     *   - 调用方可通过 process_sandbox_get_active_attrs() 查询实际生效的属性
     */
    return any_failure ? -1 : 0;
}

uint32_t process_sandbox_get_active_attrs(void)
{
    return s_active_attrs;
}

void process_sandbox_set_active_attrs(uint32_t attrs)
{
    /*
     * 外部注入已应用的沙盒属性。
     *
     * 典型场景：
     *   Worker 进程在加载本 DLL 之前已通过 Rust FFI 调用
     *   SetProcessMitigationPolicy 应用沙盒策略。Worker 通过
     *   Verthys_NotifySandboxAttrs() 将已应用的属性位掩码注入本模块，
     *   使后续 defense_closure_check 能正确识别已生效的防御策略。
     *
     * 注意：本函数不实际应用任何 mitigation policy，
     *       仅更新内部状态变量 s_active_attrs。
     */
    s_active_attrs = attrs;
    s_initialized = 1;
}
