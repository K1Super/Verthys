               /*
 * job_isolation.c — 双层 Job Object 嵌套 + DACL 白名单隔离实现
 *
 * 严格遵守 Windows 10/11 平台规范，禁止降级。
 *
 * 实现要点（对应规格 7 部分）：
 *   一、放弃 PROTECT_FROM_CLOSE + DuplicateHandle（已彻底移除）
 *   二、DACL 白名单策略（默认拒绝 + 显式允许，无 Deny ACE）
 *       - ALLOW SYSTEM：JOB_OBJECT_ALL_ACCESS
 *       - ALLOW 当前进程用户 SID：JOB_OBJECT_ALL_ACCESS | JOB_OBJECT_ASSIGN_PROCESS
 *   三、完全移除 JobObjectSecurityLimitInformation（Windows 8+ 已废弃）
 *   四、资源释放采用 TerminateJobObject（非 DuplicateHandle）
 *   五、严格 5 步嵌套挂载流程，任一步失败触发立即回滚
 *   六、InitOnceExecuteOnce 并发安全 + OutputDebugStringA/Event Log 诊断
 *   七、DACL 阻断所有非 SYSTEM/非自身访问（含 SeDebugPrivilege 攻击者）
 */
#include "job_isolation.h"
#include "verthys_internal.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <strsafe.h>

/* ---------- 模块状态 ---------- */

static HANDLE s_hOuterJob = NULL;       /* 外层 Job：生命周期锁（KILL_ON_JOB_CLOSE） */
static HANDLE s_hInnerJob = NULL;       /* 内层 Job：ACL 硬隔离（BREAKAWAY_OK） */
static int    s_active = 0;             /* 0=未激活, 1=已激活 */
static INIT_ONCE s_init_once = INIT_ONCE_STATIC_INIT;
static int    s_init_result = 0;        /* 0=未初始化, 正数=成功, 负数=失败错误码 */

/* ---------- 诊断：OutputDebugStringA + Event Log（规格第六部分） ---------- */

/*
 * 统一诊断输出函数。
 * - 始终通过 OutputDebugStringA 输出，供开发环境（调试器/DebugView）捕获
 * - 同时写入 Windows 事件日志（Event Log），供正式发布版本远程排查
 * - 记录每一步的 Win32 错误码（GetLastError）
 * - 废弃 fprintf(stderr) —— 服务进程通常无控制台窗口
 */
static void job_diag(const char *msg, DWORD gle)
{
    char buf[512];
    HRESULT hr = StringCchPrintfA(buf, sizeof(buf),
                                  "[job_isolation] %s (GLE=%lu)\r\n",
                                  msg, (unsigned long)gle);
    if (FAILED(hr)) {
        return;
    }

    /* 1. OutputDebugStringA：供开发环境（调试器/DebugView）捕获 */
    OutputDebugStringA(buf);

    /* 2. Event Log：供正式发布版本远程排查 */
    HANDLE hLog = RegisterEventSourceW(NULL, L"Verthys");
    if (hLog != NULL) {
        const char *strings[] = { buf };
        WORD severity = (gle != 0) ? EVENTLOG_WARNING_TYPE
                                   : EVENTLOG_INFORMATION_TYPE;
        ReportEventA(hLog, severity, 0, 0, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hLog);
    }
}

/* ---------- DACL 构建：白名单策略（规格第二、七部分） ---------- */

/*
 * 构建白名单安全描述符。
 *
 * 策略：默认拒绝 + 显式允许（不添加任何 Deny ACE）
 *   - ALLOW SYSTEM：JOB_OBJECT_ALL_ACCESS
 *   - ALLOW 当前进程令牌所属用户 SID：JOB_OBJECT_ALL_ACCESS | JOB_OBJECT_ASSIGN_PROCESS
 *
 * 为什么不添加 Deny Everyone：
 *   当前进程的访问令牌中必然包含 Everyone SID（S-1-1-0），内核在权限检查时
 *   遇到显式拒绝项会直接返回 ACCESS_DENIED，导致后续 AssignProcessToJobObject 失败。
 *
 * 安全保证（规格第七部分）：
 *   未在列表中的任何主体（含 Administrators/Everyone）系统默认授予无任何访问权限，
 *   甚至没有 READ_CONTROL 或 SYNCHRONIZE。即便攻击者获得 SeDebugPrivilege/
 *   SeTcbPrivilege，SRM 仍严格执行 DACL，攻击者无法获得有效句柄。
 *
 * 返回 0 成功，非 0 失败。
 */
static int build_whitelist_security(SECURITY_ATTRIBUTES *sa,
                                    SECURITY_DESCRIPTOR *sd,
                                    ACL *acl_buf, DWORD acl_size)
{
    DWORD gle = 0;

    /* 1. 初始化安全描述符 */
    if (!InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION)) {
        gle = GetLastError();
        job_diag("InitializeSecurityDescriptor failed", gle);
        return -1;
    }

    /* 2. 初始化 ACL */
    if (!InitializeAcl(acl_buf, acl_size, ACL_REVISION)) {
        gle = GetLastError();
        job_diag("InitializeAcl failed", gle);
        return -2;
    }

    /* 3. ALLOW SYSTEM 完全控制 */
    PSID pSystem = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                                   0, 0, 0, 0, 0, 0, 0, &pSystem)) {
        gle = GetLastError();
        job_diag("AllocateAndInitializeSid(SYSTEM) failed", gle);
        return -3;
    }
    if (!AddAccessAllowedAce(acl_buf, ACL_REVISION,
                             JOB_OBJECT_ALL_ACCESS, pSystem)) {
        gle = GetLastError();
        job_diag("AddAccessAllowedAce(SYSTEM) failed", gle);
        FreeSid(pSystem);
        return -4;
    }
    FreeSid(pSystem);

    /* 4. ALLOW 当前进程令牌所属用户 SID：
     *    JOB_OBJECT_ALL_ACCESS | JOB_OBJECT_ASSIGN_PROCESS
     *    （组合权限，既保证服务自身可操纵 Job，又显式授予挂入权限） */
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        gle = GetLastError();
        job_diag("OpenProcessToken failed", gle);
        return -5;
    }

    DWORD tokSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokSize);
    gle = GetLastError();
    if (gle != ERROR_INSUFFICIENT_BUFFER || tokSize == 0) {
        job_diag("GetTokenInformation(size probe) failed", gle);
        CloseHandle(hToken);
        return -6;
    }

    TOKEN_USER *pTokUser = (TOKEN_USER *)LocalAlloc(LPTR, tokSize);
    if (!pTokUser) {
        gle = GetLastError();
        job_diag("LocalAlloc(TOKEN_USER) failed", gle);
        CloseHandle(hToken);
        return -7;
    }

    if (!GetTokenInformation(hToken, TokenUser, pTokUser, tokSize, &tokSize)) {
        gle = GetLastError();
        job_diag("GetTokenInformation(TokenUser) failed", gle);
        LocalFree(pTokUser);
        CloseHandle(hToken);
        return -8;
    }

    if (!AddAccessAllowedAce(acl_buf, ACL_REVISION,
                             JOB_OBJECT_ALL_ACCESS | JOB_OBJECT_ASSIGN_PROCESS,
                             pTokUser->User.Sid)) {
        gle = GetLastError();
        job_diag("AddAccessAllowedAce(self user) failed", gle);
        LocalFree(pTokUser);
        CloseHandle(hToken);
        return -9;
    }

    LocalFree(pTokUser);
    CloseHandle(hToken);

    /* 5. 设置 DACL 到安全描述符（bDaclPresent=TRUE, bDaclDefaulted=FALSE）
     *    bDaclDefaulted=FALSE 表示显式提供 DACL，不使用默认 DACL */
    if (!SetSecurityDescriptorDacl(sd, TRUE, acl_buf, FALSE)) {
        gle = GetLastError();
        job_diag("SetSecurityDescriptorDacl failed", gle);
        return -10;
    }

    /* 6. 填充 SECURITY_ATTRIBUTES */
    sa->nLength = sizeof(SECURITY_ATTRIBUTES);
    sa->lpSecurityDescriptor = sd;
    sa->bInheritHandle = FALSE;
    return 0;
}

/* ---------- 5 步严格挂载流程的各步实现（规格第五部分） ---------- */

/*
 * 步骤 1：创建内层 Job，立即设置 JOB_OBJECT_LIMIT_BREAKAWAY_OK。
 *
 * 嵌套依赖前提（规格第一部分）：
 *   内层 Job 必须设置 BREAKAWAY_OK，否则后续"进程 → 外层 Job"会被内核拒绝
 *   并返回 ERROR_ACCESS_DENIED。
 *
 * DACL 白名单已应用，仅 SYSTEM 和当前用户可访问。
 * 不设置 JobObjectSecurityLimitInformation（规格第三部分：Windows 8+ 已废弃）。
 */
static int step1_create_inner_job(void)
{
    DWORD gle = 0;
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    /* ACL 缓冲：足够容纳 2 个 ALLOW ACE（SYSTEM + self user） */
    BYTE aclBuf[256];
    ACL *pAcl = (ACL *)aclBuf;
    DWORD aclSize = sizeof(aclBuf);

    if (build_whitelist_security(&sa, &sd, pAcl, aclSize) != 0) {
        job_diag("build_whitelist_security(inner) failed", 0);
        return -1;
    }

    s_hInnerJob = CreateJobObjectW(&sa, NULL);
    if (s_hInnerJob == NULL) {
        gle = GetLastError();
        job_diag("CreateJobObjectW(inner) failed", gle);
        return -2;
    }

    /* 设置 JOB_OBJECT_LIMIT_BREAKAWAY_OK（必须，允许后续嵌套挂入外层） */
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION extLimit;
    memset(&extLimit, 0, sizeof(extLimit));
    extLimit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    if (!SetInformationJobObject(s_hInnerJob,
                                 JobObjectExtendedLimitInformation,
                                 &extLimit, sizeof(extLimit))) {
        gle = GetLastError();
        job_diag("SetInformationJobObject(inner, BREAKAWAY_OK) failed", gle);
        CloseHandle(s_hInnerJob);
        s_hInnerJob = NULL;
        return -3;
    }

    return 0;
}

/*
 * 步骤 2：调用 AssignProcessToJobObject(内层, GetCurrentProcess())，
 * 将当前进程挂入内层 Job。
 *
 * 必须先于"挂入外层 Job"执行（规格第一部分：顺序不可颠倒）。
 */
static int step2_assign_to_inner(void)
{
    DWORD gle = 0;
    if (!AssignProcessToJobObject(s_hInnerJob, GetCurrentProcess())) {
        gle = GetLastError();
        job_diag("AssignProcessToJobObject(inner) failed", gle);
        return -1;
    }
    return 0;
}

/*
 * 步骤 3：创建外层 Job，设置 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK。
 *
 * 嵌套依赖前提（规格第一部分）：
 *   外层 Job 必须设置 BREAKAWAY_OK，否则内核拒绝嵌套挂入。
 *   KILL_ON_JOB_CLOSE 保证外层句柄关闭时强制终止所有子进程。
 *
 * 不设置 PROTECT_FROM_CLOSE（规格第一部分：已证明无效）。
 * 不设置 PROTECT_FROM_CLOSE 的副本触发机制（规格第四部分：DuplicateHandle 无效）。
 */
static int step3_create_outer_job(void)
{
    DWORD gle = 0;
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    BYTE aclBuf[256];
    ACL *pAcl = (ACL *)aclBuf;
    DWORD aclSize = sizeof(aclBuf);

    if (build_whitelist_security(&sa, &sd, pAcl, aclSize) != 0) {
        job_diag("build_whitelist_security(outer) failed", 0);
        return -1;
    }

    s_hOuterJob = CreateJobObjectW(&sa, NULL);
    if (s_hOuterJob == NULL) {
        gle = GetLastError();
        job_diag("CreateJobObjectW(outer) failed", gle);
        return -2;
    }

    /* 设置 KILL_ON_JOB_CLOSE | BREAKAWAY_OK 组合标志 */
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION extLimit;
    memset(&extLimit, 0, sizeof(extLimit));
    extLimit.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    if (!SetInformationJobObject(s_hOuterJob,
                                 JobObjectExtendedLimitInformation,
                                 &extLimit, sizeof(extLimit))) {
        gle = GetLastError();
        job_diag("SetInformationJobObject(outer, KILL|BREAKAWAY) failed", gle);
        CloseHandle(s_hOuterJob);
        s_hOuterJob = NULL;
        return -3;
    }

    return 0;
}

/*
 * 步骤 4：调用 AssignProcessToJobObject(外层, GetCurrentProcess())。
 *
 * 此时内核检测到当前进程已属于内层 Job，且内外层均允许脱离（BREAKAWAY_OK），
 * 因此成功建立"进程 → 内层 → 外层"的嵌套链。
 *
 * 注意：这里是"进程 → 外层"，而非"内层 Job → 外层 Job"。
 *       Windows 内核通过进程已属于的 Job 链自动建立嵌套关系。
 */
static int step4_assign_to_outer(void)
{
    DWORD gle = 0;
    if (!AssignProcessToJobObject(s_hOuterJob, GetCurrentProcess())) {
        gle = GetLastError();
        job_diag("AssignProcessToJobObject(outer) failed", gle);
        return -1;
    }
    return 0;
}

/*
 * 步骤 5（仅在第 4 步失败时执行）：完整回滚。
 *
 * 必须先调用 TerminateJobObject(内层) 杀掉已挂入的进程，
 * 再依次关闭内层和外层句柄，否则进程会永久滞留于内层 Job 中无法清除。
 */
static void step5_rollback(void)
{
    DWORD gle = 0;

    if (s_hInnerJob != NULL) {
        if (!TerminateJobObject(s_hInnerJob, 1)) {
            gle = GetLastError();
            job_diag("TerminateJobObject(inner, rollback) failed", gle);
        }
        CloseHandle(s_hInnerJob);
        s_hInnerJob = NULL;
    }

    if (s_hOuterJob != NULL) {
        CloseHandle(s_hOuterJob);
        s_hOuterJob = NULL;
    }
}

/* ---------- InitOnceExecuteOnce 回调（规格第六部分：并发安全） ---------- */

/*
 * InitOnceExecuteOnce 回调函数，保证全局仅执行一次初始化。
 * 线程安全，防止未来可能的并发调用导致的状态不一致。
 *
 * 严格 5 步挂载流程，任一步失败触发立即回滚：
 *   step1 → step2 → step3 → step4 → (失败则 step5 回滚)
 */
static BOOL CALLBACK init_once_callback(PINIT_ONCE InitOnce,
                                        PVOID Parameter,
                                        PVOID *Context)
{
    int r;

    /* 步骤 1：创建内层 Job（BREAKAWAY_OK） */
    r = step1_create_inner_job();
    if (r != 0) {
        s_init_result = -10 + r;  /* -10 系列：内层创建失败 */
        job_diag("step1_create_inner_job failed, aborting", 0);
        return FALSE;
    }

    /* 步骤 2：当前进程 → 内层 Job */
    r = step2_assign_to_inner();
    if (r != 0) {
        /* 进程未挂入内层，仅需关闭内层句柄（无需 TerminateJobObject） */
        CloseHandle(s_hInnerJob);
        s_hInnerJob = NULL;
        s_init_result = -20 + r;
        job_diag("step2_assign_to_inner failed, aborting", 0);
        return FALSE;
    }

    /* 步骤 3：创建外层 Job（KILL_ON_JOB_CLOSE | BREAKAWAY_OK） */
    r = step3_create_outer_job();
    if (r != 0) {
        /* 进程已挂入内层 Job，需 TerminateJobObject 清理已挂入的进程 */
        DWORD gle = 0;
        if (!TerminateJobObject(s_hInnerJob, 1)) {
            gle = GetLastError();
            job_diag("TerminateJobObject(inner, step3 rollback) failed", gle);
        }
        CloseHandle(s_hInnerJob);
        s_hInnerJob = NULL;
        s_init_result = -30 + r;
        job_diag("step3_create_outer_job failed, aborting", 0);
        return FALSE;
    }

    /* 步骤 4：当前进程 → 外层 Job（建立"进程 → 内层 → 外层"嵌套链） */
    r = step4_assign_to_outer();
    if (r != 0) {
        /* 步骤 5：完整回滚 */
        step5_rollback();
        s_init_result = -40 + r;
        job_diag("step4_assign_to_outer failed, rolled back", 0);
        return FALSE;
    }

    /* 全部成功 */
    s_active = 1;
    s_init_result = 1;
    job_diag("init OK: nested job (inner+outer) established, process isolated", 0);
    return TRUE;
}

/* ---------- 公共接口 ---------- */

/*
 * 初始化双层 Job Object 嵌套隔离。
 * 使用 InitOnceExecuteOnce 保证全局仅执行一次，线程安全。
 * 严格遵循 5 步挂载流程，任一步失败触发完整回滚。
 * 返回 0 成功，非 0 失败。
 */
int job_isolation_init(void)
{
    PVOID ctx = NULL;
    InitOnceExecuteOnce(&s_init_once, init_once_callback, NULL, &ctx);
    /* s_init_result: 0=未初始化(异常), 正数=成功, 负数=失败 */
    if (s_init_result > 0) {
        return 0;
    }
    return (s_init_result == 0) ? -1 : s_init_result;
}

/*
 * 查询当前进程是否已被 Job Object 隔离。
 * 返回 0=未隔离，1=已隔离。
 * 二次确认：通过 IsProcessInJob 验证当前进程确实在内层 Job 中。
 */
int job_isolation_is_active(void)
{
    if (!s_active) return 0;
    /* 二次确认：当前进程确实在内层 Job 中 */
    BOOL isJob = FALSE;
    if (!IsProcessInJob(GetCurrentProcess(), s_hInnerJob, &isJob)) {
        DWORD gle = GetLastError();
        job_diag("IsProcessInJob query failed", gle);
        return 0;
    }
    return isJob ? 1 : 0;
}

/*
 * 主动断开 Job 隔离链路（仅 tamper_destroy 应急销毁路径调用）。
 *
 * 资源释放流程（规格第四部分）：
 *   1. TerminateJobObject(外层, 退出码) —— 瞬间终止 Job 层级内所有进程
 *   2. CloseHandle(内层) —— 释放内层句柄
 *   3. CloseHandle(外层) —— 释放外层句柄（不设置 PROTECT_FROM_CLOSE，可直接关闭）
 *
 * 注意：TerminateJobObject(外层) 会终止当前进程，后续 CloseHandle 在当前进程内
 *       不会执行，但内核在进程退出时会自动清理句柄表。CloseHandle 代码保留作为
 *       TerminateJobObject 失败时的兜底清理路径。
 *
 * 调用后进程不可恢复，应仅在检测到致命篡改时使用。
 */
void job_isolation_break(void)
{
    DWORD gle = 0;

    if (s_hOuterJob != NULL) {
        if (!TerminateJobObject(s_hOuterJob, 1)) {
            gle = GetLastError();
            job_diag("TerminateJobObject(outer, break) failed", gle);
            /* TerminateJobObject 失败时，尝试关闭句柄触发 KILL_ON_JOB_CLOSE */
        }
    }

    /* 兜底清理：仅在 TerminateJobObject 失败或进程未死时执行 */
    if (s_hInnerJob != NULL) {
        CloseHandle(s_hInnerJob);
        s_hInnerJob = NULL;
    }
    if (s_hOuterJob != NULL) {
        CloseHandle(s_hOuterJob);
        s_hOuterJob = NULL;
    }

    s_active = 0;
}
