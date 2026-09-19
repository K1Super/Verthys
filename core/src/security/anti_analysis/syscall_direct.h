/*
 * syscall_direct.h — 直接系统调用 stub（内部模块，不导出）
 *
 * ★ 关键防御检测器绕过
 *   用户态 API Hook（IAT/EAT/Inline）。P4（API Hook）路径的目标态
 *   判据之一：检测器查询不再经过可被用户态 Hook 拦截的 ntdll 导出。
 *
 * 覆盖范围（仅检测器实际使用的两个入口）：
 *   - NtQueryInformationProcess — anti_debug_v2（KILL 级调试器三重探测）
 *                                + memory_guard（父进程识别）
 *   - NtQuerySystemInformation  — memory_guard（系统句柄表防转储扫描）
 *   扩展新入口：在 .c 的 SYSCALL_TARGET 表追加一行即可（SSN 提取与
 *   stub 生成均为表驱动），无需改动提取/构建逻辑。
 *
 * SSN 提取（排序法，"从 ntdll 提取系统调用号"）：
 *   1. 解析 ntdll 导出表，收集全部 Zw* 存根的（RVA, SSN）对——
 *      未被 Hook 的存根特征：`4C 8B D1`（mov r10,rcx）+ `B8 imm32`
 *      （mov eax,SSN），SSN 即 +4 偏移的 32 位立即数；
 *   2. 按 RVA 升序排序。现代 Windows（Win10+）Zw 存根在 .text 中按
 *      SSN 顺序连续布局：任意两个有效锚点满足
 *      SSN[j] - SSN[i] == j - i（仿射一致性，作为全表校验条件）；
 *   3. 目标存根被 Hook（特征不符）时，由最近有效锚点按位次差插值：
 *      SSN[target] = SSN[anchor] + (target_pos - anchor_pos)。
 *      双侧锚点（前后各一）同时存在时两次插值必须一致，否则判定
 *      提取不可信（防御异常布局，宁降级不误算）。
 *   4. 目标存根未被 Hook 时，直接读取值必须与插值预测一致（自洽
 *      校验），不一致 → 降级。
 *
 * stub 构建（W^X 纪律）：
 *   - 单页 VirtualAlloc(PAGE_READWRITE) → 写入两条 11 字节 stub
 *     （mov r10,rcx; mov eax,SSN; syscall; ret）→ VirtualProtect
 *     收紧为 PAGE_EXECUTE_READ。全程不存在可写可执行页。
 *   - CFG（/guard:cf 已启用）：动态内存默认合法间接调用目标
 *     （非 Strict 模式）；仍以 SetProcessValidCallTargets 显式
 *     登记，若查询到 Strict CFG 且登记失败 → 激活放弃并降级
 *     （不冒 fast-fail 崩溃风险）。
 *
 * 优雅降级（"提取失败优雅降级回 GetProcAddress 路径"）：
 *   - 任一环节失败（导出表异常 / 一致性校验失败 / stub 页不可得 /
 *     Strict CFG 登记失败）→ 本模块标记未激活；
 *   - 包装函数内部回退 GetProcAddress 解析的 ntdll 导出（行为与
 *     改造前完全一致），并 emergency_report(TELEMETRY,
 *     EMERG_SIG_SYSCALL_EXTRACT_FAIL) 留痕（低置信度，无处置）；
 *   - 解析也失败（极端环境）→ 返回 STATUS_NOT_IMPLEMENTED，
 *     调用方按"无信号"处理（检测器语义安全侧）。
 *
 * 线程安全：InitOnceExecuteOnce 进程级单次初始化；包装函数仅读
 *   初始化后不变的函数指针表（无锁并发安全）。
 * 生命周期：stub 页与指针表进程级存续（同 job_isolation 惯例），
 *   内核随进程退出回收，无 deinit。
 */
#ifndef VERTHYS_SYSCALL_DIRECT_H
#define VERTHYS_SYSCALL_DIRECT_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- NT 状态码（与既有模块一致的本地定义） ---------- */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS            ((LONG)0x00000000L)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED    ((LONG)0xC0000002L)
#endif

/* ---------- NT 查询原型（参数类型用 ULONG，避免 winternl.h 依赖） ---------- */
typedef LONG (NTAPI *VerthysNtQueryInformationProcess_t)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *VerthysNtQuerySystemInformation_t)(
    ULONG, PVOID, ULONG, PULONG);

/*
 * 初始化（幂等，进程级一次）。
 * 返回 0 = 初始化完成（无论直接 stub 激活还是降级路径就绪）；
 * 激活状态经 syscall_direct_available() 查询。
 * 首次失败会缓存降级结论，不重试（避免异常环境反复解析导出表）。
 */
int syscall_direct_init(void);

/*
 * 直接系统调用 stub 是否激活（1=激活，0=降级到 GetProcAddress）。
 * defense_closure P4（API Hook）路径 BLOCKED 判据之一。
 */
int syscall_direct_available(void);

/*
 * NtQueryInformationProcess 包装（检测器唯一入口）。
 *   优先直接 stub；降级路径回退 GetProcAddress；两者皆失联返回
 *   STATUS_NOT_IMPLEMENTED（调用方按无信号处理）。
 * 语义与直接调用 ntdll!NtQueryInformationProcess 完全一致。
 */
LONG syscall_NtQueryInformationProcess(
    HANDLE process, ULONG info_class, PVOID info, ULONG len, PULONG ret_len);

/*
 * NtQuerySystemInformation 包装（检测器唯一入口）。
 *   传输策略与上者一致。
 */
LONG syscall_NtQuerySystemInformation(
    ULONG info_class, PVOID info, ULONG len, PULONG ret_len);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_SYSCALL_DIRECT_H */
