/*
 * syscall_direct.h — 直连系统调用传输（内部模块，不导出）
 *
 * 职责：
 *   为安全检测器提供不经过 ntdll 用户态导出的 NT 查询传输。
 *   激活时由映像内 thunk 直接执行 syscall 指令；未激活时回退 ntdll 导出。
 *
 * 覆盖入口：
 *   - NtQueryInformationProcess — anti_debug_v2 调试器探测与 memory_guard 父进程识别
 *   - NtQuerySystemInformation  — memory_guard 系统句柄表扫描
 *   新增入口需要同步增加目标表项、SSN 数据槽与 thunk；数量一致性由编译期断言约束。
 *
 * 激活判据（全部满足才激活）：
 *   1. ntdll 导出表解析成功；
 *   2. 目标 Zw 存根可定位；
 *   3. SSN 提取通过全表仿射一致性与单目标自洽校验；
 *   4. 映像内 thunk 可用（编译期提供）。
 *
 * 传输约束：
 *   - thunk 位于只读可执行映像段，SSN 位于可写数据槽；不产生可写可执行页，
 *     不依赖运行期可执行内存分配，因此在 ACG 下仍可激活。
 *   - SSN 槽写入完成后以完全屏障发布激活标志；此后槽位只读，无锁并发安全。
 *   - 任一提取环节失败时保持未激活，包装函数回退 GetProcAddress；
 *     回退解析也失败时返回 STATUS_NOT_IMPLEMENTED，调用方按无信号处理。
 *
 * 线程安全：InitOnceExecuteOnce 保证进程级单次初始化；包装函数只读初始化结果。
 * 生命周期：thunk 与 SSN 槽随模块映像存续；无动态资源释放路径。
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

/* ---------- NT 状态码：本地定义，避免引入额外头文件依赖 ---------- */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS            ((LONG)0x00000000L)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED    ((LONG)0xC0000002L)
#endif

/* ---------- NT 查询原型（参数类型使用 ULONG，避免依赖 winternl 类型） ---------- */
typedef LONG (NTAPI *VerthysNtQueryInformationProcess_t)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef LONG (NTAPI *VerthysNtQuerySystemInformation_t)(
    ULONG, PVOID, ULONG, PULONG);

/*
 * 初始化（幂等，进程级一次）。
 * 返回 0 表示初始化流程结束；是否激活由 syscall_direct_available() 判定。
 * 提取失败会缓存未激活结论，不重复尝试。
 * 副作用：提取失败时写入应急遥测历史（低置信度基础设施异常）。
 */
int syscall_direct_init(void);

/*
 * 返回 1 表示映像内 thunk 已激活；0 表示走 GetProcAddress 回退。
 * 结果是 defense_closure IAT/Inline Hook 路径的判据之一。
 */
int syscall_direct_available(void);

/*
 * NtQueryInformationProcess 传输。
 * 激活时直接调用映像内 thunk；未激活时调用 GetProcAddress 解析的 ntdll 导出。
 * 两者均不可用时返回 STATUS_NOT_IMPLEMENTED。
 * 语义与 ntdll 同名导出一致。
 */
LONG syscall_NtQueryInformationProcess(
    HANDLE process, ULONG info_class, PVOID info, ULONG len, PULONG ret_len);

/*
 * NtQuerySystemInformation 传输。
 * 传输策略与 syscall_NtQueryInformationProcess 一致。
 */
LONG syscall_NtQuerySystemInformation(
    ULONG info_class, PVOID info, ULONG len, PULONG ret_len);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_SYSCALL_DIRECT_H */
