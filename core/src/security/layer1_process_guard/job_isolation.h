/*
 * job_isolation.h — 双层 Job Object 嵌套 + DACL 白名单隔离（内部模块，不导出）
 *
 * 架构原则（Windows 10/11 平台，禁止降级）：
 *
 *   一、放弃"保护句柄"与"复制句柄触发关闭"的无效组合
 *      PROTECT_FROM_CLOSE 仅阻止调用方进程关闭该句柄，但关闭副本并不减少
 *      原句柄的引用计数，因此无法触发 KILL_ON_JOB_CLOSE。本模块彻底摒弃
 *      此机制，仅依赖安全描述符（DACL）对外部访问进行拦截。
 *
 *   二、DACL 白名单策略（默认拒绝 + 显式允许）
 *      - 不添加任何 Deny ACE（避免自毁：当前进程令牌含 Everyone SID，
 *        内核遇到显式拒绝项会直接返回 ACCESS_DENIED，导致 AssignProcessToJobObject 失败）
 *      - ALLOW SYSTEM：JOB_OBJECT_ALL_ACCESS
 *      - ALLOW 当前进程令牌所属用户 SID：JOB_OBJECT_ALL_ACCESS | JOB_OBJECT_ASSIGN_PROCESS
 *      - 其余主体（含 Administrators/Everyone）默认无任何访问权限
 *        （甚至无 READ_CONTROL/SYNCHRONIZE）
 *
 *   三、移除 JobObjectSecurityLimitInformation（Windows 8+ 已废弃）
 *      该 Info Class 在 Windows 8 以后被内核废弃，SetInformationJobObject 会稳定
 *      返回 ERROR_NOT_SUPPORTED (50)。本模块完全移除该调用，不再做无效的重试或降级。
 *      令牌限制职责由 Worker 进程的 mitigation policy（apply_process_sandbox）承担，
 *      或通过 CreateProcessAsUser + CreateRestrictedToken / AdjustTokenPrivileges 实现。
 *
 *   四、可靠的资源释放与主动断连机制
 *      - 正常停服清理：TerminateJobObject(外层句柄, 退出码) 瞬间终止 Job 层级内所有进程，
 *        随后 CloseHandle 释放内层和外层句柄（外层句柄不设置 PROTECT_FROM_CLOSE）。
 *      - 防意外泄露：若服务进程崩溃退出而未调用清理函数，内核在进程句柄表销毁时
 *        自动递减所有 Job 对象的引用计数，当外层 Job 引用计数归零时，
 *        KILL_ON_JOB_CLOSE 仍会生效，内核强制终止所有遗留子进程。
 *
 *   五、严格的嵌套挂载流程（5 步，任一步失败触发立即回滚）
 *      1. 创建内层 Job，立即设置 JOB_OBJECT_LIMIT_BREAKAWAY_OK
 *      2. AssignProcessToJobObject(内层, GetCurrentProcess())
 *      3. 创建外层 Job，设置 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK
 *      4. AssignProcessToJobObject(外层, GetCurrentProcess())
 *         （内核检测到当前进程已在内层 Job，且内外层均允许脱离，建立嵌套链）
 *      5. 若第 4 步失败：TerminateJobObject(内层) → CloseHandle(内层) → CloseHandle(外层)
 *
 *   六、初始化并发安全与诊断能力
 *      - 使用 InitOnceExecuteOnce 保证初始化函数全局仅执行一次
 *      - 废弃 fprintf(stderr)，改用 OutputDebugStringA 输出调试信息供开发环境捕获
 *      - 正式发布版本写入 Windows 事件日志（Event Log），记录每一步 Win32 错误码
 *
 *   七、跨进程攻击面的终极考虑
 *      即便攻击者获得 SeDebugPrivilege/SeTcbPrivilege，内核的安全引用监控器（SRM）
 *      仍严格执行内外层 Job 对象上的 DACL。由于 DACL 中没有为 Administrators 或
 *      Everyone 授予任何访问权限，攻击者无法获得任何有效句柄，也就无法调用
 *      TerminateJobObject 或 QueryInformationJobObject，保证运行时隔离坚不可摧。
 */
#ifndef VERTHYS_JOB_ISOLATION_H
#define VERTHYS_JOB_ISOLATION_H

#include <stdint.h>
#include <stddef.h>

/*
 * 初始化双层 Job Object 嵌套隔离。
 * 必须在 Worker 进程启动早期、加载任何敏感数据之前调用。
 * 使用 InitOnceExecuteOnce 保证全局仅执行一次，线程安全。
 * 当前进程（Worker）会被立即分配至内层 Job，再嵌套至外层 Job。
 * 严格遵循 5 步挂载流程，任一步失败触发完整回滚。
 * 返回 0 成功，非 0 失败（详细错误码经 OutputDebugStringA/Event Log 输出，对外仅返回失败）。
 */
int job_isolation_init(void);

/*
 * 查询当前进程是否已被 Job Object 隔离。
 * 返回 0=未隔离，1=已隔离。
 */
int job_isolation_is_active(void);

/*
 * 主动断开 Job 隔离链路（仅 tamper_destroy 应急销毁路径调用）。
 * 调用 TerminateJobObject(外层) 立即终止 Job 层级内所有进程，
 * 随后 CloseHandle 释放内层和外层句柄（外层句柄不设置 PROTECT_FROM_CLOSE）。
 * 调用后进程不可恢复，应仅在检测到致命篡改时使用。
 */
void job_isolation_break(void);

#endif /* VERTHYS_JOB_ISOLATION_H */
