/*
 * session_guard.rs — 智能会话自动锁屏
 *
 * 子模块：
 *   - types：Win32 消息/会话/电源常量、GUID、事件类型、窗口实例数据
 *            与 SessionGuardBackend trait
 *   - win_backend：Windows 后端（window：窗口类注册、窗口过程与消息循环；
 *                  notify：消息循环状态、工作线程与 WindowsBackend 组合）
 *   - noop_backend：非 Windows 平台降级实现
 *   - guard：SessionGuard 公共 API 与 Drop
 *
 * 要点：
 *   1. 使用 mpsc 消息通道传递事件，回调异步化
 *      - 窗口过程仅发送 SessionEvent 到通道，立即返回
 *      - 独立工作线程接收事件并安全执行用户回调
 *      - 避免 UAF 风险和阻塞消息循环
 *   2. 封装窗口为 RAII 类型，禁止全局状态
 *      - GuardWindow 持有 HWND、线程句柄、stop_flag
 *      - 实例数据通过 GWLP_USERDATA 存储在窗口上（非全局变量）
 *      - 窗口类通过 std::sync::Once 仅注册一次，允许多实例
 *   3. 在回调边界使用 catch_unwind 防止 panic 跨 FFI
 *      - 工作线程中用 catch_unwind 包裹用户回调
 *      - panic 被捕获并记录，不传播到 FFI 边界
 *   4. 提供平台抽象层与降级策略
 *      - SessionGuardBackend trait 定义统一接口
 *      - Windows 实现基于隐藏窗口 + WTS 会话通知
 *      - 非 Windows 平台返回错误但不阻止应用启动
 *   5. 高安全标志为实例级状态
 *      - 高安全标志为 Arc<AtomicBool>，在实例间共享
 *      - 窗口过程通过实例数据读取标志，不依赖全局变量
 *   6. 运行时健康监控与自动恢复
 *      - 工作线程使用 recv_timeout 充当看门狗
 *      - 消息循环线程意外退出时自动重启
 *      - 重启次数上限防止无限循环
 *   7. 显示器关闭锁定（display-off 硬化）
 *      - RegisterPowerSettingNotification 注册 GUID_CONSOLE_DISPLAY_STATE；
 *        高安全模式下显示器关闭等同于 Lock 事件
 *      - 与挂起锁定同门控同语义；通知注册失败退化为仅监听系统挂起
 */

mod guard;
#[cfg(not(target_os = "windows"))]
mod noop_backend;
mod types;
#[cfg(target_os = "windows")]
mod win_backend;

pub use guard::SessionGuard;
pub use types::SessionLockReason;
