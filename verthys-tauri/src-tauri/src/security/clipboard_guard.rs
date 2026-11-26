/*
 * clipboard_guard.rs — 剪贴板保护模块
 *
 * 子模块：
 *   - state：统一状态枚举、全局静态、锁与时间辅助
 *   - win32：Windows 常量、FFI 结构体、原始 FFI 与宽字符辅助
 *   - clear：统一清空入口、内部清空实现、清空决策与过期轮询
 *   - listener：监听窗口过程、窗口类注册、监听线程与异步更新处理
 *   - guard：ClipboardGuard 及生命周期管理
 *
 * 要点：
 *   1. 分离写入与清空策略，使用延迟清空模式
 *      - SetClipboardData 后绝不清空，敏感内容正常驻留供用户粘贴
 *      - 清空仅在以下条件触发：30 秒自动过期、高安全模式下检测到外部
 *        SetClipboardData（而非读取）、显式调用 clear/transactional_clear
 *   2. 以外部 SetClipboardData 检测代替单纯的序列号读取
 *      - GetClipboardSequenceNumber 仅在 SetClipboardData 成功时递增
 *      - OpenClipboard / GetClipboardData 不改变序列号
 *      - 因此"序列号递增 = 外部写入"才是正确判定
 *   3. 窗口过程仅标记事件，所有剪贴板操作在消息循环中异步处理
 *      - clipboard_window_proc 收到 WM_CLIPBOARDUPDATE 时仅设置 AtomicBool
 *      - 消息循环轮询检测到标志后在主循环上下文执行检查和处理
 *      - 完全避免窗口过程内的重入风险
 *   4. 使用单一的状态枚举与锁保护
 *      - 状态由 Mutex<ClipboardStateData> 保护
 *      - 状态结构体包含 stage、last_seq、expire_at 等字段
 *      - 所有状态读取和修改都在获取锁后原子完成
 *   5. 清空操作使用 EmptyClipboard
 *      - 不写入随机数据再清空
 *      - 直接调用 EmptyClipboard 并广播 WM_DESTROYCLIPBOARD
 *      - 写入敏感内容时通过 CF_PRIVATEFIRST 标记防止进入历史记录
 *   6. 监听线程内进行 OLE 初始化与剪贴板能力检查
 *      - 隐藏窗口与消息循环由同一线程创建，保证 WM_CLIPBOARDUPDATE 可达
 *      - 监听线程启动时调用 OleInitialize，退出前调用 OleUninitialize
 *   7. 启动幂等：窗口类进程内仅注册一次；重复下发硬化开关直接成功，
 *      不得因 ERROR_CLASS_ALREADY_EXISTS 误报“剪贴板监听启动失败”
 */

mod clear;
mod guard;
#[cfg(target_os = "windows")]
mod listener;
mod state;
#[cfg(all(test, target_os = "windows"))]
mod tests;
#[cfg(target_os = "windows")]
mod win32;

pub use clear::clear;
pub use guard::ClipboardGuard;
