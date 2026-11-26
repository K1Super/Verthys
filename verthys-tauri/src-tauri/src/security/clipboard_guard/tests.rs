/*
 * clipboard_guard/tests.rs — 单元测试
 */

use super::guard::ClipboardGuard;
use super::state::lock_state;

/// 回归：重复启动必须幂等成功，停止后重启必须成功。
///
/// 同一窗口类重复注册返回 1410（ERROR_CLASS_ALREADY_EXISTS）时，
/// 不得被当作启动失败。
#[test]
fn clipboard_monitor_start_is_idempotent_and_restartable() {
    let mut guard = ClipboardGuard::new();

    guard.start_monitoring().expect("首次启动剪贴板监听失败");
    guard
        .start_monitoring()
        .expect("重复启动必须幂等成功（不得因窗口类已注册而失败）");
    guard.stop_monitoring();

    guard
        .start_monitoring()
        .expect("停止后重新启动剪贴板监听失败");
    guard.stop_monitoring();

    assert!(!lock_state().monitoring, "停止后监听状态必须为关闭");
}
