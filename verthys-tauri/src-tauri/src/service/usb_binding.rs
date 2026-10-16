/*
 * service/usb_binding.rs — 可移动介质绑定的服务层契约
 *
 * 为什么契约放在 service 层：解锁控制器需要在口令运算前完成介质绑定守卫
 * （可移动介质的登记 / 克隆嫌疑拦截 / 重绑定确认），并在解锁成功后落实
 * 登记或重绑定；而控制器按单向依赖规则只允许引用 service / repository /
 * util / constants。控制器若直接引用 security_commands 的实现模块，即形成
 * controller → security_commands 的反向依赖（分层红线）。
 *
 * 依赖反转：本模块声明契约（判定纯函数 + 前后两个注册位），不依赖任何
 * 安全实现；具体实现（卷解析、序列号加盐哈希、注册表读写、审计）由
 * security_commands 侧在应用启动阶段注册（install）。
 *
 * 判定语义（绑定模型）：
 *   - 无登记记录（首次使用）→ 解锁成功后登记（首次信任 + 审计留痕）；
 *     不在此处拒绝：登记需要已解锁会话，若首次使用即拒绝将造成
 *     "无法解锁 → 无法登记 → 永远无法解锁"的自锁循环。
 *   - 有记录且哈希匹配 → 验证通过，无后续动作。
 *   - 有记录但哈希不匹配 → 克隆嫌疑：默认阻止解锁（fail-closed）；
 *     仅当调用方显式确认重绑定（allow_rebind，需用户以正确口令完成本次
 *     解锁后方可落实）才放行，并在解锁成功后改写绑定记录。
 *
 * 未注册实现（启动异常）时的语义：解锁前守卫按"该硬化层未启用"放行并
 * 记录错误日志——介质绑定是加固层而非凭据闸门，容器仍由口令保护；
 * 因初始化异常阻断数据访问的代价高于收益（与预设应用契约的 fail-closed
 * 取舍不同：那里失效会导致运行时防护级别未知）。
 *
 * 线程安全：注册位为 OnceLock 一次性写入；判定为无状态纯函数。
 */

use std::sync::OnceLock;
use tauri::AppHandle;

/// 绑定动作（解锁前判定 → 解锁后落实的跨层契约值）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UsbBindAction {
    /// 无需动作（不可移动介质 / 已匹配 / 该硬化层关闭）
    None,
    /// 首次使用：解锁成功后登记当前介质
    Register,
    /// 介质标识变化且调用方已确认：解锁成功后改写绑定记录
    Rebind,
}

/// 解锁前介质绑定守卫实现签名（由 security_commands 在启动阶段注册）
///
/// 返回 Ok(action) 表示允许继续解锁（action 指示解锁后需要落实的动作）；
/// 返回 Err(msg) 表示应中止解锁（克隆嫌疑且未确认重绑定），msg 含明确错误码。
pub(crate) type UsbPreUnlockFn = fn(&AppHandle, &str, bool) -> Result<UsbBindAction, String>;

/// 解锁后绑定落实实现签名（登记 / 重绑定；失败只审计，不影响已完成的解锁）
pub(crate) type UsbPostUnlockFn = fn(&AppHandle, &str, UsbBindAction);

static PRE_IMPL: OnceLock<UsbPreUnlockFn> = OnceLock::new();
static POST_IMPL: OnceLock<UsbPostUnlockFn> = OnceLock::new();

/// 注册介质绑定实现（应用启动阶段调用一次；重复注册忽略，保持首个实现）
pub(crate) fn install(pre: UsbPreUnlockFn, post: UsbPostUnlockFn) {
    let _ = PRE_IMPL.set(pre);
    let _ = POST_IMPL.set(post);
}

/// 解锁前介质绑定守卫。
///
/// fail-open（仅限实现缺失的启动异常场景，记录错误日志）：
/// 介质绑定为加固层，容器仍由口令保护；实现缺失不得阻断数据访问。
pub(crate) fn pre_unlock_guard(
    app: &AppHandle,
    verthys_path: &str,
    allow_rebind: bool,
) -> Result<UsbBindAction, String> {
    match PRE_IMPL.get() {
        Some(f) => f(app, verthys_path, allow_rebind),
        None => {
            log::error!("[usb_binding] 介质绑定实现未注册（启动异常），本次解锁不启用该硬化层");
            Ok(UsbBindAction::None)
        }
    }
}

/// 解锁成功后落实绑定动作（登记 / 重绑定）。实现缺失时为空操作。
pub(crate) fn post_unlock_commit(app: &AppHandle, verthys_path: &str, action: UsbBindAction) {
    if let Some(f) = POST_IMPL.get() {
        f(app, verthys_path, action);
    }
}

/// 绑定判定（纯函数：注册表记录 × 当前设备哈希 × 是否确认重绑定）。
///
/// - `registered`：该卷标的既有登记哈希（None = 首次使用）
/// - `current_hash`：当前设备的加盐序列号哈希
/// - `allow_rebind`：调用方是否已确认"更换介质并重绑定"
///
/// 返回 Err 表示应中止解锁（克隆嫌疑）；错误信息含 E_USB_CLONE_SUSPECTED 前缀。
pub(crate) fn decide_bind_action(
    registered: Option<&str>,
    current_hash: &str,
    allow_rebind: bool,
) -> Result<UsbBindAction, String> {
    match registered {
        Some(known) => {
            if crate::util::crypto::ct_eq(known.as_bytes(), current_hash.as_bytes()) {
                Ok(UsbBindAction::None)
            } else if allow_rebind {
                Ok(UsbBindAction::Rebind)
            } else {
                Err(
                    "E_USB_CLONE_SUSPECTED: 介质标识与登记记录不一致，已阻止解锁（如为合法更换介质，请确认后重试）"
                        .to_string(),
                )
            }
        }
        None => Ok(UsbBindAction::Register),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str = "aa11bb22cc33";
    const HASH_B: &str = "99ff88ee77dd";

    #[test]
    fn test_decide_first_use_registers() {
        // 首次使用：解锁成功后登记（不阻断）
        assert_eq!(
            decide_bind_action(None, HASH_A, false).unwrap(),
            UsbBindAction::Register
        );
    }

    #[test]
    fn test_decide_match_no_action() {
        assert_eq!(
            decide_bind_action(Some(HASH_A), HASH_A, false).unwrap(),
            UsbBindAction::None
        );
    }

    #[test]
    fn test_decide_mismatch_blocks_without_confirm() {
        let err = decide_bind_action(Some(HASH_A), HASH_B, false).unwrap_err();
        assert!(err.starts_with("E_USB_CLONE_SUSPECTED"), "错误码必须可识别: {}", err);
    }

    #[test]
    fn test_decide_mismatch_with_confirm_rebinds() {
        assert_eq!(
            decide_bind_action(Some(HASH_A), HASH_B, true).unwrap(),
            UsbBindAction::Rebind
        );
    }

    #[test]
    fn test_decide_different_length_hashes_are_mismatch() {
        // 长度不同的哈希（截断/异形输入）必须判为不匹配而非 panic（ct_eq 语义）
        let err = decide_bind_action(Some(HASH_A), "aa11", false).unwrap_err();
        assert!(err.starts_with("E_USB_CLONE_SUSPECTED"));
    }
}