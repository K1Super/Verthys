/*
 * service/preset_source.rs — 解锁期受信档位的服务层契约
 *
 * 为什么契约放在 service 层：解锁控制器需要在口令运算开始前把受信档位
 * 应用到 C 运行时策略层，而控制器按单向依赖规则只允许引用 service /
 * repository / util / constants。控制器若直接引用 security_commands 的实现
 * 模块，即形成 controller → security_commands 的反向依赖（分层红线）。
 *
 * 依赖反转：本模块只声明契约（应用函数注册位），不依赖任何安全实现；
 * 具体实现（受信文件读取 + 切档 + 回读校验 + 审计）由 security_commands 侧
 * 在应用启动阶段注册（install）。未注册时按 fail-closed 语义返回 Err，
 * 由调用方中止解锁——禁止以未知档位继续。
 *
 * 线程安全：注册位为一次性写入（OnceLock，启动阶段完成后只读）；
 * 调用为无状态转发，可并发调用。
 */

use std::sync::OnceLock;
use tauri::AppHandle;

/// 解锁前预设应用实现签名（由 security_commands 在启动阶段注册）
///
/// 参数：应用句柄 + 本次解锁的容器路径。
/// 返回：Ok 表示运行时策略已等于受信档位；Err 表示应中止解锁（fail-closed）。
pub(crate) type PresetApplyFn = fn(&AppHandle, &str) -> Result<(), String>;

static APPLY_IMPL: OnceLock<PresetApplyFn> = OnceLock::new();

/// 注册解锁前预设应用实现（应用启动阶段调用一次；重复注册忽略，保持首个实现）。
pub(crate) fn install(apply: PresetApplyFn) {
    let _ = APPLY_IMPL.set(apply);
}

/// 解锁前把受信档位应用到 C 运行时策略层。
///
/// fail-closed：实现未注册（启动异常）时返回 Err，由调用方中止解锁。
pub(crate) fn apply_persisted_preset_before_unlock(
    app: &AppHandle,
    verthys_path: &str,
) -> Result<(), String> {
    match APPLY_IMPL.get() {
        Some(f) => f(app, verthys_path),
        None => Err("安全策略模块不可用，已中止解锁（请重启应用后重试）".to_string()),
    }
}