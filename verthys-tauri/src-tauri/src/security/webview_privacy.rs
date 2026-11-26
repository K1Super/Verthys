/*
 * security/webview_privacy.rs — WebView2 表单自动填充关闭与存量清除
 *
 * 风险：WebView2 常规自动填充默认开启，输入框内容会以明文写入用户数据
 *   目录的 Web Data 数据库，并在后续输入时弹出历史值下拉。本应用的输入
 *   包含密钥、口令与账户标识，落盘即等同明文泄露。
 *
 * 约束：
 *   - 必须在主窗口对用户可见前调用，保证首次输入之前策略已生效。
 *   - 关闭与清除均走 WebView2 Profile 接口，不直接删除用户数据目录文件，
 *     避免与运行中的浏览器进程争用同一数据库。
 *   - 运行时版本过旧导致扩展接口不可用时记录警告并继续启动，不得因该
 *     策略失败阻断应用；前端 autocomplete 属性作为兜底。
 */

use tauri::Manager;
use webview2_com::ClearBrowsingDataCompletedHandler;
use webview2_com::Microsoft::Web::WebView2::Win32::{
    ICoreWebView2Profile, ICoreWebView2Profile2, ICoreWebView2Profile6, ICoreWebView2_13,
    COREWEBVIEW2_BROWSING_DATA_KINDS_GENERAL_AUTOFILL,
    COREWEBVIEW2_BROWSING_DATA_KINDS_PASSWORD_AUTOSAVE,
};
use windows_core::Interface;

/// 关闭主窗口 WebView 的常规自动填充与密码自动保存，并清除存量自动填充数据。
///
/// 幂等：重复调用只会重复下发同一策略。失败仅记录警告，调用方无需处理返回值。
pub fn harden_main_webview(app: &tauri::AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        log::warn!("[webview_privacy] 主窗口不存在，自动填充策略未应用");
        return;
    };

    let result = window.with_webview(|webview| {
        let controller = webview.controller();
        // SAFETY: controller 由已创建的 WebView2 持有，闭包在 WebView 所属线程执行；
        // 主窗口创建完成时 CoreWebView2 已可用。
        unsafe {
            let core = match controller.CoreWebView2() {
                Ok(core) => core,
                Err(e) => {
                    log::warn!("[webview_privacy] 获取 CoreWebView2 失败: {}", e);
                    return;
                }
            };
            // Profile 由 ICoreWebView2_13 提供；旧运行时缺少该接口时按不可用处理。
            let extended = match core.cast::<ICoreWebView2_13>() {
                Ok(extended) => extended,
                Err(e) => {
                    log::warn!("[webview_privacy] 获取 WebView2 Profile 接口失败: {}", e);
                    return;
                }
            };
            let profile = match extended.Profile() {
                Ok(profile) => profile,
                Err(e) => {
                    log::warn!("[webview_privacy] 获取 WebView2 Profile 失败: {}", e);
                    return;
                }
            };
            apply_profile_policy(&profile);
        }
    });

    if let Err(e) = result {
        log::warn!(
            "[webview_privacy] WebView 访问失败，自动填充策略未应用: {}",
            e
        );
    }
}

/// 下发关闭策略并清除已落盘的自动填充与密码数据。
///
/// Profile6 提供关闭开关，Profile2 提供按数据类型清除；两者按可用性
/// 独立尝试，旧运行时缺少 Profile6 时仍能清除存量。
fn apply_profile_policy(profile: &ICoreWebView2Profile) {
    match profile.cast::<ICoreWebView2Profile6>() {
        Ok(profile6) => {
            let general = unsafe { profile6.SetIsGeneralAutofillEnabled(false) };
            match general {
                Ok(()) => log::info!("[webview_privacy] 已关闭 WebView2 常规自动填充"),
                Err(e) => log::warn!("[webview_privacy] 关闭常规自动填充失败: {}", e),
            }

            let password = unsafe { profile6.SetIsPasswordAutosaveEnabled(false) };
            match password {
                Ok(()) => log::info!("[webview_privacy] 已关闭 WebView2 密码自动保存"),
                Err(e) => log::warn!("[webview_privacy] 关闭密码自动保存失败: {}", e),
            }
        }
        Err(e) => {
            log::warn!(
                "[webview_privacy] 当前 WebView2 不支持自动填充开关，依赖前端属性兜底: {}",
                e
            );
        }
    }

    match profile.cast::<ICoreWebView2Profile2>() {
        Ok(profile2) => {
            let kinds = COREWEBVIEW2_BROWSING_DATA_KINDS_GENERAL_AUTOFILL
                | COREWEBVIEW2_BROWSING_DATA_KINDS_PASSWORD_AUTOSAVE;
            let handler = ClearBrowsingDataCompletedHandler::create(Box::new(|result| {
                match result {
                    Ok(()) => log::info!("[webview_privacy] 存量自动填充与密码数据已清除"),
                    Err(e) => log::warn!("[webview_privacy] 清除存量自动填充失败: {}", e),
                }
                Ok(())
            }));

            if let Err(e) = unsafe { profile2.ClearBrowsingData(kinds, &handler) } {
                log::warn!("[webview_privacy] 发起存量自动填充清除失败: {}", e);
            }
        }
        Err(e) => {
            log::warn!(
                "[webview_privacy] 当前 WebView2 不支持按类型清除数据: {}",
                e
            );
        }
    }
}
