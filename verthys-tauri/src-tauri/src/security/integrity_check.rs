/*
 * integrity_check.rs — 程序自完整性签名核验（完整校验能力的执行路径）
 *
 * 职责：
 *   承载 11 位特性契约中 FEAT_INTEGRITY_CHECK 位的应用侧执行路径：
 *     - 启动期：对主程序镜像执行 Authenticode 签名核验（WinVerifyTrust，
 *       复用 module_whitelist 的 FFI 与结果缓存），在独立后台线程执行，
 *       不阻塞应用启动；
 *     - 运行期：由后台巡检线程按轮次对已加载模块抽样复核签名
 *       （抽样策略与威胁上报在 background_patrol 内实现）。
 *
 * 失败语义（不阻断解锁）：
 *   - 吊销检查依赖网络与系统证书状态，离线或证书服务异常时可能产生
 *     非攻击性失败；为避免自锁死循环，核验失败一律不阻断解锁与启动：
 *     Release 构建写审计事件 + 错误日志，Debug 构建仅记录日志。
 *
 * 门控语义：
 *   - 仅当应用侧策略位 FEAT_INTEGRITY_CHECK 开启时执行；策略位尚未
 *     应用任何预设时按保守值（开启）处理，与门控模块的失败方向一致。
 *
 * 平台：Windows 实现；非 Windows 平台启动核验为空操作。
 */

/// 启动期后台线程名（日志与转储定位用）
const BOOT_THREAD_NAME: &str = "verthys-integrity-boot";

/// 启动期对主程序镜像执行签名核验（异步，不阻塞调用方）
///
/// 在独立后台线程执行 WinVerifyTrust：
///   - 核验对象为当前进程主镜像（current_exe 解析出的真实路径）；
///   - 结果同时写入审计日志（INTEGRITY_CHECK 事件）与应用日志；
///   - 失败仅报告，不阻断启动与解锁（失败语义为模块级契约）。
///
/// 调用时机：应用 setup 阶段（主窗口显示前后皆可，线程自主完成）。
#[cfg(target_os = "windows")]
pub fn verify_self_image_async(app: tauri::AppHandle) {
    let spawn_result = std::thread::Builder::new()
        .name(BOOT_THREAD_NAME.into())
        .spawn(move || {
            run_boot_verification(&app);
        });
    if let Err(e) = spawn_result {
        log::error!("[integrity_check] 启动核验线程创建失败（本轮启动无签名核验）: {}", e);
    }
}

/// 非 Windows 平台：启动核验为空操作（与模块头平台声明一致）
#[cfg(not(target_os = "windows"))]
pub fn verify_self_image_async(_app: tauri::AppHandle) {}

/// 执行一次启动核验并写审计（线程体内运行）
#[cfg(target_os = "windows")]
fn run_boot_verification(app: &tauri::AppHandle) {
    // 门控：完整校验位关闭时跳过（性能档 / 自定义档关闭该能力）
    if !crate::security::app_feature_gate::enabled(
        crate::security::app_feature_gate::FEAT_INTEGRITY_CHECK,
    ) {
        log::debug!("[integrity_check] 完整校验位关闭，跳过启动核验");
        return;
    }

    let exe_path = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => {
            // 无法定位主镜像属于环境异常：按失败处置（不阻断），审计留痕
            report_result(app, false, format!("无法定位主程序镜像: {}", e));
            return;
        }
    };

    let ok = crate::security::module_whitelist::verify_signature(&exe_path);
    if ok {
        report_result(app, true, "主程序镜像签名核验通过".to_string());
    } else {
        report_result(app, false, "主程序镜像签名核验失败（不阻断启动与解锁）".to_string());
    }
}

/// 按构建类型上报核验结果：审计 + 日志（Debug 构建仅日志，不写审计）
#[cfg(target_os = "windows")]
fn report_result(app: &tauri::AppHandle, ok: bool, detail: String) {
    if cfg!(debug_assertions) {
        if ok {
            log::info!("[integrity_check] {}", detail);
        } else {
            log::warn!("[integrity_check] {}", detail);
        }
        return;
    }

    let event = crate::util::audit_log::AuditEvent::new(
        crate::util::audit_log::AuditEventType::IntegrityCheck,
        &format!("pid-{}", std::process::id()),
        "integrity_check",
        if ok {
            crate::util::audit_log::AuditResult::Success
        } else {
            crate::util::audit_log::AuditResult::Failure
        },
    )
    .with_detail(detail.clone());

    let log_path = tauri::Manager::path(app)
        .app_config_dir()
        .ok()
        .map(|d| d.join("audit.log"));
    let written = match log_path {
        Some(p) => {
            let key = crate::security_commands::audit::get_audit_hmac_key();
            match key {
                Some(k) => crate::util::audit_log::append_audit(&p, &k, event).is_ok(),
                None => false,
            }
        }
        None => false,
    };

    if ok {
        log::info!("[integrity_check] {}（审计落盘: {}）", detail, written);
    } else {
        log::error!("[integrity_check] {}（审计落盘: {}）", detail, written);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_thread_name_is_const() {
        // 线程名为运维定位契约，禁止无意变更
        assert_eq!(BOOT_THREAD_NAME, "verthys-integrity-boot");
    }
}
