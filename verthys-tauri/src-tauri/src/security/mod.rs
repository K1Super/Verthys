/*
 * security/mod.rs — Windows 安全 API 封装
 *
 * 子模块：
 *   - session_guard:    智能会话自动锁屏（mpsc 通道 + RAII 窗口 + 看门狗
 *                       + WTS 会话通知 + 显示器电源设置通知）
 *   - file_lock:        独占锁与防并发 + 私有目录 ACL 隔离
 *   - usb_guard:        移动存储安全强化（DPAPI 持久化 + 加盐哈希 + 影子休眠）
 *   - module_whitelist: 模块白名单实时巡检（路径真实化 + 吊销检查 + 缓存）
 *   - cleanup:          程序痕迹、缓存与卸载残留防护（移除 Gutmann + TRIM）
 *   - brute_force:      登录暴力拦截（DPAPI 持久化 + 不可逆计数 + 速率限制）
 *   - background_patrol:后台模块巡检线程（动态频率 + 看门狗 + 独立熔断
 *                       + 完整校验抽样复核）
 *   - clipboard_guard:  剪贴板保护升级（延迟清空 + 外部写入检测 + 统一入口）
 *   - window_affinity:  窗口显示亲和性原语（原始取值读写 + OS 能力降级）
 *   - app_feature_gate: 应用侧档位特性位镜像（11 位契约，单写多读）
 *   - integrity_check:  程序自完整性签名核验（启动主镜像 + 巡检抽样口径）
 *   - trace_cleanup:    应用自身痕迹清理（最近记录精确清理，锁定/退出触发）
 *   - command_names:    安全命令名登记
 *
 * 剪贴板清空实现要点：
 *   - 废弃"写入随机数据再清空"模式，直接调用 EmptyClipboard 清空剪贴板
 *   - 清空后广播 WM_DESTROYCLIPBOARD 通知系统清除云剪贴板缓存
 *   - 清空操作保持 CLIPBOARD_LOCK 串行化
 *   - 统一剪贴板操作入口，所有剪贴板相关操作均通过 clipboard_guard 模块暴露
 */

pub mod app_feature_gate;
pub mod background_patrol;
pub mod brute_force;
pub mod cleanup;
pub mod clipboard_guard;
pub mod command_names;
pub mod file_lock;
pub mod integrity_check;
pub mod module_whitelist;
pub mod session_guard;
pub mod trace_cleanup;
pub mod usb_guard;
pub mod window_affinity;

/// 清除可被外部注入的 WebView2 启动环境变量。
///
/// 必须在 WebView2 初始化之前调用；幂等，可重复调用。
/// 仅移除进程环境块中的变量，不修改注册表或用户配置。
pub fn harden_process_environment() {
    if std::env::var_os("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS").is_some() {
        std::env::remove_var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
        log::warn!("[security] 已清除启动环境变量: WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
    }
    if std::env::var_os("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER").is_some() {
        std::env::remove_var("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER");
        log::warn!("[security] 已清除启动环境变量: WEBVIEW2_BROWSER_EXECUTABLE_FOLDER");
    }
    if std::env::var_os("WEBVIEW2_USER_DATA_FOLDER").is_some() {
        std::env::remove_var("WEBVIEW2_USER_DATA_FOLDER");
        log::warn!("[security] 已清除启动环境变量: WEBVIEW2_USER_DATA_FOLDER");
    }
    if std::env::var_os("WEBVIEW2_RELEASE_CHANNEL_PREFERENCE").is_some() {
        std::env::remove_var("WEBVIEW2_RELEASE_CHANNEL_PREFERENCE");
        log::warn!("[security] 已清除启动环境变量: WEBVIEW2_RELEASE_CHANNEL_PREFERENCE");
    }
    if std::env::var_os("WEBVIEW2_CHANNEL_SEARCH_KIND").is_some() {
        std::env::remove_var("WEBVIEW2_CHANNEL_SEARCH_KIND");
        log::warn!("[security] 已清除启动环境变量: WEBVIEW2_CHANNEL_SEARCH_KIND");
    }
    if std::env::var_os("WEBVIEW2_PREFER_CANARY").is_some() {
        std::env::remove_var("WEBVIEW2_PREFER_CANARY");
        log::warn!("[security] 已清除启动环境变量: WEBVIEW2_PREFER_CANARY");
    }
    if std::env::var_os("WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER").is_some() {
        std::env::remove_var("WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER");
        log::warn!("[security] 已清除启动环境变量: WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER");
    }
    if std::env::var_os("WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER").is_some() {
        std::env::remove_var("WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER");
        log::warn!("[security] 已清除启动环境变量: WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER");
    }
}

/* ====================================================================== *
 *  统一剪贴板清空入口                                *
 *                                                                        *
 *  clear_clipboard() 委托到 clipboard_guard::clear() 统一入口。           *
 *  移除了旧版"写入随机数据再清空"的自相矛盾逻辑。                         *
 *  向后兼容：保持 () -> bool 签名供现有调用方使用。                       *
 * ====================================================================== */

/// 清空剪贴板（向后兼容接口）
///
/// 统一剪贴板清空入口：
///   - 废弃"写入随机数据再清空"模式，改为直接清空并广播
///   - 统一通过 clipboard_guard::clear() 实现
///   - 清空后广播 WM_DESTROYCLIPBOARD，强制系统清除云剪贴板缓存
///
/// 返回 true 表示清空成功，false 表示失败。
pub fn clear_clipboard() -> bool {
    match clipboard_guard::clear() {
        Ok(()) => {
            log::info!("[security] 剪贴板已清空（EmptyClipboard + WM_DESTROYCLIPBOARD 广播）");
            true
        }
        Err(e) => {
            log::warn!("[security] 剪贴板清空失败: {}", e);
            false
        }
    }
}
