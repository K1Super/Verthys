/*
 * security/mod.rs — Windows 安全 API 封装
 *
 * 子模块：
 *   - session_guard:    智能会话自动锁屏（mpsc 通道 + RAII 窗口 + 看门狗）
 *   - file_lock:        独占锁与防并发 + 私有目录 ACL 隔离
 *   - usb_guard:        移动存储安全强化（DPAPI 持久化 + 加盐哈希 + 影子休眠）
 *   - module_whitelist: 模块白名单实时巡检（路径真实化 + 吊销检查 + 缓存）
 *   - cleanup:          程序痕迹、缓存与卸载残留防护（移除 Gutmann + TRIM）
 *   - brute_force:      登录暴力拦截（DPAPI 持久化 + 不可逆计数 + 速率限制）
 *   - background_patrol:后台模块巡检线程（动态频率 + 看门狗 + 独立熔断）
 *   - clipboard_guard:  剪贴板保护升级（延迟清空 + 外部写入检测 + 统一入口）
 *   - window_affinity:  窗口显示亲和性原语（原始取值读写 + OS 能力降级）
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
pub mod module_whitelist;
pub mod session_guard;
pub mod usb_guard;
pub mod window_affinity;

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
            log::info!(
                "[security] 剪贴板已清空（EmptyClipboard + WM_DESTROYCLIPBOARD 广播）"
            );
            true
        }
        Err(e) => {
            log::warn!("[security] 剪贴板清空失败: {}", e);
            false
        }
    }
}