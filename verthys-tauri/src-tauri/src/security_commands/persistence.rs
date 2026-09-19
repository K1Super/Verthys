/*
 * persistence.rs — 安全状态 DPAPI 加密持久化层
 *
 *
 * 职责：
 *   1. BruteForceGuard 状态的 DPAPI 加密持久化与加载
 *   2. 受信任路径白名单的 DPAPI 加密持久化
 *   3. USB 序列号加盐哈希盐值的 DPAPI 持久化
 *   4. USB 注册表的 DPAPI 加密持久化
 *
 *   所有状态文件采用原子写入（先写 .tmp 再 rename），DPAPI 机器绑定，离机失效。
 */

use std::sync::atomic::Ordering;
use tauri::Manager;

use crate::security::{
    brute_force::{BruteForceGuard, BruteForcePersistedState},
    module_whitelist, usb_guard::UsbRegistry,
};

use super::state::SecurityState;

/* ====================================================================== *
 *  BruteForceGuard DPAPI 加密持久化                         *
 *                                                                        *
 *  状态文件路径：app_config_dir/.brute_force_state                        *
 *  格式：DPAPI( JSON BruteForcePersistedState )                           *
 *  应用启动时首次访问 brute_force 命令时自动加载。                        *
 *  每次 record_failure / record_success / clear_purge 后自动持久化。      *
 * ====================================================================== */

/// 获取暴力拦截状态文件路径
fn get_brute_force_state_file(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join(".brute_force_state")),
        Err(e) => {
            log::warn!("[brute_force] 第 13.2.2 项：获取配置目录失败: {}", e);
            None
        }
    }
}

/// 持久化暴力拦截状态（DPAPI 加密）
pub(super) fn persist_brute_force_state(app: &tauri::AppHandle, guard: &BruteForceGuard) {
    use crate::util::crypto::dpapi_protect;

    let file_path = match get_brute_force_state_file(app) {
        Some(p) => p,
        None => return,
    };

    let persisted = guard.export_state();

    let json = match serde_json::to_vec(&persisted) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("[brute_force] 第 13.2.2 项：序列化状态失败: {}", e);
            return;
        }
    };

    // DPAPI 加密（机器绑定，离机失效）
    let encrypted = match dpapi_protect(&json, Some("verthys_brute_force_state")) {
        Ok(enc) => enc,
        Err(e) => {
            log::warn!("[brute_force] 第 13.2.2 项：DPAPI 加密失败: {}", e);
            return;
        }
    };

    // 原子写入：先写 .tmp 再 rename
    let tmp_path = file_path.with_extension("brute_force_state.tmp");
    if let Err(e) = std::fs::write(&tmp_path, &encrypted) {
        log::warn!("[brute_force] 第 13.2.2 项：写入临时文件失败: {}", e);
        return;
    }
    if let Err(e) = std::fs::rename(&tmp_path, &file_path) {
        log::warn!("[brute_force] 第 13.2.2 项：重命名状态文件失败: {}", e);
        return;
    }

    log::debug!(
        "[brute_force] 第 13.2.2 项：状态已持久化 (consecutive={}, total={}, purge={})",
        persisted.consecutive_failures,
        persisted.total_failures,
        persisted.purge_triggered
    );
}

/// 从持久化加载暴力拦截状态（DPAPI 解密）
fn load_brute_force_state(app: &tauri::AppHandle, guard: &BruteForceGuard) {
    use crate::util::crypto::dpapi_unprotect;

    let file_path = match get_brute_force_state_file(app) {
        Some(p) => p,
        None => return,
    };

    if !file_path.exists() {
        log::debug!("[brute_force] 第 13.2.2 项：状态文件不存在，跳过加载（首次启动）");
        return;
    }

    let encrypted = match std::fs::read(&file_path) {
        Ok(data) => data,
        Err(e) => {
            log::warn!("[brute_force] 第 13.2.2 项：读取状态文件失败: {}", e);
            return;
        }
    };

    let json = match dpapi_unprotect(&encrypted) {
        Ok(data) => data,
        Err(e) => {
            log::warn!(
                "[brute_force] 第 13.2.2 项：DPAPI 解密失败（可能跨机器迁移）: {}",
                e
            );
            return;
        }
    };

    let persisted: BruteForcePersistedState = match serde_json::from_slice(&json) {
        Ok(state) => state,
        Err(e) => {
            log::warn!("[brute_force] 第 13.2.2 项：反序列化状态失败: {}", e);
            return;
        }
    };

    guard.import_state(&persisted);
}

/// 确保暴力拦截状态已从持久化加载（首次访问时触发）
pub(super) fn ensure_brute_force_loaded(app: &tauri::AppHandle, state: &SecurityState) {
    use std::sync::atomic::Ordering;

    if state.brute_force_loaded.swap(true, Ordering::SeqCst) {
        // 已加载
        return;
    }

    // 首次访问，从持久化加载
    if let Ok(guard) = state.brute_force.lock() {
        load_brute_force_state(app, &guard);
    } else {
        log::error!("[brute_force] 第 13.2.2 项：加载持久化状态时锁获取失败");
    }
}

/* ====================================================================== *
 *  受信任路径白名单 DPAPI 持久化                      *
 *                                                                        *
 *  白名单内容加密持久化到状态文件，应用启动时加载，形成不可篡改的安全基线。 *
 *  状态文件路径：app_config_dir/.trusted_paths_state                      *
 * ====================================================================== */

fn get_trusted_paths_state_file(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    use tauri::Manager;
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join(".trusted_paths_state")),
        Err(e) => {
            log::warn!("[trusted_paths] 获取配置目录失败: {}", e);
            None
        }
    }
}

/// 持久化受信任路径白名单（DPAPI 加密）
pub(super) fn persist_trusted_paths(app: &tauri::AppHandle) {
    use crate::util::crypto::dpapi_protect;

    let paths = module_whitelist::export_trusted_paths();

    let json = match serde_json::to_string(&paths) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("[trusted_paths] 序列化白名单失败: {}", e);
            return;
        }
    };

    let encrypted = match dpapi_protect(json.as_bytes(), Some("verthys_trusted_paths")) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("[trusted_paths] DPAPI 加密失败: {}", e);
            return;
        }
    };

    let file_path = match get_trusted_paths_state_file(app) {
        Some(p) => p,
        None => return,
    };

    let tmp_path = file_path.with_extension("trusted_paths_state.tmp");
    if let Err(e) = std::fs::write(&tmp_path, &encrypted) {
        log::warn!("[trusted_paths] 写入临时文件失败: {}", e);
        return;
    }
    if let Err(e) = std::fs::rename(&tmp_path, &file_path) {
        log::warn!("[trusted_paths] 重命名状态文件失败: {}", e);
        return;
    }

    log::info!(
        "[trusted_paths] 白名单已持久化 ({} 条路径)",
        paths.len()
    );
}

/// 加载受信任路径白名单（DPAPI 解密）
#[allow(dead_code)]
fn load_trusted_paths(app: &tauri::AppHandle) {
    use crate::util::crypto::dpapi_unprotect;

    let file_path = match get_trusted_paths_state_file(app) {
        Some(p) => p,
        None => return,
    };

    let data = match std::fs::read(&file_path) {
        Ok(d) => d,
        Err(_) => {
            log::debug!("[trusted_paths] 状态文件不存在，跳过加载（首次启动）");
            return;
        }
    };

    let json = match dpapi_unprotect(&data) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("[trusted_paths] DPAPI 解密失败（可能跨机器迁移）: {}", e);
            return;
        }
    };

    let paths: Vec<String> = match serde_json::from_slice(&json) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("[trusted_paths] 反序列化失败: {}", e);
            return;
        }
    };

    module_whitelist::import_trusted_paths(&paths);
    log::info!("[trusted_paths] 白名单已从持久化恢复 ({} 条路径)", paths.len());
}

/// 首次访问时加载白名单
#[allow(dead_code)]
fn ensure_trusted_paths_loaded(app: &tauri::AppHandle, state: &SecurityState) {
    if state.trusted_paths_loaded.swap(true, Ordering::SeqCst) {
        return;
    }
    load_trusted_paths(app);
}

/* ====================================================================== *
 *  USB 序列号加盐哈希 — 盐值 DPAPI 持久化            *
 *                                                                        *
 *  盐值（32 字节 / 256 位）在安装时随机生成，DPAPI 加密存储于应用配置      *
 *  目录。用于 HMAC-SHA256(salt, serial) 计算序列号哈希，即使数据库泄露    *
 *  也无法进行设备关联（彩虹表攻击无效）。                                  *
 *                                                                        *
 *  状态文件路径：app_config_dir/.usb_salt                                 *
 *  格式：DPAPI( 32 字节随机盐值 )                                         *
 * ====================================================================== */

/// USB 盐值长度（32 字节 = 256 位）
const USB_SALT_LEN: usize = 32;

/// 获取 USB 盐值文件路径
fn get_usb_salt_file(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join(".usb_salt")),
        Err(e) => {
            log::warn!("[usb_salt] 获取配置目录失败: {}", e);
            None
        }
    }
}

/// 生成密码学安全随机盐值（32 字节）
fn generate_usb_salt() -> Vec<u8> {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };
        let mut salt = vec![0u8; USB_SALT_LEN];
        let status = unsafe { BCryptGenRandom(None, &mut salt, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if status.is_ok() {
            return salt;
        }
        log::warn!("[usb_salt] BCryptGenRandom 失败，回退到 getrandom");
    }

    // 回退：getrandom crate
    let mut salt = vec![0u8; USB_SALT_LEN];
    if getrandom::getrandom(&mut salt).is_ok() {
        return salt;
    }

    // 最终回退：SystemTime 种子（不推荐，但保证可用）
    log::warn!("[usb_salt] getrandom 失败，回退到 SystemTime 种子");
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"verthys_usb_salt_fallback");
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    hasher.update(std::process::id().to_le_bytes());
    hasher.finalize().to_vec()
}

/// 持久化 USB 盐值（DPAPI 加密）
fn persist_usb_salt(app: &tauri::AppHandle, salt: &[u8]) {
    use crate::util::crypto::dpapi_protect;

    let file_path = match get_usb_salt_file(app) {
        Some(p) => p,
        None => return,
    };

    let encrypted = match dpapi_protect(salt, Some("verthys_usb_salt")) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("[usb_salt] DPAPI 加密失败: {}", e);
            return;
        }
    };

    let tmp_path = file_path.with_extension("usb_salt.tmp");
    if let Err(e) = std::fs::write(&tmp_path, &encrypted) {
        log::warn!("[usb_salt] 写入临时文件失败: {}", e);
        return;
    }
    if let Err(e) = std::fs::rename(&tmp_path, &file_path) {
        log::warn!("[usb_salt] 重命名盐值文件失败: {}", e);
        return;
    }

    log::info!("[usb_salt] USB 盐值已持久化 ({} 字节)", salt.len());
}

/// 加载 USB 盐值（DPAPI 解密）
fn load_usb_salt(app: &tauri::AppHandle) -> Option<Vec<u8>> {
    use crate::util::crypto::dpapi_unprotect;

    let file_path = get_usb_salt_file(app)?;

    let data = match std::fs::read(&file_path) {
        Ok(d) => d,
        Err(_) => {
            log::debug!("[usb_salt] 盐值文件不存在，将生成新盐值");
            return None;
        }
    };

    let salt = match dpapi_unprotect(&data) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("[usb_salt] DPAPI 解密失败（可能跨机器迁移）: {}", e);
            return None;
        }
    };

    if salt.len() != USB_SALT_LEN {
        log::warn!(
            "[usb_salt] 盐值长度异常 ({} 字节，期望 {})，将重新生成",
            salt.len(),
            USB_SALT_LEN
        );
        return None;
    }

    log::info!("[usb_salt] USB 盐值已从持久化加载");
    Some(salt)
}

/// 确保 USB 盐值已加载，返回盐值引用
///
/// 首次调用时从持久化加载盐值；若不存在则生成新盐值并持久化。
/// 后续调用直接从内存读取。
pub(super) fn ensure_usb_salt(app: &tauri::AppHandle, state: &SecurityState) -> Result<Vec<u8>, String> {
    if state.usb_salt_loaded.swap(true, Ordering::SeqCst) {
        // 已加载，从内存读取
        let salt = state
            .usb_salt
            .lock()
            .map_err(|e| format!("usb_salt 锁中毒: {}", e))?;
        if salt.len() == USB_SALT_LEN {
            return Ok(salt.clone());
        }
        // 盐值为空或长度不对，继续执行加载流程
    }

    // 尝试从持久化加载
    let salt = match load_usb_salt(app) {
        Some(s) => s,
        None => {
            // 不存在，生成新盐值并持久化
            let new_salt = generate_usb_salt();
            persist_usb_salt(app, &new_salt);
            new_salt
        }
    };

    // 存入内存
    {
        let mut guard = state
            .usb_salt
            .lock()
            .map_err(|e| format!("usb_salt 锁中毒: {}", e))?;
        *guard = salt.clone();
    }

    Ok(salt)
}

/* ====================================================================== *
 *  USB 注册表 DPAPI 持久化                           *
 *                                                                        *
 *  USB 注册表内容加密持久化到状态文件，应用启动时加载，形成不可篡改的     *
 *  安全基线。废除"首次自动注册"逻辑，仅管理员预先授权的设备可用。        *
 *                                                                        *
 *  状态文件路径：app_config_dir/.usb_registry_state                       *
 *  格式：DPAPI( JSON Vec<(String, String)> )                              *
 * ====================================================================== */

/// 获取 USB 注册表状态文件路径
fn get_usb_registry_state_file(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    match app.path().app_config_dir() {
        Ok(dir) => Some(dir.join(".usb_registry_state")),
        Err(e) => {
            log::warn!("[usb_registry] 获取配置目录失败: {}", e);
            None
        }
    }
}

/// 持久化 USB 注册表（DPAPI 加密）
pub(super) fn persist_usb_registry(app: &tauri::AppHandle, registry: &UsbRegistry) {
    use crate::util::crypto::dpapi_protect;

    let devices = registry.export_devices();

    let json = match serde_json::to_string(&devices) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("[usb_registry] 序列化注册表失败: {}", e);
            return;
        }
    };

    let encrypted = match dpapi_protect(json.as_bytes(), Some("verthys_usb_registry")) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("[usb_registry] DPAPI 加密失败: {}", e);
            return;
        }
    };

    let file_path = match get_usb_registry_state_file(app) {
        Some(p) => p,
        None => return,
    };

    let tmp_path = file_path.with_extension("usb_registry_state.tmp");
    if let Err(e) = std::fs::write(&tmp_path, &encrypted) {
        log::warn!("[usb_registry] 写入临时文件失败: {}", e);
        return;
    }
    if let Err(e) = std::fs::rename(&tmp_path, &file_path) {
        log::warn!("[usb_registry] 重命名状态文件失败: {}", e);
        return;
    }

    log::info!(
        "[usb_registry] 注册表已持久化 ({} 台设备)",
        devices.len()
    );
}

/// 加载 USB 注册表（DPAPI 解密）
fn load_usb_registry(app: &tauri::AppHandle, registry: &mut UsbRegistry) {
    use crate::util::crypto::dpapi_unprotect;

    let file_path = match get_usb_registry_state_file(app) {
        Some(p) => p,
        None => return,
    };

    let data = match std::fs::read(&file_path) {
        Ok(d) => d,
        Err(_) => {
            log::debug!("[usb_registry] 状态文件不存在，跳过加载（首次启动）");
            return;
        }
    };

    let json = match dpapi_unprotect(&data) {
        Ok(j) => j,
        Err(e) => {
            log::warn!("[usb_registry] DPAPI 解密失败（可能跨机器迁移）: {}", e);
            return;
        }
    };

    let devices: Vec<(String, String)> = match serde_json::from_slice(&json) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("[usb_registry] 反序列化失败: {}", e);
            return;
        }
    };

    registry.import_devices(&devices);
    log::info!(
        "[usb_registry] 注册表已从持久化恢复 ({} 台设备)",
        devices.len()
    );
}

/// 首次访问时加载 USB 注册表
pub(super) fn ensure_usb_registry_loaded(app: &tauri::AppHandle, state: &SecurityState) {
    if state.usb_registry_loaded.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Ok(mut guard) = state.usb_registry.lock() {
        load_usb_registry(app, &mut guard);
    }
}
