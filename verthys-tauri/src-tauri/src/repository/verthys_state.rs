/*
 * repository/verthys_state.rs — 状态文件持久化（实现）
 *
 *   1. 状态文件强绑定：存放到容器附属数据目录（目录内 state.json）
 *      用户整体复制容器与附属目录时状态自然跟随，跨设备无缝迁移
 *   2. 路径指针：app_config_dir/.verthys_last_path 记录上次使用的 verthys 路径
 *      verthys_init_status 据此找到状态文件
 *   3. 主动修复：verthys_init_status 中校验 .verthys magic，合法则修复状态文件
 *   4. 修复失败可观测性：repair_fail_count 计数器
 *   5. 幂等性：内存缓存避免重复 I/O
 *
 * 原子提交：先写 state.json.tmp，再 rename 覆盖
 *
 * 路径派生统一由 repository::container_layout 提供，本文件禁止自行拼接附属路径。
 */

use crate::constants::{STATE_MAGIC, STATE_VERSION};
use crate::repository::container_layout;
use crate::util::path::normalize_path;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone)]
pub struct VerthysState {
    pub magic: String,
    pub ready: bool,
    /// 加密库绝对路径（通用格式：反斜杠转正斜杠）
    pub verthys_path: String,
    pub created_at: u64,
    pub version: u32,
    /// DPAPI 加密的设备组件数据（base64）
    ///
    /// 存储 DeviceComponents 经 DPAPI CryptProtectData 加密后的密文（base64）。
    /// DPAPI 密封使状态文件离机失效（无法在其他机器解密）。
    #[serde(default)]
    pub device_binding_blob: String,
    /// 连续修复失败计数器
    /// 每次主动修复失败递增，成功时清零。
    /// 连续失败 3 次触发前端告警（通过 verthys_init_status 返回 detail）。
    #[serde(default)]
    pub repair_fail_count: u32,
}

impl VerthysState {
    pub fn new(verthys_path: &str) -> Self {
        VerthysState {
            magic: STATE_MAGIC.into(),
            ready: true,
            verthys_path: normalize_path(verthys_path),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            version: STATE_VERSION,
            device_binding_blob: String::new(),
            repair_fail_count: 0,
        }
    }
}

/* ------------------------------------------------------------------ *
 * 路径指针：app_config_dir/.verthys_last_path                          *
 *                                                                    *
 * 纯文本文件，仅记录上次使用的 verthys 文件路径。                       *
 * verthys_init_status 据此找到 .verthys 同级的状态文件。                  *
 * ------------------------------------------------------------------ */

/// 获取配置目录（app_config_dir）
pub fn get_state_dir(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    use tauri::Manager;
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("获取配置目录失败: {}", e))?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("创建配置目录失败: {}", e))?;
    }
    Ok(dir)
}

/// 读取路径指针（app_config_dir/.verthys_last_path）
/// 返回上次使用的 verthys 文件路径，None 表示全新用户
pub fn read_last_verthys_path(app: &tauri::AppHandle) -> Result<Option<String>, String> {
    let dir = get_state_dir(app)?;
    let pointer = dir.join(".verthys_last_path");
    if !pointer.exists() {
        return Ok(None);
    }
    let path = std::fs::read_to_string(&pointer).map_err(|e| format!("读取路径指针失败: {}", e))?;
    let trimmed = path.trim().to_string();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed))
}

/// 写入路径指针（app_config_dir/.verthys_last_path）
fn write_last_verthys_path(app: &tauri::AppHandle, verthys_path: &str) -> Result<(), String> {
    let dir = get_state_dir(app)?;
    let pointer = dir.join(".verthys_last_path");
    std::fs::write(&pointer, verthys_path).map_err(|e| format!("写入路径指针失败: {}", e))
}

/* ------------------------------------------------------------------ *
 * 状态文件路径：容器附属数据目录                                        *
 *                                                                    *
 * verthys_path = "D:/data/verthys.verthys"                            *
 * state_path   = "D:/data/verthys.verthys.d/state.json"               *
 * ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ *
 * .verthys 文件格式合法性校验                                           *
 *                                                                    *
 * 只识别当前 格式，旧格式一律按损坏处理。                            *
 *                                                                    *
 * 布局：偏移 0 起为 64 KiB 元数据副本 A，固定头 76B，                *
 *   [u32 magic 0x59545256 ('VRTY')][u16 version_major][u16 version_minor] *
 *                                                                    *
 * 本函数只做轻量结构探测，不代替解锁流程的密钥认证与完整性校验。        *
 * ------------------------------------------------------------------ */

/// 校验 .verthys 文件格式合法性（仅固定头）
pub fn validate_verthys_file(verthys_path: &str) -> bool {
    use std::io::Read;

    // 固定头（与 core/src/crypto/vty_types.h 同源）
    const CONTAINER_MAGIC: u32 = 0x5954_5256; // 小端字节 'V' 'R' 'T' 'Y'
    const CONTAINER_VERSION_MAJOR: u16 = 4;
    const CONTAINER_VERSION_MINOR: u16 = 2;
    const CONTAINER_MIN_FILE_BYTES: u64 = 128 * 1024; // A/B 元数据副本下限
    const CONTAINER_HEADER_BYTES: usize = 8;

    let mut file = match std::fs::File::open(verthys_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut frame = [0u8; CONTAINER_HEADER_BYTES];
    if let Err(e) = file.read_exact(&mut frame) {
        log::warn!("[state] 读取容器帧头失败: {}", e);
        return false;
    }

    /* magic 与版本字段同时匹配；文件长度必须覆盖 A/B 元数据区。 */
    let magic_le = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if magic_le != CONTAINER_MAGIC {
        log::warn!(
            "[state] 文件帧 magic 校验失败: {:02X?} (期望 'VRTY')",
            &frame[..4]
        );
        return false;
    }
    let major = u16::from_le_bytes([frame[4], frame[5]]);
    let minor = u16::from_le_bytes([frame[6], frame[7]]);
    let size = std::fs::metadata(verthys_path)
        .map(|m| m.len())
        .unwrap_or(0);
    if major == CONTAINER_VERSION_MAJOR && minor == CONTAINER_VERSION_MINOR && size >= CONTAINER_MIN_FILE_BYTES {
        return true;
    }
    log::warn!(
        "[state] 容器头非法: version={}.{} size={}",
        major,
        minor,
        size
    );
    false
}

/* ------------------------------------------------------------------ *
 * 状态文件读写                                                        *
 * ------------------------------------------------------------------ */

/// 读取状态文件
///
/// 流程：
///   1. 读取路径指针获取 verthys_path
///   2. 读取附属目录状态文件
///   3. 路径指针不存在 → None（全新用户）
///   4. 状态文件不存在 → None（跨设备复制未携带状态文件）
pub fn read_state_file(app: &tauri::AppHandle) -> Result<Option<VerthysState>, String> {
    let verthys_path = match read_last_verthys_path(app)? {
        Some(p) => p,
        None => return Ok(None),
    };
    read_state_at(&verthys_path)
}

/// 读取指定容器的状态文件（附属目录）。
fn read_state_at(verthys_path: &str) -> Result<Option<VerthysState>, String> {
    let primary = container_layout::state_file_for(verthys_path);
    if primary.exists() {
        return parse_state_file(&primary).map(Some);
    }
    // 路径指针存在但状态文件不存在：可能跨设备复制时未携带状态文件。
    // 返回 None，由 verthys_init_status / verthys_unlock 主动修复。
    log::info!(
        "[state] 状态文件不存在（可能跨设备复制未携带）: verthys_path={}",
        crate::util::path::sanitize_path(verthys_path)
    );
    Ok(None)
}

/// 解析既有状态文件（调用方保证文件存在）
fn parse_state_file(file: &std::path::Path) -> Result<VerthysState, String> {
    let content = std::fs::read_to_string(file).map_err(|e| format!("读取状态文件失败: {}", e))?;
    let state: VerthysState =
        serde_json::from_str(&content).map_err(|e| format!("解析状态文件失败: {}", e))?;
    if state.magic != STATE_MAGIC {
        return Err("状态文件 magic 不匹配".into());
    }
    Ok(state)
}

/// 原子写入状态文件（附属数据目录）+ 更新路径指针
///
/// 写入两处：
///   1. <verthys_path>.d/state.json — 状态文件（随附属目录迁移）
///   2. app_config_dir/.verthys_last_path — 路径指针（记录上次路径）
///
/// 目录保障失败返回明确错误（只读介质 / 同名文件占用）。
pub fn write_state_file_atomic(app: &tauri::AppHandle, state: &VerthysState) -> Result<(), String> {
    use crate::util::path::sanitize_path;
    container_layout::ensure_sidecar_dir(&state.verthys_path)?;
    let state_file = container_layout::state_file_for(&state.verthys_path);
    let tmp_file = std::path::PathBuf::from(format!("{}.tmp", state_file.to_string_lossy()));

    let content = serde_json::to_string(state).map_err(|e| format!("序列化状态文件失败: {}", e))?;

    // 1. 写临时文件（同文件系统，保证 rename 原子性）
    std::fs::write(&tmp_file, &content).map_err(|e| format!("写入临时状态文件失败: {}", e))?;

    // 2. 原子 rename（同文件系统内 rename 是原子的）
    std::fs::rename(&tmp_file, &state_file).map_err(|e| {
        // rename 失败：清理临时文件
        let _ = std::fs::remove_file(&tmp_file);
        format!("原子重命名状态文件失败: {}", e)
    })?;

    // 3. 更新路径指针（失败不阻塞状态文件已写入）
    if let Err(e) = write_last_verthys_path(app, &state.verthys_path) {
        log::warn!("[state] 路径指针更新失败（状态文件已写入）: {}", e);
    }

    log::info!(
        "[state] 状态文件已原子提交: ready={}, path={}, repair_fails={}",
        state.ready,
        sanitize_path(&state.verthys_path),
        state.repair_fail_count
    );
    Ok(())
}

/// 删除状态文件 + 路径指针（回滚时调用）
///
/// 删除范围为状态文件本体及其临时文件（附属目录），
/// 附属目录仅在因此清空时回收；其余附属数据由调用方按需清理。
pub fn delete_state_file(app: &tauri::AppHandle) {
    // 删除状态文件（附属目录，含临时文件）
    if let Ok(Some(verthys_path)) = read_last_verthys_path(app) {
        let state_file = container_layout::state_file_for(&verthys_path);
        let tmp_file = std::path::PathBuf::from(format!("{}.tmp", state_file.to_string_lossy()));
        let _ = std::fs::remove_file(&state_file);
        let _ = std::fs::remove_file(&tmp_file);

        let _ = container_layout::remove_dir_if_empty(&container_layout::sidecar_dir_for(
            &verthys_path,
        ));
    }
    // 删除路径指针
    if let Ok(dir) = get_state_dir(app) {
        let pointer = dir.join(".verthys_last_path");
        let _ = std::fs::remove_file(&pointer);
    }
}

/* ------------------------------------------------------------------ *
 * 主动修复                                                              *
 *                                                                    *
 * 在 verthys_init_status 中调用，启动阶段主动修复状态文件：             *
 *   - 状态文件不存在但 .verthys 存在且格式合法 → 重建状态文件           *
 *   - 状态文件 ready=false 但 .verthys 格式合法 → 修复为 ready=true    *
 *   - 修复失败递增 repair_fail_count，连续 3 次触发告警               *
 * ------------------------------------------------------------------ */

/// 主动修复状态文件
///
/// 在 verthys_init_status 中调用，校验 .verthys 文件格式后重建/修复状态文件。
/// 返回修复后的状态（如果修复成功），或 None（修复失败或不需修复）。
pub fn try_repair_state_file(app: &tauri::AppHandle, verthys_path: &str) -> Option<VerthysState> {
    use crate::util::path::sanitize_path;

    // 1. 校验 .verthys 文件格式合法性
    if !validate_verthys_file(verthys_path) {
        log::warn!(
            "[state] 主动修复中止：.verthys 格式校验失败: {}",
            sanitize_path(verthys_path)
        );
        return None;
    }

    // 2. 读取现有状态文件（如果存在）
    let existing = read_state_file(app).ok().flatten();
    let fail_count = existing.as_ref().map(|s| s.repair_fail_count).unwrap_or(0);

    // 3. 创建新状态文件
    let new_state = VerthysState::new(verthys_path);
    match write_state_file_atomic(app, &new_state) {
        Ok(()) => {
            log::info!("[state] 主动修复成功: {}", sanitize_path(verthys_path));
            Some(new_state)
        }
        Err(e) => {
            log::warn!("[state] 主动修复失败 ({}): {}", fail_count + 1, e);
            // 修复失败：尝试递增失败计数器（写入旧状态 + fail_count+1）
            if let Some(mut old_state) = existing {
                old_state.repair_fail_count = fail_count + 1;
                let _ = write_state_file_atomic(app, &old_state);
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_verthys_file;

    /// 构建 容器：magic 0x59545256 + major/minor + 指定大小文件体
    fn write_container_file(
        name: &str,
        major: u16,
        minor: u16,
        size: usize,
    ) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("{}_{}", name, std::process::id()));
        let mut body = vec![0u8; size];
        body[0..4].copy_from_slice(&0x5954_5256u32.to_le_bytes());
        body[4..6].copy_from_slice(&major.to_le_bytes());
        body[6..8].copy_from_slice(&minor.to_le_bytes());
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn test_validate_verthys_file_accepts_header() {
        let path = write_container_file("verthys_state_t", 4, 2, 128 * 1024);
        assert!(validate_verthys_file(path.to_str().unwrap()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_validate_verthys_file_rejects_wrong_version() {
        let path = write_container_file("verthys_state_t_badver", 4, 1, 128 * 1024);
        assert!(!validate_verthys_file(path.to_str().unwrap()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_validate_verthys_file_rejects_short_body() {
        let path = write_container_file("verthys_state_t_short", 4, 2, 64 * 1024);
        assert!(!validate_verthys_file(path.to_str().unwrap()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_validate_verthys_file_rejects_foreign_magic() {
        let path = write_container_file("verthys_state_t_foreign", 4, 2, 128 * 1024);
        // 改写 magic 为非 VRTY 值
        let mut body = vec![0u8; 128 * 1024];
        body[0..4].copy_from_slice(b"VERT");
        body[4..6].copy_from_slice(&4u16.to_le_bytes());
        body[6..8].copy_from_slice(&2u16.to_le_bytes());
        std::fs::write(&path, body).unwrap();
        assert!(!validate_verthys_file(path.to_str().unwrap()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_validate_verthys_file_rejects_missing_file() {
        let path =
            std::env::temp_dir().join(format!("verthys_state_t_none_{}", std::process::id()));
        assert!(!validate_verthys_file(path.to_str().unwrap()));
    }
}
