/*
 * repository/verthys_state.rs — 状态文件持久化（实现）
 *
 *   1. 状态文件强绑定：存放到 .verthys 同级目录（<verthys_path>.state）
 *      用户复制 .verthys 时状态文件自然跟随，跨设备无缝迁移
 *   2. 路径指针：app_config_dir/.verthys_last_path 记录上次使用的 verthys 路径
 *      verthys_init_status 据此找到状态文件
 *   3. 主动修复：verthys_init_status 中校验 .verthys magic，合法则修复状态文件
 *   4. 修复失败可观测性：repair_fail_count 计数器
 *   5. 幂等性：内存缓存避免重复 I/O
 *
 * 原子提交：先写 .state.tmp，再 rename 覆盖
 */

use crate::constants::{STATE_MAGIC, STATE_VERSION};
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
    /// 已绑定的设备机器码（SHA-256 hex），首次初始化全局密钥时绑定
    #[serde(default)]
    pub device_fingerprint: String,
    /// DPAPI 加密的设备组件数据（base64）
    ///
    /// 存储 DeviceComponents 经 DPAPI CryptProtectData 加密后的密文（base64）。
    /// DPAPI 密封使状态文件离机失效（无法在其他机器解密）。
    /// 空字符串表示旧版状态文件（使用 device_fingerprint 明文哈希向后兼容）。
    #[serde(default)]
    pub device_binding_blob: String,
    /// ：连续修复失败计数器
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
            device_fingerprint: String::new(),
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
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("创建配置目录失败: {}", e))?;
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
    let path = std::fs::read_to_string(&pointer)
        .map_err(|e| format!("读取路径指针失败: {}", e))?;
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
    std::fs::write(&pointer, verthys_path)
        .map_err(|e| format!("写入路径指针失败: {}", e))
}

/* ------------------------------------------------------------------ *
 * ：旧版状态文件迁移                                       *
 *                                                                    *
 * 旧版状态文件存放在 app_config_dir/.verthys_state（与 .verthys 分离）。   *
 * 新版改为 .verthys 同级目录（<verthys_path>.state）+ 路径指针。           *
 *                                                                    *
 * 升级场景：用户从旧版升级后，路径指针不存在但旧状态文件存在。         *
 * 若不迁移，verthys_init_status 会误判为全新用户，显示"初始化密钥"界面。  *
 *                                                                    *
 * 迁移流程：                                                          *
 *   1. 读取旧 app_config_dir/.verthys_state                             *
 *   2. 校验 magic + verthys_path 字段                                   *
 *   3. 校验 .verthys 文件存在且 magic 合法                              *
 *   4. 写入新路径指针 + 新状态文件                                    *
 *   5. 删除旧状态文件（迁移成功后清理）                                *
 * ------------------------------------------------------------------ */

/// 尝试从旧版状态文件迁移到新版格式
///
/// 在 read_state_file 中路径指针不存在时调用。
/// 迁移成功返回 Some(VerthysState)，无需迁移或迁移失败返回 None。
fn try_migrate_from_legacy_state(app: &tauri::AppHandle) -> Option<VerthysState> {
    let dir = match get_state_dir(app) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("[state] 迁移失败：获取配置目录失败: {}", e);
            return None;
        }
    };
    let legacy_state_file = dir.join(".verthys_state");
    if !legacy_state_file.exists() {
        // 无旧版状态文件，无需迁移
        return None;
    }

    log::info!("[state] 检测到旧版状态文件，开始迁移: {}", legacy_state_file.display());

    // 1. 读取旧版状态文件
    let content = match std::fs::read_to_string(&legacy_state_file) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("[state] 迁移失败：读取旧版状态文件失败: {}", e);
            return None;
        }
    };

    // 2. 解析旧版状态文件（JSON 格式，结构与 VerthysState 兼容）
    let legacy_state: VerthysState = match serde_json::from_str(&content) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("[state] 迁移失败：解析旧版状态文件失败: {}", e);
            return None;
        }
    };

    // 3. 校验 magic
    if legacy_state.magic != STATE_MAGIC {
        log::warn!("[state] 迁移失败：旧版状态文件 magic 不匹配: {}", legacy_state.magic);
        return None;
    }

    // 4. 校验 verthys_path 非空
    let verthys_path = legacy_state.verthys_path.trim().to_string();
    if verthys_path.is_empty() {
        log::warn!("[state] 迁移失败：旧版状态文件 verthys_path 为空");
        return None;
    }

    // 5. 校验 .verthys 文件存在
    if !std::path::Path::new(&verthys_path).exists() {
        log::warn!("[state] 迁移失败：旧版状态文件指向的 .verthys 不存在: {}", crate::util::path::sanitize_path(&verthys_path));
        // .verthys 不存在 → 清理旧版状态文件，按全新用户处理
        let _ = std::fs::remove_file(&legacy_state_file);
        return None;
    }

    // 6. 校验 .verthys 文件格式合法（防止迁移无效文件）
    if !validate_verthys_file(&verthys_path) {
        log::warn!("[state] 迁移失败：旧版状态文件指向的文件格式不合法");
        return None;
    }

    // 7. 写入新路径指针
    if let Err(e) = write_last_verthys_path(app, &verthys_path) {
        log::warn!("[state] 迁移失败：写入路径指针失败: {}", e);
        return None;
    }

    // 8. 写入新状态文件（<verthys_path>.state）
    //    保留旧版状态文件的 ready/device_fingerprint 字段，重置 repair_fail_count
    let new_state = VerthysState {
        magic: STATE_MAGIC.into(),
        ready: legacy_state.ready,
        verthys_path: normalize_path(&verthys_path),
        created_at: legacy_state.created_at,
        version: STATE_VERSION,
        device_fingerprint: legacy_state.device_fingerprint.clone(),
        device_binding_blob: String::new(),
        repair_fail_count: 0,
    };
    if let Err(e) = write_state_file_atomic(app, &new_state) {
        log::warn!("[state] 迁移失败：写入新状态文件失败: {}", e);
        return None;
    }

    // 9. 删除旧版状态文件（迁移成功后清理）
    let _ = std::fs::remove_file(&legacy_state_file);
    log::info!("[state] 旧版状态文件迁移成功: verthys_path={}", crate::util::path::sanitize_path(&verthys_path));
    Some(new_state)
}

/* ------------------------------------------------------------------ *
 * 状态文件路径：.verthys 同级目录                                       *
 *                                                                    *
 * verthys_path = "D:/data/verthys.verthys"                              *
 * state_path = "D:/data/verthys.verthys.state"                        *
 *                                                                    *
 * 用户复制 .verthys 时 .verthys.state 自然跟随，跨设备无缝迁移。          *
 * ------------------------------------------------------------------ */

/// 获取状态文件路径（.verthys 同级目录）
fn get_state_file_for_verthys(verthys_path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}.state", verthys_path))
}

/* ------------------------------------------------------------------ *
 * .verthys 文件格式合法性校验                                           *
 *                                                                    *
 * V3 布局：文件偏移 0 起为超级块副本 0，帧头 8 字节                     *
 *   [u32 帧 magic 'V3RP'][u32 payload_len]，后随 FlatBuffers 载荷。   *
 * 校验与 C 层副本读取前置校验同源（帧 magic + 载荷长度边界），         *
 * 防止非 Verthys 文件误写入状态文件；完整认证由解锁流程执行。          *
 * ------------------------------------------------------------------ */

/// 校验 .verthys 文件格式合法性（V3 副本帧头探测）
pub fn validate_verthys_file(verthys_path: &str) -> bool {
    use std::io::Read;

    // V3 副本帧头常量（与 C 层 V3 副本布局一致，小端）
    const V3_FRAME_MAGIC: [u8; 4] = [0x56, 0x33, 0x52, 0x50]; // 'V3RP'
    const V3_FRAME_HEADER_BYTES: usize = 8;
    const V3_REPLICA_BYTES: usize = 16 * 1024;

    let mut file = match std::fs::File::open(verthys_path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut frame = [0u8; V3_FRAME_HEADER_BYTES];
    if let Err(e) = file.read_exact(&mut frame) {
        log::warn!("[state] 读取 V3 帧头失败: {}", e);
        return false;
    }
    if frame[..4] != V3_FRAME_MAGIC {
        log::warn!("[state] 文件帧 magic 校验失败: {:02X?} (期望 'V3RP')", &frame[..4]);
        return false;
    }
    let payload_len = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
    let max_payload = V3_REPLICA_BYTES - V3_FRAME_HEADER_BYTES;
    if payload_len == 0 || payload_len > max_payload {
        log::warn!("[state] 帧载荷长度非法: {} (期望 1..={})", payload_len, max_payload);
        return false;
    }
    true
}

/* ------------------------------------------------------------------ *
 * 状态文件读写                                                        *
 * ------------------------------------------------------------------ */

/// 读取状态文件
///
/// 流程：
///   1. 读取路径指针获取 verthys_path
///   2. 读取 <verthys_path>.state 状态文件
///   3. 路径指针不存在 → None（全新用户）
///   4. 状态文件不存在 → None（跨设备复制未携带状态文件）
pub fn read_state_file(app: &tauri::AppHandle) -> Result<Option<VerthysState>, String> {
    let verthys_path = match read_last_verthys_path(app)? {
        Some(p) => p,
        None => {
            // 路径指针不存在 → 尝试从旧版状态文件迁移
            // 旧版状态文件存放在 app_config_dir/.verthys_state，升级后需要迁移到新格式
            // 若迁移成功，返回迁移后的状态；否则返回 None（全新用户）
            if let Some(migrated) = try_migrate_from_legacy_state(app) {
                return Ok(Some(migrated));
            }
            return Ok(None); // 全新用户，无路径指针
        }
    };
    let state_file = get_state_file_for_verthys(&verthys_path);
    if !state_file.exists() {
        // 路径指针存在但状态文件不存在
        // 可能原因：跨设备复制 .verthys 时未携带 .verthys.state
        // 返回 None，让 verthys_init_status / verthys_unlock 主动修复
        log::info!("[state] 状态文件不存在（可能跨设备复制未携带）: verthys_path={}", crate::util::path::sanitize_path(&verthys_path));
        return Ok(None);
    }
    let content = std::fs::read_to_string(&state_file)
        .map_err(|e| format!("读取状态文件失败: {}", e))?;
    let state: VerthysState = serde_json::from_str(&content)
        .map_err(|e| format!("解析状态文件失败: {}", e))?;
    if state.magic != STATE_MAGIC {
        return Err("状态文件 magic 不匹配".into());
    }
    Ok(Some(state))
}

/// 原子写入状态文件（.verthys 同级目录）+ 更新路径指针
///
/// 写入两处：
///   1. <verthys_path>.state — 状态文件（与 .verthys 同级，跨设备跟随）
///   2. app_config_dir/.verthys_last_path — 路径指针（记录上次路径）
pub fn write_state_file_atomic(app: &tauri::AppHandle, state: &VerthysState) -> Result<(), String> {
    use crate::util::path::sanitize_path;
    let state_file = get_state_file_for_verthys(&state.verthys_path);
    let tmp_file = std::path::PathBuf::from(format!("{}.tmp", state_file.to_string_lossy()));

    let content = serde_json::to_string(state)
        .map_err(|e| format!("序列化状态文件失败: {}", e))?;

    // 1. 写临时文件（同文件系统，保证 rename 原子性）
    std::fs::write(&tmp_file, &content)
        .map_err(|e| format!("写入临时状态文件失败: {}", e))?;

    // 2. 原子 rename（同文件系统内 rename 是原子的）
    std::fs::rename(&tmp_file, &state_file)
        .map_err(|e| {
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
pub fn delete_state_file(app: &tauri::AppHandle) {
    // 删除 .verthys 同级的状态文件
    if let Ok(Some(verthys_path)) = read_last_verthys_path(app) {
        let state_file = get_state_file_for_verthys(&verthys_path);
        let tmp_file = std::path::PathBuf::from(format!("{}.tmp", state_file.to_string_lossy()));
        let _ = std::fs::remove_file(&state_file);
        let _ = std::fs::remove_file(&tmp_file);
    }
    // 删除路径指针
    if let Ok(dir) = get_state_dir(app) {
        let pointer = dir.join(".verthys_last_path");
        let _ = std::fs::remove_file(&pointer);
        // 兼容旧版本：清理 app_config_dir/.verthys_state
        let old_state = dir.join(".verthys_state");
        let old_tmp = dir.join(".verthys_state.tmp");
        let _ = std::fs::remove_file(&old_state);
        let _ = std::fs::remove_file(&old_tmp);
    }
}

/* ------------------------------------------------------------------ *
 * ：主动修复                                              *
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
        log::warn!("[state] 主动修复中止：.verthys 格式校验失败: {}", sanitize_path(verthys_path));
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
    use std::io::Write;

    /// 在临时目录创建测试文件，写入帧头字节
    fn write_frame_file(name: &str, header: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("{}_{}", name, std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(header).unwrap();
        path
    }

    /// 构建 V3 帧头：'V3RP' + payload_len（小端）
    fn v3_frame(payload_len: u32) -> Vec<u8> {
        let mut h = vec![0x56, 0x33, 0x52, 0x50];
        h.extend_from_slice(&payload_len.to_le_bytes());
        h
    }

    #[test]
    fn test_validate_verthys_file_accepts_v3_frame() {
        let path = write_frame_file("verthys_state_t_v3", &v3_frame(64));
        assert!(validate_verthys_file(path.to_str().unwrap()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_validate_verthys_file_rejects_vert_magic() {
        let path = write_frame_file("verthys_state_t_vert", b"VERT\x40\x00\x00\x00");
        assert!(!validate_verthys_file(path.to_str().unwrap()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_validate_verthys_file_rejects_zero_payload() {
        let path = write_frame_file("verthys_state_t_zero", &v3_frame(0));
        assert!(!validate_verthys_file(path.to_str().unwrap()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_validate_verthys_file_rejects_oversized_payload() {
        // 载荷长度超出副本槽位容量（16KB - 8B 帧头）
        let path = write_frame_file("verthys_state_t_over", &v3_frame(16 * 1024));
        assert!(!validate_verthys_file(path.to_str().unwrap()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_validate_verthys_file_rejects_short_file() {
        let path = write_frame_file("verthys_state_t_short", &[0x56, 0x33, 0x52]);
        assert!(!validate_verthys_file(path.to_str().unwrap()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_validate_verthys_file_rejects_missing_file() {
        let path = std::env::temp_dir().join(format!("verthys_state_t_none_{}", std::process::id()));
        assert!(!validate_verthys_file(path.to_str().unwrap()));
    }
}
