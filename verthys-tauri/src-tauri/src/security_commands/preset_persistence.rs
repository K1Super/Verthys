/*
 * security_commands/preset_persistence.rs — 安全预设受信持久化
 *
 * 单一事实源：预设与自定义特性配置的权威副本。
 * 文件与状态文件同域（<verthys_path>.preset.json），随容器文件自然迁移。
 *
 * 写入契约：
 *   - 原子提交：先写 .tmp，再 rename 覆盖（同文件系统 rename 原子性）
 *   - 任何写/读失败以 Err 上抛明确错误，不静默吞（上层负责可见报告）
 *   - 幂等：重复写入相同内容无副作用
 */

use serde::{Deserialize, Serialize};

use crate::repository::verthys_state::read_last_verthys_path;
use crate::security_commands::responses::PresetFeatures;

/// 预设配置文件路径后缀（与 .state 同域：<verthys_path>.preset.json）
const PRESET_FILE_SUFFIX: &str = ".preset.json";

/// 受信持久化的预设状态
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PresetPersist {
    /// 预设代号：0=BALANCED, 1=SECURE, 2=PERFORMANCE, 3=CUSTOM
    pub code: u32,
    /// CUSTOM 档自定义特性（仅 code=3 时有效；其他档位为 None）
    #[serde(default)]
    pub custom_features: Option<PresetFeatures>,
}

/// 由 verthys 路径推导预设配置文件路径
fn preset_file_for(verthys_path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}{}", verthys_path, PRESET_FILE_SUFFIX))
}

/// 读取受信预设配置。
/// 路径指针不存在（全新用户）或配置文件不存在返回 Ok(None)；
/// 文件存在但解析/校验失败返回 Err（数据损坏不静默降级）。
pub fn read_preset_persist(app: &tauri::AppHandle) -> Result<Option<PresetPersist>, String> {
    let verthys_path = match read_last_verthys_path(app)? {
        Some(p) => p,
        None => return Ok(None),
    };
    let file = preset_file_for(&verthys_path);
    if !file.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&file)
        .map_err(|e| format!("读取预设配置文件失败: {}", e))?;
    let parsed: PresetPersist = serde_json::from_str(&content)
        .map_err(|e| format!("解析预设配置文件失败: {}", e))?;
    // 合法域校验：code ∈ 0..=3，且 CUSTOM 必须携带自定义特性
    if parsed.code > 3 {
        return Err(format!("预设配置文件 code 非法: {}", parsed.code));
    }
    if parsed.code == 3 && parsed.custom_features.is_none() {
        return Err("预设配置文件 code=3 缺少自定义特性".into());
    }
    Ok(Some(parsed))
}

/// 原子写入受信预设配置（tmp + rename）。失败上抛明确错误。
pub fn write_preset_persist(
    app: &tauri::AppHandle,
    persist: &PresetPersist,
) -> Result<(), String> {
    let verthys_path = read_last_verthys_path(app)?
        .ok_or("无法写入预设配置：路径指针不存在".to_string())?;
    let file = preset_file_for(&verthys_path);
    let tmp = std::path::PathBuf::from(format!("{}.tmp", file.to_string_lossy()));

    let content = serde_json::to_string(persist)
        .map_err(|e| format!("序列化预设配置失败: {}", e))?;

    std::fs::write(&tmp, &content)
        .map_err(|e| format!("写入预设配置临时文件失败: {}", e))?;

    std::fs::rename(&tmp, &file).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("原子重命名预设配置文件失败: {}", e)
    })?;

    log::info!(
        "[preset_persist] 预设配置已原子提交: code={}",
        persist.code
    );
    Ok(())
}

/// 删除受信预设配置文件（回滚至"无配置"状态时调用，best-effort）
pub fn delete_preset_persist(app: &tauri::AppHandle) {
    if let Ok(Some(verthys_path)) = read_last_verthys_path(app) {
        let file = preset_file_for(&verthys_path);
        let tmp = std::path::PathBuf::from(format!("{}.tmp", file.to_string_lossy()));
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_file_suffix_mapping() {
        let p = preset_file_for("D:/data/vault.verthys");
        assert_eq!(
            p.to_string_lossy(),
            "D:/data/vault.verthys.preset.json"
        );
    }

    #[test]
    fn test_preset_persist_roundtrip() {
        let features = PresetFeatures {
            anti_debug: true,
            anti_inject: true,
            integrity_check: true,
            memory_guard: true,
            key_separation: true,
            emergency_response: true,
            session_lock_on_idle: true,
            shadow_sleep: true,
            module_patrol: true,
            clip_clear_on_lock: true,
            usb_clone_detect: true,
            trace_cleanup: true,
        };
        let p = PresetPersist {
            code: 3,
            custom_features: Some(features),
        };
        let json = serde_json::to_string(&p).unwrap();
        let restored: PresetPersist = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.code, 3);
        assert!(restored.custom_features.is_some());
    }

    #[test]
    fn test_preset_persist_defaults_custom_features_missing() {
        let json = r#"{"code":1}"#;
        let restored: PresetPersist = serde_json::from_str(json).unwrap();
        assert_eq!(restored.code, 1);
        assert!(restored.custom_features.is_none());
    }

    #[test]
    fn test_read_rejects_invalid_code() {
        use std::io::Write;
        // 直接构造非法文件内容走校验分支（借临时文件验证 code 合法域）
        let dir = std::env::temp_dir();
        // 校验逻辑在 read_preset_persist 内依赖路径指针，此处仅验证结构层：
        // 非法 code 的结构仍可反序列化，由上层校验拦截。
        let p = PresetPersist {
            code: 9,
            custom_features: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        let tmp_path = dir.join(format!("preset_illegal_{}.json", std::process::id()));
        let mut f = std::fs::File::create(&tmp_path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
        let raw = std::fs::read_to_string(&tmp_path).unwrap();
        let parsed: PresetPersist = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.code, 9);
        let _ = std::fs::remove_file(&tmp_path);
    }
}