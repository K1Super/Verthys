/*
 * security_commands/preset_persistence.rs — 安全预设受信持久化
 *
 * 单一事实源：预设与自定义特性配置的权威副本。
 * 文件位于容器附属数据目录（目录内 preset.json），随附属目录整体迁移。
 * 旧布局 <verthys_path>.preset.json 仅作只读回退与一次性迁移的旧位置。
 *
 * 写入契约：
 *   - 原子提交：先写唯一命名临时文件，fsync 落盘后再 rename 覆盖
 *     （同文件系统 rename 原子性 + 数据持久性双保障）
 *   - 写序列进程内互斥：临时文件写入与重命名全序列串行，防并发交错
 *   - 任何写/读失败以 Err 上抛明确错误，不静默吞（上层负责可见报告）
 *   - 幂等：重复写入相同内容无副作用
 *
 * 路径派生统一由 repository::container_layout 提供，本文件禁止自行拼接附属路径。
 */

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::repository::container_layout;
use crate::repository::verthys_state::read_last_verthys_path;
use crate::security_commands::responses::PresetFeatures;

/// 临时文件后缀（唯一命名：{主文件}.{pid}.{seq}.tmp）
const PRESET_TMP_SUFFIX: &str = ".tmp";

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

/// 写序列互斥锁：临时文件写入 + 重命名全序列串行化（进程内并发写防护）
static PRESET_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// 临时文件序号：同进程内快速连续写入时避免临时文件重名
static PRESET_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// 读取指定路径的预设文件（调用方保证文件存在）；解析或校验失败返回 Err。
fn parse_preset_file(file: &std::path::Path) -> Result<PresetPersist, String> {
    let content =
        std::fs::read_to_string(file).map_err(|e| format!("读取预设配置文件失败: {}", e))?;
    let parsed: PresetPersist =
        serde_json::from_str(&content).map_err(|e| format!("解析预设配置文件失败: {}", e))?;
    // 合法域校验：code ∈ 0..=3，且 CUSTOM 必须携带自定义特性
    if parsed.code > 3 {
        return Err(format!("预设配置文件 code 非法: {}", parsed.code));
    }
    if parsed.code == 3 && parsed.custom_features.is_none() {
        return Err("预设配置文件 code=3 缺少自定义特性".into());
    }
    Ok(parsed)
}

/// 读取指定容器的受信预设配置（附属目录优先，旧布局命中即懒迁移）。
///
/// 迁移纪律：旧文件先解析成功再搬移；解析失败不搬移且原样保留（保留现场），
/// 搬移失败不阻断本次读取（下次访问自动重试）。
fn read_preset_at(verthys_path: &str) -> Result<Option<PresetPersist>, String> {
    let primary = container_layout::preset_file_for(verthys_path);
    if primary.exists() {
        return parse_preset_file(&primary).map(Some);
    }

    let legacy = container_layout::legacy_preset_file_for(verthys_path);
    if !legacy.exists() {
        return Ok(None);
    }

    let parsed = parse_preset_file(&legacy)?;
    match container_layout::migrate_legacy_file(&legacy, &primary) {
        Ok(()) => log::info!("[preset_persist] 旧布局预设文件已收口至附属数据目录"),
        Err(e) => log::warn!(
            "[preset_persist] 旧布局预设文件迁移失败（保持原位置，下次访问重试）: {}",
            e
        ),
    }
    Ok(Some(parsed))
}

/// 按指定容器路径读取受信预设配置（解锁期使用：不依赖路径指针，
/// 避免指针滞后于本次解锁容器导致的读错文件）。
/// 路径为空或文件不存在返回 Ok(None)；文件损坏返回 Err。
pub fn read_preset_persist_for_path(
    verthys_path: &str,
) -> Result<Option<PresetPersist>, String> {
    if verthys_path.is_empty() {
        return Ok(None);
    }
    read_preset_at(verthys_path)
}

/// 读取受信预设配置。
/// 路径指针不存在（全新用户）或配置文件不存在返回 Ok(None)；
/// 文件存在但解析/校验失败返回 Err（数据损坏不静默降级）。
pub fn read_preset_persist(app: &tauri::AppHandle) -> Result<Option<PresetPersist>, String> {
    let verthys_path = match read_last_verthys_path(app)? {
        Some(p) => p,
        None => return Ok(None),
    };
    read_preset_persist_for_path(&verthys_path)
}

/// 原子写入指定容器的受信预设配置。
///
/// 写序列（互斥保护）：
///   1. 附属数据目录保障（不可创建时明确报错，不回退旧布局写入）
///   2. 唯一命名临时文件（{主文件}.{pid}.{seq}.tmp）写入全部内容
///   3. sync_all 落盘（掉电后要么旧完整内容、要么新完整内容，不产生半截文件）
///   4. rename 原子覆盖主文件；失败清理临时文件并上抛错误
pub fn write_preset_persist_for_path(
    verthys_path: &str,
    persist: &PresetPersist,
) -> Result<(), String> {
    if verthys_path.is_empty() {
        return Err("无法写入预设配置：容器路径为空".to_string());
    }
    container_layout::ensure_sidecar_dir(verthys_path)?;
    let file = container_layout::preset_file_for(verthys_path);
    let content =
        serde_json::to_string(persist).map_err(|e| format!("序列化预设配置失败: {}", e))?;

    let _guard = PRESET_WRITE_LOCK
        .lock()
        .map_err(|e| format!("预设写锁中毒: {}", e))?;
    let seq = PRESET_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = std::path::PathBuf::from(format!(
        "{}.{}.{}{}",
        file.to_string_lossy(),
        std::process::id(),
        seq,
        PRESET_TMP_SUFFIX
    ));

    let write_result = (|| -> std::io::Result<()> {
        let mut handle = std::fs::File::create(&tmp)?;
        handle.write_all(content.as_bytes())?;
        // 持久性屏障：确保重命名前内容已落盘（rename 仅保证目录项原子替换）
        handle.sync_all()?;
        drop(handle);
        std::fs::rename(&tmp, &file)
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("原子写入预设配置文件失败: {}", e));
    }

    log::info!("[preset_persist] 预设配置已原子提交: code={}", persist.code);
    Ok(())
}

/// 原子写入受信预设配置（按路径指针定位容器）。失败上抛明确错误。
pub fn write_preset_persist(app: &tauri::AppHandle, persist: &PresetPersist) -> Result<(), String> {
    let verthys_path =
        read_last_verthys_path(app)?.ok_or("无法写入预设配置：路径指针不存在".to_string())?;
    write_preset_persist_for_path(&verthys_path, persist)
}

/// 删除受信预设配置文件（回滚至"无配置"状态时调用，best-effort）。
/// 同时清理新布局与旧布局两处主文件及其残留临时文件（异常退出可能遗留）。
pub fn delete_preset_persist(app: &tauri::AppHandle) {
    if let Ok(Some(verthys_path)) = read_last_verthys_path(app) {
        let file = container_layout::preset_file_for(&verthys_path);
        let _ = std::fs::remove_file(&file);
        remove_stray_tmp_files(&file);

        let legacy = container_layout::legacy_preset_file_for(&verthys_path);
        let _ = std::fs::remove_file(&legacy);
        remove_stray_tmp_files(&legacy);

        let _ = container_layout::remove_dir_if_empty(&container_layout::sidecar_dir_for(
            &verthys_path,
        ));
    }
}

/// 清理主文件同目录下的残留临时文件（{主文件名}.*.tmp，best-effort）
fn remove_stray_tmp_files(file: &std::path::Path) {
    let (Some(dir), Some(name)) = (file.parent(), file.file_name()) else {
        return;
    };
    let prefix = format!("{}.", name.to_string_lossy());
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let entry_name = entry.file_name();
        let entry_name = entry_name.to_string_lossy();
        if entry_name.starts_with(&prefix) && entry_name.ends_with(PRESET_TMP_SUFFIX) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_true_features() -> PresetFeatures {
        PresetFeatures {
            anti_debug: true,
            anti_inject: true,
            integrity_check: true,
            memory_guard: true,
            key_separation: true,
            emergency_response: true,
            session_lock_on_idle: true,
            module_patrol: true,
            clip_clear_on_lock: true,
            usb_clone_detect: true,
            trace_cleanup: true,
        }
    }

    /// 构造隔离的临时容器路径（同一目录下按用例名区分）
    fn temp_container_path(case: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("verthys_preset_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("创建测试目录");
        dir.join(format!("{}.verthys", case))
    }

    #[test]
    fn test_preset_file_suffix_mapping() {
        let p = container_layout::preset_file_for("D:/data/vault.verthys");
        // 派生路径保留输入分隔符体系，断言前归一为正斜杠
        assert_eq!(
            p.to_string_lossy().replace('\\', "/"),
            "D:/data/vault.verthys.d/preset.json"
        );
    }

    #[test]
    fn test_preset_persist_roundtrip() {
        let features = all_true_features();
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
    fn test_write_then_read_roundtrip_by_path() {
        let container = temp_container_path("roundtrip");
        let persist = PresetPersist {
            code: 1,
            custom_features: None,
        };
        write_preset_persist_for_path(container.to_string_lossy().as_ref(), &persist)
            .expect("写入应当成功");
        let loaded = read_preset_persist_for_path(container.to_string_lossy().as_ref())
            .expect("读取应当成功")
            .expect("文件应当存在");
        assert_eq!(loaded.code, 1);
        assert!(
            container_layout::preset_file_for(container.to_string_lossy().as_ref()).exists(),
            "写入必须落在附属数据目录"
        );
    }

    #[test]
    fn test_read_missing_file_returns_none() {
        let container = temp_container_path("missing");
        let loaded = read_preset_persist_for_path(container.to_string_lossy().as_ref()).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_read_rejects_invalid_code() {
        let container = temp_container_path("invalid_code");
        let path_str = container.to_string_lossy().to_string();
        container_layout::ensure_sidecar_dir(&path_str).unwrap();
        let file = container_layout::preset_file_for(&path_str);
        std::fs::write(&file, r#"{"code":9}"#).unwrap();
        let result = read_preset_persist_for_path(&path_str);
        assert!(result.is_err(), "非法 code 必须上抛错误而非静默降级");
    }

    #[test]
    fn test_read_rejects_custom_without_features() {
        let container = temp_container_path("custom_missing_features");
        let path_str = container.to_string_lossy().to_string();
        container_layout::ensure_sidecar_dir(&path_str).unwrap();
        let file = container_layout::preset_file_for(&path_str);
        std::fs::write(&file, r#"{"code":3}"#).unwrap();
        let result = read_preset_persist_for_path(&path_str);
        assert!(result.is_err(), "CUSTOM 缺少特性必须上抛错误");
    }

    #[test]
    fn test_legacy_preset_migrated_on_read() {
        let container = temp_container_path("legacy_migrate");
        let path_str = container.to_string_lossy().to_string();
        let legacy = container_layout::legacy_preset_file_for(&path_str);
        std::fs::write(&legacy, r#"{"code":2}"#).unwrap();

        let loaded = read_preset_persist_for_path(&path_str)
            .expect("读取应当成功")
            .expect("旧布局文件应当被读取");
        assert_eq!(loaded.code, 2);

        assert!(!legacy.exists(), "旧布局文件必须被搬走");
        assert!(
            container_layout::preset_file_for(&path_str).exists(),
            "搬移目标必须落在附属数据目录"
        );
    }

    #[test]
    fn test_legacy_preset_corrupted_not_migrated() {
        let container = temp_container_path("legacy_corrupted");
        let path_str = container.to_string_lossy().to_string();
        let legacy = container_layout::legacy_preset_file_for(&path_str);
        std::fs::write(&legacy, r#"{"code":9}"#).unwrap();

        let result = read_preset_persist_for_path(&path_str);

        assert!(result.is_err(), "损坏的旧布局文件必须上抛错误");
        assert!(legacy.exists(), "解析失败不得搬移（保留现场）");
        assert!(!container_layout::preset_file_for(&path_str).exists());
    }

    #[test]
    fn test_concurrent_writes_leave_parseable_file_and_no_tmp() {
        let container = temp_container_path("concurrent");
        let path_str = container.to_string_lossy().to_string();
        let mut handles = Vec::new();
        for code in 0..8u32 {
            let path = path_str.clone();
            handles.push(std::thread::spawn(move || {
                let persist = PresetPersist {
                    code: code % 4,
                    custom_features: (code % 4 == 3).then(all_true_features),
                };
                write_preset_persist_for_path(&path, &persist).expect("并发写入应当成功");
            }));
        }
        for handle in handles {
            handle.join().expect("线程不应 panic");
        }
        let loaded = read_preset_persist_for_path(&path_str)
            .expect("并发写入后文件必须可解析")
            .expect("文件应当存在");
        assert!(loaded.code <= 3);
        // 无残留临时文件
        let file = container_layout::preset_file_for(&path_str);
        let dir = file.parent().unwrap();
        let prefix = format!("{}.", file.file_name().unwrap().to_string_lossy());
        let leftovers: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with(&prefix) && name.ends_with(PRESET_TMP_SUFFIX)
            })
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(leftovers.is_empty(), "不得遗留临时文件: {:?}", leftovers);
    }
}