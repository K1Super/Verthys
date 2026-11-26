/*
 * 容器口令材料与创建期目标校验
 *
 * 职责边界：本机密钥材料的读取策略（只读 / 允许生成）、旧位置迁移与恢复、
 * 容器口令复杂度校验，以及 keyfile 创建目标的前置校验与失败回滚。
 *
 * 约束：只读策略缺失时返回 None 而非生成新密钥；keyfile 回滚只删除本次
 * 流程确认由 C 层创建的文件，避免形成任意文件删除原语。
 */
use crate::util::path::normalize_path;
use std::path::PathBuf;
use zeroize::Zeroizing;
// ===== 容器口令来源 =====

/// 容器口令读取策略
#[derive(Clone, Copy)]
enum ContainerPasswordPolicy {
    /// 仅接受既有密钥材料：缺失返回 None（解锁与会话内操作）
    ExistingOnly,
    /// 允许生成新密钥材料（仅创建新库）
    CreateIfMissing,
}

/// 本机密钥材料缺失的稳定错误码（前端按码分支，不按文案匹配）
pub(crate) const KEY_MATERIAL_MISSING_CODE: &str = "E_KEY_MATERIAL_MISSING";

/// 本机密钥材料缺失的用户文案（跨命令复用）
pub(crate) const KEY_MATERIAL_MISSING_MESSAGE: &str =
    "本机密钥材料已丢失，无法用普通方式打开该库；请使用恢复码解锁，并在恢复会话中重绑本机设备槽";

/// 读取机器密钥材料主目录与旧位置目录（旧位置仅在迁移/恢复时读取）。
fn container_password_dirs(app: &tauri::AppHandle) -> Result<(PathBuf, Option<PathBuf>), String> {
    use tauri::Manager;
    let paths = app
        .try_state::<crate::infrastructure::app_paths::AppPaths>()
        .ok_or_else(|| "应用数据目录未初始化".to_string())?;
    Ok((
        paths.key_material_dir.clone(),
        paths.legacy_key_material_dir.clone(),
    ))
}

/// 按策略从指定目录读取容器口令（与 Tauri 解耦，便于单元测试）。
///
/// 读取顺序：主位置 → 旧位置迁移 → （仅创建）生成。
/// 主位置损坏时先用旧位置有效副本恢复主位置；两者都不可用则失败关闭，
/// 绝不静默生成新密钥，避免既有容器永久无法打开。
/// 密钥材料不写日志、不进审计，返回值由调用方以 Zeroizing 持有并在使用后擦除。
fn load_container_password_from_dirs(
    primary_dir: &std::path::Path,
    legacy_dir: Option<&std::path::Path>,
    allow_create: bool,
) -> Result<Option<Zeroizing<String>>, String> {
    use crate::util::container_secret;

    match container_secret::load_existing(primary_dir) {
        Ok(Some(password)) => return Ok(Some(password)),
        Ok(None) => {}
        Err(e) => {
            log::error!("[container_secret] 主位置密钥材料不可用: {}", e);
            if let Some(legacy) = legacy_dir {
                if container_secret::exists(legacy) {
                    match container_secret::restore_legacy(legacy, primary_dir) {
                        Ok(password) => {
                            log::warn!("[container_secret] 已从旧位置恢复主密钥材料");
                            return Ok(Some(password));
                        }
                        Err(e2) => {
                            log::error!("[container_secret] 旧位置恢复失败: {}", e2);
                        }
                    }
                }
            }
            return Err("安全存储不可用，无法访问加密库".to_string());
        }
    }

    if let Some(legacy) = legacy_dir {
        if legacy != primary_dir {
            match container_secret::load_existing(legacy) {
                Ok(Some(_)) => match container_secret::migrate_legacy(legacy, primary_dir) {
                    Ok(password) => {
                        log::info!("[container_secret] 旧位置密钥材料已迁移到主位置");
                        return Ok(Some(password));
                    }
                    Err(e) => {
                        log::error!("[container_secret] 密钥材料迁移失败: {}", e);
                        return Err("安全存储不可用，无法访问加密库".to_string());
                    }
                },
                Ok(None) => {}
                Err(e) => {
                    log::error!("[container_secret] 旧位置密钥材料不可用: {}", e);
                    return Err("安全存储不可用，无法访问加密库".to_string());
                }
            }
        }
    }

    if !allow_create {
        return Ok(None);
    }
    container_secret::load_or_create(primary_dir)
        .map(Some)
        .map_err(|e| {
            log::error!("[container_secret] 容器口令不可用: {}", e);
            "安全存储不可用，无法访问加密库".to_string()
        })
}

/// 按策略读取容器口令（宿主入口）。
fn load_container_password_by_policy(
    app: &tauri::AppHandle,
    policy: ContainerPasswordPolicy,
) -> Result<Option<Zeroizing<String>>, String> {
    let (primary_dir, legacy_dir) = container_password_dirs(app)?;
    load_container_password_from_dirs(
        &primary_dir,
        legacy_dir.as_deref(),
        matches!(policy, ContainerPasswordPolicy::CreateIfMissing),
    )
}

/// 读取既有容器口令（解锁/会话内操作）：缺失返回 None，绝不生成。
pub(crate) fn load_existing_container_password(
    app: &tauri::AppHandle,
) -> Result<Option<Zeroizing<String>>, String> {
    load_container_password_by_policy(app, ContainerPasswordPolicy::ExistingOnly)
}

/// 读取或创建容器口令（仅创建新库）。
pub(crate) fn load_or_create_container_password(
    app: &tauri::AppHandle,
) -> Result<Zeroizing<String>, String> {
    load_container_password_by_policy(app, ContainerPasswordPolicy::CreateIfMissing)?
        .ok_or_else(|| "安全存储不可用，无法访问加密库".to_string())
}

/// keyfile 创建目标的前置校验。
///
/// keyfile 是创建流程的附属产物，但目标路径来自前端选择。若目标已存在，
/// C 层 `write_keyfile_file` 会返回 `VTY_E_EXISTS` 且不写入、不删除；宿主
/// 若把该路径当作“本次创建产物”在回滚时删除，就形成了任意文件删除原语。
/// 因此在进入 worker 前必须拒绝任何已存在的目标、错误扩展名与相对路径。
pub(super) fn validate_keyfile_create_target(
    verthys_path: &str,
    keyfile_path: &str,
) -> Result<(), String> {
    let kf = std::path::Path::new(keyfile_path);
    if !kf.is_absolute() {
        return Err("keyfile 路径必须是绝对路径".into());
    }
    let ext_ok = kf
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("vkf"))
        .unwrap_or(false);
    if !ext_ok {
        return Err("keyfile 路径必须以 .vkf 结尾".into());
    }
    if let Some(parent) = kf.parent() {
        if !parent.is_dir() {
            return Err("keyfile 父目录不存在或不是目录".into());
        }
    } else {
        return Err("keyfile 路径缺少父目录".into());
    }
    if normalize_path(keyfile_path).to_lowercase()
        == normalize_path(verthys_path).to_lowercase()
    {
        return Err("keyfile 路径不能与容器路径相同".into());
    }
    match std::fs::symlink_metadata(kf) {
        Ok(_) => Err("keyfile 目标已存在，拒绝覆盖或删除".into()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("无法检查 keyfile 目标: {}", err)),
    }
}

/// 创建失败回滚：仅当本次流程确实由 C 层创建了 keyfile 时才删除。
///
/// 响应超时/解析失败时调用方必须传 `keyfile_created=false`：宁可留下
/// 孤儿 keyfile，也不删除来源不明的文件。
pub(super) fn cleanup_created_keyfile(
    keyfile_path: Option<&str>,
    keyfile_created: bool,
) -> Result<(), String> {
    if !keyfile_created {
        return Ok(());
    }
    let Some(kf) = keyfile_path else {
        return Ok(());
    };
    match std::fs::remove_file(kf) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("keyfile 回滚删除失败: {}", err)),
    }
}

/// 容器口令复杂度校验：最小长度 8，最大 512，用于创建/解锁前的前置校验。
/// 当前为 BALANCED 预设，未来可扩展为更严格规则。
pub(super) fn validate_password_complexity(password: &str) -> Result<(), String> {
    let len = password.len();
    if len < 8 {
        return Err("密码长度不足（至少 8 位）".into());
    }
    if len > 512 {
        return Err("密码过长".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
#[test]
fn keyfile_target_validation_rejects_existing_file() {
    let dir = temp_keyfile_case_dir("exists");
    let vault = dir.join("v.verthys");
    let kf = dir.join("existing.vkf");
    std::fs::write(&kf, b"sentinel-content").expect("写 sentinel 失败");

    let err = validate_keyfile_create_target(
        vault.to_str().unwrap(),
        kf.to_str().unwrap(),
    )
    .expect_err("已存在目标必须被拒绝");
    assert!(err.contains("已存在"), "错误文案应说明目标已存在: {err}");
    assert_eq!(
        std::fs::read(&kf).expect("sentinel 必须仍可读"),
        b"sentinel-content",
        "校验失败不得修改目标文件"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keyfile_target_validation_rejects_wrong_extension() {
    let dir = temp_keyfile_case_dir("ext");
    let vault = dir.join("v.verthys");
    let kf = dir.join("not-a-keyfile.txt");

    let err = validate_keyfile_create_target(
        vault.to_str().unwrap(),
        kf.to_str().unwrap(),
    )
    .expect_err("错误扩展名必须被拒绝");
    assert!(err.contains(".vkf"), "错误文案应说明扩展名: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keyfile_target_validation_rejects_relative_path() {
    let dir = temp_keyfile_case_dir("rel");
    let vault = dir.join("v.verthys");
    let err = validate_keyfile_create_target(vault.to_str().unwrap(), "keys/a.vkf")
        .expect_err("相对路径必须被拒绝");
    assert!(err.contains("绝对路径"), "错误文案应说明绝对路径: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keyfile_target_validation_accepts_absent_vkf() {
    let dir = temp_keyfile_case_dir("absent");
    let vault = dir.join("v.verthys");
    let kf = dir.join("new.vkf");
    validate_keyfile_create_target(vault.to_str().unwrap(), kf.to_str().unwrap())
        .expect("不存在的 .vkf 目标应通过校验");
    assert!(!kf.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keyfile_target_validation_rejects_same_path_as_container() {
    let dir = temp_keyfile_case_dir("same");
    let vault = dir.join("same.vkf");
    let err = validate_keyfile_create_target(
        vault.to_str().unwrap(),
        vault.to_str().unwrap(),
    )
    .expect_err("keyfile 与容器同路径必须被拒绝");
    assert!(err.contains("不能与容器路径相同"), "错误文案不符: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rollback_deletes_keyfile_only_when_created() {
    let dir = temp_keyfile_case_dir("rollback");
    let kf = dir.join("created.vkf");
    std::fs::write(&kf, b"not-created-by-this-flow").expect("写 sentinel 失败");

    cleanup_created_keyfile(Some(kf.to_str().unwrap()), false)
        .expect("未创建时必须为空操作");
    assert_eq!(
        std::fs::read(&kf).expect("文件必须仍在"),
        b"not-created-by-this-flow",
        "keyfile_created=false 时不得删除目标"
    );
    assert!(kf.exists());

    cleanup_created_keyfile(Some(kf.to_str().unwrap()), true)
        .expect("本次创建的文件必须可删除");
    assert!(!kf.exists(), "keyfile_created=true 时应删除本次产物");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn container_password_existing_only_returns_none_without_generating() {
    let root = unique_key_material_dir("existing_none");
    let primary = root.join("primary");
    let legacy = root.join("legacy");

    let result = load_container_password_from_dirs(&primary, Some(&legacy), false)
        .expect("缺失应返回 None 而非错误");
    assert!(result.is_none());
    assert!(
        !crate::util::container_secret::exists(&primary),
        "只读策略不得生成新密钥材料"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn container_password_create_generates_at_primary() {
    let root = unique_key_material_dir("create");
    let primary = root.join("primary");

    let created = load_container_password_from_dirs(&primary, None, true)
        .expect("创建策略应成功")
        .expect("创建策略应生成密钥材料");
    assert!(crate::util::container_secret::exists(&primary));
    let loaded = crate::util::container_secret::load_existing(&primary)
        .expect("读取应成功")
        .expect("主位置应有值");
    assert_eq!(loaded.as_str(), created.as_str());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn container_password_migrates_legacy_and_keeps_source() {
    let root = unique_key_material_dir("migrate");
    let primary = root.join("primary");
    let legacy = root.join("legacy");
    let original = crate::util::container_secret::load_or_create(&legacy)
        .expect("旧位置生成应成功");

    let migrated = load_container_password_from_dirs(&primary, Some(&legacy), false)
        .expect("迁移应成功")
        .expect("迁移后应返回值");
    assert_eq!(migrated.as_str(), original.as_str());
    assert!(crate::util::container_secret::exists(&primary));
    assert!(
        crate::util::container_secret::exists(&legacy),
        "迁移不得删除旧位置副本"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn container_password_restores_corrupt_primary_from_legacy() {
    let root = unique_key_material_dir("restore");
    let primary = root.join("primary");
    let legacy = root.join("legacy");
    let original = crate::util::container_secret::load_or_create(&legacy)
        .expect("旧位置生成应成功");
    std::fs::create_dir_all(&primary).expect("主位置目录应可创建");
    std::fs::write(primary.join("container.secret"), b"corrupted")
        .expect("写入损坏副本应成功");

    let restored = load_container_password_from_dirs(&primary, Some(&legacy), false)
        .expect("主位置损坏时应由旧位置恢复")
        .expect("恢复后应返回值");
    assert_eq!(restored.as_str(), original.as_str());
    let after = crate::util::container_secret::load_existing(&primary)
        .expect("读取应成功")
        .expect("主位置应有值");
    assert_eq!(after.as_str(), original.as_str());
    let _ = std::fs::remove_dir_all(&root);
}}
