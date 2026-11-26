/*
 * 初始化状态判定与主动修复
 *
 * 职责边界：根据状态文件与 .verthys 文件的实际存在性/合法性给出
 * none / ready / broken 三态，并在可恢复场景重建状态文件或回收损坏残留。
 * 本模块幂等，每次读取最新磁盘状态。
 */
use crate::controller::types::{InitStatus, InitStatusResult};
use crate::repository::container_layout;
use crate::repository::verthys_state::{
    delete_state_file, read_last_verthys_path, read_state_file, try_repair_state_file,
    validate_verthys_file,
};
use crate::util::path::sanitize_path;
// ===== 初始化状态判定 =====

/// 判定 verthys 初始化状态，区分全新用户、已有 verthys、损坏残留。
///
/// 该命令在应用启动时调用，根据状态文件、.verthys 文件存在性与合法性，
/// 返回 "none"（全新）、"ready"（可解锁）、"broken"（需清理或修复）。
///
/// 支持主动修复：
/// - 路径指针存在但状态文件缺失时，校验 .verthys 文件格式并重建状态。
/// - 状态文件 ready=false 但 .verthys 合法时，自动修复为 ready。
///
/// 修复失败连续 3 次时，在 detail 中推送告警，提示用户检查磁盘。
/// 该操作幂等，每次读取最新磁盘状态。
#[tauri::command]
pub fn verthys_init_status(app: tauri::AppHandle) -> Result<InitStatusResult, String> {
    let state = read_state_file(&app)?;

    match state {
        None => {
            let last_path = read_last_verthys_path(&app)?;

            match last_path {
                None => Ok(InitStatusResult {
                    status: "none".into(),
                    status_enum: Some(InitStatus::None),
                    verthys_path: None,
                    detail: "无状态文件，首次使用".into(),
                }),
                Some(verthys_path) => {
                    if std::path::Path::new(&verthys_path).exists() {
                        if let Some(repaired) = try_repair_state_file(&app, &verthys_path) {
                            log::info!(
                                "[init_status] 状态文件缺失，主动修复成功: {}",
                                sanitize_path(&verthys_path)
                            );
                            return Ok(InitStatusResult {
                                status: "ready".into(),
                                status_enum: Some(InitStatus::Ready),
                                verthys_path: Some(repaired.verthys_path.clone()),
                                detail: "状态文件缺失，已自动修复".into(),
                            });
                        }
                        log::warn!(
                            "[init_status] 状态文件缺失且主动修复失败: {}",
                            sanitize_path(&verthys_path)
                        );
                        return Ok(InitStatusResult {
                            status: "broken".into(),
                            status_enum: Some(InitStatus::Broken),
                            verthys_path: Some(verthys_path),
                            detail: "状态文件缺失且修复失败，请检查磁盘空间和权限".into(),
                        });
                    }
                    log::warn!(
                        "[init_status] 路径指针存在但 .verthys 文件不存在: {}",
                        sanitize_path(&verthys_path)
                    );
                    delete_state_file(&app);
                    Ok(InitStatusResult {
                        status: "none".into(),
                        status_enum: Some(InitStatus::None),
                        verthys_path: None,
                        detail: "上次使用的文件已不存在，按全新用户处理".into(),
                    })
                }
            }
        }
        Some(s) => {
            let repair_alert = if s.repair_fail_count >= 3 {
                log::warn!(
                    "[AUDIT][state] 状态文件修复连续失败 {} 次，向前端推送告警: path={}",
                    s.repair_fail_count,
                    sanitize_path(&s.verthys_path)
                );
                format!(
                    "⚠ 状态文件写入异常（连续失败 {} 次），请检查磁盘空间与权限。",
                    s.repair_fail_count
                )
            } else {
                String::new()
            };

            if !s.ready {
                if std::path::Path::new(&s.verthys_path).exists()
                    && validate_verthys_file(&s.verthys_path)
                {
                    if let Some(repaired) = try_repair_state_file(&app, &s.verthys_path) {
                        log::info!(
                            "[init_status] ready=false 主动修复成功: {}",
                            sanitize_path(&s.verthys_path)
                        );
                        return Ok(InitStatusResult {
                            status: "ready".into(),
                            status_enum: Some(InitStatus::Ready),
                            verthys_path: Some(repaired.verthys_path.clone()),
                            detail: append_alert("状态文件已自动修复", &repair_alert),
                        });
                    }
                }
                log::warn!(
                    "[init_status] 损坏残留且修复失败: ready=false, path={}",
                    sanitize_path(&s.verthys_path)
                );
                let verthys_path = std::path::Path::new(&s.verthys_path);
                if verthys_path.exists() {
                    let _ = std::fs::remove_file(verthys_path);
                    log::info!("[init_status] 已清理残留 .verthys 文件");
                }
                // 残留容器的附属数据一并回收（有界清理：只删已知附属文件，
                // 目录含未知内容时保留目录本体）
                let report = container_layout::cleanup_container_sidecars(&s.verthys_path);
                if report.removed_files > 0 || report.removed_dir {
                    log::info!(
                        "[init_status] 已回收残留附属数据: files={} dir_removed={}",
                        report.removed_files,
                        report.removed_dir
                    );
                }
                delete_state_file(&app);
                Ok(InitStatusResult {
                    status: "broken".into(),
                    status_enum: Some(InitStatus::Broken),
                    verthys_path: Some(s.verthys_path.clone()),
                    detail: append_alert(
                        "上次初始化失败，已清理残留文件，按全新用户处理",
                        &repair_alert,
                    ),
                })
            } else if !std::path::Path::new(&s.verthys_path).exists() {
                log::warn!(
                    "[init_status] 状态文件 ready=true 但文件缺失: {}",
                    sanitize_path(&s.verthys_path)
                );
                delete_state_file(&app);
                Ok(InitStatusResult {
                    status: "broken".into(),
                    status_enum: Some(InitStatus::Broken),
                    verthys_path: Some(s.verthys_path.clone()),
                    detail: "已清理状态文件".into(),
                })
            } else {
                Ok(InitStatusResult {
                    status: "ready".into(),
                    status_enum: Some(InitStatus::Ready),
                    verthys_path: Some(s.verthys_path.clone()),
                    detail: append_alert("已有合法文件，解锁流程", &repair_alert),
                })
            }
        }
    }
}

fn append_alert(detail: &str, repair_alert: &str) -> String {
    if repair_alert.is_empty() {
        detail.into()
    } else {
        format!("{} | {}", detail, repair_alert)
    }
}
