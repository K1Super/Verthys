/*
 * 开发填充配置命令：状态、读取、保存、清空。
 *
 * 这些命令只服务开发悬浮球；发布构建直接拒绝，前端开发入口也不会进入产物。
 */

use std::path::PathBuf;

use tauri::Manager;

use crate::devfixture::{
    clear_profile, load_profile, save_profile, status, DevFixtureProfile, DevFixtureProfileView,
    DevFixtureSaveOutcome, DevFixtureStatus,
};

fn ensure_debug() -> Result<(), String> {
    if cfg!(debug_assertions) {
        Ok(())
    } else {
        Err("填充工具仅在开发构建可用".to_string())
    }
}

fn config_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map_err(|e| format!("解析应用配置目录失败: {e}"))
}

#[tauri::command]
pub fn devfixture_status(app: tauri::AppHandle) -> Result<DevFixtureStatus, String> {
    ensure_debug()?;
    Ok(status(&config_dir(&app)?))
}

#[tauri::command]
pub fn devfixture_profile_get(app: tauri::AppHandle) -> Result<DevFixtureProfileView, String> {
    ensure_debug()?;
    load_profile(&config_dir(&app)?)
}

#[tauri::command]
pub fn devfixture_profile_save(
    app: tauri::AppHandle,
    profile: DevFixtureProfile,
) -> Result<DevFixtureSaveOutcome, String> {
    ensure_debug()?;
    save_profile(&config_dir(&app)?, profile)
}

#[tauri::command]
pub fn devfixture_profile_clear(app: tauri::AppHandle) -> Result<bool, String> {
    ensure_debug()?;
    clear_profile(&config_dir(&app)?)
}
