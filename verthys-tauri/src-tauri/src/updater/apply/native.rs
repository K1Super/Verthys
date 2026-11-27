/*
 * updater/native.rs — WebView 不可用时的原生兜底
 *
 * 健康自检失败后，如果前端没有加载出来，用户不能被留在一个没有恢复入口的
 * 应用里。这里用系统对话框提供最小路径：运行修复，或打开日志并退出。
 */

use super::log;
use super::marker;
use super::repair;
use crate::state::AppState;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use tauri::{AppHandle, Manager};
use windows::core::PCWSTR;
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_YESNO,
};

/// 前端未触发自检时的原生入口：先询问是否现在执行，再按结果进入修复。
pub fn prompt_pending(app: &AppHandle) {
    let result = unsafe {
        MessageBoxW(
            None,
            PCWSTR(
                wide("新版本尚未完成健康自检。\n\n是：现在运行自检\n否：打开更新日志并退出")
                    .as_ptr(),
            ),
            PCWSTR(wide("Verthys 更新").as_ptr()),
            MB_YESNO | MB_ICONWARNING,
        )
    };
    if result == IDYES {
        let confirmed = tauri::async_runtime::block_on(super::health::run(app))
            .is_ok_and(|report| report.verdict == "health_confirmed");
        if confirmed {
            unsafe {
                MessageBoxW(
                    None,
                    PCWSTR(wide("健康自检通过，应用将重新启动。").as_ptr()),
                    PCWSTR(wide("Verthys 更新").as_ptr()),
                    MB_OK | MB_ICONINFORMATION,
                );
            }
            // 原生路径启动的 worker 不在前端缓存内；退出重启可避免后续解锁复用失败。
            shutdown(app);
            return;
        }
        prompt_failure(app);
        return;
    }
    open_logs(app);
    shutdown(app);
}

/// 弹出原生修复入口；调用方应在阻塞线程中运行。
pub fn prompt_failure(app: &AppHandle) {
    let view = repair::view(app);
    let can_repair = view.available;
    let text = if can_repair {
        "新版本健康自检未通过。\n\n是：运行修复\n否：打开更新日志并退出"
    } else {
        "新版本健康自检未通过，且未找到可用的旧版安装包。\n\n确定后将打开更新日志并退出。"
    };
    let result = unsafe {
        MessageBoxW(
            None,
            PCWSTR(wide(text).as_ptr()),
            PCWSTR(wide("Verthys 更新").as_ptr()),
            if can_repair {
                MB_YESNO | MB_ICONWARNING
            } else {
                MB_OK | MB_ICONWARNING
            },
        )
    };

    if can_repair && result == IDYES {
        if let Err(error) = repair::run(app) {
            log::append(
                app,
                "repair_failed",
                "Repair",
                Some(&error.code),
                "error",
                serde_json::json!({ "stage": "native_prompt" }),
            );
            open_logs(app);
            shutdown(app);
        }
        return;
    }

    open_logs(app);
    shutdown(app);
}

/// 打开更新日志目录；失败时保持进程，让用户自行定位应用数据目录。
pub fn open_logs(app: &AppHandle) {
    if let Ok(dir) = marker::updater_dir(app) {
        let _ = std::process::Command::new("explorer.exe")
            .arg(dir.join("logs"))
            .spawn();
    }
}

fn shutdown(app: &AppHandle) {
    app.state::<AppState>().set_session(None);
    std::process::exit(0);
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
