/*
 * security_service.rs — P2 安全服务只读状态
 *
 * 服务由 perMachine 应用安装器在同一提权流程内随应用安装，应用运行时
 * 不再执行任何安装器或用户可写二进制。这里只读取 HKLM 锚点用于启动
 * fail-closed 判定。
 */

use serde::Serialize;
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    REG_DWORD, REG_VALUE_TYPE,
};

const SERVICE_KEY: &str = r"SOFTWARE\Verthys\SecurityService";
const SERVICE_INSTALLED_VALUE: &str = "Installed";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityServiceStatus {
    pub installed: bool,
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 只读检查服务安装状态。读取失败一律视为未安装（fail-closed）。
fn service_installed() -> bool {
    let key_path = wide(SERVICE_KEY);
    let value_name = wide(SERVICE_INSTALLED_VALUE);
    let mut key = HKEY::default();
    let open = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(key_path.as_ptr()),
            0,
            KEY_READ,
            &mut key,
        )
    };
    if open.is_err() {
        return false;
    }

    let mut value_type = REG_VALUE_TYPE::default();
    let mut value: u32 = 0;
    let mut value_size = std::mem::size_of::<u32>() as u32;
    let read = unsafe {
        RegQueryValueExW(
            key,
            PCWSTR::from_raw(value_name.as_ptr()),
            None,
            Some(&mut value_type),
            Some(&mut value as *mut u32 as *mut u8),
            Some(&mut value_size),
        )
    };
    unsafe {
        let _ = RegCloseKey(key);
    }
    read.is_ok() && value_type == REG_DWORD && value == 1
}

#[tauri::command]
pub async fn security_service_status() -> Result<SecurityServiceStatus, String> {
    Ok(SecurityServiceStatus {
        installed: service_installed(),
    })
}
