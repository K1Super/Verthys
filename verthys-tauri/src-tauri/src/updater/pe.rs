/*
 * updater/pe.rs — 安装包 PE 版本身份读取
 *
 * 清单的 version 字段本身不受签名保护，攻击者可以把旧签名包配上更高版本号。
 * 安装包的 PE 版本资源包含在签名覆盖的字节内，因此读取 FileVersion 并与清单
 * 比对，才能阻断“清单说新装旧”的重放。
 */

use super::UpdaterError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use uuid::Uuid;
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
};

struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// 从安装包字节读取 PE FileVersion，返回 `MAJOR.MINOR.PATCH`。
pub fn file_version_from_bytes(bytes: &[u8]) -> Result<String, UpdaterError> {
    let path = std::env::temp_dir().join(format!("verthys-pe-{}.exe", Uuid::new_v4()));
    std::fs::write(&path, bytes).map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_PE_VERSION_MISMATCH",
            format!("无法写入版本探测临时文件: {error}"),
            false,
        )
    })?;
    let _guard = TempFile(path.clone());
    read_file_version(&path)
}

fn read_file_version(path: &std::path::Path) -> Result<String, UpdaterError> {
    let wide: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut handle = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), Some(&mut handle)) };
    if size == 0 {
        return Err(UpdaterError::new(
            "E_UPDATER_PE_VERSION_MISMATCH",
            "安装包缺少 PE 版本资源",
            false,
        ));
    }

    let mut data = vec![0u8; size as usize];
    unsafe {
        GetFileVersionInfoW(
            PCWSTR(wide.as_ptr()),
            handle,
            size,
            data.as_mut_ptr() as *mut core::ffi::c_void,
        )
    }
    .map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_PE_VERSION_MISMATCH",
            format!("读取 PE 版本资源失败: {error}"),
            false,
        )
    })?;

    let root: Vec<u16> = OsStr::new("\\")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut buffer: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut length = 0u32;
    let ok = unsafe {
        VerQueryValueW(
            data.as_ptr() as *const core::ffi::c_void,
            PCWSTR(root.as_ptr()),
            &mut buffer,
            &mut length,
        )
    };
    if !ok.as_bool() || buffer.is_null() || length < std::mem::size_of::<VS_FIXEDFILEINFO>() as u32
    {
        return Err(UpdaterError::new(
            "E_UPDATER_PE_VERSION_MISMATCH",
            "PE 版本资源结构非法",
            false,
        ));
    }

    let info = unsafe { &*(buffer as *const VS_FIXEDFILEINFO) };
    if info.dwSignature != 0xFEEF04BD {
        return Err(UpdaterError::new(
            "E_UPDATER_PE_VERSION_MISMATCH",
            "PE 版本资源签名非法",
            false,
        ));
    }
    let major = (info.dwFileVersionMS >> 16) as u16;
    let minor = (info.dwFileVersionMS & 0xFFFF) as u16;
    let patch = (info.dwFileVersionLS >> 16) as u16;
    Ok(format!("{major}.{minor}.{patch}"))
}

#[cfg(test)]
mod tests {
    use super::file_version_from_bytes;
    use std::path::Path;

    #[test]
    fn reads_real_installer_version_when_artifact_exists() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let manifest_path = root.join("build/updater/latest.json");
        if !manifest_path.exists() {
            return;
        }
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let platform = &manifest["platforms"]["windows-x86_64"];
        let file_name = platform["url"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        let installer = manifest_path.parent().unwrap().join(file_name);
        if !installer.exists() {
            return;
        }
        let bytes = std::fs::read(installer).unwrap();
        assert_eq!(
            file_version_from_bytes(&bytes).unwrap(),
            platform["file_version"].as_str().unwrap()
        );
    }
}
