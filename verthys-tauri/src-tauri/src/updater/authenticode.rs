/*
 * updater/authenticode.rs — 安装包 Authenticode 验证
 *
 * Windows 信任层与 minisign 是两条独立信任根：minisign 证明字节来自发布者，
 * Authenticode 证明 Windows 证书链、时间戳与吊销状态有效。安装包在准备阶段
 * 写入受控临时文件后交给 WinVerifyTrust，验证完立即删除，不跨阶段保留。
 *
 * 生产渠道强制开启；本机渠道允许关闭，以便未做系统签名的开发物料仍可验证
 * 更新链路。主体与指纹为可选钉扎，未配置时只要求系统信任链通过。
 */

use super::manifest::AuthenticodeConfig;
use super::UpdaterError;

/// 签名者身份，用于可选的主体 / 指纹钉扎与日志摘要。
#[derive(Debug, Clone)]
pub struct SignerIdentity {
    pub subject: String,
    pub thumbprint: String,
}

fn invalid(message: impl Into<String>) -> UpdaterError {
    UpdaterError::new("E_UPDATER_AUTHENTICODE_INVALID", message, false)
}

/// 验证字节的 Authenticode 签名；未要求验证时返回 `None`。
///
/// 写入临时文件是 WinVerifyTrust 的文件级接口要求。路径使用随机标识且只落在
/// 系统临时目录，验证结束后无论成功失败都删除，避免残留可执行副本。
pub fn verify_bytes(
    app: &tauri::AppHandle,
    bytes: &[u8],
    config: &AuthenticodeConfig,
) -> Result<Option<SignerIdentity>, UpdaterError> {
    if !config.require {
        return Ok(None);
    }
    use tauri::Manager;

    let dir = app
        .path()
        .temp_dir()
        .map_err(|error| invalid(format!("无法解析临时目录: {error}")))?;
    std::fs::create_dir_all(&dir).map_err(|error| invalid(format!("无法创建临时目录: {error}")))?;
    let path = dir.join(format!("updater-auth-{}.exe", uuid::Uuid::new_v4()));
    std::fs::write(&path, bytes).map_err(|error| invalid(format!("无法写入验证副本: {error}")))?;
    let result = verify_file(&path, config);
    let _ = std::fs::remove_file(&path);
    result.map(Some)
}

/// 验证文件签名并返回签名者身份。
#[cfg(target_os = "windows")]
pub fn verify_file(
    path: &std::path::Path,
    config: &AuthenticodeConfig,
) -> Result<SignerIdentity, UpdaterError> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{BOOL, HWND};
    use windows::Win32::Security::Cryptography::{
        CertGetCertificateContextProperty, CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_SHA1_HASH_PROP_ID,
    };
    use windows::Win32::Security::WinTrust::{
        WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
        WTHelperProvDataFromStateData, WinVerifyTrustEx, WINTRUST_ACTION_GENERIC_VERIFY_V2,
        WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_REVOKE_WHOLECHAIN,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: Default::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: if config.revocation {
            WTD_REVOKE_WHOLECHAIN
        } else {
            WTD_REVOKE_NONE
        },
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    // WINTRUST_DATA 的文件分支在本函数栈上有效，调用期间不会被移动。
    data.Anonymous.pFile = &mut file_info;

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: 参数均指向本函数持有的有效结构；WinVerifyTrust 同步执行。
    let status = unsafe { WinVerifyTrustEx(HWND::default(), &mut action, &mut data) };

    let identity = if status == 0 {
        // SAFETY: 状态数据由 WinVerifyTrust 填充，辅助函数返回的指针在关闭状态前有效。
        unsafe {
            let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
            let signer = if provider.is_null() {
                std::ptr::null_mut()
            } else {
                WTHelperGetProvSignerFromChain(provider, 0, BOOL(0), 0)
            };
            let provider_cert = if signer.is_null() {
                std::ptr::null_mut()
            } else {
                WTHelperGetProvCertFromChain(signer, 0)
            };
            if provider_cert.is_null() || (*provider_cert).pCert.is_null() {
                Err(invalid("签名状态缺少证书上下文"))
            } else {
                let cert = (*provider_cert).pCert;
                let mut name = [0u16; 512];
                let name_len = CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    None,
                    Some(&mut name),
                );
                if name_len <= 1 {
                    Err(invalid("无法读取证书主体"))
                } else {
                    let subject = String::from_utf16_lossy(&name[..name_len as usize - 1]);
                    let mut size = 0u32;
                    let _ = CertGetCertificateContextProperty(
                        cert,
                        CERT_SHA1_HASH_PROP_ID,
                        None,
                        &mut size,
                    );
                    let mut digest = vec![0u8; size as usize];
                    if size == 0
                        || CertGetCertificateContextProperty(
                            cert,
                            CERT_SHA1_HASH_PROP_ID,
                            Some(digest.as_mut_ptr() as *mut c_void),
                            &mut size,
                        )
                        .is_err()
                    {
                        Err(invalid("无法读取证书指纹"))
                    } else {
                        let thumbprint = digest
                            .iter()
                            .map(|byte| format!("{byte:02X}"))
                            .collect::<String>();
                        Ok(SignerIdentity {
                            subject,
                            thumbprint,
                        })
                    }
                }
            }
        }
    } else {
        Err(invalid(format!(
            "系统签名验证未通过（状态 0x{status:08X}）"
        )))
    };

    // SAFETY: 必须与 VERIFY 配对关闭，释放 WinTrust 状态数据。
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrustEx(HWND::default(), &mut action, &mut data);
    }

    let identity = identity?;
    if let Some(expected) = &config.subject {
        if normalize_subject(&identity.subject) != normalize_subject(expected) {
            return Err(invalid("证书主体与配置不一致"));
        }
    }
    if let Some(expected) = &config.thumbprint {
        if &identity.thumbprint != expected {
            return Err(invalid("证书指纹与配置不一致"));
        }
    }
    Ok(identity)
}

/// 非 Windows 平台无法验证 Authenticode；要求验证时直接拒绝。
#[cfg(not(target_os = "windows"))]
pub fn verify_file(
    _path: &std::path::Path,
    _config: &AuthenticodeConfig,
) -> Result<SignerIdentity, UpdaterError> {
    Err(invalid("当前平台不支持 Authenticode"))
}

/// 主体比较忽略大小写与常见的前缀写法，避免配置格式差异导致误拒。
fn normalize_subject(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("CN=")
        .trim_matches('"')
        .trim()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{normalize_subject, verify_file};
    use crate::updater::manifest::AuthenticodeConfig;

    #[test]
    fn subject_comparison_ignores_prefix_and_case() {
        assert_eq!(normalize_subject("CN=Verthys"), "verthys");
        assert_eq!(normalize_subject(" verthys "), "verthys");
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "需要 VERTHYS_AUTH_TEST_FILE 指向已签名的测试可执行文件"]
    fn verifies_signed_fixture_and_extracts_identity() {
        let path = std::env::var("VERTHYS_AUTH_TEST_FILE")
            .expect("必须通过 VERTHYS_AUTH_TEST_FILE 提供签名文件");
        let identity = verify_file(
            std::path::Path::new(&path),
            &AuthenticodeConfig {
                require: true,
                revocation: false,
                subject: None,
                thumbprint: None,
            },
        )
        .expect("签名文件应通过验证");
        assert!(!identity.subject.is_empty());
        assert_eq!(identity.thumbprint.len(), 40);
        if let Ok(expected) = std::env::var("VERTHYS_AUTH_EXPECT_THUMBPRINT") {
            assert_eq!(identity.thumbprint, expected.trim().to_ascii_uppercase());
        }
        if let Ok(expected) = std::env::var("VERTHYS_AUTH_EXPECT_SUBJECT") {
            assert_eq!(
                normalize_subject(&identity.subject),
                normalize_subject(&expected)
            );
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "需要 VERTHYS_AUTH_TAMPERED_FILE 指向签名被破坏的副本"]
    fn rejects_tampered_fixture() {
        let path = std::env::var("VERTHYS_AUTH_TAMPERED_FILE")
            .expect("必须通过 VERTHYS_AUTH_TAMPERED_FILE 提供篡改文件");
        let result = verify_file(
            std::path::Path::new(&path),
            &AuthenticodeConfig {
                require: true,
                revocation: false,
                subject: None,
                thumbprint: None,
            },
        );
        assert!(result.is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn rejects_unsigned_file() {
        let windows_dir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let unsigned = std::path::Path::new(&windows_dir).join("win.ini");
        let result = verify_file(
            &unsigned,
            &AuthenticodeConfig {
                require: true,
                revocation: false,
                subject: None,
                thumbprint: None,
            },
        );
        assert!(result.is_err());
    }
}
