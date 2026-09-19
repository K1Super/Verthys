/*
 * util/crypto.rs — 密码学工具模块
 *
 *
 *
 * 架构定位：工具层（util）密码学纯函数模块
 *   - 不依赖任何上层模块（controller / service / repository）
 *   - 不输出日志（密码学操作不泄露任何信息到日志）
 *   - 所有密钥/明文参数通过引用传入，调用方负责 Zeroize
 *
 * PBKDF2 派生密钥：
 *   pbkdf2_derive 从设备指纹 + 盐值派生密钥，用于状态文件加密绑定。
 *
 * HMAC-SHA256 防篡改：
 *   hmac_sign / hmac_verify 用于状态文件、审计日志的完整性保护。
 *
 * DPAPI 密封：
 *   dpapi_protect / dpapi_unprotect 使用 Windows DPAPI 加密敏感数据，
 *   绑定本机本用户（离机失效）。
 *
 * 常量时间比较：
 *   ct_eq 使用 subtle crate 进行常量时间比较，防时序攻击。
 *
 * CI 红线：
 *   - 本文件不得包含任何 println!/eprintln!/log::* 调用
 *   - 密钥/明文不得以任何形式泄露到日志或错误消息
 *   - 所有密码学原语使用社区审计的标准 crate（hmac/pbkdf2/sha2/subtle）
 *   - 不得自实现密码学算法
 */

use sha2::Sha256;

// ===== 常量时间比较 =====

/// 常量时间比较两个字节切片
///
/// 使用 subtle crate 确保比较时间与输入内容无关，防时序攻击。
/// 用于密码/HMAC/令牌校验场景。
///
/// 返回：
///   - true: 两切片内容与长度均相同
///   - false: 长度不同或内容不同（不区分以避免长度泄露）
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

// ===== HMAC-SHA256 =====

/// HMAC-SHA256 签名
///
/// 使用 hmac crate 计算 message 的 HMAC-SHA256 标签。
/// 用于状态文件、审计日志的完整性保护。
///
/// 参数：
///   - key: HMAC 密钥（通常为 PBKDF2 派生的设备指纹密钥）
///   - message: 待签名的消息
///
/// 返回：32 字节 HMAC 标签
pub fn hmac_sign(key: &[u8], message: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length error");
    mac.update(message);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// HMAC-SHA256 验证（常量时间比较）
///
/// 验证 message 的 HMAC 标签是否与 expected_tag 匹配。
/// 使用常量时间比较，防时序攻击。
///
/// 参数：
///   - key: HMAC 密钥
///   - message: 原始消息
///   - expected_tag: 预期的 HMAC 标签（32 字节）
///
/// 返回：
///   - true: 验证通过
///   - false: 验证失败（密钥错误/消息篡改/标签不匹配）
pub fn hmac_verify(key: &[u8], message: &[u8], expected_tag: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(message);
    mac.verify_slice(expected_tag).is_ok()
}

// ===== PBKDF2 派生密钥 =====

/// PBKDF2 迭代次数（满足当前安全强度要求）
///
/// NIST SP 800-132 建议 ≥ 10000 次，此处使用 100000 次提供更高安全余量。
/// 性能影响：在典型 CPU 上 100000 次 SHA-256 约 50-100ms，可接受。
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// PBKDF2 输出密钥长度（32 字节 = 256 位，用于 HMAC/AES-256）
pub const PBKDF2_KEY_LEN: usize = 32;

/// PBKDF2-SHA256 派生密钥
///
/// 从密码/指纹 + 盐值派生固定长度密钥。
/// 用于：
///   - 设备指纹派生密钥（加密状态文件中的验证令牌）
///   - 状态文件 HMAC 密钥派生
///
/// 参数：
///   - password: 密码/设备指纹（原始字节）
///   - salt: 盐值（建议 16 字节，每次派生唯一）
///   - iterations: 迭代次数（默认 100000）
///
/// 返回：32 字节派生密钥
pub fn pbkdf2_derive(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; PBKDF2_KEY_LEN], String> {
    let mut key = [0u8; PBKDF2_KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
    Ok(key)
}

/// 便捷函数：使用默认迭代次数派生密钥
pub fn pbkdf2_derive_default(
    password: &[u8],
    salt: &[u8],
) -> Result<[u8; PBKDF2_KEY_LEN], String> {
    pbkdf2_derive(password, salt, PBKDF2_ITERATIONS)
}

// ===== Windows DPAPI 密封 =====

// windows-rs 0.58 未导出 LocalFree（仅导出 LocalSize/LocalAlloc 等），
// DPAPI 使用 LocalAlloc 分配输出缓冲区，需用 LocalFree 释放。
// 通过 extern "system" 声明直接链接 kernel32，与 security/file_lock.rs 同模式。
#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(h_mem: isize) -> isize;
}

/// 释放 DPAPI 分配的内存（LocalFree 包装）
///
/// 安全性：仅释放指针，不读取内存内容。
/// 传入空指针时 LocalFree 返回 0（无操作），无需额外空检查。
#[cfg(windows)]
unsafe fn local_free(ptr: isize) {
    let _ = LocalFree(ptr);
}

/// Windows DPAPI 加密（CryptProtectData）
///
/// 使用 Windows Data Protection API 加密数据，绑定本机本用户。
/// 离机或换用户后无法解密，适用于：
///   - 状态文件敏感字段加密
///   - BruteForceGuard 状态持久化
///   - 路径指针映射表加密
///
/// 参数：
///   - plaintext: 待加密的明文
///   - description: 描述信息（可选，用于审计，不加密）
///
/// 返回：加密后的密文（字节）
///
/// 失败：DPAPI 调用失败返回 Err
#[cfg(windows)]
pub fn dpapi_protect(plaintext: &[u8], description: Option<&str>) -> Result<Vec<u8>, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPT_INTEGER_BLOB,
    };

    // windows-rs 0.58 未导出 DATA_BLOB，使用 CRYPT_INTEGER_BLOB（同构别名）
    // in_blob 以不可变引用传给 CryptProtectData，无需 mut
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };

    let desc_wide: Vec<u16> = if let Some(desc) = description {
        desc.encode_utf16().chain(std::iter::once(0u16)).collect()
    } else {
        vec![0u16]
    };
    let desc_ptr = if description.is_some() {
        PCWSTR(desc_wide.as_ptr())
    } else {
        PCWSTR::null()
    };

    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    unsafe {
        CryptProtectData(
            &in_blob,
            desc_ptr,
            None,
            None,
            None,
            0,
            &mut out_blob,
        )
        .map_err(|e| format!("CryptProtectData failed: {}", e))?;
    }

    // 复制加密数据到 Vec
    let ciphertext = unsafe {
        std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
    };

    // 释放 DPAPI 分配的内存
    // DPAPI 使用 LocalAlloc 分配内存，需用 LocalFree 释放
    // windows-rs 0.58 未导出 LocalFree/HLOCAL，通过 extern 声明调用
    unsafe {
        local_free(out_blob.pbData as isize);
    }

    Ok(ciphertext)
}

#[cfg(not(windows))]
pub fn dpapi_protect(_plaintext: &[u8], _description: Option<&str>) -> Result<Vec<u8>, String> {
    Err("DPAPI not available on non-Windows platforms".into())
}

/// Windows DPAPI 解密（CryptUnprotectData）
///
/// 解密由 dpapi_protect 加密的数据。
/// 仅在本机本用户环境下可解密。
///
/// 参数：
///   - ciphertext: 加密后的密文
///
/// 返回：解密后的明文（字节）
#[cfg(windows)]
pub fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };

    // in_blob 以不可变引用传给 CryptUnprotectData，无需 mut
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };

    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    unsafe {
        CryptUnprotectData(
            &in_blob,
            None,
            None,
            None,
            None,
            0,
            &mut out_blob,
        )
        .map_err(|e| format!("CryptUnprotectData failed: {}", e))?;
    }

    // 复制解密数据到 Vec
    let plaintext = unsafe {
        std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
    };

    // 释放 DPAPI 分配的内存
    // windows-rs 0.58 未导出 LocalFree/HLOCAL，通过 extern 声明调用
    unsafe {
        local_free(out_blob.pbData as isize);
    }

    Ok(plaintext)
}

#[cfg(not(windows))]
pub fn dpapi_unprotect(_ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI not available on non-Windows platforms".into())
}

// ===== 便捷函数：DPAPI + HMAC 组合密封 =====

/// DPAPI 加密 + HMAC 防篡改组合密封
///
/// 流程：
///   1. 用 DPAPI 加密 plaintext → ciphertext
///   2. 用 hmac_key 计算 ciphertext 的 HMAC 标签
///   3. 返回 (ciphertext, tag)
///
/// 解封时先验 HMAC 再 DPAPI 解密，防篡改。
/// 用于状态文件、审计日志的完整性与机密性双重保护。
pub fn seal(plaintext: &[u8], hmac_key: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
    let ciphertext = dpapi_protect(plaintext, Some("Verthys sealed data"))?;
    let tag = hmac_sign(hmac_key, &ciphertext);
    Ok((ciphertext, tag))
}

/// DPAPI 解密 + HMAC 验证组合解封
///
/// 流程：
///   1. 用 hmac_key 验证 ciphertext 的 HMAC 标签
///   2. 验证通过 → DPAPI 解密 ciphertext → plaintext
///   3. 任一失败返回 Err
pub fn unseal(ciphertext: &[u8], hmac_key: &[u8], expected_tag: &[u8]) -> Result<Vec<u8>, String> {
    if !hmac_verify(hmac_key, ciphertext, expected_tag) {
        return Err("HMAC verification failed: data may be tampered".into());
    }
    dpapi_unprotect(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq() {
        assert!(ct_eq(b"hello", b"hello"));
        assert!(!ct_eq(b"hello", b"world"));
        assert!(!ct_eq(b"hello", b"helloo"));
        assert!(!ct_eq(b"", b"hello"));
    }

    #[test]
    fn test_hmac_sign_verify() {
        let key = b"test_key_1234567890";
        let msg = b"test message";
        let tag = hmac_sign(key, msg);
        assert_eq!(tag.len(), 32);
        assert!(hmac_verify(key, msg, &tag));
        assert!(!hmac_verify(key, b"tampered", &tag));
        assert!(!hmac_verify(b"wrong_key", msg, &tag));
    }

    #[test]
    fn test_pbkdf2_derive() {
        let password = b"device_fingerprint_abc";
        let salt = b"random_salt_12345678";
        let key1 = pbkdf2_derive_default(password, salt).unwrap();
        let key2 = pbkdf2_derive_default(password, salt).unwrap();
        assert_eq!(key1, key2); // 相同输入派生相同密钥
        assert_eq!(key1.len(), PBKDF2_KEY_LEN);

        // 不同盐值派生不同密钥
        let key3 = pbkdf2_derive_default(password, b"different_salt").unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    #[cfg(windows)]
    fn test_dpapi_roundtrip() {
        let plaintext = b"sensitive data to protect";
        let ciphertext = dpapi_protect(plaintext, Some("test")).unwrap();
        assert_ne!(&plaintext[..], &ciphertext[..]);

        let decrypted = dpapi_unprotect(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    #[cfg(windows)]
    fn test_seal_unseal() {
        let plaintext = b"sealed secret data";
        let hmac_key = b"hmac_key_for_integrity";

        let (ciphertext, tag) = seal(plaintext, hmac_key).unwrap();
        let decrypted = unseal(&ciphertext, hmac_key, &tag).unwrap();
        assert_eq!(decrypted, plaintext);

        // 篡改密文应失败
        let mut tampered = ciphertext.clone();
        if !tampered.is_empty() {
            tampered[0] ^= 0xFF;
        }
        assert!(unseal(&tampered, hmac_key, &tag).is_err());
    }
}
