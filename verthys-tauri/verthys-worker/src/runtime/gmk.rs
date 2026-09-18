/* gmk.rs — GMK 全局主密钥状态 + 派生命令
 *
 * 职责：
 *   - GMK thread_local 内存持有（Zeroizing 自动清零）
 *   - VERIFIER_PLAIN / VERIFIER_AD / MODULE_INFO_PREFIX 常量
 *   - handle_derive_global_key / handle_verify_global_key
 *     / handle_derive_module_subkey / handle_clear_global_key
 *
 * 依赖：std::cell::RefCell、zeroize、protocol（Request/Response/base64）。
 * 被引用方：dispatch.rs（handle_*）、worker.rs（GMK，Drop 时清零）。
 */

use std::cell::RefCell;
use zeroize::Zeroize;

use super::protocol::{Request, Response, base64_encode, base64_decode};

/* ------------------------------------------------------------------ *
 * GMK 全局主密钥状态（会话级，worker 内存中持有）                     *
 *                                                                    *
 * 设计：                                                             *
 *   - GMK 永不出 worker 子进程                                       *
 *   - 前端通过 IPC 请求派生子密钥                                    *
 *   - worker 退出（Drop）或 clear_global_key 时自动清零              *
 * ------------------------------------------------------------------ */

/// 验证器明文常量（32 字节，AES-GCM 加密后 = 48 字节含 tag）
/// v2：品牌重塑（ValtCore→Verthys，8→7 字符）后以版本号+尾下划线补齐定长 32 字节
const VERIFIER_PLAIN: &[u8; 32] = b"VERTHYS_GLOBAL_KEY_VERIFIER_v2__";
/// 验证器 AES-GCM 附加数据
#[allow(dead_code)]
const VERIFIER_AD: &[u8] = b"VERTHYS_GLOBAL_VERIFIER_v1";
/// 模块子密钥 HKDF info 前缀
const MODULE_INFO_PREFIX: &str = "verthys/module/";

thread_local! {
    /// GMK 内存持有（Zeroizing 保证清零）
    pub(crate) static GMK: RefCell<Option<zeroize::Zeroizing<[u8; 32]>>> = RefCell::new(None);
}

/* ------------------------------------------------------------------ *
 * GMK 派生命令（#2 敏感操作下沉）                                      *
 *                                                                    *
 * 所有密钥派生在 worker 子进程内完成，主进程/前端仅传递参数            *
 * GMK 永远不出 worker，前端通过 derive_module_subkey 获取子密钥        *
 * ------------------------------------------------------------------ */

/// 派生全局主密钥 GMK（首次设置）
/// 输入：password + bin_data + bin_password
/// 输出：record(base64) = salt(32) + nonce(12) + verifierCt(48) + binHash(32)
/// 副作用：GMK 存入 thread_local 内存
pub(crate) fn handle_derive_global_key(req: &Request) -> Response {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use hkdf::Hkdf;
    use pbkdf2::pbkdf2_hmac;
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    let bin_data = match base64_decode(&req.bin_data) {
        Ok(d) => d,
        Err(_) => {
            return Response {
                ok: false,
                op: "derive_global_key".into(),
                error: Some("base64 decode bin_data failed".into()),
                ..Response::ok("derive_global_key")
            }
        }
    };

    // 1. binMaterial = SHA-256(bin_data)
    let bin_material = Sha256::digest(&bin_data);

    // 2. binPasswordKey = PBKDF2(bin_password, salt=bin_material[:16], 150000)
    let mut bin_password_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        req.bin_password.as_bytes(),
        &bin_material[..16],
        150_000,
        &mut bin_password_key,
    );

    // 3. binKey = HKDF-Extract(salt=bin_material, IKM=bin_password_key)
    let bin_key = Hkdf::<Sha256>::extract(Some(&bin_material), &bin_password_key);

    // 4. globalSalt = random(32)
    let mut global_salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut global_salt);

    // 5. IKM = password || binKey
    let pw_bytes = req.password.as_bytes();
    let mut ikm = Vec::with_capacity(pw_bytes.len() + bin_key.0.len());
    ikm.extend_from_slice(pw_bytes);
    ikm.extend_from_slice(&bin_key.0);

    // 6. GMK = HKDF-Extract(salt=global_salt, IKM=password||binKey)
    let gmk = Hkdf::<Sha256>::extract(Some(&global_salt), &ikm);

    // 7. verifier: AES-GCM encrypt known constant
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&gmk.0));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let verifier_ct = match cipher.encrypt(nonce, VERIFIER_PLAIN.as_ref()) {
        Ok(c) => c,
        Err(_) => {
            bin_password_key.zeroize();
            ikm.zeroize();
            return Response {
                ok: false,
                op: "derive_global_key".into(),
                error: Some("AES-GCM encrypt verifier failed".into()),
                ..Response::ok("derive_global_key")
            };
        }
    };

    // 8. binFileHash = SHA-256(bin_data)
    let bin_file_hash = Sha256::digest(&bin_data);

    // 9. 序列化 record: salt(32) + nonce(12) + verifierCt(48) + binHash(32) = 124B
    let mut record = Vec::with_capacity(32 + 12 + 48 + 32);
    record.extend_from_slice(&global_salt);
    record.extend_from_slice(&nonce_bytes);
    record.extend_from_slice(&verifier_ct);
    record.extend_from_slice(&bin_file_hash);

    // 10. 内存持有 GMK（Zeroizing 包装，Drop 时自动清零）
    let mut gmk_arr = [0u8; 32];
    gmk_arr.copy_from_slice(&gmk.0);
    GMK.with(|g| *g.borrow_mut() = Some(zeroize::Zeroizing::new(gmk_arr)));

    // 11. 清零临时敏感变量
    bin_password_key.zeroize();
    ikm.zeroize();

    Response {
        data: Some(base64_encode(&record)),
        ..Response::ok("derive_global_key")
    }
}

/// 验证全局密钥（后续进入时）
/// 输入：password + bin_data + bin_password + record(base64)
/// 输出：ok=true 验证成功，GMK 存入内存
pub(crate) fn handle_verify_global_key(req: &Request) -> Response {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use hkdf::Hkdf;
    use pbkdf2::pbkdf2_hmac;
    use sha2::{Digest, Sha256};

    let bin_data = match base64_decode(&req.bin_data) {
        Ok(d) => d,
        Err(_) => {
            return Response {
                ok: false,
                op: "verify_global_key".into(),
                error: Some("base64 decode bin_data failed".into()),
                ..Response::ok("verify_global_key")
            }
        }
    };
    let record = match base64_decode(&req.data) {
        Ok(d) => d,
        Err(_) => {
            return Response {
                ok: false,
                op: "verify_global_key".into(),
                error: Some("base64 decode record failed".into()),
                ..Response::ok("verify_global_key")
            }
        }
    };

    // 1. 解析 record: salt(32) + nonce(12) + verifierCt(48) + binHash(32) = 124B
    if record.len() != 124 {
        return Response::err("verify_global_key", 0x02); // AUTH 错误
    }
    let global_salt = &record[..32];
    let verifier_nonce = &record[32..44];
    let verifier_ct = &record[44..92];
    let bin_file_hash = &record[92..124];

    // 2. 校验 binFileHash
    let computed_hash = Sha256::digest(&bin_data);
    if computed_hash.as_slice() != bin_file_hash {
        return Response::err("verify_global_key", 0x02);
    }

    // 3. 派生 binKey + GMK
    let bin_material = Sha256::digest(&bin_data);
    let mut bin_password_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        req.bin_password.as_bytes(),
        &bin_material[..16],
        150_000,
        &mut bin_password_key,
    );
    let bin_key = Hkdf::<Sha256>::extract(Some(&bin_material), &bin_password_key);

    let pw_bytes = req.password.as_bytes();
    let mut ikm = Vec::with_capacity(pw_bytes.len() + bin_key.0.len());
    ikm.extend_from_slice(pw_bytes);
    ikm.extend_from_slice(&bin_key.0);

    let gmk = Hkdf::<Sha256>::extract(Some(global_salt), &ikm);

    // 4. 解密 verifier
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&gmk.0));
    let nonce = Nonce::from_slice(verifier_nonce);
    match cipher.decrypt(nonce, verifier_ct) {
        Ok(plain) => {
            if plain != VERIFIER_PLAIN.as_ref() {
                bin_password_key.zeroize();
                ikm.zeroize();
                return Response::err("verify_global_key", 0x02);
            }
        }
        Err(_) => {
            bin_password_key.zeroize();
            ikm.zeroize();
            return Response::err("verify_global_key", 0x02);
        }
    }

    // 5. 内存持有 GMK
    let mut gmk_arr = [0u8; 32];
    gmk_arr.copy_from_slice(&gmk.0);
    GMK.with(|g| *g.borrow_mut() = Some(zeroize::Zeroizing::new(gmk_arr)));

    // 6. 清零
    bin_password_key.zeroize();
    ikm.zeroize();

    Response::ok("verify_global_key")
}

/// 派生模块子密钥（HKDF-Expand）
/// 输入：module_id
/// 输出：subkey(base64, 32 字节)
pub(crate) fn handle_derive_module_subkey(req: &Request) -> Response {
    use hkdf::Hkdf;
    use sha2::Sha256;

    GMK.with(|g| {
        let gmk_ref = g.borrow();
        match gmk_ref.as_ref() {
            None => Response::err("derive_module_subkey", 0x07), // LOCKED
            Some(gmk) => {
                let info = format!("{}{}", MODULE_INFO_PREFIX, req.module_id);
                let hk = match Hkdf::<Sha256>::from_prk(&gmk[..]) {
                    Ok(h) => h,
                    Err(_) => {
                        return Response {
                            ok: false,
                            op: "derive_module_subkey".into(),
                            error: Some("HKDF from_prk failed".into()),
                            ..Response::ok("derive_module_subkey")
                        }
                    }
                };
                let mut okm = [0u8; 32];
                if hk.expand(info.as_bytes(), &mut okm).is_err() {
                    return Response {
                        ok: false,
                        op: "derive_module_subkey".into(),
                        error: Some("HKDF expand failed".into()),
                        ..Response::ok("derive_module_subkey")
                    };
                }
                Response {
                    data: Some(base64_encode(&okm)),
                    ..Response::ok("derive_module_subkey")
                }
            }
        }
    })
}

/// 清零 GMK 内存（lockAll 时调用）
pub(crate) fn handle_clear_global_key() -> Response {
    GMK.with(|g| *g.borrow_mut() = None);
    Response::ok("clear_global_key")
}
