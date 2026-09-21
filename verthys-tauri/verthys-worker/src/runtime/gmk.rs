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
/// 以版本标识 + 尾下划线补齐定长 32 字节
const VERIFIER_PLAIN: &[u8; 32] = b"VERTHYS_GLOBAL_KEY_VERIFIER_v2__";
/// 验证器 AES-GCM 附加数据
#[allow(dead_code)]
const VERIFIER_AD: &[u8] = b"VERTHYS_GLOBAL_VERIFIER_v1";
/// 模块子密钥 HKDF info 前缀
const MODULE_INFO_PREFIX: &str = "verthys/module/";

thread_local! {
    /// GMK 内存持有（Zeroizing 保证清零）
    pub(crate) static GMK: RefCell<Option<zeroize::Zeroizing<[u8; 32]>>> = const { RefCell::new(None) };
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
    //    PRK 拷入 Zeroizing 后立即 volatile 清零 extract 输出缓冲
    let (mut bin_key_prk, _) = Hkdf::<Sha256>::extract(Some(&bin_material), &bin_password_key);
    let bin_key = zeroize::Zeroizing::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bin_key_prk[..]);
        arr
    });
    bin_key_prk[..].zeroize();

    // 4. globalSalt = random(32)
    let mut global_salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut global_salt);

    // 5. IKM = password || binKey
    let pw_bytes = req.password.as_bytes();
    let mut ikm = Vec::with_capacity(pw_bytes.len() + bin_key.len());
    ikm.extend_from_slice(pw_bytes);
    ikm.extend_from_slice(&bin_key[..]);

    // 6. GMK = HKDF-Extract(salt=global_salt, IKM=password||binKey)
    //    PRK 处理同 binKey：拷入 Zeroizing 后立即清零中间量
    let (mut gmk_prk, _) = Hkdf::<Sha256>::extract(Some(&global_salt), &ikm);
    let gmk = zeroize::Zeroizing::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&gmk_prk[..]);
        arr
    });
    gmk_prk[..].zeroize();

    // 7. verifier: AES-GCM encrypt known constant
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&gmk[..]));
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
    //     gmk_arr 被 move 进 Zeroizing，所有权转移无残留副本
    let mut gmk_arr = [0u8; 32];
    gmk_arr.copy_from_slice(&gmk[..]);
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
    // PRK 拷入 Zeroizing 后立即 volatile 清零 extract 输出缓冲
    let (mut bin_key_prk, _) = Hkdf::<Sha256>::extract(Some(&bin_material), &bin_password_key);
    let bin_key = zeroize::Zeroizing::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bin_key_prk[..]);
        arr
    });
    bin_key_prk[..].zeroize();

    let pw_bytes = req.password.as_bytes();
    let mut ikm = Vec::with_capacity(pw_bytes.len() + bin_key.len());
    ikm.extend_from_slice(pw_bytes);
    ikm.extend_from_slice(&bin_key[..]);

    // GMK 处理同 binKey：拷入 Zeroizing 后立即清零中间量
    let (mut gmk_prk, _) = Hkdf::<Sha256>::extract(Some(global_salt), &ikm);
    let gmk = zeroize::Zeroizing::new({
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&gmk_prk[..]);
        arr
    });
    gmk_prk[..].zeroize();

    // 4. 解密 verifier
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&gmk[..]));
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
    //    gmk_arr 被 move 进 Zeroizing，所有权转移无残留副本
    let mut gmk_arr = [0u8; 32];
    gmk_arr.copy_from_slice(&gmk[..]);
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
                // 子密钥 okm 为敏感中间量：Zeroizing 保证 base64 编码消费后
                // 响应构造完成即 volatile 清零，不驻留栈外可见副本
                let mut okm = zeroize::Zeroizing::new([0u8; 32]);
                if hk.expand(info.as_bytes(), &mut okm[..]).is_err() {
                    return Response {
                        ok: false,
                        op: "derive_module_subkey".into(),
                        error: Some("HKDF expand failed".into()),
                        ..Response::ok("derive_module_subkey")
                    };
                }
                Response {
                    data: Some(base64_encode(&okm[..])),
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

/* ------------------------------------------------------------------ *
 * 单元测试                                                            *
 *                                                                    *
 * GMK 为 thread_local：cargo test 每个测试独占线程，                *
 * 各测试间的 GMK 状态互不干扰。                                       *
 * ------------------------------------------------------------------ */

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    /// 构造派生/验证/子密钥测试请求（record 为 GMK 记录 base64）
    fn make_request(op: &str, password: &str, bin_password: &str, bin_data: &[u8], record: &str) -> Request {
        Request {
            op: op.to_string(),
            path: String::new(),
            password: Zeroizing::new(password.to_string()),
            id: 0,
            rtype: 0,
            name: String::new(),
            data: Zeroizing::new(record.to_string()),
            old_password: Zeroizing::new(String::new()),
            new_password: Zeroizing::new(String::new()),
            bin_data: Zeroizing::new(base64_encode(bin_data)),
            bin_password: Zeroizing::new(bin_password.to_string()),
            module_id: String::new(),
            preset: 0,
            ids: Vec::new(),
            flags: 0,
        }
    }

    #[test]
    fn test_derive_verify_roundtrip() {
        let bin_data = b"test bin file content 0123456789abcdef";
        let derive_req = make_request(
            "derive_global_key",
            "master-password-123",
            "bin-pass-456",
            bin_data,
            "",
        );
        let derive_resp = handle_derive_global_key(&derive_req);
        assert!(derive_resp.ok, "derive 应成功: {:?}", derive_resp.error);
        let record = derive_resp.data.expect("derive 应返回 record base64");
        assert_eq!(base64_decode(&record).unwrap().len(), 124);

        // 同参数验证必须通过（PRK 拷贝/清零重构后派生路径功能回归）
        let verify_req = make_request(
            "verify_global_key",
            "master-password-123",
            "bin-pass-456",
            bin_data,
            &record,
        );
        let verify_resp = handle_verify_global_key(&verify_req);
        assert!(verify_resp.ok, "同参数 verify 应通过: {:?}", verify_resp.error);

        // 派生后同线程 GMK 可用：子密钥为 32 字节
        let mut subkey_req = make_request("derive_module_subkey", "", "", b"", "");
        subkey_req.module_id = "photo-module".into();
        let subkey_resp = handle_derive_module_subkey(&subkey_req);
        assert!(subkey_resp.ok, "subkey 应成功: {:?}", subkey_resp.error);
        let subkey_b64 = subkey_resp.data.expect("subkey 应返回 base64");
        assert_eq!(base64_decode(&subkey_b64).unwrap().len(), 32);
    }

    #[test]
    fn test_verify_wrong_password_rejected() {
        let bin_data = b"another bin payload";
        let derive_req = make_request(
            "derive_global_key",
            "correct-horse-battery",
            "bin-pw",
            bin_data,
            "",
        );
        let derive_resp = handle_derive_global_key(&derive_req);
        assert!(derive_resp.ok);
        let record = derive_resp.data.unwrap();

        let verify_req = make_request(
            "verify_global_key",
            "wrong-password",
            "bin-pw",
            bin_data,
            &record,
        );
        let verify_resp = handle_verify_global_key(&verify_req);
        assert!(!verify_resp.ok, "错误口令必须被拒绝");
    }

    #[test]
    fn test_verify_record_from_other_derive_rejected() {
        // 不同派生产生的 record（随机 salt/nonce）解密必然失败 → AUTH
        let derive_a = handle_derive_global_key(&make_request(
            "derive_global_key", "pw-a", "bin-a", b"bin-a-data", "",
        ));
        assert!(derive_a.ok);
        let record_a = derive_a.data.unwrap();

        handle_derive_global_key(&make_request(
            "derive_global_key", "pw-b", "bin-b", b"bin-b-data", "",
        ));

        let verify_req = make_request(
            "verify_global_key", "pw-b", "bin-b", b"bin-b-data", &record_a,
        );
        let verify_resp = handle_verify_global_key(&verify_req);
        assert!(!verify_resp.ok, "跨派生的 record 必须验证失败");
    }

    #[test]
    fn test_subkey_locked_without_gmk() {
        handle_clear_global_key();
        let mut req = make_request("derive_module_subkey", "", "", b"", "");
        req.module_id = "any-module".into();
        let resp = handle_derive_module_subkey(&req);
        assert!(!resp.ok, "无 GMK 时子密钥派生必须失败");
        let err = resp.error.expect("应携带错误码");
        assert_eq!(err, "ERR_00000007", "锁定态错误码为 LOCKED(0x07)");
    }

    #[test]
    fn test_subkey_deterministic_per_module() {
        handle_derive_global_key(&make_request(
            "derive_global_key", "determinism-pw", "bin-pw", b"det-bin", "",
        ));

        let mut req = make_request("derive_module_subkey", "", "", b"", "");
        req.module_id = "module-x".into();
        let k1 = handle_derive_module_subkey(&req).data.unwrap();
        let k2 = handle_derive_module_subkey(&req).data.unwrap();
        assert_eq!(k1, k2, "同 module_id 子密钥必须确定");

        req.module_id = "module-y".into();
        let k3 = handle_derive_module_subkey(&req).data.unwrap();
        assert_ne!(k1, k3, "不同 module_id 子密钥必须不同");
    }
}
