/* GMK 材料：派生链与三要素核验（均不写 GMK 槽） */

use super::gmk_state::{GmkMaterial, CODE_AUTH, GLOBAL_KEY_RECORD_LEN, VERIFIER_PLAIN};
use crate::runtime::protocol::{Response, base64_decode};
use zeroize::Zeroize;

/// 派生全局主密钥 GMK（首次设置）
/// 输入：password + bin_data + bin_password
/// 输出：record(base64) = salt(32) + nonce(12) + verifierCt(48) + binHash(32)
/// 副作用：GMK 存入 thread_local 内存
/// 派生 GMK 核心：完整派生链（binKey → GMK → verifier → 124B record）。
/// 成功时 GMK 驻留 thread_local 并返回记录字节；失败返回已构造的
/// 错误响应（op 由调用方指定），GMK 不驻留。
/// derive_gmk_material 与 handle_derive_and_store_global_key / 改钥共用。
pub(super) fn derive_gmk_material(
    password: &str,
    bin_data_b64: &str,
    bin_password: &str,
    op: &str,
) -> Result<GmkMaterial, Box<Response>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use hkdf::Hkdf;
    use pbkdf2::pbkdf2_hmac;
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    let bin_data = match base64_decode(bin_data_b64) {
        Ok(d) => d,
        Err(_) => {
            return Err(Box::new(Response {
                ok: false,
                op: op.into(),
                error: Some("base64 decode bin_data failed".into()),
                ..Response::ok(op)
            }))
        }
    };

    // 1. binMaterial = SHA-256(bin_data)
    let bin_material = Sha256::digest(&bin_data);

    // 2. binPasswordKey = PBKDF2(bin_password, salt=bin_material[:16], 150000)
    let mut bin_password_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        bin_password.as_bytes(),
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
    let pw_bytes = password.as_bytes();
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
            return Err(Box::new(Response {
                ok: false,
                op: op.into(),
                error: Some("AES-GCM encrypt verifier failed".into()),
                ..Response::ok(op)
            }));
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

    // 10. 清零临时敏感变量（GMK 由调用方决定何时写入槽）
    bin_password_key.zeroize();
    ikm.zeroize();

    let mut gmk_arr = [0u8; 32];
    gmk_arr.copy_from_slice(&gmk[..]);
    Ok(GmkMaterial {
        gmk: zeroize::Zeroizing::new(gmk_arr),
        record,
    })
}

/// 核验全局密钥三要素（不写 GMK 槽）
///
/// 返回派生出的 GMK 供调用方决定用途：verify 命令写入槽；
/// change 命令仅用于旧钥核验，用后立即 drop（Zeroizing）。
pub(super) fn verify_gmk_material(
    password: &str,
    bin_data_b64: &str,
    bin_password: &str,
    record_b64: &str,
    op: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>, Box<Response>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use hkdf::Hkdf;
    use pbkdf2::pbkdf2_hmac;
    use sha2::{Digest, Sha256};

    let bin_data = match base64_decode(bin_data_b64) {
        Ok(d) => d,
        Err(_) => {
            return Err(Box::new(Response {
                ok: false,
                op: op.into(),
                error: Some("base64 decode bin_data failed".into()),
                ..Response::ok(op)
            }))
        }
    };
    let record = match base64_decode(record_b64) {
        Ok(d) => d,
        Err(_) => {
            return Err(Box::new(Response {
                ok: false,
                op: op.into(),
                error: Some("base64 decode record failed".into()),
                ..Response::ok(op)
            }))
        }
    };

    // 1. 解析 record: salt(32) + nonce(12) + verifierCt(48) + binHash(32) = 124B
    if record.len() != GLOBAL_KEY_RECORD_LEN {
        return Err(Box::new(Response::err(op, CODE_AUTH)));
    }
    let global_salt = &record[..32];
    let verifier_nonce = &record[32..44];
    let verifier_ct = &record[44..92];
    let bin_file_hash = &record[92..124];

    // 2. 校验 binFileHash
    let computed_hash = Sha256::digest(&bin_data);
    if computed_hash.as_slice() != bin_file_hash {
        return Err(Box::new(Response::err(op, CODE_AUTH)));
    }

    // 3. 派生 binKey + GMK
    let bin_material = Sha256::digest(&bin_data);
    let mut bin_password_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        bin_password.as_bytes(),
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

    let pw_bytes = password.as_bytes();
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
                return Err(Box::new(Response::err(op, CODE_AUTH)));
            }
        }
        Err(_) => {
            bin_password_key.zeroize();
            ikm.zeroize();
            return Err(Box::new(Response::err(op, CODE_AUTH)));
        }
    }

    // 5. 清零临时量，返回 GMK（由调用方决定何时入槽）
    let mut gmk_arr = [0u8; 32];
    gmk_arr.copy_from_slice(&gmk[..]);
    bin_password_key.zeroize();
    ikm.zeroize();

    Ok(zeroize::Zeroizing::new(gmk_arr))
}
