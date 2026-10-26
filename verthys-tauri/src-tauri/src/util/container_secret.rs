/*
 * util/container_secret.rs — 本机容器口令的生成与保管
 *
 * 职责边界：
 *   为容器创建与解锁提供唯一的本机口令来源。口令是 32 字节系统 CSPRNG
 *   随机值，Base64 编码后交给容器密钥派生使用；落盘副本经 DPAPI 密封。
 *   本模块只负责“口令从哪来”，不参与容器创建、解锁流程本身。
 *
 * 安全边界：
 *   - DPAPI 只绑定本机本用户：口令文件连同容器被复制到其他机器或其他
 *     用户时无法解封，容器即无法打开；同一用户下运行的恶意代码仍可解封，
 *     这是本层能力的上限。
 *   - 解封失败、长度不符必须失败关闭。禁止重新生成口令：重新生成会让
 *     既有容器永久无法打开，并被误判为空库。
 *   - 口令以 Zeroizing<String> 返回，调用方在发送给 worker 后立即销毁。
 *   - 本模块不写日志，避免口令或其摘要进入日志。
 */
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use zeroize::{Zeroize, Zeroizing};

use crate::util::{base64, crypto};

/// 随机口令字节数：256 位熵，满足容器密钥派生的输入强度要求
const SECRET_BYTES: usize = 32;

/// 密封口令文件名（位于应用数据根目录）
const SECRET_FILE_NAME: &str = "container.secret";

/// DPAPI 描述串：仅用于系统诊断展示，不参与任何密码学运算
const DPAPI_DESCRIPTION: &str = "verthys container secret";

/// 临时文件后缀：与目标文件同目录，保证 rename 落在同一卷上从而原子提交
const TEMP_FILE_SUFFIX: &str = ".tmp";

/// 读取本机容器口令；口令文件不存在时生成一次并密封落盘。
///
/// 参数：
///   - dir: 应用本地数据目录（由调用方按应用路径规则解析后传入）。
///
/// 返回：
///   - Ok: Base64 编码的 32 字节随机口令，调用方持有所有权并负责擦除。
///   - Err: 目录不可写、口令文件损坏、DPAPI 解封失败等。任何错误都不会
///     触发重新生成，避免覆盖既有口令。
///
/// 并发：多个进程同时首次启动时，只有一个能成功提交临时文件；
/// 落败方读取已提交文件，确保所有进程使用同一口令。
pub fn load_or_create(dir: &Path) -> Result<Zeroizing<String>, String> {
    let path = dir.join(SECRET_FILE_NAME);

    match fs::read(&path) {
        Ok(sealed) => return unseal(&sealed),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(format!("读取容器口令文件失败: {}", e)),
    }

    fs::create_dir_all(dir).map_err(|e| format!("创建应用数据目录失败: {}", e))?;

    let mut raw = [0u8; SECRET_BYTES];
    getrandom::getrandom(&mut raw).map_err(|e| format!("系统随机源不可用: {}", e))?;
    let sealed = crypto::dpapi_protect(&raw, Some(DPAPI_DESCRIPTION))?;
    raw.zeroize();

    let tmp = temp_path(&path);
    commit_atomically(&tmp, &path, &sealed)?;

    // 提交后统一从盘面回读：并发首启时落败方也由此拿到先落盘的口令，
    // 不会把本地生成但未提交的口令当作有效口令使用。
    let committed = fs::read(&path).map_err(|e| format!("读取容器口令文件失败: {}", e))?;
    unseal(&committed)
}

/// 临时文件路径：随机后缀避免并发进程相互覆盖；随机源不可用时退化为进程号
fn temp_path(target: &Path) -> PathBuf {
    let mut suffix = [0u8; 8];
    // 随机后缀失败时退化为进程号，仍可保证同一进程内唯一
    let _ = getrandom::getrandom(&mut suffix);
    let tag = if suffix.iter().all(|b| *b == 0) {
        format!("{}", std::process::id())
    } else {
        suffix.iter().map(|b| format!("{:02x}", b)).collect()
    };
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| SECRET_FILE_NAME.to_string());
    target.with_file_name(format!("{}.{}.{}", name, tag, TEMP_FILE_SUFFIX))
}

/// 先写临时文件并落盘，再原子重命名到目标路径。
///
/// 目标已存在表示其他进程先完成提交：删除本次临时文件并视为成功，
/// 由调用方回读目标文件取口令。
fn commit_atomically(tmp: &Path, target: &Path, sealed: &[u8]) -> Result<(), String> {
    let write_result = (|| -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp)
            .map_err(|e| format!("创建临时口令文件失败: {}", e))?;
        file.write_all(sealed)
            .map_err(|e| format!("写入临时口令文件失败: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("临时口令文件落盘失败: {}", e))?;
        Ok(())
    })();

    if let Err(e) = write_result {
        // 写入/落盘失败时不留残余临时文件，避免下次误判为并发冲突
        let _ = fs::remove_file(tmp);
        return Err(e);
    }

    match fs::rename(tmp, target) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(tmp);
            if target.exists() {
                Ok(())
            } else {
                Err(format!("提交容器口令文件失败: {}", e))
            }
        }
    }
}

/// 解封盘面口令并校验长度
fn unseal(sealed: &[u8]) -> Result<Zeroizing<String>, String> {
    let mut plain =
        crypto::dpapi_unprotect(sealed).map_err(|e| format!("容器口令解封失败: {}", e))?;
    if plain.len() != SECRET_BYTES {
        plain.zeroize();
        return Err("容器口令文件内容非法".to_string());
    }
    let password = Zeroizing::new(base64::base64_encode(&plain));
    plain.zeroize();
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut buf = [0u8; 8];
        let _ = getrandom::getrandom(&mut buf);
        let suffix: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
        std::env::temp_dir().join(format!("verthys_container_secret_{}_{}", tag, suffix))
    }

    #[test]
    #[cfg(windows)]
    fn test_load_or_create_is_stable() {
        let dir = temp_dir("stable");
        let first = load_or_create(&dir).expect("首次生成应成功");
        let second = load_or_create(&dir).expect("二次读取应成功");
        assert_eq!(first.as_str(), second.as_str());
        assert_eq!(first.len(), 44);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn test_secret_file_is_sealed() {
        let dir = temp_dir("sealed");
        let password = load_or_create(&dir).expect("生成应成功");
        let sealed = fs::read(dir.join(SECRET_FILE_NAME)).expect("口令文件应存在");
        assert_ne!(sealed.as_slice(), password.as_bytes());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn test_corrupted_secret_fails_closed() {
        let dir = temp_dir("corrupt");
        fs::create_dir_all(&dir).expect("目录应可创建");
        fs::write(dir.join(SECRET_FILE_NAME), b"not a sealed secret").expect("写入应成功");
        let result = load_or_create(&dir);
        assert!(result.is_err(), "损坏文件必须失败关闭，不得重新生成");
        let after = fs::read(dir.join(SECRET_FILE_NAME)).expect("原文件应保留");
        assert_eq!(after.as_slice(), b"not a sealed secret");
        let _ = fs::remove_dir_all(&dir);
    }
}
