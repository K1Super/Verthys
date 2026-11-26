/*
 * file_controller 单元测试
 *
 * 覆盖路径校验、原子写入、分片读取、流式落盘与暂存清理的边界行为。
 */
use super::stream::{cleanup_stale_stream_temps, generate_stream_id};
use super::*;
use crate::constants::export_stream::{
    MAX_EXPORT_SINGLE_BYTES, USER_FILE_SIZE_LIMIT, WRITE_FILE_CHUNK_BYTES,
};
use crate::controller::api_error::ErrorCode;
use crate::infrastructure::audit::get_audit_hmac_key;
use crate::util::sandbox::SandboxError;

#[test]
fn test_sandbox_error_to_code() {
    use crate::util::path::PathValidationError;

    let err = SandboxError::InvalidPath(PathValidationError::Empty);
    assert_eq!(sandbox_error_to_code(&err), ErrorCode::InvalidPath);

    let err = SandboxError::ResolveFailed("not found".into());
    assert_eq!(sandbox_error_to_code(&err), ErrorCode::InvalidPath);

    let err = SandboxError::NotInWhitelist;
    assert_eq!(sandbox_error_to_code(&err), ErrorCode::PermissionDenied);
}

#[test]
fn test_file_size_limit() {
    assert_eq!(FILE_SIZE_LIMIT, 50 * 1024 * 1024);
}

/* ===== x-path 百分号解码测试（中文/空格/特殊字符/畸形编码） ===== */

#[test]
fn test_decode_percent_path_chinese() {
    // encodeURIComponent("C:\\Users\\张三\\文档\\photo.venc")
    let raw = "C%3A%5CUsers%5C%E5%BC%A0%E4%B8%89%5C%E6%96%87%E6%A1%A3%5Cphoto.venc";
    assert_eq!(
        decode_percent_path(raw).unwrap(),
        "C:\\Users\\张三\\文档\\photo.venc"
    );
}

#[test]
fn test_decode_percent_path_space_and_special_chars() {
    // 空格、#、%、&、?、+（encodeURIComponent 语义全覆盖）
    let raw = "C%3A%5CMy%20Files%5C100%25%20off%23%20%26%20q%3F%20plus%2B.venc";
    assert_eq!(
        decode_percent_path(raw).unwrap(),
        "C:\\My Files\\100% off# & q? plus+.venc"
    );
}

#[test]
fn test_decode_percent_path_plain_ascii_passthrough() {
    // 纯 ASCII 路径：encodeURIComponent 不转换字母数字与部分保留字，解码应原样
    assert_eq!(
        decode_percent_path("C:/Users/Admin/AppData/photo.bin").unwrap(),
        "C:/Users/Admin/AppData/photo.bin"
    );
}

#[test]
fn test_decode_percent_path_rejects_malformed_percent() {
    // 畸形编码：%ZZ / 尾部孤立 % / %A（不足两位）
    assert!(decode_percent_path("C%3A%5Cpath%ZZfile").is_err());
    assert!(decode_percent_path("C%3A%5Cpath%").is_err());
    assert!(decode_percent_path("C%3A%5Cpath%A").is_err());
}

#[test]
fn test_decode_percent_path_rejects_empty() {
    // 空串 / 仅分隔符
    assert!(decode_percent_path("").is_err());
}

#[test]
fn test_decode_percent_path_rejects_invalid_utf8() {
    // 合法 %XX 序列但解码后非 UTF-8（0x80 为延续字节首现，非法起始）
    assert!(decode_percent_path("%80%81").is_err());
}

#[test]
fn test_decode_percent_path_long_path() {
    // 超长路径（>260 传统 MAX_PATH，现代 Windows 长路径支持）
    let segment = "%E5%BC%A0%E4%B8%89%E6%96%87%E6%A1%A3"; // 张三文档
    let raw = format!("C%3A%5C{}", segment.repeat(80));
    let decoded = decode_percent_path(&raw).unwrap();
    assert!(decoded.starts_with("C:\\张三文档"));
    assert_eq!(decoded.chars().count(), 3 + 80 * 4);
}

#[test]
fn test_read_chunk_size() {
    assert_eq!(READ_CHUNK_SIZE, 64 * 1024);
}

#[test]
fn test_file_op_timeout() {
    assert_eq!(FILE_OP_TIMEOUT, TIMEOUT_CONFIG.ipc);
}

#[test]
fn test_user_file_chunk_op_timeout_shorter_than_full_read() {
    // 分片读取的短超时语义：单次分片必须比整文件读取更早暴露卡顿
    assert_eq!(USER_FILE_CHUNK_OP_TIMEOUT, Duration::from_secs(15));
    assert!(USER_FILE_CHUNK_OP_TIMEOUT < USER_FILE_OP_TIMEOUT);
}

#[test]
fn test_user_file_size_limit_is_unified_with_export_limit() {
    // 单文件体量上限单一权威来源：读写上限与导出累计上限同源（生成器侧另有
    // 编译期断言，此处锁定 Rust 侧取值与关系，防生成物被绕过）
    assert_eq!(USER_FILE_SIZE_LIMIT, MAX_EXPORT_SINGLE_BYTES);
    assert_eq!(USER_FILE_SIZE_LIMIT, 2 * 1024 * 1024 * 1024);
}

#[test]
fn test_audit_hmac_key_is_cached_and_stable() {
    // 审计 HMAC 密钥在进程内只派生一次：分片读写按片追加审计，
    // 逐次重派生（10 万次 PBKDF2）会把单次大文件导入放大成秒级 CPU 开销
    let first = get_audit_hmac_key();
    let second = get_audit_hmac_key();
    assert_eq!(first, second, "同一进程内两次取键必须一致");
    if first.is_some() {
        assert!(
            crate::infrastructure::audit::audit_hmac_key_is_cached(),
            "成功结果必须进入缓存"
        );
    }
}

#[test]
fn test_check_disk_space_reads_existing_dir_and_missing_child() {
    let temp = std::env::temp_dir().join("verthys_test_disk_space");
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();
    let dir = temp.to_string_lossy().to_string();

    // 存在的目录：返回可用空间（0 视为环境异常）
    let existing = check_disk_space_blocking(Some(&dir), None).unwrap();
    assert!(existing.free_bytes > 0, "已存在目录必须返回可用空间");

    // 目标尚未创建（导出保存位置）：解析父目录后仍可查询
    let missing = temp
        .join("not-created-yet.bin")
        .to_string_lossy()
        .to_string();
    let pending = check_disk_space_blocking(Some(&missing), None).unwrap();
    assert!(pending.free_bytes > 0, "未创建目标必须按父目录卷查询");

    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn test_check_disk_space_rejects_invalid_and_system_paths() {
    // 相对路径在字符级校验即拒绝
    assert!(check_disk_space_blocking(Some("relative/path.bin"), None).is_err());

    #[cfg(windows)]
    {
        // 系统关键目录一律拒绝（父目录解析后命中拒绝链）
        assert!(check_disk_space_blocking(Some("C:/Windows/notepad.exe"), None).is_err());
    }
}

#[test]
fn test_check_disk_space_session_path_branch() {
    let temp = std::env::temp_dir().join("verthys_test_disk_space_session");
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).unwrap();
    let container = temp.join("c.verthys").to_string_lossy().to_string();

    // 路径缺省 = 容器卷：查询容器所在卷的可用空间
    let info = check_disk_space_blocking(None, Some(&container)).unwrap();
    assert!(info.free_bytes > 0);

    // 无显式路径且无容器路径：拒绝（不得静默按未知放行）
    assert!(check_disk_space_blocking(None, None).is_err());

    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn test_write_mutex_can_lock() {
    let guard = WRITE_MUTEX.lock();
    assert!(guard.is_ok());
}

#[test]
fn test_read_file_blocking_rejects_invalid_path() {
    let whitelist = vec!["C:/safe".to_string()];
    let result = read_file_blocking("", &whitelist);
    assert!(result.is_err());
}

#[test]
fn test_read_file_blocking_rejects_relative_path() {
    let whitelist = vec!["C:/safe".to_string()];
    let result = read_file_blocking("relative/path/file.txt", &whitelist);
    assert!(result.is_err());
}

#[test]
fn test_read_file_blocking_rejects_parent_traversal() {
    let whitelist = vec!["C:/safe".to_string()];
    let result = read_file_blocking("C:/safe/../../../etc/passwd", &whitelist);
    assert!(result.is_err());
}

#[test]
fn test_write_file_blocking_rejects_invalid_path() {
    let temp_dir = std::env::temp_dir();
    let whitelist = vec![temp_dir.to_string_lossy().to_string()];

    // 二进制 IPC：无效路径（空串）必须被拒绝
    let result = write_file_blocking("", b"binary data", &whitelist);
    assert!(result.is_err());
}

#[test]
fn test_write_file_blocking_atomic_write() {
    let temp_dir = std::env::temp_dir();
    let whitelist = vec![temp_dir.to_string_lossy().to_string()];

    let test_dir = temp_dir.join("verthys_test_atomic");
    let _ = std::fs::create_dir_all(&test_dir);
    let test_file = test_dir.join("atomic_test.txt");
    let path_str = test_file.to_string_lossy().to_string();

    // 二进制 IPC：原始字节直传（无 base64 编解码）
    let test_data = b"Hello, Verthys atomic write!";

    let result = write_file_blocking(&path_str, test_data, &whitelist);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), test_data.len() as u64);

    let read_back = std::fs::read(&test_file).unwrap();
    assert_eq!(read_back, test_data);

    let entries = std::fs::read_dir(&test_dir).unwrap();
    for entry in entries {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        assert!(!name_str.contains(".tmp."), "临时文件残留: {}", name_str);
    }

    let _ = std::fs::remove_dir_all(&test_dir);
}

/* ===== 用户文件分片读取与元数据快照测试 ===== */

/// 构造定长测试文件（内容为递增字节），返回（目录，路径串）
fn make_range_test_file(tag: &str, bytes: &[u8]) -> (std::path::PathBuf, String) {
    let dir = std::env::temp_dir().join(format!("verthys_test_range_{}", tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("src.bin");
    std::fs::write(&file, bytes).unwrap();
    let path = file.to_string_lossy().to_string();
    (dir, path)
}

#[test]
fn test_range_read_head_and_tail_exact_bytes() {
    let data: Vec<u8> = (0..=63u8).collect();
    let (dir, path) = make_range_test_file("head_tail", &data);

    // 头部：offset 0 + 定长
    let head = read_user_file_range_blocking(&path, Some(0), Some(4)).unwrap();
    assert_eq!(head, data[..4]);

    // 末块：offset = 长度 - 3，恰好读到文件末尾
    let tail = read_user_file_range_blocking(&path, Some(61), Some(3)).unwrap();
    assert_eq!(tail, data[61..]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_range_read_rejects_offset_beyond_size() {
    let data = vec![7u8; 10];
    let (dir, path) = make_range_test_file("offset_over", &data);

    // offset 越过文件长度（即使 length=1 也在界外）
    let err = read_user_file_range_blocking(&path, Some(11), Some(1)).unwrap_err();
    assert!(err.contains("越界"), "越界必须给出明确原因: {}", err);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_range_read_rejects_tail_overrun_without_truncation() {
    let data = vec![7u8; 10];
    let (dir, path) = make_range_test_file("tail_over", &data);

    // offset 合法但 offset + length 越过末尾：拒绝，不得静默截断
    let err = read_user_file_range_blocking(&path, Some(8), Some(4)).unwrap_err();
    assert!(err.contains("越界"), "超尾必须给出明确原因: {}", err);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_range_read_rejects_oversize_and_empty_length() {
    let data = vec![7u8; 16];
    let (dir, path) = make_range_test_file("oversize", &data);

    let err =
        read_user_file_range_blocking(&path, Some(0), Some(WRITE_FILE_CHUNK_BYTES as u64 + 1))
            .unwrap_err();
    assert!(err.contains("上限"), "超分片上界必须拒绝: {}", err);

    let err = read_user_file_range_blocking(&path, Some(0), Some(0)).unwrap_err();
    assert!(err.contains("大于 0"), "空分片必须拒绝: {}", err);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_range_read_requires_paired_params() {
    let data = vec![7u8; 8];
    let (dir, path) = make_range_test_file("unpaired", &data);

    assert!(read_user_file_range_blocking(&path, Some(0), None).is_err());
    assert!(read_user_file_range_blocking(&path, None, Some(4)).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_range_read_default_mode_unchanged() {
    let data: Vec<u8> = (0..=99u8).collect();
    let (dir, path) = make_range_test_file("default_mode", &data);

    // 缺省参数按整文件读取处理（返回全部字节）
    let all = read_user_file_range_blocking(&path, None, None).unwrap();
    assert_eq!(all, data);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_user_file_stat_contract() {
    let data = vec![9u8; 12345];
    let (dir, path) = make_range_test_file("stat", &data);

    let stat = user_file_stat_blocking(&path).unwrap();
    assert_eq!(stat.size, data.len() as u64);
    assert!(stat.mtime_ms > 0, "修改时间必须可读（身份校验依据）");

    // 与读取命令共用同一校验链：非法路径一律拒绝
    assert!(user_file_stat_blocking("relative/file.bin").is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

/* ===== 流式写入（暂存 + 原子替换）测试 ===== */

#[test]
fn test_stream_roundtrip_and_no_residue() {
    let temp_dir = std::env::temp_dir().join("verthys_test_stream_roundtrip");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    let target = temp_dir.join("out.venc");
    let target_str = target.to_string_lossy().to_string();

    let (stream_id, entry) = stream_create_blocking(&target_str).unwrap();
    assert_eq!(stream_id.len(), 32);

    let part1 = vec![0x41u8; 100_000];
    let part2 = vec![0x42u8; 50_000];
    stream_append_blocking(&entry, &part1).unwrap();
    stream_append_blocking(&entry, &part2).unwrap();

    let total = stream_finalize_blocking(entry, None).unwrap();
    assert_eq!(total, 150_000);

    let read_back = std::fs::read(&target).unwrap();
    assert_eq!(read_back.len(), 150_000);
    assert_eq!(&read_back[..100_000], &part1[..]);
    assert_eq!(&read_back[100_000..], &part2[..]);

    // 暂存文件已 rename 消失，无残留
    let residue = std::fs::read_dir(&temp_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".venc.tmp"));
    assert!(!residue, "暂存文件残留");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_stream_abort_removes_temp_and_leaves_target_untouched() {
    let temp_dir = std::env::temp_dir().join("verthys_test_stream_abort");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    let target = temp_dir.join("out.venc");
    let target_str = target.to_string_lossy().to_string();

    let (_, entry) = stream_create_blocking(&target_str).unwrap();
    stream_append_blocking(&entry, b"unfinished").unwrap();
    stream_abort_blocking(entry).unwrap();

    // 目标文件不存在（从未 rename），暂存已清理
    assert!(!target.exists());
    let residue = std::fs::read_dir(&temp_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(".venc.tmp"));
    assert!(!residue, "中止后暂存残留");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_stream_finalize_replaces_existing_target() {
    let temp_dir = std::env::temp_dir().join("verthys_test_stream_replace");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    let target = temp_dir.join("out.venc");
    std::fs::write(&target, b"old-version").unwrap();
    let target_str = target.to_string_lossy().to_string();

    let (_, entry) = stream_create_blocking(&target_str).unwrap();
    stream_append_blocking(&entry, b"new-version").unwrap();
    stream_finalize_blocking(entry, None).unwrap();

    assert_eq!(std::fs::read(&target).unwrap(), b"new-version");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_stream_append_rejects_oversize_chunk_keeping_session_usable() {
    let temp_dir = std::env::temp_dir().join("verthys_test_stream_oversize");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    let target = temp_dir.join("out.venc");
    let target_str = target.to_string_lossy().to_string();

    let (_, entry) = stream_create_blocking(&target_str).unwrap();
    let big = vec![0u8; WRITE_FILE_CHUNK_BYTES + 1];
    let err = stream_append_blocking(&entry, &big).unwrap_err();
    assert_eq!(err, ErrorCode::FileTooLarge.default_message().to_string());

    // 超限拒绝后会话仍可用（不破坏状态）
    stream_append_blocking(&entry, b"ok").unwrap();
    stream_abort_blocking(entry).unwrap();
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_stream_create_fails_on_fresh_temp_residue() {
    let temp_dir = std::env::temp_dir().join("verthys_test_stream_fresh_residue");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    let target = temp_dir.join("out.venc");
    let target_str = target.to_string_lossy().to_string();

    // 伪造未过期的暂存残留：按龄清理不会触碰，独占创建必须失败
    std::fs::write(temp_dir.join(".verthys-out.venc.tmp"), b"residue").unwrap();
    let err = stream_create_blocking(&target_str).unwrap_err();
    assert_eq!(
        err,
        ErrorCode::TemporaryFailure.default_message().to_string()
    );
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_stream_create_rejects_invalid_paths() {
    // 空串与相对路径必须在字符级校验层被拒绝
    assert!(stream_create_blocking("").is_err());
    assert!(stream_create_blocking("relative/out.venc").is_err());
}

#[test]
fn test_cleanup_stale_temps_preserves_fresh() {
    let temp_dir = std::env::temp_dir().join("verthys_test_cleanup_fresh");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    std::fs::write(temp_dir.join(".verthys-a.venc.tmp"), b"x").unwrap();
    std::fs::write(temp_dir.join("foreign.venc.tmp"), b"y").unwrap();
    cleanup_stale_stream_temps(&temp_dir);
    assert!(temp_dir.join(".verthys-a.venc.tmp").exists());
    assert!(
        temp_dir.join("foreign.venc.tmp").exists(),
        "非本应用前缀的同后缀文件不得被清理"
    );
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_generate_stream_id_format() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..500 {
        let id = generate_stream_id();
        assert_eq!(id.len(), 32);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        seen.insert(id);
    }
    assert_eq!(seen.len(), 500);
}

#[cfg(windows)]
#[test]
fn system_critical_path_matches_verbatim_canonical_form() {
    // canonicalize 在 Windows 上返回 \\?\C:\...；保护判定必须能剥离前缀命中。
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let canonical = std::fs::canonicalize(&system_root).expect("系统目录必须可 canonicalize");
    assert!(
        is_system_critical_path(&canonical),
        "canonical 形态未被识别: {canonical:?}"
    );
    assert!(is_system_critical_path(std::path::Path::new(
        r"\\?\C:\Windows\System32\config\SAM"
    )));
    assert!(!is_system_critical_path(&std::env::temp_dir()));
}

fn unique_cancel_case_dir(case: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "verthys_cancel_{}_{}_{}",
        std::process::id(),
        case,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("创建临时目录失败");
    dir
}

#[test]
fn write_user_file_cancel_before_commit_keeps_target() {
    use std::sync::atomic::AtomicBool;

    let dir = unique_cancel_case_dir("write");
    let target = dir.join("out.bin");
    std::fs::write(&target, b"old-version").unwrap();
    let target_str = target.to_string_lossy().to_string();

    let cancel = AtomicBool::new(true);
    let err = write_user_file_blocking(&target_str, b"new-version", Some(&cancel))
        .expect_err("取消标志置位时必须拒绝提交");
    assert!(err.contains("取消"), "错误语义不符: {err}");
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"old-version",
        "取消后目标文件不得被替换"
    );
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|name| name != "out.bin")
        .collect();
    assert!(leftovers.is_empty(), "取消后不得残留暂存文件: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stream_finalize_cancel_keeps_target_and_removes_temp() {
    use std::sync::atomic::AtomicBool;

    let dir = unique_cancel_case_dir("finalize");
    let target = dir.join("out.venc");
    std::fs::write(&target, b"old-version").unwrap();
    let target_str = target.to_string_lossy().to_string();

    let (_, entry) = stream_create_blocking(&target_str).unwrap();
    stream_append_blocking(&entry, b"new-version").unwrap();

    let cancel = AtomicBool::new(true);
    let err = stream_finalize_blocking(entry, Some(&cancel))
        .expect_err("取消标志置位时必须拒绝 rename");
    assert!(err.contains("取消"), "错误语义不符: {err}");
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"old-version",
        "取消后目标文件不得被替换"
    );
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|name| name != "out.venc")
        .collect();
    assert!(leftovers.is_empty(), "取消后不得残留暂存文件: {leftovers:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
