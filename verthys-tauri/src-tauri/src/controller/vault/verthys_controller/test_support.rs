/*
 * verthys_controller 单元测试夹具（仅测试构建）
 *
 * 夹具只构造空文件与临时目录，不解析容器内容，不触碰真实用户数据。
 */

/* ------------------------------------------------------------------ *
 * 容器会话闸门测试辅助                                                *
 *                                                                    *
 * 测试只依赖文件锁与路径，不解析容器内容，因此构造空文件即可。         *
 * ------------------------------------------------------------------ */

/// 构造空容器文件（供文件锁/会话守卫使用）。
pub(super) fn make_container_fixture(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::create(path).map(|_| ())
}

/// 临时文件路径（进程 id + 用例名隔离，避免并行测试冲突）
pub(super) fn temp_container_path(case: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "verthys_vdp_{}_{}_{}.verthys",
        std::process::id(),
        case,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ))
}

pub(super) fn temp_keyfile_case_dir(case: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "verthys_kf_{}_{}_{}",
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

/* ===== 机器密钥材料目录策略 ===== */

pub(super) fn unique_key_material_dir(tag: &str) -> std::path::PathBuf {
    let mut buf = [0u8; 8];
    let _ = getrandom::getrandom(&mut buf);
    let suffix: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
    std::env::temp_dir().join(format!("verthys_keymat_{}_{}", tag, suffix))
}
