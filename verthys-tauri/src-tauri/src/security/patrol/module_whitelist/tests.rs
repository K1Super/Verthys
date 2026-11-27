/* ====================================================================== *
 *  单元测试                                                               *
 * ====================================================================== */

use super::trusted::{dev_self_module_path, is_dev_self_module, realize_path};

/// debug（测试）构建必须能取得主模块真实化路径，且格式与白名单比较一致。
#[test]
fn dev_self_module_path_matches_current_exe() {
    let self_norm = dev_self_module_path().expect("debug 构建应返回主模块路径");
    assert!(!self_norm.is_empty(), "主模块路径不得为空");
    assert_eq!(self_norm, self_norm.to_lowercase(), "路径应已规范化为小写");
    assert!(!self_norm.contains("\\\\?\\"), "路径不应保留扩展长度前缀");

    let exe = std::env::current_exe().expect("current_exe 失败");
    let file_name = exe
        .file_name()
        .expect("主模块应有文件名")
        .to_string_lossy()
        .to_lowercase();
    assert!(
        self_norm.ends_with(&file_name),
        "主模块路径应与当前进程一致"
    );
}

/// 豁免只允许“完全相等”的主模块路径，不得通过前缀/同目录扩散。
#[test]
fn dev_self_module_exemption_is_exact_path_only() {
    let self_norm = dev_self_module_path().expect("debug 构建应返回主模块路径");

    assert!(is_dev_self_module(&self_norm, Some(&self_norm)));
    assert!(
        !is_dev_self_module(&format!("{}.bak", self_norm), Some(&self_norm)),
        "带后缀的同前缀路径不得豁免"
    );

    let dir = self_norm
        .rsplit_once('\\')
        .map(|(d, _)| d)
        .unwrap_or_default();
    let sibling = format!("{}\\\\unsigned-other.dll", dir);
    assert!(
        !is_dev_self_module(&sibling, Some(&self_norm)),
        "同目录其他模块不得豁免"
    );
    assert!(!is_dev_self_module("", Some(&self_norm)), "空路径不得豁免");
    assert!(!is_dev_self_module(&self_norm, None), "发布构建不得豁免");
}

/// 后台完整校验候选必须排除开发主程序自身。
///
/// 测试进程位于 target/debug/deps；若把该目录当作安装目录，未签名的主
/// 模块会进入候选并随机抽样失败。豁免后不得再出现。
#[test]
fn trusted_signable_candidates_exclude_dev_self_exe() {
    let exe = std::env::current_exe().expect("current_exe 失败");
    let dir = exe
        .parent()
        .expect("主模块应有父目录")
        .to_string_lossy()
        .to_string();
    let self_norm = realize_path(&exe.to_string_lossy());

    let candidates = super::win_impl::trusted_signable_module_paths(&dir);
    assert!(
        !candidates
            .iter()
            .any(|(_, path)| realize_path(path) == self_norm),
        "开发主程序自身不得进入完整校验抽样候选"
    );
}
