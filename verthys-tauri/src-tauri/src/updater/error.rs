/*
 * updater/error.rs — 更新域错误码清单
 *
 * 错误码是 Rust 与前端共享的稳定契约。新增失败路径必须先登记到本清单，
 * 再由前端补全文案；清单外的错误码视为契约违规。
 */

/// 全部对外错误码；顺序仅用于阅读，比较一律按集合处理。
#[cfg(test)]
pub const CODES: &[&str] = &[
    "E_UPDATER_NETWORK",
    "E_UPDATER_MANIFEST_INVALID",
    "E_UPDATER_MANIFEST_SIG_INVALID",
    "E_UPDATER_CHANNEL_MISMATCH",
    "E_UPDATER_VERSION_BLOCKED",
    "E_UPDATER_BRIDGE_REQUIRED",
    "E_UPDATER_COMPAT_BLOCKED",
    "E_UPDATER_INSTALL_REVOKED",
    "E_UPDATER_PACKAGE_MISSING",
    "E_UPDATER_PRECHECK_SPACE",
    "E_UPDATER_PRECHECK_SINGLE_INSTANCE",
    "E_UPDATER_PRECHECK_DIR_WRITABLE",
    "E_UPDATER_SIZE_MISMATCH",
    "E_UPDATER_HASH_MISMATCH",
    "E_UPDATER_PE_VERSION_MISMATCH",
    "E_UPDATER_SIG_INVALID",
    "E_UPDATER_SIG_PUBKEY_MISMATCH",
    "E_UPDATER_AUTHENTICODE_INVALID",
    "E_UPDATER_LOCK_DIRTY",
    "E_UPDATER_LOCK_FAILED",
    "E_UPDATER_LOCK_UNKNOWN",
    "E_UPDATER_INSTALL_FAILED",
    "E_UPDATER_HEALTH_FAIL",
    "E_UPDATER_MARKER_INVALID",
    "E_UPDATER_ROLLBACK_MATERIAL_MISSING",
    "E_UPDATER_CANCELLED",
    "E_UPDATER_BUSY",
    "E_UPDATER_SESSION_INVALID",
    "E_UPDATER_CONFIG_INVALID",
    "E_UPDATER_INTERNAL",
];

#[cfg(test)]
mod tests {
    use super::CODES;
    use regex::Regex;
    use std::collections::BTreeSet;
    use std::path::Path;

    /// 扫描更新域源码，确保所有实际使用的错误码都已登记。
    #[test]
    fn emitted_codes_are_registered() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/updater");
        let pattern = Regex::new(r"E_UPDATER_[A-Z_]+").unwrap();
        let mut emitted = BTreeSet::new();
        for entry in std::fs::read_dir(root).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for found in pattern.find_iter(&text) {
                emitted.insert(found.as_str().to_string());
            }
        }
        let registered: BTreeSet<String> = CODES.iter().map(|value| value.to_string()).collect();
        let missing: Vec<_> = emitted.difference(&registered).cloned().collect();
        assert!(missing.is_empty(), "未登记的错误码: {missing:?}");
    }

    #[test]
    fn registered_codes_are_unique() {
        let unique: BTreeSet<_> = CODES.iter().collect();
        assert_eq!(unique.len(), CODES.len());
    }
}
