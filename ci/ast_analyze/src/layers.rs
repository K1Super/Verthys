/*
 * layers.rs — 源文件目录到逻辑分层的映射与允许依赖表
 *
 * security_commands 与 updater 承载 Tauri 命令入口，按控制器层治理；
 * worker 与 devfixture 是进程/开发适配器，按基础设施层治理。
 */
pub(crate) const ENTRY_FILES: &[&str] = &["main.rs", "lib.rs", "entry_template.rs"];

pub(crate) fn layer_for_module(module: &str) -> Option<&'static str> {
    match module {
        "constants" => Some("constants"),
        "util" => Some("util"),
        "infrastructure" | "worker" | "devfixture" => Some("infrastructure"),
        "repository" => Some("repository"),
        "service" => Some("service"),
        "middleware" => Some("middleware"),
        "state" => Some("state"),
        "security" => Some("security"),
        "controller" | "security_commands" | "updater" => Some("controller"),
        "dll_hash" | "resource_hashes" => Some("generated"),
        _ => None,
    }
}

pub(crate) fn layer_for_path(rel_path: &str) -> Option<&'static str> {
    let first = rel_path.split(['/', '\\']).next()?;
    layer_for_module(first)
}

/// 允许的跨层依赖；同层依赖始终允许。
const ALLOWED_DEPS: &[(&str, &[&str])] = &[
    ("constants", &[]),
    ("util", &["constants"]),
    ("infrastructure", &["util", "constants", "generated"]),
    (
        "repository",
        &["util", "infrastructure", "constants", "generated"],
    ),
    (
        "service",
        &[
            "repository",
            "infrastructure",
            "util",
            "constants",
            "generated",
        ],
    ),
    (
        "middleware",
        &["infrastructure", "util", "constants", "generated"],
    ),
    (
        "state",
        &[
            "infrastructure",
            "repository",
            "util",
            "constants",
            "generated",
        ],
    ),
    (
        "security",
        &["infrastructure", "state", "util", "constants", "generated"],
    ),
    (
        "controller",
        &[
            "service",
            "repository",
            "infrastructure",
            "util",
            "constants",
            "state",
            "security",
            "generated",
        ],
    ),
];

pub(crate) fn allowed_deps(layer: &str) -> &'static [&'static str] {
    ALLOWED_DEPS
        .iter()
        .find(|(name, _)| *name == layer)
        .map(|(_, deps)| *deps)
        .unwrap_or(&[])
}
