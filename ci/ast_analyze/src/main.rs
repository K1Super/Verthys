/*
 * CI 第二级：AST 深度分析工具
 *
 * 目标：在合并前阻断架构红线，且基线本身不因行号漂移产生假阳性。
 *
 * 分析内容：
 *   1. 基于 syn AST 提取 crate 内部依赖边，按分层契约校验方向
 *   2. 入口文件禁止直接调用底层文件/密码学 API
 *   3. 禁止 match 分支吞掉 Err
 *   4. C 生产源码禁止 printf/fprintf/OutputDebugString 输出
 *
 * 基线治理：
 *   - 指纹 = 类别|相对路径|目标（模块/函数），不含行号
 *   - 同一指纹按出现次数计数，新增次数仍阻断
 *   - 基线条目不再出现时判为 STALE 并阻断，防止豁免腐烂
 *   - --write-baseline 重写前打印与旧基线的增删差异，便于评审
 */
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use quote::ToTokens;
use regex::Regex;
use syn::spanned::Spanned;
use syn::visit::Visit;
use walkdir::WalkDir;

const RUST_SRC_DIR: &str = "verthys-tauri/src-tauri/src";
const C_SRC_DIR: &str = "core/src";

const ENTRY_FILES: &[&str] = &["main.rs", "lib.rs", "entry_template.rs"];

/// 源文件目录到逻辑分层的映射。
///
/// security_commands 与 updater 承载 Tauri 命令入口，按控制器层治理；
/// worker 与 devfixture 是进程/开发适配器，按基础设施层治理。
fn layer_for_module(module: &str) -> Option<&'static str> {
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

fn layer_for_path(rel_path: &str) -> Option<&'static str> {
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

fn allowed_deps(layer: &str) -> &'static [&'static str] {
    ALLOWED_DEPS
        .iter()
        .find(|(name, _)| *name == layer)
        .map(|(_, deps)| *deps)
        .unwrap_or(&[])
}

const DANGER_CALL_PATTERNS: &[&str] = &[
    "fs::read",
    "fs::write",
    "fs::File::open",
    "fs::File::create",
    "BCryptEncrypt",
    "BCryptDecrypt",
    "BCryptOpenAlgorithmProvider",
    "BCryptGenerateSymmetricKey",
];

/* ------------------------------------------------------------------ *
 * 违规与基线                                                          *
 * ------------------------------------------------------------------ */

#[derive(Debug, Clone)]
struct Violation {
    category: &'static str,
    file: String,
    detail: String,
    line: usize,
    message: String,
}

impl Violation {
    fn new(
        category: &'static str,
        file: &str,
        detail: impl Into<String>,
        line: usize,
        message: impl Into<String>,
    ) -> Self {
        Self {
            category,
            file: file.to_string(),
            detail: detail.into(),
            line,
            message: message.into(),
        }
    }

    /// 基线指纹：不含行号，行号漂移不会产生新违规。
    fn key(&self) -> String {
        format!("{}|{}|{}", self.category, self.file, self.detail)
    }
}

type Baseline = HashMap<String, usize>;

fn parse_baseline(text: &str) -> Result<Baseline, String> {
    let mut baseline = Baseline::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() != 4 {
            return Err(format!(
                "基线条目格式非法（第 {} 行，期望 category|file|detail|count）: {}",
                index + 1,
                line
            ));
        }
        let count: usize = parts[3]
            .parse()
            .map_err(|_| format!("基线条目计数非法（第 {} 行）: {}", index + 1, line))?;
        if count == 0 {
            return Err(format!("基线条目计数必须大于 0（第 {} 行）", index + 1));
        }
        let key = format!("{}|{}|{}", parts[0], parts[1], parts[2]);
        *baseline.entry(key).or_insert(0) += count;
    }
    Ok(baseline)
}

fn load_baseline(path: &Path) -> Result<Baseline, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("读取基线失败 {}: {e}", path.display()))?;
    parse_baseline(&text)
}

fn render_baseline(violations: &[Violation]) -> String {
    let mut entries: BTreeMap<String, usize> = BTreeMap::new();
    for violation in violations {
        *entries.entry(violation.key()).or_insert(0) += 1;
    }
    let mut body = String::from(
        "# AST 红线基线：由 --write-baseline 生成（存量豁免，新增违规不受豁免）\n\
         # 格式：category|file|detail|count；detail 为依赖模块或输出函数名\n",
    );
    for (key, count) in entries {
        body.push_str(&format!("{key}|{count}\n"));
    }
    body
}

fn apply_baseline(
    violations: Vec<Violation>,
    baseline: &Baseline,
) -> (Vec<Violation>, Vec<String>, usize) {
    let mut remaining_counts = baseline.clone();
    let mut remaining = Vec::new();
    let mut exempted = 0usize;
    for violation in violations {
        let key = violation.key();
        match remaining_counts.get_mut(&key) {
            Some(count) if *count > 0 => {
                *count -= 1;
                exempted += 1;
            }
            _ => remaining.push(violation),
        }
    }
    let stale = remaining_counts
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(key, count)| format!("{key}|{count}"))
        .collect();
    (remaining, stale, exempted)
}

/* ------------------------------------------------------------------ *
 * Rust 依赖提取                                                       *
 * ------------------------------------------------------------------ */

fn collect_use_tree(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut BTreeSet<String>) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_tree(&path.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            if prefix.first().map(String::as_str) == Some("crate") {
                if prefix.len() >= 2 {
                    out.insert(prefix[1].clone());
                } else if name.ident != "crate" {
                    out.insert(name.ident.to_string());
                }
            }
        }
        syn::UseTree::Rename(rename) => {
            if prefix.first().map(String::as_str) == Some("crate") {
                if prefix.len() >= 2 {
                    out.insert(prefix[1].clone());
                } else if rename.ident != "crate" {
                    out.insert(rename.ident.to_string());
                }
            }
        }
        syn::UseTree::Glob(_) => {
            if prefix.first().map(String::as_str) == Some("crate") && prefix.len() >= 2 {
                out.insert(prefix[1].clone());
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(item, prefix, out);
            }
        }
    }
}

struct UseVisitor {
    targets: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for UseVisitor {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let mut prefix = Vec::new();
        collect_use_tree(&node.tree, &mut prefix, &mut self.targets);
        syn::visit::visit_item_use(self, node);
    }
}

struct PathUseVisitor {
    targets: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for PathUseVisitor {
    fn visit_path(&mut self, node: &'ast syn::Path) {
        let mut segments = node.segments.iter();
        if segments.next().map(|s| s.ident == "crate").unwrap_or(false) {
            if let Some(second) = segments.next() {
                self.targets.insert(second.ident.to_string());
            }
        }
        syn::visit::visit_path(self, node);
    }
}

/* ------------------------------------------------------------------ *
 * 入口危险调用与吞异常                                                *
 * ------------------------------------------------------------------ */

struct DangerVisitor {
    file: String,
    is_entry: bool,
    violations: Vec<Violation>,
}

impl<'ast> Visit<'ast> for DangerVisitor {
    fn visit_path(&mut self, node: &'ast syn::Path) {
        if self.is_entry {
            let path = node
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            for pattern in DANGER_CALL_PATTERNS {
                if path.contains(pattern) {
                    let line = node
                        .segments
                        .first()
                        .map(|s| s.ident.span().start().line)
                        .unwrap_or(0);
                    self.violations.push(Violation::new(
                        "入口文件危险调用",
                        &self.file,
                        *pattern,
                        line,
                        format!("入口文件引用了底层 API 路径: {}", pattern),
                    ));
                }
            }
        }
        syn::visit::visit_path(self, node);
    }
}

struct SwallowVisitor {
    file: String,
    violations: Vec<Violation>,
}

impl<'ast> Visit<'ast> for SwallowVisitor {
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        for arm in &node.arms {
            // 只审查通配错误载荷（Err(_) / Err(..)）；结构化变体分支的空处理
            // 往往是显式状态机分支，不能据此判定吞错。
            let pattern = arm.pat.to_token_stream().to_string().replace(' ', "");
            let wildcard_err = pattern.contains("Err(_)") || pattern.contains("Err(..)");
            if !wildcard_err {
                continue;
            }

            let body = arm.body.to_token_stream().to_string();
            let compact = body.replace(' ', "");
            // 带日志/审计的错误分支属于显式降级，不是静默吞错。
            let handled = [
                "log::",
                "eprintln!",
                "println!",
                "Audit",
                "audit",
                "tracing::",
            ]
            .iter()
            .any(|marker| compact.contains(marker));
            if handled {
                continue;
            }

            let swallows = match arm.body.as_ref() {
                syn::Expr::Block(block) => {
                    block.block.stmts.is_empty()
                        || body.contains("return None")
                        || body.contains("return Ok(())")
                        || body.contains("continue")
                }
                syn::Expr::Path(path) => {
                    let path = path
                        .path
                        .segments
                        .iter()
                        .map(|s| s.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::");
                    path.contains("Default") || path.contains("default")
                }
                _ => false,
            };
            if swallows {
                self.violations.push(Violation::new(
                    "吞掉异常",
                    &self.file,
                    "Err",
                    arm.pat.span().start().line,
                    "检测到 match 分支吞掉 Err 异常而未重新抛出".to_string(),
                ));
            }
        }
        syn::visit::visit_expr_match(self, node);
    }
}

/* ------------------------------------------------------------------ *
 * C 输出函数检测                                                      *
 * ------------------------------------------------------------------ */

/// 去掉 C 注释与字符串/字符字面量，保留换行以维持行号。
///
/// 注释里提到 printf/OutputDebugString 不构成输出调用；仅扫描真实代码。
fn strip_c_comments_and_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    let mut state = 0u8; // 0=normal 1=line comment 2=block comment 3=string 4=char

    while index < bytes.len() {
        let current = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            0 => {
                if current == b'/' && next == Some(b'/') {
                    out.extend_from_slice(b"  ");
                    state = 1;
                    index += 2;
                } else if current == b'/' && next == Some(b'*') {
                    out.extend_from_slice(b"  ");
                    state = 2;
                    index += 2;
                } else if current == b'"' {
                    out.push(b' ');
                    state = 3;
                    index += 1;
                } else if current == b'\'' {
                    out.push(b' ');
                    state = 4;
                    index += 1;
                } else {
                    out.push(current);
                    index += 1;
                }
            }
            1 => {
                if current == b'\n' {
                    out.push(b'\n');
                    state = 0;
                } else {
                    out.push(b' ');
                }
                index += 1;
            }
            2 => {
                if current == b'*' && next == Some(b'/') {
                    out.extend_from_slice(b"  ");
                    state = 0;
                    index += 2;
                } else {
                    out.push(if current == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
            }
            3 => {
                if current == b'\\' && next.is_some() {
                    out.extend_from_slice(b"  ");
                    index += 2;
                } else if current == b'"' {
                    out.push(b' ');
                    state = 0;
                    index += 1;
                } else {
                    out.push(if current == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
            }
            _ => {
                if current == b'\\' && next.is_some() {
                    out.extend_from_slice(b"  ");
                    index += 2;
                } else if current == b'\'' {
                    out.push(b' ');
                    state = 0;
                    index += 1;
                } else {
                    out.push(if current == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

/* ------------------------------------------------------------------ *
 * 主流程                                                              *
 * ------------------------------------------------------------------ */

fn normalized_rel(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut baseline_path: Option<String> = None;
    let mut write_baseline_path: Option<String> = None;
    let mut index = 1usize;
    while index < args.len() {
        match args[index].as_str() {
            "--baseline" if index + 1 < args.len() => {
                baseline_path = Some(args[index + 1].clone());
                index += 2;
            }
            "--write-baseline" if index + 1 < args.len() => {
                write_baseline_path = Some(args[index + 1].clone());
                index += 2;
            }
            _ => index += 1,
        }
    }

    if baseline_path.is_some() && write_baseline_path.is_some() {
        eprintln!("--baseline 与 --write-baseline 不能同时使用");
        return ExitCode::from(2);
    }

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let rust_src = project_root.join(RUST_SRC_DIR);
    let c_src = project_root.join(C_SRC_DIR);

    println!("{}", "=".repeat(60));
    println!("CI 第二级：AST 深度分析");
    println!("{}", "=".repeat(60));

    let mut violations = Vec::new();

    for entry in WalkDir::new(&rust_src)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|ext| ext == "rs")
                .unwrap_or(false)
        })
    {
        let rel_path = normalized_rel(entry.path(), &rust_src);
        let content = match std::fs::read_to_string(entry.path()) {
            Ok(content) => content,
            Err(_) => continue,
        };

        if let Some(source_layer) = layer_for_path(&rel_path) {
            let syntax = match syn::parse_file(&content) {
                Ok(syntax) => syntax,
                Err(error) => {
                    violations.push(Violation::new(
                        "解析失败",
                        &rel_path,
                        "syntax",
                        0,
                        format!("Rust 语法解析失败: {error}"),
                    ));
                    continue;
                }
            };

            let mut use_visitor = UseVisitor {
                targets: BTreeSet::new(),
            };
            use_visitor.visit_file(&syntax);

            let mut path_visitor = PathUseVisitor {
                targets: BTreeSet::new(),
            };
            path_visitor.visit_file(&syntax);

            let mut targets = use_visitor.targets;
            targets.extend(path_visitor.targets);

            for target in targets {
                let target_layer = match layer_for_module(&target) {
                    Some(layer) => layer,
                    None => {
                        violations.push(Violation::new(
                            "未知模块依赖",
                            &rel_path,
                            target.clone(),
                            0,
                            format!("依赖未登记分层归属的模块 '{}'", target),
                        ));
                        continue;
                    }
                };

                if target_layer == source_layer
                    || allowed_deps(source_layer).contains(&target_layer)
                {
                    continue;
                }

                violations.push(Violation::new(
                    "反向导入",
                    &rel_path,
                    &target,
                    0,
                    format!(
                        "分层 '{}' 引用了分层 '{}'（允许: {:?}）",
                        source_layer,
                        target_layer,
                        allowed_deps(source_layer)
                    ),
                ));
            }
        }

        let is_entry = ENTRY_FILES.iter().any(|file| rel_path == *file);
        let syntax = match syn::parse_file(&content) {
            Ok(syntax) => syntax,
            Err(_) => continue,
        };

        let mut danger_visitor = DangerVisitor {
            file: rel_path.clone(),
            is_entry,
            violations: Vec::new(),
        };
        danger_visitor.visit_file(&syntax);
        violations.extend(danger_visitor.violations);

        let mut swallow_visitor = SwallowVisitor {
            file: rel_path.clone(),
            violations: Vec::new(),
        };
        swallow_visitor.visit_file(&syntax);
        violations.extend(swallow_visitor.violations);
    }

    let output_regex = Regex::new(
        r"\b(printf|fprintf|OutputDebugStringA|OutputDebugStringW|OutputDebugString)\s*\(",
    )
    .expect("C 输出函数正则必须有效");
    for entry in WalkDir::new(&c_src)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|ext| ext == "c")
                .unwrap_or(false)
        })
    {
        let rel_path = normalized_rel(entry.path(), &project_root);
        let content = match std::fs::read_to_string(entry.path()) {
            Ok(content) => content,
            Err(_) => continue,
        };
        let sanitized = strip_c_comments_and_literals(&content);
        for (line_index, line) in sanitized.lines().enumerate() {
            for capture in output_regex.captures_iter(line) {
                let function = capture.get(1).map(|m| m.as_str()).unwrap_or("printf");
                violations.push(Violation::new(
                    "C输出函数",
                    &rel_path,
                    function,
                    line_index + 1,
                    format!("C 文件包含 {} 输出函数", function),
                ));
            }
        }
    }

    if let Some(path) = &write_baseline_path {
        let old = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| parse_baseline(&text).ok())
            .unwrap_or_default();
        let body = render_baseline(&violations);
        if let Err(error) = std::fs::write(path, body) {
            eprintln!("写入基线失败: {error}");
            return ExitCode::from(2);
        }
        let new = parse_baseline(&render_baseline(&violations)).unwrap_or_default();
        let added: Vec<&String> = new.keys().filter(|key| !old.contains_key(*key)).collect();
        let removed: Vec<&String> = old.keys().filter(|key| !new.contains_key(*key)).collect();
        println!("基线已写入 {path}：{} 条 ERROR", violations.len());
        if !added.is_empty() {
            println!("新增豁免 {} 条：", added.len());
            for key in added {
                println!("  + {key}");
            }
        }
        if !removed.is_empty() {
            println!("移除豁免 {} 条：", removed.len());
            for key in removed {
                println!("  - {key}");
            }
        }
        return ExitCode::SUCCESS;
    }

    let baseline = match &baseline_path {
        Some(path) => match load_baseline(Path::new(path)) {
            Ok(baseline) => baseline,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::from(2);
            }
        },
        None => Baseline::new(),
    };

    let (remaining, stale, exempted) = apply_baseline(violations, &baseline);

    if !remaining.is_empty() {
        println!(
            "\n发现 {} 个违规（基线豁免 {} 条）：\n",
            remaining.len(),
            exempted
        );
        for violation in &remaining {
            println!(
                "[ERROR] {} {}:{} - {} ({})",
                violation.category,
                violation.file,
                violation.line,
                violation.message,
                violation.detail
            );
        }
    }

    if !stale.is_empty() {
        println!("\n基线包含 {} 条已不存在的豁免（STALE）：", stale.len());
        for entry in &stale {
            println!("  [STALE] {entry}");
        }
        println!("请运行 --write-baseline 重写基线，并在评审中确认移除项");
    }

    println!("\n{}", "=".repeat(60));
    println!(
        "第二级扫描完成：{} 错误, {} 条基线豁免",
        remaining.len(),
        exempted
    );

    if !remaining.is_empty() || !stale.is_empty() {
        println!("构建失败：存在架构红线违规或过期基线");
        return ExitCode::from(1);
    }

    println!("AST 深度分析通过，无架构红线违规。");
    ExitCode::from(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_use_targets(source: &str) -> BTreeSet<String> {
        let syntax = syn::parse_file(source).expect("fixture 必须可解析");
        let mut visitor = UseVisitor {
            targets: BTreeSet::new(),
        };
        visitor.visit_file(&syntax);
        visitor.targets
    }

    #[test]
    fn use_tree_collects_grouped_nested_and_glob_targets() {
        let targets = collect_use_targets(
            r#"
            use crate::state::AppState;
            use crate::controller::types::{VerthysResponse, VerthysRecordEntry};
            use crate::{security::module_whitelist::verify_signature, util::base64::*};
            use crate::worker;
            use std::collections::HashMap;
            "#,
        );
        assert!(targets.contains("state"));
        assert!(targets.contains("controller"));
        assert!(targets.contains("security"));
        assert!(targets.contains("util"));
        assert!(targets.contains("worker"));
        assert!(!targets.contains("std"));
    }

    #[test]
    fn path_visitor_collects_inline_crate_paths() {
        let syntax = syn::parse_file(
            r#"
            fn demo(state: tauri::State<'_, crate::state::AppState>) {
                let _ = crate::worker::kill_orphan_workers();
            }
            "#,
        )
        .expect("fixture 必须可解析");
        let mut visitor = PathUseVisitor {
            targets: BTreeSet::new(),
        };
        visitor.visit_file(&syntax);
        assert!(visitor.targets.contains("state"));
        assert!(visitor.targets.contains("worker"));
    }

    #[test]
    fn c_comments_and_strings_do_not_trigger_output_rules() {
        let source = r#"
            /* 注释里的 printf( 不算调用 */
            // OutputDebugStringA("注释")
            static const char *text = "printf( in string";
            void real(void) { OutputDebugStringA("hit"); }
        "#;
        let sanitized = strip_c_comments_and_literals(source);
        let regex = Regex::new(
            r"\b(printf|fprintf|OutputDebugStringA|OutputDebugStringW|OutputDebugString)\s*\(",
        )
        .unwrap();
        let hits: Vec<&str> = regex
            .captures_iter(&sanitized)
            .filter_map(|capture| capture.get(1).map(|m| m.as_str()))
            .collect();
        assert_eq!(hits, vec!["OutputDebugStringA"]);
    }

    #[test]
    fn layer_contract_maps_adapters_and_forbids_upward_edges() {
        assert_eq!(layer_for_path("controller/a.rs"), Some("controller"));
        assert_eq!(layer_for_path("security_commands/a.rs"), Some("controller"));
        assert_eq!(layer_for_path("updater/a.rs"), Some("controller"));
        assert_eq!(layer_for_path("worker/a.rs"), Some("infrastructure"));
        assert_eq!(layer_for_path("devfixture/mod.rs"), Some("infrastructure"));
        assert_eq!(layer_for_path("state/a.rs"), Some("state"));
        assert!(allowed_deps("controller").contains(&"state"));
        assert!(allowed_deps("security").contains(&"state"));
        assert!(!allowed_deps("state").contains(&"controller"));
        assert!(!allowed_deps("util").contains(&"service"));
    }

    #[test]
    fn baseline_key_is_line_independent() {
        let first = Violation::new("反向导入", "controller/a.rs", "state", 10, "x");
        let second = Violation::new("反向导入", "controller/a.rs", "state", 99, "x");
        assert_eq!(first.key(), second.key());
    }

    #[test]
    fn baseline_parser_rejects_malformed_entries() {
        assert!(parse_baseline("# header\n反向导入|controller/a.rs|state|1\n").is_ok());
        assert!(parse_baseline("反向导入|controller/a.rs\n").is_err());
        assert!(parse_baseline("反向导入|controller/a.rs|state|x\n").is_err());
    }

    #[test]
    fn swallow_rule_only_flags_wildcard_error_payloads() {
        let syntax = syn::parse_file(
            r#"
            fn demo() {
                match 1 {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {}
                    Err(_) => {}
                    Err(_) => { log::warn!("handled"); return None; }
                }
            }
            "#,
        )
        .expect("fixture 必须可解析");
        let mut visitor = SwallowVisitor {
            file: "demo.rs".to_string(),
            violations: Vec::new(),
        };
        visitor.visit_file(&syntax);
        assert_eq!(visitor.violations.len(), 1);
        assert_eq!(visitor.violations[0].detail, "Err");
    }

    #[test]
    fn baseline_detects_stale_entries_and_extra_occurrences() {
        let mut baseline = Baseline::new();
        baseline.insert("反向导入|controller/a.rs|state".to_string(), 1);
        baseline.insert("反向导入|controller/b.rs|util".to_string(), 1);

        let violations = vec![
            Violation::new("反向导入", "controller/a.rs", "state", 1, "x"),
            Violation::new("反向导入", "controller/a.rs", "state", 2, "x"),
        ];
        let (remaining, stale, exempted) = apply_baseline(violations, &baseline);
        assert_eq!(exempted, 1);
        assert_eq!(remaining.len(), 1);
        assert_eq!(stale.len(), 1);
        assert!(stale[0].contains("controller/b.rs"));
    }
}
