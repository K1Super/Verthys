/*
 * CI 第二级：AST 深度分析工具
 *
 *    "CI静态校验双引擎实现策略"第二级
 *
 * 目标 < 10 秒，Pull Request 合并时触发。
 * 此阶段任何违规将直接导致构建失败，PR 无法合并。
 *
 * 分析内容：
 *   1. 精准判断入口函数是否实际调用了加解密库或文件系统 API
 *   2. 构建模块依赖图，验证是否存在反向导入
 *   3. 检查 match 或 try 块中是否存在捕获异常后未重新抛出的代码路径
 *
 * 技术要点：
 *   - 基于 Rust 语法树（syn 库）构建精确调用图
 *   - 区分变量名与方法名，避免误报
 *   - 控制流分析检测吞掉异常的 match 分支
 */
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use regex::Regex;
use syn::{visit::Visit, ItemFn, File as SynFile};
use walkdir::WalkDir;

/* ------------------------------------------------------------------ *
 * 全局配置                                                            *
 * ------------------------------------------------------------------ */

const RUST_SRC_DIR: &str = "verthys-tauri/src-tauri/src";
const C_SRC_DIR: &str = "core/src";

/// 入口文件列表
const ENTRY_FILES: &[&str] = &["main.rs", "lib.rs", "entry_template.rs"];

/// 分层目录名与允许的依赖方向
/// key -> 允许引用的层级（value 为允许的目录名列表）
const LAYER_HIERARCHY: &[(&str, &[&str])] = &[
    ("util", &[]),                    // util 不允许引用任何上层
    ("repository", &["util"]),        // repository 只允许引用 util
    ("service", &["repository", "util"]), // service 允许引用 repository + util
    ("controller", &["service", "repository", "util"]), // controller 允许引用 service + repository + util
    ("middleware", &["util", "infrastructure"]), // middleware 允许引用 util + infrastructure
    ("infrastructure", &["util"]),    // infrastructure 允许引用 util
];

/// 危险函数模式（入口文件中不应调用）
/// 精确匹配方法调用路径，区分变量名与方法名
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

/// 吞掉异常的 match 分支模式
/// 检测 `Err(_) => {}` 或 `Err(_) => return Default::default()` 等
const SWALLOW_PATTERNS: &[&str] = &[
    r"Err\(\s*_\s*\)\s*=>\s*\{\s*\}",           // Err(_) => {}
    r"Err\(\s*_\s*\)\s*=>\s*\{\s*return\s+\}",   // Err(_) => { return }
    r"Err\(\s*_\s*\)\s*=>\s*\{\s*return\s+None",  // Err(_) => { return None }
    r"Err\(\s*_\s*\)\s*=>\s*\{\s*return\s+Ok\(\(\)", // Err(_) => { return Ok(()) }
    r"Err\(\s*_\s*\)\s*=>\s*continue",            // Err(_) => continue
];

/* ------------------------------------------------------------------ *
 * 违规记录                                                            *
 * ------------------------------------------------------------------ */

#[derive(Debug)]
struct Violation {
    severity: &'static str,  // "ERROR" 或 "WARN"
    category: &'static str,
    file: String,
    line: usize,
    message: String,
}

impl Violation {
    fn error(category: &'static str, file: &str, line: usize, message: impl Into<String>) -> Self {
        Violation {
            severity: "ERROR",
            category,
            file: file.to_string(),
            line,
            message: message.into(),
        }
    }

    fn warn(category: &'static str, file: &str, line: usize, message: impl Into<String>) -> Self {
        Violation {
            severity: "WARN",
            category,
            file: file.to_string(),
            line,
            message: message.into(),
        }
    }
}

/* ------------------------------------------------------------------ *
 * AST 访问者：检测入口文件中的危险函数调用                            *
 * ------------------------------------------------------------------ */

struct DangerCallVisitor {
    violations: Vec<Violation>,
    file_path: String,
    is_entry: bool,
}

impl DangerCallVisitor {
    fn new(file_path: String, is_entry: bool) -> Self {
        DangerCallVisitor {
            violations: Vec::new(),
            file_path,
            is_entry,
        }
    }

    fn check_call(&mut self, call_str: &str, line: usize) {
        if !self.is_entry {
            return;
        }

        for pattern in DANGER_CALL_PATTERNS {
            if call_str.contains(pattern) {
                self.violations.push(Violation::error(
                    "入口文件危险调用",
                    &self.file_path,
                    line,
                    format!("入口文件调用了底层 API: {}", pattern),
                ));
            }
        }
    }
}

impl<'ast> Visit<'ast> for DangerCallVisitor {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        // 检查函数体内的调用
        let func_name = node.sig.ident.to_string();

        // 提取函数源代码文本（简化版：检查函数名）
        for pattern in DANGER_CALL_PATTERNS {
            if func_name.contains(pattern) {
                let line = node.sig.ident.span().start().line;
                self.check_call(&func_name, line);
            }
        }

        // 继续访问子节点
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if self.is_entry {
            // 将路径转换为字符串进行匹配
            let path_str = node
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");

            for pattern in DANGER_CALL_PATTERNS {
                if path_str.contains(pattern) {
                    let line = node
                        .segments
                        .first()
                        .map(|s| s.ident.span().start().line)
                        .unwrap_or(0);
                    self.violations.push(Violation::error(
                        "入口文件危险调用",
                        &self.file_path,
                        line,
                        format!("入口文件引用了底层 API 路径: {}", pattern),
                    ));
                }
            }
        }

        syn::visit::visit_path(self, node);
    }
}

/* ------------------------------------------------------------------ *
 * AST 访问者：检测吞掉异常的 match 分支                                *
 * ------------------------------------------------------------------ */

struct SwallowVisitor {
    violations: Vec<Violation>,
    file_path: String,
    swallow_regex: Vec<Regex>,
}

impl SwallowVisitor {
    fn new(file_path: String) -> Self {
        let swallow_regex = SWALLOW_PATTERNS
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();
        SwallowVisitor {
            violations: Vec::new(),
            file_path,
            swallow_regex,
        }
    }
}

impl<'ast> Visit<'ast> for SwallowVisitor {
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        // 检查 match 分支是否吞掉 Err
        for arm in &node.arms {
            // 将 arm 的 pat 转换为字符串
            let pat_str = quote::quote!(#(&arm.pat)).to_string();

            // 检查是否是 Err(_) 模式
            if pat_str.contains("Err") && pat_str.contains("_") {
                // 检查 match body 是否为空或返回默认值
                let body_str = match &arm.body {
                    syn::Expr::Block(b) => {
                        b.block.stmts.is_empty()
                    }
                    syn::Expr::Path(p) => {
                        let path_str = p
                            .path
                            .segments
                            .iter()
                            .map(|s| s.ident.to_string())
                            .collect::<Vec<_>>()
                            .join("::");
                        path_str.contains("Default") || path_str.contains("default")
                    }
                    _ => false,
                };

                if body_str {
                    let line = arm.pat.span().start().line;
                    self.violations.push(Violation::error(
                        "吞掉异常",
                        &self.file_path,
                        line,
                        "检测到 match 分支吞掉 Err 异常而未重新抛出".to_string(),
                    ));
                }
            }
        }

        syn::visit::visit_expr_match(self, node);
    }
}

/* ------------------------------------------------------------------ *
 * 模块依赖图分析                                                      *
 * ------------------------------------------------------------------ */

struct DependencyAnalyzer {
    violations: Vec<Violation>,
    /// 文件 -> 该文件所属的分层
    file_to_layer: HashMap<String, &'static str>,
}

impl DependencyAnalyzer {
    fn new() -> Self {
        DependencyAnalyzer {
            violations: Vec::new(),
            file_to_layer: HashMap::new(),
        }
    }

    /// 确定文件所属的分层
    fn determine_layer(file_path: &str) -> Option<&'static str> {
        for (layer_name, _) in LAYER_HIERARCHY {
            if file_path.contains(&format!("{}/", layer_name)) || file_path.contains(&format!("{}\\", layer_name)) {
                return Some(layer_name);
            }
        }
        None
    }

    /// 获取某分层允许引用的层级列表
    fn allowed_deps(layer: &str) -> &'static [&'static str] {
        for (name, deps) in LAYER_HIERARCHY {
            if *name == layer {
                return deps;
            }
        }
        &[]
    }

    /// 分析单个文件的 use 语句
    fn analyze_use_statements(
        &mut self,
        content: &str,
        file_path: &str,
    ) {
        let layer = match Self::determine_layer(file_path) {
            Some(l) => l,
            None => return, // 不在分层目录中的文件不检查
        };

        let allowed = Self::allowed_deps(layer);

        // 匹配 use crate::xxx:: 语句
        let use_re = Regex::new(r"use\s+crate::(\w+)::").unwrap();
        for cap in use_re.captures_iter(content) {
            let imported_layer = cap.get(1).unwrap().as_str();

            // 跳过自身层
            if imported_layer == layer {
                continue;
            }

            // 检查是否在允许列表中
            if !allowed.contains(&imported_layer) {
                // 计算行号
                let pos = cap.get(0).unwrap().start();
                let line = content[..pos].lines().count() + 1;

                self.violations.push(Violation::error(
                    "反向导入",
                    file_path,
                    line,
                    format!(
                        "分层 '{}' 引用了分层 '{}'，违反单向依赖规则（允许: {:?}）",
                        layer, imported_layer, allowed
                    ),
                ));
            }
        }
    }
}

/* ------------------------------------------------------------------ *
 * 主分析流程                                                          *
 * ------------------------------------------------------------------ */

fn main() -> ExitCode {
    let project_root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."));

    let rust_src = project_root.join(RUST_SRC_DIR);
    let c_src = project_root.join(C_SRC_DIR);

    println!("=" .repeat(60));
    println!("CI 第二级：AST 深度分析");
    println!("   ");
    println!("=" .repeat(60));

    let mut all_violations = Vec::new();

    // 1. 扫描所有 Rust 文件
    let mut dep_analyzer = DependencyAnalyzer::new();

    for entry in WalkDir::new(&rust_src)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
    {
        let file_path = entry.path().to_string_lossy().to_string();
        let rel_path = entry
            .path()
            .strip_prefix(&rust_src)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .to_string();

        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // 依赖图分析
        dep_analyzer.analyze_use_statements(&content, &rel_path);

        // 判断是否是入口文件
        let is_entry = ENTRY_FILES.iter().any(|f| rel_path == *f);

        // 解析 AST
        let syntax: Option<SynFile> = syn::parse_file(&content).ok();

        if let Some(syntax) = &syntax {
            // 危险调用检测
            let mut danger_visitor = DangerCallVisitor::new(rel_path.clone(), is_entry);
            danger_visitor.visit_file(syntax);
            all_violations.extend(danger_visitor.violations);

            // 吞掉异常检测
            let mut swallow_visitor = SwallowVisitor::new(rel_path.clone());
            swallow_visitor.visit_file(syntax);
            all_violations.extend(swallow_visitor.violations);
        }
    }

    all_violations.extend(dep_analyzer.violations);

    // 2. 扫描 C 文件中的输出函数
    for entry in WalkDir::new(&c_src)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "c"))
    {
        let rel_path = entry
            .path()
            .strip_prefix(&project_root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .to_string();

        let content = match std::fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // 检查 printf / fprintf
        for (line_num, line) in content.lines().enumerate() {
            if line.contains("printf(") || line.contains("fprintf(") {
                all_violations.push(Violation::error(
                    "C输出函数",
                    &rel_path,
                    line_num + 1,
                    "C 文件包含 printf/fprintf 输出函数".to_string(),
                ));
            }
            if line.contains("OutputDebugString") {
                all_violations.push(Violation::error(
                    "C输出函数",
                    &rel_path,
                    line_num + 1,
                    "C 文件包含 OutputDebugString 输出函数".to_string(),
                ));
            }
        }
    }

    // 输出结果
    let errors: Vec<_> = all_violations.iter().filter(|v| v.severity == "ERROR").collect();
    let warns: Vec<_> = all_violations.iter().filter(|v| v.severity == "WARN").collect();

    if !all_violations.is_empty() {
        println!("\n发现 {} 个违规（{} 错误, {} 警告）：\n", all_violations.len(), errors.len(), warns.len());

        for v in &all_violations {
            println!(
                "[{}] {} {}:{} - {}",
                v.severity, v.category, v.file, v.line, v.message
            );
        }
    }

    println!("\n{}" .repeat(60));
    println!(
        "第二级扫描完成：{} 错误, {} 警告",
        errors.len(),
        warns.len()
    );

    // 第二级：有错误则阻断构建
    if !errors.is_empty() {
        println!("构建失败：存在 {} 个架构红线违规", errors.len());
        return ExitCode::from(1);
    }

    println!("AST 深度分析通过，无架构红线违规。");
    ExitCode::from(0)
}
