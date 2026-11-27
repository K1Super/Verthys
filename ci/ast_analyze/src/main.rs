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
 * 模块划分：
 *   - layers      分层映射与允许依赖表
 *   - violation   违规模型与基线治理
 *   - rust_rules  Rust AST 规则（依赖提取 / 危险调用 / 吞异常）
 *   - c_scan      C 源码去注释与路径归一化
 *   - tests       规则与基线契约
 *
 * 基线治理：
 *   - 指纹 = 类别|相对路径|目标（模块/函数），不含行号
 *   - 同一指纹按出现次数计数，新增次数仍阻断
 *   - 基线条目不再出现时判为 STALE 并阻断，防止豁免腐烂
 *   - --write-baseline 重写前打印与旧基线的增删差异，便于评审
 */
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use regex::Regex;
use syn::visit::Visit;
use walkdir::WalkDir;

mod c_scan;
mod layers;
mod rust_rules;
mod violation;

#[cfg(test)]
mod tests;

use c_scan::{normalized_rel, strip_c_comments_and_literals};
use layers::{allowed_deps, layer_for_module, layer_for_path, ENTRY_FILES};
use rust_rules::{DangerVisitor, PathUseVisitor, SwallowVisitor, UseVisitor};
use violation::{
    apply_baseline, load_baseline, parse_baseline, render_baseline, Baseline, Violation,
};

const RUST_SRC_DIR: &str = "verthys-tauri/src-tauri/src";
const C_SRC_DIR: &str = "core/src";

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
