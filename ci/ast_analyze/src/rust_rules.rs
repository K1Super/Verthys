/*
 * rust_rules.rs — Rust AST 规则：依赖提取、入口危险调用、吞异常检测
 *
 * 依赖提取同时覆盖 use 树与行内 crate:: 路径，二者取并集；
 * 吞异常只审查通配错误载荷（Err(_) / Err(..)），结构化变体分支不据此判定。
 */
use std::collections::BTreeSet;

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::violation::Violation;

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

pub(crate) fn collect_use_tree(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    out: &mut BTreeSet<String>,
) {
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

pub(crate) struct UseVisitor {
    pub(crate) targets: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for UseVisitor {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let mut prefix = Vec::new();
        collect_use_tree(&node.tree, &mut prefix, &mut self.targets);
        syn::visit::visit_item_use(self, node);
    }
}

pub(crate) struct PathUseVisitor {
    pub(crate) targets: BTreeSet<String>,
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

pub(crate) struct DangerVisitor {
    pub(crate) file: String,
    pub(crate) is_entry: bool,
    pub(crate) violations: Vec<Violation>,
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

pub(crate) struct SwallowVisitor {
    pub(crate) file: String,
    pub(crate) violations: Vec<Violation>,
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
