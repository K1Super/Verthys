/*
 * tests.rs — AST 规则与基线治理契约
 */
use std::collections::BTreeSet;

use regex::Regex;
use syn::visit::Visit;

use crate::c_scan::strip_c_comments_and_literals;
use crate::layers::{allowed_deps, layer_for_path};
use crate::rust_rules::{PathUseVisitor, SwallowVisitor, UseVisitor};
use crate::violation::{apply_baseline, parse_baseline, Baseline, Violation};

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
