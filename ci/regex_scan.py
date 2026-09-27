#!/usr/bin/env python3
"""
regex_scan.py — CI 第一级：快速正则过滤
"CI静态校验双引擎实现策略"第一级

目标 < 0.5 秒，每次提交时触发。
此阶段仅输出警告，帮助开发者即时发现典型问题，但不强制阻断
（允许在修复后提交）。

扫描内容：
1. 入口文件是否包含危险关键词（encrypt、decrypt、fs::read、write）
2. Rust 源码是否包含 println!、eprintln!、log::*! 输出类函数调用
   （覆盖主进程 src-tauri/src、worker crate verthys-worker/src、
   根共享契约 shm_schema.rs 与 src-tauri/build.rs）
3. C 文件是否包含 printf / fprintf
4. 底层文件是否反向引用上层模块（use crate::controller / use crate::service）

扫描根目录列表化：任何 Rust 新增目录/根级敏感文件必须显式加入
RUST_SCAN_ROOTS / RUST_SCAN_FILES，防止"新增 crate 默认不被扫"的
覆盖盲区。
"""

import os
import re
import sys
from pathlib import Path

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.parent

# 主进程 Rust 源码目录（白名单 ALLOWED_OUTPUT_FILES 的相对基准）
RUST_MAIN_SRC = PROJECT_ROOT / "verthys-tauri" / "src-tauri" / "src"

# Rust 扫描根目录（递归扫描其中全部 .rs）
RUST_SCAN_ROOTS = [
    RUST_MAIN_SRC,                                             # 主进程逻辑
    PROJECT_ROOT / "verthys-tauri" / "verthys-worker" / "src",  # worker（协议/GMK 等敏感代码）
]

# Rust 扫描单文件（位于扫描根之外的同源契约与构建脚本）
RUST_SCAN_FILES = [
    PROJECT_ROOT / "verthys-tauri" / "shm_schema.rs",           # 主进程/worker 同源 SHM 契约
    PROJECT_ROOT / "verthys-tauri" / "src-tauri" / "build.rs",  # 构建脚本（素材门禁逻辑）
]

# C 源码目录
C_SRC = PROJECT_ROOT / "core" / "src"

# 入口文件（不应包含业务逻辑关键词）
ENTRY_FILES = ["main.rs", "lib.rs", "entry_template.rs"]

# 危险关键词（入口文件中不应出现）
ENTRY_DANGER_KEYWORDS = [
    r"\bencrypt\b",
    r"\bdecrypt\b",
    r"fs::read",
    r"fs::write",
    r"std::fs::",
    r"BCrypt",
    r"CreateFile",
]

# 输出类函数（全项目禁用，除入口层和特定允许文件）
OUTPUT_PATTERNS = [
    (r"println!\s*\(", "println!"),
    (r"eprintln!\s*\(", "eprintln!"),
    (r"log::(info|debug|warn|error|trace)!\s*\(", "log::*!"),
]

# C 输出函数
C_OUTPUT_PATTERNS = [
    (r"\bprintf\s*\(", "printf"),
    (r"\bfprintf\s*\(", "fprintf"),
    (r"OutputDebugString", "OutputDebugString"),
]

# 反向导入模式（底层引用上层）
REVERSE_IMPORT_PATTERNS = [
    # util 引用 controller/service/middleware
    (r"use\s+crate::(controller|service|middleware)::", "util/repository 反向引用上层"),
    # repository 引用 controller/service
    (r"use\s+crate::(controller|service)::", "repository 反向引用上层"),
    # service 引用 controller
    (r"use\s+crate::controller::", "service 反向引用 controller"),
]

# 允许使用 println!/eprintln! 的文件白名单（入口层日志消费者等）
ALLOWED_OUTPUT_FILES = {
    "infrastructure/log_pipe.rs",  # 日志消费者线程需要写文件
    "middleware/panic_hook.rs",     # panic 钩子需要构造日志
    "entry_template.rs",            # 入口模板
}

# 警告计数
warnings = []


def scan_file(filepath: Path, patterns, category: str, file_filter=None):
    """扫描单个文件，匹配所有模式"""
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return

    rel_path = filepath.relative_to(PROJECT_ROOT).as_posix() if filepath.is_relative_to(PROJECT_ROOT) else str(filepath)

    for pattern, label in patterns:
        for match in re.finditer(pattern, content):
            line_num = content[:match.start()].count("\n") + 1
            warnings.append(f"[WARN] {category}: {rel_path}:{line_num} - 发现 \"{label}\"")


def scan_entry_files():
    """扫描入口文件是否包含危险关键词"""
    for entry_file in ENTRY_FILES:
        filepath = RUST_MAIN_SRC / entry_file
        if filepath.exists():
            scan_file(filepath, [(p, p) for p in ENTRY_DANGER_KEYWORDS], "入口文件危险关键词")


def scan_rust_output():
    """扫描 Rust 文件中的输出类函数"""
    for root in RUST_SCAN_ROOTS:
        for filepath in root.rglob("*.rs"):
            # 跳过白名单文件（白名单键相对主进程 src 目录）
            if filepath.is_relative_to(RUST_MAIN_SRC):
                rel_path = filepath.relative_to(RUST_MAIN_SRC).as_posix()
                if rel_path in ALLOWED_OUTPUT_FILES:
                    continue
            scan_file(filepath, OUTPUT_PATTERNS, "Rust输出函数")
    for filepath in RUST_SCAN_FILES:
        if filepath.exists():
            scan_file(filepath, OUTPUT_PATTERNS, "Rust输出函数")


def scan_c_output():
    """扫描 C 文件中的输出类函数"""
    for filepath in C_SRC.rglob("*.c"):
        scan_file(filepath, C_OUTPUT_PATTERNS, "C输出函数")


def scan_reverse_imports():
    """扫描反向导入"""
    # 工具层文件不应引用上层
    util_dir = RUST_MAIN_SRC / "util"
    if util_dir.exists():
        for filepath in util_dir.rglob("*.rs"):
            scan_file(filepath, REVERSE_IMPORT_PATTERNS, "反向导入")

    # 持久层文件不应引用 controller/service
    repo_dir = RUST_MAIN_SRC / "repository"
    if repo_dir.exists():
        for filepath in repo_dir.rglob("*.rs"):
            # repository 可以引用 util，但不能引用 controller/service
            repo_patterns = [
                (r"use\s+crate::(controller|service)::", "repository反向引用上层"),
            ]
            scan_file(filepath, repo_patterns, "反向导入")

    # 服务层文件不应引用 controller
    service_dir = RUST_MAIN_SRC / "service"
    if service_dir.exists():
        for filepath in service_dir.rglob("*.rs"):
            service_patterns = [
                (r"use\s+crate::controller::", "service反向引用controller"),
            ]
            scan_file(filepath, service_patterns, "反向导入")


def main():
    """主扫描入口"""
    print("=" * 60)
    print("CI 第一级：快速正则过滤")
    print("=" * 60)

    scan_entry_files()
    scan_rust_output()
    scan_c_output()
    scan_reverse_imports()

    if warnings:
        print(f"\n发现 {len(warnings)} 个警告：\n")
        for w in warnings:
            print(w)
        print(f"\n{'=' * 60}")
        print(f"第一级扫描完成：{len(warnings)} 个警告")
        print("注意：此阶段仅输出警告，不强制阻断。")
        print("第二级 AST 深度分析将在 PR 合并时触发。")
    else:
        print(f"\n{'=' * 60}")
        print("第一级扫描完成：无警告")

    # 第一级不阻断构建（返回 0）
    sys.exit(0)


if __name__ == "__main__":
    main()
