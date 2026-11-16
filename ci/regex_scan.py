#!/usr/bin/env python3
"""
regex_scan.py — CI 第一级：快速文本过滤

目标 < 0.5 秒，作为第二级 AST 的廉价前哨：
1. 入口文件是否出现底层 I/O / 加解密关键词
2. Rust 源码是否直接写 stdout/stderr（println!/eprintln!）
3. C 源码是否直接调用 printf/fprintf/OutputDebugString

治理原则：
- 注释与字符串不参与判定，避免文档说明触发告警
- #[cfg(test)] 模块整体屏蔽，测试代码的调试输出不算生产输出
- 依赖方向由第二级 AST 统一判定，本层不再重复实现
- 输出函数使用词边界，避免 println! 命中 eprintln!
"""

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
RUST_MAIN_SRC = PROJECT_ROOT / "verthys-tauri" / "src-tauri" / "src"
WORKER_SRC = PROJECT_ROOT / "verthys-tauri" / "verthys-worker" / "src"

RUST_SCAN_ROOTS = [RUST_MAIN_SRC, WORKER_SRC]
RUST_SCAN_FILES = [PROJECT_ROOT / "verthys-tauri" / "shm_schema.rs"]
C_SRC = PROJECT_ROOT / "core" / "src"

ENTRY_FILES = ["main.rs", "lib.rs", "entry_template.rs"]
ENTRY_DANGER_KEYWORDS = [
    r"\bencrypt\b",
    r"\bdecrypt\b",
    r"\bfs::read\b",
    r"\bfs::write\b",
    r"\bstd::fs::",
    r"\bBCrypt",
    r"\bCreateFile",
]

OUTPUT_PATTERNS = [
    (r"\bprintln!\s*\(", "println!"),
    (r"\beprintln!\s*\(", "eprintln!"),
]

C_OUTPUT_PATTERNS = [
    (r"\bprintf\s*\(", "printf"),
    (r"\bfprintf\s*\(", "fprintf"),
    (r"\bOutputDebugString", "OutputDebugString"),
]

# 主进程允许直接写 stdout/stderr 的文件（相对 RUST_MAIN_SRC）
# - lib.rs / main.rs：日志系统初始化之前的早期致命错误
# - infrastructure/log_pipe.rs：日志消费者落盘失败兜底
# - middleware/panic_hook.rs：panic 钩子构造诊断
# - infrastructure/resource_guard.rs：启动期资源完整性校验，日志系统尚未初始化
# - updater/log.rs：更新日志落盘失败兜底
ALLOWED_MAIN_OUTPUT_FILES = {
    "lib.rs",
    "main.rs",
    "entry_template.rs",
    "infrastructure/log_pipe.rs",
    "middleware/panic_hook.rs",
    "infrastructure/resource_guard.rs",
    "updater/log.rs",
}

# worker 的 stderr 是父进程采集的诊断通道；仅日志基础设施与入口允许直接输出
ALLOWED_WORKER_OUTPUT_FILES = {
    "log.rs",
    "main.rs",
}

warnings = []


def _blank_preserving_newlines(chars, start, end):
    """把 `chars[start:end]` 替换为空格，保留换行以维持行号。"""
    for index in range(start, end):
        if chars[index] != "\n":
            chars[index] = " "


def strip_rust_noise(source: str) -> str:
    """剥离 Rust 注释、字符串、字符与 raw string，保留换行。"""
    chars = list(source)
    length = len(chars)
    index = 0
    while index < length:
        current = chars[index]
        nxt = chars[index + 1] if index + 1 < length else ""

        if current == "/" and nxt == "/":
            end = source.find("\n", index)
            end = length if end == -1 else end
            _blank_preserving_newlines(chars, index, end)
            index = end
            continue

        if current == "/" and nxt == "*":
            depth = 1
            cursor = index + 2
            while cursor < length and depth > 0:
                if chars[cursor] == "/" and cursor + 1 < length and chars[cursor + 1] == "*":
                    depth += 1
                    cursor += 2
                elif chars[cursor] == "*" and cursor + 1 < length and chars[cursor + 1] == "/":
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            _blank_preserving_newlines(chars, index, cursor)
            index = cursor
            continue

        # raw string：r"..." / r#"..."# / br#"..."#
        raw_prefix = None
        if current == "r":
            raw_prefix = index
        elif current == "b" and nxt == "r":
            raw_prefix = index
        if raw_prefix is not None:
            cursor = raw_prefix + (1 if chars[raw_prefix] == "r" else 2)
            hashes = 0
            while cursor < length and chars[cursor] == "#":
                hashes += 1
                cursor += 1
            if cursor < length and chars[cursor] == '"':
                terminator = '"' + "#" * hashes
                end = source.find(terminator, cursor + 1)
                end = length if end == -1 else end + len(terminator)
                _blank_preserving_newlines(chars, index, end)
                index = end
                continue

        if current == '"' or (current == "b" and nxt == '"'):
            start = index
            cursor = index + (2 if current == "b" else 1)
            while cursor < length:
                if chars[cursor] == "\\":
                    cursor += 2
                elif chars[cursor] == '"':
                    cursor += 1
                    break
                else:
                    cursor += 1
            _blank_preserving_newlines(chars, start, cursor)
            index = cursor
            continue

        if current == "'":
            # 字符字面量：'a' / '\n'；生命周期 'a 不含结束引号，遇到换行即放弃
            cursor = index + 1
            while cursor < length and chars[cursor] != "\n":
                if chars[cursor] == "\\":
                    cursor += 2
                elif chars[cursor] == "'":
                    cursor += 1
                    break
                else:
                    cursor += 1
            if cursor <= length and cursor > index + 1 and chars[cursor - 1] == "'":
                _blank_preserving_newlines(chars, index, cursor)
                index = cursor
                continue

        index += 1
    return "".join(chars)


def mask_cfg_test(source: str) -> str:
    """屏蔽 #[cfg(test)] 修饰的模块/函数体，避免测试代码触发生产输出规则。"""
    chars = list(source)
    pattern = re.compile(r"#\s*\[\s*cfg\s*\(\s*test")
    for match in pattern.finditer(source):
        brace = source.find("{", match.end())
        if brace == -1:
            continue
        depth = 0
        cursor = brace
        while cursor < len(source):
            if source[cursor] == "{":
                depth += 1
            elif source[cursor] == "}":
                depth -= 1
                if depth == 0:
                    cursor += 1
                    break
            cursor += 1
        _blank_preserving_newlines(chars, match.start(), cursor)
    return "".join(chars)


def sanitize_rust(source: str) -> str:
    return mask_cfg_test(strip_rust_noise(source))


def strip_c_noise(source: str) -> str:
    """剥离 C 注释、字符串与字符字面量，保留换行。"""
    chars = list(source)
    length = len(chars)
    index = 0
    state = 0  # 0=normal 1=line comment 2=block comment 3=string 4=char

    while index < length:
        current = chars[index]
        nxt = chars[index + 1] if index + 1 < length else ""
        if state == 0:
            if current == "/" and nxt == "/":
                state = 1
                _blank_preserving_newlines(chars, index, index + 2)
                index += 2
            elif current == "/" and nxt == "*":
                state = 2
                _blank_preserving_newlines(chars, index, index + 2)
                index += 2
            elif current == '"':
                state = 3
                _blank_preserving_newlines(chars, index, index + 1)
                index += 1
            elif current == "'":
                state = 4
                _blank_preserving_newlines(chars, index, index + 1)
                index += 1
            else:
                index += 1
        elif state == 1:
            if current == "\n":
                state = 0
            else:
                _blank_preserving_newlines(chars, index, index + 1)
            index += 1
        elif state == 2:
            if current == "*" and nxt == "/":
                _blank_preserving_newlines(chars, index, index + 2)
                state = 0
                index += 2
            else:
                _blank_preserving_newlines(chars, index, index + 1)
                index += 1
        elif state == 3:
            if current == "\\" and nxt:
                _blank_preserving_newlines(chars, index, index + 2)
                index += 2
            elif current == '"':
                _blank_preserving_newlines(chars, index, index + 1)
                state = 0
                index += 1
            else:
                _blank_preserving_newlines(chars, index, index + 1)
                index += 1
        else:
            if current == "\\" and nxt:
                _blank_preserving_newlines(chars, index, index + 2)
                index += 2
            elif current == "'":
                _blank_preserving_newlines(chars, index, index + 1)
                state = 0
                index += 1
            else:
                _blank_preserving_newlines(chars, index, index + 1)
                index += 1

    return "".join(chars)


def relative_posix(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def scan_text(rel_path: str, content: str, patterns, category: str):
    for pattern, label in patterns:
        for match in re.finditer(pattern, content):
            line_num = content[: match.start()].count("\n") + 1
            warnings.append(f"[WARN] {category}: {rel_path}:{line_num} - 发现 \"{label}\"")


def scan_file(filepath: Path, patterns, category: str):
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return
    rel_path = relative_posix(filepath, PROJECT_ROOT)
    scan_text(rel_path, content, patterns, category)


def scan_entry_files():
    for entry_file in ENTRY_FILES:
        filepath = RUST_MAIN_SRC / entry_file
        if filepath.exists():
            try:
                content = sanitize_rust(filepath.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            scan_text(
                relative_posix(filepath, PROJECT_ROOT),
                content,
                [(pattern, pattern) for pattern in ENTRY_DANGER_KEYWORDS],
                "入口文件危险关键词",
            )


def scan_rust_output():
    for root in RUST_SCAN_ROOTS:
        for filepath in root.rglob("*.rs"):
            if filepath.name == "build.rs":
                continue
            rel_to_root = relative_posix(filepath, root)
            if root == RUST_MAIN_SRC:
                if rel_to_root in ALLOWED_MAIN_OUTPUT_FILES:
                    continue
            elif root == WORKER_SRC:
                if rel_to_root in ALLOWED_WORKER_OUTPUT_FILES:
                    continue
            try:
                content = sanitize_rust(filepath.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            scan_text(
                relative_posix(filepath, PROJECT_ROOT),
                content,
                OUTPUT_PATTERNS,
                "Rust输出函数",
            )
    for filepath in RUST_SCAN_FILES:
        if filepath.exists():
            try:
                content = sanitize_rust(filepath.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            scan_text(
                relative_posix(filepath, PROJECT_ROOT),
                content,
                OUTPUT_PATTERNS,
                "Rust输出函数",
            )


def scan_c_output():
    for filepath in C_SRC.rglob("*.c"):
        try:
            content = strip_c_noise(filepath.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        scan_text(
            relative_posix(filepath, PROJECT_ROOT),
            content,
            C_OUTPUT_PATTERNS,
            "C输出函数",
        )


def self_test() -> bool:
    failures = []
    noisy = "// println!(\"comment\")\nlet s = \"eprintln!(x)\";\neprintln!(\"real\");\n"
    cleaned = strip_rust_noise(noisy)
    if "// println!" in cleaned or '"eprintln!(x)"' in cleaned:
        failures.append("Rust 注释/字符串剥离失败")
    if "eprintln!(" not in cleaned:
        failures.append("Rust 真实输出被误剥离")
    if cleaned.count("\n") != noisy.count("\n"):
        failures.append("Rust 剥离未保留行号")

    test_module = "#[cfg(test)]\nmod tests {\n    fn demo() { eprintln!(\"test\"); }\n}\nfn prod() { eprintln!(\"prod\"); }\n"
    masked = mask_cfg_test(test_module)
    if "eprintln!(\"test\")" in masked:
        failures.append("#[cfg(test)] 模块未被屏蔽")
    if "eprintln!(\"prod\")" not in masked:
        failures.append("生产代码被误屏蔽")

    c_source = "/* printf(comment) */\nconst char *s = \"fprintf(str)\";\nvoid f(void) { OutputDebugStringA(\"x\"); }\n"
    c_clean = strip_c_noise(c_source)
    if "printf(comment)" in c_clean or "fprintf(str)" in c_clean:
        failures.append("C 注释/字符串剥离失败")
    if "OutputDebugStringA" not in c_clean:
        failures.append("C 真实输出被误剥离")

    println_pattern = re.compile(OUTPUT_PATTERNS[0][0])
    if println_pattern.search("eprintln!(\"x\")"):
        failures.append("println! 模式命中 eprintln!")

    if failures:
        for failure in failures:
            print(f"[SELFTEST-FAIL] {failure}")
        return False
    print("[SELFTEST] 通过：注释/字符串剥离、cfg(test) 屏蔽、词边界均符合预期")
    return True


def main():
    if "--self-test" in sys.argv:
        sys.exit(0 if self_test() else 1)

    print("=" * 60)
    print("CI 第一级：快速文本过滤")
    print("=" * 60)

    scan_entry_files()
    scan_rust_output()
    scan_c_output()

    if warnings:
        print(f"\n发现 {len(warnings)} 个警告：\n")
        for warning in warnings:
            print(warning)
        print(f"\n{'=' * 60}")
        print(f"第一级扫描完成：{len(warnings)} 个警告")
        print("注意：此阶段仅输出警告，不阻断构建。")
    else:
        print(f"\n{'=' * 60}")
        print("第一级扫描完成：无警告")

    # 第一级不阻断构建（返回 0）；--self-test 失败时才返回 1
    sys.exit(0)


if __name__ == "__main__":
    main()
