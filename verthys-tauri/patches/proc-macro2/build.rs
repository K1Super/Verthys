#![allow(unknown_lints)]
#![allow(unexpected_cfgs)]
#![allow(clippy::uninlined_format_args)]

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::iter;
use std::path::Path;
use std::process::{self, Command, Stdio};
use std::str;

fn main() {
    let rustc = rustc_minor_version().unwrap_or(u32::MAX);

    if rustc >= 80 {
        println!("cargo:rustc-check-cfg=cfg(fuzzing)");
        println!("cargo:rustc-check-cfg=cfg(no_is_available)");
        println!("cargo:rustc-check-cfg=cfg(no_literal_byte_character)");
        println!("cargo:rustc-check-cfg=cfg(no_literal_c_string)");
        println!("cargo:rustc-check-cfg=cfg(no_source_text)");
        println!("cargo:rustc-check-cfg=cfg(proc_macro_span)");
        println!("cargo:rustc-check-cfg=cfg(proc_macro_span_file)");
        println!("cargo:rustc-check-cfg=cfg(proc_macro_span_location)");
        println!("cargo:rustc-check-cfg=cfg(procmacro2_backtrace)");
        println!("cargo:rustc-check-cfg=cfg(procmacro2_build_probe)");
        println!("cargo:rustc-check-cfg=cfg(procmacro2_nightly_testing)");
        println!("cargo:rustc-check-cfg=cfg(procmacro2_semver_exempt)");
        println!("cargo:rustc-check-cfg=cfg(randomize_layout)");
        println!("cargo:rustc-check-cfg=cfg(span_locations)");
        println!("cargo:rustc-check-cfg=cfg(super_unstable)");
        println!("cargo:rustc-check-cfg=cfg(wrap_proc_macro)");
    }

    let semver_exempt = cfg!(procmacro2_semver_exempt);
    if semver_exempt {
        // https://github.com/dtolnay/proc-macro2/issues/147
        println!("cargo:rustc-cfg=procmacro2_semver_exempt");
    }

    // PATCHED (Verthys): unconditionally emit span_locations.
    // 原因：tauri-macros 2.6.3 在 wrapper.rs:269 调用 function.span().start()，该方法被
    // `#[cfg(span_locations)]` 门控（见 src/wrapper.rs）。span_locations cfg 仅在启用
    // `span-locations` feature 时由 build.rs 输出。但 Cargo resolver v2 不会将 host
    // [build-dependencies] 上启用的 feature 统一到 proc-macro 上下文（tauri-macros 作为
    // proc-macro crate 编译时使用的 proc-macro2）。这导致完整构建中 tauri-macros 链接到的
    // proc-macro2 rlib 缺少 --cfg span_locations，从而 E0599: no method named `start`。
    // 通过 [patch.crates-io] 指向此本地补丁，强制无条件输出 cfg，绕过 feature 不统一问题。
    // 副作用：proc-macro2 在所有上下文都启用 span 跟踪，性能略降（可接受）。
    let _ = semver_exempt; // 保留变量避免 unused 警告
    println!("cargo:rustc-cfg=span_locations");

    // PATCHED (Verthys): 在 early return 之前无条件输出 proc_macro_span_location 和
    // proc_macro_span_file（Rust 1.88+）。原 build.rs 将这些 cfg 输出放在 `proc-macro`
    // feature 门控的 early return 之后，导致未启用 `proc-macro` feature 的编译上下文
    //（如 tauri-macros 使用的 proc-macro2 实例）不输出这些 cfg，Span::start() 不可用。
    // 此处移到 early return 之前，确保所有编译上下文都能使用 Span::start/end/file 等方法。
    if rustc >= 88 {
        println!("cargo:rustc-cfg=proc_macro_span_location");
        println!("cargo:rustc-cfg=proc_macro_span_file");
    }

    if rustc < 57 {
        // Do not use proc_macro::is_available() to detect whether the proc
        // macro API is available vs needs to be polyfilled. Instead, use the
        // proc macro API unconditionally and catch the panic that occurs if it
        // isn't available.
        println!("cargo:rustc-cfg=no_is_available");
    }

    if rustc < 66 {
        // Do not call libproc_macro's Span::source_text. Always return None.
        println!("cargo:rustc-cfg=no_source_text");
    }

    if rustc < 79 {
        // Do not call Literal::byte_character nor Literal::c_string. They can
        // be emulated by way of Literal::from_str.
        println!("cargo:rustc-cfg=no_literal_byte_character");
        println!("cargo:rustc-cfg=no_literal_c_string");
    }

    if !cfg!(feature = "proc-macro") {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    // PATCHED (Verthys): 跳过 compile_probe_unstable 探测。
    // 原因：do_compile_probe 通过 spawn rustc 子进程编译探测文件来检测不稳定特性可用性。
    // 在本机构建环境中该子进程会无限挂起（可能是 rustflags 中的 --cfg=windows_raw_dylib
    // 导致探测编译异常），使整个构建卡死（build-script-build CPU 0.02s 挂起 12+ 分钟）。
    // 由于：
    //   1. 我们已在上方（行 54-62）为 Rust 1.88+ 无条件输出 proc_macro_span_location
    //      和 proc_macro_span_file cfg，tauri-macros 的 Span::start()/end() 不依赖
    //      proc_macro_span cfg
    //   2. wrap_proc_macro cfg 由 !semver_exempt 保证输出（semver_exempt 为 false）
    //   3. proc_macro_span cfg 仅影响 Span::byte_range 和 Span::join（非必需 API）
    // 因此安全地将 proc_macro_span 设为 false，consider_rustc_bootstrap 设为 true。
    let proc_macro_span = false;
    let consider_rustc_bootstrap = true;

    if proc_macro_span || !semver_exempt {
        // Wrap types from libproc_macro rather than polyfilling the whole API.
        // Enabled as long as procmacro2_semver_exempt is not set, because we
        // can't emulate the unstable API without emulating everything else.
        // Also enabled unconditionally on nightly, in which case the
        // procmacro2_semver_exempt surface area is implemented by using the
        // nightly-only proc_macro API.
        println!("cargo:rustc-cfg=wrap_proc_macro");
    }

    if proc_macro_span {
        // Enable non-dummy behavior of Span::byte_range and Span::join methods
        // which requires an unstable compiler feature. Enabled when building
        // with nightly, unless `-Z allow-feature` in RUSTFLAGS disallows
        // unstable features.
        println!("cargo:rustc-cfg=proc_macro_span");
    }

    if proc_macro_span || rustc >= 88 {
        // PATCHED (Verthys): 移除 compile_probe_stable 探测，在 Rust 1.88+ 上无条件启用。
        // 原因：探测通过 do_compile_probe 编译测试文件来验证 Span::start/end 等方法可用性，
        // 但在沙箱/CI 环境中探测可能间歇性失败（编译器探测子进程被限制或超时），
        // 导致 proc_macro_span_location cfg 未设置，tauri-macros 的 Span::start() 调用
        // 报 E0599。Rust 1.88+ 已稳定这些 API，无需探测，直接启用。
        // Enable non-dummy behavior of Span::start and Span::end methods on
        // Rust 1.88+.
        println!("cargo:rustc-cfg=proc_macro_span_location");
    }

    if proc_macro_span || rustc >= 88 {
        // PATCHED (Verthys): 同上，移除探测，Rust 1.88+ 无条件启用。
        // Enable non-dummy behavior of Span::file and Span::local_file methods
        // on Rust 1.88+.
        println!("cargo:rustc-cfg=proc_macro_span_file");
    }

    if semver_exempt && proc_macro_span {
        // Implement the semver exempt API in terms of the nightly-only
        // proc_macro API.
        println!("cargo:rustc-cfg=super_unstable");
    }

    if consider_rustc_bootstrap {
        println!("cargo:rerun-if-env-changed=RUSTC_BOOTSTRAP");
    }
}

#[allow(dead_code)]
fn compile_probe_unstable(feature: &str, rustc_bootstrap: bool) -> bool {
    // RUSTC_STAGE indicates that this crate is being compiled as a dependency
    // of a multistage rustc bootstrap. This environment uses Cargo in a highly
    // non-standard way with issues such as:
    //
    //     https://github.com/rust-lang/cargo/issues/11138
    //     https://github.com/rust-lang/rust/issues/114839
    //
    env::var_os("RUSTC_STAGE").is_none() && do_compile_probe(feature, rustc_bootstrap)
}

#[allow(dead_code)]
fn compile_probe_stable(feature: &str) -> bool {
    env::var_os("RUSTC_STAGE").is_some() || do_compile_probe(feature, true)
}

#[allow(dead_code)]
fn do_compile_probe(feature: &str, rustc_bootstrap: bool) -> bool {
    println!("cargo:rerun-if-changed=src/probe/{}.rs", feature);

    let rustc = cargo_env_var("RUSTC");
    let out_dir = cargo_env_var("OUT_DIR");
    let out_subdir = Path::new(&out_dir).join("probe");
    let probefile = Path::new("src")
        .join("probe")
        .join(feature)
        .with_extension("rs");

    if let Err(err) = fs::create_dir(&out_subdir) {
        if err.kind() != ErrorKind::AlreadyExists {
            eprintln!("Failed to create {}: {}", out_subdir.display(), err);
            process::exit(1);
        }
    }

    let rustc_wrapper = env::var_os("RUSTC_WRAPPER").filter(|wrapper| !wrapper.is_empty());
    let rustc_workspace_wrapper =
        env::var_os("RUSTC_WORKSPACE_WRAPPER").filter(|wrapper| !wrapper.is_empty());
    let mut rustc = rustc_wrapper
        .into_iter()
        .chain(rustc_workspace_wrapper)
        .chain(iter::once(rustc));
    let mut cmd = Command::new(rustc.next().unwrap());
    cmd.args(rustc);

    if !rustc_bootstrap {
        cmd.env_remove("RUSTC_BOOTSTRAP");
    }

    cmd.stderr(Stdio::null())
        .arg("--cfg=procmacro2_build_probe")
        .arg("--edition=2021")
        .arg("--crate-name=proc_macro2")
        .arg("--crate-type=lib")
        .arg("--cap-lints=allow")
        .arg("--emit=dep-info,metadata")
        .arg("--out-dir")
        .arg(&out_subdir)
        .arg(probefile);

    if let Some(target) = env::var_os("TARGET") {
        cmd.arg("--target").arg(target);
    }

    // If Cargo wants to set RUSTFLAGS, use that.
    if let Ok(rustflags) = env::var("CARGO_ENCODED_RUSTFLAGS") {
        if !rustflags.is_empty() {
            for arg in rustflags.split('\x1f') {
                cmd.arg(arg);
            }
        }
    }

    let success = match cmd.status() {
        Ok(status) => status.success(),
        Err(_) => false,
    };

    // Clean up to avoid leaving nondeterministic absolute paths in the dep-info
    // file in OUT_DIR, which causes nonreproducible builds in build systems
    // that treat the entire OUT_DIR as an artifact.
    if let Err(err) = fs::remove_dir_all(&out_subdir) {
        // libc::ENOTEMPTY
        // Some filesystems (NFSv3) have timing issues under load where '.nfs*'
        // dummy files can continue to get created for a short period after the
        // probe command completes, breaking remove_dir_all.
        // To be replaced with ErrorKind::DirectoryNotEmpty (Rust 1.83+).
        const ENOTEMPTY: i32 = 39;

        if !(err.kind() == ErrorKind::NotFound
            || (cfg!(target_os = "linux") && err.raw_os_error() == Some(ENOTEMPTY)))
        {
            eprintln!("Failed to clean up {}: {}", out_subdir.display(), err);
            process::exit(1);
        }
    }

    success
}

fn rustc_minor_version() -> Option<u32> {
    let rustc = cargo_env_var("RUSTC");
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    pieces.next()?.parse().ok()
}

fn cargo_env_var(key: &str) -> OsString {
    env::var_os(key).unwrap_or_else(|| {
        eprintln!(
            "Environment variable ${} is not set during execution of build script",
            key,
        );
        process::exit(1);
    })
}
