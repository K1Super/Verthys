//! 宿主侧注入与预注册：开发旁路、测试注入与 worker 映像识别。

/// 开发构建向 worker 注入 P2 机器预算测试旁路。
///
/// 仅 debug 构建注入；生产构建返回 None，生产 DLL 也不包含该旁路分支。
/// 作用：未签名开发客户端会被已安装的 VerthysSecuritySvc 以 image-auth
/// 拒绝，C 层据此 fail-closed 返回 VTY_E_LOCKED；注入后测试钩子 DLL 在
/// 本机预算检查处直接放行，使创建/打开不依赖启动方式。
pub(super) fn dev_machine_limiter_bypass() -> Option<(&'static str, &'static str)> {
    if cfg!(debug_assertions) {
        Some(("VERTHYS_TEST_MACHINE_LIMITER_BYPASS", "1"))
    } else {
        None
    }
}

/// 测试构建专用：强制 REGISTER 失败，用于验证 preferred 降级路径。
///
/// 仅 `test_hooks` 特性编译；生产构建恒为 false。
#[cfg(feature = "test_hooks")]
pub(super) fn test_register_failure() -> bool {
    std::env::var("VERTHYS_TEST_KERNEL_REGISTER_FAIL").ok().as_deref() == Some("1")
}

#[cfg(not(feature = "test_hooks"))]
pub(super) fn test_register_failure() -> bool {
    false
}

/// 按基名识别生产 worker 映像。
///
/// 只接受部署链实际产出的两个名称；其他文件名即使位于宿主目录也不预 ARM。
#[cfg(target_os = "windows")]
pub(super) fn worker_image_for_name(
    name: &str,
) -> Option<crate::infrastructure::security_service_client::WorkerImage> {
    use crate::infrastructure::security_service_client::WorkerImage;
    if name.eq_ignore_ascii_case("verthys-worker.exe") {
        Some(WorkerImage::Default)
    } else if name.eq_ignore_ascii_case("verthys-worker-x86_64-pc-windows-msvc.exe") {
        Some(WorkerImage::Sidecar)
    } else {
        None
    }
}

/// 判定是否具备宿主预 ARM 条件：白名单 worker 基名且与宿主同目录。
///
/// 开发树中 worker 与宿主分处不同 target 目录，跳过预 ARM，
/// 由 worker 解锁时自 ARM；生产安装目录中两者同根。
#[cfg(target_os = "windows")]
pub(super) fn prearm_image(
    worker_exe: &str,
) -> Option<crate::infrastructure::security_service_client::WorkerImage> {
    use std::path::Path;

    let worker = Path::new(worker_exe);
    let image = worker_image_for_name(worker.file_name()?.to_str()?)?;
    let worker_dir = worker.parent()?.canonicalize().ok()?;
    let host = std::env::current_exe().ok()?;
    let host_dir = host.parent()?.canonicalize().ok()?;
    if worker_dir != host_dir {
        return None;
    }
    Some(image)
}
