/*
 * 平台原语与路径/时间辅助
 *
 * 每个平台函数保留 Windows 与非 Windows 两个 cfg 版本。
 */

/// 枚举当前进程已加载模块的 (名称, 路径) 列表
#[cfg(target_os = "windows")]
pub(super) fn enumerate_loaded_module_paths() -> Vec<(String, String)> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };
    use windows::Win32::System::Threading::GetCurrentProcessId;

    let mut result = Vec::new();
    let pid = unsafe { GetCurrentProcessId() };
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    let snapshot = match snapshot {
        Ok(h) => h,
        Err(_) => return result,
    };

    let mut me = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    let mut ok = unsafe { Module32FirstW(snapshot, &mut me) }.is_ok();
    while ok {
        let name_len = me
            .szModule
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(me.szModule.len());
        let name = String::from_utf16_lossy(&me.szModule[..name_len]);
        let path_len = me
            .szExePath
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(me.szExePath.len());
        let path = String::from_utf16_lossy(&me.szExePath[..path_len]);

        if !path.is_empty() {
            result.push((name, path));
        }

        ok = unsafe { Module32NextW(snapshot, &mut me) }.is_ok();
    }

    let _ = unsafe { CloseHandle(snapshot) };
    result
}

/// 非 Windows 平台：枚举模块（空实现）
#[cfg(not(target_os = "windows"))]
pub(super) fn enumerate_loaded_module_paths() -> Vec<(String, String)> {
    Vec::new()
}

/*
 * 进程完整性监控
 *
 * 使用 SetProcessMitigationPolicy 启用进程缓解策略：
 * - ProcessSignaturePolicy：限制仅加载 Microsoft 签名的 DLL
 * - ProcessImageLoadPolicy：禁止从远程位置加载镜像
 *
 * 注意：此策略必须在进程启动早期应用。在 setup 阶段调用可能已晚
 * （部分 DLL 已加载），调用失败时记录告警但不阻止启动。
 */

#[cfg(target_os = "windows")]
pub(super) fn apply_process_mitigation_policies() {
    use std::ffi::c_void;

    // PROCESS_MITIGATION_POLICY 枚举值
    // ProcessSignaturePolicy = 8
    // ProcessImageLoadPolicy = 10
    const PROCESS_SIGNATURE_POLICY: u32 = 8;
    const PROCESS_IMAGE_LOAD_POLICY: u32 = 10;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetProcessMitigationPolicy(
            mitigation_policy: u32,
            lp_buffer: *const c_void,
            dw_length: u32,
        ) -> i32;
    }

    unsafe {
        // ProcessImageLoadPolicy：禁止从远程 UNC 路径加载镜像 + 优先从 System32 加载
        // 结构体：PROCESS_MITIGATION_IMAGE_LOAD_POLICY（4 字节位域）
        // NoRemoteMgmtImages = bit 0, NoLowMandatoryLabelImages = bit 1, PreferSystem32Images = bit 2
        #[repr(C)]
        #[derive(Default)]
        struct ProcessImageLoadPolicy {
            flags: u32,
        }

        // NoRemoteMgmtImages=1 | PreferSystem32Images=4 = 0x5
        let image_load_policy = ProcessImageLoadPolicy { flags: 0x5 };

        let result = SetProcessMitigationPolicy(
            PROCESS_IMAGE_LOAD_POLICY,
            &image_load_policy as *const _ as *const c_void,
            std::mem::size_of::<ProcessImageLoadPolicy>() as u32,
        );

        if result != 0 {
            log::warn!(
                "[background_patrol] SetProcessMitigationPolicy(ProcessImageLoadPolicy) 失败 \
                 (可能已有 DLL 加载，策略应用过晚)"
            );
        } else {
            log::info!(
                "[background_patrol] ProcessImageLoadPolicy 已启用 \
                 (NoRemoteMgmtImages + PreferSystem32Images)"
            );
        }

        // ProcessSignaturePolicy：限制仅加载 Microsoft 签名 DLL
        // 注意：此策略非常严格，可能导致后续非 Microsoft 签名 DLL 加载失败。
        // 使用 AuditMicrosoftSignedOnly（bit 3 = 0x8）进行审计模式，
        // 而非 MicrosoftSignedOnly（bit 0 = 0x1）的阻断模式，
        // 以避免意外阻断合法 DLL 加载。
        #[repr(C)]
        #[derive(Default)]
        struct ProcessSignaturePolicy {
            flags: u32,
        }

        // AuditMicrosoftSignedOnly = bit 3 = 0x8（审计模式，记录但不阻断）
        let sig_policy = ProcessSignaturePolicy { flags: 0x8 };

        let result = SetProcessMitigationPolicy(
            PROCESS_SIGNATURE_POLICY,
            &sig_policy as *const _ as *const c_void,
            std::mem::size_of::<ProcessSignaturePolicy>() as u32,
        );

        if result != 0 {
            log::warn!(
                "[background_patrol] SetProcessMitigationPolicy(ProcessSignaturePolicy) 失败 \
                 (可能已有非 Microsoft 签名 DLL 加载)"
            );
        } else {
            log::info!(
                "[background_patrol] ProcessSignaturePolicy 已启用 (AuditMicrosoftSignedOnly)"
            );
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub(super) fn apply_process_mitigation_policies() {
    // 非 Windows：无对应 API
}

/*
 * 系统空闲时间获取（Windows GetLastInputInfo）
 */

/// 获取系统空闲时间（秒）
///
/// 使用 GetLastInputInfo + GetTickCount 计算自上次输入以来的时间。
/// 非 Windows 平台返回 0（视为始终活跃）。
#[cfg(target_os = "windows")]
pub(super) fn get_system_idle_secs() -> u64 {
    #[repr(C)]
    #[derive(Default)]
    struct LastInputInfo {
        cb_size: u32,
        dw_time: u32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn GetLastInputInfo(plii: *mut LastInputInfo) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetTickCount() -> u32;
    }

    unsafe {
        let mut lii = LastInputInfo {
            cb_size: std::mem::size_of::<LastInputInfo>() as u32,
            ..Default::default()
        };

        if GetLastInputInfo(&mut lii) == 0 {
            return 0; // 获取失败，视为活跃
        }

        let now = GetTickCount();
        // 处理 32 位 tick count 回绕（约 49 天）
        let idle_ms = if now >= lii.dw_time {
            now - lii.dw_time
        } else {
            // 回绕情况：now 在回绕后，dw_time 在回绕前
            (u32::MAX - lii.dw_time) + now + 1
        };

        (idle_ms / 1000) as u64
    }
}

/// 非 Windows 平台：系统空闲时间（返回 0，视为始终活跃）
#[cfg(not(target_os = "windows"))]
pub(super) fn get_system_idle_secs() -> u64 {
    0
}

/*
 * 线程优先级设置（Windows SetThreadPriority）
 */

#[cfg(target_os = "windows")]
pub(super) fn set_current_thread_priority_lowest() {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThread() -> *mut c_void;
        fn SetThreadPriority(thread: *mut c_void, npriority: i32) -> i32;
    }

    const THREAD_PRIORITY_LOWEST: i32 = -2;

    unsafe {
        let h = GetCurrentThread();
        let ok = SetThreadPriority(h, THREAD_PRIORITY_LOWEST);
        if ok == 0 {
            log::warn!("[background_patrol] SetThreadPriority(THREAD_PRIORITY_LOWEST) 失败");
        } else {
            log::debug!("[background_patrol] 线程优先级已设为 THREAD_PRIORITY_LOWEST(-2)");
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub(super) fn set_current_thread_priority_lowest() {
    // 非 Windows：无对应 API
}

/*
 * 辅助函数
 */

/// 路径键规范化：剥离 \\?\ 前缀、统一反斜杠、转小写、去尾分隔符。
pub(super) fn normalize_key(path: &str) -> String {
    let mut s = path;
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        s = stripped;
    }
    let mut s = s.replace('/', "\\");
    s = s.to_lowercase();
    while s.len() > 1 && s.ends_with('\\') {
        s.pop();
    }
    s
}

/// 日志脱敏：隐藏用户路径中的用户名
pub(super) fn sanitize_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    if let Ok(home) = std::env::var("USERPROFILE") {
        let h = home.replace('\\', "/");
        if normalized.contains(&h) {
            return normalized.replace(&h, "<USER_HOME>");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let h = home.replace('\\', "/");
        if normalized.contains(&h) {
            return normalized.replace(&h, "<USER_HOME>");
        }
    }
    normalized
}

/// 当前 Unix 毫秒时间戳
pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 当前 Unix 秒时间戳
pub(super) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
