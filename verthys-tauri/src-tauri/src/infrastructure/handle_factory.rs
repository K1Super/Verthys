/*
 * @file infrastructure/handle_factory.rs
 * @brief Windows内核对象句柄统一创建工厂，强制实现多进程资源隔离规范
 *
 * 模块硬性约束与安全设计规则：
 * 1. 所有内核对象安全属性强制固定 bInheritHandle = FALSE，操作系统底层禁止句柄自动传递给子进程，杜绝资源泄漏、句柄占用、跨进程意外操作风险；
 * 2. 项目CI强制准入规则：禁止业务代码直接裸调用CreateFileW/CreatePipe/CreateEventW等原生Win32 API，全部必须经由本封装方法创建；
 * 3. 子进程强制启动自检机制：进程入口执行继承句柄校验，一旦检测到可继承标记句柄直接抛出错误阻断运行，作为兜底防御防线；
 * 4. 非Windows平台无句柄继承概念，校验函数直接空实现兼容编译。
 */

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows::Win32::Security::SECURITY_ATTRIBUTES;

/// 生成禁止子进程继承的安全属性结构体
/// 全局统一模板，所有句柄创建统一复用该配置，保证继承标志一致性
#[cfg(windows)]
pub fn non_inheritable_security_attributes() -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: false.into(),
    }
}

/// 创建禁止子进程继承的文件内核句柄
/// 封装CreateFileW系统调用，强制注入不可继承安全属性，避免文件句柄被子进程长期占用无法释放
#[cfg(windows)]
pub fn create_non_inheritable_file(
    path: &str,
    access: u32,
    share_mode: windows::Win32::Storage::FileSystem::FILE_SHARE_MODE,
    creation_disposition: windows::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION,
    flags: windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
) -> Result<HANDLE, String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::CreateFileW;

    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let security_attr = non_inheritable_security_attributes();

    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            access,
            share_mode,
            Some(&security_attr),
            creation_disposition,
            flags,
            HANDLE::default(),
        )
    };

    handle.map_err(|err| format!("CreateFileW 创建文件句柄失败：{}", err))
}

/// 创建禁止继承的匿名管道读写句柄对
/// 用于父子进程IPC通信，规避管道句柄意外继承导致的管道无法正常关闭、读写阻塞问题
#[cfg(windows)]
pub fn create_non_inheritable_pipe(buffer_size: u32) -> Result<(HANDLE, HANDLE), String> {
    use windows::Win32::System::Pipes::CreatePipe;

    let security_attr = non_inheritable_security_attributes();
    let mut read_handle = HANDLE::default();
    let mut write_handle = HANDLE::default();

    unsafe { CreatePipe(&mut read_handle, &mut write_handle, Some(&security_attr), buffer_size) }
        .map_err(|err| format!("CreatePipe 创建匿名管道失败：{}", err))?;

    Ok((read_handle, write_handle))
}

/// 子进程启动阶段句柄继承合规自检
/// 安全兜底校验：检查标准输入输出错误句柄是否被标记为可继承，发现违规直接返回错误终止进程初始化，防止违规句柄扩散
#[cfg(windows)]
pub fn validate_no_inherited_handles() -> Result<(), String> {
    use windows::Win32::Foundation::GetHandleInformation;
    use windows::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    // HANDLE_FLAG_INHERIT 常量值：句柄可被子进程继承标记
    const HANDLE_FLAG_INHERIT: u32 = 0x00000001;

    let standard_handles = [
        (STD_INPUT_HANDLE, "标准输入stdin"),
        (STD_OUTPUT_HANDLE, "标准输出stdout"),
        (STD_ERROR_HANDLE, "标准错误stderr"),
    ];

    for (handle_id, desc) in standard_handles {
        let handle = match unsafe { GetStdHandle(handle_id) } {
            Ok(h) if !h.is_invalid() => h,
            _ => continue,
        };

        let mut flags = 0u32;
        if unsafe { GetHandleInformation(handle, &mut flags) }.is_ok() {
            if (flags & HANDLE_FLAG_INHERIT) != 0 {
                return Err(format!("进程安全自检不通过：{} 被设置为可继承句柄，违反资源隔离规范", desc));
            }
        }
    }

    Ok(())
}

/// 非Windows系统兼容空实现，直接校验通过
#[cfg(not(windows))]
pub fn validate_no_inherited_handles() -> Result<(), String> {
    Ok(())
}

/// 创建禁止子进程继承的事件同步内核句柄
/// 用于多进程间信号同步、等待唤醒，防止事件句柄继承造成重复触发、信号状态错乱
#[cfg(windows)]
pub fn create_non_inheritable_event(
    manual_reset: bool,
    initial_state: bool,
) -> Result<HANDLE, String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Threading::CreateEventW;

    let security_attr = non_inheritable_security_attributes();

    let handle = unsafe {
        CreateEventW(
            Some(&security_attr),
            manual_reset,
            initial_state,
            PCWSTR::null(),
        )
    };

    handle.map_err(|err| format!("CreateEventW 创建事件句柄失败：{}", err))
}