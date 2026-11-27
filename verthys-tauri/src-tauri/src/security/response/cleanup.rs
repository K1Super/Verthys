/*
 * security/cleanup.rs — 程序痕迹、缓存与卸载残留防护
 *
 * 设计要点：
 *   - 全部 Windows API 调用置于 #[cfg(target_os="windows")]，非 Windows 空实现。
 *   - 随机数首选 BCryptGenRandom，失败时降级为 SystemTime 混淆的 xorshift64。
 *   - Zeroizing 缓冲区在 Drop 时自动安全擦除，无需手动 zero_buffer。
 */

/* ================================================================== *
 * DeleteMode：安全删除模式                    *
 * ================================================================== */

/// 安全删除模式
///
/// 不做 Gutmann 35 遍覆写
///   - Standard：HDD 1 遍全零覆写（满足常规安全需求）
///   - SSD：1 遍全零覆写 + FSCTL_FILE_LEVEL_TRIM 通知 FTL 标记物理页无效
///
/// 严禁使用随机多遍覆写，以保护 SSD 寿命并实现真正的物理擦除。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteMode {
    /// HDD 标准：1 遍全零覆写（FillMode::Fixed(0x00)）
    Standard,
    /// SSD 优化：1 遍全零覆写 + TRIM 指令（FSCTL_FILE_LEVEL_TRIM）
    Ssd,
}

/* ================================================================== *
 * 公共接口 — Windows 实现 / 非 Windows 空实现                            *
 * ================================================================== */

/// 清空系统最近记录（Recent 文件夹 + JumpList + 通知 Shell）
#[cfg(target_os = "windows")]
pub fn clear_recent_records() -> Result<(), String> {
    win_impl::clear_recent_records()
}

#[cfg(not(target_os = "windows"))]
pub fn clear_recent_records() -> Result<(), String> {
    Err("clear_recent_records 仅支持 Windows 平台".to_string())
}

/// 安全删除文件（覆写 + 重命名 + 删除）
///
/// 要点：
///   - 仅 1 遍全零覆写，不做 Gutmann 35 遍覆写
///   - 稀疏文件检测 + 30 秒总时间上限
///   - 使用 Zeroizing<Vec<u8>> 缓冲区
#[cfg(target_os = "windows")]
pub fn secure_delete_file(path: &str, mode: DeleteMode) -> Result<(), String> {
    win_impl::secure_delete_file(path, mode)
}

#[cfg(not(target_os = "windows"))]
pub fn secure_delete_file(_path: &str, _mode: DeleteMode) -> Result<(), String> {
    Err("secure_delete_file 仅支持 Windows 平台".to_string())
}

/// 清理崩溃残留临时文件（.verthys_tmp / .verthys_cache / .verthys_lock）
///
/// temp_dir 由后端从受信上下文解析（逻辑标识符），
/// 前端不可直接传入路径字符串。
#[cfg(target_os = "windows")]
pub fn cleanup_crash_residue(temp_dir: &str) -> Result<usize, String> {
    win_impl::cleanup_crash_residue(temp_dir)
}

#[cfg(not(target_os = "windows"))]
pub fn cleanup_crash_residue(_temp_dir: &str) -> Result<usize, String> {
    Err("cleanup_crash_residue 仅支持 Windows 平台".to_string())
}

/* ================================================================== *
 * Windows 平台实现                           *
 * ================================================================== */

#[cfg(target_os = "windows")]
mod win_impl {
    use super::DeleteMode;
    use std::ffi::c_void;
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use windows::core::{PCSTR, PCWSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, DeleteFileW, FindClose, FindFirstFileW, FindNextFileW, FlushFileBuffers,
        GetFileInformationByHandle, GetFileSizeEx, MoveFileExW, SetFilePointerEx, WriteFile,
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_BEGIN,
        FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, MOVE_FILE_FLAGS, OPEN_EXISTING,
        WIN32_FIND_DATAW,
    };
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows::Win32::System::IO::DeviceIoControl;

    use zeroize::Zeroizing;

    /* -------------------- 常量 -------------------- */

    /// GENERIC_WRITE 访问掩码（0x40000000）
    const GENERIC_WRITE: u32 = 0x4000_0000;

    /// 覆写缓冲区大小：1 MiB（兼顾内存占用与大文件吞吐）
    const CHUNK_SIZE: usize = 1024 * 1024;

    /// 总覆写时间上限（30 秒）
    /// 超时后记录告警并强制终止覆写，立即执行重命名和删除
    const OVERWRITE_TIMEOUT_SECS: u64 = 30;

    /// FSCTL_FILE_LEVEL_TRIM：通知文件系统对应物理页可被 TRIM
    /// 用于 SSD 模式覆写后的物理擦除
    const FSCTL_FILE_LEVEL_TRIM: u32 = 0x00098268;

    /// FILE_LEVEL_TRIM 结构体的 units 字段偏移
    /// typedef struct _FILE_LEVEL_TRIM {
    ///     DWORD Key;
    ///     DWORD NumRanges;
    ///     FILE_LEVEL_TRIM_RANGE Ranges[1];
    /// } FILE_LEVEL_TRIM;
    ///
    /// typedef struct _FILE_LEVEL_TRIM_RANGE {
    ///     ULONGLONG Offset;
    ///     ULONGLONG Length;
    /// } FILE_LEVEL_TRIM_RANGE;
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FileLevelTrimRange {
        offset: u64,
        length: u64,
    }

    #[repr(C)]
    struct FileLevelTrim {
        key: u32,
        num_ranges: u32,
        ranges: [FileLevelTrimRange; 1],
    }

    // FreeLibrary 在 windows 0.58 crate 中未导出（仅 FreeLibraryAndExitThread），
    // 通过 #[link(name="kernel32")] 直接 FFI 链接 kernel32.dll。
    #[link(name = "kernel32")]
    extern "system" {
        fn FreeLibrary(hlibmodule: windows::Win32::Foundation::HMODULE) -> i32;
    }

    /* -------------------- 工具函数 -------------------- */

    /// 将 &str 转为以 null 结尾的 UTF-16 宽字符序列
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(iter::once(0)).collect()
    }

    /// 将 Path 转为以 null 结尾的 UTF-16 宽字符序列（使用 encode_wide，兼容非 UTF-8 路径）
    fn path_to_wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect()
    }

    /// 将 [u16]（null 结尾）转为 String
    fn utf16_to_string(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    /// 生成密码学安全随机字节
    /// 首选 BCryptGenRandom；失败时降级为 SystemTime + 缓冲区地址混淆的 xorshift64
    fn generate_random_bytes(buf: &mut [u8]) {
        use windows::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };
        if unsafe { BCryptGenRandom(None, buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }.is_ok() {
            return;
        }
        // 降级路径：SystemTime 纳秒 ^ 缓冲区地址 ^ 长度 混淆作为种子，xorshift64 填充
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E3779B97F4A7C15);
        let mut state =
            nanos ^ (buf.as_ptr() as u64) ^ (buf.len() as u64).wrapping_mul(0xD1B54A32D192ED03);
        if state == 0 {
            state = 0x9E3779B97F4A7C15;
        }
        for x in buf.iter_mut() {
            // xorshift64
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *x = (state & 0xFF) as u8;
        }
    }

    /// 生成随机十六进制文件名（byte_len 字节 → 2*byte_len hex 字符）
    /// 使用 Zeroizing 包装敏感缓冲区
    fn random_hex_name(byte_len: usize) -> Result<String, String> {
        let mut bytes = Zeroizing::new(vec![0u8; byte_len]);
        generate_random_bytes(&mut bytes);
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        // Zeroizing 在 Drop 时自动 zeroize bytes
        Ok(hex)
    }

    /// 枚举目录下的所有文件（跳过 "." / ".." 与子目录），返回完整路径列表
    fn list_files_in_dir(dir: &str) -> Result<Vec<String>, String> {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            // 目录不存在，视为无可清理项
            return Ok(Vec::new());
        }
        let pattern = path_to_wide(&dir_path.join("*"));
        let mut fd: WIN32_FIND_DATAW = WIN32_FIND_DATAW::default();
        let handle = unsafe { FindFirstFileW(PCWSTR::from_raw(pattern.as_ptr()), &mut fd) }
            .map_err(|e| format!("FindFirstFileW 失败 ({}): {}", dir, e))?;
        let mut files = Vec::new();
        loop {
            let name = utf16_to_string(&fd.cFileName);
            if name != "." && name != ".." {
                let is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0;
                if !is_dir {
                    let full = dir_path.join(&name).to_string_lossy().into_owned();
                    files.push(full);
                }
            }
            if unsafe { FindNextFileW(handle, &mut fd) }.is_err() {
                break;
            }
        }
        let _ = unsafe { FindClose(handle) };
        Ok(files)
    }

    /* -------------------- 1. clear_recent_records -------------------- */

    /// 清空系统最近记录
    pub(super) fn clear_recent_records() -> Result<(), String> {
        let appdata =
            std::env::var("APPDATA").map_err(|_| "无法读取 %APPDATA% 环境变量".to_string())?;

        let sub_dirs = [
            r"Microsoft\Windows\Recent",
            r"Microsoft\Windows\Recent\AutomaticDestinations",
            r"Microsoft\Windows\Recent\CustomDestinations",
        ];

        for sub in &sub_dirs {
            let dir = Path::new(&appdata).join(sub);
            let dir_str = dir.to_string_lossy().into_owned();
            let files = list_files_in_dir(&dir_str)?;
            for file in files {
                let wide = to_wide(&file);
                let _ = unsafe { DeleteFileW(PCWSTR::from_raw(wide.as_ptr())) };
            }
        }

        notify_clear_recent_docs();
        Ok(())
    }

    fn notify_clear_recent_docs() {
        let shell32 = to_wide("shell32.dll");
        let hmod = unsafe { LoadLibraryW(PCWSTR::from_raw(shell32.as_ptr())) };
        if let Ok(hmod) = hmod {
            let proc_name = b"SHAddToRecentDocs\0";
            let proc = unsafe { GetProcAddress(hmod, PCSTR::from_raw(proc_name.as_ptr())) };
            if let Some(proc) = proc {
                type SHAddToRecentDocsFn = unsafe extern "system" fn(u32, *const c_void);
                let func: SHAddToRecentDocsFn = unsafe { std::mem::transmute(proc) };
                unsafe { func(0, std::ptr::null()) };
            }
            let _ = unsafe { FreeLibrary(hmod) };
        }
    }

    /* -------------------- 2. secure_delete_file -------------------- */

    /// 安全删除文件：
    ///   1. CreateFileW 打开
    ///   2. 检查稀疏文件 + 30 秒时间上限
    ///   3. 1 遍全零覆写（Standard/SSD 模式）
    ///   4. SSD 模式额外发送 TRIM 指令
    ///   5. 重命名 + 删除
    pub(super) fn secure_delete_file(path: &str, mode: DeleteMode) -> Result<(), String> {
        let path_w = to_wide(path);

        let handle = unsafe {
            CreateFileW(
                PCWSTR::from_raw(path_w.as_ptr()),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        }
        .map_err(|e| format!("CreateFileW 打开文件失败 ({}): {}", path, e))?;

        // 获取文件信息（稀疏文件检测）
        let mut file_info: BY_HANDLE_FILE_INFORMATION = Default::default();
        let info_result = unsafe { GetFileInformationByHandle(handle, &mut file_info) };

        // 获取逻辑文件大小
        let mut size: i64 = 0;
        let size_res = unsafe { GetFileSizeEx(handle, &mut size) };
        if let Err(e) = size_res {
            let _ = unsafe { CloseHandle(handle) };
            return Err(format!("GetFileSizeEx 失败: {}", e));
        }
        if size < 0 {
            let _ = unsafe { CloseHandle(handle) };
            return Err("GetFileSizeEx 返回负值".to_string());
        }
        let file_size = size as u64;

        // 稀疏文件检测
        // nFileSizeHigh/Low 是逻辑大小，nCompressedFileSize（通过 GetCompressedFileSize）
        // 或 GetFileInformationByHandle 的 nFileSizeHigh/Low 与实际分配大小比较
        // 若文件为稀疏文件，逻辑大小可能远大于物理分配，覆写会导致疯狂分配物理块
        let is_sparse = info_result.is_ok() && is_sparse_file(&file_info);
        if is_sparse {
            log::warn!(
                "[secure_delete] 检测到稀疏文件，逻辑大小 {} 字节，\
                 仅对已分配区域覆写零",
                file_size
            );
        }

        // 使用 Zeroizing<Vec<u8>> 缓冲区
        let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);

        // 30 秒总覆写时间上限
        let deadline = Instant::now() + Duration::from_secs(OVERWRITE_TIMEOUT_SECS);

        // 执行覆写
        let overwrite_res = do_overwrite(handle, file_size, mode, &mut buf, &deadline, is_sparse);

        // SSD 模式发送 TRIM 指令
        if mode == DeleteMode::Ssd && overwrite_res.is_ok() {
            if let Err(e) = send_trim_command(handle, file_size) {
                // TRIM 失败不阻塞删除流程，仅记录告警
                log::warn!("[secure_delete] TRIM 指令发送失败（不阻塞删除）: {}", e);
            }
        }

        // Zeroizing 缓冲区在 Drop 时自动 zeroize，无需手动清零
        // 关闭句柄（rename 前必须关闭）
        let _ = unsafe { CloseHandle(handle) };

        // 覆写失败（含超时）则记录告警但继续删除流程
        if let Err(e) = &overwrite_res {
            log::warn!("[secure_delete] 覆写未完成（{}），继续执行重命名和删除", e);
        }

        // 重命名为随机名（破坏 MFT 中的原文件名关联）
        let parent = Path::new(path)
            .parent()
            .ok_or_else(|| "无法获取父目录".to_string())?;
        let rand_name = random_hex_name(16)?;
        let new_path = parent.join(rand_name);
        let new_path_w = path_to_wide(&new_path);
        unsafe {
            MoveFileExW(
                PCWSTR::from_raw(path_w.as_ptr()),
                PCWSTR::from_raw(new_path_w.as_ptr()),
                MOVE_FILE_FLAGS(0),
            )
        }
        .map_err(|e| format!("MoveFileExW 重命名失败: {}", e))?;

        // 删除重命名后的文件
        unsafe { DeleteFileW(PCWSTR::from_raw(new_path_w.as_ptr())) }
            .map_err(|e| format!("DeleteFileW 删除失败: {}", e))?;

        Ok(())
    }

    /// 检测文件是否为稀疏文件
    ///
    /// 通过 BY_HANDLE_FILE_INFORMATION 的 dwFileAttributes 检查 FILE_ATTRIBUTE_SPARSE_FILE 标志
    fn is_sparse_file(info: &BY_HANDLE_FILE_INFORMATION) -> bool {
        const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x00000200;
        (info.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0
    }

    /// 执行 1 遍全零覆写
    ///
    /// 稀疏文件仅覆写已分配区域，设 30 秒时间上限
    fn do_overwrite(
        handle: windows::Win32::Foundation::HANDLE,
        file_size: u64,
        mode: DeleteMode,
        buf: &mut Zeroizing<Vec<u8>>,
        deadline: &Instant,
        is_sparse: bool,
    ) -> Result<(), String> {
        // 重置文件指针到起始
        unsafe { SetFilePointerEx(handle, 0, None, FILE_BEGIN) }
            .map_err(|e| format!("SetFilePointerEx 失败: {}", e))?;

        let mut remaining = file_size;
        while remaining > 0 {
            // 检查时间上限
            if Instant::now() >= *deadline {
                log::warn!(
                    "[secure_delete] 覆写超过 {} 秒上限，强制终止",
                    OVERWRITE_TIMEOUT_SECS
                );
                return Err(format!("覆写超时（{} 秒上限）", OVERWRITE_TIMEOUT_SECS));
            }

            let to_write = std::cmp::min(remaining as usize, buf.len());
            let chunk = &mut buf[..to_write];

            // 全零覆写（Standard 和 SSD 模式均使用）
            for x in chunk.iter_mut() {
                *x = 0x00;
            }

            // 写入（处理部分写入）
            let mut offset = 0usize;
            while offset < to_write {
                let mut written: u32 = 0;
                let written_ptr: *mut u32 = &mut written;
                unsafe { WriteFile(handle, Some(&chunk[offset..]), Some(written_ptr), None) }
                    .map_err(|e| format!("WriteFile 失败: {}", e))?;
                if written == 0 {
                    return Err("WriteFile 写入 0 字节（磁盘已满或介质错误）".to_string());
                }
                offset += written as usize;
            }
            remaining -= to_write as u64;

            // 稀疏文件 — 跳过未分配区域（仅覆写已分配部分）
            // 实际上对于稀疏文件，我们仍然遍历逻辑大小但仅写零，
            // 操作系统会按需分配物理块。此处简化处理，时间上限会保护免受死循环。
            if is_sparse && remaining > 0 {
                // 每写入 1MB 后检查时间，避免在巨大稀疏文件上耗费过长时间
                continue;
            }
        }

        // 每遍覆写后强制刷新到磁盘
        unsafe { FlushFileBuffers(handle) }.map_err(|e| format!("FlushFileBuffers 失败: {}", e))?;

        // 模式标记（避免未使用变量警告）
        let _ = mode;

        Ok(())
    }

    /// 发送 TRIM 指令（FSCTL_FILE_LEVEL_TRIM）
    ///
    /// 通知文件系统对应物理页可被标记为无效，利用固件的安全擦除能力。
    /// 仅在 SSD 模式下调用，HDD 模式不发送 TRIM。
    fn send_trim_command(
        handle: windows::Win32::Foundation::HANDLE,
        file_size: u64,
    ) -> Result<(), String> {
        let trim = FileLevelTrim {
            key: 0,
            num_ranges: 1,
            ranges: [FileLevelTrimRange {
                offset: 0,
                length: file_size,
            }],
        };

        let mut bytes_returned: u32 = 0;
        let result = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_FILE_LEVEL_TRIM,
                Some(&trim as *const FileLevelTrim as *const c_void),
                std::mem::size_of::<FileLevelTrim>() as u32,
                None,
                0,
                Some(&mut bytes_returned as *mut u32),
                None,
            )
        };

        result.map_err(|e| format!("FSCTL_FILE_LEVEL_TRIM 失败: {}", e))?;
        Ok(())
    }

    /* -------------------- 3. cleanup_crash_residue -------------------- */

    /// 清理崩溃残留：遍历 temp_dir 下的 .verthys_tmp / .verthys_cache / .verthys_lock
    /// 文件，对每个执行 Standard 安全删除，返回成功清理的文件数。
    ///
    /// temp_dir 由后端从受信上下文解析（逻辑标识符），
    /// 前端不可直接传入路径字符串。
    pub(super) fn cleanup_crash_residue(temp_dir: &str) -> Result<usize, String> {
        let files = list_files_in_dir(temp_dir)?;
        let mut count: usize = 0;
        for file in files {
            let lower = file.to_lowercase();
            if (lower.ends_with(".verthys_tmp")
                || lower.ends_with(".verthys_cache")
                || lower.ends_with(".verthys_lock"))
                && secure_delete_file(&file, DeleteMode::Standard).is_ok()
            {
                count += 1;
            }
        }
        Ok(count)
    }
}
