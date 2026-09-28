/*
 * util/disk.rs — 磁盘空间查询工具
 *
 * 架构定位：工具层（util）模块
 *   - 不依赖任何上层模块（controller / service / repository）
 *   - 不输出日志
 *
 * 设计说明：
 *   - Windows 平台通过 GetDiskFreeSpaceExW 系统调用查询
 *   - 非 Windows 平台返回 None（当前仅支持 Windows）
 *   - 字节口径为基准读数；MB 口径为派生视图（保留既有调用方语义）
 */

/// 获取指定路径所在磁盘的剩余空间（字节）
///
/// 入参可以是文件或目录路径（系统调用按卷解析）；路径不存在或无法解析
/// 卷信息返回 None，由调用方按"空间未知"处置，不得按 0 处理。
pub fn get_disk_space_bytes(path: &std::path::Path) -> Option<u64> {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let path_str: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        #[repr(C)]
        struct DiskFreeSpaceEx {
            free_bytes_available: u64,
            total_bytes: u64,
            total_free_bytes: u64,
        }

        extern "system" {
            fn GetDiskFreeSpaceExW(
                directory: *const u16,
                free_bytes_available: *mut u64,
                total_bytes: *mut u64,
                total_free_bytes: *mut u64,
            ) -> i32;
        }

        unsafe {
            let mut info = DiskFreeSpaceEx {
                free_bytes_available: 0,
                total_bytes: 0,
                total_free_bytes: 0,
            };
            let ret = GetDiskFreeSpaceExW(
                path_str.as_ptr(),
                &mut info.free_bytes_available,
                &mut info.total_bytes,
                &mut info.total_free_bytes,
            );
            if ret != 0 {
                Some(info.free_bytes_available)
            } else {
                None
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        None
    }
}

/// 获取指定路径所在磁盘的剩余空间（MB，字节口径的派生视图）
pub fn get_disk_space_mb(path: &std::path::Path) -> Option<u64> {
    get_disk_space_bytes(path).map(|bytes| bytes / (1024 * 1024))
}
