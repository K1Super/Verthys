/*
 * @file infrastructure/shared_memory.rs
 * @brief 跨进程共享内存只读映射与记录解析
 *
 * 本模块提供 Windows 平台下对 worker 进程写入的共享内存的安全读取能力。
 * 读取完成后以随机字节覆写已消费区域，防止残留数据被恶意进程读取。
 * 同时使用 VirtualLock 锁定物理内存页，避免敏感数据被交换到 pagefile。
 *
 * 核心安全约束：
 * - 所有头部字段和索引条目必须经过边界校验，防止损坏或竞争导致越界访问。
 * - 返回记录数与 worker 头部报告数不一致时视为数据损坏，由上层熔断。
 * - 名称和数据使用 SecuredString 包装，确保 Drop 时内存清零。
 *
 * 依赖 util::base64、util::random、controller::types。
 */

use crate::constants::{
    SHM_ENTRY_SIZE, SHM_HEADER_SIZE, SHM_MAGIC, SHM_MAX_SIZE,
    SHM_SUMMARY_ENTRY_SIZE, SHM_SUMMARY_MAGIC, SHM_SUMMARY_MAX_SIZE,
};
use crate::controller::types::{VerthysRecordEntry, VerthysSummaryEntry};
use crate::util::base64::base64_encode;
use crate::util::random::fill_random_bytes;
use crate::util::secured_string::SecuredString;

/// 句柄/映射清理失败的观测：debug 构建记录失败码，release 与原先
/// `let _=` 行为一致（清理尽力而为：失败不可恢复，不阻断主流程）。
#[cfg(windows)]
fn note_cleanup_failure(op: &str, result: windows::core::Result<()>) {
    #[cfg(debug_assertions)]
    if result.is_err() {
        log::debug!("[shared_memory] 清理失败: {}", op);
    }
    #[cfg(not(debug_assertions))]
    let _ = (op, result);
}

/// 从指定共享内存名称读取完整记录批次。
///
/// 返回三元组：(记录列表, 遍历是否结束, worker 头部声明的 record_count)。
/// 调用方应校验 `records.len() == record_count`，不一致则判定数据损坏并熔断。
///
/// 读取前验证魔数，并严格校验所有偏移和长度，防止恶意或损坏数据导致段错误。
/// 成功读取后使用随机字节覆写整个数据区，确保敏感数据不残留。
///
/// # 安全边界
/// - 拒绝 `record_count > 10000`，防止内存分配耗尽。
/// - 逐条矩形校验：名称字节完整落在名称区、数据字节完整落在数据区
///   （下界 + 上界双约束，坏 offset 拒绝），防 `base.add` 越界指针。
/// - 越界记录跳过而非整体失败，兼容部分损坏场景。
/// - 使用 `VirtualLock` 锁定映射页，防止换出到 pagefile。
#[cfg(windows)]
pub fn read_shm_records(shm_name: &str) -> Result<(Vec<VerthysRecordEntry>, bool, usize), String> {
    use windows::Win32::System::Memory::{
        MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, VirtualLock,
        VirtualUnlock, FILE_MAP_WRITE,
    };
    use windows::Win32::Foundation::CloseHandle;
    use windows::core::PCWSTR;

    let wide: Vec<u16> = shm_name.encode_utf16().chain(std::iter::once(0u16)).collect();

    unsafe {
        let handle = OpenFileMappingW(FILE_MAP_WRITE.0, false, PCWSTR::from_raw(wide.as_ptr()))
            .map_err(|e| format!("OpenFileMappingW failed: {}", e))?;

        let addr = MapViewOfFile(handle, FILE_MAP_WRITE, 0, 0, 0);
        let base = addr.Value as *const u8;
        if base.is_null() {
            note_cleanup_failure("CloseHandle", CloseHandle(handle));
            return Err("MapViewOfFile failed: null pointer".into());
        }

        let lock_size = SHM_MAX_SIZE;
        note_cleanup_failure("VirtualLock", VirtualLock(base as *const _, lock_size));

        // 验证魔数
        let magic = *(base as *const u32);
        if magic != SHM_MAGIC {
            note_cleanup_failure("VirtualUnlock", VirtualUnlock(base as *const _, lock_size));
            note_cleanup_failure("UnmapViewOfFile", UnmapViewOfFile(addr));
            note_cleanup_failure("CloseHandle", CloseHandle(handle));
            return Err("shared memory magic mismatch".into());
        }

        // 解析头部元数据
        let record_count = *(base.add(8) as *const u64) as usize;
        let total_name_bytes = *(base.add(16) as *const u64) as usize;
        let total_data_bytes = *(base.add(24) as *const u64) as usize;
        let exhausted = *(base.add(32) as *const u32) != 0;

        if record_count > 10_000 {
            note_cleanup_failure("VirtualUnlock", VirtualUnlock(base as *const _, lock_size));
            note_cleanup_failure("UnmapViewOfFile", UnmapViewOfFile(addr));
            note_cleanup_failure("CloseHandle", CloseHandle(handle));
            return Err(format!("shared memory record_count too large: {}", record_count));
        }

        let entries_size = record_count.checked_mul(SHM_ENTRY_SIZE)
            .ok_or_else(|| "record_count * SHM_ENTRY_SIZE overflow".to_string())?;
        let total_size = SHM_HEADER_SIZE.checked_add(entries_size)
            .and_then(|s| s.checked_add(total_name_bytes))
            .and_then(|s| s.checked_add(total_data_bytes))
            .ok_or_else(|| "total_size arithmetic overflow".to_string())?;

        if total_size > SHM_MAX_SIZE {
            note_cleanup_failure("VirtualUnlock", VirtualUnlock(base as *const _, lock_size));
            note_cleanup_failure("UnmapViewOfFile", UnmapViewOfFile(addr));
            note_cleanup_failure("CloseHandle", CloseHandle(handle));
            return Err(format!(
                "shared memory data exceeds SHM_MAX_SIZE: {} > {}",
                total_size, SHM_MAX_SIZE
            ));
        }

        // 遍历索引条目
        // 区域矩形（与 worker 写入布局一致：索引区 → 名称区 → 数据区）：
        // 名称字节必须完整落在名称区、数据字节必须完整落在数据区
        let entries_start = base.add(SHM_HEADER_SIZE);
        let name_region_start = SHM_HEADER_SIZE + entries_size;
        let name_region_end = name_region_start + total_name_bytes;
        let data_region_start = name_region_end;
        let data_region_end = data_region_start + total_data_bytes;

        let mut records = Vec::with_capacity(record_count);
        for i in 0..record_count {
            let entry_ptr = entries_start.add(i * SHM_ENTRY_SIZE);
            let lid = *(entry_ptr as *const u64);
            let rtype = *(entry_ptr.add(8) as *const u32);
            let name_len = *(entry_ptr.add(12) as *const u32) as usize;
            let data_len = *(entry_ptr.add(16) as *const u64) as usize;
            let name_offset = *(entry_ptr.add(24) as *const u64) as usize;
            let data_offset = *(entry_ptr.add(32) as *const u64) as usize;

            // 逐条矩形区间校验：名称/数据字节必须完整落在各自区域内
            //（下界 + 上界双约束；坏 offset 拒绝并跳过该记录——与既有
            // 降级策略一致，防 base.add 越界指针）
            let name_end = name_offset.checked_add(name_len)
                .ok_or_else(|| "name_offset + name_len overflow".to_string())?;
            let data_end = data_offset.checked_add(data_len)
                .ok_or_else(|| "data_offset + data_len overflow".to_string())?;

            let name_in_region = name_len == 0
                || (name_offset >= name_region_start && name_end <= name_region_end);
            let data_in_region = data_len == 0
                || (data_offset >= data_region_start && data_end <= data_region_end);
            if !name_in_region || !data_in_region {
                continue; // 跳过损坏记录
            }

            let name = if name_len > 0 {
                let name_ptr = base.add(name_offset);
                let slice = std::slice::from_raw_parts(name_ptr, name_len);
                String::from_utf8_lossy(slice).into_owned()
            } else {
                String::new()
            };

            let data_b64 = if data_len > 0 {
                let data_ptr = base.add(data_offset);
                let slice = std::slice::from_raw_parts(data_ptr, data_len);
                base64_encode(slice)
            } else {
                String::new()
            };

            records.push(VerthysRecordEntry {
                id: lid,
                rtype,
                name: SecuredString::new(name),
                data: SecuredString::new(data_b64),
                original_size: Some(data_len as u64),
            });
        }

        // 消费完成后用随机字节覆写共享内存，防止残留数据泄露
        log::info!(
            "[read_shm_records] 消费完成: count={}, total_size={}, 开始覆写共享内存",
            record_count, total_size
        );
        let wipe_slice = std::slice::from_raw_parts_mut(base as *mut u8, total_size);
        fill_random_bytes(wipe_slice);

        note_cleanup_failure("VirtualUnlock", VirtualUnlock(base as *const _, lock_size));
        note_cleanup_failure("UnmapViewOfFile", UnmapViewOfFile(addr));
        note_cleanup_failure("CloseHandle", CloseHandle(handle));

        Ok((records, exhausted, record_count))
    }
}

#[cfg(not(windows))]
pub fn read_shm_records(_shm_name: &str) -> Result<(Vec<VerthysRecordEntry>, bool, usize), String> {
    Err("shared memory scan not supported on non-Windows".into())
}

/* ------------------------------------------------------------------ *
 * 摘要扫描共享内存读取（轻量元数据，无数据块）              *
 * ------------------------------------------------------------------ */

/// 读取摘要扫描共享内存，返回轻量级摘要记录列表。
///
/// 与 `read_shm_records` 的区别：
/// - 验证 `SHM_SUMMARY_MAGIC` 而非 `SHM_MAGIC`。
/// - 每条索引条目为 72 字节（含 `data_size`, `physical_offset`, `merkle_leaf`）。
/// - 无独立数据区（`total_data_bytes` 恒为 0，`merkle_leaf` 内联在条目中）。
/// - 返回 `VerthysSummaryEntry` 而非 `VerthysRecordEntry`。
///
/// 同样进行严格的边界校验，消费后覆写共享内存，防止残留。
#[cfg(windows)]
pub fn read_shm_summary_records(shm_name: &str) -> Result<(Vec<VerthysSummaryEntry>, bool, usize), String> {
    use windows::Win32::System::Memory::{
        MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, VirtualLock,
        VirtualUnlock, FILE_MAP_WRITE,
    };
    use windows::Win32::Foundation::CloseHandle;
    use windows::core::PCWSTR;

    let wide: Vec<u16> = shm_name.encode_utf16().chain(std::iter::once(0u16)).collect();

    unsafe {
        let handle = OpenFileMappingW(FILE_MAP_WRITE.0, false, PCWSTR::from_raw(wide.as_ptr()))
            .map_err(|e| format!("OpenFileMappingW failed: {}", e))?;

        let addr = MapViewOfFile(handle, FILE_MAP_WRITE, 0, 0, 0);
        let base = addr.Value as *const u8;
        if base.is_null() {
            note_cleanup_failure("CloseHandle", CloseHandle(handle));
            return Err("MapViewOfFile failed: null pointer".into());
        }

        let lock_size = SHM_SUMMARY_MAX_SIZE;
        note_cleanup_failure("VirtualLock", VirtualLock(base as *const _, lock_size));

        let magic = *(base as *const u32);
        if magic != SHM_SUMMARY_MAGIC {
            note_cleanup_failure("VirtualUnlock", VirtualUnlock(base as *const _, lock_size));
            note_cleanup_failure("UnmapViewOfFile", UnmapViewOfFile(addr));
            note_cleanup_failure("CloseHandle", CloseHandle(handle));
            return Err("shared memory summary magic mismatch".into());
        }

        let record_count = *(base.add(8) as *const u64) as usize;
        let total_name_bytes = *(base.add(16) as *const u64) as usize;
        let total_data_bytes = *(base.add(24) as *const u64) as usize;
        let exhausted = *(base.add(32) as *const u32) != 0;

        if record_count > 10_000 {
            note_cleanup_failure("VirtualUnlock", VirtualUnlock(base as *const _, lock_size));
            note_cleanup_failure("UnmapViewOfFile", UnmapViewOfFile(addr));
            note_cleanup_failure("CloseHandle", CloseHandle(handle));
            return Err(format!("shared memory summary record_count too large: {}", record_count));
        }

        if total_data_bytes != 0 {
            note_cleanup_failure("VirtualUnlock", VirtualUnlock(base as *const _, lock_size));
            note_cleanup_failure("UnmapViewOfFile", UnmapViewOfFile(addr));
            note_cleanup_failure("CloseHandle", CloseHandle(handle));
            return Err(format!("summary total_data_bytes must be 0, got {}", total_data_bytes));
        }

        let entries_size = record_count.checked_mul(SHM_SUMMARY_ENTRY_SIZE)
            .ok_or_else(|| "summary record_count * SHM_SUMMARY_ENTRY_SIZE overflow".to_string())?;
        let total_size = SHM_HEADER_SIZE.checked_add(entries_size)
            .and_then(|s| s.checked_add(total_name_bytes))
            .ok_or_else(|| "summary total_size arithmetic overflow".to_string())?;

        if total_size > SHM_SUMMARY_MAX_SIZE {
            note_cleanup_failure("VirtualUnlock", VirtualUnlock(base as *const _, lock_size));
            note_cleanup_failure("UnmapViewOfFile", UnmapViewOfFile(addr));
            note_cleanup_failure("CloseHandle", CloseHandle(handle));
            return Err(format!(
                "summary shared memory data exceeds SHM_SUMMARY_MAX_SIZE: {} > {}",
                total_size, SHM_SUMMARY_MAX_SIZE
            ));
        }

        let entries_start = base.add(SHM_HEADER_SIZE);
        // 名称区矩形（与 worker 写入布局一致：索引区 → 名称区，无数据区）
        let name_region_start = SHM_HEADER_SIZE + entries_size;
        let name_region_end = name_region_start + total_name_bytes;

        let mut records = Vec::with_capacity(record_count);
        for i in 0..record_count {
            let entry_ptr = entries_start.add(i * SHM_SUMMARY_ENTRY_SIZE);
            let lid = *(entry_ptr as *const u64);
            let rtype = *(entry_ptr.add(8) as *const u32);
            let name_len = *(entry_ptr.add(12) as *const u32) as usize;
            let data_size = *(entry_ptr.add(16) as *const u64);
            let physical_offset = *(entry_ptr.add(24) as *const u64);
            let name_offset = *(entry_ptr.add(32) as *const u64) as usize;
            let merkle_ptr = entry_ptr.add(40);
            let merkle_slice = std::slice::from_raw_parts(merkle_ptr, 32);
            let created_time = *(entry_ptr.add(72) as *const u64);

            // 逐条矩形区间校验：名称字节必须完整落在名称区内
            //（下界 + 上界双约束；坏 offset 拒绝并跳过该记录）
            let name_end = name_offset.checked_add(name_len)
                .ok_or_else(|| "summary name_offset + name_len overflow".to_string())?;
            let name_in_region = name_len == 0
                || (name_offset >= name_region_start && name_end <= name_region_end);
            if !name_in_region {
                continue;
            }

            let name = if name_len > 0 {
                let name_ptr = base.add(name_offset);
                let slice = std::slice::from_raw_parts(name_ptr, name_len);
                String::from_utf8_lossy(slice).into_owned()
            } else {
                String::new()
            };

            records.push(VerthysSummaryEntry {
                id: lid,
                rtype,
                name: SecuredString::new(name),
                data_size,
                physical_offset,
                merkle_leaf: SecuredString::new(base64_encode(merkle_slice)),
                created_time,
            });
        }

        log::info!(
            "[read_shm_summary_records] 消费完成: count={}, total_size={}, 开始覆写共享内存",
            record_count, total_size
        );
        let wipe_slice = std::slice::from_raw_parts_mut(base as *mut u8, total_size);
        fill_random_bytes(wipe_slice);

        note_cleanup_failure("VirtualUnlock", VirtualUnlock(base as *const _, lock_size));
        note_cleanup_failure("UnmapViewOfFile", UnmapViewOfFile(addr));
        note_cleanup_failure("CloseHandle", CloseHandle(handle));

        Ok((records, exhausted, record_count))
    }
}

#[cfg(not(windows))]
pub fn read_shm_summary_records(_shm_name: &str) -> Result<(Vec<VerthysSummaryEntry>, bool, usize), String> {
    Err("shared memory summary scan not supported on non-Windows".into())
}

/* ------------------------------------------------------------------ *
 * 边界校验测试：构造畸形共享内存布局（坏 offset 落在区外/区内重叠）， *
 * 断言坏记录被跳过、好记录被接受、头部计数原样回传。              *
 * ------------------------------------------------------------------ */
#[cfg(all(test, windows))]
mod tests {
    use super::*;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS,
        MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
    };

    /// 测试脚手架：创建 8MB 命名共享内存映射（全零），返回 (句柄, 视图, 名字)
    fn create_test_mapping(tag: &str) -> (HANDLE, MEMORY_MAPPED_VIEW_ADDRESS, String) {
        let name = format!("verthys_shm_test_{}_{}", tag, std::process::id());
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0u16)).collect();
        let size: usize = 8 * 1024 * 1024;

        unsafe {
            let handle = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                None,
                PAGE_READWRITE,
                0,
                size as u32,
                PCWSTR(wide.as_ptr()),
            )
            .expect("CreateFileMappingW");
            /* MapViewOfFile 失败表现为空值（windows 0.58 非 Result 契约） */
            let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, size);
            if view.Value.is_null() {
                let _ = CloseHandle(handle);
                panic!("MapViewOfFile returned null");
            }
            std::ptr::write_bytes(view.Value as *mut u8, 0, size);
            (handle, view, name)
        }
    }

    fn destroy_test_mapping(handle: HANDLE, view: MEMORY_MAPPED_VIEW_ADDRESS) {
        unsafe {
            let _ = UnmapViewOfFile(view);
            let _ = CloseHandle(handle);
        }
    }

    /// 构造 records SHM：header + 条目区 + 名称区 + 数据区（与 worker 写入布局一致）
    /// 条目元组：(lid, rtype, name_len, data_len, name_offset, data_offset)
    #[allow(clippy::type_complexity)]
    unsafe fn write_records_layout(
        base: *mut u8,
        entries: &[(u64, u32, u32, u64, u64, u64)],
        names: &[u8],
        data: &[u8],
    ) {
        *(base as *mut u32) = SHM_MAGIC;
        *((base.add(4)) as *mut u32) = 1u32; /* version */
        *((base.add(8)) as *mut u64) = entries.len() as u64;
        *((base.add(16)) as *mut u64) = names.len() as u64;
        *((base.add(24)) as *mut u64) = data.len() as u64;
        *((base.add(32)) as *mut u32) = 0; /* exhausted */
        *((base.add(36)) as *mut u32) = 0;

        let entries_start = base.add(SHM_HEADER_SIZE);
        for (i, (lid, rtype, nlen, dlen, noff, doff)) in entries.iter().enumerate() {
            let ep = entries_start.add(i * SHM_ENTRY_SIZE);
            *(ep as *mut u64) = *lid;
            *((ep.add(8)) as *mut u32) = *rtype;
            *((ep.add(12)) as *mut u32) = *nlen;
            *((ep.add(16)) as *mut u64) = *dlen;
            *((ep.add(24)) as *mut u64) = *noff;
            *((ep.add(32)) as *mut u64) = *doff;
        }
        let names_start = entries_start.add(entries.len() * SHM_ENTRY_SIZE);
        std::ptr::copy_nonoverlapping(names.as_ptr(), names_start, names.len());
        if !data.is_empty() {
            let data_start = names_start.add(names.len());
            std::ptr::copy_nonoverlapping(data.as_ptr(), data_start, data.len());
        }
    }

    /// 构造 summary SHM：header + 条目区 + 名称区（无数据区）
    /// 条目元组：(lid, rtype, name_len, name_offset)
    unsafe fn write_summary_layout(base: *mut u8, entries: &[(u64, u32, u32, u64)], names: &[u8]) {
        *(base as *mut u32) = SHM_SUMMARY_MAGIC;
        *((base.add(8)) as *mut u64) = entries.len() as u64;
        *((base.add(16)) as *mut u64) = names.len() as u64;
        *((base.add(24)) as *mut u64) = 0; /* 摘要无数据区 */
        *((base.add(32)) as *mut u32) = 0;
        *((base.add(36)) as *mut u32) = 0;

        let entries_start = base.add(SHM_HEADER_SIZE);
        for (i, (lid, rtype, nlen, noff)) in entries.iter().enumerate() {
            let ep = entries_start.add(i * SHM_SUMMARY_ENTRY_SIZE);
            *(ep as *mut u64) = *lid;
            *((ep.add(8)) as *mut u32) = *rtype;
            *((ep.add(12)) as *mut u32) = *nlen;
            *((ep.add(16)) as *mut u64) = 0; /* data_size */
            *((ep.add(24)) as *mut u64) = 0; /* physical_offset */
            *((ep.add(32)) as *mut u64) = *noff;
            /* merkle(32B) 与 created_time 保持零 */
        }
        let names_start = entries_start.add(entries.len() * SHM_SUMMARY_ENTRY_SIZE);
        std::ptr::copy_nonoverlapping(names.as_ptr(), names_start, names.len());
    }

    #[test]
    fn records_bad_name_offset_skipped_good_accepted() {
        let (handle, view, name) = create_test_mapping("records_bounds");
        let base = view.Value as *mut u8;

        /* 布局：header(64) + 2×40 条目 + 名称区 2B；名称区起点 = 144 */
        /* 条目 0：name_offset=8（header 区内）→ 拒绝跳过 */
        /* 条目 1：name_offset=144（名称区起点）→ 接受 */
        let entries = [
            (1u64, 1u32, 2u32, 0u64, 8u64, 0u64),
            (2u64, 1u32, 2u32, 0u64, 144u64, 0u64),
        ];
        unsafe { write_records_layout(base, &entries, b"AB", b"") };

        let (out, _exhausted, count) = read_shm_records(&name).expect("read_shm_records");
        assert_eq!(count, 2, "头部声明计数原样回传");
        assert_eq!(out.len(), 1, "坏 offset 记录被跳过");
        assert_eq!(out[0].id, 2);
        assert_eq!(out[0].name.as_str(), "AB");

        destroy_test_mapping(handle, view);
    }

    #[test]
    fn records_data_offset_out_of_region_skipped() {
        let (handle, view, name) = create_test_mapping("records_data_bounds");
        let base = view.Value as *mut u8;

        /* 布局：header(64) + 2×40 条目 + 名称区 0B + 数据区 8B；
         * 数据区 = [104, 112) */
        /* 条目 0：data_offset=104 但 data_end=112 越过上界 → 拒绝 */
        /* 条目 1：data_offset=96（名称/条目区内）→ 拒绝 */
        let entries = [
            (1u64, 1u32, 0u32, 8u64, 0u64, 104u64),
            (2u64, 1u32, 0u32, 8u64, 0u64, 96u64),
        ];
        unsafe { write_records_layout(base, &entries, b"", b"XXXXXXXX") };

        let (out, _exhausted, count) = read_shm_records(&name).expect("read_shm_records");
        assert_eq!(count, 2);
        assert_eq!(out.len(), 0, "数据区越界/重叠记录全部拒绝");

        destroy_test_mapping(handle, view);
    }

    #[test]
    fn summary_bad_name_offset_skipped_good_accepted() {
        let (handle, view, name) = create_test_mapping("summary_bounds");
        let base = view.Value as *mut u8;

        /* 布局：header(64) + 2×80 条目 + 名称区 2B；名称区起点 = 224 */
        /* 条目 0：name_offset=8（条目区内）→ 拒绝跳过 */
        /* 条目 1：name_offset=224（名称区起点）→ 接受 */
        let entries = [(1u64, 1u32, 2u32, 8u64), (2u64, 1u32, 2u32, 224u64)];
        unsafe { write_summary_layout(base, &entries, b"XY") };

        let (out, _exhausted, count) = read_shm_summary_records(&name).expect("read_shm_summary_records");
        assert_eq!(count, 2);
        assert_eq!(out.len(), 1, "坏 offset 摘要记录被跳过");
        assert_eq!(out[0].id, 2);
        assert_eq!(out[0].name.as_str(), "XY");

        destroy_test_mapping(handle, view);
    }
}