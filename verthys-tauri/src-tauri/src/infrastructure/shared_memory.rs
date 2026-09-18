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
/// - 逐条校验 `name_offset + name_len` 和 `data_offset + data_len` 不超过 `SHM_MAX_SIZE`。
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
            let _ = CloseHandle(handle);
            return Err("MapViewOfFile failed: null pointer".into());
        }

        let lock_size = SHM_MAX_SIZE;
        let _ = VirtualLock(base as *const _, lock_size);

        // 验证魔数
        let magic = *(base as *const u32);
        if magic != SHM_MAGIC {
            let _ = VirtualUnlock(base as *const _, lock_size);
            let _ = UnmapViewOfFile(addr);
            let _ = CloseHandle(handle);
            return Err("shared memory magic mismatch".into());
        }

        // 解析头部元数据
        let record_count = *(base.add(8) as *const u64) as usize;
        let total_name_bytes = *(base.add(16) as *const u64) as usize;
        let total_data_bytes = *(base.add(24) as *const u64) as usize;
        let exhausted = *(base.add(32) as *const u32) != 0;

        if record_count > 10_000 {
            let _ = VirtualUnlock(base as *const _, lock_size);
            let _ = UnmapViewOfFile(addr);
            let _ = CloseHandle(handle);
            return Err(format!("shared memory record_count too large: {}", record_count));
        }

        let entries_size = record_count.checked_mul(SHM_ENTRY_SIZE)
            .ok_or_else(|| "record_count * SHM_ENTRY_SIZE overflow".to_string())?;
        let total_size = SHM_HEADER_SIZE.checked_add(entries_size)
            .and_then(|s| s.checked_add(total_name_bytes))
            .and_then(|s| s.checked_add(total_data_bytes))
            .ok_or_else(|| "total_size arithmetic overflow".to_string())?;

        if total_size > SHM_MAX_SIZE {
            let _ = VirtualUnlock(base as *const _, lock_size);
            let _ = UnmapViewOfFile(addr);
            let _ = CloseHandle(handle);
            return Err(format!(
                "shared memory data exceeds SHM_MAX_SIZE: {} > {}",
                total_size, SHM_MAX_SIZE
            ));
        }

        // 遍历索引条目
        let entries_start = base.add(SHM_HEADER_SIZE);
        let names_start = entries_start.add(entries_size);
        let _data_start = names_start.add(total_name_bytes);

        let mut records = Vec::with_capacity(record_count);
        for i in 0..record_count {
            let entry_ptr = entries_start.add(i * SHM_ENTRY_SIZE);
            let lid = *(entry_ptr as *const u64);
            let rtype = *(entry_ptr.add(8) as *const u32);
            let name_len = *(entry_ptr.add(12) as *const u32) as usize;
            let data_len = *(entry_ptr.add(16) as *const u64) as usize;
            let name_offset = *(entry_ptr.add(24) as *const u64) as usize;
            let data_offset = *(entry_ptr.add(32) as *const u64) as usize;

            // 校验每条记录的偏移和长度是否超出安全边界
            let name_end = name_offset.checked_add(name_len)
                .ok_or_else(|| "name_offset + name_len overflow".to_string())?;
            let data_end = data_offset.checked_add(data_len)
                .ok_or_else(|| "data_offset + data_len overflow".to_string())?;

            if name_end > SHM_MAX_SIZE || data_end > SHM_MAX_SIZE {
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

        let _ = VirtualUnlock(base as *const _, lock_size);
        let _ = UnmapViewOfFile(addr);
        let _ = CloseHandle(handle);

        Ok((records, exhausted, record_count))
    }
}

#[cfg(not(windows))]
pub fn read_shm_records(_shm_name: &str) -> Result<(Vec<VerthysRecordEntry>, bool, usize), String> {
    Err("shared memory scan not supported on non-Windows".into())
}

/* ------------------------------------------------------------------ *
 * 摘要扫描共享内存读取（Phase 2C：轻量元数据，无数据块）              *
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
            let _ = CloseHandle(handle);
            return Err("MapViewOfFile failed: null pointer".into());
        }

        let lock_size = SHM_SUMMARY_MAX_SIZE;
        let _ = VirtualLock(base as *const _, lock_size);

        let magic = *(base as *const u32);
        if magic != SHM_SUMMARY_MAGIC {
            let _ = VirtualUnlock(base as *const _, lock_size);
            let _ = UnmapViewOfFile(addr);
            let _ = CloseHandle(handle);
            return Err("shared memory summary magic mismatch".into());
        }

        let record_count = *(base.add(8) as *const u64) as usize;
        let total_name_bytes = *(base.add(16) as *const u64) as usize;
        let total_data_bytes = *(base.add(24) as *const u64) as usize;
        let exhausted = *(base.add(32) as *const u32) != 0;

        if record_count > 10_000 {
            let _ = VirtualUnlock(base as *const _, lock_size);
            let _ = UnmapViewOfFile(addr);
            let _ = CloseHandle(handle);
            return Err(format!("shared memory summary record_count too large: {}", record_count));
        }

        if total_data_bytes != 0 {
            let _ = VirtualUnlock(base as *const _, lock_size);
            let _ = UnmapViewOfFile(addr);
            let _ = CloseHandle(handle);
            return Err(format!("summary total_data_bytes must be 0, got {}", total_data_bytes));
        }

        let entries_size = record_count.checked_mul(SHM_SUMMARY_ENTRY_SIZE)
            .ok_or_else(|| "summary record_count * SHM_SUMMARY_ENTRY_SIZE overflow".to_string())?;
        let total_size = SHM_HEADER_SIZE.checked_add(entries_size)
            .and_then(|s| s.checked_add(total_name_bytes))
            .ok_or_else(|| "summary total_size arithmetic overflow".to_string())?;

        if total_size > SHM_SUMMARY_MAX_SIZE {
            let _ = VirtualUnlock(base as *const _, lock_size);
            let _ = UnmapViewOfFile(addr);
            let _ = CloseHandle(handle);
            return Err(format!(
                "summary shared memory data exceeds SHM_SUMMARY_MAX_SIZE: {} > {}",
                total_size, SHM_SUMMARY_MAX_SIZE
            ));
        }

        let entries_start = base.add(SHM_HEADER_SIZE);
        let _names_start = entries_start.add(entries_size);

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

            let name_end = name_offset.checked_add(name_len)
                .ok_or_else(|| "summary name_offset + name_len overflow".to_string())?;
            if name_end > SHM_SUMMARY_MAX_SIZE {
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

        let _ = VirtualUnlock(base as *const _, lock_size);
        let _ = UnmapViewOfFile(addr);
        let _ = CloseHandle(handle);

        Ok((records, exhausted, record_count))
    }
}

#[cfg(not(windows))]
pub fn read_shm_summary_records(_shm_name: &str) -> Result<(Vec<VerthysSummaryEntry>, bool, usize), String> {
    Err("shared memory summary scan not supported on non-Windows".into())
}