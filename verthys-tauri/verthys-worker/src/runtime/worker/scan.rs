use libloading::Symbol;

#[cfg(windows)]
use crate::runtime::scan_shm;

use crate::runtime::ffi_types::*;

#[cfg(windows)]
use super::ffi_guards::{PlainBatchGuard, SummaryBatchGuard};
#[cfg(windows)]
use super::{clamp_enum_count, ffi_call};
use super::Worker;

impl Worker {
    /* ----------------------------------------------------------------
     * 游标批量扫描（共享内存零拷贝传输）
     * ---------------------------------------------------------------- */

    /// 打开扫描游标 + 创建共享内存 + 首批预加载
    /// 返回 (shm_name, shm_size, record_count, exhausted, failed_lids)
    ///
    /// project / index_inline_max_bytes 为投影参数（FULL=全部记录解密；
    /// INDEX=仅对不超过内联阈值的记录解密取数），取批预算恒取 SHM 水位线
    /// SCAN_BATCH_MAX_BYTES：单批载荷因此恒落在段容量内（取满即返回本批），
    /// 大记录数据集不再出现"单批超容 → 整批失败"。
    #[cfg(windows)]
    pub(crate) fn call_scan_open(&mut self, start_lid: u64, batch_size: u64,
                                 project: u32, index_inline_max_bytes: u64,
                                 auth_key: Option<&[u8]>)
        -> Result<(String, usize, usize, bool, Vec<u64>), u32>
    {
        // 1. 创建共享内存段（VirtualLock + 随机名称）
        let shm = scan_shm::ScanShm::create(scan_shm::SHM_DEFAULT_SIZE)
            .map_err(|_| 0xFFFFFFFFu32)?;
        let shm_name = shm.name().to_string();
        let shm_size = shm.size();

        // 2. 打开 C 游标（复用 vbtree_scan_all，绑定瞬时只读快照）
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysScanOpenExFn> = match lib.get(b"Verthys_ScanOpenEx") {
                Ok(f) => f,
                Err(_) => { shm.destroy(); return Err(0xFFFFFFFF); }
            };
            let mut cursor: VerthysScanCursorPtr = std::ptr::null_mut();
            // 传 C 前同样 clamp：batch_size 进入游标状态，保持与预分配上限一致
            let r = ffi_call(|| { func(self.handle, start_lid, clamp_enum_count(batch_size),
                                      project, index_inline_max_bytes,
                                      scan_shm::SCAN_BATCH_MAX_BYTES, &mut cursor) }).unwrap_or(0xFFFFFFFF);
            if r != VERTHYS_OK {
                shm.destroy();
                return Err(r);
            }
            self.scan_cursor = Some(cursor);
        }

        // 3. 销毁旧共享内存段（如有），存入新段
        if let Some(old) = self.scan_shm.take() {
            old.destroy();
        }
        self.scan_shm = Some(shm);

        // 4. 首批预加载：驱动遍历器填充共享内存（同样携带 SHM 认证密钥）
        let (count, exhausted, failed_ids) = self.fetch_into_shm(batch_size, auth_key)?;
        Ok((shm_name, shm_size, count, exhausted, failed_ids))
    }

    /// 批量拉取记录写入共享内存
    /// 返回 (record_count, exhausted, failed_lids)
    #[cfg(windows)]
    pub(crate) fn call_scan_fetch(
        &mut self,
        max_count: u64,
        auth_key: Option<&[u8]>,
    ) -> Result<(usize, bool, Vec<u64>), u32> {
        self.fetch_into_shm(max_count, auth_key)
    }

    /// 内部：调用 C Verthys_ScanFetch → 拷贝到共享内存 → 释放 C 深拷贝 → 安全擦除临时缓冲
    /// 紧急熔断响应：ScanFetch 返回 VERTHYS_ERR_LOCKED 时立即吊销游标 + 销毁 SHM
    #[cfg(windows)]
    fn fetch_into_shm(
        &mut self,
        max_count: u64,
        auth_key: Option<&[u8]>,
    ) -> Result<(usize, bool, Vec<u64>), u32> {
        const VERTHYS_ERR_LOCKED: u32 = 0x00000007;
        let cursor = match self.scan_cursor {
            Some(c) => c,
            None => return Err(0xFFFFFFFF),
        };
        let shm = match self.scan_shm.as_mut() {
            Some(s) => s,
            None => return Err(0xFFFFFFFF),
        };
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysScanFetchFn> = match lib.get(b"Verthys_ScanFetch") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };
            let free_fn: Symbol<VerthysScanRecordFreeFn> = match lib.get(b"Verthys_ScanRecordFree") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };

            // 上限截断后以同一值驱动预分配与 FFI：两者尺寸必须一致，
            // C 端按传入条数写入 out_count 条，缓冲过小即溢出
            let mc = clamp_enum_count(max_count) as usize;
            let mut records: Vec<VerthysRecordC> = (0..mc).map(|_| VerthysRecordC {
                rtype: 0, name: std::ptr::null(), name_len: 0,
                data: std::ptr::null(), data_len: 0,
            }).collect();
            let mut lids: Vec<u64> = vec![0u64; mc];
            let mut out_count: u64 = 0;
            /* 失败条目清单：C 端按 lid 记账解密失败/索引不一致的条目
             * （不静默丢弃），此处必须传入真实缓冲——传 NULL 会让上层
             * 完全看不到损坏条目，把"损坏"误当"不存在"。
             * 缓冲按本批条数上限分配，超出部分 C 端不再写（计数仍报总数）。 */
            let mut failed_lids: Vec<u64> = vec![0u64; mc];
            let mut out_failed_count: u64 = 0;
            let r = ffi_call(|| { func(cursor, records.as_mut_ptr(), lids.as_mut_ptr(), mc as u64,
                                      &mut out_count, failed_lids.as_mut_ptr(),
                                      &mut out_failed_count) }).unwrap_or(0xFFFFFFFF);
            if r != VERTHYS_OK {
                // 紧急熔断吊销：ScanFetch 返回 LOCKED 表示 emergency_is_triggered
                // 或游标已被标记 invalidated，立即销毁 SHM 缓冲区 + 关闭游标
                if r == VERTHYS_ERR_LOCKED {
                    self.revoke_scan_cursor();
                }
                return Err(r);
            }

            // 从 C 深拷贝收集到守卫化临时缓冲（Drop 三轮覆写，含写 SHM 失败的提前返回路径）
            let mut result = PlainBatchGuard::with_capacity(out_count as usize);
            for i in 0..out_count as usize {
                let rec = &records[i];
                let name = if !rec.name.is_null() && rec.name_len > 0 {
                    let slice = std::slice::from_raw_parts(rec.name as *const u8, rec.name_len);
                    String::from_utf8_lossy(slice).into_owned()
                } else { String::new() };
                let data = if !rec.data.is_null() && rec.data_len > 0 {
                    let slice = std::slice::from_raw_parts(rec.data, rec.data_len);
                    slice.to_vec()
                } else { Vec::new() };
                result.push((lids[i], rec.rtype, name, data));

                // 释放 C 深拷贝（含安全擦除）
                let _ = ffi_call(|| { free_fn(&mut records[i] as *mut VerthysRecordC) }).unwrap_or(0xFFFFFFFF);
            }

            // 失败条目：仅取缓冲范围内已写入的 lid（计数可能大于缓冲容量）
            let failed: Vec<u64> = failed_lids
                .iter()
                .take((out_failed_count as usize).min(mc))
                .copied()
                .collect();

            let exhausted = out_count == 0;

            // 写入共享内存（内部先 3 轮擦除旧数据）
            // 失败时 ? 提前返回 → 守卫 Drop 仍三轮覆写全部明文行
            let count = shm.write_records(result.rows(), exhausted, auth_key).map_err(|_| 0xFFFFFFFFu32)?;

            // 成功路径由守卫 Drop 在函数返回时统一擦除
            Ok((count, exhausted, failed))
        }
    }

    /// 紧急熔断吊销：擦除存储进程侧 SHM 缓冲区 + 关闭游标 + 标记句柄无效
    /// 安全模块通知存储进程立即吊销所有活跃游标，
    /// 吊销动作包括擦除缓冲区、关闭游标、标记句柄无效
    #[cfg(windows)]
    fn revoke_scan_cursor(&mut self) {
        // 1. 销毁共享内存缓冲区（随机字节覆写 → 解锁 → 取消映射 → 关闭句柄）
        if let Some(shm) = self.scan_shm.take() {
            shm.destroy();
        }
        // 2. 关闭 C 游标（注销 memory_guard → 解锁 → 安全擦除 → 释放）
        if let Some(cursor) = self.scan_cursor.take() {
            unsafe {
                let lib = &self._lib;
                if let Ok(func) = lib.get(b"Verthys_ScanClose") {
                    let func: Symbol<VerthysScanCloseFn> = func;
                    let _ = ffi_call(|| { func(cursor) });
                }
            }
        }
    }

    /// 关闭扫描游标 + 销毁共享内存
    #[cfg(windows)]
    pub(crate) fn call_scan_close(&mut self) -> u32 {
        // 销毁共享内存（擦除 → 解锁 → 取消映射 → 关闭句柄）
        if let Some(shm) = self.scan_shm.take() {
            shm.destroy();
        }
        // 关闭 C 游标（注销 memory_guard → 解锁 → 擦除 → 释放）
        let cursor = match self.scan_cursor.take() {
            Some(c) => c,
            None => return 0,
        };
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysScanCloseFn> = match lib.get(b"Verthys_ScanClose") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            ffi_call(|| { func(cursor) }).unwrap_or(0xFFFFFFFF)
        }
    }

    /* 非 Windows 平台：游标扫描不支持，返回错误 */
    #[cfg(not(windows))]
    pub(crate) fn call_scan_open(&mut self, _start_lid: u64, _batch_size: u64, _auth_key: Option<&[u8]>)
        -> Result<(String, usize, usize, bool), u32> { Err(0xFFFFFFFF) }
    #[cfg(not(windows))]
    pub(crate) fn call_scan_fetch(&mut self, _max_count: u64, _auth_key: Option<&[u8]>) -> Result<(usize, bool), u32> { Err(0xFFFFFFFF) }
    #[cfg(not(windows))]
    pub(crate) fn call_scan_close(&mut self) -> u32 { 0xFFFFFFFF }

    /* ================================================================ *
     * 摘要扫描（轻量元数据，不读数据块）                       *
     *                                                                  *
     * 与全量扫描的区别：                                                *
     *   - 复用 VerthysScanCursor 游标结构（Open 逻辑相同）               *
     *   - Fetch 调用 Verthys_ScanSummaryFetch，仅提取索引元数据           *
     *   - SHM 写入 write_summary_records（72B 条目，无数据块）          *
     *   - Close 复用 call_scan_close（Verthys_ScanClose 不区分摘要/全量） *
     * ================================================================ */

    /// 打开摘要扫描游标 + 创建共享内存 + 首批预加载
    /// 返回 (shm_name, shm_size, record_count, exhausted)
    ///
    /// 摘要扫描使用更小的 SHM（4MB），因为元数据体积极小。
    /// 游标复用 self.scan_cursor 字段（与全量扫描互斥，不会并发）。
    #[cfg(windows)]
    pub(crate) fn call_scan_summary_open(&mut self, start_lid: u64, batch_size: u64,
                                         auth_key: Option<&[u8]>)
        -> Result<(String, usize, usize, bool), u32>
    {
        // 1. 创建摘要专用共享内存段（4MB，VirtualLock + 随机名称）
        let shm = scan_shm::ScanShm::create(scan_shm::SHM_SUMMARY_DEFAULT_SIZE)
            .map_err(|_| 0xFFFFFFFFu32)?;
        let shm_name = shm.name().to_string();
        let shm_size = shm.size();

        // 2. 打开 C 摘要扫描游标（Verthys_ScanSummaryOpen，复用 VerthysScanCursor 结构）
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysScanSummaryOpenFn> = match lib.get(b"Verthys_ScanSummaryOpen") {
                Ok(f) => f,
                Err(_) => { shm.destroy(); return Err(0xFFFFFFFF); }
            };
            let mut cursor: VerthysScanCursorPtr = std::ptr::null_mut();
            // 传 C 前同样 clamp：与全量扫描同纪律
            let r = ffi_call(|| { func(self.handle, start_lid, clamp_enum_count(batch_size), &mut cursor) }).unwrap_or(0xFFFFFFFF);
            if r != VERTHYS_OK {
                shm.destroy();
                return Err(r);
            }
            self.scan_cursor = Some(cursor);
        }

        // 3. 销毁旧共享内存段（如有），存入新段
        if let Some(old) = self.scan_shm.take() {
            old.destroy();
        }
        self.scan_shm = Some(shm);

        // 4. 首批预加载：驱动摘要遍历器填充共享内存（同样携带 SHM 认证密钥）
        let (count, exhausted) = self.fetch_summary_into_shm(batch_size, auth_key)?;
        Ok((shm_name, shm_size, count, exhausted))
    }

    /// 批量拉取摘要记录写入共享内存
    /// 返回 (record_count, exhausted)
    #[cfg(windows)]
    pub(crate) fn call_scan_summary_fetch(
        &mut self,
        max_count: u64,
        auth_key: Option<&[u8]>,
    ) -> Result<(usize, bool), u32> {
        self.fetch_summary_into_shm(max_count, auth_key)
    }

    /// 内部：调用 C Verthys_ScanSummaryFetch → 拷贝到共享内存 → 释放 C 深拷贝 → 安全擦除临时缓冲
    /// 紧急熔断响应：ScanSummaryFetch 返回 VERTHYS_ERR_LOCKED 时立即吊销游标 + 销毁 SHM
    #[cfg(windows)]
    fn fetch_summary_into_shm(
        &mut self,
        max_count: u64,
        auth_key: Option<&[u8]>,
    ) -> Result<(usize, bool), u32> {
        const VERTHYS_ERR_LOCKED: u32 = 0x00000007;
        let cursor = match self.scan_cursor {
            Some(c) => c,
            None => return Err(0xFFFFFFFF),
        };
        let shm = match self.scan_shm.as_mut() {
            Some(s) => s,
            None => return Err(0xFFFFFFFF),
        };
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysScanSummaryFetchFn> = match lib.get(b"Verthys_ScanSummaryFetch") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };
            let free_fn: Symbol<VerthysScanSummaryRecordFreeFn> =
                match lib.get(b"Verthys_ScanSummaryRecordFree") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };

            // 上限截断后以同一值驱动预分配与 FFI（与全量扫描同纪律）
            let mc = clamp_enum_count(max_count) as usize;
            let mut records: Vec<VerthysSummaryRecordC> = (0..mc).map(|_| VerthysSummaryRecordC {
                lid: 0,
                rtype: 0,
                name_len: 0,
                name: std::ptr::null(),
                data_size: 0,
                physical_offset: 0,
                merkle_leaf: [0u8; 32],
                created_time: 0,
                slot_state: 0,    /* 根治：与 C 端对齐 */
            }).collect();
            let mut lids: Vec<u64> = vec![0u64; mc];
            let mut out_count: u64 = 0;

            let r = ffi_call(|| { func(cursor, records.as_mut_ptr(), lids.as_mut_ptr(), mc as u64, &mut out_count) }).unwrap_or(0xFFFFFFFF);
            if r != VERTHYS_OK {
                // 紧急熔断吊销：ScanSummaryFetch 返回 LOCKED 表示 emergency_is_triggered
                // 或游标已被标记 invalidated，立即销毁 SHM 缓冲区 + 关闭游标
                if r == VERTHYS_ERR_LOCKED {
                    self.revoke_scan_cursor();
                }
                return Err(r);
            }

            // 从 C 深拷贝收集到守卫化临时缓冲（摘要元组：无数据块，含 created_time 字段）
            // Drop 三轮覆写（name 明文 + merkle_leaf 哈希），含写 SHM 失败的提前返回路径
            let mut result = SummaryBatchGuard::with_capacity(out_count as usize);
            for rec in records.iter_mut().take(out_count as usize) {
                let name = if !rec.name.is_null() && rec.name_len > 0 {
                    let slice = std::slice::from_raw_parts(rec.name, rec.name_len as usize);
                    String::from_utf8_lossy(slice).into_owned()
                } else {
                    String::new()
                };
                result.push((
                    rec.lid,
                    rec.rtype,
                    name,
                    rec.data_size,
                    rec.physical_offset,
                    rec.merkle_leaf,
                    rec.created_time,
                ));

                // 释放 C 深拷贝（name 被安全擦除并释放，merkle_leaf 擦除）
                let _ = ffi_call(|| { free_fn(rec as *mut VerthysSummaryRecordC) }).unwrap_or(0xFFFFFFFF);
            }

            let exhausted = out_count == 0;

            // 写入共享内存（内部先随机覆写旧数据）
            // 失败时 ? 提前返回 → 守卫 Drop 仍三轮覆写全部摘要行
            let count = shm.write_summary_records(result.rows(), exhausted, auth_key).map_err(|_| 0xFFFFFFFFu32)?;

            // 成功路径由守卫 Drop 在函数返回时统一擦除
            Ok((count, exhausted))
        }
    }

    /* 非 Windows 平台：摘要扫描不支持，返回错误 */
    #[cfg(not(windows))]
    pub(crate) fn call_scan_summary_open(&mut self, _start_lid: u64, _batch_size: u64, _auth_key: Option<&[u8]>)
        -> Result<(String, usize, usize, bool), u32> { Err(0xFFFFFFFF) }
    #[cfg(not(windows))]
    pub(crate) fn call_scan_summary_fetch(&mut self, _max_count: u64, _auth_key: Option<&[u8]>) -> Result<(usize, bool), u32> { Err(0xFFFFFFFF) }
}
