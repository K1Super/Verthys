use libloading::Symbol;

use crate::log::diag;
use crate::runtime::ffi_types::*;

use super::{ffi_call, Worker};

impl Worker {
    pub(crate) fn call_add_record(&self, rtype: u32, name: &str, data: &[u8]) -> Result<u64, u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysAddRecordFn> = match lib.get(b"Verthys_AddRecord") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };
            let name_c = match std::ffi::CString::new(name) {
                Ok(c) => c,
                Err(_) => {
                    // 嵌入 NUL 的记录名：日志只记字节长度，不回显原始内容（防日志注入）
                    diag!("[worker] add_record: 名称含内嵌 NUL，length={}", name.len());
                    return Err(0xFFFFFFFF);
                }
            };
            let rec = VerthysRecordC {
                rtype,
                name: name_c.as_ptr(),
                name_len: name.len(),
                data: data.as_ptr(),
                data_len: data.len(),
            };
            let mut id: u64 = 0;
            let r = ffi_call(|| { func(self.handle, &rec, &mut id) }).unwrap_or(0xFFFFFFFF);
            if r == VERTHYS_OK {
                Ok(id)
            } else {
                Err(r)
            }
        }
    }

    /// 批量新增记录（API 0x0013）：单次 C 层事务提交，返回与输入等长的 ID 列表。
    ///
    /// 调用方（dispatch）负责构造稳定的 CString 与数据缓冲，并保证切片内的
    /// 指针在调用期间有效；本方法只负责 FFI 调用与错误码转换。
    pub(crate) fn call_add_records(&self, records: &[VerthysRecordC]) -> Result<Vec<u64>, u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysAddRecordsFn> = match lib.get(b"Verthys_AddRecords") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };
            let mut ids = vec![0u64; records.len()];
            let r = ffi_call(|| {
                func(self.handle, records.as_ptr(), records.len() as u32, ids.as_mut_ptr())
            })
            .unwrap_or(0xFFFFFFFF);
            if r == VERTHYS_OK {
                Ok(ids)
            } else {
                Err(r)
            }
        }
    }

    pub(crate) fn call_get_record(&self, id: u64) -> Result<(u32, String, Vec<u8>), u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetRecordFn> = match lib.get(b"Verthys_GetRecord") {
                Ok(f) => f,
                Err(_) => return Err(0xFFFFFFFF),
            };
            let mut rec = VerthysRecordC {
                rtype: 0,
                name: std::ptr::null(),
                name_len: 0,
                data: std::ptr::null(),
                data_len: 0,
            };
            let r = ffi_call(|| { func(self.handle, id, &mut rec) }).unwrap_or(0xFFFFFFFF);
            if r != VERTHYS_OK {
                return Err(r);
            }
            // 借用指针：立即拷贝数据（下次调用或 Lock 前有效）
            let name = if !rec.name.is_null() && rec.name_len > 0 {
                let slice = std::slice::from_raw_parts(rec.name as *const u8, rec.name_len);
                String::from_utf8_lossy(slice).into_owned()
            } else {
                String::new()
            };
            let data = if !rec.data.is_null() && rec.data_len > 0 {
                let slice = std::slice::from_raw_parts(rec.data, rec.data_len);
                slice.to_vec()
            } else {
                Vec::new()
            };
            /* 借用指针已深拷贝到自有缓冲，立即清零 C 层缓存，
             * 缩短明文在 DLL 堆中的驻留窗口。旧 DLL 不导出该符号时
             * 保持原行为，由 next GetRecord/Lock 失效缓存。 */
            if let Ok(clear) = lib.get::<VerthysClearRecordCacheFn>(b"Verthys_ClearRecordCache") {
                let _ = ffi_call(|| { clear(self.handle) });
            }
            Ok((rec.rtype, name, data))
        }
    }


    pub(crate) fn call_delete_record(&self, id: u64) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysDeleteRecordFn> = match lib.get(b"Verthys_DeleteRecord") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            ffi_call(|| { func(self.handle, id) }).unwrap_or(0xFFFFFFFF)
        }
    }

    /// 原子替换单条记录（API 0x0017）：同一次提交内墓碑化旧记录并写入新记录。
    ///
    /// 旧核心未导出该符号时返回 `VERTHYS_SYMBOL_UNSUPPORTED`，调用方回退
    /// 到"写新 + 读回 + 删旧"路径；真实调用失败原样返回 C 层错误码。
    pub(crate) fn call_replace_record(
        &self,
        old_id: u64,
        rtype: u32,
        name: &str,
        data: &[u8],
    ) -> Result<u64, u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysReplaceRecordFn> =
                match lib.get(b"Verthys_ReplaceRecord") {
                    Ok(f) => f,
                    Err(_) => return Err(VERTHYS_SYMBOL_UNSUPPORTED),
                };
            let name_c = match std::ffi::CString::new(name) {
                Ok(c) => c,
                Err(_) => {
                    diag!("[worker] replace_record: 名称含内嵌 NUL，length={}", name.len());
                    return Err(0xFFFFFFFF);
                }
            };
            let rec = VerthysRecordC {
                rtype,
                name: name_c.as_ptr(),
                name_len: name.len(),
                data: data.as_ptr(),
                data_len: data.len(),
            };
            let mut new_id: u64 = 0;
            let r = ffi_call(|| { func(self.handle, old_id, &rec, &mut new_id) })
                .unwrap_or(0xFFFFFFFF);
            if r == VERTHYS_OK {
                Ok(new_id)
            } else {
                Err(r)
            }
        }
    }

    /// 批量删除记录（单次事务，合并为单次 flush）
    /// C 层在单事务内逐条删除，最后一次收口（一次 PREPARE → COMMIT → CONFIRM），
    /// 磁盘写入量与条目数解耦；任一 ID 不存在则整体回滚为 NOTFOUND。
    pub(crate) fn call_delete_records(&self, ids: &[u64]) -> u32 {
        if ids.is_empty() {
            return 0; /* VERTHYS_OK */
        }
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysDeleteRecordsFn> = match lib.get(b"Verthys_DeleteRecords") {
                Ok(f) => f,
                Err(_) => return 0xFFFFFFFF,
            };
            ffi_call(|| { func(self.handle, ids.as_ptr(), ids.len()) }).unwrap_or(0xFFFFFFFF)
        }
    }

    /// 获取已加载的轻量摘要记录数
    /// 返回解锁时从 summary_index_off 加载的摘要记录数（0=无摘要索引）
    pub(crate) fn call_get_summary_count(&self) -> (u32, u64) {
        let mut count: u64 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetSummaryCountFn> = match lib.get(b"Verthys_GetSummaryCount") {
                Ok(f) => f,
                Err(_) => return (0xFFFFFFFF, 0),
            };
            let rc = ffi_call(|| { func(self.handle, &mut count as *mut u64) }).unwrap_or(0xFFFFFFFF);
            (rc, count)
        }
    }

    /// ：轻量级记录类型存在性检查
    /// 仅遍历 B+ 树索引节点检查 type 字段，不读数据块，典型 < 100ms
    /// 返回 (rc, found)：rc=0 成功（found=0/1），rc!=0 失败
    pub(crate) fn call_has_record_by_type(&self, rtype: u8) -> (u32, bool) {
        let mut found: u8 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysHasRecordByTypeFn> = match lib.get(b"Verthys_HasRecordByType") {
                Ok(f) => f,
                Err(_) => return (0xFFFFFFFF, false),
            };
            let rc = ffi_call(|| { func(self.handle, rtype, &mut found as *mut u8) }).unwrap_or(0xFFFFFFFF);
            (rc, found != 0)
        }
    }

    /// 进程内查找指定类型的首条记录 lid
    /// 返回 (rc, found, lid)：rc=0 成功（found=0/1），rc!=0 失败
    /// 与 call_has_record_by_type 的关键差异：
    ///   1. 同时返回 lid，省去二次 find_lid IPC 往返
    ///   2. 格式不符时 C 层返回 FORMAT（无旧格式兼容分支）
    pub(crate) fn call_find_first_lid_by_type(&self, rtype: u8) -> (u32, bool, u64) {
        let mut found: u8 = 0;
        let mut lid: u64 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysFindFirstLidByTypeFn> =
                match lib.get(b"Verthys_FindFirstLidByType") {
                    Ok(f) => f,
                    Err(_) => return (0xFFFFFFFF, false, 0),
                };
            let rc = ffi_call(|| { func(self.handle, rtype, &mut found as *mut u8, &mut lid as *mut u64) }).unwrap_or(0xFFFFFFFF);
            (rc, found != 0, lid)
        }
    }

    /// 按名称精确查找记录 ID（名称盲索引，API 0x0015）。
    ///
    /// 未命中返回 Ok((false, 0))；符号缺失或 C 层错误返回 Err(rc)。
    pub(crate) fn call_find_lid_by_name(&self, name: &str) -> Result<(bool, u64), u32> {
        if name.is_empty() {
            return Err(0x00000001);
        }
        let c_name = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => return Err(0x00000001),
        };
        let mut found: u8 = 0;
        let mut lid: u64 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysFindLidByNameFn> =
                match lib.get(b"Verthys_FindLidByName") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let rc = ffi_call(|| {
                func(
                    self.handle,
                    c_name.as_ptr(),
                    name.len(),
                    &mut found as *mut u8,
                    &mut lid as *mut u64,
                )
            })
            .unwrap_or(0xFFFFFFFF);
            if rc != 0 {
                Err(rc)
            } else {
                Ok((found != 0, lid))
            }
        }
    }

    /// 按类型分页枚举记录 ID（类型盲索引，API 0x0012）。
    /// 不读取记录密文；out_ids 长度必须 >= max_count。
    pub(crate) fn call_list_ids_by_type(
        &self,
        rtype: u8,
        after_id: u64,
        max_count: u64,
        out_ids: &mut [u64],
        out_count: &mut u64,
        out_exhausted: &mut u8,
    ) -> u32 {
        if max_count == 0u64 || (out_ids.len() as u64) < max_count {
            return 0xFFFFFFFF;
        }
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysListIdsByTypeFn> =
                match lib.get(b"Verthys_ListIdsByType") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            ffi_call(|| {
                func(
                    self.handle,
                    rtype,
                    after_id,
                    max_count,
                    out_ids.as_mut_ptr(),
                    out_count as *mut u64,
                    out_exhausted as *mut u8,
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }

    /// 全量存活记录 ID 枚举（目录叶迭代，可选符号）。
    ///
    /// 不读取记录段、不解密名称，与模块锁定状态无关；旧 DLL 缺符号时
    /// 返回 VERTHYS_SYMBOL_UNSUPPORTED，由宿主跳过收敛（保守保留去重键）。
    pub(crate) fn call_list_all_lids(
        &self,
        after_id: u64,
        max_count: u64,
        out_ids: &mut [u64],
        out_count: &mut u64,
        out_exhausted: &mut u8,
    ) -> u32 {
        if max_count == 0u64 || (out_ids.len() as u64) < max_count {
            return 0xFFFFFFFF;
        }
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysListAllLidsFn> = match lib.get(b"Verthys_ListAllLids") {
                Ok(f) => f,
                Err(_) => return VERTHYS_SYMBOL_UNSUPPORTED,
            };
            ffi_call(|| {
                func(
                    self.handle,
                    after_id,
                    max_count,
                    out_ids.as_mut_ptr(),
                    out_count as *mut u64,
                    out_exhausted as *mut u8,
                )
            })
            .unwrap_or(0xFFFFFFFF)
        }
    }
}
