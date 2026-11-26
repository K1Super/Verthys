use crate::log::init_diag;

#[cfg(windows)]
use crate::runtime::scan_shm;

/* ------------------------------------------------------------------ *
 * 扫描临时缓冲 RAII 守卫（Windows）                                    *
 *                                                                    *
 * 原实现：写入共享内存成功后手工循环三轮覆写临时缓冲；                  *
 * 写入失败（? 提前返回）时擦除循环被整体跳过，明文残留。               *
 *                                                                    *
 * 守卫化：Drop 时统一三轮覆写（0x00 → 0xFF → 0x00），                  *
 * 任何提前返回路径（含 ? 传播/panic）均被覆盖。                        *
 * ------------------------------------------------------------------ */

/// 三轮覆写擦除（len=0 时为空操作，避免对空缓冲取悬垂指针）
#[cfg(windows)]
fn overwrite_3rounds(p: *mut u8, len: usize) {
    if len == 0 {
        return;
    }
    unsafe {
        std::ptr::write_bytes(p, 0x00, len);
        std::ptr::write_bytes(p, 0xFF, len);
        std::ptr::write_bytes(p, 0x00, len);
    }
}

/// 全量扫描临时缓冲守卫：(lid, rtype, name, data)
#[cfg(windows)]
pub(super) struct PlainBatchGuard {
    pub(super) rows: Vec<(u64, u32, String, Vec<u8>)>,
}

#[cfg(windows)]
impl PlainBatchGuard {
    pub(super) fn with_capacity(n: usize) -> Self {
        Self { rows: Vec::with_capacity(n) }
    }

    pub(super) fn push(&mut self, row: (u64, u32, String, Vec<u8>)) {
        self.rows.push(row);
    }

    /// 只读访问行数据（直传 write_records 的切片签名）
    pub(super) fn rows(&self) -> &[(u64, u32, String, Vec<u8>)] {
        &self.rows
    }

    /// 立即擦除全部明文行（幂等：覆写后再次调用无害）
    pub(super) fn scrub(&mut self) {
        for (_, _, name, data) in self.rows.iter_mut() {
            overwrite_3rounds(name.as_mut_ptr(), name.len());
            overwrite_3rounds(data.as_mut_ptr(), data.len());
        }
    }
}

#[cfg(windows)]
impl Drop for PlainBatchGuard {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// 摘要扫描临时缓冲守卫：(lid, rtype, name, data_size, physical_offset, merkle_leaf, created_time)
#[cfg(windows)]
pub(super) struct SummaryBatchGuard {
    pub(super) rows: Vec<scan_shm::SummaryRecord>,
}

#[cfg(windows)]
impl SummaryBatchGuard {
    pub(super) fn with_capacity(n: usize) -> Self {
        Self { rows: Vec::with_capacity(n) }
    }

    pub(super) fn push(&mut self, row: scan_shm::SummaryRecord) {
        self.rows.push(row);
    }

    pub(super) fn rows(&self) -> &[scan_shm::SummaryRecord] {
        &self.rows
    }

    /// 立即擦除全部摘要行（name 明文 + merkle_leaf 哈希）
    pub(super) fn scrub(&mut self) {
        for (_, _, name, _, _, merkle, _) in self.rows.iter_mut() {
            overwrite_3rounds(name.as_mut_ptr(), name.len());
            overwrite_3rounds(merkle.as_mut_ptr(), merkle.len());
        }
    }
}

#[cfg(windows)]
impl Drop for SummaryBatchGuard {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// 批量枚举单批条数硬上限
///
/// 游标批量扫描（全量/摘要）按 max_count 预分配记录数组与 lid 数组，
/// 前端可控的 id 字段直达此处；无上限时超大 id 直接触发巨大分配。
/// 上限值按单批内存预算选取（5000 × 全量记录结构 ≈ 数百 KB 级），
/// 与本进程单请求内存宽度匹配。调用点须始终经 clamp_enum_count，
/// 超限请求被静默截断（截断语义对游标无害：后续批次继续拉取）。
pub(crate) const MAX_ENUM_COUNT: u64 = 5000;

/// 将外部可控的批量条数限制到硬上限以内
pub(crate) fn clamp_enum_count(v: u64) -> u64 {
    v.min(MAX_ENUM_COUNT)
}

/// 落盘自查结构化结果（Verthys_VerifyPersist 出参的 Rust 侧投影）
///
/// status_code 语义（对齐 C 端 VerPersistStatus）：
///   0=OK / 1=HEADER_INVALID / 2=SIZE_MISMATCH / 3=WAL_REGION
///   / 4=IO / 5=INTERNAL
pub(crate) struct VerifyPersistOutcome {
    pub(crate) status_code: i32,
    pub(crate) file_size: u64,
    pub(crate) mtime_ms: u64,
    pub(crate) header_magic: u32,
    pub(crate) header_version: u32,
    pub(crate) wal_offset: u64,
    pub(crate) last_error: String,
}

/// 统一 FFI 调用收口：所有对 C 导出函数的调用必须经此函数
///
/// Rust panic 展开穿过 extern "C" 边界属于未定义行为。
/// catch_unwind 捕获 panic 后：置位进程级标记（主循环检测后安全退出）
/// 并返回 Err，调用方转换为 0xFFFFFFFF 失败码——panic 绝不展开进 C。
pub(crate) fn ffi_call<R, F: FnOnce() -> R>(invoke: F) -> Result<R, ()> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(invoke)) {
        Ok(v) => Ok(v),
        Err(_) => {
            crate::log::mark_panic_flag();
            init_diag!("[worker] FFI 调用捕获到 panic（已阻断跨边界展开，返回失败码）");
            Err(())
        }
    }
}
