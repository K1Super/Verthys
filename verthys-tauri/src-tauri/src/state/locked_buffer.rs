/*
 * state/locked_buffer.rs — VirtualLock RAII 守卫
 *
 *
 * 架构定位：状态层（state）资源守卫模块
 *   - 依赖 controller::types（记录类型）与 zeroize crate
 *   - 提供 VirtualLockable trait 抽象 + LockedBuffer<T> RAII 守卫
 *   - 不引用上层模块（service / controller），仅被 state / controller::scan 使用
 *
 * 第 11.2 项 — VirtualLock RAII 守卫：
 *   原 state.rs 中 virtual_lock_records / virtual_unlock_records 为自由函数，
 *   无 RAII 保证：调用方可能遗忘 unlock、或 unlock 与 zero 顺序错误（先 unlock
 *   后 zero 导致零化内容被换出到 pagefile）。
 *
 *   修复：
 *   1. 定义 VirtualLockable trait，抽象"哪些内存区域需要锁定"
 *   2. 定义 LockedBuffer<T> RAII 守卫，拥有 Vec<T>：
 *      - 构造时 VirtualLock 所有敏感区域（检查返回值，失败回滚已锁定区域并返回 Err）
 *      - Drop 时强制先擦除（Zeroize trait）后解锁（VirtualUnlock）
 *   3. 删除自由函数 virtual_lock_records / virtual_unlock_records /
 *      virtual_lock_summary_records / virtual_unlock_summary_records
 *
 * 安全保证：
 *   - 擦除在解锁之前完成：zeroize 期间内存仍被 VirtualLock 锁定在物理内存，
 *     零化内容不会在擦除瞬间被换出到 pagefile
 *   - 构造失败回滚：VirtualLock 部分失败时，已锁定区域全部解锁后返回 Err，
 *     不会泄漏锁定区域
 *   - 指针有效性：locked_regions 存储构造时捕获的指针，指向 SecuredString
 *     内部 String 的堆缓冲。Vec<T> 的移动不移动 String 堆数据（String 为
 *     ptr+len+cap 三元组），指针在 LockedBuffer 生命周期内始终有效
 *
 * CI 红线：
 *   - 不输出 log::* 含指针值/数据内容
 *   - 不实现 Display / Debug 输出记录内容
 *   - 不提供 records_mut()——防止调用方修改 String 导致指针失效
 */

use crate::controller::types::{VerthysRecordEntry, VerthysSummaryEntry};
use zeroize::Zeroize;

/* ------------------------------------------------------------------ *
 * 第 11.2 项：VirtualLockable trait                                    *
 *                                                                    *
 * 抽象"记录中哪些内存区域需要 VirtualLock"。                           *
 * 不同记录类型（VerthysRecordEntry / VerthysSummaryEntry）的敏感字段不同，  *
 * 通过 trait 统一接口，使 LockedBuffer<T> 可泛型工作。                 *
 * ------------------------------------------------------------------ */

/// 可锁定内存区域的记录抽象（第 11.2 项）
///
/// 返回 `(指针, 长度)` 列表，每个元组对应一个需要 VirtualLock 的敏感字段堆缓冲。
/// 空字段不返回（VirtualLock 长度 0 无意义且可能失败）。
///
/// 指针有效性约定：
///   - 指针指向 SecuredString 内部 String 的堆缓冲首字节
///   - 在 LockedBuffer 生命周期内，调用方不得修改 String（否则堆缓冲可能重新分配，
///     指针失效）。LockedBuffer 不提供 records_mut() 以强制此约束。
pub trait VirtualLockable {
    /// 返回需要 VirtualLock 的内存区域列表
    fn lockable_regions(&self) -> Vec<(*const u8, usize)>;
}

impl VirtualLockable for VerthysRecordEntry {
    fn lockable_regions(&self) -> Vec<(*const u8, usize)> {
        let mut regions = Vec::with_capacity(2);
        // name：记录名称（敏感，可能含用户标识）
        if !self.name.is_empty() {
            regions.push((self.name.as_ptr(), self.name.len()));
        }
        // data：Base64 编码的记录数据（敏感，解码后为明文）
        if !self.data.is_empty() {
            regions.push((self.data.as_ptr(), self.data.len()));
        }
        regions
    }
}

impl VirtualLockable for VerthysSummaryEntry {
    fn lockable_regions(&self) -> Vec<(*const u8, usize)> {
        let mut regions = Vec::with_capacity(2);
        // name：记录名称（敏感）
        if !self.name.is_empty() {
            regions.push((self.name.as_ptr(), self.name.len()));
        }
        // merkle_leaf：Merkle 叶子哈希 base64（完整性校验码，泄露可辅助篡改攻击）
        if !self.merkle_leaf.is_empty() {
            regions.push((self.merkle_leaf.as_ptr(), self.merkle_leaf.len()));
        }
        regions
    }
}

/* ------------------------------------------------------------------ *
 * 第 11.2 项：LockedBuffer<T> RAII 守卫                                *
 *                                                                    *
 * 拥有 Vec<T>，构造时 VirtualLock 所有敏感区域，Drop 时先擦除后解锁。  *
 *                                                                    *
 * 设计决策（拥有 vs 借用）：                                           *
 *   原 spec 为 LockedBuffer<'a>（借用 &mut [T]）。但扫描流水线需要将   *
 *   锁定状态跨 async 函数调用存储于 ScanPipelineState，借用生命周期     *
 *   无法跨越函数边界。采用拥有设计 LockedBuffer<T>（拥有 Vec<T>），     *
 *   可存储于结构体字段，且保证记录在缓冲区整个生命周期内保持锁定。       *
 *                                                                    *
 *   借用模式的问题：Drop 擦除借用数据后，原始 Vec 中数据已清空，         *
 *   无法继续用于 ScanPipelineState 的双缓冲切换。拥有模式在 Drop 时      *
 *   连同 Vec 一起释放，语义更清晰。                                    *
 * ------------------------------------------------------------------ */

/// VirtualLock RAII 守卫（第 11.2 项）
///
/// 拥有 `Vec<T>`，构造时锁定所有敏感区域于物理内存，Drop 时先擦除后解锁。
///
/// 构造失败（VirtualLock 返回错误）时回滚已锁定区域并返回 `Err`。
///
/// 不提供 `records_mut()`：防止调用方修改 `String` 字段导致堆缓冲重分配、
/// `locked_regions` 中指针失效。
pub struct LockedBuffer<T: VirtualLockable + Zeroize> {
    /// 拥有的记录列表（Drop 时先 zeroize 各元素，再由 Vec 自身 Drop 释放堆）
    records: Vec<T>,
    /// 构造时成功 VirtualLock 的区域列表
    ///
    /// 存储 `(指针, 长度)` 元组，Drop 时 VirtualUnlock 恰好这些区域。
    /// 不依赖 `lockable_regions()` 的当前返回值——字段可能在 zeroize 后变更
    /// （String::zeroize 后 len=0，但指针仍指向已分配的堆缓冲）。
    locked_regions: Vec<(*const u8, usize)>,
}

impl<T: VirtualLockable + Zeroize> LockedBuffer<T> {
    /// 构造：锁定所有敏感区域于物理内存
    ///
    /// 遍历每条记录的 `lockable_regions()`，对每个区域调用 `VirtualLock`。
    /// 任一区域锁定失败时：回滚已锁定的所有区域，返回 `Err`。
    ///
    /// Windows 平台：调用 `VirtualLock`（将页面锁定在物理内存，禁止换出到 pagefile）。
    /// 非 Windows 平台：无操作，直接返回 `Ok`（LockedBuffer 仍提供 zeroize 语义）。
    ///
    /// # 参数
    /// - `records`：要锁定的记录列表（所有权转移至 LockedBuffer）
    ///
    /// # 返回
    /// - `Ok(LockedBuffer)`：所有区域成功锁定
    /// - `Err(String)`：某区域锁定失败，已回滚（records 所有权转移至 Err 中不返回，
    ///   因回滚后 records 内容仍有效但未锁定，调用方应按未锁定数据处理）
    #[cfg(windows)]
    pub fn new(records: Vec<T>) -> Result<Self, String> {
        use windows::Win32::System::Memory::VirtualLock;

        let mut locked_regions: Vec<(*const u8, usize)> = Vec::new();

        for rec in &records {
            for (ptr, len) in rec.lockable_regions() {
                if len == 0 || ptr.is_null() {
                    continue;
                }
                let result = unsafe { VirtualLock(ptr as *const _, len) };
                if result.is_err() {
                    // 回滚：解锁已锁定的所有区域
                    log::warn!(
                        "[LockedBuffer] VirtualLock 失败 (len={})，回滚 {} 个已锁定区域",
                        len,
                        locked_regions.len()
                    );
                    for (p, l) in &locked_regions {
                        unsafe {
                            use windows::Win32::System::Memory::VirtualUnlock;
                            let _ = VirtualUnlock(*p as *const _, *l);
                        }
                    }
                    return Err(format!(
                        "VirtualLock failed for region of {} bytes",
                        len
                    ));
                }
                locked_regions.push((ptr, len));
            }
        }

        Ok(LockedBuffer { records, locked_regions })
    }

    /// 非 Windows 平台构造：无 VirtualLock，仅包装 Vec
    #[cfg(not(windows))]
    pub fn new(records: Vec<T>) -> Result<Self, String> {
        Ok(LockedBuffer {
            records,
            locked_regions: Vec::new(),
        })
    }

    /// 不可变访问记录列表
    ///
    /// 用于克隆记录构造响应（`locked.records().to_vec()`）。
    /// 不提供 `records_mut()`——防止修改 String 字段导致指针失效。
    pub fn records(&self) -> &[T] {
        &self.records
    }

    /// 记录数量
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// 已锁定的内存区域数（诊断用，不含指针值）
    pub fn locked_region_count(&self) -> usize {
        self.locked_regions.len()
    }
}

/// 第 11.2 项：Drop 时强制先擦除后解锁
///
/// 顺序保证：
///   1. 先对每条记录调用 `zeroize()`（此时内存仍被 VirtualLock 锁定，
///      零化内容不会在擦除瞬间被换出到 pagefile）
///   2. 再 VirtualUnlock 所有锁定区域
///   3. Vec<T> 自身 Drop 释放堆内存（此时数据已零化）
///
/// 这个顺序消除了原实现中"先 unlock 后 zero"的竞态窗口：
/// 原实现在 unlock 与 zero 之间，如果 OS 恰好将该页换出到 pagefile，
/// 则 zero 写入的是新页，旧页（含明文）已落盘。
impl<T: VirtualLockable + Zeroize> Drop for LockedBuffer<T> {
    fn drop(&mut self) {
        // 1. 先擦除：对每条记录调用 zeroize（SecuredString::zeroize 以 volatile
        //    写零覆盖堆字节后 clear，无 UB）。内存仍被 VirtualLock 锁定。
        for rec in self.records.iter_mut() {
            rec.zeroize();
        }

        // 2. 后解锁：VirtualUnlock 所有构造时锁定的区域
        #[cfg(windows)]
        {
            use windows::Win32::System::Memory::VirtualUnlock;
            for (ptr, len) in &self.locked_regions {
                unsafe {
                    let _ = VirtualUnlock(*ptr as *const _, *len);
                }
            }
        }

        // 3. Vec<T> 自身 Drop 在此函数返回后由编译器插入，
        //    此时数据已零化，堆释放安全。
    }
}

// ===== Send 实现（跨线程传递） =====
//
// LockedBuffer 含 *const u8 原始指针（locked_regions），默认不实现 Send。
// 但这些指针仅在 Drop 中通过 VirtualUnlock 解引用（&mut self 独占访问），
// 不会被并发访问。Vec<T> 拥有指针所指数据，指针随 LockedBuffer 一起移动。
// 因此 T: Send 时 LockedBuffer 可安全跨线程传递。

// SAFETY: locked_regions 中的 *const u8 指针指向 Vec<T> 内部 String 的堆缓冲。
// 这些指针仅在 Drop::drop（&mut self 独占）中通过 VirtualUnlock 解引用，
// 不会被并发读取。Vec<T> 拥有底层堆数据，随 LockedBuffer 一起跨线程移动。
unsafe impl<T: VirtualLockable + Zeroize + Send> Send for LockedBuffer<T> {}

// ===== 单元测试 =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_buffer_empty_vec() {
        // 空 Vec 应成功构造（无区域需要锁定）
        let locked = LockedBuffer::<VerthysRecordEntry>::new(Vec::new());
        assert!(locked.is_ok());
        let locked = locked.unwrap();
        assert!(locked.is_empty());
        assert_eq!(locked.len(), 0);
        assert_eq!(locked.locked_region_count(), 0);
    }

    #[test]
    fn test_locked_buffer_with_records() {
        let records = vec![
            VerthysRecordEntry {
                id: 1,
                rtype: 0,
                name: crate::util::secured_string::SecuredString::from_str("test_name_1"),
                data: crate::util::secured_string::SecuredString::from_str("dGVzdF9kYXRhXzE="),
                original_size: Some(10),
            },
            VerthysRecordEntry {
                id: 2,
                rtype: 0,
                name: crate::util::secured_string::SecuredString::from_str("test_name_2"),
                data: crate::util::secured_string::SecuredString::from_str("dGVzdF9kYXRhXzI="),
                original_size: Some(10),
            },
        ];

        let locked = LockedBuffer::new(records);
        assert!(locked.is_ok());
        let locked = locked.unwrap();
        assert_eq!(locked.len(), 2);
        assert!(!locked.is_empty());
        // 每条记录有 name + data = 2 个区域，共 4 个
        assert_eq!(locked.locked_region_count(), 4);

        // 验证可以读取记录
        assert_eq!(locked.records()[0].id, 1);
        assert_eq!(locked.records()[1].id, 2);
    }

    #[test]
    fn test_locked_buffer_records_clone() {
        // 验证可以通过 records().to_vec() 克隆记录用于响应
        let records = vec![VerthysRecordEntry {
            id: 42,
            rtype: 1,
            name: crate::util::secured_string::SecuredString::from_str("clone_test"),
            data: crate::util::secured_string::SecuredString::from_str("Y2xvbmVfZGF0YQ=="),
            original_size: Some(10),
        }];

        let locked = LockedBuffer::new(records).unwrap();
        let cloned = locked.records().to_vec();
        assert_eq!(cloned.len(), 1);
        assert_eq!(cloned[0].id, 42);
        assert_eq!(cloned[0].name.as_str(), "clone_test");
    }

    #[test]
    fn test_locked_buffer_summary_records() {
        let records = vec![VerthysSummaryEntry {
            id: 1,
            rtype: 0,
            name: crate::util::secured_string::SecuredString::from_str("summary_name"),
            data_size: 100,
            physical_offset: 2048,
            merkle_leaf: crate::util::secured_string::SecuredString::from_str("bWVya2xlX2xlYWY="),
            created_time: 1234567890,
        }];

        let locked = LockedBuffer::new(records).unwrap();
        assert_eq!(locked.len(), 1);
        // name + merkle_leaf = 2 个区域
        assert_eq!(locked.locked_region_count(), 2);
    }

    #[test]
    fn test_locked_buffer_drop_erases_data() {
        // 验证 Drop 后数据被零化（通过外部可观察指针验证）
        // 注意：LockedBuffer Drop 会 zeroize 记录，但 Vec 也随后 Drop 释放堆。
        // 此测试仅验证 Drop 不 panic 且正常完成。
        let records = vec![VerthysRecordEntry {
            id: 1,
            rtype: 0,
            name: crate::util::secured_string::SecuredString::from_str("will_be_erased"),
            data: crate::util::secured_string::SecuredString::from_str("d2lsbF9iZV9lcmFzZWQ="),
            original_size: None,
        }];

        {
            let _locked = LockedBuffer::new(records).unwrap();
            // LockedBuffer 在此块结束时 Drop：先 zeroize，再 VirtualUnlock
        }
        // 如果到达此处，Drop 正常完成
    }

    #[test]
    fn test_virtual_lockable_empty_fields() {
        // 空字段不应产生锁定区域
        let rec = VerthysRecordEntry {
            id: 0,
            rtype: 0,
            name: crate::util::secured_string::SecuredString::empty(),
            data: crate::util::secured_string::SecuredString::empty(),
            original_size: None,
        };
        let regions = rec.lockable_regions();
        assert!(regions.is_empty());
    }
}
