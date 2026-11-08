/* ffi_types.rs — C ABI 类型定义（与 verthys.h 对齐）
 *
 * 职责：所有 #[repr(C)] 结构体、函数指针 type 别名、VerthysHandle、VERTHYS_OK 常量。
 * 无内部依赖，仅依赖 std::os::raw。
 * 被引用方：worker.rs / gmk.rs / progress_cb.rs / dispatch.rs。
 */

use std::os::raw::{c_char, c_void};

/// 不透明句柄：外部仅持有指针
pub(crate) type VerthysHandle = *mut c_void;

/// 标准化错误码
pub(crate) const VERTHYS_OK: u32 = 0x00000000;
/// 入参非法 / 句柄无效（与 verthys.h VERTHYS_ERR_INVALID 对齐）
pub(crate) const VERTHYS_ERR_INVALID: u32 = 0x00000001;

/// 落盘自查成功状态码（对齐 C 端 VerPersistStatus::VERTHYS_PERSIST_OK）
pub(crate) const VERTHYS_PERSIST_OK: i32 = 0;

/// repr(C) 记录结构（与 C 端 VerthysRecord 对齐）
#[repr(C)]
pub(crate) struct VerthysRecordC {
    pub(crate) rtype: u32,
    pub(crate) name: *const c_char,
    pub(crate) name_len: usize,
    pub(crate) data: *const u8,
    pub(crate) data_len: usize,
}

/// 函数指针类型
pub(crate) type VerthysInitFn = unsafe extern "C" fn(*mut VerthysHandle) -> u32;
/// 通知 DLL 当前 Worker 已应用的沙盒属性位掩码
pub(crate) type VerthysNotifySandboxAttrsFn = unsafe extern "C" fn(u32) -> u32;
/// 通知 DLL 运行时守卫完整掩码（bit0=心跳运行 bit1=挂起守卫接线）
pub(crate) type VerthysNotifyRuntimeGuardsFn = unsafe extern "C" fn(u32) -> u32;
/// 容器版本探测结构：仅映射 C 端 VerthysContainerInfo 的前 8 字节
/// （api_version u32 + fmt_version u16 + preset u16）。前导字段布局为
/// ABI 固定契约，加载方据此在布局敏感调用之前校准版本兼容性；
/// 后续字段一概不触碰。
#[repr(C)]
pub(crate) struct VerthysContainerInfoProbeC {
    pub(crate) api_version: u32,
    pub(crate) fmt_version: u16,
    pub(crate) preset: u16,
}
pub(crate) type VerthysGetContainerInfoFn =
    unsafe extern "C" fn(VerthysHandle, *mut VerthysContainerInfoProbeC) -> u32;
pub(crate) type VerthysDeinitFn = unsafe extern "C" fn(VerthysHandle) -> u32;
/// 专用解锁：只接受 VRTY 容器，内部强制 magic 校验（无 flags 参数）。
pub(crate) type VerthysV4UnlockFn =
    unsafe extern "C" fn(VerthysHandle, *const c_char, *const c_char, usize) -> u32;
/// 运行时切换安全预设（双缓冲原子发布，立即生效）
pub(crate) type VerthysSwitchSecurityPresetFn = unsafe extern "C" fn(VerthysHandle, u32) -> u32;
/// 查询活跃安全预设档位（快照读取，供切档回读校验）
pub(crate) type VerthysGetSecurityPresetFn = unsafe extern "C" fn(VerthysHandle, *mut u32) -> u32;
/// 查询指定档位的特性位投影（跨层特性契约的唯一权威输出）
pub(crate) type VerthysGetPresetFeatureBitsFn =
    unsafe extern "C" fn(VerthysHandle, u32, *mut u32) -> u32;
pub(crate) type VerthysLockFn = unsafe extern "C" fn(VerthysHandle) -> u32;
/// 修复：Verthys_Flush 显式刷盘接口
///   签名与 Verthys_Lock 相同：接收 handle，返回 VerthysResult(u32)
///   v2：commit 未完成事务（add_record 已 commit 时为 no-op），不清零密钥、不改 state
///   v1：dirty 标记则写回（保持兼容）
///   与 lock+unlock 的区别：不清零密钥、不改变 state、不重新加载索引，安全且高效
pub(crate) type VerthysFlushFn = unsafe extern "C" fn(VerthysHandle) -> u32;
pub(crate) type VerthysAddRecordFn =
    unsafe extern "C" fn(VerthysHandle, *const VerthysRecordC, *mut u64) -> u32;
/// 批量新增（API 0x0013）：单次事务提交，count ∈ [1, 512]。
pub(crate) type VerthysAddRecordsFn =
    unsafe extern "C" fn(VerthysHandle, *const VerthysRecordC, u32, *mut u64) -> u32;
pub(crate) type VerthysGetRecordFn =
    unsafe extern "C" fn(VerthysHandle, u64, *mut VerthysRecordC) -> u32;
pub(crate) type VerthysClearRecordCacheFn = unsafe extern "C" fn(VerthysHandle) -> u32;
pub(crate) type VerthysDeleteRecordFn = unsafe extern "C" fn(VerthysHandle, u64) -> u32;
pub(crate) type VerthysDeleteRecordsFn = unsafe extern "C" fn(VerthysHandle, *const u64, usize) -> u32;
pub(crate) type VerthysExportFn =
    unsafe extern "C" fn(VerthysHandle, *const c_char, *const c_char, usize) -> u32;
pub(crate) type VerthysImportFn =
    unsafe extern "C" fn(VerthysHandle, *const c_char, *const c_char, usize) -> u32;
pub(crate) type VerthysChangePasswordFn = unsafe extern "C" fn(
    VerthysHandle,
    *const c_char,
    usize,
    *const c_char,
    usize,
) -> u32;

/* 模块 M1 会话接口（与 verthys.h VerthysModuleStatus / Verthys_V4Module* 对齐） */

/// 模块状态投影：不含任何密钥材料
#[repr(C)]
pub(crate) struct VerthysModuleStatusC {
    pub(crate) enabled: u32,
    pub(crate) unlocked: u32,
    pub(crate) has_recovery: u32,
    pub(crate) deleted: u32,
}

pub(crate) type VerthysV4ModuleEnableFn = unsafe extern "C" fn(
    VerthysHandle,
    u32,
    *const c_char,
    usize,
    *const c_char,
) -> u32;
pub(crate) type VerthysV4ModuleUnlockFn =
    unsafe extern "C" fn(VerthysHandle, u32, *const c_char, usize) -> u32;
pub(crate) type VerthysV4ModuleLockFn = unsafe extern "C" fn(VerthysHandle, u32) -> u32;
pub(crate) type VerthysV4ModuleRotatePasswordFn = unsafe extern "C" fn(
    VerthysHandle,
    u32,
    *const c_char,
    usize,
    *const c_char,
    usize,
) -> u32;
pub(crate) type VerthysV4ModuleDisableFn =
    unsafe extern "C" fn(VerthysHandle, u32, *const c_char, usize) -> u32;
pub(crate) type VerthysV4ModuleDeleteFn = unsafe extern "C" fn(
    VerthysHandle,
    u32,
    *const c_char,
    usize,
    *const c_char,
) -> u32;
pub(crate) type VerthysV4ModuleBindRecoveryFn = unsafe extern "C" fn(
    VerthysHandle,
    u32,
    *const c_char,
    usize,
    *const c_char,
) -> u32;
pub(crate) type VerthysV4ModuleResealDeviceFn =
    unsafe extern "C" fn(VerthysHandle, u32, *const c_char, usize) -> u32;
pub(crate) type VerthysV4ModuleStatusFn =
    unsafe extern "C" fn(VerthysHandle, u32, *mut VerthysModuleStatusC) -> u32;
/// 只读查询模块锁剩余秒数（0x1D 响应携带）
pub(crate) type VerthysV4ModuleLockoutRemainingFn =
    unsafe extern "C" fn(VerthysHandle, u32, *mut u32) -> u32;
/// 只读查询库级熔断剩余秒数（0x0A 响应携带；无需句柄）
pub(crate) type VerthysGetLibLockoutRemainingFn = unsafe extern "C" fn(*mut u32) -> u32;
pub(crate) type VerthysV4RecoveryRotateFn = unsafe extern "C" fn(
    VerthysHandle,
    *const c_char,
    usize,
    *const c_char,
    *mut c_char,
    usize,
) -> u32;

/* 全库 DEK 轮换（API 版本 0x0010，与 verthys.h Verthys_V4Rotate* 对齐）
 *
 * 作业式接口：Begin 创建临时新库并登记作业，UnlockModule 逐模块登记口令，
 * Run 全量复制并回调进度，Commit 原子替换，Abort 丢弃临时库。
 * 轮换期间源库只读，所有写入口在 C 层返回 ROTATE_PENDING。 */

/// 轮换进度/统计投影（与 C 端 VerthysRotateInfo 对齐）
#[repr(C)]
pub(crate) struct VerthysRotateInfoC {
    pub(crate) stage: u32,
    pub(crate) modules_ready: u32,
    pub(crate) records: u64,
    pub(crate) files: u64,
    pub(crate) chunks: u64,
    pub(crate) bytes: u64,
    pub(crate) reserved: [u32; 4],
}

/// 进度回调：在 Run 内同步调用；返回非 0 取消本次 Run。
pub(crate) type VerthysRotateProgressC =
    unsafe extern "C" fn(*mut c_void, *const VerthysRotateInfoC) -> i32;

pub(crate) type VerthysV4RotateBeginFn = unsafe extern "C" fn(
    VerthysHandle,
    *const c_char,
    *const c_char,
    usize,
    u32,
    *mut VerthysRotateInfoC,
) -> u32;
/// 恢复会话补录 keyfile（API 0x0011）：路径只转发，字节由 C 层进程内读取。
pub(crate) type VerthysV4RotateAttachKeyfileFn =
    unsafe extern "C" fn(VerthysHandle, *const c_char, *const c_char, usize) -> u32;
pub(crate) type VerthysV4RotateUnlockModuleFn = unsafe extern "C" fn(
    VerthysHandle,
    u32,
    *const c_char,
    usize,
    *const c_char,
) -> u32;
pub(crate) type VerthysV4RotateRunFn = unsafe extern "C" fn(
    VerthysHandle,
    Option<VerthysRotateProgressC>,
    *mut c_void,
) -> u32;
pub(crate) type VerthysV4RotateCommitFn = unsafe extern "C" fn(VerthysHandle, u32) -> u32;
pub(crate) type VerthysV4RotateAbortFn = unsafe extern "C" fn(VerthysHandle) -> u32;

/* 容器创建/恢复与 PCR 策略（与 verthys.h 对应入口对齐） */
pub(crate) type VerthysV4CreateFn = unsafe extern "C" fn(
    VerthysHandle,
    *const c_char,
    *const c_char,
    usize,
    *mut c_char,
    usize,
) -> u32;
pub(crate) type VerthysV4UnlockRecoveryFn =
    unsafe extern "C" fn(VerthysHandle, *const c_char, *const c_char) -> u32;

/* keyfile 因子（API 版本 0x000F）：只传路径，keyfile 字节由 C 层
 * 在 worker 进程内读取/生成，不经过 IPC。 */
pub(crate) type VerthysV4CreateKeyfileFn = unsafe extern "C" fn(
    VerthysHandle,
    *const c_char,
    *const c_char,
    usize,
    *const c_char,
    *mut c_char,
    usize,
) -> u32;
pub(crate) type VerthysV4UnlockKeyfileFn = unsafe extern "C" fn(
    VerthysHandle,
    *const c_char,
    *const c_char,
    usize,
    *const c_char,
) -> u32;
pub(crate) type VerthysV4KeyfileEnableFn =
    unsafe extern "C" fn(VerthysHandle, *const c_char, usize, *const c_char) -> u32;
pub(crate) type VerthysV4KeyfileDisableFn =
    unsafe extern "C" fn(VerthysHandle, *const c_char, usize, *const c_char) -> u32;
pub(crate) type VerthysV4KeyfileStatusFn =
    unsafe extern "C" fn(VerthysHandle, *mut u32, *mut u32) -> u32;
/// 恢复会话容器 user/device 槽重绑（password + 可选 keyfile_path）
pub(crate) type VerthysV4ResealDeviceFn =
    unsafe extern "C" fn(VerthysHandle, *const c_char, usize, *const c_char) -> u32;
pub(crate) type VerthysV4PcrStatusFn =
    unsafe extern "C" fn(VerthysHandle, *mut u32, *mut u32) -> u32;
pub(crate) type VerthysV4PcrEnableFn =
    unsafe extern "C" fn(VerthysHandle, u32, *const c_char) -> u32;
pub(crate) type VerthysV4PcrDisableFn =
    unsafe extern "C" fn(VerthysHandle, *const c_char) -> u32;
pub(crate) type VerthysV4PcrResealFn =
    unsafe extern "C" fn(VerthysHandle, *const c_char) -> u32;
pub(crate) type VerthysV4ChunkSealFn = unsafe extern "C" fn(
    VerthysHandle,
    u32,
    *const u8,
    u32,
    u32,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> u32;
pub(crate) type VerthysV4ChunkOpenFn = unsafe extern "C" fn(
    VerthysHandle,
    u32,
    *const u8,
    u32,
    u32,
    *const u8,
    usize,
    *mut u8,
    usize,
    *mut usize,
) -> u32;
/* 说明：清单（manifest）只服务于 C 层模块重写事务，产品内容路径不调用；
 * 分片集合的完整性由 meta 内 BLAKE3 哈希表 + chunkset 记录认证。 */

/* 游标批量扫描函数指针类型 */
/// VerthysScanCursor 不透明指针
pub(crate) type VerthysScanCursorPtr = *mut c_void;

/// VerthysScanProject 取值（与 verthys.h 对齐）
pub(crate) const VERTHYS_SCAN_PROJECT_FULL: u32 = 0;
pub(crate) const VERTHYS_SCAN_PROJECT_INDEX: u32 = 1;

/// Verthys_ScanOpenEx：带投影与取批预算的扫描游标入口
///
/// 投影与取批预算均随游标携带（Fetch 签名不变）：
///   - project：投影选择（FULL=全量解密 / INDEX=仅内联小记录解密）
///   - index_inline_max_bytes：INDEX 投影的内联数据阈值（0=纯索引）
///   - max_batch_bytes：单次 Fetch 输出字节预算（0=不限）
///
/// 既有入口 Verthys_ScanOpen 保留在 C 侧（等价于 Ex 的 FULL/0/0），
/// worker 统一经本入口打开游标：投影与预算无法经旧签名传入。
pub(crate) type VerthysScanOpenExFn = unsafe extern "C" fn(
    VerthysHandle,
    u64,                    /* start_lid */
    u64,                    /* batch_size */
    u32,                    /* project（VerthysScanProject） */
    u64,                    /* index_inline_max_bytes */
    u64,                    /* max_batch_bytes */
    *mut VerthysScanCursorPtr, /* out_cursor */
) -> u32;
pub(crate) type VerthysScanFetchFn = unsafe extern "C" fn(
    VerthysScanCursorPtr,     /* cursor */
    *mut VerthysRecordC,      /* out_records */
    *mut u64,               /* out_lids */
    u64,                    /* max_count */
    *mut u64,               /* out_count */
    *mut u64,               /* out_failed_lids  — 修复：与 C 端 verthys.h:574-580 严格对齐 */
    *mut u64,               /* out_failed_count — 原缺陷：缺这 2 参数，C 从栈读垃圾值→0xC0000005 */
) -> u32;
pub(crate) type VerthysScanRecordFreeFn = unsafe extern "C" fn(*mut VerthysRecordC) -> u32;
pub(crate) type VerthysScanCloseFn = unsafe extern "C" fn(VerthysScanCursorPtr) -> u32;

/* 摘要扫描函数指针类型（轻量元数据扫描，不读数据块） */
/// repr(C) 摘要记录结构（与 C 端 VerthysSummaryRecord 对齐）
/// 新增 created_time 字段
#[repr(C)]
pub(crate) struct VerthysSummaryRecordC {
    pub(crate) lid: u64,
    pub(crate) rtype: u8,
    pub(crate) name_len: u16,
    pub(crate) name: *const u8,
    pub(crate) data_size: u64,
    pub(crate) physical_offset: u64,
    pub(crate) merkle_leaf: [u8; 32],
    pub(crate) created_time: u64,  /* 创建时间戳 */
    pub(crate) slot_state: u8,     /* 修复：与 C 端 VerthysSummaryRecord 严格对齐 */
    // #[repr(C)] 自动追加 7 字节尾部填充 → sizeof = 88，与 C 端一致
    //
    // 原缺陷（worker 崩溃 0xC0000005，导致"无法验证全局密钥"）：
    //   C 端 Verthys_ScanSummaryFetch 按 sizeof(VerthysSummaryRecord)=88 步长索引
    //   out_records[count]，但 Rust 端缺 slot_state → 元素 size=80。
    //   C 写入第 count 条时落在 base+count*88，而 Rust 第 count 条在 base+count*80，
    //   8 字节错位 → C 越界写入堆缓冲（heap overflow）+ Rust 读取错位字段
    //   （尤以 name 指针读为垃圾值 → 解引用野指针）→ worker 子进程
    //   ACCESS_VIOLATION at 0x0 退出 → 后续 verthys_verify_global_key 报
    //   "worker 子进程已退出" → 用户看到"无法验证全局密钥"。
    //   verthys 内记录 ≥2 条时必现。
}
pub(crate) type VerthysScanSummaryOpenFn = unsafe extern "C" fn(
    VerthysHandle,
    u64,                    /* start_lid */
    u64,                    /* batch_size */
    *mut VerthysScanCursorPtr, /* out_cursor */
) -> u32;
pub(crate) type VerthysScanSummaryFetchFn = unsafe extern "C" fn(
    VerthysScanCursorPtr,          /* cursor */
    *mut VerthysSummaryRecordC,    /* out_records */
    *mut u64,                    /* out_lids */
    u64,                         /* max_count */
    *mut u64,                    /* out_count */
) -> u32;
pub(crate) type VerthysScanSummaryRecordFreeFn = unsafe extern "C" fn(*mut VerthysSummaryRecordC) -> u32;
/// 轻量摘要记录数查询。
/// 该符号仍在导出白名单且在役（core/verthys.def 导出，worker 经
/// scan_summary 路径实际调用）——保留对应 FFI 绑定额。
pub(crate) type VerthysGetSummaryCountFn = unsafe extern "C" fn(VerthysHandle, *mut u64) -> u32;

/* 动态防护状态查询 FFI 绑定（API 0x0014 追加式扩展）
 * 与 verthys.h VerthysSecurityStatus 严格对齐（C enum 为 int = 4 字节）：
 *   [u32 path_state; 7][u32 blocked][u32 degraded][u32 failed]
 *   [u8 all_critical_blocked][u8 has_degraded][u8 reserved; 6] = 48B
 *   [u32 path_reason; 7][u32 limited][u32 policy_flags][u32 reserved2] = 40B
 *   [u64 checked_at_unix_ms][u32 reserved3; 2] = 16B
 *   合计 104B / align 8 */
#[repr(C)]
pub(crate) struct VerthysSecurityStatusC {
    /// 逐路径防御状态（下标 = VerthysDefensePath；值 = VerthysDefenseState）
    pub(crate) path_state: [u32; 7],
    pub(crate) blocked_count: u32,
    pub(crate) degraded_count: u32,
    pub(crate) failed_count: u32,
    pub(crate) all_critical_blocked: u8,
    pub(crate) has_degraded: u8,
    pub(crate) reserved: [u8; 6],
    /// 逐路径判定原因码（VerthysDefenseReason）
    pub(crate) path_reason: [u32; 7],
    /// 架构限制导致的降级路径数
    pub(crate) limited_count: u32,
    /// 运行时守卫与策略位
    pub(crate) policy_flags: u32,
    pub(crate) reserved2: u32,
    /// 快照采样时间（Unix 毫秒）
    pub(crate) checked_at_unix_ms: u64,
    pub(crate) reserved3: [u32; 2],
}

pub(crate) type VerthysGetSecurityStatusFn =
    unsafe extern "C" fn(VerthysHandle, *mut VerthysSecurityStatusC) -> u32;
/*   轻量级记录类型存在性检查 FFI 绑定
 *   与 verthys.h 中 Verthys_HasRecordByType 严格对齐
 *   签名：VerthysResult Verthys_HasRecordByType(VerthysHandle, uint8_t rtype, uint8_t *out_found)
 *   仅遍历索引节点检查 type 字段，不读数据块，典型 < 100ms */
pub(crate) type VerthysHasRecordByTypeFn = unsafe extern "C" fn(VerthysHandle, u8, *mut u8) -> u32;
/*   进程内类型记录首条 lid 查找 FFI 绑定
 *   与 verthys.h 中 Verthys_FindFirstLidByType 严格对齐
 *   签名：VerthysResult Verthys_FindFirstLidByType(VerthysHandle, uint8_t rtype,
 *                                              uint8_t *out_found, uint64_t *out_lid)
 *   容器未解锁或格式不符时返回 FORMAT；容器内未找到返回 OK + found=0
 *   （不报 FORMAT，避免前端 probe 抛异常）
 *   用于解锁成功后进程内探测全局主密钥记录，消除解锁后 3~4 次 IPC 往返 */
pub(crate) type VerthysFindFirstLidByTypeFn = unsafe extern "C" fn(VerthysHandle, u8, *mut u8, *mut u64) -> u32;

/* 按类型分页枚举记录 ID FFI 绑定（API 0x0012）
 * 签名：VerthysResult Verthys_ListIdsByType(
 *   handle, rtype, after_id, max_count, out_ids, out_count, out_exhausted)
 * 走 类型盲索引，不读取记录密文；max_count 上限由 C 层校验。 */
pub(crate) type VerthysListIdsByTypeFn = unsafe extern "C" fn(
    VerthysHandle,
    u8,
    u64,
    u64,
    *mut u64,
    *mut u64,
    *mut u8,
) -> u32;

/* 落盘自查 FFI 绑定（与 verthys.h Verthys_VerifyPersist 严格对齐）
 *
 * C 端签名：VerPersistStatus Verthys_VerifyPersist(VerthysHandle, VerPersistVerifyResult*)
 *   - 返回 VerPersistStatus（C enum = int = 4 字节，0=OK）
 *   - 结构体布局（x64，8 字节对齐）：
 *       [i32 status][4B pad][u64 file_size][u64 mtime_ms]
 *       [u32 header_magic][u32 header_version][u64 wal_offset]
 *       [c_char last_error; 256]  → sizeof = 296
 *
 * Why 走 worker 而非主机主进程：容器会话在 C 层子进程内以独占方式
 * 持有超级块区 [0,64KB) 字节范围锁（Windows 强制锁），主进程新开句柄
 * 读取恒被 ERROR_LOCK_VIOLATION 拒绝；只有持锁子进程内的会话持锁句柄
 * 能完成自查。 */
#[repr(C)]
pub(crate) struct VerPersistVerifyResultC {
    pub(crate) status: i32,
    pub(crate) file_size: u64,
    pub(crate) mtime_ms: u64,
    pub(crate) header_magic: u32,
    pub(crate) header_version: u32,
    pub(crate) wal_offset: u64,
    pub(crate) last_error: [c_char; 256],
}

pub(crate) type VerthysVerifyPersistFn =
    unsafe extern "C" fn(VerthysHandle, *mut VerPersistVerifyResultC) -> i32;

#[cfg(test)]
mod tests {
    use super::*;

    /// 跨语言 ABI 布局锁定：任何字段增删/重排都必须同步 C 结构体。
    #[test]
    fn security_status_c_layout_matches_c_abi() {
        assert_eq!(std::mem::size_of::<VerthysSecurityStatusC>(), 104);
        assert_eq!(std::mem::align_of::<VerthysSecurityStatusC>(), 8);
    }
}