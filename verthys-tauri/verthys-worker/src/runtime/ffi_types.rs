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
pub(crate) type VerthysDeinitFn = unsafe extern "C" fn(VerthysHandle) -> u32;
pub(crate) type VerthysUnlockFn =
    unsafe extern "C" fn(VerthysHandle, *const c_char, *const c_char, usize, u32) -> u32;
pub(crate) type VerthysCreateWithPresetFn = unsafe extern "C" fn(
    VerthysHandle,
    *const c_char,
    *const c_char,
    usize,
    u32, /* VerthysPreset */
) -> u32;
pub(crate) type VerthysLockFn = unsafe extern "C" fn(VerthysHandle) -> u32;
/// ★ 企业级根治：Verthys_Flush 显式刷盘接口
///   签名与 Verthys_Lock 相同：接收 handle，返回 VerthysResult(u32)
///   v2：commit 未完成事务（add_record 已 commit 时为 no-op），不清零密钥、不改 state
///   v1：dirty 标记则写回（保持兼容）
///   与 lock+unlock 的区别：不清零密钥、不改变 state、不重新加载索引，安全且高效
pub(crate) type VerthysFlushFn = unsafe extern "C" fn(VerthysHandle) -> u32;
pub(crate) type VerthysAddRecordFn =
    unsafe extern "C" fn(VerthysHandle, *const VerthysRecordC, *mut u64) -> u32;
pub(crate) type VerthysGetRecordFn =
    unsafe extern "C" fn(VerthysHandle, u64, *mut VerthysRecordC) -> u32;
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

/* ★ 方案5：解锁进度回调 FFI 绑定（与 verthys.h 中 VerthysUnlockProgress /
 * VerthysUnlockProgressCallback / Verthys_RegisterUnlockProgressCallback 严格对齐）
 *
 * 流式进度协议（与 migrate_progress 一致）：
 *   - worker 在 call_unlock 阻塞期间，由 C 回调直接向 stdout 写入
 *     {"ok":true,"op":"unlock_progress",...} 进度行
 *   - C 函数 Verthys_Unlock 返回后，worker 写入最终 {"ok":true,"op":"unlock",...} 终止行
 *   - 父进程 send_json_with_unlock_progress 区分进度行与终止行 */

/// repr(C) 解锁进度结构（与 C 端 VerthysUnlockProgress 对齐）
/// 布局：u32(4) + u32(4) + u64(8) + ptr(8) = 24B（x64 下 8 字节对齐）
#[repr(C)]
pub(crate) struct VerthysUnlockProgressC {
    pub(crate) stage: u32,       /* VerthysUnlockStage 枚举值 */
    pub(crate) percent: u32,     /* 0~100 累计百分比 */
    pub(crate) elapsed_ms: u64,  /* 累计耗时（毫秒） */
    pub(crate) message: *const c_char,  /* UTF-8 阶段描述（只读，回调期间有效） */
}

/// C 回调函数指针类型：void (*)(const VerthysUnlockProgress*, void*)
pub(crate) type VerthysUnlockProgressCallbackC =
    unsafe extern "C" fn(*const VerthysUnlockProgressC, *mut c_void);

/// Verthys_RegisterUnlockProgressCallback 函数指针类型
pub(crate) type VerthysRegisterUnlockProgressFn = unsafe extern "C" fn(
    VerthysHandle,
    Option<VerthysUnlockProgressCallbackC>,  /* callback */
    *mut c_void,                           /* user_data */
) -> u32;

/* 游标批量扫描函数指针类型 */
/// VerthysScanCursor 不透明指针
pub(crate) type VerthysScanCursorPtr = *mut c_void;
pub(crate) type VerthysScanOpenFn = unsafe extern "C" fn(
    VerthysHandle,
    u64,                    /* start_lid */
    u64,                    /* batch_size */
    *mut VerthysScanCursorPtr, /* out_cursor */
) -> u32;
pub(crate) type VerthysScanFetchFn = unsafe extern "C" fn(
    VerthysScanCursorPtr,     /* cursor */
    *mut VerthysRecordC,      /* out_records */
    *mut u64,               /* out_lids */
    u64,                    /* max_count */
    *mut u64,               /* out_count */
    *mut u64,               /* out_failed_lids  — ★ 企业级根治：与 C 端 verthys.h:574-580 严格对齐 */
    *mut u64,               /* out_failed_count — 原缺陷：缺这 2 参数，C 从栈读垃圾值→0xC0000005 */
) -> u32;
pub(crate) type VerthysScanRecordFreeFn = unsafe extern "C" fn(*mut VerthysRecordC) -> u32;
pub(crate) type VerthysScanCloseFn = unsafe extern "C" fn(VerthysScanCursorPtr) -> u32;

/* 摘要扫描函数指针类型（Phase 2B：轻量元数据扫描，不读数据块） */
/// repr(C) 摘要记录结构（与 C 端 VerthysSummaryRecord 对齐）
/// ★ Phase 2G：新增 created_time 字段
#[repr(C)]
pub(crate) struct VerthysSummaryRecordC {
    pub(crate) lid: u64,
    pub(crate) rtype: u8,
    pub(crate) name_len: u16,
    pub(crate) name: *const u8,
    pub(crate) data_size: u64,
    pub(crate) physical_offset: u64,
    pub(crate) merkle_leaf: [u8; 32],
    pub(crate) created_time: u64,  /* ★ Phase 2G：创建时间戳 */
    pub(crate) slot_state: u8,     /* ★ 企业级根治：与 C 端 VerthysSummaryRecord 严格对齐 */
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
/// ★ Phase 2I：轻量摘要记录数查询
/// E-8：Verthys_RebuildMerkle / Verthys_RebuildMerkleChunked 已随 V2 容器退役
/// 移出导出白名单（ci/export_baseline.txt），对应 FFI 类型一并删除
pub(crate) type VerthysGetSummaryCountFn = unsafe extern "C" fn(VerthysHandle, *mut u64) -> u32;

/* ★ WP-11（P2-3 观测出口）：防御闭环状态查询 FFI 绑定
 * 与 verthys.h VerthysSecurityStatus 严格对齐（C enum 为 int = 4 字节）：
 *   [u32 path_state; 7][u32 blocked][u32 degraded][u32 failed]
 *   [u8 all_critical_blocked][u8 has_degraded][u8 reserved; 6] = 48B / align 4 */
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
}

pub(crate) type VerthysGetSecurityStatusFn =
    unsafe extern "C" fn(VerthysHandle, *mut VerthysSecurityStatusC) -> u32;
/* ★ 企业级方案：轻量级记录类型存在性检查 FFI 绑定
 *   与 verthys.h 中 Verthys_HasRecordByType 严格对齐
 *   签名：VerthysResult Verthys_HasRecordByType(VerthysHandle, uint8_t rtype, uint8_t *out_found)
 *   仅遍历索引节点检查 type 字段，不读数据块，典型 < 100ms */
pub(crate) type VerthysHasRecordByTypeFn = unsafe extern "C" fn(VerthysHandle, u8, *mut u8) -> u32;
/* ★ 企业级根治方案：进程内类型记录首条 lid 查找 FFI 绑定
 *   与 verthys.h 中 Verthys_FindFirstLidByType 严格对齐
 *   签名：VerthysResult Verthys_FindFirstLidByType(VerthysHandle, uint8_t rtype,
 *                                              uint8_t *out_found, uint64_t *out_lid)
 *   v2 走 B+树叶子链表遍历，v1 走线性扫描，绝不返回 FORMAT 错误（根治 v1 假阴性）
 *   用于解锁成功后进程内探测全局主密钥记录，消除解锁后 3~4 次 IPC 往返 */
pub(crate) type VerthysFindFirstLidByTypeFn = unsafe extern "C" fn(VerthysHandle, u8, *mut u8, *mut u64) -> u32;

/* ================================================================ *
 * ★ E-8（V2 退役收口）：以下 FFI 绑定已删除                          *
 *                                                                  *
 * Verthys_RebuildMerkle / Verthys_RebuildMerkleChunked（Phase 2J / 项8  *
 * 分片重建）与 Verthys_MigrateV1ToV2（阶段8 V1→V2 迁移）均已随 V2    *
 * 容器退役移出 verthys.dll 导出白名单（29 符号，见                 *
 * ci/export_baseline.txt），worker 对应 call_* 方法改为直接返回     *
 * VERTHYS_ERR_UNSUPPORTED，不再保留死 FFI 类型：                      *
 *   - VerthysRebuildMerkleFn / VerthysRebuildMerkleChunkedFn            *
 *   - VerthysMigrateFn / VerthysMigrationCallbackC                      *
 *   - VerthysMigrationProgressC（migrate 进度结构）                   *
 * ================================================================ */
