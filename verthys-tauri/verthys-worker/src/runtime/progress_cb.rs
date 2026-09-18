/* progress_cb.rs — 解锁进度回调（C → Rust → stdout 流式推送）
 *
 * 职责：unlock_progress_cb（unsafe extern "C"）。
 * 依赖：std::io、std::os::raw::c_void、ffi_types 中的进度 C 结构体。
 * 被引用方：worker.rs（在 call_unlock 注册回调时传入）。
 * E-8：migrate_progress_cb 已随 V1→V2 迁移链路退役删除
 *   （Verthys_MigrateV1ToV2 移出导出白名单，无注册方）。
 */

use std::io::{self, Write};
use std::os::raw::c_void;

use super::ffi_types::VerthysUnlockProgressC;

/* ★ 方案5：解锁进度回调（C → Rust → stdout JSON 行）
 *
 * C DLL 在 verthys_v2_open_existing 各阶段调用此回调，回调将进度信息
 * 序列化为 JSON 行写入 stdout，父进程 send_json_with_unlock_progress
 * 识别 op="unlock_progress" 行并转发给前端。
 *
 * 格式严格对齐前端 UnlockProgress 类型：
 *   {"ok":true,"op":"unlock_progress","stage":N,"percent":N,
 *    "elapsed_ms":N,"message":"..."}
 *
 * 安全边界：
 *   - message 为 C 端字符串字面量（只读），从 C 指针读取 UTF-8 并立即序列化
 *   - 不含任何密钥/密码/明文，仅阶段编号/百分比/耗时/描述
 *   - 回调在 Unlock 调用线程内同步执行，writeln+flush 耗时 <0.1ms */
pub(crate) unsafe extern "C" fn unlock_progress_cb(
    progress: *const VerthysUnlockProgressC,
    _user_data: *mut c_void,
) {
    if progress.is_null() {
        return;
    }
    let p = &*progress;

    /* 从 C 指针安全提取 UTF-8 字符串（message 为编译期字面量，始终合法 UTF-8）
     * 空指针兜底为空字符串，避免 CStr::from_ptr 对 null 的 UB */
    let message: String = if p.message.is_null() {
        String::new()
    } else {
        /* CStr 从 null 终结的 C 字符串构造，lossy 转换避免非 UTF-8 字节 panic */
        std::ffi::CStr::from_ptr(p.message)
            .to_string_lossy()
            .into_owned()
    };

    /* 手动转义 message 中的 JSON 特殊字符（阶段描述为 DLL 内部字面量，
     * 正常情况不含特殊字符，但防御性转义避免 JSON 注入/损坏） */
    let message_escaped = message
        .replace('\\', r"\\")
        .replace('"', r#"\""#)
        .replace('\n', r"\n")
        .replace('\r', r"\r")
        .replace('\t', r"\t");

    let json = format!(
        r#"{{"ok":true,"op":"unlock_progress","stage":{},"percent":{},"elapsed_ms":{},"message":"{}"}}"#,
        p.stage, p.percent, p.elapsed_ms, message_escaped,
    );
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{}", json);
    let _ = lock.flush();
}
