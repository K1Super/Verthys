/*
 * util/ffi.rs — Rust FFI 桥接层模板
 *
 *    
 *
 * 职责：
 *   - 使用 extern "C" 块声明 C 函数
 *   - 提供安全 Rust 封装函数，调用 C 函数并立即将返回的错误码转换为 VerthysError
 *   - 转换时附加当前操作上下文信息
 *   - 不包含任何业务逻辑，不做错误重试或降级处理
 *   - C 函数产生的堆内存由 Rust 侧 Vec/Box 管理生命周期
 *
 * CI 红线：本文件严禁包含业务逻辑、日志输出、重试逻辑。
 */
use super::error::{VerthysError, VerthysResult};

/// C 层错误码常量（与 core/include/error_codes.h 对齐）
///
/// FFI 桥接层依据此常量将 C 返回值转换为 Rust VerthysError 变体。
pub mod c_error_codes {
    pub const VERTHYS_C_SUCCESS: i32 = 0;
    pub const VERTHYS_C_ERR_INVALID: i32 = -1;
    pub const VERTHYS_C_ERR_LOCKED: i32 = -2;
    pub const VERTHYS_C_ERR_AUTH: i32 = -3;
    pub const VERTHYS_C_ERR_IO: i32 = -4;
    pub const VERTHYS_C_ERR_CORRUPT: i32 = -5;
    pub const VERTHYS_C_ERR_FULL: i32 = -6;
    pub const VERTHYS_C_ERR_NOTFOUND: i32 = -7;
    pub const VERTHYS_C_ERR_NOMEM: i32 = -8;
    pub const VERTHYS_C_ERR_STATE: i32 = -9;
    pub const VERTHYS_C_ERR_INTERNAL: i32 = -10;
    pub const VERTHYS_C_ERR_ROLLBACK: i32 = -11;
}

/// 将 C 错误码转换为 VerthysError，附加操作上下文
///
/// 此函数为 FFI 桥接层核心：所有 C 函数返回非零值时均通过此函数转换。
/// context 参数用于附加人类可读的操作描述（如"调用C层CNG加密函数失败"）。
pub fn c_error_to_verthys(code: i32, context: &str) -> VerthysError {
    match code {
        c_error_codes::VERTHYS_C_ERR_INVALID => {
            VerthysError::InvalidArgument(format!("{}: C层参数无效", context))
        }
        c_error_codes::VERTHYS_C_ERR_LOCKED => VerthysError::VerthysLocked,
        c_error_codes::VERTHYS_C_ERR_AUTH => VerthysError::InvalidPassword,
        c_error_codes::VERTHYS_C_ERR_IO => {
            VerthysError::Io(std::io::Error::other(context))
        }
        c_error_codes::VERTHYS_C_ERR_CORRUPT => VerthysError::IntegrityCheckFailed,
        c_error_codes::VERTHYS_C_ERR_FULL => VerthysError::VerthysFull,
        c_error_codes::VERTHYS_C_ERR_NOTFOUND => VerthysError::RecordNotFound(0),
        c_error_codes::VERTHYS_C_ERR_NOMEM => VerthysError::OutOfMemory,
        c_error_codes::VERTHYS_C_ERR_STATE => VerthysError::InvalidState(context.to_string()),
        c_error_codes::VERTHYS_C_ERR_ROLLBACK => VerthysError::RollbackDetected,
        _ => VerthysError::FfiError(code, context.to_string()),
    }
}

/// 检查 C 返回值，非零时转换为 VerthysError 并返回 Err
///
/// 用法：`check_c(rv, "调用CNG加密")?;`
#[inline]
pub fn check_c(rv: i32, context: &str) -> VerthysResult<()> {
    if rv == c_error_codes::VERTHYS_C_SUCCESS {
        Ok(())
    } else {
        Err(c_error_to_verthys(rv, context))
    }
}

/* ------------------------------------------------------------------ *
 * FFI 外部函数声明模板                                                *
 *                                                                    *
 * 实际项目中，以下 extern 块应声明 core/include/verthys.h 中定义     *
 * 的所有公共 C ABI 函数。此处仅展示模式，实际绑定位于 worker.rs。      *
 * ------------------------------------------------------------------ */

/*
extern "C" {
    // 示例：CNG 加密函数
    pub fn Verthys_Encrypt(
        handle: *mut std::ffi::c_void,
        plaintext: *const u8,
        plaintext_len: usize,
        ciphertext: *mut u8,
        ciphertext_len: *mut usize,
    ) -> i32;
}
*/

// FFI 安全封装模板：调用 C 加密函数并转换错误码
//
// 此函数展示 FFI 桥接层的标准封装模式：
// 1. 准备输入输出缓冲区（Rust 侧管理内存生命周期）
// 2. 调用 C 函数
// 3. 检查返回值并转换为 VerthysResult
//
// 实际项目中应根据 verthys.h 的函数签名逐个封装。
/*
pub fn verthys_encrypt(
    handle: *mut std::ffi::c_void,
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> VerthysResult<usize> {
    let mut written: usize = 0;
    let rv = unsafe {
        Verthys_Encrypt(
            handle,
            plaintext.as_ptr(),
            plaintext.len(),
            ciphertext.as_mut_ptr(),
            &mut written,
        )
    };
    check_c(rv, "调用C层CNG加密函数失败")?;
    Ok(written)
}
*/
