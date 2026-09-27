/*
 * runtime/mod.rs — Worker 进程业务运行时（controller + service 层）
 *
 * 架构定位：业务逻辑层（非入口）
 *   - Worker 加载 DLL、持有 VerthysHandle、处理 JSON 协议
 *   - 主循环：stdin 读取 → handle_request 派发 → stdout 输出
 *   - 入口文件 main.rs 仅负责 arg 解析 + panic hook 安装 + 调用 run()
 *
 * 分层约束：
 *   - 入口文件单一职责：业务逻辑下沉至本模块
 *   - 分层依赖：entry → controller(runtime) → service → repository → util
 *
 * 模块拆分：
 *   - protocol      : Request / RecordEntry / Response / base64 编解码
 *   - ffi_types     : C ABI 结构体与函数指针类型（与 verthys.h 对齐）
 *   - scan_shm      : 共享内存传输层（Windows 专用）+ 非 windows 空壳
 *   - gmk           : 全局主密钥状态 + 派生命令
 *   - progress_cb   : 迁移/解锁进度回调
 *   - worker        : Worker（持有 DLL + 句柄）+ Drop
 *   - dispatch       : probe_global_key_inproc + handle_request 派发器
 *   - main_loop     : pub fn run 主循环
 *   - diagnostics   : GetLastError FFI + 错误码格式化
 */

mod protocol;
mod ffi_types;
mod scan_shm;
mod gmk;
mod progress_cb;
mod worker;
mod dispatch;
mod main_loop;
mod diagnostics;

/// 跨层预算常量（与主进程同源）
///
/// 单独成模块而非并入 scan_shm：预算常量同时被非 Windows 路径的协议
/// 行上限与请求侧校验消费，而 scan_shm 为 Windows 专用传输层；
/// 此处与平台无关地引入同一份生成物，保证任何目标平台都引用同一定义。
pub(crate) mod budget {
    #![allow(dead_code)]
    include!("../../../photo_budget.rs");
}

pub use main_loop::run;
pub use diagnostics::{ffi_get_last_error, format_os_error};
// panic 清零器（log.rs hook 经入口层注册；模块本体保持私有）
pub(crate) use gmk::wipe_thread_gmk;
