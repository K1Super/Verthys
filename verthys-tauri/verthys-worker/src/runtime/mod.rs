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

pub use main_loop::run;
pub use diagnostics::{ffi_get_last_error, format_os_error};
