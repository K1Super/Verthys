/*
 * Windows 会话守卫后端
 *
 * window 负责窗口类注册、窗口过程与消息循环；notify 负责消息循环状态、
 * 工作线程（含看门狗）与 WindowsBackend 组合。
 */

mod notify;
mod window;

pub(super) use notify::WindowsBackend;
