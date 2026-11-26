/*
 * controller/protection — 防护面
 *
 * 职责边界：防截屏隐私保护（窗口捕获排除）与剪贴板清理。两者都以系统 API
 * 副作用为主，命令层只做参数校验、限流与状态编排。
 */
pub mod clipboard_controller;
pub mod privacy_controller;
