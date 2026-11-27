/*
 * @file infrastructure/path_resolver.rs
 * @brief 路径解析与完整性校验基础设施
 *
 * 本模块负责解析 verthys-worker.exe 和 verthys.dll 的运行时路径，
 * 并提供 DLL 完整性校验能力（SHA-256 比对编译时嵌入哈希）。
 * 路径解析策略优先使用开发环境最新构建产物，生产环境回退至 Tauri 资源目录。
 * 完整性校验为失败关闭门禁：Release 构建缺少嵌入哈希或哈希不匹配即拒绝加载；
 * 开发构建允许未构建 C 核心时跳过，仅记录警告。
 *
 * 依赖：
 *   - dll_hash：编译时由 build.rs 嵌入的 DLL 哈希
 *   - sha2：用于 SHA-256 计算
 *   - tauri::AppHandle：用于资源路径解析
 *
 * 安全约束：
 *   - DLL 哈希不匹配即拒绝加载，不降级
 *   - 路径解析结果需经 sanitize_path 脱敏后记录日志，避免泄露本地文件结构
 *
 * 子模块：
 *   - dll_verify：DLL 摘要与 VC++ 运行库校验
 *   - pe：PE 架构与导入表解析
 *   - deps：加载器搜索路径与二进制导入依赖预检
 *   - resolve：worker / DLL 运行时路径解析
 */

mod deps;
mod dll_verify;
mod pe;
mod resolve;

#[cfg(test)]
mod tests;

pub use deps::check_binary_dependencies;
pub use dll_verify::{check_dll_dependencies, get_dll_hash_prefix, verify_dll_integrity};
pub use pe::{detect_pe_architecture, parse_pe_imports, verify_binary_architecture, PeArch};
pub use resolve::{resolve_dll_path, resolve_worker_path};
