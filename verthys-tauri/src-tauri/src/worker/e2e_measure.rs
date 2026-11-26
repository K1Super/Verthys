//! worker/e2e_measure.rs — 导入数据面端到端测量（仅测试构建）
//!
//! 目的：用真实 `verthys-worker.exe` + 真实 `verthys.dll`，走与生产导入
//! 相同的 IPC 协议（签名信封、JSON、base64）测量：
//!   - worker 启动与就绪
//!   - 建库 / 解锁
//!   - 每张照片的块记录 add_records、meta add_records 与 flush
//!
//! 不包含：前端加密、缩略图生成、宿主 WAL 与命令层调度。
//! 由 `VERTHYS_WORKER_E2E=1` 启用；未设置时直接通过，避免影响常规测试。
//!
//! 环境变量：
//!   VERTHYS_WORKER_E2E_WORKER  worker 可执行文件（必填）
//!   VERTHYS_WORKER_E2E_DLL     verthys.dll（必填，须与 worker 构建期基线一致）
//!   VERTHYS_WORKER_E2E_LABEL   结果标签（默认 unknown）
//!   VERTHYS_WORKER_E2E_PHOTO_BYTES      单张照片精确字节数
//!   VERTHYS_WORKER_E2E_PHOTO_SIZES_MB   逗号分隔的小数 MiB 列表（如 10,17.73,24.43）
//!   VERTHYS_WORKER_E2E_PHOTO_MB         单张照片 MiB（未设置且无列表时跑 10/17.73/24.43 矩阵）
//!   VERTHYS_WORKER_E2E_ROUNDS  轮次（默认 3）
//!   VERTHYS_WORKER_E2E_BATCH=1 合并记录
//!   VERTHYS_WORKER_E2E_FLUSH=0 跳过 flush
//!   VERTHYS_WORKER_E2E_DEFER=1 批量导入锚点推迟（G0-A2 原型 DLL）
//!   VERTHYS_WORKER_E2E_JSON    可选：结果写入 JSON 文件
//!
//! 原生导入/读取/导出还原 E2E 分别由 VERTHYS_NATIVE_E2E、
//! VERTHYS_NATIVE_READ_E2E、VERTHYS_NATIVE_EXPORT_E2E 启用；
//! 可选 VERTHYS_NATIVE_EXPORT_E2E_OUT 落盘容器供前端兼容性复核，
//! VERTHYS_JS_VENC_E2E_DIR 指向前端 packVenc 产物供 worker 还原复核。

mod common;
mod export_restore;
mod import_measure;
mod js_fixture;
mod native_import;
mod read;
mod staged_smoke;
