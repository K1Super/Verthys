/*
 * verthys.ts — 前端唯一与后端通信的接口层（最小指令白名单）
 *
 * 设计原则（codebase-design 深模块）：
 *   - 前端仅能调用预定义的受限 Tauri 指令，无法自定义调用 DLL 底层接口
 *   - 文件二进制数据经 Tauri v2 raw IPC（ArrayBuffer 请求体 +
 *     tauri::ipc::Response 响应）直传，零 base64 编解码；账号序列化等
 *     小体量数据仍走 base64 in JSON 协议
 *   - 前端不含任何加密、密钥、文件读写逻辑，完全无安全权重
 *
 * 分层架构：
 *   types/verthys.ts            ← 类型定义
 *   constants/verthys_const.ts  ← 常量定义
 *   utils/binary_codec.ts     ← base64/hex/ArrayBuffer 编解码
 *   utils/json_codec.ts       ← 通用 JSON↔base64 序列化
 *   utils/invoke_wrapper.ts   ← 统一带超时 invoke 包装
 *   lib/verthys_error.ts        ← 标准化 IPC 通信错误
 *   lib/crypto.ts             ← encryptPasswordField/decryptPasswordField
 *   lib/ipc/*.ts              ← 按域拆分的纯 IPC 调用
 *   lib/verthys.ts              ← barrel 重导出（本文件）
 *
 * 本文件仅保留纯 IPC 调用，不包含加密实现。
 */

export * from "./ipc/shared";
export * from "./ipc/worker";
export * from "./ipc/container";
export * from "./ipc/imports";
export * from "./ipc/media";
export * from "./ipc/records";
export * from "./ipc/security";
export * from "./ipc/global_key";
export * from "./ipc/modules";
