/*
 * utils/verthys-error-i18n.ts — Verthys 错误码国际化翻译工具
 *
 * 落实白皮书 9.2：将 VerthysResult 错误码翻译为用户可读中文消息。
 *
 * 设计原则：
 *   1. 单一映射表：所有 VerthysErrorCode → 中文消息映射集中于此文件
 *   2. 零依赖：仅依赖 verthys_error.ts 的类型与枚举，无其他业务依赖
 *   3. 兜底消息：未知错误码或未覆盖场景使用 result.message 兜底
 *   4. 复用性：所有 Vue 组件通过 keyManager.ts 的再导出或直接导入使用
 *
 * 使用示例：
 *   import { translateVerthysError } from "../utils/verthys-error-i18n";
 *   if (!result.ok) {
 *     showError(translateVerthysError(result));
 *   }
 */
import { VerthysErrorCode, type VerthysErrorResult } from "../lib/verthys_error";

/**
 * VerthysResult 错误码 → 用户可读中文消息的完整映射表
 *
 * 命名规范与 VerthysErrorCode 一一对应：
 *   - 通用：E_VERTHYS_*、E_INIT_*、E_PERSIST_*、E_RECORD_*、E_FLUSH_*
 *   - 全局密钥：E_GLOBAL_KEY_*
 *   - 设备绑定：E_DEVICE_*
 *   - 模块密钥：E_MODULE_*
 *
 * 所有消息使用动词开头的简洁句式，避免技术术语泄露给最终用户。
 */
const ERROR_CODE_MESSAGES: Record<VerthysErrorCode, string> = {
  // ===== 通用 =====
  [VerthysErrorCode.E_VERTHYS_NOT_READY]: "加密库未解锁，请先解锁",
  [VerthysErrorCode.E_VERTHYS_LOCKED]: "加密库已锁定",
  [VerthysErrorCode.E_RECORD_NOT_FOUND]: "记录不存在",
  [VerthysErrorCode.E_PERSIST_FAILED]: "持久化失败，请重试",
  [VerthysErrorCode.E_FLUSH_TIMEOUT]: "落盘超时，请重试",

  // ===== 初始化 =====
  [VerthysErrorCode.E_INIT_FAILED]: "初始化失败",
  [VerthysErrorCode.E_PATH_INVALID]: "路径不可用，请检查权限或磁盘空间",
  [VerthysErrorCode.E_PATH_EXISTS]: "文件已存在，请使用打开而非创建",
  [VerthysErrorCode.E_PATH_NOT_EXISTS]: "文件不存在，请使用创建而非打开",
  [VerthysErrorCode.E_WORKER_INIT_FAILED]: "安全核心启动失败",
  [VerthysErrorCode.E_VERTHYS_CREATE_FAILED]: "创建加密库失败",
  [VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED]: "打开加密库失败",

  // ===== 全局密钥 =====
  [VerthysErrorCode.E_GLOBAL_KEY_DERIVE_FAILED]: "全局密钥派生失败",
  [VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED]: "全局密钥验证失败",
  [VerthysErrorCode.E_GLOBAL_KEY_RECORD_NOT_FOUND]: "全局密钥记录未找到，请先初始化",
  [VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED]: "全局密钥落盘失败，请重试",

  // ===== 设备绑定 =====
  [VerthysErrorCode.E_DEVICE_BINDING]: "设备绑定异常",
  [VerthysErrorCode.E_DEVICE_BIND_FAILED]: "设备绑定失败，请重试",
  [VerthysErrorCode.E_DEVICE_MISMATCH]: "当前设备与绑定设备不匹配",
  [VerthysErrorCode.E_DEVICE_UNBOUND]: "设备未绑定，请先绑定设备",

  // ===== 模块密钥 =====
  [VerthysErrorCode.E_MODULE_KEY_NOT_FOUND]: "模块密钥未设置",
  [VerthysErrorCode.E_MODULE_VERIFY_FAILED]: "原独立密钥验证失败",
  [VerthysErrorCode.E_MODULE_KEY_SET_FAILED]: "保存失败，请重试",
  [VerthysErrorCode.E_MODULE_CONFIG_SAVE_FAILED]: "持久化失败，已回滚",
  [VerthysErrorCode.E_MODULE_NOT_READY]: "模块未就绪，请先登录",
  [VerthysErrorCode.E_MODULE_VERTHYS_NOT_READY]: "加密库未解锁",
};

/**
 * 将 VerthysResult 失败值翻译为用户可读中文消息
 *
 * @param result VerthysResult 的失败分支（ok: false）
 * @returns 用户可读中文消息（带兜底：未知错误码或空消息时返回通用提示）
 *
 * 使用示例：
 *   const result = await initCreate(path);
 *   if (!result.ok) {
 *     showError(translateVerthysError(result));
 *     return;
 *   }
 *
 * 兜底策略：
 *   1. 优先返回 ERROR_CODE_MESSAGES 中映射的消息
 *   2. 若映射不存在（理论上不应发生，TypeScript 已穷举），返回 result.message
 *   3. 若 result.message 为空，返回 "操作失败"
 */
export function translateVerthysError(result: VerthysErrorResult): string {
  // 优先使用映射表中的标准消息
  const mapped = ERROR_CODE_MESSAGES[result.code];
  if (mapped) {
    return mapped;
  }
  // 兜底 1：使用 result.message
  if (result.message && result.message.trim().length > 0) {
    return result.message;
  }
  // 兜底 2：通用提示
  return "操作失败";
}

/**
 * 判断给定错误码是否属于「用户可重试」类（非致命）
 *
 * 用于决定是否在 UI 上展示「重试」按钮：
 *   - 设备绑定失败、持久化失败、落盘超时 → 可重试
 *   - 路径不存在、密钥验证失败、模块未就绪 → 不可重试（需用户主动纠正）
 *
 * @param code VerthysErrorCode
 * @returns true 表示可重试，false 表示需用户纠正后才能继续
 */
export function isRetryableError(code: VerthysErrorCode): boolean {
  switch (code) {
    case VerthysErrorCode.E_DEVICE_BIND_FAILED:
    case VerthysErrorCode.E_PERSIST_FAILED:
    case VerthysErrorCode.E_FLUSH_TIMEOUT:
    case VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED:
    case VerthysErrorCode.E_MODULE_CONFIG_SAVE_FAILED:
    case VerthysErrorCode.E_MODULE_KEY_SET_FAILED:
    case VerthysErrorCode.E_WORKER_INIT_FAILED:
    case VerthysErrorCode.E_VERTHYS_CREATE_FAILED:
    case VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED:
    case VerthysErrorCode.E_GLOBAL_KEY_DERIVE_FAILED:
      return true;
    default:
      return false;
  }
}
