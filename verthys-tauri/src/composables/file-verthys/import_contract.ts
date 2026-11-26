/**
 * file-verthys/import_contract.ts — 清藏导入的前端展示契约
 *
 * 导入数据面已收敛到宿主 + worker 原生管线；前端只保留两件事：
 *   - 把宿主返回的结构化原因码映射为面向用户的简洁文案；
 *   - 把进度回调投影为覆盖层状态（见模块组件）。
 *
 * 错误码与宿主/worker 的 `reason` 字段同值；映射表是唯一文案来源，
 * 禁止在组件内按异常文本做分支。
 */

/** 单文件导入失败原因分类（与宿主/worker 契约同值） */
export type FileImportErrorCode =
  | "E_STAT_FAILED"
  | "E_READ_FAILED"
  | "E_ENCRYPT_FAILED"
  | "E_CHUNK_FAILED"
  | "E_META_FAILED"
  | "E_FILE_CHANGED"
  | "E_FILE_TOO_LARGE"
  | "E_DISK_FULL"
  | "E_UNKNOWN";

/** 错误码 → 面向用户的简洁文案。
 *  禁止把原始异常文本（如 Linux/Windows 系统错误、堆栈）直出界面：
 *  异常文本可达数千字符，会把提示撑满窗口。 */
const FILE_IMPORT_ERROR_TEXT: Record<FileImportErrorCode, string> = {
  E_STAT_FAILED: "无法读取文件信息",
  E_READ_FAILED: "读取文件失败",
  E_ENCRYPT_FAILED: "文件加密失败",
  E_CHUNK_FAILED: "数据块写入失败",
  E_META_FAILED: "文件元数据写入失败",
  E_FILE_CHANGED: "文件在导入过程中被改动",
  E_FILE_TOO_LARGE: "文件超过大小上限",
  E_DISK_FULL: "磁盘空间不足",
  E_UNKNOWN: "导入失败，请重试",
};

/** 取错误码对应的用户可见文案（未知码回退为通用文案） */
export function fileImportErrorMessage(code: string): string {
  return FILE_IMPORT_ERROR_TEXT[code as FileImportErrorCode] ?? FILE_IMPORT_ERROR_TEXT.E_UNKNOWN;
}
