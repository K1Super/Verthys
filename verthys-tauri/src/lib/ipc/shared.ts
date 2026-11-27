/*
 * ipc/shared.ts — IPC 共享底座
 *
 * 类型/常量再导出、跨域结构化错误码。私有 invoke 包装见 ./internal，
 * 不经 barrel 暴露，避免绕过受限指令白名单。
 */

import { Channel } from "@tauri-apps/api/core";

/* ------------------------------------------------------------------ *
 * 再导出                                                              *
 *                                                                    *
 * 上层组件和 keyManager 分层通过 `from "../verthys"` 导入       *
 * 类型、常量、加密函数。                                              *
 * ------------------------------------------------------------------ */

// 类型再导出
export type {
  VerthysResponse,
  VerthysRecordEntry,
  VerthysSummaryEntry,
  EnumerateBatch,
  AccountFields,
  RecordEntry,
  PreflightResult,
  InitStatusResult,
  VerthysPreset,
  BruteForceCheckResponse,
  BruteForceStatus,
  UnknownModuleInfo,
  ShadowSleepStatus,
  UsbVolumeStatus,
  SecurityPresetCode,
  PresetConfig,
  SecurityStatusReport,
  UnlockProgress,
  RotateProgress,
  ClipboardResult,
  PrivacyModeResult,
  PrivacyStatusResult,
  BatchRecordInput,
  ImportBatchProgress,
  ImportBeginResult,
  AddRecordsBatchResult,
  ChunkBlobInput,
  AddChunkBatchResult,
  WalRecoverResult,
  DeviceBindingResult,
  PhotoImportProgress,
  PhotoImportItem,
  PhotoImportFailure,
  PhotoImportResult,
  FileImportSource,
  FileImportProgress,
  FileImportEntry,
  FileImportFailure,
  FileImportResult,
  PhotoPreviewResult,
  PhotoFullBegin,
  PhotoExportProgress,
  PhotoExportResult,
  PhotoMetaItem,
  PhotoMetaBatch,
  PhotoDamageScan,
  PhotoParsePreviewResult,
} from "../../types/verthys";
export type {
  PresetFeatures,
  VaultEntry,
  StorageStats,
} from "../../types/verthys";

// 常量再导出
export {
  VERTHYS_PRESET_BALANCED,
  VERTHYS_PRESET_SECURE,
  SECURITY_PRESET_BALANCED,
  SECURITY_PRESET_SECURE,
  SECURITY_PRESET_PERFORMANCE,
  SECURITY_PRESET_CUSTOM,
} from "../../constants/verthys_const";

// 加密函数再导出（实现位于 crypto.ts）
export { encryptPasswordField, decryptPasswordField } from "../crypto";

/* ------------------------------------------------------------------ *
 * base64 编解码（由 utils/binary_codec 再导出）                      *
 * ------------------------------------------------------------------ */

export { bytesToBase64, base64ToBytes } from "../../utils/codec/binary_codec";

/** 导入会话繁忙（结构化错误码）：前端据此唤起会话冲突确认，不做文案判定 */
export const IMPORT_SESSION_BUSY_CODE = "E_IMPORT_SESSION_BUSY";

/** 加密库未就绪（结构化错误码）：前端据此给出重新解锁引导，不做文案判定 */
export const VERTHYS_NOT_READY_CODE = "E_VERTHYS_NOT_READY";
