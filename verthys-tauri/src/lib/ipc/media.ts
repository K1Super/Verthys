/*
 * ipc/media.ts — 照片/文件导入与导出还原
 */

import { Channel } from "@tauri-apps/api/core";
import { markFrontendIpcActive } from "../../core/frontend-ipc-priority";
import { ipc } from "./internal";
import type {
  PhotoImportProgress,
  PhotoImportResult,
  FileImportSource,
  FileImportProgress,
  FileImportResult,
  PhotoPreviewResult,
  PhotoFullBegin,
  PhotoMetaBatch,
  PhotoDamageScan,
  PhotoParsePreviewResult,
  PhotoExportProgress,
  PhotoExportResult,
} from "../../types/verthys";

/* ================================================================== *
 * 原生照片导入 IPC 封装                                              *
 *                                                                  *
 * 读取/加密/写入均由后端流水线完成，前端只传路径与进度 Channel。     *
 * 不设 IPC 超时：单次调用可能持续数分钟（大相册导入）。               *
 * ================================================================== */

/**
 * 启动原生照片导入（阻塞至整个批次结束或取消）。
 *
 * @param paths 待导入文件的绝对路径列表
 * @param onProgress 进度回调（scanning / importing / finishing 阶段流式推送）
 * @returns 导入结果（imported / failedRecords / skipped / total / elapsedMs / cancelled）
 */
export async function photoImportStart(
  paths: string[],
  onProgress?: (progress: PhotoImportProgress) => void,
): Promise<PhotoImportResult> {
  const channel = new Channel<PhotoImportProgress>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }

  // 前端 IPC 优先级门控：标记前端活跃，后台任务让出 worker 通道
  markFrontendIpcActive();

  const r = await ipc<PhotoImportResult>("photo_import_start", {
    paths,
    onProgress: channel,
  });
  return {
    ok: r.ok === true,
    imported: r.imported ?? [],
    failedRecords: r.failedRecords ?? [],
    skipped: r.skipped ?? 0,
    total: r.total ?? 0,
    elapsedMs: r.elapsedMs ?? 0,
    error: r.error,
    errorCode: r.errorCode,
    cancelled: r.cancelled === true,
  };
}

/**
 * 请求取消进行中的原生导入。
 *
 * 取消是尽力而为：失败只告警不抛出，避免阻断前端既有的取消收尾路径。
 */
export async function photoImportCancel(): Promise<void> {
  try {
    await ipc("photo_import_cancel");
  } catch (e) {
    console.warn("[photoImportCancel] 取消失败", e);
  }
}

/* ================================================================== *
 * 原生清藏导入 IPC 封装                                              *
 *                                                                  *
 * 读取、哈希、KDF、加密与分块暂存全部在 worker 内完成；前端只传路径与  *
 * 展示字段，不接触任何块字节。不设 IPC 超时：单次调用可能持续数分钟。  *
 * ================================================================== */

/**
 * 启动原生清藏导入（阻塞至整批结束或取消）。
 *
 * @param files 待导入文件（路径 + 展示名 + MIME）
 * @param password 独立访问密码；不加密传 null
 * @param allowSessionTakeover 用户已确认结束上一导入会话（保留其断点）
 * @param onProgress 进度回调
 */
export async function fileImportStart(
  files: FileImportSource[],
  password: string | null,
  allowSessionTakeover: boolean,
  onProgress?: (progress: FileImportProgress) => void,
): Promise<FileImportResult> {
  const channel = new Channel<FileImportProgress>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }

  markFrontendIpcActive();

  const r = await ipc<FileImportResult>("file_import_start", {
    files,
    password,
    allowSessionTakeover,
    onProgress: channel,
  });
  return {
    ok: r.ok === true,
    entries: r.entries ?? [],
    failures: r.failures ?? [],
    skipped: r.skipped ?? [],
    successCount: r.successCount ?? 0,
    skippedCount: r.skippedCount ?? 0,
    failCount: r.failCount ?? 0,
    total: r.total ?? 0,
    elapsedMs: r.elapsedMs ?? 0,
    cancelled: r.cancelled === true,
    error: r.error,
    errorCode: r.errorCode,
    sessionWarning: r.sessionWarning,
  };
}

/** 请求取消进行中的清藏导入（尽力而为；失败只告警）。 */
export async function fileImportCancel(): Promise<void> {
  try {
    await ipc("file_import_cancel");
  } catch (e) {
    console.warn("[fileImportCancel] 取消失败", e);
  }
}

/* ================================================================== *
 * 原生照片查看 IPC 封装                                              *
 *                                                                  *
 * 预览优先：photo_preview_get 一次返回 2048px JPEG；原图经           *
 * photo_full_begin/next 按块拉取，前端以 Blob 分片组装。             *
 * 布局不支持时后端返回 E_PHOTO_LAYOUT_UNSUPPORTED，调用方回退旧链路。*
 * ================================================================== */

/** 读取照片预览（命中预览记录或 worker 懒生成） */
export async function photoPreviewGet(metaId: number): Promise<PhotoPreviewResult> {
  markFrontendIpcActive();
  const r = await ipc<PhotoPreviewResult>("photo_preview_get", { metaId });
  return {
    dataB64: r.dataB64 ?? "",
    name: r.name ?? "",
    mime: r.mime ?? "",
    size: r.size ?? 0,
    cached: r.cached === true,
    elapsedMs: r.elapsedMs ?? 0,
  };
}

/** 打开原图读取 job */
export async function photoFullBegin(metaId: number): Promise<PhotoFullBegin> {
  markFrontendIpcActive();
  const r = await ipc<PhotoFullBegin>("photo_full_begin", { metaId });
  return {
    jobId: r.jobId ?? "",
    name: r.name ?? "",
    mime: r.mime ?? "",
    size: r.size ?? 0,
    chunkTotal: r.chunkTotal ?? 0,
  };
}

/** 拉取下一块原图明文（二进制 IPC：直接返回原始字节，无帧头、无 base64） */
export async function photoFullNext(jobId: string): Promise<Uint8Array> {
  markFrontendIpcActive();
  const raw = await ipc<ArrayBuffer>("photo_full_next", { jobId });
  if (!(raw instanceof ArrayBuffer)) {
    throw new Error("原图分块响应类型非法");
  }
  return new Uint8Array(raw);
}

/** 取消原图读取（失败只告警） */
export async function photoFullCancel(jobId: string): Promise<void> {
  if (!jobId) return;
  try {
    await ipc("photo_full_cancel", { jobId });
  } catch (e) {
    console.warn("[photoFullCancel] 取消失败", e);
  }
}

/**
 * 批量读取网格展示元数据（worker 内解密记录并读取独立缩略图记录）。
 */
export async function photoMetaGet(metaIds: number[]): Promise<PhotoMetaBatch> {
  markFrontendIpcActive();
  const r = await ipc<PhotoMetaBatch>("photo_meta_get", { metaIds });
  return {
    items: r.items ?? [],
    failedIds: r.failedIds ?? [],
  };
}

/** 扫描照片元数据，返回确定损坏的 metaId（原生判定，不上传密文到 JS）。 */
export async function photoMetaProbe(metaIds: number[]): Promise<PhotoDamageScan> {
  markFrontendIpcActive();
  const r = await ipc<PhotoDamageScan>("photo_meta_probe", { metaIds });
  return {
    checked: r.checked ?? 0,
    damaged: r.damaged ?? [],
    inconclusive: r.inconclusive ?? 0,
  };
}

/** 解析 .venc 清单预览（worker 流式认证，不把容器读入前端）。 */
export async function photoParseStart(
  path: string,
  token: string,
): Promise<PhotoParsePreviewResult[]> {
  markFrontendIpcActive();
  const r = await ipc<PhotoParsePreviewResult[]>("photo_parse_start", { path, token });
  return Array.isArray(r) ? r : [];
}

/* ================================================================== *
 * 原生照片导出与备份还原 IPC 封装                                     *
 *                                                                    *
 * worker 只产出字节，宿主负责暂存写盘与原子替换；前端只收进度与结果。 *
 * ================================================================== */

/**
 * 启动原生导出（阻塞至整批结束或取消）。
 *
 * @param ids 照片记录 ID 列表
 * @param format original / venc-single / venc-multiple / png
 * @param dest 单文件模式为目标文件路径，其余为目录
 * @param token venc 导出令牌；明文格式不传
 */
export async function photoExportStart(
  ids: number[],
  format: "original" | "venc-single" | "venc-multiple" | "png",
  dest: string,
  token: string | undefined,
  onProgress?: (progress: PhotoExportProgress) => void,
): Promise<PhotoExportResult> {
  const channel = new Channel<PhotoExportProgress>();
  if (onProgress) channel.onmessage = onProgress;
  markFrontendIpcActive();
  const r = await ipc<PhotoExportResult>("photo_export_start", {
    ids,
    format,
    dest,
    token,
    onProgress: channel,
  });
  return {
    ok: r.ok === true,
    exported: r.exported ?? 0,
    failed: r.failed ?? [],
    total: r.total ?? 0,
    elapsedMs: r.elapsedMs ?? 0,
    cancelled: r.cancelled === true,
    error: r.error,
    errorCode: r.errorCode,
  };
}

/** 请求取消进行中的原生导出（尽力而为，失败只告警） */
export async function photoExportCancel(): Promise<void> {
  try {
    await ipc("photo_export_cancel");
  } catch (e) {
    console.warn("[photoExportCancel] 取消失败", e);
  }
}

/**
 * 启动原生备份还原（阻塞至整批结束或取消）。
 *
 * @param path .venc 文件绝对路径（worker 经 job 授权读取）
 * @param token 导出令牌
 * @param expectedHashes 预览扫描得到的逐张 fileHash（容器替换检测）
 */
export async function photoRestoreStart(
  path: string,
  token: string,
  expectedHashes: string[],
  onProgress?: (progress: PhotoImportProgress) => void,
): Promise<PhotoImportResult> {
  const channel = new Channel<PhotoImportProgress>();
  if (onProgress) channel.onmessage = onProgress;
  markFrontendIpcActive();
  const r = await ipc<PhotoImportResult>("photo_restore_start", {
    path,
    token,
    expectedHashes,
    onProgress: channel,
  });
  return {
    ok: r.ok === true,
    imported: r.imported ?? [],
    failedRecords: r.failedRecords ?? [],
    skipped: r.skipped ?? 0,
    total: r.total ?? 0,
    elapsedMs: r.elapsedMs ?? 0,
    error: r.error,
    errorCode: r.errorCode,
    cancelled: r.cancelled === true,
  };
}
