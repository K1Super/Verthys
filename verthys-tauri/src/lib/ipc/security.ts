/*
 * ipc/security.ts — 动态防护状态查询与回退锚点维护
 */

import { Channel } from "@tauri-apps/api/core";
import { ipc } from "./internal";
import type {
  VerthysResponse,
  SecurityStatusReport,
  AnchorInfo,
  AnchorScanResult,
  AnchorScanProgress,
} from "../../types/verthys";

/* ------------------------------------------------------------------ *
 * 动态防护状态查询                                                  *
 *                                                                    *
 * verthysGetSecurityStatus 透传 worker 的 security_status op，          *
 * 返回 7 条攻击路径的阻断/降级/失败状态。                              *
 * 防御状态为进程级事实，锁定态亦可查询。                               *
 * ------------------------------------------------------------------ */

/**
 * 查询动态防护实时状态
 *
 * 调用链：前端 → verthys_security_status → worker security_status
 *   → FFI Verthys_GetSecurityStatus → SecurityStatusReport
 *
 * 7 条攻击路径（path_state 下标）：
 *   0=挂起绕过 1=内存转储 2=休眠取证 3=IAT Hook
 *   4=DLL 劫持 5=进程读取 6=跨设备
 *
 * 报告同时携带 path_reason（判定原因码）、limited_count（已加固的用户态上限项数）、
 * policy_flags（运行时守卫位）与 checked_at_unix_ms（采样时间）；
 * 前端只做展示映射，禁止在本地推导安全结论。
 *
 * @returns 防御状态报告（worker 失败时抛异常）
 * @throws Error worker 未初始化或防御状态查询失败
 */
export async function verthysGetSecurityStatus(): Promise<SecurityStatusReport> {
  const r = await ipc<VerthysResponse & { security_status?: SecurityStatusReport }>(
    "verthys_security_status",
    {}
  );
  if (!r.ok || !r.security_status) {
    throw new Error(`verthys_security_status 失败: ${r.error ?? "未知错误"}`);
  }
  return r.security_status;
}

/**
 * 记录内核防护降级审计（SECURE preferred 下的用户态降级事实）
 *
 * 只写审计链，不改变内核/服务/会话状态。模块级按 (state, reason) 去重，
 * 组件重挂载不会重复写链；降级事实恢复后由调用方显式重置。
 *
 * @param kernelState 内核状态码（0..10，与 VtyKernelState 对齐）
 * @param kernelReason 原因码（0..11，与 VtyKernelReason 对齐）
 */
let lastKernelDegradedAuditKey: string | null = null;

export async function verthysAuditKernelDegraded(
  kernelState: number,
  kernelReason: number,
): Promise<void> {
  const key = `${kernelState}:${kernelReason}`;
  if (key === lastKernelDegradedAuditKey) return;
  lastKernelDegradedAuditKey = key;
  try {
    await ipc<void>("verthys_audit_kernel_degraded", {
      kernelState,
      kernelReason,
    });
  } catch (e) {
    /* 写入失败允许下轮重试，不把失败键保留为已审计 */
    lastKernelDegradedAuditKey = null;
    throw e;
  }
}

/** 重置内核降级审计去重键（观测到非降级事实后调用） */
export function verthysResetKernelDegradedAudit(): void {
  lastKernelDegradedAuditKey = null;
}

/* ------------------------------------------------------------------ *
 * 回退锚点维护                                                     *
 *                                                                    *
 * List 只读；Reclaim 只回收 DEAD；Release 必须 confirm=true。         *
 * 前端不自行判断“哪些锚点可删”，只展示后端状态并要求用户显式确认。 *
 * ------------------------------------------------------------------ */

export interface AnchorListResult {
  anchors: AnchorInfo[];
  /** 0=absent / 1=ok / 2=corrupt */
  state: number;
}

export interface AnchorMutationResult {
  ok: boolean;
  removed?: number;
  released?: number;
  cleanupFailed?: number;
  error?: string;
  errorCode?: string;
}

/** 列出本机回退锚点（不要求容器已解锁） */
export async function verthysRollbackAnchorList(): Promise<AnchorListResult> {
  const r = await ipc<VerthysResponse>("verthys_rollback_anchor_list", {});
  if (!r.ok) {
    throw new Error(`verthys_rollback_anchor_list 失败: ${r.error ?? "未知错误"}`);
  }
  return { anchors: r.anchors ?? [], state: r.anchor_state ?? 1 };
}

/** 回收所有 DEAD 锚点；ACTIVE/TAMPERED/UNKNOWN 由后端保留 */
export async function verthysRollbackAnchorReclaim(
  confirm: boolean,
): Promise<AnchorMutationResult> {
  const r = await ipc<VerthysResponse>("verthys_rollback_anchor_reclaim", {
    confirm,
  });
  return {
    ok: r.ok,
    removed: r.anchor_removed,
    cleanupFailed: r.anchor_cleanup_failed,
    error: r.error,
    errorCode: r.error_code ?? undefined,
  };
}

/** 显式释放指定 UUID 的锚点；调用方必须先完成二次确认 */
export async function verthysRollbackAnchorRelease(
  uuid: string,
  confirm: boolean,
): Promise<AnchorMutationResult> {
  const r = await ipc<VerthysResponse>("verthys_rollback_anchor_release", {
    uuid,
    confirm,
  });
  return {
    ok: r.ok,
    released: r.anchor_released,
    cleanupFailed: r.anchor_cleanup_failed,
    error: r.error,
    errorCode: r.error_code ?? undefined,
  };
}

/** 扫描选项：roots 添加自定义位置，force 强制重扫，peek 只读持久化证据 */
export interface AnchorScanOptions {
  roots?: string[];
  force?: boolean;
  peek?: boolean;
}

/** 扫描本地容器位置；peek=true 时只读取持久化证据，不遍历磁盘 */
export async function verthysRollbackAnchorScan(
  options: AnchorScanOptions = {},
  onProgress?: (progress: AnchorScanProgress) => void,
): Promise<AnchorScanResult> {
  const channel = new Channel<AnchorScanProgress>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }
  const r = await ipc<VerthysResponse>("verthys_rollback_anchor_scan", {
    roots: options.roots ?? [],
    force: options.force ?? false,
    peek: options.peek ?? false,
    onProgress: channel,
  });
  if (!r.ok || !r.anchor_scan) {
    throw new Error(`verthys_rollback_anchor_scan 失败: ${r.error ?? "未知错误"}`);
  }
  return r.anchor_scan;
}

/** 请求停止正在进行的扫描；已完成的证据照常保留 */
export async function verthysRollbackAnchorScanCancel(): Promise<void> {
  const r = await ipc<VerthysResponse>("verthys_rollback_anchor_scan_cancel", {});
  if (!r.ok) {
    throw new Error(
      `verthys_rollback_anchor_scan_cancel 失败: ${r.error ?? "未知错误"}`,
    );
  }
}

/** 移除一个自定义扫描位置，返回移除后的持久化证据 */
export async function verthysRollbackAnchorForgetRoot(
  path: string,
): Promise<AnchorScanResult> {
  const r = await ipc<VerthysResponse>("verthys_rollback_anchor_scan_forget_root", {
    path,
  });
  if (!r.ok || !r.anchor_scan) {
    throw new Error(
      `verthys_rollback_anchor_scan_forget_root 失败: ${r.error ?? "未知错误"}`,
    );
  }
  return r.anchor_scan;
}
