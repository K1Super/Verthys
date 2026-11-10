/**
 * file-verthys/useFileRepair.ts — 清藏损坏文件清理交互层
 *
 * 职责：扫描（只验证内容外层）→ 结果呈现 → 二次显式确认 → 删除。
 * 删除由调用方注入（复用清藏既有批量删除 / 落盘 / 缓存失效 / 孤儿回收
 * 链路），本层只负责状态机，不直接触碰记录。
 */

import { ref } from "vue";
import type { ShallowRef } from "vue";
import {
  scanDamagedFiles,
  type FileDamageDeps,
  type FileRepairEntry,
} from "./damage";

export type FileRepairStage = "idle" | "scanning" | "scanned" | "cleaning";

export interface UseFileRepairParams extends FileDamageDeps {
  /** 清藏列表条目 */
  files: ShallowRef<FileRepairEntry[]>;
  /** 是否处于 Tauri 环境 */
  isTauri: boolean;
  /** 删除确定损坏的条目（含落盘/缓存/回收）；成功返回 true */
  cleanup: (entries: FileRepairEntry[]) => Promise<boolean>;
  /** 错误提示 */
  showError: (msg: string) => void;
}

export function useFileRepair(params: UseFileRepairParams) {
  const { files, isTauri, fetchRecord, probeOuter, cleanup, showError } = params;

  const visible = ref(false);
  const stage = ref<FileRepairStage>("idle");
  const confirming = ref(false);
  const checked = ref(0);
  const damaged = ref<FileRepairEntry[]>([]);
  const healthy = ref(0);
  const skipped = ref(0);
  const inconclusive = ref(0);

  const resetResult = () => {
    confirming.value = false;
    checked.value = 0;
    damaged.value = [];
    healthy.value = 0;
    skipped.value = 0;
    inconclusive.value = 0;
  };

  const runScan = async (): Promise<void> => {
    if (stage.value === "scanning" || stage.value === "cleaning") return;
    resetResult();
    stage.value = "scanning";
    try {
      const result = await scanDamagedFiles(files.value, { fetchRecord, probeOuter });
      checked.value = result.checked;
      damaged.value = result.damaged;
      healthy.value = result.healthy;
      skipped.value = result.skipped;
      inconclusive.value = result.inconclusive;
      stage.value = "scanned";
    } catch (e) {
      stage.value = "idle";
      showError(e instanceof Error ? e.message : "扫描失败，请重试");
    }
  };

  const open = async (): Promise<void> => {
    if (!isTauri) {
      showError("损坏清理仅在桌面端可用");
      return;
    }
    if (files.value.length === 0) {
      showError("暂无文件可检查");
      return;
    }
    if (stage.value === "scanning" || stage.value === "cleaning") return;
    visible.value = true;
    await runScan();
  };

  /** 第一次点击“删除损坏文件”：进入二次确认，不执行删除 */
  const requestCleanup = (): void => {
    if (stage.value !== "scanned" || damaged.value.length === 0) return;
    confirming.value = true;
  };

  const cancelConfirm = (): void => {
    confirming.value = false;
  };

  const cleanupDamaged = async (): Promise<void> => {
    if (stage.value !== "scanned" || damaged.value.length === 0) return;
    stage.value = "cleaning";
    confirming.value = false;
    const entries = [...damaged.value];
    const ok = await cleanup(entries);
    if (!ok) {
      // 删除未发生：保留结果页供重试或关闭
      stage.value = "scanned";
      return;
    }
    resetResult();
    stage.value = "idle";
    visible.value = false;
  };

  const close = (): void => {
    if (stage.value === "scanning" || stage.value === "cleaning") return;
    visible.value = false;
    stage.value = "idle";
    resetResult();
  };

  return {
    visible,
    stage,
    confirming,
    checked,
    damaged,
    healthy,
    skipped,
    inconclusive,
    open,
    runScan,
    requestCleanup,
    cancelConfirm,
    cleanupDamaged,
    close,
  };
}
