/**
 * file-verthys/useFileRepair.ts — 清藏损坏文件检查与清理
 *
 * 交互口径：
 *   - 检查结果是瞬时事件，只走统一 Toast（顶部红/底部状态），不弹窗；
 *   - 若存在损坏文件，由调用方在模块内常驻告知条呈现数量与清理入口，
 *     告知条承担存续状态，Toast 只承担一次性结果；
 *   - 删除不可逆，执行前必须由调用方走统一二次确认。
 */

import { ref } from "vue";
import type { ShallowRef } from "vue";
import {
  scanDamagedFiles,
  type FileDamageDeps,
  type FileRepairEntry,
} from "./damage";

export interface UseFileRepairParams extends FileDamageDeps {
  /** 清藏列表条目 */
  files: ShallowRef<FileRepairEntry[]>;
  /** 是否处于 Tauri 环境 */
  isTauri: boolean;
  /** 删除确定损坏的条目（含落盘/缓存/回收）；成功返回 true */
  cleanup: (entries: FileRepairEntry[]) => Promise<boolean>;
  /** 错误提示（顶部红色 Toast） */
  showError: (msg: string) => void;
  /** 状态提示（底部中性 Toast） */
  showStatus: (msg: string) => void;
}

/** 检查结果文案：宁可少一个字，也不堆砌形容词 */
function buildSummary(result: {
  damaged: FileRepairEntry[];
  healthy: number;
  skipped: number;
  inconclusive: number;
}): { text: string; danger: boolean } {
  const pending = result.inconclusive > 0 ? `，${result.inconclusive} 个待确认` : "";
  if (result.damaged.length > 0) {
    return {
      text: `完整性检查：${result.damaged.length} 个文件无法解密${pending}`,
      danger: true,
    };
  }
  if (result.healthy > 0) {
    return {
      text: "完整性检查通过",
      danger: false,
    };
  }
  if (result.skipped > 0) {
    return {
      text: "完整性检查：无独立密码或历史布局，跳过校验",
      danger: false,
    };
  }
  return { text: "完整性检查：无可检查的文件", danger: false };
}

export function useFileRepair(params: UseFileRepairParams) {
  const { files, isTauri, fetchRecord, probeOuter, cleanup, showError, showStatus } = params;

  const scanning = ref(false);
  const damaged = ref<FileRepairEntry[]>([]);

  /** 执行检查，结果只走 Toast；损坏列表供常驻告知条消费 */
  const scan = async (): Promise<void> => {
    if (scanning.value) return;
    if (!isTauri) {
      showError("完整性检查仅在桌面端可用");
      return;
    }
    if (files.value.length === 0) {
      showStatus("完整性检查：暂无文件可检查");
      return;
    }

    scanning.value = true;
    damaged.value = [];
    try {
      const result = await scanDamagedFiles(files.value, { fetchRecord, probeOuter });
      damaged.value = result.damaged;
      const summary = buildSummary(result);
      if (summary.danger) showError(summary.text);
      else showStatus(summary.text);
    } catch (e) {
      showError(e instanceof Error ? e.message : "完整性检查失败，请重试");
    } finally {
      scanning.value = false;
    }
  };

  /** 清理已确认损坏的条目；成功后才清空告知条 */
  const cleanupDamaged = async (): Promise<boolean> => {
    if (damaged.value.length === 0) return true;
    const entries = [...damaged.value];
    const ok = await cleanup(entries);
    if (!ok) return false;
    damaged.value = [];
    showStatus(`已清理 ${entries.length} 个无法打开的文件`);
    return true;
  };

  /** 用户关闭告知条（保留列表数据，下次检查重新计算） */
  const clearResult = (): void => {
    damaged.value = [];
  };

  return {
    scanning,
    damaged,
    scan,
    cleanupDamaged,
    clearResult,
  };
}
