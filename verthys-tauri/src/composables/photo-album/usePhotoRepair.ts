/**
 * photo-album/usePhotoRepair.ts — 损坏照片记录清理层
 *
 * 背景：全库轮换缺陷会让照片内容层仍由旧 MDEK 封装；元数据无法解密时
 * 相册只剩占位卡片，记录本身已不可用，且旧密钥已随旧库删除而不可恢复。
 * 本组合式负责把“确定损坏”的记录清出相册：
 *
 *   1. 扫描全部照片元数据，只把内容层认证失败（ERR_00000002）判定为
 *      损坏；模块锁定/超时/记录暂不可读等一律跳过，绝不误删（见 damage.ts）；
 *   2. 结果必须经用户二次显式确认后才删除（不可逆，绝不自动执行）；
 *   3. 删除复用 usePhotoDelete 的台账级联、落盘校验与孤儿块回收链路。
 */
import { ref } from "vue";
import type { ShallowRef } from "vue";
import type { PhotoEntry } from "./types";

/** 损坏清理阶段 */
export type RepairStage = "idle" | "scanning" | "scanned" | "cleaning";

export interface UsePhotoRepairParams {
  /** 照片列表（用于判断是否有可扫描记录） */
  photos: ShallowRef<PhotoEntry[]>;
  /** 是否处于 Tauri 环境 */
  isTauri: boolean;
  /** 扫描全部照片元数据（usePhotoData 提供） */
  scanDamaged: () => Promise<{
    checked: number;
    damaged: number[];
    inconclusive: number;
  }>;
  /** 按 metaId 删除确定损坏的记录（usePhotoDelete 提供） */
  cleanupDamaged: (metaIds: number[]) => Promise<boolean>;
  /** 错误提示（全局 Toast 中心） */
  showError: (msg: string) => void;
}

export function usePhotoRepair(params: UsePhotoRepairParams) {
  const { photos, isTauri, scanDamaged, cleanupDamaged, showError } = params;

  const visible = ref(false);
  const stage = ref<RepairStage>("idle");
  /** 二次确认态：扫描结果出来后仍需用户再点一次“确认永久删除” */
  const confirming = ref(false);
  const checked = ref(0);
  const damagedIds = ref<number[]>([]);
  const inconclusive = ref(0);

  const resetResult = () => {
    confirming.value = false;
    checked.value = 0;
    damagedIds.value = [];
    inconclusive.value = 0;
  };

  const runScan = async (): Promise<void> => {
    if (stage.value === "scanning" || stage.value === "cleaning") return;
    resetResult();
    stage.value = "scanning";
    try {
      const result = await scanDamaged();
      checked.value = result.checked;
      damagedIds.value = result.damaged;
      inconclusive.value = result.inconclusive;
      stage.value = "scanned";
    } catch (e) {
      stage.value = "idle";
      showError(e instanceof Error ? e.message : "扫描失败，请重试");
    }
  };

  /** 打开对话框并立即开始扫描 */
  const open = async (): Promise<void> => {
    if (!isTauri) {
      showError("损坏清理仅在桌面端可用");
      return;
    }
    if (photos.value.length === 0) {
      showError("暂无照片可检查");
      return;
    }
    if (stage.value === "scanning" || stage.value === "cleaning") return;
    visible.value = true;
    await runScan();
  };

  /** 第一次点击“删除损坏记录”：进入二次确认（不执行删除） */
  const requestCleanup = (): void => {
    if (stage.value !== "scanned" || damagedIds.value.length === 0) return;
    confirming.value = true;
  };

  const cancelConfirm = (): void => {
    confirming.value = false;
  };

  /** 二次确认后执行删除 */
  const cleanup = async (): Promise<void> => {
    if (stage.value !== "scanned" || damagedIds.value.length === 0) return;
    stage.value = "cleaning";
    confirming.value = false;
    const ids = [...damagedIds.value];
    const ok = await cleanupDamaged(ids);
    if (!ok) {
      // 删除未发生：保持结果页，用户可重试或关闭
      stage.value = "scanned";
      return;
    }
    // 记录已删除，移除本地结果并关闭
    damagedIds.value = [];
    checked.value = 0;
    inconclusive.value = 0;
    stage.value = "idle";
    visible.value = false;
  };

  /** 关闭（扫描/删除在途时不允许关闭，避免状态错位） */
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
    damagedIds,
    inconclusive,
    open,
    runScan,
    requestCleanup,
    cancelConfirm,
    cleanup,
    close,
  };
}
