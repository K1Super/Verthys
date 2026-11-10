/**
 * app/launch-presentation.ts — 启动展示判定（纯函数）
 *
 * 职责：根据“本次开机启动时刻”与“上次记录的启动时刻”判定本次启动
 *   应播放完整首映，还是直接进入主界面。
 *
 * 语义：
 *   - 两次启动时刻相差在容差内 → 同一次开机 → 直接进入
 *   - 相差超过容差、标记缺失、标记损坏、当前时刻不可用 → 首映
 *
 * Why：首映是每次开机一次的仪式，不是每次进程启动的关卡。判定只依赖
 *   系统启动时刻这一个信号，不引入安装标记、日期或界面状态，保证
 *   “关闭应用再启动直接进入、重启电脑后恢复首映”两个行为来自同一规则。
 */

export type LaunchPresentation = "ceremony" | "direct";

/** 上次启动时刻的持久化键（命名空间前缀与既有诊断键保持一致） */
export const LAUNCH_BOOT_EPOCH_KEY = "Verthys:launch:boot-epoch";

/** 同一次开机的判定容差：覆盖 NTP 微调与启动阶段秒级时钟误差 */
export const BOOT_EPOCH_TOLERANCE_MS = 120_000;

/** 解析持久化的启动时刻；非正整数、溢出或非数字一律视为无效 */
export function parseStoredBootEpoch(raw: string | null): number | null {
  if (raw === null) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

/**
 * 判定本次启动的展示形态。
 *
 * 当前时刻不可用时必须回退首映：宁可多播一次，不可漏播。
 */
export function decideLaunchPresentation(
  currentBootEpochMs: number | null,
  storedBootEpochMs: number | null,
): LaunchPresentation {
  if (
    currentBootEpochMs === null ||
    !Number.isSafeInteger(currentBootEpochMs) ||
    currentBootEpochMs <= 0
  ) {
    return "ceremony";
  }
  if (storedBootEpochMs === null) return "ceremony";
  return Math.abs(currentBootEpochMs - storedBootEpochMs) <= BOOT_EPOCH_TOLERANCE_MS
    ? "direct"
    : "ceremony";
}
