/*
 * useAppTransition — 应用页面流转 + 星河阶段编排
 *
 * 职责：
 *   - 管理 entered / mainPrewarmed / phase 三态
 *   - 编排 onEnter 转场（渡越 → 双缓冲预挂载 → 页面交接 → 星河流动）
 *   - 统一调度 setTimeout 并在卸载时清理
 *
 *   v3 双缓冲预挂载（「突然跳转」根治）：
 *   旧实现交接帧（v-if 切换）同一帧内同步执行 UnlockView 整树卸载 +
 *   MainView 巨树挂载（组件构建 / 首次布局 / composable 初始化）+
 *   双全屏 blur 滤镜启动 → 主线程停帧 → 星系渡越冻结跳越 +
 *   MainView 跳过淡入前段直接出现 = 用户感知的突兀跳变。
 *   chunk 预取只解决「加载解析」，未解决「挂载布局」。
 *   根治 = 预挂载双缓冲：MainView 提前挂载进 prewarm 冻结层
 *   （visibility:hidden + 动画 paused + pointer-events:none），
 *   挂载尖峰在蓄能平缓段消化，交接帧只剩一次 class 切换。
 */

import { ref, onBeforeUnmount } from "vue";
import { PREWARM_MOUNT, TRANSITION } from "../app/constants";

type GalaxyPhase = "ambient" | "warping" | "galaxy";

export function useAppTransition() {
  /* 页面状态：未进入引导页 / 已进入主界面 */
  const entered = ref(false);
  /* MainView 预挂载标志：PREWARM_MOUNT 时刻置 true —
   * MainView 渲染进 prewarm 冻结层（App.vue .main-layer.prewarm），
   * 交接时刻解除冻结（entered=true 同帧移除 prewarm class） */
  const mainPrewarmed = ref(false);
  /* 星河阶段：ambient（引导页静旋）→ warping（引力正渡）→ galaxy（主界面流动星河） */
  const phase = ref<GalaxyPhase>("ambient");

  /** 定时器句柄池：统一注册与清理 */
  const timers: ReturnType<typeof setTimeout>[] = [];

  /** 注册延时任务并纳入统一管理 */
  const schedule = (fn: () => void, delay: number): void => {
    const id = setTimeout(fn, delay);
    timers.push(id);
  };

  /** 清除全部已注册的定时器 */
  const clearAllTimers = (): void => {
    timers.forEach(clearTimeout);
    timers.length = 0;
  };

  /**
   * 进入主界面转场编排（引力正渡 — 节点由 constants 等比派生，与引擎
   * ENTER_T 同源对齐；当前 5000ms：蓄能 0-1500 / 峰驻 1500-3100 /
   * 消散 3100-5000）「星系松开 → 界面浮现 → 同步收束」叙事轴：
   *   0ms    : 触发正渡（引擎蓄能段启动，星系缠绕收紧）
   *   1100ms : MainView 预挂载（弹射已完成，蓄能平缓段消化挂载尖峰）
   *   3100ms : 页面交接（包络 x=0.62 峰驻末端·消散起点 — 星系开始
   *            松开；UnlockView 淡出 + MainView 解冻 materialize）
   *   4167ms : 进入 galaxy 状态（消散尾声，星河重组落位 — 包络 x=5/6）
   *   5000ms : 引擎包络归零 = materialize 完成（星系落定 = 界面清晰
   *            同步收束；氛围苏醒锚点 MAINVIEW_AMBIENT_WAIT）
   */
  const onEnter = (): void => {
    /* 立即触发引力正渡（星系缠绕收紧 + 相机掠翼弧线） */
    phase.value = "warping";

    /* 双缓冲预挂载：MainView 挂进 prewarm 冻结层（蓄能平缓段） */
    schedule(() => {
      mainPrewarmed.value = true;
    }, PREWARM_MOUNT);

    /* 峰驻末端切换到主界面（UnlockView 淡出 / MainView 解冻浮现） */
    schedule(() => {
      entered.value = true;
    }, TRANSITION.PAGE_HANDOFF);

    /* 消散尾声星河进入流动状态 */
    schedule(() => {
      phase.value = "galaxy";
    }, TRANSITION.GALAXY_PHASE);
  };

  onBeforeUnmount(() => {
    clearAllTimers();
  });

  return {
    entered,
    mainPrewarmed,
    phase,
    onEnter,
  };
}
