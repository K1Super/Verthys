/**
 * useModuleEntrance — 模块步入窗口与错峰编排（单一权威）
 *
 * 职责边界：
 *   - 只产出「步入窗口标记」与「错峰延迟」，不持有任何视觉样式；
 *     关键帧与包络为 styles/animations.css「模块步入编排」段的单源。
 *
 * 步入窗口（entering）：
 *   宿主元素据本标记决定内容条目是否播放入场动画（.reveal-host.is-entering
 *   .reveal-item）。窗口为一次性 —— 结束即撤标记，此后动态挂载的条目
 *   （虚拟滚动换行 / 数据增量）直接呈现：既杜绝滚动期条目以错峰延迟留白，
 *   也杜绝停稳后整屏重演闪烁。
 *
 * 起算时刻：
 *   窗口自「内容首次就绪」起算，而非自组件挂载起算 —— 数据异步就绪的模块
 *   （本地缓存未命中 / 相册索引扫描）其条目在挂载后若干帧才落地，若以挂载
 *   起算，窗口会在条目出现前耗尽而致整批直接呈现。就绪判定与宿主渲染同批
 *   落地（watch 默认 pre 刷新序先于组件渲染）：标记与首批条目同一 patch 生效，
 *   首帧即入场起点，无「先整帧可见再跳回 0」的闪跳。
 *
 * 并发与生命周期：
 *   窗口定时器与侦听在 onBeforeUnmount 释放；单实例单窗口，重复就绪不重开。
 */

import { onBeforeUnmount, ref, watch, type Ref } from "vue";
import { MODULE_REVEAL } from "../app/constants";

/**
 * 序 → 错峰延迟（毫秒）。
 *
 * 曲线：渐近饱和 delay = span × (1 − 1/(1 + 序/K))。
 *   - 前段步长明显（相邻条目可辨的先后次序），后段渐次收拢至 span：
 *     任意长度列表的尾部延迟均有界（不出现秒级空白），且无「前半错峰、
 *     后半齐现」的折线感 —— 该折线是线性延迟截顶的固有形态。
 *   - 与主界面「谱线逐条递减加速扫掠」同族（同刻起笔、幕内步长非等距），
 *     故模块内容入场与品牌编排读作同一套运动语言。
 *
 * @param order 条目在内容组内的序（从 0 起；虚拟滚动可传绝对索引 —
 *              饱和曲线保证其延迟有界）
 */
export function revealDelayOf(order: number): number {
  const { staggerSpanMs, staggerK } = MODULE_REVEAL;
  const ordinal = order > 0 ? order : 0;
  return Math.round(staggerSpanMs * (1 - 1 / (1 + ordinal / staggerK)));
}

/**
 * 创建步入窗口。
 *
 * @param isReady 内容就绪判定（返回 true 即开启窗口）— 传入 getter 而非快照，
 *                使异步就绪的模块在数据落地的那一渲染批开启窗口
 * @returns entering 响应式标记，绑定到宿主的 is-entering 类
 */
export function useModuleEntrance(isReady: () => boolean): { entering: Ref<boolean> } {
  const entering = ref(isReady());
  /* 单窗口标记：窗口已开启或已耗尽后不再重开（重复就绪不重演入场） */
  let consumed = entering.value;
  let timer: number | undefined;

  const open = (): void => {
    consumed = true;
    entering.value = true;
    timer = window.setTimeout(() => { entering.value = false; }, MODULE_REVEAL.holdMs);
  };

  /* 就绪侦听仅在「挂载时尚未就绪」时注册（静态内容模块不留常驻侦听）；
   * 释放句柄由 watch 同步返回，回调执行时已就绪 —— 开启即注销（一次性） */
  let stopWatch: (() => void) | null = null;
  if (entering.value) {
    open();
  } else {
    stopWatch = watch(isReady, (ready) => {
      if (!ready || consumed) return;
      open();
      stopWatch?.();
    });
  }

  onBeforeUnmount(() => {
    if (timer !== undefined) window.clearTimeout(timer);
    timer = undefined;
    stopWatch?.();
  });

  return { entering };
}
