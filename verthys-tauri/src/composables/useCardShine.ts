/**
 * useCardShine — 卡片指针光晕（指针位置驱动的径向高光）
 *
 * 全模块唯一实现（存签 / 枢钥 / 钥域 / 拾光）。职责边界：
 * - 本模块只把指针位置写成卡片元素上的 CSS 变量（--shine-x / --shine-y，经自定义
 *   属性继承到光晕层），不写任何渐变/颜色/强度字面量；
 * - 光晕强度是设计令牌单源：styles/tokens.css 的 --shine-alpha / --shine-reach
 *   （色相取 --accent-rgb）——改强度只改令牌一处；
 * - 各表面只保留几何与混合模式差异（卡片表面 mix-blend-mode: screen；
 *   拾光照片面为常规混合）。
 *
 * 卡片 3D 视差倾斜已按用户决策整体移除（Wave 53）。原实现逐帧写入
 * perspective/rotate transform，但卡片入场动画（card-in，前向填充）在 CSS 级联中
 * 优先级高于内联样式，transform 恒被动画终态覆盖——该倾斜实际从未渲染
 * （与 Wave 51/52 拾光卡片属同一缺陷类）。如未来需要恢复倾斜，必须同时满足：
 * 入场动画不得前向填充 transform、3D/非整数缩放不得作用于文字层、不得与 CSS
 * 过渡或逐帧写入双写。
 *
 * mousemove 事件用主循环排帧节流（合并同帧多次调用，60fps 上限）
 * 原问题：mousemove 每秒触发 60~120 次，每次都执行 getBoundingClientRect + style 写入，
 *        连续移动鼠标时主线程 JS 执行时间远超 16.6ms（60fps 一帧预算）。
 * 优化后：同一帧内多次 mousemove 仅执行最后一次，计算开销降低 90%。
 *
 * 关键修复（两则）：
 * 1. event.currentTarget 在事件分发结束后被浏览器置空——必须在同步阶段
 *    （事件触发时）捕获 card 元素；clientX/clientY 是事件对象属性，派发后
 *    仍可安全读取。
 * 2. 布局读取（getBoundingClientRect）全部延迟到排帧回调——同步阶段只做
 *    引用与坐标捕获。原实现在事件同步阶段读布局：滚动期/高频事件下会形成
 *    强制同步 reflow（每事件一次）；现在每帧至多一次布局读（同帧事件合并）。
 *    另：滚动静默期（根类 app-scrolling）直接跳过采集——滚动中光晕视觉已
 *    冻结（样式层），采集无意义且会引入布局读。
 *
 * 用法：
 *   const { onCardMove, onCardLeave, cancel } = useCardShine();
 *   // 模板: @mousemove="onCardMove($event)" @mouseleave="onCardLeave($event)"
 *   // 卸载: cancel()
 */

import { masterFrameLoop } from "../core/master-frame-loop";

export function useCardShine() {
  /* 排帧标志（once 单发无句柄 — 靠布尔置位去重同帧多次事件） */
  let scheduled = false;
  /* 排帧待处理：同步阶段仅捕获元素引用与指针坐标，布局读/写入在排帧回调 */
  let pending: { card: HTMLElement; clientX: number; clientY: number } | null = null;

  const onCardMove = (e: MouseEvent) => {
    const card = e.currentTarget as HTMLElement | null;
    if (!card) return;
    /* 滚动静默期不采集（滚动中光晕已被样式层冻结，且不引入任何布局读取） */
    if (document.documentElement.classList.contains("app-scrolling")) return;
    pending = { card, clientX: e.clientX, clientY: e.clientY };
    if (!scheduled) {
      scheduled = true;
      masterFrameLoop.once(() => {
        scheduled = false;
        if (!pending) return;
        const { card: c, clientX, clientY } = pending;
        pending = null;
        const r = c.getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) return;
        const px = (clientX - r.left) / r.width - 0.5;
        const py = (clientY - r.top) / r.height - 0.5;
        c.style.setProperty("--shine-x", `${(px * 100 + 50).toFixed(1)}%`);
        c.style.setProperty("--shine-y", `${(py * 100 + 50).toFixed(1)}%`);
      });
    }
  };

  /* mouseleave 是低频事件（每秒最多几次），无需节流 */
  const onCardLeave = (e: MouseEvent) => {
    const card = e.currentTarget as HTMLElement | null;
    if (!card) return;
    card.style.removeProperty("--shine-x");
    card.style.removeProperty("--shine-y");
  };

  /** 取消未触发的排帧写入（卸载时调用，避免卸载后写入已脱离文档的元素） */
  const cancel = () => {
    pending = null;
  };

  return { onCardMove, onCardLeave, cancel };
}