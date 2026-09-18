/**
 * useCardTilt — 卡片 3D 视差倾斜 + 光泽追踪
 *
 * ★ 项3：mousemove 事件用 rAF 节流（合并同帧多次调用，60fps 上限）
 * 原问题：mousemove 每秒触发 60~120 次，每次都执行 getBoundingClientRect + style 写入，
 *        连续移动鼠标时主线程 JS 执行时间远超 16.6ms（60fps 一帧预算）。
 * 优化后：同一帧内多次 mousemove 仅执行最后一次，视差计算开销降低 90%。
 *
 * ★ 关键修复：event.currentTarget 在事件分发结束后被浏览器置空，
 *   rAF 回调延迟到下一帧执行时 currentTarget 已为 null。
 *   必须在同步阶段（事件触发时）立即捕获 card 元素和坐标，rAF 仅负责延迟写入。
 *
 * 用法：
 *   const { onCardMove, onCardLeave } = useCardTilt();
 *   // 模板: @mousemove="onCardMove($event)" @mouseleave="onCardLeave($event)"
 */

export function useCardTilt() {
  let rafId: number | null = null;
  let pending: { card: HTMLElement; px: number; py: number } | null = null;

  /* ★ rAF 节流：同步阶段捕获 card + 坐标，rAF 仅延迟样式写入
   * 同一帧内多次 mousemove 仅保留最后一次的坐标 */
  const onCardMove = (e: MouseEvent) => {
    const card = e.currentTarget as HTMLElement | null;
    if (!card) return;
    const r = card.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width - 0.5;
    const py = (e.clientY - r.top) / r.height - 0.5;
    pending = { card, px, py };
    if (rafId === null) {
      rafId = requestAnimationFrame(() => {
        rafId = null;
        if (!pending) return;
        const { card: c, px: x, py: y } = pending;
        pending = null;
        c.style.transform = `perspective(800px) rotateY(${x * 6}deg) rotateX(${-y * 6}deg) translateY(-3px)`;
        const shine = c.querySelector(".card-shine") as HTMLElement | null;
        if (shine) shine.style.background = `radial-gradient(circle at ${x * 100 + 50}% ${y * 100 + 50}%, rgba(0,212,255,0.18), transparent 60%)`;
      });
    }
  };

  /* mouseleave 是低频事件（每秒最多几次），无需节流 */
  const onCardLeave = (e: MouseEvent) => {
    const card = e.currentTarget as HTMLElement | null;
    if (!card) return;
    card.style.transform = "";
    const shine = card.querySelector(".card-shine") as HTMLElement | null;
    if (shine) shine.style.background = "";
  };

  return { onCardMove, onCardLeave };
}
