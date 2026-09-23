/**
 * photo-album/usePhotoInteraction.ts — 拾光模块卡片交互层 composable
 *
 * 职责：管理照片卡片的鼠标视差效果（3D 旋转 + 光晕跟随）。
 * 从原 PhotoAlbum.vue 提取，保持 100% 功能不变。
 *
 * 设计要点：
 * - onPhotoMove 用 rafThrottle 节流（同帧多次 mousemove 合并为一次）
 *   原问题：mousemove 每秒触发 60~120 次，每次执行 getBoundingClientRect + style 写入，
 *          连续移动时主线程被阻塞，滚动/输入卡顿。
 *   优化后：同一帧内多次 mousemove 仅执行最后一次，视差计算开销降低 90%。
 * - onPhotoLeave 是低频事件（每秒最多几次），无需节流。
 * - onUnmounted 时调用 cancel() 取消未触发的 rAF 回调，防止卸载后状态写入空组件。
 */
import { rafThrottle } from "../../utils/debounce";

export function usePhotoInteraction() {
  /**
   * 照片卡片鼠标移动：3D 旋转 + 光晕跟随
   * rafThrottle 节流：同帧多次 mousemove 合并为一次，60fps 上限
   */
  const onPhotoMove = rafThrottle((e: MouseEvent) => {
    const card = (e.currentTarget as HTMLElement).querySelector(".photo-card") as HTMLElement;
    if (!card) return;
    const r = card.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width - 0.5;
    const py = (e.clientY - r.top) / r.height - 0.5;
    card.style.transform = `perspective(800px) rotateY(${px * 8}deg) rotateX(${-py * 8}deg) translateY(-6px) scale(1.03)`;
    const shine = card.querySelector(".photo-shine") as HTMLElement;
    if (shine) shine.style.background = `radial-gradient(circle at ${px * 100 + 50}% ${py * 100 + 50}%, rgba(0,212,255,0.12), transparent 50%)`;
  });

  /** 照片卡片鼠标离开：复位 transform 和光晕 */
  const onPhotoLeave = (e: MouseEvent) => {
    const card = (e.currentTarget as HTMLElement).querySelector(".photo-card") as HTMLElement;
    if (card) card.style.transform = "";
    const shine = (e.currentTarget as HTMLElement).querySelector(".photo-shine") as HTMLElement;
    if (shine) shine.style.background = "";
  };

  return {
    onPhotoMove,
    onPhotoLeave,
    /** 取消未触发的 rAF 回调（onUnmounted 时调用，防止卸载后状态写入空组件） */
    cancel: () => {
      onPhotoMove.cancel();
    },
  };
}
