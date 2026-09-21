<!--
  DockNav.vue — 浮动宇宙 Dock（下坠光瀑动态背景）
  从 MainView.vue 抽离，功能 100% 保留
-->
<template>
  <nav
    class="dock"
    :class="{ collapsed: collapsed }"
  >
    <div class="dock-fx">
      <div class="dock-border"></div>
      <div class="dock-cascade">
        <span class="dock-beam" v-for="i in 5" :key="`db${i}`" :style="{ '--i': i }"></span>
      </div>
      <div class="dock-stardust">
        <span class="dock-dust" v-for="i in 10" :key="`dd${i}`" :style="{ '--i': i }"></span>
      </div>
      <div class="dock-drip"></div>
      <div class="dock-scan"></div>
      <div class="dock-rail"></div>
    </div>
    <button
      v-for="m in modules"
      :key="m.id"
      class="dock-item"
      :class="{ active: currentModule === m.id }"
      @click="$emit('switch', m.id)"
    >
      <span class="dock-icon" v-html="m.icon"></span>
      <span class="dock-label">{{ m.label }}</span>
    </button>
  </nav>
</template>

<script setup lang="ts">
import { modules } from "../../composables/useModuleNavigation";

defineProps<{
  currentModule: string;
  collapsed: boolean;
}>();

defineEmits<{
  (e: "switch", id: string): void;
}>();
</script>

<style scoped>
/* ===== 浮动宇宙 Dock（下坠光瀑·极致美学动态背景） ===== */
@property --dock-angle {
  syntax: "<angle>";
  initial-value: 0deg;
  inherits: false;
}
.dock {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 16px 8px;
  width: 56px;
  flex-shrink: 0;
  position: absolute;
  left: 16px;
  top: 50%;
  transform: translateY(-50%);
  z-index: 50;
  border-radius: var(--radius);
  isolation: isolate;
  /* 多层宇宙渐变底板（顶部青光汇聚；背景层不得在底边缘残留亮度，
   * 否则元素边界处形成硬切断层线） */
  background:
    linear-gradient(180deg, rgba(0, 212, 255, 0.1) 0%, transparent 18%),
    linear-gradient(180deg, rgba(20, 22, 36, 0.88), rgba(8, 10, 18, 0.94)),
    radial-gradient(ellipse at 50% 0%, rgba(0, 212, 255, 0.14), transparent 55%);
  border: 1px solid transparent;
  background-clip: padding-box;
  box-shadow:
    0 8px 32px rgba(0, 0, 0, 0.5),
    0 0 24px rgba(0, 212, 255, 0.08),
    inset 0 1px 0 rgba(255, 255, 255, 0.06),
    inset 0 -1px 0 rgba(0, 0, 0, 0.3);
  animation: dock-in 0.5s var(--ease) backwards;
  /* 收起/展开过渡：磁吸式弹射 */
  transition:
    opacity 0.4s var(--ease),
    transform 0.55s cubic-bezier(0.34, 1.56, 0.64, 1);
}
@keyframes dock-in {
  from { opacity: 0; transform: translateY(-50%) translateX(-20px); }
  to { opacity: 1; transform: translateY(-50%) translateX(0); }
}

/* 收起态：侧向坍缩 + 磁吸入射 */
.dock.collapsed {
  animation: none;
  opacity: 0;
  transform: translateY(-50%) translateX(-24px) perspective(80px) rotateY(28deg);
  pointer-events: none;
}

/* 特效容器（裁剪溢出，不影响 dock-label） */
.dock-fx {
  position: absolute;
  inset: 0;
  border-radius: inherit;
  overflow: hidden;
  pointer-events: none;
  z-index: 0;
}

/* 旋转锥形渐变描边 — 全息棱镜色环 */
.dock-border {
  position: absolute;
  inset: -1px;
  border-radius: inherit;
  padding: 1px;
  background: conic-gradient(
    from var(--dock-angle),
    rgba(0, 212, 255, 0.55),
    rgba(139, 92, 246, 0.4) 25%,
    rgba(255, 110, 200, 0.3) 50%,
    rgba(0, 255, 200, 0.4) 75%,
    rgba(0, 212, 255, 0.55)
  );
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  animation: dock-rotate 10s linear infinite;
}
@keyframes dock-rotate {
  to { --dock-angle: 360deg; }
}

/* 下坠光瀑 — 多束垂直光带从顶部持续坠落 */
.dock-cascade {
  position: absolute;
  inset: 0;
}
.dock-beam {
  position: absolute;
  top: -40%;
  left: calc(15% + (var(--i) - 1) * 17%);
  width: 2px;
  height: 45%;
  background: linear-gradient(180deg,
    transparent,
    rgba(0, 212, 255, 0.75) 35%,
    rgba(139, 92, 246, 0.5) 75%,
    transparent);
  filter: blur(0.6px);
  border-radius: 2px;
  opacity: 0;
  animation: dock-beam-fall 3.6s cubic-bezier(0.4, 0, 0.7, 1) infinite;
  animation-delay: calc(var(--i) * 0.55s);
}
@keyframes dock-beam-fall {
  0%   { transform: translateY(-60%); opacity: 0; }
  12%  { opacity: 0.95; }
  55%  { opacity: 0.5; }
  /* 亮段在接近底边缘前完全消隐，绝不允许可见亮度接触 dock-fx 底边裁剪 */
  72%  { opacity: 0; }
  100% { transform: translateY(320%); opacity: 0; }
}

/* 下坠星尘 — 微小光点缓缓飘落，色彩交替 */
.dock-stardust {
  position: absolute;
  inset: 0;
}
.dock-dust {
  position: absolute;
  top: -6%;
  left: calc(8% + (var(--i) - 1) * 9%);
  width: 2px;
  height: 2px;
  border-radius: 50%;
  background: var(--dd-color, #aaddff);
  color: var(--dd-color, #aaddff);
  box-shadow: 0 0 4px currentColor;
  opacity: 0;
  animation: dock-dust-fall 6.5s linear infinite;
  animation-delay: calc(var(--i) * 0.6s);
}
.dock-dust:nth-child(3n)     { --dd-color: #ccaaff; }
.dock-dust:nth-child(3n+1)   { --dd-color: #aaddff; }
.dock-dust:nth-child(3n+2)   { --dd-color: #ffccdd; }
@keyframes dock-dust-fall {
  0%   { transform: translateY(0) scale(0.4); opacity: 0; }
  12%  { opacity: 0.95; transform: scale(1); }
  88%  { opacity: 0.55; }
  /* 行程收在 dock 内部：星尘在接近底边缘前消散（100% 时距底边
   * 仍有余量），全程不触及 dock-fx 底边裁剪 */
  100% { transform: translateY(270px) scale(0.3); opacity: 0; }
}

/* 顶部能量滴落 — 光珠凝聚后坠落 */
.dock-drip {
  position: absolute;
  top: 0;
  left: 50%;
  width: 28px;
  height: 28px;
  transform: translateX(-50%);
}
.dock-drip::before {
  content: "";
  position: absolute;
  top: 1px;
  left: 50%;
  width: 18px;
  height: 5px;
  transform: translateX(-50%);
  background: radial-gradient(ellipse at center, rgba(0, 212, 255, 0.85), transparent 70%);
  animation: drip-gather 3.2s ease-in-out infinite;
}
.dock-drip::after {
  content: "";
  position: absolute;
  top: 5px;
  left: 50%;
  width: 3px;
  height: 3px;
  border-radius: 50%;
  background: #00d4ff;
  box-shadow: 0 0 6px #00d4ff, 0 0 12px rgba(0, 212, 255, 0.5);
  transform: translateX(-50%);
  opacity: 0;
  animation: drip-fall 3.2s ease-in infinite;
}
@keyframes drip-gather {
  0%, 100% { opacity: 0.25; width: 18px; }
  35%      { opacity: 1; width: 7px; }
  45%      { opacity: 0; width: 0; }
  46%, 99% { opacity: 0; }
}
@keyframes drip-fall {
  0%, 38%  { transform: translateX(-50%) translateY(0); opacity: 0; }
  42%      { transform: translateX(-50%) translateY(2px); opacity: 1; }
  100%     { transform: translateX(-50%) translateY(160px); opacity: 0; }
}

/* 垂直扫描线 — 自顶向下循环扫描 */
.dock-scan {
  position: absolute;
  left: 0;
  right: 0;
  top: 0;
  height: 48px;
  background: linear-gradient(180deg,
    transparent,
    rgba(0, 212, 255, 0.18) 45%,
    rgba(139, 92, 246, 0.1) 65%,
    transparent);
  opacity: 0;
  animation: dock-scan-move 5.5s ease-in-out infinite;
}
@keyframes dock-scan-move {
  0%   { transform: translateY(-48px); opacity: 0; }
  10%  { opacity: 0.85; }
  30%  { opacity: 0.65; }
  /* 扫描线在接近底边缘前渐隐归零，消除全宽光带被
   * dock-fx 底边硬切的断层 */
  38%  { opacity: 0; }
  100% { transform: translateY(800px); opacity: 0; }
}

/* 能量导轨 — 中线脉冲光流（下坠方向） */
.dock-rail {
  position: absolute;
  left: 50%;
  top: 14px;
  bottom: 48px;
  width: 1px;
  transform: translateX(-50%);
  background: linear-gradient(180deg,
    transparent,
    rgba(0, 212, 255, 0.12) 15%,
    rgba(139, 92, 246, 0.1) 50%,
    rgba(0, 212, 255, 0.08) 85%,
    transparent);
  overflow: hidden;
}
.dock-rail::after {
  content: "";
  position: absolute;
  top: 0;
  left: -1px;
  width: 3px;
  height: 24px;
  background: linear-gradient(180deg, transparent, rgba(0, 212, 255, 0.9), transparent);
  animation: rail-flow 2.8s ease-in infinite;
}
@keyframes rail-flow {
  0%   { transform: translateY(-24px); opacity: 0; }
  20%  { opacity: 1; }
  80%  { opacity: 0.8; }
  /* 行程精确收在导轨高度内：终点时光包底边恰达导轨下缘，
   * 且光包渐变尾端透明 — 亮芯全程不触及 rail 的裁剪边界 */
  100% { transform: translateY(216px); opacity: 0; }
}

.dock-item {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all var(--dur) var(--ease);
  z-index: 2;
}
.dock-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  transition: transform var(--dur) var(--ease);
}
.dock-icon svg {
  width: 100%;
  height: 100%;
}
.dock-item:hover {
  color: var(--text-primary);
  background: rgba(0, 212, 255, 0.06);
  border-color: var(--border-glass);
}
.dock-item:hover .dock-icon {
  transform: scale(1.15);
}
.dock-item:hover .dock-label {
  opacity: 1;
  transform: translateY(-50%) translateX(0);
}
.dock-item:hover .dock-label::before,
.dock-item:hover .dock-label::after {
  transform: scaleX(1);
}
.dock-item.active {
  color: var(--accent);
  background: rgba(0, 212, 255, 0.1);
  border-color: rgba(0, 212, 255, 0.2);
  box-shadow: 0 0 12px rgba(0, 212, 255, 0.15);
}
/* ===== 导航悬浮提示 — 双能量光轨（打破传统气泡框架） ===== */
.dock-label {
  position: absolute;
  left: calc(100% + 14px);
  top: 50%;
  /* 明确字体配置 — 防止继承或过渡导致字体突变 */
  font-family: var(--font);
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 2px;
  color: var(--text-primary);
  white-space: nowrap;
  pointer-events: none;
  z-index: 200;
  /* 初始隐藏态 — 保留 translateY(-50%) 避免垂直位置突变 */
  opacity: 0;
  transform: translateY(-50%) translateX(-8px);
  /* 仅过渡 opacity 和 transform — 严禁 transition: all（会导致字体渲染抖动） */
  transition:
    opacity 0.35s var(--ease),
    transform 0.45s cubic-bezier(0.34, 1.56, 0.64, 1);
  /* 文字发光 — 替代传统背景框 */
  text-shadow:
    0 0 8px rgba(0, 212, 255, 0.55),
    0 0 16px rgba(0, 212, 255, 0.25),
    0 0 24px rgba(139, 92, 246, 0.15);
  padding: 3px 2px;
}
/* 主能量光轨 — 文字下方水平光谱带（青→白→紫） */
.dock-label::before {
  content: "";
  position: absolute;
  left: -6px;
  right: -6px;
  bottom: 0;
  height: 1px;
  background: linear-gradient(90deg,
    transparent 0%,
    rgba(0, 212, 255, 0.35) 15%,
    rgba(165, 243, 252, 0.95) 50%,
    rgba(139, 92, 246, 0.35) 85%,
    transparent 100%);
  box-shadow:
    0 0 6px rgba(0, 212, 255, 0.55),
    0 0 12px rgba(0, 212, 255, 0.22);
  transform: scaleX(0);
  transform-origin: center;
  transition: transform 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.08s;
}
/* 副能量光轨 — 文字上方更细更淡的光谱带（紫→青，反向配色） */
.dock-label::after {
  content: "";
  position: absolute;
  left: -4px;
  right: -4px;
  top: 0;
  height: 1px;
  background: linear-gradient(90deg,
    transparent 0%,
    rgba(139, 92, 246, 0.28) 20%,
    rgba(180, 108, 255, 0.65) 50%,
    rgba(0, 212, 255, 0.28) 80%,
    transparent 100%);
  box-shadow: 0 0 4px rgba(139, 92, 246, 0.35);
  transform: scaleX(0);
  transform-origin: center;
  transition: transform 0.5s cubic-bezier(0.16, 1, 0.3, 1) 0.12s;
}
</style>
