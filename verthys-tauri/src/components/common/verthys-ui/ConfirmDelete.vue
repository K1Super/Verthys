<!--
  ConfirmDelete.vue — 通用删除二次确认弹窗
  主题：黑洞引力场 · 全窗口事件视界 · 相对论喷流 · 多普勒吸积盘
  核心：吸积盘 + 两极喷流 + 数据碎片螺旋 — 层次清晰不杂乱
  用法：
    <ConfirmDelete
      :show="showConfirm"
      :item-name="targetName"
      title=""
      desc=""
      @confirm="doDelete"
      @cancel="showConfirm = false"
    />
-->
<template>
  <Teleport to="body">
    <Transition name="cd-fade">
      <div v-if="show" class="cd-overlay" @click.self="onCancel">
        <!-- 深空星场（单层，淡薄不干扰） -->
        <div class="cd-stars"></div>

        <!-- 相对论性喷流（黑洞两极垂直能量束） -->
        <div class="cd-jet cd-jet-top"></div>
        <div class="cd-jet cd-jet-bottom"></div>

        <!-- 数据碎片双圈螺旋（从窗口边缘吸入到中心弹窗） -->
        <div class="cd-fragments">
          <div
            v-for="(f, i) in fragments"
            :key="i"
            class="cd-frag-orbit"
            :style="f.orbitStyle"
          >
            <span class="cd-fragment" :style="f.fragStyle"></span>
          </div>
        </div>

        <Transition name="cd-pop" appear>
          <div v-if="show" class="cd-dialog">
            <!-- 事件视界光环（环绕弹窗） -->
            <div class="cd-horizon cd-horizon-1"></div>
            <div class="cd-horizon cd-horizon-2"></div>

            <!-- 奇点核心 -->
            <div class="cd-core">
              <div class="cd-core-photon"></div>
            </div>

            <!-- 标题 + 描述 -->
            <div class="cd-title">{{ title }}</div>
            <div class="cd-desc">{{ desc }}</div>

            <!-- 操作按钮 -->
            <div class="cd-actions">
              <button class="cd-btn cd-cancel" @click="onCancel">
                <span class="cd-btn-text">取消</span>
              </button>
              <button class="cd-btn cd-confirm" @click="onConfirm">
                <span class="cd-confirm-swirl"></span>
                <span class="cd-confirm-glow"></span>
                <span class="cd-btn-text">确认删除</span>
              </button>
            </div>
          </div>
        </Transition>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
interface Props {
  show: boolean;
  itemName?: string;
  title?: string;
  desc?: string;
}

withDefaults(defineProps<Props>(), {
  itemName: "",
  title: "确认删除",
  desc: "此操作不可撤销，删除后数据将永久丢失",
});

const emit = defineEmits<{
  confirm: [];
  cancel: [];
}>();

const onCancel = () => emit("cancel");
const onConfirm = () => emit("confirm");

/* ===== 数据碎片粒子配置：20 条双圈螺旋，多普勒色温 ===== */
const FRAG_COLORS = [
  "rgba(255, 255, 255, 1)",
  "rgba(165, 243, 252, 0.95)",
  "rgba(0, 212, 255, 0.95)",
  "rgba(139, 92, 246, 0.85)",
  "rgba(196, 181, 253, 0.8)",
];

const fragments = Array.from({ length: 20 }, (_, i) => {
  const orbitDur = 9 + (i % 4);
  const angle = (i / 20) * 720;
  const orbitDelay = -(angle / 720) * orbitDur;
  const pullDur = 4 + (i % 5) * 0.4;
  const pullDelay = -((i / 20) * pullDur);
  const size = 2 + (i % 3);
  const color = FRAG_COLORS[i % FRAG_COLORS.length];
  return {
    orbitStyle: {
      animationDuration: `${orbitDur}s`,
      animationDelay: `${orbitDelay}s`,
    } as Record<string, string>,
    fragStyle: {
      color,
      background: "currentColor",
      boxShadow: `0 0 4px ${color}, 0 0 10px ${color}`,
      animationDuration: `${pullDur}s`,
      animationDelay: `${pullDelay}s`,
      width: `${size}px`,
      height: `${i % 2 === 0 ? size : Math.round(size * 1.5)}px`,
    } as Record<string, string>,
  };
});
</script>

<style scoped>
/* ===== 遮罩层 — 黑洞引力场（全窗口） ===== */
.cd-overlay {
  position: fixed;
  inset: 0;
  z-index: 3000;
  display: flex;
  align-items: center;
  justify-content: center;
  /* 中心绝对黑，向外渐变 — 简洁的空间纵深 */
  background:
    radial-gradient(circle at 50% 50%,
      #000 0%,
      #000 8%,
      rgba(10, 6, 28, 0.96) 20%,
      rgba(4, 3, 14, 0.92) 50%,
      rgba(0, 0, 0, 0.88) 100%);
  overflow: hidden;
  isolation: isolate;
}

/* ===== 深空星场（单层，淡薄） ===== */
.cd-stars {
  position: absolute;
  inset: 0;
  pointer-events: none;
  background-image:
    radial-gradient(1px 1px at 15% 25%, rgba(255, 255, 255, 0.4), transparent),
    radial-gradient(1px 1px at 35% 65%, rgba(0, 212, 255, 0.3), transparent),
    radial-gradient(1px 1px at 55% 15%, rgba(255, 255, 255, 0.25), transparent),
    radial-gradient(1px 1px at 75% 45%, rgba(139, 92, 246, 0.25), transparent),
    radial-gradient(1px 1px at 85% 85%, rgba(255, 255, 255, 0.3), transparent),
    radial-gradient(1px 1px at 25% 85%, rgba(165, 243, 252, 0.2), transparent);
  background-size: 420px 420px;
  background-repeat: repeat;
  z-index: 1;
  animation: cd-twinkle 6s ease-in-out infinite;
}
@keyframes cd-twinkle {
  0%, 100% { opacity: 0.35; }
  50% { opacity: 0.7; }
}

/* ===== 相对论性喷流（黑洞两极垂直能量束） ===== */
.cd-jet {
  position: absolute;
  left: 50%;
  width: 12px;
  pointer-events: none;
  z-index: 2;
  filter: blur(2px);
  transform: translateX(-50%);
  overflow: hidden;
}
.cd-jet-top {
  top: 0;
  height: 50vh;
  background: linear-gradient(to bottom,
    transparent 0%,
    rgba(139, 92, 246, 0.06) 15%,
    rgba(0, 212, 255, 0.18) 40%,
    rgba(165, 243, 252, 0.4) 70%,
    rgba(255, 255, 255, 0.7) 92%,
    rgba(0, 212, 255, 0.85) 100%);
  box-shadow:
    0 0 20px rgba(0, 212, 255, 0.3),
    0 0 50px rgba(139, 92, 246, 0.15);
}
.cd-jet-bottom {
  bottom: 0;
  height: 50vh;
  background: linear-gradient(to top,
    transparent 0%,
    rgba(139, 92, 246, 0.06) 15%,
    rgba(0, 212, 255, 0.18) 40%,
    rgba(165, 243, 252, 0.4) 70%,
    rgba(255, 255, 255, 0.7) 92%,
    rgba(0, 212, 255, 0.85) 100%);
  box-shadow:
    0 0 20px rgba(0, 212, 255, 0.3),
    0 0 50px rgba(139, 92, 246, 0.15);
}
/* 喷流内粒子流 */
.cd-jet::before {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(to bottom,
    transparent 0%,
    rgba(255, 255, 255, 0.9) 50%,
    transparent 100%);
  background-size: 100% 18%;
  filter: blur(0.5px);
}
.cd-jet-top::before {
  animation: cd-jet-flow-down 2s linear infinite;
}
.cd-jet-bottom::before {
  animation: cd-jet-flow-up 2s linear infinite;
}
@keyframes cd-jet-flow-down {
  from { transform: translateY(-100%); }
  to { transform: translateY(550%); }
}
@keyframes cd-jet-flow-up {
  from { transform: translateY(550%); }
  to { transform: translateY(-100%); }
}

/* ===== 数据碎片双圈螺旋（从窗口边缘吸入到中心弹窗） ===== */
.cd-fragments {
  position: absolute;
  top: 50%;
  left: 50%;
  width: 0;
  height: 0;
  z-index: 4;
  pointer-events: none;
}
.cd-frag-orbit {
  position: absolute;
  top: 0;
  left: 0;
  width: 0;
  height: 0;
  animation: cd-orbit-spin 10s linear infinite;
}
.cd-fragment {
  position: absolute;
  top: -1px;
  left: -1px;
  border-radius: 1px;
  animation: cd-frag-pull 4.5s ease-in infinite;
  will-change: transform, opacity;
}
.cd-fragment::after {
  content: "";
  position: absolute;
  top: 50%;
  right: 100%;
  width: 16px;
  height: 1px;
  background: linear-gradient(to left, currentColor, transparent);
  transform: translateY(-50%);
  opacity: 0.6;
}
@keyframes cd-orbit-spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(720deg); }
}
@keyframes cd-frag-pull {
  0% {
    transform: translateX(min(45vmin, 380px)) scale(1.2);
    opacity: 0;
  }
  8% { opacity: 1; }
  65% {
    transform: translateX(90px) scale(0.85);
    opacity: 0.85;
  }
  100% {
    transform: translateX(48px) scale(0.1);
    opacity: 0;
  }
}

/* ===== 弹窗容器 — 奇点信息载体 ===== */
.cd-dialog {
  position: relative;
  width: 320px;
  max-width: 90vw;
  padding: 28px 24px 20px;
  border-radius: 16px;
  overflow: hidden;
  isolation: isolate;
  background:
    radial-gradient(circle at 50% 30%, rgba(0, 0, 0, 0.65) 0%, rgba(8, 5, 18, 0.92) 50%, rgba(4, 3, 12, 0.96) 100%);
  box-shadow:
    0 24px 60px rgba(0, 0, 0, 0.8),
    inset 0 1px 0 rgba(255, 255, 255, 0.04),
    inset 0 0 30px rgba(0, 0, 0, 0.6);
  z-index: 10;
}

/* ===== 事件视界光环（环绕弹窗） ===== */
.cd-horizon {
  position: absolute;
  top: 50%;
  left: 50%;
  border-radius: 50%;
  pointer-events: none;
  z-index: 0;
}
.cd-horizon-1 {
  width: 300px;
  height: 300px;
  transform: translate(-50%, -50%);
  border: 1px solid rgba(0, 212, 255, 0.22);
  box-shadow:
    0 0 30px rgba(0, 212, 255, 0.12),
    inset 0 0 20px rgba(0, 212, 255, 0.06);
  animation: cd-horizon-pulse 4s ease-in-out infinite;
}
.cd-horizon-2 {
  width: 360px;
  height: 360px;
  transform: translate(-50%, -50%);
  border: 0.5px solid rgba(139, 92, 246, 0.18);
  animation: cd-horizon-pulse 4s ease-in-out infinite 2s;
}
@keyframes cd-horizon-pulse {
  0%, 100% { opacity: 0.5; transform: translate(-50%, -50%) scale(1); }
  50% { opacity: 0.9; transform: translate(-50%, -50%) scale(1.04); }
}

/* ===== 奇点核心（弹窗顶部） ===== */
.cd-core {
  position: relative;
  width: 56px;
  height: 56px;
  margin: 0 auto 16px;
  border-radius: 50%;
  background:
    radial-gradient(circle at 38% 35%, #0a0a16 0%, #000 55%, #000 100%);
  box-shadow:
    0 0 24px rgba(0, 212, 255, 0.32),
    0 0 48px rgba(139, 92, 246, 0.16),
    inset 0 0 18px rgba(0, 0, 0, 1),
    inset 3px 3px 10px rgba(0, 212, 255, 0.08);
  z-index: 1;
  animation: cd-core-pulse 4s ease-in-out infinite;
}
@keyframes cd-core-pulse {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(0.92); }
}
.cd-core-photon {
  position: absolute;
  inset: -4px;
  border-radius: 50%;
  border: 0.5px solid rgba(0, 212, 255, 0.6);
  box-shadow:
    0 0 12px rgba(0, 212, 255, 0.4),
    inset 0 0 6px rgba(0, 212, 255, 0.25);
  animation: cd-photon-flicker 2.5s ease-in-out infinite;
}
@keyframes cd-photon-flicker {
  0%, 100% { opacity: 0.7; }
  30% { opacity: 1; }
  60% { opacity: 0.5; }
}

/* ===== 标题 + 描述 ===== */
.cd-title {
  position: relative;
  z-index: 2;
  text-align: center;
  font-size: 15px;
  font-weight: 500;
  color: var(--text-primary, #e8eaf6);
  letter-spacing: 3px;
  margin-bottom: 6px;
}
.cd-desc {
  position: relative;
  z-index: 2;
  text-align: center;
  font-size: 11px;
  color: var(--text-muted, #8b8fa3);
  line-height: 1.6;
  margin-bottom: 20px;
  letter-spacing: 0.5px;
}

/* ===== 操作按钮 ===== */
.cd-actions {
  position: relative;
  z-index: 2;
  display: flex;
  gap: 10px;
  padding-top: 14px;
  border-top: 1px solid rgba(255, 255, 255, 0.05);
}
.cd-btn {
  flex: 1;
  padding: 10px 16px;
  border-radius: 8px;
  font-size: 12px;
  font-family: var(--font);
  letter-spacing: 1.5px;
  cursor: pointer;
  transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  overflow: hidden;
  position: relative;
  border: 1px solid transparent;
}
.cd-btn-text {
  position: relative;
  z-index: 2;
}

.cd-cancel {
  background: rgba(255, 255, 255, 0.02);
  border-color: rgba(255, 255, 255, 0.08);
  color: var(--text-secondary, #a0a4b8);
}
.cd-cancel:hover {
  color: var(--text-primary, #e8eaf6);
  background: rgba(255, 255, 255, 0.05);
  border-color: rgba(255, 255, 255, 0.15);
}

.cd-confirm {
  background: linear-gradient(135deg, rgba(10, 10, 28, 0.9), rgba(6, 6, 18, 0.95));
  border-color: rgba(0, 212, 255, 0.3);
  color: rgba(165, 243, 252, 0.9);
}
.cd-confirm:hover {
  color: #fff;
  border-color: rgba(0, 212, 255, 0.6);
  box-shadow:
    0 0 20px rgba(0, 212, 255, 0.3),
    0 0 40px rgba(139, 92, 246, 0.12),
    inset 0 0 14px rgba(0, 212, 255, 0.08);
}
.cd-confirm:active {
  transform: scale(0.97);
}
.cd-confirm-swirl {
  position: absolute;
  inset: -50%;
  z-index: 0;
  background: conic-gradient(
    transparent 0deg,
    rgba(0, 212, 255, 0.4) 50deg,
    rgba(139, 92, 246, 0.55) 120deg,
    transparent 180deg,
    transparent 360deg);
  animation: cd-swirl-rotate 4s linear infinite;
  opacity: 0;
  transition: opacity 0.2s cubic-bezier(0.16, 1, 0.3, 1);
}
.cd-confirm:hover .cd-confirm-swirl {
  opacity: 1;
}
@keyframes cd-swirl-rotate {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
.cd-confirm-glow {
  position: absolute;
  inset: 0;
  z-index: 1;
  background: linear-gradient(135deg,
    rgba(0, 212, 255, 0.1),
    rgba(139, 92, 246, 0.08));
  opacity: 0;
  transition: opacity 0.2s cubic-bezier(0.16, 1, 0.3, 1);
}
.cd-confirm:hover .cd-confirm-glow {
  opacity: 1;
}

/* ===== 过渡动画 ===== */
.cd-fade-enter-active,
.cd-fade-leave-active {
  transition: opacity 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}
.cd-fade-enter-from,
.cd-fade-leave-to {
  opacity: 0;
}
.cd-pop-enter-active {
  transition: all 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.cd-pop-leave-active {
  transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}
.cd-pop-enter-from {
  opacity: 0;
  transform: scale(0.7);
}
.cd-pop-leave-to {
  opacity: 0;
  transform: scale(0.85);
}
</style>
