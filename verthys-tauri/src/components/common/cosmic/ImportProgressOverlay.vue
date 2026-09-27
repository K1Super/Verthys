<!--
  ImportProgressOverlay.vue — 模块导入进度悬浮覆盖层（全局复用）

  用途：模块（拾光 / 清藏）执行导入类阻塞任务时的统一进度呈现。
  语义：绝对定位悬浮于模块内容区中央，不挤占下方列表/网格布局，
       避免"顶部进度条挤压内容"的突兀观感；导入期间遮挡底层交互。

  复用基准：内部复用 QuantumProgressFlow（量子能量导流通道），
       进度/文案/耗时全部来自调用方状态，本层零业务逻辑。

  Props:
    - visible:  boolean  是否显示（false 时无 DOM）
    - percent?: number   进度百分比（0-100，透传 QuantumProgressFlow）
    - message?: string   阶段文案（透传 QuantumProgressFlow，单一数据源）
    - elapsed?: number   已用时间毫秒（showMeta=true 时显示）
    - detail?:  string   附加明细行（如清藏 "12 / 48 块 · 36%"）
    - showMeta?: boolean 是否显示百分比/耗时（默认 false，明细由 detail 承担）
    - compact?: boolean  紧凑通道（默认 true，居中悬浮更轻量）

  Emits: 无
-->
<template>
  <div v-if="visible" class="import-overlay" role="status" aria-live="polite">
    <div class="import-overlay-card">
      <QuantumProgressFlow
        :loading="true"
        :percent="percent"
        :message="message"
        :elapsed="elapsed"
        :show-meta="showMeta"
        :show-loader="false"
        :compact="compact"
      />
      <div v-if="detail" class="import-overlay-detail">{{ detail }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * ImportProgressOverlay — 导入进度悬浮覆盖层（全局复用组件）
 *
 * 职责：仅为 QuantumProgressFlow 提供居中悬浮容器与遮罩，
 * 纯展示、单向数据流、零业务逻辑；动画仅走 opacity/transform。
 */
import QuantumProgressFlow from './QuantumProgressFlow.vue';

interface Props {
  /** 是否显示（false 时无 DOM） */
  visible: boolean;
  /** 进度百分比（0-100） */
  percent?: number;
  /** 阶段文案（单一数据源，来自导入层状态） */
  message?: string;
  /** 已用时间（毫秒，仅 showMeta=true 时显示） */
  elapsed?: number;
  /** 附加明细行（替代或补充元信息） */
  detail?: string;
  /** 是否显示百分比/耗时元信息 */
  showMeta?: boolean;
  /** 紧凑通道模式 */
  compact?: boolean;
}

withDefaults(defineProps<Props>(), {
  percent: 0,
  message: '',
  elapsed: 0,
  detail: '',
  showMeta: false,
  compact: true,
});
</script>

<style scoped>
/* 悬浮覆盖层：绝对定位铺满宿主（宿主需 position: relative），
   中央卡片 + 半透明遮罩；动画仅 opacity/transform（合成器友好） */
.import-overlay {
  position: absolute;
  inset: 0;
  z-index: 40;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(3, 8, 16, 0.42);
}

.import-overlay-card {
  width: min(420px, 86%);
  animation: overlay-enter 0.35s var(--ease, ease-out) both;
}

.import-overlay-detail {
  margin-top: 2px;
  text-align: center;
  font-size: 12px;
  color: var(--text-muted, rgba(255, 255, 255, 0.5));
  font-family: var(--font, inherit);
}

@keyframes overlay-enter {
  from {
    opacity: 0;
    transform: translateY(8px) scale(0.98);
  }
  to {
    opacity: 1;
    transform: none;
  }
}
</style>