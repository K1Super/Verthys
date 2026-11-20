<!--
  ImportProgressOverlay.vue — 模块导入进度悬浮覆盖层（全局复用）

  用途：模块执行导入类阻塞任务时的统一进度呈现。
  语义：绝对定位悬浮于模块内容区中央，不挤占下方列表/网格布局；
       导入期间遮挡底层交互。

  复用基准：内部复用 QuantumProgressFlow（量子能量导流通道），
       进度/文案/耗时全部来自调用方状态，本层零业务逻辑。

  Props:
    - visible:  boolean  是否显示（false 时无 DOM）
    - percent?: number   进度百分比（0-100，透传 QuantumProgressFlow）
    - message?: string   阶段文案（无结构化状态且无插槽时使用）
    - statusLabel?: string  结构化状态标签（提供时渲染统一进度状态行）
    - statusCurrent?: number 结构化当前序号
    - statusTotal?: number   结构化总数（0 时仅显示标签）
    - message 插槽        结构化状态内容（可选；优先级高于 statusLabel）
    - elapsed?: number   已用时间毫秒（showMeta=true 时显示）
    - showMeta?: boolean 是否显示百分比/耗时（默认 false）
    - compact?: boolean  紧凑通道（默认 true，居中悬浮更轻量）
    - cancelable?: boolean 是否显示"取消"操作（默认 false）
    - cancelLabel?: string 取消按钮文案

  Emits:
    - cancel: 用户点击取消（调用方负责把取消意图传递给任务并收敛状态）
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
      >
        <!-- 结构化状态：插槽优先；否则按标签/计数渲染统一状态行，
             进度条与通道布局保持不变 -->
        <template v-if="$slots.message || statusLabel" #message>
          <slot name="message">
            <ProgressStatusLine
              :label="statusLabel || ''"
              :current="statusCurrent"
              :total="statusTotal"
            />
          </slot>
        </template>
      </QuantumProgressFlow>
      <button
        v-if="cancelable"
        type="button"
        class="import-overlay-cancel btn btn-neutral btn-compact"
        @click="emit('cancel')"
      >
        {{ cancelLabel }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * ImportProgressOverlay — 导入进度悬浮覆盖层（全局复用组件）
 *
 * 职责：仅为 QuantumProgressFlow 提供居中悬浮容器与遮罩，
 * 纯展示、单向数据流、零业务逻辑；动画仅走 opacity/transform。
 * 取消操作只向调用方发出意图，任务收敛与状态复位由调用方负责。
 */
import QuantumProgressFlow from './QuantumProgressFlow.vue';
import ProgressStatusLine from './ProgressStatusLine.vue';

interface Props {
  /** 是否显示（false 时无 DOM） */
  visible: boolean;
  /** 进度百分比（0-100） */
  percent?: number;
  /** 阶段文案（无结构化状态且无插槽时使用） */
  message?: string;
  /** 结构化状态标签（提供时渲染统一进度状态行） */
  statusLabel?: string;
  /** 结构化当前序号 */
  statusCurrent?: number;
  /** 结构化总数（0 时仅显示标签） */
  statusTotal?: number;
  /** 已用时间（毫秒，仅 showMeta=true 时显示） */
  elapsed?: number;
  /** 是否显示百分比/耗时元信息 */
  showMeta?: boolean;
  /** 紧凑通道模式 */
  compact?: boolean;
  /** 是否显示取消操作 */
  cancelable?: boolean;
  /** 取消按钮文案 */
  cancelLabel?: string;
}

withDefaults(defineProps<Props>(), {
  percent: 0,
  message: '',
  statusLabel: '',
  statusCurrent: 0,
  statusTotal: 0,
  elapsed: 0,
  showMeta: false,
  compact: true,
  cancelable: false,
  cancelLabel: '取消',
});

const emit = defineEmits<{ cancel: [] }>();
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

/* 仅负责在进度卡内水平居中；键面、三态与禁用全部来自星野键族 */
.import-overlay-cancel {
  display: block;
  width: fit-content;
  margin: 12px auto 0;
}

/* 入场只走 2D 平移与不透明度：覆盖层内含文字与矢量控件，
 * scale 会让内容纹理按非 1 比例缩放、结束帧再重栅格化 —
 * 出现中即"模糊 → 清晰"跳变，故不设缩放分量 */
@keyframes overlay-enter {
  from {
    opacity: 0;
    transform: translateY(8px);
  }
  to {
    opacity: 1;
    transform: none;
  }
}
</style>