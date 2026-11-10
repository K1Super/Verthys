<!--
  QuantumProgressFlow.vue — 量子能量导流通道进度条

  职责：渲染导流通道 DOM 与节点状态，纯展示组件，单向数据流，零业务逻辑。

  设计约束：
    - 进度来源单一：percent 完全由上游提供（安全中心为感知层输出的按帧
      连续视觉值，其它导入场景为真实进度），组件不做时间平滑
    - 提示词单一数据源：直接显示上游 emit 的 message，前端不维护预设映射
    - 淡雅美学：低饱和度青/紫/粉，不使用浓厚原色
    - 动态构成：粒子流、节点脉动、能量呼吸、扫光
    - 防跳变：固定高度槽位（min-height），加载/隐藏零抖动
-->
<template>
  <div
    v-if="loading"
    class="qf-slot"
    :class="{
      compact,
      'no-text': !displayText,
      'no-loader': !showLoader,
      'qf-complete': safePercent >= 99.9,
      'qf-dimmed': dimmed,
    }"
  >
    <!-- ===== 量子核心加载动画（复用 QuantumCoreLoader） ===== -->
    <QuantumCoreLoader v-if="showLoader" :loading="true" />

    <!-- ===== 量子能量导流通道进度条 ===== -->
    <!-- 导流通道主体 -->
    <div class="qf-channel">
      <!-- 通道两端能量端口 -->
      <div class="qf-port qf-port-in"></div>
      <div class="qf-port qf-port-out"></div>

      <!-- 能量填充（进度推进）
           合成器驱动：只改 transform: scaleX，不动 width —
           width 每帧触发布局与渐变重绘，主线程被解密/IPC 占用时必然掉帧；
           transform 由合成线程补间，主线程繁忙时仍保持连续。 -->
      <div
        class="qf-fill"
        :style="{ transform: `scaleX(${safePercent / 100})` }"
      >
        <!-- 能量流粒子（填充内流动） -->
        <div class="qf-stream"></div>
        <div class="qf-stream qf-stream-2"></div>
      </div>
    </div>

    <!-- 精简提示词（单行短文字，来自后端 emit 的 message） -->
    <div v-if="displayText" class="qf-text">{{ displayText }}</div>

    <!-- 元信息（百分比/耗时，默认隐藏） -->
    <div v-if="showMeta" class="qf-meta">
      <span class="qf-percent">{{ safePercent }}%</span>
      <span class="qf-elapsed">{{ ((elapsed || 0) / 1000).toFixed(1) }}s</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch, type Ref } from 'vue';
import QuantumCoreLoader from './QuantumCoreLoader.vue';

interface Props {
  /** 是否显示（true 时显示导流通道，可选量子核心动画） */
  loading: boolean;
  /** 进度百分比（0-100，上游连续视觉值或真实进度） */
  percent?: number;
  /** 进度来源（感知层 ref）：传入后本组件直接订阅，父视图不再逐帧重渲染 */
  percentSource?: Readonly<Ref<number>>;
  /** 后端 emit 的精简提示词（单一数据源） */
  message?: string;
  /** 已用时间（毫秒，仅 showMeta=true 时显示） */
  elapsed?: number;
  /** 是否显示百分比/耗时（默认 false，解锁/验证不显示） */
  showMeta?: boolean;
  /** 紧凑模式（缩小通道尺寸，用于空间受限场景） */
  compact?: boolean;
  /** 是否显示量子核心加载动画（默认 true，复用 QuantumCoreLoader 组件） */
  showLoader?: boolean;
  /** 失败冻结降级标识（样式标识：整体降低不透明度与饱和度） */
  dimmed?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  percent: 0,
  message: '',
  elapsed: 0,
  showMeta: false,
  compact: false,
  showLoader: true,
  dimmed: false,
});

/* ===== 计算属性 ===== */

/** 当前显示的提示词（直接取上游 emit 的 message — 单一数据源） */
const displayText = computed<string>(() => props.message || '');

/* ===== 30fps 显示采样 =====
   感知层以 60fps 输出视觉值；呈现层按 30fps 采样并交给合成器过渡，
   视觉等价，主线程样式写入减半。 */
const sourceValue = (): number => {
  const p = props.percentSource ? props.percentSource.value : props.percent;
  const n = Number(p) || 0;
  return Number.isFinite(n) ? Math.min(100, Math.max(0, n)) : 0;
};

const displayPercent = ref(sourceValue());
let hasSampled = false;
let lastSampleAt = 0;
let pendingSample: number | null = null;
let sampleTimer: ReturnType<typeof setTimeout> | null = null;

const nowMs = (): number =>
  typeof performance !== 'undefined' ? performance.now() : Date.now();

const applySample = (value: number): void => {
  displayPercent.value = value;
  lastSampleAt = nowMs();
  hasSampled = true;
};

watch(sourceValue, (value) => {
  if (!hasSampled || nowMs() - lastSampleAt >= 33) {
    if (sampleTimer !== null) {
      clearTimeout(sampleTimer);
      sampleTimer = null;
    }
    pendingSample = null;
    applySample(value);
    return;
  }
  pendingSample = value;
  if (sampleTimer === null) {
    sampleTimer = setTimeout(() => {
      sampleTimer = null;
      if (pendingSample !== null) {
        applySample(pendingSample);
        pendingSample = null;
      }
    }, 33);
  }
});

onBeforeUnmount(() => {
  if (sampleTimer !== null) {
    clearTimeout(sampleTimer);
    sampleTimer = null;
  }
});

/** 呈现层显示值（0..100，已在 sourceValue 中钳制，30fps 采样） */
const safePercent = computed<number>(() => displayPercent.value);
</script>

<style scoped>
/* 导流通道样式经 @import 引入。
 * 禁止在此覆盖 min-height：Vite 会将 @import 内容与自定义样式拆到不同
 * CSS chunk，data-v 属性不一致，覆盖值无法命中元素，量子加载动画被压缩。
 * .ql-loader 样式由 QuantumCoreLoader 自行 scoped 引入（本组件不直接渲染）。 */
@import '../../../styles/security/quantum-flow.css';
</style>
