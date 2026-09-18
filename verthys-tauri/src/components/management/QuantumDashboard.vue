<!--
  QuantumDashboard.vue — 量子态势面板（进入中枢首屏）

  ★ 全新架构：Canvas 物理场引擎（useQuantumField）+ 精简交互 DOM 层

  分层结构：
    canvas（qd-field-canvas）  — 物理场渲染：引力尘埃 / 数据碎片 / 能量连线 /
                                 数据包 / 非对称吸积盘（三层视差独立系数）
    qd-layer-mid               — 4 个模块轨道节点 DOM（图标+文字，可交互）
    qd-layer-near              — 中心量子核心 DOM（文字组，可交互）

  交互（全部由引擎弹簧驱动，无 CSS transition 突变）：
    - 节点 hover：弹簧缩放 + 对应连线能量增益 + 视差让位（优先级仲裁）
    - 核心 hover：吸积盘能量应答 + 弹簧缩放
    - 面板视差：三层独立系数 + 噪声漂移（欠阻尼惯性跟手）
    - 鼠标力场：高斯衰减漩涡扰动尘埃/碎片/连线亮度

  Props: globalKeyReady / moduleIds / moduleLabels / moduleStateClass(fn) / moduleStateText(fn)
  Emits: enterSection(section: "globalKey" | "moduleKeys")
-->
<template>
  <div ref="panelRef" class="qd-panel">
    <!-- 物理场画布（尘埃/连线/碎片/吸积盘，三层视差） -->
    <canvas ref="canvasRef" class="qd-field-canvas"></canvas>

    <!-- 模块轨道节点（视差中层，hover 弹簧由引擎驱动） -->
    <div ref="midLayerRef" class="qd-layer qd-layer-mid">
      <div
        v-for="(mid, i) in moduleIds"
        :key="`node-${mid}`"
        :ref="(el) => setNodeRef(el, i)"
        class="qd-module-node"
        :class="moduleStateClass(mid)"
        :style="{ left: `${moduleNodePos[i].x}%`, top: `${moduleNodePos[i].y}%` }"
        @click="$emit('enterSection', 'moduleKeys')"
      >
        <div class="qd-node-orb">
          <div class="qd-node-core">
            <span v-if="mid === 'photo'" class="qd-node-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
            </span>
            <span v-else-if="mid === 'accounts'" class="qd-node-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            </span>
            <span v-else-if="mid === 'certs'" class="qd-node-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>
            </span>
            <span v-else-if="mid === 'fileverthys'" class="qd-node-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-6l-2-2H5a2 2 0 0 0-2 2z"/></svg>
            </span>
          </div>
        </div>
        <div class="qd-node-label">{{ moduleLabels[mid] }}</div>
        <div class="qd-node-state">{{ moduleStateText(mid) }}</div>
      </div>
    </div>

    <!-- 中心量子核心（视差近层，吸积盘在 canvas 中渲染，此处为可交互文字簇） -->
    <div ref="nearLayerRef" class="qd-layer qd-layer-near">
      <div ref="coreRef" class="qd-core-cluster" @click="$emit('enterSection', 'globalKey')">
        <div class="qd-core-text">
          <div class="qd-core-label">全局密钥</div>
          <div class="qd-core-hint">点击管理</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, toRef } from 'vue';
import type { ModuleId } from '../../lib/keyManager';
import { useQuantumField } from '../../composables/security-center/useQuantumField';

/**
 * QuantumDashboard Props
 */
const props = defineProps<{
  /** 全局密钥就绪状态（吸积盘能量与色相应答） */
  globalKeyReady: boolean;
  /** 模块 ID 列表（渲染节点 + 能量连线） */
  moduleIds: ModuleId[];
  /** 模块标签映射（节点文字） */
  moduleLabels: Record<string, string>;
  /** 模块状态指示条样式类（函数） */
  moduleStateClass: (mid: ModuleId) => string;
  /** 模块状态文本（函数） */
  moduleStateText: (mid: ModuleId) => string;
}>();

/**
 * QuantumDashboard Emits
 */
defineEmits<{
  /** 点击节点/核心进入指定区块（父组件切换到 detail 视图并滚动定位） */
  (e: 'enterSection', section: 'globalKey' | 'moduleKeys'): void;
}>();

/* 4 个模块节点位置（百分比，0-100 坐标系）
 * ★ 非对称布局：手工设计的可控不规则偏差（±4.5%），
 *   打破正交对称但保持构图张力（反AI大众化：拒绝完全均匀分布） */
const moduleNodePos = [
  { x: 54.5, y: 13.5 },  // photo — 偏右上
  { x: 86.5, y: 47.5 },  // accounts — 偏上
  { x: 45.5, y: 86.5 },  // certs — 偏左下
  { x: 12.5, y: 53.5 },  // fileverthys — 偏下
];

/* ===== 物理场引擎 DOM refs ===== */
const panelRef = ref<HTMLElement | null>(null);
const canvasRef = ref<HTMLCanvasElement | null>(null);
const midLayerRef = ref<HTMLElement | null>(null);
const nearLayerRef = ref<HTMLElement | null>(null);
const coreRef = ref<HTMLElement | null>(null);
const nodeRefs = ref<HTMLElement[]>([]);
/** 模板 ref 回调收集（v-for 中 ref 数组收集的标准方式） */
const setNodeRef = (el: unknown, idx: number) => {
  if (el) nodeRefs.value[idx] = el as HTMLElement;
};

/** globalKeyReady → 引擎响应式桥接（toRef 保持引用同步，状态变化即时应答） */
const coreReadyRef = toRef(props, 'globalKeyReady');

/* ===== 引擎实例（watch coreReady + onBeforeUnmount 自动清理） ===== */
const field = useQuantumField({
  panel: panelRef,
  canvas: canvasRef,
  midLayer: midLayerRef,
  nearLayer: nearLayerRef,
  coreCluster: coreRef,
  nodes: nodeRefs,
  nodePositions: moduleNodePos,
  coreReady: coreReadyRef,
});

/* DOM 就绪后初始化引擎（绑定事件 + 构建粒子池 + ResizeObserver + 启动 rAF） */
onMounted(() => {
  field.init();
});
</script>
