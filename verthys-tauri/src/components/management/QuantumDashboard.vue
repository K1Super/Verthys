<!--
  QuantumDashboard.vue — 量子态势面板（进入中枢首屏）

  全新架构：Canvas 物理场引擎（useQuantumField）+ 精简交互 DOM 层

  分层结构：
    canvas（qd-field-canvas）  — 物理场渲染：引力尘埃 / 数据碎片 / 能量连线 /
                                 数据包 / 非对称吸积盘（三层视差独立系数）
    qd-layer-mid               — 3 个模块轨道节点 DOM（仅 48px 图标热区 + 导航栏
                                 同源图标；装饰环饰全部由 Canvas 引擎绘制，
                                 节点无任何文字）
    qd-layer-near              — 中心量子核心 DOM（文字组，可交互）

  交互（全部由引擎弹簧驱动，无 CSS transition 突变）：
    - 节点 hover：弹簧缩放 + 对应连线能量增益 + 视差让位（优先级仲裁）
    - 核心 hover：吸积盘能量应答 + 弹簧缩放
    - 面板视差：三层独立系数 + 噪声漂移（欠阻尼惯性跟手）
    - 鼠标力场：高斯衰减漩涡扰动尘埃/碎片/连线亮度

  Props: globalKeyReady / moduleIds / moduleStateClass(fn)
  Emits: enterSection(section: "globalKey" | "moduleKeys")
-->
<template>
  <div ref="panelRef" class="qd-panel">
    <!-- 物理场画布（尘埃/碎片视差在画布内部完成；连线/吸积盘为零视差组） -->
    <canvas ref="canvasRef" class="qd-field-canvas"></canvas>

    <!-- 模块轨道节点（静态居中定位：三个模块与三条连线同为零视差组） -->
    <div class="qd-layer qd-layer-mid">
      <div
        v-for="(mid, i) in moduleIds"
        :key="`node-${mid}`"
        :ref="(el) => setNodeRef(el, i)"
        class="qd-module-node"
        :class="moduleStateClass(mid)"
        :style="{ left: `${moduleNodePos[i].x}%`, top: `${moduleNodePos[i].y}%` }"
        role="button"
        tabindex="0"
        :aria-label="`${MODULE_LABELS[mid] ?? mid} · 模块密钥`"
        @click="onNodeClick"
        @keydown.enter.prevent="onNodeClick"
        @keydown.space.prevent="onNodeClick"
      >
        <div class="qd-node-orb">
          <!-- 装饰环饰（引力锚点环）由 Canvas 引擎绘制 —— 精密刻度盘语言：
               三段非均匀断裂刻度环 + 断口主刻度 + 细刻度扇 + 镜筒细环 +
               内外双自转能量弧 + 状态扇段（正常混合、无大面积软光）。
               DOM 侧只留可交互的导航栏同源图标（无 DOM 描边 → 无 DOM transform）。 -->
          <span class="qd-node-icon" v-html="MODULE_ICONS[mid]"></span>
        </div>
      </div>
    </div>

    <!-- 中心量子核心（近层为纯布局容器：核心文字静态居中，不参与任何位移；
         吸积盘在 canvas 中渲染，此处为可交互文字簇） -->
    <div class="qd-layer qd-layer-near">
      <div
        ref="coreRef"
        class="qd-core-cluster"
        role="button"
        tabindex="0"
        aria-label="全局密钥管理"
        @click="onCoreClick"
        @keydown.enter.prevent="onCoreClick"
        @keydown.space.prevent="onCoreClick"
      >
        <div class="qd-core-text">
          <div class="qd-core-label">全局密钥</div>
          <div class="qd-core-hint">点击管理</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, toRef } from 'vue';
import { MODULE_LABELS, type ModuleId } from '../../lib/keyManager';
import { useQuantumField } from '../../composables/security-center/useQuantumField';
/* 模块图标（导航栏同一权威源）：节点图标与 Dock 共享同一份 SVG 路径 */
import { MODULE_ICONS } from '../../composables/useModuleNavigation';

/**
 * QuantumDashboard Props
 */
const props = defineProps<{
  /** 全局密钥就绪状态（吸积盘能量与色相应答） */
  globalKeyReady: boolean;
  /** 模块 ID 列表（渲染节点 + 能量连线） */
  moduleIds: ModuleId[];
  /** 模块状态样式类（函数 — 驱动节点状态扇段的弧长与色相） */
  moduleStateClass: (mid: ModuleId) => string;
}>();

/**
 * QuantumDashboard Emits
 */
const emit = defineEmits<{
  /** 点击节点/核心进入指定区块（父组件切换到 detail 视图并滚动定位） */
  (e: 'enterSection', section: 'globalKey' | 'moduleKeys'): void;
}>();

/* 模块节点位置（百分比，0-100 坐标系）
 * 非对称布局：手工设计的可控不规则偏差（±4.5%），
 *   打破正交对称但保持构图张力（反AI大众化：拒绝完全均匀分布） */
const moduleNodePos = [
  { x: 54.5, y: 16.5 },  // photo — 偏右上
  { x: 84.5, y: 50.0 },  // accounts — 偏上
  { x: 24.0, y: 76.0 },  // fileverthys — 偏左下
];

/* ===== 物理场引擎 DOM refs ===== */
const panelRef = ref<HTMLElement | null>(null);
const canvasRef = ref<HTMLCanvasElement | null>(null);
const coreRef = ref<HTMLElement | null>(null);
const nodeRefs = ref<HTMLElement[]>([]);
/** 模板 ref 回调收集（v-for 中 ref 数组收集的标准方式） */
const setNodeRef = (el: unknown, idx: number) => {
  if (el) nodeRefs.value[idx] = el as HTMLElement;
};

/** globalKeyReady → 引擎响应式桥接（toRef 保持引用同步，状态变化即时应答） */
const coreReadyRef = toRef(props, 'globalKeyReady');

/* 模块状态类名（与 DOM 上的 state-* 类同源）→ 引擎侧状态扇段
 * （跨度 / 色相 / 休眠压暗）—— 单一状态源，DOM 与 Canvas 两处不会漂移 */
const nodeStates = computed(() => props.moduleIds.map((mid) => props.moduleStateClass(mid)));

/* ===== 引擎实例（watch coreReady + onBeforeUnmount 自动清理） ===== */
const field = useQuantumField({
  panel: panelRef,
  canvas: canvasRef,
  coreCluster: coreRef,
  nodes: nodeRefs,
  nodePositions: moduleNodePos,
  nodeStates,
  coreReady: coreReadyRef,
  /* 视图切换由光水仪式完成事件驱动（传播 + 落定渲染完成后的下一帧）——
     与引导区「传播完成事件驱动」同规范，避免固定延时的时序漂移。 */
  onFlowComplete: (section) => emit('enterSection', section),
});

/* ===== 点击入口：先走光水仪式，再由完成事件驱动视图切换 =====
 * 仪式进行中重复点击被状态机幂等拒绝（playFlow 返回 false），
 * 故此处无需额外闸门 —— 与引导区同一语义。 */
const onCoreClick = (): void => {
  field.playFlow('globalKey');
};

const onNodeClick = (): void => {
  field.playFlow('moduleKeys');
};

/* DOM 就绪后初始化引擎（绑定事件 + 构建粒子池 + ResizeObserver + 启动 rAF） */
onMounted(() => {
  field.init();
});
</script>
