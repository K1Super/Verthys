<!--
  App.vue — 根组件
  暗调沉浸赛博风界面｜视觉+交互整体设计
  流程：IntroView（动态引导页，点击进入）→ MainView（主界面）
  全局样式已拆分至 styles/ 目录，main.ts 统一引入
-->
<template>
  <!-- ★ 全局空闲状态机根节点：idle-{level} 驱动 CSS 动画治理 / 毛玻璃降载；
       glass-calm（deep-idle）移除 backdrop-filter；reduce-motion 无障碍静止 -->
  <div
    class="app-root"
    :class="[
      `idle-${idleLevel}`,
      { 'glass-calm': idleLevel === 'deep-idle', 'reduce-motion': prefersReducedMotion },
    ]"
  >
    <ParticleBackground :phase="phase" />
    <div class="app-shell">
      <!-- 引导页层（上层 — 淡出离场） -->
      <div class="intro-layer">
        <transition name="page-glitch">
          <UnlockView v-if="!entered" key="intro" @enter="onEnter" />
        </transition>
      </div>

      <!-- ★ 主界面层（双缓冲预挂载 — 下层，交接帧零成本浮现）：
           PREWARM_MOUNT（1100ms）挂载进 prewarm 冻结层（隐藏 + 动画
           暂停 + 免交互）；PAGE_HANDOFF（3100ms）解除冻结 → materialize
           过渡启动 + 全部子入场动画从 0 同步播放 -->
      <div class="main-layer" :class="{ prewarm: !entered }">
        <MainView v-if="mainPrewarmed" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { defineAsyncComponent, ref, computed, onMounted, onBeforeUnmount } from "vue";
import ParticleBackground from "./components/ParticleBackground.vue";
import UnlockView from "./components/UnlockView.vue";
// 主界面懒加载：MainView 静态导入会拉入 keyManager.ts → verthys.ts 整个业务层，
// 改为 defineAsyncComponent 后，业务层代码移至独立 chunk，主包体积大幅下降。
const MainView = defineAsyncComponent(() => import("./components/MainView.vue"));
import { useAppTransition } from "./composables/useAppTransition";
import { useSecurityGuard } from "./composables/useSecurityGuard";
import { useGlobalIdleScheduler } from "./composables/useGlobalIdleScheduler";
import { frameBudgetMonitor } from "./core/frame-budget";

/* 页面流转 + 星河阶段编排（v3 双缓冲预挂载：预挂载冻结层 → 交接零成本
 * 切换 → materialize 与渡越消散同步收束；旧撕裂过渡层无残留） */
const { entered, mainPrewarmed, phase, onEnter } = useAppTransition();

/* 全局前端安全拦截（dev 环境自动关闭） */
useSecurityGuard();

/* ===== ★ 全局空闲状态机（唯一权威源，根节点类绑定） ===== */
const { level } = useGlobalIdleScheduler();
const idleLevel = computed(() => level.value);

/* prefers-reduced-motion 响应式跟踪（无障碍：动画静止 + 引擎降档） */
const prefersReducedMotion = ref(
  typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches,
);
let onMotionChange: ((e: MediaQueryListEvent) => void) | null = null;
onMounted(() => {
  const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
  onMotionChange = (e: MediaQueryListEvent) => { prefersReducedMotion.value = e.matches; };
  mq.addEventListener("change", onMotionChange);

  /* ★ MainView chunk 空闲预取（双缓冲预挂载前置条件）：
   * MainView 为懒加载 chunk，PREWARM_MOUNT（1100ms）预挂载时才触发
   * "加载+解析"，若未就绪则挂载延后（交接前 2s 余量兜底）。
   * 引导页展示期间的空闲时段后台完成加载与解析，预挂载时刻
   * defineAsyncComponent 命中模块缓存瞬时就绪（仅剩挂载）。 */
  const prefetchMainView = () => { void import("./components/MainView.vue"); };
  if (typeof window.requestIdleCallback === "function") {
    window.requestIdleCallback(prefetchMainView, { timeout: 3000 });
  } else {
    window.setTimeout(prefetchMainView, 300);
  }

  /* ★ 帧预算监控启动（根组件生命周期驱动启停）：
   * rAF 帧间隔采样 → P95 评估 → 迟滞降级/自愈（粒子密度 + CSS 治理类）；
   * 采样守卫（仅 active 档 + 暖机窗口 + 巨帧丢弃）位于 core/frame-budget.ts */
  frameBudgetMonitor.start();
});
onBeforeUnmount(() => {
  frameBudgetMonitor.stop();
  if (onMotionChange) {
    window.matchMedia("(prefers-reduced-motion: reduce)").removeEventListener("change", onMotionChange);
    onMotionChange = null;
  }
});
</script>

<style>
/* ===== App.vue 专属样式 =====
 * 仅保留：应用外壳、双缓冲页面层、page-glitch 离场
 * 全局通用类、设计令牌、keyframes 已拆分至 styles/ 目录
 */

/* ★ 空闲状态机根容器：全尺寸包裹，不改变既有布局层级 */
.app-root {
  position: relative;
  width: 100%;
  height: 100%;
}

.app-shell {
  position: relative;
  z-index: 1;
  width: 100%;
  height: 100%;
}

/* ===== 双缓冲页面层（v3 — 「突然跳转」根治架构） =====
 * 两层绝对叠放：intro-layer（上）淡出 / main-layer（下）浮现。
 * 旧 v-if 同帧「卸载+挂载」= 交接帧主线程停帧 → 星系跳越（已根除）。 */
.intro-layer {
  position: absolute;
  inset: 0;
}
.main-layer {
  position: absolute;
  inset: 0;
}

/* ===== MainView materialize（自星系消散的辉光深处浮现成型） =====
 * prewarm 态 = 静态 from 样式（非动画）；解除 prewarm（entered=true）
 * 触发 transition 插值回基线 — 过渡结束 filter/transform 归 none：
 * 零 render surface 残留、MainView 树不进 3D 渲染上下文（文字
 * ClearType 渲染路径恒定 — 与表单模糊根治同一纪律）。
 * 时长 --dur-page-enter(1.9s) = 渡越消散段等长（3100→5000ms）：
 * 引擎包络归零时刻「星系落定 = 界面清晰」同步收束。
 * ★ GPU 成本约束：交接窗口全屏 blur 仅此一层（UnlockView 离场
 * 已简化为纯 opacity — 双全屏 blur 叠加根除）。 */
.main-layer {
  transition: opacity var(--dur-page-enter) var(--ease),
              filter var(--dur-page-enter) var(--ease),
              transform var(--dur-page-enter) var(--ease);
}
.main-layer.prewarm {
  visibility: hidden;
  pointer-events: none;
  opacity: 0;
  filter: blur(14px) brightness(1.55);
  transform: scale(1.045);
}

/* ★ prewarm 动画冻结：MainView 子树全部 CSS 动画（入场编排/呼吸/
 * 微跳）自挂载起 paused（时钟冻结于 t=0，含 delay 期）——预挂载期
 * 不偷跑；解除 prewarm 同帧解冻，与外层 materialize 从 0 同步启动
 * （「整体虚化成型 + 内部元素错峰编排」双层同步的层次感）。
 * transition 不受 animation-play-state 影响 — prewarm 态为静态
 * 样式，无过渡触发。 */
.main-layer.prewarm,
.main-layer.prewarm * {
  animation-play-state: paused !important;
}

/* 无障碍：减少动态 — materialize 静止（解除冻结直接跳终态） */
.reduce-motion .main-layer {
  transition: none;
}

/* ===== UnlockView 离场（page-glitch leave） =====
 * 交接时刻（3100ms）UnlockView 内容早已弹射清空（逐字弹射/谱线
 * 塌缩/丝线收回于 ~1000ms 完成，全子树 opacity=0）——离场仅需
 * 容器残余淡出。旧实现的 blur(8px)+hue-rotate+scale 在交接窗口
 * 与 materialize 的 blur(14px) 形成双全屏重采样叠加（渡越帧节奏
 * 被挤占）→ 简化为纯 opacity（视觉等效：无可视内容可模糊）。 */
.page-glitch-leave-active {
  transition: opacity var(--dur-page-leave) var(--ease);
  position: absolute;
  inset: 0;
}
.page-glitch-leave-to {
  opacity: 0;
}
</style>
