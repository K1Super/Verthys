<!--
  ModuleStage.vue — 模块舞台（路由出口 + 切换过渡）
  从 MainView.vue 抽离，功能 100% 保留
-->
<template>
  <main class="stage">
    <transition name="module-switch">
      <HomeView v-if="!currentModule" key="home" />
      <AccountVerthys v-else-if="currentModule === 'accounts'" key="accounts" />
      <PasswordTools v-else-if="currentModule === 'tools'" key="tools" />
      <PhotoAlbum v-else-if="currentModule === 'photos'" key="photos" />
      <FileVerthys v-else-if="currentModule === 'verthys'" key="verthys" />
      <SecurityCenter v-else-if="currentModule === 'security'" key="security" @back="$emit('back')" @panel-active="(v: boolean) => $emit('panel-active', v)" />
    </transition>
  </main>
</template>

<script setup lang="ts">
import { defineAsyncComponent, onMounted, provide, toRef } from "vue";
import HomeView from "./HomeView.vue";
import { MODULE_DIALOG_GUARD_KEY } from "../../composables/useModuleDialogGuard";
import { TRANSITION } from "../../app/constants";

/* 页面级组件懒加载：每个模块独立分包，按需加载 */
const AccountVerthys = defineAsyncComponent(() => import("../modules/AccountVerthys.vue"));
const PasswordTools = defineAsyncComponent(() => import("../modules/PasswordTools.vue"));
const PhotoAlbum = defineAsyncComponent(() => import("../modules/PhotoAlbum.vue"));
const FileVerthys = defineAsyncComponent(() => import("../modules/FileVerthys.vue"));
const SecurityCenter = defineAsyncComponent(() => import("../modules/SecurityCenter.vue"));

const props = defineProps<{
  currentModule: string;
}>();

defineEmits<{
  (e: "back"): void;
  (e: "panel-active", val: boolean): void;
}>();

/* 修复「页面覆盖」：provide currentModule 响应式引用
 *   各模块通过 useModuleDialogGuard inject 并 watch，
 *   切换模块时同步关闭旧模块的所有 Teleport 弹窗，杜绝残留覆盖 */
provide(MODULE_DIALOG_GUARD_KEY, toRef(props, "currentModule"));

/* 首次点击模块延迟根治：挂载后空闲期预热全部分包
 *
 * 根因：6 个模块均为懒加载，首次点击某模块时才拉取其完整分包图
 *   （中枢分包最大），加载/解析/执行全部落在点击后的 UI 线程，
 *   期间舞台空白（dev 下还需 Vite 按需编译整个依赖图，更慢）。
 *
 * 根治：应用启动完成（本组件挂载）后，在浏览器空闲期逐个静默
 *   预取全部分包。预热 import() 与加载器使用完全相同的模块说明符
 *   → 命中同一 chunk 与 ESM 模块缓存：用户首次点击时模块已在
 *   缓存中，加载器在微任务级同步解析，零网络、零编译、零解析等待。
 *
 * 策略：串行预热（每个分包独占一个空闲窗口），绝不与首帧渲染/用户
 *   交互争抢主线程；预热顺序按模块常点击概率（中枢最先）。
 *   容错：任一分包预取失败仅静默忽略（点击时加载器会自行重试）。 */
const moduleWarmups: Array<() => Promise<unknown>> = [
  () => import("../modules/SecurityCenter.vue"),
  () => import("../modules/AccountVerthys.vue"),
  () => import("../modules/PhotoAlbum.vue"),
  () => import("../modules/FileVerthys.vue"),
  () => import("../modules/PasswordTools.vue"),
];
let warmIdx = 0;

function warmNext(): void {
  if (warmIdx >= moduleWarmups.length) return;
  const load = moduleWarmups[warmIdx++];
  load().catch(() => { /* 预热失败静默忽略，点击时加载器自行重试 */ }).finally(() => scheduleWarm());
}

function scheduleWarm(): void {
  if (warmIdx >= moduleWarmups.length) return;
  /* 兜底超时差异化：主循环每帧均有任务运行，空闲回调在持续动画下
   * 基本不触发，实际调度延迟≈兜底值 — 首包（中枢，最高点击概率）
   * 500ms、其余 1200ms，全部在渡越与全屏过渡收束之后（见挂载处
   * 的错峰延迟），短兜底不与入场动画争抢。 */
  const timeout = warmIdx === 0 ? 500 : 1200;
  if (typeof window.requestIdleCallback === "function") {
    window.requestIdleCallback(() => warmNext(), { timeout });
  } else {
    window.setTimeout(warmNext, 250);
  }
}

onMounted(() => {
  /* 首包预热延迟至星系渡越包络归零之后（含 400ms 缓冲），
   * 避免分包加载/解析/执行落入入场动画窗口与满帧过渡争抢主线程。
   * 点击中枢通常在启动数秒之后 — 延迟后首包仍先于点击完成。 */
  window.setTimeout(scheduleWarm, TRANSITION.MAINVIEW_AMBIENT_WAIT + 400);
});
</script>

<style scoped>
/* ===== 模块舞台 ===== */
.stage {
  flex: 1;
  overflow: hidden;
  position: relative;
  border-radius: var(--radius);
  /* 正常模式为 dock 留出空间（dock 宽 56 + 间距 16） */
  margin-left: 72px;
  transition: margin-left 0.55s cubic-bezier(0.34, 1.56, 0.64, 1);
}

/* 模块切换过渡（cross-fade：新旧组件同时存在，无 out-in 死等）
 * 修复：z-index 层级确保新模块覆盖旧模块，杜绝视觉覆盖 */
/* 渡越只走不透明度：模块子树承载全部界面文字，任何位移或缩放都会把字形
 * 提升到合成层（灰度抗锯齿），动画结束回落主层时再子像素化 ——
 * 用户所见即"整个模块忽然模糊、随即变清晰"。方向感改由进出场时长错峰承担
 * （入场慢于离场），不再下发 transform。
 *
 * 包络改用共享「模块步入编排」关键帧（见 styles/animations.css）而非
 * transition：原 transition 走 --ease（cubic-bezier(0.16, 1, 0.3, 1)），
 * 在 0.35s 的前 20% 时长内不透明度即冲到约七成 —— 肉眼读作"整块直接呈现"，
 * 正是入场生硬的成因。关键帧的两段式包络把"沉积"摊开成可辨的渐显，
 * 后段再缓慢沉降到实；模块根与内容条目由此共用同一运动语言。 */
.module-switch-enter-active {
  animation: module-reveal var(--stage-reveal-dur, 0.4s) linear backwards;
  position: relative;
  z-index: 2;
}
.module-switch-leave-active {
  animation: module-reveal-out var(--stage-leave-dur, 0.18s) linear forwards;
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 1;
}
.module-switch-enter-from {
  opacity: 0;
}
.module-switch-leave-to {
  opacity: 0;
}
</style>
