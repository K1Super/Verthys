<!--
  ModuleStage.vue — 模块舞台（路由出口 + 切换过渡）
  从 MainView.vue 抽离，功能 100% 保留
-->
<template>
  <main class="stage">
    <transition name="module-switch">
      <HomeView v-if="!currentModule" key="home" />
      <AccountVerthys v-else-if="currentModule === 'accounts'" key="accounts" />
      <CertManager v-else-if="currentModule === 'certs'" key="certs" />
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
const CertManager = defineAsyncComponent(() => import("../modules/CertManager.vue"));
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

/* ★ 企业级修复「页面覆盖」：provide currentModule 响应式引用
 *   各模块通过 useModuleDialogGuard inject 并 watch，
 *   切换模块时同步关闭旧模块的所有 Teleport 弹窗，杜绝残留覆盖 */
provide(MODULE_DIALOG_GUARD_KEY, toRef(props, "currentModule"));

/* ★ 企业级根治「首次点击模块导航数秒延迟」：挂载后空闲期预热全部分包
 *
 * 根因：6 个模块均为 defineAsyncComponent 懒加载，首次点击某模块时
 *   才拉取其完整分包图（如 SecurityCenter 93KB JS + 77KB CSS +
 *   crypto-vendor 等共享块），加载/解析/执行全部落在点击后的 UI 线程，
 *   期间舞台空白数秒（dev 下还需 Vite 按需编译整个依赖图，更慢）。
 *
 * 根治：应用启动完成（本组件挂载）后，在浏览器空闲期（requestIdleCallback，
 *   兜底 setTimeout）逐个静默预取全部分包。预热 import() 与
 *   defineAsyncComponent 的加载器使用完全相同的模块说明符 → 命中同一
 *   chunk 与 ESM 模块缓存：用户首次点击时模块已在缓存中，加载器在
 *   微任务级同步解析，零网络、零编译、零解析等待。
 *
 * 策略：串行预热（每个分包独占一个空闲窗口），绝不与首帧渲染/用户
 *   交互争抢主线程；预热顺序按模块常点击概率（中枢最先）。
 *   容错：任一分包预取失败仅静默忽略（点击时加载器会自行重试）。 */
const moduleWarmups: Array<() => Promise<unknown>> = [
  () => import("../modules/SecurityCenter.vue"),
  () => import("../modules/AccountVerthys.vue"),
  () => import("../modules/PhotoAlbum.vue"),
  () => import("../modules/FileVerthys.vue"),
  () => import("../modules/CertManager.vue"),
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
  if (typeof window.requestIdleCallback === "function") {
    window.requestIdleCallback(() => warmNext(), { timeout: 2000 });
  } else {
    window.setTimeout(warmNext, 250);
  }
}

onMounted(() => {
  /* ★ 入场错峰（v3 — 预挂载提前量补偿）：首包预热延迟至星系渡越
   * 包络归零之后（MAINVIEW_AMBIENT_WAIT + 400ms 缓冲 = 自预挂载
   * 起算，含 PREWARM_MOUNT 提前量 — 苏醒锚点仍精确对齐渡越归零）。
   * 旧实现挂载即 rIC 且 timeout 2s 强制触发 —— SecurityCenter 等
   * 分包的加载/解析/执行恰好落在主界面入场动画窗口中段，与渡越
   * 尾部 + materialize 全屏过渡争抢主线程。延迟后首次点击模块仍
   * 远早于预热完成前的任何时点（预热全程 ≤ 数秒，点击通常在
   * 数秒之后）。 */
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

/* 模块切换过渡（cross-fade：新旧组件同时存在，无 out-in 死等） */
/* ★ 企业级修复：z-index 层级确保新模块覆盖旧模块，杜绝视觉覆盖 */
.module-switch-enter-active {
  transition: opacity 0.35s var(--ease), filter 0.35s var(--ease), transform 0.35s var(--ease);
  position: relative;
  z-index: 2;
}
.module-switch-leave-active {
  transition: opacity 0.2s var(--ease), filter 0.2s var(--ease), transform 0.2s var(--ease);
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 1;
}
.module-switch-enter-from {
  opacity: 0;
  filter: blur(10px);
  transform: scale(0.98) translateX(16px);
}
.module-switch-leave-to {
  opacity: 0;
  filter: blur(6px);
  transform: scale(1.01) translateX(-12px);
}
</style>
