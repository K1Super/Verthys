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
import { defineAsyncComponent, defineComponent, h, onMounted, provide, toRef } from "vue";
import HomeView from "./HomeView.vue";
import { MODULE_DIALOG_GUARD_KEY } from "../../composables/useModuleDialogGuard";
import { TRANSITION } from "../../app/constants";

/* ★ 模块加载兜底提示（预热未完成时点击模块可达）：
 * 「深空对接」— 双层反向旋转叠加出偏心轨迹光点（非标准圆环旋转），
 * 纯 transform 动画无 filter；delay 250ms — chunk 就绪快时不闪现 */
const ModuleLoading = defineComponent({
  name: "ModuleLoading",
  render() {
    return h("div", { class: "module-loading" }, [
      h("span", { class: "ml-orbit-a" }, [
        h("span", { class: "ml-orbit-b" }, [
          h("i", { class: "ml-pip" }),
        ]),
      ]),
      h("p", { class: "ml-text" }, "正在对接"),
    ]);
  },
});

/** 异步模块工厂：统一挂载兜底提示 */
function asyncModule(loader: () => Promise<unknown>) {
  return defineAsyncComponent({
    loader: loader as never,
    loadingComponent: ModuleLoading,
    delay: 250,
  });
}

/* 页面级组件懒加载：每个模块独立分包，按需加载 */
const AccountVerthys = asyncModule(() => import("../modules/AccountVerthys.vue"));
const CertManager = asyncModule(() => import("../modules/CertManager.vue"));
const PasswordTools = asyncModule(() => import("../modules/PasswordTools.vue"));
const PhotoAlbum = asyncModule(() => import("../modules/PhotoAlbum.vue"));
const FileVerthys = asyncModule(() => import("../modules/FileVerthys.vue"));
const SecurityCenter = asyncModule(() => import("../modules/SecurityCenter.vue"));

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

/* ★ 首次点击模块延迟根治：挂载后空闲期预热全部分包
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

/* 模块切换过渡（cross-fade：新旧组件同时存在，无 out-in 死等） */
/* ★ 企业级修复：z-index 层级确保新模块覆盖旧模块，杜绝视觉覆盖 */
.module-switch-enter-active {
  transition: opacity 0.35s var(--ease), transform 0.35s var(--ease);
  position: relative;
  z-index: 2;
}
.module-switch-leave-active {
  transition: opacity 0.2s var(--ease), transform 0.2s var(--ease);
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 1;
}
.module-switch-enter-from {
  opacity: 0;
  transform: scale(0.98) translateX(16px);
}
.module-switch-leave-to {
  opacity: 0;
  transform: scale(1.01) translateX(-12px);
}

/* ===== 模块加载兜底（「深空对接」— 点击时有即时反馈不空白） =====
 * 双层反向旋转叠加成偏心轨迹光点（非标准圆环/螺旋），
 * 纯 transform 动画（无 filter — 动画目标禁令），静态微光为
 * 一次性光栅化 box-shadow */
.module-loading {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
  z-index: 1;
}
.ml-orbit-a {
  position: relative;
  width: 46px;
  height: 46px;
  animation: ml-a 3.4s linear infinite;
}
.ml-orbit-b {
  position: absolute;
  top: 9px;
  left: 9px;
  width: 28px;
  height: 28px;
  animation: ml-b 2.2s linear infinite reverse;
}
.ml-pip {
  position: absolute;
  top: 1px;
  left: 50%;
  width: 5px;
  height: 5px;
  margin-left: -2.5px;
  border-radius: 50%;
  background: rgba(0, 212, 255, 0.85);
  box-shadow: 0 0 8px rgba(0, 212, 255, 0.45);
}
@keyframes ml-a {
  to { transform: rotate(360deg); }
}
@keyframes ml-b {
  to { transform: rotate(360deg); }
}
.ml-text {
  margin: 0;
  font-size: 12px;
  letter-spacing: 0.35em;
  text-indent: 0.35em;
  color: rgba(160, 190, 220, 0.55);
}
</style>
