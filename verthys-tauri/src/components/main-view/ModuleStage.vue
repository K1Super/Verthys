<!--
  ModuleStage.vue — 模块舞台（路由出口 + 切换过渡）
-->
<template>
  <main ref="stageRef" class="stage">
    <transition
      name="module-switch"
      @before-leave="onStageBeforeLeave"
      @leave-cancelled="onStageLeaveCancelled"
    >
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
import { defineAsyncComponent, onBeforeUnmount, onMounted, provide, ref, toRef } from "vue";
import HomeView from "./HomeView.vue";
import { MODULE_DIALOG_GUARD_KEY } from "../../composables/useModuleDialogGuard";
import { TRANSITION } from "../../app/constants";
import { MODULE_LOADERS, MODULE_WARM_ORDER, loadModule } from "../../app/module-loaders";

/* 页面级组件懒加载：每个模块独立分包，按需加载。
 * 说明符取自模块加载器注册表 —— 异步组件与预热共享同一份加载 Promise，
 * 预热完成即组件可即时解析。 */
const AccountVerthys = defineAsyncComponent(MODULE_LOADERS.accounts);
const PasswordTools = defineAsyncComponent(MODULE_LOADERS.tools);
const PhotoAlbum = defineAsyncComponent(MODULE_LOADERS.photos);
const FileVerthys = defineAsyncComponent(MODULE_LOADERS.verthys);
const SecurityCenter = defineAsyncComponent(MODULE_LOADERS.security);

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

/* ===== 离场几何钉定（避免中枢离场瞬间横向跳变 + 淡出突兀） =====
 *
 * 成因（结构性）：中枢的面板模式（panel-active）收起 Dock 并让舞台全幅
 *   （.workspace.dock-floating → .stage margin-left:0）。离开中枢时 Dock 复位，
 *   舞台左缘在同一帧内收 72px（stage-margin-instant 使其即时生效）。离场元素为
 *   absolute inset:0，随舞台一起被右移并压窄 —— 量子面板的圆环与三卫星在淡出
 *   起点就被整体推移/重新居中，读作「突然一跳后消失」，而非「消散」。
 *
 * 做法：切换前（DOM 尚未 patch 的 pre 阶段，由 MainView 调用）量取离场元素的视口
 *   矩形；离场钩子里以 fixed 定位把它钉在原位。此后：
 *     - 离场编排全程几何恒定（Canvas 的 ResizeObserver 不触发、圆环不重居中）；
 *     - 新模块按最终布局挂载（自身无跳变，只在交叉淡入中浮现）；
 *     - 仅「离开中枢」需要钉定（唯一会改变舞台边距的模块），其余切换零额外开销。
 * 生命周期：leave-cancelled 复位内联样式（快速往返会取消离场并复用该元素）。
 */
const stageRef = ref<HTMLElement | null>(null);

interface StagedLeave { el: HTMLElement; rect: DOMRect }
/** 切换前量取的离场元素与视口矩形（一次性消费） */
let stagedLeave: StagedLeave | null = null;

/** 由 MainView 在当前模块变化的 pre 阶段调用（此时舞台尚为旧布局） */
function captureOutgoing(): void {
  const stage = stageRef.value;
  if (!stage) return;
  const children = stage.children;
  for (let i = 0; i < children.length; i++) {
    const el = children[i] as HTMLElement;
    // 跳过仍在离场的旧模块（快速连续切换时舞台内会有多个子元素）
    if (el.classList.contains("module-switch-leave-active")) continue;
    stagedLeave = { el, rect: el.getBoundingClientRect() };
    return;
  }
}

/** 离场钩子：把量取到的几何钉死在视口原位（inline 覆盖过渡类的 absolute inset:0） */
function onStageBeforeLeave(el: Element): void {
  const staged = stagedLeave;
  stagedLeave = null;
  if (!staged || staged.el !== el) return;
  const s = (el as HTMLElement).style;
  s.position = "fixed";
  s.left = `${staged.rect.left}px`;
  s.top = `${staged.rect.top}px`;
  s.width = `${staged.rect.width}px`;
  s.height = `${staged.rect.height}px`;
  s.right = "auto";
  s.bottom = "auto";
  /* 钉定后脱离 .stage 的 overflow 裁剪：复刻舞台圆角。用 clip-path 而非
     overflow:hidden —— 后者会移除分区视图的纵向滚动条，使内容横向重排
     （一个像素级跳变），恰好是在消灭的那种突变。clip-path 不参与布局。 */
  s.borderRadius = "var(--radius)";
  s.clipPath = "inset(0 round var(--radius))";
}

/** 离场被取消（元素被复用）：撤销钉定，恢复常规布局参与 */
function onStageLeaveCancelled(el: Element): void {
  const s = (el as HTMLElement).style;
  s.position = "";
  s.left = "";
  s.top = "";
  s.width = "";
  s.height = "";
  s.right = "";
  s.bottom = "";
  s.borderRadius = "";
  s.clipPath = "";
}

onBeforeUnmount(() => {
  stagedLeave = null;
});

defineExpose({ captureOutgoing });

/* 首次点击模块延迟抑制：首包在预挂载窗口内完成预热
 *
 * 机制：模块均为懒加载。页面交接后主界面立即可点击；若预热起点在
 *   渡越收束之后（本组件挂载后 4.3s），两者之间存在约两秒的可交互窗口。
 *   用户此刻点击中枢，分包加载、解析与样式表注入全部落在交互帧内，
 *   表现为“停顿一下才进入”。
 *
 * 因此：首包（中枢，最高点击概率）在预挂载层完成首帧后立即预热 ——
 *   主界面此时仍处于隐藏冻结层，挂载类尖峰本就安排在此窗口消化；预热
 *   在页面交接前完成，点击时只剩组件挂载，不承担分包成本。
 *   其余分包维持渡越收束后的串行节拍，不与 materialize 满帧窗口争抢。
 *   容错：任一分包预取失败仅静默忽略（点击时加载器会自行重试）。 */
let warmIdx = 1;

function warmNext(): void {
  if (warmIdx >= MODULE_WARM_ORDER.length) return;
  const id = MODULE_WARM_ORDER[warmIdx++];
  loadModule(id)
    .catch(() => { /* 预热失败静默忽略，点击时加载器自行重试 */ })
    .finally(() => scheduleWarm());
}

function scheduleWarm(): void {
  if (warmIdx >= MODULE_WARM_ORDER.length) return;
  /* 兜底超时差异化：主循环每帧均有任务运行，空闲回调在持续动画下
   * 基本不触发，实际调度延迟≈兜底值 — 首包之外的第一个分包 500ms、
   * 其余 1200ms，全部在渡越与全屏过渡收束之后。 */
  const timeout = warmIdx === 1 ? 500 : 1200;
  if (typeof window.requestIdleCallback === "function") {
    window.requestIdleCallback(() => warmNext(), { timeout });
  } else {
    window.setTimeout(warmNext, 250);
  }
}

onMounted(() => {
  /* 首包预热：预挂载首帧落定后立即启动。requestAnimationFrame 保证
   * 不与本组件的挂载任务同帧叠加；加载与解析在交接前完成，用户首次
   * 点击中枢时组件已在模块缓存中。 */
  window.requestAnimationFrame(() => {
    loadModule(MODULE_WARM_ORDER[0]).catch(() => { /* 点击时加载器自行重试 */ });
  });
  /* 其余分包：渡越包络归零后再调度（含 400ms 缓冲），避免落入
   * materialize 全屏过渡的满帧窗口。 */
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
 * z-index 层级确保新模块覆盖旧模块，杜绝视觉覆盖 */
/* 渡越只走不透明度：模块子树承载全部界面文字，任何位移或缩放都会把字形
 * 提升到合成层（灰度抗锯齿），动画结束回落主层时再子像素化 ——
 * 用户所见即"整个模块忽然模糊、随即变清晰"。方向感改由进出场时长错峰承担
 * （入场慢于离场），不再下发 transform。
 *
 * 包络使用共享「模块步入编排」关键帧而非 transition：--ease
 * （cubic-bezier(0.16, 1, 0.3, 1)）在 0.35s 的前 20% 时长内不透明度即冲到约七成 ——
 * 肉眼读作"整块直接呈现"，正是入场生硬的成因。关键帧的两段式包络把"沉积"
 * 摊开成可辨的渐显，后段再缓慢沉降到实；模块根与内容条目由此共用同一运动语言。 */
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

/* ===== 中枢模块专属离场：先驻留、后加速消散 =====
 * 通用离场（0.18s linear）对中枢这类「全幅 Canvas 构图」过快：圆环与三卫星
 * 在不到 11 帧内均匀褪尽，读作硬切。中枢改为专属包络：
 *   0 → 26%（≈110ms）仅褪去 7% —— 构图先「驻留」一息，让新模块显影在
 *   其上层展开；随后 26% → 100% 以加速曲线收束，末段速度最大但不留硬边。
 * 时长与几何钉定（见脚本）配合：离场元素全程停在自己的原位，
 * 叠加中枢面板的引力内缩（同一 --stage-leave-dur-hub）。
 * Vue 以根动画 animationend 判定卸载 → 子树编排（≤ 根时长）必不被截断。
 * 更长的离场窗口内交出命中：旧模块不得拦截新模块的点击。 */
.module-switch-leave-active.security-center {
  animation: hub-dissolve-out var(--stage-leave-dur-hub, 0.42s) linear forwards;
  pointer-events: none;
}
@keyframes hub-dissolve-out {
  0% {
    opacity: 1;
    animation-timing-function: cubic-bezier(0.4, 0, 0.7, 0.55);
  }
  26% {
    opacity: 0.93;
    animation-timing-function: cubic-bezier(0.33, 0, 0.62, 1);
  }
  100% {
    opacity: 0;
  }
}
</style>
