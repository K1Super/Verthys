<!--
  MainView.vue — 主界面壳层（精简骨架）
  布局：浮动玻璃 Dock（左侧）+ 沉浸式模块舞台（右侧）
  彻底抛弃传统导航栏，Dock 即导航
  模块：存签 / 枢钥 / 钥域 / 拾光 / 清藏 / 中枢

  拆分架构：
    骨架组件 MainView.vue（本文件）→ 组合子组件 + 组合式函数
    - main-view/CosmicBackground.vue   宇宙星空背景
    - main-view/WindowControls.vue     窗口控制按钮
    - main-view/DockNav.vue            浮动 Dock 导航
    - main-view/ModuleStage.vue        模块路由舞台
    - main-view/ModuleKeyDialog.vue    模块密钥登录弹窗
    - main-view/VerthysNotReadyDialog.vue Verthys 未就绪提示
    - composables/useCosmicBackground.ts 视差+星场数据
    - composables/useWindowControls.ts   窗口控制逻辑
    - composables/useModuleNavigation.ts 模块导航+密钥守卫
-->
<template>
  <div class="main-view" @mousemove="onParallax">
    <!-- 顶部错误提示弹窗 -->
    <Teleport to="body">
      <transition name="err-toast">
        <div v-if="errorMsg" class="error-toast glass"><span class="toast-dot"></span>{{ errorMsg }}</div>
      </transition>
    </Teleport>

    <!-- ===== 宇宙交响曲氛围背景层 ===== -->
    <CosmicBackground
      :parallax-far="parallaxFar"
      :parallax-mid="parallaxMid"
      :parallax-near="parallaxNear"
      :stars-far="starsFar"
      :stars-mid="starsMid"
      :stars-near="starsNear"
      :cosmic-dust="cosmicDust"
      :constellation-stars="constellationStars"
      :constellation-lines="constellationLines"
    />

    <!-- 超精简状态条（窗口控制） -->
    <WindowControls />

    <!-- 工作区：Dock + 模块舞台 -->
    <div
      class="workspace"
      :class="{ 'dock-floating': dockCollapsed }"
      @mousemove="onDockEdgeHover"
    >
      <!-- 浮动宇宙 Dock -->
      <DockNav
        :current-module="currentModule"
        :collapsed="dockCollapsed && !dockHovered"
        @switch="switchModule"
      />

      <!-- 模块舞台 -->
      <ModuleStage
        :current-module="currentModule"
        @back="currentModule = ''"
        @panel-active="onPanelActive"
      />
    </div>

    <!-- 模块密钥登录对话框 -->
    <ModuleKeyDialog
      :show="showModuleKeyVerify"
      :pending-module-label="pendingModuleLabel"
      :has-module-key-record="hasModuleKeyRecordRef[pendingModuleId]"
      v-model:module-key-input="moduleKeyInput"
      :module-key-verifying="moduleKeyVerifying"
      :module-key-verify-percent="moduleKeyVerifyPercent"
      :module-key-verify-msg="moduleKeyVerifyMsg"
      :module-key-verify-error="moduleKeyVerifyError"
      @close="cancelModuleKeyVerify"
      @confirm="confirmModuleKeyVerify"
    />

    <!-- Verthys 未就绪提示 -->
    <VerthysNotReadyDialog
      :show="showVerthysNotReadyHint"
      :pending-module-label="pendingModuleLabel"
      @close="showVerthysNotReadyHint = false"
      @go-to-security="goToSecurityFromHint"
    />
  </div>
</template>

<script setup lang="ts">
/* ===== 子组件（静态导入：壳层组件始终需要） ===== */
import CosmicBackground from "./main-view/CosmicBackground.vue";
import WindowControls from "./main-view/WindowControls.vue";
import DockNav from "./main-view/DockNav.vue";
import ModuleStage from "./main-view/ModuleStage.vue";
import ModuleKeyDialog from "./main-view/ModuleKeyDialog.vue";
import VerthysNotReadyDialog from "./main-view/VerthysNotReadyDialog.vue";

/* ===== 组合式函数 ===== */
import { useCosmicBackground } from "../composables/useCosmicBackground";
import { useWindowControls } from "../composables/useWindowControls";
import { useModuleNavigation } from "../composables/useModuleNavigation";

/* ★ 缓存层组合根初始化（v3 懒加载架构修复 — 由 bootstrap 迁入）：
 * MainView 为异步 chunk（静态入口不引用 verthys-cache，业务层不进主包）；
 * onBeforeMount 先于全部子组件的挂载钩子（父先于子时序）——
 * 首个业务消费方（模块登录/数据加载，均在子树内）运行前
 * VerthysCacheDomain 必已装配。幂等 + ensureDomain fail-fast 契约不变。 */
import { onBeforeMount } from "vue";
import { initVerthysCache } from "../cache/composition/verthys-cache";
onBeforeMount(() => {
  initVerthysCache();
});

/* ===== 宇宙背景数据与视差 ===== */
const {
  parallaxFar,
  parallaxMid,
  parallaxNear,
  onParallax,
  starsFar,
  starsMid,
  starsNear,
  cosmicDust,
  constellationStars,
  constellationLines,
} = useCosmicBackground();

/* ===== 窗口控制 ===== */
/* useWindowControls 内部注册 onMounted 拦截关闭事件 */
useWindowControls();

/* ===== 模块导航与密钥守卫 ===== */
const {
  errorMsg,
  currentModule,
  dockCollapsed,
  dockHovered,
  onPanelActive,
  onDockEdgeHover,
  showModuleKeyVerify,
  showVerthysNotReadyHint,
  moduleKeyInput,
  moduleKeyVerifying,
  moduleKeyVerifyPercent,
  moduleKeyVerifyMsg,
  moduleKeyVerifyError,
  pendingModuleId,
  pendingModuleLabel,
  hasModuleKeyRecordRef,
  switchModule,
  confirmModuleKeyVerify,
  cancelModuleKeyVerify,
  goToSecurityFromHint,
} = useModuleNavigation();
</script>

<style scoped>
/* ===== 主界面壳层 ===== */
.main-view {
  position: relative;
  display: flex;
  flex-direction: column;
  width: 100%;
  height: 100%;
  /* ★ 性能根治：全屏 backdrop-filter 叠在持续动画的深空背景上 =
   * 合成器每帧全屏重采样（掉帧主因）→ 去实时毛玻璃，
   * 底色加深补偿视觉（背后本就是弥散星空，暗化层视觉等效）
   * ★ 入场语义统一（v3）：本层零入场动画 — 外层 App.vue 双缓冲层
   * materialize 过渡（opacity/blur/scale 1.9s 与渡越消散同步收束）
   * 独立承担「自星系辉光深处浮现成型」；旧 view-fade-in 0.6s 与
   * 外层 2.5s 不同步（opacity 先到终点、blur 仍在途）= 双层入场
   * 节奏割裂 → 移除。子组件入场编排由 prewarm 冻结体系与外层
   * 同步解冻（App.vue .main-layer.prewarm 动画冻结规则） */
  /* ★ v3：过渡遮罩减淡 0.66→0.55 — 页面交接淡入窗口内，星系消散段
   * 透出更亮（「由明到暗过暗」校正）。稳态下本层位于不透明深空底
   * （CosmicBackground.deep-space）之下，仅在入场淡入期生效 */
  background: rgba(6, 8, 13, 0.55);
  overflow: hidden;
}

/* ===== 工作区 ===== */
.workspace {
  position: relative;
  z-index: 2;
  flex: 1;
  display: flex;
  padding: 0 16px 16px;
  overflow: hidden;
}

/* 面板全屏模式：stage 占满，dock 浮于其上 */
/* 使用 :deep() 穿透子组件 ModuleStage 的 scoped 边界 */
.workspace.dock-floating :deep(.stage) {
  margin-left: 0;
}
</style>
