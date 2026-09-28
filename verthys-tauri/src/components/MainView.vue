<!--
  MainView.vue — 主界面壳层
  布局：浮动玻璃 Dock（左侧）+ 沉浸式模块舞台（右侧）
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

import { onBeforeMount } from "vue";
import { initVerthysCache } from "../cache/composition/verthys-cache";
import { ensureAdopted as ensurePrivacyAdopted } from "../session/privacy-session";
onBeforeMount(() => {
  initVerthysCache();
  // 防截屏保护会话接管（单飞幂等）：启动序列把槽位置为待采纳时取得关闭保护
  // 所需凭证；此处是业务层的最早挂载点，拾光挂载时会再次调用（幂等命中缓存）
  ensurePrivacyAdopted().catch((e) => {
    console.warn("[privacy] 会话接管失败", e);
  });
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

.workspace.dock-floating :deep(.stage) {
  margin-left: 0;
}
</style>
