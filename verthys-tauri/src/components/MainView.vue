<!--
  MainView.vue — 主界面壳层
  布局：浮动玻璃 Dock（左侧）+ 沉浸式模块舞台（右侧）
  模块：存签 / 钥域 / 拾光 / 清藏 / 中枢

  架构：
    骨架组件 MainView.vue（本文件）→ 组合子组件 + 组合式函数
    - main-view/CosmicBackground.vue   宇宙星空背景
    - main-view/DockNav.vue            浮动 Dock 导航
    - main-view/ModuleStage.vue        模块路由舞台
    - main-view/ModuleKeyDialog.vue    模块密钥登录弹窗
    - main-view/VerthysNotReadyDialog.vue Verthys 未就绪提示
    - composables/useCosmicBackground.ts 视差+星场数据
    - composables/useModuleNavigation.ts 模块导航+密钥守卫
  （窗口控制条 WindowControls 已提升至 App.vue 壳层：启动页起常驻，
   不随页面交接重建/隐藏；本视图仅保留等高留白）
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

    <!-- 超精简状态条（窗口控制）由 App.vue 壳层常驻承载 -->

    <!-- 工作区：Dock + 模块舞台 -->
    <div
      class="workspace"
      :class="{ 'dock-floating': dockCollapsed, 'stage-margin-instant': stageMarginInstant }"
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
        ref="stageRef"
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

    <!-- 后台空间回收状态（不拦截交互，只做事实展示） -->
    <div v-if="storageReclaimVisible" class="storage-reclaim">{{ storageReclaimText }}</div>
  </div>
</template>

<script setup lang="ts">
/* ===== 子组件（静态导入：壳层组件始终需要） ===== */
import CosmicBackground from "./main-view/CosmicBackground.vue";
import DockNav from "./main-view/DockNav.vue";
import ModuleStage from "./main-view/ModuleStage.vue";
import ModuleKeyDialog from "./main-view/ModuleKeyDialog.vue";
import VerthysNotReadyDialog from "./main-view/VerthysNotReadyDialog.vue";

/* ===== 组合式函数 ===== */
import { useCosmicBackground } from "../composables/useCosmicBackground";
import { useModuleNavigation } from "../composables/useModuleNavigation";

import { onBeforeMount, onBeforeUnmount, ref, watch } from "vue";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  clearFullRecordCache,
  clearRecordScanCache,
  clearSummaryCache,
  initVerthysCache,
} from "../cache/composition/verthys-cache";
import type {
  StorageCompactProgress,
  StorageCompactResult,
} from "../types/verthys";
import { ensureAdopted as ensurePrivacyAdopted } from "../session/privacy-session";
onBeforeMount(() => {
  initVerthysCache();
  // 防截屏保护会话接管（单飞幂等）：启动序列把槽位置为待采纳时取得关闭保护
  // 所需凭证；此处是业务层的最早挂载点，拾光挂载时会再次调用（幂等命中缓存）
  ensurePrivacyAdopted().catch((e) => {
    console.warn("[privacy] 会话接管失败", e);
  });
  void initStorageReclaimEvents();
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

/* ===== 窗口控制 =====
 * 由 App.vue 壳层统一承担（WindowControls 常驻组件内部注册关闭事件拦截），
 * 本视图不注册监听。 */

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
  moduleKeyVerifyError,
  pendingModuleId,
  pendingModuleLabel,
  hasModuleKeyRecordRef,
  switchModule,
  confirmModuleKeyVerify,
  cancelModuleKeyVerify,
  goToSecurityFromHint,
} = useModuleNavigation();

/* 模块切换窗口内抑制舞台边距过渡。
 * Why：中枢的面板模式会同时收展 Dock，而 Dock 收展经 .stage 的 margin-left 弹性
 *   过渡改变舞台宽度 —— 若与模块交叉淡入同一时刻发生，整块模块内容会被横向推移，
 *   形成"从左至右"的方向感，与其它模块之间的切换（纯交叉淡入）不一致。
 *   故仅在切换窗口内让边距变化即时生效；Dock 悬停展开的过渡不受影响。
 * 窗口时长取模块渡越总时长（入场 0.35s）之上留余量。 */
const stageMarginInstant = ref(false);
let stageMarginTimer: number | undefined;

/** 模块舞台实例（离场几何钉定的量取入口） */
const stageRef = ref<InstanceType<typeof ModuleStage> | null>(null);

/* 模块切换：中枢离场前先量取旧舞台几何（pre 阶段 — 本回调先于渲染，
 * DOM 仍为旧布局；见 ModuleStage.captureOutgoing 的成因说明） */
watch(currentModule, (m, prev) => {
  if (prev === "security" && m !== "security") {
    stageRef.value?.captureOutgoing();
  }
  stageMarginInstant.value = true;
  window.clearTimeout(stageMarginTimer);
  stageMarginTimer = window.setTimeout(() => {
    stageMarginInstant.value = false;
  }, 600);
});
/* ===== 后台空间回收状态 =====
 * 删除后宿主按阈值自动压缩；这里只做事实展示与缓存失效，
 * 不提供交互、不拦截点击。 */
const storageReclaimVisible = ref(false);
const storageReclaimText = ref("");
let storageUnlisten: UnlistenFn[] = [];
let storageHideTimer: number | undefined;

function formatReclaimBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let n = value;
  let unit = 0;
  while (n >= 1024 && unit < units.length - 1) {
    n /= 1024;
    unit++;
  }
  return `${n >= 100 ? n.toFixed(0) : n.toFixed(1)} ${units[unit]}`;
}

async function initStorageReclaimEvents(): Promise<void> {
  try {
    storageUnlisten.push(
      await listen<StorageCompactProgress>("storage://compact-progress", (event) => {
        const p = event.payload;
        storageReclaimVisible.value = true;
        window.clearTimeout(storageHideTimer);
        const pct = p.live_bytes > 0
          ? Math.min(100, Math.floor((p.bytes / p.live_bytes) * 100))
          : 0;
        storageReclaimText.value = `空间回收 ${pct}% · ${formatReclaimBytes(p.bytes)}`;
      }),
    );
    storageUnlisten.push(
      await listen<StorageCompactResult>("storage://compacted", (event) => {
        const r = event.payload;
        storageReclaimVisible.value = true;
        storageReclaimText.value = `空间回收完成 · 释放 ${formatReclaimBytes(r.reclaimed_bytes)}`;
        // 物理偏移已变：失效扫描/摘要/全量缓存，按需重建。
        clearRecordScanCache();
        clearSummaryCache();
        clearFullRecordCache();
        window.clearTimeout(storageHideTimer);
        storageHideTimer = window.setTimeout(() => {
          storageReclaimVisible.value = false;
        }, 2400);
      }),
    );
    storageUnlisten.push(
      await listen<{ error?: string }>("storage://compact-failed", () => {
        window.clearTimeout(storageHideTimer);
        storageHideTimer = window.setTimeout(() => {
          storageReclaimVisible.value = false;
        }, 1200);
      }),
    );
  } catch (e) {
    console.warn("[storage] 回收状态事件注册失败", e);
  }
}

onBeforeUnmount(() => {
  window.clearTimeout(stageMarginTimer);
  window.clearTimeout(storageHideTimer);
  for (const unlisten of storageUnlisten) unlisten();
  storageUnlisten = [];
});
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
  /* 顶部 40px = 应用级常驻窗控条高度（与原状态条等高，几何不变） */
  padding: 40px 16px 16px;
  overflow: hidden;
}

.workspace.dock-floating :deep(.stage) {
  margin-left: 0;
}
/* 模块切换窗口内：舞台边距变化即时生效，不参与弹性过渡 ——
   避免"中枢面板模式收展 Dock"与模块交叉淡入叠加成横向推移的方向感 */
.workspace.stage-margin-instant :deep(.stage) {
  transition: none;
}

/* 后台空间回收状态：固定右下角纯文字，不拦截交互 */
.storage-reclaim {
  position: fixed;
  right: 18px;
  bottom: 16px;
  z-index: 8;
  pointer-events: none;
  font-family: var(--font);
  font-size: 10px;
  letter-spacing: 0.08em;
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
  user-select: none;
}
</style>
