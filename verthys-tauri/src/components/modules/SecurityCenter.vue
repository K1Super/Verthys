<!--
  SecurityCenter.vue — 安全管理中心（密钥仓库中枢）
  交互流程（四态严格互斥）：
    unlock  → verthys 未解锁：显示解锁表单
    init    → 已解锁但无全局密钥记录：非全屏「初始化安全密钥」弹窗
    verify  → 已有全局密钥记录但未验证：验证表单
    management → 全局密钥已就绪（或只读模式）：管理主界面
  全局根密钥 = 用户密码 + .bin 密钥文件 + .bin 自定义密码（XChaCha20-Poly1305 加密 .verthys）
  模块独立密钥 = 每个模块独立的访问密钥（非派生，由本界面生成/修改）
-->
<template>
  <div class="security-center">
    <!-- ===== 顶部错误提示弹窗（统一替代所有内联错误） ===== -->
    <ToastOverlay :message="errorMsg" />

    <!-- ===== 解锁视图 ===== -->
    <UnlockView
      v-if="viewMode === 'unlock'"
      :verthys-path="verthysPath"
      :unlocking="unlocking"
      :unlock-progress-msg="unlockProgressMsg"
      :unlock-progress-percent="unlockProgressPercent"
      :unlock-progress-elapsed="unlockProgressElapsed"
      :init-status-ref="initStatusRef"
      :init-detail-ref="initDetailRef"
      @unlock="doUnlock(verthysPath, pendingIsCreate)"
      @back="goBack"
      @open-existing="openExistingVerthys"
      @create-new="createNewVerthys"
    />

    <!-- ===== 初始化弹窗（引力悬浮场体系：CosmicBackdrop 遮罩 + LevitationField 无底板悬浮场） ===== -->
    <InitKeyView
      v-else-if="viewMode === 'init'"
      v-model:init-password="initPassword"
      v-model:bin-password="binPassword"
      :bin-file-name="binFileName"
      :processing="processing"
      @init="onInitKey"
      @back="goBackToUnlock"
      @browse-bin="browseBin"
    />

    <!-- ===== 验证视图 ===== -->
    <VerifyView
      v-else-if="viewMode === 'verify'"
      v-model:verify-password="verifyPassword"
      v-model:bin-password="binPassword"
      :bin-file-name="binFileName"
      :processing="processing"
      :unlock-progress-msg="unlockProgressMsg"
      :unlock-progress-percent="unlockProgressPercent"
      :unlock-progress-elapsed="unlockProgressElapsed"
      @verify="onVerify"
      @back="goBackToUnlock"
      @browse-bin="browseBin"
    />

    <!-- ===== 设备机器码不匹配拦截 ===== -->
    <DeviceMismatchView
      v-else-if="viewMode === 'device_mismatch'"
      :device-fingerprint-short="deviceFingerprintShort"
      @back="goBack"
    />

    <!-- ===== 管理主界面 ===== -->
    <ManagementView
      v-else
      :initializing="initializing"
      :global-key-ready="globalKeyReadyRef"
      :session-remaining="sessionRemaining"
      :device-check-result="deviceCheckResult"
      :device-fingerprint-short="deviceFingerprintShort"
      :module-ids="moduleIds"
      :module-labels="moduleLabels"
      :module-key-enabled="moduleKeyEnabledRef"
      :has-module-key-record="hasModuleKeyRecordRef"
      :module-key-ready="moduleKeyReadyRef"
      :has-module-key="hasModuleKey"
      :is-module-ready="isModuleReady"
      :module-state-class="moduleStateClass"
      :module-state-text="moduleStateText"
      :security-preset-code="securityPresetRef"
      :preset-applying="presetApplying"
      :preset-ambience-mode="presetAmbienceMode"
      :cpu-overhead="cpuOverhead"
      :security-coverage="securityCoverage"
      :overall-score="overallScore"
      :ring-circumference="ringCircumference"
      :ring-dash-offset="ringDashOffset"
      :orbit-anchors="orbitAnchors"
      :nearest-anchor-idx="nearestAnchorIdx"
      :active-anchor-idx="activeAnchorIdx"
      :orbit-track-gradient="orbitTrackGradient"
      :toggleable-features="toggleableFeatures"
      :locked-features="lockedFeatures"
      :custom-features="customFeatures"
      :custom-panel-open="customPanelOpen"
      :defense-paths="defensePaths"
      :defense-meta="defenseMeta"
      v-model:orbit-slider-pos="orbitSliderPos"
      @panel-active="(v: boolean) => emit('panel-active', v)"
      @lock-all="onLockAll"
      @open-change-key-dialog="onOpenChangeKeyDialog"
      @export-bin="onExportBin"
      @toggle-module-key-enabled="onToggleModuleKeyEnabled"
      @open-key-dialog="onOpenKeyDialog"
      @show-module-key="onShowModuleKey"
      @logout-module="onLogoutModule"
      @toggle-gear-panel="onToggleGearPanel"
      @toggle-custom-feature="onToggleCustomFeature"
      @reset-custom="onResetCustom"
      @apply-custom="onApplyCustom"
      @orbit-slider-input="onOrbitSliderInput"
      @orbit-slider-release="onOrbitSliderRelease"
      @snap-to-anchor="snapToAnchor"
    />

    <!-- 密钥编辑弹窗 -->
    <KeyEditDialog
      :show="showKeyDialog"
      :module-label="moduleLabels[editingModuleId]"
      :has-record="hasModuleKeyRecordRef[editingModuleId]"
      :key-dialog-processing="keyDialogProcessing"
      :pending-enable="pendingEnableModuleId === editingModuleId"
      v-model:editing-key-value="editingKeyValue"
      v-model:editing-old-key-value="editingOldKeyValue"
      @close="onCloseKeyDialog"
      @random-key="onRandomKey"
      @confirm="onConfirmKeyDialog"
    />

    <!-- 关闭密钥保护验证弹窗 -->
    <DisableVerifyDialog
      :show="showDisableVerifyDialog"
      :module-label="moduleLabels[disableVerifyModuleId]"
      :disable-verify-processing="disableVerifyProcessing"
      v-model:disable-verify-key="disableVerifyKey"
      @close="onCancelDisableVerify"
      @confirm="onConfirmDisableVerify"
    />

    <!-- 修改全局密钥弹窗 -->
    <ChangeKeyDialog
      :show="showChangeKeyDialog"
      :change-key-processing="changeKeyProcessing"
      :old-bin-file-name="oldBinFileName"
      :new-bin-file-name="newBinFileName"
      v-model:old-password="oldPassword"
      v-model:old-bin-password="oldBinPassword"
      v-model:new-password="newPassword"
      v-model:new-bin-password="newBinPassword"
      @close="onCloseChangeKeyDialog"
      @browse-old-bin="browseOldBin"
      @browse-new-bin="browseNewBin"
      @confirm="onConfirmChangeKey"
    />

    <!-- 导出密钥文件验证弹窗（复用全局密钥窗口样式 · 紧凑版：
         双要素凭据，密钥文件在确认后的导出流程中选择） -->
    <ExportVerifyDialog
      :show="showExportVerifyDialog"
      :processing="exportVerifyProcessing"
      v-model:password="exportVerifyPassword"
      v-model:bin-password="exportVerifyBinPassword"
      @close="onCancelExportVerify"
      @confirm="onConfirmExportVerify"
    />

    <!-- 复制提示 -->
    <transition name="toast">
      <div v-if="toast" class="sc-toast glass">{{ toast }}</div>
    </transition>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch } from "vue";
import {
  lockAll,
  hasModuleKey, isModuleReady,
  verthysReadyRef, globalKeyReadyRef, hasGlobalKeyRecordRef,
  initStatusRef, initDetailRef,
  hasModuleKeyRecordRef, moduleKeyReadyRef, moduleKeyEnabledRef,
  MODULE_IDS, MODULE_LABELS,
  securityPresetRef, applySecurityPreset,
  checkInitStatus,
} from "../../lib/keyManager";
import {
  verthysPreheat,
  preloadWorker, workerDestroy,
} from "../../lib/verthys";
import ToastOverlay from "../common/feedback/ToastOverlay.vue";
import KeyEditDialog from "../dialogs/KeyEditDialog.vue";
import DisableVerifyDialog from "../dialogs/DisableVerifyDialog.vue";
import UnlockView from "../views/UnlockView.vue";
import InitKeyView from "../views/InitKeyView.vue";
import VerifyView from "../views/VerifyView.vue";
import DeviceMismatchView from "../views/DeviceMismatchView.vue";
import ManagementView from "../views/ManagementView.vue";
import ChangeKeyDialog from "../management/ChangeKeyDialog.vue";
import ExportVerifyDialog from "../management/ExportVerifyDialog.vue";
import { useErrorToast } from "../../composables/useErrorToast";
import { useViewMode } from "../../composables/security-center/useViewMode";
// useDeviceBinding 必须在 useViewMode / useUnlockFlow 之前调用（提供 deviceCheckResult / checkDevice 注入）
import { useDeviceBinding } from "../../composables/security-center/useDeviceBinding";
import { useSessionTimer } from "../../composables/security-center/useSessionTimer";
import { useUnlockFlow } from "../../composables/security-center/useUnlockFlow";
import { useGlobalKey } from "../../composables/security-center/useGlobalKey";
import { useModuleKeys } from "../../composables/security-center/useModuleKeys";
import { usePreset } from "../../composables/security-center/usePreset";
import { useDefenseStatus } from "../../composables/security-center/useDefenseStatus";
import { isCacheDirty } from "../../cache/composition/verthys-cache";

const emit = defineEmits<{ (e: "back"): void; (e: "panel-active", val: boolean): void }>();

/* ===== 顶部错误提示弹窗（统一替代所有内联 sc-error / kv-error） ===== */
const { errorMsg, showError } = useErrorToast();

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/* ===== Toast（成功提示，2.5s 自动消失）
 * ★ 提前至 useUnlockFlow 调用前定义以避免 TDZ（showToast 被 useUnlockFlow 注入使用） */
const toast = ref("");
let toastTimer: number | null = null;
const showToast = (msg: string) => {
  toast.value = msg;
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => { toast.value = ""; }, 2500);
};

/* ===== 初始化守卫：组件挂载期间禁止管理视图交互 ===== */
const initializing = ref(true);

/* ===== 设备机器码校验 =====
 * ★ 必须在 useViewMode / useUnlockFlow 之前调用（提供 deviceCheckResult / checkDevice 注入） */
const { deviceCheckResult, deviceFingerprintShort, checkDevice, refreshDeviceFingerprint } = useDeviceBinding({ isTauri });

/* 验证后强制 2s 量子核心动画：无论成功或失败都保持 loading 视图
 * ★ 移至 useViewMode 调用前定义以避免 TDZ（时序死区） */
const postVerifyAnim = ref(false);

/* ===== 视图模式（五态严格互斥） =====
 * ★ 企业级根治方案：移除 "loading" 态。worker 解锁成功后进程内即时完成
 *   全局密钥记录探测，结果内联到 unlock 响应，前端零异步扫描阶段。
 *   解锁完成即确定 hasGlobalKeyRecord，直接进入 init 或 verify，无中间态。 */
const { viewMode } = useViewMode({
  verthysReady: verthysReadyRef,
  hasGlobalKeyRecord: hasGlobalKeyRecordRef,
  globalKeyReady: globalKeyReadyRef,
  deviceCheckResult,
  postVerifyAnim,
});

/* ===== 解锁/创建逻辑 ===== */
const {
  verthysPath,
  unlocking,
  pendingIsCreate,
  unlockProgressMsg,
  unlockProgressPercent,
  unlockProgressElapsed,
  unlockProgressDone,
  openExistingVerthys,
  createNewVerthys,
  doUnlock,
} = useUnlockFlow({
  isTauri,
  showError,
  showToast,
  checkDevice,
});

/* ===== 全局密钥管理 =====
 * ★ 依赖注入：postVerifyAnim（useViewMode 读取 / onVerify 写入）
 *   + unlockProgress*（来自 useUnlockFlow，验证视图复用进度条显示） */
const {
  initPassword,
  verifyPassword,
  binPassword,
  binFileName,
  processing,
  showChangeKeyDialog,
  changeKeyProcessing,
  oldPassword,
  oldBinFileName,
  oldBinPassword,
  newPassword,
  newBinFileName,
  newBinPassword,
  showExportVerifyDialog,
  exportVerifyPassword,
  exportVerifyBinPassword,
  exportVerifyProcessing,
  browseBin,
  onInitKey,
  onVerify,
  browseOldBin,
  browseNewBin,
  onOpenChangeKeyDialog,
  onCloseChangeKeyDialog,
  onConfirmChangeKey,
  onCancelExportVerify,
  onConfirmExportVerify,
  onExportBin,
  resetInitVerifyForm,
} = useGlobalKey({
  isTauri,
  showError,
  showToast,
  postVerifyAnim,
  unlockProgressMsg,
  unlockProgressPercent,
  unlockProgressElapsed,
});

/* ===== 管理界面状态 ===== */
const moduleIds = MODULE_IDS;
const moduleLabels = MODULE_LABELS;

/* ===== 会话超时计时器（仅 UI 显示，实际超时由 keyManager 守护） ===== */
const { sessionRemaining, startSessionTick, stopSessionTick, resetSession } = useSessionTimer({ globalKeyReady: globalKeyReadyRef });

/* ===== 剪贴板工具（注入 useModuleKeys 的 onShowModuleKey 使用） ===== */
const onCopyText = async (text: string) => {
  try { await navigator.clipboard.writeText(text); } catch { /* */ }
  showToast("已复制到剪贴板");
};

/* ===== 模块独立密钥管理 ===== */
const {
  moduleStateClass,
  moduleStateText,
  showKeyDialog,
  editingModuleId,
  editingKeyValue,
  editingOldKeyValue,
  keyDialogProcessing,
  pendingEnableModuleId,
  showDisableVerifyDialog,
  disableVerifyModuleId,
  disableVerifyKey,
  disableVerifyProcessing,
  onToggleModuleKeyEnabled,
  onConfirmDisableVerify,
  onCancelDisableVerify,
  onOpenKeyDialog,
  onCloseKeyDialog,
  onRandomKey,
  onConfirmKeyDialog,
  onShowModuleKey,
  onLogoutModule,
} = useModuleKeys({ showError, showToast, onCopyText });

/* ===== 安全防护预设 ===== */
const {
  presetApplying,
  customPanelOpen,
  customFeatures,
  orbitSliderPos,
  orbitAnchors,
  nearestAnchorIdx,
  activeAnchorIdx,
  cpuOverhead,
  securityCoverage,
  overallScore,
  presetAmbienceMode,
  ringCircumference,
  ringDashOffset,
  orbitTrackGradient,
  toggleableFeatures,
  lockedFeatures,
  onOrbitSliderInput,
  onOrbitSliderRelease,
  snapToAnchor,
  onToggleGearPanel,
  onToggleCustomFeature,
  onResetCustom,
  onApplyCustom,
  loadPresetConfig,
} = usePreset({ showError, showToast, resetSession });

/* ===== 防御闭环状态（WP-11 消费出口：verthys 就绪即拉取 + 60s 轮询） ===== */
const { defensePaths, defenseMeta } = useDefenseStatus();

/* ===== 返回重新选择（锁定当前 verthys，回到解锁视图） ===== */
const goBackToUnlock = async () => {
  if (processing.value || unlocking.value) return;
  // ★ 企业级根治E：锁定 UI，防止 lockAll 期间用户重选 verthys 触发 doUnlock
  //
  // 根治"回退重选 verthys 卡死"根因：
  //   lockAll 异步执行（最多 40s），期间 doLockAll 同步置 verthysReady=false
  //   → UI 立即显示解锁视图 → 用户可重选 verthys → doUnlock → initUnlock →
  //   ensureWorkerReady 复用被 lockAll 销毁中的 worker → 永久卡死。
  //
  // 防护：设置 unlocking=true 锁定解锁按钮（doUnlock 守卫 if(unlocking) return），
  //   并显示量子核心加载动画告知用户"正在清理上一个会话…"。
  //   lockAll 完成后 finally 释放 UI 锁，允许用户重选 verthys。
  unlocking.value = true;
  const lockStart = Date.now();
  unlockProgressMsg.value = "清理会话";
  unlockProgressPercent.value = 0;
  unlockProgressElapsed.value = 0;
  // 阻止残留进度回调覆盖此消息（onUnlockProgress 守卫）
  unlockProgressDone.value = true;
  resetInitVerifyForm();
  // 锁定 verthys，重置所有状态 → viewMode 自动回到 "unlock"
  try {
    await lockAll((percent, message) => {
      unlockProgressPercent.value = percent;
      unlockProgressMsg.value = message;
      unlockProgressElapsed.value = Date.now() - lockStart;
    });
    // ★ 方案 6.2.4：返回解锁页时也检查脏数据状态
    if (isCacheDirty()) {
      showError("部分数据可能未保存，请检查最近操作");
    }
  } catch (e) {
    console.error("[goBackToUnlock] lockAll 异常", e);
  } finally {
    unlocking.value = false;
    unlockProgressDone.value = false;
  }
};

/* ===== 立即锁定 ===== */
const onLockAll = async () => {
  await lockAll();
  // ★ 方案 6.2.4：lockAll 完成后检查脏数据状态
  //    40s 超时或 22s waitForFlush 超时可能标记 cacheDirty
  if (isCacheDirty()) {
    showError("部分数据可能未保存，请检查最近操作");
  } else {
    showToast("已锁定全部并清零内存密钥");
  }
};

/** 返回主页（通知父组件退出当前模块） */
const goBack = () => {
  emit("back");
};

/* ===== 会话计时（仅显示，实际超时由 keyManager 管理） ===== */
onMounted(() => {
  // 不再调用 lockAll()：切换模块时保持 verthys 解锁状态，避免反复初始化和验证。
  // verthys 状态为全局 keyState，跨模块切换时持久化。
  // lockAll() 仅在以下场景调用：
  //   - 用户主动点击"立即锁定"
  //   - 系统锁屏（会话守卫触发）
  //   - 会话空闲超时
  //   - 应用关闭（MainView.onClose）
  initializing.value = false;

  // ★ 企业级根治修复：挂载即刷新设备机器码短显示
  //
  // 根因：deviceFingerprintShort 唯一填充点是 checkDevice()，而它仅在
  // doUnlock 成功且已有全局密钥记录时被调用。以下场景管理界面机器码空白：
  //   a) 新建 verthys → 初始化密钥路径（doUnlock 时 hasGlobalKeyRecord=false）
  //   b) 跨模块切换重挂载（Composable 状态重置，checkDevice 不再触发）
  //
  // 机器码为本机硬件固有属性（CPU/主板/磁盘 SHA-256），与 verthys 解锁状态无关，
  // 挂载立即获取（fire-and-forget，失败仅警告不阻断主流程）。
  void refreshDeviceFingerprint();

  startSessionTick();
  // 若挂载时已解锁（跨模块切回本组件），恢复持久化预设的运行时状态并刷新显示；
  // 未解锁时仅加载预设显示快照（securityPresetRef 已在模块加载时从 localStorage 恢复）
  if (globalKeyReadyRef.value) {
    applySecurityPreset(securityPresetRef.value)
      .then(() => loadPresetConfig())
      .catch((e) => console.warn("[onMounted] 恢复安全预设失败", e));
  } else {
    loadPresetConfig();
  }

  // ★ 企业级修复：启动时自动查询初始化状态，填充上次使用的 verthys 路径
  //
  // 原问题：checkInitStatus 从未被调用，导致：
  //   - initStatusRef 始终为 "none"（初始值）
  //   - storedVerthysPathRef 始终为空
  //   - 用户每次启动都需要手动选择 verthys 文件，无法自动填充上次路径
  //   - 模板中 initStatusRef === 'broken' 的提示文案永远不显示
  //
  // 修复：onMounted 时调用 checkInitStatus 查询 .verthys_state 状态文件：
  //   - status="ready" → 自动填充 verthysPath，用户只需点击确认即可解锁
  //   - status="broken" → 显示"上次初始化失败，已自动清理残留"提示
  //   - status="none" → 全新用户，显示默认引导
  //
  // 注意：此处仅填充路径，不自动触发解锁（用户需手动点击确认按钮）
  if (isTauri && !verthysReadyRef.value) {
    void checkInitStatus()
      .then((result) => {
        console.log("[onMounted] checkInitStatus:", result.status, result.verthys_path);
        if (result.status === "ready" && result.verthys_path) {
          // 自动填充上次使用的 verthys 路径
          verthysPath.value = result.verthys_path;
          pendingIsCreate.value = false;
          // ★ 第一层：选择即预热 — 自动填充路径后也触发预热
          //   与 openExistingVerthys 行为一致，用户点击确认时索引区已进页缓存
          void verthysPreheat(result.verthys_path).catch((e) => {
            console.warn("[onMounted] 预热失败（不影响后续解锁）:", e);
          });
          // ★ 第二层：选择即预启动 Worker 子进程
          void preloadWorker().catch((e) => {
            console.warn("[onMounted] worker 预启动失败:", e);
          });
        }
      })
      .catch((e) => {
        console.warn("[onMounted] checkInitStatus 失败:", e);
      });
  }
});

// 监听全局密钥就绪状态：解锁后恢复持久化预设的运行时状态（会话超时 / 高安全模式）并刷新显示
watch(globalKeyReadyRef, (ready) => {
  if (!ready) return;
  // ★ 兜底：进入管理界面前确保机器码短显示已就绪
  //   （覆盖 onMounted 刷新失败/未完成的时序窗口，如初始化密钥后立即进入）
  if (!deviceFingerprintShort.value) {
    void refreshDeviceFingerprint();
  }
  applySecurityPreset(securityPresetRef.value)
    .then(() => loadPresetConfig())
    .catch((e) => console.warn("[globalKeyReady] 恢复安全预设失败", e));
});

onBeforeUnmount(() => {
  stopSessionTick();
  if (toastTimer !== null) window.clearTimeout(toastTimer);
  // ★ 清理预启动但未使用的 worker，防止僵尸进程
  //    场景：用户选定文件触发了 preloadWorker，但未点击「确认」就切走模块
  //    若 verthys 已解锁（verthysReadyRef=true），worker 仍在使用中，不销毁
  //    workerDestroy 内部会作废预启动缓存，防止后续复用已失效会话
  if (!verthysReadyRef.value) {
    void workerDestroy().catch(() => { /* 后端无 worker 时为 no-op */ });
  }
});
</script>

<style>
/* ============================================================
   SecurityCenter.vue 样式引用聚合
   引用顺序：容器 → 表单 → 按钮 → 加载 → 悬浮场 → 图标 → 路径状态 →
   仪表盘 → 量子面板
   （flow-hint.css 已删 — FlowHint 流程指示组件随弹窗精简一并移除）
   ============================================================ */
@import '../../styles/security/management.css';
@import '../../styles/security/section-field.css';
@import '../../styles/security/form-inputs.css';
@import '../../styles/security/cosmic-submit.css';
@import '../../styles/security/ql-loader.css';
@import '../../styles/security/float-field.css';
@import '../../styles/security/icons.css';
@import '../../styles/security/path-status.css';
@import '../../styles/security/dashboard.css';
@import '../../styles/security/qd-panel.css';
@import '../../styles/security/mgmt-hub.css';
</style>
