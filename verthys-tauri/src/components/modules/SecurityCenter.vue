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
    <!-- 瞬时提示（错误/成功）统一由全局 ToastLayer 渲染（App 根节点单点挂载，--z-toast 最高层） -->

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
      :unlock-progress-msg="unlockProgressMsg"
      :visual-percent="verifyRhythm.visualPercent.value"
      :dimmed="verifyRhythm.dimmed.value"
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
      :visual-percent="verifyRhythm.visualPercent.value"
      :dimmed="verifyRhythm.dimmed.value"
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
      :global-key-ready="globalKeyReadyRef"
      :session-remaining="sessionRemaining"
      :idle-lock-enabled="sessionLockEnabledRef"
      :update-available="!!availableUpdate"
      :update-version="availableUpdate?.version ?? ''"
      :update-checking="updateChecking"
      :update-installing="updateInstalling || updateFlowActive"
      :update-percent="updatePercent"
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
      :preset-applying="presetApplying"
      :preset-ambience-mode="presetAmbienceMode"
      :preset-sync-failed="presetSyncFailed"
      :hardening-failed="securityHardeningFailedRef"
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
      :preset-features="currentPresetFeatures"
      :custom-features="customFeatures"
      :custom-session-minutes="customSessionMinutes"
      :defense-paths="defensePaths"
      :defense-meta="defenseMeta"
      v-model:orbit-slider-pos="orbitSliderPos"
      @panel-active="(v: boolean) => emit('panel-active', v)"
      @lock-all="onLockAll"
      @check-update="onCheckUpdate"
      @install-update="onInstallUpdate"
      @open-change-key-dialog="onOpenChangeKeyDialog"
      @export-bin="onExportBin"
      @toggle-module-key-enabled="onToggleModuleKeyEnabled"
      @open-key-dialog="onOpenKeyDialog"
      @show-module-key="onShowModuleKey"
      @logout-module="onLogoutModule"
      @toggle-custom-feature="onToggleCustomFeature"
      @reset-custom="onResetCustom"
      @set-custom-session-minutes="onSetCustomSessionMinutes"
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

    <!-- 导出密钥文件验证弹窗（核验台皮肤 · 双闸凭据：
         密钥文件在确认后的导出流程中选择） -->
    <ExportVerifyDialog
      :show="showExportVerifyDialog"
      :processing="exportVerifyProcessing"
      v-model:password="exportVerifyPassword"
      v-model:bin-password="exportVerifyBinPassword"
      @close="onCancelExportVerify"
      @confirm="onConfirmExportVerify"
    />

    <!-- 介质标识变化确认（克隆嫌疑阻断后的自助重绑定；
         确认参数只放行阻断，重绑定以本次密码验证通过为前提） -->
    <VerthysDialog
      :model-value="usbRebindPrompt !== null"
      layout="plain"
      width="480px"
      title="介质标识变化"
      save-label="确认更换介质"
      saving-label="重试解锁中…"
      :saving="usbRebindSaving"
      :save-disabled="unlocking"
      @update:model-value="onUsbRebindDialogToggle"
      @save="confirmUsbRebind"
    >
      <p class="usb-rebind-text">
        检测到加密库所在可移动介质的标识与登记记录不一致（可能为更换介质，或介质被克隆）。
      </p>
      <p class="usb-rebind-text">
        如确为本人更换介质，可确认后重试：本次仍须通过密码验证，验证通过后才会更新绑定记录。
      </p>
    </VerthysDialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, watch, defineAsyncComponent } from "vue";
import {
  lockAll,
  hasModuleKey, isModuleReady,
  verthysReadyRef, globalKeyReadyRef, hasGlobalKeyRecordRef,
  initStatusRef, initDetailRef,
  hasModuleKeyRecordRef, moduleKeyReadyRef, moduleKeyEnabledRef,
  MODULE_IDS, MODULE_LABELS,
  restoreSecurityPreset,
  sessionLockEnabledRef,
  securityHardeningFailedRef,
  checkInitStatus,
} from "../../lib/keyManager";
import {
  verthysPreheat,
  preloadWorker, workerDestroy,
} from "../../lib/verthys";
import KeyEditDialog from "../dialogs/KeyEditDialog.vue";
import DisableVerifyDialog from "../dialogs/DisableVerifyDialog.vue";
import VerthysDialog from "../common/verthys-ui/VerthysDialog.vue";
/* 视图级懒加载：拆分中枢首挂载成本 — 首次进入仅执行 UnlockView
 * （最常见入口视图，保持同步渲染零等待），其余视图/弹窗按需拉取
 * （本地分包，切换时微任务级就绪） */
import UnlockView from "../views/UnlockView.vue";
const InitKeyView = defineAsyncComponent(() => import("../views/InitKeyView.vue"));
const VerifyView = defineAsyncComponent(() => import("../views/VerifyView.vue"));
const DeviceMismatchView = defineAsyncComponent(() => import("../views/DeviceMismatchView.vue"));
const ManagementView = defineAsyncComponent(() => import("../views/ManagementView.vue"));
const ChangeKeyDialog = defineAsyncComponent(() => import("../management/ChangeKeyDialog.vue"));
const ExportVerifyDialog = defineAsyncComponent(() => import("../management/ExportVerifyDialog.vue"));
import { useToastCenter } from "../../composables/useToastCenter";
import { useClipToast } from "../../composables/useClipToast";
import { useViewMode } from "../../composables/security-center/useViewMode";
// useDeviceBinding 必须在 useViewMode / useUnlockFlow 之前调用（提供 deviceCheckResult / checkDevice 注入）
import { useDeviceBinding } from "../../composables/security-center/useDeviceBinding";
import { useSessionTimer } from "../../composables/security-center/useSessionTimer";
import { useUnlockFlow } from "../../composables/security-center/useUnlockFlow";
import { useGlobalKey } from "../../composables/security-center/useGlobalKey";
import { useVerifyRhythm } from "../../composables/security-center/useVerifyRhythm";
import { useModuleKeys } from "../../composables/security-center/useModuleKeys";
import { usePreset } from "../../composables/security-center/usePreset";
import { useDefenseStatus } from "../../composables/security-center/useDefenseStatus";
import { useSystemMetrics } from "../../composables/security-center/useSystemMetrics";
import { useAppUpdater } from "../../composables/useAppUpdater";
import { isCacheDirty } from "../../cache/composition/verthys-cache";

const emit = defineEmits<{ (e: "back"): void; (e: "panel-active", val: boolean): void }>();

/* ===== 瞬时提示（统一替代所有内联 sc-error / kv-error / sc-toast）
 * 全局单例中心：渲染统一归 ToastLayer（最高层），本处仅取用方法 ===== */
const { showError, showStatus } = useToastCenter();
/* 安全子 composable 注入口径（DI 参数名沿用 showToast，指向标准状态通道） */
const showToast = showStatus;

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/* ===== 设备机器码校验 =====
 * 必须在 useViewMode / useUnlockFlow 之前调用（提供 deviceCheckResult / checkDevice 注入） */
const { deviceCheckResult, deviceFingerprintShort, checkDevice, refreshDeviceFingerprint } = useDeviceBinding({ isTauri });

/* 验证收束标志：验证流程与成功收束（补满 100%）期间保持验证视图。
 * 收束完成事件触发后由上层的 onVerify 复位，视图随即切换；
 * 视图切换由感知层收束完成事件驱动，不依赖固定时长。
 * 移至 useViewMode 调用前定义以避免 TDZ（时序死区） */
const postVerifyAnim = ref(false);
/** 初始化收束标志（用途同 postVerifyAnim）：onInitKey 写入、useViewMode 读取。
 *  缺此保持位时，初始化成功会在收束完成前抢跳视图（表现为「点击后直接放行」）。 */
const postInitAnim = ref(false);

/* ===== 验证进度感知层（信号层 → 感知层 → 呈现层 的中间层） ===== */
const verifyRhythm = useVerifyRhythm();

/* ===== 视图模式（五态严格互斥） =====
 *   移除 "loading" 态。worker 解锁成功后进程内即时完成
 *   全局密钥记录探测，结果内联到 unlock 响应，前端零异步扫描阶段。
 *   解锁完成即确定 hasGlobalKeyRecord，直接进入 init 或 verify，无中间态。 */
const { viewMode } = useViewMode({
  verthysReady: verthysReadyRef,
  hasGlobalKeyRecord: hasGlobalKeyRecordRef,
  globalKeyReady: globalKeyReadyRef,
  deviceCheckResult,
  postVerifyAnim,
  postInitAnim,
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
  usbRebindPrompt,
  usbRebindSaving,
  openExistingVerthys,
  createNewVerthys,
  doUnlock,
  confirmUsbRebind,
  cancelUsbRebind,
} = useUnlockFlow({
  isTauri,
  showError,
  showToast,
  checkDevice,
});

/** 介质确认弹层显隐：仅允许关闭路径（确认动作走 @save → confirmUsbRebind） */
const onUsbRebindDialogToggle = (visible: boolean) => {
  if (!visible) cancelUsbRebind();
};

/* ===== 全局密钥管理 =====
 * 依赖注入：postVerifyAnim（useViewMode 读取 / onVerify 写入）
 *   + verifyRhythm（验证进度感知层实例）
 *   + unlockProgress*（来自 useUnlockFlow，作为真实进度信号注入验证复用） */
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
  postInitAnim,
  verifyRhythm,
  unlockProgressMsg,
  unlockProgressPercent,
  unlockProgressElapsed,
});

/* ===== 管理界面状态 ===== */
const moduleIds = MODULE_IDS;
const moduleLabels = MODULE_LABELS;

/* ===== 会话超时计时器（仅 UI 显示，实际超时由 keyManager 守护） ===== */
const { sessionRemaining, startSessionTick, stopSessionTick, resetSession } = useSessionTimer({
  globalKeyReady: globalKeyReadyRef,
  idleLockEnabled: sessionLockEnabledRef,
});

/* ===== 剪贴板工具（模块密钥复制；生命周期归 useClipToast） =====
 * 复制结果与清空时间轮番提示（先结果、后清空时间），默认 1 分钟后静默清空；
 * 写入失败如实返回，由调用方红字直陈 —— 禁止无条件提示「已复制」。 */
const writeViaTextarea = async (content: string): Promise<boolean> => {
  const prevFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const ta = document.createElement("textarea");
  try {
    ta.value = content;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    ta.remove();
    prevFocus?.focus?.();
  }
};
const { copyWithTimeout: copySecure } = useClipToast("模块密钥已复制", { write: writeViaTextarea });

/** 复制敏感文本（失败不得静默；成功/清空时间由安全通道轮番提示） */
const onCopyText = async (text: string): Promise<boolean> => {
  if (!text) return false;
  const ok = await copySecure(text);
  if (!ok) showError("复制失败：剪贴板不可用或权限被拒绝");
  return ok;
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

/* ===== 动态防护状态（消费出口：verthys 就绪即拉取 + 60s 轮询） =====
 * 先于 usePreset 装配：defenseMeta 作为真实信号注入预设指标合成 */
const { defensePaths, defenseMeta } = useDefenseStatus();

/* ===== 系统运行指标（CPU 占用率真实采样，就绪期 2s 轮询） ===== */
const { cpuUsage } = useSystemMetrics(globalKeyReadyRef);

/* ===== 安全防护预设 ===== */
const {
  presetApplying,
  presetSyncFailed,
  currentPresetFeatures,
  customFeatures,
  customSessionMinutes,
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
  onToggleCustomFeature,
  onResetCustom,
  onSetCustomSessionMinutes,
  onApplyCustom,
  loadPresetConfig,
} = usePreset({ showError, showToast, resetSession, cpuUsage, defenseMeta });

/* ===== 应用更新 =====
 * 状态与启动静默检查共享同一单例；安装分两段执行：
 *   1. 先下载安装包 —— 传输期间会话保持解锁，不打断当前操作；
 *   2. 再锁库落盘 —— 缓存脏或锁定失败即中止，绝不启动覆盖程序的安装器。
 * 安装器接管后进程由插件退出，因此锁库必须发生在安装之前。 */
const {
  availableUpdate,
  checking: updateChecking,
  installing: updateInstalling,
  downloadedBytes: updateDownloadedBytes,
  totalBytes: updateTotalBytes,
  lastError: updateLastError,
  checkForUpdate,
  downloadUpdate,
  installUpdate: installDownloadedUpdate,
} = useAppUpdater();

/** 下载进度百分比（0-100；总长未知时保持 0，端子只显示「正在更新…」） */
const updatePercent = computed(() => {
  if (updateTotalBytes.value <= 0) return 0;
  return Math.min(100, Math.round((updateDownloadedBytes.value / updateTotalBytes.value) * 100));
});

/** 安装流程互斥闸门：覆盖下载、锁库与安装全过程，防止重复点击并发启动安装器 */
const updateFlowActive = ref(false);

/** 手动检查更新：区分「已是最新」与「检查失败」两种无更新结果 */
const onCheckUpdate = async () => {
  if (updateChecking.value || updateInstalling.value || updateFlowActive.value) return;
  const found = await checkForUpdate();
  if (found) {
    showToast(`发现新版本 ${found.version}`);
  } else if (updateLastError.value) {
    showError(`检查更新失败：${updateLastError.value}`);
  } else {
    showToast("当前已是最新版本");
  }
};

/** 下载并安装更新：下载完成后先锁库落盘，再交给安装器接管进程 */
const onInstallUpdate = async () => {
  if (updateInstalling.value || updateFlowActive.value) return;
  updateFlowActive.value = true;
  try {
    if (!availableUpdate.value) {
      const found = await checkForUpdate();
      if (!found) {
        if (updateLastError.value) {
          showError(`检查更新失败：${updateLastError.value}`);
        } else {
          showToast("当前已是最新版本");
        }
        return;
      }
    }
    await downloadUpdate();
    if (verthysReadyRef.value) {
      await lockAll();
      if (isCacheDirty()) {
        showError("部分数据可能未保存，已中止更新安装");
        return;
      }
    }
    await installDownloadedUpdate();
  } catch (e) {
    console.error("[updater] 更新安装失败", e);
    showError(`更新失败：${e instanceof Error ? e.message : String(e)}`);
  } finally {
    /* 安装成功时进程由安装器接管退出，不会执行此处；失败或中止时释放闸门 */
    updateFlowActive.value = false;
  }
};

/* ===== 返回重新选择（锁定当前 verthys，回到解锁视图） ===== */
const goBackToUnlock = async () => {
  if (processing.value || unlocking.value) return;

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
    // 返回解锁页时也检查脏数据状态
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
  // lockAll 完成后检查脏数据状态
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
  // 机器码为本机硬件固有属性（CPU/主板/磁盘 SHA-256），与 verthys 解锁状态无关，
  // 挂载立即获取（fire-and-forget，失败仅警告不阻断主流程）。
  void refreshDeviceFingerprint();

  startSessionTick();
  // 预设恢复统一收敛到下方 watch(globalKeyReadyRef, { immediate }) 单通道：
  //   - 挂载时已解锁 → immediate 立即恢复（避免与 watch 就绪回调双触发重复落盘）
  //   - 挂载时未解锁 → onChange 在解锁瞬间恢复；解锁前仅展示 localStorage 快照

  // 注意：此处仅填充路径，不自动触发解锁（用户需手动点击确认按钮）
  if (isTauri && !verthysReadyRef.value) {
    void checkInitStatus()
      .then((result) => {
        if (result.status === "ready" && result.verthys_path) {
          // 自动填充上次使用的 verthys 路径
          verthysPath.value = result.verthys_path;
          pendingIsCreate.value = false;
          // 第一层：选择即预热 — 自动填充路径后也触发预热
          //   与 openExistingVerthys 行为一致，用户点击确认时索引区已进页缓存
          void verthysPreheat(result.verthys_path).catch((e) => {
            console.warn("[onMounted] 预热失败（不影响后续解锁）:", e);
          });
          // 第二层：选择即预启动 Worker 子进程
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

/* ===== 预设恢复链（唯一权威同步路径：读取受信档位 → 应用 → 刷新面板配置） =====
 * 失败可见：单次退避重试仍失败时置 presetSyncFailed 并弹出通用错误提示，
 * 禁止静默吞掉（安全关键配置的同步状态必须对用户可见）。 */
const runPresetRestore = async (attempt: number): Promise<void> => {
  try {
    const report = await restoreSecurityPreset();
    // loadPresetConfig 内部按真实结果置 presetSyncFailed（成功清除 / 失败置位）
    await loadPresetConfig();
    if (report.persistDirty) {
      // 后端此前处于回滚失败状态：本次已按受信文件重新收敛，向用户可见告知
      showToast("预设持久化状态异常，已按受信配置重新同步");
    }
  } catch (e) {
    console.warn("[globalKeyReady] 恢复安全预设失败", e);
    if (attempt < 1) {
      // 单次退避重试：覆盖后端瞬时不可用（IPC 抖动/落盘竞争）
      await new Promise((resolve) => window.setTimeout(resolve, 1000));
      return runPresetRestore(attempt + 1);
    }
    presetSyncFailed.value = true;
    showError("安全预设恢复失败，当前档位可能未同步");
  }
};

// 监听全局密钥就绪状态：解锁后以后端受信配置为权威恢复预设（迁移/落盘/真实切档）
// immediate：挂载时已解锁立即恢复（onMounted 不再单独触发，避免双写重复落盘）
watch(globalKeyReadyRef, (ready) => {
  if (!ready) return;
  // 兜底：进入管理界面前确保机器码短显示已就绪
  //   （覆盖 onMounted 刷新失败/未完成的时序窗口，如初始化密钥后立即进入）
  if (!deviceFingerprintShort.value) {
    void refreshDeviceFingerprint();
  }
  // 设备绑定补检：进入管理界面（含已解锁重挂载）时主动校验一次，
  // 覆盖 useUnlockFlow 解锁路径之外的重进场景（设备在会话期间变更可被发现）
  void checkDevice();
  void runPresetRestore(0);
}, { immediate: true });

onBeforeUnmount(() => {
  stopSessionTick();
  // 清理感知层动画帧调度（中断策略：取消调度并冻结状态）
  verifyRhythm.dispose();
  // 清理预启动但未使用的 worker，防止僵尸进程
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

/* ===== 介质标识变化确认弹层（说明文案：纯文本、零阴影） ===== */
.usb-rebind-text {
  margin: 0 0 10px;
  font-size: 13px;
  line-height: 1.8;
  letter-spacing: 0.02em;
  color: var(--text-muted);
}
.usb-rebind-text:last-child {
  margin-bottom: 0;
}
</style>
