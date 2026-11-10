<!--
  SecurityCenter.vue — 安全管理中心（密钥仓库中枢）
  交互流程（五态严格互斥）：
    unlock  → verthys 未解锁：显示解锁表单
    init    → 已解锁但无全局密钥记录：非全屏「初始化安全密钥」弹窗
    verify  → 已有全局密钥记录但未验证：验证表单
    device_mismatch → 设备机器码不匹配：拦截视图
    management → 全局密钥已就绪（或只读模式）：管理主界面
  全局根密钥 = 用户密码 + .bin 密钥文件 + .bin 自定义密码（XChaCha20-Poly1305 加密 .verthys）
  模块独立密钥 = 每个模块独立的访问密钥（非派生，由本界面生成/修改）
-->
<template>
  <div
    class="security-center"
    :class="{ 'has-notice-rail': viewMode === 'management' && recoveryNotices.length > 0 }"
  >
    <!-- 瞬时提示（错误/成功）统一由全局 ToastLayer 渲染（App 根节点单点挂载，--z-toast 最高层） -->

    <!-- 恢复会话常驻状态轨：状态源在全局 keyState，进入中枢管理界面即恢复；
         仅在中枢内提供处置入口，离开中枢不保留全局浮层 -->
    <StatusRail
      v-if="viewMode === 'management'"
      :notices="recoveryNotices"
      @action="onRecoveryNoticeAction"
    />

    <!-- ===== 解锁视图 ===== -->
    <UnlockView
      v-if="viewMode === 'unlock'"
      :verthys-path="verthysPath"
      :unlocking="unlocking"
      :progress-suppressed="recoveryUnlockOpen"
      :unlock-progress-msg="unlockProgressMsg"
      :progress-source="progressRhythm.visualPercent"
      :dimmed="progressRhythm.dimmed.value"
      :unlock-progress-elapsed="unlockProgressElapsed"
      :init-status-ref="initStatusRef"
      :init-detail-ref="initDetailRef"
      :is-create="pendingIsCreate"
      :can-recover="canRecoverVault"
      v-model:keyfile-create-enabled="keyfileCreateEnabled"
      @unlock="doUnlock(verthysPath, pendingIsCreate)"
      @recovery="openRecoveryUnlock"
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
      :progress-source="progressRhythm.visualPercent"
      :dimmed="progressRhythm.dimmed.value"
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
      :progress-source="progressRhythm.visualPercent"
      :dimmed="progressRhythm.dimmed.value"
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
      ref="managementViewRef"
      :global-key-ready="globalKeyReadyRef"
      :session-remaining="sessionRemaining"
      :idle-lock-enabled="sessionLockEnabledRef"
      :update-available="!!availableUpdate"
      :update-version="availableUpdate?.version ?? ''"
      :update-checking="updateChecking"
      :update-installing="updateInstalling || updateFlowActive"
      :update-percent="updatePercent"
      :update-cancellable="updateCancellable"
      :device-check-result="deviceCheckResult"
      :device-fingerprint-short="deviceFingerprintShort"
      :module-ids="moduleIds"
      :module-labels="moduleLabels"
      :module-key-enabled="moduleKeyEnabledRef"
      :has-module-key-record="hasModuleKeyRecordRef"
      :module-key-ready="moduleKeyReadyRef"
      :module-has-recovery="moduleHasRecoveryRef"
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
      :custom-mode="isCustomPreset"
      :preset-idle-minutes="activeIdleMinutes"
      :custom-session-minutes="customSessionMinutes"
      :defense-paths="defensePaths"
      :defense-meta="defenseMeta"
      v-model:orbit-slider-pos="orbitSliderPos"
      @panel-active="(v: boolean) => emit('panel-active', v)"
      @lock-all="onLockAll"
      @check-update="onCheckUpdate"
      @install-update="onInstallUpdate"
      @cancel-update="onCancelUpdate"
      @open-change-key-dialog="onOpenChangeKeyDialog"
      @export-bin="onExportBin"
      @recovery-rotated="onRotatedRecovery"
      @toggle-module-key-enabled="onToggleModuleKeyEnabled"
      @open-key-dialog="onOpenKeyDialog"
      @logout-module="onLogoutModule"
      @toggle-custom-feature="onToggleCustomFeature"
      @reset-custom="onResetCustom"
      @set-custom-session-minutes="onSetCustomSessionMinutes"
      @orbit-slider-input="onOrbitSliderInput"
      @orbit-slider-release="onOrbitSliderRelease"
      @snap-to-anchor="snapToAnchor"
    />

    <!-- 全库 DEK 轮换（仅恢复码会话可用；入口在中枢状态轨）
         首次打开才装载，未使用时不占中枢挂载成本 -->
    <VaultRotateDialog
      v-if="rotateDialogMounted"
      :show="rotateDialogOpen"
      @close="rotateDialogOpen = false"
      @committed="onRotateCommitted"
    />

    <!-- 密钥编辑弹窗 -->
    <KeyEditDialog
      :show="showKeyDialog"
      :module-label="moduleLabels[editingModuleId]"
      :has-record="hasModuleKeyRecordRef[editingModuleId]"
      :key-dialog-processing="keyDialogProcessing"
      v-model:editing-key-value="editingKeyValue"
      v-model:editing-old-key-value="editingOldKeyValue"
      v-model:editing-recovery-code="editingRecoveryCode"
      v-model:skip-recovery-binding="skipRecoveryBinding"
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

    <!-- 高安全预设：默认 PCR[7,11] 提示（不在弹窗内收集恢复码） -->
    <SecurePcrDialog
      :show="showSecurePcrDialog"
      :pcr-enabled="securePcrEnabled"
      @close="onSecurePcrDialogClose"
      @goto="onGotoSecurePcr"
    />

    <!-- 高安全预设：默认 keyfile 第二因子引导（PCR 引导之后） -->
    <SecureKeyfileDialog
      :show="showSecureKeyfileDialog"
      :busy="secureKeyfileBusy"
      @close="showSecureKeyfileDialog = false"
      @confirm="onConfirmSecureKeyfile"
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
      :overlay-z="10000"
      teleport
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

    <!-- 一次性恢复码展示与确认（新建 / 轮换共用；确认/关闭即清零） -->
    <RecoveryCodeDialog
      :show="activeRecoveryCode !== null"
      :code="activeRecoveryCode ?? ''"
      @confirmed="onRecoveryCodeDialogClose"
      @close="onRecoveryCodeDialogClose"
    />

    <!-- 恢复码解锁（换机/灾难恢复） -->
    <RecoveryUnlockDialog
      :show="recoveryUnlockOpen"
      :submitting="unlocking"
      :error="recoveryUnlockError"
      @submit="onRecoveryUnlockSubmit"
      @close="closeRecoveryUnlock"
    />

    <!-- 更新说明与强制更新入口：手动检查发现版本后展示；强制更新不可关闭 -->
    <UpdaterAvailableDialog
      v-model="updateDialogOpen"
      :current-version="availableUpdate?.currentVersion ?? ''"
      :version="availableUpdate?.version ?? ''"
      :notes="availableUpdate?.notes ?? ''"
      :force-update="availableUpdate?.forceUpdate ?? false"
      :installing="updateInstalling || updateFlowActive"
      :percent="updatePercent"
      :cancellable="updateCancellable"
      :error-message="updateDialogError"
      @install="onInstallUpdate"
      @cancel="onCancelUpdate"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, watch, defineAsyncComponent } from "vue";
import {
  lockAll,
  verthysReadyRef, globalKeyReadyRef, hasGlobalKeyRecordRef,
  initStatusRef, initDetailRef,
  hasModuleKeyRecordRef, moduleKeyReadyRef, moduleKeyEnabledRef, moduleHasRecoveryRef,
  MODULE_IDS, MODULE_LABELS,
  restoreSecurityPreset,
  sessionLockEnabledRef,
  securityHardeningFailedRef,
  checkInitStatus,
} from "../../lib/keyManager";
import {
  verthysPreheat,
  verthysPreflight,
  verthysPcrStatus,
  verthysKeyfileStatus,
  verthysKeyfileEnable,
  preloadWorker, workerDestroy,
} from "../../lib/verthys";
import { save } from "@tauri-apps/plugin-dialog";
import KeyEditDialog from "../dialogs/KeyEditDialog.vue";
import DisableVerifyDialog from "../dialogs/DisableVerifyDialog.vue";
import SecurePcrDialog from "../dialogs/SecurePcrDialog.vue";
import SecureKeyfileDialog from "../dialogs/SecureKeyfileDialog.vue";
import RecoveryCodeDialog from "../dialogs/RecoveryCodeDialog.vue";
import RecoveryUnlockDialog from "../dialogs/RecoveryUnlockDialog.vue";
import VerthysDialog from "../common/verthys-ui/VerthysDialog.vue";
import StatusRail from "../common/feedback/StatusRail.vue";
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
const UpdaterAvailableDialog = defineAsyncComponent(() => import("../dialogs/UpdaterAvailableDialog.vue"));
const VaultRotateDialog = defineAsyncComponent(() => import("../management/VaultRotateDialog.vue"));
import { useToastCenter } from "../../composables/useToastCenter";
import { useRecoveryNotices } from "../../composables/useRecoveryNotices";
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
import { updaterErrorMessage } from "../../lib/updater_error";

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

/* ===== 安全中心进度感知层（信号层 → 感知层 → 呈现层 的中间层） =====
 * 解锁/创建/验证/初始化/会话清理共用同一实例：业务层只推送真实阶段进度，
 * 本层统一负责平滑、软上限与成功收束，杜绝各流程各自实现节奏。 */
const progressRhythm = useVerifyRhythm();

/* ===== 解锁/创建逻辑 ===== */
const {
  verthysPath,
  unlocking,
  pendingIsCreate,
  keyfileCreateEnabled,
  unlockProgressMsg,
  unlockProgressPercent,
  unlockProgressElapsed,
  unlockProgressDone,
  pendingRecoveryCode,
  clearRecoveryCode,
  usbRebindPrompt,
  usbRebindSaving,
  openExistingVerthys,
  createNewVerthys,
  doUnlock,
  doRecoveryUnlock,
  confirmUsbRebind,
  cancelUsbRebind,
} = useUnlockFlow({
  isTauri,
  showError,
  showToast,
  checkDevice,
  rhythm: progressRhythm,
});

/* ===== 视图模式（五态严格互斥） =====
 *   无 "loading" 态：worker 解锁成功后进程内即时完成
 *   全局密钥记录探测，结果内联到 unlock 响应，前端零异步扫描阶段。
 *   解锁完成即确定 hasGlobalKeyRecord，直接进入 init 或 verify，无中间态。
 *   unlockInProgress 保持位：解锁/创建在收束补满 100% 前锁定解锁视图，
 *   避免底层状态先翻转导致进度条在收尾前被卸载（与 postInitAnim 同理）。 */
const { viewMode } = useViewMode({
  verthysReady: verthysReadyRef,
  hasGlobalKeyRecord: hasGlobalKeyRecordRef,
  globalKeyReady: globalKeyReadyRef,
  deviceCheckResult,
  postVerifyAnim,
  postInitAnim,
  unlockInProgress: unlocking,
});

/* ===== 恢复会话常驻入口（中枢内） =====
 * 状态源在全局 keyState：离开中枢不丢状态，重新进入管理界面即恢复入口；
 * 界面载体与处置动作仅在中枢管理界面提供，不保留跨模块全局浮层。 */
const {
  notices: recoveryNotices,
  rotateDialogOpen,
  rotateDialogMounted,
  onNoticeAction: onRecoveryNoticeAction,
  onRotateCommitted,
} = useRecoveryNotices();

/* ===== 选中路径是否已有容器 =====
 * 恢复码只对“已存在的容器”有意义：新建模式或目标文件不存在时，
 * 解锁页不得出现恢复码入口（否则会在初始化页展示无意义的恢复动作）。
 * 以 worker 预检 file_exists 为准；预检失败时退回初始化状态兜底，
 * 既不误藏既有库入口，也不会在新建模式下显示。 */
const selectedVaultExists = ref(false);
/** 预检失败标记：worker 尚未就绪时用初始化状态兜底，避免误藏恢复入口 */
const preflightFailed = ref(false);

watch(
  [verthysPath, pendingIsCreate] as const,
  async ([path, isCreate]) => {
    preflightFailed.value = false;
    if (!path || isCreate) {
      selectedVaultExists.value = false;
      return;
    }
    try {
      const preflight = await verthysPreflight(path);
      selectedVaultExists.value = preflight.ok === true && preflight.file_exists === true;
    } catch {
      selectedVaultExists.value = false;
      preflightFailed.value = true;
    }
  },
  { immediate: true },
);

/** 解锁页恢复码入口显示条件：已有容器且非新建。
 *  预检失败时退回 initStatus=ready（状态文件记录过既有库），仍不掩盖新建模式。 */
const canRecoverVault = computed(
  () =>
    !pendingIsCreate.value &&
    !!verthysPath.value &&
    (selectedVaultExists.value ||
      (preflightFailed.value && initStatusRef.value === 'ready')),
);

/* ===== 恢复码解锁弹层 =====
 * 恢复码只在提交时一次性传给 useUnlockFlow → initUnlock → Tauri → worker；
 * 失败文案不区分“恢复码错/槽缺失/TPM 状态”，避免泄露细分原因。 */
const recoveryUnlockOpen = ref(false);
const recoveryUnlockError = ref("");

const openRecoveryUnlock = () => {
  /* 恢复码解锁只属于 unlock 视图且必须已有容器；init/新建下不得出现 */
  if (viewMode.value !== 'unlock' || !canRecoverVault.value) return;
  recoveryUnlockError.value = "";
  recoveryUnlockOpen.value = true;
};

/** 视图一旦离开 unlock，强制关闭恢复解锁弹层（防止残留到初始化页面） */
watch(viewMode, (mode) => {
  if (mode === 'unlock') return;
  recoveryUnlockOpen.value = false;
  recoveryUnlockError.value = "";
});

const closeRecoveryUnlock = () => {
  if (unlocking.value) return;
  recoveryUnlockOpen.value = false;
  recoveryUnlockError.value = "";
};

const onRecoveryUnlockSubmit = async (code: string) => {
  recoveryUnlockError.value = "";
  const ok = await doRecoveryUnlock(verthysPath.value, code);
  if (ok) {
    recoveryUnlockOpen.value = false;
  } else {
    recoveryUnlockError.value = "恢复码无效或当前设备环境不可用";
  }
};

/* ===== 一次性恢复码统一展示 =====
 * 新建成功的恢复码与「设备与 PCR」轮换出的新码都交给此处的单一弹窗展示：
 *   1. 只有一个 RecoveryCodeDialog 实例，避免两处实例的 z-index/焦点冲突；
 *   2. 轮换码来自 ManagementView 事件，不依赖 GlobalKeySection 的 v-if 存续，
 *      切换分区不会丢失尚未抄写的新码；
 *   3. 弹窗关闭（确认或二次放弃）后统一清零，再放行被暂缓的高安全引导。 */
const rotatedRecoveryCode = ref<string | null>(null);
const securePromptDeferred = ref(false);

const activeRecoveryCode = computed<string | null>(
  () => pendingRecoveryCode.value ?? rotatedRecoveryCode.value,
);

const onRotatedRecovery = (code: string) => {
  rotatedRecoveryCode.value = code;
};

const onRecoveryCodeDialogClose = () => {
  clearRecoveryCode();
  rotatedRecoveryCode.value = null;
  if (securePromptDeferred.value) {
    securePromptDeferred.value = false;
    void handleSecurePresetApplied();
  }
};

/** 恢复码尚未抄写确认时，暂缓高安全引导，避免叠窗与“先要码后给码”的死锁 */
const deferWhileRecoveryCodeOpen = (): boolean => {
  if (activeRecoveryCode.value === null) return false;
  securePromptDeferred.value = true;
  return true;
};

/** 介质确认弹层显隐：仅允许关闭路径（确认动作走 @save → confirmUsbRebind） */
const onUsbRebindDialogToggle = (visible: boolean) => {
  if (!visible) cancelUsbRebind();
};

/* ===== 全局密钥管理 =====
 * 依赖注入：postVerifyAnim（useViewMode 读取 / onVerify 写入）
 *   + progressRhythm（安全中心统一进度感知层实例）
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
  verifyRhythm: progressRhythm,
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

/* ===== 模块独立密钥管理 ===== */
const {
  moduleStateClass,
  moduleStateText,
  showKeyDialog,
  editingModuleId,
  editingKeyValue,
  editingOldKeyValue,
  editingRecoveryCode,
  skipRecoveryBinding,
  keyDialogProcessing,
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
  onLogoutModule,
} = useModuleKeys({ showError, showToast });

/* ===== 动态防护状态（消费出口：verthys 就绪即拉取 + 60s 轮询） =====
 * 先于 usePreset 装配：defenseMeta 作为真实信号注入预设指标合成 */
const { defensePaths, defenseMeta } = useDefenseStatus();

/* ===== 系统运行指标（CPU 占用率真实采样，就绪期 2s 轮询） ===== */
const { cpuUsage } = useSystemMetrics(globalKeyReadyRef);

/* ===== 高安全预设默认第二因子引导 =====
 * 顺序：先 PCR[7,11]（现有设备校验），再 keyfile。两者都未启用时
 * 只弹一个，避免同时叠窗；PCR 提示只说明策略与恢复码前提，绑定本身
 * 仍在「设备与 PCR」面板中用当前恢复码完成。 */
const showSecurePcrDialog = ref(false);
/** 弹窗展示时的 PCR 绑定状态；null 表示读取失败，不假定未绑定 */
const securePcrEnabled = ref<boolean | null>(null);
const showSecureKeyfileDialog = ref(false);
const secureKeyfileBusy = ref(false);

/** 管理视图内部编排不对外写入：跨态跳转只经其公开的 openPcrBinding */
const managementViewRef = ref<{ openPcrBinding: () => void } | null>(null);

const maybePromptSecureKeyfile = async () => {
  if (deferWhileRecoveryCodeOpen()) return;
  try {
    const status = await verthysKeyfileStatus();
    if (status.ok && status.keyfile_enabled === true) return;
  } catch {
    // 状态读取失败仍提示用户手动确认，不静默假定已启用
  }
  showSecureKeyfileDialog.value = true;
};

const handleSecurePresetApplied = async () => {
  if (deferWhileRecoveryCodeOpen()) return;
  securePcrEnabled.value = null;
  try {
    const status = await verthysPcrStatus();
    if (status.ok) {
      securePcrEnabled.value =
        status.pcr_enabled === true ? true : status.pcr_enabled === false ? false : null;
      if (securePcrEnabled.value === true) {
        await maybePromptSecureKeyfile();
        return;
      }
    }
  } catch {
    // 状态读取失败仍提示用户手动确认，不静默假定已启用
  }
  showSecurePcrDialog.value = true;
};

/** PCR 提示关闭：继续检查 keyfile 引导 */
const onSecurePcrDialogClose = () => {
  showSecurePcrDialog.value = false;
  void maybePromptSecureKeyfile();
};

/** PCR 提示「前往」：直达设备与 PCR 面板，本次不再叠加 keyfile 引导 */
const onGotoSecurePcr = () => {
  showSecurePcrDialog.value = false;
  managementViewRef.value?.openPcrBinding();
};

/** 选择 .vkf 保存位置并启用 keyfile（使用本机保管的容器口令） */
const onConfirmSecureKeyfile = async () => {
  if (secureKeyfileBusy.value) return;
  secureKeyfileBusy.value = true;
  try {
    const target = await save({
      title: "保存 keyfile 文件",
      filters: [{ name: "Verthys keyfile", extensions: ["vkf"] }],
      defaultPath: "Verthys.keyfile.vkf",
    });
    if (!target) return; // 取消保存：保持弹窗，方便重新选择
    const path = target.toLowerCase().endsWith(".vkf") ? target : `${target}.vkf`;
    const resp = await verthysKeyfileEnable(path);
    if (!resp.ok) {
      showError("启用 keyfile 失败：请确认当前库已解锁且路径可写");
      return;
    }
    showSecureKeyfileDialog.value = false;
    showToast("已启用 keyfile 第二因子");
  } catch {
    showError("启用 keyfile 异常");
  } finally {
    secureKeyfileBusy.value = false;
  }
};

/* ===== 安全防护预设 ===== */
const {
  presetApplying,
  presetSyncFailed,
  currentPresetFeatures,
  customFeatures,
  customSessionMinutes,
  isCustomPreset,
  activeIdleMinutes,
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
  loadPresetConfig,
} = usePreset({
  showError,
  showToast,
  resetSession,
  cpuUsage,
  defenseMeta,
  onSecurePresetApplied: handleSecurePresetApplied,
});

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
  lastErrorCode: updateLastErrorCode,
  checkForUpdate,
  downloadUpdate,
  beginLock: beginUpdateLock,
  confirmLock: confirmUpdateLock,
  abortLock: abortUpdateLock,
  releaseCritical: releaseUpdaterCritical,
  installUpdate: installDownloadedUpdate,
  cancelUpdate,
} = useAppUpdater();

/** 下载进度百分比（0-100；总长未知时保持 0，端子只显示「正在更新…」） */
const updatePercent = computed(() => {
  if (updateTotalBytes.value <= 0) return 0;
  return Math.min(100, Math.round((updateDownloadedBytes.value / updateTotalBytes.value) * 100));
});

/** 安装流程互斥闸门：覆盖下载、锁库与安装全过程，防止重复点击并发启动安装器 */
const updateFlowActive = ref(false);

/** 用户取消意图：覆盖“准备尚未建立会话”的竞态，失败归因不误导为更新失败。 */
let updateCancelRequested = false;

/** 仅在下载完成前允许取消；锁库与安装移交一旦开始就不能打断。 */
const updateCancellable = computed(
  () => updateFlowActive.value && updatePercent.value < 100,
);

/** 更新说明窗口：手动检查时打开；强制更新由静默检查直接拉起。 */
const updateDialogOpen = ref(false);

/** 强制更新在发现的任意时刻都必须展示，普通更新只在手动检查后展示。 */
watch(
  availableUpdate,
  (update) => {
    if (!update) {
      updateDialogOpen.value = false;
      return;
    }
    if (update.forceUpdate) updateDialogOpen.value = true;
  },
  // 启动静默检查可能先于本组件挂载完成，强制更新必须在首帧可见。
  { immediate: true },
);

/** 窗口内错误只显示映射后的文案；取消是用户动作，不按错误呈现。 */
const updateDialogError = computed(() => {
  const code = updateLastErrorCode.value;
  if (!code || code === "E_UPDATER_CANCELLED") return "";
  return updaterErrorMessage(code);
});

/** 手动检查更新：区分「已是最新」与「检查失败」两种无更新结果 */
const onCheckUpdate = async () => {
  if (updateChecking.value || updateInstalling.value || updateFlowActive.value) return;
  const found = await checkForUpdate();
  if (found) {
    updateDialogOpen.value = true;
  } else if (updateLastErrorCode.value) {
    showError(`检查更新失败：${updaterErrorMessage(updateLastErrorCode.value)}`);
  } else {
    showToast("当前已是最新版本");
  }
};

/** 下载并安装更新：下载完成后先取挑战、锁库落盘，再兑换回执交给安装器 */
const onInstallUpdate = async () => {
  if (updateInstalling.value || updateFlowActive.value) return;
  updateFlowActive.value = true;
  updateCancelRequested = false;
  try {
    if (!availableUpdate.value) {
      const found = await checkForUpdate();
      if (!found) {
        if (updateLastErrorCode.value) {
          showError(`检查更新失败：${updaterErrorMessage(updateLastErrorCode.value)}`);
        } else {
          showToast("当前已是最新版本");
        }
        return;
      }
    }
    await downloadUpdate();
    const challenge = await beginUpdateLock();
    const lockOutcome = await lockAll();
    if (!lockOutcome.clean) {
      await abortUpdateLock();
      if (lockOutcome.dirty) {
        showError("部分数据可能未保存，已中止更新安装");
      } else if (!lockOutcome.flushed) {
        showError("数据落盘未完成，已中止更新安装");
      } else {
        showError("数据锁定状态无法确认，已中止更新安装");
      }
      return;
    }
    const receipt = await confirmUpdateLock(lockOutcome, challenge.challenge);
    await installDownloadedUpdate(receipt.receipt);
  } catch (e) {
    const code = (e as { code?: string } | null)?.code;
    if (updateCancelRequested || code === "E_UPDATER_CANCELLED") {
      showToast("已取消更新");
      return;
    }
    await abortUpdateLock();
    console.error("[updater] 更新安装失败", e);
    showError(`更新失败：${updaterErrorMessage(updateLastErrorCode.value)}`);
  } finally {
    /* 安装成功时进程由安装器接管退出，不会执行此处；失败或中止时释放闸门 */
    await releaseUpdaterCritical();
    updateFlowActive.value = false;
  }
};

/** 取消下载：Rust 侧中断传输并清理已接收字节。 */
const onCancelUpdate = async () => {
  if (!updateCancellable.value) return;
  updateCancelRequested = true;
  try {
    await cancelUpdate();
  } catch {
    // 锁库或安装移交阶段不接受取消，撤回意图并保持当前流程。
    updateCancelRequested = false;
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
  progressRhythm.start();
  unlockProgressMsg.value = "收敛当前会话";
  unlockProgressPercent.value = 0;
  unlockProgressElapsed.value = 0;
  // 阻止残留进度回调覆盖此消息（onUnlockProgress 守卫）
  unlockProgressDone.value = true;
  resetInitVerifyForm();
  // 锁定 verthys，重置所有状态 → viewMode 自动回到 "unlock"
  let sealed = false;
  try {
    const outcome = await lockAll((percent, message) => {
      unlockProgressPercent.value = percent;
      unlockProgressMsg.value = message;
      unlockProgressElapsed.value = Date.now() - lockStart;
      /* 终值由收束事件交付，避免 ACTIVE 期推送 100% 的协议异常 */
      if (percent < 100) progressRhythm.pushRealProgress(percent / 100);
    });
    if (!outcome.locked) {
      // 前置闸门失败（轮换仍在执行）：会话仍存活，不得回到解锁页
      showError("锁定未执行：安全核心仍在使用中，请稍后重试");
    } else if (outcome.dirty) {
      // 返回解锁页时也检查脏数据状态
      showError("部分数据可能未保存，请检查最近操作");
    } else if (!outcome.flushed) {
      showError("数据落盘未完成，请重启应用后确认数据完整");
    } else if (outcome.errors.length > 0) {
      showError("安全清理未完全确认，建议重启应用后重新解锁");
    }
    // 仅完全干净的清理才收束补满；其余走冻结降级，语义与结果一致
    if (outcome.locked && outcome.clean) {
      progressRhythm.seal();
      try {
        await progressRhythm.waitForComplete();
        sealed = true;
      } catch (e) {
        console.warn("[goBackToUnlock] 收束等待被中断，按已完成处理", e);
      }
    }
  } catch (e) {
    console.error("[goBackToUnlock] lockAll 异常", e);
  } finally {
    if (!sealed) progressRhythm.halt();
    unlocking.value = false;
    unlockProgressDone.value = false;
  }
};

/* ===== 立即锁定 ===== */
const onLockAll = async () => {
  const outcome = await lockAll();
  // lockAll 完成后检查会话是否真的销毁
  //    轮换收敛失败会整体放弃锁定（locked=false），此时会话与 GMK 仍存活
  //    落盘/清理超时可能标记 cacheDirty
  if (!outcome.locked) {
    showError("锁定未执行：安全核心仍在使用中，请稍后重试");
  } else if (outcome.dirty) {
    showError("部分数据可能未保存，请检查最近操作");
  } else if (!outcome.flushed) {
    showError("数据落盘未完成，请重启应用后确认数据完整");
  } else if (outcome.errors.length > 0) {
    showError("安全清理未完全确认，建议重启应用后重新解锁");
  } else {
    showToast("已锁定全部并清零内存密钥");
  }
};

/** 返回主页（通知父组件退出当前模块） */
const goBack = () => {
  emit("back");
};

/* ===== 挂载期后台预热延后 =====
 * 索引预读与 worker 子进程创建属于后台成本，不得与模块入场渲染争抢资源：
 * 进场即同步触发会加厚“点击 → 画面出现”这一帧的负担，形成停顿观感。
 * 两者都不是解锁的前置条件（解锁链路会自行确保 worker 就绪），因此推迟
 * 到入场收束后的空闲窗口执行；用户提前离开则取消，避免为已离开的模块
 * 启动后台任务。 */
const VAULT_WARM_IDLE_TIMEOUT_MS = 1200;
let vaultWarmIdleId: number | null = null;
let vaultWarmTimerId: number | null = null;

function cancelVaultWarm(): void {
  if (vaultWarmIdleId !== null) {
    window.cancelIdleCallback(vaultWarmIdleId);
    vaultWarmIdleId = null;
  }
  if (vaultWarmTimerId !== null) {
    window.clearTimeout(vaultWarmTimerId);
    vaultWarmTimerId = null;
  }
}

/** 入场收束后预热指定库：索引区预读 + worker 预启动 */
function scheduleVaultWarm(path: string): void {
  cancelVaultWarm();
  const run = () => {
    vaultWarmIdleId = null;
    vaultWarmTimerId = null;
    // 预热窗口内已解锁：worker 已在用，无须再预启动
    if (verthysReadyRef.value) return;
    // 第一层：索引区预读，与用户输入口令的时间重叠
    void verthysPreheat(path).catch((e) => {
      console.warn("[scheduleVaultWarm] 预热失败（不影响后续解锁）:", e);
    });
    // 第二层：预启动 worker 子进程
    void preloadWorker().catch((e) => {
      console.warn("[scheduleVaultWarm] worker 预启动失败:", e);
    });
  };
  if (typeof window.requestIdleCallback === "function") {
    vaultWarmIdleId = window.requestIdleCallback(run, { timeout: VAULT_WARM_IDLE_TIMEOUT_MS });
  } else {
    vaultWarmTimerId = window.setTimeout(run, 300);
  }
}

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
          // 索引预读与 worker 预启动延后到入场收束后（见 scheduleVaultWarm）：
          // 与用户输入口令的时间仍有重叠，但不占用模块进场帧
          scheduleVaultWarm(result.verthys_path);
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
      // 后端处于回滚失败状态：本次已按受信文件重新收敛，向用户可见告知
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
  // 取消尚未执行的后台预热，避免为已离开的模块启动索引预读/worker
  cancelVaultWarm();
  // 清理感知层动画帧调度（中断策略：取消调度并冻结状态）
  progressRhythm.dispose();
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
