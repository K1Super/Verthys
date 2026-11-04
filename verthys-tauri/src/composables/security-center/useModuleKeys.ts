/**
 * useModuleKeys.ts — 模块独立密钥管理 Composable
 *
 * 来源：SecurityCenter.vue 原 L1110-L1299（零行为变更提取）
 *
 * 职责：
 *   1. 模块状态指示条样式/文字计算（moduleStateClass / moduleStateText）
 *      —— 读取 keyManager 单例 ref：moduleKeyEnabledRef / hasModuleKeyRecordRef / moduleKeyReadyRef
 *   2. 密钥编辑弹窗状态（showKeyDialog / editingModuleId / editingKeyValue /
 *      editingOldKeyValue / keyDialogProcessing）
 *   3. 关闭密钥保护验证弹窗状态（showDisableVerifyDialog / disableVerifyModuleId /
 *      disableVerifyKey / disableVerifyProcessing）
 *   4. 提供核心函数：
 *      - onToggleModuleKeyEnabled：切换模块密钥保护开关（乐观更新 + 后台持久化）
 *      - onConfirmDisableVerify：关闭保护验证弹窗确认（验证原密钥 → 关闭保护）
 *      - onCancelDisableVerify：关闭保护验证弹窗取消（回滚 checkbox）
 *      - onOpenKeyDialog / onCloseKeyDialog：密钥编辑弹窗打开/关闭
 *      - onRandomKey：随机生成密钥并填入输入框
 *      - onConfirmKeyDialog：确认保存密钥（修改时需先验证原密钥）
 *      - onLogoutModule：登出模块（清除会话密钥缓存）
 *
 * 设计：
 *   - keyManager 单例 ref（moduleKeyEnabledRef / hasModuleKeyRecordRef / moduleKeyReadyRef /
 *     globalKeyReadyRef）直接从 keyManager 导入，与 SecurityCenter.vue 原实现一致
 *   - 外部依赖通过参数注入：showError / showToast / onCopyText（剪贴板工具，
 *     由 SecurityCenter 顶层持有，含 toast 反馈；未来可提取为 useClipboard）
 *   - 乐观更新策略：UI 立即响应，后台 v4 模块事务失败时回滚
 *
 * 返回契约（模块状态由 C 层 M1 承担）：
 *   - setModuleKey（启用/轮换口令）返回 VerthysResult<void>
 *   - verifyModuleKey（解锁 MDEK user 槽）返回 VerthysResult<void>
 *   - disableModuleProtection（关闭保护，需模块口令）返回 VerthysResult<void>
 *
 * 设计：纯 Composable，所有外部依赖通过参数注入，状态和方法返回给调用方。
 */

import { ref } from 'vue';
import {
  generateModuleKey,
  setModuleKey,
  hasModuleKey,
  isModuleReady,
  logoutModule,
  disableModuleProtection,
  verifyModuleKey,
  translateVerthysError,
  globalKeyReadyRef,
  hasModuleKeyRecordRef,
  moduleKeyReadyRef,
  moduleKeyEnabledRef,
  moduleHasRecoveryRef,
  MODULE_LABELS,
  touchSession,
  type ModuleId,
} from '../../lib/keyManager';

/**
 * useModuleKeys 选项
 * 所有外部依赖通过参数注入，保持 Composable 纯净可测试
 */
export interface UseModuleKeysOptions {
  /** 显示错误提示（来自全局 Toast 中心） */
  showError: (msg: string) => void;
  /** 显示成功提示（SecurityCenter 顶层注入，全局 Toast 中心状态通道，2.5s 自动消失） */
  showToast: (msg: string) => void;
}

/**
 * 模块独立密钥管理 Composable
 *
 * @param options 依赖注入
 * @returns 状态变量 + 核心函数
 *
 * @example
 * ```ts
 * const {
 *   moduleStateClass, moduleStateText,
 *   showKeyDialog, editingModuleId, editingKeyValue, editingOldKeyValue, keyDialogProcessing,
 *   showDisableVerifyDialog, disableVerifyModuleId, disableVerifyKey, disableVerifyProcessing,
 *   onToggleModuleKeyEnabled, onConfirmDisableVerify, onCancelDisableVerify,
 *   onOpenKeyDialog, onCloseKeyDialog, onRandomKey, onConfirmKeyDialog,
 *   onLogoutModule,
 * } = useModuleKeys({ showError, showToast });
 * ```
 */
export function useModuleKeys(options: UseModuleKeysOptions) {
  /* ===== 模块状态指示条样式/文字 =====
   * 状态语义（keyManager 单例 ref 实时读取）：
   *   - state-off：保护已关闭（enabled=false）
   *   - state-empty：保护已开启但未设置密钥（enabled=true, hasRecord=false）
   *   - state-active：已登录（enabled=true, hasRecord=true, ready=true）
   *   - state-set：已设置未登录（enabled=true, hasRecord=true, ready=false） */
  /** 模块状态指示条样式类 */
  const moduleStateClass = (mid: ModuleId): string => {
    if (!moduleKeyEnabledRef.value[mid]) return "state-off";
    if (!hasModuleKeyRecordRef.value[mid]) return "state-empty";
    if (moduleKeyReadyRef.value[mid]) return "state-active";
    return "state-set";
  };
  /** 模块状态指示条文字 */
  const moduleStateText = (mid: ModuleId): string => {
    if (!moduleKeyEnabledRef.value[mid]) return "保护已关闭";
    if (!hasModuleKeyRecordRef.value[mid]) return "未设置";
    /* 恢复槽决定该模块能否换机恢复：未绑定时必须显式提示，避免用户
     * 在换机后才发现模块数据无法随容器迁移。 */
    const recovery = moduleHasRecoveryRef.value[mid] ? " · 恢复槽" : " · 无恢复槽";
    if (moduleKeyReadyRef.value[mid]) return `已登录 · 256-bit${recovery}`;
    return `已设置 · 256-bit${recovery}`;
  };

  /* ===== 密钥编辑弹窗状态 ===== */
  const showKeyDialog = ref(false);
  const editingModuleId = ref<ModuleId>("photo");
  const editingKeyValue = ref("");
  const editingOldKeyValue = ref(""); // 修改密钥时验证原密钥
  /** 首次启用时用于绑定模块恢复槽的当前容器恢复码（成功后立即清空） */
  const editingRecoveryCode = ref("");
  /** 显式放弃恢复槽绑定（默认 false：默认覆盖，换机不可恢复需用户主动确认） */
  const skipRecoveryBinding = ref(false);
  const keyDialogProcessing = ref(false);

  /* ===== 待启用模块（前置密钥校验流程状态） =====
   * 修复：开启模块保护前必须先设置该模块独立密钥。
   *   未设置密钥时点击开关 → 拉起密钥设置弹窗并记录 pendingEnableModuleId；
   *   密钥设置成功 → 自动开启该模块保护（持久化，失败回滚）；
   *   中途退出（取消/遮罩关闭）→ 保护保持关闭，checkbox 回滚为关闭态。 */
  const pendingEnableModuleId = ref<ModuleId | null>(null);

  /* ===== 关闭密钥保护验证弹窗状态 ===== */
  const showDisableVerifyDialog = ref(false);
  const disableVerifyModuleId = ref<ModuleId>("photo");
  const disableVerifyKey = ref("");
  const disableVerifyProcessing = ref(false);
  /** 关闭保护验证代际：取消/切换目标即作废在途验证结果
   *  （用户在验证途中取消后，验证成功不得仍关闭保护）。 */
  let disableVerifySeq = 0;

  /* ===== 切换模块密钥保护开关（乐观更新 — 立即响应，后台持久化） =====
   *
   * 流程（v4）：开启保护已由 setModuleKey → v4_module_enable 完成；
   * 此处只维护开关显示，不产生额外后端写入。
   *
   * 流程：
   *   1. 全局密钥未就绪 → 直接返回（防御性守卫）
   *   2. 前置密钥校验：开启保护但该模块尚未设置密钥 →
   *      恢复 checkbox 关闭态 + 拉起密钥设置弹窗（pending 待启用流程）
   *   3. 关闭保护且模块已有密钥 → 强制恢复 checkbox 开启 + 打开验证弹窗（等待确认）
   *   4. 开启保护（已有密钥）/ 关闭无密钥模块 → 乐观更新 UI + 后台持久化（失败回滚）
   */
  const onToggleModuleKeyEnabled = async (mid: ModuleId, enabled: boolean) => {
    if (!globalKeyReadyRef.value) return;
    // 前置密钥校验：开启保护前必须先设置该模块独立密钥
    if (enabled && !hasModuleKey(mid)) {
      // 恢复 checkbox 关闭状态（密钥未设置前不改变保护状态）
      moduleKeyEnabledRef.value = { ...moduleKeyEnabledRef.value, [mid]: false };
      // 拉起密钥设置弹窗，记录待启用模块
      pendingEnableModuleId.value = mid;
      editingModuleId.value = mid;
      editingKeyValue.value = "";
      editingOldKeyValue.value = "";
      editingRecoveryCode.value = "";
      skipRecoveryBinding.value = false;
      showKeyDialog.value = true;
      options.showToast(`请先设置 ${MODULE_LABELS[mid]} 独立密钥`);
      return; // 等待密钥设置完成
    }
    // 关闭保护时需验证原独立密钥
    if (!enabled && hasModuleKey(mid)) {
      // 强制恢复 checkbox 开启状态（验证通过前不改变保护状态）
      moduleKeyEnabledRef.value = { ...moduleKeyEnabledRef.value, [mid]: true };
      disableVerifySeq += 1;
      disableVerifyModuleId.value = mid;
      disableVerifyKey.value = "";
      showDisableVerifyDialog.value = true;
      return; // 等待验证弹窗确认
    }
    /* 开启保护：v4 语义下"已设置口令"与"保护已启用"是同一状态，
     * 走到这里说明保护已经开启，开关本身不会产生新的后端写入。
     * 关闭保护必须经口令验证弹窗（上方分支），不在此处直接执行。 */
    moduleKeyEnabledRef.value = { ...moduleKeyEnabledRef.value, [mid]: enabled };
    options.showToast(`${MODULE_LABELS[mid]} 密钥保护${enabled ? "已开启" : "已关闭"}`);
  };

  /* ===== 关闭密钥保护验证弹窗 — 确认 =====
   *
   * 流程：口令一次性交给 C 层 `v4_module_disable`（口令正确性由 C 层判定），
   * 成功后 MDEK 回到 Keyring、数据保留；失败保持弹窗开启。
   */
  const onConfirmDisableVerify = async () => {
    if (!disableVerifyKey.value || disableVerifyProcessing.value) return;
    const seq = disableVerifySeq;
    disableVerifyProcessing.value = true;
    try {
      const mid = disableVerifyModuleId.value;
      const result = await disableModuleProtection(mid, disableVerifyKey.value);
      /* 代际仲裁：验证在途期间用户已取消 / 切换目标 / 弹窗已关闭 →
       * 本次结果作废，绝不因「验证成功」而违背用户取消意愿去关闭保护。 */
      if (seq !== disableVerifySeq || !showDisableVerifyDialog.value) return;
      if (!result.ok) {
        options.showError(translateVerthysError(result));
        return;
      }
      moduleKeyEnabledRef.value = { ...moduleKeyEnabledRef.value, [mid]: false };
      options.showToast(`${MODULE_LABELS[mid]} 密钥保护已关闭`);
      showDisableVerifyDialog.value = false;
      disableVerifyKey.value = "";
      touchSession();
    } catch {
      options.showError("验证异常");
    } finally {
      disableVerifyProcessing.value = false;
    }
  };

  /** 关闭密钥保护验证弹窗 — 取消
   *  处理中禁止取消（弹窗侧同步禁用取消/遮罩关闭）：在途验证结果一旦在
   *  用户取消后落地关闭保护，属未经确认的安全降级。 */
  const onCancelDisableVerify = () => {
    if (disableVerifyProcessing.value) return;
    disableVerifySeq += 1;
    showDisableVerifyDialog.value = false;
    disableVerifyKey.value = "";
    // 回滚 checkbox 状态
    moduleKeyEnabledRef.value = { ...moduleKeyEnabledRef.value, [disableVerifyModuleId.value]: true };
  };

  /** 打开密钥编辑弹窗 */
  const onOpenKeyDialog = (mid: ModuleId) => {
    if (!globalKeyReadyRef.value || !moduleKeyEnabledRef.value[mid]) return;
    // 防御性边界：若存在进行中的待启用流程且切换到其他模块编辑，中止该流程
    //   （保护保持关闭，checkbox 回滚为关闭态，避免悬空的 pending 状态）
    if (pendingEnableModuleId.value !== null && pendingEnableModuleId.value !== mid) {
      moduleKeyEnabledRef.value = { ...moduleKeyEnabledRef.value, [pendingEnableModuleId.value]: false };
      pendingEnableModuleId.value = null;
    }
    editingModuleId.value = mid;
    editingKeyValue.value = "";
    editingOldKeyValue.value = "";
    editingRecoveryCode.value = "";
    skipRecoveryBinding.value = false;
    showKeyDialog.value = true;
  };

  /** 关闭密钥编辑弹窗
   * 处理中禁止关闭（写入在途时关闭会让已提交的写入失去落点提示）
   * 中途退出处理：若处于「待启用」流程（开启保护触发的密钥设置），
   *   中止流程 → 保护保持关闭，checkbox 回滚为关闭态（UI 与状态一致） */
  const onCloseKeyDialog = () => {
    if (keyDialogProcessing.value) return;
    if (pendingEnableModuleId.value !== null) {
      moduleKeyEnabledRef.value = { ...moduleKeyEnabledRef.value, [pendingEnableModuleId.value]: false };
      pendingEnableModuleId.value = null;
    }
    showKeyDialog.value = false;
    editingKeyValue.value = "";
    editingOldKeyValue.value = "";
    editingRecoveryCode.value = "";
    skipRecoveryBinding.value = false;
  };

  /** 随机生成密钥并填入输入框 */
  const onRandomKey = () => {
    editingKeyValue.value = generateModuleKey();
  };

  /* ===== 确认保存密钥（修改时需先验证原密钥） =====
   *
   * 返回契约：
   *   - verifyModuleKey 返回 VerthysResult<void>
   *   - setModuleKey 返回 VerthysResult<void>
   *
   * 流程：
 *   1. 修改模式（hasModuleKey=true）→ 先验证原独立密钥
   *   2. 验证通过（或生成模式）→ 保存新密钥
   *   3. 成功 → 关闭弹窗 + 清空表单 + toast 反馈
   *   4. 待启用流程（pendingEnableModuleId 命中）→ 自动开启该模块密钥保护
   *      （乐观更新 UI + 后台持久化，持久化失败回滚为关闭态）
   */
  const onConfirmKeyDialog = async () => {
    if (!editingKeyValue.value || keyDialogProcessing.value) return;
    keyDialogProcessing.value = true;
    try {
      const mid = editingModuleId.value;
      // 保存前捕获模式（保存成功后 hasModuleKey 恒为 true，事后判断恒为「修改」）
      const isModify = hasModuleKey(mid);
      /* 首次启用默认绑定恢复槽：未显式跳过时必须提供当前容器恢复码，
       * 否则换机后该模块 MDEK 无法随容器恢复。 */
      if (!isModify && !skipRecoveryBinding.value && !editingRecoveryCode.value.trim()) {
        options.showError("请粘贴当前恢复码以绑定模块恢复槽，或显式选择暂不绑定");
        keyDialogProcessing.value = false;
        return;
      }
      // 修改模式：先验证原独立密钥
      if (isModify) {
        if (!editingOldKeyValue.value) {
          options.showError("请输入原独立密钥");
          keyDialogProcessing.value = false;
          return;
        }
        const verifyResult = await verifyModuleKey(mid, editingOldKeyValue.value);
        if (!verifyResult.ok) {
          options.showError(translateVerthysError(verifyResult));
          keyDialogProcessing.value = false;
          return;
        }
      }
      /* 验证通过（或首次设置）→ 保存口令。
       * 修改模式必须把原口令一并交给 C 层重封 user 槽（只重封，不重写数据）。 */
      const recoveryCode = !isModify && !skipRecoveryBinding.value
        ? editingRecoveryCode.value.trim()
        : undefined;
      const result = await setModuleKey(
        mid,
        editingKeyValue.value,
        isModify ? editingOldKeyValue.value : undefined,
        recoveryCode,
      );
      if (result.ok) {
        touchSession();
        // 待启用流程判定：启用成功 → 保护随口令设置一并生效
        const pendingEnable = pendingEnableModuleId.value === mid;
        pendingEnableModuleId.value = null;
        showKeyDialog.value = false;
        editingKeyValue.value = "";
        editingOldKeyValue.value = "";
        editingRecoveryCode.value = "";
        skipRecoveryBinding.value = false;
        if (pendingEnable) {
          moduleKeyEnabledRef.value = { ...moduleKeyEnabledRef.value, [mid]: true };
          options.showToast(`${MODULE_LABELS[mid]} 独立密钥已${isModify ? "修改" : "生成"}，密钥保护已开启`);
        } else {
          options.showToast(`${MODULE_LABELS[mid]} 独立密钥已${isModify ? "修改" : "生成"}`);
        }
      } else {
        options.showError(translateVerthysError(result));
      }
    } catch {
      options.showError("保存异常");
    } finally {
      keyDialogProcessing.value = false;
    }
  };

  /** 登出模块（清除会话密钥缓存） */
  const onLogoutModule = (mid: ModuleId) => {
    logoutModule(mid);
    options.showToast(`${MODULE_LABELS[mid]} 已登出`);
  };

  return {
    // 模块状态计算
    moduleStateClass,
    moduleStateText,
    // 密钥编辑弹窗状态
    showKeyDialog,
    editingModuleId,
    editingKeyValue,
    editingOldKeyValue,
    editingRecoveryCode,
    skipRecoveryBinding,
    keyDialogProcessing,
    // 待启用模块（前置密钥校验流程状态）
    pendingEnableModuleId,
    // 关闭保护验证弹窗状态
    showDisableVerifyDialog,
    disableVerifyModuleId,
    disableVerifyKey,
    disableVerifyProcessing,
    // 核心函数
    onToggleModuleKeyEnabled,
    onConfirmDisableVerify,
    onCancelDisableVerify,
    onOpenKeyDialog,
    onCloseKeyDialog,
    onRandomKey,
    onConfirmKeyDialog,
    onLogoutModule,
  };
}

/** useModuleKeys 返回值类型（便于显式标注） */
export type UseModuleKeysReturn = ReturnType<typeof useModuleKeys>;
