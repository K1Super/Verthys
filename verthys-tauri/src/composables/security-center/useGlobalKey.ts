/**
 * useGlobalKey.ts — 全局密钥初始化/验证/修改/导出 Composable
 *
 * 来源：SecurityCenter.vue 原 L1000-L1007, L1030-L1072, L1081-L1140, L1196-L1256,
 *                 L1495-L1504, L1512-L1545, L1548-L1564, L1571-L1603, L1606-L1629
 *                 （零行为变更提取）
 *
 * 职责：
 *   1. 管理初始化/验证共享表单状态（initPassword / verifyPassword / binPassword
 *      / binFileName / binBytes / processing）
 *   2. 管理验证后强制动画标志（postVerifyAnim —— 注入式：由 SecurityCenter 顶层
 *      持有 Ref，useViewMode 读取、useGlobalKey.onVerify 写入，与 deviceCheckResult
 *      同构，避免 composable 间调用顺序耦合）
 *   3. 管理修改全局密钥弹窗状态（showChangeKeyDialog / changeKeyProcessing +
 *      旧/新密钥两组表单字段）
 *   4. 提供核心函数：
 *      - browseBin：选择 .bin 密钥文件（Tauri + 浏览器双路径，含错误反馈修复）
 *      - onInitKey：初始化全局密钥（含密码长度前置校验 + 设备绑定解耦）
 *      - onVerify：验证全局密钥（含进度回调 + 验证后动画）
 *      - browseOldBin / browseNewBin：修改密钥弹窗的旧/新 .bin 文件选择
 *      - onOpenChangeKeyDialog / onCloseChangeKeyDialog：弹窗打开/关闭
 *      - onConfirmChangeKey：确认修改全局密钥（细分错误码）
 *      - onExportBin：导出密钥文件入口（强制先验证全局密钥，拉起验证弹窗）
 *      - onCancelExportVerify / onConfirmExportVerify：
 *        导出验证弹窗两件套（取消 / 确认：选密钥文件 → 验证 → 另存为导出）
 *      - resetInitVerifyForm：复位初始化/验证表单（供 goBackToUnlock 调用）
 *
 * ★ 企业级根治（已内联，零行为变更）：
 *   - 静默返回 → 明确错误反馈（browseBin / onInitKey / onVerify 三处守卫拆分）
 *   - 客户端密码长度前置校验（TextEncoder UTF-8 字节长度，与后端严格一致）
 *   - 验证后 400ms 短动画（移除原 2s sleep，成功路径立即反馈）
 *   - 修改密钥细分错误码（E_GLOBAL_KEY_VERIFY_FAILED / E_GLOBAL_KEY_PERSIST_FAILED）
 *
 * 设计：纯 Composable，所有外部依赖通过参数注入，状态和方法返回给调用方。
 *      进度状态（unlockProgress*）由 useUnlockFlow 持有并注入，验证视图复用进度条。
 */

import { ref, type Ref } from 'vue';
import { open, save } from '@tauri-apps/plugin-dialog';
import {
  initGlobalKey,
  verifyGlobalKey,
  changeGlobalKey,
  bindDevice,
  translateVerthysError,
  VerthysErrorCode,
  type VerthysResult,
} from '../../lib/keyManager';
import {
  readUserFile,
  writeUserFile,
  type UnlockProgress,
} from '../../lib/verthys';
import { withFrontendTimeout } from './useUnlockFlow';

/**
 * useGlobalKey 选项
 * 所有外部依赖通过参数注入，保持 Composable 纯净可测试
 */
export interface UseGlobalKeyOptions {
  /** 是否处于 Tauri 环境（非浏览器模式） */
  isTauri: boolean;
  /** 显示错误提示（来自 useErrorToast） */
  showError: (msg: string) => void;
  /** 显示成功提示（来自 useErrorToast） */
  showToast: (msg: string) => void;
  /** 验证后强制动画标志（SecurityCenter 顶层持有，useViewMode 读取，onVerify 写入） */
  postVerifyAnim: Ref<boolean>;
  /** 解锁进度消息（来自 useUnlockFlow，验证视图复用进度条显示） */
  unlockProgressMsg: Ref<string>;
  /** 解锁进度百分比（来自 useUnlockFlow） */
  unlockProgressPercent: Ref<number>;
  /** 解锁进度累计耗时（来自 useUnlockFlow） */
  unlockProgressElapsed: Ref<number>;
}

/**
 * 全局密钥管理 Composable
 *
 * @param options 依赖注入
 * @returns 状态变量 + 核心函数
 *
 * @example
 * ```ts
 * const {
 *   initPassword, verifyPassword, binPassword, binFileName, binBytes, processing,
 *   showChangeKeyDialog, changeKeyProcessing,
 *   oldPassword, oldBinFileName, oldBinPassword,
 *   newPassword, newBinFileName, newBinPassword,
 *   browseBin, onInitKey, onVerify,
 *   onOpenChangeKeyDialog, onCloseChangeKeyDialog, onConfirmChangeKey,
 *   browseOldBin, browseNewBin, onExportBin, resetInitVerifyForm,
 * } = useGlobalKey({
 *   isTauri, showError, showToast,
 *   postVerifyAnim,
 *   unlockProgressMsg, unlockProgressPercent, unlockProgressElapsed,
 * });
 * ```
 */
export function useGlobalKey(options: UseGlobalKeyOptions) {
  /* ===== 初始化 / 验证共享状态 ===== */
  const initPassword = ref('');
  const verifyPassword = ref('');
  const binPassword = ref('');
  const binFileName = ref('');
  const binBytes = ref<Uint8Array | null>(null);
  const processing = ref(false);

  /* ===== 修改全局密钥弹窗状态 ===== */
  const showChangeKeyDialog = ref(false);
  const changeKeyProcessing = ref(false);
  const oldPassword = ref('');
  const oldBinFileName = ref('');
  const oldBinBytes = ref<Uint8Array | null>(null);
  const oldBinPassword = ref('');
  const newPassword = ref('');
  const newBinFileName = ref('');
  const newBinBytes = ref<Uint8Array | null>(null);
  const newBinPassword = ref('');

  /* ===== 选择 .bin 密钥文件（初始化/验证视图共用） ===== */
  const browseBin = async () => {
    if (!options.isTauri) {
      // 浏览器模式：使用 File API
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.bin,application/octet-stream';
      input.onchange = async () => {
        const f = input.files?.[0];
        if (f) {
          binFileName.value = f.name;
          const buf = await f.arrayBuffer();
          binBytes.value = new Uint8Array(buf);
        }
      };
      input.click();
      return;
    }
    try {
      const selected = await open({
        filters: [{ name: '密钥文件', extensions: ['bin'] }],
      });
      if (selected) {
        binFileName.value = (selected as string).split(/[\\/]/).pop() || 'key.bin';
        binBytes.value = await readUserFile(selected as string);
      }
    } catch (e) {
      // ★ 企业级修复：不再静默吞错（消除"按钮完全无反应"根因）
      //
      // 原缺陷：catch { /* */ } 静默吞掉 readUserFile 沙箱校验失败等错误。
      // binFileName 在 readUserFile 之前已设置，但 binBytes 因异常未设置。
      // 按钮 :disabled 用 !binFileName 判断（通过，可点击），但 onVerify/
      // onInitKey 函数守卫用 !binBytes.value 判断（失败，静默 return），
      // 用户看到"按钮完全无反应"——无加载动画、无错误提示、无任何反馈。
      //
      // 修复：显示错误提示 + 重置 binFileName/binBytes 保持 UI 状态一致，
      // 让用户明确知道文件读取失败而非按钮失灵。
      binFileName.value = '';
      binBytes.value = null;
      options.showError('密钥文件读取失败，请检查文件路径与权限');
      console.error('[browseBin] 读取密钥文件失败', e);
    }
  };

  /* ===== 初始化全局密钥 ===== */
  /**
   * ★ 设计约束：
   *   - initGlobalKey 返回 VerthysResult<void>
   *   - 设备绑定解耦：成功后显式调用 bindDevice(false)
   *     失败仅 Toast 提示，不阻塞主流程
   */
  const onInitKey = async () => {
    // 显式防重复：processing 期间拒绝再次触发
    if (processing.value) return;
    // ★ 企业级修复：静默返回改为明确错误反馈
    //
    // 原缺陷：守卫 `if (!initPassword || !binBytes || !binPassword || processing) return`
    // 在 binBytes 为 null 时静默返回。按钮 :disabled 用 !binFileName 判断，
    // 若 binFileName 已设置但 binBytes 因读取异常为 null，按钮可点击但函数
    // 静默返回，用户看到"按钮完全无反应"——无加载动画、无错误提示、无任何反馈。
    //
    // 修复：拆分守卫，binBytes 为 null 时显示错误提示并重置 binFileName，
    // 保持 UI 状态一致，让用户明确知道需要重新选择密钥文件。
    if (!initPassword.value || !binPassword.value) return;
    if (!binBytes.value) {
      options.showError('密钥文件未加载，请重新选择');
      binFileName.value = '';
      return;
    }
    // ★ 企业级根治：客户端密码长度前置校验
    //
    // 原缺陷：后端 validate_password_complexity 要求 ≥8 字节，但错误提示被
    // "禁止输出错误的具体信息"约束刻意模糊为"初始化失败"。用户不知 8 位下限，
    // 反复输入短密码均失败，误以为"无法初始化密钥"（日志三次密码复杂度校验失败）。
    //
    // 修复：提交前用 TextEncoder 精确计算 UTF-8 字节长度（与后端 password.len()
    // 严格一致），不足 8 字节直接顶部红色弹窗提示"访问密钥至少 8 位"。
    // 此为前置 UX 要求提示（非后端敏感错误披露），不违反模糊化约束。
    const initPwByteLen = new TextEncoder().encode(initPassword.value).length;
    if (initPwByteLen < 8) {
      options.showError('访问密钥至少 8 位');
      return;
    }
    processing.value = true;
    try {
      const result = await withFrontendTimeout(
        initGlobalKey(initPassword.value, binBytes.value!, binPassword.value),
        '初始化全局密钥',
      );
      if (result.ok) {
        initPassword.value = '';
        binPassword.value = '';
        binFileName.value = '';
        binBytes.value = null;
        options.showToast('全局安全密钥已初始化');
        // ★ 设备绑定解耦，由 UI 显式调用
        //    失败仅提示不阻塞主流程，用户可在设置中重新绑定
        const bindResult = await bindDevice(false);
        if (!bindResult.ok) {
          options.showError('设备绑定失败，可在设置中重新绑定');
        }
      } else {
        options.showError(translateVerthysError(result));
      }
    } catch (e) {
      console.error('[onInitKey] 异常', e);
      options.showError('初始化失败');
    } finally {
      processing.value = false;
    }
  };

  /* ===== 验证全局密钥 ===== */
  /**
   * ★ verifyGlobalKey 返回 VerthysResult<void>
   */
  const onVerify = async () => {
    // 显式防重复：processing 期间拒绝再次触发
    if (processing.value) return;
    // ★ 企业级修复：静默返回改为明确错误反馈（同 onInitKey 逻辑）
    //
    // 原缺陷：binBytes 为 null 时静默返回，用户看到"验证按钮完全无反应"。
    // 修复：binBytes 为 null 时显示错误提示并重置 binFileName。
    if (!verifyPassword.value || !binPassword.value) return;
    if (!binBytes.value) {
      options.showError('密钥文件未加载，请重新选择');
      binFileName.value = '';
      return;
    }
    processing.value = true;
    options.postVerifyAnim.value = true;

    // ★ 修复4：重置验证进度状态，与解锁进度条复用同一组响应式变量
    options.unlockProgressMsg.value = '准备验证';
    options.unlockProgressPercent.value = 0;
    options.unlockProgressElapsed.value = 0;

    // ★ 修复4：验证进度回调 — verifyGlobalKey 内部各阶段直接调用
    const onVerifyProgress = (p: UnlockProgress) => {
      options.unlockProgressMsg.value = p.message;
      options.unlockProgressPercent.value = p.percent;
      options.unlockProgressElapsed.value = p.elapsed_ms;
    };

    let result: VerthysResult<void> | null = null;
    let errored = false;
    try {
      result = await withFrontendTimeout(
        verifyGlobalKey(verifyPassword.value, binBytes.value!, binPassword.value, onVerifyProgress),
        '验证全局密钥',
      );
    } catch (e) {
      errored = true;
      console.error('[onVerify] 异常', e);
    }
    // ★ 修复5：移除强制 2s sleep — 成功路径立即反馈，失败路径保留 400ms 短动画
    //   原 2s sleep 在 40s 之上叠加无意义等待，严重恶化用户体验
    if (!result?.ok) {
      await new Promise<void>((r) => setTimeout(r, 400));
    }
    options.postVerifyAnim.value = false;
    processing.value = false;
    // 动画结束后展示结果
    if (result?.ok) {
      verifyPassword.value = '';
      binPassword.value = '';
      binFileName.value = '';
      binBytes.value = null;
      options.showToast('验证成功');
    } else {
      // ★ 结构化错误提示：translateVerthysError 处理 VerthysResult 失败分支
      const msg = result && !result.ok
        ? translateVerthysError(result)
        : (errored ? '验证失败，请重试' : '验证失败');
      options.showError(msg);
    }
  };

  /* ===== 修改全局密钥弹窗：旧/新 .bin 文件选择 ===== */
  /** 浏览旧 .bin 文件 */
  const browseOldBin = async () => {
    if (!options.isTauri) return;
    try {
      const selected = await open({
        filters: [{ name: 'BIN 密钥文件', extensions: ['bin'] }],
      });
      if (typeof selected !== 'string' || !selected) return;
      oldBinBytes.value = await readUserFile(selected);
      const parts = selected.replace(/\\/g, '/').split('/');
      oldBinFileName.value = parts[parts.length - 1];
    } catch (e) {
      console.error('[browseOldBin] 异常', e);
      options.showError('读取文件失败');
    }
  };

  /** 浏览新 .bin 文件 */
  const browseNewBin = async () => {
    if (!options.isTauri) return;
    try {
      const selected = await open({
        filters: [{ name: 'BIN 密钥文件', extensions: ['bin'] }],
      });
      if (typeof selected !== 'string' || !selected) return;
      newBinBytes.value = await readUserFile(selected);
      const parts = selected.replace(/\\/g, '/').split('/');
      newBinFileName.value = parts[parts.length - 1];
    } catch (e) {
      console.error('[browseNewBin] 异常', e);
      options.showError('读取文件失败');
    }
  };

  /** 打开修改全局密钥弹窗 */
  const onOpenChangeKeyDialog = () => {
    showChangeKeyDialog.value = true;
    oldPassword.value = '';
    oldBinFileName.value = '';
    oldBinBytes.value = null;
    oldBinPassword.value = '';
    newPassword.value = '';
    newBinFileName.value = '';
    newBinBytes.value = null;
    newBinPassword.value = '';
  };

  /** 关闭修改全局密钥弹窗 */
  const onCloseChangeKeyDialog = () => {
    if (changeKeyProcessing.value) return;
    showChangeKeyDialog.value = false;
  };

  /** 确认修改全局密钥
   *
   * ★ changeGlobalKey 返回 VerthysResult<void>
   *   细分错误码：旧密钥错误 vs 落盘失败，提供精确 UI 提示
   */
  const onConfirmChangeKey = async () => {
    if (!oldBinBytes.value || !newBinBytes.value) return;
    changeKeyProcessing.value = true;
    try {
      const result = await withFrontendTimeout(
        changeGlobalKey(
          oldPassword.value, oldBinBytes.value, oldBinPassword.value,
          newPassword.value, newBinBytes.value, newBinPassword.value,
        ),
        '修改全局密钥',
      );
      if (!result.ok) {
        // ★ 细分错误码：旧密钥错误 vs 落盘失败
        if (result.code === VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED) {
          options.showError('旧密钥验证失败，请检查');
        } else if (result.code === VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED) {
          options.showError('落盘失败，请重试');
        } else {
          options.showError(translateVerthysError(result));
        }
        return;
      }
      options.showToast('全局密钥修改成功');
      showChangeKeyDialog.value = false;
      // 清空敏感字段
      oldPassword.value = ''; oldBinFileName.value = ''; oldBinBytes.value = null; oldBinPassword.value = '';
      newPassword.value = ''; newBinFileName.value = ''; newBinBytes.value = null; newBinPassword.value = '';
    } catch (e) {
      options.showError(e instanceof Error ? e.message : String(e));
    } finally {
      changeKeyProcessing.value = false;
    }
  };

  /* ===== 导出密钥文件验证弹窗状态 =====
   * ★ 企业级根治：导出密钥文件属高敏感操作，必须先验证全局密钥。
   *   弹窗仅采集双要素凭据（访问密钥 + 密钥口令）— 密钥文件在确认后
   *   的导出流程中选择，验证与导出合一（文件一次选择，验证三要素
   *   完整不降级：访问密钥 + 密钥文件 + 密钥口令）。 */
  const showExportVerifyDialog = ref(false);
  const exportVerifyPassword = ref('');
  const exportVerifyBinPassword = ref('');
  const exportVerifyProcessing = ref(false);

  /** 导出验证弹窗 — 取消（清空全部敏感字段） */
  const onCancelExportVerify = () => {
    if (exportVerifyProcessing.value) return;
    showExportVerifyDialog.value = false;
    exportVerifyPassword.value = '';
    exportVerifyBinPassword.value = '';
  };

  /** 导出验证弹窗 — 确认（选择密钥文件 → 验证全局密钥 → 通过后另存为导出）
   * 密钥文件在本流程中选择（弹窗内无需选文件）：所选文件同时作为
   * 验证要素与导出源，杜绝旧流程"验证选一次 + 导出再选一次"的冗余。 */
  const onConfirmExportVerify = async () => {
    if (exportVerifyProcessing.value) return;
    if (!exportVerifyPassword.value || !exportVerifyBinPassword.value) return;
    exportVerifyProcessing.value = true;
    try {
      // 1. 选择源 .bin 密钥文件（同时是验证要素与导出源）
      const src = await open({
        filters: [{ name: 'BIN 密钥文件', extensions: ['bin'] }],
        multiple: false,
      });
      if (typeof src !== 'string' || !src) return; // 用户取消 → 静默中止
      let srcBytes: Uint8Array;
      try {
        srcBytes = await readUserFile(src);
      } catch (readErr) {
        console.error('[onConfirmExportVerify] 密钥文件读取失败', readErr);
        options.showError('密钥文件读取失败，请检查文件路径与权限');
        return;
      }

      // 2. 全局密钥验证（三要素完整：访问密钥 + 密钥文件 + 密钥口令）
      const result = await withFrontendTimeout(
        verifyGlobalKey(
          exportVerifyPassword.value,
          srcBytes,
          exportVerifyBinPassword.value,
        ),
        '验证全局密钥',
      );
      if (!result.ok) {
        options.showError(translateVerthysError(result));
        return;
      }

      // 3. 验证通过 → 关闭弹窗 + 立即清空敏感凭据 → 选择保存位置导出
      showExportVerifyDialog.value = false;
      exportVerifyPassword.value = '';
      exportVerifyBinPassword.value = '';

      // 保存位置（14位无规律随机文件名，每次不同，不暴露任何信息）
      const fileNameBytes = new Uint8Array(14);
      crypto.getRandomValues(fileNameBytes);
      const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
      let randomName = '';
      for (let i = 0; i < 14; i++) randomName += alphabet[fileNameBytes[i] % alphabet.length];
      const dst = await save({
        defaultPath: randomName + '.bin',
        filters: [{ name: 'BIN 密钥文件', extensions: ['bin'] }],
      });
      if (!dst) return; // 用户取消保存 → 已验证不缓存，下次导出需重新验证
      await writeUserFile(dst, srcBytes);
      options.showToast('已导出密钥文件备份');
    } catch (e) {
      console.error('[onConfirmExportVerify] 异常', e);
      options.showError('导出失败');
    } finally {
      exportVerifyProcessing.value = false;
    }
  };

  /** 导出密钥文件入口 — 强制先验证全局密钥（拉起验证弹窗，复用全局密钥窗口样式） */
  const onExportBin = () => {
    if (!options.isTauri) return;
    // 复位验证表单（每次导出均需重新验证，不缓存凭据）
    exportVerifyPassword.value = '';
    exportVerifyBinPassword.value = '';
    showExportVerifyDialog.value = true;
  };

  /** 复位初始化/验证表单（供 goBackToUnlock 调用，清空敏感字段） */
  const resetInitVerifyForm = () => {
    initPassword.value = '';
    verifyPassword.value = '';
    binPassword.value = '';
    binFileName.value = '';
    binBytes.value = null;
  };

  return {
    // 初始化/验证共享状态
    initPassword,
    verifyPassword,
    binPassword,
    binFileName,
    processing,
    // 修改全局密钥弹窗状态
    showChangeKeyDialog,
    changeKeyProcessing,
    oldPassword,
    oldBinFileName,
    oldBinPassword,
    newPassword,
    newBinFileName,
    newBinPassword,
    // 导出密钥文件验证弹窗状态
    showExportVerifyDialog,
    exportVerifyPassword,
    exportVerifyBinPassword,
    exportVerifyProcessing,
    // 核心函数
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
  };
}

/** useGlobalKey 返回值类型（便于显式标注） */
export type UseGlobalKeyReturn = ReturnType<typeof useGlobalKey>;
