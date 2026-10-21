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
 * 修复（已内联，零行为变更）：
 *   - 静默返回 → 明确错误反馈（browseBin / onInitKey / onVerify 三处守卫拆分）
 *   - 客户端密码长度前置校验（TextEncoder UTF-8 字节长度，与后端严格一致）
 *   - 验证进度由感知层（VerifyRhythm）驱动：成功路径等待收束完成事件后
 *     再切换视图，失败路径按感知层配置的错误最小展示时长保留冻结降级态，
 *     业务层零动画时长硬编码
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
  globalKeyReadyRef,
  hasGlobalKeyRecordRef,
  globalKeyRecordIdRef,
  VerthysErrorCode,
  type VerthysResult,
} from '../../lib/keyManager';
import {
  readUserFile,
  writeUserFile,
  type UnlockProgress,
} from '../../lib/verthys';
import { withFrontendTimeout } from './useUnlockFlow';
import type { VerifyRhythm } from './useVerifyRhythm';

/* ===== 前端超时矩阵（最后防线） =====
 * 均严格大于内部单步上界（INIT_TIMEOUT_MS 30s / derive_verify 15s），
 * 避免前端先于后端收口 —— 否则会出现「前端报超时、后端仍在跑」的
 * 假失败与状态错配。超时后一律回查权威状态，不直接断言失败。 */
export const INIT_KEY_FRONTEND_TIMEOUT_MS = 90 * 1000;
export const VERIFY_KEY_FRONTEND_TIMEOUT_MS = 90 * 1000;
export const CHANGE_KEY_FRONTEND_TIMEOUT_MS = 150 * 1000;
export const EXPORT_VERIFY_FRONTEND_TIMEOUT_MS = 90 * 1000;

/** .bin 密钥文件字节上限（密钥文件为小体积记录，超限拒绝读取） */
export const MAX_BIN_FILE_BYTES = 64 * 1024;

/** 密钥文件读取前端超时（后端 read_user_file 自身 10s 超时） */
const BIN_READ_TIMEOUT_MS = 15 * 1000;

/** 判定是否为前端兜底超时（与 withFrontendTimeout 的文案契约一致） */
const isFrontendTimeout = (e: unknown): boolean =>
  e instanceof Error && e.message.includes('前端超时');

/** 清零敏感字节（成功/关闭/卸载路径统一调用，降低内存驻留窗口） */
const zeroBytes = (bytes: Uint8Array | null): void => {
  if (bytes && typeof bytes.fill === 'function') bytes.fill(0);
};

/** 读取 .bin 密钥文件：大小上限 + 前端超时 + 统一错误语义 */
const readBinBytes = async (path: string): Promise<Uint8Array> => {
  const bytes = await withFrontendTimeout(
    readUserFile(path),
    '读取密钥文件',
    BIN_READ_TIMEOUT_MS,
  );
  if (bytes.byteLength > MAX_BIN_FILE_BYTES) {
    zeroBytes(bytes);
    throw new Error('密钥文件超出大小上限（64 KiB），请选择正确的 .bin 文件');
  }
  return bytes;
};

/** 生成无取模偏差的随机导出文件名（拒绝采样，36 进制等概率） */
const randomExportFileName = (): string => {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const length = 14;
  // 拒绝采样阈值：256 - (256 % 36) = 252，落在阈值外的字节直接丢弃
  const limit = 256 - (256 % alphabet.length);
  let name = '';
  while (name.length < length) {
    const buf = new Uint8Array(length - name.length + 8);
    crypto.getRandomValues(buf);
    for (const b of buf) {
      if (b >= limit) continue;
      name += alphabet[b % alphabet.length];
      if (name.length === length) break;
    }
  }
  return name;
};

/**
 * useGlobalKey 选项
 * 所有外部依赖通过参数注入，保持 Composable 纯净可测试
 */
export interface UseGlobalKeyOptions {
  /** 是否处于 Tauri 环境（非浏览器模式） */
  isTauri: boolean;
  /** 显示错误提示（来自全局 Toast 中心） */
  showError: (msg: string) => void;
  /** 显示成功提示（来自全局 Toast 中心） */
  showToast: (msg: string) => void;
  /** 验证后强制动画标志（SecurityCenter 顶层持有，useViewMode 读取，onVerify 写入） */
  postVerifyAnim: Ref<boolean>;
  /** 初始化后强制动画标志（SecurityCenter 顶层持有，useViewMode 读取，onInitKey 写入） */
  postInitAnim: Ref<boolean>;
  /** 验证进度感知层（注入：信号订阅 + 收束完成事件驱动视图切换） */
  verifyRhythm: VerifyRhythm;
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
  isTauri, showError, showToast,
  postVerifyAnim,
  verifyRhythm,
  unlockProgressMsg, unlockProgressPercent, unlockProgressElapsed,
});
```
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
      // 浏览器模式：使用 File API（同样受大小上限与错误反馈约束）
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.bin,application/octet-stream';
      input.onchange = async () => {
        const f = input.files?.[0];
        if (!f) return;
        if (f.size > MAX_BIN_FILE_BYTES) {
          binFileName.value = '';
          zeroBytes(binBytes.value);
          binBytes.value = null;
          options.showError('密钥文件超出大小上限（64 KiB），请选择正确的 .bin 文件');
          return;
        }
        try {
          binFileName.value = f.name;
          const buf = await f.arrayBuffer();
          zeroBytes(binBytes.value);
          binBytes.value = new Uint8Array(buf);
        } catch (e) {
          binFileName.value = '';
          binBytes.value = null;
          options.showError('密钥文件读取失败，请检查文件路径与权限');
          console.error('[browseBin] 浏览器模式读取失败', e);
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
        const next = await readBinBytes(selected as string);
        zeroBytes(binBytes.value);
        binBytes.value = next;
      }
    } catch (e) {
      // 修复：不再静默吞错（消除"按钮完全无反应"根因）
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
      zeroBytes(binBytes.value);
      binBytes.value = null;
      options.showError(
        e instanceof Error && e.message.includes('大小上限')
          ? e.message
          : '密钥文件读取失败，请检查文件路径与权限',
      );
      console.error('[browseBin] 读取密钥文件失败', e);
    }
  };

  /**
   * 提交前置校验失败的统一呈现：先跑完进度与加载收束，再给出结果。
   *
   * 与提交路径同构 —— 点击提交后一律先走完整段进度/加载编排，
   * 不在动画开始前抢先把结果落地（避免「点击即报错」的观感断裂）。
   *
   * @param keepView 对应视图的收束保持位（初始化传 postInitAnim、
   *   验证传 postVerifyAnim），使视图在收束期间不被状态翻转抢跳。
   */
  const presentPreCheckError = async (
    message: string,
    keepView: Ref<boolean>,
  ): Promise<void> => {
    processing.value = true;
    keepView.value = true;
    options.verifyRhythm.start();
    options.verifyRhythm.seal();
    try {
      await options.verifyRhythm.waitForComplete();
    } catch (e) {
      console.warn('[pre-check] 收束等待被中断，按已完成处理', e);
    }
    keepView.value = false;
    processing.value = false;
    options.showError(message);
  };

  /* ===== 初始化全局密钥 ===== */
  /**
   * 设计约束：
   *   - initGlobalKey 返回 VerthysResult<void>
   *   - 设备绑定解耦：成功后显式调用 bindDevice(false)
   *     失败仅 Toast 提示，不阻塞主流程
   */
  const onInitKey = async () => {
    // 显式防重复：processing 期间拒绝再次触发
    if (processing.value) return;
    // 修复：静默返回改为明确错误反馈
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
      binFileName.value = '';
      await presentPreCheckError('密钥文件未加载，请重新选择', options.postInitAnim);
      return;
    }
    // 修复：客户端密码长度前置校验
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
      await presentPreCheckError('访问密钥至少 8 位', options.postInitAnim);
      return;
    }
    processing.value = true;
    options.postInitAnim.value = true;

    // 进度接入（与验证视图同构复用同一感知层）：
    //   信号层 = initGlobalKey 的阶段 emit（真实进度）；
    //   感知层 = verifyRhythm（平滑吸收，视图切换由收束事件驱动）；
    //   呈现层 = InitKeyView 的 QuantumProgressFlow（绑定视觉值）。
    options.unlockProgressMsg.value = '准备初始化';
    options.unlockProgressPercent.value = 0;
    options.unlockProgressElapsed.value = 0;
    options.verifyRhythm.start();

    const onInitProgress = (p: UnlockProgress) => {
      options.unlockProgressMsg.value = p.message;
      options.unlockProgressPercent.value = p.percent;
      options.unlockProgressElapsed.value = p.elapsed_ms;
      options.verifyRhythm.pushRealProgress(p.percent / 100);
    };

    let result: VerthysResult<void> | null = null;
    let errored = false;
    let timedOut = false;
    try {
      result = await withFrontendTimeout(
        initGlobalKey(initPassword.value, binBytes.value!, binPassword.value, onInitProgress),
        '初始化全局密钥',
        INIT_KEY_FRONTEND_TIMEOUT_MS,
      );
    } catch (e) {
      errored = true;
      timedOut = isFrontendTimeout(e);
      console.error('[onInitKey] 异常', e);
    }

    // 超时回查权威状态：初始化成功的唯一判据是「记录已存在且 GMK 就绪」。
    // 前端兜底超时不等于后端失败（后端可能仍在跑或已成功），禁止直接断言失败。
    const recovered = timedOut
      && !result?.ok
      && hasGlobalKeyRecordRef.value
      && globalKeyReadyRef.value;

    if (result?.ok || recovered) {
      // 成功：收束补满 100% 后释放视图（与验证成功路径同构）
      options.verifyRhythm.seal();
      try {
        await options.verifyRhythm.waitForComplete();
      } catch (e) {
        console.warn('[onInitKey] 收束等待被中断，按已完成处理', e);
      }
      initPassword.value = '';
      binPassword.value = '';
      binFileName.value = '';
      zeroBytes(binBytes.value);
      binBytes.value = null;
      options.showToast('全局安全密钥已初始化');
      // 设备绑定解耦，由 UI 显式调用
      //    失败仅提示不阻塞主流程，用户可在设置中重新绑定；
      //    bindDevice 无内部超时，此处以 15s 前端兜底防止按钮永久 pending
      try {
        const bindResult = await withFrontendTimeout(bindDevice(), '绑定设备', 15 * 1000);
        if (!bindResult.ok) {
          options.showError('设备绑定失败，可在设置中重新绑定');
        }
      } catch (e) {
        console.warn('[onInitKey] 设备绑定超时/异常', e);
        options.showError('设备绑定超时，可在设置中重新绑定');
      }
    } else {
      /* 失败：与 onVerify 同构 —— 先跑完进度收束再呈现结果
       * （不以冻结/降级打断编排，结果不抢先落地） */
      options.verifyRhythm.seal();
      try {
        await options.verifyRhythm.waitForComplete();
      } catch (e) {
        console.warn('[onInitKey] 收束等待被中断，按已完成处理', e);
      }
      const msg = result && !result.ok
        ? translateVerthysError(result)
        : timedOut
          ? '初始化超时，结果未确认：请重启应用后确认密钥状态'
          : (errored ? '初始化失败，请重试' : '初始化失败');
      options.showError(msg);
    }
    options.postInitAnim.value = false;
    processing.value = false;
  };

  /* ===== 验证全局密钥 ===== */
  /**
   * verifyGlobalKey 返回 VerthysResult<void>
   *
   * 感知层协作契约（无固定延时，时长全部由感知层配置源决定）：
   *   - 启动：reset/start 感知层，开启一轮假进度节奏
   *   - 进行：真实进度推送给感知层，由它吸收平滑为视觉值
   *   - 成功：seal 指令 → await waitForComplete()（收束完成事件），
   *     完成后再复位 postVerifyAnim 切视图
   *   - 失败：halt 指令（冻结 + 降级）→ showError 淡入覆盖 →
   *     await waitForHaltMin()（错误最小展示时长）
   */
  const onVerify = async () => {
    // 显式防重复：processing 期间拒绝再次触发
    if (processing.value) return;
    // 修复：静默返回改为明确错误反馈（同 onInitKey 逻辑）
    //
    // 原缺陷：binBytes 为 null 时静默返回，用户看到"验证按钮完全无反应"。
    // 修复：binBytes 为 null 时显示错误提示并重置 binFileName。
    if (!verifyPassword.value || !binPassword.value) return;
    if (!binBytes.value) {
      binFileName.value = '';
      await presentPreCheckError('密钥文件未加载，请重新选择', options.postVerifyAnim);
      return;
    }
    processing.value = true;
    options.postVerifyAnim.value = true;

    // 重置真实进度信号状态（解锁进度条与验证共享同一组响应式变量）
    options.unlockProgressMsg.value = '准备验证';
    options.unlockProgressPercent.value = 0;
    options.unlockProgressElapsed.value = 0;

    // 感知层开启新一轮验证（失败重试场景自 HALTED 复位）
    options.verifyRhythm.start();

    // 验证进度回调 — verifyGlobalKey 内部各阶段直接调用
    const onVerifyProgress = (p: UnlockProgress) => {
      options.unlockProgressMsg.value = p.message;
      options.unlockProgressPercent.value = p.percent;
      options.unlockProgressElapsed.value = p.elapsed_ms;
      // 真实进度作为信号推送感知层（0-1），呈现层只消费感知层视觉值
      options.verifyRhythm.pushRealProgress(p.percent / 100);
    };

    let result: VerthysResult<void> | null = null;
    let errored = false;
    let timedOut = false;
    try {
      result = await withFrontendTimeout(
        verifyGlobalKey(verifyPassword.value, binBytes.value!, binPassword.value, onVerifyProgress),
        '验证全局密钥',
        VERIFY_KEY_FRONTEND_TIMEOUT_MS,
      );
    } catch (e) {
      errored = true;
      timedOut = isFrontendTimeout(e);
      console.error('[onVerify] 异常', e);
    }

    // 超时回查权威状态：验证成功的唯一判据是 GMK 就绪（会话已解锁）
    const recovered = timedOut && !result?.ok && globalKeyReadyRef.value;

    if (result?.ok || recovered) {
      // 成功：发出收束指令，等待收束完成事件；视图切换由该事件驱动，
      // 不猜测动画时长（成功路径必须补满 100% 后才释放视图）
      options.verifyRhythm.seal();
      try {
        await options.verifyRhythm.waitForComplete();
      } catch (e) {
        // 收束中途被 halt/reset/销毁：后端已验证成功，不阻塞业务收尾
        console.warn('[onVerify] 收束等待被中断，按已完成处理', e);
      }
      verifyPassword.value = '';
      binPassword.value = '';
      binFileName.value = '';
      zeroBytes(binBytes.value);
      binBytes.value = null;
      options.showToast('验证成功');
    } else {
      /* 失败与成功同构：先跑完进度收束（补满 100%）再呈现结果。
       * 结果一律在收束完成事件之后给出 —— 不因成败抢先落地，
       * 也不以冻结/降级打断进度与加载编排（加载动画随 processing
       * 一直持续到收束完成，故「跑完」含进度条与加载两部分）。 */
      options.verifyRhythm.seal();
      try {
        await options.verifyRhythm.waitForComplete();
      } catch (e) {
        // 收束中途被 halt/reset/销毁：按已完成处理，照常给出失败提示
        console.warn('[onVerify] 收束等待被中断，按已完成处理', e);
      }
      // 结构化错误提示：translateVerthysError 处理 VerthysResult 失败分支
      const msg = result && !result.ok
        ? translateVerthysError(result)
        : timedOut
          ? '验证超时，结果未确认：请重新验证'
          : (errored ? '验证失败，请重试' : '验证失败');
      options.showError(msg);
    }
    options.postVerifyAnim.value = false;
    processing.value = false;
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
      const next = await readBinBytes(selected);
      zeroBytes(oldBinBytes.value);
      oldBinBytes.value = next;
      const parts = selected.replace(/\\/g, '/').split('/');
      oldBinFileName.value = parts[parts.length - 1];
    } catch (e) {
      console.error('[browseOldBin] 异常', e);
      oldBinFileName.value = '';
      zeroBytes(oldBinBytes.value);
      oldBinBytes.value = null;
      options.showError(
        e instanceof Error && e.message.includes('大小上限') ? e.message : '读取文件失败',
      );
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
      const next = await readBinBytes(selected);
      zeroBytes(newBinBytes.value);
      newBinBytes.value = next;
      const parts = selected.replace(/\\/g, '/').split('/');
      newBinFileName.value = parts[parts.length - 1];
    } catch (e) {
      console.error('[browseNewBin] 异常', e);
      newBinFileName.value = '';
      zeroBytes(newBinBytes.value);
      newBinBytes.value = null;
      options.showError(
        e instanceof Error && e.message.includes('大小上限') ? e.message : '读取文件失败',
      );
    }
  };

  /** 清空修改密钥弹窗的全部敏感字段（打开/关闭/成功后统一调用） */
  const clearChangeKeyFields = () => {
    oldPassword.value = '';
    oldBinFileName.value = '';
    zeroBytes(oldBinBytes.value);
    oldBinBytes.value = null;
    oldBinPassword.value = '';
    newPassword.value = '';
    newBinFileName.value = '';
    zeroBytes(newBinBytes.value);
    newBinBytes.value = null;
    newBinPassword.value = '';
  };

  /** 打开修改全局密钥弹窗 */
  const onOpenChangeKeyDialog = () => {
    showChangeKeyDialog.value = true;
    clearChangeKeyFields();
  };

  /** 关闭修改全局密钥弹窗（处理中禁止关闭；关闭即清空敏感字段） */
  const onCloseChangeKeyDialog = () => {
    if (changeKeyProcessing.value) return;
    showChangeKeyDialog.value = false;
    clearChangeKeyFields();
  };

  /** 确认修改全局密钥
   *
   * changeGlobalKey 返回 VerthysResult<void>
   *   细分错误码：旧密钥错误 vs 落盘失败，提供精确 UI 提示
   *
   * 超时处理：changeGlobalKey 成功时会把 globalKeyRecordId 更新为新记录 id，
   *   前端兜底超时后以「记录 id 是否变化」判定真实结果，不直接断言失败。
   */
  const onConfirmChangeKey = async () => {
    // 重入闸门：处理中拒绝再次提交（按钮 disabled 之外的第二道防线）
    if (changeKeyProcessing.value) return;
    if (!oldBinBytes.value || !newBinBytes.value) return;
    changeKeyProcessing.value = true;
    const recordIdBefore = globalKeyRecordIdRef.value;
    try {
      const result = await withFrontendTimeout(
        changeGlobalKey(
          oldPassword.value, oldBinBytes.value, oldBinPassword.value,
          newPassword.value, newBinBytes.value, newBinPassword.value,
        ),
        '修改全局密钥',
        CHANGE_KEY_FRONTEND_TIMEOUT_MS,
      );
      if (!result.ok) {
        // 细分错误码：旧密钥错误 vs 落盘失败
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
      clearChangeKeyFields();
    } catch (e) {
      if (isFrontendTimeout(e)) {
        // 超时回查权威状态：记录 id 变化 = 后端已成功写入新记录
        const changed = globalKeyRecordIdRef.value > 0
          && globalKeyRecordIdRef.value !== recordIdBefore;
        if (changed) {
          options.showToast('全局密钥已修改（响应超时，结果已确认）');
          showChangeKeyDialog.value = false;
          clearChangeKeyFields();
        } else {
          options.showError('修改超时，结果未确认：请重启应用后以新密钥验证');
        }
      } else {
        options.showError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      changeKeyProcessing.value = false;
    }
  };

  /* ===== 导出密钥文件验证弹窗状态 =====
   * 修复：导出密钥文件属高敏感操作，必须先验证全局密钥。
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
    let srcBytes: Uint8Array | null = null;
    try {
      // 1. 选择源 .bin 密钥文件（同时是验证要素与导出源）
      const src = await open({
        filters: [{ name: 'BIN 密钥文件', extensions: ['bin'] }],
        multiple: false,
      });
      if (typeof src !== 'string' || !src) return; // 用户取消 → 静默中止
      try {
        srcBytes = await readBinBytes(src);
      } catch (readErr) {
        console.error('[onConfirmExportVerify] 密钥文件读取失败', readErr);
        options.showError(
          readErr instanceof Error && readErr.message.includes('大小上限')
            ? readErr.message
            : '密钥文件读取失败，请检查文件路径与权限',
        );
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
        EXPORT_VERIFY_FRONTEND_TIMEOUT_MS,
      );
      if (!result.ok) {
        options.showError(translateVerthysError(result));
        return;
      }

      // 3. 验证通过 → 关闭弹窗 + 立即清空敏感凭据 → 选择保存位置导出
      showExportVerifyDialog.value = false;
      exportVerifyPassword.value = '';
      exportVerifyBinPassword.value = '';

      // 保存位置（14 位无规律随机文件名，拒绝采样保证字符等概率）
      const dst = await save({
        defaultPath: randomExportFileName() + '.bin',
        filters: [{ name: 'BIN 密钥文件', extensions: ['bin'] }],
      });
      if (!dst) return; // 用户取消保存 → 已验证不缓存，下次导出需重新验证
      await writeUserFile(dst, srcBytes);
      options.showToast('已导出密钥文件备份');
    } catch (e) {
      console.error('[onConfirmExportVerify] 异常', e);
      if (isFrontendTimeout(e)) {
        options.showError('导出验证超时，请重试');
      } else {
        options.showError('导出失败');
      }
    } finally {
      // 源密钥字节在流程结束（成功/取消/失败）一律清零
      zeroBytes(srcBytes);
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

  /** 复位初始化/验证表单（供 goBackToUnlock 调用，清空并清零敏感字段） */
  const resetInitVerifyForm = () => {
    initPassword.value = '';
    verifyPassword.value = '';
    binPassword.value = '';
    binFileName.value = '';
    zeroBytes(binBytes.value);
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
