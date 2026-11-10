/**
 * @file useUnlockFlow.ts
 * @brief 解锁/创建 .verthys 文件的逻辑 Composable
 *
 * 本模块封装 SecurityCenter 中与 .verthys 文件路径选择、解锁/创建操作
 * 及进度反馈相关的核心逻辑。它提供文件选择、超时保护、进度回调及
 * 结果处理，确保前端与后端交互的可靠性和用户体验。
 *
 * =============================================================================
 * 职责范围
 * =============================================================================
 * - 管理 .verthys 文件路径状态（verthysPath）、解锁中标志（unlocking）、
 *   是否为新建操作（pendingIsCreate）。
 * - 提供 openExistingVerthys 和 createNewVerthys 方法，分别触发文件选择对话框
 *   并预填充路径，同时触发后台预热（索引预读）和 worker 预启动。
 * - 提供 doUnlock 核心方法，调用后端 initUnlock/initCreate，处理进度回调、
 *   超时兜底、错误翻译及后续设备校验。
 * - 暴露前端超时工具 withFrontendTimeout 及三组超时常量，作为最后防线。
 *
 * =============================================================================
 * 设计约束与安全策略
 * =============================================================================
 * 1. 进程内探测即时完成：hasGlobalKeyRecord 在解锁响应中内联返回，
 *    无需前端额外扫描，也不存在独立的 "loading" 中间态。
 * 2. 进度单调闸门：unlockProgressDone 标志阻止残留进度回调
 *    在 Promise resolve 后覆盖 UI 最终状态（如 "解锁完成" 被旧阶段覆盖）。
 * 3. 三层超时防护：前端超时 > 后端硬超时，确保前端永不早于后端完成，
 *    避免状态不一致（如前端超时报错但后端继续执行并改变 verthysReady）。
 * 4. 设备校验 fire-and-forget：不阻塞主流程，校验失败仅记录日志，
 *    由 viewMode 根据 deviceCheckResult 动态切换拦截视图。
 * 5. 选择即预热/预启动：用户选择文件后立即异步启动后台任务（索引预读、
 *    worker 子进程），与用户输入密码时间重叠，显著缩短感知等待时间。
 * 6. 进度感知统一：真实阶段进度只注入安全中心共享的进度感知层，
 *    由感知层完成平滑与收束；终值 100% 一律由收束事件交付，
 *    业务层不得自行跳变或伪造完成。
 *
 * =============================================================================
 * 超时策略
 * =============================================================================
 * - FRONTEND_TIMEOUT_MS (35s)：通用 IPC 操作的前端兜底。
 * - CREATE_FRONTEND_TIMEOUT_MS (150s)：覆盖创建操作的长时间流程。
 * - UNLOCK_FRONTEND_TIMEOUT_MS (200s)：专为解锁设计，大于后端 120s 硬超时，
 *   确保前端永远不会在后端完成前触发超时，避免状态不一致。
 *
 * =============================================================================
 * 依赖注入
 * =============================================================================
 * 所有外部依赖（isTauri、showError、showToast、checkDevice）通过参数注入，
 * 保持 Composable 纯净、可测试，并符合单向数据流原则。
 */

import { getCurrentInstance, onBeforeUnmount, ref } from 'vue';
import { open, save } from '@tauri-apps/plugin-dialog';
import {
  initCreate,
  initUnlock,
  hasGlobalKeyRecordRef,
  translateVerthysError,
  VerthysErrorCode,
  type VerthysResult,
} from '../../lib/keyManager';
import {
  verthysPreheat,
  verthysPreflight,
  verthysKeyfileStatus,
  preloadWorker,
  type UnlockProgress,
} from '../../lib/verthys';
import type { VerifyRhythm } from './useVerifyRhythm';
import { keyState } from '../../state/key_state';

/* ===== 前端超时兜底常量 ===== */

/**
 * 通用 IPC 操作的前端超时（35s），比后端默认超时略长，
 * 作为最后一道防线阻止永久卡死。
 */
const FRONTEND_TIMEOUT_MS = 35 * 1000;

/**
 * 创建操作前端超时（150s），覆盖 initCreate 内部的三步流程（create→lock→unlock）
 * 加上额外余量，避免误判。
 */
const CREATE_FRONTEND_TIMEOUT_MS = 150 * 1000;

/**
 * 解锁操作前端超时（200s）。
 *
 * 必须大于后端 UNLOCK_HARD_TIMEOUT_MS (120s)，并计入 worker 冷启动、
 * 进度回调等额外开销。留出充足余量，确保前端超时永不先于后端完成触发
 * ——前端先超时而后端继续执行，会造成 verthysReady 状态突变。
 */
const UNLOCK_FRONTEND_TIMEOUT_MS = 200 * 1000;

/**
 * 为异步 IPC 操作添加前端超时保护。
 *
 * 对任意 Promise 设置定时器，若超时则 reject，避免 UI 永久卡死。
 * 超时消息包含操作标签和实际超时秒数，便于诊断。
 */
export function withFrontendTimeout<T>(
  promise: Promise<T>,
  label: string,
  timeoutMs?: number,
): Promise<T> {
  const ms = timeoutMs ?? FRONTEND_TIMEOUT_MS;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${label} 前端超时（${ms / 1000}s）— 可能后端无响应`));
    }, ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

/**
 * useUnlockFlow 依赖注入接口。
 *
 * 所有外部能力通过参数传入，保持 Composable 纯计算特性，
 * 便于测试和重用。
 */
export interface UseUnlockFlowOptions {
  /** 是否处于 Tauri 环境 */
  isTauri: boolean;
  /** 显示错误提示的方法（来自全局 Toast 中心） */
  showError: (msg: string) => void;
  /** 显示成功提示的方法（来自全局 Toast 中心） */
  showToast: (msg: string) => void;
  /** 设备机器码校验回调（fire-and-forget 调用） */
  checkDevice: () => Promise<void>;
  /** 进度感知层（安全中心统一实例：解锁/创建/验证/初始化/清理共用，
   *  信号层只推送真实阶段进度，本层负责平滑与收束） */
  rhythm: VerifyRhythm;
}

/**
 * 解锁/创建 Composable 的主函数。
 *
 * 返回状态和方法，供 SecurityCenter.vue 使用。
 * 状态包括路径、解锁中标志、进度反馈和进度完成标志。
 * 方法提供文件选择（打开/新建）和执行解锁/创建操作。
 */
export function useUnlockFlow(options: UseUnlockFlowOptions) {
  /* ===== 响应式状态 ===== */
  const verthysPath = ref('');
  const unlocking = ref(false);
  const pendingIsCreate = ref(false);
  /** 当前会话是否由恢复码打开：状态源在全局 keyState，跨中枢卸载存续 */
  const recoveryMode = keyState.recoveryMode;

  /** 进度反馈：当前阶段描述 */
  const unlockProgressMsg = ref('');
  /** 进度反馈：0~100 累计百分比 */
  const unlockProgressPercent = ref(0);
  /** 进度反馈：累计耗时（毫秒） */
  const unlockProgressElapsed = ref(0);

  /**
   * 介质标识变化确认态（非 null 时显示确认对话框）。
   *
   * 场景：加密库位于可移动介质上，介质标识与登记记录不一致（克隆嫌疑）
   * 时后端阻止解锁；此处不直接报错，交由用户确认"合法更换介质"后带
   * 确认参数重试——重绑定仅在凭据验证通过后由后端落实。
   */
  const usbRebindPrompt = ref<{ path: string; isCreate: boolean } | null>(null);
  /** 确认后的重试进行中（禁用按钮，避免重复提交） */
  const usbRebindSaving = ref(false);

  /**
   * 进度完成标志。
   *
   * 目的：阻止 Tauri Channel 残留消息在 Promise resolve 后覆盖最终 UI 状态。
   * 原因：Channel 回调异步，当 initUnlock resolve 时，队列中可能仍有
   * 之前的心跳消息（如 "密钥计算较慢"），这些消息会覆盖已设置的
   * "解锁完成" 状态。本标志在 result.ok 时立即置位，
   * onUnlockProgress 检查并丢弃后续所有消息，保证 UI 稳定。
   */
  const unlockProgressDone = ref(false);

  /**
   * 一次性恢复码（仅新建成功时出现）。
   *
   * 安全约束：只驻留内存，由恢复码弹窗展示并强制抄写确认；确认/关闭后
   * 必须调用 clearRecoveryCode() 清零，禁止写入 localStorage、日志或状态文件。
   */
  const pendingRecoveryCode = ref<string | null>(null);

  const clearRecoveryCode = () => {
    pendingRecoveryCode.value = null;
  };

  /* ===== 文件选择方法 ===== */

  /**
   * 打开已有 .verthys 文件。
   *
   * 触发系统文件选择对话框，选中后填充 verthysPath，并标记为非新建。
   * 选择完成后异步触发后台预热（索引预读）和 worker 预启动，
   * 这些后台任务不阻塞 UI，失败仅记录警告。
   */
  const openExistingVerthys = async () => {
    if (!options.isTauri || unlocking.value) return;
    try {
      const selected = await open({
        filters: [{ name: 'Verthys 文件', extensions: ['verthys'] }],
        multiple: false,
      });
      if (typeof selected !== 'string' || !selected) return;
      verthysPath.value = selected;
      pendingIsCreate.value = false;
      void verthysPreheat(selected).catch((e) => {
        console.warn('[openExistingVerthys] 预热失败（不影响后续解锁）:', e);
      });
      void preloadWorker().catch((e) => {
        console.warn('[openExistingVerthys] worker 预启动失败（不影响后续解锁）:', e);
      });
    } catch (e) {
      console.error('[openExistingVerthys] 异常', e);
      options.showError('选择文件失败');
    }
  };

  /**
   * 新建 .verthys 文件。
   *
   * 触发系统文件保存对话框（默认文件名 Vault.verthys），选中后自动补全
   * .verthys 扩展名，填充 verthysPath 并标记为新建操作。
   */
  const createNewVerthys = async () => {
    if (!options.isTauri || unlocking.value) return;
    try {
      const newPath = await save({
        filters: [{ name: 'Verthys 加密库', extensions: ['verthys'] }],
        defaultPath: 'Vault.verthys',
      });
      if (!newPath) return;
      const finalPath = newPath.toLowerCase().endsWith('.verthys') ? newPath : newPath + '.verthys';
      verthysPath.value = finalPath;
      pendingIsCreate.value = true;
    } catch (e) {
      console.error('[createNewVerthys] 异常', e);
      options.showError('创建文件失败');
    }
  };

  /**
   * keyfile 因子：创建时是否启用 keyfile 保护（由解锁页勾选）。
   *
   * 只保存路径，keyfile 字节由 C 层生成；前端不接触文件内容。
   */
  const keyfileCreateEnabled = ref(false);
  /** 已选 keyfile 路径（创建时为新文件保存位置，解锁时为用户选择的已有文件） */
  const keyfilePath = ref('');

  /** 打开 keyfile 文件选择对话框（解锁路径） */
  const pickExistingKeyfile = async (): Promise<string | null> => {
    try {
      const selected = await open({
        title: '选择 keyfile 文件',
        multiple: false,
      });
      return typeof selected === 'string' && selected ? selected : null;
    } catch {
      return null;
    }
  };

  /** 选择 keyfile 保存位置（创建/启用路径） */
  const pickKeyfileSavePath = async (): Promise<string | null> => {
    try {
      const target = await save({
        title: '保存 keyfile 文件',
        filters: [{ name: 'Verthys keyfile', extensions: ['vkf'] }],
        defaultPath: 'Verthys.keyfile.vkf',
      });
      if (!target) return null;
      return target.toLowerCase().endsWith('.vkf') ? target : `${target}.vkf`;
    } catch {
      return null;
    }
  };

  /**
   * 执行解锁或创建操作。
   *
   * 根据 isCreate 决定调用 initCreate 或 initUnlock。
   * 过程中：
   *  - 重置进度状态，并通过 onUnlockProgress 回调实时更新。
   *  - 使用 withFrontendTimeout 包裹，应用特定超时。
   *  - 若创建时文件已存在（VerthysErrorCode.E_PATH_EXISTS），
   *    则自动回退到打开操作（读取已有文件）。
   *  - 成功后置位 unlockProgressDone 阻止残留消息，显示成功提示，
   *    并 fire-and-forget 触发设备校验（若存在全局密钥）。
   *  - 失败后调用 translateVerthysError 翻译错误码为用户可读消息。
   */
  const doUnlock = async (path: string, isCreate: boolean, usbRebindConfirmed = false) => {
    if (unlocking.value) return;
    unlocking.value = true;
    options.rhythm.start();
    unlockProgressMsg.value = '准备安全环境';
    unlockProgressPercent.value = 0;
    unlockProgressElapsed.value = 0;
    unlockProgressDone.value = false;

    const onUnlockProgress = (p: UnlockProgress) => {
      if (unlockProgressDone.value) return;
      unlockProgressMsg.value = p.message;
      unlockProgressPercent.value = p.percent;
      unlockProgressElapsed.value = p.elapsed_ms;
      /* 终值由收束事件交付：100 只作为完成提示，不推向感知层，
       * 避免 ACTIVE 期出现“真实进度已满但未收束”的协议异常 */
      if (p.percent < 100) options.rhythm.pushRealProgress(p.percent / 100);
    };

    try {
      let result: VerthysResult<void>;
      /** 是否真正新建了文件（E_PATH_EXISTS 回退成功时为 false） */
      let createdNew = false;
      /** 新建成功返回的一次性恢复码（仅内存；确认后清零） */
      let createdRecoveryCode: string | null = null;
      if (isCreate) {
        /* 创建时勾选 keyfile → 先选保存位置（C 层生成 VKFL 文件）。 */
        let kfForCreate: string | undefined;
        if (keyfileCreateEnabled.value) {
          if (!keyfilePath.value) {
            const chosen = await pickKeyfileSavePath();
            if (!chosen) {
              options.showError('已启用 keyfile 保护，请先选择 keyfile 保存位置');
              return;
            }
            keyfilePath.value = chosen;
          }
          kfForCreate = keyfilePath.value;
        }
        const createResult = await withFrontendTimeout(
          initCreate(path, undefined, onUnlockProgress, kfForCreate),
          '创建文件',
          CREATE_FRONTEND_TIMEOUT_MS,
        );
        result = createResult.ok
          ? { ok: true, value: undefined }
          : createResult;
        if (createResult.ok) {
          createdNew = true;
          createdRecoveryCode = createResult.value;
        } else if (createResult.code === VerthysErrorCode.E_PATH_EXISTS) {
          try {
            const preflight = await verthysPreflight(path);
            if (preflight.file_exists) {
              result = await withFrontendTimeout(
                initUnlock(
                  path,
                  undefined,
                  onUnlockProgress,
                  usbRebindConfirmed,
                  undefined,
                  keyfilePath.value || undefined,
                ),
                '打开文件',
                UNLOCK_FRONTEND_TIMEOUT_MS,
              );
            }
          } catch {
            // preflight 失败，保留原错误
          }
        }
      } else {
        /* keyfile 库（无 keyfile 路径时）返回 E_KEYFILE_REQUIRED；
         * 立即引导选择文件并重试一次，不让用户手点两次。 */
        let allowedRetry = 1;
        for (;;) {
          result = await withFrontendTimeout(
            initUnlock(
              path,
              undefined,
              onUnlockProgress,
              usbRebindConfirmed,
              undefined,
              keyfilePath.value || undefined,
            ),
            '打开文件',
            UNLOCK_FRONTEND_TIMEOUT_MS,
          );
          if (
            result.ok ||
            result.code !== VerthysErrorCode.E_KEYFILE_REQUIRED ||
            allowedRetry <= 0
          ) {
            break;
          }
          allowedRetry -= 1;
          const chosen = await pickExistingKeyfile();
          if (!chosen) break;
          keyfilePath.value = chosen;
        }
        /* 选错文件时不保留错误路径，下次确认重新弹出选择。 */
        if (!result.ok && result.code === VerthysErrorCode.E_KEYFILE_INVALID) {
          keyfilePath.value = '';
        }
      }

      if (result.ok) {
        unlockProgressDone.value = true;
        /* 成功收束：补满 100% 后交付结果，视图切换由收束完成事件驱动，
         * 不猜测动画时长（与验证/初始化路径统一） */
        options.rhythm.seal();
        try {
          await options.rhythm.waitForComplete();
        } catch (e) {
          console.warn('[doUnlock] 收束等待被中断，按已完成处理', e);
        }
        /* 普通口令解锁：会话不是恢复会话；清除可能残留的重绑提示状态。 */
        recoveryMode.value = false;
        keyState.recoveryResealDone.value = false;
        if (createdRecoveryCode) pendingRecoveryCode.value = createdRecoveryCode;
        // 提示必须与实际路径一致：创建回退到「打开已有文件」时不得宣称已创建
        options.showToast(createdNew ? '文件已创建' : '文件已加载');
        if (hasGlobalKeyRecordRef.value) {
          void options.checkDevice().catch((e) => {
            console.warn('[doUnlock] 设备校验失败（非致命）:', e);
          });
        }
      } else if (result.code === VerthysErrorCode.E_USB_CLONE_SUSPECTED) {
        // 介质标识变化（克隆嫌疑）：不直接报错，升起确认态；
        // 用户确认后带 usbRebindConfirmed 重试，密码验证通过才改写绑定
        usbRebindPrompt.value = { path, isCreate };
      } else {
        options.showError(translateVerthysError(result));
      }
    } catch (e) {
      console.error('[doUnlock] 异常', e);
      // 抛出真实原因（超时单独收敛为可读文案），不得统一吞成「操作失败」
      if (e instanceof Error && e.message.includes('前端超时')) {
        options.showError('操作超时，请重试');
      } else {
        options.showError(e instanceof Error && e.message ? e.message : '操作失败');
      }
    } finally {
      /* 失败/提前返回：冻结并降级；成功路径已进入 DONE，halt 为幂等空操作 */
      options.rhythm.halt();
      unlocking.value = false;
    }
  };

  /**
   * 用恢复码解锁（换机/灾难恢复）。
   *
   * 与口令解锁共用 initUnlock 的会话初始化与状态机；恢复码只作为一次性
   * 参数传入，不进入前端状态、日志或持久化。
   */
  const doRecoveryUnlock = async (path: string, code: string): Promise<boolean> => {
    if (unlocking.value || !code) return false;
    unlocking.value = true;
    options.rhythm.start();
    unlockProgressMsg.value = '准备恢复解锁';
    unlockProgressPercent.value = 0;
    unlockProgressElapsed.value = 0;
    unlockProgressDone.value = false;

    const onUnlockProgress = (p: UnlockProgress) => {
      if (unlockProgressDone.value) return;
      unlockProgressMsg.value = p.message;
      unlockProgressPercent.value = p.percent;
      unlockProgressElapsed.value = p.elapsed_ms;
      if (p.percent < 100) options.rhythm.pushRealProgress(p.percent / 100);
    };

    try {
      const result = await withFrontendTimeout(
        initUnlock(path, undefined, onUnlockProgress, false, code),
        '恢复解锁',
        UNLOCK_FRONTEND_TIMEOUT_MS,
      );
      if (result.ok) {
        unlockProgressDone.value = true;
        /* 成功收束：补满 100% 后交付结果（与口令解锁路径统一） */
        options.rhythm.seal();
        try {
          await options.rhythm.waitForComplete();
        } catch (e) {
          console.warn('[doRecoveryUnlock] 收束等待被中断，按已完成处理', e);
        }
        /* 恢复会话必须提示重绑；以 C 层 status 为权威，查询失败时按恢复
         * 会话展示（误提示可被 C 层 POLICY 拒绝，不会造成数据变更）。
         * 新恢复会话尚未重绑，上一次会话的重绑结果不得沿用。 */
        keyState.recoveryResealDone.value = false;
        try {
          const status = await verthysKeyfileStatus();
          recoveryMode.value = status.ok && status.recovery_mode === true;
        } catch {
          recoveryMode.value = true;
        }
        options.showToast('已使用恢复码打开');
        if (hasGlobalKeyRecordRef.value) {
          void options.checkDevice().catch((e) => {
            console.warn('[doRecoveryUnlock] 设备校验失败（非致命）:', e);
          });
        }
        return true;
      } else {
        return false;
      }
    } catch (e) {
      console.error('[doRecoveryUnlock] 异常', e);
      return false;
    } finally {
      options.rhythm.halt();
      unlocking.value = false;
    }
  };

  /**
   * 用户确认"合法更换介质"：带确认参数重试解锁。
   *
   * 安全性：确认参数只放行克隆嫌疑阻断，重绑定仍以本次密码验证
   * 通过为前提（后端在解锁成功后落实），失败不会改写绑定记录。
   */
  const confirmUsbRebind = async () => {
    const pending = usbRebindPrompt.value;
    if (!pending || usbRebindSaving.value) return;
    usbRebindSaving.value = true;
    try {
      usbRebindPrompt.value = null;
      await doUnlock(pending.path, pending.isCreate, true);
    } finally {
      usbRebindSaving.value = false;
    }
  };

  /** 用户取消确认：关闭确认态并明确告知解锁保持阻止（不静默） */
  const cancelUsbRebind = () => {
    if (!usbRebindPrompt.value) return;
    usbRebindPrompt.value = null;
    options.showError('已取消介质更换确认，解锁保持阻止状态');
  };

  /* 开发夹具填充：只写入路径与 keyfile，不触发解锁；发布构建整段剔除。 */
  if (import.meta.env.DEV && getCurrentInstance()) {
    const fixtureFillHandler = (event: Event) => {
      const detail = (event as CustomEvent<{
        target?: string;
        containerPath?: string;
        containerKeyfilePath?: string;
      }>).detail;
      if (!detail || detail.target !== 'unlock') return;
      if (detail.containerPath) {
        verthysPath.value = detail.containerPath;
        pendingIsCreate.value = false;
      }
      if (detail.containerKeyfilePath) {
        keyfilePath.value = detail.containerKeyfilePath;
        keyfileCreateEnabled.value = true;
      }
    };
    window.addEventListener('verthys:devfixture-fill', fixtureFillHandler);
    onBeforeUnmount(() => {
      window.removeEventListener('verthys:devfixture-fill', fixtureFillHandler);
    });
  }

  return {
    verthysPath,
    unlocking,
    pendingIsCreate,
    keyfileCreateEnabled,
    keyfilePath,
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
  };
}