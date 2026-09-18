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
 *    无需前端额外扫描，彻底移除原 "loading" 中间态。
 * 2. 进度单调闸门：unlockProgressDone 标志阻止 Tauri Channel 残留消息
 *    在 Promise resolve 后覆盖 UI 最终状态（如 "解锁完成" 被心跳覆盖）。
 * 3. 三层超时防护：前端超时 > 后端硬超时，确保前端永不早于后端完成，
 *    避免状态不一致（如前端超时报错但后端继续执行并改变 verthysReady）。
 * 4. 设备校验 fire-and-forget：不阻塞主流程，校验失败仅记录日志，
 *    由 viewMode 根据 deviceCheckResult 动态切换拦截视图。
 * 5. 选择即预热/预启动：用户选择文件后立即异步启动后台任务（索引预读、
 *    worker 子进程），与用户输入密码时间重叠，显著缩短感知等待时间。
 *
 * =============================================================================
 * 超时策略
 * =============================================================================
 * - FRONTEND_TIMEOUT_MS (35s)：通用 IPC 操作的前端兜底。
 * - CREATE_FRONTEND_TIMEOUT_MS (150s)：覆盖创建操作的长时间流程。
 * - UNLOCK_FRONTEND_TIMEOUT_MS (200s)：专为解锁设计，大于后端 120s 硬超时，
 *   确保前端永远不会在后端完成前触发超时，根治状态不一致风险。
 *
 * =============================================================================
 * 依赖注入
 * =============================================================================
 * 所有外部依赖（isTauri、showError、showToast、checkDevice）通过参数注入，
 * 保持 Composable 纯净、可测试，并符合单向数据流原则。
 */

import { ref } from 'vue';
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
  preloadWorker,
  type UnlockProgress,
} from '../../lib/verthys';

/* ===== 前端超时兜底常量 ===== */

/**
 * 通用 IPC 操作的前端超时（35s），比后端默认超时略长，
 * 作为最后一道防线阻止永久卡死。
 */
export const FRONTEND_TIMEOUT_MS = 35 * 1000;

/**
 * 创建操作前端超时（150s），覆盖 initCreate 内部的三步流程（create→lock→unlock）
 * 加上额外余量，避免误判。
 */
export const CREATE_FRONTEND_TIMEOUT_MS = 150 * 1000;

/**
 * 解锁操作前端超时（200s）。
 *
 * 必须大于后端 UNLOCK_HARD_TIMEOUT_MS (120s)，并计入 worker 冷启动、
 * 进度回调等额外开销。原 35s 过短，导致前端超时后后端继续执行，
 * 造成 verthysReady 状态突变。现留出充足余量，确保前端超时永不先于
 * 后端完成触发。
 */
export const UNLOCK_FRONTEND_TIMEOUT_MS = 200 * 1000;

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
  /** 显示错误提示的方法（来自 useErrorToast） */
  showError: (msg: string) => void;
  /** 显示成功提示的方法（来自 useErrorToast） */
  showToast: (msg: string) => void;
  /** 设备机器码校验回调（fire-and-forget 调用） */
  checkDevice: () => Promise<void>;
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

  /** 进度反馈：当前阶段描述 */
  const unlockProgressMsg = ref('');
  /** 进度反馈：0~100 累计百分比 */
  const unlockProgressPercent = ref(0);
  /** 进度反馈：累计耗时（毫秒） */
  const unlockProgressElapsed = ref(0);

  /**
   * 进度完成标志（企业级根治修复）。
   *
   * 目的：阻止 Tauri Channel 残留消息在 Promise resolve 后覆盖最终 UI 状态。
   * 原因：Channel 回调异步，当 initUnlock resolve 时，队列中可能仍有
   * 之前的心跳消息（如 "密钥计算较慢"），这些消息会覆盖已设置的
   * "解锁完成" 状态。本标志在 result.ok 时立即置位，
   * onUnlockProgress 检查并丢弃后续所有消息，保证 UI 稳定。
   */
  const unlockProgressDone = ref(false);

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
   * 触发系统文件保存对话框，选中后自动补全 .verthys 扩展名，
   * 填充 verthysPath 并标记为新建操作。
   */
  const createNewVerthys = async () => {
    if (!options.isTauri || unlocking.value) return;
    try {
      const newPath = await save({
        filters: [{ name: 'Verthys 加密库', extensions: ['verthys'] }],
        defaultPath: 'verthys.verthys',
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
  const doUnlock = async (path: string, isCreate: boolean) => {
    if (unlocking.value) return;
    unlocking.value = true;
    unlockProgressMsg.value = '准备就绪';
    unlockProgressPercent.value = 0;
    unlockProgressElapsed.value = 0;
    unlockProgressDone.value = false;

    const onUnlockProgress = (p: UnlockProgress) => {
      if (unlockProgressDone.value) return;
      unlockProgressMsg.value = p.message;
      unlockProgressPercent.value = p.percent;
      unlockProgressElapsed.value = p.elapsed_ms;
    };

    try {
      let result: VerthysResult<void>;
      if (isCreate) {
        result = await withFrontendTimeout(
          initCreate(path, undefined, onUnlockProgress),
          '创建文件',
          CREATE_FRONTEND_TIMEOUT_MS,
        );
        if (!result.ok && result.code === VerthysErrorCode.E_PATH_EXISTS) {
          try {
            const preflight = await verthysPreflight(path);
            if (preflight.file_exists) {
              console.log('[doUnlock] 文件已存在，回退到打开');
              result = await withFrontendTimeout(
                initUnlock(path, undefined, onUnlockProgress),
                '打开文件',
                UNLOCK_FRONTEND_TIMEOUT_MS,
              );
            }
          } catch {
            // preflight 失败，保留原错误
          }
        }
      } else {
        result = await withFrontendTimeout(
          initUnlock(path, undefined, onUnlockProgress),
          '打开文件',
          UNLOCK_FRONTEND_TIMEOUT_MS,
        );
      }

      if (result.ok) {
        unlockProgressDone.value = true;
        options.showToast(isCreate ? '文件已创建' : '文件已加载');
        if (hasGlobalKeyRecordRef.value) {
          void options.checkDevice().catch((e) => {
            console.warn('[doUnlock] 设备校验失败（非致命）:', e);
          });
        }
      } else {
        options.showError(translateVerthysError(result));
      }
    } catch (e) {
      console.error('[doUnlock] 异常', e);
      options.showError('操作失败');
    } finally {
      unlocking.value = false;
    }
  };

  return {
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
  };
}

export type UseUnlockFlowReturn = ReturnType<typeof useUnlockFlow>;