/**
 * @file useViewMode.ts
 * @brief 视图模式（五态严格互斥）计算 Composable
 *
 * 本模块提供 SecurityCenter 视图切换的核心逻辑，根据 verthys 解锁状态、
 * 全局密钥记录存在性、设备绑定状态及验证动画标志，计算当前应展示的
 * 视图模式。五个状态严格互斥，按固定优先级裁决。
 *
 * =============================================================================
 * 设计背景
 * =============================================================================
 * 原实现包含 "loading" 中间态，由前端异步探测全局密钥记录产生。
 * 现改为 worker 解锁成功后直接将探测结果内联到响应中，解锁完成即
 * 确定 hasGlobalKeyRecord，彻底消除异步等待窗口，故移除 loading 态。
 *
 * =============================================================================
 * 五态互斥规则（按优先级从高到低）
 * =============================================================================
 * 1. !verthysReady                          → "unlock"          （verthys 未解锁）
 * 2. !hasGlobalKeyRecord                  → "init"            （已解锁但无全局密钥记录）
 * 3. deviceCheckResult === "mismatch"     → "device_mismatch" （设备机器码不匹配拦截）
 * 4. !globalKeyReady || postVerifyAnim    → "verify"          （全局密钥未验证或验证后动画）
 * 5. 其他                                  → "management"      （全局密钥已就绪，管理主界面）
 *
 * =============================================================================
 * 设计约束
 * =============================================================================
 * - 纯计算 Composable：不持有响应式状态，所有依赖通过参数注入，便于单元测试。
 * - 单向数据流：上层组件（SecurityCenter.vue）通过 props 注入 Ref，
 *   viewMode 即时响应状态变化，无需额外触发。
 * - 五态互斥：任一时刻仅匹配一个视图，无重叠或灰色地带。
 */

import { computed, type ComputedRef, type Ref } from 'vue';

/**
 * 视图模式枚举，代表 SecurityCenter 的五种展示状态。
 */
export type ViewMode =
  | 'unlock'           // verthys 未解锁：显示解锁表单
  | 'init'             // 已解锁但无全局密钥记录：初始化安全密钥弹窗
  | 'verify'           // 已有全局密钥记录但未验证：验证表单
  | 'device_mismatch'  // 设备机器码不匹配：拦截视图
  | 'management';      // 全局密钥已就绪（或只读模式）：管理主界面

/**
 * 设备机器码校验结果，用于 device_mismatch 状态的裁决。
 */
export type DeviceCheckResult =
  | 'checking'   // 校验中
  | 'match'      // 匹配
  | 'mismatch'   // 不匹配
  | 'unbound'    // 未绑定
  | 'error';     // 校验出错

/**
 * useViewMode 的依赖注入接口。
 *
 * 所有响应式状态由调用方以 Ref 形式传入，确保：
 * - 状态源单一（由上层组件管理）
 * - 本模块保持纯计算特性
 * - 便于在测试中 mock 任意状态组合
 */
export interface UseViewModeOptions {
  /** verthys 是否已解锁（来自 keyManager.verthysReadyRef） */
  verthysReady: Ref<boolean>;
  /** 是否存在全局密钥记录（来自 keyManager.hasGlobalKeyRecordRef） */
  hasGlobalKeyRecord: Ref<boolean>;
  /** 全局密钥是否已就绪/已验证（来自 keyManager.globalKeyReadyRef） */
  globalKeyReady: Ref<boolean>;
  /** 设备机器码校验结果（SecurityCenter.vue 内部状态） */
  deviceCheckResult: Ref<DeviceCheckResult>;
  /** 验证后强制动画标志（无论成功/失败都保持 verify 视图 2 秒） */
  postVerifyAnim: Ref<boolean>;
}

/**
 * 计算当前视图模式。
 *
 * 五态按固定优先级裁决，调用方仅需传入状态 Ref，视图将随状态变化
 * 自动重新计算。
 *
 * @param options 响应式依赖注入
 * @returns 包含当前视图模式的 computed 引用
 *
 * @example
 * ```ts
 * const { viewMode } = useViewMode({
 *   verthysReady: verthysReadyRef,
 *   hasGlobalKeyRecord: hasGlobalKeyRecordRef,
 *   globalKeyReady: globalKeyReadyRef,
 *   deviceCheckResult,
 *   postVerifyAnim,
 * });
 * ```
 */
export function useViewMode(options: UseViewModeOptions): {
  viewMode: ComputedRef<ViewMode>;
} {
  const viewMode = computed<ViewMode>(() => {
    // 优先级 1：verthys 未解锁 → 解锁视图
    if (!options.verthysReady.value) return 'unlock';
    // 优先级 2：已解锁但无全局密钥记录 → 初始化视图
    if (!options.hasGlobalKeyRecord.value) return 'init';
    // 优先级 3：设备机器码不匹配 → 拦截视图
    if (options.deviceCheckResult.value === 'mismatch') return 'device_mismatch';
    // 优先级 4：全局密钥未验证或验证后动画 → 验证视图
    if (!options.globalKeyReady.value || options.postVerifyAnim.value) return 'verify';
    // 优先级 5：默认 → 管理主界面
    return 'management';
  });

  return { viewMode };
}