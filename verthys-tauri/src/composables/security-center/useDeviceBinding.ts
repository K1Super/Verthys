/**
 * useDeviceBinding.ts — 设备机器码校验与绑定 Composable
 *
 * 来源：SecurityCenter.vue 原 L929-L931, L950-L975（零行为变更提取）
 *
 * 职责：
 *   1. 管理设备机器码校验状态（deviceCheckResult：checking/match/mismatch/unbound/error）
 *   2. 管理机器码短显示（deviceFingerprintShort，用于 device_mismatch 视图与全局密钥区诊断）
 *   3. 提供核心函数：
 *      - checkDevice：校验当前设备与已绑定设备是否匹配（fire-and-forget，由 useUnlockFlow 注入）
 *      - refreshDeviceFingerprint：独立刷新机器码短显示（不依赖校验流程，
 *        由 SecurityCenter onMounted / watch 兜底调用，根治生命周期空白问题）
 *
 * 设计：
 *   - deviceCheckResult 注入到 useViewMode（读取，控制 device_mismatch 视图拦截）
 *   - deviceFingerprintShort 注入到模板（device_mismatch 视图 + 全局密钥区显示）
 *   - checkDevice 注入到 useUnlockFlow（解锁成功后 fire-and-forget 调用，不阻塞验证密钥界面出现）
 *   - 异常隔离：校验失败仅记录日志 + 标记 "error"，不阻断主流程
 *
 * 设计：纯 Composable，所有外部依赖通过参数注入，状态和方法返回给调用方。
 *      必须在 useViewMode / useUnlockFlow 之前调用（提供 deviceCheckResult / checkDevice 注入）。
 */

import { ref } from 'vue';
import {
  verifyDeviceBinding,
  getDeviceFingerprintShort,
} from '../../lib/keyManager';
import { type DeviceCheckResult } from './useViewMode';

/**
 * useDeviceBinding 选项
 * 所有外部依赖通过参数注入，保持 Composable 纯净可测试
 */
export interface UseDeviceBindingOptions {
  /** 是否处于 Tauri 环境（非浏览器模式；浏览器模式直接标记 "unbound"） */
  isTauri: boolean;
}

/**
 * 设备机器码校验与绑定 Composable
 *
 * @param options 依赖注入
 * @returns 状态变量 + 核心函数
 *
 * @example
 * ```ts
 * const { deviceCheckResult, deviceFingerprintShort, checkDevice, refreshDeviceFingerprint } = useDeviceBinding({ isTauri });
 * ```
 */
export function useDeviceBinding(options: UseDeviceBindingOptions) {
  /* ===== 设备机器码校验状态 ===== */
  const deviceCheckResult = ref<DeviceCheckResult>('checking');
  const deviceFingerprintShort = ref('');

  /* ===== 独立刷新机器码短显示（不依赖校验流程） =====
   * 修复修复：原实现 deviceFingerprintShort 仅在 checkDevice() 内部填充，
   *   而 checkDevice 只在 doUnlock 成功且已有全局密钥记录时被调用（useUnlockFlow）。
   *   以下场景机器码永远空白：
   *     a) 新建 verthys → 初始化密钥路径（doUnlock 时 hasGlobalKeyRecord=false，
   *        checkDevice 不触发；onInitKey 后直接进入 management 视图）
   *     b) 跨模块切换 → SecurityCenter 卸载/重挂载，本 Composable 状态重置为空，
   *        checkDevice 不会再被调用（doUnlock 不触发）
   *
   *   机器码为本机硬件固有属性（CPU/主板/磁盘 SHA-256），与 verthys 解锁状态无关，
   *   因此提供独立刷新入口，由 SecurityCenter onMounted / watch 兜底调用。 */
  const refreshDeviceFingerprint = async () => {
    if (!options.isTauri) return;
    try {
      deviceFingerprintShort.value = await getDeviceFingerprintShort();
    } catch (e) {
      console.warn('[useDeviceBinding] 获取设备机器码失败:', e);
    }
  };

  /* ===== 校验设备机器码 =====
   * 须在 useUnlockFlow 调用前定义（以参数注入，避免 TDZ 时序死区）；
   * 依赖 isTauri / deviceCheckResult / deviceFingerprintShort（均已先行定义） */
  const checkDevice = async () => {
    if (!options.isTauri) {
      deviceCheckResult.value = 'unbound';
      return;
    }
    deviceCheckResult.value = 'checking';
    try {
      const result = await verifyDeviceBinding();
      if (result.ok) {
        deviceCheckResult.value = result.value;
      } else {
        // VerthysResult 失败：标记为 error，记录日志（不阻塞主流程）
        console.error('[SecurityCenter] 设备校验失败:', result.code, result.message);
        deviceCheckResult.value = 'error';
      }
      // 获取机器码短显示（即使校验失败也尝试获取，用于诊断）
      await refreshDeviceFingerprint();
    } catch (e) {
      console.error('[SecurityCenter] 设备校验失败:', e);
      deviceCheckResult.value = 'error';
    }
  };

  return {
    // 状态
    deviceCheckResult,
    deviceFingerprintShort,
    // 方法
    checkDevice,
    refreshDeviceFingerprint,
  };
}

/** useDeviceBinding 返回值类型（便于显式标注） */
export type UseDeviceBindingReturn = ReturnType<typeof useDeviceBinding>;
