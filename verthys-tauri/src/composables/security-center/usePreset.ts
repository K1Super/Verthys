/**
 * usePreset.ts — 安全防护预设 Composable（三档模式 + 无极轨道滑块 + 自定义模板）
 *
 * 来源：SecurityCenter.vue 原 L1325-L1573（零行为变更提取）
 *
 * 职责：
 *   1. 预设特性列表定义（presetFeatureList，与 Rust PresetFeatures 字段对齐）
 *   2. 预设应用状态（presetApplying / currentPresetFeatures / presetFeaturesCache）
 *   3. 自定义模板配置（customPanelOpen / customFeatures）
 *   4. 无极轨道滑块状态（orbitSliderPos / orbitAnchors / activeAnchorIdx / orbitDragging）
 *   5. 双环 + 蜂窝计算（cpuOverhead / securityCoverage / overallScore /
 *      presetAmbienceMode / currentModeLabel / ringDashOffset / orbitTrackGradient）
 *   6. 特性列表分组（toggleableFeatures / lockedFeatures）
 *   7. 核心函数：
 *      - onOrbitSliderInput / onOrbitSliderRelease：滑块拖拽 + 磁性吸附
 *      - snapToAnchor：点击锚点直接吸附并切换
 *      - onToggleGearPanel：齿轮按钮打开/关闭自定义面板
 *      - onToggleCustomFeature / onResetCustom / onApplyCustom：自定义特性管理
 *      - onApplyPreset：应用三档预设（调用 keyManager.applySecurityPreset）
 *      - loadPresetConfig：加载预设配置（onMounted / 全局密钥就绪后调用）
 *
 * ★ 企业级设计：
 *   - keyManager 单例 ref（securityPresetRef / globalKeyReadyRef）直接从 keyManager 导入
 *   - 外部依赖通过参数注入：showError / showToast / resetSession（来自 useSessionTimer）
 *   - 滑块磁性吸附：拖拽时实时更新视觉，松手时吸附到最近锚点并应用预设
 *   - 预设应用防重复：presetApplying 标志禁用按钮
 *   - 特性快照缓存：presetFeaturesCache 预加载各预设特性，用于特性摘要条显示
 *
 * 设计：纯 Composable，所有外部依赖通过参数注入，状态和方法返回给调用方。
 *      loadPresetConfig 需由 SecurityCenter 在 onMounted / watch(globalKeyReadyRef) 中调用。
 */

import { ref, computed } from 'vue';
import {
  securityPresetRef,
  applySecurityPreset,
  loadCustomFeatures,
  saveCustomFeatures,
  isLockedFeature,
  globalKeyReadyRef,
} from '../../lib/keyManager';
import {
  securityGetPresetConfig,
  type SecurityPresetCode,
  type PresetFeatures,
} from '../../lib/verthys';

/**
 * usePreset 选项
 * 所有外部依赖通过参数注入，保持 Composable 纯净可测试
 */
export interface UsePresetOptions {
  /** 显示错误提示（来自 useErrorToast） */
  showError: (msg: string) => void;
  /** 显示成功提示（SecurityCenter 顶层持有，2.5s 自动消失） */
  showToast: (msg: string) => void;
  /** 重置会话计时器（来自 useSessionTimer，预设切换后同步本地超时显示） */
  resetSession: () => void;
}

/**
 * 安全防护预设 Composable
 *
 * @param options 依赖注入
 * @returns 状态变量 + 计算属性 + 核心函数
 *
 * @example
 * ```ts
 * const {
 *   presetFeatureList, presetApplying, currentPresetFeatures,
 *   customPanelOpen, customFeatures, presetFeaturesCache,
 *   orbitSliderPos, orbitAnchors, nearestAnchorIdx, activeAnchorIdx, orbitDragging,
 *   cpuOverhead, securityCoverage, overallScore,
 *   presetAmbienceMode, currentModeLabel,
 *   ringCircumference, ringDashOffset, orbitTrackGradient,
 *   toggleableFeatures, lockedFeatures,
 *   onOrbitSliderInput, onOrbitSliderRelease, snapToAnchor,
 *   onToggleGearPanel, onToggleCustomFeature, onResetCustom, onApplyCustom,
 *   onApplyPreset, loadPresetConfig,
 * } = usePreset({ showError, showToast, resetSession });
 * ```
 */
export function usePreset(options: UsePresetOptions) {
  /* ===== 预设特性列表（与 Rust PresetFeatures 字段对齐） ===== */
  const presetFeatureList: { key: keyof PresetFeatures; label: string; desc: string }[] = [
    { key: "anti_debug", label: "反调试", desc: "C 层固定启用" },
    { key: "anti_inject", label: "反注入", desc: "C 层固定启用" },
    { key: "integrity_check", label: "完整性校验", desc: "C 层固定启用" },
    { key: "memory_guard", label: "内存保护", desc: "C 层固定启用" },
    { key: "key_separation", label: "密钥三分离", desc: "C 层固定启用" },
    { key: "emergency_response", label: "紧急熔断", desc: "C 层固定启用" },
    { key: "session_lock_on_idle", label: "空闲锁定", desc: "会话空闲超时自动锁定" },
    { key: "shadow_sleep", label: "影子休眠", desc: "USB 拔出后索引加密驻留" },
    { key: "module_patrol", label: "模块巡检", desc: "定期扫描已加载模块签名" },
    { key: "clip_clear_on_lock", label: "剪贴板清理", desc: "锁定时清除剪贴板残留" },
    { key: "usb_clone_detect", label: "USB 克隆检测", desc: "序列号哈希比对拒绝克隆外设" },
    { key: "trace_cleanup", label: "痕迹清理", desc: "退出时清理系统最近记录" },
  ];

  /* ===== 预设应用状态 ===== */
  /** 预设应用中标志（禁用按钮防止重复点击） */
  const presetApplying = ref(false);
  /** 当前预设的特性开关快照（驱动 UI 显示 ON/OFF） */
  const currentPresetFeatures = ref<Record<string, boolean>>({});

  /* ===== 自定义模板配置 ===== */
  /** 自定义面板展开状态 */
  const customPanelOpen = ref(false);
  /** 自定义特性配置（localStorage 持久化） */
  const customFeatures = ref<PresetFeatures>(loadCustomFeatures());
  /** 各预设的特性快照（用于特性摘要条显示） */
  const presetFeaturesCache = ref<Record<number, Record<string, boolean>>>({});

  /* ===== 无极轨道滑块 — 性能↔安全权衡 ===== */
  /** 滑块位置 (0=性能, 50=平衡, 100=安全) */
  const orbitSliderPos = ref(50);
  /** 三个磁性吸附锚点 */
  const orbitAnchors = [
    { pos: 0, label: '性能', code: 2 as SecurityPresetCode },
    { pos: 50, label: '平衡', code: 0 as SecurityPresetCode },
    { pos: 100, label: '安全', code: 1 as SecurityPresetCode },
  ];
  /** 最近锚点索引（拖拽时实时计算，用于磁性吸附视觉反馈） */
  const nearestAnchorIdx = computed(() => {
    let min = Infinity, idx = 1;
    orbitAnchors.forEach((a, i) => {
      const d = Math.abs(orbitSliderPos.value - a.pos);
      if (d < min) { min = d; idx = i; }
    });
    return idx;
  });
  /** 当前激活锚点索引（松手后吸附到的位置） */
  const activeAnchorIdx = ref(1);
  /** 拖拽中标志（拖拽时不触发预设切换，松手时吸附） */
  const orbitDragging = ref(false);

  /* ===== 双环 + 蜂窝计算 ===== */
  /** CPU/IO 开销百分比 — 此消彼长：性能端 15%，安全端 88% */
  const cpuOverhead = computed(() => {
    const p = orbitSliderPos.value;
    return Math.round(15 + (p / 100) * 73);
  });
  /** 安全覆盖度百分比 — 性能端 42%，安全端 98% */
  const securityCoverage = computed(() => {
    const p = orbitSliderPos.value;
    return Math.round(42 + (p / 100) * 56);
  });
  /** 综合百分比（加权平均） */
  const overallScore = computed(() => {
    return Math.round((cpuOverhead.value + securityCoverage.value) / 2);
  });
  /** 环境光晕模式 */
  const presetAmbienceMode = computed<'performance' | 'balanced' | 'secure'>(() => {
    if (securityPresetRef.value === 3) return 'balanced';
    const p = orbitSliderPos.value;
    if (p < 25) return 'performance';
    if (p > 75) return 'secure';
    return 'balanced';
  });
  /** 当前模式标签 */
  const currentModeLabel = computed(() => {
    if (securityPresetRef.value === 3) return '自定义';
    const labels = ['平衡', '安全', '性能'];
    return labels[activeAnchorIdx.value] ?? '平衡';
  });

  /* ===== SVG 环周长 + dashoffset 计算 ===== */
  /** SVG 环周长 (r=50 → 2πr ≈ 314.159) */
  const ringCircumference = 2 * Math.PI * 50;
  /** 计算环的 stroke-dashoffset */
  const ringDashOffset = (percentage: number): number => {
    return ringCircumference * (1 - percentage / 100);
  };

  /* ===== 轨道渐变背景 ===== */
  /** 轨道渐变背景 — 随滑块位置流动 */
  const orbitTrackGradient = computed(() => ({
    background: `linear-gradient(90deg,
    rgba(0,255,200,0.25) 0%,
    rgba(0,212,255,0.35) ${orbitSliderPos.value / 2}%,
    rgba(139,92,246,0.35) ${50 + orbitSliderPos.value / 2}%,
    rgba(255,110,180,0.25) 100%)`,
  }));

  /* ===== 特性列表分组 ===== */
  /** 可切换特性列表（非核心防护） */
  const toggleableFeatures = computed(() =>
    presetFeatureList.filter(f => !isLockedFeature(f.key))
  );
  /** 核心防护特性列表（固定开启） */
  const lockedFeatures = computed(() =>
    presetFeatureList.filter(f => isLockedFeature(f.key))
  );

  /* ===== 滑块拖拽 + 磁性吸附 ===== */
  /** 滑块拖拽输入处理 — 实时更新视觉，松手时磁性吸附 */
  const onOrbitSliderInput = () => {
    orbitDragging.value = true;
  };
  /** 滑块松手时磁性吸附到最近锚点并应用预设 */
  const onOrbitSliderRelease = () => {
    if (!orbitDragging.value) return;
    orbitDragging.value = false;
    const idx = nearestAnchorIdx.value;
    const anchor = orbitAnchors[idx];
    orbitSliderPos.value = anchor.pos;
    activeAnchorIdx.value = idx;
    // 应用对应预设
    if (securityPresetRef.value !== anchor.code) {
      onApplyPreset(anchor.code);
    }
  };
  /** 点击锚点 — 直接吸附并切换 */
  const snapToAnchor = (idx: number) => {
    if (!globalKeyReadyRef.value || presetApplying.value) return;
    const anchor = orbitAnchors[idx];
    orbitSliderPos.value = anchor.pos;
    activeAnchorIdx.value = idx;
    if (securityPresetRef.value !== anchor.code) {
      onApplyPreset(anchor.code);
    }
  };
  /** 齿轮按钮 — 打开/关闭自定义面板 */
  const onToggleGearPanel = () => {
    customPanelOpen.value = !customPanelOpen.value;
    if (customPanelOpen.value && securityPresetRef.value !== 3) {
      // 打开自定义面板时切换到 CUSTOM 模式
      onApplyPreset(3);
    }
  };

  /* ===== 自定义特性管理 ===== */
  /** 切换自定义特性开关 */
  const onToggleCustomFeature = (key: string) => {
    if (isLockedFeature(key)) return;
    customFeatures.value = {
      ...customFeatures.value,
      [key]: !customFeatures.value[key as keyof PresetFeatures],
    };
  };

  /** 恢复自定义默认配置 */
  const onResetCustom = () => {
    customFeatures.value = loadCustomFeatures(); // 重新加载（含默认值合并）
    // 强制重置为全开默认值
    presetFeatureList.forEach(f => {
      (customFeatures.value as any)[f.key] = true;
    });
    options.showToast("已恢复默认配置");
  };

  /** 保存并应用自定义模板 */
  const onApplyCustom = async () => {
    if (presetApplying.value || !globalKeyReadyRef.value) return;
    presetApplying.value = true;
    try {
      saveCustomFeatures(customFeatures.value);
      const config = await applySecurityPreset(3);
      if (config) {
        currentPresetFeatures.value = { ...config.features };
      }
      options.resetSession();
      options.showToast("自定义模板已保存并应用");
    } catch (e) {
      console.error("[onApplyCustom] 应用失败", e);
      options.showError("应用自定义模板失败");
    } finally {
      presetApplying.value = false;
    }
  };

  /* ===== 应用三档预设（调用 keyManager.applySecurityPreset） =====
   * 流程：
   *   1. 防重复守卫（presetApplying / globalKeyReady）
   *   2. 应用预设 → 更新特性快照 + 缓存
   *   3. 同步会话超时显示（applySecurityPreset 内部已调用 setSessionTimeout）
   *   4. 同步无极轨道滑块位置（非 CUSTOM 预设）
   *   5. toast 反馈 + CUSTOM 预设自动展开自定义面板 */
  const onApplyPreset = async (code: SecurityPresetCode) => {
    if (presetApplying.value || !globalKeyReadyRef.value) return;
    presetApplying.value = true;
    try {
      const config = await applySecurityPreset(code);
      if (config) {
        currentPresetFeatures.value = { ...config.features };
        // 缓存各预设特性快照（用于特性摘要条显示）
        presetFeaturesCache.value[code] = { ...config.features };
      }
      // 同步本地会话超时显示（applySecurityPreset 内部已调用 setSessionTimeout）
      options.resetSession();
      // 同步无极轨道滑块位置
      if (code !== 3) {
        const anchor = orbitAnchors.find(a => a.code === code);
        if (anchor) {
          orbitSliderPos.value = anchor.pos;
          activeAnchorIdx.value = orbitAnchors.indexOf(anchor);
        }
      }
      const modeNames: Record<number, string> = { 0: '平衡', 1: '安全', 2: '性能', 3: '自定义' };
      options.showToast(`已切换至 ${modeNames[code] ?? code} 模式`);
      // CUSTOM 预设自动展开自定义面板
      if (code === 3) customPanelOpen.value = true;
    } catch (e) {
      console.error("[onApplyPreset] 切换预设失败", e);
      options.showError("切换预设失败");
    } finally {
      presetApplying.value = false;
    }
  };

  /* ===== 加载预设配置（onMounted / 全局密钥就绪后调用） =====
   * 预加载所有标准预设的特性快照，用于特性摘要条显示。
   * ★ 此函数需由 SecurityCenter 在 onMounted / watch(globalKeyReadyRef) 中调用。 */
  const loadPresetConfig = async () => {
    try {
      // 预加载 3 个标准预设的特性配置
      for (const code of [0, 1, 2] as const) {
        try {
          const config = await securityGetPresetConfig(code);
          if (config) {
            presetFeaturesCache.value[code] = { ...config.features };
            if (securityPresetRef.value === code) {
              currentPresetFeatures.value = { ...config.features };
            }
          }
        } catch { /* 单个预设加载失败不中断 */ }
      }
      // CUSTOM 预设：直接从 localStorage 读取
      presetFeaturesCache.value[3] = { ...customFeatures.value };
      if (securityPresetRef.value === 3) {
        currentPresetFeatures.value = { ...customFeatures.value };
      }
      // 同步无极轨道滑块到当前预设位置
      if (securityPresetRef.value !== 3) {
        const anchor = orbitAnchors.find(a => a.code === securityPresetRef.value);
        if (anchor) {
          orbitSliderPos.value = anchor.pos;
          activeAnchorIdx.value = orbitAnchors.indexOf(anchor);
        }
      }
    } catch (e) {
      console.warn("[loadPresetConfig] 加载预设配置失败", e);
    }
  };

  return {
    // 预设特性列表
    presetFeatureList,
    // 预设应用状态
    presetApplying,
    currentPresetFeatures,
    presetFeaturesCache,
    // 自定义模板配置
    customPanelOpen,
    customFeatures,
    // 无极轨道滑块状态
    orbitSliderPos,
    orbitAnchors,
    nearestAnchorIdx,
    activeAnchorIdx,
    orbitDragging,
    // 双环 + 蜂窝计算
    cpuOverhead,
    securityCoverage,
    overallScore,
    presetAmbienceMode,
    currentModeLabel,
    // SVG 环
    ringCircumference,
    ringDashOffset,
    // 轨道渐变
    orbitTrackGradient,
    // 特性列表分组
    toggleableFeatures,
    lockedFeatures,
    // 核心函数
    onOrbitSliderInput,
    onOrbitSliderRelease,
    snapToAnchor,
    onToggleGearPanel,
    onToggleCustomFeature,
    onResetCustom,
    onApplyCustom,
    onApplyPreset,
    loadPresetConfig,
  };
}

/** usePreset 返回值类型（便于显式标注） */
export type UsePresetReturn = ReturnType<typeof usePreset>;
