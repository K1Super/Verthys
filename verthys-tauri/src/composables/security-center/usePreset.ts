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
 *   5. 双环三指标计算（cpuOverhead 后端采样 / securityCoverage 与
 *      overallScore 真实信号双权重合成，纯函数层 presetMetrics）
 *   6. 特性列表分组（toggleableFeatures / lockedFeatures）
 *   7. 核心函数：
 *      - onOrbitSliderInput / onOrbitSliderRelease：滑块拖拽 + 磁性吸附
 *      - snapToAnchor：点击锚点直接吸附并切换
 *      - onToggleGearPanel：齿轮按钮打开/关闭自定义面板
 *      - onToggleCustomFeature / onResetCustom / onApplyCustom：自定义特性管理
 *      - onApplyPreset：应用三档预设（调用 keyManager.applySecurityPreset）
 *      - loadPresetConfig：加载预设配置（onMounted / 全局密钥就绪后调用）
 *
 * 设计：
 *   - keyManager 单例 ref（securityPresetRef / globalKeyReadyRef）直接从 keyManager 导入
 *   - 外部依赖通过参数注入：showError / showToast / resetSession（来自 useSessionTimer）
 *   - 滑块磁性吸附：拖拽时实时更新视觉，松手时吸附到最近锚点并应用预设
 *   - 预设应用防重复：presetApplying 标志禁用按钮
 *   - 特性快照缓存：presetFeaturesCache 预加载各预设特性，用于特性摘要条显示
 *
 * 设计：纯 Composable，所有外部依赖通过参数注入，状态和方法返回给调用方。
 *      loadPresetConfig 需由 SecurityCenter 在 onMounted / watch(globalKeyReadyRef) 中调用。
 */

import { ref, computed, watch, onBeforeUnmount, type Ref } from 'vue';
import {
  securityPresetRef,
  applySecurityPreset,
  bumpPresetEpoch,
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
import { withTimeout } from '../../utils/promise_utils';
import type { DefenseMetaView } from './useDefenseStatus';
import { computeSecurityCoverage, computeOverallScore } from './presetMetrics';

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
  /** 系统 CPU 占用率（真实采样轮询值；-1 = 尚无基线） */
  cpuUsage: Ref<number>;
  /** 动态防护汇总态势（真实运行时报告） */
  defenseMeta: Ref<DefenseMetaView>;
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
    { key: "anti_debug", label: "调试检测", desc: "调试器检测与反附加" },
    { key: "anti_inject", label: "注入拦截", desc: "DLL 注入与搜索顺序加固" },
    { key: "integrity_check", label: "完整校验", desc: "启动与运行期完整性核验" },
    { key: "memory_guard", label: "内存保护", desc: "内存锁定与防转储" },
    { key: "key_separation", label: "密钥分立", desc: "密钥分段隔离存储" },
    { key: "emergency_response", label: "紧急熔断", desc: "异常事件立即熔断销毁" },
    { key: "session_lock_on_idle", label: "空闲锁定", desc: "会话空闲超时自动锁定" },
    { key: "shadow_sleep", label: "影子休眠", desc: "USB 拔出后索引加密驻留" },
    { key: "module_patrol", label: "模块巡检", desc: "定期扫描已加载模块签名" },
    { key: "clip_clear_on_lock", label: "剪贴清零", desc: "锁定时清除剪贴板残留" },
    { key: "usb_clone_detect", label: "克隆检测", desc: "序列号哈希比对拒绝克隆外设" },
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
  /* 初始位置对齐后端权威档位：面板重挂载时不闪回中性位，
   * loadPresetConfig 异步确认后由同一逻辑收敛（两侧同源） */
  {
    const anchor = orbitAnchors.find(a => a.code === securityPresetRef.value);
    if (anchor) orbitSliderPos.value = anchor.pos;
  }
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

  /* ===== 双环三指标（真实数据合成，无随滑块摆动的模拟公式） ===== */
  /** CPU/IO 开销 — 后端系统采样真实值（-1 无基线时按 0 占位，2s 内更新） */
  const cpuOverhead = computed(() => Math.max(0, options.cpuUsage.value));
  /** 当前档位已启用特性数（后端权威配置快照） */
  const enabledFeatureCount = computed(() =>
    Object.values(currentPresetFeatures.value).filter(Boolean).length,
  );
  /** 安全覆盖度 — 启用特性占比 × 动态防护已防御占比 双权重合成 */
  const securityCoverage = computed(() =>
    computeSecurityCoverage({
      enabledCount: enabledFeatureCount.value,
      totalCount: presetFeatureList.length,
      blocked: options.defenseMeta.value.blocked,
      degraded: options.defenseMeta.value.degraded,
      failed: options.defenseMeta.value.failed,
    }),
  );
  /** 综合评分 — 覆盖度与系统负载双权重合成 */
  const overallScore = computed(() =>
    computeOverallScore(securityCoverage.value, options.cpuUsage.value),
  );
  /* 氛围类迟滞带宽（百分点）：进入带 25/75，退出带 31/69 —
     滑块在阈值附近往复时消除类切换风暴 */
  const AMBIENCE_HYSTERESIS = 6;
  /** 氛围类锁存档位（迟滞退出判定基准，随推算收敛同步更新） */
  const ambienceLatch = ref<'performance' | 'balanced' | 'secure'>('balanced');
  /** 环境光晕模式（迟滞收敛：单次推算内跨带跳变直接落位，最多 3 步收敛） */
  const presetAmbienceMode = computed<'performance' | 'balanced' | 'secure'>(() => {
    if (securityPresetRef.value === 3) return 'balanced';
    const p = orbitSliderPos.value;
    let mode = ambienceLatch.value;
    for (let step = 0; step < 3; step++) {
      const next =
        mode === 'performance'
          ? p > 25 + AMBIENCE_HYSTERESIS ? 'balanced' : mode
          : mode === 'secure'
            ? p < 75 - AMBIENCE_HYSTERESIS ? 'balanced' : mode
            : p < 25 ? 'performance'
              : p > 75 ? 'secure'
                : mode;
      if (next === mode) break;
      mode = next;
    }
    ambienceLatch.value = mode;
    return mode;
  });
  /** 当前模式标签 — 以 securityPresetRef（后端权威档位）为单一事实源 */
  const currentModeLabel = computed(() => {
    const code = securityPresetRef.value;
    if (code === 3) return '自定义';
    const labels: Record<number, string> = { 0: '平衡', 1: '安全', 2: '性能' };
    return labels[code] ?? '平衡';
  });

  /* ===== SVG 环周长 + dashoffset 计算 ===== */
  /** SVG 环周长 (r=50 → 2πr ≈ 314.159) */
  const ringCircumference = 2 * Math.PI * 50;
  /** 计算环的 stroke-dashoffset */
  const ringDashOffset = (percentage: number): number => {
    return ringCircumference * (1 - percentage / 100);
  };

  /* ===== 轨道渐变背景 ===== */
/** 渐变色随滑块位置流动；渐变 background 为每帧重绘属性，
 *  却随拖拽模型同步（120ms 节拍）持续改写 —— 冻结至松手吸附后
 *  一次性写最新位置（拖拽期视觉可感知差异为间隔渐变，取舍为性能） */
const gradientPos = ref(orbitSliderPos.value);
watch(orbitSliderPos, (p) => {
  if (!orbitDragging.value) gradientPos.value = p;
});
/** 轨道渐变背景 — 流动位置取自冻结档位 */
const orbitTrackGradient = computed(() => ({
  background: `linear-gradient(90deg,
    rgba(0,255,200,0.25) 0%,
    rgba(0,212,255,0.35) ${gradientPos.value / 2}%,
    rgba(139,92,246,0.35) ${50 + gradientPos.value / 2}%,
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
  /** 滑块松手时磁性吸附到最近锚点：先即时落位到相邻档位（视觉先行，
   * 游标过渡动画即刻启动），目标档位与当前档不同再异步切档；
   * 切档失败时回撤到后端权威档位，界面状态恒收敛 */
  const onOrbitSliderRelease = () => {
    if (!orbitDragging.value) return;
    orbitDragging.value = false;
    const idx = nearestAnchorIdx.value;
    const anchor = orbitAnchors[idx];
    orbitSliderPos.value = anchor.pos;
    activeAnchorIdx.value = idx;
    if (securityPresetRef.value !== anchor.code) {
      onApplyPreset(anchor.code);
    }
  };
  /** 点击锚点 — 即时落位到锚点后切换（同上：先落位后切换） */
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
    // 竞态仲裁：用户显式切换递增版本，使在途恢复链自弃
    bumpPresetEpoch();
    try {
      saveCustomFeatures(customFeatures.value);
      // 8s 超时兜底：预设应用链路阻塞时不得无限 pending 卡死按钮
      const config = await withTimeout(applySecurityPreset(3), 8000, "应用自定义模板");
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

  /* ===== 切档状态收口 ===== */
  /** 切档开始提示延迟计时器（toast 晚于落位动画启动；收口时清理） */
  let applyToastTimer: ReturnType<typeof setTimeout> | null = null;

  /** 轨道游标与激活锚点对齐后端权威档位（成功同步 / 失败回撤共用） */
  const syncOrbitFromPresetRef = () => {
    const code = securityPresetRef.value;
    if (code === 3) return;
    const anchor = orbitAnchors.find(a => a.code === code);
    if (anchor) {
      orbitSliderPos.value = anchor.pos;
      activeAnchorIdx.value = orbitAnchors.indexOf(anchor);
    }
  };

  onBeforeUnmount(() => {
    if (applyToastTimer !== null) {
      clearTimeout(applyToastTimer);
      applyToastTimer = null;
    }
  });

  /* ===== 应用三档预设（调用 keyManager.applySecurityPreset） =====
   * 流程：
   *   1. 防重复守卫（presetApplying / globalKeyReady）
   *   2. 应用预设 → 更新特性快照 + 缓存
   *   3. 成功后同步轨道位置（与后端权威档位收敛同位），失败回撤原状
   *   4. 反馈时序：松手时释放处理器已即时落位到相邻档位（视觉先行），
   *      本函数延迟 220ms 且切换仍在进行中时 toast 提示目标模式，
   *      完成后 toast 提示切换结果（快速成功只出完成提示） */
  const onApplyPreset = async (code: SecurityPresetCode) => {
    if (presetApplying.value || !globalKeyReadyRef.value) return;
    presetApplying.value = true;
    // 竞态仲裁：用户显式切换递增版本，使在途恢复链自弃
    bumpPresetEpoch();
    const modeNames: Record<number, string> = { 0: '平衡', 1: '安全', 2: '性能', 3: '自定义' };
    // 开始提示晚于落位动画启动：仅当切换仍在进行中才显示
    if (applyToastTimer !== null) clearTimeout(applyToastTimer);
    applyToastTimer = setTimeout(() => {
      applyToastTimer = null;
      if (presetApplying.value) {
        options.showToast(`正在切换至 ${modeNames[code] ?? code} 模式…`);
      }
    }, 220);
    try {
      // 8s 超时兜底：预设应用链路阻塞时不得无限 pending 卡死按钮
      const config = await withTimeout(applySecurityPreset(code), 8000, "切换安全预设");
      if (config) {
        currentPresetFeatures.value = { ...config.features };
        // 缓存各预设特性快照（用于特性摘要条显示）
        presetFeaturesCache.value[code] = { ...config.features };
      }
      // 同步本地会话超时显示（applySecurityPreset 内部已调用 setSessionTimeout）
      options.resetSession();
      // 成功后轨道位置与后端权威档位收敛同位（CUSTOM 保持游标位）
      syncOrbitFromPresetRef();
      options.showToast(`已切换至 ${modeNames[code] ?? code} 模式`);
      // CUSTOM 预设自动展开自定义面板
      if (code === 3) customPanelOpen.value = true;
    } catch (e) {
      console.error("[onApplyPreset] 切换预设失败", e);
      // 失败回撤：界面位置回齐后端权威档位（即时落位保持可逆）
      syncOrbitFromPresetRef();
      options.showError("切换预设失败");
    } finally {
      if (applyToastTimer !== null) {
        clearTimeout(applyToastTimer);
        applyToastTimer = null;
      }
      presetApplying.value = false;
    }
  };

  /* ===== 加载预设配置（onMounted / 全局密钥就绪后调用） =====
   * 预加载所有标准预设的特性快照，用于特性摘要条显示。
   * 此函数需由 SecurityCenter 在 onMounted / watch(globalKeyReadyRef) 中调用。 */
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
      // 同步无极轨道滑块到当前预设位置（与切档成功/失败共用同一逻辑）
      syncOrbitFromPresetRef();
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
