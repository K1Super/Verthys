/**
 * usePreset.ts — 安全防护预设 Composable（三档模式 + 无极轨道滑块 + 自定义模板）
 *
 * 职责：
 *   1. 预设特性列表定义（presetFeatureList，与 Rust PresetFeatures 字段对齐）
 *   2. 预设应用状态（presetApplying / currentPresetFeatures）
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
 *   - 锚点播种：初始游标与激活锚点直接按后端权威档位推导（自定义档无锚点）
 *   - 氛围迟滞：阈值带 25/75 进入、31/69 退出，由 watch 收敛写 ref，computed 只读
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
  /** 显示错误提示（来自全局 Toast 中心） */
  showError: (msg: string) => void;
  /** 显示成功提示（SecurityCenter 顶层注入，全局 Toast 中心状态通道，2.5s 自动消失） */
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
 *   customPanelOpen, customFeatures,
 *   orbitSliderPos, orbitAnchors, nearestAnchorIdx, activeAnchorIdx, orbitDragging,
 *   cpuOverhead, securityCoverage, overallScore,
 *   presetAmbienceMode,
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
    { key: "integrity_check", label: "完整校验", desc: "启动镜像签名核验 · 运行期模块抽检" },
    { key: "memory_guard", label: "内存保护", desc: "内存锁定与防转储" },
    { key: "key_separation", label: "密钥分立", desc: "密钥分段隔离存储" },
    { key: "emergency_response", label: "紧急熔断", desc: "异常事件立即熔断销毁" },
    { key: "session_lock_on_idle", label: "空闲锁定", desc: "会话空闲超时自动锁定" },
    { key: "module_patrol", label: "模块巡检", desc: "定期扫描已加载模块签名" },
    { key: "clip_clear_on_lock", label: "剪贴板防护", desc: "锁定清空恒开 · 开启后监听并清除外部写入" },
    { key: "usb_clone_detect", label: "克隆检测", desc: "序列号哈希比对拒绝克隆外设" },
    { key: "trace_cleanup", label: "痕迹清理", desc: "退出时清理系统最近记录" },
  ];

  /* ===== 预设应用状态 ===== */
  /** 预设应用中标志（禁用按钮防止重复点击） */
  const presetApplying = ref(false);
  /** 档位同步失败标志（恢复链重试仍失败时置位；驱动面板可见提示） */
  const presetSyncFailed = ref(false);
  /** 当前预设的特性开关快照（驱动 UI 显示 ON/OFF） */
  const currentPresetFeatures = ref<Record<string, boolean>>({});

  /* ===== 自定义模板配置 ===== */
  /** 自定义面板展开状态 */
  const customPanelOpen = ref(false);
  /** 自定义特性配置（localStorage 持久化） */
  const customFeatures = ref<PresetFeatures>(loadCustomFeatures());

  /* ===== 无极轨道滑块 — 性能↔安全权衡 ===== */
  /** 三个磁性吸附锚点（视觉从左到右；code 为后端档位代号） */
  const orbitAnchors = [
    { pos: 0, label: '性能', code: 2 as SecurityPresetCode },
    { pos: 50, label: '平衡', code: 0 as SecurityPresetCode },
    { pos: 100, label: '安全', code: 1 as SecurityPresetCode },
  ];
  /** 初始激活锚点索引：按后端权威档位推导（-1 = 无锚点，自定义档） */
  const initialAnchorIdx = orbitAnchors.findIndex(a => a.code === securityPresetRef.value);
  /** 滑块位置 (0=性能, 50=平衡, 100=安全)；初始与权威档位同位，
   *  自定义档停靠中位（无档位语义），面板重挂载不闪回中性位 */
  const orbitSliderPos = ref(initialAnchorIdx >= 0 ? orbitAnchors[initialAnchorIdx].pos : 50);
  /** 最近锚点索引（拖拽时实时计算，用于磁性吸附视觉反馈；
   *  等距并列时优先初始锚点，无初始锚点时取中位锚点） */
  const nearestAnchorIdx = computed(() => {
    let min = Infinity, idx = initialAnchorIdx >= 0 ? initialAnchorIdx : 1;
    orbitAnchors.forEach((a, i) => {
      const d = Math.abs(orbitSliderPos.value - a.pos);
      if (d < min) { min = d; idx = i; }
    });
    return idx;
  });
  /** 当前激活锚点索引（松手后吸附到的位置；-1 = 自定义档无激活锚点） */
  const activeAnchorIdx = ref(initialAnchorIdx);
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
  /** 氛围收敛步数上限：单次推算内跨带跳变直接落位 */
  const AMBIENCE_CONVERGE_STEPS = 3;
  /** 氛围类锁存档位（迟滞退出判定基准，随收敛同步更新） */
  const ambienceLatch = ref<'performance' | 'balanced' | 'secure'>('balanced');
  /** 氛围收敛结果（由收敛函数写入；computed 只读，禁止副作用） */
  const ambienceConv = ref<'performance' | 'balanced' | 'secure'>('balanced');
  /** 迟滞收敛：从锁存档位出发按带宽迭代，最多 AMBIENCE_CONVERGE_STEPS 步 */
  const convergeAmbience = () => {
    const p = orbitSliderPos.value;
    let mode = ambienceLatch.value;
    for (let step = 0; step < AMBIENCE_CONVERGE_STEPS; step++) {
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
    ambienceConv.value = mode;
  };
  /* 滑块位置与权威档位变化驱动收敛；setup 期先播种一次，避免首帧回调缺位 */
  watch([orbitSliderPos, securityPresetRef], convergeAmbience);
  convergeAmbience();
  /** 环境光晕模式（自定义档无档位语义 → 恒为 balanced；其余取收敛结果） */
  const presetAmbienceMode = computed<'performance' | 'balanced' | 'secure'>(() =>
    securityPresetRef.value === 3 ? 'balanced' : ambienceConv.value,
  );

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
   * 切档失败或守卫拒绝时回撤到后端权威档位，界面状态恒收敛 */
  const onOrbitSliderRelease = () => {
    if (!orbitDragging.value) return;
    orbitDragging.value = false;
    /* 守卫：未就绪或切档进行中 → 视觉回撤到权威位置，
       禁止"已移动但未应用"的位置漂移 */
    if (!globalKeyReadyRef.value || presetApplying.value) {
      syncOrbitFromPresetRef();
      return;
    }
    const idx = nearestAnchorIdx.value;
    const anchor = orbitAnchors[idx];
    orbitSliderPos.value = anchor.pos;
    activeAnchorIdx.value = idx;
    if (securityPresetRef.value !== anchor.code) {
      void onApplyPreset(anchor.code).then((ok) => { if (!ok) syncOrbitFromPresetRef(); });
    }
  };
  /** 点击锚点 — 即时落位到锚点后切换（先落位后切换）；
   *  吸附路径统一复位拖拽标志，避免轨道渐变冻结在旧位置 */
  const snapToAnchor = (idx: number) => {
    if (!globalKeyReadyRef.value || presetApplying.value) return;
    orbitDragging.value = false;
    const anchor = orbitAnchors[idx];
    orbitSliderPos.value = anchor.pos;
    activeAnchorIdx.value = idx;
    if (securityPresetRef.value !== anchor.code) {
      void onApplyPreset(anchor.code).then((ok) => { if (!ok) syncOrbitFromPresetRef(); });
    }
  };
  /** 齿轮按钮 — 打开/关闭自定义面板；打开时切入自定义档 */
  const onToggleGearPanel = () => {
    customPanelOpen.value = !customPanelOpen.value;
    if (customPanelOpen.value && securityPresetRef.value !== 3) {
      void onApplyPreset(3).then((ok) => { if (!ok) syncOrbitFromPresetRef(); });
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

  /** 轨道游标与激活锚点对齐后端权威档位（成功同步 / 失败回撤共用）；
   *  自定义档无标准锚点语义：游标停靠中位并清除激活锚点高亮 */
  const syncOrbitFromPresetRef = () => {
    const code = securityPresetRef.value;
    if (code === 3) {
      orbitSliderPos.value = 50;
      activeAnchorIdx.value = -1;
      return;
    }
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
   *   2. 应用预设 → 更新特性快照
   *   3. 成功后同步轨道位置（与后端权威档位收敛同位），失败回撤原状
   *   4. 反馈时序：松手时释放处理器已即时落位到相邻档位（视觉先行），
   *      本函数延迟 220ms 且切换仍在进行中时 toast 提示目标模式，
   *      完成后 toast 提示切换结果（快速成功只出完成提示）
   * 返回值：true = 已发起且成功；false = 守卫拒绝或失败（调用方负责视觉回撤） */
  const onApplyPreset = async (code: SecurityPresetCode): Promise<boolean> => {
    if (presetApplying.value || !globalKeyReadyRef.value) return false;
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
      }
      // 同步本地会话超时显示（applySecurityPreset 内部已调用 setSessionTimeout）
      options.resetSession();
      // 成功后轨道位置与后端权威档位收敛同位（自定义档落中位、清锚点高亮）
      syncOrbitFromPresetRef();
      options.showToast(`已切换至 ${modeNames[code] ?? code} 模式`);
      // 自定义档自动展开自定义面板
      if (code === 3) customPanelOpen.value = true;
      return true;
    } catch (e) {
      console.error("[onApplyPreset] 切换预设失败", e);
      // 失败回撤：界面位置回齐后端权威档位（即时落位保持可逆）
      syncOrbitFromPresetRef();
      options.showError("切换预设失败");
      return false;
    } finally {
      if (applyToastTimer !== null) {
        clearTimeout(applyToastTimer);
        applyToastTimer = null;
      }
      presetApplying.value = false;
    }
  };

  /* ===== 加载预设配置（onMounted / 全局密钥就绪后调用） =====
   * 拉取当前权威档位的特性快照（能力状态栏的真实状态源）；
   * 自定义档直接取本地配置。此函数需由 SecurityCenter 在
   * onMounted / watch(globalKeyReadyRef) 中调用。 */
  const loadPresetConfig = async () => {
    try {
      const code = securityPresetRef.value;
      if (code === 3) {
        currentPresetFeatures.value = { ...customFeatures.value };
      } else {
        const config = await securityGetPresetConfig(code);
        // 加载期间档位可能已切换：仅当仍为同一档位时采纳结果
        if (config && securityPresetRef.value === code) {
          currentPresetFeatures.value = { ...config.features };
        }
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
    presetSyncFailed,
    currentPresetFeatures,
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
