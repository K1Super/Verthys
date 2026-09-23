<!--
  ManagementView.vue — 管理主界面入口视图（薄容器）
  由 SecurityCenter.vue 拆分为 6 个管理子组件

  职责：
    1. 量子态势面板（mgmtView=dashboard）：委托 QuantumDashboard 渲染
    2. 前置引导区（mgmtView=hub）：ManagementHub 纯视觉引导（零文字），
       点击各引导单元进入对应管理界面
    3. 分区详情视图（mgmtView=detail）：按 activeSection 单区渲染
       GlobalKeySection / ModuleKeyList / SecurityDashboard —— 各区独立展示，
       避免全部模块聚合堆砌于一页
    4. 内部流转：dashboard → hub → detail（section）→ hub → dashboard；
       面板模块节点点击直达 moduleKeys 分区；hub 点击空白处返回 dashboard，
       detail 点击空白处返回 hub（无返回按钮/图标）
    5. panel-active 状态同步给父组件（管理三态均收起导航坞，悬浮才展开）

  Props: 从 SecurityCenter 顶层 Composable 注入的只读状态 + 函数（透传至子组件）
  defineModel: orbitSliderPos（透传至 SecurityDashboard）
  Emits: lock-all / open-change-key-dialog / export-bin / toggle-module-key-enabled /
         open-key-dialog / show-module-key / logout-module / toggle-gear-panel /
         toggle-custom-feature / reset-custom / apply-custom / orbit-slider-input /
         orbit-slider-release / snap-to-anchor / panel-active
-->
<template>
  <div class="view-management" :style="{ pointerEvents: initializing ? 'none' : 'auto' }">
    <!-- ===== 单一编排控制器：三态视图共用同一 Transition（out-in 严格串行）
       ===== 离场动画完成前入场不挂载 — 离场 Canvas / 入场挂载 / 模糊重绘
       ===== 绝不并行争抢主线程与合成器。key 保证三态间过渡触发。 -->
    <Transition name="mgmt-x" mode="out-in">
      <!-- 量子态势面板（进入中枢首屏） -->
      <QuantumDashboard
        v-if="mgmtView === 'dashboard'"
        key="dashboard"
        :global-key-ready="globalKeyReady"
        :module-ids="moduleIds"
        :module-labels="moduleLabels"
        :module-state-class="moduleStateClass"
        :module-state-text="moduleStateText"
        @enter-section="enterSection"
      />

      <!-- 前置引导区（纯视觉 · 零文字）；点击引导单元后由传播完成事件驱动进入 -->
      <ManagementHub
        v-else-if="mgmtView === 'hub'"
        key="hub"
        :global-key-ready="globalKeyReady"
        :device-check-result="deviceCheckResult"
        :module-ids="moduleIds"
        :module-state-class="moduleStateClass"
        @enter="enterHubSection"
        @back="mgmtView = 'dashboard'"
      />

      <!-- 分区详情视图（单区渲染，避免聚合堆砌） -->
      <div v-else-if="mgmtView === 'detail'" key="detail" ref="detailRef" class="mgmt-detail">
        <!-- 顶部状态栏（各区常驻） -->
        <ManagementTopBar
          :global-key-ready="globalKeyReady"
          :session-remaining="sessionRemaining"
          @lock-all="$emit('lockAll')"
        />

        <!-- 分区 1：全局密钥已就绪状态 + 全局密钥-设备绑定 -->
        <GlobalKeySection
          v-if="activeSection === 'globalKey'"
          :global-key-ready="globalKeyReady"
          :device-fingerprint-short="deviceFingerprintShort"
          @open-change-key-dialog="$emit('openChangeKeyDialog')"
          @export-bin="$emit('exportBin')"
        />

        <!-- 分区 2：模块独立密钥管理 -->
        <ModuleKeyList
          v-if="activeSection === 'moduleKeys'"
          :global-key-ready="globalKeyReady"
          :module-ids="moduleIds"
          :module-labels="moduleLabels"
          :module-key-enabled="moduleKeyEnabled"
          :has-module-key-record="hasModuleKeyRecord"
          :module-key-ready="moduleKeyReady"
          :has-module-key="hasModuleKey"
          :is-module-ready="isModuleReady"
          :module-state-class="moduleStateClass"
          :module-state-text="moduleStateText"
          @toggle-module-key-enabled="(mid, enabled) => $emit('toggleModuleKeyEnabled', mid, enabled)"
          @open-key-dialog="(mid) => $emit('openKeyDialog', mid)"
          @show-module-key="(mid) => $emit('showModuleKey', mid)"
          @logout-module="(mid) => $emit('logoutModule', mid)"
        />

        <!-- 分区 3：安全防护仪表盘 -->
        <SecurityDashboard
          v-if="activeSection === 'security'"
          :global-key-ready="globalKeyReady"
          :security-preset-code="securityPresetCode"
          :preset-applying="presetApplying"
          :preset-ambience-mode="presetAmbienceMode"
          :cpu-overhead="cpuOverhead"
          :security-coverage="securityCoverage"
          :overall-score="overallScore"
          :ring-circumference="ringCircumference"
          :ring-dash-offset="ringDashOffset"
          :orbit-anchors="orbitAnchors"
          :nearest-anchor-idx="nearestAnchorIdx"
          :active-anchor-idx="activeAnchorIdx"
          :orbit-track-gradient="orbitTrackGradient"
          :toggleable-features="toggleableFeatures"
          :locked-features="lockedFeatures"
          :preset-features="presetFeatures"
          :custom-features="customFeatures"
          :custom-panel-open="customPanelOpen"
          :defense-paths="defensePaths"
          :defense-meta="defenseMeta"
          v-model:orbit-slider-pos="orbitSliderPos"
          @toggle-gear-panel="$emit('toggleGearPanel')"
          @toggle-custom-feature="(key) => $emit('toggleCustomFeature', key)"
          @reset-custom="$emit('resetCustom')"
          @apply-custom="$emit('applyCustom')"
          @orbit-slider-input="$emit('orbitSliderInput')"
          @orbit-slider-release="$emit('orbitSliderRelease')"
          @snap-to-anchor="(idx) => $emit('snapToAnchor', idx)"
        />
      </div>
    </Transition>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import type { ModuleId } from "../../lib/keyManager";
import type { DeviceCheckResult } from "../../composables/security-center/useViewMode";
import type { DefensePathView, DefenseMetaView } from "../../composables/security-center/useDefenseStatus";
import QuantumDashboard from "../management/QuantumDashboard.vue";
import ManagementHub from "../management/ManagementHub.vue";
import ManagementTopBar from "../management/ManagementTopBar.vue";
import GlobalKeySection from "../management/GlobalKeySection.vue";
import ModuleKeyList from "../management/ModuleKeyList.vue";
import SecurityDashboard from "../management/SecurityDashboard.vue";

/* ===== Props 接口定义（从 SecurityCenter 顶层 Composable 注入，透传至子组件） ===== */
const props = defineProps<{
  /** 初始化守卫：组件挂载期间禁止管理视图交互 */
  initializing: boolean;
  /** 全局密钥就绪状态 */
  globalKeyReady: boolean;
  /** 会话剩余时间（毫秒，UI 倒计时显示） */
  sessionRemaining: number;
  /** 设备绑定校验结果（引导单元视觉形态） */
  deviceCheckResult: DeviceCheckResult;
  /** 设备机器码短显示 */
  deviceFingerprintShort: string;
  /** 模块 ID 列表（MODULE_IDS） */
  moduleIds: ModuleId[];
  /** 模块标签映射（MODULE_LABELS） */
  moduleLabels: Record<string, string>;
  /** 模块密钥保护开关状态 */
  moduleKeyEnabled: Record<string, boolean>;
  /** 模块密钥记录是否存在 */
  hasModuleKeyRecord: Record<string, boolean>;
  /** 模块密钥就绪（已登录）状态 */
  moduleKeyReady: Record<string, boolean>;
  /** 检查模块是否有密钥（函数） */
  hasModuleKey: (mid: ModuleId) => boolean;
  /** 检查模块是否就绪（函数） */
  isModuleReady: (mid: ModuleId) => boolean;
  /** 模块状态指示条样式类（函数） */
  moduleStateClass: (mid: ModuleId) => string;
  /** 模块状态文本（函数） */
  moduleStateText: (mid: ModuleId) => string;
  /** 安全预设代码 */
  securityPresetCode: number;
  /** 预设应用中状态 */
  presetApplying: boolean;
  /** 预设环境光效模式 */
  presetAmbienceMode: string;
  /** CPU/IO 开销百分比 */
  cpuOverhead: number;
  /** 安全覆盖度百分比 */
  securityCoverage: number;
  /** 综合评分 */
  overallScore: number;
  /** 双环周长 */
  ringCircumference: number;
  /** 双环 dashOffset 计算函数 */
  ringDashOffset: (val: number) => number;
  /** 轨道锚点列表 */
  orbitAnchors: Array<{ pos: number; label: string; code: number }>;
  /** 最近锚点索引 */
  nearestAnchorIdx: number;
  /** 当前激活锚点索引 */
  activeAnchorIdx: number;
  /** 轨道渐变样式 */
  orbitTrackGradient: Record<string, string>;
  /** 可切换特性列表 */
  toggleableFeatures: Array<{ key: string; label: string; desc: string }>;
  /** 锁定特性列表 */
  lockedFeatures: Array<{ key: string; label: string; desc: string }>;
  /** 已应用预设特性开关快照（后端权威配置，能力状态栏真实状态源） */
  presetFeatures: Record<string, boolean>;
  /** 自定义特性配置 */
  customFeatures: Record<string, boolean>;
  /** 自定义面板展开状态 */
  customPanelOpen: boolean;
  /** 动态防护路径状态列表（7 攻击路径 × 4 态） */
  defensePaths: DefensePathView[];
  /** 动态防护汇总态势（计数 + 全阻断标志 + 总体态势） */
  defenseMeta: DefenseMetaView;
}>();

/* ===== defineModel：无极轨道滑块位置双向绑定（透传至 SecurityDashboard） ===== */
const orbitSliderPos = defineModel<number>("orbitSliderPos", { default: 50 });

/* ===== Emits 定义（所有用户操作转发至 SecurityCenter，由 Composable 处理） ===== */
const emit = defineEmits<{
  /** 面板激活状态变化（dashboard=true / detail=false） */
  (e: "panel-active", val: boolean): void;
  /** 立即锁定全部并清零内存密钥 */
  (e: "lockAll"): void;
  /** 打开修改全局密钥弹窗 */
  (e: "openChangeKeyDialog"): void;
  /** 导出当前密钥文件备份 */
  (e: "exportBin"): void;
  /** 切换模块密钥保护开关 */
  (e: "toggleModuleKeyEnabled", mid: ModuleId, enabled: boolean): void;
  /** 打开模块密钥编辑弹窗 */
  (e: "openKeyDialog", mid: ModuleId): void;
  /** 查看/复制模块密钥 */
  (e: "showModuleKey", mid: ModuleId): void;
  /** 登出模块 */
  (e: "logoutModule", mid: ModuleId): void;
  /** 切换齿轮（自定义）面板 */
  (e: "toggleGearPanel"): void;
  /** 切换单个自定义特性 */
  (e: "toggleCustomFeature", key: string): void;
  /** 恢复自定义默认 */
  (e: "resetCustom"): void;
  /** 保存并应用自定义配置 */
  (e: "applyCustom"): void;
  /** 轨道滑块输入中 */
  (e: "orbitSliderInput"): void;
  /** 轨道滑块释放（磁性吸附） */
  (e: "orbitSliderRelease"): void;
  /** 吸附到指定锚点 */
  (e: "snapToAnchor", idx: number): void;
}>();

/* ===== 内部状态：管理视图三态流转 =====
 *   mgmtView：dashboard（量子面板）→ hub（无文字前置引导）→ detail（分区详情）
 *   activeSection：detail 内当前分区（单区渲染，避免聚合堆砌）
 *   panel-active 状态通过 watch 同步给父组件（三态均收起导航坞） */
const mgmtView = ref<"dashboard" | "hub" | "detail">("dashboard");
const activeSection = ref<"globalKey" | "moduleKeys" | "security">("globalKey");

/* 面板入口（QuantumDashboard）：
 *   核心点击（globalKey）→ 前置引导区（管理界面前置组件）
 *   模块节点点击（moduleKeys）→ 直达模块密钥分区 */
const enterSection = (section: "globalKey" | "moduleKeys") => {
  if (props.initializing) return;
  if (section === "globalKey") {
    mgmtView.value = "hub";
  } else {
    activeSection.value = "moduleKeys";
    mgmtView.value = "detail";
  }
};

/* 引导区入口（ManagementHub）：点击引导单元进入对应管理界面分区 */
const enterHubSection = (section: "globalKey" | "moduleKeys" | "security") => {
  activeSection.value = section;
  mgmtView.value = "detail";
};

/* ============================================================
 * 分区详情「点击空白处返回引导区」— 几何命中判定（健壮设计）
 * ============================================================
 * 旧实现（e.target === e.currentTarget）的结构性缺陷：
 *   判定依赖点击落点的 DOM 归属 —— 分区根元素透明铺满、祖先容器
 *   padding、高度链塌陷等任何一种布局状况都会让空白点击落在
 *   非容器元素上，判定永不成立。
 *
 * 本实现三层门控，均与布局结构无关：
 *   0. 弹窗层豁免：命中元素位于 .cosmic-backdrop 弹窗层内 → 归弹窗交互域
 *      （CosmicBackdrop 为 inline fixed 非 Teleport，DOM 上仍是 shell 后代，
 *       不豁免会导致点遮罩关弹窗的同时误触返回引导）
 *   1. 外壳包含判定：命中元素必须位于 .security-center 管理外壳之内
 *      —— 导航 dock 等外部元素的点击直接忽略（祖先链上溯，无 DOM 查询开销）
 *   2. 几何包围盒判定：点击坐标（clientX/Y 视口系）若落在任一内容
 *      元素（会话谱线 .sf-meridian / 当前分区 .sf-zone）的
 *      getBoundingClientRect 包围盒内 → 视为内容点击，不返回；
 *      否则视为空白 → 返回引导区
 *
 * 健壮性保障：
 *   - 滚动安全：getBoundingClientRect 为视口系实时渲染位置，
 *     与 clientX/Y 同坐标系，容器滚动/变换后依然精确
 *   - 冒泡免疫：document 捕获阶段监听，内部 stopPropagation 不影响
 *   - 状态门控：仅 detail 态 + 非初始化 + 主键点击生效
 *   - 生命周期闭环：随组件挂载注册 / 卸载精确移除（同一引用）
 */
const detailRef = ref<HTMLElement | null>(null);

/** 判定节点是否位于指定祖先元素之内（祖先链上溯，O(深度)） */
function isWithin(node: Node | null, ancestor: Element): boolean {
  let cur: Node | null = node;
  while (cur) {
    if (cur === ancestor) return true;
    cur = cur.parentNode;
  }
  return false;
}

/** document 捕获阶段点击处理：空白处返回引导区 */
const onDetailBlankClick = (e: MouseEvent) => {
  if (mgmtView.value !== "detail" || props.initializing) return;
  if (e.button !== 0 || !(e.target instanceof Element)) return;
  const root = detailRef.value;
  if (!root || !root.isConnected) return;

  /* 0. 弹窗层豁免：CosmicBackdrop 系弹窗为 inline fixed（非 Teleport），
   *    DOM 上仍是 shell 后代 —— 遮罩/卡片点击归弹窗交互域所有
   *    （遮罩点击=关弹窗），严禁同时触发返回引导 */
  if (e.target.closest(".cosmic-backdrop")) return;

  /* 1. 外壳包含判定：仅响应管理外壳内的点击（导航 dock 等外部元素忽略） */
  const shell = root.closest(".security-center") ?? root;
  if (!isWithin(e.target, shell)) return;

  /* 2. 几何包围盒判定：落在会话谱线或分区（引力谱系无底板体系）内的
   *    点击为内容点击 */
  const contents = root.querySelectorAll<HTMLElement>(".sf-meridian, .sf-zone");
  for (const el of contents) {
    const r = el.getBoundingClientRect();
    if (
      e.clientX >= r.left && e.clientX <= r.right &&
      e.clientY >= r.top && e.clientY <= r.bottom
    ) {
      return;
    }
  }

  mgmtView.value = "hub";
};

onMounted(() => document.addEventListener("click", onDetailBlankClick, true));
onBeforeUnmount(() => document.removeEventListener("click", onDetailBlankClick, true));

/* 面板激活状态同步给父组件（收起导航坞）：管理三态均视为面板激活，
 * 导航坞悬浮 Dock 区域才展开 —— 与首屏量子面板行为一致，
 * 避免进入引导区/分区详情后导航坞常驻弹出 */
watch(mgmtView, () => emit("panel-active", true), { immediate: true });
</script>
