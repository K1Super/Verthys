<!--
  CosmicSubmit.vue — 引力锚点按钮（v4.1 · 悬浮伸展收敛 · 悬浮场体系）
  ★ v4.1 悬浮伸展收敛（样式见 styles/security/cosmic-submit.css）：
    悬停/焦点充能终点自全宽收敛至 86%（--cs-reach-hover 唯一
    权威源，悬停/焦点/按下三态等比派生）— 悬停轨道锚定于标注
    场内不铺满整钮；loading 全轨巡行不受收敛约束
  ★ v4 轨道联动升级（样式见 styles/security/cosmic-submit.css）：
    - 静默势能线动态化：待机微幅呼吸（非对称相位 7.4s）+ 悬浮
      先行全宽铺展（充能光谱 +50ms 迟滞跟进 — 轨道先行/能量充入
      的分层纵深）+ 按下同步收缩 + loading 全轨充能
    - 呼吸仅作用于 opacity 通道，与 transform 伸展正交 — 无状态
      抢占；idle 由全局空闲治理自动暂停（氛围装饰类，未豁免）
  ★ v3 全面重设计（根除卡片式按钮语法 — 与引力悬浮场同源）：
    - 根除：深空底板渐变盒、SVG 巡行描边（圆角边框）、loading
      旋转环（border spinner 模板）— 零边框零圆角零底板
    - 重建（引力锚点 — 与光谱底轨输入同构语法）：
      1. 纯净锚点：无背景无边框无圆角 — 文字标注悬浮于场中，
         按钮即轨道上的一枚引力锚（遮罩即空间，组件即天体）
      2. 光谱能量轨：底部三层轨道 — 静默 hairline 轨 + 悬停充能轨
         （青→紫光谱渐变自中心 scaleX 展开）+ loading 光包巡行轨
         （一枚亮段沿轨差速巡行 — 数据注入锚点语义）
      3. 交互物理：悬停 = 充能（轨道延展 + 标注升亮上浮 1px）、
         按下 = 引力压陷（标注下沉 2px + 轨道收缩）、禁用 = 休眠
         （整体沉降调暗）、键盘焦点 = 充能等价 — 全部平滑复合缓动，
         无生硬跳转无弹性回弹
      4. loading：标注切换 + 光包沿轨非对称巡行（加速-滑行-消散）
  用途：解锁/初始化/验证视图提交按钮（悬浮场动作锚点）
  Props: label / loadingLabel / disabled / loading / compact
-->
<template>
  <button
    class="cosmic-submit"
    :class="{ 'cs-compact': compact, 'cs-loading': loading }"
    :disabled="disabled || loading"
    @click="onClick"
  >
    <span class="cs-label">
      <slot>{{ loading ? (loadingLabel || label) : label }}</slot>
    </span>
    <!-- 光谱能量轨（三层 — 静默轨 / 充能轨 / 光包巡行轨） -->
    <span class="cs-rail" aria-hidden="true">
      <i class="cs-rail-base"></i>
      <i class="cs-rail-charge"></i>
      <i v-if="loading" class="cs-rail-packet"></i>
    </span>
  </button>
</template>

<script setup lang="ts">
/**
 * 引力锚点按钮 v4.1（悬浮场体系）
 * - 零边框零圆角零底板：标注 + 光谱能量轨（与光谱底轨输入同构）
 * - 交互物理：悬停充能（伸展至 86% 终点）/ 按下压陷 / 禁用休眠 /
 *   loading 光包巡行 — 三态宽度由 --cs-reach-hover 等比派生
 * - v4 轨道联动：势能线待机呼吸 + 悬浮铺展 + 按下收缩 + loading
 *   全轨 — 与充能光谱轨差速联动（详见 cosmic-submit.css 头注）
 * - compact 模式：收敛纵向呼吸（适配短标签密集场）
 */
interface Props {
  /** 默认（非加载态）标签 */
  label: string;
  /** 加载态标签（缺省时回退到 label） */
  loadingLabel?: string;
  /** 禁用按钮 */
  disabled?: boolean;
  /** 加载态（光包巡行 + 切换标签） */
  loading?: boolean;
  /** 紧凑模式（收敛纵向呼吸 — 适配短标签） */
  compact?: boolean;
}
const props = withDefaults(defineProps<Props>(), {
  loadingLabel: '',
  disabled: false,
  loading: false,
  compact: false,
});
const emit = defineEmits<{
  click: [event: MouseEvent];
}>();
function onClick(e: MouseEvent) {
  if (props.disabled || props.loading) return;
  emit('click', e);
}
</script>

<style scoped>
@import '../../../styles/security/cosmic-submit.css';
</style>
