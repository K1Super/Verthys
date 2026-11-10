<!--
  CosmicSubmit.vue — 引力锚点按钮（悬浮场体系）
  结构：零边框、零圆角、零底板 — 标注悬浮于场中，底部三层光谱能量轨
        （静默 hairline 轨 / 悬停充能轨 / loading 光包巡行轨）
  交互物理：
    - 悬停/焦点：充能 — 轨道自全宽收敛至 74%（--cs-reach-hover 唯一
      权威源，悬停/焦点/按下三态等比派生），标注升亮上浮 1px
    - 按下：引力压陷 — 标注下沉 2px + 轨道收缩
    - 禁用：休眠 — 整体沉降调暗；键盘焦点与悬停等价
    - loading：标注切换 + 光包沿轨非对称巡行（加速-滑行-消散），
      全轨巡行不受收敛约束
  轨道联动：待机微幅呼吸（非对称相位 7.4s）+ 悬浮先行全宽铺展
    （充能光谱延迟 50ms 跟进）+ 按下同步收缩；呼吸仅作用于 opacity，
    与 transform 伸展正交；idle 由全局空闲治理自动暂停
  用途：解锁 / 初始化 / 验证视图提交按钮
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
 * 引力锚点按钮（悬浮场体系）
 * - 零边框零圆角零底板：标注 + 光谱能量轨（与光谱底轨输入同构）
 * - 交互物理：悬停充能（伸展至 74% 终点）/ 按下压陷 / 禁用休眠 /
 *   loading 光包巡行 — 三态宽度由 --cs-reach-hover 等比派生
 * - 轨道联动：势能线待机呼吸 + 悬浮铺展 + 按下收缩 + loading
 *   全轨 — 与充能光谱轨差速联动
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
