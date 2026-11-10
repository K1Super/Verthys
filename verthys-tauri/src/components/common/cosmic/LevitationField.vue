<!--
  LevitationField.vue — 悬浮场容器（无底板弹窗体系 · 静态版）
  设计（用于安全弹窗，区别于卡片式弹窗底板 CosmicDialog）：
    - 零底板：无背景 / 无边框 / 无阴影 / 无圆角面板 — 纯布局容器，
      UI 组件直接悬浮于遮罩之上（遮罩即空间，组件即天体）
    - 卡片职能由"场"承接：
        分组 → 轨道基准线（标题两侧 hairline）
        可读性 → 中心衰减渐晕（::before 径向暗化，无边缘无形状感知）
        层级 → 节点逐条显影入场（仅不透明度 + 2D 平移，无透视/旋转）
    - 静态驻留：无 3D 上下文、零监听、零 rAF、零每帧样式写入 —
      文字渲染恒定锐利
  节点协议（视图模板配合）：
    <div class="ff-node ff-node--{role}">        ← 出场层：逐条显影入射（一次性）
      …内容…
    </div>
    角色入场参数由 ff-node--{role} 规则承载。
  用法：
    <LevitationField width="330px">…ff-node…</LevitationField>
    <LevitationField width="420px" inline>…</LevitationField>   ← 模块内嵌（无遮罩场景）
-->
<template>
  <div
    class="ff-field"
    :class="{ 'ff-field--inline': inline }"
    :style="{ width }"
  >
    <slot />
  </div>
</template>

<script setup lang="ts">
interface Props {
  /** 场宽度（内容逻辑宽度，渐晕向外扩展） */
  width?: string;
  /** 模块内嵌模式：无全屏遮罩场景（设备拦截视图），渐晕收敛适配模块底景 */
  inline?: boolean;
}

withDefaults(defineProps<Props>(), {
  width: "330px",
  inline: false,
});
</script>
