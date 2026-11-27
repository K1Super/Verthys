<!--
  SpectrumSubPanel.vue — 引力谱系子分区骨架（单一来源）

  职责：收敛三个子面板重复的「坐标头 + 星座双栏 + 注记/错误尾栏」结构：
    1. 坐标头：坐标标签 / 标题 / 摘要；
    2. 双栏：左星座插槽（field）、右数据与端子插槽（info）；
    3. 尾栏：错误红字置前，随后渲染注记插槽；无错误且无注记时不渲染尾栏；
    4. 可选的 tail 插槽承载弹窗等不属于视觉布局的节点。

  样式仍在 section-field.css（.sf-sub*）；本组件只负责结构与插槽，
  危险域坐标色通过 tone 属性映射到 `.sf-sub-coord.is-danger`。
-->
<template>
  <section class="sf-sub" :aria-label="title">
    <header class="sf-sub-head">
      <span class="sf-sub-coord" :class="{ 'is-danger': tone === 'danger' }">{{ coord }}</span>
      <h3 class="sf-sub-title">{{ title }}</h3>
      <p class="sf-sub-digest">{{ digest }}</p>
    </header>

    <div class="sf-sub-grid">
      <slot name="field" />
      <div class="sf-sub-info">
        <slot name="info" />
      </div>
    </div>

    <div v-if="error || $slots.notes" class="sf-sub-notes">
      <p v-if="error" class="sf-sub-error">{{ error }}</p>
      <slot name="notes" />
    </div>

    <slot name="tail" />
  </section>
</template>

<script setup lang="ts">
/**
 * SpectrumSubPanel Props
 */
withDefaults(
  defineProps<{
    /** 分区坐标标签（mono/主字体由分区决定） */
    coord: string;
    /** 分区标题（同时作为 section 的可访问名） */
    title: string;
    /** 分区摘要 */
    digest: string;
    /** 坐标语义色：danger = 危险域红字直陈 */
    tone?: "default" | "danger";
    /** 当前错误（红字直陈；空串时不渲染） */
    error?: string;
  }>(),
  { tone: "default", error: "" },
);
</script>
