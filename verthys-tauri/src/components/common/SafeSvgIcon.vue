<template>
  <span ref="host" class="safe-svg-icon" aria-hidden="true"></span>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import { sanitizeSvg } from "../../utils/safe_svg";

const props = defineProps<{ source: string }>();
const host = ref<HTMLSpanElement | null>(null);

function render(): void {
  const el = host.value;
  if (!el) return;
  el.replaceChildren();
  const svg = sanitizeSvg(props.source ?? "");
  if (svg) {
    el.appendChild(document.importNode(svg, true));
  }
}

onMounted(render);
watch(() => props.source, render);
</script>

<style scoped>
/* 宿主只负责居中，不声明自身宽高：尺寸属于使用方的布局决策。
 * 组件自带 width/height 会编译成带 scope 属性的选择器（特异性高于使用方
 * 写在全局样式表里的单类规则），把管理面板卫星图标的 19px 覆盖成 100%，
 * 图标遂按 48px 热区放大并溢出刻度环（环半径 20.5px）。 */
.safe-svg-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

/* 图形填满使用方给定的宿主盒；viewBox 负责等比缩放。 */
.safe-svg-icon :deep(svg) {
  width: 100%;
  height: 100%;
}
</style>
