<!--
  CosmicOverlay.vue — 可复用宇宙主题弹窗遮罩
  v3: 背景层由通用组件 CosmicBackdrop 提供，底板由 CosmicDialog 提供
  与 SecurityCenter 等模块共享统一背景 + 底板规范
-->
<template>
  <Transition name="cosmic">
    <CosmicBackdrop v-if="show" fixed @backdrop="onBackdrop">
      <CosmicDialog :width="width">
        <slot />
      </CosmicDialog>
    </CosmicBackdrop>
  </Transition>
</template>

<script setup lang="ts">
import CosmicBackdrop from "./CosmicBackdrop.vue";
import CosmicDialog from "./CosmicDialog.vue";

interface Props {
  show: boolean;
  width?: string;
  /** 点击遮罩背景是否关闭（默认 true） */
  backdropClose?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  width: "400px",
  backdropClose: true,
});

const emit = defineEmits<{ (e: "close"): void }>();

const onBackdrop = () => {
  if (props.backdropClose) emit("close");
};
</script>

<style scoped>
/* ===== 进场 / 退场动画（针对子组件根元素） ===== */
.cosmic-enter-active {
  transition: opacity 0.3s var(--ease);
}
.cosmic-enter-active :deep(.cosmic-dialog) {
  transition: opacity 0.45s var(--ease), transform 0.45s var(--ease), filter 0.45s var(--ease);
}
.cosmic-leave-active {
  transition: opacity 0.2s var(--ease);
}
.cosmic-leave-active :deep(.cosmic-dialog) {
  transition: opacity 0.2s var(--ease), transform 0.2s var(--ease), filter 0.2s var(--ease);
}
.cosmic-enter-from {
  opacity: 0;
}
.cosmic-enter-from :deep(.cosmic-dialog) {
  opacity: 0;
  transform: scale(0.92) translateY(20px);
  filter: blur(10px);
}
.cosmic-leave-to {
  opacity: 0;
}
.cosmic-leave-to :deep(.cosmic-dialog) {
  opacity: 0;
  transform: scale(0.96) translateY(8px);
  filter: blur(6px);
}
</style>
