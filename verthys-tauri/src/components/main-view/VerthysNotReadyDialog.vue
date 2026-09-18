<!--
  VerthysNotReadyDialog.vue — Verthys 未就绪提示弹窗
  从 MainView.vue 抽离，功能 100% 保留
-->
<template>
  <CosmicOverlay :show="show" width="380px" @close="$emit('close')">
    <div class="kv-title">数据存储未就绪</div>
    <div class="kv-desc">
      {{ pendingModuleLabel }} · 需要先初始化数据存储才能访问
    </div>
    <div class="kv-actions kv-actions-center">
      <button class="btn btn-primary kv-confirm" @click="$emit('go-to-security')">
        前往中枢
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";

defineProps<{
  show: boolean;
  pendingModuleLabel: string;
}>();

defineEmits<{
  (e: "close"): void;
  (e: "go-to-security"): void;
}>();
</script>
