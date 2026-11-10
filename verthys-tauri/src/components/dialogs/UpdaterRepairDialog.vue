<!--
  UpdaterRepairDialog — 更新健康自检失败后的恢复入口

  只在启动自检失败或安装未完成时出现；修复物料存在时允许一键运行旧版安装器，
  缺失时如实说明。外壳与内容词汇统一复用全局弹窗组件。
-->
<template>
  <CosmicOverlay :show="open" width="460px" aria-labelledby="repair-title" @close="open = false">
    <div class="kv-title" id="repair-title">更新自检未通过</div>
    <p class="kv-desc">{{ state?.reason ?? "新版本健康自检未通过" }}</p>

    <div v-if="state?.version" class="kv-form">
      <div class="kv-row">
        <span class="kv-row-label">可修复版本</span>
        <span class="kv-row-value">{{ state.version }}</span>
      </div>
      <div v-if="state?.releaseId" class="kv-row">
        <span class="kv-row-label">发布标识</span>
        <span class="kv-row-value">{{ state.releaseId }}</span>
      </div>
    </div>
    <p v-else class="kv-error">
      未找到可用的旧版安装包。请重新安装旧版或联系维护人。
    </p>

    <div class="kv-actions">
      <button class="btn kv-cancel" type="button" @click="open = false">关闭</button>
      <button
        class="btn btn-primary kv-confirm"
        type="button"
        :disabled="!state?.available"
        @click="$emit('repair')"
      >
        运行修复
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { computed } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";
import type { RepairState } from "../../composables/useAppUpdater";

const props = defineProps<{
  modelValue: boolean;
  state: RepairState | null;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", value: boolean): void;
  (e: "repair"): void;
}>();

const open = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit("update:modelValue", value),
});
</script>
