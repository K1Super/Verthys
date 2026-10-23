<!--
  UpdaterRepairDialog — 更新健康自检失败后的恢复入口

  只在启动自检失败或安装未完成时出现；修复物料存在时允许一键运行旧版安装器，
  缺失时如实说明并保留日志导出。视觉沿用既有对话框外壳与按钮语言，不新增阴影。
-->
<template>
  <VerthysDialog
    v-model="open"
    title="更新自检未通过"
    layout="plain"
    hide-actions
  >
    <div class="repair-body">
      <p class="repair-lead">{{ state?.reason ?? "新版本健康自检未通过" }}</p>

      <div v-if="state?.version" class="repair-meta">
        <div class="repair-row">
          <span class="repair-label">可修复版本</span>
          <span class="repair-value">{{ state.version }}</span>
        </div>
        <div v-if="state?.releaseId" class="repair-row">
          <span class="repair-label">发布标识</span>
          <span class="repair-value">{{ state.releaseId }}</span>
        </div>
      </div>
      <p v-else class="repair-missing">
        未找到可用的旧版安装包。请重新安装旧版或联系维护人。
      </p>

      <div class="repair-actions">
        <button class="btn kv-cancel" type="button" @click="open = false">关闭</button>
        <button class="btn" type="button" @click="$emit('export')">导出日志</button>
        <button
          class="btn btn-primary"
          type="button"
          :disabled="!state?.available"
          @click="$emit('repair')"
        >
          运行修复
        </button>
      </div>
    </div>
  </VerthysDialog>
</template>

<script setup lang="ts">
import { computed } from "vue";
import VerthysDialog from "../common/verthys-ui/VerthysDialog.vue";
import type { RepairState } from "../../composables/useAppUpdater";

const props = defineProps<{
  modelValue: boolean;
  state: RepairState | null;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", value: boolean): void;
  (e: "repair"): void;
  (e: "export"): void;
}>();

const open = computed({
  get: () => props.modelValue,
  set: (value: boolean) => emit("update:modelValue", value),
});
</script>

<style scoped>
.repair-body {
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-width: 420px;
  max-width: 520px;
}

.repair-lead {
  margin: 0;
  color: var(--text-primary);
  line-height: 1.7;
  font-size: 13px;
}

.repair-meta {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.repair-row {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 18px;
  border-bottom: 1px solid var(--border);
  padding-bottom: 6px;
}

.repair-label {
  color: var(--text-secondary);
  font-size: 12px;
}

.repair-value {
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: 12px;
  text-align: right;
  overflow-wrap: anywhere;
}

.repair-missing {
  margin: 0;
  color: var(--danger);
  font-size: 12px;
  line-height: 1.7;
}

.repair-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}
</style>
