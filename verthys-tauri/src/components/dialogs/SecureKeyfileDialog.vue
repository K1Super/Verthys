<!--
  SecureKeyfileDialog.vue — 高安全模式默认 keyfile 提示

  切换到安全（高安全）预设后，若当前库尚未启用 keyfile，提示用户生成新的
  .vkf 文件作为第二因子。启用后解锁需要“口令 + keyfile”；keyfile 丢失只能
  用恢复码解锁（恢复会话中可重绑）。用户可稍后到「全局密钥」面板手动启用。
-->
<template>
  <VerthysDialog
    :model-value="show"
    layout="plain"
    width="460px"
    title="高安全模式 · keyfile 第二因子"
    hide-actions
    :saving="busy"
    :persistent="busy"
    @update:model-value="(v: boolean) => { if (!v) $emit('close'); }"
  >
    <div class="kv-desc">
      安全预设默认建议启用 keyfile：解锁需要口令 + keyfile 文件双因子。
      请把 keyfile 保存在与容器不同的目录或介质，不要和容器一起备份。
    </div>
    <p class="kv-desc kv-desc-note">
      点击“选择位置并启用”后会生成新的 .vkf 文件；关闭本弹窗不会改变当前库。
    </p>
    <p v-if="error" class="kd-error">{{ error }}</p>
    <div class="kv-actions">
      <button class="btn kv-cancel" type="button" :disabled="busy" @click="$emit('close')">
        稍后
      </button>
      <button class="btn btn-primary kv-confirm" type="button" :disabled="busy" @click="onConfirm">
        {{ busy ? "启用中…" : "选择位置并启用" }}
      </button>
    </div>
  </VerthysDialog>
</template>

<script setup lang="ts">
import { ref, watch } from "vue";
import VerthysDialog from "../common/verthys-ui/VerthysDialog.vue";

const props = defineProps<{
  show: boolean;
  busy: boolean;
}>();

const emit = defineEmits<{
  (e: "close"): void;
  (e: "confirm"): void;
}>();

const error = ref("");

watch(
  () => props.show,
  (show) => {
    if (!show) error.value = "";
  },
);

const onConfirm = () => {
  if (props.busy) return;
  error.value = "";
  emit("confirm");
};
</script>
