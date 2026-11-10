<!--
  ConfirmDelete.vue — 通用删除二次确认弹窗

  形态：复用全局弹窗外壳 CosmicOverlay 与 kv-* 内容词汇，不另建底板。
  焦点：初始焦点落在取消键 —— 误按回车不得执行删除。

  用法：
    <ConfirmDelete
      :show="showConfirm"
      title=""
      desc=""
      @confirm="doDelete"
      @cancel="showConfirm = false"
    />
-->
<template>
  <CosmicOverlay
    :show="show"
    width="400px"
    role="alertdialog"
    initial-focus=".kv-cancel"
    aria-labelledby="cd-confirm-title"
    @close="onCancel"
  >
    <div class="kv-title" id="cd-confirm-title">{{ title }}</div>
    <div class="kv-desc">{{ desc }}</div>
    <div class="kv-actions">
      <button class="btn kv-cancel" type="button" @click="onCancel">取消</button>
      <button class="btn kv-confirm kv-danger" type="button" @click="onConfirm">
        确认删除
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import CosmicOverlay from "../cosmic/CosmicOverlay.vue";

interface Props {
  show: boolean;
  title?: string;
  desc?: string;
}

withDefaults(defineProps<Props>(), {
  title: "确认删除",
  desc: "此操作不可撤销，删除后数据将永久丢失",
});

const emit = defineEmits<{
  confirm: [];
  cancel: [];
}>();

const onCancel = (): void => emit("cancel");
const onConfirm = (): void => emit("confirm");
</script>
