<!--
  VerthysSearchBar.vue — 模块搜索栏（复用组件）
  外观：星野导航带 —— 半透明无框；底板、星野与左右溶解边界由 StarlitSky 承担，
        本组件仅负责布局承载（.starlit-bar 提供图层秩序）
  用法:
    <VerthysSearchBar v-model="searchKey" placeholder="搜索账号…" add-label="添加账号" @add="onAdd">
      <template #filters>…</template>
    </VerthysSearchBar>
-->
<template>
  <div class="search-bar starlit-bar">
    <StarlitSky :seed="skySeed" />
    <div class="search-inner">
      <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
      </svg>
      <input class="search-input" :value="modelValue" @input="onInput" :placeholder="placeholder" />
      <slot name="filters" />
    </div>
    <ActionButton :label="addLabel" @click="$emit('add')" />
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount } from "vue";
import ActionButton from "./ActionButton.vue";
import StarlitSky from "../cosmic/StarlitSky.vue";
import { debounce } from "../../../utils/debounce";

/* 项3：搜索输入防抖（300ms 尾部触发）
 * 原问题：v-model 每次按键触发 update:modelValue → 父组件 computed filter
 *        连续快速输入时累加造成可感知延迟（每按键卡顿 50ms）。
 * 优化后：用户停止输入 300ms 后才触发过滤，输入过程零卡顿。 */
defineProps<{
  modelValue: string;
  placeholder?: string;
  addLabel?: string;
  /* 星野相位种子：各模块传入不同值，使各处导航带的星空分布互不相同 */
  skySeed?: number;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", val: string): void;
  (e: "add"): void;
}>();

/* 防抖发射 update:modelValue（300ms 尾部触发） */
const debouncedEmit = debounce((v: string) => {
  emit("update:modelValue", v);
}, 300);

const onInput = (e: Event): void => {
  debouncedEmit((e.target as HTMLInputElement).value);
};

/* 组件卸载时取消未触发的防抖调用，防止内存泄漏 */
onBeforeUnmount(() => {
  debouncedEmit.cancel();
});
</script>

<style scoped>
/* 星野导航带：仅布局（无边框/圆角/投影 —— 边界由星野的渐变消解） */
.search-bar {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 12px 9px 14px;
  animation: slide-down 0.5s var(--ease) both;
}
.search-inner {
  flex: 1; display: flex; align-items: center; gap: 8px;
  min-width: 0;
}
.search-icon {
  width: 16px; height: 16px; opacity: 0.4; flex-shrink: 0;
}
.search-input {
  flex: 1; background: none; border: none; outline: none;
  color: var(--text-primary); font-size: 13px; min-width: 0;
}
.search-input::placeholder { color: var(--text-muted); }

@keyframes slide-down {
  from { opacity: 0; transform: translateY(-8px); }
  to { opacity: 1; transform: translateY(0); }
}
</style>