<!--
  SfActionNode.vue — 机械刻度动作节点（纯图标）
  设计：引力谱系 · sf-act —— 几何与皮肤由全局 sf-act 单源提供，
  本组件只负责状态类、无障碍名称，以及禁用态仍可悬浮查看提示的槽位

  Props: label / tip / tone / disabled / busy / progressing / cancel / latched / pressed
  Slots: default（图标）/ overlay（徽点、环形量表等绝对定位覆盖层）
  Emits: click
-->
<template>
  <span class="sf-act-slot" v-tip="tip || label">
    <button
      type="button"
      class="sf-act"
      :class="[
        tone === 'neutral' ? '' : `sf-act--${tone}`,
        {
          'is-busy': busy,
          'is-progressing': progressing,
          'is-cancel': cancel,
          'is-latched': latched,
        },
      ]"
      :disabled="disabled"
      :aria-label="label"
      :aria-pressed="pressed ?? undefined"
      @click="$emit('click', $event)"
    >
      <slot />
      <slot name="overlay" />
    </button>
  </span>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    /** 无障碍名称，同时作为默认悬浮提示 */
    label: string;
    /** 独立悬浮提示（缺省复用 label） */
    tip?: string;
    /** 色调：中性 / 更新青 / 警示琥珀 / 成功青绿 / 危险红 */
    tone?: "neutral" | "update" | "warn" | "success" | "danger";
    /** 原生禁用；槽位保留悬浮提示命中面 */
    disabled?: boolean;
    /** 进行中但可继续辨识（检查 / 移交阶段） */
    busy?: boolean;
    /** 进行中且不可取消，保持满亮以便读取覆盖层 */
    progressing?: boolean;
    /** 更新节点切换为中止语义 */
    cancel?: boolean;
    /** 常驻点亮（恢复槽已绑定等稳定状态） */
    latched?: boolean;
    /** 双态开关按钮的按压状态；未传时不渲染 aria-pressed
     * （以 null 作缺省，避免 Vue Boolean 缺省转换把普通动作键标成 false） */
    pressed?: boolean | null;
  }>(),
  {
    tip: "",
    tone: "neutral",
    pressed: null,
    disabled: false,
    busy: false,
    progressing: false,
    cancel: false,
    latched: false,
  },
);

defineEmits<{ (e: "click", ev: MouseEvent): void }>();
</script>
