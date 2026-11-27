<!--
  ActionTerminal.vue — 引力谱系动作端子（单一来源）

  职责：把「标签 + 描述微文 + 图标」收敛为一个原生按钮，保证：
    1. 鼠标落在标签或描述上均为可点击光标，点击整块触发同一动作；
    2. 禁用态由原生 disabled 统一截断点击并整块降亮；
    3. 轮换等二次确认警示态沿用 `.sf-terminal-block.is-armed` 语义；
    4. 标签、描述、图标与悬停能量线只维护这一套结构。

  视觉皮肤仍在 section-field.css（.sf-terminal-block / .sf-tb-label / .sf-tb-desc），
  本组件只负责结构与图标注册；提示指令由调用方透传到根按钮。
-->
<template>
  <button
    class="sf-terminal-block"
    :class="{ 'is-armed': armed }"
    type="button"
    :disabled="disabled"
    @click="emit('action')"
  >
    <span class="sf-tb-label">
      <!-- 图标归一到 24 网格内的 20 单位光学框：形态按自身边界缩放、
           描边宽度反向补偿，确保渲染后各图标视觉尺寸与线宽一致 -->
      <svg
        v-if="icon"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        aria-hidden="true"
      >
        <g v-if="icon === 'shield'" stroke-width="1.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <polyline points="9 12 11 14 15 10" />
        </g>
        <g
          v-else-if="icon === 'sync'"
          transform="translate(-1.333 -1.333) scale(1.111)"
          stroke-width="1.35"
        >
          <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
          <path d="M21 3v5h-5" />
          <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
          <path d="M8 16H3v5" />
        </g>
        <g
          v-else-if="icon === 'key'"
          transform="translate(-0.105 -0.105) scale(1.053)"
          stroke-width="1.425"
        >
          <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5" />
        </g>
        <g v-else-if="icon === 'off'" transform="translate(1.5 1)" stroke-width="1.5">
          <path d="M18 8h1a4 4 0 0 1 0 8h-1" />
          <path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z" />
          <line x1="6" y1="1" x2="6" y2="4" />
          <line x1="10" y1="1" x2="10" y2="4" />
          <line x1="14" y1="1" x2="14" y2="4" />
        </g>
        <g
          v-else-if="icon === 'download'"
          transform="translate(-1.333 -1.333) scale(1.111)"
          stroke-width="1.35"
        >
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
          <polyline points="7 10 12 15 17 10" />
          <line x1="12" y1="15" x2="12" y2="3" />
        </g>
      </svg>
      {{ label }}
    </span>
    <span class="sf-tb-desc">{{ desc }}</span>
  </button>
</template>

<script setup lang="ts">
/** 端子图标注册：新增动作时只在此处补一枚，避免各面板重复内联 SVG */
type TerminalIcon = "shield" | "sync" | "key" | "off" | "download";

withDefaults(
  defineProps<{
    /** 动作标签（按钮可访问名的主体） */
    label: string;
    /** 描述微文（与标签同属按钮，整块可点） */
    desc: string;
    /** 图标语义（缺省时不渲染图标） */
    icon?: TerminalIcon;
    /** 原生禁用：截断点击并整块降亮 */
    disabled?: boolean;
    /** 二次确认警示态（琥珀语义） */
    armed?: boolean;
  }>(),
  { disabled: false, armed: false },
);

const emit = defineEmits<{ (e: "action"): void }>();
</script>
