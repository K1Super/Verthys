<!--
  WindowControls.vue — 超精简状态条（窗口控制按钮）
  从 MainView.vue 抽离，功能 100% 保留
-->
<template>
  <div class="status-bar" data-tauri-drag-region @mousedown="onDragRegionMouseDown">
    <div class="window-controls">
      <button class="win-btn" @click="onMinimize" v-tip="'最小化'">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <line x1="5" y1="12" x2="19" y2="12" />
        </svg>
      </button>
      <button class="win-btn" @click="onToggleMax" v-tip="'最大化/还原'">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <rect x="5" y="5" width="14" height="14" rx="1" />
        </svg>
      </button>
      <button class="win-btn win-close" @click="onClose" v-tip="'关闭'">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <line x1="6" y1="6" x2="18" y2="18" />
          <line x1="18" y1="6" x2="6" y2="18" />
        </svg>
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useWindowControls } from "../../composables/useWindowControls";

const { onMinimize, onToggleMax, onClose, onDragRegionMouseDown } = useWindowControls();
</script>

<style scoped>
/* ===== 超精简状态条 ===== */
.status-bar {
  position: relative;
  z-index: 2;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  height: 40px;
  padding: 0 16px;
  flex-shrink: 0;
  -webkit-user-select: none;
  user-select: none;
}
.window-controls {
  display: flex;
  align-items: center;
  gap: 4px;
}
.win-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all var(--dur-fast) var(--ease);
}
.win-btn svg {
  width: 14px;
  height: 14px;
}
.win-btn:hover {
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.06);
  border-color: var(--border-glass);
}
.win-close:hover {
  color: #fff;
  background: rgba(255, 46, 99, 0.5);
  border-color: rgba(255, 46, 99, 0.4);
  box-shadow: 0 0 10px rgba(255, 46, 99, 0.2);
}
</style>
