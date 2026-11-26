<!--
  实时日志面板：读取当前构建最近的应用日志尾部。

  只做展示与筛选，不持有日志写入能力；来源与等级筛选复用项目标准控件，
  样式全部限制在开发悬浮球作用域内，不写入全局样式。
-->
<template>
  <section class="log-panel" aria-label="实时日志">
    <header class="log-head">
      <div class="log-filters">
        <div class="log-select">
          <VaultSelect
            compact
            :panel-width="96"
            :allow-empty="false"
            :model-value="source"
            :options="SOURCE_OPTIONS"
            aria-label="日志来源"
            @update:model-value="onSourceChange"
          />
        </div>
        <div class="log-select">
          <VaultSelect
            compact
            :panel-width="96"
            :allow-empty="false"
            :model-value="levelFilter"
            :options="LEVEL_OPTIONS"
            aria-label="日志等级"
            @update:model-value="levelFilter = $event"
          />
        </div>
      </div>
      <div class="log-keys">
        <ActionButton
          label="刷新"
          :show-plus="false"
          :loading="loading"
          @click="refresh(false)"
        />
        <ActionButton
          label="复制"
          :show-plus="false"
          :disabled="visibleLines.length === 0"
          @click="copyVisible"
        />
      </div>
    </header>

    <label class="kv-option log-auto" :class="{ 'is-on': autoRefresh }">
      <input type="checkbox" :checked="autoRefresh" @change="toggleAutoRefresh" />
      <span class="kv-option-check" aria-hidden="true"></span>
      <span class="kv-option-text">自动刷新</span>
      <span class="kv-option-hint">{{ AUTO_REFRESH_MS / 1000 }}s</span>
    </label>

    <p v-if="error" class="kv-error log-error">{{ error }}</p>

    <div ref="streamEl" class="log-stream" role="log" aria-live="polite">
      <p v-if="visibleLines.length === 0 && !error" class="log-empty">暂无日志</p>
      <ol v-else class="log-list">
        <li
          v-for="(line, index) in visibleLines"
          :key="`${line.timestamp}-${line.pid}-${index}`"
          class="log-row"
          :class="`is-${line.level.toLowerCase()}`"
        >
          <span class="log-time">{{ formatTime(line.timestamp) }}</span>
          <span class="log-level">{{ line.level }}</span>
          <span class="log-process">{{ processLabel(line.processName) }}</span>
          <span class="log-module" :title="line.module">{{ line.module }}</span>
          <span class="log-message">{{ line.message }}</span>
        </li>
      </ol>
    </div>

    <footer class="log-foot">
      <span class="log-dir" :title="logDir">{{ logDir || "日志目录不可用" }}</span>
      <span class="log-count">{{ visibleLines.length }} / {{ lines.length }}</span>
    </footer>
  </section>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from "vue";
import ActionButton from "../../components/common/verthys-ui/ActionButton.vue";
import VaultSelect from "../../components/common/verthys-ui/VaultSelect.vue";
import { useToastCenter } from "../../composables/useToastCenter";
import { tailDevLogs, type DevLogLine, type DevLogSource } from "./log_client";

const AUTO_REFRESH_MS = 1500;
const MAX_LINES = 200;

const SOURCE_OPTIONS = [
  { value: "all", label: "全部" },
  { value: "main_ui", label: "主进程" },
  { value: "worker", label: "Worker" },
  { value: "inspector", label: "巡检" },
];

const LEVEL_OPTIONS = [
  { value: "all", label: "全部" },
  { value: "INFO", label: "INFO+" },
  { value: "WARN", label: "WARN+" },
  { value: "ERROR", label: "ERROR+" },
];

const LEVEL_RANK: Record<string, number> = {
  TRACE: 0,
  DEBUG: 1,
  INFO: 2,
  WARN: 3,
  ERROR: 4,
  FATAL: 5,
};

const { showStatus, showError } = useToastCenter();

const source = ref<DevLogSource>("all");
const levelFilter = ref("all");
const autoRefresh = ref(true);
const lines = ref<DevLogLine[]>([]);
const logDir = ref("");
const error = ref("");
const loading = ref(false);
const streamEl = ref<HTMLElement | null>(null);

let pollTimer: number | null = null;

const visibleLines = computed(() => {
  const threshold = levelFilter.value === "all" ? -1 : (LEVEL_RANK[levelFilter.value] ?? -1);
  if (threshold < 0) return lines.value;
  return lines.value.filter((line) => (LEVEL_RANK[line.level] ?? 0) >= threshold);
});

function processLabel(name: string): string {
  if (name === "main_ui") return "主";
  if (name === "worker") return "W";
  if (name === "inspector") return "巡";
  return name;
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value.slice(11, 19);
  return date.toLocaleTimeString("zh-CN", { hour12: false });
}

function nearBottom(element: HTMLElement): boolean {
  return element.scrollHeight - element.scrollTop - element.clientHeight < 24;
}

async function refresh(silent: boolean): Promise<void> {
  if (!silent) loading.value = true;
  try {
    const tail = await tailDevLogs(source.value, MAX_LINES);
    const shouldStick = streamEl.value ? nearBottom(streamEl.value) : true;
    lines.value = tail.lines;
    logDir.value = tail.logDir;
    error.value = "";
    if (shouldStick) {
      await nextTick();
      if (streamEl.value) streamEl.value.scrollTop = streamEl.value.scrollHeight;
    }
  } catch (cause) {
    error.value = describeError(cause, "读取日志失败");
  } finally {
    if (!silent) loading.value = false;
  }
}

function describeError(cause: unknown, fallback: string): string {
  if (cause instanceof Error && cause.message.trim()) return cause.message;
  if (typeof cause === "string" && cause.trim()) return cause;
  return fallback;
}

function onSourceChange(value: string): void {
  source.value = value as DevLogSource;
  void refresh(false);
}

function toggleAutoRefresh(event: Event): void {
  autoRefresh.value = (event.target as HTMLInputElement).checked;
  syncPollTimer();
}

function syncPollTimer(): void {
  if (pollTimer !== null) {
    window.clearInterval(pollTimer);
    pollTimer = null;
  }
  if (!autoRefresh.value) return;
  pollTimer = window.setInterval(() => {
    if (document.visibilityState === "hidden") return;
    void refresh(true);
  }, AUTO_REFRESH_MS);
}

async function copyVisible(): Promise<void> {
  if (visibleLines.value.length === 0) return;
  const text = visibleLines.value
    .map((line) =>
      [line.timestamp, line.level, line.processName, line.module, line.message].join("\t"),
    )
    .join("\n");
  try {
    await navigator.clipboard.writeText(text);
    showStatus(`已复制 ${visibleLines.value.length} 条日志`);
  } catch {
    showError("复制日志失败");
  }
}

onMounted(() => {
  void refresh(false);
  syncPollTimer();
});

onBeforeUnmount(() => {
  if (pollTimer !== null) {
    window.clearInterval(pollTimer);
    pollTimer = null;
  }
});
</script>

<style scoped>
.log-panel {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 14px 0 4px;
  /* 日志流置于工具行之后：以细线分隔，滚动时先看到工具再进入日志 */
  border-top: 1px solid rgba(205, 224, 244, 0.07);
}

.log-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 6px 10px;
}

.log-filters {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}

.log-select {
  width: 88px;
  flex: 0 0 auto;
}

.log-keys {
  display: flex;
  align-items: center;
  gap: 6px;
  flex: 0 0 auto;
}

/* 动作键与紧凑选择器同高：同一行控件不出现高度断层 */
.log-keys :deep(.action-btn) {
  height: 30px;
  padding-top: 0;
  padding-bottom: 0;
}

/* 自动刷新沿用项目选项条：整行可点、原生输入只保留焦点语义 */
.log-auto {
  margin: 0;
}

.log-error {
  margin: 0;
}

.log-stream {
  height: 236px;
  overflow-y: auto;
  overflow-x: hidden;
  border-top: 1px solid rgba(205, 224, 244, 0.07);
  border-bottom: 1px solid rgba(205, 224, 244, 0.07);
}

.log-empty {
  padding: 28px 0;
  font-size: 11px;
  letter-spacing: 0.2px;
  color: var(--text-muted);
  text-align: center;
}

.log-list {
  margin: 0;
  padding: 0;
  list-style: none;
}

.log-row {
  display: grid;
  grid-template-columns: 54px 40px 18px minmax(0, 88px) minmax(0, 1fr);
  align-items: baseline;
  gap: 6px;
  padding: 4px 2px;
  border-bottom: 1px solid rgba(205, 224, 244, 0.045);
  font-size: 10.5px;
  line-height: 1.5;
}

.log-row:last-child {
  border-bottom: 0;
}

.log-time {
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.log-level {
  font-size: 9px;
  letter-spacing: 0.06em;
  color: var(--text-secondary);
  white-space: nowrap;
}

.log-row.is-warn .log-level {
  color: var(--warning);
}

.log-row.is-error .log-level,
.log-row.is-fatal .log-level {
  color: var(--danger);
}

.log-row.is-debug .log-level,
.log-row.is-trace .log-level {
  color: var(--text-muted);
}

.log-process {
  font-size: 9.5px;
  color: var(--text-muted);
  text-align: center;
  white-space: nowrap;
}

.log-module {
  color: var(--text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.log-message {
  color: var(--text-primary);
  overflow-wrap: anywhere;
}

.log-row.is-error .log-message,
.log-row.is-fatal .log-message {
  color: rgba(255, 143, 156, 0.96);
}

.log-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  min-width: 0;
  font-size: 9.5px;
  letter-spacing: 0.02em;
  color: var(--text-muted);
}

.log-dir {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.log-count {
  flex: 0 0 auto;
  font-variant-numeric: tabular-nums;
}

@media (prefers-reduced-motion: reduce) {
  .log-row {
    transition: none;
  }
}
</style>
