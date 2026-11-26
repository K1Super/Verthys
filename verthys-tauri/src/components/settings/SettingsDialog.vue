<!--
  SettingsDialog.vue — 全局显示与性能设置
  入口：窗控条齿轮；关闭：保存、点击遮罩或 Esc（外壳统一承担）
  编辑：面板内维护草稿，保存时经 settings/display-settings 归一化并持久化
-->
<template>
  <CosmicOverlay
    :show="show"
    width="340px"
    role="dialog"
    aria-labelledby="display-settings-title"
    @close="$emit('close')"
  >
    <div class="settings-panel">
      <h2 id="display-settings-title" class="kv-title settings-title">显示与性能</h2>

      <section class="kv-section settings-section">
        <div class="kv-section-label">帧率</div>
        <div class="settings-row">
          <span class="settings-row-name">上限</span>
          <div class="settings-controls">
            <div class="settings-rate">
              <div class="settings-select">
                <VaultSelect
                  compact
                  :panel-width="76"
                  :model-value="String(draft.activeFps)"
                  :options="ACTIVE_OPTIONS"
                  :allow-empty="false"
                  aria-label="帧率上限"
                  @update:model-value="setActiveFps"
                />
              </div>
              <span class="settings-unit settings-unit--fps">FPS</span>
            </div>
          </div>
        </div>
      </section>

      <section class="kv-section settings-section">
        <div class="kv-section-label">空闲降频</div>
        <div v-for="row in TIER_ROWS" :key="row.key" class="settings-row">
          <span class="settings-row-name">{{ row.label }}</span>
          <div class="settings-controls">
            <label class="settings-wait">
              <input
                class="kv-input settings-input"
                type="number"
                autocomplete="off"
                inputmode="numeric"
                step="1"
                :min="TIER_AFTER_RANGE[row.key][0]"
                :max="TIER_AFTER_RANGE[row.key][1]"
                :value="waitText[row.key]"
                :aria-label="`${row.label}等待秒数`"
                @input="onWaitInput(row.key, $event)"
                @change="commitWait(row.key)"
                @keydown.enter.prevent="commitWait(row.key)"
              />
              <span class="settings-unit">秒</span>
            </label>
            <div class="settings-rate">
              <div class="settings-select">
                <VaultSelect
                  compact
                  :panel-width="76"
                  :model-value="String(draft.tiers[row.key].fps)"
                  :options="tierFpsOptions[row.key]"
                  :allow-empty="false"
                  :aria-label="`${row.label}帧率`"
                  @update:model-value="onTierFpsChange(row.key, $event)"
                />
              </div>
              <span class="settings-unit settings-unit--fps">FPS</span>
            </div>
          </div>
        </div>
      </section>

      <section class="kv-section settings-section">
        <div class="kv-section-label">存储</div>
        <div class="settings-row">
          <span class="settings-row-name">可回收</span>
          <div class="settings-controls">
            <span class="settings-storage-readout">{{ storageReadout }}</span>
            <ActionButton
              v-if="storageBusy"
              label="取消"
              :show-plus="false"
              @click="cancelStorage"
            />
            <ActionButton
              v-else
              label="立即回收"
              :show-plus="false"
              :disabled="!storageStats || storageStats.reclaimable_bytes === 0"
              @click="compactStorage"
            />
          </div>
        </div>
        <div v-if="storageProgress" class="settings-storage-progress">
          {{ storageProgressText }}
        </div>
        <div v-if="storageError" class="settings-storage-error">{{ storageError }}</div>
      </section>

      <div class="settings-actions">
        <ActionButton label="恢复默认" :show-plus="false" @click="restoreDefaults" />
        <ActionButton
          label="保存"
          primary
          :show-plus="false"
          :disabled="!dirty"
          @click="save"
        />
      </div>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";
import ActionButton from "../common/verthys-ui/ActionButton.vue";
import VaultSelect from "../common/verthys-ui/VaultSelect.vue";
import { useGlobalIdleScheduler } from "../../composables/useGlobalIdleScheduler";
import {
  verthysStorageCompact,
  verthysStorageCompactCancel,
  verthysStorageStats,
} from "../../lib/verthys";
import type {
  StorageStats,
  StorageCompactProgress,
} from "../../types/verthys";
import {
  ACTIVE_FPS_VALUES,
  IDLE_TIERS,
  TIER_AFTER_RANGE,
  TIER_FPS_VALUES,
  createDefaultDisplaySettings,
  displaySettings as settings,
  normalizeDisplaySettings,
  updateDisplaySettings,
  type ActiveFpsPreset,
  type DisplaySettings,
  type IdleTier,
  type IdleTierSettings,
} from "../../settings/display-settings";

const props = defineProps<{ show: boolean }>();
const emit = defineEmits<{ (e: "close"): void }>();

const { resetIdle } = useGlobalIdleScheduler();

/* ===== 存储维护（即时操作，不进入显示设置草稿） ===== */
const storageStats = ref<StorageStats | null>(null);
const storageBusy = ref(false);
const storageError = ref("");
const storageProgress = ref<StorageCompactProgress | null>(null);

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let n = value;
  let unit = 0;
  while (n >= 1024 && unit < units.length - 1) {
    n /= 1024;
    unit++;
  }
  return `${n >= 100 ? n.toFixed(0) : n.toFixed(1)} ${units[unit]}`;
}

const storageReadout = computed(() => {
  const s = storageStats.value;
  if (!s) return "—";
  return `文件 ${formatBytes(s.file_size)} · 有效 ${formatBytes(s.live_bytes)} · 可回收 ${formatBytes(s.reclaimable_bytes)}`;
});

const storageProgressText = computed(() => {
  const p = storageProgress.value;
  if (!p) return "";
  return `已复制 ${formatBytes(p.bytes)} · 记录 ${p.records} · 分片 ${p.chunks}`;
});

async function refreshStorage(): Promise<void> {
  try {
    storageStats.value = await verthysStorageStats();
    storageError.value = "";
  } catch (e) {
    storageStats.value = null;
    storageError.value = e instanceof Error ? e.message : String(e);
  }
}

async function cancelStorage(): Promise<void> {
  try {
    await verthysStorageCompactCancel();
  } catch (e) {
    storageError.value = e instanceof Error ? e.message : String(e);
  }
}

async function compactStorage(): Promise<void> {
  if (storageBusy.value) return;
  storageBusy.value = true;
  storageError.value = "";
  storageProgress.value = null;
  try {
    await verthysStorageCompact((p) => {
      storageProgress.value = p;
    });
    await refreshStorage();
  } catch (e) {
    storageError.value = e instanceof Error ? e.message : String(e);
  } finally {
    storageBusy.value = false;
    storageProgress.value = null;
  }
}

watch(
  () => props.show,
  (show) => {
    if (show) {
      void refreshStorage();
    } else {
      storageProgress.value = null;
      storageError.value = "";
    }
  },
  { immediate: true },
);

/** 交互态上限选项：值与文案分离，无限制使用文字值“无” */
const ACTIVE_OPTIONS = ACTIVE_FPS_VALUES.map((value) => ({
  value: String(value),
  label: value === "unlimited" ? "无" : String(value),
}));

const TIER_ROWS: ReadonlyArray<{ key: IdleTier; label: string }> = [
  { key: "settling", label: "缓降" },
  { key: "idle", label: "空闲" },
  { key: "deep-idle", label: "深度空闲" },
];

/** 各档帧率候选项：单位固定在触发面右侧，选项只保留数值 */
const tierFpsOptions: Record<IdleTier, ReadonlyArray<{ value: string; label: string }>> = {
  settling: TIER_FPS_VALUES.settling.map((fps) => ({ value: String(fps), label: String(fps) })),
  idle: TIER_FPS_VALUES.idle.map((fps) => ({ value: String(fps), label: String(fps) })),
  "deep-idle": TIER_FPS_VALUES["deep-idle"].map((fps) => ({
    value: String(fps),
    label: String(fps),
  })),
};

interface DraftSettings {
  activeFps: ActiveFpsPreset;
  tiers: Record<IdleTier, IdleTierSettings>;
}

/** 从完整设置生成独立草稿：默认值与运行时设置共用同一来源 */
function toDraft(source: DisplaySettings): DraftSettings {
  return {
    activeFps: source.activeFps,
    tiers: {
      settling: { ...source.tiers.settling },
      idle: { ...source.tiers.idle },
      "deep-idle": { ...source.tiers["deep-idle"] },
    },
  };
}

/** 面板草稿：保存前不触碰运行时与持久化 */
const draft = reactive<DraftSettings>(toDraft(createDefaultDisplaySettings()));

/* 数值输入以字符串草稿承接键入中间态；提交时经归一化回写 */
const waitText = reactive<Record<IdleTier, string>>({
  settling: "",
  idle: "",
  "deep-idle": "",
});

/** 以一份完整设置覆盖草稿（打开面板 / 恢复默认共用） */
function applyDraft(source: DisplaySettings): void {
  const next = toDraft(source);
  draft.activeFps = next.activeFps;
  for (const tier of IDLE_TIERS) {
    draft.tiers[tier] = next.tiers[tier];
    waitText[tier] = String(next.tiers[tier].afterSec);
  }
}

/** 归一化草稿：越界钳制、档位递增冲突在此即时反映到界面 */
function normalizeDraft(): void {
  applyDraft(
    normalizeDisplaySettings({
      schemaVersion: 1,
      activeFps: draft.activeFps,
      tiers: draft.tiers,
    }),
  );
}

applyDraft(createDefaultDisplaySettings());

/** 读取等待秒数键入值：空串与非数字均视为无效，交由调用方回退 */
function readWaitInput(tier: IdleTier): number {
  const raw = waitText[tier].trim();
  return raw === "" ? Number.NaN : Number(raw);
}

const dirty = computed(() => {
  const current = settings.value;
  if (draft.activeFps !== current.activeFps) return true;
  return IDLE_TIERS.some((tier) => {
    if (
      draft.tiers[tier].fps !== current.tiers[tier].fps ||
      draft.tiers[tier].afterSec !== current.tiers[tier].afterSec
    ) {
      return true;
    }
    /* 尚未失焦的合法键入也视为修改，保证保存按钮即时可用 */
    const pending = readWaitInput(tier);
    return Number.isFinite(pending) && pending !== current.tiers[tier].afterSec;
  });
});

watch(
  () => props.show,
  (open) => {
    if (!open) return;
    applyDraft(settings.value);
    resetIdle();
  },
  { immediate: true },
);

function setActiveFps(value: string): void {
  draft.activeFps =
    value === "unlimited" ? "unlimited" : (Number(value) as ActiveFpsPreset);
}

function onTierFpsChange(tier: IdleTier, value: string): void {
  draft.tiers[tier].fps = Number(value);
}

function onWaitInput(tier: IdleTier, event: Event): void {
  waitText[tier] = (event.target as HTMLInputElement).value;
}

function commitWait(tier: IdleTier): void {
  const value = readWaitInput(tier);
  if (!Number.isFinite(value)) {
    waitText[tier] = String(draft.tiers[tier].afterSec);
    return;
  }
  draft.tiers[tier].afterSec = value;
  normalizeDraft();
}

function restoreDefaults(): void {
  applyDraft(createDefaultDisplaySettings());
}

/** 保存前收敛未失焦的合法键入；非法输入保留草稿原值 */
function commitPendingWaits(): void {
  for (const tier of IDLE_TIERS) {
    const pending = readWaitInput(tier);
    if (Number.isFinite(pending)) {
      draft.tiers[tier].afterSec = pending;
    }
  }
}

function save(): void {
  commitPendingWaits();
  normalizeDraft();
  updateDisplaySettings({
    activeFps: draft.activeFps,
    tiers: draft.tiers,
  });
  emit("close");
}
</script>

<style scoped>
.settings-panel {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.settings-title {
  margin: 0 0 12px;
}

/* 标题之后的第一个分区不再重复顶部分隔线 */
.settings-section:first-of-type {
  padding-top: 0;
  margin-top: 0;
  border-top: 0;
}

/* ===== 行布局：名称 + 右侧紧凑控件组 ===== */
.settings-row {
  display: grid;
  grid-template-columns: 56px minmax(0, 1fr);
  gap: 10px;
  align-items: center;
  min-height: 26px;
}
.settings-row + .settings-row {
  border-top: 1px solid rgba(205, 224, 244, 0.06);
}
.settings-row-name {
  font-size: 12px;
  letter-spacing: 0.5px;
  color: var(--text-secondary);
  white-space: nowrap;
}
.settings-controls {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  min-width: 0;
}
.settings-wait {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}
.settings-rate {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}
/* 仅约束几何；输入框视觉仍由全局 .kv-input 单一来源定义 */
.settings-input {
  width: 56px;
  padding: 6px 8px;
  font-size: 12px;
  text-align: center;
  font-variant-numeric: tabular-nums;
}
/* 数值输入不提供步进按钮：秒数是精确输入，不需要鼠标加减 */
.settings-input::-webkit-outer-spin-button,
.settings-input::-webkit-inner-spin-button {
  -webkit-appearance: none;
  margin: 0;
}
.settings-unit {
  flex-shrink: 0;
  font-size: 10px;
  color: var(--text-muted);
}
.settings-unit--fps {
  min-width: 20px;
  letter-spacing: 0.5px;
}
.settings-select {
  width: 56px;
  flex-shrink: 0;
}
/* 触发面与等待输入同宽同高；值居中，箭头绝对定位在右缘，不挤占文本宽度 */
.settings-select :deep(.vault-select.is-compact .vs-trigger) {
  position: relative;
  justify-content: center;
  padding: 6px;
}
.settings-select :deep(.vs-value) {
  flex: 1;
  text-align: center;
}
.settings-select :deep(.vault-select.is-compact .vs-chevron) {
  position: absolute;
  right: 3px;
  top: 50%;
  margin-top: -5px;
}

.settings-storage-readout {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 10px;
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}
.settings-storage-progress {
  margin-top: 6px;
  font-size: 10px;
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}
.settings-storage-error {
  margin-top: 6px;
  font-size: 10px;
  color: var(--danger);
}

.settings-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 16px;
}
</style>
