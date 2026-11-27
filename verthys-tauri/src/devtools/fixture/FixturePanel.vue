<!--
  开发夹具配置面板。

  只保存与填充测试参数；不自动创建容器、不自动打开、不自动提交。
  配置经 Rust 侧 DPAPI 加密，前端不写 localStorage 保存凭据。
-->
<template>
  <section class="fixture-panel" aria-label="填充配置">
    <div v-if="loading" class="fixture-loading">读取填充状态…</div>

    <div v-else-if="!status?.enabled" class="fixture-blocked">
      <span class="fixture-blocked-title">填充通道不可用</span>
      <span class="fixture-blocked-reason">{{ status?.reason || "无法读取填充状态" }}</span>
    </div>

    <template v-else>
      <header class="fixture-head">
        <div class="fixture-id">
          <h2 class="fixture-title">填充配置</h2>
          <span class="fixture-sub">保存后由卫星或自动填充写入表单</span>
        </div>
        <span class="fixture-state" :class="{ 'is-ready': status.profileExists }">
          {{ status.profileExists ? "已保存" : "未保存" }}
        </span>
      </header>

      <p class="fixture-store" :title="status.storeDir">{{ status.storeDir }}</p>

      <label class="kv-option fixture-auto" :class="{ 'is-on': autoFill }">
        <input
          type="checkbox"
          :checked="autoFill"
          :disabled="busy !== ''"
          @change="toggleAutoFill"
        />
        <span class="kv-option-check" aria-hidden="true"></span>
        <span class="kv-option-text">自动填充</span>
        <span class="kv-option-hint">启用后自动写入已挂载表单</span>
      </label>

      <section class="kv-section fixture-section">
        <div class="kv-section-label">容器</div>
        <div class="fixture-grid">
          <label class="kv-field fixture-field fixture-field--wide">
            <span class="kv-label">容器路径</span>
            <div class="fixture-path-row">
              <input
                v-model="form.containerPath"
                class="kv-input fixture-input"
                type="text"
                autocomplete="off"
                spellcheck="false"
              />
              <button type="button" class="btn btn-neutral btn-mini" @click="browseContainer">
                选择
              </button>
              <button
                type="button"
                class="btn btn-neutral btn-mini"
                @click="clearPath('containerPath')"
              >
                清除
              </button>
            </div>
          </label>

          <label class="kv-field fixture-field fixture-field--wide">
            <span class="kv-label">容器 keyfile</span>
            <div class="fixture-path-row">
              <input
                v-model="form.containerKeyfilePath"
                class="kv-input fixture-input"
                type="text"
                autocomplete="off"
                spellcheck="false"
              />
              <button
                type="button"
                class="btn btn-neutral btn-mini"
                @click="browseContainerKeyfile"
              >
                选择
              </button>
              <button
                type="button"
                class="btn btn-neutral btn-mini"
                @click="clearPath('containerKeyfilePath')"
              >
                清除
              </button>
            </div>
          </label>
        </div>
      </section>

      <section class="kv-section fixture-section">
        <div class="kv-section-label">全局密钥</div>
        <div class="fixture-grid">
          <label class="kv-field fixture-field">
            <span class="kv-label">访问密钥</span>
            <input
              v-model="form.globalPassword"
              class="kv-input fixture-input"
              type="text"
              autocomplete="off"
              spellcheck="false"
            />
          </label>
          <label class="kv-field fixture-field">
            <span class="kv-label">密钥口令</span>
            <input
              v-model="form.binPassword"
              class="kv-input fixture-input"
              type="text"
              autocomplete="off"
              spellcheck="false"
            />
          </label>
          <label class="kv-field fixture-field fixture-field--wide">
            <span class="kv-label">密钥文件路径</span>
            <div class="fixture-path-row">
              <input
                v-model="form.binKeyfilePath"
                class="kv-input fixture-input"
                type="text"
                autocomplete="off"
                spellcheck="false"
              />
              <button type="button" class="btn btn-neutral btn-mini" @click="browseBinKeyfile">
                选择
              </button>
              <button
                type="button"
                class="btn btn-neutral btn-mini"
                @click="clearPath('binKeyfilePath')"
              >
                清除
              </button>
            </div>
          </label>
        </div>
      </section>

      <section class="kv-section fixture-section">
        <div class="kv-section-label">模块密钥</div>
        <div class="fixture-grid">
          <label
            v-for="[id, label] in moduleEntries"
            :key="id"
            class="kv-field fixture-field"
          >
            <span class="kv-label">{{ label }}</span>
            <input
              v-model="form.moduleKeys[id]"
              class="kv-input fixture-input"
              type="text"
              autocomplete="off"
              spellcheck="false"
            />
          </label>
        </div>
      </section>

      <section class="kv-section fixture-section">
        <div class="kv-section-label">恢复码</div>
        <label class="kv-field fixture-field">
          <textarea
            v-model="form.recoveryCode"
            class="kv-input kv-textarea fixture-input fixture-textarea"
            rows="2"
            autocomplete="off"
            spellcheck="false"
          ></textarea>
        </label>
      </section>

      <p v-if="lastError" class="kv-error fixture-error">{{ lastError }}</p>

      <div class="fixture-actions">
        <span class="fixture-updated">
          {{ lastSavedLabel ? `最近保存 ${lastSavedLabel}` : "尚未保存" }}
        </span>
        <div class="fixture-action-keys">
          <ActionButton
            :label="clearArmed ? '再次点击清空' : '清空配置'"
            variant="destructive"
            :show-plus="false"
            :disabled="busy !== ''"
            @click="clear"
          />
          <ActionButton
            label="填充当前表单"
            :show-plus="false"
            :loading="busy === 'fill'"
            :disabled="busy !== ''"
            @click="fill"
          />
          <ActionButton
            label="保存配置"
            primary
            :show-plus="false"
            :loading="busy === 'save'"
            :disabled="busy !== ''"
            @click="save"
          />
        </div>
      </div>

      <footer class="fixture-meta">
        <span>全局 {{ fingerprints.global }}</span>
        <span>口令 {{ fingerprints.bin }}</span>
        <span>恢复 {{ fingerprints.recovery }}</span>
        <span v-for="(value, key) in fingerprints.modules" :key="key">
          {{ key }} {{ value }}
        </span>
      </footer>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import ActionButton from "../../components/common/verthys-ui/ActionButton.vue";
import { MODULE_LABELS } from "../../constants/key_manager_const";
import { useToastCenter } from "../../composables/ui/useToastCenter";
import {
  clearFixtureProfile,
  getFixtureProfile,
  getFixtureStatus,
  saveFixtureProfile,
  type DevFixtureFingerprints,
  type DevFixtureProfile,
  type DevFixtureStatus,
} from "./profile_client";
import { dispatchFill } from "./fill_action";
import { readAutoFillPreference, writeAutoFillPreference } from "./preferences";

const { showStatus, showError } = useToastCenter();

const moduleEntries = Object.entries(MODULE_LABELS) as Array<[string, string]>;

const loading = ref(true);
const busy = ref<"" | "save" | "fill" | "clear">("");
const clearArmed = ref(false);
const autoFill = ref(readAutoFillPreference());
const status = ref<DevFixtureStatus | null>(null);
const lastError = ref("");
const lastSaved = ref("");
const lastSavedLabel = computed(() => {
  const seconds = Number(lastSaved.value);
  if (Number.isFinite(seconds) && seconds > 0) {
    return new Date(seconds * 1000).toLocaleString();
  }
  return lastSaved.value;
});
const fingerprints = ref<DevFixtureFingerprints>({
  global: "—",
  bin: "—",
  recovery: "—",
  modules: {},
});

const form = reactive<DevFixtureProfile>({
  schemaVersion: 1,
  containerPath: "",
  containerKeyfilePath: "",
  globalPassword: "",
  binPassword: "",
  binKeyfilePath: "",
  moduleKeys: {},
  recoveryCode: "",
  updatedAt: "",
});

function resetForm(): void {
  form.containerPath = "";
  form.containerKeyfilePath = "";
  form.globalPassword = "";
  form.binPassword = "";
  form.binKeyfilePath = "";
  form.moduleKeys = {};
  form.recoveryCode = "";
  form.updatedAt = "";
}

function describeError(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) return error.message;
  if (typeof error === "string" && error.trim()) return error;
  const text = String(error ?? "").trim();
  return text || fallback;
}

function snapshot(): DevFixtureProfile {
  return { ...form, moduleKeys: { ...form.moduleKeys } };
}

async function refresh(): Promise<void> {
  loading.value = true;
  lastError.value = "";
  try {
    status.value = await getFixtureStatus();
    if (!status.value.enabled) return;
    const view = await getFixtureProfile();
    fingerprints.value = view.fingerprints;
    resetForm();
    if (view.profile) {
      Object.assign(form, view.profile);
      form.moduleKeys = { ...view.profile.moduleKeys };
      lastSaved.value = view.profile.updatedAt;
    }
  } catch (error) {
    lastError.value = describeError(error, "读取填充配置失败");
    showError(lastError.value);
  } finally {
    loading.value = false;
  }
}

async function save(): Promise<void> {
  if (busy.value) return;
  busy.value = "save";
  lastError.value = "";
  try {
    const outcome = await saveFixtureProfile({
      ...snapshot(),
      schemaVersion: 1,
    });
    fingerprints.value = outcome.fingerprints;
    lastSaved.value = outcome.updatedAt;
    if (status.value) status.value.profileExists = true;
    if (autoFill.value) {
      dispatchFill(snapshot());
      showStatus("已保存并自动填充");
    } else {
      showStatus("填充配置已加密保存");
    }
  } catch (error) {
    lastError.value = describeError(error, "保存配置失败");
    showError(lastError.value);
  } finally {
    busy.value = "";
  }
}

function fill(): void {
  if (busy.value) return;
  busy.value = "fill";
  try {
    dispatchFill(snapshot());
    showStatus("已填充表单");
  } finally {
    busy.value = "";
  }
}

function toggleAutoFill(event: Event): void {
  const enabled = (event.target as HTMLInputElement).checked;
  autoFill.value = enabled;
  writeAutoFillPreference(enabled);
  if (!enabled) return;
  if (status.value?.profileExists) {
    dispatchFill(snapshot());
    showStatus("已启用自动填充");
  } else {
    showStatus("已启用自动填充，保存配置后生效");
  }
}

async function clear(): Promise<void> {
  if (busy.value) return;
  if (!clearArmed.value) {
    clearArmed.value = true;
    window.setTimeout(() => {
      clearArmed.value = false;
    }, 3000);
    return;
  }
  clearArmed.value = false;
  busy.value = "clear";
  lastError.value = "";
  try {
    await clearFixtureProfile();
    resetForm();
    fingerprints.value = { global: "—", bin: "—", recovery: "—", modules: {} };
    lastSaved.value = "";
    if (status.value) status.value.profileExists = false;
    showStatus("填充配置已清空");
  } catch (error) {
    lastError.value = describeError(error, "清空配置失败");
    showError(lastError.value);
  } finally {
    busy.value = "";
  }
}

async function pickPath(
  current: string,
  extensions: string[],
  title: string,
): Promise<string | null> {
  const selected = await open({
    multiple: false,
    directory: false,
    title,
    defaultPath: current || undefined,
    filters: [{ name: title, extensions }],
  });
  return typeof selected === "string" && selected ? selected : null;
}

async function browseContainer(): Promise<void> {
  const picked = await pickPath(form.containerPath, ["verthys"], "选择 Verthys 容器");
  if (picked) form.containerPath = picked;
}

async function browseContainerKeyfile(): Promise<void> {
  const picked = await pickPath(form.containerKeyfilePath, ["vkf"], "选择容器 keyfile");
  if (picked) form.containerKeyfilePath = picked;
}

async function browseBinKeyfile(): Promise<void> {
  const picked = await pickPath(form.binKeyfilePath, ["bin"], "选择访问密钥文件");
  if (picked) form.binKeyfilePath = picked;
}

function clearPath(field: "containerPath" | "containerKeyfilePath" | "binKeyfilePath"): void {
  form[field] = "";
}

onMounted(() => {
  void refresh();
});
</script>

<style scoped>
.fixture-panel {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 16px 16px 18px;
  font-family: var(--font);
  color: var(--text-primary);
}

.fixture-loading,
.fixture-blocked {
  display: flex;
  flex-direction: column;
  gap: 7px;
  padding: 12px 0;
  color: var(--text-secondary);
  font-size: 11px;
  line-height: 1.55;
}

.fixture-blocked-title {
  font-size: 11px;
  color: var(--danger);
}

.fixture-blocked-reason {
  color: var(--text-secondary);
}

.fixture-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.fixture-id {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}

.fixture-title {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
  line-height: 1.3;
  letter-spacing: 0.03em;
  color: #e8f1fa;
}

.fixture-sub {
  font-size: 10.5px;
  line-height: 1.5;
  color: var(--text-muted);
}

.fixture-state {
  flex: 0 0 auto;
  font-size: 10.5px;
  line-height: 1.6;
  letter-spacing: 0.04em;
  color: var(--text-muted);
}

.fixture-state.is-ready {
  color: var(--text-primary);
}

.fixture-store {
  margin: -4px 0 0;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 9.5px;
  line-height: 1.5;
  color: var(--text-muted);
}

.fixture-auto {
  margin: 0;
}

/* 分区沿用项目 kv 词汇，只压缩间距以适配窄面板 */
.fixture-section {
  padding-top: 12px;
  margin-top: 0;
}

.fixture-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 12px;
}

.fixture-field {
  min-width: 0;
}

.fixture-field + .fixture-field {
  margin-top: 0;
}

.fixture-field--wide {
  grid-column: 1 / -1;
}

.fixture-path-row {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}

.fixture-path-row .fixture-input {
  flex: 1 1 auto;
  min-width: 0;
}

/* 输入视觉完全复用 kv-input；此处只收敛开发面板的几何与字号 */
.fixture-input {
  padding: 7px 10px;
  font-size: 12px;
  line-height: 1.35;
}

.fixture-textarea {
  min-height: 48px;
  max-height: 120px;
}

/* 星野键族的微缩规格已由全局 btn-mini 提供，这里只锁住不换行 */
.fixture-path-row .btn {
  flex: 0 0 auto;
}

.fixture-error {
  margin: 0;
}

.fixture-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-top: 2px;
}

.fixture-updated {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 9.5px;
  color: var(--text-muted);
}

.fixture-action-keys {
  display: flex;
  align-items: center;
  gap: 6px;
  flex: 0 0 auto;
}

.fixture-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 12px;
  padding-top: 10px;
  border-top: 1px solid rgba(205, 224, 244, 0.07);
  font-size: 9px;
  letter-spacing: 0.02em;
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}

/* 控制台作为尺寸容器：面板变窄时字段改单列，不依赖窗口宽度 */
@container (max-width: 360px) {
  .fixture-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .fixture-actions {
    flex-direction: column;
    align-items: stretch;
  }

  .fixture-action-keys {
    justify-content: flex-end;
    flex-wrap: wrap;
  }
}
</style>
