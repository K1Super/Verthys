<!--
  开发夹具配置面板。

  只保存与填充测试参数；不自动创建容器、不自动打开、不自动提交。
  配置经 Rust 侧 DPAPI 加密，前端不写 localStorage。
-->
<template>
  <section class="fixture-panel" aria-label="填充配置">
    <div v-if="loading" class="fixture-loading">读取填充状态…</div>

    <div v-else-if="!status?.enabled" class="fixture-blocked">
      <span class="fixture-blocked-title">FILL / DISABLED</span>
      <span class="fixture-blocked-reason">{{ status?.reason || "无法读取填充状态" }}</span>
    </div>

    <template v-else>
      <header class="fixture-head">
        <span class="fixture-state" :class="{ 'is-ready': status.profileExists }">
          FILL / {{ status.profileExists ? "READY" : "EMPTY" }}
        </span>
        <span class="fixture-root">PROFILE {{ status.storeDir }}</span>
      </header>

      <div class="fixture-groups">
        <section class="fixture-group">
          <h3 class="fixture-group-title">容器</h3>
          <div class="fixture-grid">
            <label class="fixture-field fixture-field--wide">
              <span>容器路径</span>
              <div class="fixture-path">
                <input v-model="form.containerPath" type="text" autocomplete="off" spellcheck="false" />
                <button type="button" class="fixture-browse" @click="browseContainer">选择</button>
                <button type="button" class="fixture-browse fixture-browse--clear" @click="clearPath('containerPath')">清除</button>
              </div>
            </label>
            <label class="fixture-field fixture-field--wide">
              <span>容器 keyfile</span>
              <div class="fixture-path">
                <input v-model="form.containerKeyfilePath" type="text" autocomplete="off" spellcheck="false" />
                <button type="button" class="fixture-browse" @click="browseContainerKeyfile">选择</button>
                <button type="button" class="fixture-browse fixture-browse--clear" @click="clearPath('containerKeyfilePath')">清除</button>
              </div>
            </label>
          </div>
        </section>

        <section class="fixture-group">
          <h3 class="fixture-group-title">全局密钥</h3>
          <div class="fixture-grid">
            <label class="fixture-field">
              <span>访问密钥</span>
              <input v-model="form.globalPassword" type="text" autocomplete="off" spellcheck="false" />
            </label>
            <label class="fixture-field">
              <span>密钥口令</span>
              <input v-model="form.binPassword" type="text" autocomplete="off" spellcheck="false" />
            </label>
            <label class="fixture-field fixture-field--wide">
              <span>访问密钥文件</span>
              <div class="fixture-path">
                <input v-model="form.binKeyfilePath" type="text" autocomplete="off" spellcheck="false" />
                <button type="button" class="fixture-browse" @click="browseBinKeyfile">选择</button>
                <button type="button" class="fixture-browse fixture-browse--clear" @click="clearPath('binKeyfilePath')">清除</button>
              </div>
            </label>
          </div>
        </section>

        <section class="fixture-group">
          <h3 class="fixture-group-title">模块密钥</h3>
          <div class="fixture-grid">
            <label
              v-for="[id, label] in moduleEntries"
              :key="id"
              class="fixture-field"
            >
              <span>{{ label }}</span>
              <input v-model="form.moduleKeys[id]" type="text" autocomplete="off" spellcheck="false" />
            </label>
          </div>
        </section>

        <section class="fixture-group">
          <h3 class="fixture-group-title">恢复码</h3>
          <div class="fixture-grid">
            <label class="fixture-field fixture-field--wide">
              <textarea v-model="form.recoveryCode" rows="2" autocomplete="off" spellcheck="false"></textarea>
            </label>
          </div>
        </section>
      </div>

      <div class="fixture-actions">
        <button type="button" class="fixture-key" :disabled="busy !== ''" @click="save">
          {{ busy === "save" ? "保存中…" : "保存配置" }}
        </button>
        <button type="button" class="fixture-key fixture-key--accent" :disabled="busy !== ''" @click="fill">
          填充当前表单
        </button>
        <button
          type="button"
          class="fixture-key fixture-key--danger"
          :disabled="busy !== ''"
          @click="clear"
        >
          {{ clearArmed ? "再次点击清空" : "清空配置" }}
        </button>
      </div>

      <footer class="fixture-meta">
        <span>PROFILE {{ status.profileExists ? "SET" : "EMPTY" }}</span>
        <span v-if="fingerprints.global !== '—'">FP {{ fingerprints.global }}</span>
        <span v-if="lastSaved">SAVED {{ lastSavedLabel }}</span>
      </footer>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import { MODULE_LABELS } from "../../lib/keyManager";
import { useToastCenter } from "../../composables/useToastCenter";
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

const { showStatus, showError } = useToastCenter();

const moduleEntries = Object.entries(MODULE_LABELS) as Array<[string, string]>;

const loading = ref(true);
const busy = ref<"" | "save" | "fill" | "clear">("");
const clearArmed = ref(false);
const status = ref<DevFixtureStatus | null>(null);
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

async function refresh(): Promise<void> {
  loading.value = true;
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
    showError(error instanceof Error ? error.message : "读取填充配置失败");
  } finally {
    loading.value = false;
  }
}

async function save(): Promise<void> {
  if (busy.value) return;
  busy.value = "save";
  try {
    const outcome = await saveFixtureProfile({
      ...form,
      schemaVersion: 1,
      moduleKeys: { ...form.moduleKeys },
    });
    fingerprints.value = outcome.fingerprints;
    lastSaved.value = outcome.updatedAt;
    if (status.value) status.value.profileExists = true;
    showStatus("填充配置已加密保存");
  } catch (error) {
    showError(error instanceof Error ? error.message : "保存配置失败");
  } finally {
    busy.value = "";
  }
}

function fill(): void {
  if (busy.value) return;
  busy.value = "fill";
  try {
    dispatchFill({ ...form, moduleKeys: { ...form.moduleKeys } });
    showStatus("已填充表单");
  } finally {
    busy.value = "";
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
  try {
    await clearFixtureProfile();
    resetForm();
    fingerprints.value = { global: "—", bin: "—", recovery: "—", modules: {} };
    lastSaved.value = "";
    if (status.value) status.value.profileExists = false;
    showStatus("填充配置已清空");
  } catch (error) {
    showError(error instanceof Error ? error.message : "清空配置失败");
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
  --fixture-line: rgba(158, 184, 210, 0.14);
  --fixture-line-soft: rgba(158, 184, 210, 0.08);
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 15px 16px 20px;
  font-family: var(--font);
  color: var(--text-primary);
}

.fixture-loading,
.fixture-blocked {
  display: flex;
  flex-direction: column;
  gap: 7px;
  padding: 14px 1px;
  color: var(--text-secondary);
  font-size: 11px;
  line-height: 1.55;
}

.fixture-blocked-title {
  font-family: var(--font);
  font-size: 9px;
  letter-spacing: 0.14em;
  color: rgba(255, 146, 146, 0.92);
}

.fixture-blocked-reason {
  line-height: 1.6;
  color: var(--text-secondary);
}

.fixture-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  padding-bottom: 11px;
  border-bottom: 1px solid var(--fixture-line);
}

.fixture-state {
  font-family: var(--font);
  font-size: 9px;
  line-height: 1;
  letter-spacing: 0.14em;
  color: rgba(255, 176, 112, 0.9);
}

.fixture-state.is-ready {
  color: rgba(96, 224, 174, 0.9);
}

.fixture-root {
  flex-basis: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-family: var(--font);
  font-size: 9px;
  line-height: 1.4;
  color: var(--text-secondary);
  opacity: 0.72;
}

.fixture-groups {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.fixture-group {
  display: flex;
  flex-direction: column;
  gap: 9px;
}

.fixture-group + .fixture-group {
  padding-top: 14px;
  border-top: 1px solid var(--fixture-line-soft);
}

.fixture-group-title {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 0;
  font-family: var(--font);
  font-size: 9px;
  font-weight: 500;
  letter-spacing: 0.14em;
  color: var(--text-secondary);
}

.fixture-group-title::after {
  content: "";
  flex: 1;
  height: 1px;
  background: var(--fixture-line-soft);
}

.fixture-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 12px;
}

.fixture-field {
  display: flex;
  flex-direction: column;
  gap: 5px;
  min-width: 0;
  font-size: 10px;
  color: var(--text-secondary);
}

.fixture-field--wide {
  grid-column: 1 / -1;
}

.fixture-path {
  display: flex;
  gap: 6px;
  min-width: 0;
}

.fixture-path input {
  flex: 1 1 auto;
  min-width: 0;
}

.fixture-browse {
  flex: 0 0 auto;
  min-height: 28px;
  padding: 0 9px;
  border: 1px solid rgba(148, 184, 220, 0.22);
  border-radius: 2px;
  background: transparent;
  color: var(--text-secondary);
  font-family: var(--font);
  font-size: 9.5px;
  line-height: 1;
  letter-spacing: 0.04em;
  cursor: pointer;
  transition:
    border-color 0.2s var(--ease),
    color 0.2s var(--ease);
}

.fixture-browse:hover {
  border-color: rgba(172, 212, 246, 0.55);
  color: var(--text-primary);
}

.fixture-browse:focus-visible {
  outline: 1px solid rgba(172, 212, 246, 0.7);
  outline-offset: 1px;
}

.fixture-browse--clear {
  color: rgba(255, 156, 156, 0.9);
  border-color: rgba(255, 120, 120, 0.3);
}

.fixture-browse--clear:hover {
  border-color: rgba(255, 120, 120, 0.55);
  color: rgba(255, 184, 184, 0.96);
}

.fixture-field input,
.fixture-field textarea {
  box-sizing: border-box;
  padding: 6px 8px;
  border: 1px solid rgba(148, 184, 220, 0.2);
  border-radius: 2px;
  background: rgba(4, 7, 11, 0.62);
  color: var(--text-primary);
  font-family: var(--font);
  font-size: 10.5px;
  line-height: 1.35;
  outline: none;
  transition: border-color 0.2s var(--ease);
}

.fixture-field > input,
.fixture-field > textarea {
  width: 100%;
}

.fixture-field textarea {
  resize: vertical;
  min-height: 48px;
}

.fixture-field input:focus,
.fixture-field textarea:focus {
  border-color: rgba(172, 212, 246, 0.55);
}

.fixture-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding-top: 2px;
}

.fixture-key {
  min-height: 30px;
  padding: 0 12px;
  border: 1px solid rgba(148, 184, 220, 0.24);
  border-radius: 2px;
  background: transparent;
  color: var(--text-secondary);
  font-family: var(--font);
  font-size: 9.5px;
  line-height: 1;
  letter-spacing: 0.05em;
  cursor: pointer;
  transition:
    border-color 0.2s var(--ease),
    background-color 0.2s var(--ease),
    color 0.2s var(--ease),
    transform 0.12s var(--ease);
}

.fixture-key--accent {
  border-color: rgba(112, 205, 255, 0.42);
  color: rgba(172, 225, 255, 0.94);
}

.fixture-key--danger {
  border-color: rgba(255, 120, 120, 0.38);
  color: rgba(255, 156, 156, 0.9);
}

.fixture-key:hover:not(:disabled) {
  border-color: rgba(172, 212, 246, 0.58);
  background: rgba(172, 212, 246, 0.05);
  color: var(--text-primary);
}

.fixture-key--danger:hover:not(:disabled) {
  border-color: rgba(255, 120, 120, 0.58);
  background: rgba(255, 90, 90, 0.05);
  color: rgba(255, 184, 184, 0.98);
}

.fixture-key:active:not(:disabled) {
  transform: translateY(1px);
}

.fixture-key:focus-visible {
  outline: 1px solid rgba(172, 212, 246, 0.72);
  outline-offset: 1px;
}

.fixture-key:disabled {
  cursor: not-allowed;
  opacity: 0.42;
}

.fixture-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  padding-top: 11px;
  border-top: 1px solid var(--fixture-line-soft);
  font-family: var(--font);
  font-size: 8px;
  letter-spacing: 0.06em;
  color: var(--text-secondary);
  opacity: 0.72;
}

@media (prefers-reduced-motion: reduce) {
  .fixture-browse,
  .fixture-field input,
  .fixture-field textarea,
  .fixture-key {
    transition: none;
  }
}
</style>
