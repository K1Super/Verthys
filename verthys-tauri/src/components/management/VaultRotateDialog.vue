<!--
  VaultRotateDialog.vue — 全库 DEK 轮换向导

  职责：
    1. 仅在恢复码会话可用：配置新库位置、备份/PCR 选项与已启用模块口令；
    2. 依次调用 Begin → UnlockModule（每个启用模块）→ Run（流式进度）
       → Commit 或 Abort；
    3. 展示阶段与复制统计；提交成功后通知父组件收起恢复会话提示。

  安全边界：
    - 容器口令由宿主保管，本组件不读取、不传递；
    - 模块口令只驻留本组件内存，提交/中止/关闭即清零；
    - 轮换进度只含统计计数，不含记录名或明文。
-->
<template>
  <CosmicOverlay
    :show="show"
    width="640px"
    aria-label="全库密钥轮换"
    teleport
    :overlay-z="10000"
    @close="requestClose"
  >
    <div class="vr-body">
      <div class="vr-head">
        <div class="kv-title">全库密钥轮换</div>
        <div class="vr-coord">
          <span class="vr-mark" aria-hidden="true"></span>
          DEK · 全库重建 / 源库只读
        </div>
      </div>

      <p class="vr-intro">
        轮换会重建整个容器的数据加密密钥（DEK），并原子替换源库。
        轮换期间源库只读；当前恢复码在轮换后继续有效。
      </p>

      <p v-if="blockReason" class="vr-error">{{ blockReason }}</p>

      <!-- 配置阶段 -->
      <template v-if="phase === 'config'">
        <section class="vr-section">
          <div class="vr-section-head">
            <span class="vr-index">01</span>
            <span class="vr-section-title">新库位置</span>
          </div>
          <div class="vr-path-row">
            <input
              class="kv-input vr-path"
              :value="targetPath || '尚未选择'"
              readonly
              aria-label="新库位置"
            />
            <button class="vr-ghost" type="button" :disabled="processing" @click="chooseTarget">
              选择位置…
            </button>
          </div>
        </section>

        <section class="vr-section">
          <div class="vr-section-head">
            <span class="vr-index">02</span>
            <span class="vr-section-title">备份与设备绑定</span>
          </div>
          <div class="vr-options">
            <label class="kf-toggle vr-toggle" :class="{ 'kf-toggle--on': keepOld }">
              <input v-model="keepOld" type="checkbox" />
              <span class="kf-box" aria-hidden="true"></span>
              <span class="kf-text">保留旧库备份（.old-*，推荐）</span>
            </label>
            <label class="kf-toggle vr-toggle" :class="{ 'kf-toggle--on': dropPcr }">
              <input v-model="dropPcr" type="checkbox" />
              <span class="kf-box" aria-hidden="true"></span>
              <span class="kf-text">移除 PCR 绑定（仅在 TPM/PCR 不可用时勾选）</span>
            </label>
          </div>

          <p v-if="keepOld && pcrEnabled" class="vr-warn">
            容器已启用 PCR 绑定：轮换会重封同名 TPM 密钥，旧备份的普通口令解锁
            将被 PCR 门拒绝（防止旧副本回滚）。旧备份只能用恢复码打开。
          </p>
        </section>

        <section v-if="modules.length > 0" class="vr-section">
          <div class="vr-section-head">
            <span class="vr-index">03</span>
            <span class="vr-section-title">模块口令</span>
          </div>
          <p class="vr-section-note">已启用模块需要提供模块口令（不是容器口令）</p>
          <div class="vr-modules">
            <div v-for="row in modules" :key="row.mid" class="vr-module-row">
              <span class="vr-module-name">{{ row.label }}</span>
              <div class="vr-secret">
                <input
                  v-model="row.password"
                  class="kv-input"
                  :type="row.visible ? 'text' : 'password'"
                  autocomplete="off"
                  spellcheck="false"
                  :aria-label="`${row.label}模块口令`"
                  :disabled="processing"
                  @keyup.enter="start"
                />
                <button
                  type="button"
                  class="vr-eye"
                  :disabled="processing"
                  :aria-label="row.visible ? '隐藏模块口令' : '显示模块口令'"
                  :aria-pressed="row.visible"
                  @click="row.visible = !row.visible"
                >
                  <svg v-if="!row.visible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                </button>
              </div>
            </div>
          </div>
        </section>
        <p v-else class="vr-hint">当前没有启用保护的模块，无需登记模块口令。</p>

        <section v-if="keyfileEnabled" class="vr-section">
          <div class="vr-section-head">
            <span class="vr-index">{{ modules.length > 0 ? "04" : "03" }}</span>
            <span class="vr-section-title">keyfile 补录</span>
          </div>
          <p class="vr-warn">
            容器已启用 keyfile：轮换需要当前 keyfile 文件补录会话摘要；
            文件内容只在 worker 进程内读取。
          </p>
          <div class="vr-path-row">
            <input
              class="kv-input vr-path"
              :value="keyfilePath || '尚未选择 keyfile'"
              readonly
              aria-label="当前 keyfile"
            />
            <button
              class="vr-ghost"
              type="button"
              :disabled="processing"
              @click="chooseKeyfile"
            >
              选择 keyfile…
            </button>
          </div>
        </section>

        <div class="kv-actions vr-actions">
          <button class="btn kv-cancel" type="button" :disabled="processing" @click="requestClose">
            取消
          </button>
          <button
            class="btn btn-primary kv-confirm"
            type="button"
            :disabled="!canStart"
            @click="start"
          >
            {{ processing ? "准备中…" : "开始轮换" }}
          </button>
        </div>
      </template>

      <!-- 进行中 -->
      <template v-else-if="busy">
        <div class="vr-live">
          <p class="vr-phase">{{ phaseText }}</p>
          <div class="vr-steps" aria-hidden="true">
            <span
              v-for="(step, index) in ROTATION_STEPS"
              :key="step"
              class="vr-step"
              :class="{ 'is-done': index < activeStep, 'is-active': index === activeStep }"
            >
              <i></i>
              <b>{{ step }}</b>
            </span>
          </div>
          <p class="vr-stats">{{ statsText }}</p>
        </div>
        <p class="vr-hint">轮换期间源库只读；完成后可选择提交或中止。</p>
        <div v-if="phase === 'unlocking' || phase === 'running'" class="kv-actions">
          <button
            class="btn kv-cancel"
            type="button"
            :disabled="cancelPending"
            @click="cancelRotate"
          >
            {{ cancelPending || cancelRequested ? "正在取消…" : "取消轮换" }}
          </button>
        </div>
      </template>

      <!-- 复制完成，等待提交 -->
      <template v-else-if="phase === 'ready'">
        <p class="vr-success">复制与完整性复核已完成，源库尚未替换。</p>
        <p class="vr-stats">{{ statsText }}</p>
        <div class="kv-actions">
          <button class="btn kv-cancel" type="button" :disabled="processing" @click="abort">
            中止并丢弃新库
          </button>
          <button
            class="btn btn-primary kv-confirm"
            type="button"
            :disabled="processing"
            @click="commit"
          >
            {{ processing ? "提交中…" : "提交并替换源库" }}
          </button>
        </div>
      </template>

      <!-- 完成 -->
      <template v-else-if="phase === 'done'">
        <p class="vr-success">轮换已提交：新库已原子替换源库，当前恢复码继续有效。{{ keepOld ? '旧库备份（.old-*）已保留，可用恢复码打开。' : '' }}</p>
        <p class="vr-stats">{{ statsText }}</p>
        <div class="kv-actions">
          <button class="btn btn-primary kv-confirm" type="button" @click="requestClose">完成</button>
        </div>
      </template>

      <!-- 已中止 -->
      <template v-else-if="phase === 'aborted'">
        <p class="vr-phase">轮换已中止，临时库已丢弃，源库未改动。</p>
        <div class="kv-actions">
          <button class="btn btn-primary kv-confirm" type="button" @click="requestClose">关闭</button>
        </div>
      </template>

      <!-- 失败 -->
      <template v-else>
        <p class="vr-error">{{ error || "轮换失败" }}</p>
        <p v-if="jobActive" class="vr-warn">
          轮换作业仍处于活动状态（源库只读）；请先中止作业再关闭。
        </p>
        <div class="kv-actions">
          <button
            v-if="jobActive"
            class="btn btn-primary kv-confirm"
            type="button"
            :disabled="processing"
            @click="abort"
          >
            {{ processing ? "中止中…" : "中止作业" }}
          </button>
          <button
            v-else
            class="btn btn-primary kv-confirm"
            type="button"
            :disabled="processing"
            @click="reset"
          >
            重新配置
          </button>
          <button
            class="btn kv-cancel"
            type="button"
            :disabled="processing || jobActive"
            @click="requestClose"
          >
            关闭
          </button>
        </div>
      </template>

      <p v-if="error && phase !== 'failed'" class="vr-error">{{ error }}</p>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";
import { open, save } from "@tauri-apps/plugin-dialog";
import { MODULE_LABELS, MODULE_IDS } from "../../constants/key_manager_const";
import type { ModuleId } from "../../types/key_manager";
import { getCurrentVerthysPath } from "../../state/key_state";
import { setSessionLockSuppressed } from "../../session/security-session";
import {
  verthysKeyfileStatus,
  verthysPcrStatus,
  verthysV4ModuleStatus,
  verthysV4RotateAbort,
  verthysV4RotateAttachKeyfile,
  verthysV4RotateBegin,
  verthysV4RotateCancel,
  verthysV4RotateCommit,
  verthysV4RotateRun,
  verthysV4RotateUnlockModule,
  type RotateProgress,
  type VerthysResponse,
} from "../../lib/verthys";

/** 前端模块标识 → C 层模块索引（0=photo 1=accounts 2=fileverthys） */
const MODULE_INDEX: Record<ModuleId, number> = {
  photo: 0,
  accounts: 1,
  fileverthys: 2,
};

interface ModuleRow {
  mid: ModuleId;
  index: number;
  label: string;
  password: string;
  visible: boolean;
}

type Phase =
  | "config"
  | "beginning"
  | "unlocking"
  | "running"
  | "ready"
  | "committing"
  | "done"
  | "aborted"
  | "failed";

const props = defineProps<{
  /** 弹窗显示状态 */
  show: boolean;
}>();

const emit = defineEmits<{
  (e: "close"): void;
  /** 提交成功：父组件据此收起恢复会话提示 */
  (e: "committed"): void;
}>();

const phase = ref<Phase>("config");
const error = ref("");
const blockReason = ref("");
const targetPath = ref("");
const keyfilePath = ref("");
const keepOld = ref(true);
const dropPcr = ref(false);
const pcrEnabled = ref(false);
const keyfileEnabled = ref(false);
const modules = ref<ModuleRow[]>([]);
const progress = ref<RotateProgress | null>(null);
const beginInfo = ref<VerthysResponse | null>(null);
const jobActive = ref(false);
const processing = ref(false);
const unlockIndex = ref(0);
const cancelRequested = ref(false);
const cancelPending = ref(false);

const busy = computed(
  () =>
    phase.value === "beginning" ||
    phase.value === "unlocking" ||
    phase.value === "running" ||
    phase.value === "committing",
);

/** 轮换命令在途期间暂停空闲锁定：长时间 Run 不应被会话超时打断。
 *
 * 仅 `processing`（后端命令真正在途）抑制；`ready` / `failed` 阶段 worker
 * 空闲，空闲锁定必须照常生效 —— 否则对话框停留会让已超时的会话永久驻留
 * GMK。此时锁定会中止尚未提交的作业（源库保持完整），这是安全优先的结果。 */
const rotationActive = computed(() => processing.value);
watch(
  rotationActive,
  (active) => setSessionLockSuppressed(active),
  { immediate: true },
);

const canStart = computed(
  () =>
    phase.value === "config" &&
    !processing.value &&
    !blockReason.value &&
    targetPath.value.trim().length > 0 &&
    (!keyfileEnabled.value || keyfilePath.value.trim().length > 0) &&
    modules.value.every((row) => row.password.length > 0),
);

const phaseText = computed(() => {
  switch (phase.value) {
    case "beginning":
      return "正在校验会话并创建临时新库…";
    case "unlocking":
      return `正在登记模块口令（${Math.min(unlockIndex.value + 1, modules.value.length)}/${modules.value.length}）…`;
    case "running":
      return "正在全量复制记录与文件…";
    case "committing":
      return "正在原子替换源库并推进回退锚点…";
    default:
      return "";
  }
});

const ROTATION_STEPS = ["会话校验", "模块口令", "全量复制", "原子替换"] as const;

/** 进行中阶段对应的刻度：已越过为完成、当前为点亮 */
const activeStep = computed(() => {
  switch (phase.value) {
    case "beginning":
      return 0;
    case "unlocking":
      return 1;
    case "running":
      return 2;
    case "committing":
      return 3;
    default:
      return ROTATION_STEPS.length;
  }
});

const stats = computed(() => {
  const p = progress.value;
  if (p) {
    return {
      modules: p.modules_ready,
      records: p.records,
      files: p.files,
      chunks: p.chunks,
      bytes: p.bytes,
    };
  }
  const b = beginInfo.value;
  return {
    modules: b?.rotate_modules_ready ?? 0,
    records: b?.rotate_records ?? 0,
    files: b?.rotate_files ?? 0,
    chunks: b?.rotate_chunks ?? 0,
    bytes: b?.rotate_bytes ?? 0,
  };
});

const statsText = computed(() => {
  const s = stats.value;
  return `已登记模块 ${s.modules} · 记录 ${s.records} · 文件 ${s.files} · 分片 ${s.chunks} · ${formatBytes(s.bytes)}`;
});

function formatBytes(bytes: number): string {
  if (bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/** 轮换错误码 → 用户可读文案（worker 只回错误码，不回内部细节） */
const ROTATE_ERROR_MESSAGES: Record<string, string> = {
  ERR_00000001: "参数非法：请检查新库位置与模块索引",
  ERR_00000002: "认证失败：请检查模块口令或恢复码",
  ERR_00000003: "目标不存在",
  ERR_00000004: "新库位置已存在，请选择其他位置",
  ERR_00000007: "加密库已锁定，请重新解锁",
  ERR_00000008: "磁盘读写失败，请检查磁盘状态",
  ERR_00000009: "数据完整性校验失败：轮换已中止，旧库未被替换；请保留现场并联系技术支持",
  ERR_0000000A: "尝试过于频繁：口令失败已触发退避，请稍后重试",
  ERR_00000017: "策略拒绝：仅恢复码会话可用，或 keyfile/恢复槽条件不满足",
  ERR_00000018: "TPM/PCR 不可用；如确认放弃 PCR 绑定，请勾选移除 PCR 后重试",
  ERR_0000001A: "容器需要 keyfile，但本次会话未持有",
  ERR_0000001B: "keyfile 文件无效",
  ERR_0000001C: "已有轮换作业进行中，请先提交或中止",
  ERR_0000001D: "模块未解锁：请先登记该模块口令",
  ERR_0000001E: "磁盘空间不足，请清理空间后重试",
  ERR_0000001F: "完整性复核失败，临时库已丢弃",
};

const ROTATE_ERR_IO = "ERR_00000008";
/** 取消在 C 层以策略拒绝（0x17）收敛；只有该码 + 取消置位才视为用户取消。 */
const ROTATE_ERR_CANCELLED = "ERR_00000017";

/** worker 稳定错误码：新响应优先 error_code，兼容仅带 error 的旧响应。 */
function respCode(resp: VerthysResponse): string {
  if (resp.error_code) return resp.error_code;
  const raw = resp.error ?? "";
  return /^ERR_[0-9A-F]{8}$/.test(raw) ? raw : "";
}

function rotateError(resp: VerthysResponse): string {
  const code = respCode(resp);
  if (code && ROTATE_ERROR_MESSAGES[code]) return ROTATE_ERROR_MESSAGES[code];
  if (resp.error) return resp.error;
  return code ? `轮换失败（${code}）` : "轮换失败";
}

function appendError(message: string) {
  error.value = error.value ? `${error.value}；${message}` : message;
}

function resetState() {
  phase.value = "config";
  error.value = "";
  blockReason.value = "";
  progress.value = null;
  beginInfo.value = null;
  jobActive.value = false;
  processing.value = false;
  unlockIndex.value = 0;
  keepOld.value = true;
  dropPcr.value = false;
  pcrEnabled.value = false;
  keyfileEnabled.value = false;
  keyfilePath.value = "";
  cancelRequested.value = false;
  cancelPending.value = false;
  modules.value = [];
  targetPath.value = defaultTargetPath();
}

function defaultTargetPath(): string {
  const src = getCurrentVerthysPath();
  return src ? `${src}.rot.vty` : "";
}

function clearSecrets() {
  for (const row of modules.value) row.password = "";
  modules.value = [];
  keyfilePath.value = "";
  cancelRequested.value = false;
  cancelPending.value = false;
}

/** 读取恢复会话状态与已启用模块清单 */
async function prepare() {
  resetState();
  try {
    const status = await verthysKeyfileStatus();
    if (!status.ok) {
      blockReason.value = "无法读取容器会话状态，请重新解锁后重试";
      return;
    }
    if (status.recovery_mode !== true) {
      blockReason.value = "仅恢复码会话可执行全库密钥轮换：请先用恢复码解锁";
      return;
    }
    keyfileEnabled.value = status.keyfile_enabled === true;

    /* PCR 绑定仅用于备份解锁警示：失败不阻断轮换（Commit 会按实际状态判定）。 */
    try {
      const pcr = await verthysPcrStatus();
      pcrEnabled.value = pcr.ok && pcr.pcr_enabled === true;
    } catch {
      pcrEnabled.value = false;
    }

    const rows: ModuleRow[] = [];
    for (const mid of MODULE_IDS) {
      const st = await verthysV4ModuleStatus(MODULE_INDEX[mid]);
      if (!st.ok) {
        blockReason.value = `无法读取「${MODULE_LABELS[mid]}」模块状态`;
        return;
      }
      if (st.deleted === true) continue;
      if (st.enabled === true) {
        rows.push({
          mid,
          index: MODULE_INDEX[mid],
          label: MODULE_LABELS[mid],
          password: "",
          visible: false,
        });
      }
    }
    modules.value = rows;
  } catch {
    blockReason.value = "读取轮换前置状态失败，请重试";
  }
}

async function chooseTarget() {
  if (processing.value) return;
  try {
    const selected = await save({
      title: "选择轮换临时库位置",
      defaultPath: targetPath.value || defaultTargetPath(),
      filters: [{ name: "Verthys Vault", extensions: ["vty"] }],
    });
    if (typeof selected === "string" && selected.trim()) {
      targetPath.value = selected.trim();
    }
  } catch {
    error.value = "选择位置失败，请重试";
  }
}

/** 选择当前 keyfile（仅容器启用 KEYFILE 时使用；只取路径） */
async function chooseKeyfile() {
  if (processing.value) return;
  try {
    const selected = await open({
      title: "选择当前 keyfile 文件",
      multiple: false,
      filters: [{ name: "Verthys Keyfile", extensions: ["vkf"] }],
    });
    if (typeof selected === "string" && selected.trim()) {
      keyfilePath.value = selected.trim();
    }
  } catch {
    error.value = "选择 keyfile 失败，请重试";
  }
}

/** 请求取消：置位父进程命名事件，Run 在下一进度回调前收敛 */
async function cancelRotate() {
  if (
    cancelPending.value ||
    (phase.value !== "unlocking" && phase.value !== "running")
  ) {
    return;
  }
  cancelPending.value = true;
  error.value = "";
  try {
    const r = await verthysV4RotateCancel();
    if (!r.ok) {
      cancelPending.value = false;
      error.value = rotateError(r);
      return;
    }
    cancelRequested.value = true;
  } catch {
    cancelPending.value = false;
    error.value = "取消通信异常，请重试";
  }
}

async function start() {
  if (!canStart.value) return;
  error.value = "";
  progress.value = null;
  cancelRequested.value = false;
  cancelPending.value = false;
  processing.value = true;
  phase.value = "beginning";
  try {
    /* 容器启用 keyfile 时先把当前 keyfile 摘要补录到恢复会话；
     * 只有摘要有效才能重封 user/device 槽。 */
    if (keyfileEnabled.value) {
      const attach = await verthysV4RotateAttachKeyfile(keyfilePath.value.trim());
      if (!attach.ok) {
        clearSecrets();
        phase.value = "failed";
        error.value = `keyfile 补录失败：${rotateError(attach)}`;
        return;
      }
    }
    const begin = await verthysV4RotateBegin(targetPath.value.trim(), dropPcr.value ? 1 : 0);
    if (!begin.ok) {
      clearSecrets();
      phase.value = "failed";
      error.value = rotateError(begin);
      return;
    }
    beginInfo.value = begin;
    jobActive.value = true;

    phase.value = "unlocking";
    for (let i = 0; i < modules.value.length; i += 1) {
      unlockIndex.value = i;
      const row = modules.value[i];
      const r = await verthysV4RotateUnlockModule(row.index, row.password);
      if (!r.ok) {
        const detail = rotateError(r);
        await abortAfterFailure();
        clearSecrets();
        phase.value = "failed";
        error.value = `「${row.label}」模块口令登记失败：${detail}`;
        return;
      }
    }

    phase.value = "running";
    const run = await verthysV4RotateRun((p) => {
      progress.value = p;
    });
    if (!run.ok) {
      const detail = rotateError(run);
      /* 只有 C 层 0x17 且用户已置位取消，才是“取消”；其他失败不得
       * 被伪装成用户中止，否则 IO/完整性错误会从界面消失。 */
      const cancelled =
        cancelRequested.value && respCode(run) === ROTATE_ERR_CANCELLED;
      await abortAfterFailure();
      cancelRequested.value = false;
      cancelPending.value = false;
      if (cancelled && !jobActive.value) {
        clearSecrets();
        phase.value = "aborted";
        /* 保留 abortAfterFailure 产生的清理告警（如有）。 */
        if (!error.value) error.value = "";
      } else {
        const abortNote = error.value;
        clearSecrets();
        phase.value = "failed";
        error.value = abortNote
          ? `复制阶段失败：${detail}；${abortNote}`
          : `复制阶段失败：${detail}`;
      }
      return;
    }
    /* 取消请求与 Run 完成竞态：用户已取消时不得进入提交态，必须强制丢弃。 */
    if (cancelRequested.value) {
      await abortAfterFailure();
      cancelRequested.value = false;
      cancelPending.value = false;
      clearSecrets();
      if (!jobActive.value) {
        phase.value = "aborted";
      } else {
        phase.value = "failed";
        error.value =
          error.value || "取消未生效且中止失败：作业仍在活动状态，请重试中止";
      }
      return;
    }
    phase.value = "ready";
  } catch {
    await abortAfterFailure();
    clearSecrets();
    phase.value = "failed";
    error.value = error.value || "轮换通信异常，请重试";
  } finally {
    processing.value = false;
  }
}

/** 失败后尽力丢弃临时库；中止失败则保留作业并提示用户手动中止 */
async function abortAfterFailure() {
  if (!jobActive.value) return;
  try {
    const r = await verthysV4RotateAbort();
    if (r.ok) {
      jobActive.value = false;
      return;
    }
    if (respCode(r) === ROTATE_ERR_IO) {
      /* C 层 Abort 已释放作业，仅临时文件删除失败：不得让 UI 继续锁死。 */
      jobActive.value = false;
      appendError("作业已释放，但临时库删除失败，请手动清理残留文件");
      return;
    }
    appendError(`中止失败（${rotateError(r)}）`);
  } catch {
    appendError("中止通信异常，作业可能仍在活动状态");
  }
}

async function commit() {
  if (processing.value) return;
  processing.value = true;
  error.value = "";
  phase.value = "committing";
  try {
    const r = await verthysV4RotateCommit(keepOld.value);
    if (!r.ok) {
      clearSecrets();
      phase.value = "failed";
      error.value = `提交失败：${rotateError(r)}`;
      return;
    }
    jobActive.value = false;
    clearSecrets();
    phase.value = "done";
    emit("committed");
  } catch {
    phase.value = "failed";
    error.value = "提交通信异常；作业可能仍在活动状态，请重试或中止";
  } finally {
    processing.value = false;
  }
}

async function abort() {
  if (processing.value) return;
  processing.value = true;
  error.value = "";
  try {
    const r = await verthysV4RotateAbort();
    if (!r.ok && respCode(r) !== ROTATE_ERR_IO) {
      clearSecrets();
      phase.value = "failed";
      error.value = `中止失败：${rotateError(r)}`;
      return;
    }
    jobActive.value = false;
    progress.value = null;
    clearSecrets();
    phase.value = "aborted";
    if (!r.ok) {
      error.value = "作业已释放，但临时库删除失败，请手动清理残留文件";
    }
  } catch {
    phase.value = "failed";
    error.value = "中止通信异常，作业可能仍在活动状态";
  } finally {
    processing.value = false;
  }
}

function reset() {
  if (jobActive.value) return;
  void prepare();
}

function requestClose() {
  if (processing.value) return;
  if (jobActive.value) {
    error.value = "轮换作业仍在进行，请先提交或中止";
    return;
  }
  clearSecrets();
  emit("close");
}

watch(
  () => props.show,
  (visible) => {
    if (visible) {
      void prepare();
    } else {
      clearSecrets();
    }
  },
  { immediate: true },
);

onUnmounted(() => {
  setSessionLockSuppressed(false);
  clearSecrets();
});
</script>

<style scoped>
/* 单据式配置面：可滚动内容限高，外壳与底部动作保持在统一弹窗体系内 */
.vr-body {
  max-height: min(72vh, 680px);
  overflow-y: auto;
  overscroll-behavior: contain;
  padding-right: 4px;
  scrollbar-width: thin;
  scrollbar-color: rgba(0, 212, 255, 0.22) transparent;
}

.vr-head {
  margin-bottom: 16px;
}
.vr-head .kv-title {
  margin-bottom: 6px;
}
.vr-coord {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 10px;
  letter-spacing: 0.2em;
  color: var(--text-muted);
}
.vr-mark {
  width: 5px;
  height: 5px;
  transform: rotate(45deg);
  background: rgba(0, 212, 255, 0.5);
}

.vr-intro {
  margin: 0 0 14px;
  font-size: 12px;
  line-height: 1.66;
  letter-spacing: 0.01em;
  color: var(--text-muted);
}
.vr-error {
  margin: 0 0 10px;
  font-size: 11.5px;
  line-height: 1.55;
  color: var(--danger);
}
.vr-success {
  margin: 0 0 10px;
  font-size: 12px;
  line-height: 1.55;
  color: var(--accent);
}
.vr-phase {
  margin: 0;
  font-size: 12px;
  line-height: 1.55;
  letter-spacing: 0.02em;
  color: var(--accent);
}
.vr-hint {
  margin: 8px 0 0;
  font-size: 11px;
  line-height: 1.55;
  color: var(--text-muted);
}

/* 配置分段：以发丝级横线与坐标索引收束，不设卡片围框 */
.vr-section {
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid rgba(205, 224, 244, 0.06);
}
.vr-section-head {
  display: flex;
  align-items: baseline;
  gap: 8px;
  margin-bottom: 8px;
}
.vr-index {
  font-size: 10px;
  letter-spacing: 0.16em;
  color: rgba(0, 212, 255, 0.46);
  font-variant-numeric: tabular-nums;
}
.vr-section-title {
  font-size: 11px;
  letter-spacing: 0.16em;
  color: rgba(205, 224, 244, 0.82);
}
.vr-section-note {
  margin: 0 0 8px;
  font-size: 11px;
  line-height: 1.55;
  color: var(--text-muted);
}
.vr-path-row {
  display: flex;
  align-items: center;
  gap: 10px;
}
.vr-path {
  flex: 1;
  min-width: 0;
  font-size: 11.5px;
  letter-spacing: 0.02em;
  color: var(--text-muted);
  cursor: default;
}

/* 极简端子：无框无底，只有文字与一段可展引线 */
.vr-ghost {
  position: relative;
  flex: none;
  padding: 6px 2px;
  border: 0;
  background: none;
  color: var(--text-muted);
  font-size: 11px;
  letter-spacing: 0.06em;
  white-space: nowrap;
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease);
}
.vr-ghost::after {
  content: "";
  position: absolute;
  left: 2px;
  right: 2px;
  bottom: 2px;
  height: 1px;
  background: rgba(205, 224, 244, 0.18);
  transform: scaleX(0.38);
  transform-origin: left;
  transition:
    transform var(--dur-fast) var(--ease),
    background-color var(--dur-fast) var(--ease);
}
.vr-ghost:not(:disabled):hover {
  color: var(--accent);
}
.vr-ghost:not(:disabled):hover::after {
  transform: scaleX(1);
  background: var(--accent);
}
.vr-ghost:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: 1px;
}
.vr-ghost:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
.vr-ghost:disabled::after {
  display: none;
}

.vr-options {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.vr-toggle {
  justify-content: flex-start;
  padding: 2px 0;
}
.vr-warn {
  margin: 8px 0 0;
  font-size: 11px;
  line-height: 1.6;
  color: var(--warning);
}

/* 进行中：阶段读数 + 离散刻度 + 计数，无滚动光条 */
.vr-live {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.vr-steps {
  display: flex;
}
.vr-step {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
  font-size: 9.5px;
  letter-spacing: 0.12em;
  color: rgba(148, 160, 178, 0.45);
}
.vr-step i {
  flex: none;
  width: 5px;
  height: 5px;
  transform: rotate(45deg);
  background: rgba(205, 224, 244, 0.16);
}
.vr-step b {
  font-weight: 400;
  white-space: nowrap;
}
.vr-step.is-done {
  color: rgba(205, 224, 244, 0.62);
}
.vr-step.is-done i {
  background: rgba(var(--accent-rgb), 0.35);
}
.vr-step.is-active {
  color: var(--text-primary);
}
.vr-step.is-active i {
  background: var(--accent);
}
.vr-stats {
  margin: 0;
  font-size: 11px;
  line-height: 1.6;
  letter-spacing: 0.02em;
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}

.vr-modules {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.vr-module-row {
  display: grid;
  grid-template-columns: 76px minmax(0, 1fr);
  align-items: center;
  gap: 10px;
}
.vr-module-name {
  font-size: 11px;
  letter-spacing: 0.06em;
  color: var(--text-muted);
}
.vr-secret {
  position: relative;
  min-width: 0;
  --kv-input-pad-right: 38px;
}
/* 显隐端子内嵌：图标即控件，零底板、零阴影 */
.vr-eye {
  position: absolute;
  top: 50%;
  right: 6px;
  transform: translateY(-50%);
  z-index: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease);
}
.vr-eye:not(:disabled):hover {
  color: var(--accent);
}
.vr-eye:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: 1px;
}
.vr-eye:disabled {
  cursor: not-allowed;
  opacity: 0.4;
}
.vr-eye svg {
  width: 14px;
  height: 14px;
}

.vr-actions {
  flex-wrap: wrap;
}
</style>
