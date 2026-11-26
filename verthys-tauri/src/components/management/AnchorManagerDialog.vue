<!--
  AnchorManagerDialog.vue — 回退锚点管理弹窗

  职责：
    1. 展示全部锚点与见证状态（ACTIVE/DEAD/TAMPERED/UNKNOWN）
    2. 展示宿主自动扫描到的 UUID → 路径证据与每个位置的覆盖率；
       扫描结果只作为证据，不自动删除
    3. 通过二次确认触发“释放选中”或“回收失效”
    4. 明确告知：释放 ACTIVE/TAMPERED 后，仍存在的容器必须用恢复码重建锚点

  扫描边界：
    - 打开弹窗自动扫描容器目录、最近容器目录与自定义位置；
    - 深度扫描仅在用户显式确认后触发，耗时较长且允许关闭窗口；
    - 扫描不完整时禁用批量“勾选缺失”，避免把未覆盖位置误判为不存在

  安全边界：
    - 组件不自行决定“哪些可以删”，只按后端状态展示并要求用户显式选择
    - DEAD 才允许回收；释放选中必须由用户勾选并二次确认
    - 不展示指纹、私钥或任何密钥材料
-->
<template>
  <CosmicOverlay
    :show="show"
    width="780px"
    role="alertdialog"
    aria-labelledby="anchor-manager-title"
    :persistent="busy"
    scrollbar-hidden
    @close="close"
  >
    <div class="anchor-dialog">
      <header class="anchor-dialog-head">
        <div class="kv-title" id="anchor-manager-title">回退锚点管理</div>
        <span class="kv-readout">{{ anchors.length }}/64</span>
        <SfActionNode
          class="anchor-refresh"
          label="刷新回退锚点"
          :disabled="busy"
          :busy="busy"
          @click="$emit('refresh')"
        >
          <svg
            class="sf-act-icon"
            :class="{ 'is-spinning-once': busy }"
            aria-hidden="true"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
          ><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>
        </SfActionNode>
      </header>

      <p v-if="state === 0" class="kv-warn">
        回退状态文件不存在：可能是首次运行，也可能是文件被删除。删除安全状态文件属于异常操作，请先确认设备未被回滚。
      </p>
      <p v-else-if="state === 2" class="kv-error">
        回退状态文件损坏或无法认证，维护接口已 fail-closed。请先修复状态文件，或使用恢复码重建锚点。
      </p>
      <p v-if="error" class="kv-error">{{ error }}</p>
      <p v-if="notice" class="kv-note anchor-notice">{{ notice }}</p>

      <div class="anchor-toolbar">
        <button
          class="btn btn-neutral btn-compact"
          type="button"
          :disabled="busy || scanning"
          @click="$emit('scan', { force: true })"
        >
          重新扫描
        </button>
        <button
          class="btn btn-neutral btn-compact"
          type="button"
          :disabled="busy || scanning"
          @click="pickRoots"
        >
          添加位置
        </button>
        <button
          class="btn btn-neutral btn-compact"
          type="button"
          :disabled="busy || scanning || !canBulkSelect"
          :title="canBulkSelect ? '' : '扫描完整后才可批量勾选'"
          @click="selectNotFound"
        >
          勾选缺失
        </button>
        <button
          class="btn btn-destructive btn-compact"
          type="button"
          :disabled="busy || scanning || deadCount === 0"
          @click="pending = 'reclaim'"
        >
          回收失效
        </button>
        <button
          class="btn btn-neutral btn-compact"
          type="button"
          :disabled="busy || scanning"
          @click="pending = 'deep'"
        >
          深度扫描
        </button>
      </div>
      <p class="kv-hint">
        仅 DEAD 可回收；勾选缺失只选择使用中且未找到的锚点，见证异常/未知请逐条核对。扫描只读取容器固定头，不会打开或修改容器。
      </p>

      <Transition name="anchor-reveal">
        <div v-if="show" class="anchor-reveal">
          <div class="anchor-reveal-body">
            <section class="kv-section">
              <div class="kv-section-label">
                扫描范围
                <span v-if="scanning" class="anchor-scan-state">扫描中</span>
              </div>
              <div v-if="scanning" class="anchor-scan-line">
                <span class="kv-readout anchor-scan-progress">{{ progressText }}</span>
                <button
                  class="btn btn-neutral btn-compact"
                  type="button"
                  @click="$emit('cancel-scan')"
                >
                  停止扫描
                </button>
              </div>
              <template v-else-if="scan">
                <div class="kv-readout">
                  已知位置 {{ autoDirRoots.length }} · 已知容器 {{ knownFileRoots.length
                  }}{{ knownFileMissing ? `（缺失 ${knownFileMissing}）` : "" }} · 文件
                  {{ scan.files_seen }} · 命中 {{ scan.matched_count }} · 更新 {{ formatTime(scan.scanned_at) }}
                </div>
                <p v-if="scan.partial" class="kv-error">
                  本次扫描未完成：{{ partialReason }}。批量勾选已停用，请重新扫描或手动逐条选择。
                </p>
                <p v-if="deepRoots.length" class="kv-readout">
                  深度扫描：{{ deepCompleted }}/{{ deepRoots.length }} 个目录{{ deepIncomplete ? " · 部分未完成，可再次扫描" : "" }}
                </p>
                <ul v-if="visibleDirRoots.length" class="anchor-coverage">
                  <li
                    v-for="root in visibleDirRoots"
                    :key="`${root.source}:${root.path}`"
                    class="anchor-coverage-row"
                  >
                    <span class="anchor-coverage-source">{{ sourceLabel(root.source) }}</span>
                    <span class="anchor-coverage-path" v-tip="root.path">{{ root.path }}</span>
                    <span class="anchor-coverage-state" :class="rootStateClass(root)">
                      {{ rootStateText(root) }}
                    </span>
                    <button
                      v-if="root.source === 'custom'"
                      class="btn btn-neutral btn-compact anchor-root-remove"
                      type="button"
                      :disabled="busy || scanning"
                      @click="$emit('forget-root', root.path)"
                    >
                      移除
                    </button>
                  </li>
                </ul>
                <p v-if="hiddenDirRootCount > 0" class="kv-readout">
                  另有 {{ hiddenDirRootCount }} 个位置
                </p>
                <p class="kv-hint">
                  扫描结果只是证据，不作为自动删除依据；未在扫描范围内找到的锚点仍需逐条确认。
                </p>
              </template>
              <p v-else class="kv-readout">正在准备扫描…</p>
            </section>
          </div>
        </div>
      </Transition>

      <Transition name="anchor-reveal">
        <div v-if="pending" class="anchor-reveal">
          <div class="anchor-reveal-body">
            <section
              class="kv-section"
              role="alertdialog"
              :aria-label="pendingTitle"
              aria-live="assertive"
            >
              <div class="kv-section-label">{{ pendingTitle }}</div>
              <p v-if="pending === 'release'" class="kv-warn">
                将释放 {{ selectedCount }} 个锚点。若对应容器仍存在，普通解锁会被拒绝，必须使用恢复码重新建立锚点。
              </p>
              <p
                v-if="pending === 'release' && activeOrTamperedSelected.length"
                class="kv-error"
              >
                其中 {{ activeOrTamperedSelected.length }} 个并非 DEAD，属于仍可能有效的锚点。
              </p>
              <p
                v-if="pending === 'release' && tamperedSelected.length"
                class="kv-error"
              >
                其中 {{ tamperedSelected.length }} 个是“见证异常（TAMPERED）”；释放会删除其见证键并销毁篡改证据，建议先联系支持。
              </p>
              <p v-if="pending === 'release'" class="kv-note">
                已解锁会话在下次保存时会重新登记锚点；释放前建议先锁定容器。
              </p>
              <p v-else-if="pending === 'reclaim'" class="kv-warn">
                将回收 {{ deadCount }} 个 DEAD 锚点。ACTIVE/TAMPERED/UNKNOWN 不会被删除，仍在使用中的容器不受影响。
              </p>
              <template v-else>
                <p class="kv-warn">
                  将扫描所有固定磁盘的顶级目录与当前用户桌面/文档/下载，跳过系统目录；耗时较长，结果只作为证据，不会自动释放锚点。
                </p>
                <p class="kv-note">
                  扫描期间可以关闭窗口；已完成位置的证据会自动保留，未完成位置下次优先。
                </p>
              </template>
              <div class="kv-actions">
                <button
                  class="btn btn-neutral btn-compact"
                  type="button"
                  :disabled="busy || scanning"
                  @click="pending = null"
                >
                  取消
                </button>
                <button
                  class="btn btn-compact"
                  :class="pending === 'deep' ? 'btn-neutral' : 'btn-destructive'"
                  type="button"
                  :disabled="busy || scanning"
                  @click="confirmPending"
                >
                  {{ pending === "deep" ? "开始扫描" : "确认" }}
                </button>
              </div>
            </section>
          </div>
        </div>
      </Transition>

      <section class="kv-section">
        <div class="kv-section-label">
          锚点清单
          <span class="anchor-selected">已选 {{ selectedCount }}</span>
        </div>
        <div class="anchor-table-wrap">
          <table class="anchor-table">
            <thead>
              <tr>
                <th aria-label="选择" />
                <th><span class="anchor-th-label">UUID</span></th>
                <th v-tip="'容器元数据的提交版本；低于回退锚点记录时判定为回退'"><span class="anchor-th-label">元数据版本</span></th>
                <th v-tip="'该锚点的 TPM 见证密钥校验状态；见证异常表示见证密钥存在但指纹不符'"><span class="anchor-th-label">见证状态</span></th>
                <th><span class="anchor-th-label">扫描证据</span></th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="a in anchors"
                :key="a.uuid"
                class="anchor-row"
                :class="[`anchor-row--${a.witness}`, { 'is-selected': selected.includes(a.uuid) }]"
              >
                <td>
                  <label class="kf-toggle anchor-check">
                    <input
                      type="checkbox"
                      :checked="selected.includes(a.uuid)"
                      :disabled="busy || scanning"
                      :aria-label="`选择锚点 ${a.uuid}`"
                      @change="toggle(a.uuid)"
                    />
                    <span class="kf-box" aria-hidden="true"></span>
                  </label>
                </td>
                <td class="anchor-uuid-cell">
                  <span
                    class="anchor-uuid"
                    role="button"
                    tabindex="0"
                    :aria-label="`复制完整 UUID：${a.uuid}`"
                    v-tip="'点击复制完整 UUID'"
                    @click="copyUuid(a.uuid)"
                    @keydown.enter.prevent="copyUuid(a.uuid)"
                    @keydown.space.prevent="copyUuid(a.uuid)"
                  >{{ a.uuid }}</span>
                </td>
                <td class="anchor-id">{{ a.generation }}</td>
                <td>
                  <span class="anchor-state" :class="`anchor-state--${a.witness}`">
                    {{ witnessLabel(a.witness) }}
                  </span>
                </td>
                <td class="anchor-paths">
                  <!-- td 必须是 table-cell：flex 只能放在内层，直接设在 td 上会
                       让它退出表格布局，导致最后一列的宽度/行高与表头错位 -->
                  <div class="anchor-paths-stack">
                    <template v-if="evidencePaths(a.uuid)?.length">
                      <span v-for="p in evidencePaths(a.uuid)" :key="p" class="anchor-path">{{ p }}</span>
                    </template>
                    <span v-else class="anchor-path anchor-path--missing">
                      {{ scanning ? "正在扫描…" : scan ? "未在扫描范围内找到" : "尚未扫描" }}
                    </span>
                  </div>
                </td>
              </tr>
              <tr v-if="anchors.length === 0">
                <td colspan="5" class="anchor-empty">暂无锚点</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <Transition name="anchor-reveal">
        <div v-if="scan && unregistered.length" class="anchor-reveal">
          <div class="anchor-reveal-body">
            <section class="kv-section">
              <div class="kv-section-label">未登记 UUID</div>
              <p class="kv-hint">容器存在但状态中无锚点，仅作为扫描证据。</p>
              <div v-for="e in unregistered" :key="e.uuid" class="anchor-path anchor-unregistered-item">
                {{ e.uuid }} — {{ e.paths.join("; ") }}
              </div>
            </section>
          </div>
        </div>
      </Transition>

      <footer class="kv-actions">
        <button
          class="btn btn-neutral btn-compact"
          type="button"
          :disabled="busy"
          @click="close"
        >
          关闭
        </button>
        <button
          class="btn btn-destructive btn-compact"
          type="button"
          :disabled="busy || scanning || selectedCount === 0"
          @click="requestRelease"
        >
          释放选中
        </button>
      </footer>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";
import SfActionNode from "./SfActionNode.vue";
import { useClipToast } from "../../composables/useClipToast";
import { useToastCenter } from "../../composables/useToastCenter";
import type { AnchorScanOptions } from "../../lib/verthys";
import type {
  AnchorInfo,
  AnchorScanProgress,
  AnchorScanResult,
  AnchorScanRootReport,
} from "../../types/verthys";

const props = defineProps<{
  show: boolean;
  anchors: AnchorInfo[];
  state: number;
  scan: AnchorScanResult | null;
  busy: boolean;
  scanning: boolean;
  scanProgress: AnchorScanProgress | null;
  error: string;
  notice: string;
}>();

const emit = defineEmits<{
  (e: "close"): void;
  (e: "refresh"): void;
  (e: "scan", options: AnchorScanOptions): void;
  (e: "cancel-scan"): void;
  (e: "forget-root", path: string): void;
  (e: "reclaim"): void;
  (e: "release", uuids: string[]): void;
}>();

const selected = ref<string[]>([]);
const pending = ref<"release" | "reclaim" | "deep" | null>(null);

/* 复制走全项目统一的安全剪贴板通道：成功后提示并按时清空 */
const { copyWithTimeout } = useClipToast("锚点 UUID 已复制");
const { showError } = useToastCenter();

const copyUuid = async (uuid: string): Promise<void> => {
  const copied = await copyWithTimeout(uuid);
  if (!copied) showError("复制失败：剪贴板不可用或权限被拒绝");
};

const selectedCount = computed(() => selected.value.length);
const deadCount = computed(
  () => props.anchors.filter((a) => a.witness === "dead").length,
);
const activeOrTamperedSelected = computed(() =>
  selected.value.filter((uuid) => {
    const anchor = props.anchors.find((a) => a.uuid === uuid);
    return anchor && anchor.witness !== "dead";
  }),
);
const tamperedSelected = computed(() =>
  selected.value.filter(
    (uuid) =>
      props.anchors.find((a) => a.uuid === uuid)?.witness === "tampered",
  ),
);

const scanMap = computed(() => {
  const map = new Map<string, string[]>();
  for (const entry of props.scan?.entries ?? []) {
    map.set(entry.uuid.toLowerCase(), entry.paths);
  }
  return map;
});

function evidencePaths(uuid: string): string[] | undefined {
  return scanMap.value.get(uuid.toLowerCase());
}

const unregistered = computed(() => {
  const known = new Set(props.anchors.map((a) => a.uuid.toLowerCase()));
  return (props.scan?.entries ?? []).filter(
    (entry) => !known.has(entry.uuid.toLowerCase()),
  );
});

const autoDirRoots = computed(
  () =>
    (props.scan?.roots ?? []).filter(
      (root) =>
        root.kind === "dir" &&
        root.source !== "deep" &&
        root.source !== "deep_user",
    ),
);
const knownFileRoots = computed(
  () => (props.scan?.roots ?? []).filter((root) => root.kind === "file"),
);
const knownFileMissing = computed(
  () => knownFileRoots.value.filter((root) => !root.available).length,
);
const deepRoots = computed(
  () =>
    (props.scan?.roots ?? []).filter(
      (root) => root.source === "deep" || root.source === "deep_user",
    ),
);
const visibleDirRoots = computed(() => autoDirRoots.value.slice(0, 8));
const hiddenDirRootCount = computed(() =>
  Math.max(0, autoDirRoots.value.length - visibleDirRoots.value.length),
);
const deepCompleted = computed(
  () => deepRoots.value.filter((root) => root.last_success_at > 0).length,
);
const deepIncomplete = computed(() =>
  deepRoots.value.some(
    (root) => root.deferred || !root.available || root.truncated,
  ),
);
const deferredRoots = computed(
  () => (props.scan?.roots ?? []).filter((root) => root.deferred),
);

/** 只有完整扫描才允许“勾选缺失”：截断或预算用尽时“未找到”不可靠。 */
const canBulkSelect = computed(
  () => !!props.scan && !props.scan.partial && !props.scanning,
);

const partialReason = computed(() => {
  const parts: string[] = [];
  if (deferredRoots.value.length) {
    parts.push(`${deferredRoots.value.length} 个位置未扫描`);
  }
  if (props.scan?.truncated) {
    parts.push("遍历被截断");
  }
  if (props.scan?.permission_errors) {
    parts.push(`权限受限 ${props.scan.permission_errors}`);
  }
  if (props.scan?.other_errors) {
    parts.push(`读取错误 ${props.scan.other_errors}`);
  }
  return parts.join(" · ") || "覆盖不完整";
});

const progressText = computed(() => {
  const progress = props.scanProgress;
  if (!progress || progress.phase === "collecting") {
    return "正在收集扫描位置…";
  }
  if (progress.phase === "done") {
    return "扫描完成";
  }
  const current = progress.current_path ? ` · ${progress.current_path}` : "";
  return `位置 ${progress.roots_done}/${progress.roots_total}${current} · 文件 ${progress.files_seen} · 命中 ${progress.matched_count}`;
});

const pendingTitle = computed(() => {
  if (pending.value === "release") return "确认释放";
  if (pending.value === "reclaim") return "确认回收";
  return "深度扫描";
});

function formatTime(seconds: number): string {
  if (!seconds) return "尚未完成";
  return new Date(seconds * 1000).toLocaleTimeString("zh-CN", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
  });
}

function sourceLabel(source: string): string {
  switch (source) {
    case "container":
      return "容器目录";
    case "recent":
      return "最近位置";
    case "custom":
      return "自定义";
    case "deep":
      return "深度扫描";
    case "deep_user":
      return "深度扫描";
    default:
      return "位置";
  }
}

function rootStateText(root: AnchorScanRootReport): string {
  if (root.deferred) return "本次未扫描";
  if (!root.available) return "位置不可用";
  const limited = root.permission_errors + root.other_errors;
  if (limited > 0) return `受限 ${limited}`;
  if (root.truncated) return "扫描未完成";
  return "正常";
}

function rootStateClass(root: AnchorScanRootReport): string {
  if (
    root.deferred ||
    !root.available ||
    root.truncated ||
    root.permission_errors + root.other_errors > 0
  ) {
    return "is-alert";
  }
  return "is-ok";
}

watch(
  () => props.show,
  (visible) => {
    if (!visible) {
      selected.value = [];
      pending.value = null;
    }
  },
);

/* 释放/回收刷新后，勾选列表只保留仍存在的 UUID，避免对已删除条目再次确认。 */
watch(
  () => props.anchors,
  (anchors) => {
    const alive = new Set(anchors.map((anchor) => anchor.uuid));
    selected.value = selected.value.filter((uuid) => alive.has(uuid));
  },
);

function witnessLabel(witness: string): string {
  switch (witness) {
    case "active":
      return "使用中";
    case "dead":
      return "已失效";
    case "tampered":
      return "见证异常";
    default:
      return "未知";
  }
}

function toggle(uuid: string) {
  if (props.busy || props.scanning) return;
  selected.value = selected.value.includes(uuid)
    ? selected.value.filter((item) => item !== uuid)
    : [...selected.value, uuid];
}

/**
 * 按扫描证据勾选“未在扫描范围内找到”的使用中锚点。
 *
 * 只改变勾选，不执行释放；DEAD 交给“回收失效”，TAMPERED/UNKNOWN 不批量勾选，
 * 必须逐条阅读确认文案后手动选择。
 */
function selectNotFound() {
  if (!canBulkSelect.value || props.busy) return;
  const found = new Set(
    (props.scan?.entries ?? [])
      .filter((entry) => entry.paths.length > 0)
      .map((entry) => entry.uuid.toLowerCase()),
  );
  selected.value = props.anchors
    .filter(
      (anchor) =>
        anchor.witness === "active" && !found.has(anchor.uuid.toLowerCase()),
    )
    .map((anchor) => anchor.uuid);
}

function requestRelease() {
  if (selectedCount.value === 0) return;
  pending.value = "release";
}

function confirmPending() {
  if (pending.value === "release") {
    emit("release", [...selected.value]);
  } else if (pending.value === "reclaim") {
    emit("reclaim");
  } else if (pending.value === "deep") {
    emit("scan", { deep: true, force: true });
  }
  pending.value = null;
}

function close() {
  if (props.busy) return;
  emit("close");
}

async function pickRoots() {
  if (props.busy || props.scanning) return;
  try {
    const picked = await open({
      directory: true,
      multiple: true,
      title: "添加容器所在目录",
    });
    if (!picked) return;
    const roots = Array.isArray(picked) ? picked : [picked];
    if (roots.length > 0) emit("scan", { roots });
  } catch {
    // 目录选择取消或宿主不可用：由父组件展示扫描错误；此处不抛异常。
  }
}
</script>

<style scoped>
/* 头部：标题 / 计数 / 刷新节点一行；间距与标题排印沿用 kv-* 单源 */
.anchor-dialog-head {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}
.anchor-dialog-head .kv-title {
  margin-bottom: 0;
}
.anchor-dialog-head .kv-readout {
  color: rgba(0, 212, 255, 0.8);
}
/* 锚点面板文本统一使用项目主字体，不混用等宽字体 */
.anchor-dialog .kv-readout {
  font-family: var(--font);
}
.anchor-refresh {
  margin-left: auto;
}
/* 成功提示沿用 kv-note，仅补与下方工具条的间距 */
.anchor-notice {
  margin: 0 0 12px;
}
/* 清单标题尾的常驻勾选计数：分区分隔线之后靠右，字体口径同只读读数 */
.anchor-selected {
  order: 1;
  flex-shrink: 0;
  font-size: 10.5px;
  letter-spacing: 0.4px;
  color: var(--text-secondary);
}
/* 工具条只负责排列；按钮皮肤来自星野键族（中性 / 赤势），
   尺寸统一走 .btn-compact，与动作行按钮同高同字阶 */
.anchor-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}
/* 扫描中状态：只作为分区标题后的文字读数，不加底色或发光 */
.anchor-scan-state {
  order: 1;
  flex-shrink: 0;
  font-size: 10px;
  letter-spacing: 0.16em;
  color: rgba(0, 212, 255, 0.75);
}
.anchor-scan-progress {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.anchor-scan-line {
  display: flex;
  align-items: center;
  gap: 10px;
}
/* 覆盖范围清单：每行一个位置，路径单行省略，状态用纯文字颜色区分 */
.anchor-coverage {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin: 8px 0 0;
  padding: 0;
  list-style: none;
}
.anchor-coverage-row {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  font-family: var(--font);
  font-size: 10px;
  line-height: 1.5;
  color: var(--text-secondary);
}
.anchor-coverage-source {
  flex: none;
  color: var(--text-muted);
  letter-spacing: 0.08em;
}
.anchor-coverage-path {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.anchor-coverage-state {
  flex: none;
}
.anchor-coverage-state.is-alert {
  color: var(--danger);
}
.anchor-coverage-state.is-ok {
  color: var(--text-muted);
}
.anchor-root-remove {
  flex: none;
}
/* 动态分区揭示：高度与不透明度平滑展开，避免新面板把清单整体瞬移；
   文字层不做位移/缩放/滤镜，保持字形清晰 */
.anchor-reveal {
  display: grid;
  grid-template-rows: 1fr;
}
.anchor-reveal-body {
  min-height: 0;
  overflow: hidden;
}
.anchor-reveal-enter-active {
  transition: grid-template-rows 0.34s var(--ease), opacity 0.34s var(--ease);
}
.anchor-reveal-leave-active {
  transition: grid-template-rows 0.26s var(--ease), opacity 0.26s var(--ease);
  pointer-events: none;
}
.anchor-reveal-enter-from {
  grid-template-rows: 0fr;
  opacity: 0;
}
.anchor-reveal-leave-to {
  grid-template-rows: 0fr;
  opacity: 0;
}
@media (prefers-reduced-motion: reduce) {
  .anchor-reveal-enter-active,
  .anchor-reveal-leave-active {
    transition: none;
  }
}
.anchor-table-wrap {
  /* 表格是独立滚动区：高度随视口收敛，阻止滚动链把父级内容一起带走；
     滚动条完全隐藏，滚动仍由滚轮/触控板/键盘完成。 */
  max-height: min(320px, 44vh);
  overflow: auto;
  overscroll-behavior: contain;
  scrollbar-width: none;
  -ms-overflow-style: none;
}
.anchor-table-wrap::-webkit-scrollbar {
  width: 0;
  height: 0;
  display: none;
}
.anchor-table {
  width: 100%;
  /* 表头要做成一枚独立的半透明圆角托板：必须用 separate 才能让首尾
     单元格的圆角真正生效；border-spacing:0 保证列与行仍严丝合缝。 */
  border-collapse: separate;
  border-spacing: 0;
  font-family: var(--font);
  font-size: 12px;
}
.anchor-table th {
  position: sticky;
  top: 0;
  z-index: 1;
  padding: 9px 8px 7px;
  /* 半透明冷光托板：不再向透明渐隐，读作一枚完整的圆角表头条；
     背衬模糊负责压住滚动内容，文字保持在上层。 */
  background: linear-gradient(
    180deg,
    rgba(205, 224, 244, 0.075) 0%,
    rgba(205, 224, 244, 0.045) 100%
  );
  -webkit-backdrop-filter: blur(16px) saturate(150%);
  backdrop-filter: blur(16px) saturate(150%);
  box-shadow:
    inset 0 1px 0 rgba(var(--white-rgb), 0.07),
    inset 0 -1px 0 rgba(205, 224, 244, 0.12);
  text-align: left;
  font-weight: 500;
  font-size: 10px;
  letter-spacing: 0.16em;
  color: rgba(212, 226, 241, 0.92);
  text-shadow: 0 1px 2px rgba(var(--black-rgb), 0.55);
}
.anchor-table th:first-child {
  border-radius: 8px 0 0 8px;
}
.anchor-table th:last-child {
  border-radius: 0 8px 8px 0;
}
/* 列名与尾线：线从标签右侧起、向右渐隐；单元格之间留出自然断口，
   读作一排分区标题，而不是一根贯穿表头的横杠。 */
.anchor-th-label {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}
.anchor-th-label::after {
  content: "";
  flex: 1;
  min-width: 12px;
  height: 1px;
  background: linear-gradient(90deg, rgba(205, 224, 244, 0.22), transparent);
}
.anchor-table td {
  padding: 7px 8px;
  border-top: 1px solid rgba(205, 224, 244, 0.07);
  vertical-align: top;
  /* 统一行内基线：勾选格与 UUID / 版本 / 状态共用同一 18px 行盒 */
  line-height: 1.5;
  color: var(--text-secondary);
}
/* 行选择：复用全局 kf-toggle 指示格，左对齐贴单元格起始边 */
.anchor-check {
  justify-content: flex-start;
  width: fit-content;
  height: 18px;
}
.anchor-check:has(input:disabled) {
  cursor: not-allowed;
}
.anchor-check input:disabled ~ .kf-box {
  opacity: 0.4;
}
.anchor-row.is-selected td {
  background: rgba(var(--accent-rgb), 0.04);
}
/* 选中态是一整条圆角带：首尾单元格各收一端圆角，与表头托板同半径。
   表格已使用 border-collapse: separate，圆角裁切才会生效。 */
.anchor-row.is-selected td:first-child {
  border-radius: 8px 0 0 8px;
}
.anchor-row.is-selected td:last-child {
  border-radius: 0 8px 8px 0;
}
.anchor-row--tampered td:first-child {
  box-shadow: inset 2px 0 0 var(--danger);
}
.anchor-id {
  font-family: var(--font);
  white-space: nowrap;
}
/* UUID 是释放操作的唯一定位依据：表格只占固定一列宽，超出省略；
   点击/回车复制完整值，避免既要可读又不被 36 位长串撑破行高。 */
.anchor-uuid-cell {
  width: 200px;
  min-width: 200px;
  max-width: 200px;
}
.anchor-uuid {
  display: block;
  width: 100%;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-family: var(--font);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease);
}
.anchor-uuid:hover {
  color: var(--text-primary);
}
.anchor-uuid:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: 2px;
  border-radius: 3px;
}
.anchor-state {
  font-size: 10.5px;
}
.anchor-state--active { color: rgba(0, 212, 255, 0.9); }
.anchor-state--dead { color: rgba(255, 165, 2, 0.9); }
.anchor-state--tampered { color: var(--danger); }
.anchor-state--unknown { color: var(--text-muted); }
.anchor-paths {
  min-width: 0;
}
.anchor-paths-stack {
  display: flex;
  flex-direction: column;
  gap: 3px;
  word-break: break-all;
}
.anchor-path {
  font-family: var(--font);
  font-size: 10px;
  line-height: 1.5;
  color: var(--text-secondary);
}
.anchor-path--missing {
  color: var(--text-muted);
}
.anchor-unregistered-item {
  margin-top: 6px;
  word-break: break-all;
}
.anchor-empty {
  padding: 18px 0;
  text-align: center;
  font-size: 12px;
  color: var(--text-muted);
}
</style>
