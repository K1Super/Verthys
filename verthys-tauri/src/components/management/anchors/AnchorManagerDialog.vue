<!--
  AnchorManagerDialog.vue — 回退锚点管理弹窗

  职责：
    1. 展示全部锚点与见证状态（ACTIVE=见证有效 / DEAD=见证缺失 /
       TAMPERED=见证异常 / UNKNOWN=见证未知）
    2. 展示全量扫描到的 UUID → 路径证据与每个位置的覆盖率；
       扫描结果只作为证据，不自动删除
    3. 通过二次确认触发单一入口：选中项全为 DEAD 时清理，否则释放
    4. 明确告知：释放 ACTIVE/TAMPERED 后，仍存在的容器必须用恢复码重建锚点

  扫描边界：
    - 只有一个扫描入口：本地磁盘根 + 自定义位置 + 当前/最近容器探针；
    - 扫描完整时自动勾选“见证有效且未找到”的锚点；不完整时保持清空，
      避免把未覆盖位置误判为不存在
    - 单 UUID 证据超过展示上限只在该条目标注，不影响扫描完整性判定
    - 扫描只读容器固定头，不打开或修改容器

  语义边界：
    - 见证状态只反映 TPM 见证密钥的探测结果，不代表容器文件仍然存在；
      容器是否存在以扫描证据为准

  安全边界：
    - 组件不自行决定“哪些可以删”，只按后端状态展示并要求用户显式确认
    - DEAD 只通过统一入口清理；包含其它状态时必须由用户显式确认释放
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

      <div class="anchor-toolbar">
        <button
          class="btn btn-neutral btn-compact"
          type="button"
          :disabled="busy || scanning"
          @click="$emit('scan', { force: true })"
        >
          扫描
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
          class="btn btn-destructive btn-compact"
          type="button"
          :disabled="busy || scanning || selectedCount === 0"
          @click="requestRelease"
        >
          {{ selectedAllDead ? "清理选中" : "释放选中" }}
        </button>
      </div>
      <p class="kv-hint">
        打开时自动勾选见证缺失（DEAD）锚点；选中项全为 DEAD 时为清理，包含其它状态时为释放。扫描只读取容器固定头，不会打开或修改容器。
      </p>

      <section class="kv-section anchor-scan-section">
        <div class="kv-section-label">
          扫描范围
          <span v-if="scanning" class="anchor-scan-state">扫描中</span>
          <span v-else-if="scan && scan.scanned_at" class="anchor-scan-updated">
            更新 {{ formatTime(scan.scanned_at) }}
          </span>
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

        <template v-else-if="scan && scan.scanned_at">
          <div class="anchor-scan-metrics">
            <span class="anchor-metric">
              <span class="anchor-metric-label">位置</span>
              <span class="anchor-metric-value">{{ scanRoots.length }}</span>
            </span>
            <span class="anchor-metric">
              <span class="anchor-metric-label">深度</span>
              <span class="anchor-metric-value">{{ scan.depth }}</span>
            </span>
            <span class="anchor-metric">
              <span class="anchor-metric-label">文件</span>
              <span class="anchor-metric-value">{{ scan.files_seen }}</span>
            </span>
            <span class="anchor-metric">
              <span class="anchor-metric-label">命中</span>
              <span class="anchor-metric-value">{{ scan.matched_count }}</span>
            </span>
          </div>
          <p v-if="scan.partial" class="kv-error anchor-scan-partial">
            本次扫描未完成：{{ partialReason }}。为避免误判，未自动勾选缺失锚点。
          </p>
        </template>
        <p v-else class="kv-readout anchor-scan-empty">尚未扫描</p>

        <Transition name="anchor-reveal">
          <div v-if="!scanning && orderedRoots.length" class="anchor-reveal">
            <div class="anchor-reveal-body">
              <ul class="anchor-coverage">
                <li
                  v-for="root in orderedRoots"
                  :key="`${root.source}:${root.path}`"
                  class="anchor-coverage-row"
                >
                  <span class="anchor-coverage-source">{{ sourceShort(root.source) }}</span>
                  <span class="anchor-coverage-path" v-tip="root.path">
                    {{ coveragePath(root) }}
                  </span>
                  <span
                    class="anchor-coverage-state"
                    :class="rootStateClass(root)"
                  >
                    {{ rootStateText(root) }}
                  </span>
                  <button
                    v-if="root.source === 'custom'"
                    class="btn btn-neutral btn-mini anchor-root-remove"
                    type="button"
                    :disabled="busy || scanning"
                    @click="$emit('forget-root', root.path)"
                  >
                    移除
                  </button>
                </li>
              </ul>
            </div>
          </div>
        </Transition>

        <p
          v-if="!scanning && scan && scan.scanned_at"
          class="kv-hint anchor-scan-hint"
        >
          见证状态只反映 TPM 见证，不代表容器仍然存在
        </p>
      </section>

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
                <th v-tip="'TPM 见证密钥校验结果：见证有效＝密钥存在且指纹匹配；见证缺失＝密钥确定不存在；见证异常＝密钥存在但指纹不符；见证未知＝探测失败。见证状态不代表容器文件仍然存在。'"><span class="anchor-th-label">见证状态</span></th>
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
                      <span v-if="evidenceCapped(a.uuid)" class="anchor-path anchor-path--capped">
                        另有副本未展示
                      </span>
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
    </div>
  </CosmicOverlay>

  <!-- 二次确认：独立高优先弹窗，叠在管理面板之上；初始焦点在取消键，
       误按回车不会执行不可逆操作 -->
  <CosmicOverlay
    :show="pending"
    width="440px"
    role="alertdialog"
    aria-labelledby="anchor-pending-title"
    initial-focus=".btn-neutral"
    :overlay-z="10000"
    :persistent="busy"
    scrollbar-hidden
    @close="pending = false"
  >
    <div class="kv-title" id="anchor-pending-title">{{ pendingTitle }}</div>
    <template v-if="selectedAllDead">
      <p class="kv-warn">
        将清理 {{ selectedCount }} 个见证缺失（DEAD）锚点。见证有效/异常/未知不会受影响，容器文件不会被改动。
      </p>
      <p v-if="selectedCount" class="kv-readout anchor-dead-ids">
        <span>待清理：</span>
        <span v-for="uuid in visibleSelected" :key="uuid" class="anchor-dead-id">
          {{ uuid }}
        </span>
        <span v-if="selectedCount > visibleSelected.length" class="anchor-dead-more">
          另有 {{ selectedCount - visibleSelected.length }} 个
        </span>
      </p>
    </template>
    <template v-else>
      <p class="kv-warn">
        将释放 {{ selectedCount }} 个锚点。若对应容器仍存在，普通解锁会被拒绝，必须使用恢复码重新建立锚点。
      </p>
      <p v-if="activeOrTamperedSelected.length" class="kv-error">
        其中 {{ activeOrTamperedSelected.length }} 个并非见证缺失（DEAD），见证状态仍可能有效。
      </p>
      <p v-if="tamperedSelected.length" class="kv-error">
        其中 {{ tamperedSelected.length }} 个是“见证异常（TAMPERED）”；释放会删除其见证键并销毁篡改证据，建议先联系支持。
      </p>
    </template>
    <div class="kv-actions">
      <button
        class="btn btn-neutral btn-compact"
        type="button"
        :disabled="busy"
        @click="pending = false"
      >
        取消
      </button>
      <button
        class="btn btn-destructive btn-compact"
        type="button"
        :disabled="busy"
        @click="confirmPending"
      >
        {{ selectedAllDead ? "确认清理" : "确认释放" }}
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import CosmicOverlay from "../../common/cosmic/CosmicOverlay.vue";
import SfActionNode from "../security/SfActionNode.vue";
import { useClipToast } from "../../../composables/ui/useClipToast";
import { useToastCenter } from "../../../composables/ui/useToastCenter";
import type { AnchorScanOptions } from "../../../lib/verthys";
import type {
  AnchorInfo,
  AnchorScanEntry,
  AnchorScanProgress,
  AnchorScanResult,
  AnchorScanRootReport,
} from "../../../types/verthys";

const props = defineProps<{
  show: boolean;
  anchors: AnchorInfo[];
  state: number;
  scan: AnchorScanResult | null;
  busy: boolean;
  scanning: boolean;
  scanProgress: AnchorScanProgress | null;
  error: string;
}>();

const emit = defineEmits<{
  (e: "close"): void;
  (e: "refresh"): void;
  (e: "scan", options: AnchorScanOptions): void;
  (e: "cancel-scan"): void;
  (e: "forget-root", path: string): void;
  (e: "release", uuids: string[]): void;
}>();

const selected = ref<string[]>([]);
const pending = ref(false);

/* 复制走全项目统一的安全剪贴板通道：成功后提示并按时清空 */
const { copyWithTimeout } = useClipToast("锚点 UUID 已复制");
const { showError } = useToastCenter();

const copyUuid = async (uuid: string): Promise<void> => {
  const copied = await copyWithTimeout(uuid);
  if (!copied) showError("复制失败：剪贴板不可用或权限被拒绝");
};

const selectedCount = computed(() => selected.value.length);
const visibleSelected = computed(() => selected.value.slice(0, 3));
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
/** 选中集合非空且全部为 DEAD：语义为清理，不涉及恢复码风险。 */
const selectedAllDead = computed(
  () => selectedCount.value > 0 && activeOrTamperedSelected.value.length === 0,
);

const scanMap = computed(() => {
  const map = new Map<string, AnchorScanEntry>();
  for (const entry of props.scan?.entries ?? []) {
    map.set(entry.uuid.toLowerCase(), entry);
  }
  return map;
});

function evidencePaths(uuid: string): string[] | undefined {
  return scanMap.value.get(uuid.toLowerCase())?.paths;
}

function evidenceCapped(uuid: string): boolean {
  return scanMap.value.get(uuid.toLowerCase())?.capped ?? false;
}

const scanRoots = computed(() => props.scan?.roots ?? []);

const COVERAGE_SOURCE_ORDER = ["custom", "container", "recent", "volume"];

/** 按来源优先级排序；来源在行内标注，不再单独占用组标题行。 */
const orderedRoots = computed(() => {
  const rank = new Map(
    COVERAGE_SOURCE_ORDER.map((source, index) => [source, index]),
  );
  return [...scanRoots.value].sort(
    (a, b) =>
      (rank.get(a.source) ?? COVERAGE_SOURCE_ORDER.length) -
      (rank.get(b.source) ?? COVERAGE_SOURCE_ORDER.length),
  );
});

/** 文件探针只显示文件名，完整路径留给悬浮提示；目录保留完整路径。 */
function coveragePath(root: AnchorScanRootReport): string {
  if (root.kind !== "file") return root.path;
  const parts = root.path.split(/[\\/]/);
  return parts[parts.length - 1] || root.path;
}

/** 来源短标签：固定列宽，让每行路径起点对齐。 */
function sourceShort(source: string): string {
  switch (source) {
    case "container":
      return "当前";
    case "recent":
      return "最近";
    case "custom":
      return "自定义";
    default:
      return "磁盘";
  }
}
const deferredRoots = computed(
  () => (props.scan?.roots ?? []).filter((root) => root.deferred),
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

const pendingTitle = computed(() =>
  selectedAllDead.value ? "确认清理" : "确认释放",
);

function formatTime(seconds: number): string {
  if (!seconds) return "尚未完成";
  return new Date(seconds * 1000).toLocaleTimeString("zh-CN", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
  });
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

/**
 * 自动勾选全部见证缺失（DEAD）锚点。
 *
 * DEAD 由 TPM 见证确定，与文件扫描证据无关；扫描不完整也不会改变该
 * 判定。ACTIVE/TAMPERED/UNKNOWN 不自动勾选，避免默认动作波及不确定状态。
 */
function autoSelectDead(anchors: AnchorInfo[]): string[] {
  return anchors
    .filter((anchor) => anchor.witness === "dead")
    .map((anchor) => anchor.uuid);
}

/**
 * 扫描完成后的默认勾选：始终包含全部 DEAD；仅当扫描完整时追加
 * 「见证有效且未在扫描范围内找到」的锚点。缓存、部分、截断或读取
 * 错误时只勾 DEAD，避免把未覆盖位置误判为不存在。
 */
function autoSelectAfterScan(
  scan: AnchorScanResult | null,
  anchors: AnchorInfo[],
): string[] {
  const selected = autoSelectDead(anchors);
  if (
    !scan ||
    scan.cached ||
    scan.partial ||
    scan.truncated ||
    scan.permission_errors > 0 ||
    scan.other_errors > 0
  ) {
    return selected;
  }
  const found = new Set(
    scan.entries
      .filter((entry) => entry.paths.length > 0)
      .map((entry) => entry.uuid.toLowerCase()),
  );
  const picked = new Set(selected);
  for (const anchor of anchors) {
    if (anchor.witness !== "active") continue;
    if (found.has(anchor.uuid.toLowerCase())) continue;
    if (picked.has(anchor.uuid)) continue;
    picked.add(anchor.uuid);
    selected.push(anchor.uuid);
  }
  return selected;
}

watch(
  () => props.show,
  (visible) => {
    if (visible) {
      selected.value = autoSelectDead(props.anchors);
    } else {
      selected.value = [];
      pending.value = false;
    }
  },
  { immediate: true },
);

/* 释放/清理刷新后，弹窗可见时把勾选重置为剩余 DEAD；关闭时不改。 */
watch(
  () => props.anchors,
  (anchors) => {
    if (!props.show) return;
    selected.value = autoSelectDead(anchors);
  },
);

/* 扫描结束回到默认勾选：DEAD + 完整扫描下「见证有效且未找到」的锚点；
   不勾 TAMPERED/UNKNOWN，也不在扫描不完整时按缺失推断。 */
watch(
  () => props.scanning,
  (scanning, wasScanning) => {
    if (wasScanning && !scanning && props.show) {
      selected.value = autoSelectAfterScan(props.scan, props.anchors);
    }
  },
);

function witnessLabel(witness: string): string {
  switch (witness) {
    case "active":
      return "见证有效";
    case "dead":
      return "见证缺失";
    case "tampered":
      return "见证异常";
    default:
      return "见证未知";
  }
}

function toggle(uuid: string) {
  if (props.busy || props.scanning) return;
  selected.value = selected.value.includes(uuid)
    ? selected.value.filter((item) => item !== uuid)
    : [...selected.value, uuid];
}

function requestRelease() {
  if (selectedCount.value === 0) return;
  pending.value = true;
}

function confirmPending() {
  if (pending.value) emit("release", [...selected.value]);
  pending.value = false;
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
.anchor-scan-updated {
  font-size: 10px;
  letter-spacing: 0.08em;
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
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
/* 扫描摘要：标签与数值紧邻成组，按内容宽度排列，不做等分留白 */
.anchor-scan-metrics {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 4px 18px;
}
.anchor-metric {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}
.anchor-metric-label {
  flex: none;
  font-size: 10px;
  line-height: 1.2;
  letter-spacing: 0.08em;
  color: var(--text-muted);
}
.anchor-metric-value {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 10px;
  line-height: 1.2;
  font-weight: 500;
  font-variant-numeric: tabular-nums;
  color: var(--text-secondary);
}
.anchor-scan-partial {
  margin-top: 10px;
}
.anchor-scan-empty {
  margin-top: 2px;
}
/* 覆盖范围：一行一个位置，来源固定列宽，路径与状态紧邻；列表限高滚动 */
.anchor-coverage {
  display: flex;
  flex-direction: column;
  gap: 1px;
  margin: 8px 0 0;
  padding: 0;
  list-style: none;
  max-height: 132px;
  overflow-y: auto;
  overscroll-behavior: contain;
  scrollbar-width: none;
}
.anchor-coverage::-webkit-scrollbar {
  display: none;
}
.anchor-coverage-row {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  min-height: 22px;
  font-family: var(--font);
  font-size: 10.5px;
  line-height: 1.5;
  color: var(--text-secondary);
}
.anchor-coverage-source {
  flex: none;
  min-width: 32px;
  font-size: 9.5px;
  letter-spacing: 0.04em;
  color: var(--text-muted);
}
.anchor-coverage-path {
  flex: 0 1 auto;
  min-width: 0;
  max-width: 64%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.anchor-coverage-state {
  flex: none;
  font-size: 10px;
}
.anchor-coverage-state.is-alert {
  color: var(--danger);
}
.anchor-coverage-state.is-ok {
  color: var(--text-muted);
}
.anchor-root-remove {
  flex: none;
  margin-left: 2px;
}
.anchor-scan-hint {
  margin-top: 10px;
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
  /* 表格保持 separate：sticky 表头与单元格边框不合并，滚动时不抖动 */
  border-collapse: separate;
  border-spacing: 0;
  font-family: var(--font);
  font-size: 12px;
}
/* 表头：无托板、无光缝，只保留薄线与圆角；透明材质负责压住滚动内容 */
.anchor-table th {
  position: sticky;
  top: 0;
  z-index: 1;
  padding: 9px 8px 8px;
  background: rgba(7, 11, 18, 0.55);
  -webkit-backdrop-filter: blur(14px) saturate(140%);
  backdrop-filter: blur(14px) saturate(140%);
  box-shadow: none;
  border-bottom: 1px solid rgba(205, 224, 244, 0.10);
  text-align: left;
  font-weight: 500;
  font-size: 10px;
  letter-spacing: 0.16em;
  color: rgba(212, 226, 241, 0.92);
  text-shadow: none;
}
/* 无背衬折射能力时加深底色，保证表头文字可读 */
@supports not ((-webkit-backdrop-filter: blur(2px)) or (backdrop-filter: blur(2px))) {
  .anchor-table th {
    background: rgba(7, 11, 18, 0.92);
  }
}
.anchor-table th:first-child {
  border-radius: 6px 0 0 6px;
}
.anchor-table th:last-child {
  border-radius: 0 6px 6px 0;
}
.anchor-table tbody tr:first-child td {
  border-top: 0;
}
/* 列名与尾线：线从标签右侧起、向右渐隐；单元格之间留出自然断口，
   读作一排分区标题，而不是一根贯穿表头的横杠。 */
.anchor-th-label {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  /* 列名是不中断的单一词条：窄列下换行会把「元数据版本」拆成两行，
     列宽由 wrap 容器的横向滚动兜底，不靠折行压缩表头 */
  white-space: nowrap;
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
.anchor-path--capped {
  color: var(--text-muted);
}
.anchor-dead-ids {
  display: flex;
  flex-wrap: wrap;
  gap: 3px 10px;
  word-break: break-all;
}
.anchor-dead-id {
  font-family: var(--font);
  color: var(--text-secondary);
}
.anchor-dead-more {
  color: var(--text-muted);
}
.anchor-empty {
  padding: 18px 0;
  text-align: center;
  font-size: 12px;
  color: var(--text-muted);
}
</style>
