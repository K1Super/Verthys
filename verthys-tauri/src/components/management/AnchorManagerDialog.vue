<!--
  AnchorManagerDialog.vue — 回退锚点管理弹窗

  职责：
    1. 展示全部锚点与见证状态（ACTIVE/DEAD/TAMPERED/UNKNOWN）
    2. 展示宿主扫描到的 UUID → 路径证据；扫描结果只作为证据，不自动删除
    3. 通过二次确认触发“释放选中”或“回收失效”
    4. 明确告知：释放 ACTIVE/TAMPERED 后，仍存在的容器必须用恢复码重建锚点

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
          :disabled="busy"
          @click="pickRoots"
        >
          扫描容器
        </button>
        <button
          class="btn btn-neutral btn-compact"
          type="button"
          :disabled="busy || !scan"
          @click="selectNotFound"
        >
          勾选缺失
        </button>
        <button
          class="btn btn-destructive btn-compact"
          type="button"
          :disabled="busy || deadCount === 0"
          @click="pending = 'reclaim'"
        >
          回收失效
        </button>
      </div>
      <p class="kv-hint">
        仅 DEAD 可回收，即见证确定不存在的锚点；ACTIVE、TAMPERED、UNKNOWN 永不自动删除。
      </p>

      <Transition name="anchor-reveal">
        <div v-if="scan" class="anchor-reveal">
          <div class="anchor-reveal-body">
            <section class="kv-section">
              <div class="kv-section-label">扫描证据</div>
              <div class="kv-readout">
                文件 {{ scan.files_seen }} · 命中 {{ scan.matched_count }} · 权限错误
                {{ scan.permission_errors }}{{ scan.truncated ? " · 结果已截断" : "" }}
              </div>
              <p class="kv-hint">
                扫描结果只是证据，不作为自动删除依据；未覆盖目录中的容器可能被显示为“未在扫描范围内找到”。
              </p>
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
              :aria-label="pending === 'release' ? '确认释放' : '确认回收'"
              aria-live="assertive"
            >
              <div class="kv-section-label">{{ pending === "release" ? "确认释放" : "确认回收" }}</div>
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
              <p v-else class="kv-warn">
                将回收 {{ deadCount }} 个 DEAD 锚点。ACTIVE/TAMPERED/UNKNOWN 不会被删除，仍在使用中的容器不受影响。
              </p>
              <div class="kv-actions">
                <button
                  class="btn btn-neutral btn-compact"
                  type="button"
                  :disabled="busy"
                  @click="pending = null"
                >
                  取消
                </button>
                <button
                  class="btn btn-destructive btn-compact"
                  type="button"
                  :disabled="busy"
                  @click="confirmPending"
                >
                  确认
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
                      :disabled="busy"
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
                    <template v-if="scanMap.get(a.uuid)?.length">
                      <span v-for="p in scanMap.get(a.uuid)" :key="p" class="anchor-path">{{ p }}</span>
                    </template>
                    <span v-else class="anchor-path anchor-path--missing">
                      {{ scan ? "未在扫描范围内找到" : "尚未扫描" }}
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
          :disabled="busy || selectedCount === 0"
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
import type { AnchorInfo, AnchorScanResult } from "../../types/verthys";

const props = defineProps<{
  show: boolean;
  anchors: AnchorInfo[];
  state: number;
  scan: AnchorScanResult | null;
  busy: boolean;
  error: string;
  notice: string;
}>();

const emit = defineEmits<{
  (e: "close"): void;
  (e: "refresh"): void;
  (e: "scan", roots: string[]): void;
  (e: "reclaim"): void;
  (e: "release", uuids: string[]): void;
}>();

const selected = ref<string[]>([]);
const pending = ref<"release" | "reclaim" | null>(null);

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
    map.set(entry.uuid, entry.paths);
  }
  return map;
});

const unregistered = computed(() => {
  const known = new Set(props.anchors.map((a) => a.uuid));
  return (props.scan?.entries ?? []).filter((e) => !known.has(e.uuid));
});

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
  if (props.busy) return;
  selected.value = selected.value.includes(uuid)
    ? selected.value.filter((item) => item !== uuid)
    : [...selected.value, uuid];
}

/**
 * 按扫描证据勾选“未在扫描范围内找到”的锚点。
 *
 * 只改变勾选，不执行释放；用户仍需阅读确认文案并二次确认。扫描结果可能
 * 不覆盖离线磁盘/网络盘，确认文案会明确提示这一限制。
 */
function selectNotFound() {
  if (!props.scan || props.busy) return;
  const found = new Set(
    props.scan.entries
      .filter((entry) => entry.paths.length > 0)
      .map((entry) => entry.uuid),
  );
  selected.value = props.anchors
    .filter((anchor) => !found.has(anchor.uuid))
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
  }
  pending.value = null;
}

function close() {
  if (props.busy) return;
  emit("close");
}

async function pickRoots() {
  if (props.busy) return;
  try {
    const picked = await open({
      directory: true,
      multiple: true,
      title: "选择容器所在目录",
    });
    if (!picked) return;
    const roots = Array.isArray(picked) ? picked : [picked];
    if (roots.length > 0) emit("scan", roots);
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
  max-height: 320px;
  overflow: auto;
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
