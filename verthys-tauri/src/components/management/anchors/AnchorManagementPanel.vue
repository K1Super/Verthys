<!--
  AnchorManagementPanel.vue — 安全防护 · 回退锚点面板

  位置：嵌入 SecurityDashboard，位于“动态防护”之后、“数据流转轨道”之前。
  职责：
    1. 展示本机锚点占用与生命周期摘要（ACTIVE/DEAD/TAMPERED/UNKNOWN）
    2. 提供刷新、扫描与清理/释放入口；打开管理弹窗时自动执行全量扫描，
       清理/释放必须进入 AnchorManagerDialog 完成证据核对与二次确认
    3. 容量/状态异常时给出可行动提示，不把容量问题伪装成文件回退

  安全边界：
    - 面板不自动删除任何锚点；见证缺失（DEAD）之外的锚点只能由用户在弹窗中显式勾选释放
    - 见证状态只反映 TPM 见证，不代表容器文件仍然存在
    - 不展示指纹、私钥或任何密钥材料
-->
<template>
  <div class="def-board">
    <div class="def-head anchor-head">
      <span class="cap-glyph" aria-hidden="true"></span>
      <span class="def-title">回退锚点</span>
      <div class="cus-actions">
        <SfActionNode
          label="刷新回退锚点"
          :disabled="opBusy"
          :busy="opBusy"
          @click="refresh"
        >
          <svg
            class="sf-act-icon"
            :class="{ 'is-spinning-once': opBusy }"
            aria-hidden="true"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
          ><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>
        </SfActionNode>
        <SfActionNode
          label="扫描"
          tip="打开回退锚点管理"
          :disabled="opBusy"
          @click="dialogOpen = true"
        >
          <svg
            class="sf-act-icon"
            aria-hidden="true"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
          ><circle cx="11" cy="11" r="6.2"/><path d="M20 20l-4.4-4.4"/></svg>
        </SfActionNode>
      </div>
      <span class="def-count" :class="countClass">{{ anchors.length }}/64</span>
    </div>

    <ul v-if="preview.length" class="def-ledger">
      <li
        v-for="anchor in preview"
        :key="anchor.uuid"
        class="def-item"
        :class="`def-item--${stateClass(anchor.witness)}`"
      >
        <span class="def-dot" aria-hidden="true"></span>
        <span class="def-name" v-tip="anchor.uuid">{{ shortUuid(anchor.uuid) }}</span>
        <span class="def-tag">{{ witnessLabel(anchor.witness) }} · g{{ anchor.generation }}</span>
        <span class="def-lead" aria-hidden="true"></span>
      </li>
    </ul>
    <p v-else class="anchor-empty">
      <span class="anchor-empty-dot" aria-hidden="true"></span>
      <span>{{ emptyText }}</span>
      <span class="anchor-empty-lead" aria-hidden="true"></span>
    </p>

    <p v-if="!dialogOpen && error" class="anchor-inline anchor-inline--danger">
      <span class="anchor-inline-mark" aria-hidden="true"></span>
      <span>{{ error }}</span>
    </p>

    <!-- 生命周期摘要：与动态防护总体态势行同款，右下对齐 -->
    <div class="def-stance">
      <span class="def-stance-detail">见证缺失 {{ deadCount }} · 见证异常 {{ tamperedCount }} · {{ stateLabel }}</span>
    </div>

    <AnchorManagerDialog
      :show="dialogOpen"
      :anchors="anchors"
      :state="state"
      :scan="scan"
      :busy="opBusy"
      :scanning="scanBusy"
      :scan-progress="scanProgress"
      :error="error"
      @close="dialogOpen = false"
      @refresh="refresh"
      @scan="handleScan"
      @cancel-scan="handleCancelScan"
      @forget-root="handleForgetRoot"
      @release="handleRelease"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import AnchorManagerDialog from "./AnchorManagerDialog.vue";
import SfActionNode from "../security/SfActionNode.vue";
import { useToastCenter } from "../../../composables/ui/useToastCenter";
import {
  verthysRollbackAnchorForgetRoot,
  verthysRollbackAnchorList,
  verthysRollbackAnchorReleaseBatch,
  verthysRollbackAnchorScan,
  verthysRollbackAnchorScanCancel,
  type AnchorScanOptions,
} from "../../../lib/verthys";
import type {
  AnchorInfo,
  AnchorScanProgress,
  AnchorScanResult,
} from "../../../types/verthys";

const anchors = ref<AnchorInfo[]>([]);
const state = ref(1);
const scan = ref<AnchorScanResult | null>(null);
const opBusy = ref(false);
const scanBusy = ref(false);
const scanProgress = ref<AnchorScanProgress | null>(null);
const error = ref("");
const dialogOpen = ref(false);
/** 成功/清理结果统一走全局状态 toast，不占用面板或弹窗正文。 */
const { showStatus } = useToastCenter();
/** 扫描请求序号：关闭/重开弹窗后丢弃过期响应 */
let scanSeq = 0;

/** 刷新最短 busy 窗口：与一次性旋转时长对齐，避免请求瞬间返回时
    刷新图标只转几度就复位、相邻按钮的禁用态一闪而过。 */
const MIN_BUSY_MS = 460;

const deadCount = computed(
  () => anchors.value.filter((a) => a.witness === "dead").length,
);
const tamperedCount = computed(
  () => anchors.value.filter((a) => a.witness === "tampered").length,
);
const preview = computed(() => anchors.value.slice(0, 8));

const stateLabel = computed(() => {
  if (state.value === 0) return "状态文件缺失";
  if (state.value === 2) return "状态文件损坏";
  return "状态已加载";
});

const countClass = computed(() => {
  if (state.value !== 1) return "def-count--breach";
  if (deadCount.value > 0 || tamperedCount.value > 0) return "def-count--degraded";
  return "";
});

const emptyText = computed(() => {
  if (state.value === 0) return "状态文件不存在：首次运行或文件被删除";
  if (state.value === 2) return "状态文件损坏，维护接口已 fail-closed";
  return "暂无锚点";
});

/** 短 UUID 只保留定长前缀并追加省略号：全行等长，端子排名字列与状态标签起点对齐 */
const SHORT_UUID_LEN = 8;

function shortUuid(uuid: string): string {
  return `${uuid.slice(0, SHORT_UUID_LEN)}...`;
}

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

function stateClass(witness: string): string {
  switch (witness) {
    case "active":
      return "blocked";
    case "dead":
      return "degraded";
    case "tampered":
      return "failed";
    default:
      return "unchecked";
  }
}

/** 维护接口可行动错误码 → 用户可读文案（不暴露内部路径/堆栈）。 */
function anchorErrorText(raw: string): string {
  const match = raw.match(/ERR_[0-9A-F]{8}/);
  const code = match ? match[0] : raw;
  switch (code) {
    case "ERR_00000008":
      return "回退状态文件读写失败，请检查状态目录权限";
    case "ERR_00000009":
      return "回退状态文件损坏或无法认证，维护接口已 fail-closed";
    case "ERR_00000016":
      return "当前调用方未通过发布者签名校验";
    case "ERR_00000018":
      return "设备安全模块不可用，请稍后重试";
    case "ERR_00000021":
      return "回退锚点表已满，请先清理见证缺失锚点或释放废弃条目";
    case "ERR_00000001":
      return "参数非法或缺少显式确认";
    default:
      return raw;
  }
}

async function refresh() {
  if (opBusy.value) return;
  opBusy.value = true;
  error.value = "";
  const startedAt = performance.now();
  try {
    const result = await verthysRollbackAnchorList();
    anchors.value = result.anchors;
    state.value = result.state;
  } catch (e) {
    error.value = anchorErrorText(e instanceof Error ? e.message : String(e));
  } finally {
    const remaining = MIN_BUSY_MS - (performance.now() - startedAt);
    if (remaining > 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, remaining));
    }
    opBusy.value = false;
  }
}

/**
 * 扫描全部本地容器位置。
 *
 * 只由“扫描”按钮显式触发；打开管理弹窗时仅读取持久化证据，不遍历磁盘。
 * 扫描与刷新/释放互不阻塞：扫描只读容器头，不占用 worker。
 */
async function handleScan(options: AnchorScanOptions = {}) {
  if (scanBusy.value) return;
  scanBusy.value = true;
  error.value = "";
  const seq = ++scanSeq;
  scanProgress.value = null;
  try {
    const result = await verthysRollbackAnchorScan(options, (progress) => {
      if (seq === scanSeq) scanProgress.value = progress;
    });
    if (seq === scanSeq) scan.value = result;
  } catch (e) {
    if (seq === scanSeq) {
      error.value = anchorErrorText(e instanceof Error ? e.message : String(e));
    }
  } finally {
    if (seq === scanSeq) {
      scanBusy.value = false;
      scanProgress.value = null;
    }
  }
}

async function handleCancelScan() {
  try {
    await verthysRollbackAnchorScanCancel();
  } catch (e) {
    error.value = anchorErrorText(e instanceof Error ? e.message : String(e));
  }
}

async function handleForgetRoot(path: string) {
  if (opBusy.value || scanBusy.value) return;
  opBusy.value = true;
  error.value = "";
  try {
    scan.value = await verthysRollbackAnchorForgetRoot(path);
  } catch (e) {
    error.value = anchorErrorText(e instanceof Error ? e.message : String(e));
  } finally {
    opBusy.value = false;
  }
}

/**
 * 打开管理弹窗时只读取上次持久化的扫描证据，绝不触发磁盘遍历。
 * 真实扫描只由弹窗内的“扫描”按钮触发。
 */
async function loadPersistedEvidence() {
  if (scanBusy.value) return;
  const seq = ++scanSeq;
  error.value = "";
  try {
    const result = await verthysRollbackAnchorScan({ peek: true });
    if (seq === scanSeq) scan.value = result;
  } catch (e) {
    if (seq === scanSeq) {
      error.value = anchorErrorText(e instanceof Error ? e.message : String(e));
    }
  }
}

watch(dialogOpen, (visible) => {
  if (visible) void loadPersistedEvidence();
});

/**
 * 批量释放/清理选中锚点：无论选中多少条都只发起一次 IPC。
 *
 * 选中集合全为 DEAD 时语义是“清理”（温和文案）；包含任何非 DEAD 时
 * 语义是“释放”，确认区已给出恢复码警告。后端一次状态锁完成全部条目。
 */
async function handleRelease(uuids: string[]) {
  if (uuids.length === 0) return;
  opBusy.value = true;
  error.value = "";
  let failure = "";
  const dead = new Set(
    anchors.value.filter((anchor) => anchor.witness === "dead").map((anchor) => anchor.uuid),
  );
  const allDead = uuids.every((uuid) => dead.has(uuid));
  try {
    const result = await verthysRollbackAnchorReleaseBatch(uuids, true);
    if (result.ok) {
      const action = allDead ? "清理" : "释放";
      showStatus(
        `${action}完成：${result.released ?? 0} 条${
          (result.cleanupFailed ?? 0) > 0
            ? `；见证清理失败 ${result.cleanupFailed} 条（残留键不影响其它锚点）`
            : ""
        }`,
      );
    } else {
      failure = anchorErrorText(result.error ?? "释放失败");
    }
  } catch (e) {
    failure = anchorErrorText(e instanceof Error ? e.message : String(e));
  } finally {
    opBusy.value = false;
    await refresh();
    if (failure) error.value = failure;
  }
}

onMounted(refresh);
</script>

<style scoped>
/* 头部与其余面板同构：动作节点靠右、计数随后，28px 动作键主导行高 */
.anchor-head {
  align-items: center;
}
.anchor-head .def-count {
  margin-left: 14px;
  font-family: var(--font);
}
/* 短 UUID 定长 8 位前缀 + 省略号：列宽锁死，十六进制字形宽窄不一
   也不会让后续状态标签逐行错位 */
.def-name {
  width: calc(8ch + 2.4em);
  white-space: nowrap;
}
/* 端子排第二列整列下沉 13px：满 8 项时末枚会伸进摘要行上方间距，
   补同量下内边距，把上下留白还原为参考态势行的 13px / 2px 节奏 */
.def-ledger:has(.def-item:nth-child(8)) {
  padding-bottom: 13px;
}
/* 空账本沿用端子排语言：虚线四边形 + 说明 + 虚线引出 */
.anchor-empty {
  display: flex;
  align-items: center;
  gap: 9px;
  margin: 0;
  padding: 2px 0;
  font-family: var(--font);
  font-size: 10px;
  line-height: 1.5;
  letter-spacing: 0.04em;
  color: var(--text-muted);
}
.anchor-empty-dot {
  width: 5px;
  height: 5px;
  flex: none;
  border: 1px dashed rgba(148, 160, 178, 0.4);
  transform: rotate(45deg);
}
.anchor-empty-lead {
  flex: 1;
  height: 1px;
  background: repeating-linear-gradient(90deg,
    rgba(148, 160, 178, 0.2) 0 3px,
    transparent 3px 9px);
}
/* 维护反馈：危险红 / 成功青，四边形标记与端子排同族 */
.anchor-inline {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin: 0;
  padding: 0 4px;
  font-family: var(--font);
  font-size: 9.5px;
  line-height: 1.6;
  letter-spacing: 0.06em;
}
.anchor-inline-mark {
  width: 5px;
  height: 5px;
  flex: none;
  margin-top: 4px;
  border: 1px solid currentColor;
  transform: rotate(45deg);
}
.anchor-inline--danger {
  color: var(--danger);
}
.anchor-inline--ok {
  color: rgba(0, 212, 255, 0.85);
}
</style>
