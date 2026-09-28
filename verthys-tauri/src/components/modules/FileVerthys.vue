<!--
  FileVerthys.vue — 加密文件加密库模块（清藏）
  功能：
    - 支持 PDF / Word / Excel / 压缩包等任意格式文档加密入库
    - 大文件分块加密存储（分块口径取跨层预算常量），块经导入会话单写者落库
    - 可保存到本地（加密文档需输入独立密码解密后导出）
    - 可单独给文档设置独立访问密码，实现细粒度权限隔离
  导入语义：文件级去重跳过（同内容同形态命中即跳过）；中断后重传经会话日志
    续传，块级重传不保证幂等（加密形态每块随机盐使密文互异）。
  删除语义：块引用与元数据合并为单次批量事务删除；删除提交后立即落盘、
    释放文件级去重键并触发孤儿回收；任一子步骤失败保留条目并给出
    重试入口（删除失败直接重试；落盘失败仅重放落盘与收尾）。
  记录类型：0x08 元数据，0x04 数据块
-->
<template>
  <div class="file-verthys">
    <!-- 瞬时提示（错误/状态）统一由全局 ToastLayer 渲染（App 根节点单点挂载，--z-toast 最高层） -->

    <!-- 顶部栏：星野导航带（半透明无框；星野底板与溶解边界由 StarlitSky 承担） -->
    <div class="search-bar starlit-bar">
      <StarlitSky :seed="7" />
      <div class="search-inner">
        <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        </svg>
        <!-- 项3：搜索输入防抖（300ms 尾部触发），连续快速输入仅触发一次过滤 -->
        <input class="search-input" :value="searchKey" @input="onSearchInput" placeholder="搜索文件…" />
      </div>
      <ActionButton
        :label="importing ? '导入中…' : '导入文件'"
        :loading="importing"
        @click="onImport"
      />
    </div>

    <!-- 文件卡片网格：≥150 条启用虚拟滚动（项1），小列表保留原 v-for 路径零开销 -->
    <VirtualCardGrid
      v-if="filteredFiles.length >= 150"
      :items="filteredFiles"
      :item-height="120"
      :min-column-width="300"
      v-slot="{ item: f, index }"
    >
      <div
        class="acct-card glass"
        :style="{ '--i': index }"
        @mousemove="onCardMove($event)"
        @mouseleave="onCardLeave($event)"
      >
        <div class="card-accent"></div>
        <div class="card-head">
          <span class="file-icon-wrap" v-html="getFileIcon(f.mime)"></span>
          <span class="platform" v-tip="f.name">{{ f.name }}</span>
          <span v-if="f.encrypted" class="lock-badge" v-tip="'独立加密'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </span>
        </div>
        <div class="file-info">
          <span class="info-item"><span class="info-label">大小</span> {{ formatSize(f.size) }}</span>
          <span class="info-item"><span class="info-label">类型</span> {{ getFileType(f.mime) }}</span>
          <span class="info-item"><span class="info-label">分块</span> {{ f.totalChunks }} 块</span>
        </div>
        <div class="card-actions">
          <button
            class="mini-btn"
            :disabled="deleteStateOf(f) !== undefined"
            @click="onSave(f)"
          >保存</button>
          <button
            class="mini-btn danger"
            :disabled="deleteStateOf(f) === 'deleting'"
            v-tip="deleteStateOf(f) === 'persist-retry' ? '删除已提交但落盘失败，点击重试完成落盘' : ''"
            @click="onDelete(f)"
          >{{ deleteStateOf(f) === 'deleting' ? '删除中…' : deleteStateOf(f) === 'persist-retry' ? '重试' : '删除' }}</button>
        </div>
        <div class="card-shine"></div>
      </div>
    </VirtualCardGrid>
    <div v-else class="card-grid">
      <div
        v-for="(f, idx) in filteredFiles"
        :key="f.id"
        class="acct-card glass"
        :style="{ '--i': idx }"
        @mousemove="onCardMove($event)"
        @mouseleave="onCardLeave($event)"
      >
        <div class="card-accent"></div>
        <div class="card-head">
          <span class="file-icon-wrap" v-html="getFileIcon(f.mime)"></span>
          <span class="platform" v-tip="f.name">{{ f.name }}</span>
          <span v-if="f.encrypted" class="lock-badge" v-tip="'独立加密'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </span>
        </div>
        <div class="file-info">
          <span class="info-item"><span class="info-label">大小</span> {{ formatSize(f.size) }}</span>
          <span class="info-item"><span class="info-label">类型</span> {{ getFileType(f.mime) }}</span>
          <span class="info-item"><span class="info-label">分块</span> {{ f.totalChunks }} 块</span>
        </div>
        <div class="card-actions">
          <button
            class="mini-btn"
            :disabled="deleteStateOf(f) !== undefined"
            @click="onSave(f)"
          >保存</button>
          <button
            class="mini-btn danger"
            :disabled="deleteStateOf(f) === 'deleting'"
            v-tip="deleteStateOf(f) === 'persist-retry' ? '删除已提交但落盘失败，点击重试完成落盘' : ''"
            @click="onDelete(f)"
          >{{ deleteStateOf(f) === 'deleting' ? '删除中…' : deleteStateOf(f) === 'persist-retry' ? '重试' : '删除' }}</button>
        </div>
        <div class="card-shine"></div>
      </div>

      <CosmicEmpty v-if="!loading && filteredFiles.length === 0" text="暂无加密文件" hint="点击「导入文件」添加" />
    </div>

    <!-- 导入对话框（含独立密码选项） -->
    <div v-if="showImportDialog" class="dialog-overlay" @click.self="showImportDialog = false">
      <div class="dialog glass">
        <div class="dialog-title">导入文件到加密库</div>
        <div class="import-file-info">
          <span class="file-icon-lg" v-html="getFileIcon(pendingMime)"></span>
          <div class="file-meta">
            <div class="file-name">{{ pendingName }}</div>
            <template v-if="pendingFiles.length === 1">
              <div class="file-size">{{ formatSize(pendingSize) }}</div>
              <div class="file-chunks">将分块加密存储（大小在导入时读取）</div>
            </template>
            <template v-else>
              <div class="file-size">共 {{ pendingFiles.length }} 个文件</div>
              <div class="file-chunks">将逐个加密导入</div>
            </template>
          </div>
        </div>
        <div class="encrypt-row" :class="{ on: usePassword }">
          <label class="encrypt-toggle">
            <input type="checkbox" v-model="usePassword" />
            <span class="encrypt-check"></span>
            <span class="encrypt-label">设置独立访问密码（细粒度权限隔离）</span>
          </label>
          <div v-if="usePassword" class="encrypt-key-input">
            <input
              class="input"
              v-model="docPassword"
              type="password"
              placeholder="文档独立访问密码"
            />
          </div>
        </div>
        <div class="dialog-actions">
          <button class="btn kv-cancel" @click="showImportDialog = false">取消</button>
          <button class="btn btn-primary kv-confirm" :disabled="usePassword && !docPassword" @click="startImport">开始加密导入</button>
        </div>
      </div>
    </div>

    <!-- 保存密钥输入框（加密文档保存到本地前需解密） -->
    <div v-if="showKeyDialog" class="dialog-overlay" @click.self="showKeyDialog = false">
      <div class="dialog glass key-dialog">
        <div class="dialog-title">输入文档访问密码</div>
        <div class="key-target">{{ saveTarget?.name }}</div>
        <input
          class="input"
          v-model="keyInput"
          type="password"
          placeholder="独立访问密码"
          @keydown.enter="confirmSaveKey"
          autofocus
        />
        <div class="dialog-actions">
          <button class="btn kv-cancel" @click="showKeyDialog = false">取消</button>
          <button class="btn btn-primary kv-confirm" :disabled="!keyInput" @click="confirmSaveKey">解密保存</button>
        </div>
      </div>
    </div>

    <!-- 非阻塞加载：无底板居中展示，加载完成自动消失 -->
    <CosmicLoading :show="loading" text="正在加载文件数据…" />

    <!-- 删除二次确认弹窗 -->
    <ConfirmDelete
      :show="showDeleteConfirm"
      :item-name="deleteTargetName"
      @confirm="confirmDelete"
      @cancel="showDeleteConfirm = false"
    />

    <!-- 导入进度悬浮覆盖层（统一组件，复用量子能量导流通道）：
         悬浮模块内容区中央，不挤压下方文件网格；导入中可取消（断点状态保留） -->
    <ImportProgressOverlay
      :visible="importing"
      :percent="importPercent"
      :message="importingFile"
      :detail="`${importDone} / ${importTotal} 块 · ${importPercent}%`"
      :show-meta="false"
      :cancelable="!cancelPending"
      cancel-label="取消导入"
      @cancel="requestImportCancel"
    />

    <!-- 并发导入互斥：存在活跃导入会话时的显式确认（结束上一会话保留其断点状态） -->
    <div v-if="showSessionConflict" class="dialog-overlay" @click.self="resolveSessionConflict(false)">
      <div class="dialog glass">
        <div class="dialog-title">已有导入会话进行中</div>
        <div class="session-conflict-text">
          检测到未结束的导入会话（可能是上次导入中断或另一模块正在导入）。
          继续将先结束该会话并保留其断点状态，之后可续传。
        </div>
        <div class="dialog-actions">
          <button class="btn kv-cancel" @click="resolveSessionConflict(false)">取消导入</button>
          <button class="btn btn-primary kv-confirm" @click="resolveSessionConflict(true)">结束并继续</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, shallowRef, computed, onMounted, onUnmounted } from "vue";
import { open, save } from "@tauri-apps/plugin-dialog";
import ActionButton from "../common/verthys-ui/ActionButton.vue";
import StarlitSky from "../common/cosmic/StarlitSky.vue";
import CosmicLoading from "../common/cosmic/CosmicLoading.vue";
import CosmicEmpty from "../common/cosmic/CosmicEmpty.vue";
import ImportProgressOverlay from "../common/cosmic/ImportProgressOverlay.vue";
import ConfirmDelete from "../common/verthys-ui/ConfirmDelete.vue";
import { useCardShine } from "../../composables/useCardShine";
import {
  verthysGetRecord, verthysForgetHashes,
  verthysWalRecover, verthysImportBegin, verthysImportEnd, verthysForceCloseImportSession,
  verthysAddChunkBatch, verthysAddRecordsBatch, verthysGcOrphanChunks,
  userFileStat, readUserFileChunked, checkDiskSpace, base64ToBytes,
  decryptPasswordField,
  writeUserFileStream, appendUserFileChunk, finalizeUserFileStream, abortUserFileStream,
} from "../../lib/verthys";
import {
  createFileKeyV2, encryptChunkV2, buildPasswordCheckV2,
  unlockFileKeyV2, verifyPasswordCheckV2, decryptChunkV2,
  type FileKdfV2,
} from "../../lib/crypto";
import { runFileExport } from "../../composables/file-verthys/useFileExport";
import {
  runFileImport,
  type FileImportDeps,
  type ImportProgress,
} from "../../composables/file-verthys/useFileImport";
import {
  runFileDelete,
  retryFileDeletePersist,
  createDedupeReleaseQueue,
  type DeleteSourceEntry,
  type FileDeleteDeps,
  type FileDeleteResult,
} from "../../composables/file-verthys/useFileDelete";
import { persistVerthys, deleteAndPersistBatch, getModuleCache, setModuleCache, invalidateSummaryRecord, invalidateFullRecord, addFullRecord, ensureIndexSourceSafe, getSummaryIdsByType, getRecordIdsByType, invalidateScannedRecord, getRecordsDataB64Batch } from "../../lib/keyManager";
import { TYPE_FILEVERTHYS_META, TYPE_FILEVERTHYS_META_OLD } from "../../constants/record_types";
import { useToastCenter } from "../../composables/useToastCenter";
import {
  pushShallowItems, replaceShallowArray,
  removeShallowItems,
} from "../../utils/shallow-array";
import { debounce } from "../../utils/debounce";
import VirtualCardGrid from "../common/verthys-ui/VirtualCardGrid.vue";

/* ===== 瞬时提示（错误 / 状态）— 全局 Toast 中心；渲染归 ToastLayer ===== */
const { showError, showStatus } = useToastCenter();
/* 状态提示口径（模块内沿用 showToast 命名，指向标准状态通道，2.5s 自动消失） */
const showToast = showStatus;

/* ===== 类型 ===== */
interface FileEntry {
  id: number;
  name: string;
  size: number;
  mime: string;
  totalChunks: number;
  encrypted: boolean;
  metaId?: number;             // 元数据记录 ID
  chunkIds?: number[];         // 外置格式：数据块记录 ID 列表（当前写入形态）
  chunkDataB64?: string[];     // 历史内联格式：meta 记录内嵌的全部块密文
  chunkHashes?: string[];      // 逐块密文哈希（当前写入形态；导出完整性权威值）
  chunkSize?: number;          // 分块口径（meta 声明值；历史记录可能缺省）
  fileHash?: string;           // 文件级去重键（删除时须释放，否则重导被跳过）
  kdf?: FileKdfV2;             // 文件级密钥派生参数（加密条目；导出解锁用）
  passwordCheck?: string;      // 口令校验块（加密条目；导出前置判定用）
}

/* ===== 常量 ===== */
/* 记录类型常量统一取自 constants/record_types.ts（单一权威来源）：
 *   TYPE_FILEVERTHYS_META (0x08) 元数据；TYPE_FILEVERTHYS_CHUNK (0x04) 数据块
 *   （块记录由导入管道按角色类型写入，本组件不直接构造块记录）。 */

/* 非阻塞加载状态（无底板居中展示，加载完成自动消失） */
const loading = ref(false);

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/* ===== 文件列表 ===== */
const searchKey = ref("");
/* 项2：shallowRef 替代 ref，避免 Vue 对 files 数组内每条记录深度代理
 * （每条记录含 metaId/chunks 等字段，万条记录深度代理开销 200-500ms） */
const files = shallowRef<FileEntry[]>([]);

const filteredFiles = computed(() => {
  const k = searchKey.value.trim().toLowerCase();
  return files.value.filter(f => !k || f.name.toLowerCase().includes(k));
});

/* 项3：搜索输入防抖（300ms 尾部触发）
 * 原问题：v-model 每次按键触发 filteredFiles computed 重新计算，
 *        连续快速输入时累加造成可感知延迟。
 * 优化后：用户停止输入 300ms 后才更新 searchKey 触发过滤，输入过程零卡顿。 */
const debouncedUpdateSearch = debounce((v: string) => {
  searchKey.value = v;
}, 300);
const onSearchInput = (e: Event): void => {
  debouncedUpdateSearch((e.target as HTMLInputElement).value);
};

/* ===== 文件类型识别 ===== */
const getMimeFromName = (name: string): string => {
  const ext = name.split(".").pop()?.toLowerCase() || "";
  const map: Record<string, string> = {
    pdf: "application/pdf",
    doc: "application/msword", docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    xls: "application/vnd.ms-excel", xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ppt: "application/vnd.ms-powerpoint", pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    zip: "application/zip", rar: "application/vnd.rar", "7z": "application/x-7z-compressed", gz: "application/gzip", tar: "application/x-tar",
    txt: "text/plain", md: "text/markdown", json: "application/json", xml: "application/xml", csv: "text/csv",
    png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", bmp: "image/bmp", svg: "image/svg+xml",
  };
  return map[ext] || "application/octet-stream";
};

const getFileType = (mime: string): string => {
  if (mime.startsWith("image/")) return "图片";
  if (mime === "application/pdf") return "PDF";
  if (mime.includes("word")) return "Word";
  if (mime.includes("sheet") || mime.includes("excel")) return "Excel";
  if (mime.includes("presentation") || mime.includes("powerpoint")) return "PPT";
  if (mime.includes("zip") || mime.includes("rar") || mime.includes("7z") || mime.includes("tar") || mime.includes("gzip")) return "压缩包";
  if (mime.startsWith("text/")) return "文本";
  return "其他";
};

const getFileIcon = (mime: string): string => {
  if (mime === "application/pdf")
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>`;
  if (mime.startsWith("image/"))
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`;
  if (mime.includes("sheet") || mime.includes("excel"))
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/><line x1="9" y1="3" x2="9" y2="21"/><line x1="15" y1="3" x2="15" y2="21"/></svg>`;
  if (mime.includes("word"))
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`;
  if (mime.includes("zip") || mime.includes("rar") || mime.includes("7z") || mime.includes("tar") || mime.includes("gzip"))
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><path d="M10 12h4"/></svg>`;
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>`;
};

const formatSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
};

/* ===== 导入流程（含分块加密 + 批量导入） ===== */
const showImportDialog = ref(false);
interface PendingFile { path: string; name: string; }
const pendingFiles = ref<PendingFile[]>([]);
// 以下用于对话框显示（单文件时填充详情，多文件时显示汇总）
const pendingPath = ref("");
const pendingName = ref("");
const pendingSize = ref(0);
const pendingMime = ref("application/octet-stream");
const usePassword = ref(false);
const docPassword = ref("");

const onImport = async () => {
  if (!isTauri) {
    // 浏览器模式：模拟导入
    // 项2：shallowRef 下 push 需用 pushShallowItems 触发 triggerRef
    pushShallowItems(files, [{
      id: Date.now(), name: `demo_doc_${files.value.length + 1}.pdf`,
      size: 1024 * 1024 * (2 + files.value.length), mime: "application/pdf",
      totalChunks: 3 + files.value.length, encrypted: false,
    }]);
    syncModuleCache();
    showToast("已添加演示文件");
    return;
  }

  // 批量导入：支持一次选择多个文件
  const selected = await open({
    multiple: true,
    filters: [{ name: "所有文件", extensions: ["*"] }],
  });
  if (!selected) return;
  const paths = Array.isArray(selected) ? selected : [selected];
  if (paths.length === 0) return;

  pendingFiles.value = paths.map(p => ({
    path: p,
    name: p.split(/[\\/]/).pop() || "file",
  }));
  // 填充显示用变量（大小在导入时获取，避免预先读取大文件）
  if (pendingFiles.value.length === 1) {
    const f = pendingFiles.value[0];
    pendingPath.value = f.path;
    pendingName.value = f.name;
    pendingMime.value = getMimeFromName(f.name);
  } else {
    pendingPath.value = "";
    pendingName.value = `${pendingFiles.value.length} 个文件`;
    pendingMime.value = "application/octet-stream";
  }
  pendingSize.value = 0;
  usePassword.value = false;
  docPassword.value = "";
  showImportDialog.value = true;
};

const importing = ref(false);
const importingFile = ref("");
const importDone = ref(0);
const importTotal = ref(0);
const importPercent = ref(0);

/* 取消导入：置位后由管道在每个文件与块批边界检查；已提交文件保留，
   会话按"未成功"语义结束（断点状态保留，下次导入续传去重） */
const importCancelRequested = ref(false);
/* 取消请求已发出但管道尚未收敛：按钮先隐藏，避免重复点击 */
const cancelPending = ref(false);
const requestImportCancel = () => {
  if (!importing.value || importCancelRequested.value) return;
  importCancelRequested.value = true;
  cancelPending.value = true;
};

/* 并发导入互斥确认：存在活跃导入会话时由管道回调唤起，用户抉择驱动后续动作 */
const showSessionConflict = ref(false);
let sessionConflictResolver: ((allow: boolean) => void) | null = null;
const askSessionConflict = (): Promise<boolean> =>
  new Promise((resolve) => {
    sessionConflictResolver = resolve;
    showSessionConflict.value = true;
  });
const resolveSessionConflict = (allow: boolean) => {
  showSessionConflict.value = false;
  const resolve = sessionConflictResolver;
  sessionConflictResolver = null;
  resolve?.(allow);
};

/* 管道进度 → 覆盖层状态（百分比按文件完成比例合并；续传形态的只读校验轮占半权重） */
const applyImportProgress = (p: ImportProgress) => {
  importingFile.value = p.fileCount === 1
    ? p.fileName
    : `${p.fileName}（${p.fileIndex + 1}/${p.fileCount}）`;
  importDone.value = p.doneInFile;
  importTotal.value = p.totalInFile;
  importPercent.value = Math.round(((p.fileIndex + p.fileFraction) / p.fileCount) * 100);
};

/* 导入管道依赖装配：全部经导入会话单写者通道落库 */
const importDeps: FileImportDeps = {
  statFile: userFileStat,
  readChunk: readUserFileChunked,
  v2: {
    createFileKey: createFileKeyV2,
    encryptChunk: encryptChunkV2,
    buildPasswordCheck: buildPasswordCheckV2,
  },
  // 容器卷空间预检：path 缺省 = 当前会话容器所在卷
  freeSpaceBytes: async (path) => (await checkDiskSpace(path ?? undefined)).free_bytes,
  walRecover: verthysWalRecover,
  importBegin: () => verthysImportBegin(),
  importEnd: async (success) => {
    const r = await verthysImportEnd(success);
    return { ok: r.ok, error: r.error };
  },
  forceCloseSession: verthysForceCloseImportSession,
  chunkBatch: verthysAddChunkBatch,
  recordsBatch: (records) => verthysAddRecordsBatch(records),
  gcOrphanChunks: verthysGcOrphanChunks,
  onSessionBusy: askSessionConflict,
  isCancelled: () => importCancelRequested.value,
  onProgress: applyImportProgress,
};

const startImport = async () => {
  // 同步重入闸门（置位于首个 await 之前）：对话框确认键连击或重复触发的
  // 第二次调用在此直接返回，杜绝两轮导入并发建会话互杀与重复入库窗口
  if (importing.value) return;
  if (usePassword.value && !docPassword.value) return;
  if (pendingFiles.value.length === 0) return;
  importing.value = true;
  importCancelRequested.value = false;
  cancelPending.value = false;
  importDone.value = 0;
  importTotal.value = 0;
  importPercent.value = 0;
  try {
    // 上轮删除遗留的去重键释放：建会话前补释放，避免旧键使本轮导入被误跳过
    await dedupeReleaseQueue.flush();
  } catch (e) {
    // 兜底：补释放异常不阻断本轮导入（旧键影响仅体现为显式"跳过"报告）
    console.warn("[FileVerthys] 待重试去重键补释放异常", e);
  }
  showImportDialog.value = false;

  const list = pendingFiles.value.slice();
  const password = usePassword.value ? docPassword.value : null;

  try {
    const result = await runFileImport(
      list.map((f) => ({ path: f.path, name: f.name, mime: getMimeFromName(f.name) })),
      password,
      importDeps,
    );

    // 列表提交：仅 meta 记录已确认（metaId > 0）的条目进入列表与缓存；
    // 失败文件的块留在台账中由孤儿回收处理，不做前端补偿删除
    const newItems: FileEntry[] = result.entries.map((e, idx) => ({
      id: Date.now() + idx,
      name: e.name,
      size: e.size,
      mime: e.mime,
      totalChunks: e.totalChunks,
      encrypted: e.encrypted,
      metaId: e.metaId,
      chunkIds: e.chunkIds,
      chunkHashes: e.chunkHashes,
      chunkSize: e.chunkSize,
      fileHash: e.fileHash,
      kdf: e.kdf,
      passwordCheck: e.passwordCheck,
    }));
    for (const e of result.entries) {
      addFullRecord(e.metaId, TYPE_FILEVERTHYS_META, e.metaName, e.metaB64, e.metaB64.length);
    }
    if (newItems.length > 0) {
      pushShallowItems(files, newItems);
    }
    syncModuleCache();

    // 持久化：与旧行为一致地检查落盘结果，失败必须显式告知
    let persistOk = false;
    try { persistOk = await persistVerthys(); } catch (e) { console.error("[onImport] persistVerthys 异常", e); }
    if (!persistOk) {
      showError("文件已加密导入内存但持久化失败，重启后可能丢失。请勿关闭应用，尝试重新导入或联系支持");
    }

    if (result.error) {
      showError(`导入初始化失败：${result.error}`);
    } else {
      if (result.failCount > 0) {
        const head = result.failures[0];
        const more = result.failCount > 1 ? ` 等 ${result.failCount} 个文件` : "";
        showError(`导入失败：${head.name}｜${head.message}${more}`);
      }
      if (result.cancelled) {
        showToast("已取消导入（断点已保留，下次导入将续传）");
      } else if (result.failCount === 0 && result.successCount > 0) {
        showToast(
          list.length === 1
            ? `已加密导入 ${result.entries[0].name}`
            : `批量导入完成：成功 ${result.successCount} 个${result.skippedCount > 0 ? `，跳过 ${result.skippedCount} 个` : ""}`,
        );
      } else if (result.successCount > 0) {
        showToast(`另有 ${result.successCount} 个文件已导入`);
      } else if (result.skippedCount > 0) {
        showToast(`已跳过 ${result.skippedCount} 个已存在的文件（删除后可重导）`);
      } else if (result.failCount === 0) {
        showToast("没有可导入的文件");
      }
      if (result.sessionWarning) {
        showError(result.sessionWarning);
      }
    }
  } catch (e) {
    console.error("[FileVerthys] 导入失败", e);
    showError("导入失败，请重试");
  } finally {
    importing.value = false;
    importPercent.value = 0;
    importDone.value = 0;
    importTotal.value = 0;
    importCancelRequested.value = false;
    cancelPending.value = false;
    pendingFiles.value = [];
  }
};

/* ===== 保存到本地 ===== */
const showKeyDialog = ref(false);
const keyInput = ref("");
const saveTarget = ref<FileEntry | null>(null);

const onSave = (f: FileEntry) => {
  if (f.encrypted) {
    saveTarget.value = f;
    keyInput.value = "";
    showKeyDialog.value = true;
    return;
  }
  void doSave(f, null);
};

const confirmSaveKey = async () => {
  if (!saveTarget.value || !keyInput.value) return;
  try {
    const saved = await doSave(saveTarget.value, keyInput.value);
    if (saved) {
      showKeyDialog.value = false;
      keyInput.value = "";
    }
  } catch {
    showError("密码错误或数据已损坏");
  }
};

/** 保存到本地：经导出管道逐块校验并流式落盘；返回是否真正写出（取消视为未成功） */
const doSave = async (f: FileEntry, password: string | null): Promise<boolean> => {
  if (!isTauri) {
    showError("浏览器模式不支持保存");
    return false;
  }

  const ext = f.name.split(".").pop() || "";
  const result = await runFileExport(f, password, {
    getRecord: async (id) => {
      const r = await verthysGetRecord(id);
      return r ? { dataB64: r.dataB64 } : null;
    },
    // 当前加密形态：解锁文件密钥并以口令校验块判定（唯一判定点）
    openV2Decryptor: async (entry, pwd) => {
      if (!entry.kdf || !entry.passwordCheck) return null;
      const key = await unlockFileKeyV2(pwd, entry.kdf);
      const ok = await verifyPasswordCheckV2(entry.passwordCheck, key);
      if (!ok) return null;
      return {
        decryptChunk: async (b64: string) => decryptChunkV2(base64ToBytes(b64), key),
      };
    },
    // 历史逐块盐形态：无口令判定点，逐块解密（失败给合并文案）
    decryptField: decryptPasswordField,
    pickSavePath: async (defaultName) => {
      const chosen = await save({
        defaultPath: defaultName,
        filters: ext
          ? [{ name: ext.toUpperCase(), extensions: [ext] }, { name: "所有文件", extensions: ["*"] }]
          : [{ name: "所有文件", extensions: ["*"] }],
      });
      return chosen ?? null;
    },
    streamOpen: writeUserFileStream,
    streamAppend: appendUserFileChunk,
    streamFinalize: finalizeUserFileStream,
    streamAbort: abortUserFileStream,
    // 导出前目标卷空间预检
    freeSpaceBytes: async (path) => (await checkDiskSpace(path)).free_bytes,
  });

  if (result.ok) {
    showToast(`已保存到本地: ${f.name}`);
    return true;
  }
  if (result.code === "CANCELLED") return false;
  showError(result.message);
  return false;
};

/* ===== 删除（单次批量事务 + 失败保留与重试） ===== */
const showDeleteConfirm = ref(false);
const deleteTargetName = ref("");
const deleteTarget = ref<FileEntry | null>(null);

/* 条目删除状态：deleting = 删除中（按钮禁用、等待收口）；
   persist-retry = 落盘失败待重试（删除已提交，仅重放落盘与收尾步骤） */
const deleteStates = ref(new Map<number, "deleting" | "persist-retry">());
const deleteStateOf = (f: FileEntry) => deleteStates.value.get(f.id);

/* 去重键释放待重试队列：删除落盘成功但释放失败时暂存键，
   下次导入开始前自动补释放（避免"删除后重导被静默跳过"残留为永久状态） */
const dedupeReleaseQueue = createDedupeReleaseQueue(verthysForgetHashes);

/* 删除管道依赖装配：批量事务删除 + 立即落盘 + 去重键释放 + 缓存失效 + 孤儿回收 */
const deleteDeps: FileDeleteDeps = {
  deleteRecords: deleteAndPersistBatch,
  persist: persistVerthys,
  forgetHashes: verthysForgetHashes,
  invalidateRecords: (ids) => {
    // 失效两层缓存（摘要 + 全量）+ 旧扫描缓存兼容，杜绝删除复活
    for (const rid of ids) {
      invalidateSummaryRecord(rid);
      invalidateFullRecord(rid);
      invalidateScannedRecord(rid);
    }
  },
  gcOrphanChunks: verthysGcOrphanChunks,
  enqueuePendingRelease: (hash) => dedupeReleaseQueue.enqueue(hash),
};

/** 列表条目 → 删除管道输入 */
const toDeleteSource = (f: FileEntry): DeleteSourceEntry => ({
  id: f.id,
  name: f.name,
  metaId: f.metaId,
  chunkIds: f.chunkIds,
  chunkDataB64: f.chunkDataB64,
  fileHash: f.fileHash,
});

/** 删除收口：移除列表条目 + 同步模块缓存（仅成功路径调用） */
const applyDeleted = (f: FileEntry) => {
  // 项2：shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
  removeShallowItems(files, x => x.id === f.id);
  syncModuleCache();
};

/** 同步模块列表缓存：按"数据层视图"写入——已删除待落盘（persist-retry）
    条目不计入缓存，避免切模块重挂载后以常规卡片复活（此时数据层已无
    该记录：保存必失败、删除因条目缺失被整体拒绝，形成幽灵条目）。 */
const syncModuleCache = () => {
  setModuleCache(
    "fileverthys",
    files.value.filter((x) => deleteStates.value.get(x.id) !== "persist-retry"),
  );
};

/** 删除结果 → 条目状态与提示：成功即移除；失败保留条目并留下重试入口 */
const settleDeleteResult = (f: FileEntry, result: FileDeleteResult) => {
  if (result.ok) {
    deleteStates.value.delete(f.id);
    applyDeleted(f);
    showToast(`已删除 ${f.name}`);
    if (result.warning) showError(result.warning);
    return;
  }
  if (result.code === "E_PERSIST_FAILED") {
    // 删除已提交：条目保留并提供"重试"入口完成落盘；缓存按数据层视图
    // 摘除该条目（重试态仅存在于本组件内存，缓存保留会让切模块重挂载后
    // 出现"看得见却打不开、删不掉"的幽灵条目，直至重启才恢复）
    deleteStates.value.set(f.id, "persist-retry");
    syncModuleCache();
  } else {
    // 删除未发生：恢复常态，删除按钮可直接重试
    deleteStates.value.delete(f.id);
  }
  showError(result.message);
};

const onDelete = (f: FileEntry) => {
  const state = deleteStates.value.get(f.id);
  if (state === "deleting") return;
  if (state === "persist-retry") {
    // 用户已确认过删除：直接重放落盘与收尾，不再二次确认
    void retryPersistDelete(f);
    return;
  }
  deleteTarget.value = f;
  deleteTargetName.value = f.name;
  showDeleteConfirm.value = true;
};

const confirmDelete = async () => {
  const f = deleteTarget.value;
  if (!f || deleteStates.value.has(f.id)) return;
  showDeleteConfirm.value = false;
  deleteTarget.value = null;
  deleteStates.value.set(f.id, "deleting");
  let result: FileDeleteResult;
  try {
    result = await runFileDelete(toDeleteSource(f), deleteDeps);
  } catch {
    // 管道异常兜底：按删除失败处理（保持条目与可重试态）
    deleteStates.value.delete(f.id);
    showError("删除失败，请重试");
    return;
  }
  settleDeleteResult(f, result);
};

/** 落盘失败重试：删除已提交，仅重放落盘与其后的收尾步骤 */
const retryPersistDelete = async (f: FileEntry) => {
  deleteStates.value.set(f.id, "deleting");
  let result: FileDeleteResult;
  try {
    result = await retryFileDeletePersist(toDeleteSource(f), deleteDeps);
  } catch {
    deleteStates.value.set(f.id, "persist-retry");
    showError("删除落盘仍失败，请重试");
    return;
  }
  settleDeleteResult(f, result);
};

/* ===== 卡片光泽追踪（共享实现；3D 视差倾斜已按用户决策移除，Wave 53） ===== */
const { onCardMove, onCardLeave } = useCardShine();

/* ===== 加载已有文件 ===== */
const loadFiles = async () => {
  if (!isTauri) {
    // 项2：shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
    replaceShallowArray(files, [
      { id: 1, name: "project_report.pdf", size: 4521984, mime: "application/pdf", totalChunks: 2, encrypted: false },
      { id: 2, name: "financial_data.xlsx", size: 1234567, mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", totalChunks: 1, encrypted: true },
      { id: 3, name: "backup_archive.zip", size: 89123456, mime: "application/zip", totalChunks: 22, encrypted: false },
    ]);
    return;
  }
  // 0. 缓存优先：先用缓存数据即时渲染，缓存有效时不显示加载动画
  const cached = getModuleCache<FileEntry[]>("fileverthys");
  let maxRecordId = 0;
  if (cached.data && cached.data.length > 0) {
    // 项2：shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
    replaceShallowArray(files, cached.data);
    // 计算缓存中最大的 metaId，作为增量扫描起点（参考 PhotoAlbum）
    maxRecordId = cached.data.reduce((max, f) => Math.max(max, f.metaId || 0), 0);
    loading.value = false; // 缓存有效，不显示加载动画
  } else {
    loading.value = true; // 缓存无效，显示加载动画
  }
  // 1. 共享扫描：首次调用扫描全部记录并缓存，后续模块直接复用（零 IPC 调用）
  //    按 metaId 去重（杜绝重复繁殖）
  const existingMetaIds = new Set(
    files.value.map(f => f.metaId).filter((id): id is number => id !== undefined)
  );
  let hasNewFiles = false;
  // 项2：批量构建新条目后一次性 pushShallowItems，避免循环内多次触发响应式
  const newItems: FileEntry[] = [];

  // ID 来源：摘要索引优先（仅读索引、不解密数据，不受记录体积影响）；
  //   摘要缓存整体为空（旧格式容器/熔断静默返回空）时回退记录扫描缓存。
  //   记录扫描仍会在后台并发触发一次作数据层预热：命中扫描缓存的小体积记录
  //   在后续批量取数时零 IPC；预热失败不影响列表可用性（取数走并行 IPC 回退）。
  const useSummaryIds = await ensureIndexSourceSafe();
  const idsOf = (type: number): number[] =>
    useSummaryIds ? getSummaryIdsByType(type) : getRecordIdsByType(type);

  let metaIds = idsOf(TYPE_FILEVERTHYS_META);
  // 修复：旧类型 0x05 回退扫描（迁移失败的兜底）
  //
  // 原缺陷：若 migrateRecordTypes 超时/失败，旧 FileVerthys 元数据仍停留在 0x05
  //   （与 TYPE_PHOTO_CHUNK 冲突的旧值），FileVerthys 仅扫描 TYPE_FILEVERTHYS_META(0x08)
  //   → 旧文件记录完全不可见 → "模块内容没有被加载出来"。
  //
  // 修复：若 0x08 无记录，追加扫描 0x05 记录。后续 JSON.parse 会自然过滤掉
  //   照片数据块（二进制密文 parse 失败 → catch 跳过），仅保留 FileVerthys 元数据。
  if (metaIds.length === 0) {
    metaIds = idsOf(TYPE_FILEVERTHYS_META_OLD);
  }

  // 增量过滤 + 去重，仅批量获取需要处理的 meta
  const pendingMetaIds = metaIds.filter(id => id > maxRecordId && !existingMetaIds.has(id));
  if (pendingMetaIds.length > 0) {
    // 1. 批量获取所有 meta 记录数据（扫描缓存优先，并行 IPC 回退）
    const metaB64Map = await getRecordsDataB64Batch(pendingMetaIds);
    for (const id of pendingMetaIds) {
      const metaDataB64 = metaB64Map.get(id);
      if (!metaDataB64) continue;
      try {
        const bytes = base64ToBytes(metaDataB64);
        const meta = JSON.parse(new TextDecoder().decode(bytes));

        // 历史内联格式：meta 内嵌块密文（读取侧优先按内联还原）
        if (meta.chunkDataB64 && meta.chunkDataB64.length > 0) {
          // 项2：收集到 newItems，循环外一次性 pushShallowItems
          newItems.push({
            id: Date.now() + id,
            name: meta.name,
            size: meta.size,
            mime: meta.mime,
            totalChunks: meta.totalChunks,
            encrypted: meta.encrypted,
            metaId: id,
            chunkDataB64: meta.chunkDataB64,
          });
          existingMetaIds.add(id);
          hasNewFiles = true;
        }
        // 外置格式：meta 只保存块引用（chunkIds），块密文在独立 chunk 记录中，
        // 读取侧按引用取块解密（导出与删除级联均依赖 chunkIds）。
        // 接纳条件按"字段存在且为数组"判定：0 字节文件的块引用恰为空数组，
        // 若按长度判定会把空文件永久排除在列表之外。
        else if (Array.isArray(meta.chunkIds)) {
          // 项2：收集到 newItems，循环外一次性 pushShallowItems
          newItems.push({
            id: Date.now() + id,
            name: meta.name,
            size: meta.size,
            mime: meta.mime,
            totalChunks: meta.totalChunks,
            encrypted: meta.encrypted,
            metaId: id,
            chunkIds: meta.chunkIds,
            chunkHashes: meta.chunkHashes,
            chunkSize: meta.chunkSize,
            fileHash: meta.fileHash,
            kdf: meta.kdf,
            passwordCheck: meta.passwordCheck,
          });
          existingMetaIds.add(id);
          hasNewFiles = true;
        }
      } catch { /* */ }
    }
  }

  // 项2：循环外一次性 pushShallowItems 触发 triggerRef
  if (newItems.length > 0) {
    pushShallowItems(files, newItems);
  }
  // 2. 只有发现新文件才更新缓存（避免不必要的缓存写入）
  if (hasNewFiles) {
    syncModuleCache();
  }
};

onMounted(() => {
  loadFiles().finally(() => {
    loading.value = false;
  });
});
onUnmounted(() => {
  /* 项3：取消未触发的防抖调用，防止内存泄漏 */
  debouncedUpdateSearch.cancel();
});

/* 修复「页面覆盖」：切换模块时同步关闭所有 Teleport 弹窗，杜绝残留覆盖 */
import { useModuleDialogGuard } from "../../composables/useModuleDialogGuard";
useModuleDialogGuard("verthys", () => {
  showImportDialog.value = false;
  showKeyDialog.value = false;
  showDeleteConfirm.value = false;
  resolveSessionConflict(false);
  sessionConflictResolver = null;
});
</script>

<style scoped>
.file-verthys { width: 100%; height: 100%; display: flex; flex-direction: column; gap: 14px; overflow: hidden; position: relative; }

/* 顶部栏：星野导航带仅承载布局（无边框/圆角/投影 —— 底板与左右溶解边界由 StarlitSky 承担） */
.search-bar { display: flex; align-items: center; gap: 12px; padding: 9px 10px 9px 14px; flex-shrink: 0; animation: slide-down 0.5s var(--ease) both; }
@keyframes slide-down { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
.search-inner { display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0; }
.search-icon { width: 14px; height: 14px; color: var(--text-muted); flex-shrink: 0; }
.search-input { flex: 1; background: transparent; border: none; color: var(--text-primary); font-size: 13px; outline: none; font-family: var(--font); min-width: 0; }
.search-input::placeholder { color: var(--text-muted); }

/* 卡片网格 */
.card-grid { flex: 1; overflow-y: auto; overflow-x: hidden; display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; align-content: start; padding-right: 4px; }
/* 悬浮效果只有阴影 + 光泽追踪（3D 视差倾斜已按用户决策移除，Wave 53）；
   入场动画填充模式必须为 backwards，不得改回 both/forwards——
   前向填充会永久用动画终态压住 hover transform（曾使卡片倾斜静默失效） */
/* 卡片底色：直接复用顶部星野导航带底板（单源 tokens.css --bar-surface，
   与 StarlitSky 底板同一定义）；.glass 仅保留边框 / 圆角 / 投影 */
.acct-card { position: relative; padding: 14px 16px 14px 18px; background: var(--bar-surface); transition: box-shadow 0.3s var(--ease); animation: card-in 0.5s var(--ease) backwards; animation-delay: calc(var(--i) * 0.05s); }
@keyframes card-in { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
.acct-card:hover { box-shadow: 0 12px 36px rgba(0,0,0,0.5), 0 0 16px rgba(0,212,255,0.1); }
.card-accent { position: absolute; left: 0; top: 10px; bottom: 10px; width: 2px; background: linear-gradient(180deg, transparent, var(--accent), transparent); opacity: 0; transition: opacity 0.3s; border-radius: 1px; }
.acct-card:hover .card-accent { opacity: 1; box-shadow: 0 0 8px rgba(0,212,255,0.4); }
/* 光晕层几何/混合/强度统一由共享定义（styles/verthys-common.css .card-shine +
   tokens.css --shine-alpha / --shine-reach）；本模块只需卡片自身的悬浮显隐（Wave 54 收口） */
.acct-card:hover .card-shine { opacity: 1; }
.card-head { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.file-icon-wrap { width: 18px; height: 18px; color: var(--accent); flex-shrink: 0; }
.file-icon-wrap svg { width: 100%; height: 100%; }
.platform { font-size: 14px; font-weight: 600; color: var(--text-primary); letter-spacing: 0.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0; }
.lock-badge { width: 14px; height: 14px; color: var(--warning); flex-shrink: 0; }
.lock-badge svg { width: 100%; height: 100%; }
.file-info { display: flex; flex-direction: column; gap: 3px; margin-bottom: 6px; }
.info-item { font-size: 11px; color: var(--text-secondary); font-family: var(--font); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.info-label { color: var(--text-muted); margin-right: 4px; }
.card-actions { display: flex; gap: 4px; opacity: 0; transition: opacity 0.3s var(--ease); margin-top: 4px; }
.acct-card:hover .card-actions { opacity: 1; }
.mini-btn { background: none; border: none; color: var(--accent); font-size: 11px; cursor: pointer; padding: 2px 8px; border-radius: 3px; transition: all 0.2s; letter-spacing: 0.5px; }
.mini-btn:hover { background: rgba(0,212,255,0.1); }
.mini-btn.danger { color: var(--danger); }
.mini-btn.danger:hover { background: rgba(255,46,99,0.1); }
/* 禁用态（删除中 / 删除已提交待落盘）：光标与可点击态明确区分，悬浮不再着色 */
.mini-btn:disabled { cursor: not-allowed; opacity: 0.45; }
.mini-btn:disabled:hover { background: none; }

/* 对话框 */
.dialog-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.74); display: flex; align-items: center; justify-content: center; z-index: 1000; }
.dialog { padding: 28px; min-width: 440px; max-width: 90vw; animation: dialog-in 0.4s var(--ease); }
@keyframes dialog-in { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
.dialog-title { font-size: 14px; margin-bottom: 20px; color: var(--accent); letter-spacing: 2px; font-family: var(--font); }

/* 导入文件信息 */
.import-file-info { display: flex; gap: 14px; padding: 14px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: var(--radius); margin-bottom: 16px; }
.file-icon-lg { width: 36px; height: 36px; color: var(--accent); flex-shrink: 0; }
.file-icon-lg svg { width: 100%; height: 100%; }
.file-meta { flex: 1; min-width: 0; }
.file-name { font-size: 13px; color: var(--text-primary); font-family: var(--font); margin-bottom: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-size { font-size: 11px; color: var(--accent); font-family: var(--font); margin-bottom: 2px; }
.file-chunks { font-size: 10px; color: var(--text-muted); }

/* 加密选项 */
.encrypt-row { padding: 10px 12px; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); transition: all 0.2s; margin-bottom: 16px; }
.encrypt-row.on { border-color: rgba(0,212,255,0.25); background: rgba(0,212,255,0.03); }
.encrypt-toggle { display: flex; align-items: center; gap: 8px; cursor: pointer; user-select: none; }
.encrypt-toggle input { display: none; }
.encrypt-check { width: 14px; height: 14px; border: 1px solid var(--border-glass); border-radius: 3px; position: relative; transition: all 0.2s; flex-shrink: 0; }
.encrypt-row.on .encrypt-check { background: var(--accent); border-color: var(--accent); }
.encrypt-row.on .encrypt-check::after { content: ""; position: absolute; left: 4px; top: 1px; width: 4px; height: 8px; border: solid #000; border-width: 0 2px 2px 0; transform: rotate(45deg); }
.encrypt-label { font-size: 11px; color: var(--text-secondary); }
.encrypt-key-input { margin-top: 8px; }
.encrypt-key-input .input { width: 100%; }

.dialog-actions { display: flex; justify-content: flex-end; gap: 10px; padding-top: 14px; border-top: 1px solid var(--border-glass); }

/* 并发导入互斥确认 */
.session-conflict-text { font-size: 12px; line-height: 1.7; color: var(--text-secondary); font-family: var(--font); margin-bottom: 6px; }

/* 密钥对话框 */
.key-dialog { min-width: 360px; }
.key-target { font-size: 12px; color: var(--text-secondary); font-family: var(--font); margin-bottom: 14px; }
</style>
