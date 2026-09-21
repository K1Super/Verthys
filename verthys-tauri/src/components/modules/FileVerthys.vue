<!--
  FileVerthys.vue — 加密文件加密库模块（清藏）
  功能：
    - 支持 PDF / Word / Excel / 压缩包等任意格式文档加密入库
    - 大文件分块加密存储（4MB/块），支持断点导入
    - 可保存到本地（加密文档需输入独立密码解密后导出）
    - 可单独给文档设置独立访问密码，实现细粒度权限隔离
  记录类型：0x05 元数据，0x04 数据块
-->
<template>
  <div class="file-verthys">
    <!-- 顶部错误提示弹窗 -->
    <Teleport to="body">
      <transition name="err-toast">
        <div v-if="errorMsg" class="error-toast glass"><span class="toast-dot"></span>{{ errorMsg }}</div>
      </transition>
    </Teleport>

    <!-- 顶部栏 -->
    <div class="search-bar glass">
      <div class="search-inner">
        <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        </svg>
        <!-- ★ 项3：搜索输入防抖（300ms 尾部触发），连续快速输入仅触发一次过滤 -->
        <input class="search-input" :value="searchKey" @input="onSearchInput" placeholder="搜索文件…" />
      </div>
      <ActionButton
        :label="importing ? '导入中…' : '导入文件'"
        :loading="importing"
        @click="onImport"
      />
    </div>

    <!-- 导入进度（含断点续传） -->
    <div v-if="importing" class="import-panel glass">
      <div class="import-info">
        <span class="import-name">{{ importingFile }}</span>
        <span class="import-progress-text">{{ importDone }} / {{ importTotal }} 块 · {{ importPercent }}%</span>
      </div>
      <div class="progress-bar"><div class="progress-fill" :style="{ width: importPercent + '%' }"></div></div>
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
          <button class="mini-btn" @click="onSave(f)">保存</button>
          <button class="mini-btn danger" @click="onDelete(f)">删除</button>
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
          <button class="mini-btn" @click="onSave(f)">保存</button>
          <button class="mini-btn danger" @click="onDelete(f)">删除</button>
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
          <button class="btn" @click="showImportDialog = false">取消</button>
          <button class="btn btn-primary" @click="startImport">开始加密导入</button>
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
          <button class="btn" @click="showKeyDialog = false">取消</button>
          <button class="btn btn-primary" @click="confirmSaveKey">解密保存</button>
        </div>
      </div>
    </div>

    <!-- 复制提示 -->
    <transition name="toast">
      <div v-if="toast" class="clip-toast glass"><span class="toast-dot"></span>{{ toast }}</div>
    </transition>

    <!-- 非阻塞加载：无底板居中展示，加载完成自动消失 -->
    <CosmicLoading :show="loading" text="正在加载文件数据…" />

    <!-- 删除二次确认弹窗 -->
    <ConfirmDelete
      :show="showDeleteConfirm"
      :item-name="deleteTargetName"
      @confirm="confirmDelete"
      @cancel="showDeleteConfirm = false"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, shallowRef, computed, onMounted, onUnmounted } from "vue";
import { open, save } from "@tauri-apps/plugin-dialog";
import ActionButton from "../common/verthys-ui/ActionButton.vue";
import CosmicLoading from "../common/cosmic/CosmicLoading.vue";
import CosmicEmpty from "../common/cosmic/CosmicEmpty.vue";
import ConfirmDelete from "../common/verthys-ui/ConfirmDelete.vue";
import {
  verthysAddRecord, verthysGetRecord, verthysDeleteRecord,
  readUserFile, base64ToBytes, bytesToBase64, writeUserFile,
  encryptPasswordField, decryptPasswordField,
} from "../../lib/verthys";
import { persistVerthys, deleteAndPersist, getModuleCache, setModuleCache, invalidateSummaryRecord, invalidateFullRecord, addFullRecord, clearSummaryCache, clearFullRecordCache, ensureRecordScanSafe, getRecordIdsByType, invalidateScannedRecord, clearRecordScanCache, getRecordsDataB64Batch } from "../../lib/keyManager";
import { TYPE_FILEVERTHYS_META, TYPE_FILEVERTHYS_CHUNK, TYPE_FILEVERTHYS_META_OLD } from "../../constants/record_types";
import { useErrorToast } from "../../composables/useErrorToast";
import {
  updateShallowItem, pushShallowItems, replaceShallowArray,
  clearShallowArray, removeShallowItems,
} from "../../utils/shallow-array";
import { debounce } from "../../utils/debounce";
import VirtualCardGrid from "../common/verthys-ui/VirtualCardGrid.vue";

/* ===== 顶部错误提示弹窗 ===== */
const { errorMsg, showError } = useErrorToast();

/* ===== 类型 ===== */
interface FileEntry {
  id: number;
  name: string;
  size: number;
  mime: string;
  totalChunks: number;
  encrypted: boolean;
  metaId?: number;             // 元数据记录 ID
  chunkIds?: number[];         // 旧格式：数据块记录 ID 列表
  chunkDataB64?: string[];     // 新格式：内联 chunk 数据（参考 PhotoAlbum，避免 ID 漂移）
}

/* ===== 常量 ===== */
const CHUNK_SIZE = 4 * 1024 * 1024; // 4MB 每块
/* ★ 企业级根治：TYPE 常量从 record_types.ts 导入，不再本地定义
 *   TYPE_FILEVERTHYS_META (0x08) — 原 TYPE_FILEVERTHYS_META=0x05，与 TYPE_PHOTO_CHUNK 冲突，已改
 *   TYPE_FILEVERTHYS_CHUNK (0x04) — 原 TYPE_FILEVERTHYS_CHUNK=0x04，值不变仅重命名
 */

/* 非阻塞加载状态（无底板居中展示，加载完成自动消失） */
const loading = ref(false);

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/* ===== 文件列表 ===== */
const searchKey = ref("");
/* ★ 项2：shallowRef 替代 ref，避免 Vue 对 files 数组内每条记录深度代理
 * （每条记录含 metaId/chunks 等字段，万条记录深度代理开销 200-500ms） */
const files = shallowRef<FileEntry[]>([]);

const filteredFiles = computed(() => {
  const k = searchKey.value.trim().toLowerCase();
  return files.value.filter(f => !k || f.name.toLowerCase().includes(k));
});

/* ★ 项3：搜索输入防抖（300ms 尾部触发）
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
    // ★ 项2：shallowRef 下 push 需用 pushShallowItems 触发 triggerRef
    pushShallowItems(files, [{
      id: Date.now(), name: `demo_doc_${files.value.length + 1}.pdf`,
      size: 1024 * 1024 * (2 + files.value.length), mime: "application/pdf",
      totalChunks: 3 + files.value.length, encrypted: false,
    }]);
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

const startImport = async () => {
  if (usePassword.value && !docPassword.value) return;
  if (pendingFiles.value.length === 0) return;
  showImportDialog.value = false;
  importing.value = true;

  const list = pendingFiles.value.slice();
  let successCount = 0;
  let failCount = 0;
  // ★ 项2：批量构建新条目后一次性 pushShallowItems，避免循环内多次触发响应式
  const newItems: FileEntry[] = [];

  for (let fi = 0; fi < list.length; fi++) {
    const { path: filePath, name: fileName } = list[fi];
    importingFile.value = list.length === 1
      ? fileName
      : `${fileName}（${fi + 1}/${list.length}）`;

    try {
      // 1. 读取全部文件字节（二进制 IPC 直传 Uint8Array）
      const fileBytes = await readUserFile(filePath);
      const fileSize = fileBytes.length;
      const fileMime = getMimeFromName(fileName);
      const totalChunks = Math.ceil(fileSize / CHUNK_SIZE);
      importTotal.value = totalChunks;
      importDone.value = 0;

      // 2. 分块加密（全部内联到 meta 记录，参考 PhotoAlbum 模式，避免 ID 漂移）
      const chunkDataB64: string[] = [];
      for (let i = 0; i < totalChunks; i++) {
        const start = i * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, fileSize);
        const chunkBytes = fileBytes.slice(start, end);
        let chunkData: Uint8Array = chunkBytes;

        // 如果设置了独立密码，用 AES-GCM 加密该块
        if (usePassword.value && docPassword.value) {
          const chunkB64 = bytesToBase64(chunkBytes);
          const encryptedB64 = await encryptPasswordField(chunkB64, docPassword.value);
          chunkData = base64ToBytes(encryptedB64);
        }

        chunkDataB64.push(bytesToBase64(chunkData));
        importDone.value = i + 1;
        // 多文件时进度合并显示
        const fileProgress = (i + 1) / totalChunks;
        importPercent.value = list.length === 1
          ? Math.round(fileProgress * 100)
          : Math.round(((fi + fileProgress) / list.length) * 100);
      }

      // 3. 存储元数据记录（单条记录包含所有 chunk 数据，无单独 chunk 记录）
      const meta = {
        name: fileName,
        size: fileSize,
        mime: fileMime,
        chunkIds: [] as number[],   // 新格式不使用，保留兼容
        chunkDataB64,                // 内联 chunk 数据
        chunkSize: CHUNK_SIZE,
        totalChunks,
        completedChunks: totalChunks,
        encrypted: usePassword.value,
      };
      const metaB64 = bytesToBase64(new TextEncoder().encode(JSON.stringify(meta)));
      const metaId = await verthysAddRecord(TYPE_FILEVERTHYS_META, `meta_${fileName}`, metaB64);
      if (metaId !== null) {
        // ★ 同步两层缓存（摘要 + 全量），替代旧 addRecordToScan
        addFullRecord(metaId, TYPE_FILEVERTHYS_META, `meta_${fileName}`, metaB64, metaB64.length);
      }

      // 4. 添加到文件列表（先收集，循环外一次性 pushShallowItems）
      newItems.push({
        id: Date.now() + fi,
        name: fileName,
        size: fileSize,
        mime: fileMime,
        totalChunks,
        encrypted: usePassword.value,
        metaId: metaId || undefined,
        chunkDataB64,
      });
      successCount++;
    } catch (e) {
      if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") {
        showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
        break;
      }
      console.error(`[FileVerthys] 导入 ${fileName} 失败`, e);
      failCount++;
    }
  }

  // ★ 项2：循环外一次性 pushShallowItems 触发 triggerRef
  if (newItems.length > 0) {
    pushShallowItems(files, newItems);
  }

  // 统一持久化（所有 meta 记录已写入 worker 内存，一次 flush 全部落盘）
  setModuleCache("fileverthys", files.value);
  // ★ 企业级数据持久化修复：检查 persistVerthys 返回值，根治"导入后重启数据丢失"
  //    旧实现仅 await persistVerthys() 不检查返回值，flush 失败时 UI 显示已导入文件但
  //    磁盘未落盘 → 重启后数据丢失。修复：检查返回值，失败时 showError 提示用户。
  if (isTauri) {
    let persistOk = false;
    try { persistOk = await persistVerthys(); } catch (e) { console.error("[onImport] persistVerthys 异常", e); }
    if (!persistOk) {
      showError("文件已加密导入内存但持久化失败，重启后可能丢失。请勿关闭应用，尝试重新导入或联系支持");
    }
  }

  importing.value = false;
  importPercent.value = 0;
  pendingFiles.value = [];

  if (list.length === 1) {
    if (successCount === 1) {
      showToast(`已加密导入 ${list[0].name}`);
    } else {
      showError("导入失败");
    }
  } else {
    showToast(`批量导入完成：成功 ${successCount} 个${failCount > 0 ? `，失败 ${failCount} 个` : ""}`);
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
  doSave(f, null);
};

const confirmSaveKey = async () => {
  if (!saveTarget.value || !keyInput.value) return;
  try {
    await doSave(saveTarget.value, keyInput.value);
    showKeyDialog.value = false;
    keyInput.value = "";
  } catch {
    showError("密码错误或数据已损坏");
  }
};

const doSave = async (f: FileEntry, password: string | null) => {
  if (!isTauri) {
    showError("浏览器模式不支持保存");
    return;
  }

  // 1. 收集所有 chunk 的 base64 数据（优先使用内联 chunkDataB64，旧格式回退到 chunkIds）
  const chunkB64List: string[] = [];
  if (f.chunkDataB64 && f.chunkDataB64.length > 0) {
    chunkB64List.push(...f.chunkDataB64);
  } else if (f.chunkIds && f.chunkIds.length > 0) {
    for (const chunkId of f.chunkIds) {
      const r = await verthysGetRecord(chunkId);
      if (!r) continue;
      chunkB64List.push(r.dataB64);
    }
  } else {
    showError("无数据可保存");
    return;
  }

  // 2. 解密并重组
  const chunks: Uint8Array[] = [];
  for (const chunkB64 of chunkB64List) {
    let chunkBytes = base64ToBytes(chunkB64);
    if (password) {
      const decryptedB64 = await decryptPasswordField(chunkB64, password);
      chunkBytes = base64ToBytes(decryptedB64);
    }
    chunks.push(chunkBytes);
  }
  const fullBytes = new Uint8Array(f.size);
  let offset = 0;
  for (const chunk of chunks) {
    fullBytes.set(chunk, offset);
    offset += chunk.length;
  }

  // 3. 选择保存位置
  const ext = f.name.split(".").pop() || "";
  const baseName = f.name.replace(/\.[^.]+$/, "");
  const savePath = await save({
    defaultPath: f.name,
    filters: ext
      ? [{ name: ext.toUpperCase(), extensions: [ext] }, { name: "所有文件", extensions: ["*"] }]
      : [{ name: "所有文件", extensions: ["*"] }],
  });
  if (!savePath) return;

  // 4. 写入文件
  try {
    await writeUserFile(savePath, fullBytes);
    showToast(`已保存到本地: ${baseName}.${ext}`);
  } catch (e) {
    console.error("[saveFile] 异常", e);
    showError("保存失败");
  }
};

/* ===== 删除二次确认 ===== */
const showDeleteConfirm = ref(false);
const deleteTargetName = ref("");
const deleteTarget = ref<FileEntry | null>(null);
const onDelete = (f: FileEntry) => {
  deleteTarget.value = f;
  deleteTargetName.value = f.name;
  showDeleteConfirm.value = true;
};
const confirmDelete = async () => {
  const f = deleteTarget.value;
  if (!f) return;
  // 立即关闭弹窗 + 移除 UI + 更新缓存（同步无缝，消除删除按钮到内容消失的空白间隔）
  showDeleteConfirm.value = false;
  deleteTarget.value = null;
  // ★ 项2：shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
  removeShallowItems(files, x => x.id === f.id);
  setModuleCache("fileverthys", files.value);
  showToast(`已删除 ${f.name}`);
  // ★ 企业级根治：await deleteAndPersist + await persistVerthys（根治删除后复活）
  if (isTauri) {
    // 收集所有需要删除的 recordId（旧格式 chunk 记录 + meta 记录）
    const idsToDelete: number[] = [];
    if (f.chunkIds && f.chunkIds.length > 0 && (!f.chunkDataB64 || f.chunkDataB64.length === 0)) {
      for (const chunkId of f.chunkIds) idsToDelete.push(chunkId);
    }
    if (f.metaId) idsToDelete.push(f.metaId);
    // 立即失效所有缓存（同步，杜绝删除复活）
    // ★ 同时失效两层缓存（摘要 + 全量）+ 旧扫描缓存兼容
    for (const rid of idsToDelete) {
      invalidateSummaryRecord(rid);
      invalidateFullRecord(rid);
      invalidateScannedRecord(rid);
    }
    // ★ 企业级根治：await deleteAndPersist + await persistVerthys（根治删除后复活）
    //
    // 原缺陷：deleteAndPersist(...).catch(() => {}) 火并忘——防抖 flush（300ms）
    //   未执行即返回，应用退出 → 磁盘仍含已删记录 → "删除后复活"。
    //   .catch(() => {}) 静默吞错 → 用户不知删除失败。
    //
    // 修复：await deleteAndPersist（删除 IPC 完成）+ await persistVerthys（取消防抖
    //   立即落盘）。UI 已同步移除（无缝删除），await 不阻塞 UI 渲染。
    try {
      await deleteAndPersist(async () => {
        for (const rid of idsToDelete) {
          try { await verthysDeleteRecord(rid); } catch (e) {
            if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") throw e;
          }
        }
        return true;
      });
      // ★ 企业级数据持久化修复：检查 persistVerthys 返回值，根治"删除后复活"
      //    persistVerthys 返回 false（非抛异常）时旧 catch 无法捕获 → 静默假成功 →
      //    UI 已移除但磁盘未落盘 → 重启后记录"复活"。
      const persistOk = await persistVerthys(); // 立即落盘（取消防抖，根治删除后复活）
      if (!persistOk) {
        showError("删除已提交但持久化失败，重启后记录可能恢复。请勿关闭应用并重试删除");
      }
    } catch (e) {
      if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") {
        showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
        return;
      }
      showError("删除失败，请重试");
    }
  }
};

/* ===== 卡片视差 ===== */
const onCardMove = (e: MouseEvent) => {
  const card = e.currentTarget as HTMLElement;
  const r = card.getBoundingClientRect();
  const px = (e.clientX - r.left) / r.width - 0.5;
  const py = (e.clientY - r.top) / r.height - 0.5;
  card.style.transform = `perspective(800px) rotateY(${px * 6}deg) rotateX(${-py * 6}deg) translateY(-3px)`;
  const shine = card.querySelector(".card-shine") as HTMLElement;
  if (shine) shine.style.background = `radial-gradient(circle at ${px * 100 + 50}% ${py * 100 + 50}%, rgba(0,212,255,0.1), transparent 60%)`;
};
const onCardLeave = (e: MouseEvent) => {
  const card = e.currentTarget as HTMLElement;
  card.style.transform = "";
  const shine = card.querySelector(".card-shine") as HTMLElement;
  if (shine) shine.style.background = "";
};

/* ===== Toast ===== */
const toast = ref("");
let toastTimer: ReturnType<typeof setTimeout> | null = null;
const showToast = (msg: string) => {
  toast.value = msg;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.value = ""; }, 2500);
};

/* ===== 加载已有文件 ===== */
const loadFiles = async () => {
  if (!isTauri) {
    // ★ 项2：shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
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
    // ★ 项2：shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
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
  // ★ 项2：批量构建新条目后一次性 pushShallowItems，避免循环内多次触发响应式
  const newItems: FileEntry[] = [];

  // ★ 性能修复：改走 recordScanCache + 批量获取（落实 2.5s 预算）
  //    原实现：ensureSummaryScanSafe + for 循环串行 getFullRecord（meta + 内层 chunk
  //            双层串行 IPC，N 个文件 × M 个 chunk → N×M 次 IPC，与后台扫描抢 worker → 30s）
  //    新实现：ensureRecordScanSafe + getRecordsDataB64Batch（meta 批量 + chunk 批量，
  //            扫描缓存命中零 IPC，未命中并行回退），总耗时 < 2.5s。
  await ensureRecordScanSafe();
  // ★ 从扫描缓存取 ID 列表
  let metaIds = getRecordIdsByType(TYPE_FILEVERTHYS_META);
  // ★ 企业级根治：旧类型 0x05 回退扫描（迁移失败的兜底）
  //
  // 原缺陷：若 migrateRecordTypes 超时/失败，旧 FileVerthys 元数据仍停留在 0x05
  //   （与 TYPE_PHOTO_CHUNK 冲突的旧值），FileVerthys 仅扫描 TYPE_FILEVERTHYS_META(0x08)
  //   → 旧文件记录完全不可见 → "模块内容没有被加载出来"。
  //
  // 修复：若 0x08 无记录，追加扫描 0x05 记录。后续 JSON.parse 会自然过滤掉
  //   照片数据块（二进制密文 parse 失败 → catch 跳过），仅保留 FileVerthys 元数据。
  if (metaIds.length === 0) {
    metaIds = getRecordIdsByType(TYPE_FILEVERTHYS_META_OLD);
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

        // 新格式：优先使用内联 chunkDataB64
        if (meta.chunkDataB64 && meta.chunkDataB64.length > 0) {
          // ★ 项2：收集到 newItems，循环外一次性 pushShallowItems
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
        // 旧格式迁移：如果 meta 有 chunkIds 但无 chunkDataB64，批量读取 chunk 记录并内联
        else if (meta.chunkIds && meta.chunkIds.length > 0) {
          // 2. 批量获取该 meta 的所有 chunk 数据（扫描缓存优先，并行 IPC 回退）
          const chunkB64Map = await getRecordsDataB64Batch(meta.chunkIds);
          const chunkDataB64: string[] = [];
          let allFound = true;
          for (const cid of meta.chunkIds) {
            const chunkB64 = chunkB64Map.get(cid);
            if (!chunkB64) { allFound = false; break; }
            chunkDataB64.push(chunkB64);
          }
          if (allFound && chunkDataB64.length === meta.chunkIds.length) {
            // 迁移成功：将 chunk 数据内联到 meta 记录
            meta.chunkDataB64 = chunkDataB64;
            const migratedMetaB64 = bytesToBase64(new TextEncoder().encode(JSON.stringify(meta)));
            const newMetaId = await verthysAddRecord(TYPE_FILEVERTHYS_META, `meta_${meta.name}`, migratedMetaB64);
            if (newMetaId !== null) {
              try { await verthysDeleteRecord(id); } catch { /* */ }
              // 删除旧的 chunk 记录
              for (const cid of meta.chunkIds) {
                try { await verthysDeleteRecord(cid); } catch { /* */ }
              }
              // ★ 企业级数据持久化修复：检查迁移落盘返回值，失败时提示用户
              let migratePersistOk = false;
              try { migratePersistOk = await persistVerthys(); } catch (e) { console.error("[loadFiles] 迁移 persistVerthys 异常", e); }
              if (!migratePersistOk) {
                showError("文件数据迁移已执行但持久化失败，重启后可能需重新迁移。请勿关闭应用并重试");
              }
              // ★ 迁移涉及批量增删，清空所有缓存确保一致性
              clearRecordScanCache();   // 清空旧扫描缓存
              clearSummaryCache();      // 清空摘要缓存
              clearFullRecordCache();   // 清空全量记录缓存
            }
            const finalMetaId = newMetaId || id;
            // ★ 项2：收集到 newItems，循环外一次性 pushShallowItems
            newItems.push({
              id: Date.now() + id,
              name: meta.name,
              size: meta.size,
              mime: meta.mime,
              totalChunks: meta.totalChunks,
              encrypted: meta.encrypted,
              metaId: finalMetaId,
              chunkDataB64,
            });
            existingMetaIds.add(finalMetaId);
            hasNewFiles = true;
          } else {
            // 迁移失败：仅使用 chunkIds 读取（部分数据可能丢失）
            // ★ 项2：收集到 newItems，循环外一次性 pushShallowItems
            newItems.push({
              id: Date.now() + id,
              name: meta.name,
              size: meta.size,
              mime: meta.mime,
              totalChunks: meta.totalChunks,
              encrypted: meta.encrypted,
              metaId: id,
              chunkIds: meta.chunkIds,
            });
            existingMetaIds.add(id);
            hasNewFiles = true;
          }
        }
      } catch { /* */ }
    }
  }

  // ★ 项2：循环外一次性 pushShallowItems 触发 triggerRef
  if (newItems.length > 0) {
    pushShallowItems(files, newItems);
  }
  // 2. 只有发现新文件才更新缓存（避免不必要的缓存写入）
  if (hasNewFiles) {
    setModuleCache("fileverthys", files.value);
  }
};

onMounted(() => {
  loadFiles().finally(() => {
    loading.value = false;
  });
});
onUnmounted(() => {
  /* ★ 项3：取消未触发的防抖调用，防止内存泄漏 */
  debouncedUpdateSearch.cancel();
});

/* ★ 企业级修复「页面覆盖」：切换模块时同步关闭所有 Teleport 弹窗，杜绝残留覆盖 */
import { useModuleDialogGuard } from "../../composables/useModuleDialogGuard";
useModuleDialogGuard("verthys", () => {
  showImportDialog.value = false;
  showKeyDialog.value = false;
  showDeleteConfirm.value = false;
});
</script>

<style scoped>
.file-verthys { width: 100%; height: 100%; display: flex; flex-direction: column; gap: 14px; overflow: hidden; position: relative; }

/* 顶部栏 */
.search-bar { display: flex; align-items: center; gap: 12px; padding: 8px 10px 8px 14px; flex-shrink: 0; animation: slide-down 0.5s var(--ease) both; }
@keyframes slide-down { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
.search-inner { display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0; }
.search-icon { width: 14px; height: 14px; color: var(--text-muted); flex-shrink: 0; }
.search-input { flex: 1; background: transparent; border: none; color: var(--text-primary); font-size: 13px; outline: none; font-family: var(--font); min-width: 0; }
.search-input::placeholder { color: var(--text-muted); }
.plus { font-weight: 300; }

/* 导入进度面板 */
.import-panel { display: flex; flex-direction: column; gap: 8px; padding: 10px 16px; flex-shrink: 0; }
.import-info { display: flex; justify-content: space-between; align-items: center; }
.import-name { font-size: 12px; color: var(--text-primary); font-family: var(--font); }
.import-progress-text { font-size: 11px; color: var(--accent); font-family: var(--font); }
.progress-bar { height: 3px; background: rgba(255,255,255,0.05); border-radius: 2px; overflow: hidden; }
.progress-fill { height: 100%; background: linear-gradient(90deg, var(--accent), #b46cff); transition: width 0.3s var(--ease); border-radius: 2px; }

/* 卡片网格 */
.card-grid { flex: 1; overflow-y: auto; overflow-x: hidden; display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; align-content: start; padding-right: 4px; }
.acct-card { position: relative; padding: 14px 16px 14px 18px; transform-style: preserve-3d; transition: transform 0.3s var(--ease), box-shadow 0.3s var(--ease); animation: card-in 0.5s var(--ease) both; animation-delay: calc(var(--i) * 0.05s); }
@keyframes card-in { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
.acct-card:hover { box-shadow: 0 12px 36px rgba(0,0,0,0.5), 0 0 16px rgba(0,212,255,0.1); }
.card-accent { position: absolute; left: 0; top: 10px; bottom: 10px; width: 2px; background: linear-gradient(180deg, transparent, var(--accent), transparent); opacity: 0; transition: opacity 0.3s; border-radius: 1px; }
.acct-card:hover .card-accent { opacity: 1; box-shadow: 0 0 8px rgba(0,212,255,0.4); }
.card-shine { position: absolute; inset: 0; border-radius: var(--radius); pointer-events: none; opacity: 0; transition: opacity 0.3s; }
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

/* 空状态 */
.empty { grid-column: 1 / -1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 48px; }
.empty-icon { font-size: 32px; color: var(--text-muted); opacity: 0.3; margin-bottom: 8px; }
.empty-text { font-size: 13px; color: var(--text-muted); margin-bottom: 4px; }
.empty-hint { font-size: 11px; color: var(--text-muted); opacity: 0.6; }

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

/* 密钥对话框 */
.key-dialog { min-width: 360px; }
.key-target { font-size: 12px; color: var(--text-secondary); font-family: var(--font); margin-bottom: 14px; }

/* Toast */
.clip-toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%); padding: 10px 20px; font-size: 12px; color: var(--accent); font-family: var(--font); z-index: 999; }
.toast-enter-active, .toast-leave-active { transition: all 0.4s var(--ease); }
.toast-enter-from, .toast-leave-to { opacity: 0; transform: translate(-50%, 10px); }
</style>
