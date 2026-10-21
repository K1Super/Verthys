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
  <div class="file-verthys reveal-host" :class="{ 'is-entering': entering }">
    <!-- 瞬时提示（错误/状态）统一由全局 ToastLayer 渲染（App 根节点单点挂载，--z-toast 最高层） -->

    <!-- 顶部栏：星野导航带（半透明无框；星野底板与溶解边界由 StarlitSky 承担） -->
    <div class="search-bar starlit-bar module-reveal">
      <StarlitSky :seed="7" />
      <div class="search-inner">
        <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
        </svg>
        <!-- 项3：搜索输入防抖（300ms 尾部触发），连续快速输入仅触发一次过滤 -->
        <input
          class="search-input"
          :value="searchKey"
          @input="onSearchInput"
          placeholder="搜索"
          aria-label="搜索加密文件"
        />
      </div>
      <!-- 悬浮提示复用全局 v-tip 气泡（量子玻璃面板）：
           指令落在 ActionButton 唯一根 <button> 上（Vue 单根组件支持组件级指令）；
           loading 时按钮为 disabled，原生不派发悬浮事件，故仅在可点击态呈现 -->
      <ActionButton
        primary
        v-tip="'导入文件'"
        aria-label="导入文件"
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
        class="acct-card glass reveal-item"
        :style="{ '--reveal-delay': revealDelayOf(index) + 'ms' }"
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
          <!-- 元数据不可读：如实直陈（状态红文字，不加底色框/图标），只留删除入口 -->
          <template v-if="f.corrupt">
            <span class="info-item is-error">元数据损坏 · 仅可删除</span>
          </template>
          <template v-else>
            <span class="info-item"><span class="info-label">大小</span> {{ formatSize(f.size) }}</span>
            <span class="info-item"><span class="info-label">类型</span> {{ getFileType(f.mime) }}</span>
            <span class="info-item"><span class="info-label">分块</span> {{ f.totalChunks }} 块</span>
          </template>
        </div>
        <div class="card-actions">
          <button
            class="mini-btn"
            :disabled="f.corrupt || deleteStateOf(f) !== undefined || exportingIds.has(f.id) || exporting"
            v-tip="f.corrupt ? '元数据损坏，无法保存' : ''"
            @click="onSave(f)"
          >{{ exportingIds.has(f.id) ? '保存中…' : '保存' }}</button>
          <button
            class="mini-btn danger"
            :disabled="deleteStateOf(f) === 'deleting' || exportingIds.has(f.id)"
            v-tip="deleteStateOf(f) === 'persist-retry' ? '删除已提交但落盘失败，点击重试完成落盘' : exportingIds.has(f.id) ? '保存进行中，结束后可删除' : ''"
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
        class="acct-card glass reveal-item"
        :style="{ '--reveal-delay': revealDelayOf(idx) + 'ms' }"
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
          <!-- 元数据不可读：如实直陈（状态红文字，不加底色框/图标），只留删除入口 -->
          <template v-if="f.corrupt">
            <span class="info-item is-error">元数据损坏 · 仅可删除</span>
          </template>
          <template v-else>
            <span class="info-item"><span class="info-label">大小</span> {{ formatSize(f.size) }}</span>
            <span class="info-item"><span class="info-label">类型</span> {{ getFileType(f.mime) }}</span>
            <span class="info-item"><span class="info-label">分块</span> {{ f.totalChunks }} 块</span>
          </template>
        </div>
        <div class="card-actions">
          <button
            class="mini-btn"
            :disabled="f.corrupt || deleteStateOf(f) !== undefined || exportingIds.has(f.id) || exporting"
            v-tip="f.corrupt ? '元数据损坏，无法保存' : ''"
            @click="onSave(f)"
          >{{ exportingIds.has(f.id) ? '保存中…' : '保存' }}</button>
          <button
            class="mini-btn danger"
            :disabled="deleteStateOf(f) === 'deleting' || exportingIds.has(f.id)"
            v-tip="deleteStateOf(f) === 'persist-retry' ? '删除已提交但落盘失败，点击重试完成落盘' : exportingIds.has(f.id) ? '保存进行中，结束后可删除' : ''"
            @click="onDelete(f)"
          >{{ deleteStateOf(f) === 'deleting' ? '删除中…' : deleteStateOf(f) === 'persist-retry' ? '重试' : '删除' }}</button>
        </div>
        <div class="card-shine"></div>
      </div>
    </div>

    <!-- 空态覆盖层：遵循「模块根视口居中」统一契约（与存签·拾光同源）——
         挂载为模块根容器（.file-verthys，position: relative）的直接子节点，
         不得置于定位/滚动子容器（如 .card-grid）之内，避免参照系漂移。 -->
    <CosmicEmpty
      v-if="!loading && filteredFiles.length === 0"
      :text="files.length === 0 ? '暂无加密文件' : '无匹配文件'"
      :hint="files.length === 0 ? '点击「导入文件」添加' : '换个关键词试试'"
    />

    <!-- 导入对话框（含独立密码选项） -->
    <!-- 导入窗口：底板（背景/描边/圆角/收边投影/入场）与头部·登记区·动作区
         结构直接复用凭证登记台共享皮肤（styles/reg-desk.css，与存签登记
         窗口同一来源）—— 面板类与两窗完全同形（dialog + glass + reg-panel），
         本组件只挂类与结构，不复制任何 reg-* 规则 -->
    <div v-if="showImportDialog" class="dialog-overlay" @click.self="showImportDialog = false">
      <div
        ref="importDialogRef"
        class="dialog glass reg-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="fv-import-title"
        tabindex="-1"
        @keydown="onImportDialogKeydown"
      >
        <header class="reg-head">
          <span class="reg-heading">
            <span class="reg-kicker">钥域 · 加密入库</span>
            <span class="reg-title" id="fv-import-title">导入文件到加密库</span>
          </span>
          <button class="reg-close" type="button" @click="showImportDialog = false" aria-label="关闭窗口" v-tip="'关闭'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </header>

        <div class="reg-body">
          <div class="import-file-info">
            <span class="file-icon-lg" v-html="getFileIcon(pendingMime)"></span>
            <div class="file-meta">
              <div class="file-name">{{ pendingName }}</div>
              <template v-if="pendingFiles.length === 1">
                <div class="file-size">{{ pendingSize === null ? "—" : formatSize(pendingSize) }}</div>
                <div class="file-chunks">分块加密存储</div>
              </template>
              <template v-else>
                <div class="file-size">
                  共 {{ pendingFiles.length }} 个文件 ·
                  {{ pendingSize === null ? "—" : formatSize(pendingSize) }}
                </div>
                <div class="file-chunks">逐个加密导入</div>
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
                :aria-invalid="docPassword.length > 0 && docPassword.length < MIN_TOKEN_LENGTH"
              />
              <!-- 口令强度下限（仅设置侧强制；解锁侧不设限，避免历史短口令被锁在门外） -->
              <p
                v-if="docPassword.length > 0 && docPassword.length < MIN_TOKEN_LENGTH"
                class="field-hint is-error"
              >访问密码至少 {{ MIN_TOKEN_LENGTH }} 位字符</p>
            </div>
          </div>
        </div>

        <div class="dialog-actions">
          <button class="btn kv-cancel" @click="showImportDialog = false">取消</button>
          <button
            class="btn btn-primary kv-confirm"
            :disabled="usePassword && docPassword.length < MIN_TOKEN_LENGTH"
            @click="startImport"
          >开始加密导入</button>
        </div>
      </div>
    </div>

    <!-- 保存密钥输入框（加密文档保存到本地前需解密）
         解锁侧不设最小长度：历史上用短口令加密的文件必须仍能导出 -->
    <div v-if="showKeyDialog" class="dialog-overlay" @click.self="closeKeyDialog">
      <div
        ref="keyDialogRef"
        class="dialog glass key-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="fv-key-title"
        tabindex="-1"
        @keydown="onKeyDialogKeydown"
      >
        <div class="dialog-title" id="fv-key-title">输入文档访问密码</div>
        <div class="key-target">{{ saveTarget?.name }}</div>
        <input
          class="input"
          v-model="keyInput"
          type="password"
          placeholder="独立访问密码"
          aria-label="文档独立访问密码"
          @keydown.enter="confirmSaveKey"
        />
        <div class="dialog-actions">
          <button class="btn kv-cancel" @click="closeKeyDialog">取消</button>
          <button class="btn btn-primary kv-confirm" :disabled="!keyInput" @click="confirmSaveKey">解密保存</button>
        </div>
      </div>
    </div>

    <!-- 非阻塞加载：无底板居中展示，加载完成自动消失 -->
    <CosmicRingLoader :overlay="true" :show="loading" text="正在加载文件数据…" />

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

    <!-- 导出进度悬浮覆盖层（与导入同源组件）：逐块可观测、可取消。
         取消后管道在块边界收敛并清理暂存，目标位置不产生文件 -->
    <ImportProgressOverlay
      :visible="exporting"
      :percent="exportPercent"
      :message="exportingFile"
      :detail="`${exportDone} / ${exportTotal} 块 · ${exportPercent}%`"
      :show-meta="false"
      :cancelable="!exportCancelPending"
      cancel-label="取消保存"
      @cancel="requestExportCancel"
    />

    <!-- 并发导入互斥：存在活跃导入会话时的显式确认（结束上一会话保留其断点状态） -->
    <div v-if="showSessionConflict" class="dialog-overlay" @click.self="resolveSessionConflict(false)">
      <div
        ref="conflictDialogRef"
        class="dialog glass"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="fv-conflict-title"
        aria-describedby="fv-conflict-desc"
        tabindex="-1"
        @keydown="onConflictDialogKeydown"
      >
        <div class="dialog-title" id="fv-conflict-title">已有导入会话进行中</div>
        <div class="session-conflict-text" id="fv-conflict-desc">
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
import { ref, shallowRef, computed, nextTick, onMounted, onUnmounted, watch } from "vue";
import { open, save } from "@tauri-apps/plugin-dialog";
import ActionButton from "../common/verthys-ui/ActionButton.vue";
import StarlitSky from "../common/cosmic/StarlitSky.vue";
import CosmicRingLoader from "../common/cosmic/CosmicRingLoader.vue";
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
  fileImportErrorMessage,
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
import { persistVerthys, persistVerthysDetailed, deleteAndPersistBatch, getModuleCache, setModuleCache, invalidateSummaryRecord, invalidateFullRecord, addFullRecord, ensureIndexSourceSafe, getSummaryIdsByType, getRecordIdsByType, invalidateScannedRecord, getRecordsDataB64Batch } from "../../lib/keyManager";
import { TYPE_FILEVERTHYS_META, TYPE_FILEVERTHYS_META_OLD } from "../../constants/record_types";
import { MIN_TOKEN_LENGTH } from "../../constants/crypto_const";
import { estimateBase64Size } from "../../cache/shared/base64-size";
import { useToastCenter } from "../../composables/useToastCenter";
import { useModuleEntrance, revealDelayOf } from "../../composables/useModuleEntrance";
import {
  pushShallowItems, replaceShallowArray, updateShallowItem,
  removeShallowItems,
} from "../../utils/shallow-array";
import { isTopModal, popModal, pushModal } from "../../utils/modal_stack";
import { debounce } from "../../utils/debounce";
import VirtualCardGrid from "../common/verthys-ui/VirtualCardGrid.vue";

/* ===== 瞬时提示（错误 / 状态）— 全局 Toast 中心；渲染归 ToastLayer ===== */
const { showError, showStatus } = useToastCenter();
/* 状态提示口径（模块内沿用 showToast 命名，指向标准状态通道，2.5s 自动消失） */
const showToast = showStatus;

/**
 * 模块自绘弹窗的模态契约（与全局模态栈共用栈序与滚动锁）。
 *
 * 导入窗 / 口令窗 / 会话冲突窗都不是 Teleport（不存在跨模块残留覆盖），
 * 但同样必须是真正的模态：入栈后锁定页面滚动、Esc 只由栈顶响应、
 * 打开时焦点移入、关闭时归还到打开前的元素、Tab 在窗内循环不逃逸。
 * 收敛为单一工厂，避免三处实现漂移（ConfirmDelete 为同款语义的既有实现）。
 */
function createModalBinding(opts: {
  close: () => void;
  root: () => HTMLElement | null;
}) {
  const id = Symbol("file-verthys-modal");
  let engaged = false;
  let returnFocus: HTMLElement | null = null;

  const focusablesOf = (root: HTMLElement): HTMLElement[] =>
    Array.from(root.querySelectorAll<HTMLElement>(
      'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex]:not([tabindex="-1"])',
    )).filter((el) => el.offsetParent !== null);

  const engage = async (): Promise<void> => {
    if (engaged) return;
    engaged = true;
    returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    pushModal(id);
    await nextTick();
    opts.root()?.focus();
  };

  const release = (): void => {
    if (!engaged) return;
    engaged = false;
    popModal(id);
    returnFocus?.focus?.();
    returnFocus = null;
  };

  const keydown = (e: KeyboardEvent): void => {
    if (!isTopModal(id)) return;
    if (e.key === "Escape") {
      e.preventDefault();
      opts.close();
      return;
    }
    if (e.key !== "Tab") return;
    const root = opts.root();
    if (!root) return;
    const items = focusablesOf(root);
    if (items.length === 0) {
      e.preventDefault();
      root.focus();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (!e.shiftKey && (active === last || !root.contains(active))) {
      e.preventDefault();
      first.focus();
    } else if (e.shiftKey && (active === first || !root.contains(active))) {
      e.preventDefault();
      last.focus();
    }
  };

  return { engage, release, keydown };
}

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
  /* 历史内联格式的整份块密文。**禁止写入模块缓存**，装载时不回填：
     单条可等于整个文件体积（上限 2 GiB），往返缓存会让整份明文体积密文
     常驻堆；仅导出/删除前按 metaId 懒读取一次（见 hydrateFilePayload）。 */
  chunkDataB64?: string[];
  chunkHashes?: string[];      // 逐块密文哈希（当前写入形态；导出完整性权威值）
  chunkSize?: number;          // 分块口径（meta 声明值；历史记录可能缺省）
  fileHash?: string;           // 文件级去重键（删除时须释放，否则重导被跳过）
  kdf?: FileKdfV2;             // 文件级密钥派生参数（加密条目；导出解锁用）
  passwordCheck?: string;      // 口令校验块（加密条目；导出前置判定用）
  /* 元数据不可读（解密或 JSON 解析失败）：条目仍须可见，仅提供删除入口，
     否则记录在列表中静默消失，用户既不知道丢了什么也无法清理 */
  corrupt?: boolean;
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

/**
 * 列表条目本地 ID（单调递增，装载与导入共用同一序列）。
 *
 * 原实现装载用 `Date.now() + metaId`、导入用 `Date.now() + idx` 双源生成，
 * 同一毫秒内可产生相同 ID；而删除与状态全部按 ID 定位
 * （`removeShallowItems(x => x.id === f.id)`），碰撞会误删第二条。
 * 基址取会话启动时刻，与缓存中上一会话 ID（同量级时间戳）不会相交。
 */
const localIdBase = Date.now();
let localIdSeq = 0;
const nextLocalId = (): number => localIdBase + ++localIdSeq;

const filteredFiles = computed(() => {
  const k = searchKey.value.trim().toLowerCase();
  return files.value.filter(f => !k || f.name.toLowerCase().includes(k));
});

/* 步入窗口：以「文件列表首次非空」起算（缓存命中即首个渲染批，未命中则
 *   数据落地批）—— 标记与首批卡片同一 patch 生效，见 useModuleEntrance 契约 */
const { entering } = useModuleEntrance(() => filteredFiles.value.length > 0);

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
/** 取展示名扩展名：无点文件名返回空串（`split(".").pop()` 会把整名当扩展名） */
const extOf = (name: string): string => {
  const dot = name.lastIndexOf(".");
  return dot > 0 && dot < name.length - 1 ? name.slice(dot + 1).toLowerCase() : "";
};

const getMimeFromName = (name: string): string => {
  const ext = extOf(name);
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
const pendingName = ref("");
const pendingSize = ref<number | null>(null);
/* 选择序号：异步取元数据期间若发生新的选择，过期回填即被丢弃 */
let importSeq = 0;
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
  // 填充显示用变量（大小在选定路径时即取 — 见下方元数据回填）
  if (pendingFiles.value.length === 1) {
    pendingName.value = pendingFiles.value[0].name;
    pendingMime.value = getMimeFromName(pendingFiles.value[0].name);
  } else {
    pendingName.value = `${pendingFiles.value.length} 个文件`;
    pendingMime.value = "application/octet-stream";
  }
  usePassword.value = false;
  docPassword.value = "";
  pendingSize.value = null;
  showImportDialog.value = true;

  /* 待导入大小 = 文件元数据（与导入管道同一权威通道 userFileStat —
   * 同源同校验，不新开并行实现）：只读 inode 元信息、不读文件内容，
   * 故并发取用亦即时且零读流量 ——「导入时才读取内容」的约束不变，
   * 变的只是把「大小」这一元数据提前到选定时刻取回。
   * 取失败（文件已移除 / 无权限）→ 显示占位并给出通用错误提示，绝不伪 0 B。 */
  const seq = ++importSeq;
  const sizes = await Promise.all(
    pendingFiles.value.map(f =>
      userFileStat(f.path).then(s => s.size).catch(() => null),
    ),
  );
  // 期间发生新的选择 → 丢弃过期回填
  if (seq !== importSeq) return;
  pendingSize.value = sizes.every((s): s is number => s !== null)
    ? sizes.reduce((a, b) => a + b, 0)
    : null;
  if (pendingSize.value === null) showError("部分文件大小无法读取");
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
  // 设置侧强制口令下限（与界面禁用同源，防程序化调用绕过）
  if (usePassword.value && docPassword.value.length < MIN_TOKEN_LENGTH) return;
  if (pendingFiles.value.length === 0) return;
  importing.value = true;
  importCancelRequested.value = false;
  cancelPending.value = false;
  importDone.value = 0;
  importTotal.value = 0;
  importPercent.value = 0;
  // 先关窗再等补释放：补释放要走 IPC，若在关窗前 await，用户会看到
  // "点了开始导入但窗口没反应"的空档（与即时反馈铁律冲突）
  showImportDialog.value = false;
  const list = pendingFiles.value.slice();
  const password = usePassword.value ? docPassword.value : null;

  try {
    // 上轮删除遗留的去重键释放：建会话前补释放，避免旧键使本轮导入被误跳过
    await dedupeReleaseQueue.flush();
  } catch (e) {
    // 兜底：补释放异常不阻断本轮导入（旧键影响仅体现为显式"跳过"报告）
    console.warn("[FileVerthys] 待重试去重键补释放异常", e);
  }

  try {
    const result = await runFileImport(
      list.map((f) => ({ path: f.path, name: f.name, mime: getMimeFromName(f.name) })),
      password,
      importDeps,
    );

    // 列表提交：仅 meta 记录已确认（metaId > 0）的条目进入列表与缓存；
    // 失败文件的块留在台账中由孤儿回收处理，不做前端补偿删除
    const newItems: FileEntry[] = result.entries.map((e) => ({
      id: nextLocalId(),
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
      // dataSize 取真实字节数（estimateBase64Size是缓存字节预算的单一权威源）；
      // 直接传 base64 长度会把单条记录高估约 33%
      addFullRecord(e.metaId, TYPE_FILEVERTHYS_META, e.metaName, e.metaB64, estimateBase64Size(e.metaB64));
    }
    if (newItems.length > 0) {
      pushShallowItems(files, newItems);
    }
    syncModuleCache();

    // 持久化：三态判别（ok / partial_persisted / not_persisted）。
    // 二态 persistVerthys 会把"已 fsync 但落盘结构自查未过"也判为成功，
    // 结构性风险被静默吞掉；这里对两种异常分别给出如实告知。
    let persistKind: "ok" | "partial_persisted" | "not_persisted" = "not_persisted";
    try { persistKind = (await persistVerthysDetailed()).kind; } catch (e) { console.error("[onImport] persistVerthysDetailed 异常", e); }
    if (persistKind === "not_persisted") {
      showError("文件已加密导入内存但持久化失败，重启后可能丢失。请勿关闭应用，尝试重新导入或联系支持");
    } else if (persistKind === "partial_persisted") {
      showError("文件已落盘，但落盘结构自查未通过：请重启后核对文件列表");
    }

    if (result.error) {
      showError(`导入初始化失败：${result.error}`);
    } else {
      if (result.failCount > 0) {
        const head = result.failures[0];
        const more = result.failCount > 1 ? ` 等 ${result.failCount} 个文件` : "";
        showError(`导入失败：${head.name}｜${fileImportErrorMessage(head.code)}${more}`);
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
    // 口令不驻留：导入会话结束后立即释放引用与开关（明文口令不留到下次导入）
    docPassword.value = "";
    usePassword.value = false;
  }
};

/**
 * 按需回填块载荷。
 *
 * 列表与模块缓存只保留展示字段（见 FileEntry 中 chunkDataB64 的注释与
 * syncModuleCache 的投影），因此缓存命中的条目、以及历史内联形态的条目
 * 在导出/删除前需要按 metaId 读取一次完整元数据。
 * 读取失败时原样返回：删除仍可只删 metaId（残留块由孤儿回收），不阻断用户；
 * 导出则由布局校验给出"元数据不完整"的明确结论。
 */
const hydrateFilePayload = async (f: FileEntry): Promise<FileEntry> => {
  const hasPayload = Array.isArray(f.chunkIds) || Array.isArray(f.chunkDataB64);
  if (hasPayload || f.corrupt || !f.metaId || !isTauri) return f;
  try {
    const rec = await verthysGetRecord(f.metaId);
    if (!rec) return f;
    const meta = JSON.parse(new TextDecoder().decode(base64ToBytes(rec.dataB64)));
    const patched: FileEntry = {
      ...f,
      name: typeof meta.name === "string" ? meta.name : f.name,
      size: typeof meta.size === "number" ? meta.size : f.size,
      mime: typeof meta.mime === "string" ? meta.mime : f.mime,
      totalChunks: typeof meta.totalChunks === "number" ? meta.totalChunks : f.totalChunks,
      encrypted: typeof meta.encrypted === "boolean" ? meta.encrypted : f.encrypted,
      chunkIds: Array.isArray(meta.chunkIds) ? meta.chunkIds : undefined,
      chunkDataB64: Array.isArray(meta.chunkDataB64) && meta.chunkDataB64.length > 0
        ? meta.chunkDataB64
        : undefined,
      chunkHashes: Array.isArray(meta.chunkHashes) ? meta.chunkHashes : undefined,
      chunkSize: typeof meta.chunkSize === "number" ? meta.chunkSize : undefined,
      fileHash: typeof meta.fileHash === "string" ? meta.fileHash : f.fileHash,
      kdf: meta.kdf ?? f.kdf,
      passwordCheck: typeof meta.passwordCheck === "string" ? meta.passwordCheck : f.passwordCheck,
    };
    // 0 字节历史内联条目：块引用归一为空数组，避免布局校验误判"元数据不完整"
    if (!Array.isArray(patched.chunkIds) && !patched.chunkDataB64 && patched.size === 0) {
      patched.chunkIds = [];
    }
    const idx = files.value.findIndex((x) => x.id === f.id);
    if (idx >= 0) updateShallowItem(files, idx, patched);
    return patched;
  } catch (e) {
    console.warn("[FileVerthys] 块载荷回填失败，按现有字段继续", f.name, e);
    return f;
  }
};

/** 收尾后释放回填的内联块密文：整份文件体积的密文不常驻列表 */
const releaseFilePayload = (id: number) => {
  const idx = files.value.findIndex((x) => x.id === id);
  if (idx < 0 || !files.value[idx].chunkDataB64) return;
  updateShallowItem(files, idx, { chunkDataB64: undefined });
};

/* ===== 保存到本地（流式导出：进度可观测、可取消、条目级防重入） ===== */
const showKeyDialog = ref(false);
const keyInput = ref("");
const saveTarget = ref<FileEntry | null>(null);

/* 导出会话状态：模块内同一时刻只允许一条导出流（进度/取消为单会话状态），
   条目级集合用于把对应卡片的按钮切成「保存中…」并阻断删除 */
const exportingIds = ref(new Set<number>());
const exporting = computed(() => exportingIds.value.size > 0);
const exportingFile = ref("");
const exportDone = ref(0);
const exportTotal = ref(0);
const exportPercent = ref(0);
const exportCancelRequested = ref(false);
/* 取消请求已发出但管道尚未收敛：按钮先隐藏，避免重复点击 */
const exportCancelPending = ref(false);

/** 关闭口令窗并清空输入：明文口令不随窗口关闭残留在内存 */
const closeKeyDialog = () => {
  showKeyDialog.value = false;
  keyInput.value = "";
  saveTarget.value = null;
};

const requestExportCancel = () => {
  if (!exporting.value || exportCancelRequested.value) return;
  exportCancelRequested.value = true;
  exportCancelPending.value = true;
};

/* ===== 三个自绘弹窗的模态绑定（滚动锁 / Esc 栈序 / 焦点归还 / Tab 循环） ===== */
const importDialogRef = ref<HTMLElement | null>(null);
const keyDialogRef = ref<HTMLElement | null>(null);
const conflictDialogRef = ref<HTMLElement | null>(null);

const importModal = createModalBinding({
  close: () => { showImportDialog.value = false; },
  root: () => importDialogRef.value,
});
const keyModal = createModalBinding({
  close: closeKeyDialog,
  root: () => keyDialogRef.value,
});
const conflictModal = createModalBinding({
  close: () => resolveSessionConflict(false),
  root: () => conflictDialogRef.value,
});

watch(showImportDialog, (open) => {
  if (open) void importModal.engage();
  else importModal.release();
});
watch(showKeyDialog, (open) => {
  if (open) void keyModal.engage();
  else keyModal.release();
});
watch(showSessionConflict, (open) => {
  if (open) void conflictModal.engage();
  else conflictModal.release();
});

const onImportDialogKeydown = (e: KeyboardEvent): void => importModal.keydown(e);
const onKeyDialogKeydown = (e: KeyboardEvent): void => keyModal.keydown(e);
const onConflictDialogKeydown = (e: KeyboardEvent): void => conflictModal.keydown(e);

const onSave = (f: FileEntry) => {
  if (f.corrupt) {
    showError("该条目元数据已损坏，无法保存；如需清理请删除该条目");
    return;
  }
  if (exporting.value || exportingIds.value.has(f.id)) return;
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
  const target = saveTarget.value;
  try {
    const saved = await doSave(target, keyInput.value);
    if (saved) closeKeyDialog();
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
  if (f.corrupt) {
    showError("该条目元数据已损坏，无法保存");
    return false;
  }
  if (exporting.value || exportingIds.value.has(f.id)) {
    if (exporting.value) showError("已有保存任务在进行中，请稍后再试");
    return false;
  }

  // 先占位再加锁：回填块载荷/选路径都是 await，若在加锁之后再 await，
  // 双击「保存」的第二次调用会在锁生效前穿过闸门（并发两条导出流）
  exportingIds.value.add(f.id);
  exportingFile.value = f.name;
  exportDone.value = 0;
  exportTotal.value = f.totalChunks;
  exportPercent.value = f.totalChunks === 0 ? 100 : 0;
  exportCancelRequested.value = false;
  exportCancelPending.value = false;

  let source = f;
  try {
    // 缓存命中/历史内联条目先回填块载荷（列表不驻留整份密文）
    source = await hydrateFilePayload(f);
    exportingFile.value = source.name;
    exportTotal.value = source.totalChunks;
    exportPercent.value = source.totalChunks === 0 ? 100 : 0;
    const ext = extOf(source.name);

    const result = await runFileExport(source, password, {
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
      // 逐块进度（写入完成后上报，进度不先于实际落盘）
      onProgress: (done, total) => {
        exportDone.value = done;
        exportTotal.value = total;
        exportPercent.value = total === 0 ? 100 : Math.round((done / total) * 100);
      },
      // 取消：在块边界生效（已写入的暂存由 abort 统一清理）
      isCancelled: () => exportCancelRequested.value,
    });

    if (result.ok) {
      showToast(`已保存到本地: ${source.name}`);
      return true;
    }
    if (result.code === "CANCELLED") {
      if (exportCancelRequested.value) showToast("已取消保存");
      return false;
    }
    showError(result.message);
    return false;
  } finally {
    exportingIds.value.delete(f.id);
    exportCancelRequested.value = false;
    exportCancelPending.value = false;
    exportPercent.value = 0;
    exportDone.value = 0;
    exportTotal.value = 0;
    releaseFilePayload(f.id);
  }
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

/**
 * 列表条目 → 缓存投影：只保留展示字段。
 *
 * 块引用/逐块哈希/派生参数/整份内联密文一律不写缓存——历史内联条目的
 * `chunkDataB64` 可等于整个文件体积（上限 2 GiB），写进模块缓存后即使
 * 切走模块仍常驻堆；导出/删除需要时按 metaId 懒读取（hydrateFilePayload）。
 */
const toCacheEntries = (list: FileEntry[]): FileEntry[] =>
  list.map((f) => ({
    id: f.id,
    name: f.name,
    size: f.size,
    mime: f.mime,
    totalChunks: f.totalChunks,
    encrypted: f.encrypted,
    metaId: f.metaId,
    corrupt: f.corrupt,
  }));

/** 同步模块列表缓存：按"数据层视图"写入——已删除待落盘（persist-retry）
    条目不计入缓存，避免切模块重挂载后以常规卡片复活（此时数据层已无
    该记录：保存必失败、删除因条目缺失被整体拒绝，形成幽灵条目）。 */
const syncModuleCache = () => {
  setModuleCache(
    "fileverthys",
    toCacheEntries(files.value.filter((x) => deleteStates.value.get(x.id) !== "persist-retry")),
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
  // 导出读取块记录期间不允许删除同一条目：否则导出必然落到"第 N 块缺失"
  if (exportingIds.value.has(f.id)) {
    showError("该文件正在保存，请等待保存结束后再删除");
    return;
  }
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
    // 缓存命中/历史内联条目先回填块引用与去重键（删除需要完整的记录集合）
    const source = await hydrateFilePayload(f);
    result = await runFileDelete(toDeleteSource(source), deleteDeps);
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
    // 去重键在缓存投影中不保留：重放落盘前同样需要回填，否则键不会被释放
    const source = await hydrateFilePayload(f);
    result = await retryFileDeletePersist(toDeleteSource(source), deleteDeps);
  } catch {
    deleteStates.value.set(f.id, "persist-retry");
    showError("删除落盘仍失败，请重试");
    return;
  }
  settleDeleteResult(f, result);
};

/* ===== 卡片光泽追踪（共享实现；3D 视差倾斜已按用户决策移除，Wave 53） ===== */
const { onCardMove, onCardLeave } = useCardShine();

/** 元数据不可读的占位条目：名称退化为记录号，仅保留删除入口 */
const makeCorruptEntry = (id: number): FileEntry => ({
  id: nextLocalId(),
  name: `文件记录 #${id}`,
  size: 0,
  mime: "application/octet-stream",
  totalChunks: 0,
  encrypted: false,
  metaId: id,
  corrupt: true,
});

/**
 * 元数据 JSON → 列表条目。
 *
 * 历史内联形态的 `chunkDataB64`（可等于整份文件体积）**不进驻列表**：
 * 仅记 metaId，导出/删除前按需回填（hydrateFilePayload）。
 */
const toFileEntry = (id: number, meta: Record<string, unknown>): FileEntry => ({
  id: nextLocalId(),
  name: typeof meta.name === "string" ? meta.name : `文件记录 #${id}`,
  size: typeof meta.size === "number" ? meta.size : 0,
  mime: typeof meta.mime === "string" ? meta.mime : "application/octet-stream",
  totalChunks: typeof meta.totalChunks === "number" ? meta.totalChunks : 0,
  encrypted: meta.encrypted === true,
  metaId: id,
  chunkIds: Array.isArray(meta.chunkIds) ? (meta.chunkIds as number[]) : undefined,
  chunkHashes: Array.isArray(meta.chunkHashes) ? (meta.chunkHashes as string[]) : undefined,
  chunkSize: typeof meta.chunkSize === "number" ? meta.chunkSize : undefined,
  fileHash: typeof meta.fileHash === "string" ? meta.fileHash : undefined,
  kdf: meta.kdf as FileKdfV2 | undefined,
  passwordCheck: typeof meta.passwordCheck === "string" ? meta.passwordCheck : undefined,
});

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
  let hasNewFiles = false;
  // 元数据不可读的条目不静默丢弃：显式占位 + 一次汇总告知
  let corruptCount = 0;
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
  //   照片数据块（二进制密文 parse 失败 → 跳过），仅保留 FileVerthys 元数据。
  //   该索引与照片块混编，解析失败属预期，不得记为"损坏条目"。
  const legacyFallback = metaIds.length === 0;
  if (legacyFallback) {
    metaIds = idsOf(TYPE_FILEVERTHYS_META_OLD);
  }

  // 增量过滤：maxRecordId 是缓存内最大 metaId，大于它的才是本轮新增
  const pendingMetaIds = metaIds.filter(id => id > maxRecordId);
  if (pendingMetaIds.length > 0) {
    // 1. 批量获取所有 meta 记录数据（扫描缓存优先，并行 IPC 回退）
    const metaB64Map = await getRecordsDataB64Batch(pendingMetaIds);
    for (const id of pendingMetaIds) {
      const metaDataB64 = metaB64Map.get(id);
      if (!metaDataB64) {
        // 取不到载荷 ≠ 记录不存在：主路径下必然是本模块元数据，
        // 必须保留为不可读条目交由用户删除（静默丢弃会让文件从列表消失）
        if (!legacyFallback) {
          newItems.push(makeCorruptEntry(id));
          corruptCount += 1;
          hasNewFiles = true;
        }
        continue;
      }
      try {
        const meta = JSON.parse(new TextDecoder().decode(base64ToBytes(metaDataB64)));
        // 历史内联格式：meta 内嵌块密文（整份密文不进驻列表，按 metaId 懒回填）
        // 外置格式：meta 只保存块引用（chunkIds）。接纳条件按"字段为数组"判定：
        //   0 字节文件的块引用恰为空数组，按长度判定会把它永久排除在列表之外。
        if (Array.isArray(meta.chunkDataB64) || Array.isArray(meta.chunkIds)) {
          newItems.push(toFileEntry(id, meta));
          hasNewFiles = true;
        }
      } catch (e) {
        if (legacyFallback) {
          // 旧索引中的照片块等二进制记录：解析失败属预期
          console.warn("[FileVerthys] 旧类型记录解析失败（预期：非元数据记录）", id, e);
        } else {
          newItems.push(makeCorruptEntry(id));
          corruptCount += 1;
          hasNewFiles = true;
        }
      }
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
  if (corruptCount > 0) {
    showError(`${corruptCount} 个文件的元数据无法读取，已标记为损坏（仅可删除）`);
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
  /* 模态栈兜底出栈：卸载时若仍有窗开着，滚动锁与栈序必须归还 */
  importModal.release();
  keyModal.release();
  conflictModal.release();
});

/* 修复「页面覆盖」：切换模块时同步关闭所有 Teleport 弹窗，杜绝残留覆盖 */
import { useModuleDialogGuard } from "../../composables/useModuleDialogGuard";
useModuleDialogGuard("verthys", () => {
  showImportDialog.value = false;
  // 口令窗必须走 closeKeyDialog（同时清空口令引用），不能只置 false
  closeKeyDialog();
  showDeleteConfirm.value = false;
  resolveSessionConflict(false);
  sessionConflictResolver = null;
});
</script>

<style scoped>
.file-verthys { width: 100%; height: 100%; display: flex; flex-direction: column; gap: 14px; overflow: hidden; position: relative; }

/* 顶部栏：星野导航带仅承载布局（无边框/圆角/投影 —— 底板与左右溶解边界由 StarlitSky 承担） */
.search-bar { display: flex; align-items: center; gap: 12px; padding: 9px 10px 9px 14px; flex-shrink: 0; }
.search-inner { display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0; }
.search-icon { width: 14px; height: 14px; color: var(--text-muted); flex-shrink: 0; }
.search-input { flex: 1; background: transparent; border: none; color: var(--text-primary); font-size: 13px; outline: none; font-family: var(--font); min-width: 0; }
.search-input::placeholder { color: var(--text-muted); }

/* 卡片网格 */
.card-grid { flex: 1; overflow-y: auto; overflow-x: hidden; display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; align-content: start; padding-right: 4px; }
/* 卡片入场已收敛到全局「模块步入编排」（styles/animations.css —
   .reveal-host.is-entering .reveal-item）：搜索栏与卡片都承载文字，
   入场一律只走不透明度（位移会让字形抗锯齿在合成层与主层之间跳变）。 */
/* 悬浮反馈只走合成器路径（opacity）：阴影/边框全状态恒定（.glass 基线）。
   原实现在 hover 上过渡 box-shadow（大半径模糊阴影是重绘型属性）并叠加
   青色柔光——滚动中卡片掠过指针时逐帧重绘，且属禁用的大面积发光；
   提亮改由 .card-shine 光层承担（Wave 54 收口），此处不得恢复。 */
.acct-card { position: relative; padding: 14px 16px 14px 18px; background: var(--bar-surface); }
.card-accent { position: absolute; left: 0; top: 10px; bottom: 10px; width: 2px; background: linear-gradient(180deg, transparent, var(--accent), transparent); opacity: 0; transition: opacity 0.3s; border-radius: 1px; }
.acct-card:hover .card-accent { opacity: 1; }
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
/* 错误/损坏语义：状态红文字直陈（不加底色方框、不加图标） */
.info-item.is-error { color: var(--danger); }
/* 动作区悬浮揭示；焦点进入卡片时同样揭示——否则 Tab 到按钮时
   opacity:0 让焦点位置完全不可见（键盘用户失去位置感） */
.card-actions { display: flex; gap: 4px; opacity: 0; transition: opacity 0.3s var(--ease); margin-top: 4px; }
.acct-card:hover .card-actions,
.acct-card:focus-within .card-actions { opacity: 1; }
.mini-btn { background: none; border: none; color: var(--accent); font-size: 11px; cursor: pointer; padding: 2px 8px; border-radius: 3px; transition: color 0.2s var(--ease), background 0.2s var(--ease); letter-spacing: 0.5px; }
.mini-btn:hover { background: rgba(0,212,255,0.1); }
.mini-btn:focus-visible { outline: 1px solid rgba(var(--accent-rgb), 0.55); outline-offset: 2px; }
.mini-btn.danger { color: var(--danger); }
.mini-btn.danger:hover { background: rgba(255,46,99,0.1); }
.mini-btn.danger:focus-visible { outline-color: rgba(255,46,99,0.55); }
/* 禁用态（删除中 / 删除已提交待落盘 / 保存中）：光标与可点击态明确区分 */
.mini-btn:disabled { cursor: not-allowed; opacity: 0.45; }
.mini-btn:disabled:hover { background: none; }

/* 对话框 */
.dialog-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.74); display: flex; align-items: center; justify-content: center; z-index: 1000; }
.dialog { padding: 28px; min-width: 440px; max-width: 90vw; animation: dialog-in 0.4s var(--ease); }
/* 模态根以 tabindex="-1" 承接程序化焦点：不绘制焦点框（焦点语义由模态本身承担） */
.dialog:focus, .dialog:focus-visible { outline: none; }
@keyframes dialog-in { from { opacity: 0; } to { opacity: 1; } }
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
.encrypt-row { padding: 10px 12px; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); transition: border-color 0.2s var(--ease), background-color 0.2s var(--ease); margin-bottom: 16px; }
.encrypt-row.on { border-color: rgba(0,212,255,0.25); background: rgba(0,212,255,0.03); }
.encrypt-toggle { display: flex; align-items: center; gap: 8px; cursor: pointer; user-select: none; }
/* 视觉隐藏但保留可聚焦：display:none 会让复选框退出焦点序列，
   键盘用户无法开启「独立访问密码」 */
.encrypt-toggle input {
  position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0;
  border: 0; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap;
}
.encrypt-toggle input:focus-visible + .encrypt-check {
  outline: 1px solid rgba(var(--accent-rgb), 0.55); outline-offset: 2px;
}
.encrypt-check { width: 14px; height: 14px; border: 1px solid var(--border-glass); border-radius: 3px; position: relative; transition: border-color 0.2s var(--ease), background-color 0.2s var(--ease); flex-shrink: 0; }
.encrypt-row.on .encrypt-check { background: var(--accent); border-color: var(--accent); }
.encrypt-row.on .encrypt-check::after { content: ""; position: absolute; left: 4px; top: 1px; width: 4px; height: 8px; border: solid #000; border-width: 0 2px 2px 0; transform: rotate(45deg); }
.encrypt-label { font-size: 11px; color: var(--text-secondary); }
.encrypt-key-input { margin-top: 8px; }
.encrypt-key-input .input { width: 100%; }
/* 字段级校验提示：错误语义用状态红文字直陈（不加底色框、不加图标） */
.field-hint { margin: 6px 0 0; font-size: 10px; line-height: 1.5; font-family: var(--font); }
.field-hint.is-error { color: var(--danger); }

.dialog-actions { display: flex; justify-content: flex-end; gap: 10px; padding-top: 14px; border-top: 1px solid var(--border-glass); }

/* 并发导入互斥确认 */
.session-conflict-text { font-size: 12px; line-height: 1.7; color: var(--text-secondary); font-family: var(--font); margin-bottom: 6px; }

/* 密钥对话框 */
.key-dialog { min-width: 360px; }
.key-target { font-size: 12px; color: var(--text-secondary); font-family: var(--font); margin-bottom: 14px; }
</style>
