<!--
  CertManager.vue — 重要证书 / 密钥管理模块
  v3: 复用 VerthysSearchBar / VerthysDialog / ClipToast / useCardTilt / useClipToast / verthys-common.css
-->
<template>
  <div class="cert-manager verthys-module">
    <!-- 顶部错误提示弹窗 -->
    <Teleport to="body">
      <transition name="err-toast">
        <div v-if="errorMsg" class="error-toast glass"><span class="toast-dot"></span>{{ errorMsg }}</div>
      </transition>
    </Teleport>

    <!-- 搜索栏（带类型筛选） -->
    <VerthysSearchBar v-model="searchKey" placeholder="搜索证书 / 密钥…" add-label="新增" @add="onAdd">
      <template #filters>
        <div class="search-divider"></div>
        <div class="type-chips">
          <button
            v-for="t in types"
            :key="t.id"
            class="type-chip"
            :class="{ active: typeFilter === t.id }"
            @click="typeFilter = typeFilter === t.id ? '' : t.id"
          >{{ t.label }}</button>
        </div>
      </template>
    </VerthysSearchBar>

    <!-- 证书卡片网格：≥300 条启用虚拟滚动（项1），小列表保留原 v-for 路径零开销 -->
    <VirtualCardGrid
      v-if="filteredCerts.length >= 300"
      :items="filteredCerts"
      :item-height="180"
      :min-column-width="300"
      v-slot="{ item: c, index }"
    >
      <div
        class="verthys-card glass"
        :class="`status-${c.status}`"
        :style="{ '--i': index }"
        @mousemove="onCardMove($event)"
        @mouseleave="onCardLeave($event)"
      >
        <div class="card-accent" :class="`accent-${c.status}`"></div>
        <div class="card-head">
          <span class="card-title" v-tip="c.name">{{ c.name }}</span>
          <span class="type-badge">{{ getTypeLabel(c.type) }}</span>
        </div>
        <div class="cert-info">
          <span class="info-item">
            <span class="info-label">到期</span>
            <span :class="`expiry-${c.status}`">{{ c.expiry || '永久' }}</span>
          </span>
        </div>
        <!-- 密钥内容行 -->
        <div v-if="c.content" class="secret-row">
          <span class="secret-text" :class="{ masked: !c.contentVisible }">{{ c.contentVisible ? c.content : '••••••••••••••••••••' }}</span>
          <div class="secret-actions">
            <button class="icon-btn" @click.stop="toggleContent(c)" v-tip="c.contentVisible ? '隐藏' : '显示'">
              <svg v-if="!c.contentVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
            </button>
            <button class="icon-btn" @click.stop="copyContent(c)" v-tip="'复制'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        </div>
        <div v-if="c.note" class="cert-note" v-tip="c.note">{{ c.note }}</div>
        <div class="card-actions">
          <button class="mini-btn" @click.stop="onEdit(c)">编辑</button>
          <button class="mini-btn danger" @click.stop="onDelete(c)">删除</button>
        </div>
        <div class="card-shine"></div>
      </div>
    </VirtualCardGrid>
    <div v-else class="card-grid">
      <div
        v-for="(c, idx) in filteredCerts"
        :key="c.id"
        class="verthys-card glass"
        :class="`status-${c.status}`"
        :style="{ '--i': idx }"
        @mousemove="onCardMove($event)"
        @mouseleave="onCardLeave($event)"
      >
        <div class="card-accent" :class="`accent-${c.status}`"></div>
        <div class="card-head">
          <span class="card-title" v-tip="c.name">{{ c.name }}</span>
          <span class="type-badge">{{ getTypeLabel(c.type) }}</span>
        </div>
        <div class="cert-info">
          <span class="info-item">
            <span class="info-label">到期</span>
            <span :class="`expiry-${c.status}`">{{ c.expiry || '永久' }}</span>
          </span>
        </div>
        <!-- 密钥内容行 -->
        <div v-if="c.content" class="secret-row">
          <span class="secret-text" :class="{ masked: !c.contentVisible }">{{ c.contentVisible ? c.content : '••••••••••••••••••••' }}</span>
          <div class="secret-actions">
            <button class="icon-btn" @click.stop="toggleContent(c)" v-tip="c.contentVisible ? '隐藏' : '显示'">
              <svg v-if="!c.contentVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
            </button>
            <button class="icon-btn" @click.stop="copyContent(c)" v-tip="'复制'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        </div>
        <div v-if="c.note" class="cert-note" v-tip="c.note">{{ c.note }}</div>
        <div class="card-actions">
          <button class="mini-btn" @click.stop="onEdit(c)">编辑</button>
          <button class="mini-btn danger" @click.stop="onDelete(c)">删除</button>
        </div>
        <div class="card-shine"></div>
      </div>

      <CosmicEmpty v-if="!loading && filteredCerts.length === 0" text="暂无证书 / 密钥" />
    </div>

    <!-- 编辑对话框 -->
    <VerthysDialog v-model="showDialog" :title="editing ? '编辑证书' : '新增证书或密钥'" @save="onSave">
      <div class="form-field full"><label>名称</label><input class="input" v-model="form.name" placeholder="如 生产环境 SSL 证书" /></div>
      <div class="form-field">
        <label>类型</label>
        <select class="input sc-select" v-model="form.type">
          <option value="" disabled>请选择证书或密钥类型</option>
          <option v-for="t in types" :key="t.id" :value="t.id">{{ t.label }}</option>
        </select>
      </div>
      <div class="form-field">
        <label>到期日期</label>
        <div class="date-wrap" @click="openDatePicker">
          <input class="input sc-select date-input" :class="{ 'has-value': form.expiry }" type="date" v-model="form.expiry" ref="dateInputRef" />
          <span v-if="!form.expiry" class="date-placeholder">请选择</span>
        </div>
      </div>
      <div class="form-field full">
        <label>内容 / 密钥</label>
        <div class="content-input-area"
          @dragover.prevent="onDragOver"
          @dragleave.prevent="onDragLeave"
          @drop.prevent="onDrop"
          :class="{ 'drag-active': isDragging }">
          <textarea class="input textarea" v-model="form.content" rows="4" placeholder="粘贴证书或密钥内容，或拖拽文件到此处…"></textarea>
          <div class="upload-btn-row">
            <button class="btn btn-sm upload-btn" @click="triggerFileUpload" type="button">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
              上传文件导入
            </button>
            <span v-if="uploadedFileName" class="uploaded-name">{{ uploadedFileName }}</span>
          </div>
          <input type="file" ref="fileInputRef" class="hidden-file-input" accept=".pem,.crt,.key,.der,.cer,.pub" @change="onFileSelected" />
        </div>
      </div>
      <div class="form-field full"><label>备注</label><input class="input" v-model="form.note" placeholder="可选备注信息" /></div>
      <template #error v-if="formError">
        <div class="form-error">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          {{ formError }}
        </div>
      </template>
    </VerthysDialog>

    <!-- 复制提示 -->
    <ClipToast :countdown="clipCountdown" text="已复制" />

    <!-- 非阻塞加载：无底板居中展示，加载完成自动消失 -->
    <CosmicLoading :show="loading" text="正在加载证书数据…" />

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
import { ref, shallowRef, computed, onMounted } from "vue";
import {
  verthysAddRecord, verthysDeleteRecord,
  bytesToBase64, base64ToBytes,
} from "../../lib/verthys";
import {
  updateShallowItem, pushShallowItems, replaceShallowArray,
  clearShallowArray, removeShallowItems,
} from "../../utils/shallow-array";
import { persistVerthys, deleteAndPersist, getModuleCache, setModuleCache,
  addFullRecord,
  invalidateSummaryRecord, invalidateFullRecord, clearSummaryCache, clearFullRecordCache,
  /* 旧全量扫描兜底（摘要缓存为空时回退） */
  ensureRecordScanSafe, getRecordIdsByType,
  invalidateScannedRecord, clearRecordScanCache, getRecordsDataB64Batch } from "../../lib/keyManager";
import { TYPE_CERT, TYPE_CERT_LIST, TYPE_CERT_LEGACY } from "../../constants/record_types";
import { useClipToast } from "../../composables/useClipToast";
import { useCardTilt } from "../../composables/useCardTilt";
import { useErrorToast } from "../../composables/useErrorToast";
import VerthysSearchBar from "../common/verthys-ui/VerthysSearchBar.vue";
import VerthysDialog from "../common/verthys-ui/VerthysDialog.vue";
import ClipToast from "../common/verthys-ui/ClipToast.vue";
import CosmicLoading from "../common/cosmic/CosmicLoading.vue";
import CosmicEmpty from "../common/cosmic/CosmicEmpty.vue";
import ConfirmDelete from "../common/verthys-ui/ConfirmDelete.vue";
import VirtualCardGrid from "../common/verthys-ui/VirtualCardGrid.vue";

/* ★ 企业级根治：顶部错误提示弹窗（.error-toast，2.5s 自动消失） */
const { errorMsg, showError } = useErrorToast();

/**
 * 独立记录存储模式（参考 PhotoAlbum / AccountVerthys）：
 *   每个证书一条独立 verthys 记录（TYPE_CERT），互不覆盖。
 *   - 新增：verthysAddRecord → 保存 recordId
 *   - 编辑：verthysAddRecord(新) → verthysDeleteRecord(旧) → 更新 recordId
 *   - 删除：verthysDeleteRecord(recordId)
 *   - 加载：扫描所有 TYPE_CERT 记录
 *   彻底避免整体替换模式（add 新 + delete 旧 + flush）的并发竞态
 *   导致数据丢失/恢复问题。
 *
 * ★ 企业级根治：TYPE_CERT 从 record_types.ts 导入，不再本地定义。
 */

/* 非阻塞加载状态（无底板居中展示，加载完成自动消失） */
const loading = ref(false);

interface CertEntry {
  id: number;          // 内存唯一 ID
  recordId?: number;   // verthys 记录 ID（用于编辑/删除）
  name: string;
  type: string;
  expiry: string;
  status: "valid" | "expiring" | "expired";
  content: string;
  note: string;
  contentVisible?: boolean;
}

const types = [
  { id: "ssl", label: "SSL 证书" },
  { id: "rsa", label: "RSA 私钥" },
  { id: "ecc", label: "ECC 密钥" },
  { id: "ca", label: "CA 根证书" },
  { id: "der", label: "DER 证书" },
  { id: "pem", label: "PEM 密钥" },
  { id: "ssh", label: "SSH 密钥" },
  { id: "api", label: "API 密钥" },
  { id: "pgp", label: "PGP 密钥" },
];

const searchKey = ref("");
const typeFilter = ref("");
/* ★ 项2：shallowRef 替代 ref，避免 Vue 对 certs 数组内每条记录深度代理
 * （每条记录含 content/密钥等敏感字段，万条记录深度代理开销 200-500ms） */
const certs = shallowRef<CertEntry[]>([]);

const filteredCerts = computed(() => {
  const k = searchKey.value.trim().toLowerCase();
  const t = typeFilter.value;
  return certs.value.filter(c =>
    (!k || c.name.toLowerCase().includes(k)) &&
    (!t || c.type === t)
  );
});

const getTypeLabel = (type: string) => types.find(t => t.id === type)?.label || type;

const computeStatus = (expiry: string): "valid" | "expiring" | "expired" => {
  if (!expiry) return "valid";
  const now = new Date();
  const exp = new Date(expiry);
  const diff = (exp.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
  if (diff < 0) return "expired";
  if (diff < 30) return "expiring";
  return "valid";
};

/* 卡片 3D 视差 */
const { onCardMove, onCardLeave } = useCardTilt();

/* 文件上传 */
const isDragging = ref(false);
const uploadedFileName = ref("");
const fileInputRef = ref<HTMLInputElement | null>(null);
const dateInputRef = ref<HTMLInputElement | null>(null);

const openDatePicker = () => {
  const el = dateInputRef.value;
  if (!el) return;
  try { (el as any).showPicker?.(); } catch { el.focus(); }
};

const triggerFileUpload = () => { fileInputRef.value?.click(); };

const readFileContent = async (file: File) => {
  const text = await file.text();
  form.value.content = text;
  uploadedFileName.value = file.name;
};

const onFileSelected = async (e: Event) => {
  const target = e.target as HTMLInputElement;
  if (target.files && target.files[0]) await readFileContent(target.files[0]);
};

const onDragOver = () => { isDragging.value = true; };
const onDragLeave = () => { isDragging.value = false; };
const onDrop = async (e: DragEvent) => {
  isDragging.value = false;
  if (e.dataTransfer && e.dataTransfer.files[0]) await readFileContent(e.dataTransfer.files[0]);
};

/* 序列化 */
const serializeCert = (cert: Omit<CertEntry, "id">): string => {
  const json = JSON.stringify(cert);
  const encoder = new TextEncoder();
  return bytesToBase64(encoder.encode(json));
};

const deserializeCert = (b64: string): Omit<CertEntry, "id"> => {
  const bytes = base64ToBytes(b64);
  const decoder = new TextDecoder();
  return JSON.parse(decoder.decode(bytes));
};

/** 反序列化旧列表记录（仅用于迁移） */
const deserializeCertList = (b64: string): Omit<CertEntry, "id">[] => {
  const bytes = base64ToBytes(b64);
  return JSON.parse(new TextDecoder().decode(bytes));
};

const loadCerts = async () => {
  // 0. 缓存优先：先用缓存数据即时渲染
  const cached = getModuleCache<CertEntry[]>("certs");
  let maxRecordId = 0;
  if (cached.data && cached.data.length > 0) {
    // ★ 项2：shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
    replaceShallowArray(certs, cached.data);
    // 计算缓存中最大的 recordId，作为增量扫描起点（参考 PhotoAlbum）
    maxRecordId = cached.data.reduce((max, c) => Math.max(max, c.recordId || 0), 0);
    loading.value = false;
  } else {
    loading.value = true;
  }

  // 1. 共享扫描：首次调用扫描全部记录并缓存，后续模块直接复用（零 IPC 调用）
  //    一次扫描同时收集新格式(TYPE_CERT)和旧格式(列表/单条)记录
  const found: { id: number; fields: Omit<CertEntry, "id"> }[] = [];
  const needMigration = maxRecordId === 0; // 缓存无效时才需要迁移旧格式
  let listRecordId: number | null = null;
  let listFields: Omit<CertEntry, "id">[] | null = null;
  const legacyRecords: { id: number; fields: Omit<CertEntry, "id"> }[] = [];

  // ★ 性能修复：改走 recordScanCache + 批量获取（落实 2.5s 预算）
  //    原方案：ensureSummaryScanSafe + for 循环串行 getFullRecord（N 条 = N 次串行 IPC，
  //            100 条 ≈ 7.5s，300 条 ≈ 22s，与后台 ensureRecordScan 抢同一常驻 worker → 30s）
  //    新方案：ensureRecordScanSafe（后台 startBackgroundTasks 已扫描则瞬时增量返回）
  //            + getRecordsDataB64Batch（扫描缓存命中零 IPC，未命中/大体积并行 IPC 回退）
  //            总耗时 < 2.5s。内存优先合并保证用户并发编辑不丢失。
  await ensureRecordScanSafe();

  // 1. 批量获取新格式 TYPE_CERT 记录数据（扫描缓存优先，并行 IPC 回退）
  const allCertIds = getRecordIdsByType(TYPE_CERT);
  const newCertIds = allCertIds.filter(id => id > maxRecordId);
  if (newCertIds.length > 0) {
    const b64Map = await getRecordsDataB64Batch(newCertIds);
    for (const id of newCertIds) {
      const certB64 = b64Map.get(id);
      if (!certB64) continue;
      try {
        const fields = deserializeCert(certB64);
        found.push({ id, fields });
      } catch { /* 跳过损坏记录 */ }
    }
  }

  // 2. 缓存无效时检查旧格式记录用于迁移（同样批量获取，消除串行 IPC）
  if (needMigration) {
    // TYPE_CERT_LIST（整体列表旧格式）
    const listIds = getRecordIdsByType(TYPE_CERT_LIST);
    if (listIds.length > 0) {
      const listB64Map = await getRecordsDataB64Batch(listIds);
      for (const id of listIds) {
        const listB64 = listB64Map.get(id);
        if (!listB64) continue;
        listRecordId = id;
        try { listFields = deserializeCertList(listB64); } catch { /* */ }
        if (listFields) break; // 只需一条列表记录
      }
    }
    // TYPE_CERT_LEGACY（单条旧格式）
    const legacyIds = getRecordIdsByType(TYPE_CERT_LEGACY);
    if (legacyIds.length > 0) {
      const legacyB64Map = await getRecordsDataB64Batch(legacyIds);
      for (const id of legacyIds) {
        const legacyB64 = legacyB64Map.get(id);
        if (!legacyB64) continue;
        try { legacyRecords.push({ id, fields: deserializeCert(legacyB64) }); } catch { /* */ }
      }
    }
  }

  // 2. 有新格式记录 → 追加到现有列表（缓存有效时是增量追加，缓存无效时是构建新列表）
  if (found.length > 0) {
    let nextMemId = certs.value.length > 0
      ? Math.max(...certs.value.map(c => c.id)) + 1
      : 1;
    // ★ 项2：批量构建新条目后一次性 pushShallowItems，避免循环内多次触发响应式
    const newItems: CertEntry[] = [];
    for (const { id, fields } of found) {
      newItems.push({
        id: nextMemId++,
        recordId: id,
        ...fields,
        status: computeStatus(fields.expiry),
      });
    }
    pushShallowItems(certs, newItems);
    setModuleCache("certs", certs.value);
    loading.value = false;
    return;
  }

  // 3. 缓存有效但无新记录 → 直接用缓存，无需迁移
  if (cached.data && cached.data.length > 0) {
    loading.value = false;
    return;
  }

  // 4. 缓存无效且无新格式 → 迁移旧格式（仅首次加载执行）
  if (needMigration) {
    const fieldsToMigrate = (listFields && listFields.length > 0)
      ? listFields
      : legacyRecords.map(r => r.fields);

    if (fieldsToMigrate.length > 0) {
      const migrated: CertEntry[] = [];
      let nextId = 1;
      for (const fields of fieldsToMigrate) {
        const certData = {
          name: fields.name, type: fields.type, expiry: fields.expiry,
          status: computeStatus(fields.expiry), content: fields.content, note: fields.note,
        };
        const dataB64 = serializeCert(certData);
        const newRid = await verthysAddRecord(TYPE_CERT, `cert_${Date.now()}_${migrated.length}`, dataB64);
        migrated.push({
          id: nextId++,
          recordId: newRid ?? undefined,
          ...certData,
        });
      }
      // ★ 项2：shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
      replaceShallowArray(certs, migrated);
      if (listRecordId !== null) {
        try { await verthysDeleteRecord(listRecordId); } catch { /* */ }
      }
      for (const lr of legacyRecords) {
        try { await verthysDeleteRecord(lr.id); } catch { /* */ }
      }
      // ★ 企业级数据持久化修复：检查迁移落盘返回值，失败时提示用户
      let migratePersistOk = false;
      try { migratePersistOk = await persistVerthys(); } catch (e) { console.error("[loadCerts] 迁移 persistVerthys 异常", e); }
      if (!migratePersistOk) {
        showError("证书数据迁移已执行但持久化失败，重启后可能需重新迁移。请勿关闭应用并重试");
      }
      // ★ Phase 2J：迁移涉及批量增删，清空三层缓存确保一致性
      //    旧格式记录已从磁盘删除，但 summaryCache / fullRecordCache 仍持有旧条目；
      //    新格式记录已写入磁盘但未入缓存。清空三层缓存后，下次 ensureSummaryScanSafe()
      //    会从 maxSummaryId=0 重新全量扫描，正确反映磁盘最新状态。
      clearSummaryCache();
      clearFullRecordCache();
      clearRecordScanCache();
    } else {
      // ★ 项2：shallowRef 清空需用 clearShallowArray 触发 triggerRef
      clearShallowArray(certs);
    }
  } else {
    // ★ 项2：shallowRef 清空需用 clearShallowArray 触发 triggerRef
    clearShallowArray(certs);
  }

  setModuleCache("certs", certs.value);
  loading.value = false;
};

onMounted(() => {
  loadCerts().finally(() => {
    loading.value = false;
  });
});

/* CRUD */
const showDialog = ref(false);
const editing = ref<CertEntry | null>(null);
const formError = ref("");
const form = ref<CertEntry>({ id: 0, name: "", type: "", expiry: "", status: "valid", content: "", note: "" });

const onAdd = () => {
  editing.value = null;
  form.value = { id: 0, name: "", type: "", expiry: "", status: "valid", content: "", note: "" };
  formError.value = "";
  uploadedFileName.value = "";
  showDialog.value = true;
};
const onEdit = (c: CertEntry) => {
  editing.value = c;
  form.value = { ...c };
  formError.value = "";
  uploadedFileName.value = "";
  showDialog.value = true;
};
const onSave = async () => {
  formError.value = "";
  if (!form.value.name.trim()) { formError.value = "请填写名称"; return; }
  if (!form.value.type) { formError.value = "请选择证书或密钥类型"; return; }
  if (!form.value.content.trim()) { formError.value = "请填写或上传密钥内容"; return; }

  const certData = {
    name: form.value.name, type: form.value.type,
    expiry: form.value.expiry, status: computeStatus(form.value.expiry),
    content: form.value.content, note: form.value.note,
  };

  showDialog.value = false; // 立即关闭对话框

  // 独立记录模式（参考 PhotoAlbum / AccountVerthys）：每条证书一条独立 verthys 记录，互不覆盖
  const dataB64 = serializeCert(certData);
  const recordName = `cert_${certData.name}_${Date.now()}`;

  if (editing.value) {
    // 编辑：先添加新记录 → 删除旧记录 → 更新内存 recordId
    // 顺序：add 新 → delete 旧，避免删除后新增时 recordId 复用导致数据错乱
    const oldRid = editing.value.recordId;
    let newRid: number | null = null;
    try {
      newRid = await verthysAddRecord(TYPE_CERT, recordName, dataB64);
    } catch (e) {
      if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") {
        showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
        return;
      }
      throw e;
    }
    if (newRid !== null) {
      // ★ Phase 2J：同步两层缓存（摘要 + 全量），确保列表立即显示新记录
      addFullRecord(newRid, TYPE_CERT, recordName, dataB64);
      if (oldRid !== undefined) {
        try { await verthysDeleteRecord(oldRid); } catch { /* 旧记录删除失败不阻断 */ }
        // ★ Phase 2J：失效两层缓存中的旧记录（杜绝删除复活）
        invalidateSummaryRecord(oldRid);
        invalidateFullRecord(oldRid);
      }
      const idx = certs.value.findIndex(c => c.id === editing.value!.id);
      if (idx >= 0) {
        // ★ 项2：shallowRef 下整体替换元素需用 updateShallowItem 触发 triggerRef
        updateShallowItem(certs, idx, { recordId: newRid, ...certData });
      }
      setModuleCache("certs", certs.value);
    }
  } else {
    // 新增：添加独立记录 → 保存 recordId 到内存
    let newRid: number | null = null;
    try {
      newRid = await verthysAddRecord(TYPE_CERT, recordName, dataB64);
    } catch (e) {
      if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") {
        showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
        return;
      }
      throw e;
    }
    if (newRid !== null) {
      // ★ Phase 2J：同步两层缓存（摘要 + 全量）
      addFullRecord(newRid, TYPE_CERT, recordName, dataB64);
      // ★ 项2：shallowRef 下 push 需用 pushShallowItems 触发 triggerRef
      pushShallowItems(certs, [{ id: Date.now(), recordId: newRid, ...certData }]);
      setModuleCache("certs", certs.value);
    }
  }

  // ★ 企业级数据持久化修复：检查 persistVerthys 返回值，根治"保存后重启数据丢失"
  //    旧实现仅 await persistVerthys() 不检查返回值，flush 失败时 UI 显示新证书但
  //    磁盘未落盘 → 重启后数据丢失。修复：检查返回值，失败时 showError 提示用户。
  let persistOk = false;
  try {
    persistOk = await persistVerthys();
  } catch (e) {
    console.error("[saveCert] persistVerthys 异常", e);
  }
  if (!persistOk) {
    showError("证书已保存到内存但持久化失败，重启后可能丢失。请勿关闭应用，尝试重新编辑保存或联系支持");
  }
};
/* ===== 删除二次确认 ===== */
const showDeleteConfirm = ref(false);
const deleteTargetName = ref("");
const deleteTargetId = ref<number | null>(null);
const onDelete = (c: CertEntry) => {
  deleteTargetId.value = c.id;
  deleteTargetName.value = `${c.name} · ${getTypeLabel(c.type)}`;
  showDeleteConfirm.value = true;
};
const confirmDelete = async () => {
  if (deleteTargetId.value === null) return;
  const id = deleteTargetId.value;
  const target = certs.value.find(c => c.id === id);
  const rid = target?.recordId;
  // 立即关闭弹窗 + 移除 UI + 更新缓存（同步无缝，消除删除按钮到内容消失的空白间隔）
  showDeleteConfirm.value = false;
  deleteTargetId.value = null;
  // ★ 项2：shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
  removeShallowItems(certs, c => c.id === id);
  setModuleCache("certs", certs.value);
  // 立即失效两层缓存（同步，杜绝删除复活）
  if (rid !== undefined) {
    // ★ Phase 2J：同步失效摘要缓存 + 全量缓存 + 旧扫描缓存（三条路径同时清理）
    //    确保无论走哪条加载路径（summary / fullRecord / 旧 scan）都不会复活已删除记录
    invalidateSummaryRecord(rid);
    invalidateFullRecord(rid);
    invalidateScannedRecord(rid);
    // ★ 企业级根治：await deleteAndPersist + await persistVerthys（根治删除后复活）
    //
    // 原缺陷：deleteAndPersist(...).catch(() => {}) 火并忘——防抖 flush（300ms）
    //   未执行即返回，应用退出 → 磁盘仍含已删记录 → "删除后复活"。
    //   .catch(() => {}) 静默吞错 → 用户不知删除失败。
    //
    // 修复：await deleteAndPersist（删除 IPC 完成）+ await persistVerthys（取消防抖
    //   立即落盘）。UI 已同步移除（无缝删除），await 不阻塞 UI 渲染。
    try {
      await deleteAndPersist(() => verthysDeleteRecord(rid), rid);
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

/* 密钥内容查看 / 复制 */
/* ★ 项2：shallowRef 下直接修改属性不触发更新，必须 updateShallowItem */
const toggleContent = (c: CertEntry) => {
  const idx = certs.value.findIndex(item => item.id === c.id);
  if (idx >= 0) {
    updateShallowItem(certs, idx, { contentVisible: !c.contentVisible });
  }
};

const { clipCountdown, copyWithTimeout } = useClipToast();
const copyContent = async (c: CertEntry) => { await copyWithTimeout(c.content); };

/* ★ 企业级修复「页面覆盖」：切换模块时同步关闭所有 Teleport 弹窗，杜绝残留覆盖 */
import { useModuleDialogGuard } from "../../composables/useModuleDialogGuard";
useModuleDialogGuard("certs", () => {
  showDialog.value = false;
  showDeleteConfirm.value = false;
});
</script>

<!-- 共享样式（非 scoped，来自 verthys-common.css） -->
<style src="../../styles/verthys-common.css"></style>

<style scoped>
/* CertManager 模块特有样式 */

/* 类型筛选 chips */
.search-divider { width: 1px; height: 16px; background: var(--border-glass); flex-shrink: 0; }
.type-chips { display: flex; gap: 4px; flex-shrink: 0; }
.type-chip { padding: 3px 8px; font-size: 10px; border: 1px solid var(--border-glass); border-radius: 10px; background: transparent; color: var(--text-muted); cursor: pointer; transition: all 0.2s; letter-spacing: 0.5px; white-space: nowrap; }
.type-chip:hover { color: var(--text-primary); border-color: var(--border-hover); }
.type-chip.active { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.08); }

/* 证书信息 */
.cert-info { display: flex; flex-direction: column; gap: 3px; margin-bottom: 6px; }
.info-item { font-size: 11px; color: var(--text-secondary); font-family: var(--font); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.info-label { color: var(--text-muted); margin-right: 4px; }
.expiry-valid { color: var(--success); }
.expiry-expiring { color: var(--warning); }
.expiry-expired { color: var(--danger); }

/* 备注文本 */
.cert-note {
  font-size: 11px; color: var(--text-muted); font-family: var(--font);
  margin-top: 4px; max-height: 32px; overflow: hidden;
  text-overflow: ellipsis; display: -webkit-box;
  -webkit-line-clamp: 2; -webkit-box-orient: vertical;
  white-space: normal; line-height: 1.4;
}

/* 表单错误提示 */
.form-error {
  display: flex; align-items: center; gap: 6px;
  margin-top: 14px; padding: 8px 12px; font-size: 11px;
  color: var(--danger); background: rgba(255, 71, 87, 0.06);
  border: 1px solid rgba(255, 71, 87, 0.2); border-radius: var(--radius-sm);
  font-family: var(--font); animation: error-shake 0.4s var(--ease);
}
.form-error svg { width: 14px; height: 14px; flex-shrink: 0; }
@keyframes error-shake {
  0%, 100% { transform: translateX(0); }
  25% { transform: translateX(-4px); }
  75% { transform: translateX(4px); }
}

/* 主题化下拉框 / 日期选择器 */
.sc-select {
  appearance: none; background: rgba(0,0,0,0.3);
  border: 1px solid rgba(255,255,255,0.1); border-radius: 6px;
  padding: 8px 12px; color: var(--text-primary);
  font-size: 12px; font-family: var(--font);
  outline: none; transition: border-color 0.2s; cursor: pointer;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%238a8a9a' stroke-width='2'%3E%3Cpolyline points='6 9 12 15 18 9'/%3E%3C/svg%3E");
  background-repeat: no-repeat; background-position: right 10px center;
  padding-right: 32px;
}
.sc-select:focus { border-color: var(--accent); }
.sc-select option { background: rgba(20,22,30,0.95); color: var(--text-primary); }
.sc-select::-webkit-calendar-picker-indicator { filter: invert(0.7); cursor: pointer; }

/* 日期选择器 */
.date-wrap { position: relative; cursor: pointer; }
input[type="date"].date-input { background-image: none; padding-right: 12px; color: transparent; cursor: pointer; }
input[type="date"].date-input.has-value { color: var(--text-primary); }
input[type="date"].date-input::-webkit-calendar-picker-indicator { filter: invert(0.7); cursor: pointer; position: absolute; right: 10px; top: 50%; transform: translateY(-50%); }
.date-placeholder { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--text-muted); font-size: 12px; font-family: var(--font); pointer-events: none; }

/* 文件上传 */
.content-input-area { position: relative; border: 1px dashed rgba(255,255,255,0.1); border-radius: 8px; padding: 4px; transition: border-color 0.2s; }
.content-input-area.drag-active { border-color: var(--accent); background: rgba(0,212,255,0.05); }
.upload-btn-row { display: flex; align-items: center; gap: 8px; margin-top: 6px; }
.upload-btn { display: flex; align-items: center; gap: 4px; }
.upload-btn svg { width: 12px; height: 12px; }
.btn-sm { padding: 5px 10px; font-size: 11px; }
.uploaded-name { font-size: 11px; color: var(--accent); font-family: var(--font); }
.hidden-file-input { display: none; }

/* 卡片可点击 */
.verthys-card { cursor: pointer; }
</style>
