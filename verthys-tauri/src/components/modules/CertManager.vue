<!--
  CertManager.vue — 枢钥：重要证书 / 密钥管理模块
  列表：搜索栏 + 卡片网格（超大列表走虚拟滚动），复用 VerthysSearchBar / VirtualCardGrid / useCardShine
  登记窗口：VerthysDialog 承载「凭证登记台」皮肤 —— 分区登记行 + 左缘刻度轴 + 凭据舱，
            表单读数（到期状态 / 字符行数）由本模块计算属性提供，持久化逻辑与列表共用
-->
<template>
  <div class="cert-manager verthys-module">
    <!-- 瞬时提示（错误/复制倒计时）统一由全局 ToastLayer 渲染（App 根节点单点挂载，--z-toast 最高层） -->

    <!-- 搜索栏（带类型筛选） -->
    <VerthysSearchBar v-model="searchKey" placeholder="搜索证书 / 密钥…" add-label="新增" :sky-seed="3" @add="onAdd">
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

    <!-- 凭证登记窗口：左侧刻度轴 + 分区登记行 + 凭据舱，实时读数回显 -->
    <VerthysDialog
      v-model="showDialog"
      :title="editing ? '编辑证书' : '新增证书或密钥'"
      layout="plain"
      class="reg-panel"
      :save-label="editing ? '保存修改' : '登记入库'"
      @save="onSave"
    >
      <template #header>
        <header class="reg-head">
          <span class="reg-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none">
              <circle cx="12" cy="12" r="2" fill="currentColor" stroke="none" />
              <circle cx="12" cy="12" r="5.4" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-dasharray="25.5 8.4" transform="rotate(38 12 12)" opacity="0.8" />
              <circle cx="12" cy="12" r="8.6" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-dasharray="38.6 15.4" transform="rotate(-76 12 12)" opacity="0.45" />
            </svg>
          </span>
          <span class="reg-heading">
            <span class="reg-kicker">枢钥 · 凭证登记</span>
            <span class="reg-title">{{ editing ? '编辑证书' : '新增证书或密钥' }}</span>
          </span>
          <button class="reg-close" type="button" @click="showDialog = false" aria-label="关闭窗口" v-tip="'关闭'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </header>
      </template>

      <div class="reg-body">
        <!-- 01 标识：名称 / 类型 / 到期（含到期状态读数） -->
        <section class="reg-section" :style="{ '--rs': '0' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">01</span>
            <span class="reg-sec-name">标识</span>
            <span class="reg-rule"></span>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="cert-f-name"><i class="reg-req" aria-hidden="true">*</i>名称</label>
            <input id="cert-f-name" class="reg-input" v-model="form.name" placeholder="如 生产环境 SSL 证书" aria-required="true" />
          </div>
          <div class="reg-row">
            <label class="reg-key" for="cert-f-type"><i class="reg-req" aria-hidden="true">*</i>类型</label>
            <select id="cert-f-type" class="reg-input reg-select" v-model="form.type" aria-required="true">
              <option value="" disabled>请选择证书或密钥类型</option>
              <option v-for="t in types" :key="t.id" :value="t.id">{{ t.label }}</option>
            </select>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="cert-f-expiry">到期</label>
            <div class="reg-expiry">
              <div class="reg-date-wrap" @click="openDatePicker">
                <input id="cert-f-expiry" ref="dateInputRef" class="reg-input reg-date" :class="{ 'has-value': form.expiry }" type="date" v-model="form.expiry" />
                <span v-if="!form.expiry" class="reg-date-ph">未设置</span>
              </div>
              <span class="reg-readout" :class="`is-${expiryReadout.tone}`">
                <i class="reg-readout-dot"></i>{{ expiryReadout.text }}
              </span>
            </div>
          </div>
        </section>

        <!-- 02 凭据：内容舱（拖拽 / 粘贴 / 文件导入），底部条形读数 -->
        <section class="reg-section" :style="{ '--rs': '1' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">02</span>
            <span class="reg-sec-name">凭据<i class="reg-req" aria-hidden="true">*</i></span>
            <span class="reg-rule"></span>
          </div>
          <div
            class="reg-vault"
            :class="{ 'is-drag': isDragging }"
            @dragover.prevent="onDragOver"
            @dragleave.prevent="onDragLeave"
            @drop.prevent="onDrop"
          >
            <textarea class="reg-vault-input" v-model="form.content" rows="5" placeholder="粘贴证书或密钥内容，或拖拽文件到此处…" aria-required="true"></textarea>
            <div class="reg-vault-bar">
              <button class="reg-vault-import" type="button" @click="triggerFileUpload">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                <span>导入文件</span>
              </button>
              <span v-if="uploadedFileName" class="reg-vault-file" v-tip="uploadedFileName">{{ uploadedFileName }}</span>
              <span class="reg-vault-readout">{{ isDragging ? '松开即导入' : contentStats }}</span>
            </div>
            <input type="file" ref="fileInputRef" class="reg-file-input" accept=".pem,.crt,.key,.der,.cer,.pub" @change="onFileSelected" />
          </div>
        </section>

        <!-- 03 附注：备注 -->
        <section class="reg-section" :style="{ '--rs': '2' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">03</span>
            <span class="reg-sec-name">附注</span>
            <span class="reg-rule"></span>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="cert-f-note">备注</label>
            <input id="cert-f-note" class="reg-input" v-model="form.note" placeholder="可选备注信息" />
          </div>
        </section>
      </div>

      <template #error v-if="formError">
        <div class="reg-error">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          {{ formError }}
        </div>
      </template>
    </VerthysDialog>

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
  /* 索引来源：摘要优先，记录扫描兜底与数据层预热 */
  ensureIndexSourceSafe, getSummaryIdsByType, getRecordIdsByType,
  invalidateScannedRecord, clearRecordScanCache, getRecordsDataB64Batch } from "../../lib/keyManager";
import { TYPE_CERT, TYPE_CERT_LIST, TYPE_CERT_LEGACY } from "../../constants/record_types";
import { useClipToast } from "../../composables/useClipToast";
import { useCardShine } from "../../composables/useCardShine";
import { useToastCenter } from "../../composables/useToastCenter";
import VerthysSearchBar from "../common/verthys-ui/VerthysSearchBar.vue";
import VerthysDialog from "../common/verthys-ui/VerthysDialog.vue";
import CosmicLoading from "../common/cosmic/CosmicLoading.vue";
import CosmicEmpty from "../common/cosmic/CosmicEmpty.vue";
import ConfirmDelete from "../common/verthys-ui/ConfirmDelete.vue";
import VirtualCardGrid from "../common/verthys-ui/VirtualCardGrid.vue";

/* 瞬时提示（错误，2.5s 自动消失）— 全局 Toast 中心；渲染归 ToastLayer */
const { showError } = useToastCenter();

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
 * 修复：TYPE_CERT 从 record_types.ts 导入，不再本地定义。
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
/* 项2：shallowRef 替代 ref，避免 Vue 对 certs 数组内每条记录深度代理
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

/* 卡片光泽追踪（3D 视差倾斜已按用户决策移除，Wave 53） */
const { onCardMove, onCardLeave } = useCardShine();

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
/* 拖拽离开判定：指针仍在舱内（子元素间移动）时保持高亮，
 * 仅真正越过舱体边界才复位，避免边缘抖动导致收纳态闪烁 */
const onDragLeave = (e: DragEvent) => {
  const current = e.currentTarget as HTMLElement | null;
  const related = e.relatedTarget as Node | null;
  if (current && related && current.contains(related)) return;
  isDragging.value = false;
};
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
    // 项2：shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
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

  // ID 来源：摘要索引优先（仅读索引、不解密数据，不受记录体积影响）；
  //   摘要缓存整体为空（旧格式容器/熔断静默返回空）时回退记录扫描缓存。
  //   记录扫描仍会在后台并发触发一次作数据层预热：命中扫描缓存的小体积记录
  //   在后续批量取数时零 IPC；预热失败不影响列表可用性（取数走并行 IPC 回退）。
  const useSummaryIds = await ensureIndexSourceSafe();
  const idsOf = (type: number): number[] =>
    useSummaryIds ? getSummaryIdsByType(type) : getRecordIdsByType(type);

  // 1. 批量获取新格式 TYPE_CERT 记录数据（缓存优先，并行 IPC 回退）
  const allCertIds = idsOf(TYPE_CERT);
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
    const listIds = idsOf(TYPE_CERT_LIST);
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
    const legacyIds = idsOf(TYPE_CERT_LEGACY);
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
    // 项2：批量构建新条目后一次性 pushShallowItems，避免循环内多次触发响应式
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
      // 项2：shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
      replaceShallowArray(certs, migrated);
      if (listRecordId !== null) {
        try { await verthysDeleteRecord(listRecordId); } catch { /* */ }
      }
      for (const lr of legacyRecords) {
        try { await verthysDeleteRecord(lr.id); } catch { /* */ }
      }
      // 数据持久化修复：检查迁移落盘返回值，失败时提示用户
      let migratePersistOk = false;
      try { migratePersistOk = await persistVerthys(); } catch (e) { console.error("[loadCerts] 迁移 persistVerthys 异常", e); }
      if (!migratePersistOk) {
        showError("证书数据迁移已执行但持久化失败，重启后可能需重新迁移。请勿关闭应用并重试");
      }
      // 迁移涉及批量增删，清空三层缓存确保一致性
      //    旧格式记录已从磁盘删除，但 summaryCache / fullRecordCache 仍持有旧条目；
      //    新格式记录已写入磁盘但未入缓存。清空三层缓存后，下次 ensureSummaryScanSafe()
      //    会从 maxSummaryId=0 重新全量扫描，正确反映磁盘最新状态。
      clearSummaryCache();
      clearFullRecordCache();
      clearRecordScanCache();
    } else {
      // 项2：shallowRef 清空需用 clearShallowArray 触发 triggerRef
      clearShallowArray(certs);
    }
  } else {
    // 项2：shallowRef 清空需用 clearShallowArray 触发 triggerRef
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

/** 凭据舱读数：字符数与行数（粘贴/导入后即时核对内容体量，空内容显式给零值） */
const contentStats = computed(() => {
  const text = form.value.content;
  if (!text) return "0 字符 · 0 行";
  return `${text.length} 字符 · ${text.split(/\r\n|\r|\n/).length} 行`;
});

/** 到期读数：与 computeStatus 同源的阈值语义（<0 过期、<30 天临期），
 *  附剩余或超期天数；未设置到期日视为永久有效 */
const expiryReadout = computed<{ tone: "none" | "valid" | "expiring" | "expired"; text: string }>(() => {
  if (!form.value.expiry) return { tone: "none", text: "永久有效" };
  const diffDays = (new Date(form.value.expiry).getTime() - Date.now()) / 86400000;
  if (diffDays < 0) return { tone: "expired", text: `已过期 ${Math.ceil(-diffDays)} 天` };
  if (diffDays < 1) return { tone: "expiring", text: "今日内到期" };
  if (diffDays < 30) return { tone: "expiring", text: `${Math.floor(diffDays)} 天后到期` };
  return { tone: "valid", text: `${Math.floor(diffDays)} 天后到期` };
});

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
    const newRid = await verthysAddRecord(TYPE_CERT, recordName, dataB64);
    if (newRid !== null) {
      // 同步两层缓存（摘要 + 全量），确保列表立即显示新记录
      addFullRecord(newRid, TYPE_CERT, recordName, dataB64);
      if (oldRid !== undefined) {
        try { await verthysDeleteRecord(oldRid); } catch { /* 旧记录删除失败不阻断 */ }
        // 失效两层缓存中的旧记录（杜绝删除复活）
        invalidateSummaryRecord(oldRid);
        invalidateFullRecord(oldRid);
      }
      const idx = certs.value.findIndex(c => c.id === editing.value!.id);
      if (idx >= 0) {
        // 项2：shallowRef 下整体替换元素需用 updateShallowItem 触发 triggerRef
        updateShallowItem(certs, idx, { recordId: newRid, ...certData });
      }
      setModuleCache("certs", certs.value);
    }
  } else {
    // 新增：添加独立记录 → 保存 recordId 到内存
    const newRid = await verthysAddRecord(TYPE_CERT, recordName, dataB64);
    if (newRid !== null) {
      // 同步两层缓存（摘要 + 全量）
      addFullRecord(newRid, TYPE_CERT, recordName, dataB64);
      // 项2：shallowRef 下 push 需用 pushShallowItems 触发 triggerRef
      pushShallowItems(certs, [{ id: Date.now(), recordId: newRid, ...certData }]);
      setModuleCache("certs", certs.value);
    }
  }

  // 数据持久化修复：检查 persistVerthys 返回值，根治"保存后重启数据丢失"
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
  // 项2：shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
  removeShallowItems(certs, c => c.id === id);
  setModuleCache("certs", certs.value);
  // 立即失效两层缓存（同步，杜绝删除复活）
  if (rid !== undefined) {
    // 同步失效摘要缓存 + 全量缓存 + 旧扫描缓存（三条路径同时清理）
    //    确保无论走哪条加载路径（summary / fullRecord / 旧 scan）都不会复活已删除记录
    invalidateSummaryRecord(rid);
    invalidateFullRecord(rid);
    invalidateScannedRecord(rid);
    // 修复：await deleteAndPersist + await persistVerthys（根治删除后复活）
    //
    // 原缺陷：deleteAndPersist(...).catch(() => {}) 火并忘——防抖 flush（300ms）
    //   未执行即返回，应用退出 → 磁盘仍含已删记录 → "删除后复活"。
    //   .catch(() => {}) 静默吞错 → 用户不知删除失败。
    //
    // 修复：await deleteAndPersist（删除 IPC 完成）+ await persistVerthys（取消防抖
    //   立即落盘）。UI 已同步移除（无缝删除），await 不阻塞 UI 渲染。
    try {
      await deleteAndPersist(() => verthysDeleteRecord(rid), rid);
      // 数据持久化修复：检查 persistVerthys 返回值，根治"删除后复活"
      //    persistVerthys 返回 false（非抛异常）时旧 catch 无法捕获 → 静默假成功 →
      //    UI 已移除但磁盘未落盘 → 重启后记录"复活"。
      const persistOk = await persistVerthys(); // 立即落盘（取消防抖，根治删除后复活）
      if (!persistOk) {
        showError("删除已提交但持久化失败，重启后记录可能恢复。请勿关闭应用并重试删除");
      }
    } catch {
      showError("删除失败，请重试");
    }
  }
};

/* 密钥内容查看 / 复制 */
/* 项2：shallowRef 下直接修改属性不触发更新，必须 updateShallowItem */
const toggleContent = (c: CertEntry) => {
  const idx = certs.value.findIndex(item => item.id === c.id);
  if (idx >= 0) {
    updateShallowItem(certs, idx, { contentVisible: !c.contentVisible });
  }
};

/* 复制内容（提示经全局 Toast 中心倒计时通道渲染） */
const { copyWithTimeout } = useClipToast("已复制");
const copyContent = async (c: CertEntry) => { await copyWithTimeout(c.content); };

/* 修复「页面覆盖」：切换模块时同步关闭所有 Teleport 弹窗，杜绝残留覆盖 */
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

/* 登记窗口皮肤已抽取到 verthys-common.css（凭证登记台 · reg-* 词汇，与存签共用） */

/* 卡片可点击 */
.verthys-card { cursor: pointer; }
</style>
