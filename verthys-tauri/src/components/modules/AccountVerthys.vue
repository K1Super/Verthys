<!--
  AccountVerthys.vue — 存签：统一条目库模块
  列表：浮动搜索栏 + 卡片网格（3D 视差、悬浮操作、密码复制倒计时）
  新增：`+` → 类型选择台（VaultTypePicker）→ 类型化编辑窗口（VaultItemFormDialog）→ 保存
  卡片：账号类型保持既有版式；其余类型按类型声明渲染主标题、次行与敏感行
  持久化：每条条目一条独立记录（TYPE_ACCOUNT），载荷为 {类型 id, 字段值字典} 信封
-->
<template>
  <div class="account-verthys verthys-module reveal-host" :class="{ 'is-entering': entering }">
    <!-- 瞬时提示（错误/复制倒计时）统一由全局 ToastLayer 渲染（App 根节点单点挂载，--z-toast 最高层） -->

    <!-- 搜索栏（筛选按钮与条件摘要挂在搜索栏右侧的筛选插槽内）
         外层包裹承担层序：搜索栏自身以 isolation 建立层叠上下文，若整层不提升，
         锚定下拉会被随后绘制的卡片网格覆盖 -->
    <div class="search-layer module-reveal">
      <VerthysSearchBar v-model="searchKey" placeholder="搜索" add-label="" :sky-seed="5" @add="onAdd">
        <template #filters>
          <VaultCardFilter
            v-model="filterCriteria"
            :types="pickTypes"
            :result-count="filteredAccounts.length"
          />
        </template>
      </VerthysSearchBar>
    </div>

    <!-- 卡片网格：≥200 条启用虚拟滚动，小列表保留原 v-for 路径零开销 -->
    <VirtualCardGrid
      v-if="filteredAccounts.length >= 200"
      :items="filteredAccounts"
      :item-height="172"
      :min-column-width="300"
      v-slot="{ item: entry, index }"
    >
      <div
        class="verthys-card glass reveal-item"
        :style="{ '--reveal-delay': revealDelayOf(index) + 'ms' }"
        @mousemove="onCardMove($event)"
        @mouseleave="onCardLeave($event)"
      >
        <div class="card-accent"></div>
        <!-- 账号条目的卡片版式与既有实现一致 -->
        <template v-if="entry.kind === accountTypeId">
          <div class="card-head">
            <span class="card-title">{{ entry.data.platform }}</span>
            <span class="vault-type-badge" :style="badgeStyle(entry)">
              <span class="badge-icon" aria-hidden="true" v-html="viewOf(entry).icon"></span>
              <span class="badge-name">{{ viewOf(entry).typeLabel }}</span>
            </span>
            <span v-if="entry.data.encrypted === '1'" class="lock-badge" v-tip="'独立加密'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </span>
          </div>
          <div class="username">{{ entry.data.username }}</div>
          <div class="secret-row">
            <span class="secret-text">{{ entry.displaySecret }}</span>
            <div class="secret-actions">
              <button class="icon-btn" @click="toggleSecret(entry)" v-tip="entry.secretVisible ? '隐藏' : '显示'">
                <svg v-if="!entry.secretVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
              </button>
              <button class="icon-btn" @click="copySecret(entry)" v-tip="'复制'">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </div>
          </div>
        </template>
        <!-- 其余类型：主标题 + 次行（敏感项掩码）+ 敏感行 -->
        <template v-else>
          <div class="card-head">
            <span class="card-title" v-tip="viewOf(entry).title">{{ viewOf(entry).title }}</span>
            <span class="vault-type-badge" :style="badgeStyle(entry)">
              <span class="badge-icon" aria-hidden="true" v-html="viewOf(entry).icon"></span>
              <span class="badge-name">{{ viewOf(entry).typeLabel }}</span>
            </span>
            <span v-if="viewOf(entry).secret?.encrypted" class="lock-badge" v-tip="'独立加密'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </span>
          </div>
          <div class="card-lines">
            <div v-for="line in viewOf(entry).lines" :key="line.fieldId" class="card-line">
              <span class="line-label">{{ line.label }}</span>
              <span class="line-value">{{ line.value }}</span>
            </div>
            <div v-if="viewOf(entry).expiry" class="card-line">
              <span class="line-label">{{ viewOf(entry).expiry?.label }}</span>
              <span class="card-readout" :style="readoutStyle(entry)">{{ viewOf(entry).expiry?.text }}</span>
            </div>
          </div>
          <div v-if="viewOf(entry).secret" class="secret-row">
            <span class="secret-label">{{ viewOf(entry).secret?.label }}</span>
            <span class="secret-text">{{ entry.displaySecret }}</span>
            <div class="secret-actions">
              <button class="icon-btn" @click="toggleSecret(entry)" v-tip="entry.secretVisible ? '隐藏' : '显示'">
                <svg v-if="!entry.secretVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
              </button>
              <button class="icon-btn" @click="copySecret(entry)" v-tip="'复制'">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </div>
          </div>
        </template>
        <div class="card-actions">
          <button class="mini-btn" @click="onEdit(entry)">编辑</button>
          <button class="mini-btn danger" @click="onDelete(entry)">删除</button>
        </div>
        <div class="card-shine"></div>
      </div>
    </VirtualCardGrid>
    <div v-else class="card-grid">
      <div
        v-for="(entry, idx) in filteredAccounts"
        :key="entry.id"
        class="verthys-card glass reveal-item"
        :style="{ '--reveal-delay': revealDelayOf(idx) + 'ms' }"
        @mousemove="onCardMove($event)"
        @mouseleave="onCardLeave($event)"
      >
        <div class="card-accent"></div>
        <template v-if="entry.kind === accountTypeId">
          <div class="card-head">
            <span class="card-title">{{ entry.data.platform }}</span>
            <span class="vault-type-badge" :style="badgeStyle(entry)">
              <span class="badge-icon" aria-hidden="true" v-html="viewOf(entry).icon"></span>
              <span class="badge-name">{{ viewOf(entry).typeLabel }}</span>
            </span>
            <span v-if="entry.data.encrypted === '1'" class="lock-badge" v-tip="'独立加密'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </span>
          </div>
          <div class="username">{{ entry.data.username }}</div>
          <div class="secret-row">
            <span class="secret-text">{{ entry.displaySecret }}</span>
            <div class="secret-actions">
              <button class="icon-btn" @click="toggleSecret(entry)" v-tip="entry.secretVisible ? '隐藏' : '显示'">
                <svg v-if="!entry.secretVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
              </button>
              <button class="icon-btn" @click="copySecret(entry)" v-tip="'复制'">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </div>
          </div>
        </template>
        <template v-else>
          <div class="card-head">
            <span class="card-title" v-tip="viewOf(entry).title">{{ viewOf(entry).title }}</span>
            <span class="vault-type-badge" :style="badgeStyle(entry)">
              <span class="badge-icon" aria-hidden="true" v-html="viewOf(entry).icon"></span>
              <span class="badge-name">{{ viewOf(entry).typeLabel }}</span>
            </span>
            <span v-if="viewOf(entry).secret?.encrypted" class="lock-badge" v-tip="'独立加密'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </span>
          </div>
          <div class="card-lines">
            <div v-for="line in viewOf(entry).lines" :key="line.fieldId" class="card-line">
              <span class="line-label">{{ line.label }}</span>
              <span class="line-value">{{ line.value }}</span>
            </div>
            <div v-if="viewOf(entry).expiry" class="card-line">
              <span class="line-label">{{ viewOf(entry).expiry?.label }}</span>
              <span class="card-readout" :style="readoutStyle(entry)">{{ viewOf(entry).expiry?.text }}</span>
            </div>
          </div>
          <div v-if="viewOf(entry).secret" class="secret-row">
            <span class="secret-label">{{ viewOf(entry).secret?.label }}</span>
            <span class="secret-text">{{ entry.displaySecret }}</span>
            <div class="secret-actions">
              <button class="icon-btn" @click="toggleSecret(entry)" v-tip="entry.secretVisible ? '隐藏' : '显示'">
                <svg v-if="!entry.secretVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
              </button>
              <button class="icon-btn" @click="copySecret(entry)" v-tip="'复制'">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </div>
          </div>
        </template>
        <div class="card-actions">
          <button class="mini-btn" @click="onEdit(entry)">编辑</button>
          <button class="mini-btn danger" @click="onDelete(entry)">删除</button>
        </div>
        <div class="card-shine"></div>
      </div>
    </div>

    <!-- 空态覆盖层：遵循「模块根视口居中」统一契约（与清藏·拾光同源）——
         挂载为模块根容器（.verthys-module，position: relative）的直接子节点，
         不得置于定位/滚动子容器（如 .card-grid）之内，避免参照系漂移。
         清除筛选动作与空态同层，共用同一居中参照系。 -->
    <CosmicEmpty v-if="!loading && filteredAccounts.length === 0" :text="emptyText" />
    <button
      v-if="!loading && filteredAccounts.length === 0 && hasActiveQuery"
      class="empty-clear"
      type="button"
      @click="clearQuery"
    >清除筛选</button>

    <!-- 类型选择台：新增条目的第一步；未知类型条目在此重新指派类型 -->
    <VaultTypePicker
      v-model="showPicker"
      :types="pickTypes"
      :title="pickTitle"
      manageable
      @select="onPickType"
      @manage="onManageTypes"
    />

    <!-- 自定义类型管理：类型声明与字段构建 -->
    <VaultTypeEditorDialog
      v-model="showTypeEditor"
      :types="customTypes"
      :entry-count-of="entryCountOf"
      @saved="onTypesSaved"
    />

    <!-- 类型化编辑窗口：账号类型保留既有版式与行为 -->
    <VaultItemFormDialog
      v-model="showForm"
      :type-def="formType"
      :initial-data="formInitial"
      @submit="onPersist"
    />

    <!-- 解密密钥输入框 -->
    <VerthysDialog v-model="showKeyDialog" title="输入密钥以查看密码" @save="confirmKey" save-label="解密查看">
      <div class="key-target">{{ keyTargetName }}</div>
      <div class="form-field full">
        <input
          class="input"
          v-model="keyInput"
          :type="keyInputVisible ? 'text' : 'password'"
          placeholder="独立密钥"
          @keydown.enter="confirmKey"
          autofocus
        />
      </div>
      <template #error v-if="keyError">
        <div class="key-error">密钥错误或密码已损坏</div>
      </template>
    </VerthysDialog>

    <!-- 非阻塞加载：无底板居中展示，加载完成自动消失 -->
    <CosmicRingLoader :overlay="true" :show="loading" text="正在加载存签数据…" />

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
  decryptPasswordField, verthysAddRecord, verthysDeleteRecord,
  type VaultEntry,
} from "../../lib/verthys";
import {
  updateShallowItem, pushShallowItems, replaceShallowArray,
  clearShallowArray, removeShallowItems,
} from "../../utils/shallow-array";
import { persistVerthys, deleteAndPersist, getModuleCache, setModuleCache, invalidateSummaryRecord, invalidateFullRecord, addFullRecord, ensureIndexSourceSafe, getSummaryIdsByType, getRecordIdsByType, invalidateScannedRecord, getRecordsDataB64Batch } from "../../lib/keyManager";
import { TYPE_ACCOUNT } from "../../constants/record_types";
import {
  ACCOUNT_VAULT_TYPE_ID, BUILTIN_VAULT_TYPES,
  buildVaultTypeIndex, type VaultItemPayload, type VaultTypeDef,
} from "../../constants/vault_item_types";
import { deserializeVaultItem, serializeVaultItem } from "../../lib/vault_item_codec";
import {
  VAULT_SECRET_MASK, VAULT_TONE_RGB_VARS, buildVaultCardView, findCardSecretField,
  vaultReadoutColorVar, vaultSearchText,
  type VaultCardView,
} from "../../lib/vault_item_card";
import { loadCustomVaultTypes } from "../../lib/vault_item_type_store";
import {
  applyVaultFilter, createEmptyVaultFilter, isEmptyVaultFilter,
  type VaultFilterCriteria,
} from "../../lib/vault_item_filter";
import { useClipToast } from "../../composables/useClipToast";
import { useCardShine } from "../../composables/useCardShine";
import { useToastCenter } from "../../composables/useToastCenter";
import { useModuleDialogGuard } from "../../composables/useModuleDialogGuard";
import { useModuleEntrance, revealDelayOf } from "../../composables/useModuleEntrance";
import VerthysSearchBar from "../common/verthys-ui/VerthysSearchBar.vue";
import VerthysDialog from "../common/verthys-ui/VerthysDialog.vue";
import CosmicRingLoader from "../common/cosmic/CosmicRingLoader.vue";
import CosmicEmpty from "../common/cosmic/CosmicEmpty.vue";
import ConfirmDelete from "../common/verthys-ui/ConfirmDelete.vue";
import VirtualCardGrid from "../common/verthys-ui/VirtualCardGrid.vue";
import VaultCardFilter from "../common/verthys-ui/VaultCardFilter.vue";
import VaultTypePicker from "./account/VaultTypePicker.vue";
import VaultTypeEditorDialog from "./account/VaultTypeEditorDialog.vue";
import VaultItemFormDialog from "./account/VaultItemFormDialog.vue";

/* 瞬时提示（错误，2.5s 自动消失）— 全局 Toast 中心；渲染归 ToastLayer */
const { showError } = useToastCenter();

/**
 * 统一条目存储模式：
 *   每条条目一条独立 verthys 记录（TYPE_ACCOUNT），载荷为 {类型 id, 字段值字典} 信封。
 *   - 新增：verthysAddRecord → 保存 recordId
 *   - 编辑：verthysAddRecord(新) → verthysDeleteRecord(旧)
 *   - 删除：verthysDeleteRecord(recordId)
 *   - 加载：扫描全部 TYPE_ACCOUNT 记录并解析信封
 *   整体替换模式（先删旧再写新）在并发场景下会导致数据丢失或复活，故不采用。
 */

/* 非阻塞加载状态（无底板居中展示，加载完成自动消失） */
const loading = ref(false);

const accountTypeId = ACCOUNT_VAULT_TYPE_ID;
const secretMask = VAULT_SECRET_MASK;

const searchKey = ref("");
/* shallowRef 替代 ref，避免 Vue 对条目数组内每条记录深度代理
 * （每条记录含字段值与敏感展示态，万条记录深度代理开销 200-500ms）
 * 代价：直接修改元素属性（如 entry.secretVisible = true）不触发更新，必须用 updateShallowItem */
const accounts = shallowRef<VaultEntry[]>([]);

/* 步入窗口：以「列表首次非空」起算（缓存命中即首个渲染批，未命中则数据落地批），
 *   标记与首批卡片同一 patch 生效 —— 见 useModuleEntrance 契约 */
const { entering } = useModuleEntrance(() => accounts.value.length > 0);

/* 自定义类型索引：内置类型在前，自定义类型补入；查询按 id 命中 */
const customTypes = ref<VaultTypeDef[]>([]);
const typeIndex = computed(() => buildVaultTypeIndex(customTypes.value));
const pickTypes = computed<VaultTypeDef[]>(() => [...BUILTIN_VAULT_TYPES, ...customTypes.value]);

/** 类型定义缺失时的兜底视图（不留白，不抛错） */
const EMPTY_CARD_VIEW: VaultCardView = buildVaultCardView({}, undefined);

/**
 * 由记录数据构造内存条目。
 * 敏感展示初始为掩码（已独立加密时显示"已加密"），明文只在用户显式查看后写入条目。
 */
const makeEntry = (
  memId: number,
  recordId: number,
  kind: string,
  data: Record<string, string>,
): VaultEntry => {
  const def = typeIndex.value.get(kind);
  const secretField = def ? findCardSecretField(def) : undefined;
  const encrypted = data.encrypted === "1";
  return {
    id: memId,
    recordId,
    kind,
    data,
    secretVisible: false,
    displaySecret: secretField ? (encrypted ? "已加密" : secretMask) : "",
  };
};

/** 加载自定义类型定义（失败按空列表处理，内置类型不受影响） */
const loadVaultTypes = async (): Promise<void> => {
  try {
    customTypes.value = await loadCustomVaultTypes();
  } catch {
    customTypes.value = [];
  }
};

const loadAccounts = async (): Promise<void> => {
  // 0. 缓存优先：先用缓存数据即时渲染
  const cached = getModuleCache<VaultEntry[]>("accounts");
  let maxRecordId = 0;
  if (cached.data && cached.data.length > 0) {
    // shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
    replaceShallowArray(accounts, cached.data);
    // 计算缓存中最大的 recordId，作为增量扫描起点
    maxRecordId = cached.data.reduce((max, e) => Math.max(max, e.recordId || 0), 0);
    loading.value = false;
  } else {
    loading.value = true;
  }

  // 1. 类型定义先就位：条目的敏感行与掩码展示依赖类型声明
  await loadVaultTypes();

  // 2. ID 来源：摘要索引优先（仅读索引、不解密数据，不受记录体积影响）；
  //    摘要缓存整体为空（旧格式容器/熔断静默返回空）时回退记录扫描缓存。
  //    记录扫描仍会在后台并发触发一次作数据层预热：命中扫描缓存的小体积记录
  //    在后续批量取数时零 IPC；预热失败不影响列表可用性（取数走并行 IPC 回退）。
  const useSummaryIds = await ensureIndexSourceSafe();
  const idsOf = (type: number): number[] =>
    useSummaryIds ? getSummaryIdsByType(type) : getRecordIdsByType(type);

  const allIds = idsOf(TYPE_ACCOUNT);
  const newIds = allIds.filter((id) => id > maxRecordId);

  const found: { recordId: number; kind: string; data: Record<string, string> }[] = [];
  if (newIds.length > 0) {
    const dataB64Map = await getRecordsDataB64Batch(newIds);
    for (const id of newIds) {
      const dataB64 = dataB64Map.get(id);
      if (!dataB64) continue;
      const payload = deserializeVaultItem(dataB64);
      // 无任何字段值的载荷一律视为损坏：信封兜底与真实条目都可区分
      if (Object.keys(payload.data).length === 0) continue;
      found.push({ recordId: id, kind: payload.kind, data: payload.data });
    }
  }

  // 3. 有新记录 → 追加到现有列表（缓存有效时增量追加，缓存无效时构建新列表）
  if (found.length > 0) {
    let nextMemId = accounts.value.length > 0
      ? Math.max(...accounts.value.map((e) => e.id)) + 1
      : 1;
    // 批量构建新条目后一次性 pushShallowItems，避免循环内多次触发响应式
    const newItems: VaultEntry[] = [];
    for (const item of found) {
      newItems.push(makeEntry(nextMemId++, item.recordId, item.kind, item.data));
    }
    pushShallowItems(accounts, newItems);
  } else if (!cached.data || cached.data.length === 0) {
    // 缓存无效且无记录 → 清空列表，避免残留上一次会话的条目
    clearShallowArray(accounts);
  }

  setModuleCache("accounts", accounts.value);
  loading.value = false;
};

onMounted(() => {
  loadAccounts().finally(() => {
    loading.value = false;
  });
});

/** 卡片视图索引：随列表变化重建，避免在模板内反复构建视图对象 */
const cardViews = computed<Map<number, VaultCardView>>(() => {
  const index = typeIndex.value;
  const map = new Map<number, VaultCardView>();
  for (const entry of filteredAccounts.value) {
    map.set(entry.id, buildVaultCardView(entry.data, index.get(entry.kind)));
  }
  return map;
});

const viewOf = (entry: VaultEntry): VaultCardView => cardViews.value.get(entry.id) ?? EMPTY_CARD_VIEW;

/**
 * 类型标识着色：把设计令牌的三元组变量注入元素自定义属性。
 * 用内联变量而非逐项类名，避免同列表内出现随数据变化的类名集合。
 */
const badgeStyle = (entry: VaultEntry): Record<string, string> => ({
  "--tone-rgb": `var(${VAULT_TONE_RGB_VARS[viewOf(entry).tone]})`,
});

/** 到期读数着色：未设置到期日不给颜色，沿用次要文字色 */
const readoutStyle = (entry: VaultEntry): Record<string, string> => {
  const readout = viewOf(entry).expiry;
  const colorVar = readout ? vaultReadoutColorVar(readout) : null;
  return colorVar ? { color: `rgb(var(${colorVar}))` } : {};
};

/** 高级筛选条件（模块内本地状态，不跨会话持久化） */
const filterCriteria = ref<VaultFilterCriteria>(createEmptyVaultFilter());

/** 是否处于检索态：关键字或任一筛选维度生效 */
const hasActiveQuery = computed(
  () => searchKey.value.trim().length > 0 || !isEmptyVaultFilter(filterCriteria.value),
);

const emptyText = computed(() => (hasActiveQuery.value ? "无匹配条目" : "暂无条目"));

/** 一键清除检索条件（关键字与筛选维度同时复位） */
const clearQuery = (): void => {
  searchKey.value = "";
  filterCriteria.value = createEmptyVaultFilter();
};

const filteredAccounts = computed(() => {
  const k = searchKey.value.trim().toLowerCase();
  const index = typeIndex.value;
  const defOf = (kind: string) => index.get(kind);

  // 关键字与筛选维度为叠加关系：先按关键字取子集，再套用维度筛选与排序
  const matched = k
    ? accounts.value.filter((entry) => vaultSearchText(entry.data, defOf(entry.kind)).includes(k))
    : accounts.value;
  return applyVaultFilter(matched, filterCriteria.value, defOf);
});

/* 卡片光泽追踪（3D 视差倾斜已按用户决策移除，Wave 53） */
const { onCardMove, onCardLeave } = useCardShine();

/* 敏感字段显隐：未独立加密的条目直接解开掩码；独立加密的条目需输入独立密钥 */
const toggleSecret = (entry: VaultEntry): void => {
  const secret = viewOf(entry).secret;
  if (!secret) return;
  const idx = accounts.value.findIndex((e) => e.id === entry.id);
  if (idx < 0) return;

  if (!entry.secretVisible) {
    if (secret.encrypted) {
      keyTargetId.value = entry.id;
      keyInput.value = "";
      keyError.value = false;
      showKeyDialog.value = true;
      return;
    }
    // shallowRef 下直接修改属性不触发更新，必须 updateShallowItem
    updateShallowItem(accounts, idx, {
      secretVisible: true,
      displaySecret: secret.raw,
      plainSecret: secret.raw,
    });
  } else {
    updateShallowItem(accounts, idx, {
      secretVisible: false,
      displaySecret: secret.encrypted ? "已加密" : secretMask,
    });
  }
};

/* 解密密钥对话框 */
const showKeyDialog = ref(false);
const keyTargetId = ref<number | null>(null);
const keyInput = ref("");
const keyInputVisible = ref(false);
const keyError = ref(false);

/** 密钥对话框中的目标描述：主标题 · 次行首项（账号条目即「平台 · 账户」） */
const keyTargetName = computed(() => {
  const target = accounts.value.find((e) => e.id === keyTargetId.value);
  if (!target) return "";
  const view = viewOf(target);
  const secondary = view.lines[0]?.value ?? "";
  return secondary ? `${view.title} · ${secondary}` : view.title;
});

const confirmKey = async (): Promise<void> => {
  const target = accounts.value.find((e) => e.id === keyTargetId.value);
  if (!target || !keyInput.value) return;
  const secret = viewOf(target).secret;
  if (!secret) return;
  try {
    const plain = await decryptPasswordField(secret.raw, keyInput.value);
    // shallowRef 下通过 id 找索引后 updateShallowItem，避免直接修改目标条目属性
    const idx = accounts.value.findIndex((e) => e.id === target.id);
    if (idx >= 0) {
      updateShallowItem(accounts, idx, {
        plainSecret: plain,
        secretVisible: true,
        displaySecret: plain,
      });
    }
    showKeyDialog.value = false;
    keyTargetId.value = null;
    keyInput.value = "";
  } catch {
    keyError.value = true;
  }
};

/* 复制敏感字段（提示经全局 Toast 中心倒计时通道渲染） */
const { copyWithTimeout } = useClipToast("密码已复制");

const copySecret = async (entry: VaultEntry): Promise<void> => {
  const secret = viewOf(entry).secret;
  if (!secret) return;
  let plain = entry.plainSecret;
  if (!plain && !secret.encrypted) plain = secret.raw;
  if (!plain) {
    toggleSecret(entry);
    return;
  }
  await copyWithTimeout(plain);
};

/* ===== 新增与编辑 ===== */
const showPicker = ref(false);
const showForm = ref(false);
const showTypeEditor = ref(false);
const formType = ref<VaultTypeDef | null>(null);
const formInitial = ref<Record<string, string> | null>(null);
const editingId = ref<number | null>(null);
/** 待重新指派类型的条目（自定义类型被删后条目类型定义缺失时使用） */
const reassignEntryId = ref<number | null>(null);

const pickTitle = computed(() => (reassignEntryId.value !== null ? "重新指派类型" : "选择类型"));

/** 指定类型的已加载条目数（类型编辑器删除类型时用于提示影响范围） */
const entryCountOf = (kind: string): number => accounts.value.filter((e) => e.kind === kind).length;

const onAdd = (): void => {
  reassignEntryId.value = null;
  showPicker.value = true;
};

const onManageTypes = (): void => {
  showTypeEditor.value = true;
};

/** 类型集合保存完成：刷新类型索引，列表中的类型名与卡片视图随之更新 */
const onTypesSaved = async (types: VaultTypeDef[]): Promise<void> => {
  customTypes.value = types;
  await loadVaultTypes();
};

/**
 * 类型选择台选定类型。
 * 新增流程：直接打开该类型的编辑窗口。
 * 重新指派流程：以既有条目数据回填新类型的同名字段，保存后条目改属新类型。
 */
const onPickType = (typeId: string): void => {
  const def = typeIndex.value.get(typeId);
  if (!def) return;
  showPicker.value = false;

  const reassignId = reassignEntryId.value;
  reassignEntryId.value = null;

  formType.value = def;
  if (reassignId !== null) {
    const entry = accounts.value.find((e) => e.id === reassignId);
    formInitial.value = entry ? { ...entry.data } : null;
    editingId.value = reassignId;
  } else {
    formInitial.value = null;
    editingId.value = null;
  }
  showForm.value = true;
};

const onEdit = (entry: VaultEntry): void => {
  const def = typeIndex.value.get(entry.kind);
  if (!def) {
    // 类型定义缺失（自定义类型已删除）：改由类型选择台重新指派，避免条目不可编辑
    reassignEntryId.value = entry.id;
    showPicker.value = true;
    return;
  }
  formType.value = def;
  formInitial.value = { ...entry.data };
  editingId.value = entry.id;
  showForm.value = true;
};

/** 保存：写入独立记录并同步两级缓存（新增与编辑同一路径，编辑时删旧记录） */
const onPersist = async (payload: VaultItemPayload): Promise<void> => {
  showForm.value = false; // 立即关闭对话框

  const dataB64 = serializeVaultItem(payload);
  const titleField = typeIndex.value.get(payload.kind)?.titleField ?? "";
  const title = titleField ? (payload.data[titleField] ?? "") : "";
  const recordName = `${payload.kind}_${title}_${Date.now()}`.slice(0, 180);

  const editing = editingId.value;
  editingId.value = null;
  const target = editing === null ? undefined : accounts.value.find((e) => e.id === editing);
  const oldRid = target?.recordId;

  const newRid = await verthysAddRecord(TYPE_ACCOUNT, recordName, dataB64);
  if (newRid === null) {
    showError("保存失败，请重试");
    return;
  }

  // 同步两级缓存（摘要 + 全量）
  addFullRecord(newRid, TYPE_ACCOUNT, recordName, dataB64, dataB64.length);

  if (target) {
    // 编辑：先添加新记录 → 删除旧记录 → 更新内存条目
    // 顺序：add 新 → delete 旧，避免删除后新增时 recordId 复用导致数据错乱
    if (oldRid !== undefined) {
      try { await verthysDeleteRecord(oldRid); } catch { /* 旧记录删除失败不阻断 */ }
      invalidateSummaryRecord(oldRid);
      invalidateFullRecord(oldRid);
      invalidateScannedRecord(oldRid);
    }
    const idx = accounts.value.findIndex((e) => e.id === target.id);
    if (idx >= 0) {
      // shallowRef 下整体替换元素需用 updateShallowItem 触发 triggerRef
      updateShallowItem(accounts, idx, makeEntry(target.id, newRid, payload.kind, payload.data));
    }
  } else {
    pushShallowItems(accounts, [makeEntry(Date.now(), newRid, payload.kind, payload.data)]);
  }
  setModuleCache("accounts", accounts.value);

  await persistVerthys(); // 落盘（串行 flush 队列）
};

/* ===== 删除二次确认 ===== */
const showDeleteConfirm = ref(false);
const deleteTargetName = ref("");
const deleteTargetId = ref<number | null>(null);
const onDelete = (entry: VaultEntry): void => {
  deleteTargetId.value = entry.id;
  const view = viewOf(entry);
  deleteTargetName.value = view.typeLabel ? `${view.title} · ${view.typeLabel}` : view.title;
  showDeleteConfirm.value = true;
};
const confirmDelete = async (): Promise<void> => {
  if (deleteTargetId.value === null) return;
  const id = deleteTargetId.value;
  const target = accounts.value.find((e) => e.id === id);
  const rid = target?.recordId;
  // 立即关闭弹窗 + 移除 UI + 更新缓存（同步无缝，消除删除按钮到内容消失的空白间隔）
  showDeleteConfirm.value = false;
  deleteTargetId.value = null;
  // shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
  removeShallowItems(accounts, (e) => e.id === id);
  setModuleCache("accounts", accounts.value);
  if (rid === undefined) return;

  // 立即失效三层缓存（同步，杜绝删除复活）
  invalidateSummaryRecord(rid);
  invalidateFullRecord(rid);
  invalidateScannedRecord(rid);

  // 删除与落盘都需确认完成：deleteAndPersist 仅入队并防抖调度，
  // 不等待则用户快速操作或应用退出时磁盘仍含已删记录（删除后复活）。
  try {
    await deleteAndPersist(() => verthysDeleteRecord(rid), rid);
    const persistOk = await persistVerthys(); // 立即落盘（取消防抖）
    if (!persistOk) {
      showError("删除已提交但持久化失败，重启后记录可能恢复。请勿关闭应用并重试删除");
    }
  } catch {
    showError("删除失败，请重试");
  }
};

/* 修复「页面覆盖」：切换模块时同步关闭所有 Teleport 弹窗，杜绝残留覆盖 */
useModuleDialogGuard("accounts", () => {
  showPicker.value = false;
  showForm.value = false;
  showTypeEditor.value = false;
  showKeyDialog.value = false;
  showDeleteConfirm.value = false;
  keyInputVisible.value = false;
  reassignEntryId.value = null;
});
</script>

<!-- 共享样式（非 scoped，来自 verthys-common.css） -->
<style src="../../styles/verthys-common.css"></style>

<style scoped>
/* AccountVerthys 模块特有样式 */
.account-verthys { /* verthys-module 已在共享样式中 */ }

/* 搜索栏层序：抬高整层以脱离卡片网格的绘制顺序。
   搜索栏以 isolation 自建层叠上下文，其内部的锚定下拉无论 z-index 多大都
   只能在该层内比较，故必须提升承载层本身；层级仍低于模块弹窗与加载遮罩。 */
.search-layer { position: relative; z-index: 10; }

/* 卡片：纵向弹性 + 撑满网格槽位 —— 卡片高度由槽位决定（虚拟网格为 item-height，
   普通网格为行高），操作区因此可贴底固定，不再随内容长短上下漂移 */
.verthys-card { display: flex; flex-direction: column; height: 100%; }

/* 操作区贴底且成紧凑簇：贴底由 margin-top:auto 承担，间距显式收紧到 2px
   （共享样式为 4px），左对齐显式声明以免受其它规则影响 */
.card-actions { margin-top: auto; gap: 2px; justify-content: flex-start; }

/* 卡片操作键：悬浮/按压的底色注能 + 内收边（登记台同族语言，零阴影；
   静置即带透明描边，故交互态不产生任何几何位移） */
.card-actions .mini-btn {
  position: relative;
  padding: 3px 6px;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  transition:
    color var(--dur-fast) var(--ease),
    border-color var(--dur-fast) var(--ease),
    background-color var(--dur-fast) var(--ease);
}
.card-actions .mini-btn:hover {
  color: var(--text-primary);
  border-color: rgba(var(--accent-rgb), 0.3);
  background-color: rgba(var(--accent-rgb), 0.09);
}
.card-actions .mini-btn:active {
  border-color: rgba(var(--accent-rgb), 0.42);
  background-color: rgba(var(--accent-rgb), 0.14);
}
.card-actions .mini-btn:focus-visible { outline: 1px solid var(--border-hover); outline-offset: 1px; }
.card-actions .mini-btn.danger:hover {
  color: var(--danger);
  border-color: rgba(var(--danger-rgb), 0.34);
  background-color: rgba(var(--danger-rgb), 0.09);
}
.card-actions .mini-btn.danger:active {
  border-color: rgba(var(--danger-rgb), 0.44);
  background-color: rgba(var(--danger-rgb), 0.14);
}

/* 底缘微亮线：与主键皮肤的势隙线同族，克制到只在悬浮/按压时出现（仅走 opacity） */
.card-actions .mini-btn::after {
  content: ""; position: absolute; left: 15%; right: 24%; bottom: 0; height: 1px;
  background: linear-gradient(
    90deg,
    transparent,
    rgba(var(--accent-rgb), 0.3) 34%,
    rgba(var(--white-rgb), 0.5) 71%,
    transparent
  );
  opacity: 0;
  transition: opacity var(--dur-fast) var(--ease);
  pointer-events: none;
}
.card-actions .mini-btn:hover::after,
.card-actions .mini-btn:active::after { opacity: 1; }
.card-actions .mini-btn.danger::after {
  background: linear-gradient(
    90deg,
    transparent,
    rgba(var(--danger-rgb), 0.3) 34%,
    rgba(var(--white-rgb), 0.5) 71%,
    transparent
  );
}

/* 用户名行 */
.username {
  font-size: 12px; color: var(--text-secondary);
  margin-bottom: 8px; font-family: var(--font);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

/* 类型化次行：标签 + 取值紧凑排布 */
.card-lines {
  display: flex; flex-direction: column; gap: 4px;
  margin-bottom: 8px;
}
.card-line {
  display: flex; align-items: baseline; gap: 8px; min-width: 0;
  font-family: var(--font); font-size: 12px;
}
.line-label {
  flex-shrink: 0; font-size: 10.5px; letter-spacing: 0.5px;
  color: var(--text-muted);
}
.line-value {
  color: var(--text-secondary);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0;
}

/* 敏感行标签：类型化卡片的敏感行带字段名（账号卡片沿用无标签版式） */
.secret-label {
  flex-shrink: 0; font-size: 10.5px; letter-spacing: 0.5px;
  color: var(--text-muted); font-family: var(--font);
}

/* 到期读数：沿用仪表式回显的字体口径，色调由内联样式给出 */
.card-readout {
  font-family: var(--font-mono); font-size: 10.5px; letter-spacing: 0.4px;
  color: var(--text-muted);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

/* 类型标识：右上角绝对定位，固定字号与最大宽度，超长类型名截断加省略号；
   不参与标题行布局，标题可用宽度与既有版式一致 */
.vault-type-badge {
  position: absolute; top: 11px; right: 14px;
  display: inline-flex; align-items: center; gap: 4px;
  max-width: 68px; padding: 2px 8px;
  font-size: 10px; letter-spacing: 1px; font-family: var(--font);
  border-radius: 10px;
  border: 1px solid rgba(var(--tone-rgb, var(--accent-rgb)), 0.2);
  background: rgba(var(--tone-rgb, var(--accent-rgb)), 0.04);
  color: rgb(var(--tone-rgb, var(--accent-rgb)));
  white-space: nowrap; pointer-events: none;
}
.badge-icon { width: 10px; height: 10px; flex-shrink: 0; }
.badge-icon :deep(svg) { width: 100%; height: 100%; }
.badge-name { overflow: hidden; text-overflow: ellipsis; }

/* 空结果的清除入口：与空态文字同层，故用绝对定位与空态居中口径对齐 */
.empty-clear {
  position: absolute; top: calc(50% + 64px); left: 50%; transform: translateX(-50%);
  z-index: 2;
  padding: 4px 12px; background: none;
  border: 1px solid var(--border-glass); border-radius: 6px;
  color: var(--text-secondary); font-size: 11px; font-family: var(--font);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}
.empty-clear:hover { color: var(--accent); border-color: var(--border-hover); }
.empty-clear:focus-visible { outline: 1px solid var(--border-hover); outline-offset: 1px; }

/* 锁定徽章：同处右上角并让出类型标识的位置，不占用标题行宽度 */
.lock-badge { position: absolute; top: 15px; right: 90px; width: 14px; height: 14px; color: var(--warning); }
.lock-badge svg { width: 100%; height: 100%; }

/* 登记窗口的选项条 / 登记行 / 输入控件样式已抽取到 verthys-common.css（凭证登记台 · reg-* 词汇） */

/* 解密密钥对话框 */
.key-target { font-size: 12px; color: var(--text-secondary); font-family: var(--font); margin-bottom: 14px; }
.key-error { font-size: 11px; color: var(--danger); margin-top: 6px; }
</style>
