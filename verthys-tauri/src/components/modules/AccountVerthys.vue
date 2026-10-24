<!--
  AccountVerthys.vue — 存签：统一条目库模块
  列表：浮动搜索栏 + 卡片网格（光泽追踪、悬浮操作、密码复制安全清空）
  新增：`+` → 类型选择台（VaultTypePicker）→ 类型化编辑窗口（VaultItemFormDialog）→ 保存
  卡片：唯一渲染源为 account/VaultItemCard.vue（虚拟滚动与普通网格共用）
  持久化：每条条目一条独立记录（TYPE_ACCOUNT），载荷为 {类型 id, 字段值字典} 信封；
        历史扁平账号载荷（旧版 AccountFields）由 lib/vault_item_codec 形态嗅探兼容

  记录不可读时的裁定（禁止静默丢弃）：
    载荷解码失败 / 无任何字段值的记录仍进入列表，标记为 corrupt ——
    记录在容器内真实存在，直接过滤会让用户误判为「数据丢失」。
    此类条目只呈现「数据不可读」与删除入口，不提供编辑（空表单覆盖会抹掉
    仍可能恢复的原始载荷）。
-->
<template>
  <div class="account-verthys verthys-module reveal-host" :class="{ 'is-entering': entering }">
    <!-- 瞬时提示（错误 / 复制结果与清空时间）统一由全局 ToastLayer 渲染（App 根节点单点挂载，--z-toast 最高层） -->

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

    <!-- 卡片网格：≥200 条启用虚拟滚动，小列表保留原 v-for 路径零开销。
         两条路径共用同一卡片组件，仅容器不同。 -->
    <VirtualCardGrid
      v-if="filteredAccounts.length >= 200"
      :items="filteredAccounts"
      :item-height="148"
      :min-column-width="300"
      :item-key="itemKeyOf"
      v-slot="{ item: entry, index }"
    >
      <VaultItemCard
        :entry="entry"
        :view="viewOf(entry)"
        :reveal-delay="revealDelayOf(index)"
        @detail="onDetail(entry)"
        @toggle="toggleSecret(entry)"
        @copy="copySecret(entry, $event)"
        @edit="onEdit(entry)"
        @remove="onDelete(entry)"
      />
    </VirtualCardGrid>
    <div v-else class="card-grid">
      <VaultItemCard
        v-for="(entry, idx) in filteredAccounts"
        :key="entry.id"
        :entry="entry"
        :view="viewOf(entry)"
        :reveal-delay="revealDelayOf(idx)"
        @detail="onDetail(entry)"
        @toggle="toggleSecret(entry)"
        @copy="copySecret(entry, $event)"
        @edit="onEdit(entry)"
        @remove="onDelete(entry)"
      />
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
      :saving="saving"
      @submit="onPersist"
    />

    <!-- 条目详情：只读全字段；遮罩空白处 / Esc / 头部关闭键均可关闭 -->
    <VaultItemDetailDialog
      v-model="showDetail"
      :type-def="detailDef"
      :entry="detailEntry"
      @toggle="onDetailToggle"
      @copy="onDetailCopy"
    />

    <!-- 解密密钥输入框（显隐切换与表单同语言；显隐只为核对输入，不落盘） -->
    <VerthysDialog
      v-model="showKeyDialog"
      title="输入密钥以查看密码"
      save-label="解密查看"
      :saving="keyBusy"
      @save="confirmKey"
    >
      <div class="key-target">{{ keyTargetName }}</div>
      <div class="form-field full key-field">
        <input
          id="vault-key-input"
          class="input"
          v-model="keyInput"
          :type="keyInputVisible ? 'text' : 'password'"
          placeholder="独立密钥"
          aria-label="独立密钥"
          autofocus
          @keydown.enter="confirmKey"
        />
        <button
          class="icon-btn"
          type="button"
          @click="keyInputVisible = !keyInputVisible"
          :aria-label="keyInputVisible ? '隐藏密钥' : '显示密钥'"
          v-tip="keyInputVisible ? '隐藏' : '显示'"
        >
          <svg v-if="!keyInputVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
        </button>
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
import { ref, shallowRef, computed, onMounted, watch } from "vue";
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
  BUILTIN_VAULT_TYPES,
  buildVaultTypeIndex, type VaultItemPayload, type VaultTypeDef,
} from "../../constants/vault_item_types";
import { decodeVaultItem, serializeVaultItem } from "../../lib/vault_item_codec";
import {
  buildVaultCardView, vaultSearchText,
  type VaultCardView,
} from "../../lib/vault_item_card";
import { loadCustomVaultTypes } from "../../lib/vault_item_type_store";
import {
  applyVaultFilter, createEmptyVaultFilter, isEmptyVaultFilter,
  type VaultFilterCriteria,
} from "../../lib/vault_item_filter";
import { useClipToast } from "../../composables/useClipToast";
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
import VaultItemDetailDialog from "./account/VaultItemDetailDialog.vue";
import VaultItemCard from "./account/VaultItemCard.vue";

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

const searchKey = ref("");
/* shallowRef 替代 ref，避免 Vue 对条目数组内每条记录深度代理
 * （每条记录含字段值与敏感展示态，万条记录深度代理开销 200-500ms）
 * 代价：直接修改元素属性（如 entry.secretVisible = true）不触发更新，必须用 updateShallowItem */
const accounts = shallowRef<VaultEntry[]>([]);

/**
 * 内存 id 分配器（唯一出口）。
 * 禁止用 Date.now() 充当条目 id：同一毫秒内新增两条会得到同一 id，
 * 导致列表 key 重复、findIndex 定位到错误条目（隐藏/复制会作用到别人身上）。
 * 载入缓存后按既有最大值续号，保证会话内单调且不冲突。
 */
let memIdSeq = 1;
const allocMemId = (): number => memIdSeq++;
const reseedMemId = (): void => {
  let max = 0;
  for (const entry of accounts.value) {
    if (entry.id > max) max = entry.id;
  }
  memIdSeq = max + 1;
};

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
 * 敏感字段初始处于掩码态（secretVisible=false），明文只在用户显式查看后写入
 * plainSecrets；卡片据此统一渲染全部敏感行。
 *
 * @param corrupt 载荷不可读：保留占位条目（不得静默丢弃），不建敏感行
 */
const makeEntry = (
  memId: number,
  recordId: number,
  kind: string,
  data: Record<string, string>,
  corrupt = false,
): VaultEntry => {
  if (corrupt) {
    return {
      id: memId,
      recordId,
      kind,
      data: {},
      secretVisible: false,
      corrupt: true,
    };
  }
  return {
    id: memId,
    recordId,
    kind,
    data,
    secretVisible: false,
  };
};

/** 加载自定义类型定义（失败保留上次已知类型并提示，绝不静默清空） */
const loadVaultTypes = async (): Promise<void> => {
  const result = await loadCustomVaultTypes();
  if (result.failed) {
    showError("自定义类型读取失败，已暂时沿用上次已知类型");
    return;
  }
  customTypes.value = result.types;
};

const loadAccounts = async (): Promise<void> => {
  // 0. 缓存优先：先用缓存数据即时渲染
  const cached = getModuleCache<VaultEntry[]>("accounts");
  let maxRecordId = 0;
  if (cached.data && cached.data.length > 0) {
    // shallowRef 整体替换即触发更新（replaceShallowArray 内部只做赋值）
    replaceShallowArray(accounts, cached.data);
    reseedMemId();
    // 计算缓存中最大的 recordId，作为增量扫描起点
    for (const entry of cached.data) {
      if ((entry.recordId ?? 0) > maxRecordId) maxRecordId = entry.recordId ?? 0;
    }
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

  const found: { recordId: number; kind: string; data: Record<string, string>; corrupt: boolean }[] = [];
  if (newIds.length > 0) {
    const dataB64Map = await getRecordsDataB64Batch(newIds);
    for (const id of newIds) {
      const dataB64 = dataB64Map.get(id);
      // 取不到载荷不等于记录不存在：保留为不可读条目，交由用户决定删除
      if (!dataB64) {
        found.push({ recordId: id, kind: "", data: {}, corrupt: true });
        continue;
      }
      const decoded = decodeVaultItem(dataB64);
      if (!decoded.ok) {
        found.push({ recordId: id, kind: "", data: {}, corrupt: true });
        continue;
      }
      // 无任何字段值的载荷：仍保留为不可读条目（既不丢弃，也不伪装成空条目）
      if (Object.keys(decoded.payload.data).length === 0) {
        found.push({ recordId: id, kind: decoded.payload.kind, data: {}, corrupt: true });
        continue;
      }
      found.push({
        recordId: id,
        kind: decoded.payload.kind,
        data: decoded.payload.data,
        corrupt: false,
      });
    }
  }

  // 3. 有新记录 → 追加到现有列表（缓存有效时增量追加，缓存无效时构建新列表）
  if (found.length > 0) {
    // 批量构建新条目后一次性 pushShallowItems，避免循环内多次触发响应式
    const newItems: VaultEntry[] = [];
    for (const item of found) {
      newItems.push(makeEntry(allocMemId(), item.recordId, item.kind, item.data, item.corrupt));
    }
    pushShallowItems(accounts, newItems);
  } else if (!cached.data || cached.data.length === 0) {
    // 缓存无效且无记录 → 清空列表，避免残留上一次会话的条目
    clearShallowArray(accounts);
    memIdSeq = 1;
  }

  setModuleCache("accounts", accounts.value);
  loading.value = false;
};

onMounted(() => {
  loadAccounts().finally(() => {
    loading.value = false;
  });
});

/** 虚拟网格的稳定键：条目内存 id 会话内唯一（禁止退回 index 键） */
const itemKeyOf = (entry: VaultEntry): number => entry.id;

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

  // 关键字与筛选维度为叠加关系：先按关键字取子集，再套用维度筛选与排序。
  // 不可读条目不参与关键字匹配：其字段名/值不可知，检索命中即等于旁路泄露。
  const matched = k
    ? accounts.value.filter((entry) =>
        entry.corrupt ? false : vaultSearchTextOf(entry, defOf(entry.kind)).includes(k),
      )
    : accounts.value;
  return applyVaultFilter(matched, filterCriteria.value, defOf);
});

/** 搜索文本（不可读条目不参与；类型缺失由 vaultSearchText 自身返回空串） */
const vaultSearchTextOf = (entry: VaultEntry, def: VaultTypeDef | undefined): string =>
  entry.corrupt ? "" : vaultSearchText(entry.data, def);

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

/* 敏感字段显隐：未独立加密的条目直接解开掩码；存在独立加密字段时先走密钥窗口 */
const toggleSecret = (entry: VaultEntry): void => {
  const secrets = viewOf(entry).secrets;
  if (secrets.length === 0) return;
  const idx = accounts.value.findIndex((e) => e.id === entry.id);
  if (idx < 0) return;

  if (!entry.secretVisible) {
    // 任一致密敏感字段需要独立密钥：先走密钥授权，绝不以掩码冒充已解密
    if (secrets.some((secret) => secret.encrypted)) {
      keyTargetId.value = entry.id;
      keyInput.value = "";
      keyError.value = false;
      showKeyDialog.value = true;
      return;
    }
    // 非加密字段的 raw 即明文：一次展示全部敏感行
    const plainSecrets: Record<string, string> = {};
    for (const secret of secrets) plainSecrets[secret.fieldId] = secret.raw;
    // shallowRef 下直接修改属性不触发更新，必须 updateShallowItem
    updateShallowItem(accounts, idx, { secretVisible: true, plainSecrets });
  } else {
    // 隐藏即撤销授权：明文不再留在内存条目上（否则复制会绕过密钥校验）
    updateShallowItem(accounts, idx, { secretVisible: false, plainSecrets: {} });
  }
};

/* 解密密钥对话框 */
const showKeyDialog = ref(false);
const keyTargetId = ref<number | null>(null);
const keyInput = ref("");
const keyInputVisible = ref(false);
const keyError = ref(false);
const keyBusy = ref(false);

/* 输入即清除错误态：错误提示只描述「上一次提交」的结果 */
watch(keyInput, () => {
  if (keyError.value) keyError.value = false;
});

/** 密钥对话框中的目标描述：主标题 · 次行首项（账号条目即「平台 · 账户」） */
const keyTargetName = computed(() => {
  const target = accounts.value.find((e) => e.id === keyTargetId.value);
  if (!target) return "";
  const view = viewOf(target);
  const secondary = view.lines[0]?.value ?? "";
  return secondary ? `${view.title} · ${secondary}` : view.title;
});

const confirmKey = async (): Promise<void> => {
  if (keyBusy.value) return;
  const target = accounts.value.find((e) => e.id === keyTargetId.value);
  if (!target || !keyInput.value) return;
  const secret = viewOf(target).secret;
  if (!secret) return;
  keyBusy.value = true;
  try {
    const plain = await decryptPasswordField(secret.raw, keyInput.value);
    // shallowRef 下通过 id 找索引后 updateShallowItem，避免直接修改目标条目属性
    const idx = accounts.value.findIndex((e) => e.id === target.id);
    if (idx >= 0) {
      updateShallowItem(accounts, idx, {
        secretVisible: true,
        plainSecrets: { [secret.fieldId]: plain },
      });
    }
    showKeyDialog.value = false;
    keyTargetId.value = null;
    keyInput.value = "";
  } catch {
    keyError.value = true;
  } finally {
    keyBusy.value = false;
    keyInputVisible.value = false;
  }
};

/* 复制敏感字段（提示经全局 Toast 中心状态通道轮番渲染：结果 → 清空时间） */
const { copyWithTimeout } = useClipToast("敏感字段已复制");

const copySecret = async (entry: VaultEntry, fieldId: string): Promise<void> => {
  const secrets = viewOf(entry).secrets;
  const secret = secrets.find((item) => item.fieldId === fieldId) ?? secrets[0];
  if (!secret) return;
  // 独立加密且未处于已解锁展示态 → 先走密钥授权，绝不使用残留明文
  if (secret.encrypted && !entry.secretVisible) {
    toggleSecret(entry);
    return;
  }
  const plain = entry.secretVisible
    ? (entry.plainSecrets?.[secret.fieldId] ?? (secret.encrypted ? "" : secret.raw))
    : (secret.encrypted ? "" : secret.raw);
  if (!plain) {
    toggleSecret(entry);
    return;
  }
  const copied = await copyWithTimeout(plain);
  if (!copied) showError("复制失败：剪贴板不可用或权限被拒绝");
};

/* ===== 新增与编辑 ===== */
const showPicker = ref(false);
const showForm = ref(false);
const showTypeEditor = ref(false);
const formType = ref<VaultTypeDef | null>(null);
const formInitial = ref<Record<string, string> | null>(null);
const editingId = ref<number | null>(null);
/** 保存进行中（编辑窗口保持开启并锁定动作，失败不丢输入） */
const saving = ref(false);
/** 待重新指派类型的条目（自定义类型被删后条目类型定义缺失时使用） */
const reassignEntryId = ref<number | null>(null);

/* ===== 详情查看（只读全字段） ===== */
const showDetail = ref(false);
const detailEntryId = ref<number | null>(null);
/** 详情目标条目：按内存 id 定位，条目被删除/替换时自动失效 */
const detailEntry = computed(
  () => accounts.value.find((entry) => entry.id === detailEntryId.value) ?? null,
);
/** 详情目标类型：未知类型不提供详情（走重新指派入口） */
const detailDef = computed(() => {
  const entry = detailEntry.value;
  return entry ? (typeIndex.value.get(entry.kind) ?? null) : null;
});

/** 打开详情：损坏/未知类型不进入（前者不可读，后者需先重新指派） */
const onDetail = (entry: VaultEntry): void => {
  if (entry.corrupt) return;
  if (!typeIndex.value.has(entry.kind)) return;
  detailEntryId.value = entry.id;
  showDetail.value = true;
};

/* 条目在详情打开期间被移除时关闭详情，避免窗口停留在空目标上 */
watch(detailEntry, (entry) => {
  if (showDetail.value && !entry) {
    showDetail.value = false;
    detailEntryId.value = null;
  }
});

/** 详情窗口敏感字段的显隐/复制：复用同一份条目展示态与模块入口 */
const onDetailToggle = (): void => {
  if (detailEntry.value) toggleSecret(detailEntry.value);
};
const onDetailCopy = (fieldId: string): void => {
  if (detailEntry.value) void copySecret(detailEntry.value, fieldId);
};

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

/** 类型集合保存完成：直接采用保存结果（落盘侧已同步模块缓存，无需二次读盘） */
const onTypesSaved = (types: VaultTypeDef[]): void => {
  customTypes.value = types;
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
  if (entry.corrupt) return;
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
  if (saving.value) return;
  saving.value = true;

  try {
    const dataB64 = serializeVaultItem(payload);
    const titleField = typeIndex.value.get(payload.kind)?.titleField ?? "";
    const title = titleField ? (payload.data[titleField] ?? "") : "";
    const recordName = `${payload.kind}_${title}_${Date.now()}`.slice(0, 180);

    const editing = editingId.value;
    const target = editing === null ? undefined : accounts.value.find((e) => e.id === editing);
    const oldRid = target?.recordId;

    const newRid = await verthysAddRecord(TYPE_ACCOUNT, recordName, dataB64);
    if (newRid === null) {
      // 写入未发生：保持窗口与全部输入，用户可直接重试
      showError("保存失败，请重试");
      return;
    }

    // 同步两级缓存（摘要 + 全量）
    addFullRecord(newRid, TYPE_ACCOUNT, recordName, dataB64, dataB64.length);

    if (target) {
      // 编辑：先添加新记录 → 删除旧记录 → 更新内存条目
      // 顺序：add 新 → delete 旧，避免删除后新增时 recordId 复用导致数据错乱
      if (oldRid !== undefined) {
        let removed = false;
        try {
          removed = await deleteAndPersist(() => verthysDeleteRecord(oldRid), oldRid);
        } catch {
          removed = false;
        }
        if (!removed) {
          // 旧版本未被清理：必须在界面上说清，否则下次启动出现同一条目两份
          showError("条目已保存，但旧版本未能清理；重启后可能出现重复条目，请再次编辑以重试");
        }
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
      pushShallowItems(accounts, [makeEntry(allocMemId(), newRid, payload.kind, payload.data)]);
    }
    setModuleCache("accounts", accounts.value);
    editingId.value = null;
    formInitial.value = null;
    showForm.value = false;

    const persisted = await persistVerthys(); // 落盘（串行 flush 队列）
    if (!persisted) {
      showError("条目已写入，但落盘失败；请勿关闭应用并重试保存");
    }
  } finally {
    saving.value = false;
  }
};

/* ===== 删除二次确认 ===== */
const showDeleteConfirm = ref(false);
const deleteTargetName = ref("");
const deleteTargetId = ref<number | null>(null);
const onDelete = (entry: VaultEntry): void => {
  deleteTargetId.value = entry.id;
  const view = viewOf(entry);
  if (entry.corrupt) {
    deleteTargetName.value = `数据不可读 · 记录 #${entry.recordId ?? "—"}`;
  } else {
    deleteTargetName.value = view.typeLabel ? `${view.title} · ${view.typeLabel}` : view.title;
  }
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
  showDetail.value = false;
  detailEntryId.value = null;
  keyInputVisible.value = false;
  reassignEntryId.value = null;
});
</script>

<!-- 共享样式（非 scoped，来自 verthys-common.css） -->
<style src="../../styles/verthys-common.css"></style>

<style scoped>
/* 搜索栏层序：抬高整层以脱离卡片网格的绘制顺序。
   搜索栏以 isolation 自建层叠上下文，其内部的锚定下拉无论 z-index 多大都
   只能在该层内比较，故必须提升承载层本身；层级仍低于模块弹窗与加载遮罩。 */
.search-layer { position: relative; z-index: 10; }

/* 卡片网格：固定为旧版卡面实测的原始高度（148px = 原卡片自然高度上限），
   卡片不随内容拉伸；完整信息由整卡点击的详情窗口承载。虚拟路径同高。 */
.card-grid { grid-auto-rows: 148px; align-items: stretch; }

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

/* 解密密钥对话框 */
.key-target { font-size: 12px; color: var(--text-secondary); font-family: var(--font); margin-bottom: 14px; }
.key-field { display: flex; align-items: center; gap: 8px; }
.key-field .input { flex: 1; min-width: 0; }
.key-error { font-size: 11px; color: var(--danger); margin-top: 6px; }
</style>
