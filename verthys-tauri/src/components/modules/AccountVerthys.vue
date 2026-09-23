<!--
  AccountVerthys.vue — 账户密码库模块
  布局：浮动搜索栏 + 卡片网格（非传统表格）
  交互：3D 视差卡片、悬浮操作、密码复制倒计时
  v2: 移除标签/密保，密码显隐用图标，支持单条密码独立加密
  v3: 复用 VerthysSearchBar / VerthysDialog / ClipToast / useCardTilt / useClipToast
-->
<template>
  <div class="account-verthys verthys-module">
    <!-- 顶部错误提示弹窗 -->
    <Teleport to="body">
      <transition name="err-toast">
        <div v-if="errorMsg" class="error-toast glass"><span class="toast-dot"></span>{{ errorMsg }}</div>
      </transition>
    </Teleport>

    <!-- 搜索栏 -->
    <VerthysSearchBar v-model="searchKey" placeholder="搜索平台 / 账户…" add-label="新增账户" @add="onAdd" />

    <!-- 卡片网格：≥200 条启用虚拟滚动（项1），小列表保留原 v-for 路径零开销 -->
    <VirtualCardGrid
      v-if="filteredAccounts.length >= 200"
      :items="filteredAccounts"
      :item-height="172"
      :min-column-width="300"
      v-slot="{ item: acc, index }"
    >
      <div
        class="verthys-card glass"
        :style="{ '--i': index }"
        @mousemove="onCardMove($event)"
        @mouseleave="onCardLeave($event)"
      >
        <div class="card-accent"></div>
        <div class="card-head">
          <span class="card-title">{{ acc.fields.platform }}</span>
          <span v-if="acc.fields.encrypted" class="lock-badge" v-tip="'独立加密'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </span>
        </div>
        <div class="username">{{ acc.fields.username }}</div>
        <div class="secret-row">
          <span class="secret-text">{{ acc.displayPwd }}</span>
          <div class="secret-actions">
            <button class="icon-btn" @click="togglePwd(acc)" v-tip="acc.pwdVisible ? '隐藏' : '显示'">
              <svg v-if="!acc.pwdVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
            </button>
            <button class="icon-btn" @click="copyPwd(acc)" v-tip="'复制'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        </div>
        <div class="card-actions">
          <button class="mini-btn" @click="onEdit(acc)">编辑</button>
          <button class="mini-btn danger" @click="onDelete(acc)">删除</button>
        </div>
        <div class="card-shine"></div>
      </div>
    </VirtualCardGrid>
    <div v-else class="card-grid">
      <div
        v-for="(acc, idx) in filteredAccounts"
        :key="acc.id"
        class="verthys-card glass"
        :style="{ '--i': idx }"
        @mousemove="onCardMove($event)"
        @mouseleave="onCardLeave($event)"
      >
        <div class="card-accent"></div>
        <div class="card-head">
          <span class="card-title">{{ acc.fields.platform }}</span>
          <span v-if="acc.fields.encrypted" class="lock-badge" v-tip="'独立加密'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </span>
        </div>
        <div class="username">{{ acc.fields.username }}</div>
        <div class="secret-row">
          <span class="secret-text">{{ acc.displayPwd }}</span>
          <div class="secret-actions">
            <button class="icon-btn" @click="togglePwd(acc)" v-tip="acc.pwdVisible ? '隐藏' : '显示'">
              <svg v-if="!acc.pwdVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
            </button>
            <button class="icon-btn" @click="copyPwd(acc)" v-tip="'复制'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        </div>
        <div class="card-actions">
          <button class="mini-btn" @click="onEdit(acc)">编辑</button>
          <button class="mini-btn danger" @click="onDelete(acc)">删除</button>
        </div>
        <div class="card-shine"></div>
      </div>

      <CosmicEmpty v-if="!loading && filteredAccounts.length === 0" text="暂无账号" />
    </div>

    <!-- 编辑对话框 -->
    <VerthysDialog v-model="showDialog" :title="editing ? '编辑账户' : '新增账户'" @save="onSave" :save-disabled="form.encrypted && !form.encKey" width="420px">
      <div class="form-field"><label>平台</label><input class="input" v-model="form.platform"/></div>
      <div class="form-field"><label>账户</label><input class="input" v-model="form.username" /></div>
      <div class="form-field full"><label>密码</label><input class="input" v-model="form.password" :type="formPwdVisible ? 'text' : 'password'" /></div>
      <div class="form-field full"><label>备注</label><textarea class="input textarea" v-model="form.note" rows="2"></textarea></div>

      <!-- 独立加密选项 -->
      <div class="form-field full encrypt-row" :class="{ on: form.encrypted }">
        <label class="encrypt-toggle">
          <input type="checkbox" v-model="form.encrypted" :disabled="editing !== null && editing.fields.encrypted" />
          <span class="encrypt-check"></span>
          <span class="encrypt-label">加密此密码（需独立密钥才能查看）</span>
        </label>
        <div v-if="form.encrypted" class="encrypt-key-input">
          <input
            class="input"
            v-model="form.encKey"
            :type="encKeyVisible ? 'text' : 'password'"
            :placeholder="editing ? '输入密钥以重新加密' : '设置独立密钥'"
          />
          <button class="icon-btn" @click="encKeyVisible = !encKeyVisible" tabindex="-1">
            <svg v-if="!encKeyVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
          </button>
        </div>
      </div>
    </VerthysDialog>

    <!-- 解密密钥输入框 -->
    <VerthysDialog v-model="showKeyDialog" title="输入密钥以查看密码" @save="confirmKey" save-label="解密查看">
      <div class="key-target">{{ keyTarget?.fields.platform }} · {{ keyTarget?.fields.username }}</div>
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

    <!-- 复制提示 -->
    <ClipToast :countdown="clipCountdown" text="密码已复制" />

    <!-- 非阻塞加载：无底板居中展示，加载完成自动消失 -->
    <CosmicLoading :show="loading" text="正在加载账户数据…" />

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
  encryptPasswordField, decryptPasswordField,
  verthysAddRecord, verthysDeleteRecord,
  serializeAccount, deserializeAccount,
  bytesToBase64, base64ToBytes,
  type AccountFields,
} from "../../lib/verthys";
import {
  updateShallowItem, pushShallowItems, replaceShallowArray,
  clearShallowArray, removeShallowItems,
} from "../../utils/shallow-array";
import { persistVerthys, deleteAndPersist, getModuleCache, setModuleCache, invalidateSummaryRecord, invalidateFullRecord, addFullRecord, ensureRecordScanSafe, getRecordIdsByType, invalidateScannedRecord, clearRecordScanCache, getRecordsDataB64Batch } from "../../lib/keyManager";
import { TYPE_ACCOUNT, TYPE_ACCOUNT_LIST, TYPE_ACCOUNT_LEGACY, TYPE_ACCOUNT_OLD } from "../../constants/record_types";
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

/* 修复：顶部错误提示弹窗（.error-toast，2.5s 自动消失） */
const { errorMsg, showError } = useErrorToast();

/**
 * 独立记录存储模式（参考 PhotoAlbum）：
 *   每个账户一条独立 verthys 记录（TYPE_ACCOUNT），互不覆盖。
 *   - 新增：verthysAddRecord → 保存 recordId
 *   - 编辑：verthysDeleteRecord(旧) + verthysAddRecord(新)
 *   - 删除：verthysDeleteRecord(recordId)
 *   - 加载：扫描所有 TYPE_ACCOUNT 记录
 *   彻底避免整体替换模式（add 新 + delete 旧 + flush）的并发竞态
 *   导致数据丢失/恢复问题。
 *
 * 修复：TYPE_ACCOUNT 从 record_types.ts 导入（值 0x02），
 *   不再本地定义。原本地定义 0x10 与 TYPE_GLOBAL_KEY 冲突，已根除。
 */

/* 非阻塞加载状态（无底板居中展示，加载完成自动消失） */
const loading = ref(false);

interface AccountEntry {
  id: number;          // 内存唯一 ID
  recordId?: number;   // verthys 记录 ID（用于编辑/删除）
  fields: AccountFields;
  pwdVisible: boolean;
  displayPwd: string;
  plainPwd?: string;
}

const searchKey = ref("");
/* 项2：shallowRef 替代 ref，避免 Vue 对 accounts 数组内每条记录深度代理
 * （每条记录含 fields.password/dataB64 等敏感字段，万条记录深度代理开销 200-500ms）
 * 代价：直接修改元素属性（如 acc.pwdVisible = true）不触发更新，必须用 updateShallowItem */
const accounts = shallowRef<AccountEntry[]>([]);

const loadAccounts = async () => {
  // 0. 缓存优先：先用缓存数据即时渲染
  const cached = getModuleCache<AccountEntry[]>("accounts");
  let maxRecordId = 0;
  if (cached.data && cached.data.length > 0) {
    // 项2：shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
    replaceShallowArray(accounts, cached.data);
    // 计算缓存中最大的 recordId，作为增量扫描起点（参考 PhotoAlbum）
    maxRecordId = cached.data.reduce((max, a) => Math.max(max, a.recordId || 0), 0);
    loading.value = false;
  } else {
    loading.value = true;
  }

  // 1. 共享扫描：首次调用扫描全部记录并缓存，后续模块直接复用（零 IPC 调用）
  //    一次扫描同时收集新格式(TYPE_ACCOUNT)和旧格式(列表/单条)记录
  const found: { id: number; fields: AccountFields }[] = [];
  const needMigration = maxRecordId === 0; // 缓存无效时才需要迁移旧格式
  let listRecordId: number | null = null;
  let listFields: AccountFields[] | null = null;
  const legacyRecords: { id: number; fields: AccountFields }[] = [];

  // 性能修复：改走 recordScanCache + 批量获取（落实 2.5s 预算）
  //    原实现：ensureSummaryScanSafe + for 循环串行 getFullRecord（N 条 = N 次串行 IPC，
  //            100 条 ≈ 7.5s，300 条 ≈ 22s，与后台 ensureRecordScan 抢同一常驻 worker → 30s）
  //    新实现：ensureRecordScanSafe（后台 startBackgroundTasks 已扫描则瞬时增量返回）
  //            + getRecordsDataB64Batch（扫描缓存命中零 IPC，未命中/大体积并行 IPC 回退）
  //            总耗时 < 2.5s。内存优先合并保证用户并发编辑不丢失。
  await ensureRecordScanSafe();

  // 1. 批量获取新格式 TYPE_ACCOUNT 记录数据（扫描缓存优先，并行 IPC 回退）
  const allAccountIds = getRecordIdsByType(TYPE_ACCOUNT);
  const newAccountIds = allAccountIds.filter(id => id > maxRecordId);
  if (newAccountIds.length > 0) {
    const b64Map = await getRecordsDataB64Batch(newAccountIds);
    for (const id of newAccountIds) {
      const accDataB64 = b64Map.get(id);
      if (!accDataB64) continue;
      try {
        const fields = deserializeAccount(accDataB64);
        found.push({ id, fields });
      } catch { /* 跳过损坏记录 */ }
    }
  }

  // 2. 缓存无效时检查旧格式记录用于迁移（同样批量获取，消除串行 IPC）
  if (needMigration) {
    // TYPE_ACCOUNT_LIST（整体列表旧格式）
    const listIds = getRecordIdsByType(TYPE_ACCOUNT_LIST);
    if (listIds.length > 0) {
      const listB64Map = await getRecordsDataB64Batch(listIds);
      for (const id of listIds) {
        const listDataB64 = listB64Map.get(id);
        if (!listDataB64) continue;
        listRecordId = id;
        try {
          const bytes = base64ToBytes(listDataB64);
          const json = new TextDecoder().decode(bytes);
          listFields = JSON.parse(json) as AccountFields[];
        } catch { /* */ }
        if (listFields) break; // 只需一条列表记录
      }
    }
    // TYPE_ACCOUNT_LEGACY（单条旧格式）
    const legacyIds = getRecordIdsByType(TYPE_ACCOUNT_LEGACY);
    if (legacyIds.length > 0) {
      const legacyB64Map = await getRecordsDataB64Batch(legacyIds);
      for (const id of legacyIds) {
        const legacyDataB64 = legacyB64Map.get(id);
        if (!legacyDataB64) continue;
        try { legacyRecords.push({ id, fields: deserializeAccount(legacyDataB64) }); } catch { /* */ }
      }
    }

    // 修复：扫描 TYPE_ACCOUNT_OLD (0x10) 旧账户记录（迁移失败的兜底）
    //
    // 原缺陷：若 initUnlock 中的 migrateRecordTypes 超时/失败，旧账户记录仍停留在
    //   0x10（与 TYPE_GLOBAL_KEY 冲突的旧值），AccountVerthys 仅扫描 TYPE_ACCOUNT(0x02)
    //   + TYPE_ACCOUNT_LIST(0x20) + TYPE_ACCOUNT_LEGACY(0x03)，不扫描 0x10 →
    //   旧账户记录完全不可见 → "模块内容没有被加载出来"。
    //
    // 修复：扫描 0x10 记录，用 deserializeAccount 内容嗅探区分账户 vs 全局密钥——
    //   账户记录为 JSON（platform/username），全局密钥为二进制，反序列化必然失败。
    //   匹配的记录加入 legacyRecords，后续迁移为 TYPE_ACCOUNT (0x02)。
    const oldIds = getRecordIdsByType(TYPE_ACCOUNT_OLD);
    if (oldIds.length > 0) {
      const oldB64Map = await getRecordsDataB64Batch(oldIds);
      for (const id of oldIds) {
        const oldDataB64 = oldB64Map.get(id);
        if (!oldDataB64) continue;
        try {
          const fields = deserializeAccount(oldDataB64);
          legacyRecords.push({ id, fields });
        } catch { /* 非账户记录（全局密钥二进制）→ 跳过 */ }
      }
    }
  }

  // 2. 有新格式记录 → 追加到现有列表（缓存有效时是增量追加，缓存无效时是构建新列表）
  if (found.length > 0) {
    let nextMemId = accounts.value.length > 0
      ? Math.max(...accounts.value.map(a => a.id)) + 1
      : 1;
    // 项2：批量构建新条目后一次性 pushShallowItems，避免循环内多次触发响应式
    const newItems: AccountEntry[] = [];
    for (const { id, fields } of found) {
      newItems.push({
        id: nextMemId++,
        recordId: id,
        fields,
        pwdVisible: false,
        displayPwd: fields.encrypted ? "已加密" : "••••••••••",
      });
    }
    pushShallowItems(accounts, newItems);
    setModuleCache("accounts", accounts.value);
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
      const migrated: AccountEntry[] = [];
      let nextId = 1;
      for (const fields of fieldsToMigrate) {
        const dataB64 = serializeAccount(fields);
        const newRid = await verthysAddRecord(TYPE_ACCOUNT, `account_${Date.now()}_${migrated.length}`, dataB64);
        migrated.push({
          id: nextId++,
          recordId: newRid ?? undefined,
          fields,
          pwdVisible: false,
          displayPwd: fields.encrypted ? "已加密" : "••••••••••",
        });
      }
      // 项2：shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
      replaceShallowArray(accounts, migrated);
      if (listRecordId !== null) {
        try { await verthysDeleteRecord(listRecordId); } catch { /* */ }
      }
      for (const lr of legacyRecords) {
        try { await verthysDeleteRecord(lr.id); } catch { /* */ }
      }
      // 数据持久化修复：检查迁移落盘返回值，失败时提示用户
      let migratePersistOk = false;
      try { migratePersistOk = await persistVerthys(); } catch (e) { console.error("[loadAccounts] 迁移 persistVerthys 异常", e); }
      if (!migratePersistOk) {
        showError("账号数据迁移已执行但持久化失败，重启后可能需重新迁移。请勿关闭应用并重试");
      }
      clearRecordScanCache(); // 迁移涉及批量增删，清空 scan cache 确保一致性
    } else {
      // 项2：shallowRef 清空需用 clearShallowArray 触发 triggerRef
      clearShallowArray(accounts);
    }
  } else {
    // 项2：shallowRef 清空需用 clearShallowArray 触发 triggerRef
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

const filteredAccounts = computed(() => {
  const k = searchKey.value.trim().toLowerCase();
  return accounts.value.filter(a =>
    !k || a.fields.platform.toLowerCase().includes(k) || a.fields.username.toLowerCase().includes(k)
  );
});

/* 卡片 3D 视差 */
const { onCardMove, onCardLeave } = useCardTilt();

/* 密码显隐 */
const togglePwd = (acc: AccountEntry) => {
  if (!acc.pwdVisible) {
    if (acc.fields.encrypted) {
      keyTarget.value = acc;
      keyInput.value = "";
      keyError.value = false;
      showKeyDialog.value = true;
      return;
    }
    // 项2：shallowRef 下直接修改属性不触发更新，必须 updateShallowItem
    const idx = accounts.value.findIndex(a => a.id === acc.id);
    if (idx >= 0) {
      updateShallowItem(accounts, idx, {
        pwdVisible: true,
        displayPwd: acc.fields.password,
        plainPwd: acc.fields.password,
      });
    }
  } else {
    // 项2：shallowRef 下直接修改属性不触发更新，必须 updateShallowItem
    const idx = accounts.value.findIndex(a => a.id === acc.id);
    if (idx >= 0) {
      updateShallowItem(accounts, idx, {
        pwdVisible: false,
        displayPwd: acc.fields.encrypted ? "已加密" : "••••••••••",
      });
    }
  }
};

/* 解密密钥对话框 */
const showKeyDialog = ref(false);
const keyTarget = ref<AccountEntry | null>(null);
const keyInput = ref("");
const keyInputVisible = ref(false);
const keyError = ref(false);

const confirmKey = async () => {
  if (!keyTarget.value || !keyInput.value) return;
  try {
    const plain = await decryptPasswordField(keyTarget.value.fields.password, keyInput.value);
    // 项2：shallowRef 下通过 id 找索引后 updateShallowItem，避免直接修改 keyTarget.value 属性
    const targetId = keyTarget.value.id;
    const idx = accounts.value.findIndex(a => a.id === targetId);
    if (idx >= 0) {
      updateShallowItem(accounts, idx, {
        plainPwd: plain,
        pwdVisible: true,
        displayPwd: plain,
      });
    }
    showKeyDialog.value = false;
    keyTarget.value = null;
    keyInput.value = "";
  } catch {
    keyError.value = true;
  }
};

/* 复制密码 */
const { clipCountdown, copyWithTimeout } = useClipToast();

const copyPwd = async (acc: AccountEntry) => {
  let plain = acc.plainPwd;
  if (!plain && !acc.fields.encrypted) {
    plain = acc.fields.password;
  }
  if (!plain) {
    togglePwd(acc);
    return;
  }
  await copyWithTimeout(plain);
};

/* CRUD */
const showDialog = ref(false);
const editing = ref<AccountEntry | null>(null);
const form = ref<AccountFields>({ platform: "", username: "", password: "", note: "", encrypted: false, encKey: "" });
const formPwdVisible = ref(false);
const encKeyVisible = ref(false);

const onAdd = () => {
  editing.value = null;
  form.value = { platform: "", username: "", password: "", note: "", encrypted: false, encKey: "" };
  formPwdVisible.value = false;
  encKeyVisible.value = false;
  showDialog.value = true;
};
const onEdit = (acc: AccountEntry) => {
  editing.value = acc;
  form.value = { ...acc.fields, encKey: "" };
  formPwdVisible.value = false;
  encKeyVisible.value = false;
  showDialog.value = true;
};
const onSave = async () => {
  if (!form.value.platform || !form.value.username) return;
  if (form.value.encrypted && !form.value.encKey) return;

  let storedPassword = form.value.password;
  if (form.value.encrypted && form.value.encKey) {
    storedPassword = await encryptPasswordField(form.value.password, form.value.encKey);
  }

  const fields: AccountFields = {
    platform: form.value.platform,
    username: form.value.username,
    password: storedPassword,
    note: form.value.note,
    encrypted: form.value.encrypted,
  };

  showDialog.value = false; // 立即关闭对话框

  // 独立记录模式（参考 PhotoAlbum）：每条账户一条独立 verthys 记录，互不覆盖
  const dataB64 = serializeAccount(fields);
  const recordName = `account_${fields.platform}_${Date.now()}`;

  if (editing.value) {
    // 编辑：先添加新记录 → 删除旧记录 → 更新内存 recordId
    // 顺序：add 新 → delete 旧，避免删除后新增时 recordId 复用导致数据错乱
    const oldRid = editing.value.recordId;
    let newRid: number | null = null;
    try {
      newRid = await verthysAddRecord(TYPE_ACCOUNT, recordName, dataB64);
    } catch (e) {
      if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") {
        showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
        return;
      }
      throw e;
    }
    if (newRid !== null) {
      // 同步两层缓存（摘要 + 全量），替代旧 addRecordToScan
      addFullRecord(newRid, TYPE_ACCOUNT, recordName, dataB64, dataB64.length);
      if (oldRid !== undefined) {
        try { await verthysDeleteRecord(oldRid); } catch { /* 旧记录删除失败不阻断 */ }
        // 失效两层缓存（摘要 + 全量）+ 旧扫描缓存兼容
        invalidateSummaryRecord(oldRid);
        invalidateFullRecord(oldRid);
        invalidateScannedRecord(oldRid);
      }
      const idx = accounts.value.findIndex(a => a.id === editing.value!.id);
      if (idx >= 0) {
        // 项2：shallowRef 下整体替换元素需用 updateShallowItem 触发 triggerRef
        updateShallowItem(accounts, idx, {
          recordId: newRid,
          fields,
          pwdVisible: false,
          displayPwd: fields.encrypted ? "已加密" : "••••••••••",
          plainPwd: undefined,
        });
      }
      setModuleCache("accounts", accounts.value);
    }
  } else {
    // 新增：添加独立记录 → 保存 recordId 到内存
    let newRid: number | null = null;
    try {
      newRid = await verthysAddRecord(TYPE_ACCOUNT, recordName, dataB64);
    } catch (e) {
      if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") {
        showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
        return;
      }
      throw e;
    }
    if (newRid !== null) {
      // 同步两层缓存（摘要 + 全量），替代旧 addRecordToScan
      addFullRecord(newRid, TYPE_ACCOUNT, recordName, dataB64, dataB64.length);
      // 项2：shallowRef 下 push 需用 pushShallowItems 触发 triggerRef
      pushShallowItems(accounts, [{
        id: Date.now(),
        recordId: newRid,
        fields,
        pwdVisible: false,
        displayPwd: fields.encrypted ? "已加密" : "••••••••••",
      }]);
      setModuleCache("accounts", accounts.value);
    }
  }

  await persistVerthys(); // 落盘（串行 flush 队列）
};
/* ===== 删除二次确认 ===== */
const showDeleteConfirm = ref(false);
const deleteTargetName = ref("");
const deleteTargetId = ref<number | null>(null);
const onDelete = (acc: AccountEntry) => {
  deleteTargetId.value = acc.id;
  deleteTargetName.value = `${acc.fields.platform} · ${acc.fields.username}`;
  showDeleteConfirm.value = true;
};
const confirmDelete = async () => {
  if (deleteTargetId.value === null) return;
  const id = deleteTargetId.value;
  const target = accounts.value.find(a => a.id === id);
  const rid = target?.recordId;
  // 立即关闭弹窗 + 移除 UI + 更新缓存（同步无缝，消除删除按钮到内容消失的空白间隔）
  showDeleteConfirm.value = false;
  deleteTargetId.value = null;
  // 项2：shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
  removeShallowItems(accounts, a => a.id === id);
  setModuleCache("accounts", accounts.value);
  // 立即失效扫描缓存（同步，杜绝删除复活）
  if (rid !== undefined) {
    // 失效两层缓存（摘要 + 全量）+ 旧扫描缓存兼容，杜绝删除复活
    invalidateSummaryRecord(rid);
    invalidateFullRecord(rid);
    invalidateScannedRecord(rid);
    // 修复：await deleteAndPersist + await persistVerthys（根治删除后复活）
    //
    // 原缺陷：deleteAndPersist(...).catch(() => {}) 火并忘——
    //   deleteAndPersist 仅将删除 IPC 入队 flushChain + 防抖调度 flush（300ms）。
    //   不 await 意味着函数立即返回，若用户快速操作或应用退出，
    //   防抖 flush 尚未执行 → 磁盘仍含已删记录 → 下次加载"删除后复活"。
    //   .catch(() => {}) 静默吞错 → 用户不知删除失败。
    //
    // 修复：
    //   1. await deleteAndPersist — 确保删除 IPC 完成写入 worker 内存
    //   2. await persistVerthys — 取消防抖，立即落盘（persistVerthys 内部
    //      cancelDebouncedFlush + doFlush，确保磁盘写入完成才返回）
    //   3. 失败时 showError 提示用户重试（不静默吞错）
    //   UI 已同步移除（无缝删除），await 不阻塞 UI 渲染。
    try {
      await deleteAndPersist(() => verthysDeleteRecord(rid), rid);
      // 数据持久化修复：检查 persistVerthys 返回值，根治"删除后复活"
      //    persistVerthys 返回 false（非抛异常）时旧 catch 无法捕获 → 静默假成功 →
      //    UI 已移除但磁盘未落盘 → 重启后记录"复活"。
      //    修复：检查返回值，失败时 showError 提示用户记录可能未真正删除。
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

/* 修复「页面覆盖」：切换模块时同步关闭所有 Teleport 弹窗，杜绝残留覆盖 */
import { useModuleDialogGuard } from "../../composables/useModuleDialogGuard";
useModuleDialogGuard("accounts", () => {
  showDialog.value = false;
  showKeyDialog.value = false;
  showDeleteConfirm.value = false;
  keyInputVisible.value = false;
  formPwdVisible.value = false;
  encKeyVisible.value = false;
});
</script>

<!-- 共享样式（非 scoped，来自 verthys-common.css） -->
<style src="../../styles/verthys-common.css"></style>

<style scoped>
/* AccountVerthys 模块特有样式 */
.account-verthys { /* verthys-module 已在共享样式中 */ }

/* 用户名行 */
.username {
  font-size: 12px; color: var(--text-secondary);
  margin-bottom: 8px; font-family: var(--font);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

/* 锁定徽章 */
.lock-badge { width: 14px; height: 14px; color: var(--warning); flex-shrink: 0; }
.lock-badge svg { width: 100%; height: 100%; }

/* 加密选项 */
.encrypt-row { padding: 10px 12px; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); transition: all 0.2s; }
.encrypt-row.on { border-color: rgba(0,212,255,0.25); background: rgba(0,212,255,0.03); }
.encrypt-toggle { display: flex; align-items: center; gap: 8px; cursor: pointer; user-select: none; }
.encrypt-toggle input { display: none; }
.encrypt-check { width: 14px; height: 14px; border: 1px solid var(--border-glass); border-radius: 3px; position: relative; transition: all 0.2s; flex-shrink: 0; }
.encrypt-row.on .encrypt-check { background: var(--accent); border-color: var(--accent); }
.encrypt-row.on .encrypt-check::after { content: ""; position: absolute; left: 4px; top: 1px; width: 4px; height: 8px; border: solid #000; border-width: 0 2px 2px 0; transform: rotate(45deg); }
.encrypt-label { font-size: 11px; color: var(--text-secondary); }
.encrypt-key-input { display: flex; align-items: center; gap: 6px; margin-top: 8px; }
.encrypt-key-input .input { flex: 1; min-width: 0; }

/* 解密密钥对话框 */
.key-target { font-size: 12px; color: var(--text-secondary); font-family: var(--font); margin-bottom: 14px; }
.key-error { font-size: 11px; color: var(--danger); margin-top: 6px; }
</style>
