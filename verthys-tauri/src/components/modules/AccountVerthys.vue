<!--
  AccountVerthys.vue — 存签：账户密码库模块
  列表：浮动搜索栏 + 卡片网格（3D 视差、悬浮操作、密码复制倒计时）
  登记窗口：VerthysDialog 承载「凭证登记台」皮肤（与枢钥共用 reg-* 词汇），
            独立加密开关联动独立密钥登记行；保存前校验以窗口内联提示反馈
-->
<template>
  <div class="account-verthys verthys-module">
    <!-- 瞬时提示（错误/复制倒计时）统一由全局 ToastLayer 渲染（App 根节点单点挂载，--z-toast 最高层） -->

    <!-- 搜索栏 -->
    <VerthysSearchBar v-model="searchKey" placeholder="搜索平台 / 账户…" add-label="新增账户" :sky-seed="5" @add="onAdd" />

    <!-- 卡片网格：≥200 条启用虚拟滚动，小列表保留原 v-for 路径零开销 -->
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

    <!-- 账户登记窗口：与枢钥共用「凭证登记台」皮肤（分区登记行 + 刻度轴 + 选项条） -->
    <VerthysDialog
      v-model="showDialog"
      :title="editing ? '编辑账户' : '新增账户'"
      layout="plain"
      class="reg-panel"
      :save-label="editing ? '保存修改' : '登记入库'"
      :save-disabled="form.encrypted && !form.encKey"
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
            <span class="reg-kicker">存签 · 账户登记</span>
            <span class="reg-title">{{ editing ? '编辑账户' : '新增账户' }}</span>
          </span>
          <button class="reg-close" type="button" @click="showDialog = false" aria-label="关闭窗口" v-tip="'关闭'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </header>
      </template>

      <div class="reg-body">
        <!-- 01 标识：平台 / 账户 -->
        <section class="reg-section" :style="{ '--rs': '0' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">01</span>
            <span class="reg-sec-name">标识</span>
            <span class="reg-rule"></span>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="acc-f-platform"><i class="reg-req" aria-hidden="true">*</i>平台</label>
            <input id="acc-f-platform" class="reg-input" v-model="form.platform" placeholder="如 GitHub / 公司邮箱" aria-required="true" />
          </div>
          <div class="reg-row">
            <label class="reg-key" for="acc-f-username"><i class="reg-req" aria-hidden="true">*</i>账户</label>
            <input id="acc-f-username" class="reg-input" v-model="form.username" placeholder="登录名或邮箱" aria-required="true" />
          </div>
        </section>

        <!-- 02 凭据：密码（显隐切换） -->
        <section class="reg-section" :style="{ '--rs': '1' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">02</span>
            <span class="reg-sec-name">凭据<i class="reg-req" aria-hidden="true">*</i></span>
            <span class="reg-rule"></span>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="acc-f-password">密码</label>
            <div class="reg-input-group">
              <input id="acc-f-password" class="reg-input" v-model="form.password" :type="formPwdVisible ? 'text' : 'password'" aria-required="true" />
              <button
                class="icon-btn"
                type="button"
                @click="formPwdVisible = !formPwdVisible"
                :aria-label="formPwdVisible ? '隐藏密码' : '显示密码'"
                v-tip="formPwdVisible ? '隐藏' : '显示'"
              >
                <svg v-if="!formPwdVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
              </button>
            </div>
          </div>
        </section>

        <!-- 03 加密：独立加密开关（编辑既有加密记录时锁定），启用后联动密钥登记行 -->
        <section class="reg-section" :style="{ '--rs': '2' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">03</span>
            <span class="reg-sec-name">加密</span>
            <span class="reg-rule"></span>
          </div>
          <label class="reg-option" :class="{ on: form.encrypted }">
            <input class="reg-option-input" type="checkbox" v-model="form.encrypted" :disabled="editing !== null && editing.fields.encrypted" />
            <span class="reg-option-check"></span>
            <span class="reg-option-text">独立加密</span>
            <span class="reg-option-hint">查看时需二次输入独立密钥</span>
          </label>
          <div v-if="form.encrypted" class="reg-row reg-option-row">
            <label class="reg-key" for="acc-f-encKey">密钥</label>
            <div class="reg-input-group">
              <input
                id="acc-f-encKey"
                class="reg-input"
                v-model="form.encKey"
                :type="encKeyVisible ? 'text' : 'password'"
                :placeholder="editing ? '输入密钥以重新加密' : '设置独立密钥'"
                aria-required="true"
              />
              <button
                class="icon-btn"
                type="button"
                @click="encKeyVisible = !encKeyVisible"
                :aria-label="encKeyVisible ? '隐藏密钥' : '显示密钥'"
                v-tip="encKeyVisible ? '隐藏' : '显示'"
              >
                <svg v-if="!encKeyVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
              </button>
            </div>
          </div>
        </section>

        <!-- 04 附注：备注 -->
        <section class="reg-section" :style="{ '--rs': '3' }">
          <div class="reg-sec-head">
            <span class="reg-sec-no">04</span>
            <span class="reg-sec-name">附注</span>
            <span class="reg-rule"></span>
          </div>
          <div class="reg-row">
            <label class="reg-key" for="acc-f-note">备注</label>
            <textarea id="acc-f-note" class="reg-input reg-textarea" v-model="form.note" rows="2" placeholder="可选备注信息"></textarea>
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
import { persistVerthys, deleteAndPersist, getModuleCache, setModuleCache, invalidateSummaryRecord, invalidateFullRecord, addFullRecord, ensureIndexSourceSafe, getSummaryIdsByType, getRecordIdsByType, invalidateScannedRecord, clearRecordScanCache, getRecordsDataB64Batch } from "../../lib/keyManager";
import { TYPE_ACCOUNT, TYPE_ACCOUNT_LIST, TYPE_ACCOUNT_LEGACY, TYPE_ACCOUNT_OLD } from "../../constants/record_types";
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
/* shallowRef 替代 ref，避免 Vue 对 accounts 数组内每条记录深度代理
 * （每条记录含 fields.password/dataB64 等敏感字段，万条记录深度代理开销 200-500ms）
 * 代价：直接修改元素属性（如 acc.pwdVisible = true）不触发更新，必须用 updateShallowItem */
const accounts = shallowRef<AccountEntry[]>([]);

const loadAccounts = async () => {
  // 0. 缓存优先：先用缓存数据即时渲染
  const cached = getModuleCache<AccountEntry[]>("accounts");
  let maxRecordId = 0;
  if (cached.data && cached.data.length > 0) {
    // shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
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

  // ID 来源：摘要索引优先（仅读索引、不解密数据，不受记录体积影响）；
  //   摘要缓存整体为空（旧格式容器/熔断静默返回空）时回退记录扫描缓存。
  //   记录扫描仍会在后台并发触发一次作数据层预热：命中扫描缓存的小体积记录
  //   在后续批量取数时零 IPC；预热失败不影响列表可用性（取数走并行 IPC 回退）。
  const useSummaryIds = await ensureIndexSourceSafe();
  const idsOf = (type: number): number[] =>
    useSummaryIds ? getSummaryIdsByType(type) : getRecordIdsByType(type);

  // 1. 批量获取新格式 TYPE_ACCOUNT 记录数据（缓存优先，并行 IPC 回退）
  const allAccountIds = idsOf(TYPE_ACCOUNT);
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
    const listIds = idsOf(TYPE_ACCOUNT_LIST);
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
    const legacyIds = idsOf(TYPE_ACCOUNT_LEGACY);
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
    const oldIds = idsOf(TYPE_ACCOUNT_OLD);
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
    // 批量构建新条目后一次性 pushShallowItems，避免循环内多次触发响应式
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
      // shallowRef 整体替换需用 replaceShallowArray 触发 triggerRef
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
      // shallowRef 清空需用 clearShallowArray 触发 triggerRef
      clearShallowArray(accounts);
    }
  } else {
    // shallowRef 清空需用 clearShallowArray 触发 triggerRef
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

/* 卡片光泽追踪（3D 视差倾斜已按用户决策移除，Wave 53） */
const { onCardMove, onCardLeave } = useCardShine();

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
    // shallowRef 下直接修改属性不触发更新，必须 updateShallowItem
    const idx = accounts.value.findIndex(a => a.id === acc.id);
    if (idx >= 0) {
      updateShallowItem(accounts, idx, {
        pwdVisible: true,
        displayPwd: acc.fields.password,
        plainPwd: acc.fields.password,
      });
    }
  } else {
    // shallowRef 下直接修改属性不触发更新，必须 updateShallowItem
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
    // shallowRef 下通过 id 找索引后 updateShallowItem，避免直接修改 keyTarget.value 属性
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

/* 复制密码（提示经全局 Toast 中心倒计时通道渲染） */
const { copyWithTimeout } = useClipToast("密码已复制");

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
const formError = ref("");
const form = ref<AccountFields>({ platform: "", username: "", password: "", note: "", encrypted: false, encKey: "" });
const formPwdVisible = ref(false);
const encKeyVisible = ref(false);

const onAdd = () => {
  editing.value = null;
  form.value = { platform: "", username: "", password: "", note: "", encrypted: false, encKey: "" };
  formError.value = "";
  formPwdVisible.value = false;
  encKeyVisible.value = false;
  showDialog.value = true;
};
const onEdit = (acc: AccountEntry) => {
  editing.value = acc;
  form.value = { ...acc.fields, encKey: "" };
  formError.value = "";
  formPwdVisible.value = false;
  encKeyVisible.value = false;
  showDialog.value = true;
};
const onSave = async () => {
  formError.value = "";
  if (!form.value.platform) { formError.value = "请填写平台名称"; return; }
  if (!form.value.username) { formError.value = "请填写账户"; return; }
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
    const newRid = await verthysAddRecord(TYPE_ACCOUNT, recordName, dataB64);
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
        // shallowRef 下整体替换元素需用 updateShallowItem 触发 triggerRef
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
    const newRid = await verthysAddRecord(TYPE_ACCOUNT, recordName, dataB64);
    if (newRid !== null) {
      // 同步两层缓存（摘要 + 全量），替代旧 addRecordToScan
      addFullRecord(newRid, TYPE_ACCOUNT, recordName, dataB64, dataB64.length);
      // shallowRef 下 push 需用 pushShallowItems 触发 triggerRef
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
  // shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
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
    } catch {
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

/* 登记窗口的选项条 / 登记行 / 输入控件样式已抽取到 verthys-common.css（凭证登记台 · reg-* 词汇） */

/* 解密密钥对话框 */
.key-target { font-size: 12px; color: var(--text-secondary); font-family: var(--font); margin-bottom: 14px; }
.key-error { font-size: 11px; color: var(--danger); margin-top: 6px; }
</style>
