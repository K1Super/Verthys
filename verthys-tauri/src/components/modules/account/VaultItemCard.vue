<!--
  VaultItemCard.vue — 条目卡片（存签唯一卡片渲染源）

  为什么单独成组件：虚拟滚动路径与普通网格路径此前各自内联了一份逐字相同的
  卡片模板（约 70 行）。两份模板必然漂移 —— 一处改了卡片结构、另一处忘改，
  同一模块内出现两种卡片。抽成单一源后，两条路径只保留容器差异。

  版式安全（对应虚拟滚动固定行高）：次行最多展示 2 项，其余以「+N」并入
  同一行；操作区由 margin-top:auto 贴底。内容层因此恒在 172px 行高内，
  不会被虚拟网格的 overflow:hidden 裁掉操作按钮。

  未知类型与损坏条目的呈现裁定：
    - 类型定义缺失 → 不展示任何字段名与字段值（类型声明是「哪些字段敏感」的
      唯一依据，缺失时展示原文等于把密码平铺在卡片上），只给出字段数与
      「重新指派」入口；
    - 载荷不可读 → 只给出「数据不可读」与删除入口，不提供编辑
      （以空表单覆盖保存会抹掉仍可能恢复的原始载荷）。
-->
<template>
  <div
    class="verthys-card glass reveal-item"
    :style="{ '--reveal-delay': `${revealDelay}ms` }"
    @mousemove="onCardMove"
    @mouseleave="onCardLeave"
  >
    <div class="card-accent"></div>

    <div class="card-head">
      <span class="card-title" v-tip="headTitle">{{ headTitle }}</span>
      <span class="vault-type-badge" :style="badgeStyle">
        <span class="badge-icon" aria-hidden="true" v-html="view.icon"></span>
        <span class="badge-name">{{ view.typeLabel }}</span>
      </span>
      <span v-if="locked" class="lock-badge" v-tip="'独立加密'">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      </span>
    </div>

    <!-- 损坏载荷：记录仍存在，但不提供任何字段与编辑入口 -->
    <div v-if="entry.corrupt" class="card-state">
      数据不可读 · 记录 #{{ entry.recordId ?? "—" }}
    </div>

    <!-- 类型定义缺失：只给待重新指派的数据量，不回显任何取值 -->
    <div v-else-if="view.unknown" class="card-state">
      原类型已删除 · {{ view.fieldCount }} 项数据待重新指派
    </div>

    <!-- 账号类型：沿用既有版式（平台 / 账户 / 密码行） -->
    <template v-else-if="isAccount">
      <div class="username">{{ entry.data.username }}</div>
      <div class="secret-row">
        <span class="secret-text">{{ entry.displaySecret }}</span>
        <div class="secret-actions">
          <button
            class="icon-btn"
            type="button"
            @click="$emit('toggle')"
            :aria-label="entry.secretVisible ? '隐藏密码' : '显示密码'"
            v-tip="entry.secretVisible ? '隐藏' : '显示'"
          >
            <svg v-if="!entry.secretVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
          </button>
          <button
            class="icon-btn"
            type="button"
            @click="$emit('copy')"
            aria-label="复制密码"
            v-tip="'复制'"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
      </div>
    </template>

    <!-- 其余类型：主标题 + 次行（最多 2 项 + 余量并入）+ 到期读数 + 敏感行 -->
    <template v-else>
      <div class="card-lines">
        <div v-for="(line, i) in shownLines" :key="line.fieldId" class="card-line">
          <span class="line-label">{{ line.label }}</span>
          <span class="line-value">{{ line.value }}</span>
          <span v-if="i === shownLines.length - 1 && hiddenLineCount > 0" class="line-more">
            +{{ hiddenLineCount }}
          </span>
        </div>
        <div v-if="view.expiry" class="card-line">
          <span class="line-label">{{ view.expiry.label }}</span>
          <span class="card-readout" :style="readoutStyle">{{ view.expiry.text }}</span>
        </div>
      </div>
      <div v-if="view.secret" class="secret-row">
        <span class="secret-label">{{ view.secret.label }}</span>
        <span class="secret-text">{{ entry.displaySecret }}</span>
        <div class="secret-actions">
          <button
            class="icon-btn"
            type="button"
            @click="$emit('toggle')"
            :aria-label="entry.secretVisible ? '隐藏敏感字段' : '显示敏感字段'"
            v-tip="entry.secretVisible ? '隐藏' : '显示'"
          >
            <svg v-if="!entry.secretVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
          </button>
          <button
            class="icon-btn"
            type="button"
            @click="$emit('copy')"
            aria-label="复制敏感字段"
            v-tip="'复制'"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </button>
        </div>
      </div>
    </template>

    <div class="card-actions">
      <button
        v-if="!entry.corrupt"
        class="mini-btn"
        type="button"
        @click="$emit('edit')"
      >{{ view.unknown ? "重新指派" : "编辑" }}</button>
      <button class="mini-btn danger" type="button" @click="$emit('remove')">删除</button>
    </div>

    <div class="card-shine"></div>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import type { VaultEntry } from "../../../types/verthys";
import type { VaultCardView } from "../../../lib/vault_item_card";
import { VAULT_TONE_RGB_VARS, vaultReadoutColorVar } from "../../../lib/vault_item_card";
import { useCardShine } from "../../../composables/useCardShine";

/**
 * 卡片次行展示上限（与 172px 虚拟行高对齐）。
 * 到期读数与敏感行各占一行，故次行收在 2 项；余量以「+N」并入末行。
 */
const MAX_CARD_LINES = 2;

const props = defineProps<{
  /** 内存条目（含展示态） */
  entry: VaultEntry;
  /** 预先构建的卡片视图 */
  view: VaultCardView;
  /** 是否为账号类型（保留既有版式） */
  isAccount: boolean;
  /** 步入错峰延迟（毫秒） */
  revealDelay: number;
}>();

defineEmits<{
  (e: "toggle"): void;
  (e: "copy"): void;
  (e: "edit"): void;
  (e: "remove"): void;
}>();

/* 光泽追踪自持：每张卡片一份（逐帧写入卡片自身 --shine-*，卸载自动断泵） */
const { onCardMove, onCardLeave } = useCardShine();

const headTitle = computed(() => {
  if (props.entry.corrupt) return "数据不可读";
  if (props.view.unknown) return "类型已删除";
  return props.view.title;
});

const locked = computed(() =>
  props.isAccount
    ? props.entry.data.encrypted === "1"
    : props.view.secret?.encrypted === true,
);

const shownLines = computed(() => props.view.lines.slice(0, MAX_CARD_LINES));
const hiddenLineCount = computed(() => Math.max(0, props.view.lines.length - MAX_CARD_LINES));

const badgeStyle = computed<Record<string, string>>(() => ({
  "--tone-rgb": `var(${VAULT_TONE_RGB_VARS[props.view.tone]})`,
}));

const readoutStyle = computed<Record<string, string>>(() => {
  const style: Record<string, string> = {};
  const readout = props.view.expiry;
  if (!readout) return style;
  const colorVar = vaultReadoutColorVar(readout);
  if (colorVar) style.color = `rgb(var(${colorVar}))`;
  return style;
});
</script>

<style scoped>
/* 卡片：撑满虚拟槽位 / 网格行高，操作区贴底 */
.verthys-card {
  display: flex;
  flex-direction: column;
  height: 100%;
}

/* 操作区：贴底紧凑簇（贴底由 margin-top:auto 承担，间距显式收紧到 2px） */
.card-actions { margin-top: auto; gap: 2px; justify-content: flex-start; }

/* 卡片操作键：悬浮/按压的底色注能 + 内收边（登记台同族语言，零阴影） */
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

/* 底缘微亮线：与主键皮肤的势隙线同族，只在悬浮/按压时出现（仅走 opacity） */
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

/* 类型化次行：标签 + 取值紧凑排布（最多两行 + 余量标记） */
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
/* 余量标记：并入末行，不额外占行高 */
.line-more {
  flex-shrink: 0; font-size: 10px; font-family: var(--font-mono);
  color: var(--text-muted);
}

/* 未知类型 / 损坏载荷的状态行（不含任何字段取值） */
.card-state {
  margin-bottom: 8px;
  font-size: 11px; line-height: 1.5; letter-spacing: 0.3px;
  color: var(--text-muted); font-family: var(--font);
}

/* 敏感行标签：类型化卡片的敏感行带字段名（账号卡片沿用无标签版式） */
.secret-label {
  flex-shrink: 0; font-size: 10.5px; letter-spacing: 0.5px;
  color: var(--text-muted); font-family: var(--font);
}

/* 到期读数：仪表式回显口径，色调由内联样式给出 */
.card-readout {
  font-family: var(--font-mono); font-size: 10.5px; letter-spacing: 0.4px;
  color: var(--text-muted);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

/* 类型标识：右上角绝对定位，固定字号与最大宽度，超长类型名截断 */
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

/* 锁定徽章：同处右上角并让出类型标识位置，不占标题行宽度 */
.lock-badge { position: absolute; top: 15px; right: 90px; width: 14px; height: 14px; color: var(--warning); }
.lock-badge svg { width: 100%; height: 100%; }
</style>
