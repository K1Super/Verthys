<!--
  ModuleKeyRow.vue — 模块轨道条目（无行底色 · 能量丝上的轨道体）
  设计：引力谱系 · sf-orbit —— 轨道序号（mono）+ 名称 + 状态光谱刻度
  （短竖标状态色 + mono 状态文）锚定于底部能量丝线上；
  操作区：能级跃迁开关（sf-toggle）+ 图标节点（sf-node）

  职责：
    1. 模块名称 + 状态光谱刻度（stateClass/stateText）
    2. 密钥保护开关（能级跃迁，禁用条件：!globalKeyReady）
    3. 生成/修改密钥节点（禁用条件：!globalKeyReady || !enabled）
    4. 查看密钥节点（仅 hasRecord 时显示，禁用条件：!hasKey || !isReady）
    5. 登出模块节点（仅 ready 时显示）

  Props: mid / idx / label / globalKeyReady / enabled / hasRecord / ready /
         stateClass / stateText / hasKey / isReady
  Emits: toggleEnabled(checked) / openKeyDialog / showModuleKey / logoutModule
-->
<template>
  <div class="sf-orbit" :class="stateClass">
    <span class="sf-orbit-idx">{{ String(idx + 1).padStart(2, '0') }}</span>
    <span class="sf-orbit-name">{{ label }}</span>
    <div class="sf-orbit-state">
      <span class="sf-state-tick" aria-hidden="true"></span>
      <span>{{ stateText }}</span>
    </div>

    <div class="sf-orbit-actions">
      <!-- 密钥保护开关：能级跃迁 -->
      <label class="sf-toggle" :class="{ disabled: !globalKeyReady }">
        <input
          type="checkbox"
          :checked="enabled"
          :disabled="!globalKeyReady"
          @change="$emit('toggleEnabled', ($event.target as HTMLInputElement).checked)"
        />
        <span class="sf-toggle-track" aria-hidden="true"></span>
        <span class="sf-toggle-node" aria-hidden="true"></span>
      </label>
      <!-- 生成/修改密钥节点（仅密钥保护开启时可用） -->
      <button
        class="sf-node"
        @click="$emit('openKeyDialog')"
        :disabled="!globalKeyReady || !enabled"
        v-tip="hasRecord ? '修改独立密钥' : '生成独立密钥'"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>
      </button>
      <!-- 查看密钥（需已登录） -->
      <button
        v-if="hasRecord"
        class="sf-node"
        @click="$emit('showModuleKey')"
        :disabled="!hasKey || !isReady"
        v-tip="'查看/复制密钥（需先登录该模块）'"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
      </button>
      <!-- 登出模块 -->
      <button
        v-if="ready"
        class="sf-node"
        @click="$emit('logoutModule')"
        v-tip="'登出模块'"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { ModuleId } from "../../lib/keyManager";

/**
 * ModuleKeyRow Props
 * 所有值由父组件 ModuleKeyList 预计算后传入（函数调用已扁平化为值）
 */
defineProps<{
  /** 模块 ID */
  mid: ModuleId;
  /** 轨道序号（moduleIds 索引，mono 两位数显示） */
  idx: number;
  /** 模块显示名称 */
  label: string;
  /** 全局密钥就绪状态（控制全部节点 disabled） */
  globalKeyReady: boolean;
  /** 密钥保护开关状态 */
  enabled: boolean;
  /** 是否存在密钥记录 */
  hasRecord: boolean;
  /** 模块是否已登录就绪 */
  ready: boolean;
  /** 状态指示样式类（moduleStateClass(mid) 预计算值） */
  stateClass: string;
  /** 状态文本（moduleStateText(mid) 预计算值） */
  stateText: string;
  /** 是否有密钥（hasModuleKey(mid) 预计算值，控制查看节点 disabled） */
  hasKey: boolean;
  /** 是否就绪（isModuleReady(mid) 预计算值，控制查看节点 disabled） */
  isReady: boolean;
}>();

/**
 * ModuleKeyRow Emits
 * 所有事件转发至父组件，由 ModuleKeyList 携带 mid 再转发至 ManagementView
 */
defineEmits<{
  /** 切换密钥保护开关（携带新状态） */
  (e: "toggleEnabled", checked: boolean): void;
  /** 打开密钥编辑弹窗 */
  (e: "openKeyDialog"): void;
  /** 查看/复制模块密钥 */
  (e: "showModuleKey"): void;
  /** 登出模块 */
  (e: "logoutModule"): void;
}>();
</script>
