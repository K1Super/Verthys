<!--
  ModuleKeyRow.vue — 模块密钥轨道条目（无行底色 · 双行标识 + 读数 + 动作节点组）
  设计：引力谱系 · sf-orbit —— 模块索引（坐标）+ 名称/状态双行标识，
  状态以离散菱标 + 分段读数呈现，不再使用竖标分隔；
  操作区：密钥保护开关 + 修改密钥 / 恢复槽 / 登出，全部复用 SfActionNode
  （开关开启时以 latched 常驻青色，悬浮与图标节点同一套双环校准）

  职责：
    1. 模块名称 + 状态读数（stateClass 控制菱标与状态词色相）
    2. 密钥保护开关（禁用条件：!globalKeyReady）
    3. 生成/修改密钥节点（仅密钥保护开启时显示，禁用条件：!globalKeyReady）
    4. 恢复槽节点（仅启用且已设置时显示，已绑定常驻青绿）
    5. 登出模块节点（仅启用且已登录时显示）

  Props: mid / idx / label / globalKeyReady / enabled / hasRecord / ready /
         hasRecovery / stateClass / stateText
  Emits: toggleEnabled(checked) / openKeyDialog / logoutModule
-->
<template>
  <div class="sf-orbit" :class="stateClass">
    <span class="sf-orbit-idx" aria-hidden="true">{{ String(idx + 1).padStart(2, "0") }}</span>

    <div class="sf-orbit-id">
      <span class="sf-orbit-name">{{ label }}</span>
      <span class="sf-orbit-status">
        <span class="sf-status-mark" aria-hidden="true"></span>
        <span class="sf-orbit-state-word">{{ stateWord }}</span>
        <span
          v-for="part in stateMeta"
          :key="part"
          class="sf-orbit-state-meta"
          :class="{ 'is-ok': part === '恢复槽', 'is-alert': part === '无恢复槽' }"
        >{{ part }}</span>
      </span>
    </div>

    <div class="sf-orbit-actions">
      <!-- 密钥保护开关：与修改独立密钥节点同一套机械刻度键；
           开启时常驻青色（latched），悬浮双环校准完全一致 -->
      <SfActionNode
        :label="`${label} · 模块密钥保护开关`"
        :tip="enabled ? '关闭模块密钥保护' : '启用模块密钥保护'"
        :latched="enabled"
        :pressed="enabled"
        :disabled="!globalKeyReady"
        @click="$emit('toggleEnabled', !enabled)"
      >
        <svg
          class="sf-act-icon"
          aria-hidden="true"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
        ><path d="M12 3l7 2.5v5.7c0 5-3 8-7 9.8-4-1.8-7-4.8-7-9.8V5.5z"/><circle cx="12" cy="10.4" r="1.9"/><path d="M12 12v3"/></svg>
      </SfActionNode>

      <!-- 修改/生成独立密钥：仅密钥保护开启时展示，关闭态不出现也不可聚焦 -->
      <SfActionNode
        v-if="enabled"
        :label="`${label} · ${hasRecord ? '修改独立密钥' : '生成独立密钥'}`"
        :tip="hasRecord ? '修改独立密钥' : '生成独立密钥'"
        :disabled="!globalKeyReady"
        @click="$emit('openKeyDialog')"
      >
        <svg
          class="sf-act-icon"
          aria-hidden="true"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
        ><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>
      </SfActionNode>

      <!-- 恢复槽：换机恢复该模块的前提；已绑定常驻青绿 -->
      <SfActionNode
        v-if="enabled && hasRecord"
        tone="success"
        :latched="hasRecovery"
        :label="`${label} · 恢复槽`"
        :tip="hasRecovery ? '恢复槽已绑定' : '绑定恢复槽'"
        @click="showRecovery = true"
      >
        <svg
          class="sf-act-icon"
          aria-hidden="true"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
        ><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
      </SfActionNode>

      <!-- 登出模块：仅密钥保护开启且模块已登录时展示，关闭态不保留入口 -->
      <SfActionNode
        v-if="enabled && ready"
        :label="`${label} · 登出模块`"
        tip="登出模块"
        @click="$emit('logoutModule')"
      >
        <svg
          class="sf-act-icon"
          aria-hidden="true"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
        ><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      </SfActionNode>
    </div>

    <ModuleRecoveryDialog
      :show="showRecovery"
      :module-label="label"
      :module-id="mid"
      :has-recovery="hasRecovery"
      @close="showRecovery = false"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";
import type { ModuleId } from "../../lib/keyManager";
import ModuleRecoveryDialog from "./ModuleRecoveryDialog.vue";
import SfActionNode from "./SfActionNode.vue";

/** 恢复槽弹窗开关（行内自包含，不向父层扩散状态） */
const showRecovery = ref(false);

/**
 * ModuleKeyRow Props
 * 所有值由父组件 ModuleKeyList 预计算后传入（函数调用已扁平化为值）
 */
const props = defineProps<{
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
  /** 是否已绑定恢复槽 */
  hasRecovery: boolean;
  /** 状态指示样式类（moduleStateClass(mid) 预计算值） */
  stateClass: string;
  /** 状态文本（moduleStateText(mid) 预计算值） */
  stateText: string;
}>();

/** 状态读数按中点分段：首段为主状态词，其余为密级/恢复槽等读数 */
const stateParts = computed(() => props.stateText.split(" · ").filter(Boolean));
const stateWord = computed(() => stateParts.value[0] ?? "");
const stateMeta = computed(() => stateParts.value.slice(1));

/**
 * ModuleKeyRow Emits
 * 所有事件转发至父组件，由 ModuleKeyList 携带 mid 再转发至 ManagementView
 */
defineEmits<{
  /** 切换密钥保护开关（携带新状态） */
  (e: "toggleEnabled", checked: boolean): void;
  /** 打开密钥编辑弹窗 */
  (e: "openKeyDialog"): void;
  /** 登出模块 */
  (e: "logoutModule"): void;
}>();
</script>
