<!--
  ModuleKeyList.vue — 模块独立密钥管理 · 轨道编队分区（无底板）
  设计：引力谱系 · sf-formation —— 每模块一条「轨道条目」：
  模块索引（mono 轨道序号）+ 名称 + 状态光谱刻度，锚定于能量丝线上；
  行无底色，hover 丝线从灰暗点亮为青绿能量流

  职责：
    1. 谱系坐标头（ORBITAL FORMATION / 模块独立密钥管理 / 摘要）
    2. 遍历 moduleIds，为每个模块渲染 ModuleKeyRow（传入轨道索引）
    3. 预计算每个模块的状态值（stateClass/stateText/hasKey/isReady）传入
    4. 转发 ModuleKeyRow 的事件，携带 mid 上抛至 ManagementView

  Props: globalKeyReady / moduleIds / moduleLabels / moduleKeyEnabled /
         hasModuleKeyRecord / moduleKeyReady / hasModuleKey(fn) / isModuleReady(fn) /
         moduleStateClass(fn) / moduleStateText(fn)
  Emits: toggleModuleKeyEnabled(mid, enabled) / openKeyDialog(mid) /
         showModuleKey(mid) / logoutModule(mid)
-->
<template>
  <div class="sf-zone">
    <!-- 谱系坐标头 -->
    <header class="sf-head">
      <span class="sf-ghost" aria-hidden="true">02</span>
      <span class="sf-coord">Orbital Formation</span>
      <h2 class="sf-title">模块独立密钥管理</h2>
      <p class="sf-digest">为每个业务模块生成/修改独立访问密钥，可开启或关闭密钥保护</p>
    </header>

    <!-- 轨道编队：模块条目列表 -->
    <div class="sf-formation">
      <ModuleKeyRow
        v-for="(mid, i) in moduleIds"
        :key="mid"
        :mid="mid"
        :idx="i"
        :label="moduleLabels[mid]"
        :global-key-ready="globalKeyReady"
        :enabled="moduleKeyEnabled[mid]"
        :has-record="hasModuleKeyRecord[mid]"
        :ready="moduleKeyReady[mid]"
        :state-class="moduleStateClass(mid)"
        :state-text="moduleStateText(mid)"
        :has-key="hasModuleKey(mid)"
        :is-ready="isModuleReady(mid)"
        @toggle-enabled="(checked: boolean) => $emit('toggleModuleKeyEnabled', mid, checked)"
        @open-key-dialog="$emit('openKeyDialog', mid)"
        @show-module-key="$emit('showModuleKey', mid)"
        @logout-module="$emit('logoutModule', mid)"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import ModuleKeyRow from "./ModuleKeyRow.vue";
import type { ModuleId } from "../../lib/keyManager";

/**
 * ModuleKeyList Props
 * 函数类型 props（hasModuleKey / isModuleReady / moduleStateClass / moduleStateText）
 * 用于在模板中为每个 mid 预计算状态值，扁平化后传入 ModuleKeyRow
 */
defineProps<{
  /** 全局密钥就绪状态 */
  globalKeyReady: boolean;
  /** 模块 ID 列表 */
  moduleIds: ModuleId[];
  /** 模块标签映射 */
  moduleLabels: Record<string, string>;
  /** 模块密钥保护开关状态 */
  moduleKeyEnabled: Record<string, boolean>;
  /** 模块密钥记录是否存在 */
  hasModuleKeyRecord: Record<string, boolean>;
  /** 模块密钥就绪（已登录）状态 */
  moduleKeyReady: Record<string, boolean>;
  /** 检查模块是否有密钥（函数） */
  hasModuleKey: (mid: ModuleId) => boolean;
  /** 检查模块是否就绪（函数） */
  isModuleReady: (mid: ModuleId) => boolean;
  /** 模块状态指示条样式类（函数） */
  moduleStateClass: (mid: ModuleId) => string;
  /** 模块状态文本（函数） */
  moduleStateText: (mid: ModuleId) => string;
}>();

/**
 * ModuleKeyList Emits
 * 所有事件携带 mid 上抛至 ManagementView，由 Composable 处理
 */
defineEmits<{
  /** 切换模块密钥保护开关 */
  (e: "toggleModuleKeyEnabled", mid: ModuleId, enabled: boolean): void;
  /** 打开模块密钥编辑弹窗 */
  (e: "openKeyDialog", mid: ModuleId): void;
  /** 查看/复制模块密钥 */
  (e: "showModuleKey", mid: ModuleId): void;
  /** 登出模块 */
  (e: "logoutModule", mid: ModuleId): void;
}>();
</script>
