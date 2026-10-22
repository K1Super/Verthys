<!--
  ManagementTopBar.vue — 管理界面会话谱线（无卡片顶栏）
  设计：引力谱系 · sf-meridian —— 状态脉动点 + 行内文本 + 接线端子，
  水平能量丝线收尾（零底板/零边框/零阴影）

  职责：
    1. 全局密钥状态脉动点（on=青绿呼吸 / 琥珀静止）
    2. 状态文本（标题 + 子标题含会话空闲倒计时，mono 微文）
    3. 更新端子（无可用更新=检查；有可用更新=更新到指定版本）
    4. 立即锁定端子（sf-terminal--warn，禁用条件：!globalKeyReady）

  Props: globalKeyReady / sessionRemaining / idleLockEnabled
         / updateAvailable / updateVersion / updateChecking / updateInstalling
         / updatePercent
  Emits: lockAll / checkUpdate / installUpdate
-->
<template>
  <div class="sf-meridian">
    <div class="sf-meridian-status">
      <span class="sf-pulse anim-status" :class="{ on: globalKeyReady }"></span>
      <div class="sf-meridian-text">
        <div class="sf-meridian-title">
          {{ globalKeyReady ? '全局密钥已就绪' : '未就绪' }}
        </div>
        <div class="sf-meridian-sub">
          <span v-if="globalKeyReady && idleLockEnabled">会话空闲 {{ Math.ceil(sessionRemaining / 60000) }} 分钟后自动锁定</span>
          <span v-else-if="globalKeyReady">会话空闲锁定已关闭</span>
          <span v-else>请验证全局密钥</span>
        </div>
      </div>
    </div>
    <div class="sf-meridian-actions">
      <button
        class="sf-terminal sf-terminal--update"
        :disabled="updateChecking || updateInstalling"
        @click="updateAvailable ? $emit('installUpdate') : $emit('checkUpdate')"
        v-tip="updateAvailable ? '下载并安装新版本（安装前自动落盘并锁定）' : '检查是否有可用更新'"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M20 12a8 8 0 1 1-2.34-5.66"/><path d="M20 4v4h-4"/></svg>
        {{ updateLabel }}
      </button>
      <button
        class="sf-terminal sf-terminal--warn"
        @click="$emit('lockAll')"
        :disabled="!globalKeyReady"
        v-tip="'锁定全部并清零内存密钥'"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        立即锁定
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";

/**
 * ManagementTopBar Props
 */
const props = defineProps<{
  /** 全局密钥就绪状态（控制状态图标 + 锁定按钮 disabled） */
  globalKeyReady: boolean;
  /** 会话剩余时间（毫秒，UI 倒计时显示） */
  sessionRemaining: number;
  /** 会话空闲锁定开关（false = 不自动锁定，展示"已关闭"） */
  idleLockEnabled: boolean;
  /** 是否存在已发现且尚未安装的更新 */
  updateAvailable: boolean;
  /** 可安装的更新版本号（无更新时为空串） */
  updateVersion: string;
  /** 更新检查进行中 */
  updateChecking: boolean;
  /** 更新下载或安装进行中 */
  updateInstalling: boolean;
  /** 下载进度百分比（0-100，未知总长时为 0） */
  updatePercent: number;
}>();

/**
 * ManagementTopBar Emits
 */
defineEmits<{
  /** 立即锁定全部并清零内存密钥 */
  (e: "lockAll"): void;
  /** 手动检查更新 */
  (e: "checkUpdate"): void;
  /** 下载并安装已发现的更新 */
  (e: "installUpdate"): void;
}>();

/** 端子文案：检查中 / 更新中（含进度）/ 更新到指定版本 / 检查更新 */
const updateLabel = computed(() => {
  if (props.updateInstalling) {
    return props.updatePercent > 0 ? `正在更新 ${props.updatePercent}%` : "正在更新…";
  }
  if (props.updateChecking) return "检查中…";
  return props.updateAvailable ? `更新到 ${props.updateVersion}` : "检查更新";
});
</script>
