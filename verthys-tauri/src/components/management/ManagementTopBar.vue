<!--
  ManagementTopBar.vue — 管理界面会话谱线（无卡片顶栏）
  设计：引力谱系 · sf-meridian —— 状态脉动点 + 行内文本 + 危险域端子，
  水平能量丝线收尾（零底板/零边框/零阴影）

  职责：
    1. 全局密钥状态脉动点（on=青绿呼吸 / 琥珀静止）
    2. 状态文本（标题 + 子标题含会话空闲倒计时，mono 微文）
    3. 立即锁定端子（sf-terminal--warn，禁用条件：!globalKeyReady）

  Props: globalKeyReady / sessionRemaining
  Emits: lockAll
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
          <span v-if="globalKeyReady">XChaCha20-Poly1305 · 会话空闲 {{ Math.ceil(sessionRemaining / 60000) }} 分钟后自动锁定</span>
          <span v-else>请验证全局密钥</span>
        </div>
      </div>
    </div>
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
</template>

<script setup lang="ts">
/**
 * ManagementTopBar Props
 */
defineProps<{
  /** 全局密钥就绪状态（控制状态图标 + 锁定按钮 disabled） */
  globalKeyReady: boolean;
  /** 会话剩余时间（毫秒，UI 倒计时显示） */
  sessionRemaining: number;
}>();

/**
 * ManagementTopBar Emits
 */
defineEmits<{
  /** 立即锁定全部并清零内存密钥 */
  (e: "lockAll"): void;
}>();
</script>
