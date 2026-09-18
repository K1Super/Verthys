<!--
  GlobalKeySection.vue — 全局密钥与设备绑定 · 奇点锚定分区（无底板）
  设计：引力谱系 · sf-anchor —— 不对称双栏：
    左：奇点星座 SVG（核心辉点 + 双开放弧 + 设备系链曲线 + 终端节点，
        形态即绑定状态，与引导区/量子面板视觉语言同源）
    右：数据基准（设备机器码 mono 分段）+ 动作端子纵列（带描述微文）

  职责：
    1. 谱系坐标头（SINGULARITY ANCHOR / 全局密钥与设备绑定 / 摘要）
    2. 设备机器码分段显示（gk 异步获取期间显示「获取中」占位）
    3. 修改全局密钥端子（禁用条件：!globalKeyReady）
    4. 导出密钥文件端子（禁用条件：!globalKeyReady）

  Props: globalKeyReady / deviceFingerprintShort
  Emits: openChangeKeyDialog / exportBin
-->
<template>
  <div class="sf-zone">
    <!-- 谱系坐标头 -->
    <header class="sf-head">
      <span class="sf-ghost" aria-hidden="true">01</span>
      <span class="sf-coord">Singularity Anchor</span>
      <h2 class="sf-title">全局密钥与设备绑定</h2>
      <p class="sf-digest">修改全局访问密钥、更换密钥文件、查看设备绑定</p>
    </header>

    <div class="sf-anchor">
      <!-- 奇点星座：核心 + 开放弧（差速旋转）+ 设备系链 -->
      <svg class="sf-anchor-svg" viewBox="0 0 208 168" aria-hidden="true">
        <defs>
          <linearGradient id="sf-arc-a" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="rgba(0,255,190,0.85)"/>
            <stop offset="100%" stop-color="rgba(0,212,255,0.45)"/>
          </linearGradient>
          <linearGradient id="sf-arc-b" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stop-color="rgba(139,92,246,0.7)"/>
            <stop offset="100%" stop-color="rgba(0,212,255,0.3)"/>
          </linearGradient>
        </defs>

        <!-- 主开放弧（120°，顺时针慢旋） -->
        <g class="sf-arc-spin-a">
          <path class="sf-singularity-arc" stroke="url(#sf-arc-a)" stroke-width="2.2"
            d="M 46 96 A 46 46 0 0 1 88 52" />
        </g>
        <!-- 次开放弧（80°，逆时针差速） -->
        <g class="sf-arc-spin-b">
          <path class="sf-singularity-arc" stroke="url(#sf-arc-b)" stroke-width="1.1"
            d="M 92 108 A 32 32 0 0 0 124 88" />
        </g>

        <!-- 奇点核心：白色炽点 + 青色辉晕 -->
        <circle cx="84" cy="84" r="14" fill="rgba(0,255,190,0.08)" />
        <circle cx="84" cy="84" r="3.2" fill="#dbfff4"
          style="filter: drop-shadow(0 0 4px rgba(120,235,255,0.7))" />

        <!-- 设备系链：悬链曲线（奇点 → 设备终端节点） -->
        <path fill="none" stroke="rgba(0,255,190,0.55)" stroke-width="1.15"
          stroke-linecap="round" stroke-dasharray="4 3"
          d="M 98 94 C 128 112, 148 118, 172 118" />
        <!-- 系链终端节点（设备端点） -->
        <circle cx="176" cy="118" r="3.4" fill="#00ffbe"
          style="filter: drop-shadow(0 0 3px rgba(0,255,190,0.6))" />
        <!-- 系链旁能量微屑（非均匀三枚） -->
        <circle cx="132" cy="108" r="1" fill="rgba(0,212,255,0.5)" />
        <circle cx="154" cy="124" r="0.8" fill="rgba(139,92,246,0.5)" />
        <circle cx="118" cy="102" r="0.6" fill="rgba(0,255,170,0.45)" />
      </svg>

      <!-- 数据基准 + 动作端子纵列 -->
      <div class="sf-anchor-info">
        <div class="sf-datum">
          <span class="sf-datum-label">Device Fingerprint · 设备机器码</span>
          <div class="sf-datum-segments">
            <template v-if="segments.length">
              <template v-for="(seg, i) in segments" :key="i">
                <span v-if="i > 0" class="sf-datum-dot" aria-hidden="true"></span>
                <span class="sf-datum-seg">{{ seg }}</span>
              </template>
            </template>
            <span v-else class="sf-datum-seg">获取中…</span>
          </div>
        </div>

        <div class="sf-terminal-col">
          <button
            class="sf-terminal-block"
            @click="$emit('openChangeKeyDialog')"
            :disabled="!globalKeyReady"
            v-tip="'修改全局访问密钥和密钥文件'"
          >
            <span class="sf-tb-label">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>
              修改全局密钥
            </span>
            <span class="sf-tb-desc">更换全局访问密钥与密钥文件口令</span>
          </button>
          <button
            class="sf-terminal-block"
            @click="$emit('exportBin')"
            :disabled="!globalKeyReady"
            v-tip="'导出当前密钥文件备份'"
          >
            <span class="sf-tb-label">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              导出密钥文件
            </span>
            <span class="sf-tb-desc">导出当前密钥文件至本地安全备份</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";

/**
 * GlobalKeySection Props
 */
const props = defineProps<{
  /** 全局密钥就绪状态（控制端子 disabled） */
  globalKeyReady: boolean;
  /** 设备机器码短显示 */
  deviceFingerprintShort: string;
}>();

/** 机器码分段：每 4 字符一段（mono 分段排版；空值占位由模板兜底「获取中…」） */
const segments = computed<string[]>(() => {
  const raw = props.deviceFingerprintShort.trim();
  if (!raw) return [];
  return raw.match(/.{1,4}/g) ?? [raw];
});

/**
 * GlobalKeySection Emits
 */
defineEmits<{
  /** 打开修改全局密钥弹窗 */
  (e: "openChangeKeyDialog"): void;
  /** 导出当前密钥文件备份 */
  (e: "exportBin"): void;
}>();
</script>

<style scoped>
/* 弧流差速旋转（氛围动画 — idle-governance 通配治理覆盖） */
.sf-arc-spin-a {
  transform-origin: 84px 84px;
  animation: sf-arc-cw 16s linear infinite;
}
.sf-arc-spin-b {
  transform-origin: 84px 84px;
  animation: sf-arc-ccw 10s linear infinite;
}
@keyframes sf-arc-cw { to { transform: rotate(360deg); } }
@keyframes sf-arc-ccw { to { transform: rotate(-360deg); } }
</style>
