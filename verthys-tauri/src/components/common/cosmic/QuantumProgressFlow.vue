<!--
  QuantumProgressFlow.vue — 量子能量导流通道进度条

  设计哲学：
    - 量子能量导流通道作为独立的进度条组件，用于全局复用
    - 进度严格控制：percent 严格对应后端代码关键节点 emit 的值（非纯动画）
    - 提示词单一数据源：直接显示后端 emit 的 message（global-verthys.ts 中精简映射）
      前端不再维护预设映射表，消除前后端提示词不一致问题
    - 淡雅美学：低饱和度青/紫/粉，禁止浓厚原色
    - 顶级动态：粒子流、节点脉动、能量呼吸、扫光
    - 防跳变：固定高度槽位（min-height），加载/隐藏零抖动

  组成：
    1. 量子核心加载动画（可选，showLoader=true 时复用 QuantumCoreLoader 组件）
    2. 量子能量导流通道进度条（按代码关键节点推进 percent）


  Props:
    - loading: boolean              是否显示（true 时显示导流通道，可选量子核心动画）
    - percent?: number              进度百分比（0-100，严格按代码节点推进）
    - message?: string              后端 emit 的精简提示词（单一数据源）
    - showMeta?: boolean            是否显示百分比/耗时（默认 false，解锁/验证不显示）
    - compact?: boolean             紧凑模式（缩小通道尺寸）
    - showLoader?: boolean          是否显示量子核心加载动画（默认 true，复用 QuantumCoreLoader）
    - dimmed?: boolean              失败冻结降级样式标识（仅样式，无判断逻辑）

  Emits: 无
  用法：
    <QuantumProgressFlow
      :loading="unlocking"
      :percent="unlockProgressPercent"
      :message="unlockProgressMsg"
    />
-->
<template>
  <div
    v-if="loading"
    class="qf-slot"
    :class="{
      compact,
      'no-text': !displayText,
      'no-loader': !showLoader,
      'qf-dimmed': dimmed,
    }"
  >
    <!-- ===== 量子核心加载动画（复用 QuantumCoreLoader 组件，消除重复代码） ===== -->
    <QuantumCoreLoader v-if="showLoader" :loading="true" />

    <!-- ===== 量子能量导流通道进度条 ===== -->
    <!-- 导流通道主体 -->
    <div class="qf-channel">
      <!-- 通道两端能量端口 -->
      <div class="qf-port qf-port-in"></div>
      <div class="qf-port qf-port-out"></div>

      <!-- 能量填充（进度推进） -->
      <div class="qf-fill" :style="{ width: (percent || 0) + '%' }">
        <!-- 能量流粒子（填充内流动） -->
        <div class="qf-stream"></div>
        <div class="qf-stream qf-stream-2"></div>
      </div>
    </div>

    <!-- 精简提示词（单行短文字，来自后端 emit 的 message） -->
    <div v-if="displayText" class="qf-text">{{ displayText }}</div>

    <!-- 元信息（百分比/耗时，默认隐藏） -->
    <div v-if="showMeta" class="qf-meta">
      <span class="qf-percent">{{ percent || 0 }}%</span>
      <span class="qf-elapsed">{{ ((elapsed || 0) / 1000).toFixed(1) }}s</span>
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * QuantumProgressFlow — 量子能量导流通道进度条（全局复用）
 *
 * 职责：仅渲染导流通道 DOM 与节点状态，纯展示组件，单向数据流，零业务逻辑
 *
 * 重构说明：
 *   - 删除内置 7 层量子核心加载动画（与 QuantumCoreLoader.vue 重复）
 *   - 通过 <QuantumCoreLoader> 组件化复用，单一数据源
 *   - 本组件作为全局进度条复用基准（替代已删除的 QuantumProgressBar）
 *
 * 提示词策略（企业级根治）：
 *   - 后端 emit 的 message 作为单一数据源（global-verthys.ts 中精简映射）
 *   - 前端直接显示 message prop，不再维护预设映射表
 *   - 消除前端预设阈值与后端实际 emit percent 不一致导致的提示词提前/滞后
 *
 * 防跳变机制：
 *   - 固定 min-height 槽位（230px），loading 切换时窗口零抖动
 */
import { computed } from 'vue';
import QuantumCoreLoader from './QuantumCoreLoader.vue';

interface Props {
  /** 是否显示（true 时显示导流通道，可选量子核心动画） */
  loading: boolean;
  /** 进度百分比（0-100，严格按后端代码节点推进） */
  percent?: number;
  /** 后端 emit 的精简提示词（单一数据源，来自 global-verthys.ts emit message） */
  message?: string;
  /** 已用时间（毫秒，仅 showMeta=true 时显示） */
  elapsed?: number;
  /** 是否显示百分比/耗时（默认 false，解锁/验证不显示） */
  showMeta?: boolean;
  /** 紧凑模式（缩小通道尺寸，用于空间受限场景） */
  compact?: boolean;
  /** 是否显示量子核心加载动画（默认 true，复用 QuantumCoreLoader 组件） */
  showLoader?: boolean;
  /** 失败冻结降级标识（样式标识：整体降低不透明度与饱和度） */
  dimmed?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  percent: 0,
  message: '',
  elapsed: 0,
  showMeta: false,
  compact: false,
  showLoader: true,
  dimmed: false,
});

/* ===== 计算属性 ===== */

/**
 * 当前显示的提示词
 *
 * 企业级根治：直接使用后端 emit 的 message（单一数据源）
 * 后端在 global-verthys.ts 中已统一为精简高级文案：
 *   - initCreate: 校验路径/启动安全核心/创建加密库/检查密钥记录/加载摘要/加载密钥配置/创建完成
 *   - initUnlock: 校验路径/启动安全核心/检测格式/升级加密库/解锁加密库/读取索引/派生密钥/
 *                 校验完整性/解密数据/重建索引/生成摘要/校验完成/加载密钥配置/解锁完成
 *   - verifyGlobalKey: 定位密钥记录/扫描密钥记录/验证量子签名/激活安全会话/验证完成
 */
const displayText = computed<string>(() => props.message || '');
</script>

<style scoped>
/* ============================================================
   quantum-flow.css — 量子能量导流通道进度条（scoped 引入）
   ★ min-height 已在 quantum-flow.css 中定义，禁止在此覆盖
     原因：Vite 会将 <style scoped> 中 @import 内容与自定义样式拆分到
     不同 CSS chunk，使用不同 data-v 属性，导致自定义 min-height 无法
     匹配元素（data-v 不一致），量子加载动画被压缩
   ★ ql-loader.css 由 QuantumCoreLoader 组件自行 scoped 引入管理
     （本组件不直接渲染 .ql-loader 元素，通过 <QuantumCoreLoader> 复用）
   ============================================================ */
@import '../../../styles/security/quantum-flow.css';
</style>
