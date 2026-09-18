<!--
  DeviceMismatchView.vue — 设备机器码不匹配拦截视图（引力悬浮场体系）
  职责：
    1. 展示设备验证失败信息（当前设备与已绑定设备不匹配）
    2. 显示当前机器码短显示
    3. 提供返回按钮（通知父组件退出当前模块）

  ★ 悬浮场重构：去除 dm-card glass 卡片底板 — 内容以 ff-node
    悬浮于模块底景之上（inline 内嵌场，渐晕收敛适配）；警示图标改用
    薄环容场（去填充盒），提示语改轨道分隔排印

  Props: deviceFingerprintShort — 机器码短显示
  Emits: back — 返回主页（通知父组件退出当前模块）
-->
<template>
  <div class="view-device-mismatch">
    <LevitationField width="400px" inline>

      <div class="ff-node ff-node--brand">
        <div class="dm-icon-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
          </svg>
        </div>
      </div>

      <div class="ff-node ff-node--title">
        <div class="ff-overline">DEVICE · LOCK</div>
        <div class="ff-title ff-title--alert">设备验证失败</div>
      </div>

      <div class="ff-node ff-node--body">
        <div class="dm-desc">
          当前设备与已绑定设备不匹配，中枢模块已被锁定<br/>
          <!-- ★ 空值占位兜底：机器码异步获取期间显示"获取中"而非空白 -->
          机器码: <code>{{ deviceFingerprintShort || '获取中…' }}</code>
        </div>
      </div>

      <div class="ff-node ff-node--body">
        <div class="dm-hint">
          中枢模块仅限首次初始化时的设备访问<br/>
          其他模块仍可正常使用
        </div>
      </div>

      <div class="ff-node ff-node--action">
        <button class="dm-back" @click="$emit('back')">返回</button>
      </div>

    </LevitationField>
  </div>
</template>

<script setup lang="ts">
import LevitationField from "../common/cosmic/LevitationField.vue";

/**
 * DeviceMismatchView Props
 */
defineProps<{
  /** 机器码短显示（用于诊断信息展示） */
  deviceFingerprintShort: string;
}>();

/**
 * DeviceMismatchView Emits
 */
defineEmits<{
  /** 返回主页（通知父组件退出当前模块） */
  (e: 'back'): void;
}>();
</script>
