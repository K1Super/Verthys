<!--
  SecurePcrDialog.vue — 高安全模式 PCR 绑定提示

  切换到安全（高安全）预设后，若当前库尚未启用 PCR，提示用户安全预设
  建议绑定 PCR[7,11]（位图 0x880）。本弹窗只承担提示：不收集恢复码、
  不在此处启用；「前往」把管理视图直接带到「设备与 PCR」面板，绑定与
  恢复码校验都在该面板内完成。当前绑定状态作为读数落在标题行右端：
  嵌进提示长句会被读成叙述的一部分。
-->
<template>
  <CosmicOverlay
    :show="show"
    width="460px"
    aria-label="高安全模式 PCR 绑定提示"
    @close="$emit('close')"
  >
    <div class="pcr-head">
      <div class="kv-title">高安全模式 · PCR 绑定</div>
      <span class="pcr-state" :class="stateClass">{{ stateText }}</span>
    </div>

    <div class="pcr-notice">
      固件或启动状态变更将导致解锁失效，需恢复码重密封密钥，启用前请确认恢复码已保存
    </div>

    <div class="kv-actions">
      <button class="btn btn-neutral btn-compact" type="button" @click="$emit('close')">
        确认
      </button>
      <button class="btn btn-primary btn-compact" type="button" @click="$emit('goto')">
        前往
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { computed } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";

const props = defineProps<{
  show: boolean;
  /** 当前库 PCR 绑定状态；null 表示状态读取失败，不假定未绑定 */
  pcrEnabled: boolean | null;
}>();

defineEmits<{
  (e: "close"): void;
  (e: "goto"): void;
}>();

const stateText = computed(() =>
  props.pcrEnabled === true
    ? "当前已绑定"
    : props.pcrEnabled === false
      ? "当前未绑定"
      : "当前状态未确认",
);

const stateClass = computed(() =>
  props.pcrEnabled === true
    ? "is-bound"
    : props.pcrEnabled === false
      ? "is-unbound"
      : "is-unknown",
);
</script>

<style scoped>
/* ===== 标题行读数 =====
 * 绑定状态随标题落在右端：嵌进提示长句会被读成叙述的一部分，独立成行
 * 又多出一条事实轴；标题行右端是唯一不与正文争夺注意力的落点。 */
.pcr-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 10px;
}
.pcr-head .kv-title {
  margin-bottom: 0;
}
.pcr-state {
  flex-shrink: 0;
  font-size: 11px;
  letter-spacing: 0.04em;
  white-space: nowrap;
}
.pcr-state.is-unbound {
  color: rgba(255, 217, 160, 0.92);
}
.pcr-state.is-unknown {
  color: rgba(132, 148, 168, 0.92);
}
.pcr-state.is-bound {
  color: rgba(120, 235, 255, 0.85);
}
/* ===== 提示正文 =====
 * 影响与前提压在一段叙述里，只保留一条信息轴。 */
.pcr-notice {
  font-size: 12px;
  line-height: 1.8;
  letter-spacing: 0.01em;
  color: rgba(155, 171, 194, 0.9);
}
</style>
