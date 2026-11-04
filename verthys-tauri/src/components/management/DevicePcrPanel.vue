<!--
  DevicePcrPanel.vue — 设备与 PCR / 恢复码策略 · 引力谱系子分区
  设计：与「奇点锚定」同一维度 —— 无底板、坐标头、左星座 + 右数据与端子：
    左：PCR 寄存器星座（24 枚刻度沿 240° 开放弧排布，已选位点亮；
        核心为开放菱形封印 + 炽点，开放弧差速旋转；系链通往设备终端节点）
    右：数据基准（已绑定 PCR 序号 + 十六进制位图）+ 输入谱线 + 端子纵列
    尾：安全注记（上缘细线分隔，不用提示盒）

  职责：
    1. 查询并展示 PCR 绑定状态与位图；
    2. 启用/关闭/重密封 PCR（恢复码二次认证）；
    3. 轮换一次性恢复码（二次确认后提交），新码上抛给 SecurityCenter
       顶层的单一 RecoveryCodeDialog 展示，避免嵌套弹窗随分区卸载丢码。

  安全约束：恢复码只在本组件内存中短暂驻留，提交或确认后立即清空；
  不写 localStorage、不输出 console、不进入 URL。
-->
<template>
  <SpectrumSubPanel
    coord="PCR Bind"
    title="设备与 PCR"
    digest="PCR 绑定默认关闭；启用、关闭、重密封都需要当前恢复码"
    :error="error"
  >
    <template #field>
      <!-- PCR 寄存器星座：开放弧 + 24 枚寄存器刻度 + 封印核心 + 设备系链 -->
      <svg
        class="sf-sub-svg dp-field"
        viewBox="0 0 208 168"
        :class="{ 'is-bound': pcrEnabled }"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id="dp-arc-a" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="rgba(0,255,190,0.8)" />
            <stop offset="100%" stop-color="rgba(0,212,255,0.38)" />
          </linearGradient>
          <linearGradient id="dp-arc-b" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stop-color="rgba(139,92,246,0.6)" />
            <stop offset="100%" stop-color="rgba(0,212,255,0.26)" />
          </linearGradient>
        </defs>

        <!-- 氛围弧：差速旋转，形态不承载状态 -->
        <g class="sf-spin-cw dp-spin-a">
          <path class="sf-constellation-arc" stroke="url(#dp-arc-a)" stroke-width="2.1"
            d="M 40 98 A 46 46 0 0 1 78 42" />
        </g>
        <g class="sf-spin-ccw dp-spin-b">
          <path class="sf-constellation-arc" stroke="url(#dp-arc-b)" stroke-width="1"
            d="M 96 114 A 32 32 0 0 0 126 90" />
        </g>

        <!-- 寄存器阵列：240° 开放弧（底部留缺口给设备系链） -->
        <g>
          <g
            v-for="reg in registers"
            :key="reg.idx"
            :transform="`rotate(${reg.angle} 84 84)`"
          >
            <line
              class="dp-reg"
              :class="{ 'is-lit': reg.lit }"
              x1="84"
              y1="40"
              x2="84"
              :y2="reg.lit ? '26' : '33'"
            />
          </g>
        </g>

        <!-- 封印核心：开放菱形（四边留缝）+ 白色炽点 -->
        <path class="dp-seal" fill="none" stroke-width="1.2" stroke-linecap="round"
          d="M 84 66 L 99 81 M 99 87 L 84 102 M 84 102 L 69 87 M 69 81 L 84 66" />
        <circle cx="84" cy="84" r="2.2" fill="#dbfff4"
          style="filter: drop-shadow(0 0 3px rgba(120, 235, 255, 0.55))" />

        <!-- 设备系链：悬链曲线（封印 → 设备终端节点） -->
        <path class="dp-tether" fill="none" stroke-width="1.1"
          stroke-linecap="round" stroke-dasharray="4 3"
          d="M 100 98 C 130 114, 150 120, 172 120" />
        <circle class="dp-node" cx="176" cy="120" r="3.2" />
        <circle cx="132" cy="110" r="1" fill="rgba(0,212,255,0.45)" />
        <circle cx="154" cy="124" r="0.8" fill="rgba(139,92,246,0.45)" />
        <circle cx="118" cy="104" r="0.6" fill="rgba(0,255,170,0.4)" />
      </svg>
    </template>

    <template #info>
      <!-- 数据基准：目标/已绑定寄存器序号 + 位图值 -->
        <div class="sf-sub-datum">
          <span class="sf-datum-label">
            {{ pcrEnabled ? "Bound Registers · 已绑定 PCR" : "Target Registers · 目标 PCR" }}
          </span>
          <div class="sf-sub-datum-row">
            <div class="sf-sub-datum-list">
              <template v-if="selectedIndexes.length">
                <template v-for="(idx, i) in selectedIndexes" :key="idx">
                  <span v-if="i > 0" class="sf-datum-dot" aria-hidden="true"></span>
                  <span class="sf-datum-seg">{{ String(idx).padStart(2, "0") }}</span>
                </template>
              </template>
              <span v-else class="sf-sub-datum-void">—</span>
            </div>
            <span v-if="selectedIndexes.length" class="sf-sub-datum-value">{{ activeHex }}</span>
            <SfActionNode
              label="刷新设备 PCR 状态"
              :disabled="loading"
              :busy="loading"
              @click="loadStatus"
            >
              <svg
                class="sf-act-icon"
                :class="{ 'is-spinning': loading }"
                aria-hidden="true"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="1.5"
              ><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>
            </SfActionNode>
          </div>
        </div>

        <!-- 输入谱线：位图与恢复码 -->
        <div class="sf-ports">
          <div class="sf-port">
            <label class="sf-port-label" for="pcr-set">PCR 集合 · 十六进制位图</label>
            <input
              id="pcr-set"
              v-model="pcrSelectText"
              class="sf-port-input"
              :disabled="pcrEnabled || busy"
              spellcheck="false"
              autocomplete="off"
            />
          </div>
          <div class="sf-port">
            <label class="sf-port-label" for="pcr-recovery">恢复码</label>
            <input
              id="pcr-recovery"
              v-model="recoveryCode"
              class="sf-port-input"
              type="password"
              autocomplete="off"
              spellcheck="false"
            />
          </div>
        </div>

        <!-- 端子纵列：统一动作端子（标签 + 描述整体为一个按钮） -->
        <div class="sf-terminal-col">
          <ActionTerminal
            :label="pcrEnabled ? '关闭 PCR 绑定' : '启用 PCR 绑定'"
            :desc="pcrEnabled ? '解除固件状态门槛，恢复标准口令认证' : '将容器解锁绑定到当前固件的 PCR 状态'"
            icon="shield"
            :disabled="busy"
            @action="onToggle"
          />
          <ActionTerminal
            label="重密封"
            desc="固件或启动环境变化后，用恢复码重新封装本机密钥槽"
            icon="sync"
            :disabled="busy || !pcrEnabled"
            @action="onReseal"
          />
          <ActionTerminal
            :label="rotateArmed ? '确认轮换（旧码立即失效）' : '轮换恢复码'"
            desc="作废旧恢复码并签发一次性新码，仅展示一次"
            icon="key"
            :armed="rotateArmed"
            :disabled="busy"
            @action="onRotateRecovery"
          />
        </div>
      </template>

      <template #notes>
        <p v-if="recoveryMode" class="sf-sub-note is-warn">
          当前为恢复会话（已由恢复码认证）：启用、关闭、重密封可留空恢复码
        </p>
        <p v-if="rotateArmed" class="sf-sub-note is-warn">
          轮换成功后旧恢复码立即失效，新恢复码单次展示，请妥善保存
        </p>
        <p class="sf-sub-note">
          PCR 只绑定当前固件/启动状态；环境变化导致普通解锁失败时，请先用恢复码解锁再重密封
        </p>
      </template>
    </SpectrumSubPanel>
  </template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import ActionTerminal from "./ActionTerminal.vue";
import SfActionNode from "./SfActionNode.vue";
import SpectrumSubPanel from "./SpectrumSubPanel.vue";
import {
  verthysPcrStatus,
  verthysPcrEnable,
  verthysPcrDisable,
  verthysPcrReseal,
  verthysRecoveryRotate,
  verthysKeyfileStatus,
} from "../../lib/verthys";
import { keyState } from "../../state/key_state";

const emit = defineEmits<{ (e: "recoveryRotated", code: string): void }>();

const DEFAULT_PCR_SELECT = 0x880;
const PCR_MASK = 0x00ff_ffff;
/** 寄存器刻度：24 枚沿 240° 开放弧排布（底部留缺口给设备系链） */
const REGISTER_COUNT = 24;
const REGISTER_START_DEG = -120;
const REGISTER_SPAN_DEG = 240;

const loading = ref(false);
const busy = ref(false);
const pcrEnabled = ref(false);
const pcrSelect = ref(0);
const pcrSelectText = ref(DEFAULT_PCR_SELECT.toString(16));
const recoveryCode = ref("");
/** 当前会话是否由恢复码打开（恢复会话已认证，PCR 操作可不填恢复码） */
const recoveryMode = ref(false);
const error = ref("");
/** 轮换二次确认：首次点击只给出警告，第二次才真正提交。 */
const rotateArmed = ref(false);

watch(recoveryCode, () => {
  rotateArmed.value = false;
});

const loadStatus = async () => {
  loading.value = true;
  error.value = "";
  try {
    const resp = await verthysPcrStatus();
    if (!resp.ok) {
      error.value = "无法读取 PCR 状态";
      return;
    }
    pcrEnabled.value = resp.pcr_enabled === true;
    pcrSelect.value = resp.pcr_select ?? 0;
    if (pcrEnabled.value) {
      pcrSelectText.value = pcrSelect.value.toString(16);
    }
  } catch {
    error.value = "无法读取 PCR 状态";
  } finally {
    loading.value = false;
  }
  /* 恢复会话判定：读数失败按普通会话处理（fail-closed：仍需恢复码） */
  try {
    const kf = await verthysKeyfileStatus();
    recoveryMode.value = kf.ok && kf.recovery_mode === true;
  } catch {
    recoveryMode.value = false;
  }
};

/* 轮换提交后恢复标记清零：重查 PCR 与恢复会话状态。 */
watch(
  () => keyState.verthysStateVersion.value,
  () => {
    void loadStatus();
  },
);

const parseSelect = (): number | null => {
  const value = Number.parseInt(pcrSelectText.value.trim(), 16);
  if (!Number.isFinite(value) || value <= 0 || (value & ~PCR_MASK) !== 0) return null;
  return value;
};

/** 星座与数据基准取用的位图：启用后以权威状态为准，未启用时预览输入值 */
const activeMask = computed<number>(() => {
  if (pcrEnabled.value) return pcrSelect.value;
  return parseSelect() ?? 0;
});

const selectedIndexes = computed<number[]>(() => {
  const indexes: number[] = [];
  for (let i = 0; i < REGISTER_COUNT; i += 1) {
    if ((activeMask.value & (1 << i)) !== 0) indexes.push(i);
  }
  return indexes;
});

const activeHex = computed<string>(() =>
  activeMask.value > 0 ? `0x${activeMask.value.toString(16).toUpperCase()}` : "—",
);

const registers = computed(() =>
  Array.from({ length: REGISTER_COUNT }, (_, i) => ({
    idx: i,
    angle: REGISTER_START_DEG + (REGISTER_SPAN_DEG / (REGISTER_COUNT - 1)) * i,
    lit: (activeMask.value & (1 << i)) !== 0,
  })),
);

const onToggle = async () => {
  if (busy.value) return;
  const code = recoveryCode.value.trim();
  if (!code && !recoveryMode.value) {
    error.value = "请输入当前恢复码";
    return;
  }
  busy.value = true;
  error.value = "";
  try {
    if (pcrEnabled.value) {
      const resp = await verthysPcrDisable(code);
      if (!resp.ok) {
        error.value = "关闭 PCR 失败：恢复码无效或策略拒绝";
        return;
      }
    } else {
      const select = parseSelect();
      if (select === null) {
        error.value = "PCR 位图非法（只允许 PCR0–23，且不能为 0）";
        return;
      }
      const resp = await verthysPcrEnable(select, code);
      if (!resp.ok) {
        error.value = "启用 PCR 失败：恢复码无效、TPM 不可用或策略拒绝";
        return;
      }
    }
    recoveryCode.value = "";
    await loadStatus();
  } catch {
    error.value = "PCR 操作失败";
  } finally {
    busy.value = false;
  }
};

const onReseal = async () => {
  if (busy.value) return;
  const code = recoveryCode.value.trim();
  if (!code && !recoveryMode.value) {
    error.value = "请输入当前恢复码";
    return;
  }
  busy.value = true;
  error.value = "";
  try {
    const resp = await verthysPcrReseal(code);
    if (!resp.ok) {
      error.value = "重密封失败：请在恢复会话中操作或确认恢复码正确";
      return;
    }
    recoveryCode.value = "";
    await loadStatus();
  } catch {
    error.value = "重密封失败";
  } finally {
    busy.value = false;
  }
};

const onRotateRecovery = async () => {
  if (busy.value) return;
  const code = recoveryCode.value.trim();
  if (!code) {
    error.value = "请输入旧恢复码";
    return;
  }
  if (!rotateArmed.value) {
    rotateArmed.value = true;
    error.value = "";
    return;
  }
  busy.value = true;
  error.value = "";
  rotateArmed.value = false;
  try {
    const resp = await verthysRecoveryRotate(code);
    if (!resp.ok || !resp.recovery_code) {
      error.value = "恢复码轮换失败：旧恢复码无效或策略拒绝";
      return;
    }
    recoveryCode.value = "";
    emit("recoveryRotated", resp.recovery_code);
  } catch {
    error.value = "恢复码轮换失败";
  } finally {
    busy.value = false;
  }
};

onMounted(() => {
  void loadStatus();
});
</script>

<style scoped>
/* 氛围弧差速旋转：共享关键帧由 section-field.css 承载，
 * 本面板只声明时长；原点沿用默认 84px 84px（idle-governance 通配治理覆盖） */
.dp-spin-a {
  --sf-spin-duration: 18s;
}
.dp-spin-b {
  --sf-spin-duration: 11s;
}

/* 寄存器刻度：未选中为暗刻度，选中后加长并点亮（形态即绑定拓扑） */
.dp-reg {
  stroke: rgba(148, 160, 178, 0.2);
  stroke-width: 1;
  transition: stroke 0.3s var(--ease);
}
.dp-reg.is-lit {
  stroke: rgba(0, 212, 255, 0.82);
}
.dp-field.is-bound .dp-reg.is-lit {
  stroke: rgba(0, 255, 190, 0.85);
}
/* 封印核心：未启用为冷灰开放菱形，启用后转青绿 */
.dp-seal {
  stroke: rgba(200, 212, 226, 0.42);
  transition: stroke 0.4s var(--ease);
}
.dp-field.is-bound .dp-seal {
  stroke: rgba(0, 255, 190, 0.58);
}
/* 设备系链：未绑定为灰暗断续，绑定后转青绿实段 */
.dp-tether {
  stroke: rgba(148, 160, 178, 0.32);
  stroke-dasharray: 2 6;
  transition: stroke 0.4s var(--ease);
}
.dp-field.is-bound .dp-tether {
  stroke: rgba(0, 255, 190, 0.62);
  stroke-dasharray: 4 3;
}
.dp-node {
  fill: rgba(148, 160, 178, 0.5);
  transition: fill 0.4s var(--ease);
}
.dp-field.is-bound .dp-node {
  fill: #00ffbe;
  filter: drop-shadow(0 0 3px rgba(0, 255, 190, 0.55));
}
</style>
