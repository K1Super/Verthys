<!--
  KeyfilePanel.vue — keyfile 因子（D3）· 引力谱系子分区
  设计：与「奇点锚定」同一维度 —— 无底板、坐标头、左星座 + 右数据与端子：
    左：钥匙星座（开放弧匙环 + 匙杆 + 双齿 + 文件槽终端节点，系链形态即启用状态；
        开放弧差速旋转）
    右：数据基准（解锁因子谱：口令 / KEYFILE 两段）+ 端子纵列
    尾：安全注记（上缘细线分隔，不用提示盒）

  职责：
    1. 查询并展示 keyfile 是否启用；
    2. 启用/轮换（生成新 VKFL 文件）与关闭（校验当前 VKFL 文件）。

  安全约束：
    - 只把路径交给后端；keyfile 字节由 C 层在 worker 进程内读取/生成；
    - keyfile 不进入 WebView、不写 localStorage、不输出 console；
    - 启用后必须提醒用户：keyfile 丢失将只能靠恢复码。
-->
<template>
  <SpectrumSubPanel
    coord="Keyfile Factor"
    title="keyfile 因子"
    digest="keyfile 是口令之外的第二个解锁因子；启用后普通解锁必须同时选择 keyfile 文件"
    :error="error"
  >
    <template #field>
      <!-- 钥匙星座：开放匙环 + 匙杆双齿 + 文件槽终端节点 -->
      <svg
        class="sf-sub-svg kf-field"
        viewBox="0 0 208 168"
        :class="{ 'is-on': keyfileEnabled }"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id="kf-arc-a" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="rgba(0,255,190,0.78)" />
            <stop offset="100%" stop-color="rgba(0,212,255,0.36)" />
          </linearGradient>
          <linearGradient id="kf-arc-b" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stop-color="rgba(139,92,246,0.6)" />
            <stop offset="100%" stop-color="rgba(0,212,255,0.24)" />
          </linearGradient>
          <linearGradient id="kf-key" x1="0%" y1="0%" x2="100%" y2="60%">
            <stop offset="0%" stop-color="rgba(0,255,190,0.9)" />
            <stop offset="100%" stop-color="rgba(0,212,255,0.55)" />
          </linearGradient>
        </defs>

        <!-- 氛围弧：差速旋转，形态不承载状态 -->
        <g class="sf-spin-cw kf-spin-a">
          <path class="sf-constellation-arc" stroke="url(#kf-arc-a)" stroke-width="2"
            d="M 34 100 A 48 48 0 0 1 72 40" />
        </g>
        <g class="sf-spin-ccw kf-spin-b">
          <path class="sf-constellation-arc" stroke="url(#kf-arc-b)" stroke-width="1"
            d="M 96 116 A 30 30 0 0 0 125 92" />
        </g>

        <!-- 钥匙本体：300° 开放匙环（下缘留缺口）+ 匙杆 + 双齿 -->
        <g class="kf-key">
          <path class="kf-key-stroke" fill="none" stroke-width="2.1" stroke-linecap="round"
            d="M 55.3 75 A 14 14 0 1 1 52.8 88.8" />
          <line class="kf-key-stroke" x1="80" y1="84" x2="120" y2="84" stroke-width="2.1"
            stroke-linecap="round" />
          <line class="kf-key-stroke" x1="104" y1="84" x2="104" y2="94" stroke-width="2"
            stroke-linecap="round" />
          <line class="kf-key-stroke" x1="114" y1="84" x2="114" y2="91" stroke-width="2"
            stroke-linecap="round" />
        </g>

        <!-- 文件槽终端：开放括号 + 两道文件行 + 对接节点 -->
        <path class="kf-slot" fill="none" stroke-width="1.2" stroke-linecap="round"
          d="M 158 106 L 168 106 L 168 130 L 158 130" />
        <line class="kf-slot-line" x1="161" y1="114" x2="166" y2="114" stroke-width="0.9" />
        <line class="kf-slot-line" x1="161" y1="120" x2="166" y2="120" stroke-width="0.9" />
        <circle class="kf-node" cx="158" cy="114" r="2.4" />

        <!-- 系链：钥匙尖端 → 文件槽（启用后为青绿实段） -->
        <path class="kf-tether" fill="none" stroke-width="1.1"
          stroke-linecap="round" stroke-dasharray="3 4"
          d="M 122 88 C 136 98, 146 104, 155 110" />
        <circle cx="130" cy="96" r="0.8" fill="rgba(0,212,255,0.45)" />
        <circle cx="144" cy="103" r="0.6" fill="rgba(139,92,246,0.45)" />
      </svg>
    </template>

    <template #info>
      <!-- 数据基准：解锁因子谱 -->
        <div class="sf-sub-datum">
          <span class="sf-datum-label">Unlock Factors · 解锁因子</span>
          <div class="sf-sub-datum-row">
            <div class="sf-sub-datum-list">
              <span class="sf-datum-seg">PASSPHRASE</span>
              <span class="sf-datum-dot" aria-hidden="true"></span>
              <span class="sf-datum-seg" :class="{ 'is-dim': !keyfileEnabled }">KEYFILE</span>
            </div>
            <SfActionNode
              label="刷新 Keyfile 因子状态"
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

        <!-- 端子纵列：统一动作端子（标签 + 描述整体为一个按钮） -->
        <div v-if="recoveryMode" class="sf-terminal-col">
          <ActionTerminal
            label="生成新 keyfile 并重绑"
            desc="以本机容器口令签发新 keyfile 并替换当前绑定"
            icon="key"
            :disabled="busy"
            @action="onEnable"
          />
          <ActionTerminal
            label="关闭 keyfile（改为仅口令）"
            desc="解除第二因子，之后仅凭口令解锁（使用本机保管的容器口令）"
            icon="off"
            :disabled="busy || !keyfileEnabled"
            @action="onDisableRecovery"
          />
        </div>

        <div v-else class="sf-terminal-col">
          <ActionTerminal
            :label="keyfileEnabled ? '轮换 keyfile' : '启用 keyfile'"
            :desc="keyfileEnabled ? '签发新的 keyfile 文件并替换当前绑定' : '签发 keyfile 文件，解锁需口令与该文件同持'"
            icon="key"
            :disabled="busy"
            @action="onEnable"
          />
          <ActionTerminal
            label="关闭 keyfile"
            desc="验证当前 keyfile 后解除第二因子"
            icon="off"
            :disabled="busy || !keyfileEnabled"
            @action="onDisable"
          />
        </div>
      </template>

      <template #notes>
        <p v-if="recoveryMode" class="sf-sub-note is-warn">
          当前是恢复码会话。keyfile 丢失时可直接重绑新 keyfile 或改为仅口令：
          这些操作使用本机保管的容器口令，不要求旧 keyfile
        </p>
        <p class="sf-sub-note">
          启用后请妥善保管 keyfile 文件（默认 .vkf）；文件丢失时只能用恢复码解锁，
          解锁后可在本面板重绑新 keyfile 或改为仅口令
        </p>
      </template>
    </SpectrumSubPanel>
  </template>

<script setup lang="ts">
import { onMounted, ref, watch } from "vue";
import ActionTerminal from "./ActionTerminal.vue";
import SfActionNode from "./SfActionNode.vue";
import SpectrumSubPanel from "./SpectrumSubPanel.vue";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  verthysKeyfileStatus,
  verthysKeyfileEnable,
  verthysKeyfileDisable,
} from "../../lib/verthys";
import { keyState } from "../../state/key_state";

const loading = ref(false);
const busy = ref(false);
const keyfileEnabled = ref(false);
const recoveryMode = ref(false);
const error = ref("");

const loadStatus = async () => {
  loading.value = true;
  error.value = "";
  try {
    const resp = await verthysKeyfileStatus();
    if (!resp.ok) {
      error.value = "无法读取 keyfile 状态";
      return;
    }
    keyfileEnabled.value = resp.keyfile_enabled === true;
    recoveryMode.value = resp.recovery_mode === true;
  } catch {
    error.value = "无法读取 keyfile 状态";
  } finally {
    loading.value = false;
  }
};

/* 轮换提交后 C 层恢复标记清零：会话级版本变化时重查权威状态。 */
watch(
  () => keyState.verthysStateVersion.value,
  () => {
    void loadStatus();
  },
);

/** 选择新的 keyfile 保存位置（.vkf） */
const pickSavePath = async (): Promise<string | null> => {
  try {
    const target = await save({
      title: "保存 keyfile 文件",
      filters: [{ name: "Verthys keyfile", extensions: ["vkf"] }],
      defaultPath: "Verthys.keyfile.vkf",
    });
    if (!target) return null;
    return target.toLowerCase().endsWith(".vkf") ? target : `${target}.vkf`;
  } catch {
    return null;
  }
};

/** 选择当前已启用的 keyfile 文件 */
const pickExisting = async (): Promise<string | null> => {
  try {
    const selected = await open({ title: "选择当前 keyfile 文件", multiple: false });
    return typeof selected === "string" && selected ? selected : null;
  } catch {
    return null;
  }
};

const errText = (prefix: string, errorText?: string): string => {
  if (!errorText) return prefix;
  if (errorText.includes("ERR_00000004")) return `${prefix}：目标文件已存在，请换一个位置`;
  if (errorText.includes("ERR_0000001B")) return `${prefix}：keyfile 文件无效`;
  if (errorText.includes("ERR_00000002") || errorText.includes("ERR_00000005")) {
    return `${prefix}：口令校验失败或策略拒绝`;
  }
  return prefix;
};

const onEnable = async () => {
  if (busy.value) return;
  const target = await pickSavePath();
  if (!target) return;
  busy.value = true;
  error.value = "";
  try {
    const resp = await verthysKeyfileEnable(target);
    if (!resp.ok) {
      error.value = errText("启用 keyfile 失败", resp.error);
      return;
    }
    keyfileEnabled.value = true;
    await loadStatus();
  } catch {
    error.value = "启用 keyfile 失败";
  } finally {
    busy.value = false;
  }
};

const onDisable = async () => {
  if (busy.value) return;
  const current = await pickExisting();
  if (!current) return;
  await disableWithPath(current);
};

/** 恢复会话专用：无旧 keyfile，直接改为仅口令（C 层按会话模式放行） */
const onDisableRecovery = async () => {
  if (busy.value) return;
  await disableWithPath(undefined);
};

const disableWithPath = async (path?: string) => {
  busy.value = true;
  error.value = "";
  try {
    const resp = await verthysKeyfileDisable(path);
    if (!resp.ok) {
      error.value = errText("关闭 keyfile 失败", resp.error);
      return;
    }
    keyfileEnabled.value = false;
    await loadStatus();
  } catch {
    error.value = "关闭 keyfile 失败";
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
 * 本面板只声明时长与匙环旋转原点（idle-governance 通配治理覆盖） */
.kf-spin-a {
  --sf-spin-duration: 17s;
  --sf-spin-origin: 72px 84px;
}
.kf-spin-b {
  --sf-spin-duration: 10.5s;
}

/* 钥匙本体：未启用为冷灰，启用后转青绿渐变 */
.kf-key-stroke {
  stroke: rgba(200, 212, 226, 0.4);
  transition: stroke 0.4s var(--ease);
}
.kf-field.is-on .kf-key-stroke {
  stroke: url(#kf-key);
}
/* 文件槽：未绑定为灰暗，启用后点亮 */
.kf-slot,
.kf-slot-line {
  stroke: rgba(148, 160, 178, 0.34);
  transition: stroke 0.4s var(--ease);
}
.kf-field.is-on .kf-slot,
.kf-field.is-on .kf-slot-line {
  stroke: rgba(0, 212, 255, 0.62);
}
/* 系链与对接节点：启用后为青绿实段 */
.kf-tether {
  stroke: rgba(148, 160, 178, 0.3);
  stroke-dasharray: 2 6;
  transition: stroke 0.4s var(--ease);
}
.kf-field.is-on .kf-tether {
  stroke: rgba(0, 255, 190, 0.6);
  stroke-dasharray: 4 3;
}
.kf-node {
  fill: rgba(148, 160, 178, 0.5);
  transition: fill 0.4s var(--ease);
}
.kf-field.is-on .kf-node {
  fill: #00ffbe;
  filter: drop-shadow(0 0 3px rgba(0, 255, 190, 0.5));
}
</style>
