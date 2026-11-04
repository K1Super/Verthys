<!--
  ModuleDangerZone.vue — v4 模块不可逆删除 · 引力谱系子分区
  设计：与「奇点锚定」同一维度 —— 无底板、坐标头、左星座 + 右数据与端子：
    左：裂解星座（断裂开放弧 + 开放菱形核心 + 漂散碎片 + 衰减系链终端）
    右：数据基准（存活 / 已销毁计数）+ 三条轨道条目（模块状态光谱刻度 +
        行尾危险端子）
    尾：错误红字直陈，不用提示盒

  职责：
    1. 查询三个模块的 enabled/unlocked/deleted 状态；
    2. 提供不可逆删除入口，要求用户输入 DELETE 二次确认；
    3. 删除成功后刷新状态。

  安全边界：容器口令由宿主注入；本组件只发 confirm 字面量，不接触密钥。
-->
<template>
  <SpectrumSubPanel
    coord="Module Destruction"
    title="模块数据销毁"
    digest="删除会销毁模块密钥并清除其记录/文件/分片引用，之后可重建空模块"
    tone="danger"
    :error="deleteTarget === null ? error : ''"
  >
    <template #field>
      <!-- 裂解星座：断裂开放弧 + 开放菱形核心 + 漂散碎片 + 衰减系链 -->
      <svg class="sf-sub-svg mdz-field" viewBox="0 0 208 168" aria-hidden="true">
        <defs>
          <linearGradient id="mdz-arc-a" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="rgba(255,71,87,0.55)" />
            <stop offset="100%" stop-color="rgba(255,170,0,0.22)" />
          </linearGradient>
          <linearGradient id="mdz-arc-b" x1="100%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stop-color="rgba(255,170,0,0.32)" />
            <stop offset="100%" stop-color="rgba(139,92,246,0.18)" />
          </linearGradient>
        </defs>

        <!-- 氛围弧：断裂开放弧（两段不连续，慢速差速旋转） -->
        <g class="sf-spin-cw mdz-spin-a">
          <path class="sf-constellation-arc" stroke="url(#mdz-arc-a)" stroke-width="1.8"
            d="M 42 100 A 46 46 0 0 1 74 42" />
        </g>
        <g class="sf-spin-ccw mdz-spin-b">
          <path class="sf-constellation-arc" stroke="url(#mdz-arc-b)" stroke-width="0.9"
            d="M 98 114 A 30 30 0 0 0 125 90" />
        </g>

        <!-- 裂解核心：开放菱形（四边留缝）+ 衰变炽点 -->
        <path class="mdz-seal" fill="none" stroke-width="1.2" stroke-linecap="round"
          d="M 84 66 L 99 81 M 99 87 L 84 102 M 84 102 L 69 87 M 69 81 L 84 66" />
        <circle cx="84" cy="84" r="2" fill="rgba(255,150,150,0.85)" />

        <!-- 漂散碎片：非均匀断片，越远越稀 -->
        <g class="mdz-shards" fill="none" stroke-width="1" stroke-linecap="round">
          <path d="M 112 62 L 118 58" opacity="0.72" />
          <path d="M 120 71 L 126 67 L 127 73" opacity="0.55" />
          <path d="M 134 84 L 143 82" opacity="0.46" />
          <path d="M 130 97 L 137 101 L 133 105" opacity="0.4" />
          <path d="M 116 112 L 121 117" opacity="0.3" />
          <path d="M 146 108 L 150 112" opacity="0.26" />
        </g>
        <circle cx="126" cy="78" r="0.9" fill="rgba(255,170,0,0.35)" />
        <circle cx="141" cy="94" r="0.7" fill="rgba(255,71,87,0.3)" />
        <circle cx="152" cy="101" r="0.6" fill="rgba(139,92,246,0.25)" />

        <!-- 衰减系链：指向已失效的终端节点 -->
        <path class="mdz-tether" fill="none" stroke-width="1"
          stroke-linecap="round" stroke-dasharray="3 7"
          d="M 100 100 C 128 116, 150 122, 172 122" />
        <circle class="mdz-node" cx="176" cy="122" r="2.6" />
      </svg>
    </template>

    <template #info>
      <!-- 数据基准：模块登记计数 -->
        <div class="sf-sub-datum">
          <span class="sf-datum-label">Module Registry · 模块登记</span>
          <div class="sf-sub-datum-row">
            <div class="sf-sub-datum-list">
              <span class="sf-datum-seg">{{ aliveCount }}</span>
              <span class="sf-sub-datum-value">ACTIVE</span>
              <span class="sf-datum-dot" aria-hidden="true"></span>
              <span class="sf-datum-seg" :class="{ 'is-dim': deletedCount === 0 }">{{ deletedCount }}</span>
              <span class="sf-sub-datum-value">DESTROYED</span>
            </div>
            <SfActionNode
              label="刷新模块销毁状态"
              :disabled="loading || busy"
              :busy="loading || busy"
              @click="loadStatuses"
            >
              <svg
                class="sf-act-icon"
                :class="{ 'is-spinning': loading || busy }"
                aria-hidden="true"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                stroke-width="1.5"
              ><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>
            </SfActionNode>
          </div>
        </div>

        <!-- 轨道条目：模块状态光谱刻度 + 行尾危险端子 -->
        <div class="sf-formation">
          <div
            v-for="(m, i) in modules"
            :key="m.id"
            class="sf-orbit mdz-orbit"
            :class="stateClass(m.id)"
          >
            <span class="sf-orbit-idx">{{ String(i + 1).padStart(2, "0") }}</span>
            <div class="sf-orbit-id">
              <span class="sf-orbit-name">{{ m.label }}</span>
              <span class="sf-orbit-status">
                <span class="sf-status-mark" aria-hidden="true"></span>
                <span class="sf-orbit-state-word">{{ stateParts(m.id)[0] }}</span>
                <span
                  v-for="part in stateParts(m.id).slice(1)"
                  :key="part"
                  class="sf-orbit-state-meta"
                >{{ part }}</span>
              </span>
            </div>
            <div class="sf-orbit-actions">
              <SfActionNode
                :label="`${m.label} · 删除模块`"
                :tip="statuses[m.id]?.deleted ? '模块已销毁' : '删除模块（不可逆）'"
                tone="danger"
                :disabled="busy || loading || statuses[m.id]?.deleted === true"
                @click="openDelete(m.id, m.label)"
              >
                <svg
                  class="sf-act-icon"
                  aria-hidden="true"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.5"
                ><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/><path d="M10 11v5M14 11v5"/></svg>
              </SfActionNode>
            </div>
          </div>
        </div>
      </template>

      <template #tail>
        <VerthysDialog
          :model-value="deleteTarget !== null"
          layout="plain"
          width="500px"
          title="删除模块（不可逆）"
          save-label="永久删除"
          :save-disabled="confirmText !== 'DELETE' || busy"
          :saving="busy"
          @update:model-value="(v) => { if (!v && !busy) closeDelete(); }"
          @save="onDelete"
        >
          <div class="mdz-dialog">
            <p class="mdz-warn">
              将永久删除「{{ deleteLabel }}」模块的全部记录、文件与分片，并销毁其模块密钥。
              之后只能重建空模块，旧数据不可恢复。
            </p>
            <p class="mdz-note">
              旧段、低代副本与备份中的旧密文不做物理擦除；请确认已完成必要备份。
            </p>
            <p class="mdz-note">
              删除会逐条清除记录/文件/分片引用，数据量大时可能持续数分钟；
              期间请勿关闭应用。
            </p>
            <p v-if="busy" class="mdz-elapsed" role="status">正在删除，已耗时 {{ busyElapsed }} 秒…</p>
            <p v-if="error" class="mdz-error">{{ error }}</p>
            <label class="mdz-label" for="mdz-confirm">输入 <code>DELETE</code> 确认</label>
            <input
              id="mdz-confirm"
              v-model="confirmText"
              class="mdz-input"
              autocomplete="off"
              spellcheck="false"
            />
          </div>
        </VerthysDialog>
      </template>
    </SpectrumSubPanel>
  </template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import SfActionNode from "./SfActionNode.vue";
import SpectrumSubPanel from "./SpectrumSubPanel.vue";
import VerthysDialog from "../common/verthys-ui/VerthysDialog.vue";
import {
  verthysV4ModuleDelete,
  verthysV4ModuleStatus,
} from "../../lib/verthys";
import { loadModuleKeyStatus } from "../../key/module-auth";
import { clearModuleCache, clearRecordScanCache } from "../../cache/composition/verthys-cache";
import { MODULE_CACHE_KEY, MODULE_IDS } from "../../constants/key_manager_const";
import type { VerthysResponse } from "../../types/verthys";

const modules = [
  { id: 0, label: "照片" },
  { id: 1, label: "账户" },
  { id: 2, label: "文件" },
] as const;

const statuses = reactive<Record<number, VerthysResponse | null>>({ 0: null, 1: null, 2: null });
const loading = ref(false);
const busy = ref(false);
const error = ref("");
const deleteTarget = ref<number | null>(null);
const deleteLabel = ref("");
const confirmText = ref("");
/** 删除事务已耗时（秒）：C 层清除耗时随数据量增长，必须显示真实推进 */
const busyElapsed = ref(0);
let elapsedTimer: ReturnType<typeof setInterval> | null = null;

/** 登记计数：存活 = 状态可读且未删除；销毁 = 已删除（读数失败不计入任一侧） */
const aliveCount = computed(
  () =>
    modules.filter((m) => {
      const st = statuses[m.id];
      return !!st && st.ok !== false && st.deleted !== true;
    }).length,
);
const deletedCount = computed(
  () => modules.filter((m) => statuses[m.id]?.deleted === true).length,
);

const startElapsed = () => {
  stopElapsed();
  const startedAt = Date.now();
  busyElapsed.value = 0;
  elapsedTimer = setInterval(() => {
    busyElapsed.value = Math.floor((Date.now() - startedAt) / 1000);
  }, 1000);
};

function stopElapsed(): void {
  if (elapsedTimer) {
    clearInterval(elapsedTimer);
    elapsedTimer = null;
  }
}

const loadStatuses = async () => {
  loading.value = true;
  error.value = "";
  try {
    const results = await Promise.all(
      modules.map(async (m) => {
        try {
          return await verthysV4ModuleStatus(m.id);
        } catch {
          return null;
        }
      }),
    );
    modules.forEach((m, i) => {
      statuses[m.id] = results[i];
    });
  } finally {
    loading.value = false;
  }
};

const stateText = (id: number): string => {
  const st = statuses[id];
  if (!st) return "状态未知";
  if (st.deleted) return "已删除";
  if (st.enabled) return st.unlocked ? "已启用 · 已解锁" : "已启用 · 未解锁";
  return "未启用";
};

/** 状态读数分段：首段为主状态词，其余为解锁态等附加读数 */
const stateParts = (id: number): string[] => stateText(id).split(" · ");

/** 状态光谱语义（与 section-field 轨道条目同一套状态色）：绿=活态 / 青=已设 / 灰=未启用 / 红=已销毁 / 琥珀=未知 */
const stateClass = (id: number): string => {
  const st = statuses[id];
  if (!st) return "state-empty";
  if (st.deleted) return "state-deleted";
  if (st.enabled) return st.unlocked ? "state-active" : "state-set";
  return "state-off";
};

const openDelete = (id: number, label: string) => {
  deleteTarget.value = id;
  deleteLabel.value = label;
  confirmText.value = "";
  error.value = "";
};

const closeDelete = () => {
  deleteTarget.value = null;
  deleteLabel.value = "";
  confirmText.value = "";
};

const onDelete = async () => {
  if (deleteTarget.value === null || confirmText.value !== "DELETE" || busy.value) return;
  busy.value = true;
  error.value = "";
  startElapsed();
  try {
    const resp = await verthysV4ModuleDelete(deleteTarget.value, "DELETE");
    if (!resp.ok) {
      error.value = "删除失败：口令校验或策略拒绝";
      return;
    }
    closeDelete();
    await loadStatuses();
    /* 删除后 C 层模块状态已变（deleted），模块保护状态缓存必须同步刷新，
     * 否则安全中心仍会显示"已设置口令"并尝试解锁已删除模块。 */
    await loadModuleKeyStatus();
    /* 记录/分片已被密码学销毁：扫描缓存与三个模块列表缓存必须清空，
     * 否则界面会继续显示已删除模块的旧条目。 */
    clearRecordScanCache();
    for (const moduleId of MODULE_IDS) {
      clearModuleCache(MODULE_CACHE_KEY[moduleId]);
    }
  } catch {
    error.value = "删除失败";
  } finally {
    stopElapsed();
    busy.value = false;
  }
};

onMounted(() => {
  void loadStatuses();
});
</script>

<style scoped>
/* 氛围弧差速旋转：共享关键帧由 section-field.css 承载，
 * 本面板只声明时长；原点沿用默认 84px 84px（idle-governance 通配治理覆盖） */
.mdz-spin-a {
  --sf-spin-duration: 21s;
}
.mdz-spin-b {
  --sf-spin-duration: 13s;
}

/* 裂解核心：危险语义红，克制无辉光 */
.mdz-seal {
  stroke: rgba(255, 120, 120, 0.46);
}
.mdz-shards {
  stroke: rgba(255, 120, 120, 0.55);
}
.mdz-tether {
  stroke: rgba(255, 120, 120, 0.22);
}
.mdz-node {
  fill: rgba(255, 120, 120, 0.3);
}
/* 危险域轨道：悬停丝线不转青，保持红—琥珀衰减语义 */
.mdz-orbit:hover::after {
  background: linear-gradient(
    90deg,
    transparent,
    rgba(255, 71, 87, 0.36) 18%,
    rgba(255, 170, 0, 0.18) 78%,
    transparent
  );
}
.mdz-orbit:hover .sf-orbit-idx {
  color: rgba(255, 120, 120, 0.85);
}
/* 已销毁：状态菱标与文字转危险红 */
.mdz-orbit.state-deleted .sf-status-mark {
  background: rgba(255, 71, 87, 0.75);
}
.mdz-orbit.state-deleted .sf-orbit-state-word {
  color: rgba(255, 120, 120, 0.85);
}
/* 二次确认弹窗：危险语义红字直陈，不加底色与图标 */
.mdz-dialog {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.mdz-warn {
  margin: 0;
  color: rgba(255, 140, 140, 0.92);
  line-height: 1.7;
  font-size: 13px;
  letter-spacing: 0.02em;
}
.mdz-note {
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-secondary);
}
.mdz-elapsed {
  margin: 0;
  font-size: 12px;
  color: rgba(0, 255, 190, 0.85);
}
/* 删除失败：红字直陈（对话框内可见，不加底色、不加图标） */
.mdz-error {
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  letter-spacing: 0.03em;
  color: var(--danger);
}
.mdz-label {
  font-family: var(--font);
  font-size: 10px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--text-muted);
}
.mdz-label code {
  font-family: var(--font);
  color: rgba(255, 140, 140, 0.85);
  letter-spacing: 0.12em;
}
.mdz-input {
  width: 100%;
  padding: 3px 0 7px;
  border: none;
  border-bottom: 1px solid rgba(148, 160, 178, 0.22);
  border-radius: 0;
  background: none;
  color: #e0f4ff;
  font-family: var(--font);
  font-size: 12px;
  letter-spacing: 0.16em;
  outline: none;
  transition: border-color 0.3s var(--ease), color 0.3s var(--ease);
}
.mdz-input:focus {
  border-bottom-color: rgba(255, 71, 87, 0.55);
}
.mdz-input::placeholder {
  color: transparent;
}
</style>
