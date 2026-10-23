<!--
  ManagementTopBar.vue — 管理界面会话谱线（无卡片顶栏）
  设计：引力谱系 · sf-meridian —— 状态脉动点 + 行内文本 + 接线端子，
  水平能量丝线收尾（零底板/零边框/零阴影）

  职责：
    1. 全局密钥状态脉动点（on=青绿呼吸 / 琥珀静止）
    2. 状态文本（标题 + 子标题含会话空闲倒计时，mono 微文）
    3. 更新端子（无可用更新=检查；有可用更新=更新到指定版本）
    4. 更新下载中：端子下沿分段刻度按格点亮，主/次刻度构成机械量表
    5. 立即锁定端子（sf-terminal--warn，禁用条件：!globalKeyReady）

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
        :class="{ 'is-progressing': updateInstalling }"
        :disabled="updateChecking || (updateInstalling && !updateCancellable)"
        @click="onUpdateClick"
        v-tip="updateTooltip"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M20 12a8 8 0 1 1-2.34-5.66"/><path d="M20 4v4h-4"/></svg>
        {{ updateLabel }}
        <span v-if="updateInstalling" class="sf-update-scale" aria-hidden="true">
          <span
            v-for="tick in updateTicks"
            :key="tick.index"
            class="sf-update-tick"
            :class="{ 'is-major': tick.major, 'is-lit': tick.lit }"
            :style="{ '--sf-tick-color': tick.color }"
          ></span>
        </span>
      </button>
      <button
        v-if="updateFailed"
        class="sf-terminal"
        @click="$emit('exportLogs')"
        v-tip="'导出更新日志用于排查'"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8M8 17h5"/></svg>
        日志
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
  /** 下载阶段允许取消；锁库与安装移交期间为 false */
  updateCancellable: boolean;
  /** 最近一次更新失败，展示日志导出入口 */
  updateFailed: boolean;
}>();

/**
 * ManagementTopBar Emits
 */
const emit = defineEmits<{
  /** 立即锁定全部并清零内存密钥 */
  (e: "lockAll"): void;
  /** 手动检查更新 */
  (e: "checkUpdate"): void;
  /** 下载并安装已发现的更新 */
  (e: "installUpdate"): void;
  /** 取消当前下载 */
  (e: "cancelUpdate"): void;
  /** 导出更新日志 */
  (e: "exportLogs"): void;
}>();

/** 端子文案：取消下载 / 更新中（含进度）/ 检查中 / 更新到指定版本 */
const updateLabel = computed(() => {
  if (props.updateCancellable) return "取消更新";
  if (props.updateInstalling) {
    return props.updatePercent > 0 ? `正在更新 ${props.updatePercent}%` : "正在更新…";
  }
  if (props.updateChecking) return "检查中…";
  return props.updateAvailable ? `更新到 ${props.updateVersion}` : "检查更新";
});

/** 取消态使用独立提示，避免用户把取消误解为再次安装 */
const updateTooltip = computed(() => {
  if (props.updateCancellable) return "取消下载并清理已接收数据";
  return props.updateAvailable
    ? "下载并安装新版本（安装前自动落盘并锁定）"
    : "检查是否有可用更新";
});

/** 单一入口按当前状态分流，避免按钮文案与动作不一致 */
function onUpdateClick(): void {
  if (props.updateCancellable) {
    emit("cancelUpdate");
    return;
  }
  if (props.updateAvailable) {
    emit("installUpdate");
  } else {
    emit("checkUpdate");
  }
}

/** 机械量表刻度数；固定数量保证文案宽度变化时刻度间距稳定重排，不改变刻度身份 */
const UPDATE_TICK_COUNT = 30;

/** 首尾端桩与每五格主刻度同高，构成可读的量表节拍 */
const isMajorTick = (index: number) => index % 5 === 0 || index === UPDATE_TICK_COUNT - 1;

/** 颜色沿整条量表固定映射，同一刻度在进度推进时保持同色，避免逐帧变色形成液态填充观感 */
const UPDATE_TICK_COLORS = Array.from({ length: UPDATE_TICK_COUNT }, (_, index) => {
  const ratio = index / (UPDATE_TICK_COUNT - 1);
  const green = Math.round(212 + (255 - 212) * ratio);
  const blue = Math.round(255 + (170 - 255) * ratio);
  return `rgba(0, ${green}, ${blue}, 0.90)`;
});

/** 点亮数量按整格推进，避免连续填充变成流体进度条；100% 单独补满末格 */
const litTickCount = computed(() => {
  if (!props.updateInstalling) return 0;
  const percent = Math.max(0, Math.min(100, props.updatePercent));
  if (percent >= 100) return UPDATE_TICK_COUNT;
  return Math.floor((percent / 100) * UPDATE_TICK_COUNT);
});

const updateTicks = computed(() =>
  Array.from({ length: UPDATE_TICK_COUNT }, (_, index) => ({
    index,
    major: isMajorTick(index),
    lit: index < litTickCount.value,
    color: UPDATE_TICK_COLORS[index],
  })),
);
</script>
