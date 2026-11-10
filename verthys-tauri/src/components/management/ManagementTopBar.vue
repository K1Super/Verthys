<!--
  ManagementTopBar.vue — 管理界面会话谱线（无卡片顶栏）
  设计：引力谱系 · sf-meridian —— 状态脉动点 + 行内文本 + 机械刻度动作节点，
  水平能量丝线收尾（零底板/零边框/零阴影）

  职责：
    1. 全局密钥状态脉动点（on=青绿呼吸 / 琥珀静止）
    2. 状态文本（标题 + 子标题含会话空闲倒计时，mono 微文）
    3. 动作节点（更新 / 立即锁定）：纯图标机械刻度键，
       语义全部由悬浮提示与 aria-label 承载；更新节点悬浮提示首列当前版本
       （构建期由根 VERSION 注入，发布新版本或应用更新后随构建自然同步）
    4. 更新进行中：图标旋转 + 环形刻度量表按格点亮，
       不可取消阶段保持量表可读
    5. 立即锁定节点（sf-act--warn，禁用条件：!globalKeyReady）

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
      <SfActionNode
        :label="updateAction"
        :tip="updateTip"
        tone="update"
        :disabled="updateChecking || (updateInstalling && !updateCancellable)"
        :busy="updateChecking || (updateInstalling && !updateCancellable)"
        :progressing="updateInstalling"
        :cancel="updateCancellable"
        @click="onUpdateClick"
      >
        <svg
          v-if="updateCancellable"
          class="sf-act-icon"
          aria-hidden="true"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
        ><path d="M6 6l12 12M18 6 6 18"/></svg>
        <svg
          v-else
          class="sf-act-icon"
          :class="{ 'is-spinning': updateChecking || updateInstalling }"
          aria-hidden="true"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
        ><path d="M20 12a8 8 0 1 1-2.34-5.66"/><path d="M20 4v4h-4"/></svg>
        <template #overlay>
          <span v-if="updateAvailable && !updateInstalling" class="sf-act-badge" aria-hidden="true"></span>
          <span v-if="updateInstalling" class="sf-update-dial" aria-hidden="true">
            <span
              v-for="tick in updateTicks"
              :key="tick.index"
              class="sf-update-tick"
              :class="{ 'is-major': tick.major, 'is-lit': tick.lit }"
              :style="{ '--sf-tick-angle': `${tick.angle}deg`, '--sf-tick-color': tick.color }"
            ></span>
          </span>
        </template>
      </SfActionNode>
      <SfActionNode
        label="锁定全部并清零内存密钥"
        tone="warn"
        :disabled="!globalKeyReady"
        @click="$emit('lockAll')"
      >
        <svg
          class="sf-act-icon"
          aria-hidden="true"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
        ><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      </SfActionNode>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import SfActionNode from "./SfActionNode.vue";

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
}>();

/** 当前运行版本：构建期由根 VERSION 注入，不在前端保留任何版本常量；
 * 发布新版本或应用完成更新后，新构建产物内的注入值即为新版本。 */
const appVersion = (import.meta.env.VITE_APP_VERSION ?? "").trim();

/** 更新节点的动作语义：仅描述按钮将执行什么，作为无障碍名称与提示的动作段 */
const updateAction = computed(() => {
  if (props.updateCancellable) return "取消下载并清理已接收数据";
  if (props.updateInstalling) {
    return props.updatePercent > 0 ? `正在更新 ${props.updatePercent}%` : "正在更新";
  }
  if (props.updateChecking) return "正在检查更新";
  return props.updateAvailable
    ? `更新到 ${props.updateVersion}，安装前自动落盘并锁定`
    : "检查是否有可用更新";
});

/** 悬浮提示：当前版本是判断是否需要更新的第一信息，置于动作描述之前；
 * 有可安装版本时用箭头建立「当前 → 目标」的版本对照 */
const updateTip = computed(() => {
  if (!appVersion) return updateAction.value;
  if (props.updateAvailable && !props.updateInstalling && !props.updateCancellable) {
    return `当前 v${appVersion} → ${updateAction.value}`;
  }
  return `当前 v${appVersion} · ${updateAction.value}`;
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

/** 环形量表刻度数；固定数量与角度保证进度推进时刻度身份不变，
 * 不会出现刻度沿圆周重排的旋涡感 */
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
    angle: (index / UPDATE_TICK_COUNT) * 360,
    major: isMajorTick(index),
    lit: index < litTickCount.value,
    color: UPDATE_TICK_COLORS[index],
  })),
);
</script>
