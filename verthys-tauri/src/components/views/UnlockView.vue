<!--
  UnlockView.vue — 解锁视图（引力悬浮场 · 无底板悬浮体系）
  职责：
    1. 显示初始化状态提示（首次/broken/ready）
    2. 修复失败告警（repair_fail_count >= 3 时显示 ⚠ 提示）
    3. 存储位置选择器（静态选中 + 恢复码/打开/新建图标按钮）
    4. 确认按钮（解锁/创建）
    5. 脉冲星磁层辐射加载 + 解锁进度实时反馈

  悬浮场布局（零底板，不套用卡片式 CosmicDialog）：
    - 零底板：UI 组件直接悬浮于遮罩之上（LevitationField 透视舞台）
    - 节点协议：ff-node（深空定位入射 — 一次性，终态静态驻留；
      无指针视差/斥力/漂移，弹窗保持静态）
    - 排印：协议谱号（VERTHYS · STORAGE）+ 轨道基准线场域命名
-->
<template>
  <div class="view-unlock">
    <Teleport to="body">
    <CosmicBackdrop fixed layer="view" :paused="unlocking" @backdrop="$emit('back')">
    <LevitationField width="330px" class="ff-field--stable">

      <div class="ff-node ff-node--brand">
        <BrandMark />
      </div>

      <div class="ff-node ff-node--title">
        <div class="ff-overline">{{ canRecover ? 'VERTHYS · UNLOCK' : 'VERTHYS · STORAGE' }}</div>
        <div class="ff-title">{{ canRecover ? '解锁安全存储' : '安全存储初始化' }}</div>
        <div class="sc-desc">
          {{ canRecover
            ? '已选择已有存储文件'
            : (initStatusRef === 'broken'
              ? '上次初始化失败，已自动清理残留'
              : '选择已有存储文件或新建保存位置以继续') }}
        </div>
      </div>

      <!-- 修复失败告警 — 初始化详情含 ⚠ 时显示（左缘警示刻线） -->
      <div v-if="initDetailRef && initDetailRef.includes('⚠')" class="ff-node ff-node--body">
        <div class="sc-repair-alert">{{ initDetailRef }}</div>
      </div>

      <div v-if="!unlocking" class="ff-node ff-node--body">
        <div class="form-row">
          <div class="path-row">
            <div class="path-status" :class="{ active: verthysPath, 'path-status--recover': canRecover }">
              <!-- 已选存储位置（文件名 + 完整路径悬停可见） -->
              <span class="ps-path" :class="{ 'ps-path--empty': !verthysPath }" :title="verthysPath || '未选择存储位置'">{{ selectedPathDisplay }}</span>
              <!-- 锁定刻痕组（静态点亮 — 选中确认） -->
              <div class="ps-lock">
                <i class="ps-lock-tick ps-lock-tick-1"></i>
                <i class="ps-lock-tick ps-lock-tick-2"></i>
                <i class="ps-lock-tick ps-lock-tick-3"></i>
              </div>
              <!-- 操作图标（右侧内嵌）：恢复码为备选解锁路径，图标 + 悬浮提示承载语义 -->
              <div class="ps-actions">
                <button
                  v-if="canRecover"
                  class="ps-btn"
                  type="button"
                  aria-label="使用恢复码解锁"
                  @click="$emit('recovery')"
                  v-tip="'使用恢复码解锁'"
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7.5" cy="15.5" r="3.5"/><line x1="10" y1="13" x2="20" y2="3"/><line x1="16.5" y1="6.5" x2="19" y2="9"/></svg>
                </button>
                <span v-if="canRecover" class="ps-divider"></span>
                <button class="ps-btn" type="button" aria-label="打开已有存储文件" @click="$emit('openExisting')" :disabled="unlocking" v-tip="'打开已有存储文件'">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-6l-2-2H5a2 2 0 0 0-2 2z"/></svg>
                </button>
                <span class="ps-divider"></span>
                <button class="ps-btn" type="button" aria-label="新建存储文件" @click="$emit('createNew')" :disabled="unlocking" v-tip="'新建存储文件'">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 创建时 keyfile 因子：仅新建模式显示；勾选后创建前选择保存位置 -->
      <div v-if="!unlocking && isCreate" class="ff-node ff-node--body">
        <label class="kf-toggle" :class="{ 'kf-toggle--on': keyfileCreateEnabled }">
          <input
            type="checkbox"
            :checked="keyfileCreateEnabled"
            :disabled="unlocking"
            @change="
              $emit(
                'update:keyfileCreateEnabled',
                ($event.target as HTMLInputElement).checked,
              )
            "
          />
          <span class="kf-box" aria-hidden="true"></span>
          <span class="kf-text">创建时启用 keyfile 保护</span>
        </label>
      </div>

      <!-- 确认按钮（轨道巡行提交 — 悬浮场锚点）
           布局零位移：按钮常驻（未选路径时 disabled）—
           checkInitStatus 异步自动填充 verthysPath 时仅切换可用态；
           若按 verthysPath 条件挂载该节点，内容高度 +50px 会使
           justify-content: center 重新分布 → 全场内容瞬间下移 ~25px。 -->
      <div v-if="!unlocking" class="ff-node ff-node--action">
        <CosmicSubmit
          label="确认"
          compact
          :loading="unlocking"
          :disabled="!verthysPath"
          @click="$emit('unlock')"
        />
      </div>

      <!-- 引力吸积加载 + 导流通道（按代码关键节点推进进度，精简提示词） -->
      <div class="ff-node ff-node--body">
        <QuantumProgressFlow
          :loading="unlocking && !progressSuppressed"
          :percent-source="progressSource"
          :message="unlockProgressMsg"
          :dimmed="dimmed"
        />
      </div>

    </LevitationField>
    </CosmicBackdrop>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { computed, type Ref } from "vue";
import CosmicBackdrop from "../common/cosmic/CosmicBackdrop.vue";
import LevitationField from "../common/cosmic/LevitationField.vue";
import CosmicSubmit from "../common/cosmic/CosmicSubmit.vue";
import QuantumProgressFlow from "../common/cosmic/QuantumProgressFlow.vue";
import BrandMark from "../common/BrandMark.vue";

/**
 * UnlockView Props
 */
const props = defineProps<{
  /** 已选 verthys 路径 */
  verthysPath: string;
  /** 解锁处理中标志 */
  unlocking: boolean;
  /** 抑制底层解锁进度显示
   *
   * 恢复码弹窗提交期间由弹窗内的验证态承载进度；底层进度仍按同一流程
   * 推进，但不得同时渲染，否则同一操作出现两套进度叙事。 */
  progressSuppressed?: boolean;
  /** 解锁进度消息（阶段描述） */
  unlockProgressMsg: string;
  /** 进度视觉值来源（感知层 ref；由进度条组件直接订阅，避免整视图逐帧重渲染） */
  progressSource?: Readonly<Ref<number>>;
  /** 失败冻结降级标识（进度条降级呈现） */
  dimmed?: boolean;
  /** 解锁进度累计耗时 */
  unlockProgressElapsed: number;
  /** 初始化状态（none/ready/broken） */
  initStatusRef: string;
  /** 初始化详情（含 ⚠ repair_fail_count 告警） */
  initDetailRef: string;
  /** 是否为新建模式（决定是否显示 keyfile 选项） */
  isCreate?: boolean;
  /** 是否存在可恢复的已有容器（决定是否显示恢复码入口与解锁标题） */
  canRecover?: boolean;
  /** 创建时是否启用 keyfile（v-model:keyfileCreateEnabled） */
  keyfileCreateEnabled?: boolean;
}>();

/** 已选路径显示名（仅文件名；完整路径经 title 悬停可见，避免长路径挤爆定宽指示器） */
const selectedPathDisplay = computed(() => {
  const p = props.verthysPath;
  if (!p) return "未选择存储位置";
  return p.split(/[\\/]/).filter(Boolean).pop() || p;
});

/**
 * UnlockView Emits
 */
defineEmits<{
  /** 确认解锁/创建（父组件调用 doUnlock(verthysPath, pendingIsCreate)） */
  (e: 'unlock'): void;
  (e: 'recovery'): void;
  /** 返回主页 */
  (e: 'back'): void;
  /** 打开已有 verthys 文件 */
  (e: 'openExisting'): void;
  /** 创建时是否启用 keyfile */
  (e: 'update:keyfileCreateEnabled', value: boolean): void;
  /** 新建 verthys 文件 */
  (e: 'createNew'): void;
}>();
</script>

<style scoped>
/* 恢复码入口占用操作区后，路径文本与刻痕组左移让位（唯一定宽 260px —
   三枚 24px 图标 + 两道 1px 分隔共占 80px，组内间距归零） */
.path-status--recover .ps-actions {
  gap: 0;
}
.path-status--recover .ps-btn {
  width: 24px;
}
.path-status--recover .ps-path {
  right: 96px;
}
.path-status--recover .ps-lock {
  padding-right: 84px;
}
/* 选择指示格（keyfile 保护）由全局共享层承载，本视图无需声明 */
</style>

