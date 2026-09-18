<!--
  UnlockView.vue — 解锁视图（引力悬浮场 · 无底板悬浮体系）
  职责：
    1. 显示初始化状态提示（首次/broken/ready）
    2. 修复失败告警（repair_fail_count >= 3 时显示 ⚠ 提示）
    3. 存储位置选择器（星尘川流 + 打开/新建按钮）
    4. 确认按钮（解锁/创建）
    5. 脉冲星磁层辐射加载 + 解锁进度实时反馈

  ★ 悬浮场重构（替代卡片式 CosmicDialog）：
    - 零底板：UI 组件直接悬浮于遮罩之上（LevitationField 透视舞台）
    - 节点协议：ff-node（深空定位入射 — 一次性，终态静态驻留；
      指针视差/斥力/漂移体系已彻底移除，弹窗静态）
    - 排印：协议谱号（VERTHYS · STORAGE）+ 轨道基准线场域命名

  Props: verthysPath / unlocking / pendingIsCreate / unlockProgressMsg /
         unlockProgressPercent / unlockProgressElapsed / initStatusRef / initDetailRef
  Emits: unlock / back / openExisting / createNew
-->
<template>
  <div class="view-unlock">
    <Teleport to="body">
    <CosmicBackdrop fixed @backdrop="$emit('back')">
    <LevitationField width="330px" class="ff-field--stable">

      <div class="ff-node ff-node--brand">
        <BrandMark />
      </div>

      <div class="ff-node ff-node--title">
        <div class="ff-overline">VERTHYS · STORAGE</div>
        <div class="ff-title">安全存储初始化</div>
        <div class="sc-desc">
          {{ initStatusRef === 'broken'
            ? '上次初始化失败，已自动清理残留'
            : '选择已有存储文件或新建保存位置以继续' }}
        </div>
      </div>

      <!-- ★ 企业级方案：修复失败告警 — repair_fail_count >= 3 时显示（左缘警示刻线） -->
      <div v-if="initDetailRef && initDetailRef.includes('⚠')" class="ff-node ff-node--body">
        <div class="sc-repair-alert">{{ initDetailRef }}</div>
      </div>

      <div v-if="!unlocking" class="ff-node ff-node--body">
        <div class="form-row">
          <div class="path-row">
            <div class="path-status" :class="{ active: verthysPath }">
              <!-- 深空静默底 + 微星闪烁 -->
              <div class="ps-void">
                <span v-for="i in 6" :key="`s${i}`" class="ps-star" :style="{ '--i': i }"></span>
              </div>
              <!-- 萤群掠痕（激活态：5 粒光尘三速度剖面差化川渡） -->
              <div class="ps-stream" aria-hidden="true">
                <span v-for="m in 5" :key="`m${m}`" class="ps-mote" :class="`ps-mote-${m}`">
                  <i class="ps-mote-core"></i>
                </span>
              </div>
              <!-- 锁定刻痕组（级联点亮 — 激活瞬间的扫描确认） -->
              <div class="ps-lock">
                <i class="ps-lock-tick ps-lock-tick-1"></i>
                <i class="ps-lock-tick ps-lock-tick-2"></i>
                <i class="ps-lock-tick ps-lock-tick-3"></i>
              </div>
              <!-- 操作图标（右侧内嵌） -->
              <div class="ps-actions">
                <button class="ps-btn" @click="$emit('openExisting')" :disabled="unlocking" v-tip="'打开'">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-6l-2-2H5a2 2 0 0 0-2 2z"/></svg>
                </button>
                <span class="ps-divider"></span>
                <button class="ps-btn" @click="$emit('createNew')" :disabled="unlocking" v-tip="'新建'">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 确认按钮（轨道巡行提交 — 悬浮场锚点）
           ★ 布局零位移根治：按钮常驻（未选路径时 disabled）—
           checkInitStatus 异步自动填充 verthysPath 时仅切换可用态，
           节点不再突然挂载（原 v-if="!unlocking && verthysPath" 会使
           内容高度 +50px → justify-content: center 重新分布 →
           全场内容瞬间下移 ~25px 的布局抖动） -->
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
          :loading="unlocking"
          :percent="unlockProgressPercent"
          :message="unlockProgressMsg"
        />
      </div>

    </LevitationField>
    </CosmicBackdrop>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import CosmicBackdrop from "../common/cosmic/CosmicBackdrop.vue";
import LevitationField from "../common/cosmic/LevitationField.vue";
import CosmicSubmit from "../common/cosmic/CosmicSubmit.vue";
import QuantumProgressFlow from "../common/cosmic/QuantumProgressFlow.vue";
import BrandMark from "../common/BrandMark.vue";

/**
 * UnlockView Props
 */
defineProps<{
  /** 已选 verthys 路径 */
  verthysPath: string;
  /** 解锁处理中标志 */
  unlocking: boolean;
  /** 解锁进度消息（阶段描述） */
  unlockProgressMsg: string;
  /** 解锁进度百分比 */
  unlockProgressPercent: number;
  /** 解锁进度累计耗时 */
  unlockProgressElapsed: number;
  /** 初始化状态（none/ready/broken） */
  initStatusRef: string;
  /** 初始化详情（含 ⚠ repair_fail_count 告警） */
  initDetailRef: string;
}>();

/**
 * UnlockView Emits
 */
defineEmits<{
  /** 确认解锁/创建（父组件调用 doUnlock(verthysPath, pendingIsCreate)） */
  (e: 'unlock'): void;
  /** 返回主页 */
  (e: 'back'): void;
  /** 打开已有 verthys 文件 */
  (e: 'openExisting'): void;
  /** 新建 verthys 文件 */
  (e: 'createNew'): void;
}>();
</script>
