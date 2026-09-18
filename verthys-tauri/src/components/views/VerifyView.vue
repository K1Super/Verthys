<!--
  VerifyView.vue — 验证全局密钥视图（引力悬浮场 · 无底板悬浮体系）
  职责：
    1. 输入访问密钥（v-model 双向绑定，回车提交）
    2. 选择 .bin 密钥文件（emit browseBin）
    3. 输入密钥口令（v-model 双向绑定，回车提交）
    4. 量子核心加载动画 + 验证进度实时反馈（阶段描述 + 百分比 + 耗时）
    5. 提交验证（emit verify）

  ★ 悬浮场重构：光谱底轨输入（去盒化）+ 标注式标签 + 深空定位入射
  ★ 尺寸稳定模式（ff-field--stable）：表单态↔加载态切换高度零抖动

  Models: verifyPassword / binPassword — 访问密钥 / 密钥口令
  Props: binFileName / processing / unlockProgressMsg / unlockProgressPercent / unlockProgressElapsed
  Emits: verify / back / browseBin
-->
<template>
  <div class="view-verify">
    <Teleport to="body">
    <CosmicBackdrop fixed @backdrop="$emit('back')">
    <LevitationField width="330px" class="ff-field--stable">

      <div class="ff-node ff-node--brand">
        <BrandMark />
      </div>

      <div class="ff-node ff-node--title">
        <div class="ff-overline">KEY · VERIFY</div>
        <div class="ff-title">身份验证</div>
      </div>

      <div v-if="!processing" class="ff-node ff-node--body">
        <PasswordInput
          v-model="verifyPassword"
          label="访问密钥"
          placeholder="请输入访问密钥"
          :disabled="processing"
          @submit="$emit('verify')"
        />
      </div>

      <div v-if="!processing" class="ff-node ff-node--body">
        <div class="form-row">
          <label class="form-label">密钥文件</label>
          <div class="path-row">
            <input class="sc-input" :value="binFileName || ''" readonly placeholder="请选择密钥文件" />
            <button class="sc-browse-icon" @click="$emit('browseBin')" :disabled="processing" v-tip="'选择密钥文件'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-6l-2-2H5a2 2 0 0 0-2 2z"/></svg>
            </button>
          </div>
        </div>
      </div>

      <div v-if="!processing" class="ff-node ff-node--body">
        <PasswordInput
          v-model="binPassword"
          label="密钥口令"
          placeholder="请输入密钥口令"
          :disabled="processing"
          @submit="$emit('verify')"
        />
      </div>

      <!-- 量子能量导流通道（按代码关键节点推进进度，精简提示词） -->
      <div class="ff-node ff-node--body">
        <QuantumProgressFlow
          :loading="processing"
          :percent="unlockProgressPercent"
          :message="unlockProgressMsg"
        />
      </div>

      <div v-if="!processing" class="ff-node ff-node--action">
        <CosmicSubmit
          label="验证"
          loading-label="验证中"
          :loading="processing"
          :disabled="!verifyPassword || !binFileName || !binPassword"
          @click="$emit('verify')"
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
import PasswordInput from "../common/form/PasswordInput.vue";
import QuantumProgressFlow from "../common/cosmic/QuantumProgressFlow.vue";
import BrandMark from "../common/BrandMark.vue";

/**
 * VerifyView Props
 */
defineProps<{
  /** 已选 .bin 密钥文件名 */
  binFileName: string;
  /** 验证处理中标志（禁用表单 + 显示加载动画） */
  processing: boolean;
  /** 验证进度消息（阶段描述） */
  unlockProgressMsg: string;
  /** 验证进度百分比 */
  unlockProgressPercent: number;
  /** 验证进度累计耗时 */
  unlockProgressElapsed: number;
}>();

/**
 * VerifyView Emits
 */
defineEmits<{
  /** 提交验证全局密钥 */
  (e: 'verify'): void;
  /** 返回解锁视图 */
  (e: 'back'): void;
  /** 选择 .bin 密钥文件 */
  (e: 'browseBin'): void;
}>();

/**
 * VerifyView Models（v-model 双向绑定）
 */
const verifyPassword = defineModel<string>('verifyPassword', { default: '' });
const binPassword = defineModel<string>('binPassword', { default: '' });
</script>
