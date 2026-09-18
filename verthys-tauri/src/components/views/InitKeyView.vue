<!--
  InitKeyView.vue — 初始化全局密钥视图（引力悬浮场 · 无底板悬浮体系）
  职责：
    1. 输入访问密钥（v-model 双向绑定）
    2. 选择 .bin 密钥文件（emit browseBin）
    3. 输入密钥口令（v-model 双向绑定）
    4. 脉冲星磁层辐射加载动画（初始化中，无进度文字）
    5. 提交初始化（emit init）

  ★ 悬浮场重构：光谱底轨输入（去盒化）+ 标注式标签 + 深空定位入射
  ★ 尺寸稳定模式（ff-field--stable）：表单态↔加载态切换高度零抖动

  Models: initPassword / binPassword — 访问密钥 / 密钥口令
  Props: binFileName / processing
  Emits: init / back / browseBin
-->
<template>
  <div class="view-init">
    <Teleport to="body">
    <CosmicBackdrop fixed @backdrop="$emit('back')">
    <LevitationField width="330px" class="ff-field--stable">

      <div class="ff-node ff-node--brand">
        <BrandMark />
      </div>

      <div class="ff-node ff-node--title">
        <div class="ff-overline">KEY · GENESIS</div>
        <div class="ff-title">初始化安全密钥</div>
      </div>

      <div v-if="!processing" class="ff-node ff-node--body">
        <PasswordInput
          v-model="initPassword"
          label="访问密钥"
          placeholder="设置访问密钥"
          :disabled="processing"
        />
      </div>

      <div v-if="!processing" class="ff-node ff-node--body">
        <div class="form-row">
          <label class="form-label">密钥文件</label>
          <div class="path-row">
            <input class="sc-input" :value="binFileName || ''" readonly placeholder="选择密钥文件" />
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
        />
      </div>

      <!-- 量子核心加载动画（初始化中，无文字） -->
      <div class="ff-node ff-node--body">
        <QuantumCoreLoader :loading="processing" />
      </div>

      <div v-if="!processing" class="ff-node ff-node--action">
        <CosmicSubmit
          label="初始化安全密钥"
          loading-label="初始化中"
          :loading="processing"
          :disabled="!initPassword || !binFileName || !binPassword"
          @click="$emit('init')"
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
import QuantumCoreLoader from "../common/cosmic/QuantumCoreLoader.vue";
import BrandMark from "../common/BrandMark.vue";

/**
 * InitKeyView Props
 */
defineProps<{
  /** 已选 .bin 密钥文件名 */
  binFileName: string;
  /** 初始化处理中标志（禁用表单 + 显示加载动画） */
  processing: boolean;
}>();

/**
 * InitKeyView Emits
 */
defineEmits<{
  /** 提交初始化全局密钥 */
  (e: 'init'): void;
  /** 返回解锁视图 */
  (e: 'back'): void;
  /** 选择 .bin 密钥文件 */
  (e: 'browseBin'): void;
}>();

/**
 * InitKeyView Models（v-model 双向绑定）
 */
const initPassword = defineModel<string>('initPassword', { default: '' });
const binPassword = defineModel<string>('binPassword', { default: '' });
</script>
