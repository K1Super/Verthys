<!--
  ChangeKeyDialog.vue — 修改全局密钥弹窗
  来源：SecurityCenter.vue 原 L189-L237（零行为变更提取）

  职责：
    1. 两段式表单：① 验证当前密钥（访问密钥/密钥文件/口令） ② 设置新密钥（同三项）
    2. 当前密钥文件/新密钥文件为只读显示 + 选择按钮（emit browseOldBin/browseNewBin）
    3. 确认修改按钮（禁用条件：changeKeyProcessing 或任一字段为空）
    4. 取消按钮（禁用条件：changeKeyProcessing）

  Props: show / changeKeyProcessing / oldBinFileName / newBinFileName
  Models: oldPassword / oldBinPassword / newPassword / newBinPassword
  Emits: close / browseOldBin / browseNewBin / confirm
-->
<template>
  <CosmicOverlay :show="show" width="500px" @close="$emit('close')">
    <div class="kv-title">修改全局密钥</div>
    <div class="kv-desc ck-desc-strong">
      修改全局访问密钥和密钥文件。需先验证当前密钥，再设置新密钥。<br/>
      <strong>注意：修改后当前密钥和当前密钥文件将无法使用</strong>
    </div>
    <div class="ck-section">
      <div class="ck-section-title">① 验证当前密钥</div>
      <div class="ck-field">
        <label>当前全局访问密钥</label>
        <input class="kv-input" v-model="oldPassword" type="password" placeholder="输入当前全局访问密钥" />
      </div>
      <div class="ck-field">
        <label>当前密钥文件</label>
        <div class="ck-file-row">
          <input class="kv-input" :value="oldBinFileName || ''" readonly placeholder="选择当前密钥文件" />
          <button class="btn btn-sm ck-browse" @click="$emit('browseOldBin')" :disabled="changeKeyProcessing">选择</button>
        </div>
      </div>
      <div class="ck-field">
        <label>当前密钥口令</label>
        <input class="kv-input" v-model="oldBinPassword" type="password" placeholder="输入当前密钥口令" />
      </div>
    </div>
    <div class="ck-section">
      <div class="ck-section-title">② 设置新密钥</div>
      <div class="ck-field">
        <label>新全局访问密钥</label>
        <input class="kv-input" v-model="newPassword" type="password" placeholder="输入新的全局访问密钥" />
      </div>
      <div class="ck-field">
        <label>新密钥文件</label>
        <div class="ck-file-row">
          <input class="kv-input" :value="newBinFileName || ''" readonly placeholder="选择新密钥文件" />
          <button class="btn btn-sm ck-browse" @click="$emit('browseNewBin')" :disabled="changeKeyProcessing">选择</button>
        </div>
      </div>
      <div class="ck-field">
        <label>新密钥口令</label>
        <input class="kv-input" v-model="newBinPassword" type="password" placeholder="输入新密钥口令" />
      </div>
    </div>
    <div class="kv-actions">
      <button class="btn kv-cancel" @click="$emit('close')" :disabled="changeKeyProcessing">取消</button>
      <button class="btn btn-primary kv-confirm" @click="$emit('confirm')" :disabled="changeKeyProcessing || !oldPassword || !oldBinFileName || !oldBinPassword || !newPassword || !newBinFileName || !newBinPassword">
        {{ changeKeyProcessing ? '修改中…' : '确认修改' }}
      </button>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";

/**
 * ChangeKeyDialog Props
 */
defineProps<{
  /** 弹窗显示状态 */
  show: boolean;
  /** 修改处理中状态（禁用表单 + 按钮） */
  changeKeyProcessing: boolean;
  /** 当前密钥文件名（只读显示） */
  oldBinFileName: string;
  /** 新密钥文件名（只读显示） */
  newBinFileName: string;
}>();

/**
 * ChangeKeyDialog Models（密码字段双向绑定）
 */
const oldPassword = defineModel<string>("oldPassword", { default: "" });
const oldBinPassword = defineModel<string>("oldBinPassword", { default: "" });
const newPassword = defineModel<string>("newPassword", { default: "" });
const newBinPassword = defineModel<string>("newBinPassword", { default: "" });

/**
 * ChangeKeyDialog Emits
 */
defineEmits<{
  /** 关闭弹窗（取消或点击遮罩） */
  (e: "close"): void;
  /** 选择当前密钥文件 */
  (e: "browseOldBin"): void;
  /** 选择新密钥文件 */
  (e: "browseNewBin"): void;
  /** 确认修改全局密钥 */
  (e: "confirm"): void;
}>();
</script>
