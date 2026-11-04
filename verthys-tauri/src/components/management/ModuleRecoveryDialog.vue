<!--
  ModuleRecoveryDialog.vue — 模块恢复槽绑定与换机重密封

  形态：复用 CosmicOverlay 光学切片底板，内容分三段 ——
        状态读数 / 凭据注入 / 动作通道，排版随底板刻度轴对齐。
  职责：
    1. 展示当前恢复槽绑定状态；
    2. 绑定：模块口令 + 容器恢复码 → C 层包裹 device share；
    3. 重密封：只用模块口令，仅在恢复码解锁的会话中通过 C 层策略。

  安全约束：模块口令与恢复码只在本组件内存中驻留，提交/关闭即清零；
  不写本地存储、不输出日志。
-->
<template>
  <CosmicOverlay
    :show="show"
    width="520px"
    :backdrop-close="!busy"
    :aria-label="`${moduleLabel} · 恢复槽`"
    @close="close"
  >
    <div class="kv-title">{{ moduleLabel }} · 恢复槽</div>

    <!-- 状态读数：离散菱标 + 状态词 + 收束细线，不另设卡片或底色 -->
    <div class="mr-readout" :class="{ 'is-bound': hasRecovery }">
      <span class="mr-readout-mark" aria-hidden="true"></span>
      <span class="mr-readout-text">
        {{ hasRecovery ? "恢复槽已绑定" : "恢复槽未绑定" }}
      </span>
      <span class="mr-readout-rule" aria-hidden="true"></span>
    </div>

    <div class="kv-desc">
      绑定后在换机场景可通过容器恢复码替代设备因子校验，模块口令仍需提供，绑定操作不覆盖已有记录与分片
    </div>

    <div class="mr-body" :aria-busy="busy">
      <div class="mr-field">
        <label class="mr-field-label" for="mr-password">模块口令</label>
        <div class="mr-field-input">
          <input
            id="mr-password"
            v-model="password"
            class="kv-input"
            :type="passwordVisible ? 'text' : 'password'"
            autocomplete="current-password"
            autocapitalize="off"
            autocorrect="off"
            spellcheck="false"
            :disabled="busy"
            placeholder="输入该模块的独立口令"
          />
          <button
            type="button"
            class="mr-eye"
            :disabled="busy"
            :aria-label="passwordVisible ? '隐藏模块口令' : '显示模块口令'"
            :aria-pressed="passwordVisible"
            @click="passwordVisible = !passwordVisible"
          >
            <svg v-if="!passwordVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
          </button>
        </div>
      </div>

      <div class="mr-field">
        <label class="mr-field-label" for="mr-recovery">容器恢复码（绑定用）</label>
        <div class="mr-field-input">
          <input
            id="mr-recovery"
            v-model="recoveryCode"
            class="kv-input"
            :type="recoveryVisible ? 'text' : 'password'"
            autocomplete="off"
            autocapitalize="off"
            autocorrect="off"
            spellcheck="false"
            :disabled="busy"
            placeholder="创建容器时保存的一次性恢复码"
          />
          <button
            type="button"
            class="mr-eye"
            :disabled="busy"
            :aria-label="recoveryVisible ? '隐藏容器恢复码' : '显示容器恢复码'"
            :aria-pressed="recoveryVisible"
            @click="recoveryVisible = !recoveryVisible"
          >
            <svg v-if="!recoveryVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
          </button>
        </div>
      </div>

      <p v-if="error" class="mr-feedback is-error" role="alert">{{ error }}</p>
      <p v-if="success" class="mr-feedback is-success" role="status">{{ success }}</p>

      <!-- 动作通道：重密封是会话内副通道，绑定与关闭构成主决策面 -->
      <div class="mr-deck">
        <div class="mr-channel">
          <button
            class="btn mr-secondary"
            type="button"
            :disabled="busy || !password"
            @click="onReseal"
          >
            {{ busy && action === "reseal" ? "重密封中…" : "重密封设备槽" }}
          </button>
          <span class="mr-channel-hint">仅恢复码解锁会话可用</span>
        </div>
        <div class="mr-footer">
          <button class="btn kv-cancel" type="button" :disabled="busy" @click="close">
            关闭
          </button>
          <button
            class="btn btn-primary kv-confirm"
            type="button"
            :disabled="busy || !password || !recoveryCode"
            @click="onBind"
          >
            {{ busy && action === "bind" ? "绑定中…" : "绑定恢复槽" }}
          </button>
        </div>
      </div>
    </div>
  </CosmicOverlay>
</template>

<script setup lang="ts">
import { ref } from "vue";
import CosmicOverlay from "../common/cosmic/CosmicOverlay.vue";
import { bindModuleRecovery, resealModuleDevice } from "../../key/module-auth";
import { translateVerthysError } from "../../lib/keyManager";
import type { ModuleId } from "../../types/key_manager";

const props = defineProps<{
  /** 弹窗显示状态 */
  show: boolean;
  /** 模块显示名称 */
  moduleLabel: string;
  /** 模块 ID（前端语义标识） */
  moduleId: ModuleId;
  /** 是否已绑定恢复槽（C 层状态投影） */
  hasRecovery: boolean;
}>();

const emit = defineEmits<{ (e: "close"): void }>();

const password = ref("");
const recoveryCode = ref("");
const busy = ref(false);
const action = ref<"bind" | "reseal" | "">("");
const error = ref("");
const success = ref("");
const passwordVisible = ref(false);
const recoveryVisible = ref(false);

/** 关闭并清零全部内存凭据 */
const close = () => {
  if (busy.value) return;
  password.value = "";
  recoveryCode.value = "";
  error.value = "";
  success.value = "";
  passwordVisible.value = false;
  recoveryVisible.value = false;
  emit("close");
};

const onBind = async () => {
  if (busy.value || !password.value || !recoveryCode.value) return;
  busy.value = true;
  action.value = "bind";
  error.value = "";
  success.value = "";
  try {
    const result = await bindModuleRecovery(
      props.moduleId,
      password.value,
      recoveryCode.value,
    );
    if (!result.ok) {
      error.value = translateVerthysError(result);
      return;
    }
    success.value = "恢复槽已绑定，可在换机时使用同一恢复码恢复该模块。";
    recoveryCode.value = "";
  } catch {
    error.value = "绑定异常";
  } finally {
    busy.value = false;
    action.value = "";
  }
};

const onReseal = async () => {
  if (busy.value || !password.value) return;
  busy.value = true;
  action.value = "reseal";
  error.value = "";
  success.value = "";
  try {
    const result = await resealModuleDevice(props.moduleId, password.value);
    if (!result.ok) {
      error.value = translateVerthysError(result);
      return;
    }
    success.value = "设备槽已重密封到当前设备。";
  } catch {
    error.value = "重密封异常";
  } finally {
    busy.value = false;
    action.value = "";
  }
};
</script>

<style scoped>
/* ===== 状态读数 =====
 * 绑定态与未绑定态只改信号色，不改变几何、不加底板：
 * 状态是仪器读数，不是第二张卡片。 */
.mr-readout {
  --mr-state-c: rgba(255, 184, 108, 0.88);
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}
.mr-readout.is-bound {
  --mr-state-c: rgba(46, 213, 115, 0.88);
}
.mr-readout-mark {
  flex: none;
  width: 5px;
  height: 5px;
  background: var(--mr-state-c);
  transform: rotate(45deg);
}
.mr-readout-text {
  font-size: 11px;
  letter-spacing: 0.08em;
  color: var(--mr-state-c);
  white-space: nowrap;
}
.mr-readout-rule {
  flex: 1;
  height: 1px;
  background: linear-gradient(
    90deg,
    rgba(205, 224, 244, 0.14),
    transparent 82%
  );
}

/* ===== 凭据注入 =====
 * 字段只保留标签刻度与凹槽输入；显隐端子内嵌输入框右侧，
 * 不占独立水平槽位。 */
.mr-body {
  display: flex;
  flex-direction: column;
}
.mr-field + .mr-field {
  margin-top: 14px;
}
.mr-field-label {
  display: flex;
  align-items: center;
  gap: 7px;
  margin-bottom: 7px;
  font-size: 10px;
  letter-spacing: 0.06em;
  color: rgba(132, 148, 168, 0.9);
  cursor: pointer;
}
.mr-field-label::before {
  content: "";
  flex: none;
  width: 10px;
  height: 1px;
  background: linear-gradient(
    90deg,
    rgba(205, 224, 244, 0.38),
    transparent
  );
}
.mr-field-input {
  position: relative;
  --kv-input-pad-right: 40px;
}
.mr-field-input .kv-input {
  width: 100%;
}
.mr-field-input .kv-input:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
.mr-eye {
  position: absolute;
  right: 4px;
  top: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transform: translateY(-50%);
  transition: color var(--dur-fast) var(--ease);
}
.mr-eye:hover:not(:disabled) {
  color: var(--accent);
}
.mr-eye:focus-visible {
  outline: 1px solid var(--border-hover);
  outline-offset: 1px;
}
.mr-eye:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
.mr-eye svg {
  width: 14px;
  height: 14px;
}

/* ===== 反馈 =====
 * 错误与成功只以文字直陈，不加底色方框、不加图标。 */
.mr-feedback {
  margin: 14px 0 0;
  font-size: 11.5px;
  line-height: 1.65;
}
.mr-feedback.is-error {
  color: #ff9c9c;
}
.mr-feedback.is-success {
  color: rgba(46, 213, 115, 0.9);
}

/* ===== 动作通道 =====
 * 副通道（重密封）与主决策面（关闭 / 绑定）分层；
 * 副通道仅收敛为中性按钮，不争夺主确认钮的注能语义。 */
.mr-deck {
  display: flex;
  flex-direction: column;
  gap: 14px;
  margin-top: 18px;
}
.mr-channel {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
}
.mr-secondary {
  padding: 6px 14px;
  font-size: 12px;
}
.mr-channel-hint {
  font-size: 10px;
  line-height: 1.5;
  letter-spacing: 0.04em;
  color: rgba(122, 138, 160, 0.7);
}
.mr-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}
</style>
