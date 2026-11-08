<!--
  SecurityServiceGate.vue — P2 安全服务状态阻断
  服务由 perMachine 应用安装器随应用安装；此处只做 fail-closed 提示与重试，
  不再从应用内提权执行任何安装器。
-->
<template>
  <div v-if="visible" class="svc-gate" role="dialog" aria-modal="true" aria-labelledby="svc-gate-title">
    <section class="svc-panel">
      <h2 id="svc-gate-title">本机安全服务不可用</h2>
      <p class="svc-copy">
        Verthys 的解锁与模块认证依赖系统级安全服务。该服务应随应用安装完成；
        当前检测到服务未安装或状态异常，请重新运行应用安装程序修复。
      </p>

      <p v-if="error" class="svc-error" role="alert">{{ error }}</p>

      <div class="svc-actions">
        <button type="button" class="svc-secondary" @click="$emit('retry')">
          重新检测
        </button>
      </div>

      <p class="svc-hint">
        若重新安装后仍不可用，请检查 Windows 服务 VerthysSecuritySvc 是否被安全软件拦截。
      </p>
    </section>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  visible: boolean;
  error: string;
}>();

defineEmits<{
  retry: [];
}>();
</script>

<style scoped>
.svc-gate {
  position: fixed;
  inset: 0;
  z-index: 10000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: rgba(2, 4, 10, 0.88);
  backdrop-filter: blur(8px);
}

.svc-panel {
  width: min(520px, 100%);
  padding: 28px 30px;
  border: 1px solid rgba(120, 200, 255, 0.26);
  border-radius: 4px;
  background: rgba(8, 14, 24, 0.96);
  box-shadow: 0 24px 80px rgba(0, 0, 0, 0.55);
}

.svc-panel h2 {
  margin: 0 0 12px;
  color: var(--text-primary, #e8f2ff);
  font-size: 15px;
  letter-spacing: 0.08em;
}

.svc-copy,
.svc-hint {
  margin: 0 0 12px;
  color: var(--text-secondary, rgba(210, 226, 246, 0.72));
  font-size: 11px;
  line-height: 1.7;
}

.svc-error {
  margin: 0 0 14px;
  padding: 8px 10px;
  border: 1px solid rgba(255, 120, 120, 0.38);
  border-radius: 2px;
  background: rgba(255, 90, 90, 0.06);
  color: rgba(255, 176, 176, 0.96);
  font-size: 10px;
  line-height: 1.6;
  word-break: break-all;
}

.svc-actions {
  display: flex;
  gap: 10px;
  margin: 18px 0 14px;
}

.svc-secondary {
  min-width: 128px;
  padding: 9px 14px;
  border-radius: 2px;
  font-size: 11px;
  letter-spacing: 0.04em;
  cursor: pointer;
  border: 1px solid rgba(160, 180, 205, 0.28);
  background: transparent;
  color: var(--text-secondary, rgba(210, 226, 246, 0.72));
}

.svc-hint {
  margin-bottom: 0;
}
</style>
