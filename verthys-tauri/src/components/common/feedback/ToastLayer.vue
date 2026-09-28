<!--
  ToastLayer.vue — 全局 Toast 渲染层（唯一渲染通道 / 全应用最高层）

  职责：全应用瞬时提示（错误 / 状态 / 复制 / 导出完成 / 剪贴板倒计时）的
       唯一渲染方 —— 状态源自 composables/useToastCenter（单例）。

  层级（硬约束）：
    1. <Teleport to="body"> 附加到 body —— 脱离 #app 栈上下文，任何弹窗 /
       查看器 / 覆盖层（z 1000~9999）都无法覆盖提示；
    2. 层级唯一权威 = --z-toast（tokens.css 分层序最高层）—— 提示本体不声明
       z-index，调整层级只改令牌一处；
    3. pointer-events: none —— 提示永不拦截交互。

  治理透传：Teleport 出栈后不再位于 .app-root 之下，空闲治理类
    （idle-*）由本层根节点按同一权威源（useGlobalIdleScheduler）透传承载，
    提示立标（.toast-dot）的暂停/豁免语义与主界面一致。

  Props:
    - idleLevel: 全局空闲档位（App.vue 唯一权威源透传）
  用法：App.vue 根节点单点挂载 —— <ToastLayer :idle-level="idleLevel" />
-->
<template>
  <Teleport to="body">
    <div class="toast-layer" :class="`idle-${idleLevel}`">
      <!-- 顶部错误提示 -->
      <transition name="err-toast">
        <div v-if="error" class="error-toast"><span class="toast-dot"></span>{{ error }}</div>
      </transition>

      <!-- 顶部导出完成提示（success/error 变体） -->
      <transition name="toast">
        <div
          v-if="exportDone"
          class="clip-toast clip-toast--top"
          :class="exportDone.type === 'success' ? 'clip-toast--success' : 'clip-toast--error'"
        ><span class="toast-dot"></span>{{ exportDone.msg }}</div>
      </transition>

      <!-- 底部：剪贴板安全倒计时 -->
      <transition name="toast">
        <div v-if="clip" class="clip-toast"><span class="toast-dot"></span>{{ clip.text }} · {{ clip.seconds }}s 后自动清空</div>
      </transition>

      <!-- 底部：复制成功 -->
      <transition name="toast">
        <div v-if="copied" class="clip-toast"><span class="toast-dot"></span>已复制到剪贴板</div>
      </transition>

      <!-- 底部：状态 / 成功提示 -->
      <transition name="toast">
        <div v-if="status" class="clip-toast"><span class="toast-dot"></span>{{ status }}</div>
      </transition>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { toastState } from "../../../composables/useToastCenter";
import type { IdleLevel } from "../../../composables/useGlobalIdleScheduler";

defineProps<{
  /** 全局空闲档位（唯一权威源 App.vue 透传；透传后空闲治理语义不因 Teleport 丢失） */
  idleLevel: IdleLevel;
}>();

/* 单例状态解构（模板内自动解包 ref；状态唯一来源 = useToastCenter） */
const { error, status, copied, exportDone, clip } = toastState;
</script>