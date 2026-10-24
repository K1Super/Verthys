<!--
  PasswordTools.vue — 密码安全辅助工具模块
  三项工具散落在同一透视舞台上：默认按不规则层叠摆放（允许重叠），
  整张卡片的非交互区域都可起拖，位置每次进入复位：
    1. 密码生成器（随机字符 / 数字 PIN / 分段字母数字 / 随机令牌 / UUID）
    2. 密码安全评估（本地模式分析 + Argon2id 单向哈希）
    3. 密钥生成工具（生成密钥并导出 .bin）
  定位与运动由 useFloatingCards 承担；本组件只保留卡片内容与舞台结构。
-->
<template>
  <div class="password-tools">
    <div class="water-stage" ref="stageRef">
      <!-- ===== 密码生成器 =====
           两层各司其职：float-card 只承接整像素平移（控制器每帧写入），
           float-card__body 只承载入场淡入。卡片子树内不存在任何缩放 / 旋转 /
           透视，文字始终按 1:1 栅格绘制，静止与拖拽都不会被重采样 -->
      <div
        class="float-card"
        :ref="(el) => registerCard('generator', el as HTMLElement | null)"
        :style="{ '--enter-delay': '0ms' }"
      >
      <div class="float-card__body">
      <section class="tool-section glass gen-section">
        <div class="section-header" data-drag-handle tabindex="0" aria-label="密码生成器，可拖动或用方向键移动">
          <span class="section-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>
          </span>
          <span class="section-title">密码生成器</span>
        </div>

        <!-- 大显示区（点击或 Enter/Space 复制） -->
        <div
          class="gen-display field-box"
          role="button"
          tabindex="0"
          :aria-label="genMode === 'password' ? '复制生成的密码' : '复制随机令牌'"
          @click="copyText(genOutput, genMode === 'password' ? 'password' : 'token')"
          @keydown="onDisplayKeydown($event, genOutput, genMode === 'password' ? 'password' : 'token')"
        >
          <span class="gen-pwd" :class="`strength-${genStrength.level}`">{{ genOutput || '点击生成' }}</span>
          <div class="gen-actions">
            <button
              class="icon-btn icon-btn--spin"
              @click.stop="generateGenOutput"
              v-tip="'重新生成'"
              :aria-label="genMode === 'password' ? '重新生成密码' : '生成令牌'"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            </button>
          </div>
        </div>

        <!-- 生成类型（显示框下方一行五项）：随机字符 / 数字 PIN / 分段字母数字 / 随机令牌 / UUID -->
        <div class="gen-types">
          <button class="fmt-btn" :class="{ active: genSelection === 'random' }" @click="selectGen('random')">随机字符</button>
          <button class="fmt-btn" :class="{ active: genSelection === 'pin' }" @click="selectGen('pin')">数字 PIN</button>
          <button class="fmt-btn" :class="{ active: genSelection === 'segmented' }" @click="selectGen('segmented')">分段字母数字</button>
          <button class="fmt-btn" :class="{ active: genSelection === 'token' }" @click="selectGen('token')">随机令牌</button>
          <button class="fmt-btn" :class="{ active: genSelection === 'uuid' }" @click="selectGen('uuid')">UUID</button>
        </div>

        <!-- 控制面板：随机字符（长度与字符集） -->
        <div v-if="genSelection === 'random'" class="gen-controls">
          <div class="ctrl-length">
            <div class="ctrl-label">
              <span>长度</span>
              <span class="ctrl-value">{{ genLength }}</span>
            </div>
            <input
              type="range"
              class="slider"
              v-model.number="genLength"
              min="8"
              max="64"
              step="1"
              aria-label="密码长度"
            />
          </div>
          <div class="ctrl-opts">
            <label class="opt-chip" :class="{ on: genOpts.upper }">
              <input type="checkbox" v-model="genOpts.upper" aria-label="包含大写字母" />
              <span>A-Z</span>
            </label>
            <label class="opt-chip" :class="{ on: genOpts.lower }">
              <input type="checkbox" v-model="genOpts.lower" aria-label="包含小写字母" />
              <span>a-z</span>
            </label>
            <label class="opt-chip" :class="{ on: genOpts.digits }">
              <input type="checkbox" v-model="genOpts.digits" aria-label="包含数字" />
              <span>0-9</span>
            </label>
            <label class="opt-chip" :class="{ on: genOpts.symbols }">
              <input type="checkbox" v-model="genOpts.symbols" aria-label="包含符号" />
              <span>!@#</span>
            </label>
            <label class="opt-chip" :class="{ on: genOpts.exclude }">
              <input type="checkbox" v-model="genOpts.exclude" aria-label="排除易混淆字符" />
              <span>排除相似</span>
            </label>
          </div>
        </div>

        <!-- 控制面板：数字 PIN（仅 0-9，位数可调，附常用位数） -->
        <div v-else-if="genSelection === 'pin'" class="gen-controls">
          <div class="ctrl-length">
            <div class="ctrl-label">
              <span>位数</span>
              <span class="ctrl-value">{{ pinLength }}</span>
            </div>
            <input
              type="range"
              class="slider"
              v-model.number="pinLength"
              min="4"
              max="10"
              step="1"
              aria-label="PIN 位数"
            />
          </div>
          <div class="token-format">
            <button
              v-for="n in [4, 6, 8]"
              :key="n"
              class="fmt-btn"
              :class="{ active: pinLength === n }"
              @click="pinLength = n"
            >{{ n }} 位</button>
          </div>
        </div>

        <!-- 控制面板：分段字母数字（段数与每段位数） -->
        <div v-else-if="genSelection === 'segmented'" class="gen-controls">
          <div class="ctrl-length">
            <div class="ctrl-label">
              <span>段数</span>
            </div>
            <div class="token-format">
              <button
                v-for="n in [3, 4, 5]"
                :key="n"
                class="fmt-btn"
                :class="{ active: segGroups === n }"
                @click="setSegGroups(n)"
              >{{ n }}</button>
            </div>
          </div>
          <div class="ctrl-length">
            <div class="ctrl-label">
              <span>每段位数</span>
            </div>
            <div class="token-format">
              <button
                v-for="n in [3, 4, 5]"
                :key="n"
                class="fmt-btn"
                :class="{ active: segLength === n }"
                @click="setSegLength(n)"
              >{{ n }}</button>
            </div>
          </div>
        </div>

        <!-- 控制面板：随机令牌 / UUID（字节数与输出格式） -->
        <div v-else class="gen-controls">
          <div class="ctrl-length">
            <div class="ctrl-label">
              <span>字节数</span>
              <span class="ctrl-value">{{ tokenBytes }}</span>
            </div>
            <input
              type="range"
              class="slider"
              v-model.number="tokenBytes"
              min="4"
              max="64"
              step="1"
              aria-label="令牌字节数"
              :disabled="genSelection === 'uuid'"
            />
          </div>
          <div v-if="genSelection === 'token'" class="token-format">
            <button class="fmt-btn" :class="{ active: tokenFormat === 'hex' }" @click="tokenFormat = 'hex'; generateToken()">HEX</button>
            <button class="fmt-btn" :class="{ active: tokenFormat === 'base64' }" @click="tokenFormat = 'base64'; generateToken()">Base64</button>
          </div>
          <div v-else class="ctrl-hint">标准 UUIDv4：版本位与变体位固定，随机位 122 bit</div>
        </div>

        <!-- 强度指示：仅口令模式；令牌模式改为熵与长度信息，保持卡片内部节奏一致 -->
        <template v-if="genMode === 'password'">
          <div
            class="strength-bar"
            role="meter"
            aria-label="密码熵估算"
            aria-valuemin="0"
            aria-valuemax="128"
            :aria-valuenow="genStrength.entropy"
          >
            <div class="strength-fill" :class="`strength-${genStrength.level}`" :style="{ width: `${genStrength.percent}%` }"></div>
          </div>
          <div class="strength-info">
            <span class="strength-label">{{ genStrength.label }}</span>
            <span class="strength-entropy">熵 ~{{ genStrength.entropy }} bits</span>
          </div>
        </template>
        <div v-else class="strength-info">
          <span class="strength-label">随机令牌</span>
          <span class="strength-entropy">{{ tokenBitsText }}</span>
        </div>
      </section>
      </div>
      </div>

      <!-- ===== 密码安全评估 ===== -->
      <div
        class="float-card"
        :ref="(el) => registerCard('assessment', el as HTMLElement | null)"
        :style="{ '--enter-delay': '70ms' }"
      >
      <div class="float-card__body">
      <section class="tool-section glass check-section">
        <div class="section-header" data-drag-handle tabindex="0" aria-label="密码安全评估，可拖动或用方向键移动">
          <span class="section-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </span>
          <span class="section-title">密码安全评估</span>
        </div>
        <!-- 待评估口令默认遮罩：安全工具里不得把真实口令全程明文展示 -->
        <div class="check-input-row">
          <input
            class="check-input field-box"
            v-model="checkInput"
            :type="checkVisible ? 'text' : 'password'"
            :maxlength="CHECK_INPUT_MAX"
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
            aria-label="待评估密码"
            :placeholder="checkInputPlaceholder"
            @input="checkStrength"
            @focus="preloadStrength"
          />
          <button
            class="icon-btn check-toggle"
            type="button"
            :aria-label="checkVisible ? '隐藏密码' : '显示密码'"
            v-tip="checkVisible ? '隐藏密码' : '显示密码'"
            @click="checkVisible = !checkVisible"
          >
            <svg v-if="!checkVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
          </button>
        </div>
        <div
          class="check-meter"
          role="meter"
          aria-label="密码强度等级"
          aria-valuemin="0"
          aria-valuemax="5"
          :aria-valuenow="checkResult.level"
          :aria-valuetext="checkResult.label || '未评估'"
        >
          <div class="meter-segment" v-for="i in 5" :key="i" :class="{ filled: checkResult.level >= i, [`seg-${i}`]: true }"></div>
        </div>
        <div class="check-result" :aria-busy="checkPending">
          <span class="check-level" :class="`strength-${checkResult.level}`" aria-live="polite">{{ checkResult.label }}</span>
          <span class="check-entropy">熵 ≈{{ checkResult.entropy }} bits · 破解 ~{{ checkResult.crackTime }}</span>
        </div>
        <!-- 弱点提示：固定占位高度，避免强弱切换时面板高度跳动；不回显口令片段 -->
        <div class="check-advice">{{ checkResult.warning }}</div>
        <!-- 口径如实标注：来源与截断事实随评估结果切换 -->
        <div class="check-caveat">{{ checkCaveat }}</div>

        <!-- Argon2id 单向加密 -->
        <div class="argon-divider"></div>
        <div class="argon-section">
          <div class="argon-header">
            <span class="argon-title">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              Argon2id 凭证串
            </span>
            <button
              class="argon-gen-btn"
              @click="generateArgonHash"
              :disabled="argonProcessing || !checkInput"
              :aria-label="argonProcessing ? '正在计算' : '生成 Argon2id 凭证串'"
              v-tip="argonProcessing ? '计算中…' : '生成 Argon2id 哈希'"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            </button>
          </div>
          <!-- 参数标签与 KDF 调用同源（key-tools/password_tools.ts ARGON2_PARAMS） -->
          <div class="argon-params">
            <span>{{ argonParams }}</span>
          </div>
          <div
            class="argon-result"
            :class="{ clickable: argonResult, processing: argonProcessing }"
            role="button"
            :tabindex="argonResult ? 0 : -1"
            :aria-label="argonResult ? '复制凭证串' : '凭证串尚未生成'"
            :aria-disabled="!argonResult"
            @click="copyArgonResult"
            @keydown="onDisplayKeydown($event, argonResult, 'argon')"
          >
            <code v-if="argonResult" class="argon-code">{{ argonResult }}</code>
            <span v-else-if="argonProcessing" class="argon-loading">计算中…</span>
            <span v-else class="argon-placeholder">{{ checkInput ? '点击按钮生成凭证串' : '请先输入密码' }}</span>
            <svg v-if="argonResult" class="argon-copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </div>
        </div>
      </section>
      </div>
      </div>

      <!-- ===== 密钥生成工具（支持 .bin 导出） ===== -->
      <div
        class="float-card"
        :ref="(el) => registerCard('keygen', el as HTMLElement | null)"
        :style="{ '--enter-delay': '140ms' }"
      >
      <div class="float-card__body">
      <section class="tool-section glass keygen-section">
        <div class="section-header" data-drag-handle tabindex="0" aria-label="密钥生成工具，可拖动或用方向键移动">
          <span class="section-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3"/></svg>
          </span>
          <span class="section-title">密钥生成工具</span>
          <button
            class="gen-btn"
            @click="exportBin"
            :disabled="!keygenRaw.length || exportingKey"
            :aria-label="exportingKey ? '正在导出密钥' : '导出密钥'"
            v-tip="'导出密钥'"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          </button>
        </div>

        <!-- 密钥显示区 -->
        <div
          class="keygen-display field-box"
          role="button"
          tabindex="0"
          aria-label="复制密钥"
          @click="copyText(keygenDisplay, 'key')"
          @keydown="onDisplayKeydown($event, keygenDisplay, 'key')"
        >
          <code class="keygen-code">{{ keygenDisplay || '点击生成密钥' }}</code>
          <div class="keygen-actions">
            <button class="icon-btn icon-btn--spin" @click.stop="generateKey" v-tip="'重新生成'" aria-label="重新生成密钥">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            </button>
          </div>
        </div>

        <!-- 密钥配置 -->
        <div class="keygen-controls">
          <div class="keygen-length">
            <div class="ctrl-label">
              <span>密钥长度（字节）</span>
              <span class="ctrl-value">{{ keygenBytes }} B · {{ keygenBits }} bit</span>
            </div>
            <div class="keygen-presets">
              <button
                v-for="n in [16, 24, 32, 64]"
                :key="n"
                class="preset-btn"
                :class="{ active: keygenBytes === n }"
                @click="keygenBytes = n"
              >{{ n }}</button>
            </div>
          </div>
          <div class="keygen-format-row">
            <span class="format-label">显示格式</span>
            <div class="token-format">
              <button class="fmt-btn" :class="{ active: keygenFormat === 'hex' }" @click="keygenFormat = 'hex'">HEX</button>
              <button class="fmt-btn" :class="{ active: keygenFormat === 'base64' }" @click="keygenFormat = 'base64'">Base64</button>
            </div>
          </div>
        </div>

        <!-- 密钥状态提示 -->
        <div class="keygen-export-row">
          <span class="keygen-hint">{{ keygenRaw.length ? `当前密钥 ${keygenRaw.length} 字节 · SHA-256: ${keygenHashShort}` : '生成密钥后点击右上角图标导出 .bin 文件' }}</span>
        </div>
      </section>
      </div>
      </div>
    </div>

    <!-- 瞬时提示（错误/复制/状态）统一由全局 ToastLayer 渲染（App 根节点单点挂载，--z-toast 最高层） -->
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from "vue";
import { save } from "@tauri-apps/plugin-dialog";
import { sha256 } from "@noble/hashes/sha2";
import { argon2id } from "hash-wasm";
import { writeUserFile } from "../../lib/verthys";
import { useToastCenter } from "../../composables/useToastCenter";
import { useClipToast } from "../../composables/useClipToast";
import { useFloatingCards } from "../../composables/key-tools/useFloatingCards";
import {
  ARGON2_PARAMS,
  argonParamsLabel,
  buildCharset,
  calcStrength,
  composePassword,
  formatToken,
  levelFromEntropy,
  pickCharset,
  randomKeyFileName,
  spaceEntropy,
  type CharsetOptions,
  type RandomSource,
  type Strength,
} from "../../composables/key-tools/password_tools";
import {
  PASSWORD_ANALYSIS_MAX_CHARS,
} from "../../composables/key-tools/password_strength";
import { usePasswordStrength } from "../../composables/key-tools/usePasswordStrength";

/* 漂浮舞台阵型：沿左上 → 右下的斜向层叠（与设计稿一致），三卡刻意不共享基准线。
 *   只用像素偏移与层序制造"散落层叠"——缩放 / 自转 / 纵深三类变换都会让合成器
 *   重采样文字栅格，静止时也会发虚，故一律不用；
 *   层序：密码生成器（z 3）在前，压住评估卡右下缘；评估（z 2）居中偏上，
 *   压住密钥卡右下缘；密钥生成工具（z 1）在左上最深处。
 *   被压住的部分可用拖拽移出，卡片本身整面可拖，不设固定槽位。 */
const { stageRef, registerCard } = useFloatingCards([
  { key: "generator", xOffset: 185, yOffset: 160, zIndex: 3 },
  { key: "assessment", xOffset: -5, yOffset: -15, zIndex: 2 },
  { key: "keygen", xOffset: -210, yOffset: -150, zIndex: 1 },
]);

/* ===== 瞬时提示（错误 / 复制 / 状态）— 全局 Toast 中心；渲染归 ToastLayer ===== */
const { showError, showStatus } = useToastCenter();
/* 状态提示口径（模块内沿用 showToast 命名，指向标准状态通道，2.5s 自动消失） */
const showToast = showStatus;

/* ===== 环境检测 ===== */
const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/* ===== 安全复制（生命周期归 useClipToast：默认 1 分钟 + 到期覆写/Tauri 清空） ===== */
/** 随机源适配（Uint32/Uint8 两种取样共用） */
const randomSource: RandomSource = (out) => {
  crypto.getRandomValues(out);
};

/**
 * 降级写入（Clipboard API 不可用时）：textarea + execCommand。
 *
 * 明文节点必须在 finally 中回收 —— 早期实现在 execCommand 抛错时跳过
 * removeChild，含完整密钥的 textarea 会永久留在 document 中。
 */
const writeViaTextarea = async (content: string): Promise<boolean> => {
  const prevFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const ta = document.createElement("textarea");
  try {
    ta.value = content;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    ta.remove();
    prevFocus?.focus?.();
  }
};

/* 各类内容各自独立文案；同一时刻只有最后一次复制持有清空计时归属权 */
const { copyWithTimeout: copyPassword } = useClipToast("密码已复制", { write: writeViaTextarea });
const { copyWithTimeout: copyToken } = useClipToast("令牌已复制", { write: writeViaTextarea });
const { copyWithTimeout: copyKey } = useClipToast("密钥已复制", { write: writeViaTextarea });
const { copyWithTimeout: copyArgon } = useClipToast("凭证串已复制", { write: writeViaTextarea });

type CopyKind = "password" | "token" | "key" | "argon";
const copyWriterOf = (kind: CopyKind): ((v: string) => Promise<boolean>) => {
  if (kind === "password") return copyPassword;
  if (kind === "token") return copyToken;
  if (kind === "key") return copyKey;
  return copyArgon;
};

/** 复制并给出如实结果（失败必须显式告知，不得静默） */
const copyText = async (text: string, kind: CopyKind): Promise<void> => {
  if (!text) return;
  const ok = await copyWriterOf(kind)(text);
  if (!ok) showError("复制失败：剪贴板不可用或权限被拒绝");
};

/** 展示区键盘可达：Enter/Space 等价于点击复制（只响应当前元素本身） */
const onDisplayKeydown = (e: KeyboardEvent, text: string, kind: CopyKind): void => {
  if (e.target !== e.currentTarget) return;
  if (e.key !== "Enter" && e.key !== " ") return;
  e.preventDefault();
  void copyText(text, kind);
};

/* ===== 密码生成器 ===== */
/** 口令类型：随机字符（可定制字符集）/ 数字 PIN / 分段字母数字 */
type GenType = "random" | "pin" | "segmented";
const genType = ref<GenType>("random");
const genLength = ref(16);
const genOpts = ref<CharsetOptions>({ upper: true, lower: true, digits: true, symbols: false, exclude: false });
const pinLength = ref(6);
const segGroups = ref(4);
const segLength = ref(4);
const genPassword = ref("");

/** PIN 固定字符集：只允许 0-9，前导零合法 */
const PIN_POOL = "0123456789";
/** 分段口令字符集：大小写与数字，排除易混淆字符（I l 1 O 0 o） */
const SEGMENT_POOL = buildCharset({ upper: true, lower: true, digits: true, symbols: false, exclude: true });

const generatePin = (): string => pickCharset(PIN_POOL, pinLength.value, randomSource);

const generateSegmented = (): string => {
  const groups: string[] = [];
  for (let i = 0; i < segGroups.value; i++) {
    groups.push(pickCharset(SEGMENT_POOL, segLength.value, randomSource));
  }
  return groups.join("-");
};

const generatePassword = (): void => {
  if (genType.value === "pin") {
    genPassword.value = generatePin();
    return;
  }
  if (genType.value === "segmented") {
    genPassword.value = generateSegmented();
    return;
  }
  const opts: CharsetOptions = { ...genOpts.value };
  // 全部关闭时明确置空（不接受"看起来生成了但实际为空池"）
  if (!buildCharset(opts)) {
    genPassword.value = "";
    return;
  }
  genPassword.value = composePassword(opts, genLength.value, randomSource);
};

const setSegGroups = (n: number): void => {
  segGroups.value = n;
  generatePassword();
};

const setSegLength = (n: number): void => {
  segLength.value = n;
  generatePassword();
};

/**
 * 强度指示。
 *
 * 随机字符沿用字符集模型（含重复/顺子扣减，与评估面板同口径）；PIN 与分段
 * 口令按生成空间计算——分隔符是固定结构，不得计入熵。
 */
const genStrength = computed<Strength>(() => {
  if (genMode.value === "password" && genType.value === "pin") {
    const bits = spaceEntropy(pinLength.value, PIN_POOL.length);
    return { ...levelFromEntropy(bits), entropy: bits };
  }
  if (genMode.value === "password" && genType.value === "segmented") {
    const bits = spaceEntropy(segGroups.value * segLength.value, SEGMENT_POOL.length);
    return { ...levelFromEntropy(bits), entropy: bits };
  }
  return calcStrength(genPassword.value);
});

/* 生成器模式：随机令牌已并入本卡，两种模式共用显示框、重生成钮与复制入口 */
const genMode = ref<"password" | "token">("password");
const genOutput = computed(() => (genMode.value === "password" ? genPassword.value : tokenResult.value));
const generateGenOutput = (): void => {
  if (genMode.value === "password") generatePassword();
  else generateToken();
};

/** 生成类型总览：五种类型共用一行选择，口令模式按 genType 展开，令牌模式按格式区分 */
type GenSelection = GenType | "token" | "uuid";
const genSelection = computed<GenSelection>(() => {
  if (genMode.value === "password") return genType.value;
  return tokenFormat.value === "uuid" ? "uuid" : "token";
});

const selectGen = (next: GenSelection): void => {
  if (next === genSelection.value) return;
  if (next === "token" || next === "uuid") {
    genMode.value = "token";
    tokenFormat.value = next === "uuid" ? "uuid" : "hex";
    generateToken();
    return;
  }
  genMode.value = "password";
  genType.value = next;
  generatePassword();
};

/* ===== 密码安全评估 ===== */
const checkInput = ref("");
const checkVisible = ref(false);
/** 评估输入长度上限：防止超长字符串直接进入 Argon2id 造成可感知卡顿 */
const CHECK_INPUT_MAX = 256;
const checkInputPlaceholder = "输入要检测的密码…";

/** 评估状态：模式分析在 Worker 中执行，字符集估算作为纯随机串口径与降级兜底 */
const {
  result: checkResult,
  pending: checkPending,
  assess: assessPassword,
  preload: preloadStrength,
} = usePasswordStrength();

const checkStrength = (): void => {
  assessPassword(checkInput.value);
};

/** 口径文案：来源与截断都必须如实呈现，禁止把降级结果说成模式分析 */
const checkCaveat = computed(() => {
  // 空输入没有可评估对象，展示默认口径而不是「未检出模式」
  if (checkResult.value.analyzedChars === 0) {
    return "覆盖常见口令词典、键盘路径、重复序列与日期模式识别";
  }
  let base: string;
  switch (checkResult.value.source) {
    case "pattern":
      base = "按猜测数模型评估：覆盖常见口令词典、键盘路径、重复序列与日期模式识别";
      break;
    case "charset-fallback":
      base = "模式分析不可用，已退回字符集熵估算";
      break;
    default:
      base = "未检出常见模式，按字符集空间估算";
  }
  return checkResult.value.truncated
    ? `${base}；超过 ${PASSWORD_ANALYSIS_MAX_CHARS} 字符的部分不参与模式分析`
    : base;
});

/* ===== Argon2id 单向加密 ===== */
const argonResult = ref("");
const argonProcessing = ref(false);
/** 计算代际：输入在计算期间变化时，过期结果必须丢弃（不得冒充当前口令的哈希） */
let argonRunSeq = 0;
/** 参数标签与计算调用同源（单一权威来源） */
const argonParams = argonParamsLabel();

const generateArgonHash = async () => {
  const pwd = checkInput.value;
  if (!pwd || argonProcessing.value) return;
  const seq = ++argonRunSeq;
  argonProcessing.value = true;
  argonResult.value = "";
  try {
    // 异步执行避免阻塞 UI
    await new Promise(r => setTimeout(r, 10));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await argon2id({
      password: pwd,
      salt,
      ...ARGON2_PARAMS,
      outputType: "encoded",
    });
    if (seq !== argonRunSeq) return;
    argonResult.value = hash;
  } catch (e) {
    console.error("[argonCompute] 异常", e);
    showError("计算失败，请重试");
  } finally {
    argonProcessing.value = false;
  }
};

const copyArgonResult = (): void => {
  if (!argonResult.value || argonProcessing.value) return;
  void copyText(argonResult.value, "argon");
};

/** 输入变化即失效旧哈希：结果必须始终属于当前输入 */
watch(checkInput, () => {
  argonRunSeq += 1;
  argonResult.value = "";
});

/* ===== 随机令牌（并入密码生成器卡） ===== */
const tokenBytes = ref(16);
const tokenFormat = ref<"hex" | "base64" | "uuid">("hex");
const tokenResult = ref("");

const generateToken = (): void => {
  if (tokenFormat.value === "uuid") {
    tokenResult.value = crypto.randomUUID();
    return;
  }
  const arr = new Uint8Array(tokenBytes.value);
  crypto.getRandomValues(arr);
  tokenResult.value = formatToken(arr, tokenFormat.value);
};

/** 令牌信息：UUIDv4 固定 122 位随机；其余格式为字节数 × 8 */
const tokenBitsText = computed(() => (
  tokenFormat.value === "uuid"
    ? "熵 ~122 bits · UUIDv4"
    : `熵 ~${tokenBytes.value * 8} bits · ${tokenBytes.value} 字节`
));

/* ===== 密钥生成工具（支持 .bin 导出） ===== */
const keygenBytes = ref(32);
const keygenFormat = ref<"hex" | "base64">("hex");
const keygenRaw = ref<Uint8Array>(new Uint8Array(0));
const keygenDisplay = computed(() => (
  keygenRaw.value.length === 0 ? "" : formatToken(keygenRaw.value, keygenFormat.value)
));
/** 导出会话闸门：双击不得并发打开两个保存对话框 */
const exportingKey = ref(false);

const keygenBits = computed(() => keygenBytes.value * 8);

const generateKey = (): void => {
  const arr = new Uint8Array(keygenBytes.value);
  crypto.getRandomValues(arr);
  keygenRaw.value = arr;
};

const keygenHashShort = computed(() => {
  if (keygenRaw.value.length === 0) return "";
  const h = sha256(keygenRaw.value);
  return Array.from(h.slice(0, 6)).map(b => b.toString(16).padStart(2, "0")).join("");
});

/** 导出 .bin 文件（密钥副本用后清零；失败如实告知） */
const exportBin = async () => {
  if (keygenRaw.value.length === 0 || exportingKey.value) return;
  exportingKey.value = true;
  const data = keygenRaw.value.slice();
  const suggestedName = randomKeyFileName(randomSource);

  try {
    if (isTauri) {
      try {
        const target = await save({
          filters: [{ name: "密钥文件", extensions: ["bin"] }],
          defaultPath: suggestedName,
        });
        if (target) {
          await writeUserFile(target, data);
          showToast(`已导出密钥文件：${target.split(/[\\/]/).pop()}`);
        }
      } catch {
        showError("导出失败");
      }
      return;
    }
    // 浏览器模式：Blob 下载
    try {
      const blob = new Blob([data.buffer as ArrayBuffer], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = suggestedName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showToast(`已导出 ${suggestedName}`);
    } catch {
      showError("导出失败");
    }
  } finally {
    // 内存中的密钥副本不驻留
    data.fill(0);
    exportingKey.value = false;
  }
};

onMounted(() => {
  generatePassword();
  generateToken();
  generateKey();
});

watch([genLength, genOpts], () => generatePassword(), { deep: true });
watch(pinLength, () => {
  if (genMode.value === "password" && genType.value === "pin") generatePassword();
});
watch(keygenBytes, () => generateKey());
watch(tokenBytes, () => generateToken());
</script>

<style scoped>
.password-tools {
  width: 100%;
  height: 100%;
  /* 卡片可在舞台内自由重叠，根容器不滚动，滚动条不出现 */
  overflow: hidden;
}

/* ===== 漂浮舞台 =====
 *   纯 2D 平面容器：不建透视、不建 3D 渲染上下文。卡片只做整像素平移，
 *   文字始终按 1:1 栅格绘制（任何 perspective / preserve-3d / translateZ /
 *   rotate / scale 都会让合成器重采样文字边缘，静止态即发虚）。
 *   卡片固定 312px 高、宽度取 46%（上限 520px），与内部排版预算一致；
 *   舞台宽度低于断点时整体让位给单列文档流，控制器同时停止写 transform。 */
.water-stage {
  position: relative;
  width: 100%;
  height: 100%;
  overflow: hidden;
}
.float-card {
  position: absolute;
  left: 0;
  top: 0;
  width: min(46%, 520px);
  height: 312px;
}
/* 入场只改 opacity。文字层不做任何常驻 transform 动画：连续的小数位移与微旋转
 * 会让合成器每帧重采样文字边缘，静止时也发虚、拖动时更明显。
 * 图层提升由控制器按需开关（拖拽 / 惯性 / 推挤期间临时 will-change，静止即撤销），
 * 常态不常驻合成层，桌面端保留完整文字抗锯齿。
 * 整卡是抓取面：留白、标题、标签、刻度条都可起拖，故抓取手势挂在这一层；
 * 按钮/输入/滑杆/复选框标签由控制器按命中选择器排除，并在此恢复各自的 cursor。 */
.float-card__body {
  width: 100%;
  height: 100%;
  opacity: 0;
  cursor: grab;
  touch-action: none;
  user-select: none;
  transition: opacity 0.42s var(--ease, ease) var(--enter-delay, 0ms);
}
.float-card.is-ready .float-card__body { opacity: 1; }
.float-card.is-grabbed .float-card__body { cursor: grabbing; }
/* 抓取反馈只由投影与层序承担：不缩放、不旋转、不抬 Z，文字始终落在同一栅格上 */
.float-card.is-grabbed .tool-section {
  border-color: var(--border-hover);
  box-shadow:
    0 22px 56px rgba(var(--black-rgb), 0.55),
    0 0 1px rgba(var(--accent-rgb), 0.18),
    inset 0 1px 0 rgba(var(--white-rgb), 0.06);
}
/* 文本可读/可选中：评估输入框与可复制显示框不因整卡禁选而失去选区能力 */
.float-card .check-input,
.float-card .field-box { user-select: text; }
.float-card .tool-section { width: 100%; height: 100%; min-height: 0; }

@media (prefers-reduced-motion: reduce) {
  .float-card__body { transition: none; opacity: 1; }
}

/* 文档流兜底：窄视口或矮视口下卡片回到文档流，控制器停止写 transform */
@media (max-width: 680px), (max-height: 700px) {
  .password-tools { overflow-y: auto; scrollbar-width: thin; }
  .water-stage {
    height: auto;
    min-height: 100%;
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .float-card {
    position: relative;
    width: 100%;
    transform: none !important;
  }
  /* 文档流下卡片不再可拖：交还光标与触屏滚动/文本选择，避免误锁滚动 */
  .float-card__body {
    opacity: 1;
    transition: none;
    cursor: auto;
    touch-action: auto;
    user-select: auto;
  }
  /* 头部在桌面是键盘入口并示意可拖；文档流下卡片不可拖，须一并交还触屏滚动与光标 */
  .float-card .section-header { cursor: auto; touch-action: auto; user-select: auto; }
  .float-card .tool-section { min-height: 280px; height: auto; }
}

/* 工具区块通用 */
/* 卡片底色：直接复用星野导航带底板（单源 tokens.css --bar-surface，
   与 StarlitSky 底板同一定义）；.glass 仅保留边框 / 圆角 / 投影 */
.tool-section {
  padding: 18px;
  background: var(--bar-surface);
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
}
/* 头部是键盘入口（聚焦后方向键移动卡片）；指针拖拽由整卡承担，此处只保留提示性 cursor */
.section-header {
  display: flex; align-items: center; gap: 8px; margin-bottom: 12px;
  cursor: grab; touch-action: none; user-select: none;
}
.section-header:focus-visible { outline: 1px solid var(--border-hover); outline-offset: 4px; }
.float-card.is-grabbed .section-header { cursor: grabbing; }
.section-icon { width: 16px; height: 16px; color: var(--accent); }
.section-icon svg { width: 100%; height: 100%; }
.section-title { font-size: 12px; color: var(--text-secondary); letter-spacing: 2px; text-transform: uppercase; font-family: var(--font); flex: 1; }
.section-badge {
  font-size: 9px;
  color: var(--accent);
  font-family: var(--font-mono);
  letter-spacing: 0.5px;
  padding: 2px 8px;
  border: 1px solid rgba(0, 212, 255, 0.2);
  border-radius: 8px;
  background: rgba(0, 212, 255, 0.05);
}

/* ===== 显示框（密码 / 令牌 / 密钥）=====
   与密码安全评估的输入框共用同一外观：40px 定高、同底色/描边/圆角/等宽字号，
   四个"密码框"因此尺寸完全一致（框内图标为 28px 命中区，落在 38px 内容区内） */
.field-box {
  height: 40px;
  padding: 0 14px;
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid var(--border-glass);
  border-radius: var(--radius);
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: 14px;
}
.field-box::placeholder { font-family: var(--font); font-size: 11px; color: var(--text-muted); font-style: italic; }
.field-box:focus-visible { outline: none; border-color: var(--accent); }
.gen-display,
.token-display,
.keygen-display {
  display: flex; align-items: center; justify-content: space-between; gap: 10px;
  /* 右侧 7px + 1px 描边 = 图标命中区距外沿 8px，14px 图标居中后
     字形右缘距外沿 15px —— 与评估框显隐钮的 8px 定位完全对齐 */
  padding-right: 7px;
  margin-bottom: 12px;
  cursor: pointer;
  transition: border-color 0.3s, background-color 0.3s;
}
.gen-display:hover,
.token-display:hover,
.keygen-display:hover { border-color: var(--border-hover); }

/* ===== 无框图标按钮 =====
   重新生成 / 复制 / 显隐只保留图标与状态色：无描边、无底色、无阴影 */
.icon-btn {
  display: flex; align-items: center; justify-content: center;
  width: 28px; height: 28px; padding: 0;
  border: 0; background: transparent;
  color: var(--text-muted);
  cursor: pointer; flex-shrink: 0;
  transition: color 0.2s;
}
.icon-btn svg { width: 14px; height: 14px; transition: transform 0.5s var(--ease); }
.icon-btn:hover:not(:disabled) { color: var(--accent); }
.icon-btn:disabled { opacity: 0.35; cursor: not-allowed; }
.icon-btn:focus-visible { outline: 1px solid var(--border-hover); outline-offset: 2px; }
.icon-btn--spin:hover:not(:disabled) svg { transform: rotate(180deg); }
.icon-btn--spin:active:not(:disabled) svg { transform: rotate(360deg); transition: transform 0.6s var(--ease); }

/* ===== 生成器 ===== */
/* 五种类型一行展示：内距压缩以在窄卡片上也保持单行 */
.gen-types { display: flex; gap: 4px; margin-bottom: 10px; flex-wrap: wrap; }
.gen-types .fmt-btn { padding: 5px 9px; font-size: 10px; letter-spacing: 0.5px; }
.gen-pwd { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1;
  background: linear-gradient(90deg, #00d4ff, #b46cff, #ff6eb4, #00d4ff);
  background-size: 200% auto;
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent; color: transparent;
  animation: gradient-flow 4s linear infinite;
}
@keyframes gradient-flow { to { background-position: 200% center; } }
.gen-actions { display: flex; gap: 6px; flex-shrink: 0; }
/* 导出密钥按钮沿用全局 .gen-btn 皮肤；显示框内的重新生成/复制为无框 .icon-btn */

/* 控件区纵向排列：滑杆独占一行，选项/预设另起一行，卡片下段不留大片空白 */
.gen-controls { display: flex; flex-direction: column; gap: 8px; margin-bottom: 12px; }
.ctrl-length { flex: 1; min-width: 140px; }
.ctrl-label { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-secondary); margin-bottom: 6px; letter-spacing: 1px; }
.ctrl-value { color: var(--accent); font-family: var(--font); font-weight: 600; }
/* 单项说明（UUID 随机位等）：与控件同列，高度固定，不随切换改变卡片节奏 */
.ctrl-hint { font-size: 10px; line-height: 15px; color: var(--text-muted); font-family: var(--font); letter-spacing: 0.2px; }
.slider { -webkit-appearance: none; appearance: none; width: 100%; height: 4px; background: rgba(0,212,255,0.1); border-radius: 2px; outline: none; }
.slider::-webkit-slider-thumb { -webkit-appearance: none; appearance: none; width: 14px; height: 14px; border-radius: 50%; background: var(--accent); cursor: pointer; transition: transform 0.2s; }
.slider::-webkit-slider-thumb:hover { transform: scale(1.2); }
.slider::-moz-range-thumb { width: 14px; height: 14px; border-radius: 50%; background: var(--accent); cursor: pointer; border: none; }
/* 键盘可达：remove outline 后必须以 focus-visible 补回焦点指示 */
.slider:focus-visible { outline: 1px solid var(--accent); outline-offset: 4px; }
.slider:disabled { opacity: 0.45; cursor: not-allowed; }
.slider:disabled::-webkit-slider-thumb { background: var(--text-muted); cursor: not-allowed; transform: none; }
.slider:disabled::-moz-range-thumb { background: var(--text-muted); cursor: not-allowed; }
.ctrl-opts { display: flex; gap: 6px; flex-wrap: wrap; }
.opt-chip { position: relative; display: flex; align-items: center; gap: 4px; padding: 5px 10px; border: 1px solid var(--border-glass); border-radius: 12px; font-size: 11px; color: var(--text-muted); cursor: pointer; transition: color 0.2s, border-color 0.2s, background-color 0.2s; font-family: var(--font); user-select: none; }
/* 复选框视觉隐藏但保留在无障碍树与 Tab 序列中（display:none 会同时剥夺键盘可达） */
.opt-chip input {
  position: absolute;
  width: 1px; height: 1px;
  margin: -1px; padding: 0; border: 0;
  overflow: hidden;
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  white-space: nowrap;
}
/* 仅键盘聚焦（:focus-visible）才点亮焦点环 —— 鼠标点选只改选中态，不遗留焦点描边 */
.opt-chip:has(input:focus-visible) { border-color: var(--accent); color: var(--accent); }
.opt-chip.on { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.08); }

/* 强度条 */
.strength-bar { height: 4px; background: rgba(255,255,255,0.05); border-radius: 2px; overflow: hidden; margin-bottom: 6px; }
.strength-fill { height: 100%; transition: width 0.4s var(--ease); border-radius: 2px;
  background: linear-gradient(90deg, #ff2e63 0%, #ff8c42 20%, #ffd700 40%, #00d4ff 65%, #00ffaa 100%);
  background-size: 200% 100%;
}
.strength-info { display: flex; justify-content: space-between; font-size: 11px; }
.strength-label { color: var(--text-secondary); }
.strength-entropy { color: var(--text-muted); font-family: var(--font); }

/* ===== 检测器 ===== */
/* 评估输入框与三个显示框共用 .field-box 外观；此处只补输入框专属度量：
   右侧留出显隐钮命中区 + 内距，长口令滚动时文字不钻入图标下方 */
.check-input-row { position: relative; margin-bottom: 8px; }
.check-input { width: 100%; min-width: 0; padding-right: 52px; outline: none; transition: border-color 0.2s; }
/* 显隐钮只剩眼睛本身：外形与命中区来自 .icon-btn，此处仅做定位 */
.check-toggle { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); }
.check-meter { display: flex; gap: 3px; margin-bottom: 6px; }
.meter-segment { flex: 1; height: 4px; background: rgba(255,255,255,0.05); border-radius: 2px; transition: background-color 0.3s; }
.meter-segment.filled { background: linear-gradient(90deg, #ff2e63, #ff8c42); }
.meter-segment.filled.seg-2 { background: linear-gradient(90deg, #ff8c42, #ffd700); }
.meter-segment.filled.seg-3 { background: linear-gradient(90deg, #ffd700, #00d4ff); }
.meter-segment.filled.seg-4 { background: linear-gradient(90deg, #00d4ff, #b46cff); }
.meter-segment.filled.seg-5 { background: linear-gradient(90deg, #b46cff, #00ffaa); }
.check-result { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.check-level { font-size: 13px; font-weight: 600; letter-spacing: 1px; }
.check-level.strength-1 { color: #ff2e63; }
.check-level.strength-2 { color: #ff8c42; }
.check-level.strength-3 { color: #ffd700; }
.check-level.strength-4 { color: var(--accent); }
.check-level.strength-5 { color: var(--success); }
.check-entropy { font-size: 10px; color: var(--text-muted); font-family: var(--font); }
/* 弱点提示：状态色直陈，无底色、无图标、无阴影；固定单行高度 + 截断，
   保证提示出现/消失不改变卡片内部布局 */
.check-advice {
  font-size: 10px; line-height: 15px; height: 15px;
  color: #ff8c42; font-family: var(--font); letter-spacing: 0.2px;
  margin: 0 0 4px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
/* 口径说明固定两行：来源切换（空输入/模式分析/降级/截断）不改变高度 */
.check-caveat {
  font-size: 9px; line-height: 1.5; height: 27px;
  color: var(--text-muted); font-family: var(--font); letter-spacing: 0.2px;
  overflow: hidden;
  margin-bottom: 8px;
}

/* ===== Argon2id 单向加密 ===== */
/* 分隔线吸收卡片剩余空间：Argon 区块始终贴底，口径文案换行不会推动它 */
.argon-divider {
  height: 1px;
  margin: auto 0 8px;
  background: linear-gradient(90deg, transparent, rgba(0, 212, 255, 0.15), transparent);
}
.argon-section { display: flex; flex-direction: column; gap: 6px; }
.argon-header { display: flex; align-items: center; justify-content: space-between; }
.argon-title {
  display: flex; align-items: center; gap: 6px;
  font-size: 11px; color: var(--text-secondary); letter-spacing: 0.5px;
}
.argon-title svg { width: 13px; height: 13px; color: var(--accent); }
.argon-gen-btn {
  display: flex; align-items: center; justify-content: center;
  width: 28px; height: 28px;
  border: 1px solid var(--border-glass); border-radius: var(--radius-sm);
  background: transparent; color: var(--text-muted);
  cursor: pointer; transition: color 0.2s, border-color 0.2s, background-color 0.2s; flex-shrink: 0;
}
.argon-gen-btn svg { width: 13px; height: 13px; transition: transform 0.5s var(--ease, ease); }
.argon-gen-btn:hover:not(:disabled) { color: var(--accent); border-color: var(--border-hover); background: rgba(0,212,255,0.06); }
.argon-gen-btn:hover:not(:disabled) svg { transform: rotate(180deg); }
.argon-gen-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.argon-params {
  display: flex; gap: 8px;
  font-size: 9px; color: var(--text-muted); font-family: var(--font-mono);
  letter-spacing: 0.5px;
}
.argon-params span {
  padding: 2px 6px;
  background: rgba(0, 212, 255, 0.04);
  border-radius: 3px;
}
.argon-result {
  position: relative;
  display: flex; align-items: center; gap: 8px;
  padding: 10px 12px;
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid var(--border-glass);
  border-radius: var(--radius-sm);
  min-height: 34px;
  /* role=button：不可点击时也不能显示可抓取光标，否则暗示了不存在的拖拽 */
  cursor: default;
  transition: border-color 0.3s, background-color 0.3s;
}
.argon-result.clickable { cursor: pointer; }
.argon-result.clickable:hover { border-color: var(--border-hover); background: rgba(0, 212, 255, 0.04); }
.argon-result.processing { opacity: 0.6; }
.argon-code {
  flex: 1;
  font-family: var(--font-mono); font-size: 10px;
  color: var(--accent); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  letter-spacing: 0.3px; line-height: 1.5;
}
.argon-loading { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); animation: pulse-text 1.2s ease-in-out infinite; }
.argon-placeholder { font-size: 11px; color: var(--text-muted); font-style: italic; }
.argon-copy-icon {
  width: 13px; height: 13px;
  color: var(--text-muted);
  flex-shrink: 0;
  transition: color 0.2s;
}
.argon-result.clickable:hover .argon-copy-icon { color: var(--accent); }
@keyframes pulse-text { 0%, 100% { opacity: 0.5; } 50% { opacity: 1; } }

/* ===== 令牌格式与通用小按钮（令牌模式、密钥卡共用） ===== */
.token-format { display: flex; gap: 4px; }
.fmt-btn { padding: 5px 12px; font-size: 11px; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); background: transparent; color: var(--text-muted); cursor: pointer; transition: color 0.2s, border-color 0.2s, background-color 0.2s; font-family: var(--font); letter-spacing: 1px; }
.fmt-btn.active { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.08); }

/* ===== 密钥生成工具 ===== */
.keygen-code { font-family: var(--font-mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1;
  background: linear-gradient(90deg, #b46cff, #00d4ff, #b46cff);
  background-size: 200% auto;
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent; color: transparent;
  animation: gradient-flow 5s linear infinite;
}
.keygen-actions { display: flex; gap: 6px; flex-shrink: 0; }

.keygen-controls { display: flex; flex-direction: column; gap: 12px; margin-bottom: 12px; }
.keygen-length { display: flex; flex-direction: column; gap: 6px; }
.keygen-presets { display: flex; gap: 6px; }
.preset-btn { flex: 1; padding: 7px 0; font-size: 12px; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); background: transparent; color: var(--text-muted); cursor: pointer; transition: color 0.2s, border-color 0.2s, background-color 0.2s; font-family: var(--font); font-weight: 600; }
.preset-btn:hover { color: var(--text-primary); border-color: var(--border-hover); }
.preset-btn.active { color: var(--accent); border-color: rgba(0, 212, 255, 0.3); background: rgba(0, 212, 255, 0.08); }
.keygen-format-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.format-label { font-size: 11px; color: var(--text-secondary); letter-spacing: 1px; }

.keygen-export-row { display: flex; align-items: center; justify-content: center; gap: 6px; margin-top: auto; padding-top: 10px; border-top: 1px dashed var(--border-glass); }
.keygen-hint { font-size: 10px; color: var(--text-muted); font-family: var(--font); text-align: center; }

/* ===== 可聚焦展示区（复制入口）焦点指示 =====
 *  四块展示区均以 role=button + tabindex 提供键盘复制；
 *  鼠标点击不显示焦点环，键盘 Tab 到必须可见 —— 与全站焦点语言一致 */
.gen-display:focus-visible,
.token-display:focus-visible,
.keygen-display:focus-visible,
.argon-result.clickable:focus-visible {
  outline: 1px solid var(--accent);
  outline-offset: 2px;
}
</style>
