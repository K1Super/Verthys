<!--
  PasswordTools.vue — 密码安全辅助工具模块
  四大工具（2x2 栅格布局）：
    1. 密码生成器（左上）
    2. 密码安全评估（右上）
    3. 随机令牌生成器（左下）
    4. 密钥生成工具（右下）— 支持生成密钥并导出为 .bin 文件
-->
<template>
  <div class="password-tools reveal-host" :class="{ 'is-entering': entering }">
    <div class="tools-grid">
      <!-- ===== 密码生成器 ===== -->
      <section class="tool-section glass gen-section reveal-item" :style="{ '--reveal-delay': revealDelayOf(0) + 'ms' }">
        <div class="section-header">
          <span class="section-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>
          </span>
          <span class="section-title">密码生成器</span>
        </div>

        <!-- 大显示区（点击或 Enter/Space 复制） -->
        <div
          class="gen-display"
          role="button"
          tabindex="0"
          aria-label="复制生成的密码"
          @click="copyText(genPassword, 'password')"
          @keydown="onDisplayKeydown($event, genPassword, 'password')"
        >
          <span class="gen-pwd" :class="`strength-${genStrength.level}`">{{ genPassword || '点击生成' }}</span>
          <div class="gen-actions">
            <button class="gen-btn gen-btn--spin" @click.stop="generatePassword" v-tip="'重新生成'" aria-label="重新生成密码">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            </button>
            <button class="gen-btn" @click.stop="copyText(genPassword, 'password')" v-tip="'复制'" aria-label="复制密码">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        </div>

        <!-- 控制面板 -->
        <div class="gen-controls">
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

        <!-- 强度指示 -->
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
      </section>

      <!-- ===== 密码安全评估 ===== -->
      <section class="tool-section glass check-section reveal-item" :style="{ '--reveal-delay': revealDelayOf(1) + 'ms' }">
        <div class="section-header">
          <span class="section-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </span>
          <span class="section-title">密码安全评估</span>
        </div>
        <!-- 待评估口令默认遮罩：安全工具里不得把真实口令全程明文展示 -->
        <div class="check-input-row">
          <input
            class="check-input"
            v-model="checkInput"
            :type="checkVisible ? 'text' : 'password'"
            :maxlength="CHECK_INPUT_MAX"
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
            aria-label="待评估密码"
            :placeholder="checkInputPlaceholder"
            @input="checkStrength"
          />
          <button
            class="gen-btn check-toggle"
            type="button"
            :aria-label="checkVisible ? '隐藏密码' : '显示密码'"
            v-tip="checkVisible ? '隐藏密码' : '显示密码'"
            @click="checkVisible = !checkVisible"
          >
            <svg v-if="!checkVisible" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
          </button>
        </div>
        <div class="check-meter">
          <div class="meter-segment" v-for="i in 5" :key="i" :class="{ filled: checkResult.level >= i, [`seg-${i}`]: true }"></div>
        </div>
        <div class="check-result">
          <span class="check-level" :class="`strength-${checkResult.level}`">{{ checkResult.label }}</span>
          <span class="check-entropy">熵 ~{{ checkResult.entropy }} bits · 破解 ~{{ checkResult.crackTime }}</span>
        </div>
        <!-- 口径如实标注：本模型不含字典与键盘布局检测 -->
        <div class="check-caveat">按字符集熵估算（含重复/顺子惩罚），不含字典与键盘布局检测</div>

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

      <!-- ===== 随机令牌生成器 ===== -->
      <section class="tool-section glass token-section reveal-item" :style="{ '--reveal-delay': revealDelayOf(2) + 'ms' }">
        <div class="section-header">
          <span class="section-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          </span>
          <span class="section-title">随机令牌</span>
        </div>
        <div
          class="token-display"
          role="button"
          tabindex="0"
          aria-label="复制随机令牌"
          @click="copyText(tokenResult, 'token')"
          @keydown="onDisplayKeydown($event, tokenResult, 'token')"
        >
          <code class="token-code">{{ tokenResult || '点击生成' }}</code>
          <div class="token-actions">
            <button class="gen-btn gen-btn--spin" @click.stop="generateToken" v-tip="'重新生成'" aria-label="生成令牌">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            </button>
            <button class="gen-btn" @click.stop="copyText(tokenResult, 'token')" v-tip="'复制'" aria-label="复制令牌">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
          </div>
        </div>
        <div class="token-controls">
          <div class="token-slider-wrap">
            <div class="token-slider-label">
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
              :disabled="tokenFormat === 'uuid'"
            />
          </div>
          <div class="token-format">
            <button class="fmt-btn" :class="{ active: tokenFormat === 'hex' }" @click="tokenFormat = 'hex'; generateToken()">HEX</button>
            <button class="fmt-btn" :class="{ active: tokenFormat === 'base64' }" @click="tokenFormat = 'base64'; generateToken()">Base64</button>
            <button class="fmt-btn" :class="{ active: tokenFormat === 'uuid' }" @click="tokenFormat = 'uuid'; generateToken()">UUID</button>
          </div>
        </div>
      </section>

      <!-- ===== 密钥生成工具（新增，支持 .bin 导出） ===== -->
      <section class="tool-section glass keygen-section reveal-item" :style="{ '--reveal-delay': revealDelayOf(3) + 'ms' }">
        <div class="section-header">
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
          class="keygen-display"
          role="button"
          tabindex="0"
          aria-label="复制密钥"
          @click="copyText(keygenDisplay, 'key')"
          @keydown="onDisplayKeydown($event, keygenDisplay, 'key')"
        >
          <code class="keygen-code">{{ keygenDisplay || '点击生成密钥' }}</code>
          <div class="keygen-actions">
            <button class="gen-btn gen-btn--spin" @click.stop="generateKey" v-tip="'重新生成'" aria-label="重新生成密钥">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            </button>
            <button class="gen-btn" @click.stop="copyText(keygenDisplay, 'key')" v-tip="'复制'" aria-label="复制密钥">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
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
import { useModuleEntrance, revealDelayOf } from "../../composables/useModuleEntrance";
import {
  ARGON2_PARAMS,
  argonParamsLabel,
  buildCharset,
  calcCrackTime,
  calcStrength,
  composePassword,
  formatToken,
  randomKeyFileName,
  type CharsetOptions,
  type RandomSource,
} from "../../composables/key-tools/password_tools";

/* 步入窗口：四个工具分区为静态内容 —— 窗口随挂载开启（内容就绪恒为真），
 *   标记与分区同批落地，首帧即入场起点 */
const { entering } = useModuleEntrance(() => true);

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

/* 四类内容各自独立文案；同一时刻只有最后一次复制持有清空计时归属权 */
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
const genLength = ref(16);
const genOpts = ref<CharsetOptions>({ upper: true, lower: true, digits: true, symbols: false, exclude: false });
const genPassword = ref("");

const generatePassword = (): void => {
  const opts: CharsetOptions = { ...genOpts.value };
  // 全部关闭时明确置空（不接受"看起来生成了但实际为空池"）
  if (!buildCharset(opts)) {
    genPassword.value = "";
    return;
  }
  genPassword.value = composePassword(opts, genLength.value, randomSource);
};

/* 强度指示（口径见 key-tools/password_tools.ts：周期重复/顺子已扣减） */
const genStrength = computed(() => calcStrength(genPassword.value));

/* ===== 密码安全评估 ===== */
const checkInput = ref("");
const checkVisible = ref(false);
/** 评估输入长度上限：防止超长字符串直接进入 Argon2id 造成可感知卡顿 */
const CHECK_INPUT_MAX = 256;
const checkResult = ref({ ...calcStrength(""), crackTime: calcCrackTime(0) });
const checkInputPlaceholder = "输入要检测的密码…";

const checkStrength = (): void => {
  const base = calcStrength(checkInput.value);
  checkResult.value = { ...base, crackTime: calcCrackTime(base.entropy) };
};

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

/* ===== 随机令牌 ===== */
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
watch(keygenBytes, () => generateKey());
watch(tokenBytes, () => generateToken());
</script>

<style scoped>
.password-tools {
  width: 100%;
  height: 100%;
  display: flex;
  overflow-y: auto;
  overflow-x: hidden;
  scrollbar-width: thin;
}

/* ===== 2x2 栅格布局 =====
 *   margin: auto（而非 align-items: center）+ min-height: 100%：
 *   内容不足时整块居中；四分区总高超出视口时可从顶部完整滚到底 ——
 *   居中容器直接叠加 overflow 会把上沿推到不可达区域。
 */
.tools-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 14px;
  align-content: center;
  width: 100%;
  min-height: 100%;
  margin: auto;
  padding: 2px;
}
@media (max-width: 680px) {
  .tools-grid { grid-template-columns: 1fr; }
}

/* 工具区块通用 */
/* 卡片底色：直接复用星野导航带底板（单源 tokens.css --bar-surface，
   与 StarlitSky 底板同一定义）；.glass 仅保留边框 / 圆角 / 投影 */
.tool-section {
  padding: 20px;
  background: var(--bar-surface);
  display: flex;
  flex-direction: column;
  min-height: 280px;
  overflow: hidden;
}
/* 分区入场已收敛到全局「模块步入编排」（styles/animations.css）：
   本组件根为步入窗口宿主、四分区为内容条目，错峰由 revealDelayOf 注入 ——
   包络与错峰曲线不再各自定义 */

.section-header { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; }
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

/* ===== 生成器 ===== */
.gen-display { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 16px 18px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: var(--radius); margin-bottom: 14px; cursor: pointer; transition: border-color 0.3s, background-color 0.3s; }
.gen-display:hover { border-color: var(--border-hover); }
.gen-pwd { font-family: var(--font-mono); font-size: 16px; letter-spacing: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1;
  background: linear-gradient(90deg, #00d4ff, #b46cff, #ff6eb4, #00d4ff);
  background-size: 200% auto;
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent; color: transparent;
  animation: gradient-flow 4s linear infinite;
}
@keyframes gradient-flow { to { background-position: 200% center; } }
.gen-actions { display: flex; gap: 6px; flex-shrink: 0; }
/* .gen-btn 图标按钮统一样式已提取为全局复用类，本组件三个图标按钮（重新生成/复制/导出密钥）直接复用，不再定义专属样式 */

.gen-controls { display: flex; gap: 20px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
.ctrl-length { flex: 1; min-width: 140px; }
.ctrl-label { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-secondary); margin-bottom: 6px; letter-spacing: 1px; }
.ctrl-value { color: var(--accent); font-family: var(--font); font-weight: 600; }
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
/* 显隐钮收进检测框内右侧：与生成器/令牌的重新生成、复制按钮同用 .gen-btn
 * 皮肤（32×32 / 1px 玻璃描边 / 透明底 / 悬浮同源高亮），仅追加定位；
 * 输入框右侧留出按钮宽度 + 内距，长口令滚动时文字不钻入按钮下方 */
.check-input-row { position: relative; margin-bottom: 12px; }
.check-input { width: 100%; min-width: 0; padding: 12px 52px 12px 14px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: var(--radius); color: var(--text-primary); font-size: 14px; font-family: var(--font-mono); outline: none; transition: border-color 0.2s; }
.check-input::placeholder { font-family: var(--font); font-size: 11px; color: var(--text-muted); font-style: italic; }
.check-input:focus-visible { border-color: var(--accent); }
.check-toggle { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); }
.check-meter { display: flex; gap: 3px; margin-bottom: 8px; }
.meter-segment { flex: 1; height: 4px; background: rgba(255,255,255,0.05); border-radius: 2px; transition: background-color 0.3s; }
.meter-segment.filled { background: linear-gradient(90deg, #ff2e63, #ff8c42); }
.meter-segment.filled.seg-2 { background: linear-gradient(90deg, #ff8c42, #ffd700); }
.meter-segment.filled.seg-3 { background: linear-gradient(90deg, #ffd700, #00d4ff); }
.meter-segment.filled.seg-4 { background: linear-gradient(90deg, #00d4ff, #b46cff); }
.meter-segment.filled.seg-5 { background: linear-gradient(90deg, #b46cff, #00ffaa); }
.check-result { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.check-level { font-size: 13px; font-weight: 600; letter-spacing: 1px; }
.check-level.strength-1 { color: #ff2e63; }
.check-level.strength-2 { color: #ff8c42; }
.check-level.strength-3 { color: #ffd700; }
.check-level.strength-4 { color: var(--accent); }
.check-level.strength-5 { color: var(--success); }
.check-entropy { font-size: 10px; color: var(--text-muted); font-family: var(--font); }
.check-caveat { font-size: 9px; line-height: 1.5; color: var(--text-muted); font-family: var(--font); letter-spacing: 0.2px; }

/* ===== Argon2id 单向加密 ===== */
.argon-divider {
  height: 1px;
  margin: 14px 0 12px;
  background: linear-gradient(90deg, transparent, rgba(0, 212, 255, 0.15), transparent);
}
.argon-section { display: flex; flex-direction: column; gap: 8px; }
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
  min-height: 38px;
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

/* ===== 令牌生成器 ===== */
.token-display { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 14px 16px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: var(--radius); margin-bottom: 12px; cursor: pointer; transition: border-color 0.3s, background-color 0.3s; }
.token-display:hover { border-color: var(--border-hover); }
.token-code { font-family: var(--font-mono); font-size: 13px; color: var(--accent); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1; letter-spacing: 1px; }
.token-actions { display: flex; gap: 6px; flex-shrink: 0; }
.token-controls { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
.token-slider-wrap { flex: 1; min-width: 140px; }
.token-slider-label { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-secondary); margin-bottom: 6px; letter-spacing: 1px; }
.token-format { display: flex; gap: 4px; }
.fmt-btn { padding: 5px 12px; font-size: 11px; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); background: transparent; color: var(--text-muted); cursor: pointer; transition: color 0.2s, border-color 0.2s, background-color 0.2s; font-family: var(--font); letter-spacing: 1px; }
.fmt-btn.active { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.08); }

/* ===== 密钥生成工具 ===== */
.keygen-display { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 14px 16px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: var(--radius); margin-bottom: 12px; cursor: pointer; transition: border-color 0.3s, background-color 0.3s; }
.keygen-display:hover { border-color: var(--border-hover); }
.keygen-code { font-family: var(--font-mono); font-size: 12px; color: #b46cff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1; letter-spacing: 1px;
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
