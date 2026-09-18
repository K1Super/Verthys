<!--
  PasswordTools.vue — 密码安全辅助工具模块
  四大工具（2x2 栅格布局）：
    1. 密码生成器（左上）
    2. 密码安全评估（右上）
    3. 随机令牌生成器（左下）
    4. 密钥生成工具（右下）— 支持生成密钥并导出为 .bin 文件
-->
<template>
  <div class="password-tools">
    <div class="tools-grid">
      <!-- ===== 密码生成器 ===== -->
      <section class="tool-section glass gen-section">
        <div class="section-header">
          <span class="section-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5"/></svg>
          </span>
          <span class="section-title">密码生成器</span>
        </div>

        <!-- 大显示区 -->
        <div class="gen-display" @click="copyText(genPassword)">
          <span class="gen-pwd" :class="`strength-${genStrength.level}`">{{ genPassword || '点击生成' }}</span>
          <div class="gen-actions">
            <button class="gen-btn gen-btn--spin" @click.stop="generatePassword" v-tip="'重新生成'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            </button>
            <button class="gen-btn" @click.stop="copyText(genPassword)" v-tip="'复制'">
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
            <input type="range" class="slider" v-model.number="genLength" min="8" max="64" step="1" />
          </div>
          <div class="ctrl-opts">
            <label class="opt-chip" :class="{ on: genOpts.upper }">
              <input type="checkbox" v-model="genOpts.upper" />
              <span>A-Z</span>
            </label>
            <label class="opt-chip" :class="{ on: genOpts.lower }">
              <input type="checkbox" v-model="genOpts.lower" />
              <span>a-z</span>
            </label>
            <label class="opt-chip" :class="{ on: genOpts.digits }">
              <input type="checkbox" v-model="genOpts.digits" />
              <span>0-9</span>
            </label>
            <label class="opt-chip" :class="{ on: genOpts.symbols }">
              <input type="checkbox" v-model="genOpts.symbols" />
              <span>!@#</span>
            </label>
            <label class="opt-chip" :class="{ on: genOpts.exclude }">
              <input type="checkbox" v-model="genOpts.exclude" />
              <span>排除相似</span>
            </label>
          </div>
        </div>

        <!-- 强度指示 -->
        <div class="strength-bar">
          <div class="strength-fill" :class="`strength-${genStrength.level}`" :style="{ width: `${genStrength.percent}%` }"></div>
        </div>
        <div class="strength-info">
          <span class="strength-label">{{ genStrength.label }}</span>
          <span class="strength-entropy">熵 ~{{ genStrength.entropy }} bits</span>
        </div>
      </section>

      <!-- ===== 密码安全评估 ===== -->
      <section class="tool-section glass check-section">
        <div class="section-header">
          <span class="section-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </span>
          <span class="section-title">密码安全评估</span>
        </div>
        <input
          class="check-input"
          v-model="checkInput"
          type="text"
          :placeholder="checkInputPlaceholder"
          @input="checkStrength"
        />
        <div class="check-meter">
          <div class="meter-segment" v-for="i in 5" :key="i" :class="{ filled: checkResult.level >= i, [`seg-${i}`]: true }"></div>
        </div>
        <div class="check-result">
          <span class="check-level" :class="`strength-${checkResult.level}`">{{ checkResult.label }}</span>
          <span class="check-entropy">熵 ~{{ checkResult.entropy }} bits · 破解 ~{{ checkResult.crackTime }}</span>
        </div>

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
              v-tip="argonProcessing ? '计算中…' : '生成 Argon2id 哈希'"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            </button>
          </div>
          <div class="argon-params">
            <span>t=3</span><span>m=65536</span><span>p=1</span><span>len=32</span>
          </div>
          <div class="argon-result" @click="copyArgonResult" :class="{ clickable: argonResult, processing: argonProcessing }">
            <code v-if="argonResult" class="argon-code">{{ argonResult }}</code>
            <span v-else-if="argonProcessing" class="argon-loading">计算中…</span>
            <span v-else class="argon-placeholder">{{ checkInput ? '点击按钮生成凭证串' : '请先输入密码' }}</span>
            <svg v-if="argonResult" class="argon-copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          </div>
        </div>
      </section>

      <!-- ===== 随机令牌生成器 ===== -->
      <section class="tool-section glass token-section">
        <div class="section-header">
          <span class="section-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          </span>
          <span class="section-title">随机令牌</span>
        </div>
        <div class="token-display" @click="copyText(tokenResult)">
          <code class="token-code">{{ tokenResult || '点击生成' }}</code>
          <button class="gen-btn gen-btn--spin" @click.stop="generateToken" v-tip="'生成'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
          </button>
        </div>
        <div class="token-controls">
          <div class="token-slider-wrap">
            <div class="token-slider-label">
              <span>字节数</span>
              <span class="ctrl-value">{{ tokenBytes }}</span>
            </div>
            <input type="range" class="slider" v-model.number="tokenBytes" min="4" max="64" step="1" />
          </div>
          <div class="token-format">
            <button class="fmt-btn" :class="{ active: tokenFormat === 'hex' }" @click="tokenFormat = 'hex'; generateToken()">HEX</button>
            <button class="fmt-btn" :class="{ active: tokenFormat === 'base64' }" @click="tokenFormat = 'base64'; generateToken()">Base64</button>
            <button class="fmt-btn" :class="{ active: tokenFormat === 'uuid' }" @click="tokenFormat = 'uuid'; generateToken()">UUID</button>
          </div>
        </div>
      </section>

      <!-- ===== 密钥生成工具（新增，支持 .bin 导出） ===== -->
      <section class="tool-section glass keygen-section">
        <div class="section-header">
          <span class="section-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3"/></svg>
          </span>
          <span class="section-title">密钥生成工具</span>
          <button class="keygen-export-icon" @click="exportBin" :disabled="!keygenBytes || !keygenRaw.length" v-tip="'导出密钥'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          </button>
        </div>

        <!-- 密钥显示区 -->
        <div class="keygen-display" @click="copyText(keygenDisplay)">
          <code class="keygen-code">{{ keygenDisplay || '点击生成密钥' }}</code>
          <div class="keygen-actions">
            <button class="gen-btn gen-btn--spin" @click.stop="generateKey" v-tip="'重新生成'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            </button>
            <button class="gen-btn" @click.stop="copyText(keygenDisplay)" v-tip="'复制'">
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
                @click="keygenBytes = n; generateKey()"
              >{{ n }}</button>
            </div>
          </div>
          <div class="keygen-format-row">
            <span class="format-label">显示格式</span>
            <div class="token-format">
              <button class="fmt-btn" :class="{ active: keygenFormat === 'hex' }" @click="keygenFormat = 'hex'; updateKeygenDisplay()">HEX</button>
              <button class="fmt-btn" :class="{ active: keygenFormat === 'base64' }" @click="keygenFormat = 'base64'; updateKeygenDisplay()">Base64</button>
            </div>
          </div>
        </div>

        <!-- 密钥状态提示 -->
        <div class="keygen-export-row">
          <span class="keygen-hint">{{ keygenRaw.length ? `当前密钥 ${keygenRaw.length} 字节 · SHA-256: ${keygenHashShort}` : '生成密钥后点击右上角图标导出 .bin 文件' }}</span>
        </div>
      </section>
    </div>

    <!-- 顶部错误提示弹窗 -->
    <Teleport to="body">
      <transition name="err-toast">
        <div v-if="errorMsg" class="error-toast glass"><span class="toast-dot"></span>{{ errorMsg }}</div>
      </transition>
    </Teleport>

    <!-- 底部成功提示（复用全局 clip-toast 样式） -->
    <transition name="toast">
      <div v-if="copied" class="clip-toast glass"><span class="toast-dot"></span>已复制到剪贴板</div>
    </transition>
    <transition name="toast">
      <div v-if="toastMsg" class="clip-toast glass"><span class="toast-dot"></span>{{ toastMsg }}</div>
    </transition>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from "vue";
import { save } from "@tauri-apps/plugin-dialog";
import { sha256 } from "@noble/hashes/sha2";
import { argon2id } from "hash-wasm";
import { writeUserFile } from "../../lib/verthys";
import { useErrorToast } from "../../composables/useErrorToast";

/* ===== 顶部错误提示弹窗 ===== */
const { errorMsg, showError } = useErrorToast();

/* ===== 环境检测 ===== */
const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/* ===== 密码生成器 ===== */
const genLength = ref(16);
const genOpts = ref({ upper: true, lower: true, digits: true, symbols: false, exclude: false });
const genPassword = ref("");

const charsets = {
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lower: "abcdefghijklmnopqrstuvwxyz",
  digits: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
  similar: "Il1O0o",
};

const generatePassword = () => {
  let pool = "";
  if (genOpts.value.upper) pool += charsets.upper;
  if (genOpts.value.lower) pool += charsets.lower;
  if (genOpts.value.digits) pool += charsets.digits;
  if (genOpts.value.symbols) pool += charsets.symbols;
  if (genOpts.value.exclude) {
    pool = pool.split("").filter(c => !charsets.similar.includes(c)).join("");
  }
  if (!pool) { genPassword.value = ""; return; }
  const arr = new Uint32Array(genLength.value);
  crypto.getRandomValues(arr);
  let pwd = "";
  for (let i = 0; i < genLength.value; i++) pwd += pool[arr[i] % pool.length];
  genPassword.value = pwd;
};

/* 强度计算 */
const calcStrength = (pwd: string) => {
  if (!pwd) return { level: 0, percent: 0, entropy: 0, label: "", crackTime: "" };
  let charsetSize = 0;
  if (/[a-z]/.test(pwd)) charsetSize += 26;
  if (/[A-Z]/.test(pwd)) charsetSize += 26;
  if (/[0-9]/.test(pwd)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) charsetSize += 32;
  const entropy = Math.round(pwd.length * Math.log2(charsetSize || 1));
  let level = 1, label = "极弱", percent = 20;
  if (entropy >= 40) { level = 2; label = "弱"; percent = 40; }
  if (entropy >= 60) { level = 3; label = "中等"; percent = 60; }
  if (entropy >= 80) { level = 4; label = "强"; percent = 80; }
  if (entropy >= 100) { level = 5; label = "极强"; percent = 100; }
  return { level, percent, entropy, label, crackTime: "" };
};
const genStrength = computed(() => calcStrength(genPassword.value));

/* ===== 密码安全评估 ===== */
const checkInput = ref("");
const checkResult = ref(calcStrength(""));
const checkInputPlaceholder = "输入要检测的密码…";

const checkStrength = () => {
  const pwd = checkInput.value;
  const base = calcStrength(pwd);
  const crackTime = calcCrackTime(base.entropy);
  checkResult.value = { ...base, crackTime };
};

const calcCrackTime = (entropy: number) => {
  if (entropy === 0) return "即时";
  const seconds = Math.pow(2, entropy) / 1e10; // 10 billion guesses/sec
  if (seconds < 1) return "即时";
  if (seconds < 60) return `${Math.round(seconds)} 秒`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} 分钟`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} 小时`;
  if (seconds < 31536000) return `${Math.round(seconds / 86400)} 天`;
  if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)} 年`;
  if (seconds < 31536000 * 1e6) return `${Math.round(seconds / 31536000 / 1000)} 千年`;
  return "宇宙年龄+";
};

/* ===== Argon2id 单向加密 ===== */
const argonResult = ref("");
const argonProcessing = ref(false);

const generateArgonHash = async () => {
  if (!checkInput.value || argonProcessing.value) return;
  argonProcessing.value = true;
  argonResult.value = "";
  try {
    // 异步执行避免阻塞 UI
    await new Promise(r => setTimeout(r, 10));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await argon2id({
      password: checkInput.value,
      salt,
      parallelism: 1,
      memorySize: 65536,  // 64 MB
      iterations: 3,
      hashLength: 32,
      outputType: "encoded",
    });
    argonResult.value = hash;
  } catch (e) {
    console.error("[argonCompute] 异常", e);
    showError("计算失败，请重试");
  } finally {
    argonProcessing.value = false;
  }
};

const copyArgonResult = () => {
  if (!argonResult.value || argonProcessing.value) return;
  copyText(argonResult.value);
};

/* ===== 随机令牌 ===== */
const tokenBytes = ref(16);
const tokenFormat = ref<"hex" | "base64" | "uuid">("hex");
const tokenResult = ref("");

const generateToken = () => {
  if (tokenFormat.value === "uuid") {
    tokenResult.value = crypto.randomUUID();
    return;
  }
  const arr = new Uint8Array(tokenBytes.value);
  crypto.getRandomValues(arr);
  if (tokenFormat.value === "hex") {
    tokenResult.value = Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
  } else {
    tokenResult.value = btoa(String.fromCharCode(...arr));
  }
};

/* ===== 密钥生成工具（新增，支持 .bin 导出） ===== */
const keygenBytes = ref(32);
const keygenFormat = ref<"hex" | "base64">("hex");
const keygenRaw = ref<Uint8Array>(new Uint8Array(0));
const keygenDisplay = ref("");

const keygenBits = computed(() => keygenBytes.value * 8);

const generateKey = () => {
  const arr = new Uint8Array(keygenBytes.value);
  crypto.getRandomValues(arr);
  keygenRaw.value = arr;
  updateKeygenDisplay();
};

const updateKeygenDisplay = () => {
  if (keygenRaw.value.length === 0) {
    keygenDisplay.value = "";
    return;
  }
  if (keygenFormat.value === "hex") {
    keygenDisplay.value = Array.from(keygenRaw.value).map(b => b.toString(16).padStart(2, "0")).join("");
  } else {
    keygenDisplay.value = btoa(String.fromCharCode(...keygenRaw.value));
  }
};

const keygenHashShort = computed(() => {
  if (keygenRaw.value.length === 0) return "";
  const h = sha256(keygenRaw.value);
  return Array.from(h.slice(0, 6)).map(b => b.toString(16).padStart(2, "0")).join("");
});

/** 生成14位无规律随机文件名（大小写字母混排，每次不同，不暴露任何信息） */
const randomKeyFileName = (): string => {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const bytes = new Uint8Array(14);
  crypto.getRandomValues(bytes);
  let s = "";
  for (let i = 0; i < 14; i++) s += alphabet[bytes[i] % alphabet.length];
  return s + ".bin";
};

/** 导出 .bin 文件 */
const exportBin = async () => {
  if (keygenRaw.value.length === 0) return;
  const data = keygenRaw.value.slice();
  const suggestedName = randomKeyFileName();

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
    const blob = new Blob([data.slice().buffer as ArrayBuffer], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = suggestedName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(`已导出 ${suggestedName}`);
  } catch { showError("导出失败"); }
};

/* ===== 复制 + Toast ===== */
const copied = ref(false);
const copyText = async (text: string) => {
  if (!text) return;
  // 优先尝试 Clipboard API（浏览器安全上下文）
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch {
    // 回退：textarea + execCommand（Tauri webview 兼容）
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      ta.style.top = "0";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      ok = document.execCommand("copy");
      document.body.removeChild(ta);
    } catch { /* */ }
  }
  if (ok) {
    copied.value = true;
    setTimeout(() => { copied.value = false; }, 1500);
  }
};

const toastMsg = ref("");
let toastTimer: number | null = null;
const showToast = (msg: string) => {
  toastMsg.value = msg;
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => { toastMsg.value = ""; }, 2500);
};

onMounted(() => {
  generatePassword();
  generateToken();
  generateKey();
});

watch([genLength, genOpts], () => generatePassword(), { deep: true });
watch(keygenBytes, () => generateKey());
</script>

<style scoped>
.password-tools {
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
}

/* ===== 2x2 栅格布局 ===== */
.tools-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 14px;
  align-content: center;
  width: 100%;
}
@media (max-width: 680px) {
  .tools-grid { grid-template-columns: 1fr; }
}

/* 工具区块通用 */
.tool-section {
  padding: 20px;
  animation: section-in 0.5s var(--ease) both;
  display: flex;
  flex-direction: column;
  height: 280px;
  overflow: hidden;
}
@keyframes section-in {
  from { opacity: 0; transform: translateY(10px); filter: blur(4px); }
  to { opacity: 1; transform: translateY(0); filter: blur(0); }
}
.gen-section { animation-delay: 0s; }
.check-section { animation-delay: 0.08s; }
.token-section { animation-delay: 0.16s; }
.keygen-section { animation-delay: 0.24s; }

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
.gen-display { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 16px 18px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: var(--radius); margin-bottom: 14px; cursor: pointer; transition: all 0.3s; }
.gen-display:hover { border-color: var(--border-hover); box-shadow: 0 0 16px rgba(0,212,255,0.08); }
.gen-pwd { font-family: var(--font-mono); font-size: 16px; letter-spacing: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1;
  background: linear-gradient(90deg, #00d4ff, #b46cff, #ff6eb4, #00d4ff);
  background-size: 200% auto;
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent; color: transparent;
  animation: gradient-flow 4s linear infinite;
}
@keyframes gradient-flow { to { background-position: 200% center; } }
.gen-actions { display: flex; gap: 6px; flex-shrink: 0; }
/* .gen-btn 样式已提取为全局类（App.vue），此处复用全局定义 */

.gen-controls { display: flex; gap: 20px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
.ctrl-length { flex: 1; min-width: 140px; }
.ctrl-label { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-secondary); margin-bottom: 6px; letter-spacing: 1px; }
.ctrl-value { color: var(--accent); font-family: var(--font); font-weight: 600; }
.slider { -webkit-appearance: none; appearance: none; width: 100%; height: 4px; background: rgba(0,212,255,0.1); border-radius: 2px; outline: none; }
.slider::-webkit-slider-thumb { -webkit-appearance: none; appearance: none; width: 14px; height: 14px; border-radius: 50%; background: var(--accent); cursor: pointer; box-shadow: 0 0 8px rgba(0,212,255,0.4); transition: transform 0.2s; }
.slider::-webkit-slider-thumb:hover { transform: scale(1.2); }
.slider::-moz-range-thumb { width: 14px; height: 14px; border-radius: 50%; background: var(--accent); cursor: pointer; border: none; box-shadow: 0 0 8px rgba(0,212,255,0.4); }
.ctrl-opts { display: flex; gap: 6px; flex-wrap: wrap; }
.opt-chip { display: flex; align-items: center; gap: 4px; padding: 5px 10px; border: 1px solid var(--border-glass); border-radius: 12px; font-size: 11px; color: var(--text-muted); cursor: pointer; transition: all 0.2s; font-family: var(--font); user-select: none; }
.opt-chip input { display: none; }
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
.check-input { width: 100%; padding: 12px 14px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: var(--radius); color: var(--text-primary); font-size: 14px; font-family: var(--font-mono); outline: none; transition: all 0.2s; margin-bottom: 12px; }
.check-input::placeholder { font-family: var(--font); font-size: 11px; color: var(--text-muted); font-style: italic; }
.check-input:focus { border-color: var(--accent); box-shadow: 0 0 12px rgba(0,212,255,0.08); }
.check-meter { display: flex; gap: 3px; margin-bottom: 8px; }
.meter-segment { flex: 1; height: 4px; background: rgba(255,255,255,0.05); border-radius: 2px; transition: all 0.3s; }
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
  cursor: pointer; transition: all 0.2s; flex-shrink: 0;
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
  transition: all 0.3s;
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
.token-display { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 14px 16px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: var(--radius); margin-bottom: 12px; cursor: pointer; transition: all 0.3s; }
.token-display:hover { border-color: var(--border-hover); }
.token-code { font-family: var(--font-mono); font-size: 13px; color: var(--accent); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1; letter-spacing: 1px; }
.token-controls { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; }
.token-slider-wrap { flex: 1; min-width: 140px; }
.token-slider-label { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-secondary); margin-bottom: 6px; letter-spacing: 1px; }
.token-format { display: flex; gap: 4px; }
.fmt-btn { padding: 5px 12px; font-size: 11px; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); background: transparent; color: var(--text-muted); cursor: pointer; transition: all 0.2s; font-family: var(--font); letter-spacing: 1px; }
.fmt-btn.active { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.08); }

/* ===== 密钥生成工具 ===== */
.keygen-display { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 14px 16px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: var(--radius); margin-bottom: 12px; cursor: pointer; transition: all 0.3s; }
.keygen-display:hover { border-color: var(--border-hover); box-shadow: 0 0 16px rgba(139, 92, 246, 0.08); }
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
.preset-btn { flex: 1; padding: 7px 0; font-size: 12px; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); background: transparent; color: var(--text-muted); cursor: pointer; transition: all 0.2s; font-family: var(--font); font-weight: 600; }
.preset-btn:hover { color: var(--text-primary); border-color: var(--border-hover); }
.preset-btn.active { color: var(--accent); border-color: rgba(0, 212, 255, 0.3); background: rgba(0, 212, 255, 0.08); box-shadow: 0 0 8px rgba(0, 212, 255, 0.1); }
.keygen-format-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.format-label { font-size: 11px; color: var(--text-secondary); letter-spacing: 1px; }

.keygen-export-row { display: flex; align-items: center; justify-content: center; gap: 6px; margin-top: auto; padding-top: 10px; border-top: 1px dashed var(--border-glass); }
/* 右上角导出图标按钮 */
.keygen-export-icon {
  display: flex; align-items: center; justify-content: center;
  width: 26px; height: 26px; padding: 0;
  background: rgba(139, 92, 246, 0.08);
  border: 1px solid rgba(139, 92, 246, 0.22);
  border-radius: var(--radius-sm);
  color: #b46cff;
  cursor: pointer;
  transition: all 0.3s var(--ease);
  flex-shrink: 0;
  position: relative;
}
.keygen-export-icon::before {
  content: ''; position: absolute; inset: -1px; border-radius: inherit;
  background: linear-gradient(135deg, rgba(139, 92, 246, 0.35), rgba(0, 212, 255, 0.35));
  opacity: 0; transition: opacity 0.3s var(--ease); z-index: -1;
}
.keygen-export-icon:hover:not(:disabled) {
  border-color: #b46cff;
  color: #fff;
  transform: translateY(-1px);
  box-shadow: 0 0 14px rgba(139, 92, 246, 0.35), 0 0 4px rgba(0, 212, 255, 0.2);
}
.keygen-export-icon:hover:not(:disabled)::before { opacity: 1; }
.keygen-export-icon:active:not(:disabled) { transform: translateY(0); }
.keygen-export-icon:disabled { opacity: 0.3; cursor: not-allowed; }
.keygen-export-icon svg { width: 13px; height: 13px; transition: transform 0.3s var(--ease); }
.keygen-export-icon:hover:not(:disabled) svg { transform: translateY(1px); }
.keygen-hint { font-size: 10px; color: var(--text-muted); font-family: var(--font); text-align: center; }

/* 复制提示过渡（复用全局 .clip-toast） */
.toast-enter-active, .toast-leave-active { transition: all 0.3s var(--ease); }
.toast-enter-from, .toast-leave-to { opacity: 0; transform: translate(-50%, 10px); }
</style>
