<!--
  SecurityDashboard.vue — 安全防护 · 双星系统分区（无底板）
  设计：引力谱系 · sf-zone--binary —— 谱系坐标头（BINARY SYSTEM / 03）+
  面板五组件全部重塑（零卡片底板/边框/阴影，直接悬浮于宇宙背景）：
    1. bs-field   双星引力场：开销星（扫掠弧=CPU/IO）↔ 质心（综合评分+齿轮）
                  ↔ 覆盖星（扫掠弧=安全覆盖），氛围弧差速旋转
    2. bs-track   引力测线：非均匀测绘残段刻度（暗层休眠/潮汐亮层连续
                  点亮=能量进程）+ 端桩（左高右低非对称）+ 基准桩锚点
                  （错落桩高）+ 游标天平（速度感应摆锤，欠阻尼弹簧）
    3. bs-spectra 特性谱线：折叠面板内每特性一条光谱线（亮谱=启用），
                  grid 行高过渡无重排
    4. cap-board  安全能力状态栏：双列错位端子排清单（圆点状态位 +
                  功能名称 + 【核心】标签 + 虚线引出线，错相呼吸）
    5. def-board  防御闭环：七攻击路径端子排诊断（四态语义色
                  圆点 + 状态标签 + 虚线引出线）+ 总体态势行
    6. flow-rail  数据流转轨道：磁盘→内存电路走线（横段 + 斜向抬升
                  非对称高差，站点环 + 双层非均匀 dash 数据包差速流动），
                  轨道下方运行状态行随模式切换语义与流速

  职责：
    1. 双星引力场（左星 CPU/IO + 质心综合评分 + 右星 安全覆盖 + 齿轮入口）
    2. 引力测线滑块（三基准桩磁性吸附 + 潮汐亮层 + 游标天平）
    3. 特性谱线自定义面板（toggleableFeatures + 恢复默认/保存并应用）
    4. 安全能力状态栏（lockedFeatures 清单：圆点 + 名称 + 【核心】）
    5. 防御闭环状态（defensePaths：7 攻击路径 × 4 态 + defenseMeta 态势）
    6. 数据流转轨道（磁盘→内存走线 + 站点 + 运行状态文字）

  Props: globalKeyReady / securityPresetCode / presetApplying / presetAmbienceMode /
         cpuOverhead / securityCoverage / overallScore / ringCircumference /
         ringDashOffset(fn) / orbitAnchors / nearestAnchorIdx / activeAnchorIdx /
         orbitTrackGradient / toggleableFeatures / lockedFeatures / customFeatures /
         customPanelOpen / defensePaths / defenseMeta
  Model: orbitSliderPos
  Emits: toggleGearPanel / toggleCustomFeature(key) / resetCustom / applyCustom /
         orbitSliderInput / orbitSliderRelease / snapToAnchor(idx)

  拖拽性能架构（极其平滑 · 根治"一段一段"跳变）：
    - 连续浮点 pointer 驱动：抛弃 range 整数步进，pointermove 按测线
      宽度计算连续浮点位置；拖拽期间 DOM 直写 CSS 变量（零 Vue patch）
    - 合成器驱动：游标 translateX(cqw) + 亮层 clip-path，全程零 layout
    - 游标摆锤：拖拽速度注入欠阻尼弹簧（复合衰减曲线），倾侧随运摆、
      静止自然回正；仅写 --tilt 单变量
    - 拖拽态禁用主视觉过渡（视觉逐帧直跟指针），松手恢复 → 过冲贝塞尔
      落位（挡位落榫感）
    - 零阴影零光晕：测绘残段 + 端桩 + 基准桩 + 游标天平纯几何语言
-->
<template>
  <div class="sf-zone sf-zone--binary preset-dashboard" :class="`ambience-${presetAmbienceMode}`">
    <!-- 谱系坐标头（无底板） -->
    <header class="sf-head">
      <span class="sf-ghost" aria-hidden="true">03</span>
      <span class="sf-coord">Binary System</span>
      <h2 class="sf-title">安全防护</h2>
      <p class="sf-digest">性能 ↔ 安全 权衡 · 拖拽滑块即时切换</p>
    </header>

    <div class="security-dashboard" :class="{ 'is-dragging': dragging }">
      <!-- 环境氛围层（随模式切换的色彩倾向，无卡片形态） -->
      <div class="ambience-glow"></div>

      <!-- ===== 1. 双星引力场 ===== -->
      <div class="bs-field">
        <!-- 左星：CPU/IO 开销 -->
        <div class="bs-star bs-star-left">
          <svg viewBox="0 0 140 140" class="bs-star-svg" aria-hidden="true">
            <defs>
              <linearGradient id="bs-grad-left" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="rgba(0,255,200,0.9)"/>
                <stop offset="100%" stop-color="rgba(0,212,255,0.5)"/>
              </linearGradient>
            </defs>
            <!-- 氛围弧 A（顺时针慢旋） -->
            <g class="bs-ambient bs-ambient-a">
              <path fill="none" stroke="rgba(0,255,200,0.26)" stroke-width="1.2" stroke-linecap="round"
                d="M 30 96 A 42 42 0 0 1 60 31" />
            </g>
            <!-- 氛围弧 B（逆时针差速） -->
            <g class="bs-ambient bs-ambient-b">
              <path fill="none" stroke="rgba(0,212,255,0.18)" stroke-width="0.9" stroke-linecap="round"
                d="M 98 106 A 28 28 0 0 0 118 76" />
            </g>
            <!-- 能量扫掠弧（弧长 = 开销值，dasharray/dashoffset 由 props 驱动） -->
            <circle class="bs-sweep bs-sweep-left" cx="70" cy="70" r="52"
              :stroke-dasharray="ringCircumference"
              :stroke-dashoffset="ringDashOffset(cpuOverhead)"
            />
            <!-- 弧端能量点 -->
            <circle class="bs-sweep-dot bs-dot-left" cx="70" cy="18" r="2.6"
              :style="{ transform: `rotate(${cpuOverhead * 3.6}deg)`, transformOrigin: '70px 70px' }"
            />
          </svg>
          <div class="bs-star-info">
            <div class="bs-star-value">{{ cpuOverhead }}<span class="bs-star-unit">%</span></div>
            <div class="bs-star-label">CPU / IO 开销</div>
          </div>
        </div>

        <!-- 质心：综合评分 + 齿轮入口 -->
        <div class="bs-barycenter">
          <span class="bs-bc-filament" aria-hidden="true"></span>
          <div class="bs-bc-node">
            <span class="bs-bc-value">{{ overallScore }}<span class="bs-bc-unit">%</span></span>
            <span class="bs-bc-label">综合</span>
          </div>
          <button
            class="bs-gear"
            :class="{ active: securityPresetCode === 3, open: customPanelOpen }"
            :disabled="!globalKeyReady"
            @click="$emit('toggleGearPanel')"
            v-tip="'自定义防护模板'"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="bs-gear-icon">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
          </button>
        </div>

        <!-- 右星：安全覆盖 -->
        <div class="bs-star bs-star-right">
          <svg viewBox="0 0 140 140" class="bs-star-svg" aria-hidden="true">
            <defs>
              <linearGradient id="bs-grad-right" x1="100%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stop-color="rgba(139,92,246,0.85)"/>
                <stop offset="100%" stop-color="rgba(255,110,180,0.5)"/>
              </linearGradient>
            </defs>
            <!-- 氛围弧 A（逆时针差速） -->
            <g class="bs-ambient bs-ambient-a">
              <path fill="none" stroke="rgba(139,92,246,0.26)" stroke-width="1.2" stroke-linecap="round"
                d="M 110 96 A 42 42 0 0 0 80 31" />
            </g>
            <!-- 氛围弧 B（顺时针慢旋） -->
            <g class="bs-ambient bs-ambient-b">
              <path fill="none" stroke="rgba(255,110,180,0.18)" stroke-width="0.9" stroke-linecap="round"
                d="M 42 106 A 28 28 0 0 1 22 76" />
            </g>
            <!-- 能量扫掠弧 -->
            <circle class="bs-sweep bs-sweep-right" cx="70" cy="70" r="52"
              :stroke-dasharray="ringCircumference"
              :stroke-dashoffset="ringDashOffset(securityCoverage)"
            />
            <!-- 弧端能量点 -->
            <circle class="bs-sweep-dot bs-dot-right" cx="70" cy="18" r="2.6"
              :style="{ transform: `rotate(${securityCoverage * 3.6}deg)`, transformOrigin: '70px 70px' }"
            />
          </svg>
          <div class="bs-star-info">
            <div class="bs-star-value">{{ securityCoverage }}<span class="bs-star-unit">%</span></div>
            <div class="bs-star-label">安全覆盖</div>
          </div>
        </div>
      </div>

      <!-- ===== 2. 引力测线（非均匀测绘残段 + 游标天平） ===== -->
      <div class="bs-track-zone">
        <!-- 连续浮点 pointer 驱动：--pos(0-100) / --posw(%) DOM 直写
             （绕过整数步进与 Vue patch，逐帧直跟指针）；
             刻度以 SVG 授权坐标绘制，亮层 clip 随 --posw 连续点亮 -->
        <div
          ref="trackEl"
          class="bs-track"
          @pointerdown="onTrackPointerDown"
          @pointermove="onTrackPointerMove"
          @pointerup="onTrackPointerUp"
          @pointercancel="onTrackPointerUp"
        >
          <!-- 测绘残段 · 暗层（休眠刻度，确定性非均匀分布） -->
          <svg class="bs-survey" viewBox="0 0 1000 76" preserveAspectRatio="none" aria-hidden="true">
            <line
              v-for="(t, i) in surveyTicks"
              :key="i"
              :x1="t.x" :x2="t.x" y1="48"
              :y2="t.dir ? 48 + t.h * 0.7 : 48 - t.h"
              stroke="rgba(148, 160, 178, 1)"
              :opacity="t.o"
              stroke-width="1"
              vector-effect="non-scaling-stroke"
            />
          </svg>
          <!-- 测绘残段 · 潮汐亮层（clip 随滑块位置连续点亮 = 能量进程） -->
          <svg class="bs-survey bs-survey--lit" viewBox="0 0 1000 76" preserveAspectRatio="none" aria-hidden="true">
            <line
              v-for="(t, i) in surveyTicks"
              :key="i"
              :x1="t.x" :x2="t.x" y1="48"
              :y2="t.dir ? 48 + t.h * 0.7 : 48 - t.h"
              stroke="currentColor"
              :opacity="t.ol"
              stroke-width="1"
              vector-effect="non-scaling-stroke"
            />
          </svg>
          <!-- 端桩（左高右低非对称测绘终端） -->
          <span class="bs-post bs-post--origin" aria-hidden="true"></span>
          <span class="bs-post bs-post--term" aria-hidden="true"></span>

          <!-- 基准桩锚点（三档磁性吸附，错落桩高）
               纯视觉元素：不挂 pointer 事件 — 按下/点击统一由测线宿主
               处理（保证在锚点上可直接按下拖拽，点击吸附由释放位移判定） -->
          <div
            v-for="(anchor, i) in orbitAnchors"
            :key="i"
            class="bs-anchor"
            :class="[`bs-anchor-${i}`, { near: nearestAnchorIdx === i, current: activeAnchorIdx === i }]"
            :style="{ left: anchor.pos + '%' }"
          >
            <span class="bs-anchor-stela"></span>
            <span class="bs-anchor-text">{{ anchor.label }}</span>
          </div>

          <!-- 游标天平（速度感应摆锤：倾角 --tilt 由弹簧积分驱动） -->
          <div class="bs-caliper" aria-hidden="true">
            <span class="bs-caliper-line"></span>
            <span class="bs-caliper-bar"></span>
            <span class="bs-caliper-weight"></span>
          </div>
        </div>
        <!-- 原生 range 仅键盘可达（pointer-events:none，鼠标拖拽由测线接管） -->
        <input
          type="range"
          min="0"
          max="100"
          step="1"
          :value="orbitSliderPos"
          class="bs-range-input"
          :disabled="!globalKeyReady || presetApplying"
          @input="onKeyInput"
          @change="onKeyRelease"
        />
      </div>

      <!-- ===== 3. 特性谱线（自定义模板折叠层，grid 行高过渡无重排） ===== -->
      <div class="bs-spectra" :class="{ open: customPanelOpen }">
        <div class="bs-spectra-panel">
          <div class="bs-spectra-head">
            <span class="bs-spectra-title">自定义模板</span>
            <span class="bs-spectra-hint">点击谱线切换状态 · 亮谱=启用 · 暗谱=禁用</span>
          </div>
          <div class="bs-spectra-grid">
            <button
              v-for="feat in toggleableFeatures"
              :key="feat.key"
              class="bs-spectral"
              :class="{ on: customFeatures[feat.key], off: !customFeatures[feat.key] }"
              v-tip="feat.desc"
              @click="$emit('toggleCustomFeature', feat.key)"
            >
              <span class="bs-spec-line" aria-hidden="true"></span>
              <span class="bs-spec-label">{{ feat.label }}</span>
              <span class="bs-spec-state">{{ customFeatures[feat.key] ? 'ON' : 'OFF' }}</span>
            </button>
          </div>
          <div class="bs-spectra-actions">
            <button class="sf-terminal" @click="$emit('resetCustom')">恢复默认</button>
            <button
              class="sf-terminal"
              :disabled="presetApplying || !globalKeyReady"
              @click="$emit('applyCustom')"
            >
              {{ presetApplying ? '应用中…' : '保存并应用' }}
            </button>
          </div>
        </div>
      </div>

      <!-- ===== 4. 安全能力状态栏（核心防护清单 · 双列错位端子排） ===== -->
      <div class="cap-board">
        <div class="cap-head">
          <span class="cap-glyph" aria-hidden="true"></span>
          <span class="cap-title">安全能力状态</span>
          <span class="cap-sub">CORE ACTIVE</span>
          <span class="cap-count">{{ lockedFeatures.length }}/{{ lockedFeatures.length }}</span>
        </div>
        <ul class="cap-ledger">
          <li
            v-for="(feat, i) in lockedFeatures"
            :key="feat.key"
            class="cap-item"
            :class="`cap-item-${i}`"
            v-tip="feat.desc"
          >
            <span class="cap-dot" aria-hidden="true"></span>
            <span class="cap-name">{{ feat.label }}</span>
            <span class="cap-tag">【核心】</span>
            <span class="cap-lead" aria-hidden="true"></span>
          </li>
        </ul>
      </div>

      <!-- ===== 5. 防御闭环（7 攻击路径实时阻断状态 · 端子排诊断） ===== -->
      <div class="def-board">
        <div class="def-head">
          <span class="def-glyph" aria-hidden="true"></span>
          <span class="def-title">防御闭环</span>
          <span class="def-sub">WP-11 · RUNTIME</span>
          <span class="def-count" :class="`def-count--${defenseMeta.stance}`">
            {{ defenseMeta.blocked }}/{{ defensePaths.length }}
          </span>
        </div>
        <ul class="def-ledger">
          <li
            v-for="p in defensePaths"
            :key="p.key"
            class="def-item"
            :class="`def-item--${p.stateClass}`"
            v-tip="p.desc"
          >
            <span class="def-dot" aria-hidden="true"></span>
            <span class="def-name">{{ p.label }}</span>
            <span class="def-tag">{{ p.stateLabel }}</span>
            <span class="def-lead" aria-hidden="true"></span>
          </li>
        </ul>
        <!-- 总体态势行（失败 > 降级 > 全阻断 / 待检测） -->
        <div class="def-stance" :class="`def-stance--${defenseMeta.stance}`">
          <span class="def-stance-mark" aria-hidden="true"></span>
          <span class="def-stance-text">{{ defenseMeta.stanceLabel }}</span>
          <span class="def-stance-detail">
            阻断 {{ defenseMeta.blocked }} · 降级 {{ defenseMeta.degraded }} · 失败 {{ defenseMeta.failed }}
          </span>
        </div>
      </div>

      <!-- ===== 6. 数据流转轨道（磁盘 → 内存 · 电路走线 + 站点 + 数据包流） ===== -->
      <div class="flow-rail" :class="`flow--${presetAmbienceMode}`">
        <div class="flow-stage">
          <svg class="flow-svg" viewBox="0 0 1000 90" preserveAspectRatio="none" aria-hidden="true">
            <!-- 主走线（横段 + 斜向抬升，高差非对称） -->
            <path class="flow-wire" :d="flowWireD" />
            <!-- 数据包流：双层非均匀 dash 差速流动（近层 accent / 远层灰弱） -->
            <path class="flow-packets" :d="flowWireD" />
            <path class="flow-packets flow-packets--far" :d="flowWireD" />
            <!-- 站点节点（端点双环 + 中继细环，走线穿环而过） -->
            <circle
              v-for="s in flowStations"
              :key="s.label"
              class="flow-node"
              :class="{ 'flow-node--end': s.kind === 'end' }"
              :cx="s.x"
              :cy="s.y"
              :r="s.kind === 'end' ? 4.5 : 3"
            />
            <circle
              v-for="s in flowStations"
              :key="s.label + '-core'"
              class="flow-node-core"
              :class="{ 'flow-node-core--end': s.kind === 'end' }"
              :cx="s.x"
              :cy="s.y"
              r="1.8"
            />
          </svg>
          <!-- 站点标签（HTML 层：跟随节点高差错落，避免 SVG 拉伸变形） -->
          <span
            v-for="s in flowStations"
            :key="s.label"
            class="flow-label"
            :class="{ 'flow-label--end': s.kind === 'end' }"
            :style="{ left: s.x / 10 + '%', top: s.y + 14 + 'px' }"
          >{{ s.label }}</span>
        </div>
        <!-- 运行状态文字（随模式切换语义） -->
        <div class="flow-status">
          <span class="flow-status-mark" aria-hidden="true"></span>
          <span class="flow-status-text">{{ flowStatusText }}</span>
        </div>
      </div>

    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import type { DefensePathView, DefenseMetaView } from "../../composables/security-center/useDefenseStatus";

/**
 * SecurityDashboard Props
 */
const props = defineProps<{
  /** 全局密钥就绪状态（控制齿轮按钮 + 滑块 + 应用按钮 disabled） */
  globalKeyReady: boolean;
  /** 安全预设代码（securityPresetRef，0=平衡/1=安全/2=性能/3=自定义） */
  securityPresetCode: number;
  /** 预设应用中状态 */
  presetApplying: boolean;
  /** 预设环境光效模式 */
  presetAmbienceMode: string;
  /** CPU/IO 开销百分比（左星扫掠弧） */
  cpuOverhead: number;
  /** 安全覆盖度百分比（右星扫掠弧） */
  securityCoverage: number;
  /** 综合评分（质心节点） */
  overallScore: number;
  /** 双星周长（stroke-dasharray） */
  ringCircumference: number;
  /** 双星 dashOffset 计算函数 */
  ringDashOffset: (val: number) => number;
  /** 轨道锚点列表（三档磁性吸附点） */
  orbitAnchors: Array<{ pos: number; label: string; code: number }>;
  /** 最近锚点索引（视觉吸附高亮） */
  nearestAnchorIdx: number;
  /** 当前激活锚点索引 */
  activeAnchorIdx: number;
  /** 轨道渐变样式（谱轨底色层能量倾向） */
  orbitTrackGradient: Record<string, string>;
  /** 可切换特性列表（谱线面板，可点击切换） */
  toggleableFeatures: Array<{ key: string; label: string; desc: string }>;
  /** 锁定特性列表（星冕核心防护，不可切换） */
  lockedFeatures: Array<{ key: string; label: string; desc: string }>;
  /** 自定义特性配置（谱线开关状态） */
  customFeatures: Record<string, boolean>;
  /** 自定义面板展开状态 */
  customPanelOpen: boolean;
  /** 防御闭环路径状态列表（7 攻击路径 × 4 态端子排） */
  defensePaths: DefensePathView[];
  /** 防御闭环汇总态势（计数 + 全阻断标志 + 总体态势行） */
  defenseMeta: DefenseMetaView;
}>();

/**
 * SecurityDashboard Model
 * 无极轨道滑块位置双向绑定（松手吸附/锚点点击时由父层写回）
 */
const orbitSliderPos = defineModel<number>("orbitSliderPos", { default: 50 });

/**
 * SecurityDashboard Emits
 */
const emit = defineEmits<{
  /** 切换齿轮（自定义）面板展开状态 */
  (e: "toggleGearPanel"): void;
  /** 切换单个自定义特性 */
  (e: "toggleCustomFeature", key: string): void;
  /** 恢复自定义默认 */
  (e: "resetCustom"): void;
  /** 保存并应用自定义配置 */
  (e: "applyCustom"): void;
  /** 轨道滑块输入中 */
  (e: "orbitSliderInput"): void;
  /** 轨道滑块释放（磁性吸附触发） */
  (e: "orbitSliderRelease"): void;
  /** 吸附到指定锚点 */
  (e: "snapToAnchor", idx: number): void;
}>();

/* ============================================================
   引力测线架构（极其平滑 · 反模板化设计）
   1. 连续浮点 pointer 驱动：抛弃原生 range 整数步进（step=1 导致
      1% 跳变），pointermove 按测线宽度计算连续浮点位置
   2. DOM 直写：拖拽期间 --pos/--posw 直接写测线元素 style，
      完全绕过 Vue 响应式 —— 游标与潮汐亮层逐帧直跟指针，零组件
      patch；测线元素不绑定 Vue style，重渲染永不覆盖直写值
   3. 游标天平摆锤物理：拖拽速度注入欠阻尼弹簧（刚度/阻尼双系数
      积分 → 复合衰减曲线，非标准缓动），游标随运摆倾侧、静止后
      自然回正；仅写 --tilt 单变量，合成器 rotate
   4. 节流联动：拖拽期间 120ms 节流写 model，联动双星数值/环境
      渐变/邻近锚点高亮（低频 patch，视觉无感）
   5. pointer capture：指针移出测线/窗口仍持续跟踪；触屏不受滚动
      打断（touch-action: none）
   6. 非拖拽路径（松手吸附/锚点点击/键盘/预设同步）统一由
      watch(model) 驱动 DOM 写入；拖拽态关闭主视觉过渡（单帧
      直跟），松手恢复 → 吸附以带过冲的复合贝塞尔缓动落位
   ============================================================ */
/** 拖拽中标志（驱动 .is-dragging 状态类） */
const dragging = ref(false);
/** 测线元素引用（pointer capture 目标 + DOM 直写宿主） */
const trackEl = ref<HTMLElement | null>(null);
/** 指针最新连续位置（浮点 0-100，松手写回 model） */
let latestPos = orbitSliderPos.value;
/** 上次节流写 model 的时间戳 */
let lastModelSync = 0;
/** 按下时的位置（0-100）与测线像素宽度（点击/拖拽判定） */
let downPos = 0;
let downWidth = 1;
/** 按下时命中的锚点索引（-1 = 空白处；点击吸附判定用） */
let downHitIdx = -1;

/** 测绘残段刻度 — 确定性非均匀分布（间距/高度/明度按错位乘法序列起伏，
 * 无重复周期、无均匀间距；1/3 刻度下垂如地震仪残迹） */
const surveyTicks = (() => {
  const arr: { x: number; h: number; dir: boolean; o: number; ol: number }[] = [];
  let x = 6;
  for (let i = 0; x < 990; i++) {
    arr.push({
      x: Math.round(x),
      h: 7 + ((i * 53 + 7) % 11),
      dir: (i * 7 + 3) % 3 === 0,
      o: 0.28 + ((i * 29 + 5) % 10) * 0.03,
      ol: 0.55 + ((i * 41 + 13) % 10) * 0.045,
    });
    x += 15 + ((i * 37 + 11) % 29);
  }
  return arr;
})();

/** 位置写入测线 DOM：--pos(0-100) 供游标 cqw 位移，--posw(%) 供亮层 clip */
const writePosToDom = (pos: number) => {
  const el = trackEl.value;
  if (!el) return;
  el.style.setProperty("--pos", pos.toFixed(3));
  el.style.setProperty("--posw", `${pos.toFixed(2)}%`);
};

/* 非拖拽路径统一驱动：model 变化（松手吸附/锚点点击/键盘/预设同步）
 * → 写入 DOM；拖拽期间跳过（直写优先，避免节流值回跳覆盖最新指针位置） */
watch(
  orbitSliderPos,
  (pos) => {
    if (!dragging.value) writePosToDom(pos);
  },
  { immediate: true },
);

/* ===== 游标天平摆锤（欠阻尼弹簧积分） ===== */
/** 当前倾角（度，写入 --tilt） */
let tilt = 0;
/** 角速度 */
let tiltVel = 0;
/** 弹簧积分 rAF 句柄 */
let tiltRaf = 0;
/** 上一事件指针横坐标（速度采样） */
let prevX = 0;

const writeTilt = () => {
  trackEl.value?.style.setProperty("--tilt", `${tilt.toFixed(3)}deg`);
};

/** 弹簧积分循环：刚度 0.16 / 阻尼 0.11（欠阻尼 → 摆锤式回正震荡衰减） */
const tiltLoop = () => {
  tiltVel += -tilt * 0.16 - tiltVel * 0.11;
  tilt = Math.max(-6, Math.min(6, tilt + tiltVel));
  writeTilt();
  if (dragging.value || Math.abs(tilt) > 0.02 || Math.abs(tiltVel) > 0.02) {
    tiltRaf = requestAnimationFrame(tiltLoop);
  } else {
    tilt = 0;
    tiltVel = 0;
    writeTilt();
    tiltRaf = 0;
  }
};

/** 速度冲量注入（拖拽位移 → 摆锤角速度） */
const kickTilt = (dx: number) => {
  tiltVel += Math.max(-1.6, Math.min(1.6, dx * 0.09));
  if (!tiltRaf) tiltRaf = requestAnimationFrame(tiltLoop);
};

/** 由指针横坐标计算连续位置：DOM 直写主视觉 + 摆锤冲量 + 节流联动 model */
const updateFromPointer = (clientX: number) => {
  const el = trackEl.value;
  if (!el) return;
  const rect = el.getBoundingClientRect();
  const ratio = Math.min(1, Math.max(0, (clientX - rect.left) / rect.width));
  latestPos = ratio * 100;
  writePosToDom(latestPos);
  kickTilt(clientX - prevX);
  prevX = clientX;
  // 节流写 model：联动双星数值/环境渐变/邻近锚点（120ms，视觉无感）
  const now = performance.now();
  if (now - lastModelSync > 120) {
    lastModelSync = now;
    orbitSliderPos.value = Math.round(latestPos * 10) / 10;
  }
};

/** 测线按下 — 捕获指针 + 开始拖拽（含锚点命中记录）
 * 锚点元素为纯视觉（无 pointer 事件），在锚点上按下同样直接进入拖拽；
 * 同时记录按下位置与命中锚点，供释放时判定"点击吸附" vs "拖拽吸附" */
const onTrackPointerDown = (e: PointerEvent) => {
  if (!props.globalKeyReady || props.presetApplying) return;
  if (e.button !== undefined && e.button !== 0) return;
  trackEl.value?.setPointerCapture(e.pointerId);
  dragging.value = true;
  prevX = e.clientX;
  const el = trackEl.value;
  if (el) {
    const rect = el.getBoundingClientRect();
    downWidth = rect.width || 1;
    downPos = Math.min(1, Math.max(0, (e.clientX - rect.left) / downWidth)) * 100;
    // 命中判定：按下点距某锚点 < 13px（锚点热区，含桩体与标签）
    downHitIdx = props.orbitAnchors.findIndex(
      (a) => (Math.abs(downPos - a.pos) / 100) * downWidth < 13,
    );
  }
  updateFromPointer(e.clientX);
  emit("orbitSliderInput");
};

/** 测线拖拽中 — 连续浮点位置 DOM 直写 */
const onTrackPointerMove = (e: PointerEvent) => {
  if (!dragging.value) return;
  updateFromPointer(e.clientX);
};

/** 测线释放 — 点击吸附 / 拖拽磁性吸附（pointerup/pointercancel 幂等）
 * 位移 < 4px 且按下时命中锚点 → 点击吸附该锚点（snapToAnchor）；
 * 否则按指针最终位置走磁性吸附（orbitSliderRelease） */
const onTrackPointerUp = () => {
  if (!dragging.value) return;
  dragging.value = false;
  const movedPx = (Math.abs(latestPos - downPos) / 100) * downWidth;
  if (movedPx < 4 && downHitIdx >= 0) {
    emit("snapToAnchor", downHitIdx);
    return;
  }
  orbitSliderPos.value = Math.round(latestPos * 10) / 10;
  emit("orbitSliderRelease");
};

/** 键盘输入（原生 range 仅键盘可达，低频路径走 Vue model） */
const onKeyInput = (e: Event) => {
  orbitSliderPos.value = Number((e.target as HTMLInputElement).value);
  emit("orbitSliderInput");
};
/** 键盘提交 — 磁性吸附 */
const onKeyRelease = () => {
  emit("orbitSliderRelease");
};

/* ============================================================
   数据流转轨道 — 站点与走线（磁盘 → 内存）
   电路走线语言：横段 + 斜向抬升，高差非对称（28/60/36/56）；
   站点 x 坐标非均匀间距；标签为 HTML 层随节点高差错落
   ============================================================ */
const flowStations = [
  { x: 30, y: 48, label: "磁盘", kind: "end" },
  { x: 230, y: 28, label: "读取", kind: "mid" },
  { x: 420, y: 60, label: "解密", kind: "mid" },
  { x: 620, y: 36, label: "校验", kind: "mid" },
  { x: 820, y: 56, label: "装载", kind: "mid" },
  { x: 970, y: 48, label: "内存", kind: "end" },
] as const;
/** 走线路径（穿过全部站点节点） */
const flowWireD =
  "M 30 48 H 170 L 230 28 H 360 L 420 60 H 560 L 620 36 H 760 L 820 56 H 970";
/** 运行状态文字（随模式切换语义） */
const flowStatusText = computed(() => {
  switch (props.presetAmbienceMode) {
    case "performance":
      return "运行状态 · 直读装载 — 按需载入，绕过预热";
    case "secure":
      return "运行状态 · 加密通道 — 全量校验后装载";
    default:
      return "运行状态 · 预热流转中 — 温启动缓存与影子休眠协同";
  }
});

onBeforeUnmount(() => {
  if (tiltRaf) cancelAnimationFrame(tiltRaf);
});
</script>
