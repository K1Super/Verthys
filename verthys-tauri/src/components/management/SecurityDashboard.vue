<!--
  SecurityDashboard.vue — 安全防护 · 双星系统分区（无底板）
  设计：引力谱系 · sf-zone--binary —— 谱系坐标头（BINARY SYSTEM / 03）+
  面板五组件全部重塑（零卡片底板/边框/阴影，直接悬浮于宇宙背景）：
    1. bs-field   双星引力场：开销星（扫掠弧=CPU 占用）↔ 质心（综合评分）
                  ↔ 覆盖星（扫掠弧=安全覆盖），氛围弧差速旋转
    2. bs-track   引力测线：非均匀测绘残段刻度（暗层休眠/潮汐亮层连续
                  点亮=能量进程）+ 基准桩锚点（错落桩高，端点锚兼作
                  左高右低终点桩）+ 游标天平（速度感应摆锤，欠阻尼弹簧）
    3. cus-board  自定义防护：常驻分区（标题行 + 双列错位端子排 +
                  空闲锁定时长拖拽谱线），与安全防护/动态防护同构
    4. cap-board  安全防护栏：双列错位端子排清单（圆点状态位 +
                  功能名称 + 核心标签 + 虚线引出线）
    5. def-board  动态防护：七攻击路径端子排诊断（四态语义色
                  圆点 + 状态标签 + 虚线引出线）+ 总体态势行
    6. flow-rail  数据流转轨道：磁盘→内存电路走线（横段 + 斜向抬升
                  非对称高差，站点环 + 双层非均匀 dash 数据包差速流动），
                  轨道下方运行状态行随模式切换语义与流速

  职责：
    1. 双星引力场（左星 CPU 占用 + 质心综合评分 + 右星 安全覆盖）
    2. 引力测线滑块（三基准桩磁性吸附 + 潮汐亮层 + 游标天平）
    3. 自定义防护（toggleableFeatures 开关端子排 + 空闲锁定时长拖拽虚线 +
       toast 反馈 + 恢复默认/保存应用）
    4. 安全防护栏（lockedFeatures 清单：圆点 + 名称 + 核心）
    5. 动态防护状态（defensePaths：7 攻击路径 × 4 态 + defenseMeta 态势）
    6. 数据流转轨道（磁盘→内存走线 + 站点 + 运行状态文字）

  Props: globalKeyReady / presetApplying / presetAmbienceMode /
         cpuOverhead / securityCoverage / overallScore / ringCircumference /
         ringDashOffset(fn) / orbitAnchors / nearestAnchorIdx / activeAnchorIdx /
         orbitTrackGradient / toggleableFeatures / lockedFeatures / customFeatures /
         customSessionMinutes / defensePaths / defenseMeta
  Model: orbitSliderPos
  Emits: toggleCustomFeature / resetCustom / applyCustom /
         setCustomSessionMinutes / orbitSliderInput / orbitSliderRelease / snapToAnchor(idx)

  拖拽性能架构：
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
      <p v-if="digestWarn" class="sf-digest is-warn">{{ digestText }}</p>
    </header>

    <div class="security-dashboard" :class="{ 'is-dragging': dragging }">
      <!-- 环境氛围层（随模式切换的色彩倾向，无卡片形态） -->
      <div class="ambience-glow"></div>

      <!-- ===== 1. 双星引力场 ===== -->
      <div class="bs-field">
        <!-- 左星：CPU 占用 -->
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
            <div class="bs-star-label">CPU 占用</div>
          </div>
        </div>

        <!-- 质心：综合评分 -->
        <div class="bs-barycenter">
          <span class="bs-bc-filament" aria-hidden="true"></span>
          <div class="bs-bc-node">
            <span class="bs-bc-value">{{ overallScore }}<span class="bs-bc-unit">%</span></span>
            <span class="bs-bc-label">综合</span>
          </div>
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
        <!-- 连续浮点 pointer 驱动：--pos(0-100) 游标、--posw(%) 亮层 DOM 直写
             （绕过整数步进与 Vue patch，逐帧直跟指针）；
             刻度以 SVG 授权坐标绘制，亮层 clip 随 --posw 量化档位点亮 -->
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
          <!-- 基准桩锚点（三档磁性吸附，端点锚兼作左高右低终点桩）
               纯视觉元素：不挂 pointer 事件 — 按下/点击统一由测线宿主
               处理（保证在锚点上可直接按下拖拽，点击吸附由释放位移判定） -->
          <div
            v-for="(anchor, i) in orbitAnchors"
            :key="i"
            class="bs-anchor"
            :class="[`bs-anchor-${i}`, { near: dragging && nearestAnchorIdx === i, current: activeAnchorIdx === i }]"
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
          aria-label="安全强度轨道（性能 ↔ 平衡 ↔ 安全）"
          :aria-valuetext="rangeValueText"
          :disabled="!globalKeyReady || presetApplying"
          @input="onKeyInput"
          @change="onKeyRelease"
        />
      </div>

      <!-- ===== 3. 自定义防护（常驻分区：端子排开关 + 空闲锁定时长谱线）
           与安全防护 / 动态防护同构：标题行 + 双列错位端子排 + 虚线引出线；
           无底色 / 无边框 / 无浮层 / 无淡入淡出 — 直接悬浮于背景 ===== -->
      <div class="cus-board">
        <div class="cus-head">
          <span class="cap-glyph" aria-hidden="true"></span>
          <span class="cus-title">自定义防护</span>
          <div class="cus-actions">
            <button
              class="sf-terminal"
              :disabled="!globalKeyReady || presetApplying"
              @click="$emit('resetCustom')"
            >恢复默认</button>
            <button
              class="sf-terminal"
              :disabled="!globalKeyReady || presetApplying"
              @click="$emit('applyCustom')"
            >
              {{ presetApplying ? '应用中…' : '保存应用' }}
            </button>
          </div>
          <span class="cus-count">{{ customEnabledCount }}/{{ toggleableFeatures.length }}</span>
        </div>
        <ul class="cus-ledger">
          <li
            v-for="(feat, i) in toggleableFeatures"
            :key="feat.key"
            class="cus-item"
            :class="[
              `cus-item-${i}`,
              {
                off: !customFeatures[feat.key],
                'cus-item--idle': feat.key === 'session_lock_on_idle',
              },
            ]"
          >
            <!-- 空闲锁定行：启用/关闭后的虚线即拖动区
                 底轨为默认灰色虚线（与其余四行一致）；启用时叠加彩色
                 进度层（长度=当前时长），仅启用时可拖动；时长经 toast 反馈 -->
            <template v-if="feat.key === 'session_lock_on_idle'">
              <button
                class="cus-toggle"
                :disabled="!globalKeyReady || presetApplying"
                :aria-pressed="!!customFeatures[feat.key]"
                v-tip="feat.desc"
                @click="$emit('toggleCustomFeature', feat.key)"
              >
                <span class="cus-dot" aria-hidden="true"></span>
                <span class="cus-name">{{ feat.label }}</span>
                <span class="cus-tag">{{ customFeatures[feat.key] ? '启用' : '关闭' }}</span>
              </button>
              <div
                :ref="bindTimeoutTrack"
                class="cus-idle-track"
                :class="{ enabled: customFeatures[feat.key] }"
                role="slider"
                :tabindex="customFeatures[feat.key] ? 0 : -1"
                :aria-disabled="!customFeatures[feat.key]"
                :aria-label="'空闲锁定时长（分钟）'"
                :aria-valuemin="CUSTOM_SESSION_MINUTES_MIN"
                :aria-valuemax="CUSTOM_SESSION_MINUTES_MAX"
                @pointerdown="onTimeoutPointerDown"
                @pointermove="onTimeoutPointerMove"
                @pointerup="onTimeoutPointerUp"
                @pointercancel="onTimeoutPointerUp"
                @keydown="onTimeoutKeydown"
              >
                <span class="cus-idle-rail" aria-hidden="true"></span>
                <span :ref="bindTimeoutLit" class="cus-idle-lit" aria-hidden="true"></span>
              </div>
            </template>
            <button
              v-else
              class="cus-toggle"
              :disabled="!globalKeyReady || presetApplying"
              :aria-pressed="!!customFeatures[feat.key]"
              v-tip="feat.desc"
              @click="$emit('toggleCustomFeature', feat.key)"
            >
              <span class="cus-dot" aria-hidden="true"></span>
              <span class="cus-name">{{ feat.label }}</span>
              <span class="cus-tag">{{ customFeatures[feat.key] ? '启用' : '关闭' }}</span>
              <span class="cus-lead" aria-hidden="true"></span>
            </button>
          </li>
        </ul>
      </div>

      <!-- ===== 4. 安全防护栏（核心防护清单 · 双列错位端子排）
           圆点状态位由后端权威配置快照驱动：当前档位实际启用的能力
           亮起，缺失降档的能力呈灰态 —— 不做恒等伪装计数 ===== -->
      <div class="cap-board">
        <div class="cap-head">
          <span class="cap-glyph" aria-hidden="true"></span>
          <span class="cap-title">安全防护</span>
          <span class="cap-count">{{ capActiveCount }}/{{ lockedFeatures.length }}</span>
        </div>
        <ul class="cap-ledger">
          <li
            v-for="(feat, i) in lockedFeatures"
            :key="feat.key"
            class="cap-item"
            :class="[`cap-item-${i}`, { off: capFeatState(feat.key) === 'off', unknown: capFeatState(feat.key) === 'unknown' }]"
            v-tip="feat.desc"
          >
            <span class="cap-dot" aria-hidden="true"></span>
            <span class="cap-name">{{ feat.label }}</span>
            <span class="cap-tag">核心</span>
            <span class="cap-lead" aria-hidden="true"></span>
          </li>
        </ul>
      </div>

      <!-- ===== 5. 动态防护（7 攻击路径实时阻断状态 · 端子排诊断） ===== -->
      <div class="def-board">
        <div class="def-head">
          <span class="cap-glyph" aria-hidden="true"></span>
          <span class="def-title">动态防护</span>
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
        <!-- 总体态势行（全阻断时隐藏；仅异常/未阻断/陈旧时显示） -->
        <div
          v-if="defenseMeta.stance !== 'ok' || defenseMeta.stale"
          class="def-stance"
          :class="`def-stance--${defenseMeta.stance}`"
        >
          <span class="def-stance-mark" aria-hidden="true"></span>
          <span class="def-stance-text">{{ defenseMeta.stanceLabel }}</span>
          <span class="def-stance-detail">
            阻断 {{ defenseMeta.blocked }} · 降级 {{ defenseMeta.degraded }} · 失败 {{ defenseMeta.failed }}{{ defenseMeta.stale ? ' · 数据陈旧' : '' }}
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
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import type { DefensePathView, DefenseMetaView } from "../../composables/security-center/useDefenseStatus";
import { masterFrameLoop } from "../../core/master-frame-loop";
import { useToastCenter } from "../../composables/useToastCenter";
import {
  CUSTOM_SESSION_MINUTES_MIN,
  CUSTOM_SESSION_MINUTES_MAX,
} from "../../constants/key_manager_const";

/**
 * SecurityDashboard Props
 */
const props = defineProps<{
  /** 全局密钥就绪状态（控制滑块与应用按钮 disabled） */
  globalKeyReady: boolean;
  /** 预设应用中状态 */
  presetApplying: boolean;
  /** 预设环境光效模式 */
  presetAmbienceMode: string;
  /** CPU 占用百分比（左星扫掠弧） */
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
  /** 已应用预设特性开关快照（后端权威配置 —— 能力状态栏真实状态源） */
  presetFeatures: Record<string, boolean>;
  /** 自定义特性配置（谱线开关状态） */
  customFeatures: Record<string, boolean>;
  /** 自定义档空闲锁定时长（分钟，仅自定义档生效） */
  customSessionMinutes: number;
  /** 动态防护路径状态列表（7 攻击路径 × 4 态端子排） */
  defensePaths: DefensePathView[];
  /** 动态防护汇总态势（计数 + 全阻断标志 + 总体态势行） */
  defenseMeta: DefenseMetaView;
  /** 档位同步失败标志（恢复链失败时展示警示文案） */
  presetSyncFailed: boolean;
  /** 会话硬化/会话守卫降级标志（部分安全能力未生效时如实提示） */
  hardeningFailed: boolean;
}>();

/** 降级 / 未同步警示：仅异常时出现（常规摘要文案已移除） */
const digestWarn = computed(() =>
  props.presetSyncFailed || props.hardeningFailed,
);
const digestText = computed(() => {
  if (props.presetSyncFailed) return "档位同步失败 · 当前显示可能与后端不一致";
  if (props.hardeningFailed) return "会话硬化未完全生效 · 剪贴板监听或系统锁屏守卫可能不可用";
  return "";
});

/** 轨道键盘可达语义值（读屏播报当前锚点档位而非裸数字） */
const rangeValueText = computed(() => {
  const idx = props.nearestAnchorIdx;
  const anchor = props.orbitAnchors[idx];
  return anchor ? `当前吸附方向：${anchor.label}（${Math.round(orbitSliderPos.value)}%）` : `${Math.round(orbitSliderPos.value)}%`;
});

/**
 * SecurityDashboard Model
 * 无极轨道滑块位置双向绑定（松手吸附/锚点点击时由父层写回）
 */
const orbitSliderPos = defineModel<number>("orbitSliderPos", { default: 50 });

/**
 * SecurityDashboard Emits
 */
const emit = defineEmits<{
  /** 切换单个自定义特性 */
  (e: "toggleCustomFeature", key: string): void;
  /** 恢复自定义默认 */
  (e: "resetCustom"): void;
  /** 保存应用自定义配置 */
  (e: "applyCustom"): void;
  /** 设置自定义档空闲锁定时长（分钟） */
  (e: "setCustomSessionMinutes", minutes: number): void;
  /** 轨道滑块输入中 */
  (e: "orbitSliderInput"): void;
  /** 轨道滑块释放（磁性吸附触发） */
  (e: "orbitSliderRelease"): void;
  /** 吸附到指定锚点 */
  (e: "snapToAnchor", idx: number): void;
}>();

/** 统一状态通道（拖动时长反馈） */
const { showStatus } = useToastCenter();

/* ============================================================
   自定义防护：开关计数 + 空闲锁定拖拽虚线
   空闲锁定行「启用/关闭」之后的虚线即为拖动区：底轨保持默认灰色虚线，
   启用时叠加彩色进度层（长度=当前时长，无游标），线性映射 1~120 分钟；
   时长通过统一 toast 反馈，关闭态不显示进度层且不可拖动。
   ============================================================ */

/** 当前启用特性数（标题行计数） */
const customEnabledCount = computed(
  () => props.toggleableFeatures.filter((f) => props.customFeatures[f.key]).length,
);

/** 时长轨道与彩色进度层（函数式 ref：元素位于 v-for 内，模板 ref 会被收集成数组） */
let timeoutTrackEl: HTMLElement | null = null;
let timeoutLitEl: HTMLElement | null = null;
const bindTimeoutTrack = (el: unknown) => {
  timeoutTrackEl = el instanceof HTMLElement ? el : null;
};
const bindTimeoutLit = (el: unknown) => {
  timeoutLitEl = el instanceof HTMLElement ? el : null;
};

/** 拖拽中标志与当前读数（非响应式：拖拽不触发组件重渲染） */
let timeoutDragging = false;
let dragMinutes = props.customSessionMinutes;
/** 按下时缓存的轨道几何（拖拽期零布局读取） */
let trackLeft = 0;
let trackWidth = 1;
/** 最近一次 toast 时间戳（拖动期节流，避免提示轰炸） */
let lastToastAt = 0;

/** 分钟 → 进度百分比（线性） */
const minutesToPercent = (minutes: number): number => {
  const clamped = Math.min(
    CUSTOM_SESSION_MINUTES_MAX,
    Math.max(CUSTOM_SESSION_MINUTES_MIN, minutes),
  );
  return (
    ((clamped - CUSTOM_SESSION_MINUTES_MIN) /
      (CUSTOM_SESSION_MINUTES_MAX - CUSTOM_SESSION_MINUTES_MIN)) *
    100
  );
};

/** 把进度写入彩色虚线长度与读屏属性
 *  DOM 直写而非模板绑定：组件其余状态（CPU 采样等）重渲染时不得覆盖
 *  拖拽中的进度值，与引力测线的写入架构保持一致。 */
const applyTimeoutVisual = (minutes: number) => {
  if (timeoutLitEl) {
    timeoutLitEl.style.width = `${minutesToPercent(minutes).toFixed(3)}%`;
  }
  if (timeoutTrackEl) {
    timeoutTrackEl.setAttribute("aria-valuenow", String(minutes));
    timeoutTrackEl.setAttribute("aria-valuetext", `${minutes} 分钟`);
  }
};

/* 挂载播种 + 父层草稿变化同步（拖拽期以拖拽读数为准，不被覆盖） */
onMounted(() => applyTimeoutVisual(props.customSessionMinutes));
watch(
  () => props.customSessionMinutes,
  (minutes) => {
    if (!timeoutDragging) applyTimeoutVisual(minutes);
  },
);

/** 分钟收敛到允许区间 */
const clampIdleMinutes = (minutes: number): number =>
  Math.min(
    CUSTOM_SESSION_MINUTES_MAX,
    Math.max(CUSTOM_SESSION_MINUTES_MIN, Math.round(minutes)),
  );

/** 通过统一状态通道反馈当前时长（拖动期节流，释放时强制刷新） */
const announceIdleMinutes = (minutes: number, force = false) => {
  const now = performance.now();
  if (!force && now - lastToastAt < 120) return;
  lastToastAt = now;
  showStatus(`空闲锁定 ${minutes} 分钟`, 1600);
};

/** 指针横坐标 → 分钟（按下时缓存的轨道左缘与宽度，线性映射） */
const minutesFromPointer = (clientX: number): number => {
  const ratio = Math.min(1, Math.max(0, (clientX - trackLeft) / trackWidth));
  return Math.round(
    CUSTOM_SESSION_MINUTES_MIN +
      ratio * (CUSTOM_SESSION_MINUTES_MAX - CUSTOM_SESSION_MINUTES_MIN),
  );
};

const onTimeoutPointerDown = (e: PointerEvent) => {
  if (!props.globalKeyReady || props.presetApplying) return;
  // 关闭态只展示默认虚线，不接受拖动
  if (!props.customFeatures.session_lock_on_idle) return;
  if (e.button !== undefined && e.button !== 0) return;
  const el = timeoutTrackEl;
  if (!el) return;
  el.setPointerCapture(e.pointerId);
  timeoutDragging = true;
  const rect = el.getBoundingClientRect();
  trackLeft = rect.left;
  trackWidth = rect.width || 1;
  dragMinutes = minutesFromPointer(e.clientX);
  applyTimeoutVisual(dragMinutes);
  announceIdleMinutes(dragMinutes, true);
};

const onTimeoutPointerMove = (e: PointerEvent) => {
  if (!timeoutDragging) return;
  const next = minutesFromPointer(e.clientX);
  if (next === dragMinutes) return;
  dragMinutes = next;
  applyTimeoutVisual(dragMinutes);
  announceIdleMinutes(next);
};

const onTimeoutPointerUp = (e: PointerEvent) => {
  if (!timeoutDragging) return;
  timeoutDragging = false;
  // 取消事件不携带有效坐标：提交最后一次拖拽读数
  if (e.type === "pointerup") {
    const next = minutesFromPointer(e.clientX);
    if (next !== dragMinutes) {
      dragMinutes = next;
      applyTimeoutVisual(next);
    }
  }
  emit("setCustomSessionMinutes", dragMinutes);
  announceIdleMinutes(dragMinutes, true);
};

/** 键盘调节：方向键 ±1 分钟，Shift ±10，PageUp/PageDown ±10，Home/End 直达端点 */
const onTimeoutKeydown = (e: KeyboardEvent) => {
  if (!props.globalKeyReady || props.presetApplying) return;
  if (!props.customFeatures.session_lock_on_idle) return;
  let next = props.customSessionMinutes;
  switch (e.key) {
    case "ArrowLeft":
    case "ArrowDown":
      next -= e.shiftKey ? 10 : 1;
      break;
    case "ArrowRight":
    case "ArrowUp":
      next += e.shiftKey ? 10 : 1;
      break;
    case "PageDown":
      next -= 10;
      break;
    case "PageUp":
      next += 10;
      break;
    case "Home":
      next = CUSTOM_SESSION_MINUTES_MIN;
      break;
    case "End":
      next = CUSTOM_SESSION_MINUTES_MAX;
      break;
    default:
      return;
  }
  e.preventDefault();
  const clamped = clampIdleMinutes(next);
  applyTimeoutVisual(clamped);
  emit("setCustomSessionMinutes", clamped);
  announceIdleMinutes(clamped, true);
};

/* ============================================================
   安全防护栏真实状态（后端权威配置快照驱动）
   核心能力在部分档位会按 C 层口径降档关闭（如性能档的反调试/
   完整性校验/内存保护），圆点如实灰态 —— 禁止恒等伪装计数
   ============================================================ */

/** 判定核心能力在当前档位的真实状态（三态）
 *  - on：后端权威快照明确为启用；
 *  - off：后端权威快照明确为关闭；
 *  - unknown：快照未加载 / 同步失败 / 缺失该键 —— 不得缺省点亮
 *    （旧实现 `!== false` 把缺失当启用，配置未加载时全绿属虚假声明）。 */
const capFeatState = (key: string): 'on' | 'off' | 'unknown' => {
  if (props.presetSyncFailed) return 'unknown';
  const v = props.presetFeatures[key];
  return v === true ? 'on' : v === false ? 'off' : 'unknown';
};
/** 当前档位真实启用的核心能力数（unknown 不计入） */
const capActiveCount = computed(() =>
  props.lockedFeatures.filter((f) => capFeatState(f.key) === 'on').length,
);

/* ============================================================
   引力测线架构
   1. 连续浮点 pointer 驱动：抛弃原生 range 整数步进（step=1 导致
      1% 跳变），pointermove 按测线宽度计算连续浮点位置
   2. DOM 直写：拖拽期间 --pos/--posw 直接写测线元素 style，
      完全绕过 Vue 响应式 —— 游标逐帧直跟指针，潮汐亮层按 2% 量化
      档位 + 30Hz 抽帧推进（收敛逐帧重栅格化），零组件
      patch；测线元素不绑定 Vue style，重渲染永不覆盖直写值
   3. 游标天平摆锤物理：拖拽速度注入欠阻尼弹簧（刚度/阻尼双系数
      积分 → 复合衰减曲线，非标准缓动），游标随运摆倾侧、静止后
      自然回正；仅写 --tilt 单变量，合成器 rotate
   4. 节流联动：拖拽期间 120ms 节流写 model，联动双星数值/环境
      渐变/邻近锚点高亮（低频 patch，视觉无感）
   5. pointer capture：指针移出测线/窗口仍持续跟踪；触屏不受滚动
      打断（touch-action: none）
   6. 非拖拽路径（挂载播种 / 松手吸附 / 锚点点击 / 键盘 / 预设同步）
      统一经 syncVisualState 写入 DOM —— 挂载期由 onMounted 播种，
      变更期由 watch(model) 同步；拖拽态关闭主视觉过渡（单帧
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
/** 按下时的位置（0-100）与测线像素宽度（点击/拖拽判定；宽度按下时缓存，
 * 拖拽期间不再读布局 — 消除 pointermove 路径的同步 layout） */
let downPos = 0;
let downWidth = 1;
/** 测线左缘像素（按下时缓存，move 期间零布局读取） */
let downLeft = 0;
/** 命中锚点索引（-1 = 空白处；点击吸附判定用） */
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

/** 位置写入测线 DOM：--pos（0-100 全精度）供游标 cqw 位移 */
const writePosToDom = (pos: number) => {
  const el = trackEl.value;
  if (!el) return;
  el.style.setProperty("--pos", pos.toFixed(3));
};

/** 亮层 --posw 量化步进（百分点）：clip-path 推进最多取 50 档，
 *  收敛拖拽期逐帧整层重栅格化频次 */
const LIT_QUANT_STEP = 2;
/** 拖拽期亮层写入最小间隔（毫秒，约 30Hz 抽帧）；非拖拽路径不降频 */
const LIT_WRITE_INTERVAL_MS = 1000 / 30;
/** 上次亮层写入的量化档位与时间戳（同档去重 / 抽帧判定） */
let lastLitQuant = -1;
let lastLitWriteAt = 0;

/** 亮层位置写入：量化到 2% 档位（同档不重复写），拖拽路径按 30Hz 抽帧，
 *  非拖拽路径（吸附/锚点/键盘/预设同步）即时写入 */
const writeLitPos = (pos: number, draggingNow: boolean) => {
  const el = trackEl.value;
  if (!el) return;
  const quant = Math.round(Math.min(100, Math.max(0, pos)) / LIT_QUANT_STEP) * LIT_QUANT_STEP;
  if (quant === lastLitQuant) return;
  const now = performance.now();
  if (draggingNow && now - lastLitWriteAt < LIT_WRITE_INTERVAL_MS) return;
  lastLitQuant = quant;
  lastLitWriteAt = now;
  el.style.setProperty("--posw", `${quant.toFixed(2)}%`);
};

/** 视觉状态统一入口：挂载播种 / 变更同步 / 吸附落位共用同一写入路径。
 *  挂载期写入不可省略 —— immediate watch 回调在组件挂载前执行，
 *  此时测线元素尚未就绪，写入会被空判丢弃；缺少挂载播种会导致
 *  重进面板时 --pos/--posw 保持 CSS 默认中位，游标与亮层指示失真。 */
const syncVisualState = (pos: number) => {
  writePosToDom(pos);
  writeLitPos(pos, false);
};

/* 变更期同步：model 变化（松手吸附/锚点点击/键盘/预设同步）→ 写入 DOM
 * （游标全精度 + 亮层量化即时写入）；拖拽期间跳过
 * （直写优先，避免节流值回跳覆盖最新指针位置） */
watch(orbitSliderPos, (pos) => {
  if (!dragging.value) syncVisualState(pos);
});

/* 挂载期播种：把当前权威位置写入 DOM（重进面板不回中位的保证点） */
onMounted(() => {
  latestPos = orbitSliderPos.value;
  syncVisualState(orbitSliderPos.value);
});

/* ===== 游标天平摆锤（欠阻尼弹簧积分） ===== */
/** 当前倾角（度，写入 --tilt） */
let tilt = 0;
/** 角速度 */
let tiltVel = 0;
/** 泵循环激活标志（once 排程无句柄 — 靠标志自停 / 组件卸载断泵） */
let tiltActive = false;
/** 上一事件指针横坐标（速度采样） */
let prevX = 0;

const writeTilt = () => {
  trackEl.value?.style.setProperty("--tilt", `${tilt.toFixed(3)}deg`);
};

/** 弹簧积分循环：刚度 0.16 / 阻尼 0.11（欠阻尼 → 摆锤式回正震荡衰减）
 * 拖拽期间作为位置写入门控：--pos 逐帧全精度直跟指针、--posw 量化后
 * 按 30Hz 抽帧写入（pointermove 高频事件不再同步直写 DOM，消除逐事件
 * 重栅格化与同步 layout，收敛亮层逐帧整层重栅格化频次） */
const tiltLoop = () => {
  if (!tiltActive) return;
  if (dragging.value) {
    writePosToDom(latestPos);
    writeLitPos(latestPos, true);
  }
  tiltVel += -tilt * 0.16 - tiltVel * 0.11;
  tilt = Math.max(-6, Math.min(6, tilt + tiltVel));
  writeTilt();
  if (dragging.value || Math.abs(tilt) > 0.02 || Math.abs(tiltVel) > 0.02) {
    masterFrameLoop.once(tiltLoop);
  } else {
    tilt = 0;
    tiltVel = 0;
    writeTilt();
    tiltActive = false;
  }
};

/** 速度冲量注入（拖拽位移 → 摆锤角速度） */
const kickTilt = (dx: number) => {
  tiltVel += Math.max(-1.6, Math.min(1.6, dx * 0.09));
  if (!tiltActive) {
    tiltActive = true;
    masterFrameLoop.once(tiltLoop);
  }
};

/** 由指针横坐标计算连续位置：仅更新数值与摆锤冲量 + 节流联动 model；
 * DOM 写入由 tiltLoop 在渲染帧内合并执行（不再在 pointermove 事件中同步直写） */
const updateFromPointer = (clientX: number) => {
  const ratio = Math.min(1, Math.max(0, (clientX - downLeft) / downWidth));
  latestPos = ratio * 100;
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
    // 按下时一次性读取布局并缓存 — 拖拽期间 updateFromPointer 零布局
    const rect = el.getBoundingClientRect();
    downLeft = rect.left;
    downWidth = rect.width || 1;
    downPos = Math.min(1, Math.max(0, (e.clientX - downLeft) / downWidth)) * 100;
    // 命中判定：按下点距某锚点 < 13px（锚点热区，含桩体与标签）
    downHitIdx = props.orbitAnchors.findIndex(
      (a) => (Math.abs(downPos - a.pos) / 100) * downWidth < 13,
    );
  }
  // 按下即启动帧内写入门控（位置合并到首个渲染帧）
  tiltActive = true;
  masterFrameLoop.once(tiltLoop);
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

/** 键盘交互激活标志：仅在一次键盘输入序列内允许触发释放吸附 */
let keyActive = false;
/** 键盘输入（原生 range 仅键盘可达，低频路径走 Vue model） */
const onKeyInput = (e: Event) => {
  keyActive = true;
  orbitSliderPos.value = Number((e.target as HTMLInputElement).value);
  emit("orbitSliderInput");
};
/** 键盘提交 — 磁性吸附（无输入序列时忽略，防止空 change 触发吸附） */
const onKeyRelease = () => {
  if (!keyActive) return;
  keyActive = false;
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
  /* 断泵：已排程的下一帧回调经 tiltActive 守卫直接返回，不再续排 */
  tiltActive = false;
});
</script>
