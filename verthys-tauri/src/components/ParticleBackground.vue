<!--
  ParticleBackground.vue — 偏轴旋涡星系 · 引力坠渡引擎
  层级：远景幕布星点 + 双臂旋涡银河盘（含核心棒）+ 近景偏置轨道尘埃 + 星云云团
  转场状态：启动逆渡 3s（intro：镜像弧线 + 反向缠绕，星系倒卷成型）
            → ambient（引导页静旋）→ warping（正渡 5s：缠绕收紧 + 掠翼弧线）
            → galaxy（主界面星系差速流转）
  冲突编排：3s 内点击 → 逆渡残余 0.5s C2 衰减 + 正渡自零爬升，符号积分换向连续
  ★ v3：镜头微颤体系全量移除（加载期画面恒稳定 — 渡越动感全部由包络积分承担）
  鼠标视差（渡越期间按包络压制）+ 噪点纹理
-->
<template>
  <div class="cosmos" :style="nebulaTexVars">
    <!-- 底层：深色基底 + 径向渐变 + 噪点 -->
    <div class="layer-base"></div>

    <!-- 星云云团（blur(80px) 烘焙进 SVG 贴图，运行时零实时滤镜） -->
    <div class="nebula nebula-1"></div>
    <div class="nebula nebula-2"></div>
    <div class="nebula nebula-3"></div>

    <!-- Three.js 粒子容器 -->
    <div ref="container" class="layer-particles"></div>
  </div>
</template>

<script setup lang="ts">
/**
 * ★★ 引力坠渡引擎（偏轴旋涡星系 — v2 模块化架构）：
 *
 * v2 架构重构（本版主题 — 健壮性 / 可维护性）：
 *   - 渡越序列引擎抽离为纯数学状态机（composables/useTransitionEngine，
 *     零 THREE 依赖）— 时钟无条件单调推进 + 效果由 introDone 门控；
 *     ★ v3：微颤体系全量删除（envelopeShiver / SHIVER 常量 / introAlive）—
 *     加载期镜头高频抖动根除，画面恒稳定
 *   - onBeforeCompile 注入全面替换为自定义 ShaderMaterial（components/
 *     particleShaders.ts — 着色器全文显式声明，根除 three 内部 chunk
 *     模板耦合；uniform 引用显式保存，调试/调参路径完全显式）
 *   - 着色器参数全部具名（components/shaderParams.ts — 模板字符串注入，
 *     GLSL 内零魔法数字）；轨道层构建返回 OrbitLayer 接口（元组根除）
 *   - 显式资源登记释放：构建即登记（场景对象/几何/材质/纹理分册）→
 *     卸载逐类目 dispose — GPU 显存不归 JS 堆管，杜绝 scene=null 的
 *     GC 兜底假设
 *   - currentPhase 初始自 props.phase 同步（相位基线/相机 Z 随之初始化）
 *
 * 旧范式根除清单（对应五大历史问题）：
 *   ✗ CPU 每帧遍历 4100 粒子写 buffer → ✓ 轨道参数预烘焙（aOrbit vec4），
 *     静止/渡越位置全部在顶点着色器内确定性求值，CPU 每帧仅写 3 个
 *     uniform，全生命周期零 buffer 上传
 *   ✗ 单一指数缓动 → ✓ 三段 smootherstep 复合包络（全程 C2 连续：
 *     值/速度/加速度零跳变；物理场恒纯净 — v3 起镜头层亦零微颤），
 *     轨道缠绕/收缩为包络的确定性函数（可逆：env
 *     归零即自动复位，无状态残留）
 *   ✗ 粒子硬重置闪现 → ✓ 无环绕无重置：渡越 = 半径收缩 + 角度缠绕
 *     （引力井收紧），内圈粒子 smoothstep 淡入核心（引力吞没），
 *     env 归零全部粒子沿轨道精确归位 —— 零闪现零跳变
 *   ✗ 无噪声扰动 → ✓ 双频复合正弦扰动（当前轨道角驱动 → 拖尾层噪声
 *     随弧线弯曲）+ 静止态逐粒子独立相位漂移
 *   ✗ 无分层差异 → ✓ 三层独立物理：银河盘（差速缠绕 + 半径收缩）、
 *     近景偏置轨道（大半径弧线掠过 + 强噪声）、远景幕布（收缩 + 微漂）
 *   ✗ 盘面姿态随包络可逆滚转（消散段原路回退 = 正逆旋转）→ ✓ 姿态全程
 *     锁定（41° 斜视，旋臂完整可辨），渡越旋转全部由缠绕积分驱动
 *     （uSwirl = ∫env·dt 单调递增不回退，每帧写入本体+残影 uniform）
 *
 * 反大众化设计（非"星轨推进"范式）：
 *   - 粒子运动全部是轨道角运动（θ 微分）+ 引力径向收缩，无 Z 轴直线冲刺
 *   - 盘面倾斜姿态（斜视椭圆透视，非正对中心放射）
 *   - 渡越拖尾 = 轨道弧线残影（同 geometry 多层绘制，uLag 相位滞后
 *     采样历史位置 → 弧形拖尾，非直线星轨）
 *   - 相机掠翼弧线：侧摆 + 前推 + 视线锚点滑向臂端（非直线推进）
 *   - 双臂非对称（缠绕度/散布/色相差异）+ 核心棒（中心厚边薄）
 *
 * 方向性渡越序列（全屏样式双向复用 — 单一旋转权威源；引擎独立模块）：
 *   - 启动 0-3s 逆渡（intro）：与正渡同形的全屏样式（相机镜像弧线 + 抬升、
 *     反向缠绕、拖尾、FOV 拉伸、微颤）— 星系倒卷成型，累计约 -2.6 rad
 *   - 点击进入正渡（enter）5s：原引力坠渡全屏样式（时长 = constants
 *     ENTER_T_MS 唯一权威源，编排节点等比派生）；缠绕为包络积分，
 *     每帧速率剖面与 3s 标定一致，累计角度随 T 线性缩放（~+4.3 rad）
 *   - 缠绕角为符号积分（enterEnv − introEnv）·dt — 角度恒连续；
 *     3s 内点击 → 逆渡残余自当前包络幅度 0.5s smootherstep 衰减 +
 *     正渡自零 ramp-in → 速率过零连续换向，无冲突无跳变
 *   - 相机方向分量（弧线侧摆/lookAt/俯仰）由 dirSmooth（阻尼符号权重）
 *     驱动：逆渡镜像掠翼 + 抬升，正渡原掠翼 + 俯冲，重叠期连续穿轴
 *
 * 保留架构：自适应抗锯齿（DPR≥1.5 关 MSAA）/ 统一帧门控（60/30/5/1fps）/
 * 失焦 deep-idle / 贴图烘焙 / 全部资源清理（v2 升级为显式登记制）
 */
import { ref, computed, onMounted, onBeforeUnmount, watch } from "vue";
import * as THREE from "three";
import { useGlobalIdleScheduler } from "../composables/useGlobalIdleScheduler";
import { useFrameGate } from "../composables/useFrameGate";
import { useTransitionEngine } from "../composables/useTransitionEngine";
import { frameBudgetMonitor } from "../core/frame-budget";
import { perfFlags } from "../app/feature-flags";
import {
  CLOSE_BREATH,
  CLOSE_LAYER,
  CLOSE_ORBIT,
  CURTAIN_LAYER,
  CURTAIN_WARP,
  GALAXY_LAYER,
  GALAXY_ORBIT,
  TRAIL_RESPONSE,
} from "./shaderParams";
import {
  buildOrbitLayer,
  createCurtainMaterial,
  type CurtainShaderUniforms,
  type OrbitLayer,
  type OrbitLayerMember,
  type SharedWarpUniforms,
} from "./particleShaders";

const props = defineProps<{
  phase?: "ambient" | "warping" | "galaxy";
}>();

/* ============================================================================
 * ★ 预渲染贴图：SVG 位图（渐变 + feGaussianBlur 烘焙）
 * ============================================================================
 * 与 CosmicBackground 同手法：浏览器将 data-URI SVG 背景图栅格化一次并缓存
 * 为纹理，运行时不再执行 3×blur(80px) 实时重栅格化（星云 drift 动画只驱动
 * transform，纯合成）。视觉参数（渐变 stop / 模糊半径）与原 CSS 逐项对应。
 */
const svgUrl = (svg: string): string =>
  `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;

const svgStop = (offset: number, color: string): string =>
  `<stop offset="${offset}" stop-color="${color}"/>`;

/** 径向渐变圆 + 高斯模糊贴图（贴图经 background-size 拉伸等效 ellipse 渐变） */
function radialBlurTexture(
  stops: string,
  cssBlurPx: number,
  cssElSize: number,
): string {
  const S = 320;
  const sigma = ((cssBlurPx * S) / cssElSize).toFixed(2);
  return svgUrl(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${S}" height="${S}">` +
      `<defs>` +
      `<radialGradient id="g">${stops}</radialGradient>` +
      `<filter id="f" x="-40%" y="-40%" width="180%" height="180%">` +
      `<feGaussianBlur stdDeviation="${sigma}"/></filter>` +
      `</defs>` +
      `<circle cx="160" cy="160" r="120" fill="url(#g)" filter="url(#f)"/></svg>`,
  );
}

const nebulaTexVars = computed<Record<string, string>>(() => ({
  /* 3 星云（原 blur(80px) + radial-gradient(ellipse) → 贴图，尺寸取宽换算） */
  "--tex-pn-1": radialBlurTexture(
    svgStop(0, "rgba(0,60,100,0.15)") + svgStop(0.7, "rgba(0,60,100,0)"),
    80, 600,
  ),
  "--tex-pn-2": radialBlurTexture(
    svgStop(0, "rgba(80,30,120,0.12)") + svgStop(0.7, "rgba(80,30,120,0)"),
    80, 500,
  ),
  "--tex-pn-3": radialBlurTexture(
    svgStop(0, "rgba(0,100,80,0.08)") + svgStop(0.7, "rgba(0,100,80,0)"),
    80, 400,
  ),
}));

const container = ref<HTMLElement | null>(null);
let renderer: THREE.WebGLRenderer | null = null;
let scene: THREE.Scene | null = null;
let camera: THREE.PerspectiveCamera | null = null;

/* ★ v2 显式资源登记表（构建即登记 → 卸载逐类目释放）
 * GPU 侧资源（geometry/material/texture）不归 JS 堆管，必须显式 dispose；
 * 场景对象卸载时先逐个从 scene 移除 — 不再依赖 scene=null 的 GC 兜底假设。
 * 共享 geometry（本体+残影）仅登记一次（dispose 幂等，登记去重更明确） */
type GpuDisposable = THREE.BufferGeometry | THREE.Material | THREE.Texture;
const sceneObjects: THREE.Object3D[] = [];
const gpuDisposables: GpuDisposable[] = [];
const trackGpu = <T extends GpuDisposable>(d: T): T => {
  gpuDisposables.push(d);
  return d;
};

/* ★ 监听器清理收敛为闭包变量（移除 `(el as any)._cleanup` DOM 挂载模式） */
let cleanupListeners: (() => void) | null = null;

/* ===== ★ 渡越序列引擎（独立模块 — 唯一权威源，零 THREE 依赖） =====
 * intro 逆渡 / enter 正渡双序列包络 + 符号缠绕积分 + 幕布位移积分 +
 * 相机微颤合成（含微颤终止修复 — 同模块头注） */
const engine = useTransitionEngine();

/* ===== 共享着色器 uniform（引擎 → GPU 单向桥，每帧由引擎结果落地） ===== */
/** 渲染域时钟（秒） */
const timeUniform = { value: 0 };
/** 渡越强度包络（0-1，复合曲线） */
const warpUniform = { value: 0 };
/** 渡越位移积分（速度包络 × dt 累积，驱动着色器环绕推进） */
const warpDistUniform = { value: 0 };
/** 点尺寸透视衰减标尺 = 视口高 × 0.5 × DPR（等效 three 内部
 * size×pixelRatio 与 scale=height×0.5 的乘积 — resize 时更新） */
const uScaleUniform = { value: 1 };
const sharedWarp: SharedWarpUniforms = {
  uTime: timeUniform,
  uWarp: warpUniform,
  uWarpDist: warpDistUniform,
  uScale: uScaleUniform,
};

/* ===== 三层粒子系统（v2 — 层记录对象化，元组返回根除） ===== */
/** 幕布层句柄：Points + 帧循环动画 uniform（尺寸/透明度） */
let distantStars: THREE.Points | null = null;
let curtain: { points: THREE.Points; uniforms: CurtainShaderUniforms } | null = null;
/** 轨道层（银河盘 / 近景尘埃）：Group 承载姿态（恒定锁定）+ 本体/残影成员 */
let galaxyLayer: OrbitLayer | null = null;
let closeLayer: OrbitLayer | null = null;
/** 全部轨道层成员扁平表（每帧 uSwirl 写入 — 本体当前积分/残影历史积分） */
let orbitMembers: OrbitLayerMember[] = [];
/** 残影成员扁平表（帧循环透明度响应） */
let trailMembers: OrbitLayerMember[] = [];

/** 包络的相机级阻尼副本（相机弧线/盘面倾转用它驱动，避免包络微颤直传） */
let envSmooth = 0;
/** 方向权重的阻尼副本（相机方向分量：侧摆侧/俯仰/lookAt — 与 envSmooth 分离） */
let dirSmooth = 0;

let mouseX = 0;
let mouseY = 0;
let smoothMouseX = 0;
let smoothMouseY = 0;
/** 当前相位（初始自 props.phase 同步 — onMounted，守卫说明附于下方） */
let currentPhase: "ambient" | "warping" | "galaxy" = "ambient";
let cameraZ = 880;
let cameraFov = 60;
/* ★ 相位基线 Z 平滑值：galaxy 切换（TRANSITION.GALAXY_PHASE = 包络
 * x=5/6 派生，5s 正渡即 4167ms）时基线 880→760 瞬跳 120
 * units，旧实现直接改 target → cameraZ 速度阶跃（可感知顿挫）；
 * 现基线本身经 kCam 平滑，切换全程速度连续。 */
let phaseZ = 880;
/* ★ 相机基准位（纯平滑值）：微颤叠加其上但不进入平滑自回归
 * （若微颤混入自回归会逐帧残留 → 低频漂移 + 放大，镜头失稳） */
let camBaseX = 0;
let camBaseY = 0;

/* ===== ★ 统一空闲调度接入 =====
 * 帧率档位（60/30/5/1fps）由全局唯一权威源 useGlobalIdleScheduler 驱动，
 * 本组件不再维护私有门控状态；转场/尺寸变化经 resetIdle 强制 active。 */
const { level: idleLevel, resetIdle } = useGlobalIdleScheduler();

onMounted(() => {
  if (!container.value) return;
  const el = container.value;
  const w = el.clientWidth;
  const h = el.clientHeight;

  /* ★ 相位初始同步：currentPhase 自 props.phase 初始化（旧实现硬编码
   * "ambient" — 若父组件挂载时 phase 已非 ambient，相位基线/相机 Z 全错），
   * 相位基线 Z 与相机 Z 随之就位；后续变化由 watch 承接 */
  currentPhase = props.phase ?? "ambient";
  phaseZ = currentPhase === "galaxy" ? 760 : 880;
  cameraZ = phaseZ;

  scene = new THREE.Scene();
  camera = new THREE.PerspectiveCamera(60, w / h, 0.1, 2000);
  camera.position.z = cameraZ;

  // ★ 自适应抗锯齿：DPR ≥ 1.5 时高密度像素下 MSAA 边缘增益不可感知，关闭以省 GPU
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  /* ★ 不透明画布——alpha:false 走不透明快速合成路径，
   *   深空底色与原透明透出桌面时的视觉一致；透明窗口仅为圆角/边缘保留。
   *   ★ 回滚开关：perfFlags.opaqueCanvas = false 时回退
   *   alpha:true + 透明清屏色（alpha 合成路径）。 */
  const opaqueCanvas = perfFlags.opaqueCanvas;
  renderer = new THREE.WebGLRenderer({ alpha: !opaqueCanvas, antialias: dpr < 1.5, powerPreference: "high-performance" });
  renderer.setSize(w, h);
  renderer.setPixelRatio(dpr);
  if (opaqueCanvas) {
    renderer.setClearColor(0x0a0e1a, 1.0); // ★ 深空色（不透明）
  } else {
    renderer.setClearColor(0x000000, 0.0); // 回滚路径：透明画布
  }
  /* 深空径向渐变在模板层以 CSS 叠加（.particle-canvas::after），模拟原
   * 透明画布下的背景深度——视觉等效，合成走不透明快速路径 */
  /* 点尺寸透视衰减标尺（等效 three 内部 scale=height×0.5 × size×pixelRatio） */
  uScaleUniform.value = h * 0.5 * renderer.getPixelRatio();
  /* ★ 启动频闪根治：canvas 延迟挂载 — 全部层构建完成后先预编译着色器
   * 并暖机渲染一帧再挂载（衔接下方 buildOrbitLayer 全部完成处）。
   * 旧序（频闪根因）：canvas 先挂载（透明空帧）→ 首帧 render 时同步
   * 编译多个材质的着色器程序（WebView2 下卡顿数十至数百毫秒）→
   * 多层粒子因编译完成先后不同逐帧浮现 = 启动频闪一下。 */

  /* ===== 圆形软光点纹理（避免方块状粒子） ===== */
  const makeParticleTexture = () => {
    const canvas = document.createElement("canvas");
    canvas.width = 128;
    canvas.height = 128;
    const ctx = canvas.getContext("2d")!;
    const g = ctx.createRadialGradient(64, 64, 0, 64, 64, 64);
    g.addColorStop(0, "rgba(255,255,255,1)");
    g.addColorStop(0.18, "rgba(255,255,255,0.85)");
    g.addColorStop(0.45, "rgba(255,255,255,0.25)");
    g.addColorStop(0.75, "rgba(255,255,255,0.06)");
    g.addColorStop(1, "rgba(255,255,255,0)");
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, 128, 128);
    const tex = new THREE.CanvasTexture(canvas);
    tex.needsUpdate = true;
    return tex;
  };
  /* ★ v2：贴图纳入显式登记（Material.dispose 不级联纹理 — 独立释放） */
  const particleTexture = trackGpu(makeParticleTexture());

  /* ===== 1. 远景星点（1000 颗，极小，极深 — 渡越行为：向消失点收缩 + 慢差速推进） ===== */
  {
    const count = CURTAIN_LAYER.count;
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);
    const seeds = new Float32Array(count);

    for (let i = 0; i < count; i++) {
      const i3 = i * 3;
      positions[i3] = (Math.random() - 0.5) * 1800;
      positions[i3 + 1] = (Math.random() - 0.5) * 1400;
      positions[i3 + 2] = -200 - Math.random() * 800;
      seeds[i] = Math.random() * 10;

      const brightness = 0.3 + Math.random() * 0.5;
      const tint = Math.random();
      if (tint < 0.6) { colors[i3] = brightness; colors[i3+1] = brightness; colors[i3+2] = brightness; }
      else if (tint < 0.85) { colors[i3] = brightness * 0.4; colors[i3+1] = brightness * 0.7; colors[i3+2] = brightness; }
      else { colors[i3] = brightness; colors[i3+1] = brightness * 0.6; colors[i3+2] = brightness * 0.8; }
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    geo.setAttribute("aSeed", new THREE.BufferAttribute(seeds, 1));
    trackGpu(geo);

    /* z∈[-1000,-200] + 1100 ∈ [100,900] ⊂ [0,2000) → 静止态 mod 恒等
     * 幕布层去星轨化：微纵深漂移（speedBase 0.08 — 深空视差感而非推进），
     * 渡越视觉主体交给银河盘轨道缠绕 + 相机掠翼弧线
     * （参数权威源 = shaderParams CURTAIN_WARP / CURTAIN_LAYER） */
    const bundle = createCurtainMaterial(
      CURTAIN_WARP,
      CURTAIN_LAYER.size,
      CURTAIN_LAYER.opacity,
      sharedWarp,
      particleTexture,
    );
    distantStars = new THREE.Points(geo, bundle.material);
    curtain = { points: distantStars, uniforms: bundle.uniforms };
    scene.add(distantStars);
    sceneObjects.push(distantStars);
  }

  /* ===== 2. 银河盘（3000 颗 — 双臂非对称旋涡 + 核心棒，轨道化运动） =====
   * 分布：88% 旋臂粒子（两条臂缠绕度/散布/色相各异 — 非镜像对称）+
   * 12% 核心棒（中心厚边薄的暖金椭球）
   * 静止态：开普勒差速旋转（内圈快外圈慢，旋臂持续流转）
   * 渡越态：引力缠绕收紧（内紧外松）+ 半径收缩 + 内圈吞没核心 + 弧形拖尾
   * 姿态：Group 倾斜（斜视椭圆透视 — 拒绝正对中心放射），渡越时压向侧向掠射 */
  {
    const count = GALAXY_LAYER.count;
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);
    const seeds = new Float32Array(count);
    const orbits = new Float32Array(count * 4);

    const R_MIN = 55, R_MAX = 700;
    const ARM_WIND = 2.6; // 静止缠绕角跨度（弧度 ×2π 系数）
    const gauss = () => (Math.random() + Math.random() + Math.random() - 1.5) / 1.5;

    const colorCyan = new THREE.Color(0x00d4ff);
    const colorViolet = new THREE.Color(0x8b5cf6);
    const colorGold = new THREE.Color(0xffd9a0);
    const colorMagenta = new THREE.Color(0xff2e63);
    const colorWhite = new THREE.Color(0xffffff);

    for (let i = 0; i < count; i++) {
      const i3 = i * 3;
      const i4 = i * 4;
      const seed = Math.random() * 10;
      seeds[i] = seed;
      const isCore = Math.random() < 0.12;

      let r0: number, th0: number, z0: number;
      let c: THREE.Color;

      if (isCore) {
        // 核心棒：幂律径向（中心密）+ 中心厚边薄椭球 + 暖金白
        r0 = Math.pow(Math.random(), 1.6) * R_MIN * 1.1 + 4;
        th0 = Math.random() * Math.PI * 2;
        z0 = gauss() * (26 + (1 - r0 / R_MIN) * 18);
        c = colorGold.clone().lerp(colorWhite, Math.random() * 0.55);
        c.multiplyScalar(0.6 + Math.random() * 0.4);
      } else {
        // 双臂：arm 相位差 π，但缠绕度/散布/臂偏移各自不同（非镜像对称）
        const arm = i % 2;
        const t = Math.pow(Math.random(), 0.72); // 内密外疏
        const wind = arm === 0 ? ARM_WIND : ARM_WIND * 1.14; // 臂 B 缠绕更紧
        const armOff = arm === 0 ? 0.35 : -0.22; // 非对称臂相位偏移
        r0 = R_MIN + t * (R_MAX - R_MIN) + gauss() * (30 + t * 90);
        th0 = arm * Math.PI + armOff + t * wind * Math.PI * 2 + gauss() * (0.22 + t * 0.5);
        z0 = gauss() * (10 + (1 - t) * 16);
        // 臂 A 偏青、臂 B 偏紫（色相分化），少量品红/白点缀
        // ★ v4 静息亮度二次提升：亮度分布 0.62-1.0 → 0.72-1.0（均值再
        //   +7%，全状态生效 — 含渡越峰值，用户校正「还是太暗」）
        const rr = Math.random();
        if (rr < 0.02) c = colorMagenta.clone();
        else if (rr < 0.08) c = colorWhite.clone();
        else c = (arm === 0 ? colorCyan : colorViolet).clone().lerp(colorViolet, Math.random() * 0.7);
        c.multiplyScalar(0.72 + Math.random() * 0.28);
      }

      // 开普勒差速角速度：内圈快外圈慢 + 逐粒子 hash 扰动
      const omega = (0.055 + (seed % 1) * 0.02) / Math.pow(Math.max(r0, 50) / 100, 1.25);

      orbits[i4] = r0;
      orbits[i4 + 1] = th0;
      orbits[i4 + 2] = omega;
      orbits[i4 + 3] = z0;

      // position 仅用于包围球（静止轨道位置，着色器忽略此属性）
      positions[i3] = r0 * Math.cos(th0);
      positions[i3 + 1] = r0 * Math.sin(th0);
      positions[i3 + 2] = z0;

      colors[i3] = c.r;
      colors[i3 + 1] = c.g;
      colors[i3 + 2] = c.b;
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    geo.setAttribute("aSeed", new THREE.BufferAttribute(seeds, 1));
    geo.setAttribute("aOrbit", new THREE.BufferAttribute(orbits, 4));
    trackGpu(geo);

    /* 物理实例参数权威源 = shaderParams GALAXY_ORBIT（含 3s 标定注释），
     * 层基线 = GALAXY_LAYER（尺寸/透明度基准与渡越增幅） */
    galaxyLayer = buildOrbitLayer(
      geo,
      {
        orbit: GALAXY_ORBIT,
        pivot: new THREE.Vector2(0, 0),
        size: GALAXY_LAYER.size,
        opacity: GALAXY_LAYER.opacity,
      },
      sharedWarp,
      particleTexture,
    );

    /* 斜视姿态（椭圆透视）：X 倾 41°（-0.72 rad）— 旋臂结构完整可辨的
     * 最佳斜视角（旧 -1.05/60° 过侧致星系画面不明显）；Y/Z 微扭非正对非正侧。
     * ★ 姿态全程锁定：渡越旋转感全部由缠绕积分（单调）承担 */
    galaxyLayer.group.rotation.set(-0.72, 0.15, 0.12);
    scene.add(galaxyLayer.group);
    sceneObjects.push(galaxyLayer.group);
  }

  /* ===== 3. 近景尘埃（600 颗 — 偏置大半径轨道，渡越时弧线掠过相机） =====
   * 范式根除：非 Z 轴直线冲刺，而是绕画面外偏置中心（-260,-90）的大半径
   * 轨道差速运动 — 渡越时缠绕相位大（弧线横扫画面）+ 最强噪声扰动。
   * 静止态：慢速漂浮旋转（ω 极小）+ 独立相位漂移（近景飞尘感） */
  {
    const count = CLOSE_LAYER.count;
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);
    const seeds = new Float32Array(count);
    const orbits = new Float32Array(count * 4);

    const PIVOT = new THREE.Vector2(-260, -90);
    const colorA = new THREE.Color(0x00d4ff);
    const colorB = new THREE.Color(0x8b5cf6);

    for (let i = 0; i < count; i++) {
      const i3 = i * 3;
      const i4 = i * 4;
      const seed = Math.random() * 10;
      seeds[i] = seed;
      const h = seed % 1;

      // 偏置大半径轨道：r 480-950（轨道中心在画面外 → 粒子呈大弧掠过）
      // z 150-500：相机渡越推近至 ~550 时真正从身侧掠过（近景纵深）
      const r0 = 480 + Math.random() * 470;
      const th0 = Math.random() * Math.PI * 2;
      const z0 = 150 + Math.random() * 350;
      // 静止角速度极小（漂浮）+ hash 差异；渡越缠绕大（弧线扫过）
      const omega = (0.02 + h * 0.015) / Math.pow(r0 / 600, 1.2);

      orbits[i4] = r0;
      orbits[i4 + 1] = th0;
      orbits[i4 + 2] = omega;
      orbits[i4 + 3] = z0;

      positions[i3] = PIVOT.x + r0 * Math.cos(th0);
      positions[i3 + 1] = PIVOT.y + r0 * Math.sin(th0);
      positions[i3 + 2] = z0;

      const c = colorA.clone().lerp(colorB, Math.random());
      c.multiplyScalar(0.5 + Math.random() * 0.5);

      colors[i3] = c.r;
      colors[i3 + 1] = c.g;
      colors[i3 + 2] = c.b;
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    geo.setAttribute("aSeed", new THREE.BufferAttribute(seeds, 1));
    geo.setAttribute("aOrbit", new THREE.BufferAttribute(orbits, 4));
    trackGpu(geo);

    closeLayer = buildOrbitLayer(
      geo,
      {
        orbit: CLOSE_ORBIT,
        pivot: PIVOT,
        size: CLOSE_LAYER.size,
        opacity: CLOSE_LAYER.opacity,
      },
      sharedWarp,
      particleTexture,
    );
    scene.add(closeLayer.group);
    sceneObjects.push(closeLayer.group);
  }

  /* 轨道层成员扁平表（本体 + 残影 — uSwirl 每帧写入）与材质登记 */
  orbitMembers = [
    galaxyLayer.body,
    ...galaxyLayer.trails,
    closeLayer.body,
    ...closeLayer.trails,
  ];
  trailMembers = [...galaxyLayer.trails, ...closeLayer.trails];
  trackGpu(distantStars.material as THREE.Material);
  for (const m of orbitMembers) trackGpu(m.points.material as THREE.Material);

  /* ===== ★ 帧预算降级接入（粒子密度通道） =====
   * 监控器持有 ParticleDensityController 契约（依赖倒置 — 不感知 THREE），
   * 本组件以 setDrawRange 落地（语义 = InstancedMesh.count 尾部截断；
   * 各层粒子均匀随机分布，尾部截断无视觉偏置）。
   * 轨道层本体与残影共享 geometry — 单次 setDrawRange 全成员一致生效。
   * 注册即应用当前档位密度（晚注册不漏降级）；卸载时注销（onBeforeUnmount）。 */
  const densityGeometries: { geometry: THREE.BufferGeometry; baseCount: number }[] = [
    { geometry: distantStars.geometry, baseCount: CURTAIN_LAYER.count },
    { geometry: galaxyLayer.body.points.geometry, baseCount: GALAXY_LAYER.count },
    { geometry: closeLayer.body.points.geometry, baseCount: CLOSE_LAYER.count },
  ];
  frameBudgetMonitor.setParticleController({
    setDensity: (fraction: number): void => {
      for (const { geometry, baseCount } of densityGeometries) {
        geometry.setDrawRange(0, Math.max(1, Math.floor(baseCount * fraction)));
      }
    },
  });

  /* ===== 鼠标视差（空闲检测由全局调度器 pointermove 承担，此处仅视差） ===== */
  const onMouseMove = (e: MouseEvent) => {
    mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
    mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
  };
  window.addEventListener("mousemove", onMouseMove);

  /* ===== 动画循环（★ 引力坠渡 — CPU 每帧仅更新 uniform/相机/材质参数） =====
   * 档位：active 60fps / settling 30fps / idle 5fps / deep-idle 1fps；
   * dt 由门控按真实帧距累积供给（跳帧不推进基准 → 物理时间连续）。
   * 引擎侧 DT_CLAMP = 0.08s：保护渡越积分与平滑系数。
   * 粒子轨道位置全部在顶点着色器求值（uTime/uWarp/uWarpDist/uSwirl 驱动），
   * 全生命周期零 position buffer 上传 —— 长时间运行无性能衰减。
   * CPU 每帧工作：引擎单步 + 3 个共享 uniform + 8 个轨道层 uSwirl（银河盘/
   * 近景各本体+3 残影）+ 相机双向运镜 + ~10 个 uniform 参数（引擎内含
   * 符号缠绕积分与历史缓冲）。转场经 watch(phase) → resetIdle 强制满帧。
   * 页面隐藏/失焦：调度器置 deep-idle + rAF 天然停帧。 */
  const ENGINE_DT_CLAMP = 0.08;
  /* ★ 幕布漂移基准角（rotation 改时间绝对式：f(t) 与帧率解耦，
   *   降档跳帧零累计误差；基准取挂载时初值） */
  const curtainDriftBase = curtain.points.rotation.z;
  const renderFrame = (gateDt: number) => {
    if (!renderer || !scene || !camera || !curtain || !galaxyLayer || !closeLayer) return;
    const dt = Math.min(gateDt, ENGINE_DT_CLAMP);

    /* --- 1. ★ 渡越序列引擎单步（时钟无条件推进 + 双序列 C2 包络 +
     *     符号缠绕/幕布位移积分 — 与 useTransitionEngine 模块头注一致；
     *     v2 微颤终止修复：效果由 introDone/introAlive 门控，时钟绝不
     *     冻结 → 打断后微颤 0.5s 内平滑消失零残留） --- */
    const t = engine.update(dt);

    /* --- ★ 渡越进行中强制满帧（档位回落单帧内自愈 — 非每帧调用，
     *     零定时器 churn）：入场窗口（页面交接→包络归零）与主界面
     *     入场动画共享主线程/GPU，空闲降档会直接放大入场卡顿 --- */
    if (engine.warpEnv > 0 && idleLevel.value !== "active") {
      resetIdle();
    }

    /* 共享 uniform 落地（引擎 → GPU 单向同步） */
    timeUniform.value = t;
    warpUniform.value = engine.warpEnv;
    warpDistUniform.value = engine.warpDist;

    /* --- 1b. ★ 符号缠绕积分 → 各轨道层 uSwirl：
     *     本体（uLag=0）写当前积分，残影按 t-lag 插值取历史积分 →
     *     真实弧形拖尾（正逆渡越均呈弧形）
     * 静态相快速径：渡越未激活（warpEnv=0 且 envSmooth 收敛）
     *   时 swirl 积分恒定——跳过 8 元素循环与历史插值求值（30fps 下
     *   每帧节省 8 次超越函数求值）；渡越激活时全量执行。 --- */
    const transitionActive = engine.warpEnv > 0.0005 || Math.abs(envSmooth) > 0.0005;
    if (transitionActive) {
      const swirl = engine.swirl;
      for (const m of orbitMembers) {
        const lag = m.uniforms.uLag.value;
        m.uniforms.uSwirl.value = lag > 0 ? engine.swirlAt(t - lag) : swirl;
      }
    }

    // 帧率无关指数平滑系数（60fps 基准 per-frame 系数 → per-second）
    const S = 60 * dt;
    const kMouse = 1 - Math.pow(1 - 0.03, S);
    const kCam = 1 - Math.pow(1 - 0.04, S);
    const kEnv = 1 - Math.pow(1 - 0.08, S);

    /* --- 2. 阻尼副本（滤除包络直传）：envSmooth = 场强度（幅度分量），
     *     dirSmooth = 符号方向（方向分量）— 相机幅度/方向两类分量分离，
     *     重叠换向期各自连续
     * 静态相：渡越未激活时包络恒 0，平滑无变化——跳过写 --- */
    if (transitionActive) {
      envSmooth += (engine.warpEnv - envSmooth) * kEnv;
      dirSmooth += (engine.dirW - dirSmooth) * kEnv;
    }

    /* --- 3. 交互优先级：渡越包络压制视差（渡越 > 视差），渡越结束视差阻尼渐入 --- */
    smoothMouseX += (mouseX - smoothMouseX) * kMouse;
    smoothMouseY += (mouseY - smoothMouseY) * kMouse;
    const parallax = 1 - envSmooth;

    /* --- 4. ★ 双向相机运镜（非直线推进）：
     *     幅度分量（envSmooth）：Z 冲程（峰驻贴近视距）+ FOV 时空拉伸 —
     *       正逆渡共用（能量脉冲对称）
     *     方向分量（dirSmooth）：侧摆弧线（正渡 −120 掠左翼 / 逆渡 +120
     *       镜像掠右翼）+ 俯仰（正渡俯冲 −55 / 逆渡抬升 +55）+ lookAt
     *       锚点（正渡滑向臂端 / 逆渡滑向镜像侧）— 重叠换向期连续穿轴
     *     ★ v3 加载微颤根除：镜头高频微颤（engine.shiver）全量移除 —
     *       相机位置 = 纯平滑基准位（阻尼自回归收敛），启动/进入渡越
     *       全程画面恒稳定，渡越动感全部由包络积分承担 --- */
    phaseZ += ((currentPhase === "galaxy" ? 760 : 880) - phaseZ) * kCam;
    const targetCameraZ = phaseZ - 330 * envSmooth;
    cameraZ += (targetCameraZ - cameraZ) * kCam;
    const targetFov = 60 + envSmooth * 22;
    cameraFov += (targetFov - cameraFov) * kCam;

    const arc = Math.sin(envSmooth * Math.PI); // 0→1→0 侧摆幅度包络
    camBaseX += (smoothMouseX * 30 * parallax - 120 * arc * dirSmooth - camBaseX) * kMouse;
    camBaseY += (-smoothMouseY * 20 * parallax - 55 * dirSmooth - camBaseY) * kMouse;
    camera.position.z = cameraZ;
    camera.position.x = camBaseX;
    camera.position.y = camBaseY;
    camera.lookAt(90 * dirSmooth, -22 * dirSmooth, 0);
    if (Math.abs(camera.fov - cameraFov) > 0.02) {
      camera.fov = cameraFov;
      camera.updateProjectionMatrix();
    }

    /* --- 5. 银河盘姿态：★ 全程锁定（正逆旋转第二根因根除）
     *     旧实现 X/Z 欧拉角随包络可逆滚转：蓄能/峰驻段转过去、消散段
     *     原路转回来 = 视觉上的"正转后逆转"。现姿态恒定（构建时已定标），
     *     仅保留极慢 Y 向漂摆（120s 级正弦，无方向感知）；
     *     渡越的全部旋转感由符号缠绕积分承担（积分量，序列内绝不回退）。 --- */
    galaxyLayer.group.rotation.y = 0.15 + Math.sin(t * 0.04) * 0.015;

    /* --- 6. 分层材质响应（独立参数 = 空间纵深；v2 — uniform 写入） --- */
    // 银河盘本体：渡越尺寸增幅 + 色调偏冷青（加性混合自然过渡）
    // 基线 5.0/1.0（v4 静息亮度二次提升 — 峰值 6.2/1.0 恒定；历史：
    // v2 4.0/0.95 仍偏暗，旧 2.2/0.7 在 880 距离下仅 ~1.25px）
    /* ★ 静态相：envSmooth 已收敛（<0.0005）时 env 联动 uniform
     *   恒为基线值——跳过写（值已在收敛期写入基线）；渡越期全量写。 */
    if (transitionActive) {
      const u = galaxyLayer.body.uniforms;
      u.uSize.value = GALAXY_LAYER.size + envSmooth * GALAXY_LAYER.warpSizeGain;
      u.uOpacity.value = GALAXY_LAYER.opacity + envSmooth * GALAXY_LAYER.warpOpacityGain;
      u.uTint.value.setRGB(1 - envSmooth * 0.18, 1 - envSmooth * 0.02, 1 + envSmooth * 0.08);
      // 残影拖尾：随包络增强（v4 静息基底 0.55 — 暗相位残光再提升，峰值 1.0 不变）
      const trailVis = TRAIL_RESPONSE.base + TRAIL_RESPONSE.gain * envSmooth;
      for (const m of trailMembers) {
        m.uniforms.uOpacity.value = m.baseOpacity * trailVis;
      }
      curtain.uniforms.uSize.value = CURTAIN_LAYER.size + envSmooth * CURTAIN_LAYER.warpSizeGain;
      curtain.uniforms.uOpacity.value = CURTAIN_LAYER.opacity + envSmooth * CURTAIN_LAYER.warpOpacityGain;
    }

    // 远景幕布：极缓慢旋转（★ 改为时间绝对式——30fps/降档下漂移速率与
    // 帧率解耦：rotation = f(t)，累计误差为零）
    curtain.points.rotation.z = curtainDriftBase + CURTAIN_LAYER.driftRate * t;

    // 近景尘埃：呼吸 + 渡越最大增幅（近景层速度感最强）+ 残影增强
    {
      const u = closeLayer.body.uniforms;
      u.uOpacity.value =
        CLOSE_BREATH.base +
        Math.sin(t * CLOSE_BREATH.rate) * CLOSE_BREATH.amp +
        envSmooth * CLOSE_BREATH.warpOpacityGain;
      u.uSize.value = CLOSE_LAYER.size + envSmooth * CLOSE_LAYER.warpSizeGain;
    }

    renderer.render(scene, camera);
  };

  /* ★ 启动频闪根治（承接 canvas 延迟挂载）：预编译全部着色器程序 +
   * 暖机渲染一帧 → canvas 挂载即完整画面（零空帧、零逐层浮现）。
   * 时间 uniform 以渲染域时钟（=0）为基准：暖机帧即 t=0 轨道
   * 位置（逆渡 intro 包络(0)=0，相机位于基线），挂载后首帧 t=dt ——
   * 粒子相位与逆渡起始连续无跳变。 */
  /* ★ 暖机帧材质参数同步（与首帧 t=0/env=0 求值逐参数一致）：
   * 构建默认值 ≠ 帧循环初值（近景尘埃 opacity 0.5→0.4、残影拖尾
   * ×0.32 骤降至约 1/3）— 暖机帧会先以构建值显示一帧再跳到帧循环值
   * = 启动瞬间一次单帧亮度闪变。此处预写 t=0 帧值（v2 — uniform 写入）。 */
  if (closeLayer) {
    closeLayer.body.uniforms.uOpacity.value = CLOSE_BREATH.base;
  }
  for (const m of trailMembers) {
    m.uniforms.uOpacity.value = m.baseOpacity * TRAIL_RESPONSE.base;
  }
  timeUniform.value = 0;
  renderer.compile(scene, camera);
  renderer.render(scene, camera);
  el.appendChild(renderer.domElement);

  /* ★ 统一帧门控启动：renderFrame 由 useFrameGate 按空闲档位调度 */
  const { start: startGate, stop: stopGate } = useFrameGate(idleLevel, renderFrame);
  startGate();

  const handleResize = () => {
    if (!container.value || !renderer || !camera) return;
    const nw = container.value.clientWidth;
    const nh = container.value.clientHeight;
    camera.aspect = nw / nh;
    camera.updateProjectionMatrix();
    renderer.setSize(nw, nh);
    /* 点尺寸透视衰减标尺随视口同步（gl_PointSize = uSize × uScale / −mvz） */
    uScaleUniform.value = nh * 0.5 * renderer.getPixelRatio();
    resetIdle(); // 尺寸变化为交互信号：立即恢复满帧
  };
  window.addEventListener("resize", handleResize);

  /* ★ 监听器清理收敛为闭包变量（替代原 `(el as any)._cleanup` DOM 挂载，
     不再绕过 Vue 类型系统，onBeforeUnmount 直接调用）。
     失焦/隐藏暂停已由全局调度器（deep-idle）+ rAF 天然停帧承接，无本组件监听。 */
  cleanupListeners = () => {
    stopGate();
    window.removeEventListener("mousemove", onMouseMove);
    window.removeEventListener("resize", handleResize);
  };
});

watch(
  () => props.phase,
  (newPhase) => {
    if (newPhase) {
      currentPhase = newPhase;
      // 正渡触发：enter 时钟归零启动（蓄能 → 峰驻 → 消散全程重放）
      if (newPhase === "warping") {
        /* ★ 渡越序列冲突处理（启动 3s 内立即点击）：引擎接管 — 记录打断
         * 时刻的逆渡时钟 → 帧循环内残余包络自该时刻幅度经 0.5s
         * smootherstep 平滑衰减至零（dirW 过零连续）；正渡时钟归零启动
         * （包络自零爬升）— 缠绕角为积分量，全程无跳变 */
        engine.triggerEnter();
      }
      resetIdle(); // 转场为交互信号：门控立即恢复满帧（渡越强制 60fps）
    }
  }
);

onBeforeUnmount(() => {
  cleanupListeners?.();
  cleanupListeners = null;

  /* ★ 帧预算监控注销：控制器引用的 geometry 随下方登记制释放 —
   * 先解除监控器持有，杜绝降级回调触达已释放资源 */
  frameBudgetMonitor.setParticleController(null);

  /* ★ v2 显式资源释放（登记制）：场景对象逐个移除 + GPU 侧
   * geometry/material/texture 逐类目 dispose — 不再依赖 scene=null 的
   * GC 兜底假设（GPU 显存不归 JS 堆管，必须显式释放）。
   * 轨道层本体+残影共享 geometry 仅登记一次（dispose 幂等 + 登记去重） */
  if (scene) {
    for (const obj of sceneObjects) scene.remove(obj);
  }
  sceneObjects.length = 0;
  for (const res of gpuDisposables) res.dispose();
  gpuDisposables.length = 0;

  /* ★ 强制归还 WebGL 上下文（forceContextLoss 必须先于 renderer.dispose，
     否则 WebView2 侧上下文释放不彻底） */
  if (renderer) {
    renderer.forceContextLoss();
    renderer.dispose();
    renderer.domElement.remove();
  }
  renderer = null;
  scene = null;
  camera = null;
  distantStars = null;
  curtain = null;
  galaxyLayer = null;
  closeLayer = null;
  orbitMembers = [];
  trailMembers = [];
});
</script>

<style scoped>
.cosmos {
  position: fixed;
  inset: 0;
  z-index: 0;
  pointer-events: none;
  overflow: hidden;
}

/* 底层：深色基底 + 径向渐变 + 噪点 */
.layer-base {
  position: absolute;
  inset: 0;
  background:
    radial-gradient(ellipse at 25% 45%, rgba(0, 30, 50, 0.2) 0%, transparent 50%),
    radial-gradient(ellipse at 75% 55%, rgba(20, 0, 40, 0.15) 0%, transparent 50%),
    radial-gradient(ellipse at 50% 50%, rgba(0, 20, 35, 0.1) 0%, transparent 70%),
    #04060a;
}
.layer-base::after {
  content: "";
  position: absolute;
  inset: 0;
  opacity: 0.35;
  background-image:
    url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='3'/%3E%3CfeColorMatrix values='0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0.05 0'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
}

/* 星云云团（blur(80px) 烘焙进贴图，运行时零实时滤镜） */
.nebula {
  position: absolute;
  border-radius: 50%;
  background: center / 100% 100% no-repeat;
  pointer-events: none;
  will-change: transform;
}
.nebula-1 {
  width: 600px; height: 400px;
  top: 10%; left: -10%;
  background-image: var(--tex-pn-1);
  animation: nebula-drift-1 40s ease-in-out infinite;
}
.nebula-2 {
  width: 500px; height: 350px;
  bottom: 5%; right: -5%;
  background-image: var(--tex-pn-2);
  animation: nebula-drift-2 55s ease-in-out infinite;
}
.nebula-3 {
  width: 400px; height: 300px;
  top: 50%; left: 50%;
  background-image: var(--tex-pn-3);
  animation: nebula-drift-3 70s ease-in-out infinite;
}
@keyframes nebula-drift-1 {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50% { transform: translate(60px, -30px) scale(1.1); }
}
@keyframes nebula-drift-2 {
  0%, 100% { transform: translate(0, 0) scale(1); }
  50% { transform: translate(-40px, 40px) scale(0.9); }
}
@keyframes nebula-drift-3 {
  0%, 100% { transform: translate(-50%, -50%) scale(1); }
  50% { transform: translate(-40%, -55%) scale(1.15); }
}

/* 粒子容器 */
.layer-particles {
  position: absolute;
  inset: 0;
  z-index: 1; /* 不透明画布层 */
}

/* ★ 深空径向渐变叠加——原透明画布下 layer-base 的背景深度，
 *   移到不透明画布之上（pointer-events 穿透，纯合成层） */
.layer-particles::after {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background:
    radial-gradient(ellipse at 25% 45%, rgba(0, 30, 50, 0.14) 0%, transparent 50%),
    radial-gradient(ellipse at 75% 55%, rgba(20, 0, 40, 0.10) 0%, transparent 50%),
    radial-gradient(ellipse at 50% 50%, rgba(0, 20, 35, 0.07) 0%, transparent 70%);
}

/* ★ 星云云团移到不透明画布之上——mix-blend-mode: screen 使
 *   亮色云团在深空底上的视觉与原先（画布 alpha 透出）等效；
 *   z-index 高于画布，漂移动画不变（transform 合成器驱动） */
.nebula {
  z-index: 2;
  mix-blend-mode: screen;
}
</style>
