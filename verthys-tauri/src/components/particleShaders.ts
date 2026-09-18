/*
 * particleShaders.ts — 粒子层自定义着色器材质工厂（幕布 / 轨道）
 *
 * ★ v2 架构迁移：onBeforeCompile 注入 → 完整自定义 ShaderMaterial
 *   旧实现向 THREE.PointsMaterial 的内部 chunk（common/color_vertex/
 *   begin_vertex）做字符串替换注入 — 与 three 内部着色器模板强耦合，
 *   版本升级即脆弱。现以完整顶点/片元着色器字符串显式声明全部
 *   attribute/uniform，材质工厂持有全部引用 — 零模板依赖、零隐藏
 *   注入点，调试与调参路径完全显式。
 *
 * 顶点着色器数学（与旧注入逐项等价 — 语义零变化）：
 *   幕布层：差速推进 mod 环绕 + 边界消散 + 螺旋卷积 + 消失点收缩 +
 *           双频噪声 + 静止漂移（uWarp/uWarpDist 驱动，静止态恒等）
 *   轨道层：位置 = 轨道参数（aOrbit: r0/θ0/ω/z0）的确定性函数 —
 *           开普勒差速旋转 + 符号缠绕积分（uSwirl）+ 半径收缩 +
 *           轨道角驱动噪声 + 核心吞没（可见度下限 0.34）；
 *           uLag 相位滞后（开普勒项 + uSwirl 历史采样）→ 弧形拖尾
 *   片元（共用）：贴图 × 顶点色 × 色调 × 透明度，加性混合；
 *           alphaTest 等效 discard（阈值 ALPHA_TEST）
 *
 * 与 PointsMaterial 的行为对齐点：
 *   - 透视尺寸衰减：gl_PointSize = uSize × uScale / −mvPosition.z，
 *     其中 uScale = 视口高 × 0.5 × DPR（等效 three 内部 size×pixelRatio
 *     与 scale=height×0.5 的乘积 — CSS 像素标称尺寸跨 DPR 恒定）
 *   - 顶点色：显式 attribute vec3 color 声明（不依赖 USE_COLOR 注入）
 *   - 加性混合：blendSrc=SrcAlpha / blendDst=One，rgb×alpha 合成
 */

import * as THREE from "three";
import {
  ALPHA_TEST,
  ORBIT_GLSL,
  TRAIL_SPECS,
  WARP_GLSL,
  type CurtainShaderOpts,
  type OrbitShaderOpts,
} from "./shaderParams";

/* 数值 → GLSL float 字面量（恒带小数点 — 根除 int 字面量混入 float
 * 表达式的 GLSL ES 类型错误风险；4 位小数保留 hash 常数精度） */
const f = (n: number): string => n.toFixed(4);

/** 引擎 → GPU 共享 uniform 桥（组件持有，材质工厂仅引用） */
export interface SharedWarpUniforms {
  /** 渲染域时钟（秒 — 与门控 dt 同基准） */
  uTime: { value: number };
  /** 渡越场强度包络（0-1） */
  uWarp: { value: number };
  /** 幕布位移积分（符号 — 环绕推进） */
  uWarpDist: { value: number };
  /** 点尺寸透视衰减标尺 = 视口高 × 0.5 × DPR（resize 时更新） */
  uScale: { value: number };
}

/* ============================================================================
 * 片元着色器（幕布/轨道共用）：贴图 × 顶点色 × 色调 × 透明度 — 加性混合
 * 合成路径与旧 PointsMaterial 逐项等价：rgb = vColor·uTint·tex.rgb，
 * alpha = tex.a·uOpacity；discard 阈值 = alphaTest 等效。
 * ========================================================================== */
const fragmentShader = `
uniform sampler2D uMap;
uniform float uOpacity;
uniform vec3 uTint;
varying vec3 vColor;
void main() {
  vec4 tex = texture2D(uMap, gl_PointCoord);
  if (tex.a * uOpacity < ${f(ALPHA_TEST)}) discard;
  gl_FragColor = vec4(vColor * uTint * tex.rgb, tex.a * uOpacity);
}
`;

/* ============================================================================
 * 幕布层顶点着色器（uWarp/uWarpDist 驱动的全屏渡越 — 静止态 mod 恒等）
 * ========================================================================== */
const curtainVertexShader = (o: CurtainShaderOpts): string => `
uniform float uTime;
uniform float uWarp;
uniform float uWarpDist;
uniform float uSize;
uniform float uScale;
attribute vec3 color;
attribute float aSeed;
varying vec3 vColor;
float warpHash(float n) { return fract(sin(n * ${f(WARP_GLSL.hashMul)}) * ${f(WARP_GLSL.hashScale)}); }
void main() {
  float wSeed = aSeed;
  float wHash = warpHash(wSeed);
  /* 1) 差速推进 + 无缝环绕（静止态 uWarpDist=0 → mod 恒等，位置不变） */
  float wz = mod(position.z + uWarpDist * (${f(o.speedBase)} + wHash * ${f(o.speedVar)}) + ${f(o.center)}, ${f(o.span)}) - ${f(o.center)};
  /* 2) 边界消散：远端淡入 / 近端淡出（仅渡越强度下激活，静止全显） */
  float wFadePos = smoothstep(${f(o.fadeNear[0])}, ${f(o.fadeNear[1])}, wz) * (1.0 - smoothstep(${f(o.fadeFar[0])}, ${f(o.fadeFar[1])}, wz));
  float wFade = mix(1.0, wFadePos, clamp(uWarp * ${f(WARP_GLSL.fadeRamp)}, 0.0, 1.0));
  /* 3) 螺旋卷积：半径衰减偏转（近轴快远轴慢 — 非均匀卷积） */
  float wAng = uWarp * ${f(o.swirl)} / (1.0 + (length(position.xy) + 1.0) * ${f(WARP_GLSL.swirlRadiusK)});
  float wCa = cos(wAng), wSa = sin(wAng);
  vec2 wXY = vec2(position.x * wCa - position.y * wSa, position.x * wSa + position.y * wCa);
  /* 4) 收缩：向消失点汇聚（uWarp 驱动，渡越结束归位） */
  wXY *= 1.0 - uWarp * ${f(o.shrink)} * (${f(WARP_GLSL.shrinkScatterLo)} + wHash * ${f(WARP_GLSL.shrinkScatterVar)});
  /* 5) 渡越噪声扰动：双频复合 + 逐粒子相位（拒绝整齐划一） */
  float wN1 = sin(wXY.y * ${f(WARP_GLSL.noiseFreq1Y)} + uTime * ${f(WARP_GLSL.noiseFreq1T)} + wSeed * ${f(WARP_GLSL.tau)});
  float wN2 = sin(wXY.y * ${f(WARP_GLSL.noiseFreq2Y)} - uTime * ${f(WARP_GLSL.noiseFreq2T)} + wHash * ${f(WARP_GLSL.twoTau)});
  wXY.x += uWarp * ${f(o.noiseAmp)} * (wN1 * ${f(WARP_GLSL.noiseMixA)} + wN2 * ${f(WARP_GLSL.noiseMixB)});
  wXY.y += uWarp * ${f(o.noiseAmp)} * ${f(WARP_GLSL.noiseAmp2Ratio)} * cos(wXY.x * ${f(WARP_GLSL.noiseFreq3X)} + uTime * ${f(WARP_GLSL.noiseFreq3T)} + wSeed * ${f(WARP_GLSL.noiseSeedPhi)});
  /* 6) 静止态低强度连续漂移（逐粒子独立相位） */
  wXY.x += sin(uTime * ${f(WARP_GLSL.idleFreqX)} + wSeed * ${f(WARP_GLSL.tau)}) * ${f(o.idleDrift)};
  wXY.y += cos(uTime * ${f(WARP_GLSL.idleFreqY)} + wSeed * ${f(WARP_GLSL.idlePhaseB)}) * ${f(o.idleDrift)} * ${f(WARP_GLSL.idleAmpRatio)};
  vColor = color * wFade;
  vec4 mvPosition = modelViewMatrix * vec4(wXY, wz, 1.0);
  /* 透视尺寸衰减（等效 PointsMaterial sizeAttenuation — CSS 标称跨 DPR 恒定） */
  gl_PointSize = uSize * (uScale / -mvPosition.z);
  gl_Position = projectionMatrix * mvPosition;
}
`;

/* ============================================================================
 * 轨道层顶点着色器（位置 = 轨道参数的确定性函数 — 开普勒 + 引力缠绕）
 * position attribute 仅用于包围球求值（静止轨道位置），实际位移完全
 * 由 aOrbit 求值。
 * ========================================================================== */
const orbitVertexShader = (o: OrbitShaderOpts): string => `
uniform float uTime;
uniform float uWarp;
uniform float uSwirl;
uniform float uLag;
uniform float uSize;
uniform float uScale;
uniform vec2 uPivot;
attribute vec3 color;
attribute float aSeed;
attribute vec4 aOrbit; // x: r0, y: θ0, z: ω, w: z0
varying vec3 vColor;
float warpHash(float n) { return fract(sin(n * ${f(ORBIT_GLSL.hashMul)}) * ${f(ORBIT_GLSL.hashScale)}); }
void main() {
  float oH = warpHash(aSeed);
  float oT = uTime - uLag; /* 残影层：开普勒项相位滞后采样历史位置 */
  /* 1) 引力缠绕：uSwirl 为符号包络积分（正渡 +/逆渡 −）— 角度恒
   *    连续，序列内绝不回退；半径衰减（内圈缠绕快外圈慢，非刚体） */
  float oSw = uSwirl * ${f(o.swirlGain)} / (1.0 + aOrbit.x * ${f(ORBIT_GLSL.swirlRadiusK)}) * (${f(ORBIT_GLSL.swirlScatterLo)} + ${f(ORBIT_GLSL.swirlScatterVar)} * oH);
  float oTh = aOrbit.y + aOrbit.z * oT + oSw;
  /* 2) 半径收缩：瞬时包络脉冲（消散即释放 — 引力井松开） */
  float oR = aOrbit.x * (1.0 - uWarp * ${f(o.shrinkGain)} * (${f(ORBIT_GLSL.shrinkScatterLo)} + ${f(ORBIT_GLSL.shrinkScatterVar)} * oH));
  vec2 oP = uPivot + vec2(oR * cos(oTh), oR * sin(oTh));
  /* 3) 渡越噪声：双频复合 + 当前轨道角驱动（拖尾层噪声随弧线弯曲） */
  float oN1 = sin(oTh * ${f(ORBIT_GLSL.noiseFreq1)} + uTime * ${f(ORBIT_GLSL.noiseFreq1T)} + aSeed * ${f(ORBIT_GLSL.tau)});
  float oN2 = cos(oTh * ${f(ORBIT_GLSL.noiseFreq2)} - uTime * ${f(ORBIT_GLSL.noiseFreq2T)} + oH * ${f(ORBIT_GLSL.twoTau)});
  oP.x += uWarp * ${f(o.noiseAmp)} * (oN1 * ${f(ORBIT_GLSL.noiseMixA)} + oN2 * ${f(ORBIT_GLSL.noiseMixB)});
  oP.y += uWarp * ${f(o.noiseAmp)} * ${f(ORBIT_GLSL.noiseAmp2Ratio)} * sin(oTh * ${f(ORBIT_GLSL.noiseFreq3)} + uTime * ${f(ORBIT_GLSL.noiseFreq3T)} + aSeed * ${f(ORBIT_GLSL.noiseSeedPhi)});
  /* 4) 静止态低强度连续漂移（逐粒子独立相位，杜绝机械静止） */
  oP.x += sin(oT * ${f(ORBIT_GLSL.idleFreqX)} + aSeed * ${f(ORBIT_GLSL.tau)}) * ${f(o.idleDrift)};
  oP.y += cos(oT * ${f(ORBIT_GLSL.idleFreqY)} + aSeed * ${f(ORBIT_GLSL.idlePhaseB)}) * ${f(o.idleDrift)} * ${f(ORBIT_GLSL.idleAmpRatio)};
  /* 5) 核心吞没（★ 星团消失根治）：内圈粒子随渡越 smoothstep 压暗
   *    可见度下限 0.34：吞没深度映射至 [0.34, 1] 而非 [0, 1] —
   *    旧实现核心棒整团（~360 粒）渡越期亮度归零 = 星系中心星团
   *    突然消失、渡越结束整团复现。下限保留星团轮廓恒可辨（压暗至
   *    ~46%，含 ×1.35 吸积补偿），吞没语义仍在：内圈深吞、外圈渐亮，
   *    全程连续无跳变 */
  float oCoreRaw = ${f(o.coreFadeR)} > 0.5 ? smoothstep(${f(o.coreFadeR)} * ${f(ORBIT_GLSL.coreEdge)}, ${f(o.coreFadeR)}, oR) : 1.0;
  float oCore = ${f(ORBIT_GLSL.coreFloor)} + ${f(ORBIT_GLSL.coreSpan)} * oCoreRaw;
  vColor = color * mix(1.0, oCore * ${f(ORBIT_GLSL.coreBoost)}, clamp(uWarp * ${f(ORBIT_GLSL.coreRamp)}, 0.0, 1.0));
  vec4 mvPosition = modelViewMatrix * vec4(oP, aOrbit.w + uWarp * ${f(o.noiseAmp)} * ${f(ORBIT_GLSL.zNoiseRatio)} * oN1, 1.0);
  gl_PointSize = uSize * (uScale / -mvPosition.z);
  gl_Position = projectionMatrix * mvPosition;
}
`;

/* ============================================================================
 * 材质工厂与层构建
 * ========================================================================== */

/** 轨道层单层 uniform 集（每层独立 uSwirl/uLag/动画参数；uTime/uWarp 为共享引用） */
export interface OrbitUniforms {
  uTime: { value: number };
  uWarp: { value: number };
  /** 符号缠绕积分（本体=当前值；残影=t-lag 历史值 → 弧形拖尾） */
  uSwirl: { value: number };
  uLag: { value: number };
  uPivot: { value: THREE.Vector2 };
  /** 帧循环动画：尺寸（基线+包络增幅）/ 透明度 / 色调（银河盘偏冷青） */
  uSize: { value: number };
  uOpacity: { value: number };
  uTint: { value: THREE.Color };
}

/** 轨道层成员（本体或残影）：Points + uniform 引用 + 透明度基线 */
export interface OrbitLayerMember {
  points: THREE.Points;
  uniforms: OrbitUniforms;
  /** 静止态透明度基线（帧循环 = baseOpacity × TRAIL_RESPONSE 混合） */
  baseOpacity: number;
}

/** 轨道层构建结果（接口 — 元组返回根除）：Group 承载姿态（恒定锁定） */
export interface OrbitLayer {
  group: THREE.Group;
  /** 本体（uLag = 0） */
  body: OrbitLayerMember;
  /** 残影拖尾层（开普勒项 + 缠绕积分双历史采样 → 渡越时真实弧形拖尾） */
  trails: OrbitLayerMember[];
}

/** 轨道层构建参数 */
export interface OrbitLayerSpec {
  /** 轨道物理实例参数（缠绕/收缩/吞没/噪声/漂移增益） */
  orbit: OrbitShaderOpts;
  /** 轨道中心（银河盘原点 / 近景画面外偏置枢轴） */
  pivot: THREE.Vector2;
  /** 本体基准尺寸（CSS 世界单位 — 透视衰减前标称值） */
  size: number;
  /** 本体基准透明度 */
  opacity: number;
}

function createOrbitMember(
  geometry: THREE.BufferGeometry,
  spec: OrbitLayerSpec,
  lag: number,
  size: number,
  opacity: number,
  shared: SharedWarpUniforms,
  map: THREE.Texture,
  renderOrder?: number,
): OrbitLayerMember {
  const uniforms: OrbitUniforms = {
    uTime: shared.uTime,
    uWarp: shared.uWarp,
    uSwirl: { value: 0 },
    uLag: { value: lag },
    uPivot: { value: spec.pivot },
    uSize: { value: size },
    uOpacity: { value: opacity },
    uTint: { value: new THREE.Color(1, 1, 1) },
  };
  const material = new THREE.ShaderMaterial({
    uniforms: {
      uTime: uniforms.uTime,
      uWarp: uniforms.uWarp,
      uSwirl: uniforms.uSwirl,
      uLag: uniforms.uLag,
      uPivot: uniforms.uPivot,
      uSize: uniforms.uSize,
      uOpacity: uniforms.uOpacity,
      uTint: uniforms.uTint,
      uMap: { value: map },
      uScale: shared.uScale,
    },
    vertexShader: orbitVertexShader(spec.orbit),
    fragmentShader,
    transparent: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
  const points = new THREE.Points(geometry, material);
  if (renderOrder !== undefined) points.renderOrder = renderOrder;
  return { points, uniforms, baseOpacity: opacity };
}

/**
 * 构建轨道粒子层：本体 + 残影拖尾层（共享 geometry，独立材质/uLag/uSwirl）。
 * 每帧 CPU 为各层写 uSwirl（本体=当前积分，残影=t-lag 历史积分）。
 */
export function buildOrbitLayer(
  geometry: THREE.BufferGeometry,
  spec: OrbitLayerSpec,
  shared: SharedWarpUniforms,
  map: THREE.Texture,
): OrbitLayer {
  const group = new THREE.Group();
  const body = createOrbitMember(geometry, spec, 0, spec.size, spec.opacity, shared, map);
  group.add(body.points);
  const trails = TRAIL_SPECS.map((s) => {
    const member = createOrbitMember(
      geometry,
      spec,
      s.lag,
      spec.size * s.sizeScale,
      spec.opacity * s.opacity,
      shared,
      map,
      -1, // 残影先绘（加性混合顺序无关，保持语义）
    );
    group.add(member.points);
    return member;
  });
  return { group, body, trails };
}

/* ============================================================================
 * 幕布层材质（远景星点 — 全屏渡越收缩样式）
 * ========================================================================== */

/** 幕布层帧循环动画 uniform 引用（尺寸/透明度 — 包络调制） */
export interface CurtainShaderUniforms {
  uSize: { value: number };
  uOpacity: { value: number };
}

export interface CurtainMaterialBundle {
  material: THREE.ShaderMaterial;
  uniforms: CurtainShaderUniforms;
}

export function createCurtainMaterial(
  o: CurtainShaderOpts,
  size: number,
  opacity: number,
  shared: SharedWarpUniforms,
  map: THREE.Texture,
): CurtainMaterialBundle {
  const uniforms: CurtainShaderUniforms = {
    uSize: { value: size },
    uOpacity: { value: opacity },
  };
  const material = new THREE.ShaderMaterial({
    uniforms: {
      uTime: shared.uTime,
      uWarp: shared.uWarp,
      uWarpDist: shared.uWarpDist,
      uScale: shared.uScale,
      uMap: { value: map },
      uSize: uniforms.uSize,
      uOpacity: uniforms.uOpacity,
      uTint: { value: new THREE.Color(1, 1, 1) },
    },
    vertexShader: curtainVertexShader(o),
    fragmentShader,
    transparent: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
  return { material, uniforms };
}
