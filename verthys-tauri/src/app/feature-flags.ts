/*
 * app/feature-flags.ts — 性能优化项独立回滚开关
 * =============================================================================
 * 【定位】性能根治设计五项优化的独立回滚体系：每项优化可经 flag 单独
 * 切换，发现问题时精确回滚单项，不影响其余优化项。
 *
 * 【回滚语义（按优化项的实际作用层）】
 *   - opaqueCanvas：运行时开关 — ParticleBackground 渲染器创建时消费
 *     （false → 回退 alpha:true 透明画布 + 透明清屏色，走 alpha 合成路径）；
 *   - instancedMesh / cssAnimations / backdropOptimized / cssAnimAlternatives：
 *     提交级回滚注册表 — 对应优化已深度融入渲染架构与样式表（无并存的
 *     旧代码路径），flag 为该项优化的权威启用标记与回滚锚点：回滚 =
 *     flag 置 false 并 revert 对应提交（git 层面精确单项回退）。
 *
 * 【覆盖机制】生产默认全启用；开发/诊断期可经 localStorage 注入覆盖
 *   （键 Verthys:perf-flags，值为 PerfFlags 的 JSON 子集，仅接受布尔
 *   字段，损坏输入静默忽略回退默认 — fail-safe）。
 *   示例：localStorage.setItem("Verthys:perf-flags", '{"opaqueCanvas":false}')
 * ========================================================================== */

/** 性能优化项回滚开关（字段名为权威启用标记，禁止更名） */
export interface PerfFlags {
  /** 粒子 GPU 实例化（轨道参数预烘焙 + 顶点着色器内求值） */
  instancedMesh: boolean;
  /** CosmicBackground CSS 合成器动画（163 元素 JS 驱动 → CSS keyframes） */
  cssAnimations: boolean;
  /** backdrop-filter 精确治理（大面积 → 半透明纯色 + 渐变） */
  backdropOptimized: boolean;
  /** 不透明画布（alpha:false 快速合成路径，运行时开关） */
  opaqueCanvas: boolean;
  /** CSS 动画合成器友好替代（box-shadow/height/drop-shadow 治理） */
  cssAnimAlternatives: boolean;
}

/** 生产默认：五项优化全部启用 */
const DEFAULT_FLAGS: PerfFlags = {
  instancedMesh: true,
  cssAnimations: true,
  backdropOptimized: true,
  opaqueCanvas: true,
  cssAnimAlternatives: true,
};

/** localStorage 覆盖键（命名空间前缀防碰撞） */
const FLAGS_STORAGE_KEY = "Verthys:perf-flags";

/** 已知 flag 字段集合（覆盖解析白名单 — 未知字段静默丢弃） */
const KNOWN_FLAG_KEYS = new Set<keyof PerfFlags>([
  "instancedMesh",
  "cssAnimations",
  "backdropOptimized",
  "opaqueCanvas",
  "cssAnimAlternatives",
]);

/**
 * 解析生效 flag 集：默认值 → localStorage 覆盖合并。
 *
 * 容错契约：localStorage 不可用（隐私模式/序列化异常/JSON 损坏）或覆盖值
 * 类型非法时，静默回退默认值 — 诊断覆盖机制绝不阻断应用启动。
 */
function resolveFlags(): PerfFlags {
  const flags: PerfFlags = { ...DEFAULT_FLAGS };

  if (typeof window === "undefined" || typeof window.localStorage === "undefined") {
    return flags;
  }

  try {
    const raw = window.localStorage.getItem(FLAGS_STORAGE_KEY);
    if (!raw) return flags;

    const overrides: unknown = JSON.parse(raw);
    if (typeof overrides !== "object" || overrides === null) return flags;

    for (const [key, value] of Object.entries(overrides as Record<string, unknown>)) {
      if (KNOWN_FLAG_KEYS.has(key as keyof PerfFlags) && typeof value === "boolean") {
        flags[key as keyof PerfFlags] = value;
      }
    }
  } catch {
    // 损坏输入：静默忽略，全部回退默认（fail-safe）
  }

  return flags;
}

/** 生效 flag 集（模块级单例 — 启动时解析一次，全应用只读消费） */
export const perfFlags: Readonly<PerfFlags> = resolveFlags();

/* 开发构建启动摘要（可观测性：flag 生效状态一眼可查） */
if (import.meta.env.DEV) {
  console.info("[perf-flags] %o", perfFlags);
}
