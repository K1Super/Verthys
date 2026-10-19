/// <reference types="node" />
/*
 * text_sharpness.spec.ts — 文字清晰度铁律守卫（入场动画只允许 opacity）
 *
 * 用途：把「承载文字的层，其入场/揭示动画只允许 opacity」从口头约定升级为可复跑断言。
 *   机制：任何 transform（位移或缩放）或 filter（模糊）都会把该层提升为合成层，
 *   合成层使用灰度抗锯齿；动画结束、transform 归零回落主层时字形重新子像素化 ——
 *   观感即"忽然模糊、随即变清晰"。故承载文字的入场动画一律只走 opacity；
 *   确需运动感时，把位移/缩放交给不承载文字的装饰层（见 cosmic-tip 的光晕层）。
 *
 * 维护约定：新增承载文字的入场动画，必须在本文件的登记表中补一行；
 *   新增承载文字的揭示/过渡规则（非关键帧形态，如 hover 揭示标签），
 *   必须登记到 TEXT_BEARING_REVEALS 表；装饰层动画（纯图形、无文字）不入表。
 *
 * 边界（有意排除，非遗漏）：交互动效（如校验失败的一次性抖动反馈）属瞬时
 *   反馈信号，其合成层重采样被短时长与强语义掩盖，不在本条约束内 ——
 *   本条只约束入场/揭示，即「成形后应恒定清晰」的那些层。
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

const read = (rel: string): string => readFileSync(new URL(rel, import.meta.url), "utf8");

/** 已登记的「承载文字的入场动画」：文件 + 关键帧名 */
const TEXT_BEARING_ENTRANCES: readonly { file: string; name: string }[] = [
  /* 模块步入编排（模块根渡越 + 模块工具条/顶栏 + 内容条目）— 全局单一权威源 */
  { file: "./animations.css", name: "module-reveal" },
  { file: "./animations.css", name: "module-reveal-out" },
  { file: "./reg-desk.css", name: "reg-panel-in" },
  { file: "./reg-desk.css", name: "reg-sec-in" },
  { file: "./reg-desk.css", name: "reg-row-in" },
  { file: "./reg-desk.css", name: "reg-error-in" },
  { file: "./animations.css", name: "dialog-in" },
  { file: "../components/common/verthys-ui/VaultCardFilter.vue", name: "filter-panel-in" },
  { file: "../components/modules/PhotoAlbum.vue", name: "select-bar-enter" },
  { file: "../components/modules/PhotoAlbum.vue", name: "dialog-in" },
];

/** 已登记的「承载文字的揭示/过渡规则」：文件 + 选择器。
 *  登记前置条件：选择器须独占规则行首（不可为复合选择器的尾部形态 ——
 *  否则与同名元素的其它规则无法区分）。
 *  这些规则体内不得出现 transform / filter，也不得过渡 transform：
 *  两者都会把字形提升为合成层并按亚像素偏移重采样，收束时再子像素化，
 *  观感即「忽然模糊、随即清晰」。 */
const TEXT_BEARING_REVEALS: readonly { file: string; selector: string }[] = [
  { file: "../components/main-view/DockNav.vue", selector: ".dock-label" },
  { file: "../components/main-view/DockNav.vue", selector: ".dock-item:hover .dock-label" },
  /* 中枢管理视图切换：三态视图均承载文字（模块节点标签 / 分区读数），
   * 揭示与离场一律只走不透明度 + 全局步入编排包络 */
  { file: "./security/mgmt-hub.css", selector: ".mgmt-x-enter-active" },
  { file: "./security/mgmt-hub.css", selector: ".mgmt-x-leave-active" },
  { file: "./security/mgmt-hub.css", selector: ".mgmt-x-enter-from" },
  { file: "./security/mgmt-hub.css", selector: ".mgmt-x-leave-to" },
  /* 量子态势面板承载文字的静态层：不得自带 transform / filter ——
   * 缩放归装饰环（引擎逐帧写入），两层 DOM 与圆环、三个模块、三条连线
   * 同为零视差组（引擎不写任何层位移）。
   * 注：模块节点已改为无文字（图标 + 刻度环），故本条只登记核心文字簇 */
  { file: "./security/qd-panel.css", selector: ".qd-core-cluster" },
  { file: "./security/qd-panel.css", selector: ".qd-core-text" },
  { file: "./security/qd-panel.css", selector: ".qd-core-label" },
  { file: "./security/qd-panel.css", selector: ".qd-core-hint" },
];

/** 去注释：断言只针对声明本身 —— 注释里的措辞（如「严禁过渡 transform」）
 *  不得被当作 transform 声明命中 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ");
}

/** 属性声明匹配：property 前须为行首或分隔符 ——
 *  避免把 text-transform / -webkit-filter 这类同尾词误判为本属性 */
const TRANSFORM_DECL = /(?:^|[;\s])transform\s*:/;
const FILTER_DECL = /(?:^|[;\s])(?:-webkit-)?filter\s*:/;
const TRANSITION_MOTION = /transition[^;]*\b(?:transform|filter)\b/;

/** 取某个关键帧的声明体（按花括号配平截取，单行与多行写法均覆盖） */
function keyframeBody(source: string, name: string): string {
  const start = source.search(new RegExp(`@keyframes\\s+${name}\\s*\\{`));
  if (start < 0) return "";
  const open = source.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === "{") {
      depth += 1;
    } else if (source[i] === "}") {
      depth -= 1;
      if (depth === 0) return stripComments(source.slice(open + 1, i));
    }
  }
  return "";
}

/** 取某选择器的规则体（选择器按行首匹配；空白按一个及以上空白符匹配，
 *  故多行书写与紧凑书写均覆盖） */
function ruleBody(source: string, selector: string): string {
  const pattern = selector
    .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    .replace(/ /g, "\\s+");
  const body = source.match(new RegExp(`^\\s*${pattern}\\s*\\{([^}]*)\\}`, "m"))?.[1] ?? "";
  return stripComments(body);
}

describe("文字清晰度：入场动画只走 opacity", () => {
  it("登记的入场关键帧内部不含 transform / filter", () => {
    for (const { file, name } of TEXT_BEARING_ENTRANCES) {
      const body = keyframeBody(read(file), name);
      expect(body, `${file}#${name} 未找到关键帧`).not.toBe("");
      expect(body, `${file}#${name}`).not.toMatch(TRANSFORM_DECL);
      expect(body, `${file}#${name}`).not.toMatch(FILTER_DECL);
      expect(body, `${file}#${name}`).toMatch(/opacity\s*:/);
    }
  });

  it("模块渡越（ModuleStage）的进出场不携带 transform", () => {
    const stage = read("../components/main-view/ModuleStage.vue");
    for (const selector of [".module-switch-enter-from", ".module-switch-leave-to"]) {
      const body = stage.match(new RegExp(`\\${selector}\\s*\\{([^}]*)\\}`))?.[1] ?? "";
      expect(body, selector).not.toBe("");
      expect(body, selector).not.toMatch(TRANSFORM_DECL);
    }
    for (const selector of [".module-switch-enter-active", ".module-switch-leave-active"]) {
      const body = stage.match(new RegExp(`\\${selector}\\s*\\{([^}]*)\\}`))?.[1] ?? "";
      expect(body, selector).not.toMatch(/transition[^;]*transform/);
    }
  });

  it("悬浮提示（cosmic-tip）的揭示不携带 transform / filter，运动交给装饰层", () => {
    const css = read("./components.css");
    const tipBody = css.match(/\.cosmic-tip\s*\{([^}]*)\}/)?.[1] ?? "";
    expect(tipBody).not.toBe("");
    expect(tipBody).not.toMatch(TRANSFORM_DECL);
    const animations = read("./animations.css");
    // 运动只允许存在于装饰层关键帧（光晕层），且该层不承载文字
    expect(keyframeBody(animations, "ct-glow-rise")).toMatch(TRANSFORM_DECL);
    expect(css).toMatch(/\.cosmic-tip\.ct-show \.ct-glow\s*\{[^}]*ct-glow-rise/);
  });

  it("模块步入编排：窗口宿主与常显类均存在，且不携带 transform", () => {
    const css = read("./animations.css");
    /* 内容条目显现必须由步入窗口宿主开启 (.reveal-host.is-entering) ——
     * 窗口外的动态挂载（虚拟滚动换行 / 数据增量）不得再播放入场动画 */
    const hostRule = ruleBody(css, ".reveal-host.is-entering .reveal-item");
    expect(hostRule, "步入窗口宿主契约未声明").toMatch(/animation\s*:\s*module-reveal/);
    expect(hostRule, "步入窗口宿主契约").not.toMatch(TRANSFORM_DECL);
    /* 常显元素显现类（模块工具条 / 顶栏 / 搜索栏） */
    const alwaysRule = ruleBody(css, ".module-reveal");
    expect(alwaysRule, "常显显现类未声明").toMatch(/animation\s*:\s*module-reveal/);
    expect(alwaysRule, "常显显现类").not.toMatch(TRANSFORM_DECL);
  });

  it("登记的「承载文字的揭示规则」不携带、也不过渡 transform / filter", () => {
    for (const { file, selector } of TEXT_BEARING_REVEALS) {
      const body = ruleBody(read(file), selector);
      expect(body, `${file}#${selector} 未找到规则`).not.toBe("");
      expect(body, `${file}#${selector}`).not.toMatch(TRANSFORM_DECL);
      expect(body, `${file}#${selector}`).not.toMatch(FILTER_DECL);
      expect(body, `${file}#${selector}`).not.toMatch(TRANSITION_MOTION);
    }
  });

  it("量子面板引擎：零视差组恒静态，逐帧变换仅作用于装饰球体", () => {
    const src = read("../composables/security-center/useQuantumField.ts");
    /* 逐帧 DOM transform 写入仅一处：装饰球体（缩放）。任何新增写入 ——
     * 尤其写向承载文字的层 —— 都会在此失败：那正是「文字发糊 / 整层逐帧
     * 重栅格」的入口。 */
    const writes = src.match(/\b[A-Za-z_$][\w$]*(?:\[[^\]]+\])?\.style\.transform\s*=\s*[^;]+;/g) ?? [];
    expect(
      writes.length,
      `逐帧 transform 写入应仅装饰球体一处，实际 ${writes.length} 处`,
    ).toBe(1);
    expect(writes[0], "唯一的逐帧变换须作用于装饰球体（.qd-node-orb）").toMatch(/orb/i);
    /* 零视差组（有意设计，圆环 + 三个模块 + 三条连线一体静态）：
     *  - 圆环整组恒绘于面板静态中心（吸积弧直接取 cx, cy）；
     *  - 方位偏移量不得残留（nearOx / nearOy、midOx / midOy 均为历史遗留）；
     *  - 三条连线起点 = 静态中心，终点 = 静态节点像素坐标；
     *  - 三个模块节点所在 DOM 层无位移写入（引擎不再持有该层引用）。
     * 圆环「背后」的氛围视差（Canvas 尘埃 / 数据碎片）不受本条约束。 */
    expect(src, "吸积弧须绘于静态中心").toMatch(/ctx\.arc\(cx, cy,/);
    expect(src, "不得残留 nearOx / nearOy").not.toMatch(/nearOx|nearOy/);
    expect(src, "不得残留 midOx / midOy").not.toMatch(/midOx|midOy/);
    expect(src, "连线起点须为静态中心").toMatch(/g\.sx = cx;\s*\n\s*g\.sy = cy;/);
    expect(src, "节点像素坐标不得叠加偏移").toMatch(/nodePx\[i\]\.x = \(p\.x \/ 100\) \* width;/);
    /* 线尾对接在环沿（绝不进入环内空间）：终点自环心沿「圆环中心 → 环心」
     * 方向回缩固定半径（LINK_DOCK_R = 环半径 + 描边外缘 + 间隙）——
     * 中空刻度环 + 悬浮字形下，终点若取环心会读作「线穿过图标、把节点串起」，
     * 故本条即该缺陷的防回退点。 */
    expect(src, "连线终点须回缩至环沿").toMatch(/const LINK_DOCK_R = \d+(?:\.\d+)?;/);
    expect(src, "连线终点不得直接取节点锚点（环心）").not.toMatch(/g\.nx = nodePx\[i\]\.x;/);
    /* 节点锚点 = 装饰环圆心（transform 上移环半径 24px）：引擎的节点像素
     * 坐标即环心 —— 连线/光水终点与落定光晕因此无需任何布局补偿常量 */
    const panel = read("./security/qd-panel.css");
    expect(
      ruleBody(panel, ".qd-module-node"),
      "节点锚点须为装饰环圆心（上移环半径 24px）",
    ).toMatch(/transform:\s*translate\(-50%,\s*-24px\)/);
    /* 卫星环饰与吸积盘同一渲染语言：环饰须由引擎 Canvas 绘制（CSS 不得残留
     * 环描边 —— DOM 侧只剩图标热区），且复用同一钟形弧段形态与路径复用机制 */
    expect(src, "卫星环饰须由引擎绘制").toMatch(/function drawSatellites\(/);
    expect(src, "卫星刻度环须构建为路径复用（禁逐帧路径构建）").toMatch(/makeSatBezelPath\(/);
    expect(src, "卫星弧段须与吸积弧共用钟形形态语言").toMatch(/SAT_BELL/);
    expect(src, "卫星环饰不得写入 DOM style（唯一逐帧写入仍为装饰环热区缩放）")
      .not.toMatch(/sat[A-Za-z]*\.style\./);
    expect(panel, "CSS 不得残留节点环描边（环饰归引擎 Canvas 管线）")
      .not.toMatch(/qd-reticle|qd-node-reticle/);
    expect(src, "节点层不得有位移写入").not.toMatch(/midEl\.style\.transform/);
    expect(src, "近层不得有位移写入").not.toMatch(/nearEl\.style\.transform/);
  });
});
