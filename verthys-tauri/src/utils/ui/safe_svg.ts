const SVG_NS = "http://www.w3.org/2000/svg";

const ALLOWED_TAGS = new Set([
  "svg",
  "g",
  "path",
  "circle",
  "rect",
  "line",
  "polyline",
  "polygon",
  "ellipse",
  "defs",
  "lineargradient",
  "radialgradient",
  "stop",
  "title",
  "desc",
]);

const ALLOWED_ATTRS = new Set([
  "viewbox",
  "fill",
  "stroke",
  "stroke-width",
  "stroke-linecap",
  "stroke-linejoin",
  "stroke-miterlimit",
  "d",
  "cx",
  "cy",
  "r",
  "x",
  "y",
  "width",
  "height",
  "rx",
  "ry",
  "points",
  "x1",
  "x2",
  "y1",
  "y2",
  "opacity",
  "fill-rule",
  "clip-rule",
  "transform",
  "offset",
  "stop-color",
  "stop-opacity",
  "id",
  "class",
  "xmlns",
  "preserveaspectratio",
  "aria-hidden",
  "focusable",
  "role",
]);

/** SVG 规范中大小写敏感的属性名；其余属性统一使用小写形式。 */
const ATTR_NAME_CASE: Record<string, string> = {
  viewbox: "viewBox",
  preserveaspectratio: "preserveAspectRatio",
};

/**
 * 将 SVG 标记解析为安全的 DOM 节点。
 *
 * 仅接受 SVG 命名空间与白名单元素/属性；脚本、事件处理属性、外部引用
 * 与未知元素一律丢弃。解析失败或根节点不是 svg 时返回 null。
 *
 * 解析结果在 SVG 命名空间中重建：XML 解析器对缺少 xmlns 的片段返回无命名
 * 空间节点，直接导入 HTML 文档后不会按 SVG 渲染（表现为图标空白）。
 */
export function sanitizeSvg(source: string): SVGSVGElement | null {
  if (!source || typeof source !== "string") return null;
  const parsed = new DOMParser().parseFromString(source, "image/svg+xml");
  if (parsed.getElementsByTagName("parsererror").length > 0) return null;
  const sourceRoot = parsed.documentElement;
  if (!sourceRoot || sourceRoot.localName.toLowerCase() !== "svg") return null;

  const root = document.createElementNS(SVG_NS, "svg");
  copyAllowedAttributes(sourceRoot, root);
  appendAllowedChildren(sourceRoot, root);
  return root;
}

function copyAllowedAttributes(from: Element, to: Element): void {
  for (const attr of Array.from(from.attributes)) {
    const lower = attr.name.toLowerCase();
    if (!ALLOWED_ATTRS.has(lower)) continue;
    if (attr.namespaceURI !== null) continue;
    const name = ATTR_NAME_CASE[lower] ?? lower;
    try {
      to.setAttributeNS(null, name, attr.value);
    } catch {
      /* 非法属性名直接丢弃，不影响其余图形 */
    }
  }
}

function appendAllowedChildren(from: Element, to: Element): void {
  for (const child of Array.from(from.children)) {
    const lower = child.localName.toLowerCase();
    if (lower === "svg" || !ALLOWED_TAGS.has(lower)) continue;
    const element = document.createElementNS(SVG_NS, child.localName);
    copyAllowedAttributes(child, element);
    appendAllowedChildren(child, element);
    to.appendChild(element);
  }
}
