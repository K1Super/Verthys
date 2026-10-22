// @vitest-environment happy-dom
import { describe, expect, it } from "vitest";
import { sanitizeSvg } from "./safe_svg";

describe("sanitizeSvg", () => {
  it("保留白名单内的 SVG 结构与属性", () => {
    const svg = sanitizeSvg(
      '<svg viewBox="0 0 24 24" fill="none"><path d="M0 0h24v24H0z" stroke="currentColor"/></svg>',
    );
    expect(svg).not.toBeNull();
    expect(svg?.namespaceURI).toBe("http://www.w3.org/2000/svg");
    expect(svg?.querySelector("path")?.namespaceURI).toBe("http://www.w3.org/2000/svg");
    expect(svg?.querySelector("path")?.getAttribute("d")).toBe("M0 0h24v24H0z");
    expect(svg?.getAttribute("viewBox")).toBe("0 0 24 24");
  });

  it("丢弃脚本、事件属性与外部引用", () => {
    const svg = sanitizeSvg(
      '<svg onload="alert(1)"><script>alert(1)</script><path d="M0 0" onclick="alert(1)" href="https://x"/></svg>',
    );
    expect(svg).not.toBeNull();
    expect(svg?.querySelector("script")).toBeNull();
    expect(svg?.getAttribute("onload")).toBeNull();
    const path = svg?.querySelector("path");
    expect(path?.getAttribute("onclick")).toBeNull();
    expect(path?.getAttribute("href")).toBeNull();
  });

  it("丢弃非白名单元素", () => {
    const svg = sanitizeSvg(
      '<svg><foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject><circle cx="1" cy="1" r="1"/></svg>',
    );
    expect(svg).not.toBeNull();
    expect(svg?.querySelector("foreignObject")).toBeNull();
    expect(svg?.querySelector("circle")).not.toBeNull();
  });

  it("拒绝非 SVG 根节点与损坏标记", () => {
    expect(sanitizeSvg("<div>not svg</div>")).toBeNull();
    expect(sanitizeSvg("<svg><path></svg>")).toBeNull();
    expect(sanitizeSvg("")).toBeNull();
  });
});
