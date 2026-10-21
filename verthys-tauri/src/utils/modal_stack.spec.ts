/*
 * modal_stack.spec.ts — 模态层栈与滚动锁
 *
 * 覆盖：栈序决定 Esc 归属（只有栈顶可响应）、滚动锁按层计数（内层关闭不解锁）、
 * 未入栈身份的出栈为无副作用空操作（不得误减他人持有的锁）。
 *
 * 说明：被测模块只读写 document.body.style.overflow，故以最小 document 桩
 * 在 node 环境下验证，不引入浏览器环境依赖。
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { isTopModal, popModal, pushModal } from "./modal_stack";

const bodyStyle = { overflow: "" };

beforeEach(() => {
  vi.stubGlobal("document", { body: { style: bodyStyle } });
  bodyStyle.overflow = "auto";
});

describe("模态栈", () => {
  it("只有栈顶身份可响应 Esc", () => {
    const editor = Symbol("editor");
    const confirm = Symbol("confirm");

    pushModal(editor);
    expect(isTopModal(editor)).toBe(true);

    pushModal(confirm);
    expect(isTopModal(confirm)).toBe(true);
    // 编辑器仍在栈内，但已不是栈顶：不得同时响应同一次 Esc
    expect(isTopModal(editor)).toBe(false);

    popModal(confirm);
    expect(isTopModal(editor)).toBe(true);

    popModal(editor);
    expect(isTopModal(editor)).toBe(false);
  });
});

describe("滚动锁", () => {
  it("按层计数：内层关闭不解锁，最后一层关闭才归还原值", () => {
    const outer = Symbol("outer");
    const inner = Symbol("inner");

    pushModal(outer);
    expect(bodyStyle.overflow).toBe("hidden");

    pushModal(inner);
    popModal(inner);
    expect(bodyStyle.overflow).toBe("hidden");

    popModal(outer);
    expect(bodyStyle.overflow).toBe("auto");
  });

  it("未入栈身份的出栈不改变锁状态，也不影响栈顶判定", () => {
    const owner = Symbol("owner");
    const stranger = Symbol("stranger");

    pushModal(owner);
    expect(popModal(stranger)).toBe(false);
    expect(bodyStyle.overflow).toBe("hidden");
    expect(isTopModal(owner)).toBe(true);

    popModal(owner);
    expect(bodyStyle.overflow).toBe("auto");
  });
});
