// @vitest-environment happy-dom
/*
 * RecoveryUnlockDialog.spec.ts — 恢复码弹层清洁性契约
 *
 * 覆盖：关闭后组件内恢复码清零、重新打开不残留上次输入、提交后父组件
 * 关闭再打开同样为空。断言口径：恢复码不得在组件状态中长期驻留。
 */
import { afterEach, describe, expect, it } from "vitest";
import { createApp, h, nextTick, reactive, type App } from "vue";

import RecoveryUnlockDialog from "./RecoveryUnlockDialog.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
  document.body.innerHTML = "";
});

function mountDialog(onSubmit: (code: string) => void = () => {}) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const state = reactive({ show: true });
  const app = createApp({
    render: () =>
      h(RecoveryUnlockDialog, {
        show: state.show,
        submitting: false,
        onSubmit,
      }),
  });
  app.mount(container);
  mounted.push({ app, container });
  return state;
}

function input(): HTMLInputElement {
  const el = document.querySelector<HTMLInputElement>(".vif-input");
  if (!el) throw new Error("缺少恢复码输入框");
  return el;
}

function setValue(el: HTMLInputElement, value: string) {
  el.value = value;
  el.dispatchEvent(new Event("input"));
}

async function settle() {
  await Promise.resolve();
  await nextTick();
}

describe("RecoveryUnlockDialog", () => {
  it("关闭后清空，重新打开不残留上次输入", async () => {
    const state = mountDialog();
    await settle();
    setValue(input(), "AAAA-BBBB-CCCC-DDDD");
    await settle();
    expect(input().value).toBe("AAAA-BBBB-CCCC-DDDD");

    state.show = false;
    await nextTick();
    state.show = true;
    await settle();

    expect(input().value).toBe("");
  });

  it("提交后父组件关闭再打开：组件内恢复码为空", async () => {
    const submitted: string[] = [];
    const state = mountDialog((code) => submitted.push(code));
    await settle();
    setValue(input(), "EEEE-FFFF-0000-1111");
    await settle();

    const confirm = document.querySelector<HTMLButtonElement>(".kv-confirm");
    if (!confirm) throw new Error("缺少提交按钮");
    confirm.click();
    await settle();
    expect(submitted).toEqual(["EEEE-FFFF-0000-1111"]);

    // 父组件在成功后置 show=false；再次打开时不得残留已提交的码
    state.show = false;
    await nextTick();
    state.show = true;
    await settle();
    expect(input().value).toBe("");
  });
});
