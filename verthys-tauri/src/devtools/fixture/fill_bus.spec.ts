// @vitest-environment happy-dom
import { describe, expect, it, vi } from "vitest";
import {
  DEV_FIXTURE_FILL_EVENT,
  publishFixtureFill,
  type DevFixtureFillPayload,
} from "./fill_bus";

describe("开发夹具填充事件", () => {
  it("按契约派发填充载荷", () => {
    const handler = vi.fn();
    const listener = (event: Event): void => {
      handler((event as CustomEvent<DevFixtureFillPayload>).detail);
    };
    window.addEventListener(DEV_FIXTURE_FILL_EVENT, listener);

    publishFixtureFill({
      target: "global",
      globalPassword: "fixture-global",
      binPassword: "fixture-bin",
      binKeyfilePath: "C:\\fixture\\key.bin",
    });

    window.removeEventListener(DEV_FIXTURE_FILL_EVENT, listener);
    expect(handler).toHaveBeenCalledWith({
      target: "global",
      globalPassword: "fixture-global",
      binPassword: "fixture-bin",
      binKeyfilePath: "C:\\fixture\\key.bin",
    });
  });
});
