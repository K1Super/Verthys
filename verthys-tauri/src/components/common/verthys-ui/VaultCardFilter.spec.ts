// @vitest-environment happy-dom
/*
 * VaultCardFilter.spec.ts — 筛选条件与类型清单的一致性
 *
 * 覆盖：自定义类型被删除后，已选中的类型条件必须同步剔除，
 * 否则列表会被筛成空集且摘要回显原始类型 id。
 */
import { afterEach, describe, expect, it } from "vitest";
import { createApp, h, nextTick, ref, type App } from "vue";
import type { VaultTypeDef } from "../../../constants/vault_item_types";
import { createEmptyVaultFilter, type VaultFilterCriteria } from "../../../lib/vault/vault_item_filter";
import VaultCardFilter from "./VaultCardFilter.vue";

const mounted: Array<{ app: App; container: HTMLDivElement }> = [];

afterEach(() => {
  while (mounted.length > 0) {
    const entry = mounted.pop();
    entry?.app.unmount();
    entry?.container.remove();
  }
  document.body.innerHTML = "";
});

function makeType(id: string, label: string): VaultTypeDef {
  return {
    id,
    label,
    icon: "generic",
    tone: "accent",
    titleField: "f_name",
    cardFields: [],
    searchFields: ["f_name"],
    fields: [{ id: "f_name", label: "名称", kind: "text" }],
    builtin: false,
  };
}

describe("类型筛选条件收敛", () => {
  it("类型被删除后从筛选条件中剔除该类型", async () => {
    const types = ref<VaultTypeDef[]>([makeType("account", "账号"), makeType("custom:x", "旧类型")]);
    const criteria = ref<VaultFilterCriteria>({
      ...createEmptyVaultFilter(),
      kinds: ["account", "custom:x"],
    });

    const container = document.createElement("div");
    document.body.appendChild(container);
    const app = createApp({
      render: () =>
        h(VaultCardFilter, {
          types: types.value,
          modelValue: criteria.value,
          resultCount: 0,
          "onUpdate:modelValue": (next: VaultFilterCriteria) => {
            criteria.value = next;
          },
        }),
    });
    app.directive("tip", {});
    app.mount(container);
    mounted.push({ app, container });

    await nextTick();
    types.value = [types.value[0]];
    await nextTick();
    await nextTick();

    expect(criteria.value.kinds).toEqual(["account"]);
  });
});
