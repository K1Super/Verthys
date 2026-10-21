/// <reference types="node" />
/*
 * vault_card_contract.spec.ts — 存签模块结构契约守卫
 *
 * 为什么是源码扫描而非渲染测试：仓库没有组件测试基建（无 @vue/test-utils），
 * 而本文件守护的是一组「结构必须唯一 / 入口必须存在」的静态事实 ——
 * 卡片模板只能有一份、条目 id 只能由分配器给出、不可读记录不得丢弃、
 * 不可逆确认必须写明对象、对话框必须按模态栈处理 Esc。
 * 这些一旦回退，界面上的表现是「悄悄变差」（两份模板漂移、id 撞车、
 * 记录消失、删错对象），静态扫描能在合入前就挡住。
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

const read = (rel: string): string => readFileSync(new URL(rel, import.meta.url), "utf8");

const moduleSource = read("../AccountVerthys.vue");
const cardSource = read("./VaultItemCard.vue");
const formSource = read("./VaultItemFormDialog.vue");
const editorSource = read("./VaultTypeEditorDialog.vue");
const searchBarSource = read("../../common/verthys-ui/VerthysSearchBar.vue");
const confirmSource = read("../../common/verthys-ui/ConfirmDelete.vue");
const dialogSource = read("../../common/verthys-ui/VerthysDialog.vue");

describe("卡片渲染单源", () => {
  it("虚拟滚动与普通网格两条路径都使用同一卡片组件", () => {
    expect(moduleSource.match(/<VaultItemCard/g)?.length).toBe(2);
  });

  it("虚拟路径传入会话内唯一的稳定键，不退回 index 键", () => {
    expect(moduleSource).toContain(':item-key="itemKeyOf"');
    expect(moduleSource).toContain("const itemKeyOf = (entry: VaultEntry): number => entry.id");
  });

  it("模块内不再内联卡片标记（内联即第二份模板，必然漂移）", () => {
    expect(moduleSource).not.toContain('class="verthys-card glass reveal-item"');
    expect(moduleSource).not.toContain('class="secret-row"');
  });
});

describe("条目 id 分配", () => {
  it("内存 id 由单调分配器给出，不得以时间戳充当 id", () => {
    expect(moduleSource).toContain("const allocMemId = (): number => memIdSeq++");
    // 同一毫秒新增两条会得到同一 id：列表 key 重复且定位到错误条目
    expect(moduleSource).not.toMatch(/\bid:\s*Date\.now\(\)/);
  });
});

describe("损坏记录不得静默丢弃", () => {
  it("解码失败与空载荷都保留为不可读条目", () => {
    expect(moduleSource).toContain("decodeVaultItem(dataB64)");
    expect(moduleSource).toContain("corrupt: true");
  });

  it("不可读条目不参与关键字检索，也不提供编辑入口", () => {
    expect(moduleSource).toContain("entry.corrupt ? false : vaultSearchTextOf");
    expect(moduleSource).toContain("if (entry.corrupt) return;");
  });

  it("卡片对不可读与未知类型只给状态说明，不回显字段取值", () => {
    expect(cardSource).toContain("数据不可读 · 记录 #");
    expect(cardSource).toContain("待重新指派");
  });
});

describe("不可逆操作的可读性", () => {
  it("确认删除窗渲染待删对象并声明模态语义", () => {
    expect(moduleSource).toContain(':item-name="deleteTargetName"');
    expect(confirmSource).toContain('class="cd-target"');
    expect(confirmSource).toContain('v-if="itemName"');
    expect(confirmSource).toContain('role="alertdialog"');
    expect(confirmSource).toContain('aria-modal="true"');
  });

  it("删除目标文案包含类型名或不可读标记", () => {
    expect(moduleSource).toContain("数据不可读 · 记录 #");
    expect(moduleSource).toContain("${view.title} · ${view.typeLabel}");
  });
});

describe("类型编辑器草稿隔离", () => {
  it("打开时深拷贝数组字段与字段候选项：关闭不保存不污染父级", () => {
    expect(editorSource).toContain("cardFields: [...item.cardFields]");
    expect(editorSource).toContain("searchFields: [...item.searchFields]");
    expect(editorSource).toContain("options: [...field.options]");
  });
});

describe("对话框模态规范", () => {
  it("外壳声明模态语义、面板可聚焦，并按模态栈只让顶层响应 Esc", () => {
    expect(dialogSource).toContain('role="dialog"');
    expect(dialogSource).toContain('aria-modal="true"');
    expect(dialogSource).toContain('tabindex="-1"');
    expect(dialogSource).toContain("isTopModal()");
    expect(dialogSource).toContain('e.key === "Escape"');
  });

  it("请求在途时不得由 Esc 或点击遮罩关闭（否则提交结果无处落点）", () => {
    expect(dialogSource.match(/if \(props\.saving\) return;/g)?.length).toBe(2);
  });
});

describe("保存决策与禁用条件同源", () => {
  it("账号保存按钮的禁用条件复用同一份密钥决策，不另写一套判据", () => {
    expect(formSource).toContain("const secretPlan = computed(");
    expect(formSource).toContain('secretPlan.value.action === "needs-key"');
  });
});

describe("可访问名", () => {
  it("卡片内的纯图标键都有可访问名（文字键由自身文案命名）", () => {
    const iconButtons = (cardSource.match(/<button[\s\S]*?>/g) ?? []).filter((tag) =>
      tag.includes('class="icon-btn"'),
    );
    expect(iconButtons.length).toBeGreaterThan(0);
    for (const tag of iconButtons) expect(tag).toContain("aria-label=");
  });

  it("搜索输入与纯图标新增键都有可访问名", () => {
    expect(searchBarSource).toContain(':aria-label="placeholder || \'搜索\'"');
    expect(searchBarSource).toContain(':aria-label="addLabel || \'添加\'"');
  });
});
