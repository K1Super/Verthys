/*
 * utils/modal_stack.ts — 模态层栈与页面滚动锁（对话框外壳与确认窗共用）
 *
 * 为什么必须共享一份：
 *   同一文档可以同时叠着两层模态（类型编辑器 + 其内的「删除类型」确认）。
 *   若各自在 document 上监听 Esc 且只判断「我开着就关我」，一次 Esc 会把
 *   两层一起关掉 —— 用户只想取消删除，编辑器却随之消失。
 *   共享栈后只有栈顶响应 Esc；滚动锁按层计数，内层关闭不会提前解锁。
 *
 * 约定：
 *   - 每次 push 恰好对应一次 pop（pop 以身份为准，重复调用无副作用）；
 *   - 身份用 Symbol：多实例并存时引用比较即可判定栈序，不依赖类名/时序。
 */

const stack: symbol[] = [];

/** 已持锁的模态层数（0 表示页面未锁定） */
let scrollLockCount = 0;

/** 持锁前的 overflow 原值（解锁时原样归还） */
let lockedOverflow = "";

/**
 * 入栈并锁定页面滚动（仅首次入栈时记录原值）。
 *
 * @param id 模态层身份（实例级 Symbol）
 */
export function pushModal(id: symbol): void {
  stack.push(id);
  if (scrollLockCount === 0) {
    lockedOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
  }
  scrollLockCount += 1;
}

/**
 * 出栈并释放滚动锁。
 *
 * @param id 模态层身份
 * @returns 该身份是否确实在栈中（未入栈时不做任何变更，
 *          保证「关闭未打开的层」不会误减他人所持的锁）
 */
export function popModal(id: symbol): boolean {
  const idx = stack.lastIndexOf(id);
  if (idx === -1) return false;
  stack.splice(idx, 1);
  scrollLockCount -= 1;
  if (scrollLockCount === 0) document.body.style.overflow = lockedOverflow;
  return true;
}

/**
 * 是否为栈顶模态层（只有栈顶可响应 Esc）。
 *
 * @param id 模态层身份
 */
export function isTopModal(id: symbol): boolean {
  return stack[stack.length - 1] === id;
}
