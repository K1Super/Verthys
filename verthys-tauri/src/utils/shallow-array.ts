/**
 * shallow-array.ts — 浅层响应式数组操作工具
 *
 * 配合 Vue 的 `shallowRef` 使用，避免 Vue 对数组元素进行深度代理（reactive）。
 *
 * 背景：
 *   `ref<T[]>([])` 会对数组及每个元素进行深度代理。对于包含大型字段
 *   （如 dataB64 照片原始 Base64，可能数 MB）的记录，万条记录意味着
 *   数千个 Proxy 对象，内存暴涨且每次更新触发大量 watch/computed 重新计算。
 *
 *   `shallowRef<T[]>([])` 仅保证数组本身的变更（push/splice/赋值）可被检测，
 *   数组内的元素不进行深度代理。代价：直接修改元素属性（如 acc.pwdVisible = true）
 *   不会触发响应式更新，必须显式调用 triggerRef 或本工具的更新函数。
 *
 * 使用规则：
 *   1. 所有 `xxx.value.push/filter/splice` 后必须调用 `triggerRef(xxx)`
 *      或使用本工具的 pushShallowItems/replaceShallowArray
 *   2. 所有深层属性变更（如 acc.pwdVisible = true）改为 updateShallowItem
 *   3. 模板中 v-for 和 computed 依赖 .value 整体替换，无需修改模板
 *   4. watch(xxx, ..., { deep: true }) 改为 watch(() => xxx.value.length, ...)
 *      或在显式 triggerRef 后触发
 */

import { triggerRef, type ShallowRef } from "vue";

/**
 * 原地修改单条记录的多个字段，并触发响应式更新
 *
 * 适用场景：单条记录的深层属性变更（如 togglePwd/confirmKey/toggleContent）
 *
 * @param arr shallowRef 持有的数组
 * @param index 待修改记录的索引
 * @param patch 待合并的字段（浅合并）
 * @param trigger 可选的触发函数（默认 triggerRef(arr)）
 *
 * @example
 * // 旧代码（深度响应式）：
 * accounts.value[idx].pwdVisible = true;
 *
 * // 新代码（shallowRef）：
 * updateShallowItem(accounts, idx, { pwdVisible: true });
 */
export function updateShallowItem<T extends object>(
  arr: ShallowRef<T[]>,
  index: number,
  patch: Partial<T>,
  trigger: () => void = () => triggerRef(arr),
): void {
  if (index < 0 || index >= arr.value.length) return;
  // 创建新对象而非原地修改：确保 Vue 能检测到引用变化
  arr.value[index] = { ...arr.value[index], ...patch };
  trigger();
}

/**
 * 通过谓词查找单条记录的索引并原地修改其字段
 *
 * 适用场景：通过 id 查找并更新（无需先找到 index 再调用 updateShallowItem）
 *
 * @param arr shallowRef 持有的数组
 * @param predicate 谓词函数（返回 true 表示匹配目标记录）
 * @param patch 待合并的字段
 * @param trigger 可选的触发函数
 * @returns 是否找到并修改成功
 *
 * @example
 * updateShallowItemByPredicate(accounts, a => a.id === targetId, { pwdVisible: true });
 */
export function updateShallowItemByPredicate<T extends object>(
  arr: ShallowRef<T[]>,
  predicate: (item: T) => boolean,
  patch: Partial<T>,
  trigger: () => void = () => triggerRef(arr),
): boolean {
  const idx = arr.value.findIndex(predicate);
  if (idx === -1) return false;
  updateShallowItem(arr, idx, patch, trigger);
  return true;
}

/**
 * 批量追加记录到数组末尾，并触发响应式更新
 *
 * 适用场景：流式加载（verthysEnumerateRecords 分页推送）、批量导入
 *
 * @param arr shallowRef 持有的数组
 * @param items 待追加的记录数组
 * @param trigger 可选的触发函数
 *
 * @example
 * // 流式加载回调中：
 * pushShallowItems(accounts, batchRecords);
 */
export function pushShallowItems<T>(
  arr: ShallowRef<T[]>,
  items: T[],
  trigger: () => void = () => triggerRef(arr),
): void {
  if (items.length === 0) return;
  // 使用 push 批量追加（避免 concat 创建新数组的大内存开销）
  // shallowRef 的 .value.push 不会自动触发，必须显式 triggerRef
  arr.value.push(...items);
  trigger();
}

/**
 * 整体替换数组内容，并触发响应式更新
 *
 * 适用场景：初次加载、过滤/搜索结果替换、模块切换重置
 *
 * @param arr shallowRef 持有的数组
 * @param items 新的记录数组
 * @param trigger 可选的触发函数
 *
 * @example
 * // 初次加载：
 * replaceShallowArray(accounts, loadedRecords);
 *
 * // 搜索过滤：
 * replaceShallowArray(filteredAccounts, accounts.value.filter(a => a.name.includes(keyword)));
 */
export function replaceShallowArray<T>(
  arr: ShallowRef<T[]>,
  items: T[],
  trigger: () => void = () => triggerRef(arr),
): void {
  arr.value = items;
  trigger();
}

/**
 * 从数组中移除匹配谓词的记录，并触发响应式更新
 *
 * 适用场景：删除记录后同步前端列表
 *
 * @param arr shallowRef 持有的数组
 * @param predicate 谓词函数（返回 true 表示待删除）
 * @param trigger 可选的触发函数
 * @returns 实际删除的记录数
 *
 * @example
 * // 删除多条记录后：
 * removeShallowItems(accounts, a => deletedIds.has(a.id));
 */
export function removeShallowItems<T>(
  arr: ShallowRef<T[]>,
  predicate: (item: T) => boolean,
  trigger: () => void = () => triggerRef(arr),
): number {
  const before = arr.value.length;
  arr.value = arr.value.filter(item => !predicate(item));
  const removed = before - arr.value.length;
  if (removed > 0) {
    trigger();
  }
  return removed;
}

/**
 * 通过索引移除单条记录，并触发响应式更新
 *
 * @param arr shallowRef 持有的数组
 * @param index 待移除记录的索引
 * @param trigger 可选的触发函数
 * @returns 是否移除成功
 */
export function removeShallowItemAt<T>(
  arr: ShallowRef<T[]>,
  index: number,
  trigger: () => void = () => triggerRef(arr),
): boolean {
  if (index < 0 || index >= arr.value.length) return false;
  arr.value.splice(index, 1);
  trigger();
  return true;
}

/**
 * 清空数组，并触发响应式更新
 *
 * @param arr shallowRef 持有的数组
 * @param trigger 可选的触发函数
 */
export function clearShallowArray<T>(
  arr: ShallowRef<T[]>,
  trigger: () => void = () => triggerRef(arr),
): void {
  if (arr.value.length === 0) return;
  arr.value = [];
  trigger();
}
