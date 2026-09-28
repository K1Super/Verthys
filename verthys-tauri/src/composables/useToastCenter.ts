/**
 * useToastCenter — 全局 Toast 反馈中心（唯一权威源）
 *
 * 【职责】
 *   集中承载全应用瞬时提示的状态与生命周期（自动消失计时）；
 *   渲染唯一收敛于 components/common/feedback/ToastLayer.vue
 *   （App 根节点单点挂载 + Teleport 至 body，层级 = --z-toast 全应用最高层）。
 *
 * 【设计动机（根治两类历史问题）】
 *   1) 层级失控：旧实现各模块自行渲染 toast DOM（多数未 Teleport），
 *      提示被困在模块栈上下文内 —— 弹窗 / 查看器 / 覆盖层可整体盖过提示；
 *      各模块又各自打补丁（z 999 / 4500 / 5000 / 100000 四套口径）。
 *   2) 状态分裂：旧 useErrorToast（非单例）每次调用各持一份 errorMsg，
 *      跨 composable 共享时提示丢失（拾光模块曾因此二次封装 usePhotoToast 补救，二者均已移除）。
 *   现统一为模块级单例状态 + 唯一渲染层：任何模块任意位置调用都写入同一份 ref，
 *   渲染收敛到 ToastLayer —— 层级与状态均不再有第二处来源。
 *
 * 【通道（与 ToastLayer 一一对应）】
 *   error      顶部红色 .error-toast（错误）                默认 2.5s
 *   status     底部 .clip-toast（成功 / 中性状态）          默认 2.5s（可传时长）
 *   copied     底部 .clip-toast（「已复制到剪贴板」）       1.5s
 *   exportDone 顶部 .clip-toast--top（success/error 变体）  2.6s
 *   clip       底部 .clip-toast（剪贴板安全倒计时，秒级刷新；无自动消失计时，
 *              由 useClipToast 在倒计时结束/组件卸载时收起）
 *
 * 【硬约束】
 *   - 禁止任何模块再自行渲染 toast DOM（层级/状态分裂均由此而来）；
 *   - Toast 层级唯一来源 = tokens.css 的 --z-toast（.toast-layer 持有），
 *     提示本体不得再声明 z-index；
 *   - 新增提示通道时：在此扩展状态 + ToastLayer 扩展渲染，二者保持一一对应。
 */
import { ref, shallowRef } from "vue";

/** 导出完成提示载荷 */
export interface ToastExportDone {
  msg: string;
  type: "success" | "error";
}

/** 剪贴板安全倒计时载荷（text 为场景文案，seconds 为剩余秒数） */
export interface ToastClip {
  text: string;
  seconds: number;
}

/* ===== 显示时长（毫秒） ===== */
const ERROR_DURATION = 2500;
const STATUS_DURATION = 2500;
const COPIED_DURATION = 1500;
const EXPORT_DONE_DURATION = 2600;

/** 全局 Toast 状态（单例；唯一渲染消费方 = ToastLayer.vue）
 *  另：useClipToast 只读 clip 状态用于卸载归属判定（不渲染、不写入第二来源）。
 *  载荷类状态（exportDone / clip）用 shallowRef：载荷恒定整体替换、无深响应需求，
 *  且对象身份在写入与读取间稳定 —— 这是「单写者自守 / 卸载归属判定」
 *  （useClipToast 的对象身份比较）成立的前提，禁止改为 deep ref。 */
export const toastState = {
  /** 顶部错误提示（.error-toast） */
  error: ref(""),
  /** 底部状态提示（.clip-toast） */
  status: ref(""),
  /** 底部「已复制到剪贴板」（.clip-toast） */
  copied: ref(false),
  /** 顶部导出完成（.clip-toast--top + success/error 变体） */
  exportDone: shallowRef<ToastExportDone | null>(null),
  /** 底部剪贴板安全倒计时（.clip-toast） */
  clip: shallowRef<ToastClip | null>(null),
};

/* ===== 自动消失计时器（单例级；各通道独享，重复触发重置计时） ===== */
let errorTimer: ReturnType<typeof setTimeout> | null = null;
let statusTimer: ReturnType<typeof setTimeout> | null = null;
let copiedTimer: ReturnType<typeof setTimeout> | null = null;
let exportDoneTimer: ReturnType<typeof setTimeout> | null = null;

/** 显示顶部错误提示（红色，默认 2.5s 自动消失） */
const showError = (msg: string, duration: number = ERROR_DURATION): void => {
  toastState.error.value = msg;
  if (errorTimer) clearTimeout(errorTimer);
  errorTimer = setTimeout(() => { toastState.error.value = ""; }, duration);
};

/** 显示底部状态提示（成功 / 中性，默认 2.5s 自动消失） */
const showStatus = (msg: string, duration: number = STATUS_DURATION): void => {
  toastState.status.value = msg;
  if (statusTimer) clearTimeout(statusTimer);
  statusTimer = setTimeout(() => { toastState.status.value = ""; }, duration);
};

/** 显示「已复制到剪贴板」（底部，1.5s 自动消失） */
const showCopied = (): void => {
  toastState.copied.value = true;
  if (copiedTimer) clearTimeout(copiedTimer);
  copiedTimer = setTimeout(() => { toastState.copied.value = false; }, COPIED_DURATION);
};

/** 显示顶部导出完成提示（success/error 变体，2.6s 自动消失） */
const showExportDone = (msg: string, type: "success" | "error"): void => {
  toastState.exportDone.value = { msg, type };
  if (exportDoneTimer) clearTimeout(exportDoneTimer);
  exportDoneTimer = setTimeout(() => { toastState.exportDone.value = null; }, EXPORT_DONE_DURATION);
};

/** 写入 / 刷新剪贴板安全倒计时状态（null 收起；秒数由 useClipToast 逐秒推入） */
const setClip = (state: ToastClip | null): void => {
  toastState.clip.value = state;
};

/**
 * 全局 Toast 中心（组件 / composable 统一取用入口）
 * 单例语义：模块级共享状态，无组件级生命周期（提示随应用存续）。
 */
export function useToastCenter() {
  return { showError, showStatus, showCopied, showExportDone, setClip };
}