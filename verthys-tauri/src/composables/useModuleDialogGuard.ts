/**
 * useModuleDialogGuard — 模块弹窗清理守卫
 *
 * 根治「页面覆盖」问题：
 *   根因：各模块弹窗使用 <Teleport to="body">，脱离组件 DOM 树。
 *   cross-fade 切换模块时，旧模块的弹窗仍残留在 body 中，覆盖新模块内容。
 *
 * 做法：ModuleStage provide currentModule，各模块 inject 并 watch。
 *   当 currentModule !== 自身模块 id 时，同步（flush:'sync'）关闭所有弹窗。
 *   同步触发确保弹窗在切换瞬间立即关闭，杜绝残留覆盖。
 *
 * 用法：
 *   import { useModuleDialogGuard } from '@/composables/useModuleDialogGuard';
 *   useModuleDialogGuard('accounts', () => {
 *     showDialog.value = false;
 *     showKeyDialog.value = false;
 *   });
 */
import { inject, watch, type Ref } from 'vue';

/** provide key */
export const MODULE_DIALOG_GUARD_KEY = 'currentModule';

/**
 * 注册模块弹窗清理守卫
 *
 * @param moduleId  当前模块 id（与 switchModule 中的 id 一致）
 * @param cleanup   清理函数：关闭该模块所有打开的弹窗/对话框
 */
export function useModuleDialogGuard(moduleId: string, cleanup: () => void): void {
  const currentModule = inject<Ref<string> | null>(MODULE_DIALOG_GUARD_KEY, null);
  if (!currentModule) return;

  /* flush:'sync' — currentModule 变化时同步触发，弹窗在切换瞬间立即关闭 */
  watch(
    currentModule,
    (m) => {
      if (m !== moduleId) cleanup();
    },
    { flush: 'sync' },
  );
}
