/*
 * updater-critical — 更新锁库与安装移交期间的本地临界区标记
 *
 * 关闭窗口或切换模块会与落盘、安装器移交抢占进程。后端另有带时限的关闭
 * 拦截；本标记只负责同步前端导航守卫，二者共同保证临界区不被用户操作打断。
 */

let criticalUntil = 0;
const CRITICAL_TTL_MS = 180_000;

export function markUpdaterCritical(active: boolean): void {
  criticalUntil = active ? Date.now() + CRITICAL_TTL_MS : 0;
}

export function isUpdaterCritical(): boolean {
  return Date.now() < criticalUntil;
}
