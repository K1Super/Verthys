/*
 * 开发夹具填充事件契约。
 *
 * 产品表单只在 import.meta.env.DEV 分支内监听同名事件；本模块只由
 * DevDock 夹具面板加载，不进入生产构建。
 */
export const DEV_FIXTURE_FILL_EVENT = "verthys:devfixture-fill";

export type DevFixtureFillTarget = "unlock" | "global" | "module" | "recovery";

export interface DevFixtureFillPayload {
  target: DevFixtureFillTarget;
  containerPath?: string;
  containerKeyfilePath?: string;
  globalPassword?: string;
  binPassword?: string;
  binKeyfilePath?: string;
  moduleKeys?: Record<string, string>;
  recoveryCode?: string;
}

export function publishFixtureFill(payload: DevFixtureFillPayload): void {
  window.dispatchEvent(
    new CustomEvent<DevFixtureFillPayload>(DEV_FIXTURE_FILL_EVENT, {
      detail: payload,
    }),
  );
}
