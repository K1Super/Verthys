/*
 * 填充派发：从配置对象向当前可见表单广播填充事件。
 *
 * 只赋值，不触发解锁、初始化、验证或提交。
 */
import { publishFixtureFill } from "./fill_bus";
import type { DevFixtureProfile } from "./profile_client";

export function dispatchFill(profile: DevFixtureProfile): void {
  publishFixtureFill({
    target: "unlock",
    containerPath: profile.containerPath,
    containerKeyfilePath: profile.containerKeyfilePath,
  });
  publishFixtureFill({
    target: "global",
    globalPassword: profile.globalPassword,
    binPassword: profile.binPassword,
    binKeyfilePath: profile.binKeyfilePath,
  });
  publishFixtureFill({
    target: "module",
    moduleKeys: { ...profile.moduleKeys },
  });
  publishFixtureFill({
    target: "recovery",
    recoveryCode: profile.recoveryCode,
  });
}
