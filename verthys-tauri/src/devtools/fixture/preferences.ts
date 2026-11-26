/*
 * 开发夹具偏好：自动填充开关。
 *
 * 只保存一个布尔值，不含任何凭据；配置本体仍由 Rust 侧 DPAPI 加密保存。
 */
const AUTO_FILL_STORAGE_KEY = "verthys:devfixture:auto-fill";

export function readAutoFillPreference(): boolean {
  try {
    return window.localStorage.getItem(AUTO_FILL_STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

export function writeAutoFillPreference(enabled: boolean): void {
  try {
    window.localStorage.setItem(AUTO_FILL_STORAGE_KEY, enabled ? "1" : "0");
  } catch {
    /* 隐私模式或存储配额异常不阻断夹具使用 */
  }
}
