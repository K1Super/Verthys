/*
 * key/global/device.ts — 设备机器码绑定与 .bin 文件读取
 */
import {
  setDeviceBinding, checkDeviceBinding, getDeviceFingerprint, readUserFile,
} from "../../lib/verthys";
import { keyState } from "../../state/key_state";
import {
  ok, err,
  VerthysErrorCode, type VerthysResult,
  wrapAsVerthysError,
} from "../../lib/util/verthys_error";
import { log } from "./shared";

/**
 * 绑定当前设备机器码（独立可控）
 *
 * 由调用方决定是否绑定。
 * 绑定失败返回明确错误码，UI 层可展示提示并允许用户重试。
 *
 * 无 force 参数：setDeviceBinding 始终写入当前机器码（覆盖语义是唯一行为）。
 * @returns VerthysResult<void>
 *   - ok：绑定成功
 *   - err(E_VERTHYS_NOT_READY)：verthys 未解锁
 *   - err(E_DEVICE_BIND_FAILED)：绑定失败，UI 可提示用户重试
 */
export async function bindDevice(): Promise<VerthysResult<void>> {
  if (!keyState.verthysReady.value) {
    return err(VerthysErrorCode.E_VERTHYS_NOT_READY, "verthys 未解锁");
  }
  try {
    await setDeviceBinding();
    log.info("设备绑定成功");
    return ok(undefined);
  } catch (e) {
    const ve = wrapAsVerthysError(e);
    log.error("设备绑定失败", e);
    return err(VerthysErrorCode.E_DEVICE_BIND_FAILED, `设备绑定失败: ${ve.message}`, ve);
  }
}

/**
 * 校验当前设备是否与已绑定机器码匹配
 *
 * 返回 VerthysResult<"match"|"mismatch"|"unbound">
 *
 * 后端 check_device_binding 返回 DeviceBindingResult 结构体
 *   （{status, detail, error_code?, match_score?}），必须按 status 显式映射
 *   为前端联合类型：直接透传对象会使 useViewMode 的 === 'mismatch'
 *   字符串比较恒为 false，导致 device_mismatch 拦截视图失效。
 *
 *   映射规则：
 *     - "match"         → ok("match")     完全匹配
 *     - "partial_match" → ok("match")     部分匹配（权重 ≥80%，允许有限恢复）
 *     - "mismatch"      → ok("mismatch")  不匹配（触发拦截视图）
 *     - "unbound"       → ok("unbound")   未绑定（首次运行）
 *     - "error"         → err(E_DEVICE_BINDING) 校验出错（不阻断主流程）
 *
 * @returns VerthysResult
 *   - ok("match")：设备匹配（含部分匹配有限恢复）
 *   - ok("mismatch")：设备不匹配
 *   - ok("unbound")：未绑定
 *   - err(E_DEVICE_BINDING)：校验异常
 */
export async function verifyDeviceBinding(): Promise<VerthysResult<"match" | "mismatch" | "unbound">> {
  try {
    const result = await checkDeviceBinding();
    switch (result.status) {
      case "match":
        return ok("match");
      case "partial_match":
        // 后端权重匹配 ≥80%（MATCH_THRESHOLD_PERCENT）判定为部分匹配：
        // 允许有限恢复进入管理界面，记录审计日志便于追溯硬件变更
        log.warn(
          `设备部分匹配（${result.match_score ?? "?"}%），允许有限恢复：${result.detail}`,
        );
        return ok("match");
      case "mismatch":
        return ok("mismatch");
      case "unbound":
        return ok("unbound");
      case "error":
        log.error("设备校验出错:", result.detail, result.error_code ?? "");
        return err(
          VerthysErrorCode.E_DEVICE_BINDING,
          result.detail || "设备校验出错",
        );
      default: {
        // 防御性兜底：后端新增枚举值时按校验异常处理（fail-safe，不误放行）
        const exhaustive: never = result.status;
        log.error("未知设备绑定状态:", exhaustive);
        return err(VerthysErrorCode.E_DEVICE_BINDING, "未知设备绑定状态");
      }
    }
  } catch (e) {
    log.error("设备校验失败", e);
    return err(VerthysErrorCode.E_DEVICE_BINDING, `设备校验失败: ${wrapAsVerthysError(e).message}`, e);
  }
}

/** 获取当前设备机器码（SHA-256 hex 前 16 位，用于 UI 显示） */
export async function getDeviceFingerprintShort(): Promise<string> {
  try {
    const fp = await getDeviceFingerprint();
    return fp.substring(0, 16).toUpperCase();
  } catch {
    return "未知";
  }
}

/* ------------------------------------------------------------------ *
 * .bin 文件读取                                                       *
 * ------------------------------------------------------------------ */

/**
 * 读取 .bin 文件字节（通过 Tauri 后端读取本地文件，二进制 IPC 直传）
 */
export async function readBinFile(path: string): Promise<Uint8Array | null> {
  try {
    return await readUserFile(path);
  } catch {
    return null;
  }
}
