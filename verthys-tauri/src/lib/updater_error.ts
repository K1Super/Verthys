/*
 * updater_error — 更新错误码到用户文案的唯一映射
 *
 * 后端只返回稳定错误码与内部诊断信息；界面只能展示本表文案。新增错误码时
 * TypeScript 的穷尽 Record 会强制补齐，脚本门会校验与 Rust 清单一致。
 */

export const UPDATER_ERROR_CODES = [
  "E_UPDATER_NETWORK",
  "E_UPDATER_MANIFEST_INVALID",
  "E_UPDATER_MANIFEST_SIG_INVALID",
  "E_UPDATER_CHANNEL_MISMATCH",
  "E_UPDATER_VERSION_BLOCKED",
  "E_UPDATER_BRIDGE_REQUIRED",
  "E_UPDATER_COMPAT_BLOCKED",
  "E_UPDATER_INSTALL_REVOKED",
  "E_UPDATER_PACKAGE_MISSING",
  "E_UPDATER_PRECHECK_SPACE",
  "E_UPDATER_PRECHECK_SINGLE_INSTANCE",
  "E_UPDATER_PRECHECK_DIR_WRITABLE",
  "E_UPDATER_SIZE_MISMATCH",
  "E_UPDATER_HASH_MISMATCH",
  "E_UPDATER_PE_VERSION_MISMATCH",
  "E_UPDATER_SIG_INVALID",
  "E_UPDATER_SIG_PUBKEY_MISMATCH",
  "E_UPDATER_AUTHENTICODE_INVALID",
  "E_UPDATER_LOCK_DIRTY",
  "E_UPDATER_LOCK_FAILED",
  "E_UPDATER_LOCK_UNKNOWN",
  "E_UPDATER_INSTALL_FAILED",
  "E_UPDATER_HEALTH_FAIL",
  "E_UPDATER_MARKER_INVALID",
  "E_UPDATER_ROLLBACK_MATERIAL_MISSING",
  "E_UPDATER_CANCELLED",
  "E_UPDATER_BUSY",
  "E_UPDATER_SESSION_INVALID",
  "E_UPDATER_CONFIG_INVALID",
  "E_UPDATER_INTERNAL",
] as const;

export type UpdaterErrorCode = (typeof UPDATER_ERROR_CODES)[number];

export interface UpdaterErrorCopy {
  title: string;
  guidance: string;
  retryable: boolean;
}

export const UPDATER_ERROR_COPY: Record<UpdaterErrorCode, UpdaterErrorCopy> = {
  E_UPDATER_NETWORK: {
    title: "网络连接失败",
    guidance: "请检查网络后重试",
    retryable: true,
  },
  E_UPDATER_MANIFEST_INVALID: {
    title: "更新信息无效",
    guidance: "请稍后重试；若持续出现请导出更新日志",
    retryable: true,
  },
  E_UPDATER_MANIFEST_SIG_INVALID: {
    title: "更新信息校验失败",
    guidance: "已阻止安装；请导出日志并联系维护人",
    retryable: false,
  },
  E_UPDATER_CHANNEL_MISMATCH: {
    title: "更新渠道不匹配",
    guidance: "请检查更新配置后重试",
    retryable: false,
  },
  E_UPDATER_VERSION_BLOCKED: {
    title: "版本不满足更新条件",
    guidance: "请确认当前版本后重试",
    retryable: false,
  },
  E_UPDATER_BRIDGE_REQUIRED: {
    title: "需要先安装过渡版本",
    guidance: "请按发布说明先安装过渡版本",
    retryable: false,
  },
  E_UPDATER_COMPAT_BLOCKED: {
    title: "当前版本与新版本不兼容",
    guidance: "请安装与当前核心匹配的版本",
    retryable: false,
  },
  E_UPDATER_INSTALL_REVOKED: {
    title: "该版本已撤回",
    guidance: "请稍后重新检查更新",
    retryable: true,
  },
  E_UPDATER_PACKAGE_MISSING: {
    title: "安装包不可用",
    guidance: "请稍后重试或联系维护人",
    retryable: false,
  },
  E_UPDATER_PRECHECK_SPACE: {
    title: "磁盘空间不足",
    guidance: "请释放空间后重试",
    retryable: true,
  },
  E_UPDATER_PRECHECK_SINGLE_INSTANCE: {
    title: "应用或更新正在运行",
    guidance: "请关闭其他实例并等待当前操作结束后重试",
    retryable: true,
  },
  E_UPDATER_PRECHECK_DIR_WRITABLE: {
    title: "安装目录不可写",
    guidance: "请检查目录权限后重试",
    retryable: true,
  },
  E_UPDATER_SIZE_MISMATCH: {
    title: "安装包大小异常",
    guidance: "已阻止安装；请重新检查更新",
    retryable: false,
  },
  E_UPDATER_HASH_MISMATCH: {
    title: "安装包完整性校验失败",
    guidance: "已阻止安装；请重新检查更新",
    retryable: false,
  },
  E_UPDATER_PE_VERSION_MISMATCH: {
    title: "安装包版本不一致",
    guidance: "已阻止安装；请重新检查更新",
    retryable: false,
  },
  E_UPDATER_SIG_INVALID: {
    title: "安装包签名无效",
    guidance: "已阻止安装；请导出日志并联系维护人",
    retryable: false,
  },
  E_UPDATER_SIG_PUBKEY_MISMATCH: {
    title: "安装包签名密钥不匹配",
    guidance: "已阻止安装；请导出日志并联系维护人",
    retryable: false,
  },
  E_UPDATER_AUTHENTICODE_INVALID: {
    title: "安装包数字签名无效",
    guidance: "已阻止安装；请导出日志并联系维护人",
    retryable: false,
  },
  E_UPDATER_LOCK_DIRTY: {
    title: "仍有数据未保存",
    guidance: "请先完成保存后再更新",
    retryable: true,
  },
  E_UPDATER_LOCK_FAILED: {
    title: "安全锁库未完成",
    guidance: "请重试；若持续失败请导出更新日志",
    retryable: true,
  },
  E_UPDATER_LOCK_UNKNOWN: {
    title: "安装确认已失效",
    guidance: "请重新开始更新",
    retryable: true,
  },
  E_UPDATER_INSTALL_FAILED: {
    title: "安装未能启动",
    guidance: "请重试或导出更新日志",
    retryable: true,
  },
  E_UPDATER_HEALTH_FAIL: {
    title: "新版本自检未通过",
    guidance: "请运行修复或重新安装旧版",
    retryable: true,
  },
  E_UPDATER_MARKER_INVALID: {
    title: "更新状态记录异常",
    guidance: "请运行修复并导出更新日志",
    retryable: false,
  },
  E_UPDATER_ROLLBACK_MATERIAL_MISSING: {
    title: "未找到可用的旧版安装包",
    guidance: "请重新安装旧版或联系维护人",
    retryable: false,
  },
  E_UPDATER_CANCELLED: {
    title: "更新已取消",
    guidance: "可重新检查更新",
    retryable: true,
  },
  E_UPDATER_BUSY: {
    title: "已有更新操作在进行",
    guidance: "请等待当前操作结束后重试",
    retryable: true,
  },
  E_UPDATER_SESSION_INVALID: {
    title: "更新会话已失效",
    guidance: "请重新检查更新",
    retryable: true,
  },
  E_UPDATER_CONFIG_INVALID: {
    title: "更新配置无效",
    guidance: "已禁用更新；请检查更新端点与渠道配置",
    retryable: false,
  },
  E_UPDATER_INTERNAL: {
    title: "更新出现异常",
    guidance: "请导出更新日志后重试",
    retryable: true,
  },
};

/** 未知错误码的保守兜底；不得把后端原始诊断直接展示给用户。 */
export function updaterErrorCopy(code?: string | null): UpdaterErrorCopy {
  if (code && code in UPDATER_ERROR_COPY) {
    return UPDATER_ERROR_COPY[code as UpdaterErrorCode];
  }
  return {
    title: "更新出现异常",
    guidance: "请导出更新日志后重试",
    retryable: true,
  };
}

/** 组装唯一允许出现在界面上的错误文案。 */
export function updaterErrorMessage(code?: string | null): string {
  const copy = updaterErrorCopy(code);
  return `${copy.title}：${copy.guidance}`;
}
