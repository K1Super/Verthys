/*
 * lib/verthys_error.ts — Verthys IPC 通信标准化错误
 *
 * 所有 VerthysError 继承 Error，与全局 error-handler.ts 兼容
 * 底层仅抛出标准化错误，不包含 console 输出
 */

/** IPC 通信错误细分类型 */
export enum VerthysErrorKind {
  /** 进程异常（worker 崩溃/未初始化/通信中断） */
  PROCESS_ERROR = "PROCESS_ERROR",
  /** 文件不存在（verthys 文件/bin 文件缺失） */
  FILE_NOT_FOUND = "FILE_NOT_FOUND",
  /** 权限不足（目录不可写/系统保护目录） */
  PERMISSION_DENIED = "PERMISSION_DENIED",
  /** 参数非法（入参校验失败/格式错误） */
  INVALID_PARAM = "INVALID_PARAM",
  /** IPC 调用失败（通用通信错误） */
  IPC_FAILED = "IPC_FAILED",
}

/** Verthys IPC 标准化错误 */
export class VerthysError extends Error {
  readonly kind: VerthysErrorKind;
  readonly cause?: unknown;

  constructor(message: string, kind: VerthysErrorKind, cause?: unknown) {
    super(message);
    this.name = "VerthysError";
    this.kind = kind;
    this.cause = cause;
  }
}

/** 进程异常（worker 崩溃/未初始化/通信中断） */
export function processError(message: string, cause?: unknown): VerthysError {
  return new VerthysError(message, VerthysErrorKind.PROCESS_ERROR, cause);
}

/** 文件不存在（verthys 文件/bin 文件缺失） */
export function fileNotFound(message: string, cause?: unknown): VerthysError {
  return new VerthysError(message, VerthysErrorKind.FILE_NOT_FOUND, cause);
}

/** 权限不足（目录不可写/系统保护目录） */
export function permissionDenied(message: string, cause?: unknown): VerthysError {
  return new VerthysError(message, VerthysErrorKind.PERMISSION_DENIED, cause);
}

/** 参数非法（入参校验失败/格式错误） */
export function invalidParam(message: string, cause?: unknown): VerthysError {
  return new VerthysError(message, VerthysErrorKind.INVALID_PARAM, cause);
}

/** IPC 调用失败（通用通信错误） */
export function ipcFailed(message: string, cause?: unknown): VerthysError {
  return new VerthysError(message, VerthysErrorKind.IPC_FAILED, cause);
}

/**
 * 将未知错误包装为 VerthysError
 * - 已是 VerthysError 则原样返回（防止双重包装）
 * - 字符串匹配常见错误模式（文件不存在/权限/参数）
 * - 其他错误统一归为 IPC_FAILED
 */
export function wrapAsVerthysError(e: unknown): VerthysError {
  if (e instanceof VerthysError) return e;

  const msg = e instanceof Error ? e.message : String(e);
  const lower = msg.toLowerCase();

  // 文件不存在
  if (lower.includes("no such file") || lower.includes("not found") || lower.includes("文件不存在")) {
    return fileNotFound(msg, e);
  }
  // 权限不足
  if (lower.includes("permission denied") || lower.includes("access denied") || lower.includes("权限")) {
    return permissionDenied(msg, e);
  }
  // 参数非法
  if (lower.includes("invalid") || lower.includes("illegal") || lower.includes("参数") || lower.includes("invalid param")) {
    return invalidParam(msg, e);
  }
  // 进程异常
  if (lower.includes("process") || lower.includes("worker") || lower.includes("进程") || lower.includes("disconnected")) {
    return processError(msg, e);
  }

  // 通用 IPC 失败
  return ipcFailed(msg, e);
}

/* ------------------------------------------------------------------ *
 * ★ 结构化错误契约                                                   *
 *                                                                    *
 * 在保留现有 VerthysError/VerthysErrorKind（底层 IPC 异常）基础上，新增    *
 * VerthysErrorCode 业务错误码 + VerthysResult<T> 判别联合，使所有公共      *
 * 函数返回值统一为 Promise<VerthysResult<T>>，调用方通过 result.ok 和   *
 * result.code 获取细分错误原因，从而精确指引 UI 提示。                *
 *                                                                    *
 * 共存关系：                                                          *
 *   - VerthysError：底层 IPC 异常（lib/verthys.ts 内部抛出）              *
 *   - VerthysErrorCode：业务层结构化错误码（key/*.ts 返回 VerthysResult）  *
 *   - errFromUnknown：将底层异常包装为 VerthysResult 失败值              *
 * ------------------------------------------------------------------ */

/**
 * Verthys 业务错误码枚举（结构化错误契约）
 *
 * 命名规范：E_<DOMAIN>_<CAUSE>
 *   - 通用：E_VERTHYS_*、E_INIT_*、E_PERSIST_*、E_RECORD_*、E_FLUSH_*
 *   - 全局密钥：E_GLOBAL_KEY_*
 *   - 设备绑定：E_DEVICE_*
 *   - 模块密钥：E_MODULE_*
 */
export enum VerthysErrorCode {
  // ===== 通用 =====
  E_VERTHYS_NOT_READY = "E_VERTHYS_NOT_READY",
  E_VERTHYS_LOCKED = "E_VERTHYS_LOCKED",
  E_RECORD_NOT_FOUND = "E_RECORD_NOT_FOUND",
  E_PERSIST_FAILED = "E_PERSIST_FAILED",
  E_FLUSH_TIMEOUT = "E_FLUSH_TIMEOUT",

  // ===== 初始化 =====
  E_INIT_FAILED = "E_INIT_FAILED",
  E_PATH_INVALID = "E_PATH_INVALID",
  E_PATH_EXISTS = "E_PATH_EXISTS",
  E_PATH_NOT_EXISTS = "E_PATH_NOT_EXISTS",
  E_WORKER_INIT_FAILED = "E_WORKER_INIT_FAILED",
  E_VERTHYS_CREATE_FAILED = "E_VERTHYS_CREATE_FAILED",
  E_VERTHYS_UNLOCK_FAILED = "E_VERTHYS_UNLOCK_FAILED",

  // ===== 全局密钥 =====
  E_GLOBAL_KEY_DERIVE_FAILED = "E_GLOBAL_KEY_DERIVE_FAILED",
  E_GLOBAL_KEY_VERIFY_FAILED = "E_GLOBAL_KEY_VERIFY_FAILED",
  E_GLOBAL_KEY_RECORD_NOT_FOUND = "E_GLOBAL_KEY_RECORD_NOT_FOUND",
  E_GLOBAL_KEY_PERSIST_FAILED = "E_GLOBAL_KEY_PERSIST_FAILED",

  // ===== 设备绑定 =====
  E_DEVICE_BINDING = "E_DEVICE_BINDING",
  E_DEVICE_BIND_FAILED = "E_DEVICE_BIND_FAILED",
  E_DEVICE_MISMATCH = "E_DEVICE_MISMATCH",
  E_DEVICE_UNBOUND = "E_DEVICE_UNBOUND",

  // ===== 模块密钥 =====
  E_MODULE_KEY_NOT_FOUND = "E_MODULE_KEY_NOT_FOUND",
  E_MODULE_VERIFY_FAILED = "E_MODULE_VERIFY_FAILED",
  E_MODULE_KEY_SET_FAILED = "E_MODULE_KEY_SET_FAILED",
  E_MODULE_CONFIG_SAVE_FAILED = "E_MODULE_CONFIG_SAVE_FAILED",
  E_MODULE_NOT_READY = "E_MODULE_NOT_READY",
  E_MODULE_VERTHYS_NOT_READY = "E_MODULE_VERTHYS_NOT_READY",
}

/**
 * VerthysResult<T> — 判别联合类型
 *
 * 所有公共函数返回值统一为 Promise<VerthysResult<T>>
 * 调用方通过 result.ok 判断成功/失败，失败时通过 result.code 获取细分错误码
 */
export type VerthysResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: VerthysErrorCode; message: string; cause?: unknown };

/** VerthysResult 失败值的具体类型（用于类型守卫返回值） */
export type VerthysErrorResult = {
  ok: false;
  code: VerthysErrorCode;
  message: string;
  cause?: unknown;
};

/** 成功构造器 */
export function ok<T>(value: T): VerthysResult<T> {
  return { ok: true, value };
}

/** 失败构造器（无值） */
export function err(
  code: VerthysErrorCode,
  message: string,
  cause?: unknown,
): VerthysResult<never> {
  return { ok: false, code, message, cause };
}

/** 失败构造器（从 VerthysError 转换） */
export function errFromVerthysError(
  e: VerthysError,
  fallbackCode: VerthysErrorCode,
): VerthysResult<never> {
  return { ok: false, code: fallbackCode, message: e.message, cause: e };
}

/** 失败构造器（从未知错误转换，使用 wrapAsVerthysError 推断） */
export function errFromUnknown(
  e: unknown,
  fallbackCode: VerthysErrorCode,
): VerthysResult<never> {
  const ve = wrapAsVerthysError(e);
  return { ok: false, code: fallbackCode, message: ve.message, cause: ve };
}

/** 类型守卫：判断值是否为 VerthysError */
export function isVerthysError(e: unknown): e is VerthysError {
  return e instanceof VerthysError;
}

/** 类型守卫：判断 VerthysResult 是否成功 */
export function isOk<T>(r: VerthysResult<T>): r is { ok: true; value: T } {
  return r.ok;
}

/** 类型守卫：判断 VerthysResult 是否失败 */
export function isErr<T>(r: VerthysResult<T>): r is VerthysErrorResult {
  return !r.ok;
}

/**
 * 将 VerthysErrorKind 映射到默认的 VerthysErrorCode
 * 用于在异常捕获路径下推断合适的错误码
 */
export function defaultCodeFromKind(kind: VerthysErrorKind): VerthysErrorCode {
  switch (kind) {
    case VerthysErrorKind.FILE_NOT_FOUND: return VerthysErrorCode.E_PATH_NOT_EXISTS;
    case VerthysErrorKind.PERMISSION_DENIED: return VerthysErrorCode.E_PATH_INVALID;
    case VerthysErrorKind.PROCESS_ERROR: return VerthysErrorCode.E_WORKER_INIT_FAILED;
    case VerthysErrorKind.INVALID_PARAM: return VerthysErrorCode.E_INIT_FAILED;
    case VerthysErrorKind.IPC_FAILED:
    default: return VerthysErrorCode.E_PERSIST_FAILED;
  }
}

/* ------------------------------------------------------------------ *
 * ★ 用户友好型错误文案映射                      *
 *                                                                    *
 * 在 lib/verthys_error.ts 维护错误码→用户文案映射表，替换底层技术报错。  *
 * 每条文案附带下一步操作指引，降低用户咨询量。                         *
 *                                                                    *
 * 示例映射规则：                            *
 *   | 原始技术报错           | 面向用户提示文案     |                *
 *   | worker_init 失败       | 安全核心启动异常     |                *
 *   | superblock 校验错误    | 加密文件已损坏       |                *
 *   | 句柄打开失败           | 存储目录权限不足     |                *
 *                                                                    *
 * translateVerthysError 返回结构化用户文案：                             *
 *   - title：简短标题（用于 UI 弹窗标题）                              *
 *   - message：面向用户的描述（避免技术术语）                          *
 *   - guidance：下一步操作指引（具体可执行的恢复步骤）                  *
 * ------------------------------------------------------------------ */

/** 用户友好错误文案结构 */
export interface VerthysUserErrorText {
  /** 简短标题（用于 UI 弹窗标题） */
  title: string;
  /** 面向用户的描述（避免技术术语） */
  message: string;
  /** 下一步操作指引（具体可执行的恢复步骤） */
  guidance: string;
}

/** 错误码→用户文案映射表（核心实现） */
const VERTHYS_ERROR_TEXT_MAP: Record<VerthysErrorCode, VerthysUserErrorText> = {
  // ===== 通用 =====
  [VerthysErrorCode.E_VERTHYS_NOT_READY]: {
    title: "加密库未就绪",
    message: "加密库尚未初始化完成，暂时无法执行操作。",
    guidance: "请等待几秒后重试。若问题持续，请重启应用。",
  },
  [VerthysErrorCode.E_VERTHYS_LOCKED]: {
    title: "加密库已锁定",
    message: "加密库当前处于锁定状态，需要重新解锁后才能操作。",
    guidance: "请输入主密码重新解锁加密库。",
  },
  [VerthysErrorCode.E_RECORD_NOT_FOUND]: {
    title: "记录不存在",
    message: "指定的记录已被删除或不存在。",
    guidance: "请刷新列表后重试。若仍找不到，该记录可能已被删除。",
  },
  [VerthysErrorCode.E_PERSIST_FAILED]: {
    title: "数据保存失败",
    message: "加密库数据写入磁盘失败，可能因磁盘空间不足或权限问题。",
    guidance: "请检查磁盘剩余空间和目录写入权限，确保存储设备正常连接后重试。",
  },
  [VerthysErrorCode.E_FLUSH_TIMEOUT]: {
    title: "数据同步超时",
    message: "加密库数据同步到磁盘超时，可能因存储设备响应缓慢。",
    guidance: "请关闭占用磁盘的其他程序后重试。若使用 USB 设备，请检查连接稳定性。",
  },

  // ===== 初始化 =====
  [VerthysErrorCode.E_INIT_FAILED]: {
    title: "初始化失败",
    message: "加密库初始化过程中发生未知错误。",
    guidance: "请重启应用。若问题持续，请检查系统资源是否充足。",
  },
  [VerthysErrorCode.E_PATH_INVALID]: {
    title: "路径不可用",
    message: "所选路径不可用，可能因目录不存在、权限不足或为系统保护目录。",
    guidance: "请选择一个你有完整读写权限的普通目录（避免系统盘根目录、Program Files 等保护位置）。",
  },
  [VerthysErrorCode.E_PATH_EXISTS]: {
    title: "文件已存在",
    message: "目标位置已存在同名加密库文件。",
    guidance: "请使用「打开已有加密库」而非「创建新加密库」，或选择其他路径。",
  },
  [VerthysErrorCode.E_PATH_NOT_EXISTS]: {
    title: "文件不存在",
    message: "指定的加密库文件不存在，可能已被移动或删除。",
    guidance: "请确认文件路径正确，或使用「创建新加密库」新建一个文件。",
  },
  [VerthysErrorCode.E_WORKER_INIT_FAILED]: {
    title: "安全核心启动异常",
    message: "安全核心子进程启动失败，可能因系统资源不足或安全软件拦截。",
    guidance: "1. 请将本应用添加到杀毒软件/安全卫士的白名单中；2. 关闭其他占用内存的程序后重启应用；3. 若问题持续，请以管理员身份运行。",
  },
  [VerthysErrorCode.E_VERTHYS_CREATE_FAILED]: {
    title: "创建加密库失败",
    message: "加密库文件创建失败，可能因磁盘空间不足或路径权限问题。",
    guidance: "请检查目标磁盘剩余空间（至少需要 100MB）和目录写入权限后重试。",
  },
  [VerthysErrorCode.E_VERTHYS_UNLOCK_FAILED]: {
    title: "解锁加密库失败",
    message: "加密库解锁失败，可能因密码错误、文件损坏或连续超时触发熔断保护。",
    guidance: "1. 请确认密码输入正确；2. 若连续超时已触发熔断，请等待 30 分钟后重试或使用备份密钥恢复；3. 若文件已损坏，请使用备份文件恢复数据。",
  },

  // ===== 全局密钥 =====
  [VerthysErrorCode.E_GLOBAL_KEY_DERIVE_FAILED]: {
    title: "密钥派生失败",
    message: "全局主密钥派生失败，可能因系统资源不足或密码格式异常。",
    guidance: "请确保密码长度不少于 8 位，并关闭占用内存的程序后重试。",
  },
  [VerthysErrorCode.E_GLOBAL_KEY_VERIFY_FAILED]: {
    title: "密钥验证失败",
    message: "全局主密钥验证未通过，密码可能不正确。",
    guidance: "请重新输入正确的全局主密码。若忘记密码，请使用备份密钥恢复。",
  },
  [VerthysErrorCode.E_GLOBAL_KEY_RECORD_NOT_FOUND]: {
    title: "全局密钥记录缺失",
    message: "加密库中未找到全局主密钥记录，可能因文件损坏或未完成初始化。",
    guidance: "请重新初始化全局密钥。若已有数据，建议从备份恢复。",
  },
  [VerthysErrorCode.E_GLOBAL_KEY_PERSIST_FAILED]: {
    title: "密钥保存失败",
    message: "全局主密钥持久化到磁盘失败。",
    guidance: "请检查磁盘空间和写入权限后重试。切勿在保存完成前关闭应用。",
  },

  // ===== 设备绑定 =====
  [VerthysErrorCode.E_DEVICE_BINDING]: {
    title: "设备绑定异常",
    message: "设备绑定校验过程中发生错误。",
    guidance: "请重新进行设备绑定。若问题持续，请解除绑定后重新绑定。",
  },
  [VerthysErrorCode.E_DEVICE_BIND_FAILED]: {
    title: "设备绑定失败",
    message: "当前设备绑定到加密库失败。",
    guidance: "请以管理员身份运行应用后重试。",
  },
  [VerthysErrorCode.E_DEVICE_MISMATCH]: {
    title: "设备不匹配",
    message: "当前设备与加密库绑定的设备不一致，已拒绝访问以保护数据安全。",
    guidance: "如需在新设备上使用，请在原绑定设备上解除绑定，或使用备份密钥恢复数据。",
  },
  [VerthysErrorCode.E_DEVICE_UNBOUND]: {
    title: "设备未绑定",
    message: "当前加密库尚未绑定到任何设备。",
    guidance: "请在安全中心完成设备绑定以启用设备级保护。",
  },

  // ===== 模块密钥 =====
  [VerthysErrorCode.E_MODULE_KEY_NOT_FOUND]: {
    title: "模块密钥不存在",
    message: "指定模块的独立密钥尚未设置。",
    guidance: "请先在对应模块中设置独立访问密钥。",
  },
  [VerthysErrorCode.E_MODULE_VERIFY_FAILED]: {
    title: "模块验证失败",
    message: "模块独立密钥验证未通过。",
    guidance: "请输入正确的模块访问密钥。若忘记密码，可通过全局主密码重置模块密钥。",
  },
  [VerthysErrorCode.E_MODULE_KEY_SET_FAILED]: {
    title: "模块密钥设置失败",
    message: "模块独立密钥设置过程中发生错误。",
    guidance: "请确保加密库已解锁且全局密钥有效后重试。",
  },
  [VerthysErrorCode.E_MODULE_CONFIG_SAVE_FAILED]: {
    title: "模块配置保存失败",
    message: "模块安全配置持久化失败。",
    guidance: "请检查磁盘空间和写入权限后重试。",
  },
  [VerthysErrorCode.E_MODULE_NOT_READY]: {
    title: "模块未就绪",
    message: "指定模块尚未完成初始化。",
    guidance: "请等待模块初始化完成后再操作。",
  },
  [VerthysErrorCode.E_MODULE_VERTHYS_NOT_READY]: {
    title: "加密库未就绪",
    message: "加密库尚未解锁，模块功能不可用。",
    guidance: "请先解锁加密库后再使用模块功能。",
  },
};

/**
 * 将 VerthysErrorCode 转换为用户友好文案
 *
 * @param code VerthysErrorCode 业务错误码
 * @param originalMessage 可选的原始错误信息（用于日志，不展示给用户）
 * @returns VerthysUserErrorText 结构化用户文案（title + message + guidance）
 *
 * 使用示例：
 *   const result = await initUnlock(path);
 *   if (!result.ok) {
 *     const userText = translateVerthysError(result.code);
 *     showErrorDialog(userText.title, userText.message, userText.guidance);
 *   }
 */
export function translateVerthysError(
  code: VerthysErrorCode,
  originalMessage?: string,
): VerthysUserErrorText {
  const text = VERTHYS_ERROR_TEXT_MAP[code];
  if (text) {
    return text;
  }
  /* 未映射的错误码：返回通用文案，记录原始信息供排查 */
  return {
    title: "操作失败",
    message: "操作过程中发生未知错误，请稍后重试。",
    guidance: originalMessage
      ? `错误详情（供技术支持参考）：${originalMessage}`
      : "若问题持续，请联系技术支持并提供操作截图。",
  };
}

/**
 * 从 VerthysResult 失败值提取用户友好文案（便捷方法）
 *
 * @param result VerthysResult 失败值（result.ok === false）
 * @returns VerthysUserErrorText 结构化用户文案
 */
export function translateVerthysResult<T>(
  result: { ok: false; code: VerthysErrorCode; message: string; cause?: unknown },
): VerthysUserErrorText {
  return translateVerthysError(result.code, result.message);
}
