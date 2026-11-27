/*
 * ipc/modules.ts — 模块内容加密/隐私/剪贴板/文件 IO/设备绑定/安全防护
 */

import { invokeWithTimeout } from "../../utils/ipc/invoke_wrapper";
import { wrapAsVerthysError } from "../util/verthys_error";
import { ipc } from "./internal";
import type {
  VerthysResponse,
  PrivacyModeResult,
  PrivacyStatusResult,
  ClipboardResult,
  DeviceBindingResult,
  BruteForceCheckResponse,
  BruteForceStatus,
  UnknownModuleInfo,
  ShadowSleepStatus,
  UsbVolumeStatus,
  SecurityPresetCode,
  PresetConfig,
  PresetFeatures,
} from "../../types/verthys";

/* ------------------------------------------------------------------ *
 * 内容层加密（密钥托管在 worker，前端只传模块名、公开参数与包裹态密钥）
 * ------------------------------------------------------------------ */

/** 内容记录加解密参数（密文/明文均为 base64，不含原始密钥） */
export interface ModuleCryptParams {
  /** 模块标识（photo / file） */
  module: string;
  /** 布局种类（meta / chunk / slim_meta / slim_chunk / thumb / chunkset / v2_chunk / v2_check） */
  kind: string;
  /** 载荷 base64（写入时为明文，读取时为密文） */
  data?: string;
  /** 文件盐 base64（索引瘦身布局必填；既有布局可省略由 worker 生成） */
  salt?: string;
  /** BLAKE3 文件哈希（64 字符十六进制） */
  fileHash?: string;
  /** 块序号与块总数（chunk / slim_chunk 写入必填） */
  seq?: number;
  total?: number;
  /** 文件块 v2 的 PBKDF2 迭代次数（0/缺省 = worker 缺省值） */
  iterations?: number;
  /** 包裹态文件密钥（slim_chunk / thumb / chunkset 必填） */
  wrappedKey?: string;
  /** 文件块 v2 的独立口令（v2_chunk / v2_check 必填；密钥由 worker 派生） */
  password?: string;
}

/** 解锁模块密钥：把模块口令一次性交付 worker 托管，前端不再保留 */
export async function verthysModuleKeyUnlock(
  module: string,
  password: string,
): Promise<VerthysResponse> {
  return ipc<VerthysResponse>("verthys_module_key_unlock", { module, password });
}

/** 清除模块密钥；不传 module 表示全部清除（锁定/登出必调） */
export async function verthysModuleKeyLock(module?: string): Promise<VerthysResponse> {
  return ipc<VerthysResponse>("verthys_module_key_lock", { module });
}

/** 加密内容记录 */
export async function verthysModuleSeal(
  params: ModuleCryptParams,
): Promise<VerthysResponse> {
  return ipc<VerthysResponse>("verthys_module_seal", {
    module: params.module,
    kind: params.kind,
    data: params.data,
    salt: params.salt,
    fileHash: params.fileHash,
    seq: params.seq,
    total: params.total,
    iterations: params.iterations,
    wrappedKey: params.wrappedKey,
    password: params.password,
  });
}

/** 解密内容记录（chunk 布局额外返回密文内嵌的 seq/total） */
export async function verthysModuleOpen(
  params: ModuleCryptParams,
): Promise<VerthysResponse> {
  return ipc<VerthysResponse>("verthys_module_open", {
    module: params.module,
    kind: params.kind,
    data: params.data,
    salt: params.salt,
    fileHash: params.fileHash,
    seq: params.seq,
    total: params.total,
    iterations: params.iterations,
    wrappedKey: params.wrappedKey,
    password: params.password,
  });
}

/**
 * 外层信封探测（损坏扫描专用）
 *
 * 只验证记录能否被当前模块密钥解封，不要求文件口令、不校验布局种类标签。
 * 返回 ok=true 表示外层完整；AUTH 表示确定损坏；LOCKED/POLICY 表示不可判定。
 */
export async function verthysModuleProbeOuter(params: {
  module: string;
  data: string;
}): Promise<VerthysResponse> {
  return ipc<VerthysResponse>("verthys_module_probe_outer", {
    module: params.module,
    data: params.data,
  });
}

/**
 * 设置防截屏保护（窗口捕获排除）
 *
 * 开启（enabled=true）整体成功或整体失败，成功后返回一次性会话凭证
 * （session_token），前端需存储并在关闭时作为 authToken 传入。
 * 关闭（enabled=false）失败时凭证保留在状态机内，可用同一凭证立即重试；
 * 关闭成功后凭证即失效。返回 PrivacyModeResult 结构化结果：
 *   - ok=true, enabled=true：保护已启用（session_token 存在）
 *   - ok=true, enabled=false：保护已关闭（凭证已消费）
 *   - ok=false：按 error_code 分支（PRIVACY_* 系列 / RATE_LIMITED）
 */
export async function setPrivacyMode(
  enabled: boolean,
  authToken?: string,
): Promise<PrivacyModeResult> {
  return await ipc<PrivacyModeResult>("set_privacy_mode", {
    enabled,
    authToken: authToken ?? null,
  });
}

/**
 * 查询防截屏保护状态快照（只读幂等，不限流）
 *
 * 前端据此决定按钮状态、是否需要接管会话（slot=pending_adoption）
 * 与是否给出隔离恢复入口（state=quarantined）。
 */
export async function getPrivacyStatus(): Promise<PrivacyStatusResult> {
  return await ipc<PrivacyStatusResult>("get_privacy_status");
}

/**
 * 采纳保护会话（启动恢复与对账后的接管）
 *
 * 后端在启动保护生效与对账收敛到启用后，把凭证槽位置为待采纳：
 * 前端调用本命令取得一次性会话凭证（session_token），并进入生效态。
 * 重复采纳返回 ok=true（会话已接管），无需按错误处理。
 */
export async function adoptPrivacySession(): Promise<PrivacyModeResult> {
  return await ipc<PrivacyModeResult>("adopt_privacy_session");
}

/**
 * 隔离对账（仅在保护处于隔离状态时可达）
 *
 * 按失败前的稳定状态全窗口重扫收敛：稳定状态为启用则重新加固保护并回到待采纳
 * （前端随后需再次采纳取得新凭证）；稳定状态为关闭则清除残留保护。
 */
export async function reconcilePrivacy(): Promise<PrivacyModeResult> {
  return await ipc<PrivacyModeResult>("reconcile_privacy");
}

/**
 * 事务式安全清空剪贴板（多次覆写 + 重试）
 *
 * 完整事务序列：OpenClipboard → EmptyClipboard → 3 轮随机覆写 → 最终清空。
 * 剪贴板被占用时自动重试（50ms × 3）。
 *
 * 返回 ClipboardResult 结构化结果：
 *   - ok=true：剪贴板已安全擦除
 *   - ok=false, error_code=CLIPBOARD_LOCKED：剪贴板被占用，重试后仍失败
 *   - ok=false, error_code=RATE_LIMITED：频率超限（>10次/分钟）
 */
export async function clearClipboard(): Promise<ClipboardResult> {
  return await ipc<ClipboardResult>("clear_clipboard");
}

/** 读取文件字节（二进制 IPC：返回原始 Uint8Array，去 base64 化）
 *
 *  后端返回 tauri::ipc::Response → invoke 直接收到 ArrayBuffer，
 *  内存峰值 ×1（base64 路径为 ×2.66：Rust b64 串 + JSON 串 + 前端解码）。
 *
 *  ⚠ 白名单限制：仅允许 app_data / app_config / Documents / Pictures /
 *    Downloads / home_dir / desktop_dir 内的文件。非用户主目录路径
 *    （如 D:\、E:\、网络位置）会被沙箱拒绝。
 *
 *  适用场景：读取应用内部文件、已知白名单路径文件。
 *  不适用：用户通过文件对话框 open() 选择的任意路径文件 → 用 readUserFile。 */
export async function readFileBytes(path: string): Promise<Uint8Array> {
  const buf = await ipc<ArrayBuffer>("read_file_bytes", { path });
  return new Uint8Array(buf);
}

/** 写入原始字节到文件（二进制 IPC：raw body 直传，去 base64 化）
 *
 *  字节经请求体直传（Tauri v2 raw IPC），目标路径经 x-path 请求头传递。
 *  路径经 encodeURIComponent 百分号编码 — HTTP 头仅允许可见 ASCII，
 *  中文用户名路径（如 C:\Users\张三\）必须编码传输，Rust 端严格解码。
 *
 *  ⚠ 白名单限制：同 readFileBytes，仅允许白名单路径。
 *  用户通过对话框 save() 选择的任意路径 → 用 writeUserFile。 */
export async function writeFileBytes(path: string, data: Uint8Array): Promise<void> {
  try {
    await invokeWithTimeout<void>("write_file_bytes", data, undefined, {
      headers: { "x-path": encodeURIComponent(path) },
    });
  } catch (e) {
    throw wrapAsVerthysError(e);
  }
}

/** 读取用户通过对话框显式选择的文件字节（二进制 IPC）
 *
 *  返回原始 Uint8Array（后端 tauri::ipc::Response 二进制通道）。
 *
 *  与 readFileBytes 的区别：跳过沙箱白名单校验（用户已通过 Tauri dialog
 *  open() 显式授权），允许读取任意磁盘/网络位置的文件。
 *
 *  安全保障（后端 read_user_file 命令）：
 *  - validate_path_input 字符级校验（防路径注入、目录遍历、保留设备名）
 *  - canonicalize 解析符号链接（确保路径真实）
 *  - 系统关键目录拒绝（C:\Windows、C:\Program Files 等）
 *  - 文件大小限制（2GB）
 *  - 超时控制（10s）+ 审计日志
 *
 *  适用场景：拾光解析功能导入 .venc 文件、导入照片、读取 .bin 密钥文件等
 *  用户通过文件对话框显式选择的文件。 */
export async function readUserFile(path: string): Promise<Uint8Array> {
  // 分片参数显式置空：后端按"双缺省 = 整文件读取"判定；显式传 null 使
  // 调用面不依赖"参数缺省"的解析差异。
  const buf = await ipc<ArrayBuffer>("read_user_file", { path, offset: null, length: null });
  return new Uint8Array(buf);
}

/** 用户授权文件的元数据快照（后端 user_file_stat 契约） */
export interface UserFileStat {
  /** 文件长度（字节） */
  size: number;
  /** 最后修改时间（Unix 纪元毫秒） */
  mtime_ms: number;
}

/** 读取用户授权文件的元数据（长度 + 修改时间）
 *
 *  用途：分块规划（按长度与分块口径推出块数）与导入身份基线
 *  （导入期间按批边界复查 `(size, mtime_ms)`，源文件被改写即中止）。
 *
 *  安全链与 readUserFile 一致：字符级校验 + canonicalize + 系统关键目录拒绝。 */
export async function userFileStat(path: string): Promise<UserFileStat> {
  return await ipc<UserFileStat>("user_file_stat", { path });
}

/** 磁盘剩余空间读数（后端 check_disk_space 契约） */
export interface DiskSpaceInfo {
  /** 剩余可用字节数 */
  free_bytes: number;
}

/** 查询路径所在卷的剩余磁盘空间（字节）
 *
 *  `path` 缺省 = 当前会话容器所在卷（导入前预检容器卷）；
 *  显式路径 = 该路径所在卷（导出前预检目标卷；目标未创建时按父目录卷查询）。 */
export async function checkDiskSpace(path?: string): Promise<DiskSpaceInfo> {
  return await ipc<DiskSpaceInfo>("check_disk_space", { path: path ?? null });
}

/** 分片读取用户授权文件（读取 `[offset, offset + length)`）
 *
 *  与 readUserFile 的差别：单次只搬运一个分片（≤ 流式写入分片上界），
 *  内存占用与文件大小无关。
 *
 *  契约（后端强制，越界即报错）：
 *  - offset 与 length 必须成对给出；length 必须大于 0；
 *  - offset 不得越过文件长度，offset + length 不得越过文件末尾；
 *  - 返回字节数恒等于 length（源文件被并发截断时后端报错，不静默截断）。 */
export async function readUserFileChunked(
  path: string,
  offset: number,
  length: number,
): Promise<Uint8Array> {
  const buf = await ipc<ArrayBuffer>("read_user_file", { path, offset, length });
  return new Uint8Array(buf);
}

/** 写入原始字节到用户通过对话框选择的位置（二进制 IPC）
 *
 *  字节经请求体直传（Tauri v2 raw IPC），目标路径经 x-path 请求头传递，
 *  消除 base64 编码 1.33× 内存放大与编解码 CPU 开销。
 *  路径经 encodeURIComponent 百分号编码 — HTTP 头仅允许可见 ASCII，
 *  中文用户名路径（如 C:\Users\张三\）必须编码传输，Rust 端严格解码。
 *
 *  与 writeFileBytes 的区别：跳过沙箱白名单校验（用户已通过 Tauri dialog
 *  save() 显式授权保存位置），允许写入任意磁盘/网络位置。
 *
 *  安全保障：同 readUserFile（系统关键目录拒绝 + 其他安全检查）。
 *
 *  适用场景：导出加密照片到用户选择的保存位置等。 */
export async function writeUserFile(path: string, data: Uint8Array): Promise<void> {
  try {
    await invokeWithTimeout<void>("write_user_file", data, undefined, {
      headers: { "x-path": encodeURIComponent(path) },
    });
  } catch (e) {
    throw wrapAsVerthysError(e);
  }
}

/* ------------------------------------------------------------------ *
 * 单文件导出流式写入（暂存 + 原子替换）                                *
 *                                                                    *
 * 大文件导出不整包直传，按以下流程写入（峰值内存与容器体积无关）： *
 *   writeUserFileStream 建会话（后端独占创建暂存）→                   *
 *   appendUserFileChunk 逐帧追加原始字节 →                            *
 *   finalizeUserFileStream 后端 fsync + rename 原子替换目标。         *
 * 失败路径调用 abortUserFileStream 清理暂存；任何时刻目标文件          *
 * 要么是旧完整版、要么是新完整版，不存在部分写入的最终文件。           *
 * ------------------------------------------------------------------ */

/** 创建流式写入会话并返回会话标识（32 位小写 hex）
 *
 *  目标路径安全链与 writeUserFile 一致（字符校验 + canonicalize +
 *  系统关键目录拒绝）；同目标并发创建第二个会话因暂存独占而失败。 */
export async function writeUserFileStream(path: string): Promise<string> {
  try {
    return await invokeWithTimeout<string>("write_user_file_stream", { path });
  } catch (e) {
    throw wrapAsVerthysError(e);
  }
}

/** 向流式会话追加原始数据块（二进制 IPC）
 *
 *  块字节经请求体直传（Tauri v2 raw IPC），会话标识经 x-stream-id
 *  请求头传递 — raw body 与 JSON 参数互斥，与 writeUserFile 的
 *  x-path 同机制；标识为 32 位小写 hex，天然满足头值字符约束。 */
export async function appendUserFileChunk(streamId: string, data: Uint8Array): Promise<void> {
  try {
    await invokeWithTimeout<void>("append_user_file_chunk", data, undefined, {
      headers: { "x-stream-id": streamId },
    });
  } catch (e) {
    throw wrapAsVerthysError(e);
  }
}

/** 终结流式会话：后端同步落盘暂存并以原子替换方式改名到目标路径 */
export async function finalizeUserFileStream(streamId: string): Promise<void> {
  try {
    await invokeWithTimeout<void>("finalize_user_file_stream", { streamId });
  } catch (e) {
    throw wrapAsVerthysError(e);
  }
}

/** 中止流式会话：后端删除暂存文件（幂等，会话不存在视为成功） */
export async function abortUserFileStream(streamId: string): Promise<void> {
  try {
    await invokeWithTimeout<void>("abort_user_file_stream", { streamId });
  } catch (e) {
    throw wrapAsVerthysError(e);
  }
}

/* ------------------------------------------------------------------ *
 * 设备机器码                                                          *
 * ------------------------------------------------------------------ */

/** 获取当前设备机器码（SHA-256 hex） */
export async function getDeviceFingerprint(): Promise<string> {
  return await ipc<string>("get_device_fingerprint");
}

/** 绑定当前设备机器码到状态文件（首次初始化全局密钥时调用） */
export async function setDeviceBinding(): Promise<void> {
  await ipc<void>("set_device_binding");
}

/**
 * 校验当前设备机器码是否匹配（返回结构化结果）
 *
 * 返回 types/verthys.ts 的 DeviceBindingResult 规范类型（单一数据源，
 * 与后端 controller/types.rs serde 序列化严格一致）。 */
export async function checkDeviceBinding(): Promise<DeviceBindingResult> {
  return await ipc<DeviceBindingResult>("check_device_binding");
}

/* ====================================================================== *
 * 安全防护模块（security_commands.rs 对应封装）                          *
 *                                                                        *
 * 七组共 23 个 Tauri 命令的前端封装：
 *   1. 暴力拦截（brute_force）
 *   2. 会话守卫（session_guard）
 *   3. 模块巡检（module_whitelist）
 *   4. 痕迹清理（cleanup）
 *   5. 文件锁与 ACL（file_lock）
 *   6. USB 安全（usb_guard）
 *   7. 三档预设查询（preset）
 * ====================================================================== */

/* -------------------- 1. 暴力拦截 -------------------- */

/** 检查当前是否允许尝试解锁 */
export async function securityBruteCheck(): Promise<BruteForceCheckResponse> {
  return await ipc<BruteForceCheckResponse>("security_brute_check");
}

// 失败计数与成功重置的记录接口已上移服务端口令类命令入口（unlock /
// verify_global_key）权威执行，前端不再提供记录封装，防止同一失败
// 被前后端各计一次。此处仅保留查询类纯读操作。

/** 获取暴力拦截状态快照 */
export async function securityBruteStatus(): Promise<BruteForceStatus> {
  return await ipc<BruteForceStatus>("security_brute_status");
}

/* -------------------- 2. 会话守卫 -------------------- */

/** 启动会话守卫（监听系统锁屏/解锁事件） */
export async function securitySessionStart(): Promise<void> {
  await ipc<void>("security_session_start");
}

/** 停止会话守卫 */
export async function securitySessionStop(): Promise<void> {
  await ipc<void>("security_session_stop");
}

/** 设置会话硬化开关（挂起锁定 / 剪贴板监听，两项独立启停）
 *  后端以 SecurityResult 包装返回：授权拒绝（会话未解锁）时 ok=false，
 *  剪贴板监听启动失败时同样 ok=false（挂起标志已生效，错误码可区分），
 *  此处不抛错，将 ok 透传给调用方以便可见地报告失败。 */
export async function securitySessionSetHardening(
  suspendLock: boolean,
  clipboardMonitor: boolean,
): Promise<boolean> {
  const r = await ipc<{ ok: boolean }>("security_session_set_hardening", {
    suspendLock,
    clipboardMonitor,
  });
  return r.ok === true;
}

/* -------------------- 3. 模块巡检 -------------------- */

/** 巡检当前进程已加载模块，返回未知/可疑模块列表
 *  install_dir 为应用安装目录（主 EXE 所在目录） */
export async function securityModulePatrol(installDir: string): Promise<UnknownModuleInfo[]> {
  return await ipc<UnknownModuleInfo[]>("security_module_patrol", { installDir });
}

/** 添加受信任路径到白名单 */
export async function securityAddTrustedPath(path: string): Promise<void> {
  await ipc<void>("security_add_trusted_path", { path });
}

/** 清空受信任路径白名单 */
export async function securityClearTrustedPaths(): Promise<void> {
  await ipc<void>("security_clear_trusted_paths");
}

/* -------------------- 4. 痕迹清理 -------------------- */

/** 清空系统最近使用记录（Recent + 跳转列表 + 通知 Shell） */
export async function securityCleanupRecent(): Promise<void> {
  await ipc<void>("security_cleanup_recent");
}

/** 安全删除文件（Gutmann 35-pass 或 Simple 3-pass 覆写后删除）
 *  mode: "gutmann"=35-pass, "simple"=3-pass */
export async function securitySecureDelete(path: string, mode: "gutmann" | "simple"): Promise<void> {
  await ipc<void>("security_secure_delete", { path, mode });
}

/** 清理崩溃残留临时文件，返回清理文件数 */
export async function securityCleanupCrashResidue(tempDir: string): Promise<number> {
  return await ipc<number>("security_cleanup_crash_residue", { tempDir });
}

/* -------------------- 5. 文件锁与 ACL -------------------- */

/** 加固私有目录 ACL（当前用户完全控制，其他用户拒绝访问） */
export async function securityHardenPrivateDir(dir: string): Promise<void> {
  await ipc<void>("security_harden_private_dir", { dir });
}

/* -------------------- 6. USB 安全 -------------------- */

/** 读取 USB 设备序列号哈希（drive_letter 如 "E"） */
export async function securityUsbReadSerial(driveLetter: string): Promise<string> {
  return await ipc<string>("security_usb_read_serial", { driveLetter });
}

/** 注册已知 USB 设备（卷标 + 序列号哈希；需已解锁会话）
 *  后端以 SecurityResult 包装返回：授权拒绝/容量超限等情形 ok=false，
 *  此处不抛错，将结果透传以便调用方可见报告 */
export async function securityUsbRegisterDevice(
  volumeLabel: string,
  serialHash: string
): Promise<{ ok: boolean; detail: string; error_code?: string }> {
  return await ipc<{ ok: boolean; detail: string; error_code?: string }>(
    "security_usb_register_device",
    { volumeLabel, serialHash }
  );
}

/** 检测克隆外设（trusted=已登记且哈希匹配 / clone=序列号不匹配 / unknown=未登记） */
export async function securityUsbCheckClone(
  volumeLabel: string,
  serialHash: string
): Promise<"Trusted" | "Clone" | "Unknown"> {
  return await ipc<"Trusted" | "Clone" | "Unknown">("security_usb_check_clone", {
    volumeLabel,
    serialHash,
  });
}

/** 检测容器所在介质的绑定状态（永不阻断，仅报告 + 审计留痕）
 *  verdict：trusted / clone_suspected / first_use / not_applicable /
 *           disabled_by_preset / undetermined */
export async function securityUsbVolumeStatus(
  verthysPath: string
): Promise<UsbVolumeStatus> {
  return await ipc<UsbVolumeStatus>("security_usb_volume_status", { verthysPath });
}

/** 登记当前容器所在的可移动介质（需已解锁会话）
 *  固定盘 / 非盘符挂载点 → ok=false + error_code=NOT_APPLICABLE（无需登记） */
export async function securityUsbRegisterCurrent(
  verthysPath: string
): Promise<{ ok: boolean; detail: string; error_code?: string }> {
  return await ipc<{ ok: boolean; detail: string; error_code?: string }>(
    "security_usb_register_current",
    { verthysPath }
  );
}

/** 重新绑定介质（需已解锁会话；改写既有登记记录，卷标未登记时拒绝） */
export async function securityUsbRebindDevice(
  volumeLabel: string,
  serialHash: string
): Promise<{ ok: boolean; detail: string; error_code?: string }> {
  return await ipc<{ ok: boolean; detail: string; error_code?: string }>(
    "security_usb_rebind_device",
    { volumeLabel, serialHash }
  );
}

/** 进入影子休眠（外设拔出后加密索引驻留内存）
 *  timeoutMin: 休眠超时（分钟），超时自动 purge */
export async function securityUsbShadowSleep(
  encryptedIndexB64: string,
  txid: number,
  timeoutMin: number
): Promise<void> {
  await ipc<void>("security_usb_shadow_sleep", {
    encryptedIndexB64,
    txid,
    timeoutMin,
  });
}

/** 尝试从影子休眠恢复加密索引，返回 base64 或 null */
export async function securityUsbTryRecover(txid: number): Promise<string | null> {
  return await ipc<string | null>("security_usb_try_recover", { txid });
}

/** 清除影子休眠中的加密索引（3-round 覆写后清零） */
export async function securityUsbPurge(): Promise<void> {
  await ipc<void>("security_usb_purge");
}

/** 查询影子休眠状态 */
export async function securityUsbShadowStatus(): Promise<ShadowSleepStatus> {
  return await ipc<ShadowSleepStatus>("security_usb_shadow_status");
}

/* -------------------- 7. 预设查询 -------------------- */

/** 获取三档安全预设的配置详情
 *  preset: 0=BALANCED, 1=SECURE, 2=PERFORMANCE */
export async function securityGetPresetConfig(preset: SecurityPresetCode): Promise<PresetConfig> {
  return await ipc<PresetConfig>("security_get_preset_config", { preset });
}

/** 运行时切换安全预设：后端会话授权 → 原子落盘受信文件 → worker →
 *  C 层双缓冲切档（0/1/2 档），成功后返回新档真实配置；失败抛错（明确错误码）。
 *  CUSTOM(3) 无 C 层档位：落盘自定义特性与空闲锁定时长，会话层开关由调用方组合。 */
export async function securityApplyPreset(
  code: 0 | 1 | 2 | 3,
  features?: PresetFeatures,
  customSessionTimeoutMinutes?: number,
): Promise<PresetConfig> {
  return await ipc<PresetConfig>("security_apply_preset", {
    code,
    features,
    customSessionTimeoutMinutes,
  });
}

/** 受信持久化的预设状态（后端权威副本）
 *  code: 0=BALANCED, 1=SECURE, 2=PERFORMANCE, 3=CUSTOM
 *  customFeatures: 仅 code=3 时存在
 *  customSessionTimeoutMinutes: 仅 code=3 时存在（空闲锁定时长，分钟） */
export interface PresetPersistState {
  code: number;
  customFeatures?: PresetFeatures | null;
  customSessionTimeoutMinutes?: number | null;
}

/** 受信持久化读取响应：state 为权威副本（无配置时 null）；
 *  persistDirty 为持久化不一致标记（回滚失败后为真，任意成功落盘即清除） */
export interface PresetLoadResponse {
  state: PresetPersistState | null;
  persistDirty: boolean;
}

/** 读取受信持久化的预设状态（含持久化不一致标记） */
export async function securityLoadPresetState(): Promise<PresetLoadResponse> {
  return await ipc<PresetLoadResponse>("security_load_preset_state");
}
