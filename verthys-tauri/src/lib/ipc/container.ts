/*
 * ipc/container.ts — 容器创建/解锁/PCR/keyfile/V4 模块与轮换/锁
 */

import { Channel } from "@tauri-apps/api/core";
import { VERTHYS_PRESET_BALANCED } from "../../constants/verthys_const";
import { ipc } from "./internal";
import { invalidateWorkerPreload } from "./worker";
import type {
  VerthysResponse,
  VerthysPreset,
  RotateProgress,
} from "../../types/verthys";

/** 创建新加密库（首次初始化专用，与 unlock 分离）
 *  流程：v4_create（创建 容器并返回一次性恢复码）→ lock（写盘）→ unlock（重开）
 *  失败自动回滚：删除不完整 .verthys 文件 + 销毁 worker
 *
 *  容器口令由后端本机保管，前端不参与，避免口令出现在界面与 IPC 参数中。
 *
 *  preset: 安全预设（VERTHYS_PRESET_*）
 *    - VERTHYS_PRESET_BALANCED (0)：日常推荐（默认）
 *    - VERTHYS_PRESET_SECURE (1)：涉密/合规
 *
 *  返回值包含 `recovery_code`；该字段只在本次响应内有效，调用方展示确认后
 *  必须丢弃，不得写入 localStorage、日志或持久化状态。
 */
export async function verthysCreate(
  verthysPath: string,
  preset: VerthysPreset = VERTHYS_PRESET_BALANCED,
  keyfilePath?: string,
): Promise<VerthysResponse> {
  const r = await ipc<VerthysResponse>("verthys_create", {
    verthysPath,
    preset,
    ...(keyfilePath ? { keyfilePath } : {}),
  });
  return r;
}

/** 第一层：选择即预热 — 用户选择 .verthys 文件后立即后台预读索引区到 OS 页缓存
 *  fire-and-forget：返回 true 表示预热已启动（不等待完成）
 *  安全边界：纯文件 I/O，不加载 DLL、不接触密钥、不解密任何数据
 *
 *  实现细节：
 *  - v2 格式：从超级块明文头部（前 128 字节）读取 index_region_off/size，
 *    顺序预读索引区到页缓存
 *  - v1 格式：顺序预读整个文件
 *  - 使用 Windows FILE_FLAG_SEQUENTIAL_SCAN 提示 OS 预读
 *  - 性能收益：磁盘 I/O 耗时从 3~5 秒移出关键路径，与密码输入时间重叠
 */
export async function verthysPreheat(verthysPath: string): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_preheat", { verthysPath });
  return r.ok;
}

/** 解锁已有加密库（worker 内调用容器解锁入口）
 *
 * 容器口令由后端本机保管，前端不传递任何口令。
 *
 * @param verthysPath 加密库文件路径
 * @param usbRebindConfirmed 介质标识变化确认（可选）：
 *   可移动介质已登记但序列号哈希不匹配时，默认阻止解锁；
 *   用户确认"合法更换介质"后置 true 重试——重绑定在凭据验证通过后落实。
 * @returns 解锁响应（含 has_global_key/global_key_id/global_key_record 进程内探测结果）
 */
export async function verthysUnlock(
  verthysPath: string,
  usbRebindConfirmed?: boolean,
  recoveryCode?: string,
  keyfilePath?: string,
): Promise<VerthysResponse> {
  /* 返回完整 VerthysResponse，含 worker 进程内探测的
   * has_global_key/global_key_id/global_key_record 三字段。
   * 调用方 initUnlock 直接消费，无需解锁后 probe IPC 链。 */
  const resp = await ipc<VerthysResponse>("verthys_unlock", {
    verthysPath,
    ...(usbRebindConfirmed ? { usbRebindConfirmed: true } : {}),
    ...(recoveryCode ? { recoveryCode } : {}),
    ...(keyfilePath ? { keyfilePath } : {}),
  });
  return resp;
}

/** PCR 状态查询（不返回密钥；未解锁返回 ok=false） */
export async function verthysPcrStatus(): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_pcr_status", {});
}

/** keyfile 因子状态（仅已解锁会话可查询） */
export async function verthysKeyfileStatus(): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_keyfile_status", {});
}

/** 恢复会话重绑本机容器槽：恢复码解锁后调用，使本机普通解锁恢复可用。
 *  keyfile 仅在容器启用 keyfile 时提供；文件内容不进入前端。 */
export async function verthysResealDevice(keyfilePath?: string): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_reseal_device", {
    ...(keyfilePath ? { keyfilePath } : {}),
  });
}

/** 启用/轮换 keyfile：keyfile 文件由 C 层生成，前端只给保存路径 */
export async function verthysKeyfileEnable(keyfilePath: string): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_keyfile_enable", { keyfilePath });
}

/** 关闭 keyfile：普通会话需当前 keyfile 路径；恢复会话可省略（keyfile 丢失逃生） */
export async function verthysKeyfileDisable(keyfilePath?: string): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_keyfile_disable", {
    ...(keyfilePath ? { keyfilePath } : {}),
  });
}

/** 启用 PCR 绑定；恢复码只经本次 IPC 传递，调用方不得缓存 */
export async function verthysPcrEnable(
  pcrSelect: number,
  recoveryCode: string,
): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_pcr_enable", { pcrSelect, recoveryCode });
}

/** 关闭 PCR 绑定 */
export async function verthysPcrDisable(recoveryCode: string): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_pcr_disable", { recoveryCode });
}

/** 用当前 PCR 重密封（恢复会话可传空恢复码） */
export async function verthysPcrReseal(recoveryCode: string): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_pcr_reseal", { recoveryCode });
}

/** 轮换一次性恢复码；成功响应含新恢复码，确认后必须清零 */
export async function verthysRecoveryRotate(
  oldRecoveryCode: string,
): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_recovery_rotate", { oldRecoveryCode });
}

/** 查询 模块状态（不含密钥） */
export async function verthysV4ModuleStatus(moduleId: number): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_module_status", { moduleId });
}

/** 启用 模块保护（password 为模块口令；recoveryCode 可选，用于绑定恢复槽） */
export async function verthysV4ModuleEnable(
  moduleId: number,
  password: string,
  recoveryCode?: string,
): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_module_enable", {
    moduleId,
    password,
    ...(recoveryCode ? { recoveryCode } : {}),
  });
}

/** 轮换 模块口令（只重封 user 槽，不重写数据） */
export async function verthysV4ModuleRotatePassword(
  moduleId: number,
  oldPassword: string,
  newPassword: string,
): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_module_rotate_password", {
    moduleId,
    oldPassword,
    newPassword,
  });
}

/** 关闭 模块保护（保留 MDEK 与数据，MDEK 回到 Keyring） */
export async function verthysV4ModuleDisable(
  moduleId: number,
  password: string,
): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_module_disable", { moduleId, password });
}

/** 删除 模块（不可逆；confirm 必须为 "DELETE"） */
export async function verthysV4ModuleDelete(
  moduleId: number,
  confirm: string,
): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_module_delete", { moduleId, confirm });
}

/** 绑定模块恢复槽（模块口令 + 容器恢复码）；绑定后支持换机恢复该模块 */
export async function verthysV4ModuleBindRecovery(
  moduleId: number,
  password: string,
  recoveryCode: string,
): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_module_bind_recovery", {
    moduleId,
    password,
    recoveryCode,
  });
}

/** 换机后重密封模块设备槽；仅恢复码解锁的会话可用 */
export async function verthysV4ModuleResealDevice(
  moduleId: number,
  password: string,
): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_module_reseal_device", {
    moduleId,
    password,
  });
}

/* ===== 全库 DEK 轮换（作业式五段） ===== */

/** 开始全库轮换：仅恢复码会话可用；flags bit0=移除 PCR 绑定。
 *  newPath 必须是不存在且与源库同目录的绝对路径（由 C 层最终裁决）。 */
export async function verthysV4RotateBegin(
  newPath: string,
  flags = 0,
): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_rotate_begin", { newPath, flags });
}

/** 登记一个已启用模块的轮换口令（password 为模块口令，不是容器口令） */
export async function verthysV4RotateUnlockModule(
  moduleId: number,
  password: string,
  recoveryCode?: string,
): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_rotate_unlock_module", {
    moduleId,
    password,
    ...(recoveryCode ? { recoveryCode } : {}),
  });
}

/** 全量复制并提供进度；成功后需 Commit，失败只能 Abort。
 *  进度行经 Tauri Channel 流式推送；Promise 结束后丢弃残留消息。 */
export async function verthysV4RotateRun(
  onProgress?: (progress: RotateProgress) => void,
): Promise<VerthysResponse> {
  const channel = new Channel<RotateProgress>();
  let completed = false;
  if (onProgress) {
    channel.onmessage = (p: RotateProgress) => {
      if (!completed) onProgress(p);
    };
  }
  try {
    return await ipc<VerthysResponse>("verthys_rotate_run", {
      onProgress: channel,
    });
  } finally {
    completed = true;
  }
}

/** 原子替换源库并推进回退锚点；keepOld 默认 true，保留 .old-* 兜底备份 */
export async function verthysV4RotateCommit(keepOld = true): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_rotate_commit", { keepOld });
}

/** 恢复会话补录 keyfile：容器启用 KEYFILE 且会话未持有摘要时使用。
 *  只传路径；文件由 C 层在 worker 进程内读取。 */
export async function verthysV4RotateAttachKeyfile(
  keyfilePath: string,
): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_rotate_attach_keyfile", { keyfilePath });
}

/** 请求取消正在进行的轮换 Run（仅解锁模块与复制阶段可用）。 */
export async function verthysV4RotateCancel(): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_rotate_cancel");
}

/** 丢弃临时库并释放作业；成功后句柄仍指向原库 */
export async function verthysV4RotateAbort(): Promise<VerthysResponse> {
  return await ipc<VerthysResponse>("verthys_rotate_abort", {});
}

/** 持久化落盘（发送 lock 指令并等待响应，不销毁 worker） */
export async function verthysLockPersist(): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_lock_persist");
  return r.ok;
}

/** 锁定前置闸门：请求取消并等待全库轮换 Run 收敛（后端有界 30s）
 *
 *  必须在任何破坏性锁定步骤（清 GMK / 落盘 / 销毁 worker）之前调用。
 *  失败表示轮换仍在执行：本次锁定必须整体放弃并保留会话与空闲计时，
 *  不得继续清密钥/销毁 worker 造成“界面已锁定、worker 仍持有 GMK”。 */
export async function verthysPrepareLock(): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_prepare_lock");
  return r.ok;
}

/** 销毁 worker 并清理资源（剪贴板+文件锁）
 *  注意：verthys_lock 会销毁 worker 子进程，因此必须在 finally 作废预启动缓存，
 *    确保 IPC 超时/异常时也不残留指向死 worker 的 workerReadyPromise */
export async function verthysLock(): Promise<boolean> {
  try {
    const r = await ipc<VerthysResponse>("verthys_lock");
    return r.ok;
  } finally {
    // 无论 verthys_lock 成功/失败/超时，都作废预启动缓存
    invalidateWorkerPreload();
  }
}

/** 刷新加密库（直接触发 worker 落盘，不清零密钥、不改变解锁状态）
 *  容器口令由后端本机保管，前端不传递；目标容器由当前解锁会话确定。 */
export async function verthysFlush(): Promise<boolean> {
  const r = await ipc<VerthysResponse>("verthys_flush");
  return r.ok;
}

/** 落盘自查结果（判别式返回） */
export interface VerifyDiskPersistResult {
  /** 落盘结构是否完整（statusCode === 0） */
  ok: boolean;
  /** C 端 VerPersistStatus：0=OK / 1=HEADER / 2=SIZE / 3=WAL / 4=IO / 5=INTERNAL */
  statusCode: number;
  /** 容器文件字节大小（失败时为 0） */
  fileSize: number;
  /** 文件修改时间（Unix 毫秒；不可得为 0） */
  mtimeMs: number;
  /** 磁盘偏移 0 的副本帧头 magic */
  headerMagic: number;
  /** 容器格式版本 */
  headerVersion: number;
  /** 失败详情（成功为空串） */
  lastError: string;
}

/** 落盘持久化自查（worker 进程内 C 层持锁句柄）
 *
 *  why 不在主进程读盘：容器会话在 C 层子进程内以独占方式持有超级块区
 *  [0,64KB) 字节范围锁（Windows 强制锁），主进程新开句柄读取恒被
 *  ERROR_LOCK_VIOLATION 拒绝。故校验经 worker 的 verify_persist op 下发到
 *  持锁子进程，由 C 层用会话持锁句柄自查盘面结构（头部帧头、
 *  文件大小下限、WAL 区可达性）。
 *
 *  返回判别式结果：statusCode 供上层区分"可重试 IO 失败"与"结构性失败"。
 *  @returns 结构化自查结果（ok=true 表示结构完整）
 */
export async function verthysVerifyDiskPersist(): Promise<VerifyDiskPersistResult> {
  const r = await ipc<VerthysResponse>("verthys_verify_disk_persist", {});
  return {
    ok: r.ok,
    statusCode: r.status_code ?? -1,
    fileSize: r.file_size ?? 0,
    mtimeMs: r.mtime_ms ?? 0,
    headerMagic: r.header_magic ?? 0,
    headerVersion: r.header_version ?? 0,
    lastError: r.error ?? "",
  };
}
