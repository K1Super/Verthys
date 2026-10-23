/*
 * useAppUpdater — 应用内更新状态与动作
 *
 * 状态为模块级单例：启动静默检查与管理界面按钮共享同一结果。
 * 所有安全判定在 Rust 更新服务完成；本文件只维护 UI 状态、进度与用户动作，
 * 不直接调用插件的下载或安装接口。
 */
import { readonly, ref } from "vue";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
import { markUpdaterCritical } from "./updater-critical";

/** Rust 侧更新检查结果，字段与命令返回值一一对应。 */
export interface AvailableUpdate {
  updateId: string;
  currentVersion: string;
  version: string;
  date?: string;
  notes?: string;
  releaseId: string;
  channel: string;
  fileVersion: string;
  size: number;
  forceUpdate: boolean;
}

/** 准备完成的安装包元数据。 */
export interface PreparedUpdate {
  updateId: string;
  version: string;
  releaseId: string;
  sha256: string;
  size: number;
  fileVersion: string;
}

/** 锁库结果由会话层返回，安装闸门只接受 clean=true。 */
export interface LockOutcome {
  clean: boolean;
  flushed: boolean;
  dirty: boolean;
  errors: string[];
  durationMs: number;
}

/** Rust 在锁库前签发的挑战；只能兑换一次安装回执。 */
export interface LockChallenge {
  challenge: string;
  releaseId: string;
  sha256: string;
  expiresInMs: number;
}

/** 锁库完成后签发的一次性安装回执。 */
export interface LockReceipt {
  receipt: string;
  expiresInMs: number;
}

/** 启动阶段；前端按 phase 决定自检、等待安装或进入修复。 */
export type UpdaterStartupPhase =
  | "none"
  | "health_check"
  | "install_in_progress"
  | "install_failed"
  | "marker_invalid"
  | "repair_available"
  | "repair_confirmed";

/** 启动状态；hasPending 为真时前端必须触发 Rust 健康自检。 */
export interface UpdaterStartupState {
  hasPending: boolean;
  phase: UpdaterStartupPhase;
  currentVersion: string;
  fromVersion?: string;
  toVersion?: string;
  releaseId?: string;
  markerState?: string;
  repairAvailable: boolean;
  repairVersion?: string;
}

/** Rust 健康自检的单项结果。 */
export interface HealthItem {
  name: string;
  status: "ok" | "failed" | "skipped";
  durationMs: number;
  detail?: string;
}

/** Rust 健康自检报告。 */
export interface HealthReport {
  hasPending: boolean;
  verdict: string;
  currentVersion: string;
  fromVersion?: string;
  toVersion?: string;
  releaseId?: string;
  items: HealthItem[];
  repairAvailable: boolean;
  repairVersion?: string;
  detail?: string;
}

/** 可用的旧版修复物料。 */
export interface RepairState {
  available: boolean;
  version?: string;
  releaseId?: string;
  state?: string;
  reason?: string;
}

interface UpdaterErrorPayload {
  code: string;
  message: string;
  retryable?: boolean;
}

interface ProgressPayload {
  event: "Started" | "Progress" | "Finished";
  data: { contentLength?: number; chunkLength?: number };
}



/** 用户可见状态；动作入口先校验状态，避免越态启动下载或安装。 */
export type UpdaterState =
  | "Idle"
  | "Checking"
  | "Available"
  | "Precheck"
  | "Downloading"
  | "ReadyToInstall"
  | "Locking"
  | "Installing"
  | "Failed"
  | "Cancelled";

const TRANSITIONS: Record<UpdaterState, UpdaterState[]> = {
  Idle: ["Checking"],
  Checking: ["Available", "Idle", "Failed"],
  Available: ["Checking", "Precheck", "Idle", "Cancelled"],
  Precheck: ["Downloading", "Failed", "Cancelled"],
  Downloading: ["ReadyToInstall", "Failed", "Cancelled"],
  ReadyToInstall: ["Checking", "Locking", "Installing", "Failed", "Cancelled"],
  Locking: ["ReadyToInstall", "Failed"],
  Installing: ["Failed"],
  Failed: ["Checking", "Precheck", "ReadyToInstall", "Idle"],
  Cancelled: ["Idle", "Checking"],
};

const uiState = ref<UpdaterState>("Idle");

function moveState(next: UpdaterState): boolean {
  if (!TRANSITIONS[uiState.value].includes(next)) {
    console.warn(`[updater] 忽略越态转移: ${uiState.value} -> ${next}`);
    return false;
  }
  uiState.value = next;
  return true;
}

/** 读取当前状态快照；供跨 await 的收尾分支使用，避免类型收窄误判。 */
function snapshotState(): UpdaterState {
  return uiState.value;
}

const availableUpdate = ref<AvailableUpdate | null>(null);
const preparedUpdate = ref<PreparedUpdate | null>(null);
const checking = ref(false);
const installing = ref(false);
const downloaded = ref(false);
const downloadedBytes = ref(0);
const totalBytes = ref(0);
const lastError = ref<string | null>(null);
const lastErrorCode = ref<string | null>(null);

function errorPayload(error: unknown): UpdaterErrorPayload {
  if (typeof error === "object" && error !== null) {
    const candidate = error as Partial<UpdaterErrorPayload>;
    if (typeof candidate.code === "string" && typeof candidate.message === "string") {
      return { code: candidate.code, message: candidate.message };
    }
  }
  return {
    code: "E_UPDATER_INTERNAL",
    message: error instanceof Error ? error.message : String(error),
  };
}

function setError(error: unknown): UpdaterErrorPayload {
  const payload = errorPayload(error);
  lastErrorCode.value = payload.code;
  lastError.value = payload.message;
  return payload;
}

function resetDownloadState(): void {
  preparedUpdate.value = null;
  downloaded.value = false;
  downloadedBytes.value = 0;
  totalBytes.value = 0;
}

export function useAppUpdater() {
  /** 检查更新；静默模式不向用户弹窗，也不输出错误日志。 */
  const checkForUpdate = async (silent = false): Promise<AvailableUpdate | null> => {
    if (!isTauri()) return null;
    if (checking.value) return availableUpdate.value;
    if (installing.value) return availableUpdate.value;
    if (
      uiState.value === "Locking" ||
      uiState.value === "Installing" ||
      uiState.value === "ReadyToInstall"
    ) {
      return availableUpdate.value;
    }
    if (!moveState("Checking")) return availableUpdate.value;
    checking.value = true;
    lastError.value = null;
    lastErrorCode.value = null;
    try {
      // 渠道由构建配置决定，前端不再传递，避免请求 local 绕过生产清单签名。
      const result = await invoke<AvailableUpdate | null>("updater_check");
      availableUpdate.value = result;
      resetDownloadState();
      moveState(result ? "Available" : "Idle");
      return result;
    } catch (error) {
      setError(error);
      moveState("Failed");
      if (!silent) {
        console.error("[updater] 检查更新失败", error);
      }
      return null;
    } finally {
      checking.value = false;
    }
  };

  /** 下载并校验安装包；期间应用保持可用，进度写入共享状态。 */
  const downloadUpdate = async (): Promise<PreparedUpdate> => {
    const update = availableUpdate.value;
    if (!update) {
      throw new Error("没有可安装的更新");
    }
    if (installing.value || downloaded.value) {
      if (preparedUpdate.value) return preparedUpdate.value;
      throw new Error("更新正在处理中");
    }
    if (uiState.value === "Failed") {
      if (!moveState("Precheck")) throw new Error("当前状态不可重试下载");
    } else if (uiState.value !== "Available") {
      throw new Error("当前状态不可下载更新");
    }

    installing.value = true;
    lastError.value = null;
    lastErrorCode.value = null;
    downloadedBytes.value = 0;
    totalBytes.value = update.size;
    if (snapshotState() !== "Precheck") {
      moveState("Precheck");
    }
    moveState("Downloading");

    let unlisten: UnlistenFn | null = null;
    try {
      unlisten = await listen<ProgressPayload>("updater://progress", (event) => {
        if (event.payload.event === "Started") {
          totalBytes.value = event.payload.data.contentLength ?? update.size;
          downloadedBytes.value = 0;
        } else if (event.payload.event === "Progress") {
          downloadedBytes.value += event.payload.data.chunkLength ?? 0;
        }
      });
      const prepared = await invoke<PreparedUpdate>("updater_prepare", {
        updateId: update.updateId,
      });
      preparedUpdate.value = prepared;
      downloaded.value = true;
      downloadedBytes.value = prepared.size;
      totalBytes.value = prepared.size;
      moveState("ReadyToInstall");
      return prepared;
    } catch (error) {
      const payload = errorPayload(error);
      if (payload.code === "E_UPDATER_CANCELLED") {
        // 取消是用户意图，不写入错误面；否则会误亮失败指示与日志入口。
        lastError.value = null;
        lastErrorCode.value = null;
        resetDownloadState();
        const current = snapshotState();
        if (current !== "Cancelled" && current !== "Idle") {
          moveState("Cancelled");
          moveState("Idle");
        }
        throw error;
      }
      setError(error);
      moveState("Failed");
      throw error;
    } finally {
      if (unlisten) unlisten();
      installing.value = false;
    }
  };

  /**
   * 开始锁库：先取挑战，再允许前端执行 lockAll。
   *
   * 挑战绑定会话与已校验字节；锁库期间关闭/导航被本地与后端双重拦截。
   */
  const beginLock = async (): Promise<LockChallenge> => {
    const update = availableUpdate.value;
    if (!update || !preparedUpdate.value) {
      throw new Error("没有可安装的更新");
    }
    // 安装或锁库失败后 prepared 仍在 Rust 会话中，允许回到待安装态重试，
    // 避免用户被迫重新下载整个安装包。
    if (uiState.value === "Failed") {
      if (!moveState("ReadyToInstall")) {
        throw new Error("当前状态不可重试安装");
      }
    }
    if (uiState.value !== "ReadyToInstall") {
      throw new Error("当前状态不可开始锁库");
    }
    const challenge = await invoke<LockChallenge>("updater_begin_lock", {
      updateId: update.updateId,
    });
    markUpdaterCritical(true);
    try {
      await invoke("updater_set_critical", { active: true });
    } catch {
      /* 后端拦截为增强，失败时仍保留本地守卫 */
    }
    moveState("Locking");
    return challenge;
  };

  /** 提交锁库结果；Rust 侧会复核 worker、会话与挑战绑定。 */
  const confirmLock = async (
    outcome: LockOutcome,
    challenge: string,
  ): Promise<LockReceipt> => {
    if (uiState.value !== "Locking") {
      throw new Error("当前状态不可确认锁库");
    }
    try {
      const receipt = await invoke<LockReceipt>("updater_confirm_lock", {
        challenge,
        outcome,
      });
      moveState("ReadyToInstall");
      return receipt;
    } catch (error) {
      setError(error);
      moveState("Failed");
      throw error;
    }
  };

  /** 放弃锁库挑战但保留已准备字节；用于 lockAll 结果不干净的中止路径。 */
  const abortLock = async (): Promise<void> => {
    try {
      await invoke("updater_abort_lock");
    } catch (error) {
      setError(error);
    }
    if (uiState.value === "Locking") {
      moveState("ReadyToInstall");
    }
  };

  /** 释放关闭/导航临界区；安装成功时进程退出，无需等待。 */
  const releaseCritical = async (): Promise<void> => {
    markUpdaterCritical(false);
    try {
      await invoke("updater_set_critical", { active: false });
    } catch {
      /* 本地已释放，后端时限会兜底 */
    }
  };

  /** 安装已准备的更新；安装器接管后进程退出。 */
  const installUpdate = async (receipt: string): Promise<void> => {
    const update = availableUpdate.value;
    if (!update || !preparedUpdate.value || !downloaded.value) return;
    if (installing.value || uiState.value !== "ReadyToInstall") return;
    installing.value = true;
    lastError.value = null;
    lastErrorCode.value = null;
    moveState("Installing");
    try {
      await invoke("updater_install", {
        updateId: update.updateId,
        receipt,
      });
    } catch (error) {
      setError(error);
      moveState("Failed");
      throw error;
    } finally {
      installing.value = false;
    }
  };

  /** 取消当前更新并清理 Rust 侧准备字节。 */
  const cancelUpdate = async (): Promise<void> => {
    try {
      await invoke("updater_cancel");
    } catch (error) {
      const payload = setError(error);
      if (payload.code === "E_UPDATER_BUSY") {
        throw error;
      }
    }
    markUpdaterCritical(false);
    resetDownloadState();
    availableUpdate.value = null;
    if (uiState.value !== "Cancelled" && uiState.value !== "Idle") {
      moveState("Cancelled");
    }
    if (uiState.value === "Cancelled") {
      moveState("Idle");
    }
  };

  /** 读取启动标记；普通启动返回 hasPending=false。 */
  const readStartupState = async (): Promise<UpdaterStartupState | null> => {
    if (!isTauri()) return null;
    try {
      return await invoke<UpdaterStartupState>("updater_startup_state");
    } catch (error) {
      setError(error);
      return null;
    }
  };

  /** 触发 Rust 健康自检；结论由后端判定并归档。 */
  const runHealthCheck = async (): Promise<HealthReport | null> => {
    if (!isTauri()) return null;
    try {
      return await invoke<HealthReport>("updater_run_health");
    } catch (error) {
      setError(error);
      return null;
    }
  };

  /** 查询可用的旧版修复物料。 */
  const readRepairState = async (): Promise<RepairState | null> => {
    if (!isTauri()) return null;
    try {
      return await invoke<RepairState>("updater_repair_state");
    } catch (error) {
      setError(error);
      return null;
    }
  };

  /** 运行旧版修复；安装器接管后进程退出。 */
  const runRepair = async (): Promise<void> => {
    await invoke("updater_run_repair");
  };

  /** 导出脱敏日志，返回导出文件路径。 */
  const exportLogs = async (): Promise<string | null> => {
    if (!isTauri()) return null;
    try {
      const target = await save({
        title: "导出更新日志",
        defaultPath: "verthys-updater-logs.zip",
        filters: [{ name: "ZIP 压缩包", extensions: ["zip"] }],
      });
      if (!target) return null;
      return await invoke<string>("updater_export_logs", {
        targetPath: target,
      });
    } catch (error) {
      setError(error);
      return null;
    }
  };

  return {
    state: readonly(uiState),
    availableUpdate: readonly(availableUpdate),
    preparedUpdate: readonly(preparedUpdate),
    checking: readonly(checking),
    installing: readonly(installing),
    downloaded: readonly(downloaded),
    downloadedBytes: readonly(downloadedBytes),
    totalBytes: readonly(totalBytes),
    lastError: readonly(lastError),
    lastErrorCode: readonly(lastErrorCode),
    checkForUpdate,
    downloadUpdate,
    beginLock,
    confirmLock,
    abortLock,
    releaseCritical,
    installUpdate,
    cancelUpdate,
    readStartupState,
    runHealthCheck,
    readRepairState,
    runRepair,
    exportLogs,
  };
}
