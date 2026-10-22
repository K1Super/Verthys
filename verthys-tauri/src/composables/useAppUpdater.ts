/**
 * useAppUpdater — 应用内更新状态与动作。
 *
 * 状态为模块级单例：启动静默检查与管理界面按钮共享同一份结果。
 * 下载与安装拆分为两步：下载安装包期间应用保持可用；安装包就绪后由调用方
 * 先完成数据落盘与密钥清理，再调用 installUpdate，避免更新覆盖正在写入的进程
 * 或跳过锁定流程。
 */
import { readonly, ref } from "vue";
import { isTauri } from "@tauri-apps/api/core";
import { check, type Update } from "@tauri-apps/plugin-updater";

export interface AvailableUpdate {
  currentVersion: string;
  version: string;
  date?: string;
  notes?: string;
}

const availableUpdate = ref<AvailableUpdate | null>(null);
const checking = ref(false);
const installing = ref(false);
const downloaded = ref(false);
const downloadedBytes = ref(0);
const totalBytes = ref(0);
const lastError = ref<string | null>(null);

let pendingUpdate: Update | null = null;

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function closePending(): Promise<void> {
  if (!pendingUpdate) return;
  try {
    await pendingUpdate.close();
  } catch {
    /* 资源已释放或后端已退出：无需处理 */
  }
  pendingUpdate = null;
}

export function useAppUpdater() {
  const checkForUpdate = async (silent = false): Promise<AvailableUpdate | null> => {
    if (!isTauri()) return null;
    if (checking.value) return availableUpdate.value;
    checking.value = true;
    lastError.value = null;
    try {
      const update = await check();
      await closePending();
      pendingUpdate = update;
      downloaded.value = false;
      downloadedBytes.value = 0;
      totalBytes.value = 0;
      availableUpdate.value = update
        ? {
            currentVersion: update.currentVersion,
            version: update.version,
            date: update.date,
            notes: update.body,
          }
        : null;
      return availableUpdate.value;
    } catch (error) {
      lastError.value = errorText(error);
      if (!silent) {
        console.error("[updater] 检查更新失败", error);
      }
      return null;
    } finally {
      checking.value = false;
    }
  };

  /** 下载更新包但不安装：期间应用保持解锁与可用，进度写入共享状态。 */
  const downloadUpdate = async (): Promise<void> => {
    if (!pendingUpdate || installing.value || downloaded.value) return;
    installing.value = true;
    lastError.value = null;
    downloadedBytes.value = 0;
    totalBytes.value = 0;
    try {
      await pendingUpdate.download((event) => {
        if (event.event === "Started") {
          totalBytes.value = event.data.contentLength ?? 0;
        } else if (event.event === "Progress") {
          downloadedBytes.value += event.data.chunkLength;
        }
      });
      downloaded.value = true;
    } catch (error) {
      lastError.value = errorText(error);
      throw error;
    } finally {
      installing.value = false;
    }
  };

  /**
   * 安装已下载的更新包。
   *
   * 调用前必须完成数据落盘与密钥清理；Windows 上安装器接管后应用进程退出，
   * 因此不得在此动作之后安排任何依赖进程存活的工作。
   */
  const installUpdate = async (): Promise<void> => {
    if (!pendingUpdate || installing.value || !downloaded.value) return;
    installing.value = true;
    lastError.value = null;
    try {
      await pendingUpdate.install();
    } catch (error) {
      lastError.value = errorText(error);
      throw error;
    } finally {
      installing.value = false;
    }
  };

  return {
    availableUpdate: readonly(availableUpdate),
    checking: readonly(checking),
    installing: readonly(installing),
    downloaded: readonly(downloaded),
    downloadedBytes: readonly(downloadedBytes),
    totalBytes: readonly(totalBytes),
    lastError: readonly(lastError),
    checkForUpdate,
    downloadUpdate,
    installUpdate,
  };
}
