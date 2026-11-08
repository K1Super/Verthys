/*
 * useSecurityServiceBootstrap.ts — P2 安全服务状态检测
 *
 * 服务由 perMachine 应用安装器随应用安装，应用内不再触发任何提权安装。
 * 这里只检测服务锚点；缺失时由 Gate 提示重新运行安装程序修复。
 *
 * 开发构建（Vite DEV）使用测试钩子 core 与机器预算旁路，不触发引导。
 */

import { onMounted, ref } from "vue";
import { invoke, isTauri } from "@tauri-apps/api/core";

interface SecurityServiceStatus {
  installed: boolean;
}

function describeError(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) return error.message;
  if (typeof error === "string" && error.trim()) return error;
  const text = String(error ?? "").trim();
  return text || fallback;
}

export function useSecurityServiceBootstrap() {
  const visible = ref(false);
  const error = ref("");

  async function refresh(): Promise<void> {
    if (import.meta.env.DEV || !isTauri()) {
      visible.value = false;
      return;
    }
    error.value = "";
    try {
      const status = await invoke<SecurityServiceStatus>("security_service_status");
      visible.value = !status.installed;
    } catch (e) {
      visible.value = true;
      error.value = describeError(e, "无法检测安全服务状态");
    }
  }

  onMounted(() => {
    void refresh();
  });

  return { visible, error, refresh };
}
