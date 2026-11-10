/*
 * useRecoveryNotices — 恢复会话常驻告知（中枢管理视图实例）
 *
 * 职责：
 *   1. 把全局恢复会话状态（keyState.recoveryMode / recoveryResealDone）
 *      映射为右侧状态轨的告知条目；
 *   2. 承载重绑本机设备槽动作与全库 DEK 轮换弹窗显隐；
 *   3. 轮换提交后收敛会话恢复标记，并通知各面板重查权威状态。
 *
 * 界面载体收敛在中枢管理视图：恢复会话状态在全局存续，离开中枢不丢失，
 * 重新进入管理界面即恢复入口；不得把状态写进中枢组件生命周期，否则
 * 切换模块后无法恢复重绑与轮换入口。
 */
import { computed, ref, watch } from "vue";
import { open } from "@tauri-apps/plugin-dialog";
import { keyState, bumpVerthysState } from "../state/key_state";
import { verthysKeyfileStatus, verthysResealDevice } from "../lib/verthys";
import { loadModuleKeyStatus } from "../key/module-auth";
import { useToastCenter } from "./useToastCenter";
import type { StatusRailNotice } from "../components/common/feedback/StatusRail.vue";

export function useRecoveryNotices() {
  const { showError, showStatus } = useToastCenter();

  /** 全库轮换向导显隐：入口在中枢状态轨，弹窗随中枢卸载而关闭 */
  const rotateDialogOpen = ref(false);
  /** 轮换向导是否已按需装载：首次打开前不加载组件分包，避免占用启动成本 */
  const rotateDialogMounted = ref(false);

  const notices = computed<StatusRailNotice[]>(() => {
    if (!keyState.globalKeyReady.value || !keyState.recoveryMode.value) return [];
    const list: StatusRailNotice[] = [];
    if (!keyState.recoveryResealDone.value) {
      list.push({
        key: "reseal",
        tone: "warning",
        icon: "device",
        tip: "重绑本机设备",
        text: "当前为恢复码会话：尚未重绑本机设备槽，下次普通解锁将失败。",
        actionLabel: "重绑本机设备",
      });
    }
    list.push({
      key: "rotate",
      tone: "info",
      icon: "rotate",
      tip: "全库密钥轮换",
      text: "恢复码会话可执行全库密钥轮换：重建容器 DEK，当前恢复码继续有效。",
      actionLabel: "全库密钥轮换",
    });
    return list;
  });

  /**
   * 重绑本机设备槽。
   * keyfile 启用时必须选择当前 keyfile；未启用时不传路径。
   * 是否恢复会话由 C 层判定，前端只负责收集可选路径。
   */
  const resealDevice = async (): Promise<void> => {
    if (!keyState.globalKeyReady.value || !keyState.recoveryMode.value) return;
    let keyfilePath: string | undefined;
    try {
      const status = await verthysKeyfileStatus();
      if (status.ok && status.keyfile_enabled === true) {
        const chosen = await open({
          multiple: false,
          directory: false,
          filters: [{ name: "Keyfile", extensions: ["vkf"] }],
        });
        if (typeof chosen !== "string") return;
        keyfilePath = chosen;
      }
    } catch {
      // 状态查询失败时按无 keyfile 继续；C 层会以 KEYFILE_REQUIRED 拒绝并提示
    }
    try {
      const resp = await verthysResealDevice(keyfilePath);
      if (resp.ok) {
        keyState.recoveryResealDone.value = true;
        showStatus("本机普通解锁已恢复");
        return;
      }
      showError("重绑失败：请在恢复会话中操作，并确认 keyfile 与设备环境");
    } catch {
      showError("重绑失败：请在恢复会话中操作，并确认 keyfile 与设备环境");
    }
  };

  const onNoticeAction = (key: string): void => {
    if (key === "reseal") {
      void resealDevice();
      return;
    }
    if (key === "rotate") rotateDialogOpen.value = true;
  };

  /** 轮换提交成功：C 层已清零恢复标记，本会话不再需要重绑设备槽 */
  const onRotateCommitted = (): void => {
    rotateDialogOpen.value = false;
    keyState.recoveryMode.value = false;
    keyState.recoveryResealDone.value = false;
    bumpVerthysState();
    void loadModuleKeyStatus().catch((e) => {
      console.warn("[rotate] 提交后刷新模块状态失败", e);
    });
  };

  /* 首次打开后才装载轮换向导：组件挂载即初始化配置，未打开前不占启动成本 */
  watch(rotateDialogOpen, (open) => {
    if (open) rotateDialogMounted.value = true;
  });

  /* 恢复标记清零（锁库 / 普通解锁 / 轮换提交）时收起弹窗：
     弹窗不得脱离会话状态继续驻留 */
  watch(
    () => keyState.recoveryMode.value,
    (active) => {
      if (!active) rotateDialogOpen.value = false;
    },
  );

  return {
    notices,
    rotateDialogOpen,
    rotateDialogMounted,
    onNoticeAction,
    onRotateCommitted,
  };
}
