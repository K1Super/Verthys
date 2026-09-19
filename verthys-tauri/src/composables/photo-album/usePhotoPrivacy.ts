/**
 * photo-album/usePhotoPrivacy.ts — 拾光模块隐私模式层 composable
 *
 * 职责：管理防截屏隐私模式切换。
 * 从原 PhotoAlbum.vue 提取，保持 100% 功能不变。
 *
 * 设计要点：
 * - privacyMode 为响应式状态，控制 UI 按钮开关
 * - privacySessionToken 为非响应式 let（闭包变量），启用时由后端返回，关闭时需传入验证
 *   ★ 注意：return 时返回的是快照值（null），外部无法获取最新值。
 *   因此提供 cleanup 方法供 onUnmounted 调用，内部通过闭包访问最新 privacySessionToken。
 * - Tauri 模式：启用 setPrivacyMode(true) 成功后存储 session_token；
 *   关闭需传入 token 验证，无令牌时拒绝关闭（防止应用重启后状态不一致）
 * - 浏览器模式：直接切换 privacyMode（无后端拦截能力）
 */
import { ref } from "vue";
import { setPrivacyMode } from "../../lib/verthys";

/**
 * usePhotoPrivacy 依赖注入接口。
 */
export interface UsePhotoPrivacyOptions {
  /** 是否运行在 Tauri 环境 */
  isTauri: boolean;
}

/**
 * 管理隐私模式（防截屏）的开启 / 关闭。
 *
 * @param isTauri 是否运行在 Tauri 环境
 */
export function usePhotoPrivacy(isTauri: boolean) {
  /* ===== 隐私模式 ===== */
  const privacyMode = ref(false);
  /** 隐私模式会话令牌（启用时由后端返回，关闭时需传入验证） */
  let privacySessionToken: string | null = null;

  const togglePrivacy = async () => {
    const newEnabled = !privacyMode.value;
    if (isTauri) {
      try {
        if (newEnabled) {
          // 启用隐私模式：后端返回 session_token，前端存储
          const result = await setPrivacyMode(true);
          if (result.ok) {
            privacyMode.value = true;
            privacySessionToken = result.session_token ?? null;
          } else {
            // 启用失败（频率超限 / 窗口失败），不切换状态
            privacyMode.value = false;
            privacySessionToken = null;
          }
        } else {
          // 关闭隐私模式：需传入会话令牌验证
          if (!privacySessionToken) {
            // 无令牌（可能应用重启后恢复），无法关闭
            console.warn("[togglePrivacy] 无会话令牌，无法关闭隐私模式");
            return;
          }
          const result = await setPrivacyMode(false, privacySessionToken);
          if (result.ok) {
            privacyMode.value = false;
            privacySessionToken = null;
          } else {
            // 关闭失败（令牌不匹配 / 频率超限），保持启用状态
            console.warn("[togglePrivacy] 关闭隐私模式失败:", result.error_code);
          }
        }
      } catch { /* */ }
    } else {
      privacyMode.value = newEnabled;
    }
  };

  /**
   * 组件卸载时清理：尝试关闭隐私模式（需会话令牌验证）
   *
   * 令牌不可用时保持启用状态（安全默认：宁可不关也不无凭据关闭）
   * fire-and-forget：onUnmounted 同步回调，不阻塞卸载
   *
   * ★ 通过闭包访问最新 privacySessionToken（return 的快照值无法反映后续修改）
   */
  const cleanup = () => {
    if (privacyMode.value && isTauri && privacySessionToken) {
      setPrivacyMode(false, privacySessionToken).catch(() => { /* */ });
    }
  };

  return {
    privacyMode,
    privacySessionToken,
    togglePrivacy,
    cleanup,
  };
}
