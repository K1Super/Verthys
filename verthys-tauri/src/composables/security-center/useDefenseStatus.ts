/**
 * useDefenseStatus.ts — 防御闭环状态 Composable（WP-11 消费出口）
 *
 * 数据链路（四层全链路）：
 *   前端 verthysGetSecurityStatus()
 *     → Rust #[tauri::command] verthys_security_status
 *     → verthys-worker op "security_status"
 *     → C 核心 FFI Verthys_GetSecurityStatus（RUNTIME 级实时复检）
 *
 * 职责：
 *   1. 7 条攻击路径定义（与 core/include/verthys.h VerthysDefensePath 镜像）
 *   2. 4 态状态映射（VerthysDefenseState：0=未校验 1=已阻断 2=降级 3=失败）
 *   3. 报告拉取 + 60s 轮询刷新（verthys 就绪期间）
 *   4. 展示视图模型（defensePaths 列表 + defenseMeta 汇总态势）
 *
 * 拉取时机：
 *   - verthysReady 置 true：立即拉取 + 启动轮询（防御状态为进程级事实，
 *     worker 会话存在即有 handle）
 *   - verthysReady 置 false（lockAll）：停止轮询 + 清空报告（worker 会话
 *     已销毁，旧报告不再反映当前进程事实）
 *
 * 失败策略：静默降级 — 防御面板为可观测性出口而非交互路径，拉取失败
 *   保留上一份报告，下轮轮询重试，不弹错误打扰用户。
 *
 * 设计：纯 Composable，无外部依赖注入；onBeforeUnmount 自动停止轮询。
 */

import { ref, computed, watch, onBeforeUnmount } from 'vue';
import { verthysReadyRef } from '../../lib/keyManager';
import { verthysGetSecurityStatus, type SecurityStatusReport } from '../../lib/verthys';

/* ------------------------------------------------------------------ *
 * 常量：攻击路径定义 + 状态映射                                      *
 *                                                                    *
 * DEFENSE_PATH_DEFS 下标 = VerthysDefensePath 枚举值（编译期契约）：    *
 *   0=SUSPEND_BYPASS 1=MEM_DUMP 2=HIBERNATION 3=IAT_HOOK            *
 *   4=DLL_HIJACK 5=PROCESS_READ 6=CROSS_DEVICE                      *
 * ------------------------------------------------------------------ */

/** 攻击路径展示定义（下标即 C 层枚举值，禁止重排） */
const DEFENSE_PATH_DEFS: { key: string; label: string; desc: string }[] = [
  { key: 'suspend_bypass', label: '挂起绕过', desc: '管理员调试挂起绕过防护' },
  { key: 'mem_dump', label: '内存转储', desc: '内存 Dump / 冷启动取证防护' },
  { key: 'hibernation', label: '休眠取证', desc: '休眠文件取证残留防护' },
  { key: 'iat_hook', label: 'IAT Hook', desc: 'IAT / Inline Hook 检测' },
  { key: 'dll_hijack', label: 'DLL 劫持', desc: 'DLL 劫持 / 反射注入防护' },
  { key: 'process_read', label: '进程读取', desc: '进程打开 / 读取内存防护' },
  { key: 'cross_device', label: '跨设备', desc: '跨设备迁移解密防护' },
];

/** 防御状态视图映射（值域与 VerthysDefenseState 镜像） */
const DEFENSE_STATE_VIEW: Record<number, { label: string; cls: string }> = {
  0: { label: '未校验', cls: 'unchecked' },
  1: { label: '已阻断', cls: 'blocked' },
  2: { label: '降级', cls: 'degraded' },
  3: { label: '失败', cls: 'failed' },
};

/** 轮询间隔：防御状态为进程级事实，变化频率低，60s 刷新足够 */
const DEFENSE_POLL_INTERVAL_MS = 60_000;

/* ------------------------------------------------------------------ *
 * 视图模型类型                                                       *
 * ------------------------------------------------------------------ */

/** 单条攻击路径展示项 */
export interface DefensePathView {
  /** 路径标识（C 层枚举名小写蛇形） */
  key: string;
  /** 中文路径名 */
  label: string;
  /** tooltip 描述 */
  desc: string;
  /** 防御状态原始值（0=未校验 1=已阻断 2=降级 3=失败） */
  state: number;
  /** 状态中文标签 */
  stateLabel: string;
  /** 状态样式类（unchecked/blocked/degraded/failed） */
  stateClass: string;
}

/** 防御闭环汇总态势 */
export interface DefenseMetaView {
  /** 已阻断路径数 */
  blocked: number;
  /** 降级路径数 */
  degraded: number;
  /** 失败路径数 */
  failed: number;
  /** 未校验路径数（含报告缺位时的全量占位） */
  unchecked: number;
  /** 关键路径全阻断标志（worker 透传） */
  allCriticalBlocked: boolean;
  /** 总体态势：breach（有失败）> degraded（有降级）> ok（全阻断）/ pending（未拉取） */
  stance: 'breach' | 'degraded' | 'ok' | 'pending';
  /** 态势中文标签 */
  stanceLabel: string;
}

/* ------------------------------------------------------------------ *
 * Composable 主体                                                    *
 * ------------------------------------------------------------------ */

/**
 * 防御闭环状态 Composable
 *
 * @returns defenseReport 原始报告 / defensePaths 路径列表 /
 *          defenseMeta 汇总态势 / refreshDefenseStatus 手动刷新
 *
 * @example
 * ```ts
 * const { defensePaths, defenseMeta } = useDefenseStatus();
 * ```
 */
export function useDefenseStatus() {
  /** 最近一次防御状态报告（null = 未拉取 / 会话已锁定） */
  const defenseReport = ref<SecurityStatusReport | null>(null);

  /** 轮询定时器句柄 */
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  /** 拉取防御状态（静默失败，保留旧报告） */
  const refreshDefenseStatus = async () => {
    if (!verthysReadyRef.value) return;
    try {
      defenseReport.value = await verthysGetSecurityStatus();
    } catch (e) {
      console.warn('[useDefenseStatus] 防御状态拉取失败', e);
    }
  };

  /** 启动轮询（verthys 就绪期间，幂等） */
  const startPolling = () => {
    if (pollTimer !== null) return;
    pollTimer = setInterval(() => void refreshDefenseStatus(), DEFENSE_POLL_INTERVAL_MS);
  };

  /** 停止轮询 + 清空报告（锁定时会话销毁，报告过期） */
  const stopPolling = () => {
    if (pollTimer !== null) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    defenseReport.value = null;
  };

  /* verthys 就绪状态驱动：立即拉取 + 轮询启停（immediate 覆盖挂载时已就绪） */
  watch(
    verthysReadyRef,
    (ready) => {
      if (ready) {
        void refreshDefenseStatus();
        startPolling();
      } else {
        stopPolling();
      }
    },
    { immediate: true },
  );

  onBeforeUnmount(stopPolling);

  /* ===== 展示视图模型 ===== */

  /** 7 条路径展示项（报告缺位时全量未校验占位，布局稳定不闪跳） */
  const defensePaths = computed<DefensePathView[]>(() =>
    DEFENSE_PATH_DEFS.map((def, i) => {
      const state = defenseReport.value?.path_state?.[i] ?? 0;
      const view = DEFENSE_STATE_VIEW[state] ?? DEFENSE_STATE_VIEW[0];
      return { ...def, state, stateLabel: view.label, stateClass: view.cls };
    }),
  );

  /** 汇总态势（报告缺位时 pending 占位） */
  const defenseMeta = computed<DefenseMetaView>(() => {
    const r = defenseReport.value;
    if (!r) {
      return {
        blocked: 0,
        degraded: 0,
        failed: 0,
        unchecked: DEFENSE_PATH_DEFS.length,
        allCriticalBlocked: false,
        stance: 'pending',
        stanceLabel: '待检测',
      };
    }
    const blocked = r.blocked_count;
    const degraded = r.degraded_count;
    const failed = r.failed_count;
    const unchecked = Math.max(DEFENSE_PATH_DEFS.length - blocked - degraded - failed, 0);
    if (failed > 0) {
      return { blocked, degraded, failed, unchecked, allCriticalBlocked: r.all_critical_blocked, stance: 'breach', stanceLabel: `${failed} 条路径防御失败` };
    }
    if (degraded > 0) {
      return { blocked, degraded, failed, unchecked, allCriticalBlocked: r.all_critical_blocked, stance: 'degraded', stanceLabel: `${degraded} 条路径降级` };
    }
    return { blocked, degraded, failed, unchecked, allCriticalBlocked: r.all_critical_blocked, stance: 'ok', stanceLabel: '关键路径全阻断' };
  });

  return {
    /** 原始报告（SecurityStatusReport | null） */
    defenseReport,
    /** 7 条路径展示列表 */
    defensePaths,
    /** 汇总态势 */
    defenseMeta,
    /** 手动刷新（保留给显式刷新入口） */
    refreshDefenseStatus,
  };
}
