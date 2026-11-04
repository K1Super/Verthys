/**
 * useDefenseStatus.ts — 动态防护状态 Composable（消费出口）
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
 *   - verthys://runtime-guards：会话守卫位下发完成后立即重采样，消除
 *     “首次拉取早于守卫接线”导致的一轮可修复降级误判
 *   - verthysReady 置 false（lockAll）：停止轮询 + 清空报告（worker 会话
 *     已销毁，旧报告不再反映当前进程事实）
 *
 * 失败策略：静默降级 — 防御面板为可观测性出口而非交互路径，拉取失败
 *   保留上一份报告，下轮轮询重试，不弹错误打扰用户。
 *
 * 设计：纯 Composable，无外部依赖注入；onBeforeUnmount 自动停止轮询。
 */

import { ref, computed, watch, onBeforeUnmount } from 'vue';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { verthysReadyRef } from '../../lib/keyManager';
import { verthysGetSecurityStatus, type SecurityStatusReport } from '../../lib/verthys';
import { isTauriEnvironment } from '../../utils/tauri_env';

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
  { key: 'iat_hook', label: '接口挂钩', desc: 'IAT / Inline Hook 检测' },
  { key: 'dll_hijack', label: '动态劫持', desc: 'DLL 劫持 / 反射注入防护' },
  { key: 'process_read', label: '进程读取', desc: '进程打开 / 读取内存防护' },
  { key: 'cross_device', label: '跨端设备', desc: '跨设备迁移解密防护' },
];

/** 防御状态视图映射（值域与 VerthysDefenseState 镜像） */
const DEFENSE_STATE_VIEW: Record<number, { label: string; cls: string }> = {
  0: { label: '未校验', cls: 'unchecked' },
  1: { label: '已阻断', cls: 'blocked' },
  2: { label: '降级', cls: 'degraded' },
  3: { label: '失败', cls: 'failed' },
};

/* 判定原因码文案（与 verthys.h VerthysDefenseReason 严格对齐，集中维护；
 * 前端只做展示映射，不在本地推导安全结论） */
const DEFENSE_REASON_LABEL: Record<number, string> = {
  0: '无附加原因',
  1: '当前无驻留密钥',
  2: '密钥驻留用户态（隔离堆与转储巡检已加固）',
  3: '系统休眠已启用',
  4: '休眠状态无法证明',
  5: '心跳看门狗已加固（全线程挂起 3 秒内处置）',
  6: '挂起看门狗未启用（可修复）',
  7: 'Hook 基线扫描干净',
  8: 'Hook 扫描不可用/覆盖不全',
  9: '检测到 Hook 特征',
  10: 'mitigation 已由 OS 回读确认',
  11: '部分 mitigation 缺失',
  12: '无法回读确认 mitigation',
  13: '双层 Job 隔离有效',
  14: '设备根/PCR 绑定成立',
  15: '无可校验的绑定事实',
  16: '关键防御模块缺失',
  17: '当前预设关闭该防护',
  18: '证据超过有效期',
  19: '用户态加固已生效',
  20: '系统休眠已禁用',
};

/* 用户态上限原因：防护措施已加固；绝对阻止能力受平台边界约束。
 * UI 显示为"已加固"，与可修复缺口严格区分。 */
const DEFENSE_LIMITED_REASONS = new Set([2, 5]);

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
  /** 状态样式类（unchecked/blocked/degraded/limited/failed） */
  stateClass: string;
  /** 判定原因码（VerthysDefenseReason，0=无附加原因） */
  reason: number;
  /** 原因中文文案（供 tooltip/诊断展示） */
  reasonLabel: string;
  /** 是否为用户态上限项（原因 2/5，防护已加固但无法完全阻止） */
  limited: boolean;
}

/** 动态防护汇总态势 */
export interface DefenseMetaView {
  /** 已阻断路径数 */
  blocked: number;
  /** 降级路径数 */
  degraded: number;
  /** 已加固的用户态上限项数（degraded 的子集） */
  limited: number;
  /** 失败路径数 */
  failed: number;
  /** 未校验路径数（含报告缺位时的全量占位） */
  unchecked: number;
  /** 关键路径全阻断标志（worker 透传） */
  allCriticalBlocked: boolean;
  /** 总体态势：breach（有失败）> degraded（存在可修复降级）> limited（仅已加固
   *  的用户态上限项）> partial（部分未校验）> ok（全部已阻断）/ pending（未拉取或全未校验） */
  stance: 'breach' | 'degraded' | 'limited' | 'partial' | 'ok' | 'pending';
  /** 态势中文标签 */
  stanceLabel: string;
  /** 报告陈旧标记（启用轮询后最近一次拉取失败，当前展示的是上一次的报告） */
  stale: boolean;
  /** 快照采样时间（Unix 毫秒，0=未知） */
  checkedAtMs: number;
  /** 采样时间展示文案（本地时间，空串=未知） */
  checkedAtLabel: string;
}

/* ------------------------------------------------------------------ *
 * Composable 主体                                                    *
 * ------------------------------------------------------------------ */

/**
 * 动态防护状态 Composable
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

  /** 报告陈旧标记：最近一次拉取失败时置位（保留旧报告但如实标注） */
  const defenseReportStale = ref(false);

  /** 轮询定时器句柄 */
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  /** 拉取防御状态（静默失败，保留旧报告并标记陈旧） */
  const refreshDefenseStatus = async () => {
    if (!verthysReadyRef.value) return;
    try {
      defenseReport.value = await verthysGetSecurityStatus();
      defenseReportStale.value = false;
    } catch (e) {
      defenseReportStale.value = true;
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
    defenseReportStale.value = false;
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

  /* 守卫位变更事件：session_start 完成 runtime_guards 下发后由后端发出。
   * 首次拉取可能早于该下发（verthysReady 先于 securitySessionStart），
   * 若不重采样，首个 60s 周期会把已接线的挂起守卫显示为可修复降级。 */
  let unlistenRuntimeGuards: UnlistenFn | null = null;
  if (isTauriEnvironment()) {
    void listen('verthys://runtime-guards', () => {
      void refreshDefenseStatus();
    })
      .then((unlisten) => {
        unlistenRuntimeGuards = unlisten;
      })
      .catch(() => {
        /* 事件注册失败不影响 60s 轮询兜底 */
      });
  }

  onBeforeUnmount(() => {
    stopPolling();
    if (unlistenRuntimeGuards !== null) {
      unlistenRuntimeGuards();
      unlistenRuntimeGuards = null;
    }
  });

  /* ===== 展示视图模型 ===== */

  /** 7 条路径展示项（报告缺位时全量未校验占位，布局稳定不闪跳） */
  const defensePaths = computed<DefensePathView[]>(() =>
    DEFENSE_PATH_DEFS.map((def, i) => {
      const state = defenseReport.value?.path_state?.[i] ?? 0;
      const reason = defenseReport.value?.path_reason?.[i] ?? 0;
      const limited = state === 2 && DEFENSE_LIMITED_REASONS.has(reason);
      /* 用户态上限项显示"已加固"，强调防护已生效，不与可修复降级混淆。 */
      const view = limited
        ? { label: '已加固', cls: 'limited' }
        : (DEFENSE_STATE_VIEW[state] ?? DEFENSE_STATE_VIEW[0]);
      return {
        ...def,
        state,
        stateLabel: view.label,
        stateClass: view.cls,
        reason,
        reasonLabel: DEFENSE_REASON_LABEL[reason] ?? '未知原因',
        limited,
      };
    }),
  );

  /** 汇总态势（报告缺位时 pending 占位）
   *
   * 裁决顺序与 C 层原因码对齐：
   *   失败 > 可修复降级（degraded - limited > 0）> 仅已加固项 > 未校验
   *   > 全阻断 > 待检测。
   * limited_count 是 degraded 的子集；把"已加固的用户态上限项"单独展示，
   * 强调防护已生效，避免误读为未实现的可修复缺陷。
   */
  const defenseMeta = computed<DefenseMetaView>(() => {
    const total = DEFENSE_PATH_DEFS.length;
    const stale = defenseReportStale.value;
    const r = defenseReport.value;
    if (!r) {
      return {
        blocked: 0,
        degraded: 0,
        limited: 0,
        failed: 0,
        unchecked: total,
        allCriticalBlocked: false,
        stance: 'pending',
        stanceLabel: '待检测',
        stale,
        checkedAtMs: 0,
        checkedAtLabel: '',
      };
    }
    const blocked = r.blocked_count;
    const degraded = r.degraded_count;
    const limited = Math.min(r.limited_count ?? 0, degraded);
    const failed = r.failed_count;
    const unchecked = Math.max(total - blocked - degraded - failed, 0);
    const checkedAtMs = r.checked_at_unix_ms ?? 0;
    const checkedAtLabel =
      checkedAtMs > 0
        ? new Date(checkedAtMs).toLocaleTimeString('zh-CN', { hour12: false })
        : '';
    const base = {
      blocked,
      degraded,
      limited,
      failed,
      unchecked,
      allCriticalBlocked: r.all_critical_blocked,
      stale,
      checkedAtMs,
      checkedAtLabel,
    };
    if (failed > 0) {
      return { ...base, stance: 'breach', stanceLabel: `${failed} 条路径防御失败` };
    }
    if (degraded - limited > 0) {
      return {
        ...base,
        stance: 'degraded',
        stanceLabel: `${degraded - limited} 条可修复降级`,
      };
    }
    if (limited > 0) {
      return {
        ...base,
        stance: 'limited',
        stanceLabel: `${limited} 项已加固（用户态上限）`,
      };
    }
    if (blocked + degraded + failed === 0) {
      return { ...base, stance: 'pending', stanceLabel: '待检测' };
    }
    if (unchecked > 0) {
      return { ...base, stance: 'partial', stanceLabel: `${blocked}/${total} 条路径已阻断 · 其余待校验` };
    }
    if (blocked === total) {
      return { ...base, stance: 'ok', stanceLabel: '关键路径全阻断' };
    }
    return { ...base, stance: 'pending', stanceLabel: '待检测' };
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
