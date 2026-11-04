/*
 * defense_closure.h — 最终闭环防御能力验证（内部模块，不导出）
 *
 * 判据模型：
 *   每条攻击路径的状态必须绑定"当前进程 / 当前会话可验证的事实"，而不是
 *   防御模块的 init() 返回值。模块初始化成功只说明代码跑起来了，不说明
 *   攻击面被关闭；把 init 成功当作 BLOCKED 会产生无法解释的虚假阻断。
 *
 * 状态机：
 *   NOT_CHECKED = 未采样
 *   BLOCKED     = 攻击面已真实闭合，或当前无资产可被攻击（锁定时无驻留密钥）
 *   DEGRADED    = 防护能力缺失 / 被策略关闭 / 受架构限制，必须携带原因码
 *   FAILED      = 关键防御缺失或检测到确定性入侵（BOOT 模式拒绝启动）
 *
 * 会话事实（unlocked / 绑定）由调用方在持句柄锁的临界区内复制，
 * 进程事实（休眠 / 沙盒回读 / Hook 扫描 / 守卫位 / 采样时间）由
 * defense_closure_fill_process_facts 填充。检查过程只读 facts，
 * 不初始化任何模块、不创建句柄、不启动定时器。
 */
#ifndef VERTHYS_DEFENSE_CLOSURE_H
#define VERTHYS_DEFENSE_CLOSURE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 枚举 ---------- */

/* 7 项攻击路径 */
typedef enum {
    DEFENSE_PATH_SUSPEND_BYPASS   = 0,  /* 1. 管理员调试挂起绕过 */
    DEFENSE_PATH_MEM_DUMP         = 1,  /* 2. 内存 Dump / 冷启动 */
    DEFENSE_PATH_HIBERNATION      = 2,  /* 3. 休眠文件取证 */
    DEFENSE_PATH_IAT_INLINE_HOOK  = 3,  /* 4. IAT Hook / Inline Hook */
    DEFENSE_PATH_DLL_HIJACK       = 4,  /* 5. DLL 劫持 / 反射注入 */
    DEFENSE_PATH_PROCESS_READ     = 5,  /* 6. 进程打开/读取内存 */
    DEFENSE_PATH_CROSS_DEVICE     = 6,  /* 7. 跨设备迁移解密 */
    DEFENSE_PATH_COUNT            = 7
} DefensePath;

/* 防御状态 */
typedef enum {
    DEFENSE_STATE_NOT_CHECKED = 0,
    DEFENSE_STATE_BLOCKED     = 1,  /* 攻击面已真实闭合 / 无资产可窃取 */
    DEFENSE_STATE_DEGRADED    = 2,  /* 防护缺失或受架构限制（业务可继续） */
    DEFENSE_STATE_FAILED      = 3   /* 关键防御缺失 / 确定性入侵（拒绝启动） */
} DefenseState;

/* 判定原因码（数值与公共 enum VerthysDefenseReason 严格镜像） */
typedef enum {
    DEFENSE_REASON_NONE                     = 0,
    DEFENSE_REASON_NO_RESIDENT_KEY          = 1,
    DEFENSE_REASON_V4_KEYS_USER_RESIDENT    = 2,
    DEFENSE_REASON_HIBERNATION_ENABLED      = 3,
    DEFENSE_REASON_HIBERNATION_UNKNOWN      = 4,
    DEFENSE_REASON_SUSPEND_UNPREVENTABLE    = 5,
    DEFENSE_REASON_SUSPEND_GUARD_INACTIVE   = 6,
    DEFENSE_REASON_HOOK_SCAN_CLEAN          = 7,
    DEFENSE_REASON_HOOK_SCAN_UNAVAILABLE    = 8,
    DEFENSE_REASON_HOOK_DETECTED            = 9,
    DEFENSE_REASON_SANDBOX_VERIFIED         = 10,
    DEFENSE_REASON_SANDBOX_PARTIAL          = 11,
    DEFENSE_REASON_SANDBOX_UNVERIFIED       = 12,
    DEFENSE_REASON_JOB_ACTIVE               = 13,
    DEFENSE_REASON_DEVICE_BOUND             = 14,
    DEFENSE_REASON_NO_SESSION_FACTS         = 15,
    DEFENSE_REASON_MODULE_INIT_FAILED       = 16,
    DEFENSE_REASON_POLICY_DISABLED          = 17,
    DEFENSE_REASON_EVIDENCE_STALE           = 18,
    DEFENSE_REASON_ARCH_LIMIT_KERNEL_DEFERRED = 19,
    DEFENSE_REASON_HIBERNATION_DISABLED     = 20
} DefenseReason;

/* 运行时守卫位（policy_flags / Verthys_NotifyRuntimeGuards） */
#define DEFENSE_GUARD_HEARTBEAT     0x01u
#define DEFENSE_GUARD_SUSPEND_LOCK  0x02u
#define DEFENSE_POLICY_ANTI_DUMP    0x04u

/* 判定事实：只读快照。会话字段由调用方复制，进程字段由 fill 填充；
 * 检查过程不得在本结构构建之外产生任何副作用。 */
typedef struct {
    uint32_t any_unlocked_v4;       /* 进程内任一 V4 会话已解锁 */
    uint32_t queried_unlocked_v4;   /* 被查询句柄的会话已解锁 */
    uint32_t queried_device_bound;  /* 设备根槽存在 */
    uint32_t queried_pcr_bound;     /* PCR 槽存在 */
    uint32_t hibernation_state;     /* 0=禁用 1=启用 2=未知 */
    uint32_t sandbox_verified_mask; /* OS 回读后的 mitigation 位 */
    uint32_t hook_scan_state;       /* 0=不可用 1=干净 2=异常 3=过期 */
    uint32_t policy_flags;          /* DEFENSE_GUARD_* | DEFENSE_POLICY_ANTI_DUMP */
    uint64_t now_ms;                /* Unix 毫秒 */
} DefenseFacts;

/* 校验级别 */
typedef enum {
    DEFENSE_CHECK_BOOT   = 0,  /* 启动校验（严格：任一 FAILED 路径拒绝启动） */
    DEFENSE_CHECK_RUNTIME = 1  /* 运行时校验（宽松：仅记录状态） */
} DefenseCheckMode;

/* 全局防御状态汇总 */
typedef struct {
    DefenseState path_state[DEFENSE_PATH_COUNT];
    DefenseReason path_reason[DEFENSE_PATH_COUNT];
    int          all_critical_blocked;  /* 1=全部 7 条路径 BLOCKED（无 FAILED 且无 DEGRADED） */
    int          has_degraded;         /* 1=存在 DEGRADED，0=无 */
    uint32_t     blocked_count;        /* BLOCKED 路径数 */
    uint32_t     degraded_count;       /* DEGRADED 路径数 */
    uint32_t     failed_count;         /* FAILED 路径数 */
    uint32_t     limited_count;        /* 架构限制导致的 DEGRADED 路径数 */
    uint64_t     checked_at_unix_ms;   /* 本次快照采样时间 */
} DefenseStatusReport;

/* ---------- 公共接口 ---------- */

/*
 * 初始化闭环防御校验模块。
 *   返回 0 成功，非 0 失败。
 */
int defense_closure_init(void);

/*
 * 执行完整闭环防御校验（无会话事实兼容包装，供 BOOT 与既有测试使用）。
 */
int defense_closure_check(DefenseCheckMode mode,
                          DefenseStatusReport *out_report);

/*
 * 执行完整闭环防御校验（带会话/运行时事实）。
 * facts 必须为非 NULL；函数只读 facts，不修改调用方状态。
 */
int defense_closure_check_facts(DefenseCheckMode mode,
                                const DefenseFacts *facts,
                                DefenseStatusReport *out_report);

/*
 * 填充进程级事实（休眠状态 / 沙盒回读 / Hook 扫描 / 策略位 / 采样时间）。
 * 会话字段保持不变，由调用方在持锁快照内填充。
 */
void defense_closure_fill_process_facts(DefenseFacts *facts);

/*
 * 设置/读取运行时守卫位（heartbeat / suspend_lock），完整掩码语义。
 * 只接受 DEFENSE_GUARD_* 位，未知位丢弃。
 */
void defense_closure_set_runtime_guards(uint32_t flags);
uint32_t defense_closure_get_runtime_guards(void);

/*
 * 获取原因码名称（日志/诊断，不含敏感数据）。
 */
const char *defense_closure_reason_name(DefenseReason reason);

/*
 * 查询单项攻击路径的防御状态。
 *   必须在 defense_closure_check* 之后调用，否则返回 NOT_CHECKED。
 */
DefenseState defense_closure_get_path_state(DefensePath path);

/*
 * 查询最后一次校验的汇总状态。
 *   返回 0=全部 BLOCKED，1=有 DEGRADED，2=有 FAILED，3=未校验
 */
int defense_closure_get_summary(void);

/*
 * 获取路径名称（用于日志/UI，不含敏感数据）。
 */
const char *defense_closure_path_name(DefensePath path);

/*
 * 获取状态名称（用于日志/UI）。
 */
const char *defense_closure_state_name(DefenseState state);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_DEFENSE_CLOSURE_H */
