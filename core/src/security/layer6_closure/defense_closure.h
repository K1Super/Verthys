/*
 * defense_closure.h — 最终闭环防御能力验证（内部模块，不导出）
 *
 * 用户需求（六、最终闭环防御能力）：
 *   本终版方案已堵死所有公开、私有、内存取证级攻击路径：
 *     1. 管理员调试挂起绕过：彻底根除（无校验线程可挂，业务强制校验）
 *     2. 内存 Dump / 冷启动：密钥漂移+物理页强制回收+混沌熵池彻底免疫
 *     3. 休眠文件取证：诱饵内存+密钥落地加密双重防护
 *     4. IAT Hook / Inline Hook：内嵌CRC+动态高熵混淆表联动销毁
 *     5. DLL 劫持 / 反射注入：系统目录优先+禁止远程内存加载
 *     6. 进程打开/读取内存：Job ACL 硬隔离，等效 PPL
 *     7. 跨设备迁移解密：机器密钥+硬件哈希双重绑定
 *
 * 设计原理：
 *   本模块作为整个安全体系的"总装校验"，负责：
 *     1. 在 Worker 进程启动时按 7 项攻击路径逐项验证各防御模块是否就绪
 *     2. 任一关键防御模块未就绪 → 启动失败，进程拒绝运行
 *     3. 运行时支持周期性自检（可选，由调用方驱动）
 *     4. 提供详细的防御状态查询接口（用于诊断与日志）
 *
 * 状态机：
 *   每项攻击路径有独立的状态：
 *     DEFENSE_STATE_NOT_CHECKED = 未校验
 *     DEFENSE_STATE_BLOCKED     = 已阻断（防御模块就绪）
 *     DEFENSE_STATE_DEGRADED    = 降级（部分防御模块未生效，业务可继续）
 *     DEFENSE_STATE_FAILED      = 失败（关键防御模块缺失，应拒绝启动）
 *
 *   全局状态：所有路径非 FAILED 时整体通过。
 *             降级路径需调用方明确确认是否继续。
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
    DEFENSE_STATE_BLOCKED     = 1,  /* 完全阻断（关键防御已就绪） */
    DEFENSE_STATE_DEGRADED    = 2,  /* 降级（次要防御缺失，可继续运行） */
    DEFENSE_STATE_FAILED      = 3   /* 失败（关键防御缺失，应拒绝启动） */
} DefenseState;

/* 校验级别 */
typedef enum {
    DEFENSE_CHECK_BOOT   = 0,  /* 启动校验（严格：FAILED 路径拒绝启动） */
    DEFENSE_CHECK_RUNTIME = 1  /* 运行时校验（宽松：仅记录状态） */
} DefenseCheckMode;

/* 全局防御状态汇总 */
typedef struct {
    DefenseState path_state[DEFENSE_PATH_COUNT];
    int          all_critical_blocked;  /* 1=所有关键路径阻断，0=有 FAILED */
    int          has_degraded;         /* 1=存在 DEGRADED，0=无 */
    uint32_t     blocked_count;        /* BLOCKED 路径数 */
    uint32_t     degraded_count;       /* DEGRADED 路径数 */
    uint32_t     failed_count;         /* FAILED 路径数 */
} DefenseStatusReport;

/* ---------- 公共接口 ---------- */

/*
 * 初始化闭环防御校验模块。
 *   返回 0 成功，非 0 失败。
 */
int defense_closure_init(void);

/*
 * 执行完整闭环防御校验。
 *   mode: 校验级别（BOOT / RUNTIME）
 *   out_report: 输出详细状态报告（NULL=不输出）
 * 返回 0=全部关键路径阻断，非 0=存在 FAILED 或 DEGRADED（需调用方决策）。
 *
 * 内部按 7 项攻击路径逐一调用各防御模块的 is_active() / get_active_attrs() 等
 * 查询接口，汇总状态。
 *
 * BOOT 模式：任一关键路径 FAILED → 返回非零
 * RUNTIME 模式：仅更新状态，不阻断（返回 0）
 */
int defense_closure_check(DefenseCheckMode mode,
                          DefenseStatusReport *out_report);

/*
 * 查询单项攻击路径的防御状态。
 *   必须在 defense_closure_check 之后调用，否则返回 NOT_CHECKED。
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
