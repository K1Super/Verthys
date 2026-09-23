/*
 * emergency.h — 应急兜底与连锁响应机制（内部模块，不导出）
 *
 * 应急响应模型分级。

 * 原缺陷：所有信号无差别累积，终身不清零，累计 ≥2 个不同信号位即
 * TerminateProcess —— 任意两个检测器各误报一次即不可逆自毁。
 *
 * 分级模型（检测与响应解耦）：
 *   TELEMETRY — 仅记录诊断环，无任何处置。低置信度启发式检测器
 *               （模块巡检、未知 DLL）专用，允许自由误报。
 *   DEGRADE   — 同一信号在滑动窗口（10 分钟）内累计达到阈值后触发：
 *               注册的降级处理器清空密钥并锁定容器，进程保持存活、
 *               可经正常解锁流程恢复。中置信度信号（远程内存读取）。
 *   KILL      — 立即执行内存绝育 + 终止进程。仅限高置信度信号
 *               （调试器确认、完整性验签失败、超级块 HMAC 失败）。
 *
 * 信号窗口：8 槽环形历史（时间戳 + 信号），超过 10 分钟自动过期；
 * 与旧的"终身累积"不同，窗口过期后历史信号不再参与阈值判定。
 */
#ifndef VERTHYS_EMERGENCY_H
#define VERTHYS_EMERGENCY_H

#include <stdint.h>

/* 应急响应级别 */
typedef enum {
    EMERG_LEVEL_TELEMETRY = 0,  /* 仅记录，无处置（低置信度检测器） */
    EMERG_LEVEL_DEGRADE   = 1,  /* 清密钥 + 锁库，进程可恢复（窗口内同信号达阈值） */
    EMERG_LEVEL_KILL      = 2   /* 立即内存绝育 + 终止进程（高置信度信号） */
} EmergencyLevel;

/* 高危信号枚举（位掩码） */
typedef enum {
    EMERG_SIG_NONE             = 0x0000,
    EMERG_SIG_SUPERBLOCK_HMAC  = 0x0001,  /* 超级块 HMAC 校验失败 */
    EMERG_SIG_FRIDA_INJECTION  = 0x0002,  /* frida 注入痕迹 */
    EMERG_SIG_MTIME_ROLLBACK   = 0x0004,  /* 外部 mtime 被回拨 */
    EMERG_SIG_HARDWARE_BP      = 0x0008,  /* 硬件断点 DR0-DR3 */
    EMERG_SIG_UNKNOWN_DLL      = 0x0010,  /* 未知第三方 DLL 注入 */
    EMERG_SIG_REMOTE_MEM_READ  = 0x0020,  /* 远程内存读取检测 */
    EMERG_SIG_INTEGRITY_FAIL   = 0x0040,  /* 完整性校验失败 */
    EMERG_SIG_PROCESS_TAMPER   = 0x0080,  /* 进程内存被篡改 */
    EMERG_SIG_DEBUGGER_ACTIVE  = 0x0100,  /* 调试器活跃 */
    EMERG_SIG_HOOK_DETECTED    = 0x0200,  /* API Hook 检测 */
    /* 直接系统调用 SSN 提取失败（TELEMETRY 专用——基础设施
     * 异常留痕，非攻击信号；触发即降级回 GetProcAddress 路径） */
    EMERG_SIG_SYSCALL_EXTRACT_FAIL = 0x0400,
} EmergencySignal;

/* 匿名故障类型码（上报给看门狗，不含隐私数据） */
#define EMERGENCY_CODE_INDEX_CORRUPTION  0xE0001u
#define EMERGENCY_CODE_INJECTION_BLOCK   0xE0002u
#define EMERGENCY_CODE_DEBUG_BLOCK       0xE0003u
#define EMERGENCY_CODE_MEMORY_TAMPER     0xE0004u
#define EMERGENCY_CODE_INTEGRITY_FAIL    0xE0005u
#define EMERGENCY_CODE_MULTI_THREAT      0xE0006u

/* 降级信号在同一窗口内的触发阈值（同一信号出现多次才触发） */
#define EMERG_DEGRADE_THRESHOLD 2u

/*
 * 初始化应急响应模块。
 * 创建看门狗通知事件（命名事件，按 PID 唯一）。
 */
int emergency_init(void);

/*
 * 注册降级处理器（由 API 层在 Verthys_Init 时注入）。
 * DEGRADE 触发时由应急模块调用：处理器应清空全部句柄的密钥与明文缓存
 * 并将容器置为锁定态（进程保持存活）。传 NULL 取消注册。
 * 处理器必须可重入安全（DEGRADE 触发后熔断闩锁已置位，不会重复回调）。
 */
void emergency_set_degrade_handler(void (*handler)(void));

/*
 * 分级上报信号。
 *   level     : 响应级别（TELEMETRY / DEGRADE / KILL）
 *   signal    : 检测到的高危信号
 * 行为：
 *   TELEMETRY — 记入信号窗口历史，无处置。
 *   DEGRADE   — 记入窗口历史；窗口内同一信号累计达 EMERG_DEGRADE_THRESHOLD
 *               时置熔断闩锁并调用降级处理器（幂等，仅一次）。
 *   KILL      — 立即触发 emergency_trigger（内存绝育 + 终止进程）。
 */
__declspec(noinline) void emergency_report(EmergencyLevel level, EmergencySignal signal);

/*
 * 查询当前累积的高危信号（窗口历史并集，含已过期条目清理）。
 * 返回位掩码（EmergencySignal 的按位或）。
 */
uint32_t emergency_get_signals(void);

/*
 * 查询是否已触发应急响应（DEGRADE 或 KILL）。
 * 返回 0=未触发，1=已触发（进程处于熔断状态，IO 路径应拒绝）。
 * 高频查询路径：单标志原子读，无锁。
 */
int emergency_is_triggered(void);

/*
 * 查询是否处于降级态（密钥已清、容器已锁，进程存活）。
 * 与 emergency_is_triggered 的区别：KILL 态进程即将死亡，此查询无意义；
 * 该接口供诊断与测试区分两种熔断。
 */
int emergency_is_degraded(void);

/*
 * 手动触发 KILL 级应急响应（仅高置信度路径调用，如完整性验签失败）。
 * 执行顺序：极速熔断 → 内存绝育 → 故障码上报看门狗 → 终止进程。
 */
__declspec(noinline) void emergency_trigger(void);

/*
 * 熔断后安全退出（emergency_trigger 内部调用）。
 */
void emergency_exit(uint32_t code);

/*
 * 清除信号窗口历史与熔断状态（接入解锁成功与预设切换）。
 * 仅降级态可清除；KILL 触发后进程即将终止，清除无意义。
 */
void emergency_clear_signals(void);

#endif /* VERTHYS_EMERGENCY_H */
