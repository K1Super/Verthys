/*
 * security_preset.h — 三档安全模式枚举与配置（内部模块，不导出）
 *
 *
 * 每个模块在初始化时读取当前预设，据此调整自身行为参数。
 */
#ifndef VERTHYS_SECURITY_PRESET_H
#define VERTHYS_SECURITY_PRESET_H

#include <stdint.h>

/* 三档安全模式（与 VerthysPreset 扩展对齐） */
typedef enum {
    SEC_PRESET_BALANCED    = 0,  /* 平衡模式（默认推荐） */
    SEC_PRESET_SECURE      = 1,  /* 高安全模式（涉密/取证） */
    SEC_PRESET_PERFORMANCE = 2,  /* 极致性能模式 */
} SecurityPreset;

/* 各子系统的开关配置（运行时由预设决定） */
typedef struct {
    SecurityPreset preset;

    /* 静态本体防护 */
    uint8_t lazy_integrity;        /* 惰性关键段校验（DLL/EXE头部1MB） */
    uint8_t distributed_anchors;   /* 分散式校验锚点（功能入口触发） */
    uint8_t resource_encrypt;      /* 资源文件加密 */

    /* 运行时动态防护 */
    uint8_t anti_debug;            /* 智慧型反调试 */
    uint8_t anti_debug_aggressive; /* 高安全模式：立即零化退出（替代延迟惩罚） */
    uint8_t memory_lock;           /* VirtualLock 锁页 */
    uint8_t anti_dump;             /* 防内存转储 */
    uint8_t anti_inject;           /* 防注入 + 模块白名单 */

    /* 行为风控 */
    uint8_t file_exclusive_lock;   /* 独占锁 */
    uint8_t usb_guard;             /* U盘管控 */
    uint8_t usb_shadow_sleep_min;  /* 影子休眠时长（分钟）：BALANCED=30, SECURE=5, PERF=0 */

    /* 痕迹清理 */
    uint8_t trace_cleanup;         /* 启动时清理最近记录 */
    uint8_t log_encrypted;         /* 日志加密存储 */

    /* 会话安全 */
    uint8_t session_lock_on_system_lock;  /* 系统锁屏时销毁密钥 */
    uint8_t session_lock_on_display_off;  /* 显示器关闭触发（仅高安全） */
    uint8_t export_reauth;                /* 导出二次授权（仅高安全） */
    uint8_t remote_control_block;         /* 远程控制软件阻断（仅高安全） */

    /* 应急响应 */
    uint8_t emergency_circuit;     /* 应急熔断连锁响应 */

    /* KDF 迭代轮次（反调试延迟惩罚时提升） */
    uint32_t kdf_iters_normal;     /* 正常模式 KDF 迭代 */
    uint32_t kdf_iters_punish;     /* 惩罚模式 KDF 迭代 */
} SecurityConfig;

/* 获取当前安全配置（全局单例，初始化后只读） */
const SecurityConfig *security_get_config(void);

/* 初始化安全配置（按预设填充，幂等） */
int security_preset_init(SecurityPreset preset);

/* 运行时切换预设（触发各子系统重新读取配置） */
int security_preset_switch(SecurityPreset preset);

/* 获取预设名称（用于日志/UI，不含敏感信息） */
const char *security_preset_name(SecurityPreset preset);

#endif /* VERTHYS_SECURITY_PRESET_H */
