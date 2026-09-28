/*
 * security_preset.h — 三档安全模式枚举与配置（内部模块，不导出）
 *
 * 每个模块在生命周期内按需读取当前预设配置，据此调整自身行为参数。
 *
 * 线程契约：
 *   - 配置存储为双缓冲，切换以原子指针发布；读取方必须使用
 *     security_config_snapshot 获取完整快照（世代校验），
 *     禁止跨调用持有配置指针（旧缓冲在后续切换中会被清零复用）。
 *   - 快照读取任何返回都是完整档位的配置（无撕裂、无全零）。
 */
#ifndef VERTHYS_SECURITY_PRESET_H
#define VERTHYS_SECURITY_PRESET_H

#include <stdint.h>

/* 三档安全模式（与 VerthysPreset 数值对齐） */
typedef enum {
    SEC_PRESET_BALANCED    = 0,  /* 平衡模式（默认推荐） */
    SEC_PRESET_SECURE      = 1,  /* 高安全模式（涉密/取证） */
    SEC_PRESET_PERFORMANCE = 2,  /* 极致性能模式 */
} SecurityPreset;

/* 跨层特性位契约（与宿主特性开关一一对应；位序为跨层契约，禁止重排） */
#define SEC_FEAT_ANTI_DEBUG         (1u << 0)
#define SEC_FEAT_ANTI_INJECT        (1u << 1)
#define SEC_FEAT_INTEGRITY_CHECK    (1u << 2)
#define SEC_FEAT_MEMORY_GUARD       (1u << 3)
#define SEC_FEAT_KEY_SEPARATION     (1u << 4)
#define SEC_FEAT_EMERGENCY_RESPONSE (1u << 5)
#define SEC_FEAT_SESSION_LOCK_IDLE  (1u << 6)
#define SEC_FEAT_MODULE_PATROL      (1u << 7)
#define SEC_FEAT_CLIPBOARD_GUARD    (1u << 8)
#define SEC_FEAT_USB_CLONE_DETECT   (1u << 9)
#define SEC_FEAT_TRACE_CLEANUP      (1u << 10)
#define SEC_FEAT_VALID_MASK         (0x7FFu)

/* 各子系统的开关配置（运行时由预设决定） */
typedef struct {
    SecurityPreset preset;

    /* 运行时动态防护（C 层消费） */
    uint8_t anti_debug;            /* 调试器检测总开关 */
    uint8_t anti_debug_aggressive; /* 高安全档：检测到即零化退出 */
    uint8_t memory_lock;           /* VirtualLock 锁页 */
    uint8_t anti_dump;             /* 防内存转储与句柄巡检 */
    uint8_t anti_inject;           /* 防注入 + 模块白名单 */

    /* 应用侧策略位（跨层特性契约；宿主按位执行，C 层不消费） */
    uint32_t app_features;
} SecurityConfig;

/* 获取当前安全配置快照（世代校验，最多重试 8 次）。
 * 成功返回 0；极端争用返回 -1（此时 out 已按保守基线填充，可安全使用）。
 * 线程安全：任何返回都是某个完整档位的配置。 */
int security_config_snapshot(SecurityConfig *out);

/* 确保安全配置已初始化（未初始化时按平衡档建立基线） */
void security_config_ensure_init(void);

/* 按预设代号投影特性位（跨层契约；preset 非法返回 -1） */
int security_preset_feature_bits(SecurityPreset preset, uint32_t *out_bits);

/* 查询当前活跃档位（取自活跃配置快照；未初始化时先建立平衡基线） */
int security_active_preset(SecurityPreset *out);

/* 查询运行时活跃档位（快照读取；初始化失败按保守基线返回高安全档） */
SecurityPreset security_runtime_preset(void);

/* 初始化安全配置（按预设填充，幂等；仅建立基线，不做运行时切换） */
int security_preset_init(SecurityPreset preset);

/* 运行时切换预设（新档写入非活跃缓冲后原子发布） */
int security_preset_switch(SecurityPreset preset);

#endif /* VERTHYS_SECURITY_PRESET_H */