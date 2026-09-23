/*
 * security_preset.c — 三档安全模式配置实现
 *
 * 根据预设填充 SecurityConfig 结构体，各子系统读取配置决定行为。
 *
 * 双缓冲 + 指针原子交换。
 * 原缺陷：security_preset_switch 先清零再重填单一实例——清零与重填之间
 * 存在窗口，并发读者读到"全零配置"（所有防护开关瞬时为 0）。
 * 现实现：配置存储双缓冲，switch 在非活跃缓冲上填充完成后，以
 * InterlockedExchangePointer 原子切换活跃指针——任何时刻读者看到的都是
 * 一个完整有效的配置快照，消除 TOCTOU 窗口。旧缓冲在切换后清零复用。
 */
#include "security_preset.h"
#include "verthys_internal.h"  /* verthys_secure_zero */
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* 双缓冲配置实例（活跃缓冲经 s_config_active 原子指针发布） */
static SecurityConfig s_config_buf[2];
static SecurityConfig *volatile s_config_active = NULL;
static int s_initialized = 0;

/* 平衡模式配置（默认推荐） */
static void fill_balanced(SecurityConfig *c)
{
    c->preset = SEC_PRESET_BALANCED;

    /* 静态本体防护 */
    c->lazy_integrity       = 1;
    c->distributed_anchors  = 1;
    c->resource_encrypt     = 1;

    /* 运行时动态防护 */
    c->anti_debug           = 1;
    c->anti_debug_aggressive= 0;  /* 平衡模式使用延迟惩罚，不立即退出 */
    c->memory_lock          = 1;
    c->anti_dump            = 1;
    c->anti_inject          = 1;

    /* 行为风控 */
    c->file_exclusive_lock  = 1;
    c->usb_guard            = 1;
    c->usb_shadow_sleep_min = 30;  /* 30分钟影子休眠 */

    /* 痕迹清理 */
    c->trace_cleanup        = 1;
    c->log_encrypted        = 1;

    /* 会话安全 */
    c->session_lock_on_system_lock = 1;
    c->session_lock_on_display_off = 0;  /* 仅高安全模式 */
    c->export_reauth               = 0;  /* 仅高安全模式 */
    c->remote_control_block        = 0;  /* 仅高安全模式 */

    /* 应急响应 */
    c->emergency_circuit    = 1;

    /* KDF 迭代轮次 */
    c->kdf_iters_normal     = 3;       /* Argon2id 3次（常规） */
    c->kdf_iters_punish     = 100;     /* 惩罚模式 100次（大幅提升耗时） */
}

/* 高安全模式配置（涉密/取证场景） */
static void fill_secure(SecurityConfig *c)
{
    fill_balanced(c);  /* 继承平衡模式全部防护 */
    c->preset = SEC_PRESET_SECURE;

    /* 高安全模式强化项 */
    c->anti_debug_aggressive        = 1;  /* 立即零化退出（替代延迟惩罚） */
    c->usb_shadow_sleep_min         = 5;  /* 影子休眠缩短至5分钟 */
    c->session_lock_on_display_off  = 1;  /* 显示器关闭也触发 */
    c->export_reauth                = 1;  /* 导出二次授权 */
    c->remote_control_block         = 1;  /* 远程控制软件直接锁定 */
    c->kdf_iters_punish             = 200; /* 惩罚模式更重 */
}

/* 极致性能模式配置（保留最低安全底线） */
static void fill_performance(SecurityConfig *c)
{
    memset(c, 0, sizeof(*c));
    c->preset = SEC_PRESET_PERFORMANCE;

    /* 仅保留三项核心防护 */
    c->anti_inject          = 1;  /* DLL 搜索顺序加固 */
    c->memory_lock          = 0;  /* 不锁页（性能优先） */
    c->anti_dump            = 0;  /* 不防转储 */
    c->anti_debug           = 0;  /* 关闭反调试 */
    c->lazy_integrity       = 0;  /* 关闭启动校验 */
    c->distributed_anchors  = 0;  /* 关闭功能入口校验 */
    c->trace_cleanup        = 0;  /* 不清理痕迹 */
    c->emergency_circuit    = 1;  /* 保留应急熔断 */
    c->session_lock_on_system_lock = 1;  /* 保留系统锁屏触发 */

    /* KDF 维持标准参数 */
    c->kdf_iters_normal     = 3;
    c->kdf_iters_punish     = 3;  /* 性能模式不提升惩罚迭代 */
}

/* ===================================================================== *
 *                           公共接口                                    *
 * ===================================================================== */

const SecurityConfig *security_get_config(void)
{
    SecurityConfig *active = s_config_active;
    if (active == NULL) {
        /* 未初始化时默认使用平衡模式 */
        security_preset_init(SEC_PRESET_BALANCED);
        active = s_config_active;
    }
    return active;
}

int security_preset_init(SecurityPreset preset)
{
    if (s_initialized) return 0;

    switch (preset) {
        case SEC_PRESET_BALANCED:    fill_balanced(&s_config_buf[0]);    break;
        case SEC_PRESET_SECURE:      fill_secure(&s_config_buf[0]);      break;
        case SEC_PRESET_PERFORMANCE: fill_performance(&s_config_buf[0]); break;
        default: return -1;
    }

    s_config_active = &s_config_buf[0];
    s_initialized = 1;
    return 0;
}

int security_preset_switch(SecurityPreset preset)
{
    /* 双缓冲治理（二版修正）：非活跃缓冲"先清零后填充" → 原子切换。
     * 不得在切换后清零旧活跃缓冲——已捕获旧指针的并发读者仍可能读取，
     * 立即清零会重引全零窗口。非活跃缓冲无读者，切换前清零 + 填充
     * 覆盖全部字段，切换瞬间起读者只见新快照。 */
    SecurityConfig *active = s_config_active;
    if (active == NULL) {
        if (security_preset_init(SEC_PRESET_BALANCED) != 0) return -1;
        active = s_config_active;
    }

    SecurityConfig *inactive = (active == &s_config_buf[0]) ? &s_config_buf[1]
                                                            : &s_config_buf[0];
    /* 非活跃缓冲无读者：清零（抹除旧预设值）后完整填充 */
    verthys_secure_zero(inactive, sizeof(*inactive));
    switch (preset) {
        case SEC_PRESET_BALANCED:    fill_balanced(inactive);    break;
        case SEC_PRESET_SECURE:      fill_secure(inactive);      break;
        case SEC_PRESET_PERFORMANCE: fill_performance(inactive); break;
        default:
            return -1;
    }

    /* 原子发布新配置快照；旧缓冲继续服务已捕获旧指针的读者，
     * 直至其成为下一次切换的非活跃缓冲被清零复用 */
    InterlockedExchangePointer((volatile PVOID *)&s_config_active, inactive);
    return 0;
}

const char *security_preset_name(SecurityPreset preset)
{
    switch (preset) {
        case SEC_PRESET_BALANCED:    return "BALANCED";
        case SEC_PRESET_SECURE:      return "SECURE";
        case SEC_PRESET_PERFORMANCE: return "PERFORMANCE";
        default: return "UNKNOWN";
    }
}
