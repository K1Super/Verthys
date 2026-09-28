/*
 * security_preset.c — 三档安全模式配置实现
 *
 * 根据预设填充 SecurityConfig 结构体，各子系统读取配置决定行为。
 *
 * 并发设计（双缓冲 + 指针原子交换 + 发布世代号）：
 *   - 活跃缓冲经 s_config_active 原子指针发布，任何时刻读者都能取到
 *     一个完整有效的配置快照；
 *   - 切换在非活跃缓冲上完成填充后再原子发布，切换前对非活跃缓冲清零
 *     （该缓冲无读者持有新指针）；
 *   - 发布世代号 s_config_gen 供快照读取做乐观并发校验：读者在复制
 *     前后各读一次世代号，不一致即重试——即使读者正好跨越两次切换
 *     导致所读缓冲被清零复用，也会因世代变化而丢弃本次复制结果。
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
/* 配置发布世代号：每次原子切换后递增（快照读取的乐观并发校验基准） */
static volatile LONG s_config_gen = 0;
/* 初始化一次性门（0 = 未初始化；经 InterlockedCompareExchange 置位） */
static volatile LONG s_init_state = 0;

/* 快照读取重试上限：极端争用下放弃并回填保守基线 */
#define SEC_SNAPSHOT_MAX_RETRY 8

/* 平衡模式配置（默认推荐） */
static void fill_balanced(SecurityConfig *c)
{
    memset(c, 0, sizeof(*c));
    c->preset = SEC_PRESET_BALANCED;

    /* 运行时动态防护 */
    c->anti_debug           = 1;
    c->anti_debug_aggressive= 0;  /* 平衡模式不立即退出 */
    c->memory_lock          = 1;
    c->anti_dump            = 1;
    c->anti_inject          = 1;

    /* 应用侧策略位：完整性核验 / 空闲锁定 / 模块巡检 / 克隆检测 / 痕迹清理 */
    c->app_features = SEC_FEAT_INTEGRITY_CHECK
                    | SEC_FEAT_SESSION_LOCK_IDLE
                    | SEC_FEAT_MODULE_PATROL
                    | SEC_FEAT_USB_CLONE_DETECT
                    | SEC_FEAT_TRACE_CLEANUP;
}

/* 高安全模式配置（涉密/取证场景） */
static void fill_secure(SecurityConfig *c)
{
    fill_balanced(c);  /* 继承平衡模式全部防护 */
    c->preset = SEC_PRESET_SECURE;

    /* 高安全模式强化项 */
    c->anti_debug_aggressive = 1;  /* 检测到调试器即零化退出 */
    /* 剪贴板防护（外部写入即清空监听）仅高安全档启用 */
    c->app_features |= SEC_FEAT_CLIPBOARD_GUARD;
}

/* 极致性能模式配置（保留安全底线，仅关闭高开销能力） */
static void fill_performance(SecurityConfig *c)
{
    memset(c, 0, sizeof(*c));
    c->preset = SEC_PRESET_PERFORMANCE;

    /* 红线能力恒开：调试器检测、反注入（密钥分立与应急熔断见投影函数） */
    c->anti_debug           = 1;
    c->anti_debug_aggressive= 0;
    c->anti_inject          = 1;
    /* 高开销能力关闭：锁页 / 防转储 */
    c->memory_lock          = 0;
    c->anti_dump            = 0;

    /* 应用侧策略位：仅保留空闲锁定（超时按档位常量） */
    c->app_features = SEC_FEAT_SESSION_LOCK_IDLE;
}

/* ===================================================================== *
 *                           公共接口                                    *
 * ===================================================================== */

void security_config_ensure_init(void)
{
    if (s_config_active == NULL) {
        (void)security_preset_init(SEC_PRESET_BALANCED);
    }
}

int security_config_snapshot(SecurityConfig *out)
{
    if (out == NULL) return -1;

    for (int i = 0; i < SEC_SNAPSHOT_MAX_RETRY; i++) {
        LONG gen_before = InterlockedCompareExchange(&s_config_gen, 0, 0);
        const SecurityConfig *src = (const SecurityConfig *)s_config_active;
        if (src == NULL) {
            security_config_ensure_init();
            src = (const SecurityConfig *)s_config_active;
            if (src == NULL) break;  /* 初始化未完成：进入保守回填 */
        }
        memcpy(out, src, sizeof(*out));
        LONG gen_after = InterlockedCompareExchange(&s_config_gen, 0, 0);
        if (gen_before == gen_after) return 0;  /* 世代未变：快照一致 */
    }

    /* 极端争用：回填保守基线（全防护开启），任何路径都不朝全零失败 */
    memset(out, 0, sizeof(*out));
    out->preset       = SEC_PRESET_SECURE;
    out->anti_debug   = 1;
    out->anti_inject  = 1;
    out->memory_lock  = 1;
    out->anti_dump    = 1;
    out->app_features = SEC_FEAT_VALID_MASK;
    return -1;
}

int security_preset_feature_bits(SecurityPreset preset, uint32_t *out_bits)
{
    if (out_bits == NULL) return -1;

    SecurityConfig c;
    switch (preset) {
        case SEC_PRESET_BALANCED:    fill_balanced(&c);    break;
        case SEC_PRESET_SECURE:      fill_secure(&c);      break;
        case SEC_PRESET_PERFORMANCE: fill_performance(&c); break;
        default: return -1;
    }

    uint32_t bits = c.app_features;
    if (c.anti_debug)  bits |= SEC_FEAT_ANTI_DEBUG;
    if (c.anti_inject) bits |= SEC_FEAT_ANTI_INJECT;
    if (c.memory_lock && c.anti_dump) bits |= SEC_FEAT_MEMORY_GUARD;
    /* 密钥三权分立与应急熔断为红线恒定能力，不随档位关闭 */
    bits |= SEC_FEAT_KEY_SEPARATION | SEC_FEAT_EMERGENCY_RESPONSE;

    *out_bits = bits & SEC_FEAT_VALID_MASK;
    return 0;
}

int security_active_preset(SecurityPreset *out)
{
    if (out == NULL) return -1;
    SecurityConfig c;
    /* 失败路径的快照已回填保守基线，preset 字段同样可用 */
    (void)security_config_snapshot(&c);
    *out = c.preset;
    return 0;
}

SecurityPreset security_runtime_preset(void)
{
    SecurityConfig c;
    (void)security_config_snapshot(&c);
    return c.preset;
}

int security_preset_init(SecurityPreset preset)
{
    /* 一次性门：首个进入者完成填充与发布，其余进入者直接返回成功 */
    if (InterlockedCompareExchange(&s_init_state, 1, 0) != 0) return 0;

    switch (preset) {
        case SEC_PRESET_BALANCED:    fill_balanced(&s_config_buf[0]);    break;
        case SEC_PRESET_SECURE:      fill_secure(&s_config_buf[0]);      break;
        case SEC_PRESET_PERFORMANCE: fill_performance(&s_config_buf[0]); break;
        default:
            InterlockedExchange(&s_init_state, 0);
            return -1;
    }

    /* 发布顺序：填充完成 → 指针发布 → 世代递增（读者据此校验一致性） */
    s_config_active = &s_config_buf[0];
    InterlockedIncrement(&s_config_gen);
    return 0;
}

int security_preset_switch(SecurityPreset preset)
{
    security_config_ensure_init();

    SecurityConfig *active = s_config_active;
    if (active == NULL) return -1;

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

    /* 原子发布新配置快照，随后递增世代号：读者在复制前后比较世代，
     * 跨切换的读取会因世代变化而重试，杜绝读到清零/复用中的缓冲 */
    InterlockedExchangePointer((volatile PVOID *)&s_config_active, inactive);
    InterlockedIncrement(&s_config_gen);
    return 0;
}