/*
 * tamper_destroy.c — 篡改联动销毁策略实现
 *
 * ★ 方案 §6.4：销毁链简化为两步真实可达动作（缺陷依据见头注）。
 * 原 Nonce/密钥页注册表（零调用点）与 key_drift/working_set/cng_machine_key
 * 销毁调用一并删除——密钥销毁的唯一权威路径是 CNG 内核 purge 与
 * memory_guard 注册区清零，两者分别由本模块与 emergency_trigger 调用。
 */
#include "tamper_destroy.h"
#include "key_separation.h"
#include "emergency.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* 模块状态 */
static int s_initialized = 0;

int tamper_destroy_init(void)
{
    if (s_initialized) return 0;
    s_initialized = 1;
    return 0;
}

void tamper_destroy_trigger(void)
{
    if (!s_initialized) {
        tamper_destroy_init();
    }

    /*
     * 1. 销毁 CNG 内核密钥句柄：
     *    句柄失效后内核释放密钥材料，后续任何 BCryptEncrypt/Decrypt
     *    返回 STATUS_INVALID_HANDLE，用户态无任何路径可达密钥。
     */
    key_separation_purge_all();

    /*
     * 2. KILL 级应急响应（幂等，闩锁防重入）：
     *    memory_guard 注册区清零 → 匿名故障码上报看门狗 →
     *    TerminateProcess（不留 dump、不弹窗）。
     */
    emergency_trigger();
}
