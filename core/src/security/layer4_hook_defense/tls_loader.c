/*
 * tls_loader.c — TLS 加载标志验证实现
 *
 * ★ IAT 基准校验与 15s 混淆种子定时器已删除（缺陷依据同头注）。
 *
 * 本文件仅保留一项职责：验证 TLS 回调（tls_callbacks.c，.CRT$XLB 注册）
 * 确实在 DLL_PROCESS_ATTACH 阶段执行并置位 g_tls_init_marker。
 * 校验失败不再"自愈置位"——那等于替攻击者补票——而是上报 KILL 级
 * 完整性信号（TLS 目录被剥除/加载路径被劫持属于高置信度篡改）。
 */
#include "tls_loader.h"
#include "emergency.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* TLS 初始化标志（TLS 回调在 DLL_PROCESS_ATTACH 时原子置 1） */
volatile LONG g_tls_init_marker = 0;

int tls_loader_init(void)
{
    /*
     * 原子读取标志。注意：不进行任何"补写"——
     * 该标志唯一合法写入者是 PE 加载器调用的 TLS 回调。
     * Verthys_Init 在 LoaderLock 释放后执行，此时回调必然已完成；
     * 未置位 = 本 DLL 未经过正常 TLS 加载路径（重打包/剥除/劫持）。
     */
    if (InterlockedCompareExchange(&g_tls_init_marker, 0, 0) != 1) {
        emergency_report(EMERG_LEVEL_KILL, EMERG_SIG_HOOK_DETECTED);
        return -1;
    }
    return 0;
}

int tls_loader_iat_status(void)
{
    /* IAT 基准校验体系已删除（见头注），恒返回通过以稳定旧调用方 */
    return 0;
}

void tls_loader_shutdown(void)
{
    /* 原定时器/种子体系已删除；保留空实现兼容 DllMain detach 路径 */
}
