/*
 * tls_loader.h — TLS 加载标志验证（内部模块，不导出）
 *
 * 职责：
 *   - TLS 回调（tls_callbacks.c）在 DLL_PROCESS_ATTACH 时置 g_tls_init_marker。
 *   - tls_loader_init（Verthys_Init 中、LoaderLock 释放后调用）验证回调确已
 *     执行：未置位 = DLL 加载路径异常（可能被剥除 TLS 目录重打包）→
 *     上报 KILL 级完整性信号，不得自愈置位。
 *
 * 约束：
 *   - IAT 哈希基于 ASLR 后的运行时绝对地址，与编译期基准逻辑上不相容，
 *     必然误报，本模块不做 IAT 基准校验。
 *   - g_tls_init_marker 的未置位状态是有效信号，不得主动补写。
 */
#ifndef VERTHYS_TLS_LOADER_H
#define VERTHYS_TLS_LOADER_H

#include <stdint.h>
#include <stddef.h>

/* LONG 类型定义（windows.h 未包含时的 fallback，保证头文件可独立使用） */
#ifndef _WINDEF_
typedef long LONG;
#endif

/* TLS 初始化标志（TLS 回调仅设置此标志，无其他操作） */
extern volatile LONG g_tls_init_marker;

/*
 * 验证 TLS 回调已执行（LoaderLock 释放后在 Verthys_Init 中调用）。
 * 返回 0 = 回调标志已置位（加载路径正常）；
 * 返回 -1 = 标志未置位（加载路径异常，已上报 EMERG_SIG_HOOK_DETECTED KILL 级）。
 */
int tls_loader_init(void);

/*
 * 空操作接口，仅用于兼容 DllMain detach 路径；新代码禁止使用。
 */
void tls_loader_shutdown(void);

#endif /* VERTHYS_TLS_LOADER_H */
