/*
 * tls_loader.h — TLS 加载标志验证（内部模块，不导出）
 *
 * ★ 方案 §6.4：TLS 回调体系保留，IAT 基准与种子定时器删除。
 *
 * 原实现缺陷（security 层深度审计 §5.5）：
 *   1. IAT 哈希基于 ASLR 后的运行时绝对地址，与"编译期基准"在逻辑上
 *      不相容——基准一旦注入必然误报自毁；此前基准恒未配置，校验从未生效。
 *   2. 15s 混淆种子刷新定时器的种子无任何消费者——纯 CPU 浪费。
 *   3. g_tls_init_marker 校验为"自愈式"：未置位时主动置 1，形同虚设。
 *
 * 保留职责：
 *   - TLS 回调（tls_callbacks.c）在 DLL_PROCESS_ATTACH 时置 g_tls_init_marker。
 *   - tls_loader_init（Verthys_Init 中、LoaderLock 释放后调用）验证回调确已
 *     执行：未置位 = DLL 加载路径异常（可能被剥除 TLS 目录重打包）→
 *     上报 KILL 级完整性信号。不再自愈。
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
 * 兼容接口：原 IAT 状态查询随 IAT 校验体系一并删除，恒返回 0（通过）。
 * 保留符号以稳定内部调用方（defense_closure），新代码禁止使用。
 */
int tls_loader_iat_status(void);

/*
 * 原混淆种子刷新与定时器体系已删除；此接口保留为空操作以兼容
 * DllMain detach 路径，新代码禁止使用。
 */
void tls_loader_shutdown(void);

#endif /* VERTHYS_TLS_LOADER_H */
