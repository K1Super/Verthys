/*
 * anti_inject.h — 深度防注入与模块认证（内部模块，不导出）
 *
 * 用户需求（二.3 深度防注入与模块认证）：
 *   - 入口基因修复：程序入口点立即调用 SetDllDirectoryW(L"") 与
 *     SetSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE)，
 *     彻底移除当前工作目录在 DLL 搜索顺序中的优先级。
 *   - 运行时远程线程/APC/窗口钩子拦截：拦截远程线程注入、APC 注入、
 *     SetWindowsHookEx 全局钩子注入。
 *   - 模块白名单实时巡检：遍历已加载模块列表，发现未信任签名或路径
 *     不在安装目录/系统目录下的未知第三方 DLL → 暂停 Verthys 解密句柄。
 */
#ifndef VERTHYS_ANTI_INJECT_H
#define VERTHYS_ANTI_INJECT_H

#include <stdint.h>

/* 注入威胁类型（位掩码） */
#define INJECT_THREAT_REMOTE_THREAD  0x01  /* 远程线程注入 */
#define INJECT_THREAT_APC            0x02  /* APC 注入 */
#define INJECT_THREAT_WINDOW_HOOK    0x04  /* SetWindowsHookEx 全局钩子 */
#define INJECT_THREAT_UNKNOWN_DLL    0x08  /* 未知第三方 DLL */
#define INJECT_THREAT_UNSIGNED       0x10  /* 未签名模块 */

/*
 * 初始化防注入模块。
 * 必须在程序入口点最早执行（在加载任何其他 DLL 之前）。
 * 执行 DLL 搜索顺序加固（SetDllDirectoryW + SetSearchPathMode）。
 * 返回 0 成功，非 0 失败。
 */
int anti_inject_init(void);

/*
 * 执行入口基因修复（DLL 搜索顺序加固）。
 * 在 WinMain/main 第一行调用。
 * Windows: SetDllDirectoryW(L"") + SetSearchPathMode
 * Linux/Mac: 无操作（Unix 系统不依赖搜索路径）
 */
int anti_inject_harden_search_path(void);

/*
 * 检测远程线程注入。
 * 遍历当前进程的线程列表，检测是否存在非主线程创建的远程线程。
 * 返回 0=安全，非 0=检测到注入。
 */
int anti_inject_check_remote_thread(void);

/*
 * 检测 APC 注入。
 * 检查线程的 APC 队列是否被注入异常回调。
 * 返回 0=安全，非 0=检测到注入。
 */
int anti_inject_check_apc(void);

/*
 * 检测窗口钩子注入。
 * 检查是否存在全局 Windows 钩子（WH_CBT/WH_GETMESSAGE 等）。
 * 返回 0=安全，非 0=检测到钩子。
 */
int anti_inject_check_window_hook(void);

/*
 * 模块白名单巡检。
 * 遍历当前进程已加载的模块列表，验证：
 *   1. 模块路径在安装目录或系统目录下
 *   2. 模块具有有效数字签名（Authenticode）
 * 发现未知模块时返回位掩码（INJECT_THREAT_UNKNOWN_DLL | INJECT_THREAT_UNSIGNED）。
 * 返回 0=全部可信，非 0=检测到威胁（位掩码）。
 */
int anti_inject_check_modules(void);

/*
 * 综合注入检测（调用以上所有检测）。
 * 返回 0=安全，非 0=威胁位掩码。
 */
int anti_inject_check_all(void);

/*
 * 添加受信任模块路径（白名单）。
 * 用于注册已知安全的第三方 DLL（如 Tauri 运行时依赖）。
 */
int anti_inject_add_trusted_path(const char *path);

#endif /* VERTHYS_ANTI_INJECT_H */
