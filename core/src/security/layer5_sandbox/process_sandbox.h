/*
 * process_sandbox.h — 进程无菌沙盒（内部模块，不导出）
 *
 * 用户需求（五、进程无菌沙盒 — 1. 双进程解耦架构）：
 *   - 加密 Worker（纯无菌沙盒）：
 *     1. WIN32K_SYSTEM_CALL_DISABLE：免疫所有窗口注入
 *     2. PROCESS_CREATION_DISABLED：绝杀进程镂空、子进程注入
 *     3. IMAGE_LOAD_PREFER_SYSTEM32：防本地 DLL 劫持
 *     4. IMAGE_LOAD_NO_REMOTE：防反射注入、内存 PE 加载
 *   - 前台辅助进程：承担 UI、日志、系统调用、工具调用，全程无明文密钥，
 *     通过单向 IPC 通信
 *
 * 设计原理：
 *   Windows 10 1709+ 提供 ProcessSystemCallDisableInformation，
 *   可禁用 Win32k 系统调用（窗口、GDI、消息），免疫所有窗口注入。
 *
 *   Windows 10 1709+ 提供 ProcessChildProcessInformation，
 *   可禁用子进程创建（PROCESS_CREATION_DISABLED），绝杀进程镂空。
 *
 *   Windows 10 1607+ 提供 SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)，
 *   启用 IMAGE_LOAD_PREFER_SYSTEM32，强制从 System32 加载 DLL。
 *
 *   IMAGE_LOAD_NO_REMOTE 通过 SetProcessMitigationPolicy 实现，
 *   禁止从远程位置加载 DLL（防反射注入、内存 PE 加载）。
 *
 *   本模块对当前进程应用所有四个 mitigation policy：
 *     1. ProcessSystemCallDisableInformation
 *     2. ProcessChildProcessInformation
 *     3. SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)
 *     4. ProcessImageLoadPolicy（NoRemoteImages / NoLowMandatoryLabelImages）
 */
#ifndef VERTHYS_PROCESS_SANDBOX_H
#define VERTHYS_PROCESS_SANDBOX_H

#include <stdint.h>
#include <stddef.h>

/* 沙盒属性位掩码 */
#define SANDBOX_ATTR_WIN32K_SYS_DISABLE   0x01  /* 禁用 Win32k 系统调用 */
#define SANDBOX_ATTR_PROCESS_CREATE_DISABLE 0x02  /* 禁止创建子进程 */
#define SANDBOX_ATTR_IMAGE_PREFER_SYS32   0x04  /* System32 优先加载 */
#define SANDBOX_ATTR_IMAGE_NO_REMOTE       0x08  /* 禁止远程镜像加载 */
#define SANDBOX_ATTR_IMAGE_NO_LOW_LABEL    0x10  /* 禁止低完整性镜像加载 */
#define SANDBOX_ATTR_ALL                   0x1F  /* 全部启用 */

/*
 * 初始化无菌沙盒。
 *   attrs: 沙盒属性位掩码（SANDBOX_ATTR_*）
 * 返回 0 成功，非 0 失败（详细错误码见日志）。
 *
 * 注意：必须在 Worker 进程启动早期、加载任何业务 DLL 之前调用。
 *       部分策略应用后不可撤销。
 */
int process_sandbox_init(uint32_t attrs);

/*
 * 查询当前沙盒属性。
 * 返回已启用的属性位掩码。
 */
uint32_t process_sandbox_get_active_attrs(void);

/*
 * 设置当前沙盒属性（外部注入）。
 *   attrs: 已应用的属性位掩码
 *
 * 用于 Worker 进程在加载本 DLL 之前已应用 mitigation policy 的场景。
 * Worker（Rust 端）通过 apply_process_sandbox() 应用 policy 后，
 * 通过 Verthys_NotifySandboxAttrs() 将已应用的属性位掩码注入本模块，
 * 使 defense_closure_check 能正确识别已生效的防御策略。
 *
 * 注意：本函数仅更新内部状态变量，不实际应用任何 mitigation policy。
 *       实际 policy 应用由 Worker 进程在加载 DLL 之前完成。
 */
void process_sandbox_set_active_attrs(uint32_t attrs);

#endif /* VERTHYS_PROCESS_SANDBOX_H */
