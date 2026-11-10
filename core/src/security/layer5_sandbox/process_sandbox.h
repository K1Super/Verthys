/*
 * process_sandbox.h — 进程无菌沙盒（内部模块，不导出）
 *
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

/* 沙盒属性位掩码（与 Worker 端沙箱常量严格对齐） */
#define SANDBOX_ATTR_WIN32K_SYS_DISABLE   0x01  /* 禁用 Win32k 系统调用 */
#define SANDBOX_ATTR_PROCESS_CREATE_DISABLE 0x02  /* 禁止创建子进程 */
#define SANDBOX_ATTR_IMAGE_PREFER_SYS32   0x04  /* System32 优先加载 */
#define SANDBOX_ATTR_IMAGE_NO_REMOTE       0x08  /* 禁止远程镜像加载 */
#define SANDBOX_ATTR_IMAGE_NO_LOW_LABEL    0x10  /* 禁止低完整性镜像加载 */
#define SANDBOX_ATTR_ACG                   0x20  /* ACG：禁止动态代码 */
#define SANDBOX_ATTR_STRICT_HANDLE         0x40  /* 严格句柄校验 */
#define SANDBOX_ATTR_EXTENSION_POINT       0x80  /* 禁用扩展点 */
#define SANDBOX_ATTR_ALL                   0xFF  /* 全部启用 */

/* OS 回读可确认的核心位：子进程创建 / 镜像加载 / ACG。
 * System32 优先（0x04）由 SetDefaultDllDirectories 在加载业务 DLL 之前
 * 固定，Windows 不提供回读接口，因此不列入可回读核心，避免把不可证明
 * 的设置伪装成已验证事实。 */
#define SANDBOX_ATTR_VERIFIABLE_CORE \
    (SANDBOX_ATTR_PROCESS_CREATE_DISABLE | \
     SANDBOX_ATTR_IMAGE_NO_REMOTE | \
     SANDBOX_ATTR_IMAGE_NO_LOW_LABEL | \
     SANDBOX_ATTR_ACG)

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

/*
 * OS 回读当前进程实际生效的 mitigation 策略（不接受自报位）。
 *
 * 读取 ProcessChildProcess / ProcessImageLoad / ProcessDynamicCode /
 * ProcessStrictHandleCheck / ProcessExtensionPointDisable 五项策略，
 * 成功确认的位写入 out_verified_mask（SANDBOX_ATTR_* 子集）。
 *
 * 返回 0 = 五项查询全部成功（mask 可能为 0，表示进程未启用任何策略）；
 * 返回 -1 = 至少一项查询失败或系统不支持，此时调用方必须按“无法确认”
 * 降级，不得用部分结果宣称阻断。
 */
int process_sandbox_verify_os(uint32_t *out_verified_mask);

#endif /* VERTHYS_PROCESS_SANDBOX_H */
