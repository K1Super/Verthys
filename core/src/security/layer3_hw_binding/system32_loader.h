/*
 * system32_loader.h — System32 优先加载与 cnghwassist.sys 冲突解决（内部模块，不导出）
 *
 *
 * 设计原理：
 *   IMAGE_LOAD_PREFER_SYSTEM32 标志强制 LoadLibrary 从 System32 优先加载，
 *   防止同目录下的恶意 DLL 劫持。但部分低版本 Windows（如早期 Win10）
 *   缺少 cnghwassist.sys 硬件辅助驱动，CNG 在尝试加载此驱动时返回
 *   STATUS_IMAGE_NOT_FOUND，导致 BCryptOpenAlgorithmProvider 失败。
 *
 *   本模块在打开 CNG 算法提供者时：
 *     1. 启用 IMAGE_LOAD_PREFER_SYSTEM32（防劫持）
 *     2. 捕获 STATUS_IMAGE_NOT_FOUND
 *     3. 检测 cnghwassist.sys 是否存在
 *     4. 若缺失，设置 NCryptProviderLegacyFipsAlgoMode 强制纯软件上下文
 *     5. 不影响密钥安全性（RSA/AES 软件实现同样安全）
 */
#ifndef VERTHYS_SYSTEM32_LOADER_H
#define VERTHYS_SYSTEM32_LOADER_H

#include <stdint.h>
#include <stddef.h>

/* 加载模式 */
typedef enum {
    SYSLOADER_MODE_HW_ASSIST  = 0,  /* 硬件辅助（cnghwassist.sys 可用） */
    SYSLOADER_MODE_PURE_SOFT  = 1,  /* 纯软件降级 */
} SysLoaderMode;

/*
 * 初始化 System32 优先加载策略。
 *   - 启用 IMAGE_LOAD_PREFER_SYSTEM32（DefaultDllDirectories 等价）
 *   - 检测 cnghwassist.sys，设置降级模式
 * 返回 0 成功，非 0 失败。
 */
int system32_loader_init(void);

/*
 * 查询当前加载模式。
 */
SysLoaderMode system32_loader_get_mode(void);

/*
 * 安全加载 DLL（带 System32 优先 + 路径校验）。
 *   dll_name: DLL 文件名（仅文件名，不含路径）
 *   out_handle: 输出 HMODULE
 * 返回 0 成功，非 0 失败。
 *
 * 注意：仅允许从 System32 或当前模块目录加载，禁止其他路径。
 */
int system32_loader_load(const wchar_t *dll_name, void **out_handle);

#endif /* VERTHYS_SYSTEM32_LOADER_H */
