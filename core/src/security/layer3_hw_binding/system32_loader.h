/*
 * system32_loader.h — System32 优先加载策略与目录前缀校验（内部模块，不导出）
 *
 * 设计原理：
 *   通过 SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 |
 *   LOAD_LIBRARY_SEARCH_DEFAULT_DIRS) 将默认 DLL 搜索路径收敛到 System32
 *   与受信目录，降低同目录恶意 DLL 劫持风险。
 *
 *   模块同时保留 System32 目录前缀判定（带分隔符边界）供白盒测试，
 *   防止“同前缀旁路目录”被误判为可信位置。模块不提供独立加载函数，
 *   加载策略在 system32_loader_init 中一次性设置。
 */
#ifndef VERTHYS_SYSTEM32_LOADER_H
#define VERTHYS_SYSTEM32_LOADER_H

#include <stdint.h>
#include <stddef.h>

/*
 * 初始化 System32 优先加载策略。
 *   - 启用 IMAGE_LOAD_PREFER_SYSTEM32（DefaultDllDirectories 等价）
 * 返回 0 成功，非 0 失败。
 */
int system32_loader_init(void);

/*
 * 测试白盒：System32 目录前缀边界判定（带分隔符边界）。
 * 仅被测试 exe 对象直链调用；不在 DLL 导出清单中，发布面零变化。
 * 前置：system32_loader_init 已成功（s_system32_dir 就位）。
 */
int system32_loader_dir_prefix_test(const wchar_t *path);

#endif /* VERTHYS_SYSTEM32_LOADER_H */
