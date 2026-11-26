/*
 * verthys_api_container_internal.h — 容器 API 分片间的共享声明
 *
 * 仅承载跨翻译单元的辅助函数声明；文件级静态状态不在此重复定义。
 */
#ifndef VERTHYS_API_CONTAINER_INTERNAL_H
#define VERTHYS_API_CONTAINER_INTERNAL_H

#include "verthys_api_container.h"
#include "verthys_api_utils.h"
#include "vty_module.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 按显式长度复制口令并 NUL 终结；返回缓冲由调用方 free。 */
char *vty_api_pw_copy(const char *pw, size_t len);

/* 已解锁会话解析与 api_mutex 串行化；调用方先完成句柄/状态校验。 */
struct VerthysContext *vty_api_module_ctx(VerthysHandle handle);
void vty_api_module_lock_ctx(struct VerthysContext *ctx);
void vty_api_module_unlock_ctx(struct VerthysContext *ctx);

/* 入口参数校验：恢复码长度上限与模块号范围。 */
int vty_api_recovery_arg_ok(const char *text, int required);
int vty_api_module_id_ok(uint32_t module_id);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_API_CONTAINER_INTERNAL_H */
