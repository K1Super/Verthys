/*
 * vty_module_v4.h — 模块 M1 密钥生命周期（内部，不导出）
 *
 * 模块密钥由“模块口令 + 设备根”双包裹，且与容器主密钥分离；
 * 容器解锁成功并不自动授予模块密钥，模块必须单独解锁。
 */
#ifndef VTY_MODULE_V4_H
#define VTY_MODULE_V4_H

#include "vty_v4_types.h"
#include "vty_keymanager_v4.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_MODULE_MAGIC 0x314D5456u  /* 'VTM1' */

/* 创建模块密钥文件；v 必须处于解锁状态且包含该模块 UUID */
int vty_module_create(const char *path, const VtyVault *v,
                      const uint8_t module_uuid[VTY_UUID_BYTES],
                      const char *password,
                      uint32_t mem_kib, uint32_t iters, uint32_t parallel);

/* 解锁模块：口令 + 设备根（AND）；epoch 必须与容器一致 */
int vty_module_unlock(const char *path, const VtyVault *v,
                      const uint8_t module_uuid[VTY_UUID_BYTES],
                      const char *password,
                      uint8_t mdek_out[VTY_KEY_BYTES]);

/* 模块口令轮换：只重包裹 MDEK，不重写业务数据 */
int vty_module_rotate_password(const char *path, const VtyVault *v,
                               const uint8_t module_uuid[VTY_UUID_BYTES],
                               const char *new_password,
                               uint32_t mem_kib, uint32_t iters, uint32_t parallel);

/* 显式销毁模块密钥文件（业务数据必须由上层先行重写/删除） */
int vty_module_destroy(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* VTY_MODULE_V4_H */
