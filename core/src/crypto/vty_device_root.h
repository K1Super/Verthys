/*
 * vty_device_root.h — 设备根密钥封装（内部，不导出）
 *
 * 设备根使用 CNG 持久化、不可导出的 RSA 私钥做 OAEP 包装；密钥材料
 * 只在内核地址空间出现。设备根不可用时一律 fail-closed，不做软件
 * 降级——否则“偷库即解”的假设立刻失效。
 */
#ifndef VTY_DEVICE_ROOT_H
#define VTY_DEVICE_ROOT_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 设备根封装块：level(1) + provider(1) + 机器实例指纹(32) + RSA 密文(256) */
#define VTY_DEVICE_BLOB_BYTES 290u

/* 幂等初始化；返回 VTY_OK 或 VTY_E_TPM */
int vty_device_root_init(void);

/* 1=具备封装能力 */
int vty_device_root_available(void);

/* 用设备根封装 32B 密钥；blob 容量须 >= VTY_DEVICE_BLOB_BYTES */
int vty_device_key_seal(const uint8_t key[VTY_KEY_BYTES],
                        uint8_t *blob, size_t *blob_len);

/* 解封；机器实例不匹配或容器缺失均返回 VTY_E_TPM */
int vty_device_key_unseal(const uint8_t *blob, size_t blob_len,
                          uint8_t key[VTY_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* VTY_DEVICE_ROOT_H */
