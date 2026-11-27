/*
 * vty_keyfile.h — keyfile 因子（VKFL v1）
 *
 * keyfile 是用户口令槽的 KDF 第二输入，不新增容器槽：
 *   keyfile_digest = BLAKE3("verthys/v4/keyfile" | secret)
 *   KDF_input      = u32_le(password_len) | password | u32_le(32) | keyfile_digest
 *
 * 文件格式固定 72B，解析时校验 magic/version/flags/length/checksum；
 * 不存储 keyfile 路径，不把 secret 写入容器或日志。
 */
#ifndef VTY_KEYFILE_H
#define VTY_KEYFILE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_KEYFILE_BLOB_BYTES 72u
#define VTY_KEYFILE_SECRET_BYTES 32u

/* 生成 VKFL v1 文件内容；失败返回 VTY_E_RESOURCE/VTY_E_INVALID。 */
int vty_keyfile_generate(uint8_t blob[VTY_KEYFILE_BLOB_BYTES]);

/* 解析 VKFL v1；格式非法返回 VTY_E_KEYFILE_INVALID。 */
int vty_keyfile_parse(const uint8_t *buf, size_t len,
                      uint8_t secret[VTY_KEYFILE_SECRET_BYTES]);

/* 由 VKFL secret 计算 KDF 第二输入摘要（域分离）。 */
int vty_keyfile_digest(const uint8_t secret[VTY_KEYFILE_SECRET_BYTES],
                       uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* VTY_KEYFILE_H */
