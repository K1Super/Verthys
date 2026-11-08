/*
 * vty_record.h — 记录与名称加密（内部，不导出）
 *
 * 记录在静态存储中不出现名称明文与数据明文；长度按桶填充，降低
 * 通过密文长度侧信道推断业务字段的可能。
 */
#ifndef VTY_RECORD_H
#define VTY_RECORD_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_RECORD_NAME_BUCKET 32u
#define VTY_RECORD_DATA_BUCKET 64u
#define VTY_RECORD_MAX_NAME   65535u
#define VTY_RECORD_MAX_DATA   (256u * 1024u * 1024u)

/* 记录密文：调用方用 vty_free 释放 */
int vty_record_seal(const uint8_t mdek[VTY_KEY_BYTES],
                    const uint8_t module_uuid[VTY_UUID_BYTES],
                    uint64_t record_id, uint64_t epoch,
                    const uint8_t *name, size_t name_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t **out, size_t *out_len);

/* 打开：name/data 分别分配，调用方用 vty_free 释放；失败不返回部分明文 */
int vty_record_open(const uint8_t mdek[VTY_KEY_BYTES],
                    const uint8_t module_uuid[VTY_UUID_BYTES],
                    uint64_t epoch,
                    const uint8_t *in, size_t in_len,
                    uint8_t **name, size_t *name_len,
                    uint8_t **data, size_t *data_len);

/* 只解密名称（名称 AEAD 独立）：摘要扫描不读数据，避免为元数据付出
 * 全量数据解密代价；数据段结构仍做长度校验，防止半截记录被接受。 */
int vty_record_open_name(const uint8_t mdek[VTY_KEY_BYTES],
                         const uint8_t module_uuid[VTY_UUID_BYTES],
                         uint64_t epoch,
                         const uint8_t *in, size_t in_len,
                         uint8_t **name, size_t *name_len);

/* 盲索引：对 NFKC 归一化后的名称做 HMAC-SHA256 */
int vty_name_index(const uint8_t mdek[VTY_KEY_BYTES],
                   const uint8_t module_uuid[VTY_UUID_BYTES],
                   const uint8_t *name, size_t name_len,
                   uint8_t out[VTY_HASH_BYTES]);

/* 类型令牌：TK 绑定模块与 epoch，令牌只暴露类型等价关系，不暴露类型值 */
int vty_type_token(const uint8_t mdek[VTY_KEY_BYTES],
                   const uint8_t module_uuid[VTY_UUID_BYTES],
                   uint64_t epoch, uint8_t type,
                   uint8_t out[VTY_HASH_BYTES]);

/* 显式拒绝明文回退请求（上层适配时统一调用） */
int vty_record_reject_plaintext(int encrypted_flag);

#ifdef __cplusplus
}
#endif

#endif /* VTY_RECORD_H */
