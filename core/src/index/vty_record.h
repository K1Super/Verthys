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

/* 记录密钥头（RKH）固定 64B，位于记录段载荷最前：
 *   prev_id(8, 大端) | reserved(8, 全零) | wrapped RDK(48)
 *
 * RKH 由模块 MDEK 派生密钥 AEAD 包裹，AAD 绑定模块 UUID、记录 ID、
 * epoch 与 prev_id。删除时只擦这 64B，RDK 随之消失，记录载荷（含名称、
 * 数据与文件分片信封）永久不可解，与载荷大小无关。
 *
 * prev_id 指向上一个版本（replace 前的记录 ID）。链上的每个版本各自
 * 持有 RKH；删除沿链逐条擦除，历史版本同样不可恢复。 */
#define VTY_RECORD_KEY_HEADER_BYTES 64u

int vty_record_seal_keyed(const uint8_t root_key[VTY_KEY_BYTES],
                          const uint8_t module_uuid[VTY_UUID_BYTES],
                          uint64_t record_id, uint64_t epoch,
                          uint64_t prev_id,
                          const uint8_t *name, size_t name_len,
                          const uint8_t *data, size_t data_len,
                          uint8_t **out, size_t *out_len);

int vty_record_open_keyed(const uint8_t root_key[VTY_KEY_BYTES],
                          const uint8_t module_uuid[VTY_UUID_BYTES],
                          uint64_t epoch,
                          const uint8_t *in, size_t in_len,
                          uint8_t **name, size_t *name_len,
                          uint8_t **data, size_t *data_len);

int vty_record_open_name_keyed(const uint8_t root_key[VTY_KEY_BYTES],
                               const uint8_t module_uuid[VTY_UUID_BYTES],
                               uint64_t epoch,
                               const uint8_t *in, size_t in_len,
                               uint8_t **name, size_t *name_len);

/* 解包 RKH：认证失败返回 VTY_E_KEY_INVALID；全零视为已擦除，
 * 返回 VTY_E_INVALID，调用方据此停止链遍历。 */
int vty_record_key_header_parse(const uint8_t mdek[VTY_KEY_BYTES],
                                const uint8_t module_uuid[VTY_UUID_BYTES],
                                uint64_t record_id, uint64_t epoch,
                                const uint8_t in[VTY_RECORD_KEY_HEADER_BYTES],
                                uint64_t *out_prev_id);


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
