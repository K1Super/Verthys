/*
 * vty_chunk_v4.h — v4 分片与文件清单加密（内部，不导出）
 *
 * 分片寻址使用键控 ID，而不是内容哈希，避免确认预言机与去重侧信道。
 */
#ifndef VTY_CHUNK_V4_H
#define VTY_CHUNK_V4_H

#include "vty_v4_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_CHUNK_MAX_PT (16u * 1024u * 1024u)
#define VTY_MANIFEST_MAX_CHUNKS (1u << 20)

int vty_chunk_seal(const uint8_t mdek[VTY_KEY_BYTES],
                   const uint8_t file_uuid[VTY_UUID_BYTES],
                   uint32_t seq, uint32_t total, uint64_t epoch,
                   const uint8_t *pt, size_t pt_len,
                   uint8_t **out, size_t *out_len);

int vty_chunk_open(const uint8_t mdek[VTY_KEY_BYTES],
                   const uint8_t file_uuid[VTY_UUID_BYTES],
                   uint32_t seq, uint32_t total, uint64_t epoch,
                   const uint8_t *in, size_t in_len,
                   uint8_t **pt, size_t *pt_len);

/* 键控分片 ID：相同内容在不同文件/序号下不可关联 */
int vty_chunk_id(const uint8_t mdek[VTY_KEY_BYTES],
                 const uint8_t file_uuid[VTY_UUID_BYTES],
                 uint32_t seq, uint8_t out[VTY_HASH_BYTES]);

/* 清单：file_uuid | 明文哈希 | total | chunkId 列表（total * 32B） */
int vty_manifest_seal(const uint8_t mdek[VTY_KEY_BYTES],
                      const uint8_t file_uuid[VTY_UUID_BYTES],
                      uint64_t epoch,
                      const uint8_t pt_hash[VTY_HASH_BYTES],
                      uint32_t total,
                      const uint8_t *chunk_ids,
                      uint8_t **out, size_t *out_len);

int vty_manifest_open(const uint8_t mdek[VTY_KEY_BYTES],
                      const uint8_t file_uuid[VTY_UUID_BYTES],
                      uint64_t epoch,
                      const uint8_t *in, size_t in_len,
                      uint8_t pt_hash[VTY_HASH_BYTES],
                      uint32_t *total,
                      uint8_t **chunk_ids);

#ifdef __cplusplus
}
#endif

#endif /* VTY_CHUNK_V4_H */
