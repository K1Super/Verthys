/*
 * vty_chunk.h — 分片与文件清单加密（内部，不导出）
 *
 * 分片寻址使用键控 ID，而不是内容哈希，避免确认预言机与去重侧信道。
 */
#ifndef VTY_CHUNK_H
#define VTY_CHUNK_H

#include "vty_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_CHUNK_MAX_PT (16u * 1024u * 1024u)
#define VTY_MANIFEST_MAX_CHUNKS (1u << 20)

__declspec(noinline) int vty_chunk_seal(const uint8_t mdek[VTY_KEY_BYTES],
                   const uint8_t file_uuid[VTY_UUID_BYTES],
                   uint32_t seq, uint32_t total, uint64_t epoch,
                   const uint8_t *pt, size_t pt_len,
                   uint8_t **out, size_t *out_len);

__declspec(noinline) int vty_chunk_open(const uint8_t mdek[VTY_KEY_BYTES],
                   const uint8_t file_uuid[VTY_UUID_BYTES],
                   uint32_t seq, uint32_t total, uint64_t epoch,
                   const uint8_t *in, size_t in_len,
                   uint8_t **pt, size_t *pt_len);

/*
 * 重封装 JSON 明文中内嵌的 base64 分片信封（旧版内联布局）。
 *
 * 模块启用/全库轮换只能识别记录顶层的分片信封；旧版 meta 把分片密文
 * 嵌在 chunkDataB64 数组里，轮换无法触达。本函数在 meta 明文重封装前
 * 扫描其中可由旧 MDEK 认证的 base64 分片，逐个换成新 MDEK/新 epoch 密文；
 * 其他 base64（缩略图、v2 口令分片、密钥材料）认证失败后原样保留。
 * 仅命中至少一个分片时分配输出（*rewrapped=1），否则 out 保持 NULL。
 *
 * old_epoch/new_epoch 分离：模块启用时二者相同；全库轮换时源库与新库
 * 的 epoch 不同，内层信封必须按各自的 epoch 解封/重封。
 */
int vty_chunk_rewrap_embedded(const uint8_t old_mdek[VTY_KEY_BYTES],
                              const uint8_t new_mdek[VTY_KEY_BYTES],
                              uint64_t old_epoch,
                              uint64_t new_epoch,
                              const uint8_t *json, size_t json_len,
                              uint8_t **out, size_t *out_len,
                              int *rewrapped);

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

#endif /* VTY_CHUNK_H */
