/*
 * vty_repo_internal.h — 记录仓库跨文件内部契约（不导出）
 *
 * 写入顺序固定为：分配器/记录段/叶/索引 -> store_commit -> Keyring
 * DataRoot -> 元数据保存。目录叶只含定位与盲索引，记录段载荷单独
 * 加密；两部分必须在同一次提交中更新，否则目录与记录段分叉。
 */
#ifndef VTY_REPO_INTERNAL_H
#define VTY_REPO_INTERNAL_H

#include "vty_repo.h"
#include "vty_store.h"
#include "vty_record.h"
#include "vty_chunk.h"
#include "vty_module.h"
#include "vty_util.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    uint64_t record_id;
    uint8_t  module_uuid[VTY_UUID_BYTES];
    uint8_t  flags;
    uint8_t  name_index[VTY_HASH_BYTES];
    uint8_t  type_token[VTY_HASH_BYTES];
    uint64_t created_time;
    uint64_t data_offset;
    uint32_t data_len;
    uint32_t plain_size;
    uint8_t  data_hash[VTY_HASH_BYTES];
} RepoLeafRaw;

/* 就绪与轮转守卫 */
int repo_ready(VtyVault *v);
int repo_write_ready(VtyVault *v);
int repo_value_is_tombstone(size_t vlen, const uint8_t *val);

/* 模块路由与提交 */
int repo_module_index(VtyVault *v, uint32_t index,
                      uint8_t uuid[VTY_UUID_BYTES],
                      uint8_t mdek[VTY_KEY_BYTES]);
int repo_is_system_type(uint8_t type);
int repo_module_for_type(VtyVault *v, uint8_t type,
                         uint8_t uuid[VTY_UUID_BYTES],
                         uint8_t mdek[VTY_KEY_BYTES]);
int repo_require_file_module(VtyVault *v);
int repo_require_leaf_module(VtyVault *v, const VtyRepoLeaf *leaf);
int repo_commit(VtyVault *v);

/* 字节序与键编码 */
void repo_be64(uint8_t out[8], uint64_t v);
uint64_t repo_get_be64(const uint8_t in[8]);
void repo_be32(uint8_t out[4], uint32_t v);
uint32_t repo_get_be32(const uint8_t in[4]);
void repo_record_key(uint8_t out[8], uint64_t id);
void repo_index_key(uint8_t out[VTY_HASH_BYTES + 8u],
                    const uint8_t token[VTY_HASH_BYTES], uint64_t id);

/* 目录叶编解码与分配器 */
int repo_leaf_encode(const RepoLeafRaw *r, uint8_t out[VTY_REPO_LEAF_BYTES]);
int repo_leaf_decode(const uint8_t *in, size_t in_len, VtyRepoLeaf *out);
int repo_get_leaf_raw(VtyVault *v, uint64_t id, VtyRepoLeaf *out, int *found);
int repo_get_next_id(VtyVault *v, uint64_t *out);
int repo_put_next_id(VtyVault *v, uint64_t next_id);

/* 删除与擦除 */
int repo_skip_scrub(void);
void repo_finish_scrub(VtyVault *v, const VtyRepoLeaf *leaf, int *any_cleared);
int repo_delete_one(VtyVault *v, const VtyRepoLeaf *leaf);
/* queue_scrub=0：密钥已随模块销毁，墓碑直接清定位符并回收段区间，
 * 不再入待擦队列（避免数万条无效队列项放大水位推进成本）。 */
int repo_delete_one_ex(VtyVault *v, const VtyRepoLeaf *leaf, int queue_scrub);

/* 文件叶与分片叶 */
int repo_chunk_leaf_encode(const VtyRepoChunkEntry *e,
                           uint8_t out[VTY_REPO_CHUNK_BYTES]);
int repo_chunk_leaf_decode(const uint8_t *in, size_t len,
                           VtyRepoChunkEntry *out);
void repo_chunk_key(uint8_t out[VTY_UUID_BYTES + 4u],
                    const uint8_t file_uuid[VTY_UUID_BYTES], uint32_t seq);
int repo_file_get_raw(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                      VtyRepoFile *out);

#endif /* VTY_REPO_INTERNAL_H */
