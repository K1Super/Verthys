/*
 * vty_store.h — 追加数据区、COW 目录树与 DataRoot（内部，不导出）
 *
 * 独立于旧索引实现：旧 LSM 的分区/extent/内容哈希语义与本实现的
 * “追加段 + 加密目录 + 键控标识”不兼容；复用会把旧的寻址假设
 * 带进新实现，破坏去重与完整性边界。
 */
#ifndef VTY_STORE_H
#define VTY_STORE_H

#include "vty_types.h"
#include "vty_format.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 单节点目标大小：超过即分裂；节点载荷整体 AEAD 加密。 */
#define VTY_STORE_NODE_BYTES 4096u
#define VTY_STORE_ENTRY_MAX  (VTY_STORE_NODE_BYTES / 4u)
#define VTY_STORE_KEY_MAX    64u
#define VTY_STORE_VAL_MAX    (VTY_STORE_NODE_BYTES - 128u)
#define VTY_STORE_MAX_LEVEL  8u

/* 删除不重排 B+tree：写一个 1 字节墓碑值，由业务层解释。
 * 空值（0 字节）是合法的“存在性条目”，与墓碑必须可区分。 */
#define VTY_STORE_TOMBSTONE_BYTE 0x01u

typedef struct VtyStore VtyStore;

/* 追加段定位符：hash 覆盖段头与 payload，防止段被搬移/替换后仍被引用。 */
typedef struct {
    uint8_t  type;
    uint64_t seq;
    uint64_t id;
    uint64_t offset;
    uint32_t total_len;
    uint8_t  hash[VTY_HASH_BYTES];
} VtySegmentLocator;

/* 会话内一致点：写失败时恢复根指针即可丢弃未提交节点（COW 不覆盖旧节点）。 */
typedef struct {
    VtyDataRootLocator loc;
    uint8_t hash[VTY_HASH_BYTES];
} VtyStoreCheckpoint;

/* 空树根与最终 DataRoot 的规范计算；创建库与打开库都必须用同一实现，
 * 否则“空库”在两侧会得到不同的根摘要。 */
int vty_store_empty_root(const uint8_t vault_uuid[VTY_UUID_BYTES], uint64_t epoch,
                         uint8_t out[VTY_HASH_BYTES]);
int vty_store_data_root(const uint8_t vault_uuid[VTY_UUID_BYTES], uint64_t epoch,
                        const uint8_t root_hash[VTY_HASH_BYTES],
                        uint8_t out[VTY_HASH_BYTES]);

/* 打开既有数据区：校验 locator 边界、data_end 与根节点；
 * 失败即 VTY_E_CORRUPT，不接受“先打开再修复”。 */
int vty_store_open(const char *path,
                   const uint8_t kc[VTY_KEY_BYTES],
                   const uint8_t vault_uuid[VTY_UUID_BYTES],
                   uint64_t epoch,
                   const VtyDataRootLocator *loc,
                   const uint8_t data_root_hash[VTY_HASH_BYTES],
                   VtyStore **out);

/* 空库 locator：root_node_id=0、data_end=数据区起点；
 * 根摘要由 vty_store_empty_root 给出，创建路径不得自行拼摘要。 */
int vty_store_empty_locator(const uint8_t vault_uuid[VTY_UUID_BYTES], uint64_t epoch,
                            VtyDataRootLocator *out,
                            uint8_t root_hash[VTY_HASH_BYTES]);

void vty_store_close(VtyStore *s);

/* put/get 的 key 只含业务键（调用方给出 keyspace）；内部编码加入
 * keyspace 前缀，使跨空间键在字节层不可互换。空值表示删除。 */
int vty_store_put(VtyStore *s, uint8_t keyspace,
                  const uint8_t *key, size_t key_len,
                  const uint8_t *value, size_t value_len);

/* 空值（value_len==0）是合法条目：返回 VTY_OK 且 value=NULL/len=0。
 * 键不存在返回 VTY_E_INVALID；调用方不得把“不存在”与“空值”混为一谈。 */
int vty_store_get(VtyStore *s, uint8_t keyspace,
                  const uint8_t *key, size_t key_len,
                  uint8_t **value, size_t *value_len);

/* 追加段只写数据区、不改目录；调用方取得 locator 后必须用 DataRoot
 * 提交使其可达。type 仅接受 RECORD/CHUNK，目录段由内部写入。 */
int vty_store_append_segment(VtyStore *s, uint8_t type, uint64_t seq, uint64_t id,
                             const uint8_t *payload, size_t payload_len,
                             VtySegmentLocator *out);

/* 读取并校验段头字段与 BLAKE3(段头+payload)；失败返回 E_CORRUPT，绝不
 * 返回未经完整性校验的 payload。 */
int vty_store_read_segment(VtyStore *s, const VtySegmentLocator *loc,
                           uint8_t **payload, size_t *payload_len);

/* 写墓碑值（1 字节）；键不存在时也写入，删除语义幂等。 */
int vty_store_delete(VtyStore *s, uint8_t keyspace,
                     const uint8_t *key, size_t key_len);

/* keyspace 内全部键计数（含空值条目与墓碑，业务层自行过滤）。 */
int vty_store_count(VtyStore *s, uint8_t keyspace, uint64_t *out_count);

/* 空树判定（尚未提交任何目录节点）。 */
int vty_store_is_empty(VtyStore *s);

int vty_store_checkpoint(VtyStore *s, VtyStoreCheckpoint *out);
int vty_store_restore(VtyStore *s, const VtyStoreCheckpoint *cp);

/* 升序游标：打开时固定根节点，遍历期间新写入不改变已返回结果（COW）。
 * start_key 可为 NULL；返回的 key 不含 keyspace 前缀。 */
typedef struct VtyStoreCursor VtyStoreCursor;

int vty_store_cursor_open(VtyStore *s, uint8_t keyspace,
                          const uint8_t *start_key, size_t start_key_len,
                          VtyStoreCursor **out);
/* 取下一项。done=1 表示该 keyspace 已耗尽（本调用不返回条目）。 */
int vty_store_cursor_next(VtyStoreCursor *c, int *done,
                          uint8_t **key, size_t *key_len,
                          uint8_t **value, size_t *value_len);
void vty_store_cursor_close(VtyStoreCursor *c);

/* 返回新的 DataRoot locator 与根摘要；调用方必须在同一次元数据提交里
 * 写入 Keyring，不能先提交 locator 再补数据。 */
int vty_store_commit(VtyStore *s, VtyDataRootLocator *out,
                     uint8_t data_root_hash[VTY_HASH_BYTES]);

/* 落盘自查（flush 后调用）：校验文件大小覆盖 DataRoot、根段哈希与
 * DataRoot 摘要一致，并读取根节点 AEAD。不做全树遍历，供每次持久化
 * 后快速确认“元数据指向的根确实在盘上”。 */
int vty_store_verify_data_root(VtyStore *s,
                               const VtyDataRootLocator *loc,
                               const uint8_t data_root_hash[VTY_HASH_BYTES],
                               uint64_t *out_file_size,
                               uint64_t *out_mtime_ms);

/* 遍历全部节点与引用段，校验 hash/AEAD/偏移与 data_end。 */
int vty_store_verify(VtyStore *s);

#ifdef __cplusplus
}
#endif

#endif /* VTY_STORE_H */
