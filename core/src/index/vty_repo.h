/*
 * vty_repo.h — 记录仓库（内部，不导出）
 *
 * 仓库把“记录段 + 加密目录叶 + 名称/类型盲索引 + ID 分配器”收口在
 * 一个模块内：任何写操作都必须同一次提交更新 DataRoot，否则目录与
 * 记录段会分叉，Get 将返回无法解释的 CORRUPT。
 */
#ifndef VTY_REPO_H
#define VTY_REPO_H

#include "vty_types.h"
#include "vty_keymanager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_REPO_LEAF_BYTES     148u
#define VTY_REPO_FLAG_TOMBSTONE 0x01u
#define VTY_REPO_FLAG_FILE      0x02u
#define VTY_REPO_FLAG_KNOWN     (VTY_REPO_FLAG_TOMBSTONE | VTY_REPO_FLAG_FILE)

/* 文件/分片叶：清单不单独存 blob，由 (4,file_uuid) 范围扫描重建；
 * 这里只提供仓库 API，不暴露公共文件命令。 */
#define VTY_REPO_FILE_BYTES  44u   /* pt_hash(32) | total(4) | created(8) */
#define VTY_REPO_CHUNK_BYTES 76u   /* chunk_id(32) | offset(8) | len(4) | hash(32) */

/* 目录叶（解密后）：只含定位与盲索引，不含名称/数据明文。 */
typedef struct {
    uint8_t  flags;
    uint64_t record_id;
    uint8_t  module_uuid[VTY_UUID_BYTES];
    uint8_t  name_index[VTY_HASH_BYTES];
    uint8_t  type_token[VTY_HASH_BYTES];
    uint64_t created_time;
    uint64_t data_offset;
    uint32_t data_len;
    uint32_t plain_size;
    uint8_t  data_hash[VTY_HASH_BYTES];
} VtyRepoLeaf;

typedef struct {
    uint64_t id;
    uint8_t  type;
    uint8_t *name;
    size_t   name_len;
    uint8_t *data;
    size_t   data_len;
} VtyRepoRecord;

typedef struct {
    uint8_t        type;
    const uint8_t *name;
    size_t         name_len;
    const uint8_t *data;
    size_t         data_len;
} VtyRepoInput;

/* 创建库时写入初始分配器（next_id=1）。模块表使新库目录非空，
 * 不能再靠“空树”推断首次写入；必须先建立分配器。只写数据区。 */
int vty_repo_init_allocator(VtyVault *v);

/* ID 分配器水位读取/写入（轮换保真：新库不得复用源库已分配过的 ID）。 */
int vty_repo_next_id(VtyVault *v, uint64_t *out);
int vty_repo_set_next_id(VtyVault *v, uint64_t next);

/* 新增：分配 ID → 追加记录段 → 写记录叶/名称/类型索引/分配器 →
 * store 提交 → 更新 Keyring DataRoot → 保存元数据。 */
__declspec(noinline) int vty_repo_add(VtyVault *v, uint8_t type,
                 const uint8_t *name, size_t name_len,
                 const uint8_t *data, size_t data_len,
                 uint64_t *out_id);

/* 批量新增：全部记录只提交一次；任一条失败整体恢复到调用前的根。 */
int vty_repo_add_many(VtyVault *v, const VtyRepoInput *in, size_t count,
                      uint64_t *out_ids);

/* 轮换：按指定 ID 与创建时间新增（全库轮换保真复制）。forced_id 必须
 * 不小于当前分配器（避免 ID 回退）；created_time 原样写入叶子。 */
int vty_repo_add_ex(VtyVault *v, uint8_t type,
                    const uint8_t *name, size_t name_len,
                    const uint8_t *data, size_t data_len,
                    uint64_t forced_id, uint64_t created_time,
                    uint64_t *out_id);

/* 读取：不存在/墓碑返回 VTY_E_INVALID（API 层映射 NOTFOUND）。 */
int vty_repo_get(VtyVault *v, uint64_t id, VtyRepoRecord *out);

/* 读取已定位叶（扫描路径复用，避免重复查找目录）。 */
__declspec(noinline) int vty_repo_read(VtyVault *v, const VtyRepoLeaf *leaf,
                                       VtyRepoRecord *out);
int vty_repo_read_name(VtyVault *v, const VtyRepoLeaf *leaf,
                       uint8_t **name, size_t *name_len);

int vty_repo_delete(VtyVault *v, uint64_t id);
int vty_repo_delete_many(VtyVault *v, const uint64_t *ids, size_t count);

/* 存活记录数（跳过分配器与墓碑）。 */
int vty_repo_count(VtyVault *v, uint64_t *out_count);

/* 类型存在性：走类型盲索引，不解析记录段。 */
int vty_repo_find_by_type(VtyVault *v, uint8_t type,
                          uint8_t *out_found, uint64_t *out_id);

/* 单页类型枚举上限：调用方一次最多取 4096 个 ID（32 KiB），
 * 分页由 after_id 推进，避免无界响应。 */
#define VTY_REPO_TYPE_ID_BATCH_MAX 4096u

/* 按类型分页枚举记录 ID（升序，走 VTY_KS_TYPE 盲索引）：
 *   - after_id=0 表示从首条开始；后续传上一页最后一个 ID；
 *   - 跳过墓碑；out_exhausted=1 表示该类型已无更多记录；
 *   - 不读取记录段，不依赖摘要扫描的 type 字段。 */
int vty_repo_list_ids_by_type(VtyVault *v, uint8_t type,
                              uint64_t after_id, uint64_t max_count,
                              uint64_t *out_ids, uint64_t *out_count,
                              uint8_t *out_exhausted);

typedef struct {
    uint8_t  pt_hash[VTY_HASH_BYTES];
    uint32_t total;           /* 分片总数（chunk count） */
    uint64_t created_time;
} VtyRepoFile;

typedef struct {
    uint32_t seq;
    uint8_t  chunk_id[VTY_HASH_BYTES];
    uint64_t offset;          /* 分片段起点（含 32B 段头） */
    uint32_t len;             /* 分片段总长 */
    uint8_t  hash[VTY_HASH_BYTES];
} VtyRepoChunkEntry;

int vty_repo_file_put(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                      const uint8_t pt_hash[VTY_HASH_BYTES], uint32_t total);
/* 轮换：保留原创建时间写入文件叶。 */
int vty_repo_file_put_ex(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                         const uint8_t pt_hash[VTY_HASH_BYTES], uint32_t total,
                         uint64_t created_time);
int vty_repo_file_get(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                      VtyRepoFile *out);

/* 遍历 VTY_KS_FILE（跳过墓碑）。visitor 可空，仅计数；visitor 返回
 * 非 VTY_OK 时中止并回传该错误。out_count 可空。 */
typedef int (*VtyRepoFileVisitor)(void *user,
                                  const uint8_t file_uuid[VTY_UUID_BYTES],
                                  const VtyRepoFile *file);
int vty_repo_file_list(VtyVault *v, VtyRepoFileVisitor visitor, void *user,
                       uint64_t *out_count);

/* 轮换专用：不依赖 file 模块密钥，统计存活文件叶（墓碑跳过）。
 * 用于 fileverthys 模块已删除、键空间只剩墓碑的源库；若存在存活文件叶，
 * 说明模块删除未清空键空间，调用方按 CORRUPT 处理。 */
int vty_repo_file_count_live(VtyVault *v, uint64_t *out_count);

/* 单分片加密（首个 MDEK + 当前 epoch）→ 追加 CHUNK 段 → 写分片叶。 */
int vty_repo_chunk_add(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                       uint32_t seq, const uint8_t *pt, size_t pt_len);
int vty_repo_chunk_get(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                       uint32_t seq, uint8_t **pt, size_t *pt_len);

/* 按 (4,file_uuid) 范围扫描重建清单；out 由 vty_free 释放，seq 必须
 * 覆盖 [0,total) 且无空洞。 */
int vty_repo_file_manifest(VtyVault *v, const uint8_t file_uuid[VTY_UUID_BYTES],
                           VtyRepoChunkEntry **out, uint32_t *out_count);

/* 模块启用专用：用新 MDEK 重写该模块的记录叶/名称/类型索引；index=2 时
 * 同时重写全部文件分片叶与分片段。只写数据区，不提交元数据；失败时
 * 调用方必须恢复 store checkpoint。old_mdek 必须与当前记录一致。 */
int vty_repo_module_rekey(VtyVault *v, uint32_t index,
                          const uint8_t old_mdek[VTY_KEY_BYTES],
                          const uint8_t new_mdek[VTY_KEY_BYTES]);

/* 全库轮换专用：把单条内容记录的内层分片信封从旧 MDEK/旧 epoch 换封到
 * 新 MDEK/新 epoch。仅对非系统记录、且模块为 photo(0)/fileverthys(2) 生效；
 * 普通明文载荷认证失败时保持 *rewrapped=0 且不分配输出。
 * 调用方必须对 *rewrapped=1 的结果做 vty_repo_content_envelope_check 自检。 */
int vty_repo_rewrap_content(uint8_t type, int module_index,
                            const uint8_t old_mdek[VTY_KEY_BYTES],
                            uint64_t old_epoch,
                            const uint8_t new_mdek[VTY_KEY_BYTES],
                            uint64_t new_epoch,
                            const uint8_t *in, size_t in_len,
                            uint8_t **out, size_t *out_len,
                            int *rewrapped);

/* 内容信封自检：按给定 MDEK/epoch 解封并校验结构。
 * *openable=1 表示可解封；结构不符/认证失败时为 0；资源/内部错误返回
 * 对应错误码（不得当作“不可解封”静默吞掉）。 */
int vty_repo_content_envelope_check(const uint8_t mdek[VTY_KEY_BYTES],
                                    uint64_t epoch,
                                    const uint8_t *in, size_t in_len,
                                    int *openable);

/* 估算模块重写需要追加的字节数（含叶与索引开销，不含 10% 余量）。 */
int vty_repo_module_rekey_bytes(VtyVault *v, uint32_t index, uint64_t *out);

/* 模块删除：把该模块的记录叶/名称/类型索引写成墓碑；index=2 时同时
 * 清空全部文件叶与分片叶。只写数据区，不提交元数据；失败时调用方
 * 必须恢复 store checkpoint。 */
int vty_repo_module_purge(VtyVault *v, uint32_t index,
                          const uint8_t module_uuid[VTY_UUID_BYTES],
                          uint64_t *out_records,
                          uint64_t *out_files,
                          uint64_t *out_chunks);

/* 记录叶迭代器：打开时固定 store 根（COW 快照）。start_id 用于
 * 跳过已消费前缀；返回的叶不包含已删除记录。 */
typedef struct VtyRepoIter VtyRepoIter;

int vty_repo_iter_open(VtyVault *v, uint64_t start_id, VtyRepoIter **out);
int vty_repo_iter_next(VtyRepoIter *it, VtyRepoLeaf *leaf, int *done);
void vty_repo_iter_close(VtyRepoIter *it);

#ifdef __cplusplus
}
#endif

#endif /* VTY_REPO_H */
