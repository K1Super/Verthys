/*
 * vty_store_internal.h — 追加数据区与 COW 目录树跨文件内部契约（不导出）
 *
 * 目录节点整体 AEAD 加密，节点之间以 id/hash 引用；数据区只追加，
 * 旧节点不被覆盖。以下类型与 IO/节点原语由各实现文件共享。
 */
#ifndef VTY_STORE_INTERNAL_H
#define VTY_STORE_INTERNAL_H

#include "vty_store.h"
#include "vty_kdf.h"
#include "vty_util.h"
#include "vty_blake3.h"

#include <windows.h>
#include <string.h>
#include <stdlib.h>

#define VTY_NODE_VERSION 1u
#define VTY_NODE_LEAF    1u
#define VTY_NODE_INTERNAL 2u
#define VTY_NODE_HDR_BYTES 16u
#define VTY_STORE_PATH_MAX 1024u

typedef struct {
    uint16_t key_len;
    uint8_t  key[VTY_STORE_KEY_MAX];
    uint32_t val_len;
    uint8_t *val;
    uint64_t child_id;
    uint8_t  child_hash[VTY_HASH_BYTES];
} VtyMemEntry;

typedef struct {
    uint8_t level;
    uint8_t type;
    uint16_t n;
    /* 从段头解析出的实际总长（含段头）；不参与节点序列化。 */
    uint32_t total_len;
    VtyMemEntry e[VTY_STORE_ENTRY_MAX];
} VtyMemNode;

typedef struct {
    uint64_t id;
    uint8_t  hash[VTY_HASH_BYTES];
    uint8_t  max_key[VTY_STORE_KEY_MAX];
    uint16_t max_len;
    uint8_t  level;
    /* 新节点在数据区占用的实际总长；DataRoot 的 root_len 必须用它，
     * 不能用 data_end-id 推算（空闲区复用后节点不再位于数据区末尾）。 */
    uint32_t total_len;
} VtyNodeRef;

typedef struct {
    int split;
    VtyNodeRef left;
    VtyNodeRef right;
} VtySplit;

/* 数据区区间状态：LIVE 被当前目录树或活段引用，FREE 可被后续写入复用。
 * 区间表覆盖 [VTY_DATA_OFFSET, data_end)，按偏移升序且互不重叠。 */
#define VTY_SPACE_LIVE 0u
#define VTY_SPACE_FREE 1u
/* 小于该值的剩余空间不再切分，整段分配给请求方，避免产生不可用碎片。 */
#define VTY_SPACE_SPLIT_MIN 64u
/* 退役表上限：大批量事务超过后放弃本次精确回收，解锁期重建兜底。 */
#define VTY_SPACE_RETIRED_MAX (1u << 20)

typedef struct {
    uint64_t off;
    uint64_t len;
    uint8_t  state;
} VtySpaceRange;

typedef struct {
    uint64_t off;
    uint64_t len;
} VtySpaceExtent;

struct VtyStore {
    char path[VTY_STORE_PATH_MAX];
    HANDLE h;
    uint8_t kdir[VTY_KEY_BYTES];
    uint8_t vault_uuid[VTY_UUID_BYTES];
    uint64_t epoch;
    VtyDataRootLocator loc;
    uint8_t root_hash[VTY_HASH_BYTES];
    int dirty;

    /* 空闲区表：只在内存中存在，解锁期从 DataRoot 重建。 */
    VtySpaceRange *ranges;
    size_t range_n;
    size_t range_cap;
    uint64_t free_bytes;
    /* 本次未提交事务退役的区间；提交后才并入空闲区。 */
    VtySpaceExtent *retired;
    size_t retired_n;
    size_t retired_cap;
    /* 已提交但仍有游标可能读取的区间，全部游标关闭后释放。 */
    VtySpaceExtent *deferred;
    size_t deferred_n;
    size_t deferred_cap;
    uint32_t reader_n;
    /* 0 = 复用关闭（写入只追加）；1 = 区间表可信。 */
    int space_ready;
    /* 退役表超限：本事务放弃精确回收，解锁期重建兜底。 */
    int space_overflow;
};

int vty_st_file_size_of(HANDLE h, uint64_t *out);
int vty_st_read_at(HANDLE h, uint64_t off, uint8_t *buf, size_t len);
int vty_st_write_at(HANDLE h, uint64_t off, const uint8_t *buf, size_t len);

/* ------------------------------------------------------------------ *
 * 空闲区管理（vty_store_space.c）
 *
 * 崩溃一致性由「DataRoot 是唯一事实源」保证：区间表不落盘，任何不在
 * 当前根可达范围内的字节在解锁重建时都会被标成 FREE。
 * ------------------------------------------------------------------ */

/* 分配 len 字节：优先复用最低偏移的空闲区，无可用区时追加到 data_end。
 * space_ready=0 时只追加，行为与旧追加模型一致。 */
int vty_store_space_alloc(VtyStore *s, uint64_t len, uint64_t *out_off);

/* 登记一个将在本次事务提交后变为空闲的区间。区间在提交前保持 LIVE，
 * 防止事务内的后续写入复用仍被旧根引用的数据。 */
void vty_store_space_retire(VtyStore *s, uint64_t off, uint64_t len);

/* 提交：退役区间并入空闲区（有游标时转入 deferred），压低尾部 data_end。 */
int vty_store_space_commit(VtyStore *s);

/* 回退：丢弃未提交的退役登记；尾部状态不确定时关闭复用，绝不带着
 * 未知状态继续分配。 */
void vty_store_space_restore(VtyStore *s, const VtyStoreCheckpoint *cp);

/* 游标打开/关闭时维护读者计数：有读者时退役区间不得复用。 */
void vty_store_space_reader_enter(VtyStore *s);
void vty_store_space_reader_leave(VtyStore *s);

/* 解锁期重建：begin 清空并关闭复用；reserve 登记活区间；finish 把
 * 剩余空洞标为 FREE、合并并启用复用。 */
int vty_store_space_begin(VtyStore *s);
int vty_store_space_reserve(VtyStore *s, uint64_t off, uint64_t len);
int vty_store_space_finish(VtyStore *s);
void vty_store_space_disable(VtyStore *s);

/* 遍历当前 DataRoot 可达节点，登记其区间（重建第一步）。 */
int vty_store_space_scan_nodes(VtyStore *s);

/* 物理截断 [durable_end, file_size)：durable_end 必须取自已落盘的
 * DataRoot，截断后文件不得短于元数据声明的高水位。 */
int vty_store_trim_tail(VtyStore *s, uint64_t durable_end);

void vty_st_node_free(VtyMemNode *n);
int vty_st_node_plain_size(const VtyMemNode *n, size_t *out);
int vty_st_key_cmp(const uint8_t *a, size_t alen,
                   const uint8_t *b, size_t blen);
int vty_st_node_write(VtyStore *s, const VtyMemNode *n, VtyNodeRef *ref);
int vty_st_node_read(VtyStore *s, uint64_t id, uint8_t expected_level,
                     VtyMemNode *out, uint8_t hash_out[VTY_HASH_BYTES]);

#endif /* VTY_STORE_INTERNAL_H */
