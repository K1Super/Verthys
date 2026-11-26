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
    VtyMemEntry e[VTY_STORE_ENTRY_MAX];
} VtyMemNode;

typedef struct {
    uint64_t id;
    uint8_t  hash[VTY_HASH_BYTES];
    uint8_t  max_key[VTY_STORE_KEY_MAX];
    uint16_t max_len;
    uint8_t  level;
} VtyNodeRef;

typedef struct {
    int split;
    VtyNodeRef left;
    VtyNodeRef right;
} VtySplit;

struct VtyStore {
    char path[VTY_STORE_PATH_MAX];
    HANDLE h;
    uint8_t kdir[VTY_KEY_BYTES];
    uint8_t vault_uuid[VTY_UUID_BYTES];
    uint64_t epoch;
    VtyDataRootLocator loc;
    uint8_t root_hash[VTY_HASH_BYTES];
    int dirty;
};

int vty_st_file_size_of(HANDLE h, uint64_t *out);
int vty_st_read_at(HANDLE h, uint64_t off, uint8_t *buf, size_t len);
int vty_st_write_at(HANDLE h, uint64_t off, const uint8_t *buf, size_t len);

void vty_st_node_free(VtyMemNode *n);
int vty_st_node_plain_size(const VtyMemNode *n, size_t *out);
int vty_st_key_cmp(const uint8_t *a, size_t alen,
                   const uint8_t *b, size_t blen);
int vty_st_node_write(VtyStore *s, const VtyMemNode *n, VtyNodeRef *ref);
int vty_st_node_read(VtyStore *s, uint64_t id, uint8_t expected_level,
                     VtyMemNode *out, uint8_t hash_out[VTY_HASH_BYTES]);

#endif /* VTY_STORE_INTERNAL_H */
