/*
 * vty_store.c — 追加数据区与 COW 目录树
 *
 * 每次写入都分配新节点（新偏移）并只让新的父节点指向它；旧节点留在
 * 数据区但不被引用。这样崩溃时只需丢弃未提交的元数据，已提交版本
 * 的节点不会被原地覆盖。
 */
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

static wchar_t *utf8_to_wide(const char *s)
{
    int n;
    wchar_t *w;

    if (s == NULL) return NULL;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (w == NULL) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

static int file_size_of(HANDLE h, uint64_t *out)
{
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0) return VTY_E_IO;
    *out = (uint64_t)size.QuadPart;
    return VTY_OK;
}

/* 位置写/读必须用 OVERLAPPED 指定偏移，而不是 SetFilePointerEx：
 * 同一 store 句柄可能被多个只读扫描/摘要并发使用，共享文件指针会让
 * “定位 + 读”交错到别的偏移。偏移写读不改变文件指针，天然可并发。 */
static int read_at(HANDLE h, uint64_t off, uint8_t *buf, size_t len)
{
    OVERLAPPED ov;
    DWORD got = 0;

    if (len > 0xFFFFFFFFu) return VTY_E_INVALID;
    memset(&ov, 0, sizeof(ov));
    ov.Offset = (DWORD)(off & 0xFFFFFFFFu);
    ov.OffsetHigh = (DWORD)(off >> 32);
    if (!ReadFile(h, buf, (DWORD)len, &got, &ov) || got != (DWORD)len) {
        return VTY_E_IO;
    }
    return VTY_OK;
}

static int write_at(HANDLE h, uint64_t off, const uint8_t *buf, size_t len)
{
    OVERLAPPED ov;
    DWORD written = 0;

    if (len > 0xFFFFFFFFu) return VTY_E_INVALID;
    memset(&ov, 0, sizeof(ov));
    ov.Offset = (DWORD)(off & 0xFFFFFFFFu);
    ov.OffsetHigh = (DWORD)(off >> 32);
    if (!WriteFile(h, buf, (DWORD)len, &written, &ov) ||
        written != (DWORD)len) {
        return VTY_E_IO;
    }
    return VTY_OK;
}

/* 空根与 DataRoot 都绑定 uuid+epoch：把一棵空树搬到另一个库/另一代，
 * 摘要必然不同，不能伪装成该库的合法根。 */
int vty_store_empty_root(const uint8_t vault_uuid[VTY_UUID_BYTES], uint64_t epoch,
                         uint8_t out[VTY_HASH_BYTES])
{
    const char *domain = VTY_DOMAIN_EMPTY_ROOT;
    size_t dlen = strlen(domain);
    uint8_t buf[128];

    if (vault_uuid == NULL || out == NULL) return VTY_E_INVALID;
    if (dlen + VTY_UUID_BYTES + 8u > sizeof(buf)) return VTY_E_INVALID;
    memcpy(buf, domain, dlen);
    memcpy(buf + dlen, vault_uuid, VTY_UUID_BYTES);
    vty_put_u64(buf + dlen + VTY_UUID_BYTES, epoch);
    if (vty_blake3_32(buf, dlen + VTY_UUID_BYTES + 8u, out) != VTY_OK) {
        return VTY_E_INVALID;
    }
    vty_secure_zero(buf, sizeof(buf));
    return VTY_OK;
}

int vty_store_data_root(const uint8_t vault_uuid[VTY_UUID_BYTES], uint64_t epoch,
                        const uint8_t root_hash[VTY_HASH_BYTES],
                        uint8_t out[VTY_HASH_BYTES])
{
    const char *domain = VTY_DOMAIN_DATA_ROOT;
    size_t dlen = strlen(domain);
    uint8_t buf[192];

    if (vault_uuid == NULL || root_hash == NULL || out == NULL) return VTY_E_INVALID;
    if (dlen + VTY_UUID_BYTES + 8u + VTY_HASH_BYTES > sizeof(buf)) return VTY_E_INVALID;
    memcpy(buf, domain, dlen);
    memcpy(buf + dlen, vault_uuid, VTY_UUID_BYTES);
    vty_put_u64(buf + dlen + VTY_UUID_BYTES, epoch);
    memcpy(buf + dlen + VTY_UUID_BYTES + 8u, root_hash, VTY_HASH_BYTES);
    if (vty_blake3_32(buf, dlen + VTY_UUID_BYTES + 8u + VTY_HASH_BYTES, out) != VTY_OK) {
        return VTY_E_INVALID;
    }
    vty_secure_zero(buf, sizeof(buf));
    return VTY_OK;
}

int vty_store_empty_locator(const uint8_t vault_uuid[VTY_UUID_BYTES], uint64_t epoch,
                            VtyDataRootLocator *out,
                            uint8_t root_hash[VTY_HASH_BYTES])
{
    if (out == NULL || root_hash == NULL) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    out->version = 1u;
    out->flags = 0u;
    out->root_node_id = 0u;
    out->root_offset = 0u;
    out->root_len = 0u;
    out->level = 0u;
    out->data_end = VTY_DATA_OFFSET;
    out->pad = 0u;
    /* kind 4 的 key 是 DataRoot，不是空根本身；空根只是 DataRoot 的输入。 */
    {
        uint8_t empty[VTY_HASH_BYTES];
        int rc = vty_store_empty_root(vault_uuid, epoch, empty);
        if (rc != VTY_OK) return rc;
        return vty_store_data_root(vault_uuid, epoch, empty, root_hash);
    }
}

static void node_free(VtyMemNode *n)
{
    uint32_t i;
    if (n == NULL) return;
    for (i = 0; i < n->n && i < VTY_STORE_ENTRY_MAX; i++) {
        if (n->e[i].val != NULL) {
            vty_secure_zero(n->e[i].val, n->e[i].val_len);
            vty_free(n->e[i].val, n->e[i].val_len);
            n->e[i].val = NULL;
        }
    }
    memset(n, 0, sizeof(*n));
}

static int node_plain_size(const VtyMemNode *n, size_t *out)
{
    size_t total = VTY_NODE_HDR_BYTES;
    uint32_t i;

    if (n == NULL || out == NULL) return VTY_E_INVALID;
    if (n->n == 0 || n->n > VTY_STORE_ENTRY_MAX) return VTY_E_INVALID;
    for (i = 0; i < n->n; i++) {
        if (n->e[i].key_len == 0 || n->e[i].key_len > VTY_STORE_KEY_MAX) {
            return VTY_E_CORRUPT;
        }
        if (n->type == VTY_NODE_LEAF) {
            total += 4u + n->e[i].key_len + n->e[i].val_len;
        } else {
            total += 2u + n->e[i].key_len + 8u + VTY_HASH_BYTES;
        }
    }
    *out = total;
    return total <= VTY_STORE_NODE_BYTES ? VTY_OK : VTY_E_RESOURCE;
}

static int node_serialize(const VtyMemNode *n, uint8_t *buf, size_t cap, size_t *out_len)
{
    size_t need;
    size_t off = 0;
    uint32_t i;
    int rc;

    rc = node_plain_size(n, &need);
    if (rc != VTY_OK) return rc;
    if (need > cap) return VTY_E_INVALID;

    buf[off++] = VTY_NODE_VERSION;
    buf[off++] = n->level;
    buf[off++] = n->type;
    buf[off++] = 0;
    vty_put_u16(buf + off, n->n); off += 2;
    vty_put_u16(buf + off, 0); off += 2;
    vty_put_u64(buf + off, 0); off += 8;

    for (i = 0; i < n->n; i++) {
        const VtyMemEntry *e = &n->e[i];
        vty_put_u16(buf + off, e->key_len); off += 2;
        if (n->type == VTY_NODE_LEAF) {
            vty_put_u16(buf + off, (uint16_t)e->val_len); off += 2;
            memcpy(buf + off, e->key, e->key_len); off += e->key_len;
            if (e->val_len != 0) {
                memcpy(buf + off, e->val, e->val_len);
                off += e->val_len;
            }
        } else {
            vty_put_u64(buf + off, e->child_id); off += 8;
            memcpy(buf + off, e->child_hash, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
            memcpy(buf + off, e->key, e->key_len); off += e->key_len;
        }
    }
    if (off != need) return VTY_E_CORRUPT;
    *out_len = off;
    return VTY_OK;
}

static int key_cmp(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
    size_t n = alen < blen ? alen : blen;
    int c = n != 0 ? memcmp(a, b, n) : 0;
    if (c != 0) return c;
    if (alen < blen) return -1;
    if (alen > blen) return 1;
    return 0;
}

static int node_parse(const uint8_t *buf, size_t len, uint8_t expected_level,
                      VtyMemNode *out)
{
    VtyMemNode n;
    size_t off = 0;
    uint16_t count;
    uint32_t i;

    if (buf == NULL || out == NULL) return VTY_E_INVALID;
    if (len < VTY_NODE_HDR_BYTES) return VTY_E_CORRUPT;
    memset(&n, 0, sizeof(n));
    if (buf[off++] != VTY_NODE_VERSION) return VTY_E_CORRUPT;
    n.level = buf[off++];
    n.type = buf[off++];
    if (buf[off++] != 0) return VTY_E_CORRUPT;
    count = vty_get_u16(buf + off); off += 2;
    if (vty_get_u16(buf + off) != 0) return VTY_E_CORRUPT;
    off += 2;
    if (vty_get_u64(buf + off) != 0) return VTY_E_CORRUPT;
    off += 8;

    if (n.level != expected_level) return VTY_E_CORRUPT;
    if (n.type != VTY_NODE_LEAF && n.type != VTY_NODE_INTERNAL) return VTY_E_CORRUPT;
    if (count == 0 || count > VTY_STORE_ENTRY_MAX) return VTY_E_CORRUPT;
    n.n = count;

    for (i = 0; i < count; i++) {
        VtyMemEntry *e = &n.e[i];
        uint16_t klen;
        if (off + 2 > len) goto corrupt;
        klen = vty_get_u16(buf + off); off += 2;
        if (klen == 0 || klen > VTY_STORE_KEY_MAX) goto corrupt;
        e->key_len = klen;

        if (n.type == VTY_NODE_LEAF) {
            uint16_t vlen;
            if (off + 2 > len) goto corrupt;
            vlen = vty_get_u16(buf + off); off += 2;
            if (off + klen + vlen > len) goto corrupt;
            memcpy(e->key, buf + off, klen); off += klen;
            e->val_len = vlen;
            if (vlen != 0) {
                e->val = (uint8_t *)vty_alloc(vlen);
                if (e->val == NULL) goto corrupt;
                memcpy(e->val, buf + off, vlen);
            }
            off += vlen;
        } else {
            if (off + 8 + VTY_HASH_BYTES + klen > len) goto corrupt;
            e->child_id = vty_get_u64(buf + off); off += 8;
            memcpy(e->child_hash, buf + off, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
            memcpy(e->key, buf + off, klen); off += klen;
        }

        if (i > 0 && key_cmp(n.e[i - 1].key, n.e[i - 1].key_len,
                              e->key, e->key_len) >= 0) {
            goto corrupt;
        }
    }
    if (off != len) goto corrupt;
    *out = n;
    return VTY_OK;

corrupt:
    node_free(&n);
    return VTY_E_CORRUPT;
}

static void dir_aad(uint64_t node_id, uint8_t level, uint32_t payload_len,
                    uint8_t out[128], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_DIR;
    size_t dlen = strlen(domain);
    size_t off = dlen;

    memcpy(out, domain, dlen);
    /* 数据区结构统一大端，避免跨平台解析差异。 */
    out[off++] = (uint8_t)(node_id >> 56);
    out[off++] = (uint8_t)(node_id >> 48);
    out[off++] = (uint8_t)(node_id >> 40);
    out[off++] = (uint8_t)(node_id >> 32);
    out[off++] = (uint8_t)(node_id >> 24);
    out[off++] = (uint8_t)(node_id >> 16);
    out[off++] = (uint8_t)(node_id >> 8);
    out[off++] = (uint8_t)node_id;
    out[off++] = level;
    out[off++] = (uint8_t)(payload_len >> 24);
    out[off++] = (uint8_t)(payload_len >> 16);
    out[off++] = (uint8_t)(payload_len >> 8);
    out[off++] = (uint8_t)payload_len;
    *out_len = off;
}

static int node_write(VtyStore *s, const VtyMemNode *n, VtyNodeRef *ref)
{
    uint8_t plain[VTY_STORE_NODE_BYTES];
    uint8_t aad[128];
    uint8_t *seg;
    uint8_t hash[VTY_HASH_BYTES];
    size_t plain_len = 0;
    size_t aad_len = 0;
    size_t ct_len = 0;
    size_t payload_len;
    size_t total;
    uint64_t id;
    VtySegmentHeader sh;
    int rc;

    if (s == NULL || n == NULL || ref == NULL) return VTY_E_INVALID;
    rc = node_serialize(n, plain, sizeof(plain), &plain_len);
    if (rc != VTY_OK) return rc;

    ct_len = plain_len + VTY_TAG_BYTES;
    payload_len = VTY_NONCE_BYTES + ct_len;
    total = VTY_SEG_HEADER_BYTES + payload_len;
    id = s->loc.data_end;

    seg = (uint8_t *)vty_alloc(total);
    if (seg == NULL) {
        vty_secure_zero(plain, sizeof(plain));
        return VTY_E_RESOURCE;
    }

    memset(&sh, 0, sizeof(sh));
    sh.type = VTY_SEG_DIR;
    sh.flags = 0;
    sh.payload_len = (uint32_t)payload_len;
    sh.seq = id;
    sh.id = n->level;
    rc = vty_segment_header_write(&sh, seg);
    if (rc != VTY_OK) goto out;

    vty_random(seg + VTY_SEG_HEADER_BYTES, VTY_NONCE_BYTES);
    dir_aad(id, n->level, (uint32_t)payload_len, aad, &aad_len);
    rc = vty_aead_seal(s->kdir, seg + VTY_SEG_HEADER_BYTES, aad, aad_len,
                       plain, plain_len,
                       seg + VTY_SEG_HEADER_BYTES + VTY_NONCE_BYTES,
                       total - VTY_SEG_HEADER_BYTES - VTY_NONCE_BYTES, &ct_len);
    if (rc != VTY_OK) goto out;
    if (ct_len != plain_len + VTY_TAG_BYTES) { rc = VTY_E_CORRUPT; goto out; }

    rc = vty_blake3_32(seg, total, hash);
    if (rc != VTY_OK) goto out;
    rc = write_at(s->h, id, seg, total);
    if (rc != VTY_OK) goto out;

    s->loc.data_end = id + total;
    s->dirty = 1;

    memset(ref, 0, sizeof(*ref));
    ref->id = id;
    ref->level = n->level;
    memcpy(ref->hash, hash, VTY_HASH_BYTES);
    memcpy(ref->max_key, n->e[n->n - 1].key, n->e[n->n - 1].key_len);
    ref->max_len = n->e[n->n - 1].key_len;

out:
    vty_secure_zero(plain, sizeof(plain));
    vty_secure_zero(aad, sizeof(aad));
    vty_free(seg, total);
    return rc;
}

static int node_read(VtyStore *s, uint64_t id, uint8_t expected_level,
                     VtyMemNode *out, uint8_t hash_out[VTY_HASH_BYTES])
{
    uint8_t shbuf[VTY_SEG_HEADER_BYTES];
    VtySegmentHeader sh;
    uint8_t *seg = NULL;
    uint8_t plain[VTY_STORE_NODE_BYTES];
    uint8_t aad[128];
    uint8_t hash[VTY_HASH_BYTES];
    size_t aad_len = 0;
    size_t plain_len = 0;
    size_t total;
    int rc;

    if (s == NULL || out == NULL) return VTY_E_INVALID;
    if (id < VTY_DATA_OFFSET || id >= s->loc.data_end) return VTY_E_CORRUPT;
    if (s->loc.data_end - id < VTY_SEG_HEADER_BYTES) return VTY_E_CORRUPT;

    rc = read_at(s->h, id, shbuf, sizeof(shbuf));
    if (rc != VTY_OK) return VTY_E_IO;
    rc = vty_segment_header_parse(shbuf, &sh);
    if (rc != VTY_OK) return rc;
    if (sh.type != VTY_SEG_DIR) return VTY_E_CORRUPT;
    if (sh.seq != id || sh.id != expected_level) return VTY_E_CORRUPT;
    total = VTY_SEG_HEADER_BYTES + (size_t)sh.payload_len;
    if (total > s->loc.data_end - id) return VTY_E_CORRUPT;

    seg = (uint8_t *)vty_alloc(total);
    if (seg == NULL) return VTY_E_RESOURCE;
    rc = read_at(s->h, id, seg, total);
    if (rc != VTY_OK) goto out;
    rc = vty_blake3_32(seg, total, hash);
    if (rc != VTY_OK) goto out;

    dir_aad(id, expected_level, sh.payload_len, aad, &aad_len);
    rc = vty_aead_open(s->kdir, seg + VTY_SEG_HEADER_BYTES, aad, aad_len,
                       seg + VTY_SEG_HEADER_BYTES + VTY_NONCE_BYTES,
                       (size_t)sh.payload_len - VTY_NONCE_BYTES,
                       plain, sizeof(plain), &plain_len);
    if (rc != VTY_OK) goto out;
    rc = node_parse(plain, plain_len, expected_level, out);
    if (rc == VTY_OK && hash_out != NULL) memcpy(hash_out, hash, VTY_HASH_BYTES);

out:
    vty_secure_zero(plain, sizeof(plain));
    vty_secure_zero(aad, sizeof(aad));
    if (seg != NULL) vty_free(seg, total);
    return rc;
}

/* 校验磁盘副本头仍为当前容器。
 *
 * 会话头是解锁时解析的内存副本；落盘自查必须证明磁盘上的容器头未被
 * 整体替换（例如文件被换回旧格式或另一格式），否则「DataRoot 可读」只能
 * 证明数据区自洽，不能证明当前文件仍是本次会话对应的容器。
 * 两份元数据副本中至少一份必须携带合法 magic/版本：单副本写入中断时
 * 另一副本仍可承载有效容器（打开路径本就按代际择一）。 */
static int verify_disk_header_magic(HANDLE h)
{
    uint8_t head[8];
    uint32_t i;

    for (i = 0; i < VTY_META_COPIES; i++) {
        uint64_t off = (uint64_t)i * (uint64_t)VTY_META_COPY_BYTES;
        int rc = read_at(h, off, head, sizeof(head));
        if (rc != VTY_OK) return rc;
        if (vty_get_u32(head) == VTY_MAGIC &&
            vty_get_u16(head + 4) == VTY_VERSION_MAJOR) {
            return VTY_OK;
        }
    }
    return VTY_E_CORRUPT;
}

/* 校验 DataRoot locator 对应的根段仍在原位且摘要一致。
 * 打开库与落盘自查共用同一实现：任何“元数据指向的根不可读/被替换”
 * 都在这里收敛为 E_CORRUPT，不把未验证的根带进会话。 */
static int verify_root_against_data_root(
    HANDLE h,
    const uint8_t uuid[VTY_UUID_BYTES],
    uint64_t epoch,
    const VtyDataRootLocator *loc,
    const uint8_t data_root_hash[VTY_HASH_BYTES],
    uint8_t out_root_hash[VTY_HASH_BYTES],
    uint64_t *out_file_size)
{
    uint64_t size = 0;
    uint8_t expect_hash[VTY_HASH_BYTES];
    int rc;

    if (h == NULL || h == INVALID_HANDLE_VALUE || uuid == NULL ||
        loc == NULL || data_root_hash == NULL) {
        return VTY_E_INVALID;
    }
    rc = file_size_of(h, &size);
    if (rc != VTY_OK) return rc;
    if (out_file_size != NULL) *out_file_size = size;
    if (size < loc->data_end) return VTY_E_CORRUPT;
    rc = verify_disk_header_magic(h);
    if (rc != VTY_OK) return rc;

    if (loc->root_node_id == 0u) {
        uint8_t empty_root[VTY_HASH_BYTES];

        rc = vty_store_empty_root(uuid, epoch, empty_root);
        if (rc != VTY_OK) return rc;
        rc = vty_store_data_root(uuid, epoch, empty_root, expect_hash);
        if (rc != VTY_OK) return rc;
        if (vty_ct_equal(expect_hash, data_root_hash, VTY_HASH_BYTES) != 0) {
            return VTY_E_CORRUPT;
        }
        if (out_root_hash != NULL) {
            memcpy(out_root_hash, empty_root, VTY_HASH_BYTES);
        }
    } else {
        uint8_t shbuf[VTY_SEG_HEADER_BYTES];
        VtySegmentHeader sh;
        uint8_t seg_hash[VTY_HASH_BYTES];
        uint8_t *seg = NULL;

        if (loc->root_offset < VTY_DATA_OFFSET ||
            loc->root_offset + loc->root_len > loc->data_end ||
            loc->root_len < VTY_SEG_HEADER_BYTES + VTY_NONCE_BYTES +
                             VTY_TAG_BYTES) {
            return VTY_E_CORRUPT;
        }
        rc = read_at(h, loc->root_offset, shbuf, sizeof(shbuf));
        if (rc != VTY_OK) return rc;
        rc = vty_segment_header_parse(shbuf, &sh);
        if (rc != VTY_OK) return rc;
        if (sh.type != VTY_SEG_DIR || sh.seq != loc->root_node_id ||
            sh.id != loc->level ||
            (size_t)sh.payload_len + VTY_SEG_HEADER_BYTES != loc->root_len) {
            return VTY_E_CORRUPT;
        }
        seg = (uint8_t *)vty_alloc(loc->root_len);
        if (seg == NULL) return VTY_E_RESOURCE;
        rc = read_at(h, loc->root_offset, seg, loc->root_len);
        if (rc == VTY_OK) rc = vty_blake3_32(seg, loc->root_len, seg_hash);
        vty_free(seg, loc->root_len);
        if (rc != VTY_OK) return rc;

        rc = vty_store_data_root(uuid, epoch, seg_hash, expect_hash);
        if (rc != VTY_OK) return rc;
        if (vty_ct_equal(expect_hash, data_root_hash, VTY_HASH_BYTES) != 0) {
            return VTY_E_CORRUPT;
        }
        if (out_root_hash != NULL) {
            memcpy(out_root_hash, seg_hash, VTY_HASH_BYTES);
        }
    }

    if (out_file_size != NULL) *out_file_size = size;
    return VTY_OK;
}

static int file_mtime_ms(HANDLE h, uint64_t *out)
{
    FILETIME ft;
    ULARGE_INTEGER li;

    if (h == NULL || h == INVALID_HANDLE_VALUE || out == NULL) {
        return VTY_E_INVALID;
    }
    if (!GetFileTime(h, NULL, NULL, &ft)) return VTY_E_IO;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    /* FILETIME 为 1601-01-01 起的 100ns；转换为 Unix 毫秒。 */
    if (li.QuadPart < 116444736000000000ULL) {
        *out = 0u;
    } else {
        *out = (uint64_t)((li.QuadPart - 116444736000000000ULL) / 10000ULL);
    }
    return VTY_OK;
}

static int store_open_internal(const char *path, const uint8_t kc[VTY_KEY_BYTES],
                               const uint8_t uuid[VTY_UUID_BYTES], uint64_t epoch,
                               const VtyDataRootLocator *loc,
                               const uint8_t data_root_hash[VTY_HASH_BYTES],
                               VtyStore **out)
{
    VtyStore *s;
    wchar_t *wpath;
    uint8_t info[64];
    size_t info_len;
    int rc;

    if (path == NULL || kc == NULL || uuid == NULL || loc == NULL ||
        data_root_hash == NULL || out == NULL) {
        return VTY_E_INVALID;
    }
    if (strlen(path) + 1 > VTY_STORE_PATH_MAX) return VTY_E_INVALID;
    if (loc->data_end < VTY_DATA_OFFSET) return VTY_E_CORRUPT;

    s = (VtyStore *)vty_secure_alloc(sizeof(VtyStore), "store");
    if (s == NULL) return VTY_E_RESOURCE;
    memcpy(s->path, path, strlen(path) + 1);
    memcpy(s->vault_uuid, uuid, VTY_UUID_BYTES);
    s->epoch = epoch;
    s->loc = *loc;

    /* K_dir 与 uuid/epoch 绑定：把目录节点搬到别的库或另一代会 AEAD 失败。 */
    {
        size_t dlen = strlen(VTY_DOMAIN_DIR);
        if (dlen + VTY_UUID_BYTES + 8u > sizeof(info)) {
            vty_secure_free(s);
            return VTY_E_INVALID;
        }
        memcpy(info, VTY_DOMAIN_DIR, dlen);
        memcpy(info + dlen, uuid, VTY_UUID_BYTES);
        vty_put_u64(info + dlen + VTY_UUID_BYTES, epoch);
        info_len = dlen + VTY_UUID_BYTES + 8u;
    }
    rc = vty_hkdf_expand(s->kdir, kc, info, info_len);
    if (rc != VTY_OK) goto fail;

    wpath = utf8_to_wide(path);
    if (wpath == NULL) { rc = VTY_E_INVALID; goto fail; }
    /* 与元数据层并存：保存需要同进程再次打开文件写 meta，因此共享
     * 读写；并发写由上层单写者会话保证。 */
    s->h = CreateFileW(wpath, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);
    if (s->h == INVALID_HANDLE_VALUE) { rc = VTY_E_IO; goto fail; }
    rc = verify_root_against_data_root(s->h, uuid, epoch, &s->loc,
                                       data_root_hash, s->root_hash, NULL);
    if (rc != VTY_OK) goto fail;
    if (s->loc.root_node_id != 0u) {
        VtyMemNode root;

        memset(&root, 0, sizeof(root));
        rc = node_read(s, s->loc.root_offset, s->loc.level, &root, NULL);
        if (rc != VTY_OK) goto fail;
        node_free(&root);
    } else {
        memset(s->root_hash, 0, sizeof(s->root_hash));
        rc = vty_store_empty_root(uuid, epoch, s->root_hash);
        if (rc != VTY_OK) goto fail;
    }

    s->dirty = 0;
    *out = s;
    return VTY_OK;

fail:
    if (s->h != INVALID_HANDLE_VALUE && s->h != NULL) CloseHandle(s->h);
    vty_secure_zero(s->kdir, sizeof(s->kdir));
    vty_secure_free(s);
    return rc;
}

int vty_store_open(const char *path,
                   const uint8_t kc[VTY_KEY_BYTES],
                   const uint8_t vault_uuid[VTY_UUID_BYTES],
                   uint64_t epoch,
                   const VtyDataRootLocator *loc,
                   const uint8_t data_root_hash[VTY_HASH_BYTES],
                   VtyStore **out)
{
    return store_open_internal(path, kc, vault_uuid, epoch, loc, data_root_hash, out);
}

int vty_store_verify_data_root(VtyStore *s,
                               const VtyDataRootLocator *loc,
                               const uint8_t data_root_hash[VTY_HASH_BYTES],
                               uint64_t *out_file_size,
                               uint64_t *out_mtime_ms)
{
    int rc;

    if (s == NULL || loc == NULL || data_root_hash == NULL ||
        out_file_size == NULL) {
        return VTY_E_INVALID;
    }
    *out_file_size = 0;
    if (out_mtime_ms != NULL) *out_mtime_ms = 0;
    if (s->h == INVALID_HANDLE_VALUE || s->h == NULL) return VTY_E_IO;

    rc = verify_root_against_data_root(s->h, s->vault_uuid, s->epoch, loc,
                                       data_root_hash, NULL, out_file_size);
    if (rc != VTY_OK) return rc;

    if (loc->root_node_id != 0u) {
        VtyMemNode root;

        memset(&root, 0, sizeof(root));
        rc = node_read(s, loc->root_offset, loc->level, &root, NULL);
        if (rc != VTY_OK) return rc;
        node_free(&root);
    }
    if (out_mtime_ms != NULL) {
        (void)file_mtime_ms(s->h, out_mtime_ms);
    }
    return VTY_OK;
}

void vty_store_close(VtyStore *s)
{
    if (s == NULL) return;
    if (s->h != INVALID_HANDLE_VALUE && s->h != NULL) {
        if (s->dirty) (void)FlushFileBuffers(s->h);
        CloseHandle(s->h);
        s->h = INVALID_HANDLE_VALUE;
    }
    vty_secure_zero(s->kdir, sizeof(s->kdir));
    vty_secure_free(s);
}

/* 从段头读出子节点真实 level，而不是依赖父节点推断。 */
static int load_child_exact(VtyStore *s, uint64_t id,
                            const uint8_t expected_hash[VTY_HASH_BYTES],
                            uint8_t *level, VtyMemNode *child)
{
    uint8_t shbuf[VTY_SEG_HEADER_BYTES];
    uint8_t actual[VTY_HASH_BYTES];
    VtySegmentHeader sh;
    int rc;

    if (id < VTY_DATA_OFFSET || id >= s->loc.data_end) return VTY_E_CORRUPT;
    rc = read_at(s->h, id, shbuf, sizeof(shbuf));
    if (rc != VTY_OK) return VTY_E_IO;
    rc = vty_segment_header_parse(shbuf, &sh);
    if (rc != VTY_OK) return rc;
    if (sh.type != VTY_SEG_DIR || sh.seq != id) return VTY_E_CORRUPT;
    *level = sh.id;
    rc = node_read(s, id, sh.id, child, actual);
    if (rc != VTY_OK) return rc;
    /* 父节点存的子 hash 必须与真实段 hash 一致；否则“父指向子”的
     * 完整性链条只是装饰，无法在 VerifyIntegrity 中审计。 */
    if (expected_hash != NULL &&
        vty_ct_equal(actual, expected_hash, VTY_HASH_BYTES) != 0) {
        node_free(child);
        return VTY_E_CORRUPT;
    }
    return VTY_OK;
}

static int write_split_pair(VtyStore *s, VtyMemNode *work, uint32_t mid,
                            VtySplit *out)
{
    VtyMemNode *left = NULL;
    VtyMemNode *right = NULL;
    int rc;

    left = (VtyMemNode *)vty_alloc(sizeof(VtyMemNode));
    right = (VtyMemNode *)vty_alloc(sizeof(VtyMemNode));
    if (left == NULL || right == NULL) { rc = VTY_E_RESOURCE; goto out; }

    left->level = work->level;
    left->type = work->type;
    left->n = (uint16_t)mid;
    right->level = work->level;
    right->type = work->type;
    right->n = (uint16_t)(work->n - mid);

    memcpy(left->e, work->e, sizeof(VtyMemEntry) * mid);
    memcpy(right->e, work->e + mid, sizeof(VtyMemEntry) * right->n);
    /* 所有权转移：work 不再释放这些值。 */
    {
        uint32_t i;
        for (i = 0; i < work->n; i++) work->e[i].val = NULL;
    }

    rc = node_write(s, left, &out->left);
    if (rc == VTY_OK) rc = node_write(s, right, &out->right);
    if (rc == VTY_OK) out->split = 1;

out:
    if (left != NULL) { node_free(left); vty_free(left, sizeof(VtyMemNode)); }
    if (right != NULL) { node_free(right); vty_free(right, sizeof(VtyMemNode)); }
    return rc;
}

static int insert_rec(VtyStore *s, VtyMemNode *node,
                      const uint8_t *key, uint16_t key_len,
                      const uint8_t *val, uint32_t val_len,
                      VtySplit *out)
{
    size_t plain_len = 0;
    int rc;

    if (node->type == VTY_NODE_LEAF) {
        uint32_t i;
        int found = 0;
        for (i = 0; i < node->n; i++) {
            int c = key_cmp(node->e[i].key, node->e[i].key_len, key, key_len);
            if (c == 0) { found = 1; break; }
            if (c > 0) break;
        }
        if (found) {
            VtyMemEntry *e = &node->e[i];
            if (e->val != NULL) {
                vty_secure_zero(e->val, e->val_len);
                vty_free(e->val, e->val_len);
                e->val = NULL;
            }
            e->val_len = val_len;
            if (val_len != 0) {
                e->val = (uint8_t *)vty_alloc(val_len);
                if (e->val == NULL) return VTY_E_RESOURCE;
                memcpy(e->val, val, val_len);
            }
        } else {
            /* 空值也是合法条目（索引存在性由键表达）；不能把“值为空”
             * 当成“无写入”，否则索引键永远不会落盘。 */
            if (node->n >= VTY_STORE_ENTRY_MAX) return VTY_E_RESOURCE;
            memmove(&node->e[i + 1], &node->e[i],
                    sizeof(VtyMemEntry) * (node->n - i));
            memset(&node->e[i], 0, sizeof(VtyMemEntry));
            node->e[i].key_len = key_len;
            memcpy(node->e[i].key, key, key_len);
            node->e[i].val_len = val_len;
            if (val_len != 0) {
                node->e[i].val = (uint8_t *)vty_alloc(val_len);
                if (node->e[i].val == NULL) return VTY_E_RESOURCE;
                memcpy(node->e[i].val, val, val_len);
            }
            node->n++;
        }

        rc = node_plain_size(node, &plain_len);
        if (rc == VTY_OK) {
            out->split = 0;
            return node_write(s, node, &out->left);
        }
        if (rc != VTY_E_RESOURCE) return rc;
        return write_split_pair(s, node, node->n / 2u, out);
    }

    /* 内部节点：找到第一个 >= key 的分隔键；没有则落到最后一个子节点，
     * 由叶节点扩展上界并回传新的最大键。 */
    {
        uint32_t i;
        VtyMemNode child;
        uint8_t child_level = 0;
        VtySplit sub;

        memset(&child, 0, sizeof(child));
        memset(&sub, 0, sizeof(sub));
        for (i = 0; i < node->n; i++) {
            if (key_cmp(key, key_len, node->e[i].key, node->e[i].key_len) <= 0) break;
        }
        if (i == node->n) i = node->n - 1u;

        rc = load_child_exact(s, node->e[i].child_id,
                              node->e[i].child_hash, &child_level, &child);
        if (rc != VTY_OK) return rc;
        rc = insert_rec(s, &child, key, key_len, val, val_len, &sub);
        node_free(&child);
        if (rc != VTY_OK) return rc;

        if (!sub.split) {
            node->e[i].child_id = sub.left.id;
            memcpy(node->e[i].child_hash, sub.left.hash, VTY_HASH_BYTES);
            node->e[i].key_len = sub.left.max_len;
            memcpy(node->e[i].key, sub.left.max_key, sub.left.max_len);
        } else {
            if (node->n >= VTY_STORE_ENTRY_MAX) return VTY_E_RESOURCE;
            node->e[i].child_id = sub.left.id;
            memcpy(node->e[i].child_hash, sub.left.hash, VTY_HASH_BYTES);
            node->e[i].key_len = sub.left.max_len;
            memcpy(node->e[i].key, sub.left.max_key, sub.left.max_len);

            memmove(&node->e[i + 2], &node->e[i + 1],
                    sizeof(VtyMemEntry) * (node->n - i - 1u));
            memset(&node->e[i + 1], 0, sizeof(VtyMemEntry));
            node->e[i + 1].child_id = sub.right.id;
            memcpy(node->e[i + 1].child_hash, sub.right.hash, VTY_HASH_BYTES);
            node->e[i + 1].key_len = sub.right.max_len;
            memcpy(node->e[i + 1].key, sub.right.max_key, sub.right.max_len);
            node->n++;
        }

        rc = node_plain_size(node, &plain_len);
        if (rc == VTY_OK) {
            out->split = 0;
            return node_write(s, node, &out->left);
        }
        if (rc != VTY_E_RESOURCE) return rc;
        return write_split_pair(s, node, node->n / 2u, out);
    }
}

static int find_leaf(VtyStore *s, const uint8_t *full_key, uint16_t full_len,
                     VtyMemNode *out_leaf, int *found)
{
    VtyMemNode node;
    uint64_t id = s->loc.root_node_id;
    uint8_t level = s->loc.level;
    int rc;

    memset(&node, 0, sizeof(node));
    *found = 0;
    if (id == 0u) return VTY_E_INVALID;

    for (;;) {
        rc = node_read(s, id, level, &node, NULL);
        if (rc != VTY_OK) return rc;
        if (node.type == VTY_NODE_LEAF) {
            *out_leaf = node;
            return VTY_OK;
        }
        {
            uint32_t i;
            for (i = 0; i < node.n; i++) {
                if (key_cmp(full_key, full_len, node.e[i].key, node.e[i].key_len) <= 0) {
                    break;
                }
            }
            if (i == node.n) {
                node_free(&node);
                return VTY_E_INVALID;
            }
            id = node.e[i].child_id;
            level = (uint8_t)(level > 0 ? level - 1u : 0u);
            node_free(&node);
        }
    }
}

int vty_store_put(VtyStore *s, uint8_t keyspace,
                  const uint8_t *key, size_t key_len,
                  const uint8_t *value, size_t value_len)
{
    uint8_t full_key[VTY_STORE_KEY_MAX];
    uint16_t full_len;
    VtyMemNode root;
    VtySplit split;
    int rc;

    if (s == NULL || (key == NULL && key_len != 0)) return VTY_E_INVALID;
    if (key_len + 1u > VTY_STORE_KEY_MAX) return VTY_E_INVALID;
    if (value_len > VTY_STORE_VAL_MAX) return VTY_E_RESOURCE;
    if (value == NULL && value_len != 0) return VTY_E_INVALID;

    full_key[0] = keyspace;
    if (key_len != 0) memcpy(full_key + 1, key, key_len);
    full_len = (uint16_t)(key_len + 1u);

    if (s->loc.root_node_id == 0u) {
        memset(&root, 0, sizeof(root));
        root.level = 0;
        root.type = VTY_NODE_LEAF;
        root.n = 1;
        root.e[0].key_len = full_len;
        memcpy(root.e[0].key, full_key, full_len);
        root.e[0].val_len = (uint32_t)value_len;
        if (value_len != 0) {
            root.e[0].val = (uint8_t *)vty_alloc(value_len);
            if (root.e[0].val == NULL) return VTY_E_RESOURCE;
            memcpy(root.e[0].val, value, value_len);
        }

        memset(&split, 0, sizeof(split));
        rc = node_write(s, &root, &split.left);
        node_free(&root);
        if (rc != VTY_OK) return rc;
        s->loc.root_node_id = split.left.id;
        s->loc.root_offset = split.left.id;
        s->loc.root_len = (uint32_t)(s->loc.data_end - split.left.id);
        s->loc.level = split.left.level;
        memcpy(s->root_hash, split.left.hash, VTY_HASH_BYTES);
        return VTY_OK;
    }

    memset(&root, 0, sizeof(root));
    rc = node_read(s, s->loc.root_node_id, s->loc.level, &root, NULL);
    if (rc != VTY_OK) return rc;
    rc = insert_rec(s, &root, full_key, full_len, value, (uint32_t)value_len, &split);
    node_free(&root);
    if (rc != VTY_OK) return rc;

    if (split.split) {
        VtyMemNode newroot;
        VtyNodeRef nr;
        if (s->loc.level >= VTY_STORE_MAX_LEVEL) return VTY_E_RESOURCE;
        memset(&newroot, 0, sizeof(newroot));
        newroot.level = (uint8_t)(s->loc.level + 1u);
        newroot.type = VTY_NODE_INTERNAL;
        newroot.n = 2;
        newroot.e[0].key_len = split.left.max_len;
        memcpy(newroot.e[0].key, split.left.max_key, split.left.max_len);
        newroot.e[0].child_id = split.left.id;
        memcpy(newroot.e[0].child_hash, split.left.hash, VTY_HASH_BYTES);
        newroot.e[1].key_len = split.right.max_len;
        memcpy(newroot.e[1].key, split.right.max_key, split.right.max_len);
        newroot.e[1].child_id = split.right.id;
        memcpy(newroot.e[1].child_hash, split.right.hash, VTY_HASH_BYTES);
        rc = node_write(s, &newroot, &nr);
        node_free(&newroot);
        if (rc != VTY_OK) return rc;
        s->loc.root_node_id = nr.id;
        s->loc.root_offset = nr.id;
        s->loc.root_len = (uint32_t)(s->loc.data_end - nr.id);
        s->loc.level = nr.level;
        memcpy(s->root_hash, nr.hash, VTY_HASH_BYTES);
        return VTY_OK;
    }

    s->loc.root_node_id = split.left.id;
    s->loc.root_offset = split.left.id;
    s->loc.root_len = (uint32_t)(s->loc.data_end - split.left.id);
    s->loc.level = split.left.level;
    memcpy(s->root_hash, split.left.hash, VTY_HASH_BYTES);
    return VTY_OK;
}

int vty_store_get(VtyStore *s, uint8_t keyspace,
                  const uint8_t *key, size_t key_len,
                  uint8_t **value, size_t *value_len)
{
    uint8_t full_key[VTY_STORE_KEY_MAX];
    uint16_t full_len;
    VtyMemNode leaf;
    int rc;
    uint32_t i;

    if (s == NULL || key == NULL || value == NULL || value_len == NULL) {
        return VTY_E_INVALID;
    }
    if (key_len + 1u > VTY_STORE_KEY_MAX) return VTY_E_INVALID;
    *value = NULL;
    *value_len = 0;
    full_key[0] = keyspace;
    memcpy(full_key + 1, key, key_len);
    full_len = (uint16_t)(key_len + 1u);

    memset(&leaf, 0, sizeof(leaf));
    {
        int found = 0;
        rc = find_leaf(s, full_key, full_len, &leaf, &found);
        if (rc != VTY_OK) return rc;
    }

    for (i = 0; i < leaf.n; i++) {
        if (key_cmp(leaf.e[i].key, leaf.e[i].key_len, full_key, full_len) == 0) {
            /* 空值 = 键存在（索引条目）；返回 OK 且 value=NULL，调用方
             * 据此区分“存在但无值”和“键不存在”。 */
            if (leaf.e[i].val_len != 0) {
                *value = (uint8_t *)vty_alloc(leaf.e[i].val_len);
                if (*value == NULL) {
                    node_free(&leaf);
                    return VTY_E_RESOURCE;
                }
                memcpy(*value, leaf.e[i].val, leaf.e[i].val_len);
            }
            *value_len = leaf.e[i].val_len;
            node_free(&leaf);
            return VTY_OK;
        }
        if (key_cmp(leaf.e[i].key, leaf.e[i].key_len, full_key, full_len) > 0) break;
    }
    node_free(&leaf);
    return VTY_E_INVALID;
}

int vty_store_commit(VtyStore *s, VtyDataRootLocator *out,
                     uint8_t data_root_hash[VTY_HASH_BYTES])
{
    int rc;

    if (s == NULL || out == NULL || data_root_hash == NULL) return VTY_E_INVALID;
    if (s->dirty) {
        rc = FlushFileBuffers(s->h);
        if (!rc) return VTY_E_IO;
        s->dirty = 0;
    }
    rc = vty_store_data_root(s->vault_uuid, s->epoch, s->root_hash, data_root_hash);
    if (rc != VTY_OK) return rc;
    *out = s->loc;
    return VTY_OK;
}

static int verify_node(VtyStore *s, uint64_t id, uint8_t level, uint8_t depth)
{
    VtyMemNode n;
    int rc;
    uint32_t i;

    if (depth > VTY_STORE_MAX_LEVEL) return VTY_E_CORRUPT;
    memset(&n, 0, sizeof(n));
    rc = node_read(s, id, level, &n, NULL);
    if (rc != VTY_OK) return rc;

    if (n.type == VTY_NODE_INTERNAL) {
        for (i = 0; i < n.n; i++) {
            VtyMemNode child;
            uint8_t child_level = 0;
            memset(&child, 0, sizeof(child));
            rc = load_child_exact(s, n.e[i].child_id, n.e[i].child_hash,
                                  &child_level, &child);
            if (rc != VTY_OK) { node_free(&n); return rc; }
            if (child_level + 1u != n.level) { node_free(&child); node_free(&n); return VTY_E_CORRUPT; }
            if (key_cmp(child.e[child.n - 1].key, child.e[child.n - 1].key_len,
                        n.e[i].key, n.e[i].key_len) != 0) {
                node_free(&child);
                node_free(&n);
                return VTY_E_CORRUPT;
            }
            node_free(&child);
            rc = verify_node(s, n.e[i].child_id, (uint8_t)(n.level - 1u),
                             (uint8_t)(depth + 1u));
            if (rc != VTY_OK) { node_free(&n); return rc; }
        }
    }
    node_free(&n);
    return VTY_OK;
}

int vty_store_verify(VtyStore *s)
{
    uint64_t size = 0;
    int rc;

    if (s == NULL) return VTY_E_INVALID;
    rc = file_size_of(s->h, &size);
    if (rc != VTY_OK) return rc;
    if (size < s->loc.data_end) return VTY_E_CORRUPT;
    if (s->loc.root_node_id == 0u) {
        uint8_t empty[VTY_HASH_BYTES];
        rc = vty_store_empty_root(s->vault_uuid, s->epoch, empty);
        if (rc != VTY_OK) return rc;
        return vty_ct_equal(empty, s->root_hash, VTY_HASH_BYTES) == 0 ? VTY_OK
                                                                     : VTY_E_CORRUPT;
    }
    return verify_node(s, s->loc.root_node_id, s->loc.level, 0);
}

/* ------------------------------------------------------------------ *
 * 追加段（记录/分片）
 *
 * 段本身不再叠加 AEAD：记录/分片的机密性由各自的内层 AEAD 提供，
 * 完整性由 BLAKE3(段头+payload) 绑定到加密目录叶——若段被替换或
 * 搬移，叶中的 hash 必然失配。
 * ------------------------------------------------------------------ */
int vty_store_append_segment(VtyStore *s, uint8_t type, uint64_t seq, uint64_t id,
                             const uint8_t *payload, size_t payload_len,
                             VtySegmentLocator *out)
{
    uint8_t *seg = NULL;
    uint8_t hash[VTY_HASH_BYTES];
    size_t total;
    uint64_t offset;
    int rc;

    if (s == NULL || out == NULL) return VTY_E_INVALID;
    if (type != VTY_SEG_RECORD && type != VTY_SEG_CHUNK) return VTY_E_INVALID;
    if (payload == NULL && payload_len != 0) return VTY_E_INVALID;
    /* total_len 是 u32 字段：payload 必须给 32B 段头留出空间，否则
     * 写盘长度会被截断，目录引用到错误边界。 */
    if (payload_len > 0xFFFFFFFFu - VTY_SEG_HEADER_BYTES) return VTY_E_INVALID;
    total = VTY_SEG_HEADER_BYTES + payload_len;

    seg = (uint8_t *)vty_alloc(total);
    if (seg == NULL) return VTY_E_RESOURCE;
    {
        VtySegmentHeader sh;
        memset(&sh, 0, sizeof(sh));
        sh.type = type;
        sh.flags = 0;
        sh.payload_len = (uint32_t)payload_len;
        sh.seq = seq;
        sh.id = id;
        rc = vty_segment_header_write(&sh, seg);
        if (rc != VTY_OK) goto out;
    }
    if (payload_len != 0) memcpy(seg + VTY_SEG_HEADER_BYTES, payload, payload_len);
    rc = vty_blake3_32(seg, total, hash);
    if (rc != VTY_OK) goto out;

    offset = s->loc.data_end;
    rc = write_at(s->h, offset, seg, total);
    if (rc != VTY_OK) goto out;

    s->loc.data_end = offset + total;
    s->dirty = 1;

    memset(out, 0, sizeof(*out));
    out->type = type;
    out->seq = seq;
    out->id = id;
    out->offset = offset;
    out->total_len = (uint32_t)total;
    memcpy(out->hash, hash, VTY_HASH_BYTES);

out:
    if (seg != NULL) vty_free(seg, total);
    return rc;
}

int vty_store_read_segment(VtyStore *s, const VtySegmentLocator *loc,
                           uint8_t **payload, size_t *payload_len)
{
    uint8_t shbuf[VTY_SEG_HEADER_BYTES];
    VtySegmentHeader sh;
    uint8_t *seg = NULL;
    uint8_t hash[VTY_HASH_BYTES];
    size_t total;
    int rc;

    if (s == NULL || loc == NULL || payload == NULL || payload_len == NULL) {
        return VTY_E_INVALID;
    }
    *payload = NULL;
    *payload_len = 0;
    if (loc->offset < VTY_DATA_OFFSET || loc->offset >= s->loc.data_end) {
        return VTY_E_CORRUPT;
    }
    if (loc->total_len < VTY_SEG_HEADER_BYTES ||
        loc->total_len > s->loc.data_end - loc->offset) {
        return VTY_E_CORRUPT;
    }
    total = loc->total_len;

    rc = read_at(s->h, loc->offset, shbuf, sizeof(shbuf));
    if (rc != VTY_OK) return rc;
    rc = vty_segment_header_parse(shbuf, &sh);
    if (rc != VTY_OK) return rc;
    if (sh.type != loc->type || sh.seq != loc->seq || sh.id != loc->id) {
        return VTY_E_CORRUPT;
    }
    if (VTY_SEG_HEADER_BYTES + (size_t)sh.payload_len != total) {
        return VTY_E_CORRUPT;
    }

    seg = (uint8_t *)vty_alloc(total);
    if (seg == NULL) return VTY_E_RESOURCE;
    rc = read_at(s->h, loc->offset, seg, total);
    if (rc == VTY_OK) rc = vty_blake3_32(seg, total, hash);
    if (rc == VTY_OK &&
        vty_ct_equal(hash, loc->hash, VTY_HASH_BYTES) != 0) {
        rc = VTY_E_CORRUPT;
    }
    if (rc != VTY_OK) {
        vty_free(seg, total);
        return rc;
    }

    if (sh.payload_len != 0) {
        uint8_t *out = (uint8_t *)vty_alloc(sh.payload_len);
        if (out == NULL) {
            vty_free(seg, total);
            return VTY_E_RESOURCE;
        }
        memcpy(out, seg + VTY_SEG_HEADER_BYTES, sh.payload_len);
        *payload = out;
        *payload_len = sh.payload_len;
    }
    vty_free(seg, total);
    return VTY_OK;
}

int vty_store_delete(VtyStore *s, uint8_t keyspace,
                     const uint8_t *key, size_t key_len)
{
    uint8_t tomb = VTY_STORE_TOMBSTONE_BYTE;

    return vty_store_put(s, keyspace, key, key_len, &tomb, 1u);
}

int vty_store_checkpoint(VtyStore *s, VtyStoreCheckpoint *out)
{
    if (s == NULL || out == NULL) return VTY_E_INVALID;
    out->loc = s->loc;
    memcpy(out->hash, s->root_hash, VTY_HASH_BYTES);
    return VTY_OK;
}

int vty_store_restore(VtyStore *s, const VtyStoreCheckpoint *cp)
{
    if (s == NULL || cp == NULL) return VTY_E_INVALID;
    s->loc = cp->loc;
    memcpy(s->root_hash, cp->hash, VTY_HASH_BYTES);
    return VTY_OK;
}

/* ------------------------------------------------------------------ *
 * 升序游标
 *
 * 只保存路径上的节点 id/下标，每次推进重新读取节点；数据区只追加，
 * 旧节点不会被覆盖，因此游标天然处于打开瞬间的快照。
 * ------------------------------------------------------------------ */
struct VtyStoreCursor {
    VtyStore *s;
    uint8_t keyspace;
    uint8_t target[VTY_STORE_KEY_MAX];
    uint16_t target_len;
    uint64_t root_id;
    uint8_t root_level;
    uint8_t depth;
    uint64_t node_id[VTY_STORE_MAX_LEVEL + 2u];
    uint16_t node_idx[VTY_STORE_MAX_LEVEL + 2u];
    uint8_t node_level[VTY_STORE_MAX_LEVEL + 2u];
    VtyMemNode *leaf;
    uint16_t leaf_pos;
    int done;
};

static uint16_t lower_bound_entries(const VtyMemEntry *e, uint32_t n,
                                    const uint8_t *key, uint16_t key_len)
{
    uint32_t lo = 0, hi = n;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        if (key_cmp(e[mid].key, e[mid].key_len, key, key_len) < 0) lo = mid + 1u;
        else hi = mid;
    }
    return (uint16_t)lo;
}

static int cursor_advance(VtyStoreCursor *c);

static int cursor_descend(VtyStoreCursor *c, uint64_t id, uint8_t level, int first)
{
    uint32_t guard = 0;

    for (;;) {
        VtyMemNode node;
        int rc;

        if (++guard > VTY_STORE_MAX_LEVEL + 2u) return VTY_E_CORRUPT;
        memset(&node, 0, sizeof(node));
        rc = node_read(c->s, id, level, &node, NULL);
        if (rc != VTY_OK) return rc;

        if (node.type == VTY_NODE_LEAF) {
            c->leaf = (VtyMemNode *)vty_alloc(sizeof(VtyMemNode));
            if (c->leaf == NULL) {
                node_free(&node);
                return VTY_E_RESOURCE;
            }
            *c->leaf = node;
            c->leaf_pos = first
                ? lower_bound_entries(node.e, node.n, c->target, c->target_len)
                : 0;
            if (c->leaf_pos >= node.n) return cursor_advance(c);
            return VTY_OK;
        }

        if (c->depth >= VTY_STORE_MAX_LEVEL + 1u) {
            node_free(&node);
            return VTY_E_CORRUPT;
        }
        c->node_idx[c->depth] = first
            ? lower_bound_entries(node.e, node.n, c->target, c->target_len)
            : 0;
        if (c->node_idx[c->depth] >= node.n) c->node_idx[c->depth] = (uint16_t)(node.n - 1u);
        c->node_id[c->depth] = id;
        c->node_level[c->depth] = level;
        c->depth++;

        id = node.e[c->node_idx[c->depth - 1u]].child_id;
        level = (uint8_t)(level - 1u);
        node_free(&node);
    }
}

static int cursor_advance(VtyStoreCursor *c)
{
    if (c->leaf != NULL) {
        node_free(c->leaf);
        vty_free(c->leaf, sizeof(VtyMemNode));
        c->leaf = NULL;
    }

    while (c->depth > 0) {
        VtyMemNode parent;
        uint32_t i;
        int rc;

        memset(&parent, 0, sizeof(parent));
        rc = node_read(c->s, c->node_id[c->depth - 1u],
                       c->node_level[c->depth - 1u], &parent, NULL);
        if (rc != VTY_OK) return rc;
        i = c->node_idx[c->depth - 1u];
        c->depth--;
        if (i + 1u < parent.n) {
            uint64_t child = parent.e[i + 1u].child_id;
            uint8_t clevel = (uint8_t)(c->node_level[c->depth] - 1u);
            c->node_idx[c->depth] = (uint16_t)(i + 1u);
            c->depth++;
            node_free(&parent);
            return cursor_descend(c, child, clevel, 0);
        }
        node_free(&parent);
    }

    c->done = 1;
    return VTY_OK;
}

int vty_store_cursor_open(VtyStore *s, uint8_t keyspace,
                          const uint8_t *start_key, size_t start_key_len,
                          VtyStoreCursor **out)
{
    VtyStoreCursor *c;
    int rc;

    if (s == NULL || out == NULL) return VTY_E_INVALID;
    if (start_key == NULL && start_key_len != 0) return VTY_E_INVALID;
    if (start_key_len + 1u > VTY_STORE_KEY_MAX) return VTY_E_INVALID;

    *out = NULL;
    c = (VtyStoreCursor *)vty_alloc(sizeof(VtyStoreCursor));
    if (c == NULL) return VTY_E_RESOURCE;
    c->s = s;
    c->keyspace = keyspace;
    c->target[0] = keyspace;
    if (start_key_len != 0) memcpy(c->target + 1, start_key, start_key_len);
    c->target_len = (uint16_t)(start_key_len + 1u);
    c->root_id = s->loc.root_node_id;
    c->root_level = s->loc.level;
    c->leaf = NULL;
    c->depth = 0;
    c->done = 0;

    if (c->root_id == 0u) {
        c->done = 1;
        *out = c;
        return VTY_OK;
    }
    rc = cursor_descend(c, c->root_id, c->root_level, 1);
    if (rc != VTY_OK) {
        vty_store_cursor_close(c);
        return rc;
    }
    *out = c;
    return VTY_OK;
}

int vty_store_cursor_next(VtyStoreCursor *c, int *done,
                          uint8_t **key, size_t *key_len,
                          uint8_t **value, size_t *value_len)
{
    if (c == NULL || done == NULL || key == NULL || key_len == NULL ||
        value == NULL || value_len == NULL) {
        return VTY_E_INVALID;
    }
    *done = 0;
    *key = NULL;
    *key_len = 0;
    *value = NULL;
    *value_len = 0;

    for (;;) {
        const VtyMemEntry *e;
        int rc;

        if (c->done || c->leaf == NULL) {
            *done = 1;
            return VTY_OK;
        }
        if (c->leaf_pos >= c->leaf->n) {
            rc = cursor_advance(c);
            if (rc != VTY_OK) return rc;
            continue;
        }

        e = &c->leaf->e[c->leaf_pos];
        if (e->key_len == 0) return VTY_E_CORRUPT;
        if (e->key[0] < c->keyspace) {
            c->leaf_pos++;
            continue;
        }
        if (e->key[0] > c->keyspace) {
            *done = 1;
            return VTY_OK;
        }

        c->leaf_pos++;
        {
            size_t klen = (size_t)e->key_len - 1u;
            uint8_t *k = NULL;
            if (klen != 0) {
                k = (uint8_t *)vty_alloc(klen);
                if (k == NULL) return VTY_E_RESOURCE;
                memcpy(k, e->key + 1, klen);
            }
            *key = k;
            *key_len = klen;
        }
        if (e->val_len != 0) {
            uint8_t *v = (uint8_t *)vty_alloc(e->val_len);
            if (v == NULL) {
                if (*key != NULL) vty_free(*key, *key_len);
                *key = NULL;
                *key_len = 0;
                return VTY_E_RESOURCE;
            }
            memcpy(v, e->val, e->val_len);
            *value = v;
            *value_len = e->val_len;
        }
        return VTY_OK;
    }
}

void vty_store_cursor_close(VtyStoreCursor *c)
{
    if (c == NULL) return;
    if (c->leaf != NULL) {
        node_free(c->leaf);
        vty_free(c->leaf, sizeof(VtyMemNode));
        c->leaf = NULL;
    }
    vty_free(c, sizeof(VtyStoreCursor));
}

int vty_store_is_empty(VtyStore *s)
{
    return (s != NULL && s->loc.root_node_id == 0u) ? 1 : 0;
}

int vty_store_count(VtyStore *s, uint8_t keyspace, uint64_t *out_count)
{
    VtyStoreCursor *c = NULL;
    uint64_t n = 0;
    int rc;

    if (s == NULL || out_count == NULL) return VTY_E_INVALID;
    rc = vty_store_cursor_open(s, keyspace, NULL, 0, &c);
    if (rc != VTY_OK) return rc;
    for (;;) {
        int done = 0;
        uint8_t *k = NULL, *v = NULL;
        size_t klen = 0, vlen = 0;
        rc = vty_store_cursor_next(c, &done, &k, &klen, &v, &vlen);
        if (rc != VTY_OK) {
            vty_store_cursor_close(c);
            return rc;
        }
        if (done) break;
        n++;
        if (k != NULL) vty_free(k, klen);
        if (v != NULL) vty_free(v, vlen);
    }
    vty_store_cursor_close(c);
    *out_count = n;
    return VTY_OK;
}
