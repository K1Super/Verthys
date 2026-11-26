/*
 * vty_store.c — 数据区打开与校验、空根/DataRoot 与文件 IO
 */

#include "vty_store_internal.h"


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

int vty_st_file_size_of(HANDLE h, uint64_t *out)
{
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0) return VTY_E_IO;
    *out = (uint64_t)size.QuadPart;
    return VTY_OK;
}

/* 位置写/读必须用 OVERLAPPED 指定偏移，而不是 SetFilePointerEx：
 * 同一 store 句柄可能被多个只读扫描/摘要并发使用，共享文件指针会让
 * “定位 + 读”交错到别的偏移。偏移写读不改变文件指针，天然可并发。 */
int vty_st_read_at(HANDLE h, uint64_t off, uint8_t *buf, size_t len)
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

int vty_st_write_at(HANDLE h, uint64_t off, const uint8_t *buf, size_t len)
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
        int rc = vty_st_read_at(h, off, head, sizeof(head));
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
    rc = vty_st_file_size_of(h, &size);
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
        rc = vty_st_read_at(h, loc->root_offset, shbuf, sizeof(shbuf));
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
        rc = vty_st_read_at(h, loc->root_offset, seg, loc->root_len);
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
        rc = vty_st_node_read(s, s->loc.root_offset, s->loc.level, &root, NULL);
        if (rc != VTY_OK) goto fail;
        vty_st_node_free(&root);
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
        rc = vty_st_node_read(s, loc->root_offset, loc->level, &root, NULL);
        if (rc != VTY_OK) return rc;
        vty_st_node_free(&root);
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
