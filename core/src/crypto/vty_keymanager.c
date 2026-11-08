/*
 * vty_keymanager.c — 库创建、解锁与会话实现
 *
 * 元数据采用 A/B 两份 64 KiB 副本：保存只覆盖非活动副本，回读并由 K_c
 * 认证通过后才推进回退锚点。数据区从 128 KiB 起只追加，避免大文件
 * 全量重写，也让“删一段/换一段”必须同时伪造目录根与 DataRoot。
 */
#include "vty_keymanager.h"
#include "vty_keyfile.h"
#include "vty_kdf.h"
#include "vty_util.h"
#include "vty_device_root.h"
#include "vty_lockout.h"
#include "vty_machine_limiter.h"
#include "vty_rollback.h"
#include "vty_tpm_pcr.h"
#include "vty_store.h"
#include "vty_module.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

#define VTY_BODY_AAD_MAX 128u
#define VTY_BODY_NONCE VTY_NONCE_BYTES

/* 系统记录域保留 UUID：ASCII "VTYSYSTEM" + 8 字节零填充。
 * 不进入模块表，不参与模块 UUID 唯一性校验，不可启用或删除。 */
const uint8_t vty_system_module_uuid[VTY_UUID_BYTES] = {
    0x56u, 0x54u, 0x59u, 0x53u, 0x59u, 0x53u, 0x54u, 0x45u,
    0x4Du, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
};

typedef struct {
    int valid;
    uint32_t index;
    const uint8_t *header_buf;      /* 指向 64 KiB 副本起点 */
    VtyHeader h;
    VtySlot slots[VTY_MAX_SLOTS];
    uint32_t slot_count;
    uint8_t digest[VTY_HASH_BYTES];
    const uint8_t *body;
    size_t body_len;
} VtyMetaCopy;

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

static void put_u32le(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value & 0xffu);
    p[1] = (uint8_t)((value >> 8) & 0xffu);
    p[2] = (uint8_t)((value >> 16) & 0xffu);
    p[3] = (uint8_t)((value >> 24) & 0xffu);
}

/* 用户槽 KDF 输入：无 keyfile 时保持旧字节序（仅 password）；有 keyfile 时
 * 用长度前缀把 password 与 keyfile_digest 拼成无歧义输入。 */
static int make_user_secret(const char *password, const uint8_t *keyfile_digest,
                            uint8_t **owned, const uint8_t **secret, size_t *secret_len)
{
    size_t pw_len;

    if (password == NULL || owned == NULL || secret == NULL || secret_len == NULL) {
        return VTY_E_INVALID;
    }
    *owned = NULL;
    *secret = (const uint8_t *)password;
    *secret_len = strlen(password);
    if (keyfile_digest == NULL) return VTY_OK;

    if (*secret_len > 1024u) return VTY_E_INVALID;
    {
        /* 固定分配上限：free_user_secret 以同一长度清零/释放，避免
         * 变长分配在清零时越界。 */
        size_t alloc_len = 4u + 1024u + 4u + VTY_KEY_BYTES;
        size_t used_len = 4u + *secret_len + 4u + VTY_KEY_BYTES;
        uint8_t *buf = (uint8_t *)vty_alloc(alloc_len);

        if (buf == NULL) return VTY_E_RESOURCE;
        put_u32le(buf, (uint32_t)*secret_len);
        memcpy(buf + 4u, password, *secret_len);
        put_u32le(buf + 4u + *secret_len, VTY_KEY_BYTES);
        memcpy(buf + 8u + *secret_len, keyfile_digest, VTY_KEY_BYTES);
        *owned = buf;
        *secret = buf;
        *secret_len = used_len;
    }
    return VTY_OK;
}

static void free_user_secret(uint8_t *owned)
{
    if (owned != NULL) {
        vty_secure_zero(owned, 4u + 1024u + 4u + VTY_KEY_BYTES);
        vty_free(owned, 4u + 1024u + 4u + VTY_KEY_BYTES);
    }
}

static int seal_user_slot(VtySlot *s, uint8_t slot_type, uint8_t slot_flags,
                          const char *password, const uint8_t *keyfile_digest,
                          const uint8_t key[VTY_KEY_BYTES],
                          const VtyHeader *h, uint32_t index,
                          uint32_t mem_kib, uint32_t iters, uint32_t parallel)
{
    uint8_t *owned = NULL;
    const uint8_t *secret = NULL;
    size_t secret_len = 0;
    int rc;

    rc = make_user_secret(password, keyfile_digest, &owned, &secret, &secret_len);
    if (rc == VTY_OK) {
        rc = vty_slot_seal_argon2id(s, slot_type, slot_flags, secret, secret_len,
                                    key, h, index, mem_kib, iters, parallel);
    }
    free_user_secret(owned);
    return rc;
}

static int open_user_slot(const VtySlot *s, const char *password,
                          const uint8_t *keyfile_digest,
                          const VtyHeader *h, uint32_t index,
                          uint8_t key_out[VTY_KEY_BYTES])
{
    uint8_t *owned = NULL;
    const uint8_t *secret = NULL;
    size_t secret_len = 0;
    int rc;

    rc = make_user_secret(password, keyfile_digest, &owned, &secret, &secret_len);
    if (rc == VTY_OK) {
        rc = vty_slot_open_argon2id(s, secret, secret_len, h, index, key_out);
    }
    free_user_secret(owned);
    return rc;
}

/* 读取并解析 VKFL，返回 KDF 摘要。keyfile 只在本进程内存中出现。 */
static int load_keyfile_digest(const char *path, uint8_t digest[VTY_KEY_BYTES])
{
    wchar_t *wpath;
    HANDLE h;
    DWORD attrs;
    LARGE_INTEGER size;
    uint8_t blob[VTY_KEYFILE_BLOB_BYTES];
    uint8_t secret[VTY_KEYFILE_SECRET_BYTES];
    DWORD got = 0;
    int rc;

    if (path == NULL || digest == NULL) return VTY_E_KEYFILE_REQUIRED;
    wpath = utf8_to_wide(path);
    if (wpath == NULL) return VTY_E_KEYFILE_INVALID;
    attrs = GetFileAttributesW(wpath);
    if (attrs == INVALID_FILE_ATTRIBUTES ||
        (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        free(wpath);
        return VTY_E_KEYFILE_INVALID;
    }
    h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);
    if (h == INVALID_HANDLE_VALUE) return VTY_E_KEYFILE_INVALID;

    memset(blob, 0, sizeof(blob));
    memset(secret, 0, sizeof(secret));
    if (!GetFileSizeEx(h, &size) || size.QuadPart != (LONGLONG)VTY_KEYFILE_BLOB_BYTES) {
        CloseHandle(h);
        return VTY_E_KEYFILE_INVALID;
    }
    if (!ReadFile(h, blob, (DWORD)sizeof(blob), &got, NULL) ||
        got != (DWORD)sizeof(blob)) {
        CloseHandle(h);
        vty_secure_zero(blob, sizeof(blob));
        return VTY_E_KEYFILE_INVALID;
    }
    CloseHandle(h);

    rc = vty_keyfile_parse(blob, sizeof(blob), secret);
    if (rc == VTY_OK) rc = vty_keyfile_digest(secret, digest);
    vty_secure_zero(blob, sizeof(blob));
    vty_secure_zero(secret, sizeof(secret));
    return rc;
}

/* 生成 VKFL 并原子落盘：临时文件独占创建 → FlushFileBuffers →
 * MoveFileExW(WRITE_THROUGH，不覆盖)。目标已存在返回 VTY_E_EXISTS；
 * 任何失败都不留下目标文件或临时文件。 */
static void delete_file_utf8(const char *path)
{
    wchar_t *w;

    if (path == NULL) return;
    w = utf8_to_wide(path);
    if (w != NULL) {
        (void)DeleteFileW(w);
        free(w);
    }
}

static int write_keyfile_file(const char *path,
                              const uint8_t *blob, size_t blob_len)
{
    wchar_t *base = NULL;
    wchar_t *tmp = NULL;
    size_t base_len;
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    int attempt;
    int rc = VTY_E_IO;

    if (path == NULL || blob == NULL || blob_len != VTY_KEYFILE_BLOB_BYTES ||
        path[0] == '\0') {
        return VTY_E_INVALID;
    }
    base = utf8_to_wide(path);
    if (base == NULL) return VTY_E_INVALID;
    if (GetFileAttributesW(base) != INVALID_FILE_ATTRIBUTES) {
        free(base);
        return VTY_E_EXISTS;
    }
    base_len = wcslen(base);
    tmp = (wchar_t *)malloc((base_len + 16u) * sizeof(wchar_t));
    if (tmp == NULL) {
        free(base);
        return VTY_E_RESOURCE;
    }

    for (attempt = 0; attempt < 4; attempt++) {
        uint32_t rnd = 0;
        size_t i;

        memcpy(tmp, base, base_len * sizeof(wchar_t));
        tmp[base_len + 0] = L'.';
        tmp[base_len + 1] = L't';
        tmp[base_len + 2] = L'm';
        tmp[base_len + 3] = L'p';
        tmp[base_len + 4] = L'-';
        vty_random((uint8_t *)&rnd, sizeof(rnd));
        for (i = 0; i < 8u; i++) {
            uint32_t nibble = (rnd >> (28u - 4u * (uint32_t)i)) & 0xFu;
            tmp[base_len + 5u + i] = (wchar_t)(nibble < 10u
                ? (L'0' + (wchar_t)nibble)
                : (L'a' + (wchar_t)(nibble - 10u)));
        }
        tmp[base_len + 13u] = L'\0';
        h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_FILE_EXISTS) {
            rc = VTY_E_IO;
            goto out;
        }
    }
    if (h == INVALID_HANDLE_VALUE) {
        rc = VTY_E_IO;
        goto out;
    }

    /* 临时文件已独占创建；从这里开始成功路径必须显式把 rc 置 OK。 */
    rc = VTY_OK;
    if (!WriteFile(h, blob, (DWORD)blob_len, &written, NULL) ||
        written != (DWORD)blob_len || !FlushFileBuffers(h)) {
        rc = VTY_E_IO;
    }
    CloseHandle(h);
    h = INVALID_HANDLE_VALUE;
    if (rc != VTY_OK) goto out;

    if (!MoveFileExW(tmp, base, MOVEFILE_WRITE_THROUGH)) {
        DWORD err = GetLastError();
        rc = (err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS)
                 ? VTY_E_EXISTS : VTY_E_IO;
        goto out;
    }
    rc = VTY_OK;

out:
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (rc != VTY_OK) (void)DeleteFileW(tmp);
    free(tmp);
    free(base);
    return rc;
}

static int read_range(const char *path, uint64_t offset,
                      uint8_t *buf, size_t len, uint64_t *file_size)
{
    wchar_t *wpath;
    HANDLE h;
    LARGE_INTEGER size;
    LARGE_INTEGER pos;
    OVERLAPPED ov;
    DWORD got = 0;
    int rc = VTY_OK;

    if (path == NULL || buf == NULL || len == 0 || len > 0xFFFFFFFFu) return VTY_E_INVALID;
    wpath = utf8_to_wide(path);
    if (wpath == NULL) return VTY_E_INVALID;
    h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);
    if (h == INVALID_HANDLE_VALUE) return VTY_E_IO;

    /* 读者持元数据区共享锁：与保存的独占锁互斥，避免读到写了一半的
     * A/B 副本组合。 */
    memset(&ov, 0, sizeof(ov));
    if (!LockFileEx(h, 0, 0, VTY_DATA_OFFSET, 0, &ov)) {
        CloseHandle(h);
        return VTY_E_IO;
    }

    if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0) {
        (void)UnlockFileEx(h, 0, VTY_DATA_OFFSET, 0, &ov);
        CloseHandle(h);
        return VTY_E_IO;
    }
    if (file_size != NULL) *file_size = (uint64_t)size.QuadPart;
    if (offset > (uint64_t)size.QuadPart ||
        len > (size_t)((uint64_t)size.QuadPart - offset)) {
        (void)UnlockFileEx(h, 0, VTY_DATA_OFFSET, 0, &ov);
        CloseHandle(h);
        return VTY_E_INVALID;
    }

    pos.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN) ||
        !ReadFile(h, buf, (DWORD)len, &got, NULL) || got != (DWORD)len) {
        rc = VTY_E_IO;
    }
    (void)UnlockFileEx(h, 0, VTY_DATA_OFFSET, 0, &ov);
    CloseHandle(h);
    return rc;
}

static int write_range_locked(const char *path, uint64_t offset,
                              const uint8_t *buf, size_t len)
{
    wchar_t *wpath;
    HANDLE h = INVALID_HANDLE_VALUE;
    LARGE_INTEGER pos;
    OVERLAPPED ov;
    DWORD written = 0;
    int rc = VTY_OK;

    if (path == NULL || buf == NULL || len == 0 || len > 0xFFFFFFFFu) return VTY_E_INVALID;
    wpath = utf8_to_wide(path);
    if (wpath == NULL) return VTY_E_INVALID;
    /* 会话内 store 已持有同一文件的读写句柄；元数据保存必须以
     * 共享读写方式打开，否则二次打开会被共享检查拒绝（E_IO）。 */
    h = CreateFileW(wpath, GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);
    if (h == INVALID_HANDLE_VALUE) return VTY_E_IO;

    /* 锁住整个元数据区，而不是单个副本：读者可能同时读 A/B 两份，
     * 只锁被写副本无法阻止“读到一半切换”的跨副本不一致。 */
    memset(&ov, 0, sizeof(ov));
    if (!LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0, VTY_DATA_OFFSET, 0, &ov)) {
        CloseHandle(h);
        return VTY_E_IO;
    }

    pos.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, pos, NULL, FILE_BEGIN) ||
        !WriteFile(h, buf, (DWORD)len, &written, NULL) || written != (DWORD)len ||
        !FlushFileBuffers(h)) {
        rc = VTY_E_IO;
    }
    (void)UnlockFileEx(h, 0, VTY_DATA_OFFSET, 0, &ov);
    CloseHandle(h);
    return rc;
}

static int create_meta_file(const char *path, const uint8_t copy[VTY_META_COPY_BYTES])
{
    wchar_t *wpath;
    HANDLE h;
    uint8_t *file;
    DWORD written = 0;
    int rc = VTY_OK;

    if (path == NULL || copy == NULL) return VTY_E_INVALID;
    file = (uint8_t *)vty_alloc(VTY_DATA_OFFSET);
    if (file == NULL) return VTY_E_RESOURCE;
    memcpy(file, copy, VTY_META_COPY_BYTES);
    memcpy(file + VTY_META_COPY_BYTES, copy, VTY_META_COPY_BYTES);

    wpath = utf8_to_wide(path);
    if (wpath == NULL) {
        vty_free(file, VTY_DATA_OFFSET);
        return VTY_E_INVALID;
    }
    h = CreateFileW(wpath, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);
    if (h == INVALID_HANDLE_VALUE) {
        vty_free(file, VTY_DATA_OFFSET);
        return VTY_E_IO;
    }
    if (!WriteFile(h, file, (DWORD)VTY_DATA_OFFSET, &written, NULL) ||
        written != (DWORD)VTY_DATA_OFFSET || !FlushFileBuffers(h)) {
        rc = VTY_E_IO;
    }
    CloseHandle(h);
    vty_free(file, VTY_DATA_OFFSET);
    if (rc != VTY_OK) {
        wchar_t *w = utf8_to_wide(path);
        if (w != NULL) {
            DeleteFileW(w);
            free(w);
        }
    }
    return rc;
}

/* body AAD = 域串 || uuid || epoch || generation || keyring_len || header_digest。
 * header_digest 绑定固定头与整段槽区，使“删槽/清标志/换 minor”无法
 * 只改明文头就生效。 */
static void body_aad(const uint8_t uuid[VTY_UUID_BYTES], uint64_t epoch,
                     uint64_t generation, uint32_t keyring_len,
                     const uint8_t digest[VTY_HASH_BYTES],
                     uint8_t out[VTY_BODY_AAD_MAX], size_t *out_len)
{
    const char *domain = VTY_DOMAIN_KEYRING;
    size_t dlen = strlen(domain);
    size_t off = dlen;

    memcpy(out, domain, dlen);
    memcpy(out + off, uuid, VTY_UUID_BYTES); off += VTY_UUID_BYTES;
    vty_put_u64(out + off, epoch); off += 8u;
    vty_put_u64(out + off, generation); off += 8u;
    vty_put_u32(out + off, keyring_len); off += 4u;
    memcpy(out + off, digest, VTY_HASH_BYTES); off += VTY_HASH_BYTES;
    *out_len = off;
}

static int keyring_set_data_root(VtyKeyring *kr,
                                 const uint8_t hash[VTY_HASH_BYTES],
                                 const VtyDataRootLocator *loc)
{
    uint8_t enc[VTY_DATA_ROOT_BYTES];
    uint32_t i;
    int rc;

    rc = vty_data_root_encode(loc, enc);
    if (rc != VTY_OK) return rc;

    for (i = 0; i < kr->count; i++) {
        if (kr->entries[i].kind == VTY_KEYKIND_DATA_ROOT) {
            kr->entries[i].id_len = VTY_DATA_ROOT_BYTES;
            memcpy(kr->entries[i].id, enc, VTY_DATA_ROOT_BYTES);
            memcpy(kr->entries[i].key, hash, VTY_HASH_BYTES);
            return VTY_OK;
        }
    }
    if (kr->count >= VTY_KEYRING_MAX_ENTRIES) return VTY_E_RESOURCE;
    memset(&kr->entries[kr->count], 0, sizeof(kr->entries[0]));
    kr->entries[kr->count].kind = VTY_KEYKIND_DATA_ROOT;
    kr->entries[kr->count].id_len = VTY_DATA_ROOT_BYTES;
    memcpy(kr->entries[kr->count].id, enc, VTY_DATA_ROOT_BYTES);
    memcpy(kr->entries[kr->count].key, hash, VTY_HASH_BYTES);
    kr->count++;
    return VTY_OK;
}

static int keyring_take_data_root(const VtyKeyring *kr,
                                  const uint8_t uuid[VTY_UUID_BYTES], uint64_t epoch,
                                  VtyDataRootLocator *loc,
                                  uint8_t hash[VTY_HASH_BYTES])
{
    VtyKeyEntry e;
    uint8_t expect[VTY_HASH_BYTES];
    int rc;

    memset(&e, 0, sizeof(e));
    rc = vty_keyring_find_entry(kr, VTY_KEYKIND_DATA_ROOT, NULL, 0, &e);
    if (rc != VTY_OK) return VTY_E_CORRUPT;
    if (e.id_len != VTY_DATA_ROOT_BYTES) return VTY_E_CORRUPT;
    rc = vty_data_root_decode(e.id, loc);
    if (rc != VTY_OK) return rc;
    memcpy(hash, e.key, VTY_HASH_BYTES);

    if (loc->root_node_id == 0u) {
        uint8_t empty[VTY_HASH_BYTES];
        rc = vty_store_empty_root(uuid, epoch, empty);
        if (rc != VTY_OK) return rc;
        rc = vty_store_data_root(uuid, epoch, empty, expect);
        if (rc != VTY_OK) return rc;
        if (vty_ct_equal(expect, hash, VTY_HASH_BYTES) != 0) return VTY_E_CORRUPT;
    }
    return VTY_OK;
}

/* 构建一份完整 meta copy（header+slots+body），用于创建或保存。 */
static int build_meta_copy(const VtyVault *v, uint8_t *copy, size_t *body_len_out)
{
    uint8_t plain[VTY_KEYRING_MAX_BYTES];
    uint8_t aad[VTY_BODY_AAD_MAX];
    uint8_t digest[VTY_HASH_BYTES];
    size_t plain_len = 0;
    size_t slots_len = 0;
    size_t header_len;
    size_t body_len;
    size_t aad_len = 0;
    size_t ct_len = 0;
    uint32_t i;
    int rc;

    if (v == NULL || copy == NULL || body_len_out == NULL) return VTY_E_INVALID;

    rc = vty_keyring_serialize(&v->keyring, plain, sizeof(plain), &plain_len);
    if (rc != VTY_OK) return rc;
    for (i = 0; i < v->slot_count; i++) {
        slots_len += vty_slot_serialized_len(&v->slots[i]);
    }
    header_len = VTY_HEADER_FIXED_BYTES + slots_len + VTY_HEADER_HASH_BYTES;
    body_len = VTY_BODY_NONCE + plain_len + VTY_TAG_BYTES;
    if (header_len > VTY_META_COPY_BYTES ||
        header_len + body_len > VTY_META_COPY_BYTES) {
        vty_secure_zero(plain, sizeof(plain));
        return VTY_E_RESOURCE;
    }

    memset(copy, 0, VTY_META_COPY_BYTES);
    {
        VtyHeader h = v->header;
        h.header_len = (uint16_t)header_len;
        h.slot_count = (uint16_t)v->slot_count;
        h.keyring_len = (uint32_t)plain_len;
        rc = vty_header_write_fixed(&h, copy, VTY_META_COPY_BYTES);
        if (rc != VTY_OK) goto out;
    }

    {
        size_t off = VTY_HEADER_FIXED_BYTES;
        for (i = 0; i < v->slot_count; i++) {
            size_t w = 0;
            rc = vty_slot_write(&v->slots[i], i, &v->header, copy + off,
                                header_len - off, &w);
            if (rc != VTY_OK) goto out;
            off += w;
        }
    }

    rc = vty_header_finalize(copy, header_len);
    if (rc != VTY_OK) goto out;
    rc = vty_header_digest(copy, header_len, digest);
    if (rc != VTY_OK) goto out;

    body_aad(v->header.vault_uuid, v->header.epoch, v->header.generation,
             (uint32_t)plain_len, digest, aad, &aad_len);
    vty_random(copy + header_len, VTY_BODY_NONCE);
    rc = vty_aead_seal(v->kc, copy + header_len, aad, aad_len, plain, plain_len,
                       copy + header_len + VTY_BODY_NONCE,
                       VTY_META_COPY_BYTES - header_len - VTY_BODY_NONCE,
                       &ct_len);
    if (rc == VTY_OK) {
        if (ct_len != plain_len + VTY_TAG_BYTES) rc = VTY_E_CORRUPT;
        else *body_len_out = VTY_BODY_NONCE + ct_len;
    }

out:
    vty_secure_zero(plain, sizeof(plain));
    vty_secure_zero(aad, sizeof(aad));
    vty_secure_zero(digest, sizeof(digest));
    return rc;
}

static int parse_meta_copy(uint8_t *header_buf, uint32_t index, VtyMetaCopy *out)
{
    VtyMetaCopy c;
    size_t body_len;
    int rc;

    if (header_buf == NULL || out == NULL) return VTY_E_INVALID;
    memset(&c, 0, sizeof(c));
    c.index = index;
    c.header_buf = header_buf;

    rc = vty_header_parse(header_buf, VTY_META_COPY_BYTES, &c.h);
    if (rc != VTY_OK) return rc;
    if (c.h.keyring_len == 0u) return VTY_E_CORRUPT;

    body_len = VTY_BODY_NONCE + (size_t)c.h.keyring_len + VTY_TAG_BYTES;
    if ((size_t)c.h.header_len + body_len > VTY_META_COPY_BYTES) {
        return VTY_E_CORRUPT;
    }

    rc = vty_slots_parse_all(header_buf, c.h.header_len, &c.h,
                             c.slots, VTY_MAX_SLOTS, &c.slot_count);
    if (rc != VTY_OK) return rc;
    if (c.slot_count != c.h.slot_count) return VTY_E_CORRUPT;

    rc = vty_header_digest(header_buf, c.h.header_len, c.digest);
    if (rc != VTY_OK) return rc;

    c.body = header_buf + c.h.header_len;
    c.body_len = body_len;
    c.valid = 1;
    *out = c;
    return VTY_OK;
}

static int open_body_copy(const VtyHeader *h, const uint8_t digest[VTY_HASH_BYTES],
                          const uint8_t *body, size_t body_len,
                          const uint8_t kc[VTY_KEY_BYTES], VtyKeyring *out)
{
    uint8_t plain[VTY_KEYRING_MAX_BYTES];
    uint8_t aad[VTY_BODY_AAD_MAX];
    uint8_t check[VTY_KEY_BYTES];
    size_t aad_len = 0;
    size_t plain_len = 0;
    int rc;

    if (h == NULL || digest == NULL || body == NULL || out == NULL || kc == NULL) {
        return VTY_E_INVALID;
    }
    if (body_len != VTY_BODY_NONCE + (size_t)h->keyring_len + VTY_TAG_BYTES) {
        return VTY_E_CORRUPT;
    }

    body_aad(h->vault_uuid, h->epoch, h->generation, h->keyring_len,
             digest, aad, &aad_len);
    rc = vty_aead_open(kc, body, aad, aad_len,
                       body + VTY_BODY_NONCE, body_len - VTY_BODY_NONCE,
                       plain, sizeof(plain), &plain_len);
    if (rc == VTY_OK) {
        rc = vty_keyring_parse(plain, plain_len, out);
    }
    if (rc == VTY_OK) {
        memset(check, 0, sizeof(check));
        rc = vty_keyring_find(out, VTY_KEYKIND_KC, NULL, 0, check);
        if (rc == VTY_OK) {
            if (vty_ct_equal(check, kc, VTY_KEY_BYTES) != 0) rc = VTY_E_KEY_INVALID;
        }
        vty_secure_zero(check, sizeof(check));
    }

    vty_secure_zero(plain, sizeof(plain));
    vty_secure_zero(aad, sizeof(aad));
    return rc;
}

static int load_meta(const char *path, uint8_t **meta_out, uint64_t *file_size,
                     VtyMetaCopy copies[VTY_META_COPIES])
{
    uint8_t *meta;
    uint32_t i;
    int first_error = VTY_OK;
    int valid_count = 0;

    if (path == NULL || meta_out == NULL || file_size == NULL || copies == NULL) {
        return VTY_E_INVALID;
    }
    *meta_out = NULL;
    memset(copies, 0, sizeof(VtyMetaCopy) * VTY_META_COPIES);

    meta = (uint8_t *)vty_alloc(VTY_DATA_OFFSET);
    if (meta == NULL) return VTY_E_RESOURCE;
    if (read_range(path, 0, meta, VTY_DATA_OFFSET, file_size) != VTY_OK) {
        vty_free(meta, VTY_DATA_OFFSET);
        return VTY_E_INVALID;
    }

    for (i = 0; i < VTY_META_COPIES; i++) {
        int rc = parse_meta_copy(meta + (size_t)i * VTY_META_COPY_BYTES, i,
                                 &copies[i]);
        if (rc == VTY_OK) {
            valid_count++;
        } else if (first_error == VTY_OK) {
            first_error = rc;
        }
    }
    if (valid_count == 0) {
        vty_free(meta, VTY_DATA_OFFSET);
        return first_error == VTY_OK ? VTY_E_CORRUPT : first_error;
    }

    /* 同代不同内容意味着两份副本被分叉写入；无法判断哪份是真实提交，
     * 只能拒绝，不能按“看起来更新”的一方继续。 */
    if (copies[0].valid && copies[1].valid &&
        copies[0].h.generation == copies[1].h.generation) {
        if (memcmp(copies[0].digest, copies[1].digest, VTY_HASH_BYTES) != 0 ||
            copies[0].body_len != copies[1].body_len ||
            memcmp(copies[0].body, copies[1].body, copies[0].body_len) != 0) {
            /* 同代分叉：头/槽或 body 任一不同都无法判定真实提交。 */
            vty_free(meta, VTY_DATA_OFFSET);
            return VTY_E_CORRUPT;
        }
    }

    if (copies[1].valid &&
        (!copies[0].valid || copies[1].h.generation > copies[0].h.generation)) {
        VtyMetaCopy tmp = copies[0];
        copies[0] = copies[1];
        copies[1] = tmp;
    }

    *meta_out = meta;
    return VTY_OK;
}

static int slot_area_equal(const VtyMetaCopy *a, const VtyMetaCopy *b)
{
    size_t alen, blen;
    if (!a->valid || !b->valid) return 0;
    alen = vty_header_slots_len(&a->h);
    blen = vty_header_slots_len(&b->h);
    if (alen != blen) return 0;
    return memcmp(a->header_buf + VTY_HEADER_FIXED_BYTES,
                  b->header_buf + VTY_HEADER_FIXED_BYTES, alen) == 0;
}

static int add_module_entries(VtyKeyring *kr)
{
    uint32_t i;
    uint8_t count = kr->count;

    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        VtyKeyEntry *e;
        if (count >= VTY_KEYRING_MAX_ENTRIES) return VTY_E_INVALID;
        e = &kr->entries[count];
        memset(e, 0, sizeof(*e));
        e->kind = VTY_KEYKIND_MDEK;
        e->id_len = VTY_UUID_BYTES;
        vty_random(e->id, VTY_UUID_BYTES);
        vty_random(e->key, VTY_KEY_BYTES);
        count++;
    }
    kr->count = count;
    return VTY_OK;
}

/* 非 static：产品 .rhat X 清单需以外部符号哈希覆盖创建/解锁主路径；
 * 公开 wrapper 仅 16–49 字节，单独哈希无保护意义。本符号不导出
 *（verthys.def 白名单外），外部不可达。noinline 是"被哈希代码体 =
 * 实际执行代码体"的语义前提。 */
__declspec(noinline) int vty_vault_create_internal(const char *path,
                                 const char *password,
                                 uint32_t mem_kib, uint32_t iters, uint32_t parallel,
                                 uint32_t pcr_select,
                                 const uint8_t *keyfile_blob, size_t keyfile_len,
                                 VtyVault **out,
                                 char *recovery_text, size_t recovery_cap)
{
    VtyVault *v;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t code[VTY_RECOVERY_CODE_BYTES] = {0};
    uint8_t keyfile_secret[VTY_KEYFILE_SECRET_BYTES];
    uint8_t keyfile_digest[VTY_KEY_BYTES];
    const uint8_t *kdf_keyfile = NULL;
    uint8_t *copy = NULL;
    size_t body_len = 0;
    VtySlot *u_slot;
    VtySlot *d_slot;
    VtySlot *r_slot;
    int pcr_key_created = 0;
    int rc;

    memset(keyfile_secret, 0, sizeof(keyfile_secret));
    memset(keyfile_digest, 0, sizeof(keyfile_digest));
    if (path == NULL || password == NULL || out == NULL) return VTY_E_INVALID;
    if (keyfile_blob == NULL && keyfile_len != 0) return VTY_E_INVALID;
    if (keyfile_blob != NULL && keyfile_len != VTY_KEYFILE_BLOB_BYTES) {
        return VTY_E_KEYFILE_INVALID;
    }
    if (password[0] == '\0') return VTY_E_INVALID;
    if (recovery_text == NULL) return VTY_E_INVALID;
    if (recovery_cap < VTY_RECOVERY_TEXT_BUF) return VTY_E_INVALID;
    if (strlen(path) >= sizeof(((VtyVault *)0)->path)) return VTY_E_INVALID;

    rc = vty_kdf_params_valid(mem_kib, iters, parallel);
    if (rc != VTY_OK) return rc;
    if (pcr_select != 0) {
        rc = vty_tpm_pcr_select_valid(pcr_select);
        if (rc != VTY_OK) return rc;
        if (!vty_tpm_pcr_available()) return VTY_E_TPM;
    }
    if (keyfile_blob != NULL) {
        rc = vty_keyfile_parse(keyfile_blob, keyfile_len, keyfile_secret);
        if (rc != VTY_OK) return rc;
        rc = vty_keyfile_digest(keyfile_secret, keyfile_digest);
        if (rc != VTY_OK) return rc;
        kdf_keyfile = keyfile_digest;
    }
    rc = vty_device_root_init();
    if (rc != VTY_OK) return rc;

    v = (VtyVault *)vty_secure_alloc(sizeof(VtyVault), "vault");
    if (v == NULL) return VTY_E_RESOURCE;
    memcpy(v->path, path, strlen(path) + 1);

    v->mem_kib = mem_kib;
    v->iters = iters;
    v->parallel = parallel;
    v->header.magic = VTY_MAGIC;
    v->header.version_major = VTY_VERSION_MAJOR;
    v->header.version_minor = VTY_VERSION_MINOR;
    /* 模块 MDEK 只是载体；未启用模块策略前不置位，避免把“有 MDEK”
     * 误当成“模块隔离已交付”。 */
    v->header.flags = VTY_FLAG_RECOVERY;
    if (pcr_select != 0) v->header.flags |= VTY_FLAG_PCR;
    if (kdf_keyfile != NULL) v->header.flags |= VTY_FLAG_KEYFILE;
    v->header.epoch = 1;
    v->header.generation = 1;
    vty_random(v->header.vault_uuid, VTY_UUID_BYTES);
    vty_random(v->kc, VTY_KEY_BYTES);

    memset(&v->keyring, 0, sizeof(v->keyring));
    v->keyring.count = 1;
    v->keyring.entries[0].kind = VTY_KEYKIND_KC;
    v->keyring.entries[0].id_len = 0;
    memcpy(v->keyring.entries[0].key, v->kc, VTY_KEY_BYTES);
    rc = add_module_entries(&v->keyring);
    if (rc != VTY_OK) goto fail;

    memset(&v->data_root, 0, sizeof(v->data_root));
    rc = vty_store_empty_locator(v->header.vault_uuid, v->header.epoch,
                                 &v->data_root, v->data_root_hash);
    if (rc != VTY_OK) goto fail;
    rc = keyring_set_data_root(&v->keyring, v->data_root_hash, &v->data_root);
    if (rc != VTY_OK) goto fail;

    vty_random(share_u, VTY_KEY_BYTES);
    {
        size_t i;
        for (i = 0; i < VTY_KEY_BYTES; i++) {
            share_d[i] = (uint8_t)(v->kc[i] ^ share_u[i]);
        }
    }

    u_slot = &v->slots[0];
    d_slot = &v->slots[1];
    r_slot = &v->slots[2];
    v->slot_count = 3;

    rc = seal_user_slot(u_slot, VTY_SLOT_USER_PASSWORD,
                        VTY_SLOT_FLAG_REQUIRED, password, kdf_keyfile,
                        share_u, &v->header, 0, mem_kib, iters, parallel);
    if (rc != VTY_OK) goto fail;

    rc = vty_slot_seal_device(d_slot, VTY_SLOT_FLAG_REQUIRED, share_d,
                              &v->header, 1);
    if (rc != VTY_OK) goto fail;

    rc = vty_recovery_generate(code, recovery_text, recovery_cap);
    if (rc != VTY_OK) goto fail;
    rc = vty_recovery_slot_seal(r_slot, v->kc, code, &v->header, 2,
                                mem_kib, iters, parallel, NULL);
    vty_secure_zero(code, sizeof(code));
    if (rc != VTY_OK) goto fail;

    if (pcr_select != 0) {
        VtySlot *p_slot = &v->slots[3];

        memset(p_slot, 0, sizeof(*p_slot));
        rc = vty_tpm_pcr_key_create(v->header.vault_uuid, pcr_select, NULL, 0);
        if (rc != VTY_OK) goto fail;
        pcr_key_created = 1;
        p_slot->slot_type = VTY_SLOT_DEVICE_PCR;
        p_slot->slot_flags = VTY_SLOT_FLAG_REQUIRED;
        p_slot->kdf_id = VTY_KDF_NONE;
        p_slot->wrap_alg = VTY_WRAP_RSAOAEP;
        p_slot->params_len = VTY_SLOT_PARAMS_PCR;
        p_slot->pcr_select = pcr_select;
        rc = vty_tpm_pcr_measure(pcr_select, p_slot->pcr_digest);
        if (rc != VTY_OK) goto fail;
        rc = vty_tpm_pcr_seal(v->header.vault_uuid, v->kc, p_slot->ct);
        if (rc != VTY_OK) goto fail;
        p_slot->ct_len = VTY_SLOT_PCR_CT_BYTES;
        v->slot_count = 4;
    }

    copy = (uint8_t *)vty_alloc(VTY_META_COPY_BYTES);
    if (copy == NULL) { rc = VTY_E_RESOURCE; goto fail; }
    rc = build_meta_copy(v, copy, &body_len);
    if (rc != VTY_OK) goto fail;
    (void)body_len;
    /* 回填权威头字段（header_len/keyring_len），避免会话内后续保存
     * 用创建前的零值参与预算计算。 */
    rc = vty_header_parse(copy, VTY_META_COPY_BYTES, &v->header);
    if (rc != VTY_OK) goto fail;
    rc = create_meta_file(path, copy);
    if (rc != VTY_OK) goto fail;

    /* 创建后即建立数据区会话：空 DataRoot 也要能被 store 校验，
     * 否则第一次写入前无法复用同一提交路径。 */
    rc = vty_store_open(v->path, v->kc, v->header.vault_uuid, v->header.epoch,
                        &v->data_root, v->data_root_hash, &v->store);
    if (rc != VTY_OK) goto fail;

    v->active_copy = 0;
    v->unlocked = 1;

    /* 模块表必须在创建时落盘：模块 UUID 不能依赖 Keyring 条目顺序，
     * 且启用后 kind 3 条目会被删除。先提交数据区，再写一次元数据。 */
    rc = vty_module_table_init(v);
    if (rc == VTY_OK) rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) goto fail;

    if (kdf_keyfile != NULL) {
        memcpy(v->keyfile_digest, kdf_keyfile, VTY_KEY_BYTES);
        v->keyfile_digest_set = 1;
    }
    vty_free(copy, VTY_META_COPY_BYTES);
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(keyfile_secret, sizeof(keyfile_secret));
    vty_secure_zero(keyfile_digest, sizeof(keyfile_digest));
    *out = v;
    return VTY_OK;

fail:
    if (copy != NULL) vty_free(copy, VTY_META_COPY_BYTES);
    if (pcr_key_created) {
        (void)vty_tpm_pcr_key_delete(v->header.vault_uuid);
    }
    /* 创建中途失败不得留下不可打开的半成品库。必须先释放会话（关闭
     * store 句柄）再删除文件：Windows 上以共享读写打开的句柄会让
     * DeleteFileW 失败，既留下孤儿文件、又把真实错误改写成 E_IO
     * （worker 再把 IO 统一成 AUTH，上层就看不到根因）。删除失败只
     * 记为残留，不覆盖原始错误码。 */
    {
        wchar_t *w = NULL;
        if (v != NULL && v->path[0] != '\0') w = utf8_to_wide(v->path);
        vty_vault_free(v);
        if (w != NULL) {
            (void)DeleteFileW(w);
            free(w);
        }
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(code, sizeof(code));
    vty_secure_zero(keyfile_secret, sizeof(keyfile_secret));
    vty_secure_zero(keyfile_digest, sizeof(keyfile_digest));
    return rc;
}

int vty_vault_create_ex(const char *path, const char *password,
                        uint32_t mem_kib, uint32_t iters, uint32_t parallel,
                        VtyVault **out,
                        char *recovery_text, size_t recovery_cap)
{
    return vty_vault_create_internal(path, password, mem_kib, iters, parallel, 0,
                                 NULL, 0, out, recovery_text, recovery_cap);
}

int vty_vault_create_keyfile(const char *path, const char *password,
                             const uint8_t *keyfile_blob, size_t keyfile_len,
                             VtyVault **out,
                             char *recovery_text, size_t recovery_cap)
{
    return vty_vault_create_internal(path, password,
                                 VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN, 1,
                                 0, keyfile_blob, keyfile_len,
                                 out, recovery_text, recovery_cap);
}

int vty_vault_create_keyfile_file(const char *path, const char *password,
                                  const char *keyfile_path, VtyVault **out,
                                  char *recovery_text, size_t recovery_cap)
{
    uint8_t blob[VTY_KEYFILE_BLOB_BYTES];
    int rc;

    memset(blob, 0, sizeof(blob));
    if (keyfile_path == NULL) return VTY_E_KEYFILE_REQUIRED;
    rc = vty_keyfile_generate(blob);
    if (rc == VTY_OK) {
        rc = write_keyfile_file(keyfile_path, blob, sizeof(blob));
    }
    if (rc == VTY_OK) {
        rc = vty_vault_create_internal(path, password,
                                   VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN, 1,
                                   0, blob, sizeof(blob), out,
                                   recovery_text, recovery_cap);
        /* 库没有建成时不得留下一个“孤儿 keyfile”：用户会误以为它
         * 对应某个库。 */
        if (rc != VTY_OK) delete_file_utf8(keyfile_path);
    }
    vty_secure_zero(blob, sizeof(blob));
    return rc;
}

int vty_vault_create_pcr(const char *path, const char *password,
                         uint32_t pcr_select,
                         VtyVault **out,
                         char *recovery_text, size_t recovery_cap)
{
    return vty_vault_create_internal(path, password,
                                 VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN, 1,
                                 pcr_select, NULL, 0,
                                 out, recovery_text, recovery_cap);
}

int vty_vault_create(const char *path, const char *password,
                     VtyVault **out,
                     char *recovery_text, size_t recovery_cap)
{
    return vty_vault_create_ex(path, password,
                               VTY_ARGON2_MEM_KIB_MIN, VTY_ARGON2_ITERS_MIN, 1,
                               out, recovery_text, recovery_cap);
}

static int bytes_all_zero(const uint8_t *p, size_t n)
{
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* 轮换：以恢复会话的 K_recovery 与源库槽参数重建一个新库文件。
 * 只用于全库 DEK 轮换；调用方负责生命周期与原子替换。 */
int vty_vault_create_from_kc(const VtyVault *src, const char *path,
                             const char *password,
                             const uint8_t kc[VTY_KEY_BYTES],
                             uint16_t flags,
                             const uint8_t *keyfile_digest_or_null,
                             VtyVault **out)
{
    VtyVault *v = NULL;
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t digest[VTY_KEY_BYTES];
    uint8_t *copy = NULL;
    size_t body_len = 0;
    int u_idx, r_idx;
    uint32_t mem_kib, iters, parallel;
    size_t i;
    int file_created = 0;
    int rc;

    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    memset(digest, 0, sizeof(digest));
    if (out != NULL) *out = NULL;
    if (src == NULL || path == NULL || password == NULL || kc == NULL ||
        out == NULL) {
        return VTY_E_INVALID;
    }
    if (!src->unlocked || !src->recovery_mode) return VTY_E_POLICY;
    if (path[0] == '\0' || password[0] == '\0') return VTY_E_INVALID;
    if (strlen(path) >= sizeof(((VtyVault *)0)->path)) return VTY_E_INVALID;
    if ((flags & (uint16_t)~VTY_FLAG_KNOWN_MASK) != 0) return VTY_E_INVALID;
    if ((flags & VTY_FLAG_RECOVERY) == 0) return VTY_E_INVALID;
    if ((flags & VTY_FLAG_KEYFILE) != 0 && keyfile_digest_or_null == NULL) {
        return VTY_E_KEYFILE_REQUIRED;
    }
    if ((flags & VTY_FLAG_KEYFILE) == 0 && keyfile_digest_or_null != NULL) {
        return VTY_E_INVALID;
    }
    /* 没有恢复 KEK 就无法把同一恢复码延续到新库；降级为“恢复码失效”的
     * 换库不在本阶段允许范围内。 */
    if (bytes_all_zero(src->k_recovery, VTY_KEY_BYTES)) return VTY_E_POLICY;
    if (src->header.epoch == UINT64_MAX ||
        src->header.generation == UINT64_MAX) {
        return VTY_E_RESOURCE;
    }

    u_idx = vty_slot_find(src->slots, src->slot_count, VTY_SLOT_USER_PASSWORD);
    r_idx = vty_slot_find(src->slots, src->slot_count, VTY_SLOT_RECOVERY);
    if (u_idx < 0 || r_idx < 0) return VTY_E_SLOT_MISSING;

    /* 用户槽 KDF 参数必须沿用源库实际槽值，而不是恢复槽参数：两者在
     * 旧版策略下可能不同，沿用错误参数会让新库只能用另一个代价打开。 */
    mem_kib = src->slots[u_idx].m_cost;
    iters = src->slots[u_idx].t_cost;
    parallel = src->slots[u_idx].p_cost;
    rc = vty_kdf_params_valid(mem_kib, iters, parallel);
    if (rc != VTY_OK) return rc;
    if (keyfile_digest_or_null != NULL) {
        memcpy(digest, keyfile_digest_or_null, VTY_KEY_BYTES);
    }

    v = (VtyVault *)vty_secure_alloc(sizeof(VtyVault), "vault");
    if (v == NULL) return VTY_E_RESOURCE;
    memcpy(v->path, path, strlen(path) + 1);
    v->mem_kib = mem_kib;
    v->iters = iters;
    v->parallel = parallel;

    v->header.magic = VTY_MAGIC;
    v->header.version_major = VTY_VERSION_MAJOR;
    v->header.version_minor = VTY_VERSION_MINOR;
    v->header.flags = flags;
    v->header.epoch = src->header.epoch + 1u;
    v->header.generation = src->header.generation + 1u;
    memcpy(v->header.vault_uuid, src->header.vault_uuid, VTY_UUID_BYTES);
    memcpy(v->kc, kc, VTY_KEY_BYTES);

    memset(&v->keyring, 0, sizeof(v->keyring));
    v->keyring.count = 1;
    v->keyring.entries[0].kind = VTY_KEYKIND_KC;
    v->keyring.entries[0].id_len = 0;
    memcpy(v->keyring.entries[0].key, v->kc, VTY_KEY_BYTES);
    rc = add_module_entries(&v->keyring);
    if (rc != VTY_OK) goto fail;

    memset(&v->data_root, 0, sizeof(v->data_root));
    rc = vty_store_empty_locator(v->header.vault_uuid, v->header.epoch,
                                 &v->data_root, v->data_root_hash);
    if (rc != VTY_OK) goto fail;
    rc = keyring_set_data_root(&v->keyring, v->data_root_hash, &v->data_root);
    if (rc != VTY_OK) goto fail;

    vty_random(share_u, VTY_KEY_BYTES);
    for (i = 0; i < VTY_KEY_BYTES; i++) {
        share_d[i] = (uint8_t)(v->kc[i] ^ share_u[i]);
    }

    v->slot_count = 3;
    rc = seal_user_slot(&v->slots[0], VTY_SLOT_USER_PASSWORD,
                        VTY_SLOT_FLAG_REQUIRED, password,
                        keyfile_digest_or_null != NULL ? digest : NULL,
                        share_u, &v->header, 0, mem_kib, iters, parallel);
    if (rc != VTY_OK) goto fail;
    rc = vty_slot_seal_device(&v->slots[1], VTY_SLOT_FLAG_REQUIRED, share_d,
                              &v->header, 1);
    if (rc != VTY_OK) goto fail;

    /* 恢复槽复用源槽的 salt 与 KDF 参数（KEK 才能与旧恢复码一致），
     * 换新 nonce 并用 KEK 包裹新 K_c。 */
    v->slots[2] = src->slots[r_idx];
    rc = vty_recovery_slot_reseal(&v->slots[2], v->kc, src->k_recovery,
                                  &v->header, 2u);
    if (rc != VTY_OK) goto fail;

    copy = (uint8_t *)vty_alloc(VTY_META_COPY_BYTES);
    if (copy == NULL) { rc = VTY_E_RESOURCE; goto fail; }
    rc = build_meta_copy(v, copy, &body_len);
    if (rc != VTY_OK) goto fail;
    (void)body_len;
    rc = vty_header_parse(copy, VTY_META_COPY_BYTES, &v->header);
    if (rc != VTY_OK) goto fail;
    rc = create_meta_file(path, copy);
    if (rc != VTY_OK) goto fail;
    file_created = 1;

    /* 从这里开始写入的都是临时库：禁止推进回退锚点，直到提交完成。 */
    v->no_rollback_anchor = 1;

    rc = vty_store_open(v->path, v->kc, v->header.vault_uuid, v->header.epoch,
                        &v->data_root, v->data_root_hash, &v->store);
    if (rc != VTY_OK) goto fail;
    v->active_copy = 0;
    v->unlocked = 1;

    rc = vty_module_table_init(v);
    if (rc == VTY_OK) rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) goto fail;

    if (keyfile_digest_or_null != NULL) {
        memcpy(v->keyfile_digest, digest, VTY_KEY_BYTES);
        v->keyfile_digest_set = 1;
    }
    vty_free(copy, VTY_META_COPY_BYTES);
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(digest, sizeof(digest));
    *out = v;
    return VTY_OK;

fail:
    if (copy != NULL) vty_free(copy, VTY_META_COPY_BYTES);
    /* 先释放会话（关闭数据区句柄），再删除半成品文件；反序会因句柄
     * 仍打开而删除失败。只有本函数独占创建的文件才允许删除——
     * CreateFile(CREATE_NEW) 因目标被并发抢占而失败时不得删他人文件。 */
    vty_vault_free(v);
    if (file_created) {
        wchar_t *w = utf8_to_wide(path);
        if (w != NULL) {
            (void)DeleteFileW(w);
            free(w);
        }
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(digest, sizeof(digest));
    return rc;
}

/* PCR 门：先比对策略摘要，再要求 TPM 在 PCR 匹配下解封出同一 K_c。 */
static int check_pcr_gate(const VtyVault *v)
{
    int p_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    uint8_t cur[VTY_HASH_BYTES];
    uint8_t pcr_kc[VTY_KEY_BYTES];
    int rc;

    memset(cur, 0, sizeof(cur));
    vty_secure_zero(pcr_kc, sizeof(pcr_kc));
    if (p_idx < 0) return VTY_E_SLOT_MISSING;

    rc = vty_tpm_pcr_measure(v->slots[p_idx].pcr_select, cur);
    if (rc != VTY_OK) {
        rc = VTY_E_TPM;
    } else if (vty_ct_equal(cur, v->slots[p_idx].pcr_digest, VTY_HASH_BYTES) != 0) {
        rc = VTY_E_TPM;
    } else {
        rc = vty_tpm_pcr_unseal(v->header.vault_uuid, v->slots[p_idx].ct, pcr_kc);
        if (rc != VTY_OK) {
            rc = VTY_E_TPM;
        } else if (vty_ct_equal(pcr_kc, v->kc, VTY_KEY_BYTES) != 0) {
            rc = VTY_E_KEY_INVALID;
        }
    }
    vty_secure_zero(cur, sizeof(cur));
    vty_secure_zero(pcr_kc, sizeof(pcr_kc));
    return rc;
}

/* 轮换恢复日志布局（72 字节，字段固定偏移，全小端）：
 *   0..7 魔数；8..23 库 UUID；24..31 源代；32..35 PCR 位图；
 *   36..39 保留；40..71 PCR 策略摘要。 */
#define VTY_ROTATE_JOURNAL_MAGIC "VTYROTJ1"
#define VTY_ROTATE_JOURNAL_SUFFIX ".vtyrotj"
#define VTY_ROTATE_JOURNAL_SIZE 72u
#define VTY_ROTATE_JOURNAL_PATH_MAX 1040u

typedef struct {
    HANDLE h;
    char path[VTY_ROTATE_JOURNAL_PATH_MAX];
} VtyRotateJournalLease;

static int rotate_journal_path(const VtyVault *v, char *out, size_t cap)
{
    size_t len;

    if (v == NULL || out == NULL || cap == 0) return 0;
    len = strlen(v->path);
    if (len == 0 || len + sizeof(VTY_ROTATE_JOURNAL_SUFFIX) > cap) return 0;
    memcpy(out, v->path, len);
    memcpy(out + len, VTY_ROTATE_JOURNAL_SUFFIX, sizeof(VTY_ROTATE_JOURNAL_SUFFIX));
    return 1;
}

static int rotate_journal_pcr_slot(const VtyVault *v)
{
    if (v == NULL) return -1;
    if ((v->header.flags & VTY_FLAG_PCR) == 0) return -1;
    return vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
}

/* 读取日志并校验结构与库绑定；任何不一致一律视为不存在。 */
static int rotate_journal_read(const VtyVault *v, uint8_t buf[VTY_ROTATE_JOURNAL_SIZE])
{
    wchar_t *w;
    HANDLE h;
    LARGE_INTEGER size;
    DWORD got = 0;
    char jpath[VTY_ROTATE_JOURNAL_PATH_MAX];

    if (!rotate_journal_path(v, jpath, sizeof(jpath))) return 0;
    w = utf8_to_wide(jpath);
    if (w == NULL) return 0;
    /* 共享模式只请求读：提交进程的排他句柄会让这里直接失败。 */
    h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) return 0;
    if (!GetFileSizeEx(h, &size) || size.QuadPart != (LONGLONG)VTY_ROTATE_JOURNAL_SIZE ||
        !ReadFile(h, buf, (DWORD)VTY_ROTATE_JOURNAL_SIZE, &got, NULL) ||
        got != (DWORD)VTY_ROTATE_JOURNAL_SIZE) {
        CloseHandle(h);
        return 0;
    }
    CloseHandle(h);

    return (memcmp(buf, VTY_ROTATE_JOURNAL_MAGIC, 8) == 0) &&
           (memcmp(buf + 8, v->header.vault_uuid, VTY_UUID_BYTES) == 0);
}

static uint64_t rotate_journal_generation(const uint8_t *buf)
{
    uint64_t gen = 0;
    uint32_t i;

    for (i = 0; i < 8u; i++) gen |= (uint64_t)buf[24u + i] << (8u * i);
    return gen;
}

static uint32_t rotate_journal_select(const uint8_t *buf)
{
    uint32_t sel = 0;
    uint32_t i;

    for (i = 0; i < 4u; i++) sel |= (uint32_t)buf[32u + i] << (8u * i);
    return sel;
}

int vty_vault_rotate_journal_start(const VtyVault *v, void **token)
{
    VtyRotateJournalLease *lease;
    uint8_t buf[VTY_ROTATE_JOURNAL_SIZE];
    char jpath[VTY_ROTATE_JOURNAL_PATH_MAX];
    wchar_t *w;
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    uint64_t gen;
    uint32_t sel;
    uint32_t i;
    int p_idx;

    if (token != NULL) *token = NULL;
    if (v == NULL || token == NULL || !v->unlocked) return VTY_E_INVALID;
    p_idx = rotate_journal_pcr_slot(v);
    if (p_idx < 0) return VTY_E_POLICY;
    if (!rotate_journal_path(v, jpath, sizeof(jpath))) return VTY_E_INVALID;

    lease = (VtyRotateJournalLease *)vty_alloc(sizeof(*lease));
    if (lease == NULL) return VTY_E_RESOURCE;

    /* CREATE_ALWAYS + 独占共享：覆盖后、替换前的窗口内，其他进程无法读取
     * 或删除日志，避免并发解锁误判并重封正在迁出的密钥。 */
    w = utf8_to_wide(jpath);
    if (w != NULL) {
        h = CreateFileW(w, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
        free(w);
    }
    if (h == INVALID_HANDLE_VALUE) {
        vty_free(lease, sizeof(*lease));
        return VTY_E_IO;
    }

    memset(buf, 0, sizeof(buf));
    memcpy(buf, VTY_ROTATE_JOURNAL_MAGIC, 8);
    memcpy(buf + 8, v->header.vault_uuid, VTY_UUID_BYTES);
    gen = v->header.generation;
    for (i = 0; i < 8u; i++) buf[24u + i] = (uint8_t)(gen >> (8u * i));
    sel = v->slots[p_idx].pcr_select;
    for (i = 0; i < 4u; i++) buf[32u + i] = (uint8_t)(sel >> (8u * i));
    memcpy(buf + 40, v->slots[p_idx].pcr_digest, VTY_HASH_BYTES);

    if (!WriteFile(h, buf, (DWORD)VTY_ROTATE_JOURNAL_SIZE, &written, NULL) ||
        written != (DWORD)VTY_ROTATE_JOURNAL_SIZE || !FlushFileBuffers(h)) {
        CloseHandle(h);
        delete_file_utf8(jpath);
        vty_free(lease, sizeof(*lease));
        return VTY_E_IO;
    }

    memset(lease, 0, sizeof(*lease));
    lease->h = h;
    memcpy(lease->path, jpath, strlen(jpath) + 1u);
    *token = lease;
    return VTY_OK;
}

void vty_vault_rotate_journal_end(void **token, int delete_file)
{
    VtyRotateJournalLease *lease;

    if (token == NULL || *token == NULL) return;
    lease = (VtyRotateJournalLease *)*token;
    *token = NULL;
    if (lease->h != INVALID_HANDLE_VALUE) CloseHandle(lease->h);
    if (delete_file) delete_file_utf8(lease->path);
    vty_free(lease, sizeof(*lease));
}

int vty_vault_rotate_journal_match(const VtyVault *v)
{
    uint8_t buf[VTY_ROTATE_JOURNAL_SIZE];
    uint8_t cur[VTY_HASH_BYTES];
    int p_idx;
    int ok;

    p_idx = rotate_journal_pcr_slot(v);
    if (p_idx < 0) return 0;
    if (!rotate_journal_read(v, buf)) return 0;
    if (rotate_journal_generation(buf) != v->header.generation) return 0;
    if (rotate_journal_select(buf) != v->slots[p_idx].pcr_select) return 0;
    if (vty_ct_equal(buf + 40, v->slots[p_idx].pcr_digest, VTY_HASH_BYTES) != 0) {
        return 0;
    }
    /* 平台状态必须仍等于策略摘要：状态变化时不得自动重绑，否则等于
     * 用一次崩溃恢复绕过 PCR 策略。 */
    if (vty_tpm_pcr_measure(v->slots[p_idx].pcr_select, cur) != VTY_OK) return 0;
    ok = (vty_ct_equal(cur, buf + 40, VTY_HASH_BYTES) == 0);
    vty_secure_zero(cur, sizeof(cur));
    return ok;
}

int vty_vault_rotate_journal_stale(const VtyVault *v)
{
    uint8_t buf[VTY_ROTATE_JOURNAL_SIZE];

    if (v == NULL) return 0;
    if (!rotate_journal_read(v, buf)) return 0;
    return rotate_journal_generation(buf) < v->header.generation;
}

void vty_vault_rotate_journal_clear(const VtyVault *v)
{
    char jpath[VTY_ROTATE_JOURNAL_PATH_MAX];

    if (!rotate_journal_path(v, jpath, sizeof(jpath))) return;
    delete_file_utf8(jpath);
}

/* 从一份已认证的副本装入会话；调用方已确认 body AEAD 成功。 */
static int adopt_copy(VtyVault *v, const VtyMetaCopy *c, const VtyKeyring *kr,
                      const uint8_t kc[VTY_KEY_BYTES], uint64_t file_size)
{
    VtyDataRootLocator loc;
    uint8_t hash[VTY_HASH_BYTES];
    int rc;

    rc = keyring_take_data_root(kr, c->h.vault_uuid, c->h.epoch, &loc, hash);
    if (rc != VTY_OK) return rc;
    if (loc.data_end > file_size) return VTY_E_CORRUPT;
    if (loc.root_node_id != 0u) {
        if (loc.root_offset < VTY_DATA_OFFSET ||
            loc.root_offset > loc.data_end ||
            loc.root_len > loc.data_end - loc.root_offset) {
            return VTY_E_CORRUPT;
        }
    }

    v->header = c->h;
    v->slot_count = c->slot_count;
    memcpy(v->slots, c->slots, sizeof(c->slots));
    v->keyring = *kr;
    v->data_root = loc;
    memcpy(v->data_root_hash, hash, VTY_HASH_BYTES);
    memcpy(v->kc, kc, VTY_KEY_BYTES);
    v->active_copy = c->index;
    v->unlocked = 1;
    return VTY_OK;
}

/* 非 static：产品 .rhat X 清单覆盖标准/keyfile 解锁主路径（wrapper 过薄） */
__declspec(noinline) int vty_vault_open_internal(const char *path,
                               const char *password,
                               const char *keyfile_path, VtyVault **out)
{
    VtyVault *v;
    uint8_t *meta = NULL;
    uint64_t file_size = 0;
    VtyMetaCopy copies[VTY_META_COPIES];
    uint8_t kc_cached[VTY_KEY_BYTES];
    uint8_t keyfile_digest[VTY_KEY_BYTES];
    int keyfile_loaded = 0;
    int keyfile_required = 0;
    int kc_cached_valid = 0;
    int last_slot_rc = VTY_E_KEY_INVALID;
    int any_slot_ok = 0;
    int slot_fail = 0;
    int pcr_pending = 0;
    int rc = VTY_OK;
    uint32_t ci;

    memset(keyfile_digest, 0, sizeof(keyfile_digest));

    if (path == NULL || password == NULL || out == NULL) return VTY_E_INVALID;
    if (password[0] == '\0') return VTY_E_INVALID;
    if (strlen(path) >= sizeof(((VtyVault *)0)->path)) return VTY_E_INVALID;

    /* 机器级预算先于本地熔断：服务未安装/不可达/预算耗尽一律 fail-closed，
     * 不允许通过本地状态或服务不可达绕过全机节流。 */
    if (vty_machine_limiter_check() != VTY_OK) return VTY_E_LOCKED;
    if (vty_lockout_enabled()) {
        if (vty_lockout_init() != VTY_OK) return VTY_E_LOCKED;
        if (vty_lockout_begin_attempt() == VTY_E_LOCKED) return VTY_E_LOCKED;
    }

    v = (VtyVault *)vty_secure_alloc(sizeof(VtyVault), "vault");
    if (v == NULL) return VTY_E_RESOURCE;
    memcpy(v->path, path, strlen(path) + 1);

    rc = load_meta(path, &meta, &file_size, copies);
    if (rc != VTY_OK) goto fail;

    for (ci = 0; ci < VTY_META_COPIES; ci++) {
        uint8_t share_u[VTY_KEY_BYTES];
        uint8_t share_d[VTY_KEY_BYTES];
        uint8_t kc[VTY_KEY_BYTES];
        VtyKeyring kr;
        int u_idx, d_idx;
        int slot_rc;

        memset(share_u, 0, sizeof(share_u));
        memset(share_d, 0, sizeof(share_d));
        memset(&kr, 0, sizeof(kr));
        if (!copies[ci].valid) continue;

        v->header = copies[ci].h;
        v->slot_count = copies[ci].slot_count;
        memcpy(v->slots, copies[ci].slots, sizeof(copies[ci].slots));

        rc = vty_slot_policy_check(v->slots, v->slot_count, v->header.flags);
        if (rc != VTY_OK) goto fail;

        keyfile_required = (v->header.flags & VTY_FLAG_KEYFILE) != 0;
        if (keyfile_required) {
            if (keyfile_path == NULL) {
                rc = VTY_E_KEYFILE_REQUIRED;
                break;
            }
            if (!keyfile_loaded) {
                rc = load_keyfile_digest(keyfile_path, keyfile_digest);
                if (rc != VTY_OK) break;
                keyfile_loaded = 1;
            }
        }

        u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
        d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
        if (u_idx < 0 || d_idx < 0) {
            rc = VTY_E_SLOT_MISSING;
            goto fail;
        }

        /* A/B 槽区相同时只做一次 KDF；否则同一口令会被迫连续
         * 计算两次 Argon2id，既慢又给离线猜测提供额外样本。 */
        if (ci > 0 && slot_area_equal(&copies[ci], &copies[ci - 1])) {
            if (kc_cached_valid) {
                memcpy(kc, kc_cached, VTY_KEY_BYTES);
                slot_rc = VTY_OK;
            } else {
                /* 相同槽区已失败过一次，重复 KDF 只会再失败并放大开销。 */
                slot_rc = last_slot_rc;
            }
        } else {
            slot_rc = open_user_slot(&v->slots[u_idx], password,
                                      keyfile_required ? keyfile_digest : NULL,
                                      &v->header, (uint32_t)u_idx, share_u);
            if (slot_rc == VTY_OK) {
                slot_rc = vty_slot_open_device(&v->slots[d_idx], &v->header,
                                               (uint32_t)d_idx, share_d);
            }
            if (slot_rc == VTY_OK) {
                size_t i;
                for (i = 0; i < VTY_KEY_BYTES; i++) {
                    kc[i] = (uint8_t)(share_u[i] ^ share_d[i]);
                }
                memcpy(kc_cached, kc, VTY_KEY_BYTES);
                kc_cached_valid = 1;
            }
            vty_secure_zero(share_u, sizeof(share_u));
            vty_secure_zero(share_d, sizeof(share_d));
            last_slot_rc = slot_rc;
        }

        if (slot_rc != VTY_OK) {
            /* 结构完整的新代副本已经存在时，槽解包失败就是口令/设备根
             * 不匹配，不能降级去试更旧的副本——否则旧口令在轮换后仍可
             * 打开上一代文件，等于撤销失效。只有新代副本结构损坏或
             * body 认证失败时才回退。 */
            slot_fail++;
            rc = slot_rc;
            break;
        }
        any_slot_ok = 1;
        memcpy(v->kc, kc, VTY_KEY_BYTES);

        if ((v->header.flags & VTY_FLAG_PCR) != 0) {
            rc = check_pcr_gate(v);
            if (rc != VTY_OK) {
                /* 轮换提交在 PCR 重封后、原子替换前被杀：日志与当前文件代
                 * 严格匹配且平台状态未变时，推迟 PCR 门到会话建立后，
                 * 用口令解出的 K_c 重封；不匹配则维持 fail-closed。 */
                if (vty_vault_rotate_journal_match(v)) {
                    pcr_pending = 1;
                    rc = VTY_OK;
                } else {
                    /* 替换已完成但日志未删的残留：源代小于文件代，清掉。 */
                    if (vty_vault_rotate_journal_stale(v)) {
                        vty_vault_rotate_journal_clear(v);
                    }
                    goto fail;
                }
            }
        }

        rc = open_body_copy(&copies[ci].h, copies[ci].digest, copies[ci].body,
                            copies[ci].body_len, kc, &kr);
        if (rc != VTY_OK) {
            vty_secure_zero(kc, sizeof(kc));
            continue;
        }

        rc = adopt_copy(v, &copies[ci], &kr, kc, file_size);
        vty_secure_zero(kc, sizeof(kc));
        if (rc != VTY_OK) goto fail;

        if (vty_rollback_enabled()) {
            rc = vty_rollback_check(v->header.vault_uuid, v->header.generation);
            if (rc != VTY_OK) goto fail;
            rc = vty_rollback_commit(v->header.vault_uuid, v->header.generation);
            if (rc != VTY_OK) goto fail;
        }

        rc = vty_store_open(v->path, v->kc, v->header.vault_uuid,
                            v->header.epoch, &v->data_root, v->data_root_hash,
                            &v->store);
        if (rc != VTY_OK) goto fail;

        v->mem_kib = v->slots[u_idx].m_cost;
        v->iters = v->slots[u_idx].t_cost;
        v->parallel = v->slots[u_idx].p_cost;
        if (keyfile_required) {
            memcpy(v->keyfile_digest, keyfile_digest, VTY_KEY_BYTES);
            v->keyfile_digest_set = 1;
        }
        v->unlocked = 1;
        rc = vty_module_table_load(v);
        if (rc != VTY_OK) goto fail;
        if (vty_lockout_enabled()) {
            (void)vty_lockout_init();
            (void)vty_lockout_reset();
        }
        (void)vty_machine_limiter_reset();
        if ((v->header.flags & VTY_FLAG_PCR) != 0) {
            if (pcr_pending) {
                /* 会话与会话密钥均已建立：用当前 K_c 重封后重新验证门。
                 * 重封失败时保持日志，下一次解锁继续尝试。 */
                rc = vty_vault_pcr_reseal(v);
                if (rc != VTY_OK) goto fail;
                rc = check_pcr_gate(v);
                if (rc != VTY_OK) goto fail;
            }
            /* 到这里日志已无待恢复语义（替换已完成或重封已完成）。 */
            vty_vault_rotate_journal_clear(v);
        }
        vty_free(meta, VTY_DATA_OFFSET);
        vty_secure_zero(kc_cached, sizeof(kc_cached));
        vty_secure_zero(keyfile_digest, sizeof(keyfile_digest));
        *out = v;
        return VTY_OK;
    }

    /* 只有“所有可解析副本都无法解包槽”才计入熔断；body 认证失败
     * 说明口令/设备根已正确，是文件损坏，不应把用户锁死。 */
    if (!any_slot_ok && slot_fail > 0) {
        if (vty_lockout_enabled()) {
            (void)vty_lockout_init();
            (void)vty_lockout_record_failure();
        }
        (void)vty_machine_limiter_record_failure();
    }
    if (rc == VTY_OK) rc = VTY_E_KEY_INVALID;

fail:
    if (meta != NULL) vty_free(meta, VTY_DATA_OFFSET);
    vty_secure_zero(kc_cached, sizeof(kc_cached));
    vty_secure_zero(keyfile_digest, sizeof(keyfile_digest));
    vty_vault_free(v);
    return rc;
}

int vty_vault_open(const char *path, const char *password, VtyVault **out)
{
    return vty_vault_open_internal(path, password, NULL, out);
}

int vty_vault_open_keyfile(const char *path, const char *password,
                           const char *keyfile_path, VtyVault **out)
{
    return vty_vault_open_internal(path, password, keyfile_path, out);
}

int vty_vault_open_recovery(const char *path, const char *recovery_text,
                            VtyVault **out)
{
    VtyVault *v;
    uint8_t *meta = NULL;
    uint64_t file_size = 0;
    VtyMetaCopy copies[VTY_META_COPIES];
    int rc;
    uint32_t ci;

    if (path == NULL || recovery_text == NULL || out == NULL) return VTY_E_INVALID;
    if (strlen(path) >= sizeof(((VtyVault *)0)->path)) return VTY_E_INVALID;

    /* 恢复码解锁同样是全机可猜解入口，必须先过机器预算再计算 Argon2id。 */
    if (vty_machine_limiter_check() != VTY_OK) return VTY_E_LOCKED;

    v = (VtyVault *)vty_secure_alloc(sizeof(VtyVault), "vault");
    if (v == NULL) return VTY_E_RESOURCE;
    memcpy(v->path, path, strlen(path) + 1);

    rc = load_meta(path, &meta, &file_size, copies);
    if (rc != VTY_OK) goto fail;

    for (ci = 0; ci < VTY_META_COPIES; ci++) {
        VtyKeyring rk;
        VtyKeyring body_kr;
        uint8_t kc[VTY_KEY_BYTES];
        int r_idx;

        memset(&rk, 0, sizeof(rk));
        memset(&body_kr, 0, sizeof(body_kr));
        memset(kc, 0, sizeof(kc));
        if (!copies[ci].valid) continue;

        v->header = copies[ci].h;
        v->slot_count = copies[ci].slot_count;
        memcpy(v->slots, copies[ci].slots, sizeof(copies[ci].slots));
        if ((v->header.flags & VTY_FLAG_RECOVERY) == 0) {
            rc = VTY_E_SLOT_MISSING;
            break;
        }
        r_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_RECOVERY);
        if (r_idx < 0) {
            rc = VTY_E_SLOT_MISSING;
            break;
        }

        /* 新代副本存在时，恢复槽解包失败就是恢复码本身失效；
         * 降级去试旧副本会让轮换前的恢复码继续可用。 */
        rc = vty_recovery_slot_open(&v->slots[r_idx], recovery_text,
                                    &v->header, (uint32_t)r_idx, &rk,
                                    v->k_recovery);
        if (rc != VTY_OK) break;
        rc = vty_keyring_find(&rk, VTY_KEYKIND_KC, NULL, 0, kc);
        if (rc != VTY_OK) break;

        rc = open_body_copy(&copies[ci].h, copies[ci].digest, copies[ci].body,
                            copies[ci].body_len, kc, &body_kr);
        if (rc != VTY_OK) {
            vty_secure_zero(kc, sizeof(kc));
            continue;
        }

        rc = adopt_copy(v, &copies[ci], &body_kr, kc, file_size);
        vty_secure_zero(kc, sizeof(kc));
        if (rc != VTY_OK) goto fail;

        /* 恢复码是显式逃生通道：允许打开较旧副本，并把锚点重设为
         * 该副本的代；否则被回滚的库会永久无法恢复。 */
        if (vty_rollback_enabled()) {
            rc = vty_rollback_reset_anchor(v->header.vault_uuid,
                                           v->header.generation);
            if (rc != VTY_OK) goto fail;
        }
        if (vty_lockout_enabled()) (void)vty_lockout_reset();
        rc = vty_store_open(v->path, v->kc, v->header.vault_uuid,
                            v->header.epoch, &v->data_root, v->data_root_hash,
                            &v->store);
        if (rc != VTY_OK) goto fail;

        v->mem_kib = v->slots[r_idx].m_cost;
        v->iters = v->slots[r_idx].t_cost;
        v->parallel = v->slots[r_idx].p_cost;
        v->unlocked = 1;
        v->recovery_mode = 1;
        rc = vty_module_table_load(v);
        if (rc != VTY_OK) goto fail;
        (void)vty_machine_limiter_reset();
        vty_free(meta, VTY_DATA_OFFSET);
        *out = v;
        return VTY_OK;
    }

    /* 恢复码格式错误在 KDF 之前即被拒绝，不计入预算；格式合法但认证失败
     * （AEAD/密钥不符）属于真实猜解尝试，必须记账。 */
    if (rc == VTY_OK) rc = VTY_E_KEY_INVALID;
    if (rc == VTY_E_AEAD || rc == VTY_E_KEY_INVALID) {
        (void)vty_machine_limiter_record_failure();
    }

fail:
    if (meta != NULL) vty_free(meta, VTY_DATA_OFFSET);
    vty_vault_free(v);
    return rc;
}

/* 只验证 user 槽：恢复/换机场景设备根不可用时仍需确认当前口令。
 * AEAD 认证通过即证明口令正确，不依赖设备槽。 */
int vty_vault_verify_user_password(const VtyVault *v, const char *password)
{
    uint8_t share_u[VTY_KEY_BYTES];
    int u_idx, rc;

    if (v == NULL || password == NULL || password[0] == '\0') return VTY_E_INVALID;
    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    if (u_idx < 0) return VTY_E_SLOT_MISSING;
    if ((v->header.flags & VTY_FLAG_KEYFILE) != 0 && !v->keyfile_digest_set) {
        return VTY_E_KEYFILE_REQUIRED;
    }
    /* 口令复核同样是猜解入口（轮换 Begin / 恢复码轮换）：必须服从统一的
     * 机器预算与失败退避，否则可绕过登录熔断无限触发 Argon2。 */
    if (vty_machine_limiter_check() != VTY_OK) return VTY_E_LOCKED;
    if (vty_lockout_enabled()) {
        if (vty_lockout_init() != VTY_OK) return VTY_E_LOCKED;
        if (vty_lockout_begin_attempt() == VTY_E_LOCKED) return VTY_E_LOCKED;
    }
    memset(share_u, 0, sizeof(share_u));
    rc = open_user_slot(&v->slots[u_idx], password,
                        (v->header.flags & VTY_FLAG_KEYFILE) != 0
                            ? v->keyfile_digest : NULL,
                        &v->header, (uint32_t)u_idx, share_u);
    vty_secure_zero(share_u, sizeof(share_u));
    if (rc == VTY_E_KEY_INVALID) {
        if (vty_lockout_enabled()) {
            (void)vty_lockout_init();
            (void)vty_lockout_record_failure();
        }
        (void)vty_machine_limiter_record_failure();
    } else if (rc == VTY_OK) {
        if (vty_lockout_enabled()) {
            (void)vty_lockout_init();
            (void)vty_lockout_reset();
        }
        (void)vty_machine_limiter_reset();
    }
    return rc;
}

/* 轮换补录：恢复会话未持有 keyfile 摘要时，用当前容器口令 + keyfile 验证
 * user 槽；认证通过后才把摘要写入会话缓存。失败路径不修改任何会话字段。 */
int vty_vault_attach_keyfile(VtyVault *v, const char *keyfile_path,
                             const char *password)
{
    uint8_t digest[VTY_KEY_BYTES];
    uint8_t share_u[VTY_KEY_BYTES];
    int u_idx;
    int rc;

    if (v == NULL || keyfile_path == NULL || password == NULL ||
        password[0] == '\0') {
        return VTY_E_INVALID;
    }
    if (!v->unlocked) return VTY_E_POLICY;
    if ((v->header.flags & VTY_FLAG_KEYFILE) == 0) return VTY_E_POLICY;

    memset(digest, 0, sizeof(digest));
    rc = load_keyfile_digest(keyfile_path, digest);
    if (rc != VTY_OK) {
        vty_secure_zero(digest, sizeof(digest));
        return rc;
    }

    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    if (u_idx < 0) {
        vty_secure_zero(digest, sizeof(digest));
        return VTY_E_SLOT_MISSING;
    }
    if (vty_machine_limiter_check() != VTY_OK) {
        vty_secure_zero(digest, sizeof(digest));
        return VTY_E_LOCKED;
    }
    if (vty_lockout_enabled()) {
        if (vty_lockout_init() != VTY_OK) {
            vty_secure_zero(digest, sizeof(digest));
            return VTY_E_LOCKED;
        }
        if (vty_lockout_begin_attempt() == VTY_E_LOCKED) {
            vty_secure_zero(digest, sizeof(digest));
            return VTY_E_LOCKED;
        }
    }

    memset(share_u, 0, sizeof(share_u));
    rc = open_user_slot(&v->slots[u_idx], password, digest, &v->header,
                        (uint32_t)u_idx, share_u);
    vty_secure_zero(share_u, sizeof(share_u));
    if (rc != VTY_OK) {
        /* VKFL 合法但 keyfile 或口令不匹配：统一认证失败，不写会话。 */
        if (rc == VTY_E_KEY_INVALID) {
            if (vty_lockout_enabled()) {
                (void)vty_lockout_init();
                (void)vty_lockout_record_failure();
            }
            (void)vty_machine_limiter_record_failure();
        }
        vty_secure_zero(digest, sizeof(digest));
        return rc;
    }
    if (vty_lockout_enabled()) {
        (void)vty_lockout_init();
        (void)vty_lockout_reset();
    }
    (void)vty_machine_limiter_reset();

    memcpy(v->keyfile_digest, digest, sizeof(digest));
    v->keyfile_digest_set = 1;
    vty_secure_zero(digest, sizeof(digest));
    return VTY_OK;
}

int vty_vault_verify_recovery(const VtyVault *v, const char *recovery_text)
{
    VtyKeyring rk;
    uint8_t kc[VTY_KEY_BYTES];
    int r_idx, rc;

    if (v == NULL || recovery_text == NULL || recovery_text[0] == '\0') {
        return VTY_E_INVALID;
    }
    if (!v->unlocked) return VTY_E_POLICY;
    if ((v->header.flags & VTY_FLAG_RECOVERY) == 0) return VTY_E_SLOT_MISSING;
    r_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_RECOVERY);
    if (r_idx < 0) return VTY_E_SLOT_MISSING;

    memset(&rk, 0, sizeof(rk));
    memset(kc, 0, sizeof(kc));
    rc = vty_recovery_slot_open(&v->slots[r_idx], recovery_text,
                                &v->header, (uint32_t)r_idx, &rk, NULL);
    if (rc == VTY_OK) {
        rc = vty_keyring_find(&rk, VTY_KEYKIND_KC, NULL, 0, kc);
    }
    if (rc == VTY_OK &&
        vty_ct_equal(kc, v->kc, VTY_KEY_BYTES) != 0) {
        rc = VTY_E_KEY_INVALID;
    }
    vty_secure_zero(&rk, sizeof(rk));
    vty_secure_zero(kc, sizeof(kc));
    return rc;
}

int vty_vault_pcr_info(const VtyVault *v,
                       uint32_t *out_enabled, uint32_t *out_select)
{
    int p_idx;

    if (v == NULL || out_enabled == NULL || out_select == NULL) {
        return VTY_E_INVALID;
    }
    if (!v->unlocked) return VTY_E_POLICY;

    p_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    if (p_idx < 0) {
        /* 标志与槽必须一致：声明 PCR 却没有槽属于结构损坏。 */
        if ((v->header.flags & VTY_FLAG_PCR) != 0) return VTY_E_CORRUPT;
        *out_enabled = 0;
        *out_select = 0;
        return VTY_OK;
    }
    if ((v->header.flags & VTY_FLAG_PCR) == 0) return VTY_E_CORRUPT;

    *out_enabled = 1;
    *out_select = v->slots[p_idx].pcr_select;
    return VTY_OK;
}

int vty_vault_rotate_password(VtyVault *v, const char *new_password)
{
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    int u_idx, d_idx;
    int rc;
    size_t i;

    if (v == NULL || new_password == NULL || new_password[0] == '\0') return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (strlen(v->path) == 0) return VTY_E_INVALID;

    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    if (u_idx < 0 || d_idx < 0) return VTY_E_SLOT_MISSING;

    /* epoch 是数据代：口令轮换不改变记录、名称、分片与目录的派生参数，
     * 因此绝不能递增。恢复码是独立凭据，本函数不再重封恢复槽。 */
    vty_random(share_u, VTY_KEY_BYTES);
    for (i = 0; i < VTY_KEY_BYTES; i++) {
        share_d[i] = (uint8_t)(v->kc[i] ^ share_u[i]);
    }

    if ((v->header.flags & VTY_FLAG_KEYFILE) != 0 && !v->keyfile_digest_set) {
        vty_secure_zero(share_u, sizeof(share_u));
        vty_secure_zero(share_d, sizeof(share_d));
        return VTY_E_KEYFILE_REQUIRED;
    }
    rc = seal_user_slot(&v->slots[u_idx], VTY_SLOT_USER_PASSWORD,
                        VTY_SLOT_FLAG_REQUIRED, new_password,
                        (v->header.flags & VTY_FLAG_KEYFILE) != 0
                            ? v->keyfile_digest : NULL,
                        share_u, &v->header, (uint32_t)u_idx,
                        v->mem_kib, v->iters, v->parallel);
    if (rc == VTY_OK) {
        rc = vty_slot_seal_device(&v->slots[d_idx], VTY_SLOT_FLAG_REQUIRED,
                                  share_d, &v->header, (uint32_t)d_idx);
    }
    if (rc == VTY_OK) rc = vty_vault_save(v);

    if (rc != VTY_OK) {
        /* 轮换中途失败时内存槽位可能已与磁盘不一致；继续允许保存
         * 会把半套槽位写盘彻底毁库，强制回到锁定态。 */
        v->unlocked = 0;
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    return rc;
}

/* 重新生成 share_u/share_d 并按指定 keyfile 摘要重封用户槽与设备槽。
 * 只改槽，不重写数据；失败由调用方锁定会话。 */
static int reseal_user_device_slots(VtyVault *v, const char *password,
                                    const uint8_t *keyfile_digest)
{
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    int u_idx, d_idx;
    int rc;
    size_t i;

    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    if (u_idx < 0 || d_idx < 0) return VTY_E_SLOT_MISSING;

    vty_random(share_u, VTY_KEY_BYTES);
    for (i = 0; i < VTY_KEY_BYTES; i++) {
        share_d[i] = (uint8_t)(v->kc[i] ^ share_u[i]);
    }
    rc = seal_user_slot(&v->slots[u_idx], VTY_SLOT_USER_PASSWORD,
                        VTY_SLOT_FLAG_REQUIRED, password, keyfile_digest,
                        share_u, &v->header, (uint32_t)u_idx,
                        v->mem_kib, v->iters, v->parallel);
    if (rc == VTY_OK) {
        rc = vty_slot_seal_device(&v->slots[d_idx], VTY_SLOT_FLAG_REQUIRED,
                                  share_d, &v->header, (uint32_t)d_idx);
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    return rc;
}

int vty_vault_reseal_device(VtyVault *v, const char *password,
                            const uint8_t *keyfile_digest_or_null)
{
    uint8_t digest[VTY_KEY_BYTES];
    int has_keyfile;
    int rc;

    memset(digest, 0, sizeof(digest));
    if (v == NULL || password == NULL || password[0] == '\0') {
        return VTY_E_INVALID;
    }
    if (!v->unlocked || !v->recovery_mode) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (strlen(v->path) == 0) return VTY_E_INVALID;

    has_keyfile = (v->header.flags & VTY_FLAG_KEYFILE) != 0;
    if (has_keyfile && keyfile_digest_or_null == NULL) {
        return VTY_E_KEYFILE_REQUIRED;
    }
    if (!has_keyfile && keyfile_digest_or_null != NULL) {
        return VTY_E_INVALID;
    }
    if (has_keyfile) {
        memcpy(digest, keyfile_digest_or_null, VTY_KEY_BYTES);
    }

    rc = reseal_user_device_slots(v, password, has_keyfile ? digest : NULL);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        goto out;
    }
    if (has_keyfile) {
        memcpy(v->keyfile_digest, digest, VTY_KEY_BYTES);
        v->keyfile_digest_set = 1;
    }

    /* 新槽必须能用当前口令（及 keyfile 摘要）自检还原 K_c；失败即锁定
     * 会话，避免把半套槽位继续用于写入。 */
    rc = vty_vault_verify_password(v, password);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        if (has_keyfile) {
            v->keyfile_digest_set = 0;
            vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
        }
        goto out;
    }

    /* 只写元数据副本，不提交数据区：槽重绑不改变记录/分片。 */
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        if (has_keyfile) {
            v->keyfile_digest_set = 0;
            vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
        }
    }

out:
    vty_secure_zero(digest, sizeof(digest));
    return rc;
}

int vty_vault_reseal_device_file(VtyVault *v, const char *password,
                                 const char *keyfile_path)
{
    uint8_t digest[VTY_KEY_BYTES];
    int rc;

    memset(digest, 0, sizeof(digest));
    if (v == NULL || password == NULL || password[0] == '\0') {
        return VTY_E_INVALID;
    }
    if (!v->unlocked || !v->recovery_mode) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;

    if ((v->header.flags & VTY_FLAG_KEYFILE) != 0) {
        if (keyfile_path == NULL || keyfile_path[0] == '\0') {
            return VTY_E_KEYFILE_REQUIRED;
        }
        rc = load_keyfile_digest(keyfile_path, digest);
        if (rc != VTY_OK) {
            vty_secure_zero(digest, sizeof(digest));
            return rc;
        }
        rc = vty_vault_reseal_device(v, password, digest);
    } else {
        rc = vty_vault_reseal_device(v, password, NULL);
    }

    vty_secure_zero(digest, sizeof(digest));
    return rc;
}

int vty_vault_keyfile_enable(VtyVault *v, const char *password,
                             const uint8_t *new_blob, size_t new_len)
{
    uint8_t secret[VTY_KEYFILE_SECRET_BYTES];
    uint8_t digest[VTY_KEY_BYTES];
    int was_keyfile;
    int recovery_rebind;
    int rc;

    memset(secret, 0, sizeof(secret));
    memset(digest, 0, sizeof(digest));
    if (v == NULL || password == NULL || password[0] == '\0' ||
        new_blob == NULL || new_len != VTY_KEYFILE_BLOB_BYTES) {
        return new_blob == NULL || new_len != VTY_KEYFILE_BLOB_BYTES
            ? VTY_E_KEYFILE_INVALID : VTY_E_INVALID;
    }
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (strlen(v->path) == 0) return VTY_E_INVALID;

    was_keyfile = (v->header.flags & VTY_FLAG_KEYFILE) != 0;
    /* 恢复会话没有旧 keyfile 摘要：这是“keyfile 丢失”的唯一逃生路径。
     * 恢复码已认证根访问，允许用当前口令直接重封；重封后立即自检。 */
    recovery_rebind = v->recovery_mode && !v->keyfile_digest_set;
    if (was_keyfile && !v->keyfile_digest_set && !recovery_rebind) {
        return VTY_E_KEYFILE_REQUIRED;
    }

    rc = vty_keyfile_parse(new_blob, new_len, secret);
    if (rc == VTY_OK) rc = vty_keyfile_digest(secret, digest);
    if (rc != VTY_OK) goto out;

    /* 先验证当前口令；启用/轮换都必须知道当前口令。恢复会话无法验证
     * 旧用户槽（缺旧 keyfile 摘要），由恢复码承担认证，重封后自检。 */
    if (!recovery_rebind) {
        rc = vty_vault_verify_password(v, password);
        if (rc != VTY_OK) goto out;
    }

    rc = reseal_user_device_slots(v, password, digest);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        goto out;
    }

    v->header.flags |= VTY_FLAG_KEYFILE;
    memcpy(v->keyfile_digest, digest, VTY_KEY_BYTES);
    v->keyfile_digest_set = 1;
    if (recovery_rebind) {
        /* 新槽自检：用“口令 + 新摘要”必须能解开并还原 K_c。 */
        rc = vty_vault_verify_password(v, password);
        if (rc != VTY_OK) {
            v->unlocked = 0;
            v->keyfile_digest_set = 0;
            vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
            goto out;
        }
    }
    rc = vty_vault_save(v);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        v->keyfile_digest_set = 0;
        vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
    }

out:
    vty_secure_zero(secret, sizeof(secret));
    vty_secure_zero(digest, sizeof(digest));
    return rc;
}

int vty_vault_keyfile_enable_file(VtyVault *v, const char *password,
                                  const char *new_keyfile_path)
{
    uint8_t blob[VTY_KEYFILE_BLOB_BYTES];
    int rc;

    memset(blob, 0, sizeof(blob));
    if (new_keyfile_path == NULL) return VTY_E_KEYFILE_REQUIRED;
    if (v == NULL || password == NULL) return VTY_E_INVALID;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    rc = vty_keyfile_generate(blob);
    if (rc == VTY_OK) {
        rc = write_keyfile_file(new_keyfile_path, blob, sizeof(blob));
    }
    if (rc == VTY_OK) {
        rc = vty_vault_keyfile_enable(v, password, blob, sizeof(blob));
        /* 重封失败时新文件尚未被库接受，删除以免用户拿它去解一个
         * 仍按旧因子封装的库。 */
        if (rc != VTY_OK) delete_file_utf8(new_keyfile_path);
    }
    vty_secure_zero(blob, sizeof(blob));
    return rc;
}

int vty_vault_keyfile_disable(VtyVault *v, const char *password,
                              const char *keyfile_path)
{
    uint8_t digest[VTY_KEY_BYTES];
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t kc[VTY_KEY_BYTES];
    int u_idx, d_idx;
    int rc;

    memset(digest, 0, sizeof(digest));
    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    memset(kc, 0, sizeof(kc));
    if (v == NULL || password == NULL || password[0] == '\0') {
        return VTY_E_KEYFILE_REQUIRED;
    }
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if ((v->header.flags & VTY_FLAG_KEYFILE) == 0) return VTY_E_POLICY;
    /* 高安全模式必须有第二因子：没有 PCR 槽时不得关闭 keyfile，否则
     * 落盘后的库立即违反 vty_slot_policy_check，普通解锁被拒。 */
    if ((v->header.flags & VTY_FLAG_HIGH_SECURITY) != 0 &&
        vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR) < 0) {
        return VTY_E_POLICY;
    }

    if (keyfile_path == NULL || keyfile_path[0] == '\0') {
        /* 空路径只在恢复会话有意义：keyfile 丢失后无法校验旧文件，
         * 由恢复码承担认证；重封后立即用“仅口令”自检。 */
        if (!v->recovery_mode) {
            rc = VTY_E_KEYFILE_REQUIRED;
            goto out;
        }
        rc = reseal_user_device_slots(v, password, NULL);
        if (rc != VTY_OK) {
            v->unlocked = 0;
            goto out;
        }
        v->header.flags &= (uint16_t)~VTY_FLAG_KEYFILE;
        v->keyfile_digest_set = 0;
        vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
        rc = vty_vault_verify_password(v, password);
        if (rc != VTY_OK) {
            v->unlocked = 0;
            goto out;
        }
        rc = vty_vault_save(v);
        if (rc != VTY_OK) v->unlocked = 0;
        goto out;
    }

    rc = load_keyfile_digest(keyfile_path, digest);
    if (rc != VTY_OK) goto out;
    /* 用用户提供的 keyfile 重新计算摘要并验证口令；错误的文件会在
     * 用户槽解包时统一失败，不泄露“文件对/错”。 */
    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    if (u_idx < 0 || d_idx < 0) { rc = VTY_E_SLOT_MISSING; goto out; }
    rc = open_user_slot(&v->slots[u_idx], password, digest,
                        &v->header, (uint32_t)u_idx, share_u);
    if (rc == VTY_OK) {
        rc = vty_slot_open_device(&v->slots[d_idx], &v->header,
                                  (uint32_t)d_idx, share_d);
    }
    if (rc == VTY_OK) {
        size_t i;
        for (i = 0; i < VTY_KEY_BYTES; i++) {
            kc[i] = (uint8_t)(share_u[i] ^ share_d[i]);
        }
        if (vty_ct_equal(kc, v->kc, VTY_KEY_BYTES) != 0) rc = VTY_E_KEY_INVALID;
    }
    if (rc != VTY_OK) goto out;

    rc = reseal_user_device_slots(v, password, NULL);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        goto out;
    }

    v->header.flags &= (uint16_t)~VTY_FLAG_KEYFILE;
    v->keyfile_digest_set = 0;
    vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
    rc = vty_vault_save(v);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        v->keyfile_digest_set = 0;
        vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
    }

out:
    vty_secure_zero(digest, sizeof(digest));
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(kc, sizeof(kc));
    return rc;
}

int vty_vault_recovery_rotate(VtyVault *v,
                              const char *password,
                              const char *old_recovery_text,
                              char *new_text, size_t new_cap)
{
    uint8_t code[VTY_RECOVERY_CODE_BYTES];
    uint8_t krec_old[VTY_KEY_BYTES];
    uint8_t krec_new[VTY_KEY_BYTES];
    uint8_t kc[VTY_KEY_BYTES];
    VtySlot new_slot;
    VtySlot old_slot;
    VtyKeyring rk;
    VtyStoreCheckpoint cp;
    int r_idx;
    int committed = 0;
    int rc;

    memset(code, 0, sizeof(code));
    memset(krec_old, 0, sizeof(krec_old));
    memset(krec_new, 0, sizeof(krec_new));
    memset(kc, 0, sizeof(kc));
    memset(&new_slot, 0, sizeof(new_slot));
    memset(&old_slot, 0, sizeof(old_slot));
    memset(&rk, 0, sizeof(rk));

    if (v == NULL || password == NULL || old_recovery_text == NULL ||
        new_text == NULL) {
        return VTY_E_INVALID;
    }
    if (new_cap < VTY_RECOVERY_TEXT_BUF) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (strlen(v->path) == 0) return VTY_E_INVALID;

    r_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_RECOVERY);
    if (r_idx < 0) return VTY_E_SLOT_MISSING;

    rc = vty_vault_verify_user_password(v, password);
    if (rc != VTY_OK) return rc;

    rc = vty_recovery_slot_open(&v->slots[r_idx], old_recovery_text,
                                &v->header, (uint32_t)r_idx, &rk, krec_old);
    if (rc == VTY_OK) {
        rc = vty_keyring_find(&rk, VTY_KEYKIND_KC, NULL, 0, kc);
    }
    if (rc == VTY_OK && vty_ct_equal(kc, v->kc, VTY_KEY_BYTES) != 0) {
        rc = VTY_E_KEY_INVALID;
    }
    if (rc != VTY_OK) goto out;

    rc = vty_recovery_generate(code, new_text, new_cap);
    if (rc != VTY_OK) goto out;
    rc = vty_recovery_slot_seal(&new_slot, v->kc, code, &v->header,
                                (uint32_t)r_idx, v->mem_kib, v->iters,
                                v->parallel, krec_new);
    if (rc != VTY_OK) goto out;

    rc = vty_store_checkpoint(v->store, &cp);
    if (rc != VTY_OK) goto out;
    rc = vty_module_recovery_reseal_all(v, krec_old, krec_new);
    if (rc == VTY_OK) rc = vty_vault_commit_store(v);
    if (rc != VTY_OK) {
        (void)vty_store_restore(v->store, &cp);
        goto out;
    }
    committed = 1;

    old_slot = v->slots[r_idx];
    v->slots[r_idx] = new_slot;
    if (v->recovery_mode) memcpy(v->k_recovery, krec_new, VTY_KEY_BYTES);
    rc = vty_vault_save_meta(v);
    if (rc != VTY_OK) {
        v->slots[r_idx] = old_slot;
        v->unlocked = 0;
    }

out:
    if (rc != VTY_OK) {
        if (committed) (void)vty_store_restore(v->store, &cp);
        /* 新码只在完整成功后才允许交付；失败必须擦除输出缓冲，
         * 否则调用方会拿到一个磁盘上不存在的恢复码。 */
        vty_secure_zero(new_text, new_cap);
    }
    vty_secure_zero(code, sizeof(code));
    vty_secure_zero(krec_old, sizeof(krec_old));
    vty_secure_zero(krec_new, sizeof(krec_new));
    vty_secure_zero(kc, sizeof(kc));
    vty_secure_zero(&new_slot, sizeof(new_slot));
    vty_secure_zero(&old_slot, sizeof(old_slot));
    vty_secure_zero(&rk, sizeof(rk));
    return rc;
}

static int save_internal(VtyVault *v, int commit_store)
{
    uint8_t *copy = NULL;
    size_t body_len = 0;
    uint32_t target;
    uint8_t *readback = NULL;
    VtyMetaCopy check;
    VtyKeyring kr;
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (v->path[0] == '\0') return VTY_E_INVALID;
    if (v->header.generation == UINT64_MAX) return VTY_E_RESOURCE;

    /* 先提交数据区（flush 追加段并生成新 DataRoot），再写元数据；
     * 反序会让元数据引用未落盘的段。模块事务在调用 save_meta 前
     * 已单独提交，避免同一逻辑提交重复生成目录根。 */
    if (commit_store && v->store != NULL) {
        VtyDataRootLocator loc;
        uint8_t hash[VTY_HASH_BYTES];
        rc = vty_store_commit(v->store, &loc, hash);
        if (rc != VTY_OK) return rc;
        v->data_root = loc;
        memcpy(v->data_root_hash, hash, VTY_HASH_BYTES);
    }

    rc = keyring_set_data_root(&v->keyring, v->data_root_hash, &v->data_root);
    if (rc != VTY_OK) return rc;

    v->header.generation++;
    copy = (uint8_t *)vty_alloc(VTY_META_COPY_BYTES);
    readback = (uint8_t *)vty_alloc(VTY_META_COPY_BYTES);
    if (copy == NULL || readback == NULL) {
        rc = VTY_E_RESOURCE;
        goto fail;
    }
    rc = build_meta_copy(v, copy, &body_len);
    if (rc != VTY_OK) goto fail;
    (void)body_len;

    target = v->active_copy ^ 1u;
    rc = write_range_locked(v->path, (uint64_t)target * VTY_META_COPY_BYTES,
                            copy, VTY_META_COPY_BYTES);
    if (rc != VTY_OK) goto fail;

    /* 回读并认证非活动副本：只有确认 K_c 能解开新 body，才允许
     * 推进回退锚点；否则“文件已新、锚点未推进”会留下静默窗口。 */
    rc = read_range(v->path, (uint64_t)target * VTY_META_COPY_BYTES,
                    readback, VTY_META_COPY_BYTES, NULL);
    if (rc != VTY_OK) goto fail;
    memset(&check, 0, sizeof(check));
    rc = parse_meta_copy(readback, target, &check);
    if (rc != VTY_OK) goto fail;
    if (check.h.generation != v->header.generation) {
        rc = VTY_E_CORRUPT;
        goto fail;
    }
    memset(&kr, 0, sizeof(kr));
    rc = open_body_copy(&check.h, check.digest, check.body, check.body_len,
                        v->kc, &kr);
    if (rc != VTY_OK) goto fail;

    /* 轮换临时库构建期间不推进锚点：提交前的新库代可能低于源库锚点，
     * 提前推进会让源库在回滚路径上被锚点拒绝。 */
    if (vty_rollback_enabled() && !v->no_rollback_anchor) {
        rc = vty_rollback_commit(v->header.vault_uuid, v->header.generation);
        if (rc != VTY_OK) goto fail;
    }

    /* 回读副本是本次提交的权威头：把长度/槽数/Keyring 长度同步回会话，
     * 避免后续 PCR 开关等操作沿用上一次保存的旧预算。 */
    v->header.header_len = check.h.header_len;
    v->header.slot_count = check.h.slot_count;
    v->header.keyring_len = check.h.keyring_len;
    v->active_copy = target;
    vty_free(copy, VTY_META_COPY_BYTES);
    vty_free(readback, VTY_META_COPY_BYTES);
    vty_secure_zero(&kr, sizeof(kr));
    return VTY_OK;

fail:
    if (copy != NULL) vty_free(copy, VTY_META_COPY_BYTES);
    if (readback != NULL) vty_free(readback, VTY_META_COPY_BYTES);
    /* 磁盘状态不确定或锚点未推进：锁定会话，调用方重新打开以实际
     * 落盘内容为准。 */
    v->unlocked = 0;
    return rc;
}

int vty_vault_commit_store(VtyVault *v)
{
    VtyDataRootLocator loc;
    uint8_t hash[VTY_HASH_BYTES];
    int rc;

    if (v == NULL || !v->unlocked || v->store == NULL) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    rc = vty_store_commit(v->store, &loc, hash);
    if (rc != VTY_OK) return rc;
    v->data_root = loc;
    memcpy(v->data_root_hash, hash, VTY_HASH_BYTES);
    return VTY_OK;
}

int vty_vault_verify_persist(const VtyVault *v, VtyPersistCheck *out)
{
    int rc;

    if (v == NULL || out == NULL) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    if (!v->unlocked || v->store == NULL) return VTY_E_POLICY;
    out->header_magic = v->header.magic;
    out->header_version = v->header.version_major;
    rc = vty_store_verify_data_root(v->store, &v->data_root,
                                    v->data_root_hash, &out->file_size,
                                    &out->mtime_ms);
    return rc;
}

int vty_vault_save(VtyVault *v)
{
    return save_internal(v, 1);
}

int vty_vault_save_meta(VtyVault *v)
{
    return save_internal(v, 0);
}

int vty_vault_pcr_slot_prepare(VtyVault *v, uint32_t select, VtySlot *slot)
{
    int rc;

    memset(slot, 0, sizeof(*slot));
    rc = vty_tpm_pcr_select_valid(select);
    if (rc != VTY_OK) return rc;
    rc = vty_tpm_pcr_key_create(v->header.vault_uuid, select, NULL, 0);
    if (rc != VTY_OK) return rc;

    slot->slot_type = VTY_SLOT_DEVICE_PCR;
    slot->slot_flags = VTY_SLOT_FLAG_REQUIRED;
    slot->kdf_id = VTY_KDF_NONE;
    slot->wrap_alg = VTY_WRAP_RSAOAEP;
    slot->params_len = VTY_SLOT_PARAMS_PCR;
    slot->pcr_select = select;
    rc = vty_tpm_pcr_measure(select, slot->pcr_digest);
    if (rc == VTY_OK) {
        rc = vty_tpm_pcr_seal(v->header.vault_uuid, v->kc, slot->ct);
    }
    if (rc != VTY_OK) {
        (void)vty_tpm_pcr_key_delete(v->header.vault_uuid);
        memset(slot, 0, sizeof(*slot));
        return VTY_E_TPM;
    }
    slot->ct_len = VTY_SLOT_PCR_CT_BYTES;
    return VTY_OK;
}

int vty_vault_pcr_enable(VtyVault *v, uint32_t pcr_select)
{
    VtySlot slot;
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    if (vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR) >= 0) {
        return VTY_E_POLICY;
    }
    if (v->slot_count >= VTY_MAX_SLOTS) return VTY_E_RESOURCE;
    if (!vty_tpm_pcr_available()) return VTY_E_TPM;

    rc = vty_vault_pcr_slot_prepare(v, pcr_select, &slot);
    if (rc != VTY_OK) return rc;

    v->slots[v->slot_count] = slot;
    v->slot_count++;
    v->header.flags |= VTY_FLAG_PCR;
    rc = vty_vault_save(v);
    if (rc != VTY_OK) v->unlocked = 0;
    return rc;
}

int vty_vault_pcr_disable(VtyVault *v)
{
    int p_idx;
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    p_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    if (p_idx < 0) return VTY_E_POLICY;
    if ((uint32_t)p_idx != v->slot_count - 1u) return VTY_E_CORRUPT;
    if ((v->header.flags & VTY_FLAG_HIGH_SECURITY) != 0 &&
        (v->header.flags & VTY_FLAG_KEYFILE) == 0) {
        return VTY_E_POLICY;
    }

    v->slot_count--;
    v->header.flags &= (uint16_t)~VTY_FLAG_PCR;
    rc = vty_vault_save(v);
    if (rc != VTY_OK) {
        v->unlocked = 0;
        return rc;
    }
    (void)vty_tpm_pcr_key_delete(v->header.vault_uuid);
    return VTY_OK;
}

int vty_vault_pcr_reseal(VtyVault *v)
{
    int p_idx;
    uint8_t digest[VTY_HASH_BYTES];
    uint8_t ct[VTY_TPM_PCR_CT_BYTES];
    uint8_t check[VTY_KEY_BYTES];
    int rc;

    if (v == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (v->rotate_pending) return VTY_E_ROTATE_PENDING;
    p_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    if (p_idx < 0) return VTY_E_POLICY;
    if (!vty_tpm_pcr_available()) return VTY_E_TPM;

    memset(digest, 0, sizeof(digest));
    memset(ct, 0, sizeof(ct));
    vty_secure_zero(check, sizeof(check));

    rc = vty_tpm_pcr_key_create(v->header.vault_uuid,
                                v->slots[p_idx].pcr_select, NULL, 0);
    if (rc != VTY_OK) return rc;
    rc = vty_tpm_pcr_measure(v->slots[p_idx].pcr_select, digest);
    if (rc == VTY_OK) {
        rc = vty_tpm_pcr_seal(v->header.vault_uuid, v->kc, ct);
    }
    if (rc == VTY_OK) {
        rc = vty_tpm_pcr_unseal(v->header.vault_uuid, ct, check);
    }
    if (rc == VTY_OK && vty_ct_equal(check, v->kc, VTY_KEY_BYTES) != 0) {
        rc = VTY_E_TPM;
    }
    vty_secure_zero(check, sizeof(check));
    if (rc != VTY_OK) {
        vty_secure_zero(digest, sizeof(digest));
        vty_secure_zero(ct, sizeof(ct));
        return VTY_E_TPM;
    }

    memcpy(v->slots[p_idx].pcr_digest, digest, VTY_HASH_BYTES);
    memcpy(v->slots[p_idx].ct, ct, VTY_TPM_PCR_CT_BYTES);
    vty_secure_zero(digest, sizeof(digest));
    vty_secure_zero(ct, sizeof(ct));
    rc = vty_vault_save(v);
    if (rc != VTY_OK) v->unlocked = 0;
    return rc;
}

int vty_vault_system_key(const VtyVault *v, uint8_t key_out[VTY_KEY_BYTES])
{
    if (v == NULL || key_out == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    /* K_c 已由容器解锁认证；派生只做域分离，不引入新因子。 */
    return vty_hkdf_expand(key_out, v->kc,
                           (const uint8_t *)VTY_DOMAIN_SYSTEM_RECORD,
                           strlen(VTY_DOMAIN_SYSTEM_RECORD));
}

int vty_vault_module_key_index(const VtyVault *v, uint32_t index,
                               uint8_t key_out[VTY_KEY_BYTES])
{
    if (v == NULL || key_out == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;

    if (v->modules[index].deleted) return VTY_E_POLICY;
    if (v->modules[index].enabled) {
        /* 启用后 MDEK 不再存在于 Keyring；未解锁即策略拒绝，
         * 绝不回退到 Keyring 或描述符包裹密文。 */
        if (!v->modules[index].unlocked) return VTY_E_POLICY;
        memcpy(key_out, v->modules[index].mdek, VTY_KEY_BYTES);
        return VTY_OK;
    }
    return vty_keyring_find(&v->keyring, VTY_KEYKIND_MDEK,
                            v->modules[index].uuid, VTY_UUID_BYTES, key_out);
}

int vty_vault_module_key(const VtyVault *v, const uint8_t module_uuid[VTY_UUID_BYTES],
                         uint8_t key_out[VTY_KEY_BYTES])
{
    uint32_t i;

    if (v == NULL || module_uuid == NULL || key_out == NULL) return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;
    /* 系统记录域不属于任何模块：按 K_c 派生，不受模块锁定影响。 */
    if (memcmp(module_uuid, vty_system_module_uuid, VTY_UUID_BYTES) == 0) {
        return vty_vault_system_key(v, key_out);
    }
    for (i = 0; i < VTY_MODULE_COUNT; i++) {
        if (memcmp(v->modules[i].uuid, module_uuid, VTY_UUID_BYTES) == 0) {
            return vty_vault_module_key_index(v, i, key_out);
        }
    }
    /* 记录叶引用了模块表中不存在的 UUID：目录/记录交叉损坏 */
    return VTY_E_CORRUPT;
}

int vty_vault_module_uuid(const VtyVault *v, uint32_t index,
                          uint8_t out[VTY_UUID_BYTES])
{
    if (v == NULL || out == NULL) return VTY_E_INVALID;
    if (index >= VTY_MODULE_COUNT) return VTY_E_INVALID;
    memcpy(out, v->modules[index].uuid, VTY_UUID_BYTES);
    return VTY_OK;
}

int vty_vault_verify_password(VtyVault *v, const char *password)
{
    uint8_t share_u[VTY_KEY_BYTES];
    uint8_t share_d[VTY_KEY_BYTES];
    uint8_t kc[VTY_KEY_BYTES];
    int u_idx, d_idx;
    int rc;

    if (v == NULL || password == NULL || password[0] == '\0') return VTY_E_INVALID;
    if (!v->unlocked) return VTY_E_POLICY;

    u_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_USER_PASSWORD);
    d_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    if (u_idx < 0 || d_idx < 0) return VTY_E_SLOT_MISSING;
    if ((v->header.flags & VTY_FLAG_KEYFILE) != 0 && !v->keyfile_digest_set) {
        return VTY_E_KEYFILE_REQUIRED;
    }

    memset(share_u, 0, sizeof(share_u));
    memset(share_d, 0, sizeof(share_d));
    rc = open_user_slot(&v->slots[u_idx], password,
                        (v->header.flags & VTY_FLAG_KEYFILE) != 0
                            ? v->keyfile_digest : NULL,
                        &v->header, (uint32_t)u_idx, share_u);
    if (rc == VTY_OK) {
        rc = vty_slot_open_device(&v->slots[d_idx], &v->header,
                                  (uint32_t)d_idx, share_d);
    }
    if (rc == VTY_OK) {
        size_t i;
        for (i = 0; i < VTY_KEY_BYTES; i++) kc[i] = (uint8_t)(share_u[i] ^ share_d[i]);
        if (vty_ct_equal(kc, v->kc, VTY_KEY_BYTES) != 0) rc = VTY_E_KEY_INVALID;
    }
    vty_secure_zero(share_u, sizeof(share_u));
    vty_secure_zero(share_d, sizeof(share_d));
    vty_secure_zero(kc, sizeof(kc));
    return rc;
}

void vty_vault_lock(VtyVault *v)
{
    if (v == NULL) return;
    /* 先关闭数据区会话（flush 未提交段），再清零密钥；反序会让
     * store 在密钥已为零时执行 flush/关闭。 */
    if (v->store != NULL) {
        vty_store_close(v->store);
        v->store = NULL;
    }
    vty_secure_zero(v->kc, sizeof(v->kc));
    vty_secure_zero(&v->keyring, sizeof(v->keyring));
    vty_secure_zero(&v->data_root, sizeof(v->data_root));
    vty_secure_zero(v->data_root_hash, sizeof(v->data_root_hash));
    vty_secure_zero(v->modules, sizeof(v->modules));
    vty_secure_zero(v->k_recovery, sizeof(v->k_recovery));
    vty_secure_zero(v->keyfile_digest, sizeof(v->keyfile_digest));
    v->keyfile_digest_set = 0;
    v->recovery_mode = 0;
    v->no_rollback_anchor = 0;
    v->rotate_pending = 0;
    v->unlocked = 0;
    /* Keyring 的 32 字节条目会被编译器溢出到栈槽位，缓冲区清零无法覆盖 */
    vty_wipe_stack();
}

void vty_vault_free(VtyVault *v)
{
    if (v == NULL) return;
    vty_vault_lock(v);
    vty_secure_free(v);
}

int vty_vault_binding_info(const VtyVault *v, VtyVaultBindingInfo *out)
{
    int device_idx;
    int pcr_idx;

    if (out == NULL) return VTY_E_INVALID;
    memset(out, 0, sizeof(*out));
    if (v == NULL) return VTY_E_INVALID;

    out->unlocked = v->unlocked ? 1u : 0u;
    device_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_ROOT);
    pcr_idx = vty_slot_find(v->slots, v->slot_count, VTY_SLOT_DEVICE_PCR);
    out->device_bound = (device_idx >= 0) ? 1u : 0u;
    out->pcr_bound = (pcr_idx >= 0) ? 1u : 0u;
    return VTY_OK;
}
