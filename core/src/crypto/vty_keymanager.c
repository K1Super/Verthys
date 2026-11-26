/*
 * vty_keymanager.c — 密钥管理基础契约：路径与编码、用户密钥、槽位封开、keyfile 与范围 IO
 */

#include "vty_keymanager_internal.h"

/* 系统记录域保留 UUID：ASCII "VTYSYSTEM" + 8 字节零填充。
 * 不进入模块表，不参与模块 UUID 唯一性校验，不可启用或删除。 */
const uint8_t vty_system_module_uuid[VTY_UUID_BYTES] = {
    0x56u, 0x54u, 0x59u, 0x53u, 0x59u, 0x53u, 0x54u, 0x45u,
    0x4Du, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
};


wchar_t *vty_km_utf8_to_wide(const char *s)
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

/* 用户槽 KDF 输入：无 keyfile 时直接使用 password 字节；有 keyfile 时
 * 用长度前缀把 password 与 keyfile_digest 拼成无歧义输入。 */
int vty_km_make_user_secret(const char *password, const uint8_t *keyfile_digest,
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
        /* 固定分配上限：vty_km_free_user_secret 以同一长度清零/释放，避免
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

void vty_km_free_user_secret(uint8_t *owned)
{
    if (owned != NULL) {
        vty_secure_zero(owned, 4u + 1024u + 4u + VTY_KEY_BYTES);
        vty_free(owned, 4u + 1024u + 4u + VTY_KEY_BYTES);
    }
}

int vty_km_seal_user_slot(VtySlot *s, uint8_t slot_type, uint8_t slot_flags,
                          const char *password, const uint8_t *keyfile_digest,
                          const uint8_t key[VTY_KEY_BYTES],
                          const VtyHeader *h, uint32_t index,
                          uint32_t mem_kib, uint32_t iters, uint32_t parallel)
{
    uint8_t *owned = NULL;
    const uint8_t *secret = NULL;
    size_t secret_len = 0;
    int rc;

    rc = vty_km_make_user_secret(password, keyfile_digest, &owned, &secret, &secret_len);
    if (rc == VTY_OK) {
        rc = vty_slot_seal_argon2id(s, slot_type, slot_flags, secret, secret_len,
                                    key, h, index, mem_kib, iters, parallel);
    }
    vty_km_free_user_secret(owned);
    return rc;
}

int vty_km_open_user_slot(const VtySlot *s, const char *password,
                          const uint8_t *keyfile_digest,
                          const VtyHeader *h, uint32_t index,
                          uint8_t key_out[VTY_KEY_BYTES])
{
    uint8_t *owned = NULL;
    const uint8_t *secret = NULL;
    size_t secret_len = 0;
    int rc;

    rc = vty_km_make_user_secret(password, keyfile_digest, &owned, &secret, &secret_len);
    if (rc == VTY_OK) {
        rc = vty_slot_open_argon2id(s, secret, secret_len, h, index, key_out);
    }
    vty_km_free_user_secret(owned);
    return rc;
}

/* 读取并解析 VKFL，返回 KDF 摘要。keyfile 只在本进程内存中出现。 */
int vty_km_load_keyfile_digest(const char *path, uint8_t digest[VTY_KEY_BYTES])
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
    wpath = vty_km_utf8_to_wide(path);
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
void vty_km_delete_file_utf8(const char *path)
{
    wchar_t *w;

    if (path == NULL) return;
    w = vty_km_utf8_to_wide(path);
    if (w != NULL) {
        (void)DeleteFileW(w);
        free(w);
    }
}

int vty_km_write_keyfile_file(const char *path,
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
    base = vty_km_utf8_to_wide(path);
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

int vty_km_read_range(const char *path, uint64_t offset,
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
    wpath = vty_km_utf8_to_wide(path);
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

int vty_km_write_range_locked(const char *path, uint64_t offset,
                              const uint8_t *buf, size_t len)
{
    wchar_t *wpath;
    HANDLE h = INVALID_HANDLE_VALUE;
    LARGE_INTEGER pos;
    OVERLAPPED ov;
    DWORD written = 0;
    int rc = VTY_OK;

    if (path == NULL || buf == NULL || len == 0 || len > 0xFFFFFFFFu) return VTY_E_INVALID;
    wpath = vty_km_utf8_to_wide(path);
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
