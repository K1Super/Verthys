/*
 * util_fs.c — 宽字符路径、文件读写与原子替换
 */

#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

int vty_wide_copy(wchar_t *dst, size_t cap, const wchar_t *src)
{
    size_t len;

    if (dst == NULL || cap == 0 || src == NULL) return -1;
    len = wcslen(src);
    if (len >= cap) return -1;
    memcpy(dst, src, (len + 1u) * sizeof(wchar_t));
    return 0;
}

int vty_path_join(wchar_t *out, size_t cap, const wchar_t *dir,
                  const wchar_t *name)
{
    size_t dlen;
    size_t nlen;
    int need_sep;
    size_t total;

    if (out == NULL || cap == 0 || dir == NULL || name == NULL) return -1;
    dlen = wcslen(dir);
    nlen = wcslen(name);
    need_sep = (dlen > 0 && dir[dlen - 1u] != L'\\' && dir[dlen - 1u] != L'/');
    total = dlen + (size_t)need_sep + nlen + 1u;
    if (total > cap) return -1;
    memcpy(out, dir, dlen * sizeof(wchar_t));
    if (need_sep) {
        out[dlen] = L'\\';
    }
    memcpy(out + dlen + (size_t)need_sep, name, (nlen + 1u) * sizeof(wchar_t));
    return 0;
}

int vty_known_folder(REFKNOWNFOLDERID folder, wchar_t *out, size_t cap)
{
    PWSTR wide = NULL;
    int rc = -1;

    if (out == NULL || cap == 0) return -1;
    if (SHGetKnownFolderPath(folder, KF_FLAG_CREATE, NULL, &wide) == S_OK &&
        wide != NULL) {
        if (vty_wide_copy(out, cap, wide) == 0) {
            rc = 0;
        }
    }
    if (wide != NULL) {
        CoTaskMemFree(wide);
    }
    return rc;
}

int vty_path_exists(const wchar_t *path)
{
    if (path == NULL || path[0] == L'\0') return 0;
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES ? 1 : 0;
}

int vty_path_is_directory(const wchar_t *path)
{
    DWORD attr;

    if (path == NULL || path[0] == L'\0') return 0;
    attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return 0;
    return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0 ? 1 : 0;
}

int vty_path_has_reparse(const wchar_t *path, int allow_missing)
{
    DWORD attr;

    if (path == NULL || path[0] == L'\0') return 0;
    attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return allow_missing ? 1 : 0;
    }
    return (attr & FILE_ATTRIBUTE_REPARSE_POINT) == 0 ? 1 : 0;
}

int vty_read_file_exact(const wchar_t *path, uint8_t *buf, DWORD expected,
                        DWORD cap)
{
    HANDLE file;
    LARGE_INTEGER size;
    DWORD got = 0;
    DWORD total = 0;
    int rc = -1;

    if (path == NULL || buf == NULL || expected > cap || expected == 0) {
        return -1;
    }
    if (!vty_path_has_reparse(path, 0) || vty_path_is_directory(path)) {
        return -1;
    }
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    if (!GetFileSizeEx(file, &size) || size.QuadPart != (LONGLONG)expected) {
        goto done;
    }
    while (total < expected) {
        if (!ReadFile(file, buf + total, expected - total, &got, NULL) ||
            got == 0) {
            goto done;
        }
        total += got;
    }
    rc = 0;

done:
    CloseHandle(file);
    if (rc != 0) {
        vty_secure_zero(buf, cap);
    }
    return rc;
}

int vty_read_file_any(const wchar_t *path, uint8_t *buf, DWORD cap, DWORD *len)
{
    HANDLE file;
    LARGE_INTEGER size;
    DWORD got = 0;
    DWORD total = 0;
    int rc = -1;

    if (path == NULL || buf == NULL || len == NULL || cap == 0) return -1;
    *len = 0;
    if (!vty_path_has_reparse(path, 0) || vty_path_is_directory(path)) {
        return -1;
    }
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > (LONGLONG)cap) {
        goto done;
    }
    while (total < (DWORD)size.QuadPart) {
        if (!ReadFile(file, buf + total, (DWORD)size.QuadPart - total, &got,
                      NULL) ||
            got == 0) {
            goto done;
        }
        total += got;
    }
    *len = total;
    rc = 0;

done:
    CloseHandle(file);
    if (rc != 0) {
        vty_secure_zero(buf, cap);
    }
    return rc;
}

int vty_write_file_atomic_named(const wchar_t *dir, const wchar_t *final_name,
                                const wchar_t *temp_name,
                                const uint8_t *data, DWORD len)
{
    wchar_t temp[VTY_PATH_MAX];
    wchar_t final_path[VTY_PATH_MAX];
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD total = 0;
    DWORD written = 0;
    int attempt;
    int rc = -1;

    if (dir == NULL || final_name == NULL || temp_name == NULL ||
        data == NULL || len == 0) {
        return -1;
    }
    if (vty_path_join(final_path, VTY_PATH_MAX, dir, final_name) != 0) {
        return -1;
    }
    if (vty_path_join(temp, VTY_PATH_MAX, dir, temp_name) != 0) return -1;

    for (attempt = 0; attempt < 2; attempt++) {
        file = CreateFileW(temp, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_TEMPORARY, NULL);
        if (file != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_FILE_EXISTS || attempt != 0) return -1;
        if (!DeleteFileW(temp)) return -1;
    }
    if (file == INVALID_HANDLE_VALUE) return -1;

    while (total < len) {
        if (!WriteFile(file, data + total, len - total, &written, NULL) ||
            written == 0) {
            goto done;
        }
        total += written;
    }
    if (!FlushFileBuffers(file)) goto done;
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(temp, final_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        goto done;
    }
    rc = 0;

done:
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    if (rc != 0) {
        DeleteFileW(temp);
    }
    return rc;
}

int vty_write_file_atomic(const wchar_t *dir, const wchar_t *name,
                          const uint8_t *data, DWORD len)
{
    wchar_t temp_name[VTY_PATH_MAX];
    size_t nlen;

    if (name == NULL) return -1;
    nlen = wcslen(name);
    if (nlen + 5u >= VTY_PATH_MAX) return -1;
    memcpy(temp_name, name, nlen * sizeof(wchar_t));
    memcpy(temp_name + nlen, L".tmp", 5u * sizeof(wchar_t));
    return vty_write_file_atomic_named(dir, name, temp_name, data, len);
}
