/*
 * vty_secure_delete.c — 零写 + 刷盘 + 删除
 */
#include "vty_secure_delete.h"
#include "vty_util.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#define SECURE_DELETE_CHUNK (64u * 1024u)
#define SECURE_PATH_MAX 4096u

static wchar_t *sd_to_wide(const char *s)
{
    wchar_t *w;
    int n;

    if (s == NULL || s[0] == '\0') return NULL;
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

int vty_secure_delete_file(const char *path)
{
    wchar_t *w;
    HANDLE h;
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER size;
    uint8_t *zeros;
    LARGE_INTEGER pos;
    DWORD attrs;
    int deleted = 0;
    int rc = VTY_OK;

    if (path == NULL || path[0] == '\0') return VTY_E_INVALID;
    w = sd_to_wide(path);
    if (w == NULL) return VTY_E_INVALID;

    attrs = GetFileAttributesW(w);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD err = GetLastError();
        free(w);
        return (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
                   ? VTY_OK
                   : VTY_E_IO;
    }
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        free(w);
        return VTY_E_INVALID;
    }

    h = CreateFileW(w, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        /* 只读文件：清属性后重试一次。 */
        SetFileAttributesW(w, attrs & ~FILE_ATTRIBUTE_READONLY);
        h = CreateFileW(w, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    }
    if (h == INVALID_HANDLE_VALUE) {
        free(w);
        return VTY_E_IO;
    }

    memset(&info, 0, sizeof(info));
    if (!GetFileInformationByHandle(h, &info) ||
        info.nNumberOfLinks != 1u) {
        CloseHandle(h);
        free(w);
        return VTY_E_INVALID;
    }
    if (!GetFileSizeEx(h, &size) || size.QuadPart < 0) {
        CloseHandle(h);
        free(w);
        return VTY_E_IO;
    }

    zeros = (uint8_t *)vty_alloc(SECURE_DELETE_CHUNK);
    if (zeros == NULL) {
        CloseHandle(h);
        free(w);
        return VTY_E_RESOURCE;
    }
    memset(zeros, 0, SECURE_DELETE_CHUNK);
    pos.QuadPart = 0;
    while (pos.QuadPart < size.QuadPart) {
        LONGLONG remain = size.QuadPart - pos.QuadPart;
        DWORD chunk = (DWORD)((remain < (LONGLONG)SECURE_DELETE_CHUNK)
                                  ? remain
                                  : (LONGLONG)SECURE_DELETE_CHUNK);
        DWORD written = 0;
        OVERLAPPED ov;

        memset(&ov, 0, sizeof(ov));
        ov.Offset = (DWORD)(pos.QuadPart & 0xFFFFFFFF);
        ov.OffsetHigh = (DWORD)((unsigned long long)pos.QuadPart >> 32);
        if (!WriteFile(h, zeros, chunk, &written, &ov) ||
            written != chunk) {
            rc = VTY_E_IO;
            break;
        }
        pos.QuadPart += chunk;
    }
    vty_secure_zero(zeros, SECURE_DELETE_CHUNK);
    vty_free(zeros, SECURE_DELETE_CHUNK);
    if (rc == VTY_OK && !FlushFileBuffers(h)) rc = VTY_E_IO;
    CloseHandle(h);
    if (rc != VTY_OK) {
        free(w);
        return rc;
    }

    if (DeleteFileW(w)) {
        deleted = 1;
    } else {
        SetFileAttributesW(w, attrs & ~FILE_ATTRIBUTE_READONLY);
        deleted = DeleteFileW(w) ? 1 : 0;
    }
    free(w);
    return deleted ? VTY_OK : VTY_E_IO;
}

static int sd_exists(const char *path)
{
    wchar_t *w;
    DWORD attrs;

    if (path == NULL) return 0;
    w = sd_to_wide(path);
    if (w == NULL) return 0;
    attrs = GetFileAttributesW(w);
    free(w);
    return attrs != INVALID_FILE_ATTRIBUTES;
}

static int sd_delete_suffix(const char *container_path, const char *suffix,
                            uint64_t *deleted, uint64_t *failed)
{
    char *path;
    size_t clen, slen;
    int rc;

    if (container_path == NULL || suffix == NULL) return VTY_E_INVALID;
    clen = strlen(container_path);
    slen = strlen(suffix);
    if (clen + slen + 1u > SECURE_PATH_MAX) return VTY_E_INVALID;
    path = (char *)malloc(clen + slen + 1u);
    if (path == NULL) return VTY_E_RESOURCE;
    memcpy(path, container_path, clen);
    memcpy(path + clen, suffix, slen + 1u);
    if (!sd_exists(path)) {
        free(path);
        return VTY_OK;
    }
    rc = vty_secure_delete_file(path);
    free(path);
    if (rc == VTY_OK) {
        if (deleted != NULL) (*deleted)++;
    } else {
        if (failed != NULL) (*failed)++;
    }
    return rc;
}

int vty_secure_delete_maintain(const char *container_path,
                               uint64_t *out_deleted,
                               uint64_t *out_failed)
{
    uint64_t deleted = 0;
    uint64_t failed = 0;
    int rc;

    if (out_deleted != NULL) *out_deleted = 0;
    if (out_failed != NULL) *out_failed = 0;
    if (container_path == NULL) return VTY_E_INVALID;

    /* 只清理压缩作业的临时库/备份。轮换备份可能被 keep_old 显式保留，
     * 不能按文件名猜测并删除；轮换提交路径自行安全删除。 */
    rc = sd_delete_suffix(container_path, ".vtycompact.tmp", &deleted, &failed);
    if (rc != VTY_OK && rc != VTY_E_IO) failed++;
    rc = sd_delete_suffix(container_path, ".vtycompact.bak", &deleted, &failed);
    if (rc != VTY_OK && rc != VTY_E_IO) failed++;

    if (out_deleted != NULL) *out_deleted = deleted;
    if (out_failed != NULL) *out_failed = failed;
    return VTY_OK;
}
