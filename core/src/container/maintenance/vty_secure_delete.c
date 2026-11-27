/*
 * vty_secure_delete.c — 零写 + TRIM + 刷盘 + 删除
 *
 * 维护路径带时间预算：解锁不能被与容器同量级的残留文件拖住。预算内未
 * 完成的文件保持原样，下次解锁继续（零写幂等）。安全边界仍是密码学
 * 销毁为主，零写与 TRIM 是尽力而为的物理残留收敛。
 */
#include "vty_secure_delete.h"
#include "vty_util.h"

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#define SECURE_DELETE_CHUNK (1024u * 1024u)
#define SECURE_DELETE_BUDGET_MS 1500u
#define SECURE_PATH_MAX 4096u
#define SECURE_TRIM_RANGES 1u

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

/* 预算检查：0 表示不设截止时间。 */
static int sd_budget_hit(uint64_t deadline_ms)
{
    return deadline_ms != 0u && GetTickCount64() >= deadline_ms;
}

static int sd_zero_span(HANDLE h, uint64_t off, uint64_t len,
                        uint64_t deadline_ms, const uint8_t *zeros,
                        int *deferred)
{
    while (len != 0u) {
        DWORD chunk;
        DWORD written = 0;
        OVERLAPPED ov;

        if (sd_budget_hit(deadline_ms)) {
            if (deferred != NULL) *deferred = 1;
            return VTY_OK;
        }
        chunk = (DWORD)((len < (uint64_t)SECURE_DELETE_CHUNK)
                            ? len
                            : (uint64_t)SECURE_DELETE_CHUNK);
        memset(&ov, 0, sizeof(ov));
        ov.Offset = (DWORD)(off & 0xFFFFFFFFu);
        ov.OffsetHigh = (DWORD)(off >> 32);
        if (!WriteFile(h, zeros, chunk, &written, &ov) || written != chunk) {
            return VTY_E_IO;
        }
        off += chunk;
        len -= chunk;
    }
    return VTY_OK;
}

/* 只覆写已分配区间：稀疏文件跳过空洞，避免对逻辑大小远大于物理大小
 * 的残留文件做无意义写入。FSCTL 不支持时退回整文件覆写。 */
static int sd_zero_file(HANDLE h, uint64_t size, uint64_t deadline_ms,
                        const uint8_t *zeros, int *deferred)
{
    FILE_ALLOCATED_RANGE_BUFFER query;
    FILE_ALLOCATED_RANGE_BUFFER ranges[64];
    DWORD got = 0;
    int ok;

    if (size == 0u) return VTY_OK;
    memset(&query, 0, sizeof(query));
    query.FileOffset.QuadPart = 0;
    query.Length.QuadPart = (LONGLONG)size;
    memset(ranges, 0, sizeof(ranges));
    ok = DeviceIoControl(h, FSCTL_QUERY_ALLOCATED_RANGES, &query,
                         sizeof(query), ranges, sizeof(ranges), &got, NULL);
    if (ok) {
        size_t count;
        size_t i;

        if (got == 0u) return VTY_OK; /* 全稀疏：没有已分配簇需要覆写 */
        count = (size_t)got / sizeof(ranges[0]);
        for (i = 0; i < count; i++) {
            uint64_t roff = (uint64_t)ranges[i].FileOffset.QuadPart;
            uint64_t rlen = (uint64_t)ranges[i].Length.QuadPart;
            int rc;

            if (rlen == 0u) continue;
            if (roff > size || rlen > size - roff) {
                rc = sd_zero_span(h, 0, size, deadline_ms, zeros, deferred);
            } else {
                rc = sd_zero_span(h, roff, rlen, deadline_ms, zeros, deferred);
            }
            if (rc != VTY_OK) return rc;
            if (deferred != NULL && *deferred) return VTY_OK;
        }
        return VTY_OK;
    }
    return sd_zero_span(h, 0, size, deadline_ms, zeros, deferred);
}

/* 尽力而为：把已零写并刷盘的簇标记为空闲，压低 SSD FTL 的旧页残留。
 * 文件系统不支持时忽略，不作为删除失败条件。 */
static void sd_trim_file(HANDLE h, uint64_t size)
{
    FILE_LEVEL_TRIM *trim;
    DWORD got = 0;
    size_t bytes = sizeof(FILE_LEVEL_TRIM);

    if (size == 0u) return;
    trim = (FILE_LEVEL_TRIM *)vty_alloc(bytes);
    if (trim == NULL) return;
    memset(trim, 0, bytes);
    trim->NumRanges = SECURE_TRIM_RANGES;
    trim->Ranges[0].Offset = 0;
    trim->Ranges[0].Length = (DWORDLONG)size;
    (void)DeviceIoControl(h, FSCTL_FILE_LEVEL_TRIM, trim, (DWORD)bytes,
                          NULL, 0, &got, NULL);
    vty_free(trim, bytes);
}

int vty_secure_delete_file_budget(const char *path, uint64_t deadline_ms,
                                  int *out_deferred)
{
    wchar_t *w;
    HANDLE h;
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER size;
    uint8_t *zeros;
    DWORD attrs;
    int deferred = 0;
    int deleted = 0;
    int rc = VTY_OK;

    if (out_deferred != NULL) *out_deferred = 0;
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
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        /* 只读文件：清属性后重试一次。 */
        SetFileAttributesW(w, attrs & ~FILE_ATTRIBUTE_READONLY);
        h = CreateFileW(w, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
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

    rc = sd_zero_file(h, (uint64_t)size.QuadPart, deadline_ms, zeros,
                      &deferred);
    vty_secure_zero(zeros, SECURE_DELETE_CHUNK);
    vty_free(zeros, SECURE_DELETE_CHUNK);

    if (rc == VTY_OK && !deferred) {
        if (!FlushFileBuffers(h)) rc = VTY_E_IO;
    }
    if (rc == VTY_OK && !deferred) {
        sd_trim_file(h, (uint64_t)size.QuadPart);
    }
    CloseHandle(h);
    if (rc != VTY_OK) {
        free(w);
        return rc;
    }
    if (deferred) {
        if (out_deferred != NULL) *out_deferred = 1;
        free(w);
        return VTY_OK;
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

int vty_secure_delete_file(const char *path)
{
    return vty_secure_delete_file_budget(path, 0u, NULL);
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
                            uint64_t deadline_ms, uint64_t *deleted,
                            uint64_t *failed)
{
    char *path;
    size_t clen, slen;
    int deferred = 0;
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
    rc = vty_secure_delete_file_budget(path, deadline_ms, &deferred);
    free(path);
    if (rc == VTY_OK && !deferred) {
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
    uint64_t deadline;
    int rc;

    if (out_deleted != NULL) *out_deleted = 0;
    if (out_failed != NULL) *out_failed = 0;
    if (container_path == NULL) return VTY_E_INVALID;

    /* 整个维护共享一个时间预算：残留文件再多也不阻断解锁。未完成项
     * 保留，下次解锁继续。 */
    deadline = GetTickCount64() + SECURE_DELETE_BUDGET_MS;

    /* 压缩遗留临时库/备份，以及轮换提交失败后转存的待删备份。
     * 轮换备份可能被 keep_old 显式保留，不按通配符猜测删除。 */
    rc = sd_delete_suffix(container_path, ".vtycompact.tmp", deadline,
                          &deleted, &failed);
    if (rc != VTY_OK && rc != VTY_E_IO) failed++;
    rc = sd_delete_suffix(container_path, ".vtycompact.bak", deadline,
                          &deleted, &failed);
    if (rc != VTY_OK && rc != VTY_E_IO) failed++;
    rc = sd_delete_suffix(container_path, ".vtysdel", deadline,
                          &deleted, &failed);
    if (rc != VTY_OK && rc != VTY_E_IO) failed++;

    if (out_deleted != NULL) *out_deleted = deleted;
    if (out_failed != NULL) *out_failed = failed;
    return VTY_OK;
}
