/*
 * test_common.c — 临时目录与测试工具实现
 */
#include "test_common.h"
#include "service_util.h"

#include <stdio.h>
#include <string.h>

static LONG g_temp_counter = 0;

int test_make_temp_dir(wchar_t *out, size_t cap)
{
    wchar_t base[MAX_PATH];
    DWORD n;

    if (out == NULL || cap == 0) return -1;
    n = GetTempPathW(MAX_PATH, base);
    if (n == 0 || n >= MAX_PATH) return -1;
    if (swprintf_s(out, cap, L"%sverthys-svc-test-%lu-%llu-%ld", base,
                  (unsigned long)GetCurrentProcessId(),
                  (unsigned long long)GetTickCount64(),
                  (long)InterlockedIncrement(&g_temp_counter)) < 0) {
        return -1;
    }
    return CreateDirectoryW(out, NULL) ? 0 : -1;
}

static void remove_tree_inner(const wchar_t *path)
{
    wchar_t pattern[VTY_PATH_MAX];
    WIN32_FIND_DATAW fd;
    HANDLE find;

    if (vty_path_join(pattern, VTY_PATH_MAX, path, L"*") != 0) {
        RemoveDirectoryW(path);
        return;
    }
    find = FindFirstFileW(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE) {
        RemoveDirectoryW(path);
        return;
    }
    do {
        wchar_t full[VTY_PATH_MAX];
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0) {
            continue;
        }
        if (vty_path_join(full, VTY_PATH_MAX, path, fd.cFileName) != 0) {
            continue;
        }
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                RemoveDirectoryW(full);
            } else {
                remove_tree_inner(full);
            }
        } else {
            SetFileAttributesW(full, FILE_ATTRIBUTE_NORMAL);
            if (!DeleteFileW(full)) {
                (void)vty_acl_force_admin_full(full);
                DeleteFileW(full);
            }
        }
    } while (FindNextFileW(find, &fd));
    FindClose(find);
    RemoveDirectoryW(path);
}

int test_remove_tree(const wchar_t *path)
{
    if (path == NULL || path[0] == L'\0') return -1;
    (void)vty_acl_force_admin_full(path);
    remove_tree_inner(path);
    return vty_path_exists(path) ? -1 : 0;
}

long test_read_file(const wchar_t *path, uint8_t *buf, DWORD cap)
{
    HANDLE file;
    DWORD got = 0;
    long total = 0;

    if (path == NULL || buf == NULL || cap == 0) return -1;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    while (total < (long)cap) {
        if (!ReadFile(file, buf + total, cap - (DWORD)total, &got, NULL) ||
            got == 0) {
            break;
        }
        total += (long)got;
    }
    CloseHandle(file);
    return total;
}
