/*
 * vty_rotate_io.c — 轮换作业的路径与文件系统原语
 *
 * 负责 UTF-8 路径转换、同卷（同目录）判定、空间预检与备份路径生成，
 * 以及基于单次原子替换的移动/替换和零写删除。失败语义由调用方的
 * 阶段机决定，本文件不推进作业状态。
 */

#include "vty_rotate_internal.h"

static wchar_t *rot_utf8_to_wide(const char *s)
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

int vty_rot_file_exists(const char *path)
{
    wchar_t *w = rot_utf8_to_wide(path);
    DWORD attrs;
    int exists;

    if (w == NULL) return 0;
    attrs = GetFileAttributesW(w);
    exists = (attrs != INVALID_FILE_ATTRIBUTES);
    free(w);
    return exists;
}

int vty_rot_move(const char *from, const char *to)
{
    wchar_t *wf = rot_utf8_to_wide(from);
    wchar_t *wt = rot_utf8_to_wide(to);
    int rc = VTY_OK;

    if (wf == NULL || wt == NULL) {
        free(wf);
        free(wt);
        return VTY_E_INVALID;
    }
    if (!MoveFileExW(wf, wt, MOVEFILE_WRITE_THROUGH)) rc = VTY_E_IO;
    free(wf);
    free(wt);
    return rc;
}

/* 原子替换：target 被 replacement 替换，原 target 内容落到 backup（backup
 * 必须不存在）；成功返回时 replacement 路径不再存在。Windows ReplaceFileW
 * 保证单次调用内完成“替换 + 备份”，不存在“源路径先消失”的窗口。 */
int vty_rot_replace(const char *target, const char *replacement,
                       const char *backup)
{
    wchar_t *wt;
    wchar_t *wr;
    wchar_t *wb = NULL;
    int rc = VTY_OK;

    if (target == NULL || replacement == NULL || backup == NULL) {
        return VTY_E_INVALID;
    }
    wt = rot_utf8_to_wide(target);
    wr = rot_utf8_to_wide(replacement);
    wb = rot_utf8_to_wide(backup);
    if (wt == NULL || wr == NULL || wb == NULL) {
        free(wt);
        free(wr);
        free(wb);
        return VTY_E_INVALID;
    }
    if (!ReplaceFileW(wt, wr, wb, REPLACEFILE_WRITE_THROUGH, NULL, NULL)) {
        rc = VTY_E_IO;
    }
    free(wt);
    free(wr);
    free(wb);
    return rc;
}

/* 清理失败不应伪装成成功：旧库/临时库与源库同密钥，必须零写后删除；
 * 删除失败时保留文件，由下次解锁维护重试。 */
int vty_rot_delete(const char *path)
{
    if (path == NULL || path[0] == '\0') return 1;
    return vty_secure_delete_file(path) == VTY_OK;
}

/* 同目录（同卷）判定：跨卷 MoveFileExW 不是原子替换，必须在 Begin
 * 阶段就拒绝，而不是等临时库建完再失败。 */
static int rot_full_path(const char *path, wchar_t out[2048])
{
    wchar_t *w = rot_utf8_to_wide(path);
    DWORD n;

    if (w == NULL) return 0;
    n = GetFullPathNameW(w, 2048, out, NULL);
    free(w);
    return n > 0 && n < 2048;
}

int vty_rot_same_directory(const char *a, const char *b)
{
    wchar_t wa[2048];
    wchar_t wb[2048];
    wchar_t *pa, *pb;
    int rc;

    if (!rot_full_path(a, wa) || !rot_full_path(b, wb)) return 0;
    pa = wcsrchr(wa, L'\\');
    pb = wcsrchr(wb, L'\\');
    if (pa == NULL || pb == NULL) return 0;
    *pa = L'\0';
    *pb = L'\0';
    rc = _wcsicmp(wa, wb);
    vty_secure_zero(wa, sizeof(wa));
    vty_secure_zero(wb, sizeof(wb));
    return rc == 0;
}

/* 粗粒度空间预检：新库只保留存活记录/分片，正常不会超过旧文件大小；
 * 用旧文件大小 + 余量作为下界，空间不足时尽早返回 NO_SPACE。查询失败
 * （路径/卷信息不可得）不阻断，交给实际写入报 IO/NO_SPACE。 */
int vty_rot_space_ok(const char *old_path)
{
    wchar_t wold[2048];
    wchar_t volume[2048];
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULARGE_INTEGER free_bytes;
    uint64_t size;
    uint64_t required;

    if (!rot_full_path(old_path, wold)) return VTY_E_INVALID;
    if (!GetFileAttributesExW(wold, GetFileExInfoStandard, &fad)) {
        return VTY_OK;
    }
    size = ((uint64_t)fad.nFileSizeHigh << 32) | (uint64_t)fad.nFileSizeLow;
    if (size > UINT64_MAX - (uint64_t)VTY_ROTATE_SPACE_MARGIN) {
        return VTY_E_NO_SPACE;
    }
    required = size + (uint64_t)VTY_ROTATE_SPACE_MARGIN;

    if (!GetVolumePathNameW(wold, volume,
                            (DWORD)(sizeof(volume) / sizeof(volume[0]))) ||
        !GetDiskFreeSpaceExW(volume, &free_bytes, NULL, NULL)) {
        return VTY_OK;
    }
    return ((uint64_t)free_bytes.QuadPart >= required) ? VTY_OK
                                                       : VTY_E_NO_SPACE;
}

int vty_rot_make_backup_path(const char *old_path,
                                char out[VTY_ROTATE_BACKUP_MAX])
{
    uint32_t attempt;

    for (attempt = 0; attempt < 8u; attempt++) {
        uint32_t rnd = 0;
        vty_random((uint8_t *)&rnd, sizeof(rnd));
        if (sprintf_s(out, VTY_ROTATE_BACKUP_MAX, "%s.old-%08lx-%08lx",
                      old_path, (unsigned long)GetTickCount64(),
                      (unsigned long)rnd) < 0) {
            return VTY_E_RESOURCE;
        }
        if (!vty_rot_file_exists(out)) return VTY_OK;
    }
    return VTY_E_IO;
}
