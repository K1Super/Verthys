/*
 * verthys_container_lock.c — 容器文件跨进程互斥实现（Windows）
 *
 * 两层互斥（见头文件契约）：
 *   L1 CreateFileA 共享模式 FILE_SHARE_READ——内核级写互斥，
 *      第二写者的打开调用在句柄层即失败（ERROR_SHARING_VIOLATION）；
 *   L2 LockFileEx 超级块区独占字节范围锁——协作信号，
 *      阻止以只读句柄混入的 Verthys 实例继续写路径。
 * 两层任一命中均映射 VERTHYS_ERR_CONTAINER_BUSY，区别于
 * 设备级 IO 故障（VERTHYS_ERR_IO）。
 *
 * PID 旁路（<path>.lock）：仅承载诊断（竞争者被拒后可见持有者 PID），
 * 写入失败/解析失败一律不影响互斥判定与返回码——诊断是尽力而为。
 * 旁路文件句柄以 FILE_SHARE_DELETE 打开，保证持有者会话退出时
 * 可删除；删除后的文件对已打开句柄保持可读（Windows 延迟删除语义），
 * 竞争者侧读到的是打开时刻的完整内容。
 */

#include "verthys_container_lock.h"
#include "verthys_container_v3.h"
#include "verthys_diag.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <fcntl.h>
#include <io.h>

/* 超级块区独占锁长度：覆盖超级块三副本区 [0, 64KB)，
 * 上界即 VERTHYS_V3_WAL_REGION_OFFSET（同一布局常量，防漂移） */
#define VERTHYS_CONTAINER_LOCK_BYTES VERTHYS_V3_WAL_REGION_OFFSET
#define VERTHYS_CONTAINER_LOCK_SUFFIX ".lock"

/* 旁路路径缓冲容量：容器路径 + 后缀 + 终止符（路径超长时安全截断诊断，
 * 旁路缺失不影响互斥，仅诊断降级） */
#define VERTHYS_LOCK_SIDECAR_MIN_CAP 64

/* 构造 <path><suffix> 旁路路径（malloc，调用方 free；失败返回 NULL） */
static char *verthys_lock_sidecar_path(const char *path)
{
    const char *suffix = VERTHYS_CONTAINER_LOCK_SUFFIX;
    size_t plen, slen, total;

    if (path == NULL) return NULL;
    plen = strlen(path);
    slen = strlen(suffix);
    total = plen + slen;
    if (total < VERTHYS_LOCK_SIDECAR_MIN_CAP) {
        total = VERTHYS_LOCK_SIDECAR_MIN_CAP;
    }
    if (total + 1 < total) return NULL;   /* 溢出守卫（理论不可达） */

    char *buf = (char *)malloc(total + 1);
    if (buf == NULL) return NULL;
    memcpy(buf, path, plen);
    memcpy(buf + plen, suffix, slen + 1);
    return buf;
}

/*
 * 持有者 PID 写入旁路：READ 语义的竞争者据此定位持有进程。
 * 创建/读取均带 FILE_SHARE_DELETE，允许会话退出时立即删除。
 */
static void verthys_lock_owner_record(const char *path, DWORD pid)
{
    char *sidecar = verthys_lock_sidecar_path(path);
    char pid_text[24];
    HANDLE h;
    DWORD written = 0;
    int n;

    if (sidecar == NULL) return;
    n = _snprintf_s(pid_text, sizeof(pid_text), _TRUNCATE, "%lu", (unsigned long)pid);
    if (n < 0) {
        free(sidecar);
        return;
    }

    h = CreateFileA(sidecar, GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        free(sidecar);
        return;   /* 诊断旁路失败不阻断互斥路径 */
    }
    (void)WriteFile(h, pid_text, (DWORD)strlen(pid_text), &written, NULL);
    FlushFileBuffers(h);
    CloseHandle(h);
    free(sidecar);
}

/* 竞争者侧：读取旁路里的持有者 PID；失败返回 0（诊断尽力而为） */
static DWORD verthys_lock_owner_read(const char *path)
{
    char *sidecar = verthys_lock_sidecar_path(path);
    char buf[24];
    DWORD got = 0, pid = 0;

    if (sidecar == NULL) return 0;
    HANDLE h = CreateFileA(sidecar, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        free(sidecar);
        return 0;
    }
    memset(buf, 0, sizeof(buf));
    if (ReadFile(h, buf, (DWORD)sizeof(buf) - 1, &got, NULL) && got > 0) {
        pid = (DWORD)strtoul(buf, NULL, 10);
    }
    CloseHandle(h);
    free(sidecar);
    return pid;
}

static void verthys_lock_owner_delete(const char *path)
{
    char *sidecar = verthys_lock_sidecar_path(path);
    if (sidecar == NULL) return;
    DeleteFileA(sidecar);   /* 尽力而为：失败仅残留无害旁路文件 */
    free(sidecar);
}

/* 竞争者被拒时的统一诊断：尽可能报出持有者 PID（旁路可读时） */
static void verthys_lock_busy_diag(const char *path, const char *stage)
{
    DWORD owner = verthys_lock_owner_read(path);
    char msg[256];

    if (owner != 0) {
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                    "[verthys] container busy (%s) path=%s owner_pid=%lu",
                    stage, path, (unsigned long)owner);
    } else {
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                    "[verthys] container busy (%s) path=%s owner_pid=<unknown>",
                    stage, path);
    }
    VERTHYS_DIAG_LOG(msg);
}

#else /* _WIN32 */

/* 非 Windows：无跨进程锁语义，退化为普通 fopen（产品仅 Windows 构建） */
static void verthys_lock_busy_diag(const char *path, const char *stage)
{
    (void)path;
    (void)stage;
}

#endif /* _WIN32 */

VerthysResult verthys_container_open_exclusive(const char *path,
                                               int create_new,
                                               FILE **out_f)
{
    if (out_f == NULL) return VERTHYS_ERR_INVALID;
    *out_f = NULL;
    if (path == NULL) return VERTHYS_ERR_INVALID;

#ifdef _WIN32
    HANDLE hFile;
    OVERLAPPED ov;
    BOOL locked;
    DWORD err;

    /* L1 单写者：FILE_SHARE_READ 拒绝任何其他进程的写访问
     * （本会话为会话期唯一写句柄，读侧工具不受影响） */
    hFile = CreateFileA(path,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ,
                        NULL,
                        create_new ? CREATE_NEW : OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        err = GetLastError();
        if (create_new && err == ERROR_FILE_EXISTS) return VERTHYS_ERR_EXISTS;
        if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION) {
            verthys_lock_busy_diag(path, "share");
            return VERTHYS_ERR_CONTAINER_BUSY;
        }
        return VERTHYS_ERR_IO;
    }

    /* L2 超级块区独占锁：锁生命周期 = 容器句柄生命周期
     * （本进程持有另一个句柄时关闭/锁定自动释放） */
    memset(&ov, 0, sizeof(ov));
    locked = LockFileEx(hFile,
                        LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                        0,
                        (DWORD)VERTHYS_CONTAINER_LOCK_BYTES,
                        (DWORD)(VERTHYS_CONTAINER_LOCK_BYTES >> 32),
                        &ov);
    if (!locked) {
        err = GetLastError();
        CloseHandle(hFile);
        if (err == ERROR_LOCK_VIOLATION || err == ERROR_SHARING_VIOLATION) {
            verthys_lock_busy_diag(path, "superblock");
            return VERTHYS_ERR_CONTAINER_BUSY;
        }
        return VERTHYS_ERR_IO;
    }

    /* 诊断旁路：记录本进程 PID（失败不阻断——互斥已由上面两层保证） */
    verthys_lock_owner_record(path, GetCurrentProcessId());

    {
        int fd = _open_osfhandle((intptr_t)hFile, _O_RDWR | _O_BINARY);
        if (fd < 0) {
            CloseHandle(hFile);
            return VERTHYS_ERR_IO;
        }
        FILE *f = _fdopen(fd, "r+b");
        if (f == NULL) {
            _close(fd);
            return VERTHYS_ERR_IO;
        }
        *out_f = f;
    }
    return VERTHYS_OK;
#else
    FILE *f = fopen(path, create_new ? "wbx" : "r+");
    if (f == NULL) {
        return (create_new && errno == EEXIST) ? VERTHYS_ERR_EXISTS
                                               : VERTHYS_ERR_IO;
    }
    *out_f = f;
    return VERTHYS_OK;
#endif
}

void verthys_container_close_exclusive(FILE *f, const char *path)
{
    if (f == NULL) return;

    if (path != NULL) {
        verthys_lock_owner_delete(path);
    }
    /* 字节范围锁随句柄关闭由 OS 释放（Windows 锁与句柄同生命周期） */
    fclose(f);
}