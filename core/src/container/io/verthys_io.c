/*
 * verthys_io.c — 统一 64 位文件偏移 I/O 层实现
 *
 * ★ 最终修复方案 §4.2（P0-4 根治）：见 verthys_io.h 头注。
 * 实现要点：
 *   - Windows 使用 _fseeki64/_ftelli64（CRT 64 位文件定位）
 *   - POSIX 使用 fseeko/ftello
 *   - 偏移参数一律 int64_t/uint64_t，杜绝 long 截断
 */
#include "verthys_io.h"

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

int vio_fseek64(FILE *f, int64_t offset, int origin)
{
    if (f == NULL) return -1;
#ifdef _WIN32
    return (_fseeki64(f, (__int64)offset, origin) == 0) ? 0 : -1;
#else
    return (fseeko(f, (off_t)offset, origin) == 0) ? 0 : -1;
#endif
}

int64_t vio_ftell64(FILE *f)
{
    if (f == NULL) return -1;
#ifdef _WIN32
    __int64 pos = _ftelli64(f);
#else
    off_t pos = ftello(f);
#endif
    return (pos < 0) ? (int64_t)-1 : (int64_t)pos;
}

int vio_pread64(FILE *f, uint64_t offset, void *buf, size_t len)
{
    if (f == NULL || buf == NULL) return -1;
    if (vio_fseek64(f, (int64_t)offset, SEEK_SET) != 0) return -1;
    if (len > 0 && fread(buf, 1, len, f) != len) return -1;
    return 0;
}

int vio_pwrite64(FILE *f, uint64_t offset, const void *buf, size_t len)
{
    if (f == NULL || buf == NULL) return -1;
    if (vio_fseek64(f, (int64_t)offset, SEEK_SET) != 0) return -1;
    if (len > 0 && fwrite(buf, 1, len, f) != len) return -1;
    return 0;
}
