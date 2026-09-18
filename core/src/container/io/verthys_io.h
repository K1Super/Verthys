/*
 * verthys_io.h — 统一 64 位文件偏移 I/O 层（内部模块，不导出）
 *
 * ★ 最终修复方案 §4.2（P0-4 根治）：统一安全 I/O 层。
 *
 * 背景：Windows x64 的 long 为 32 位，`fseek(f, (long)offset, ...)` 与
 * `ftell` 在 >2GB 文件上溢出/取负——容器超过 2GB 后所有索引/数据/日志
 * IO 静默错位（verthys_api_utils.c:93 早已文档化此约束并使用 _ftelli64，
 * 其余文件未同步，形成系统性缺陷）。
 *
 * 本层是全部持久化偏移 IO 的唯一入口：
 *   - Windows：_fseeki64 / _ftelli64
 *   - POSIX：fseeko / ftello（off_t 64 位构建下等价）
 *   - 所有持久化调用方必须经本层，禁止直接使用 fseek/ftell 处理容器偏移。
 */
#ifndef VERTHYS_IO_H
#define VERTHYS_IO_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 64 位定位：成功返回 0，失败返回 -1 */
int vio_fseek64(FILE *f, int64_t offset, int origin);

/* 64 位位置查询：失败返回 -1 */
int64_t vio_ftell64(FILE *f);

/* 64 位定位读：从 offset 读取 len 字节到 buf。
 * 返回 0 成功，-1 失败（定位或读取不完整）。 */
int vio_pread64(FILE *f, uint64_t offset, void *buf, size_t len);

/* 64 位定位写：向 offset 写入 len 字节。
 * 返回 0 成功，-1 失败（定位或写入不完整）。 */
int vio_pwrite64(FILE *f, uint64_t offset, const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_IO_H */
