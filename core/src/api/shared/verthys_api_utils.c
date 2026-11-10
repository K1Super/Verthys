/*
 * verthys_api_utils.c — 共享工具模块
 *
 * 纯工具/辅助函数实现，供 verthys_api.c 及其他内部模块复用；
 * 函数为跨翻译单元可见（非 static），声明见 verthys_api_utils.h。
 *
 */
#include "verthys_api_utils.h"
#include "vty_keymanager.h"
#include "vty_rotate.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>   /* clock_gettime（非 Windows 单调时钟） */

#ifdef _WIN32
#include <windows.h>
#include <io.h>    /* _fileno */
#include <intrin.h> /* __cpuid, __cpuidex, _xgetbv — 第三层 AVX2 运行时检测 */
#include <malloc.h>
#else
#include <unistd.h> /* fileno */
#endif

/* ---------- 单调时钟 ---------- */
uint64_t verthys_monotonic_ms(void)
{
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

/* ---------- 工作线程有界汇合 ---------- */
#ifdef _WIN32
DWORD verthys_join_thread_bounded(HANDLE thread)
{
    if (thread == NULL) return WAIT_FAILED;
    return WaitForSingleObject(thread, VERTHYS_JOIN_TIMEOUT_MS);
}
#endif

/* ---------- 文件 I/O 辅助 ---------- */
/*
 * 读取文件体积上限管控
 *
 * 读取前校验文件大小，超过 VERTHYS_READ_FILE_MAX_BYTES（4GB）直接拒绝，
 * 避免超大文件耗尽进程内存。
 *
 * 定位使用 64 位接口（_fseeki64/_ftelli64），正确处理 >2GB 文件
 * （Windows long 为 32 位，ftell 在 2GB+ 文件上溢出返回负值）。
 */
#define VERTHYS_READ_FILE_MAX_BYTES  ((size_t)4u * 1024u * 1024u * 1024u)  /* 4GB 上限 */

int read_file(const char *path, uint8_t **out_buf, size_t *out_size)
{
    if (path == NULL || out_buf == NULL || out_size == NULL) return -1;

    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;

    /* 64 位文件定位：Windows 用 _fseeki64/_ftelli64，POSIX 用 fseeko/ftello */
#ifdef _WIN32
    if (_fseeki64(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    __int64 sz = _ftelli64(f);
#else
    if (fseeko(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    off_t sz = ftello(f);
#endif
    if (sz < 0) { fclose(f); return -1; }

    /* 体积上限校验，超限拒绝读取防 DoS */
    if ((uint64_t)sz > (uint64_t)VERTHYS_READ_FILE_MAX_BYTES) { fclose(f); return -1; }

#ifdef _WIN32
    if (_fseeki64(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
#else
    if (fseeko(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
#endif

    size_t read_sz = (size_t)sz;
    uint8_t *buf = malloc(read_sz);
    if (buf == NULL) { fclose(f); return -1; }
    if (read_sz > 0 && fread(buf, 1, read_sz, f) != read_sz) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);
    *out_buf = buf;
    *out_size = read_sz;
    return 0;
}

int write_file(const char *path, const uint8_t *buf, size_t size)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) return -1;
    if (size > 0 && fwrite(buf, 1, size, f) != size) { fclose(f); return -1; }
    /* fflush/_commit 的错误必须向上传播：调用方（导出/迁移）只有拿到
     * 成功才能删源或写清单，静默失败会造成“清单在、数据无”。 */
    if (fflush(f) != 0) { fclose(f); return -1; }
#ifdef _WIN32
    /* 强制物理落盘：仅 fwrite + fclose 会让数据停留在 OS page cache，
     * 容器导出/迁移中间文件依赖本函数落盘，进程异常终止或系统繁忙时
     * 会丢失数据。_commit 等同 FlushFileBuffers。 */
    if (_commit(_fileno(f)) != 0) { fclose(f); return -1; }
#else
    if (fsync(fileno(f)) != 0) { fclose(f); return -1; }
#endif
    if (fclose(f) != 0) return -1;
    return 0;
}

char *dup_string(const char *s)
{
    size_t len = strlen(s) + 1;
    char *copy = malloc(len);
    if (copy != NULL) memcpy(copy, s, len);
    return copy;
}

/* ---------- 会话生命周期（进程级原子计数） ---------- */

static volatile LONG s_vault_resident = 0;

void vault_session_attach(struct VerthysContext *ctx, struct VtyVault *v)
{
    if (ctx == NULL || v == NULL) return;

    if (ctx->vault != NULL) {
        /* 替换：旧库必须先释放，计数保持 1（会话始终存活）。 */
        vty_vault_free(ctx->vault);
    } else {
        InterlockedIncrement(&s_vault_resident);
    }
    ctx->vault = v;
}

void vault_session_detach(struct VerthysContext *ctx)
{
    if (ctx == NULL || ctx->vault == NULL) return;

    vty_vault_free(ctx->vault);
    ctx->vault = NULL;
    InterlockedDecrement(&s_vault_resident);
}

void vault_session_replace_externally_freed(struct VerthysContext *ctx,
                                         struct VtyVault *v)
{
    if (ctx == NULL || v == NULL) return;

    /* 前置条件：旧库已由 vty_rotate_commit 清零释放，本函数只接管新库。
     * 若旧指针为空（异常路径，正常轮换不应发生），按 attach 语义补计
     * 一次，避免计数与实际驻留会话数漂移。 */
    if (ctx->vault == NULL) {
        InterlockedIncrement(&s_vault_resident);
    }
    ctx->vault = v;
}

uint32_t vault_session_resident_count(void)
{
    return (uint32_t)InterlockedCompareExchange(&s_vault_resident, 0, 0);
}

/* 释放 GetRecord 借用指针缓存（安全清零 + 释放） */
void ctx_free_getrecord_cache(struct VerthysContext *ctx)
{
    if (ctx->last_getrecord_data != NULL) {
        verthys_secure_zero(ctx->last_getrecord_data, ctx->last_getrecord_data_size);
        free(ctx->last_getrecord_data);
        ctx->last_getrecord_data = NULL;
        ctx->last_getrecord_data_size = 0;
    }
    if (ctx->last_getrecord_name != NULL) {
        verthys_secure_zero(ctx->last_getrecord_name, ctx->last_getrecord_name_len);
        free(ctx->last_getrecord_name);
        ctx->last_getrecord_name = NULL;
        ctx->last_getrecord_name_len = 0;
    }
}

/* 清除上下文中的所有敏感材料（会话），不动 file_path
 *
 * 前置条件无：会话的释放经 vty_vault_free 内部清零。
 *
 * 暴力破解退避记账为进程级模块全局（跨句柄聚合），与本上下文无关，
 * 亦不在本函数清零范围。 */
void ctx_zero_sensitive(struct VerthysContext *ctx)
{
    /* 轮换作业持有源/新库引用，必须先释放，避免库被释放后悬空。 */
    if (ctx->rotate != NULL) {
        (void)vty_rotate_abort(ctx->rotate);
        ctx->rotate = NULL;
    }

    /* 会话（若仍存活）先按锁定语义清零并释放。 */
    vault_session_detach(ctx);

    /* 释放 GetRecord 借用指针缓存（明文数据/名称安全清零 + 释放） */
    ctx_free_getrecord_cache(ctx);

    /* 格式版本复位：上下文回归 Init 零态（fmt 待下次 Unlock 重新裁决） */
    ctx->fmt_version = VERTHYS_FMT_NONE;
}

/* ---------- 格式检测 ----------
 * 读取文件头判断格式：仅接受固定头 magic "VRTY" (0x56 0x52 0x54 0x59)。
 * 本函数只做路由，版本/槽区/头哈希的深度校验归解锁路径。 */
VerthysContainerVersion detect_format(const uint8_t *buf, size_t size)
{
    if (buf == NULL || size < 8) return VERTHYS_FMT_NONE;
    if (buf[0] == 0x56 && buf[1] == 0x52 && buf[2] == 0x54 && buf[3] == 0x59) {
        return VERTHYS_FMT_CONTAINER;
    }
    return VERTHYS_FMT_NONE;
}

int g_has_avx2 = -1;  /* -1=未检测, 0=不支持, 1=支持 */

#ifdef _WIN32
int verthys_check_avx2_support(void)
{
    int cpuinfo[4];
    __cpuid(cpuinfo, 0);
    int max_leaf = cpuinfo[0];
    if (max_leaf < 7) return 0;  /* 不支持 cpuid leaf 7 */

    /* leaf 7, sub-leaf 0: EBX 含 AVX2/BMI2 位 */
    __cpuidex(cpuinfo, 7, 0);
    int has_avx2 = (cpuinfo[1] >> 5) & 1;   /* AVX2 = EBX bit 5 */
    int has_bmi2 = (cpuinfo[1] >> 8) & 1;   /* BMI2 = EBX bit 8 */
    if (!has_avx2 || !has_bmi2) return 0;

    /* 检查 OS 是否支持 AVX 状态保存（XSAVE） */
    __cpuid(cpuinfo, 1);
    int has_osxsave = (cpuinfo[2] >> 27) & 1;
    if (!has_osxsave) return 0;

    /* XCR0 位 1 = XMM, 位 2 = YMM */
    uint64_t xcr0 = _xgetbv(0);
    int os_avx_support = ((xcr0 >> 1) & 1) && ((xcr0 >> 2) & 1);
    return os_avx_support ? 1 : 0;
}
#endif /* _WIN32 */
