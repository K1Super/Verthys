/*
 * verthys_api_utils.c — 共享工具模块（从 verthys_api.c 拆分，V3-only）
 *
 * 本文件收录从 verthys_api.c 抽离的纯工具/辅助函数，供 verthys_api.c 及其他内部
 * 模块复用。所有函数已移除 static 限定符以便跨翻译单元调用，声明见
 * verthys_api_utils.h。
 *
 * ★ §1.4 V2 退役：v1 记录表助手（records_*）与 V2 blob 读取器
 *   （read_v2_superblock_only / read_v2_unlock_blob）随删除清单移除；
 *   detect_format 收敛为 V3-only（'V3RP' magic，其余一律 NONE）；
 *   ctx_zero_sensitive 收敛为 V3 敏感材料销毁（CNG 内核密钥组 +
 *   GetRecord 借用缓存），V1/V2 结构释放逻辑全部移除。
 */
#include "verthys_api_utils.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>   /* ★ 缺陷 6：Verthys_VerifyIntegrity 使用 time() 记录校验时间戳 */

#ifdef _WIN32
#include <windows.h>
#include <io.h>    /* _chsize_s, _fileno */
#include <intrin.h> /* __cpuid, __cpuidex, _xgetbv — 第三层 AVX2 运行时检测 */
#include <malloc.h> /* _aligned_malloc, _aligned_free — 第二层缓存行对齐 */
#else
#include <unistd.h> /* ftruncate, fileno */
#endif

/* ---------- 暴力破解退避（project.md 5.3）---------- */
#define VERTHYS_BACKOFF_MAX_SECS 3600u

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

uint64_t verthys_backoff_remaining_ms(const struct VerthysContext *ctx)
{
    if (ctx->failed_attempts == 0 || ctx->last_failed_tick == 0) return 0;
    uint32_t k = ctx->failed_attempts;
    uint64_t wait_secs = (k >= 12) ? VERTHYS_BACKOFF_MAX_SECS : (1ull << k);
    if (wait_secs > VERTHYS_BACKOFF_MAX_SECS) wait_secs = VERTHYS_BACKOFF_MAX_SECS;
    uint64_t wait_ms = wait_secs * 1000u;
    uint64_t elapsed = verthys_monotonic_ms() - ctx->last_failed_tick;
    return (elapsed >= wait_ms) ? 0 : (wait_ms - elapsed);
}

void verthys_backoff_record_failure(struct VerthysContext *ctx)
{
    if (ctx->failed_attempts < 32) ctx->failed_attempts++;
    ctx->last_failed_tick = verthys_monotonic_ms();
}

void verthys_backoff_reset(struct VerthysContext *ctx)
{
    ctx->failed_attempts = 0;
    ctx->last_failed_tick = 0;
}

/* ---------- 小端序读取（用于索引区长度前缀） ---------- */
uint64_t verthys_get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (i * 8);
    return v;
}

/* ---------- 文件 I/O 辅助 ---------- */
/*
 * DEF-015 修复：读取文件体积上限管控
 *
 * 原实现未限制读取最大文件体积，恶意超大文件可直接耗尽进程内存触发 DoS。
 * 新增全局可配置最大读取上限 VERTHYS_READ_FILE_MAX_BYTES（4GB），
 * 超大文件直接返回错误，防御内存耗尽攻击。
 *
 * 同时使用 64 位文件定位（_fseeki64/_ftelli64），正确处理 >2GB 文件
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

    /* DEF-015：体积上限校验，超限拒绝读取防 DoS */
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
    fflush(f);
#ifdef _WIN32
    /* ★ 企业级数据持久化修复：write_file 后强制 fsync，确保物理落盘
     *
     * 原缺陷：仅 fwrite + fclose，数据停留在 OS page cache，未真正写入物理磁盘。
     * 容器导出/迁移中间文件依赖此函数落盘，未 fsync 导致进程异常终止
     * 或系统繁忙时数据丢失风险极高。
     *
     * 企业级"数据不丢"刚性要求：所有持久化写入必须 fsync 物理落盘，
     * 不能依赖 OS 异步刷盘的"最终一致性"——那是数据丢失的温床。
     * _commit 等同 FlushFileBuffers，强制将文件所有缓冲数据写入磁盘。 */
    _commit(_fileno(f));
#else
    fsync(fileno(f));
#endif
    fclose(f);
    return 0;
}

char *dup_string(const char *s)
{
    size_t len = strlen(s) + 1;
    char *copy = malloc(len);
    if (copy != NULL) memcpy(copy, s, len);
    return copy;
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

/* 清除上下文中的所有敏感材料（V3-only），不动 file_path
 *
 * ★ §1.4 V2 退役：V1/V2 字段（master_key/dek/salt/records/key_a/b/c/
 *   mount_salt/txn/merkle/dblock_mgr/btree/superblock/watcher/
 *   mount_watcher/summary_records 等）随删除清单移除，本函数收敛为
 *   V3 敏感材料销毁收口。
 *
 * 前置条件：调用方（Lock/紧急熔断/Deinit）已先行收口 V3 子系统并
 * 销毁 v3 实例（verthys_v3_ctx_subsystems_close / verthys_v3_ctx_destroy
 * ——后台预热线程汇合后内核句柄方可安全销毁，杜绝 BCrypt 句柄 UAF）。
 *
 * 暴力破解退避记账（failed_attempts/last_failed_tick）跨 Lock 周期
 * 保留（project.md 5.3：锁定状态仍需维持指数退避），不在清零范围。 */
void ctx_zero_sensitive(struct VerthysContext *ctx)
{
    /* 释放 GetRecord 借用指针缓存（明文数据/名称安全清零 + 释放） */
    ctx_free_getrecord_cache(ctx);

    /* ★ V3 升级 WP-1：销毁 CNG 内核密钥组（BCryptDestroyKey，
     * 内核态密钥材料不可恢复——Lock/Deinit/紧急熔断统一收口路径） */
    verthys_cng_km_destroy_all(&ctx->cng_keys);

    /* 格式版本复位：上下文回归 Init 零态（fmt 待下次 Unlock 重新裁决） */
    ctx->fmt_version = VERTHYS_FMT_NONE;
}

/* ---------- 格式检测（V3-only）----------
 * 读取文件头判断格式：V3 超级块首副本帧头 magic "V3RP" (0x56 0x33 0x52 0x50)。
 *
 * §1.4 V2 退役：V1（"VERT" 0x0001）/ V2（"VERT" 0x0002）/ 未知头一律
 * VERTHYS_FMT_NONE——Unlock 格式门禁据此返回 VERTHYS_ERR_FORMAT
 * （"V3 不读 V2 文件"，旧容器经 Verthys_Export 侧外部工具转换后导入）。
 */
VerthysContainerVersion detect_format(const uint8_t *buf, size_t size)
{
    if (buf == NULL || size < 8) return VERTHYS_FMT_NONE;
    /* ★ V3 升级 WP-5：V3 超级块首副本帧头 magic 'V3RP'（帧惯例
     * [u32 magic][u32 payload_len]，verthys_container_v3.h）。本函数仅做
     * 格式路由，帧结构/法定人数深度校验归解锁流水线 S0-S3。 */
    if (buf[0] == 0x56 && buf[1] == 0x33 && buf[2] == 0x52 && buf[3] == 0x50) {
        return VERTHYS_FMT_V3;
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
