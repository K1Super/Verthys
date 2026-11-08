/*
 * integrity.c — 程序镜像完整性验签（.vsec）
 *
 * 运行时从磁盘读取自身 PE 文件，重算 .text/.rdata/.rhat 的文件内容 HMAC，
 * 与构建期写入的 .vsec 只读节基准做常量时间比对。
 * 验签失败 = 分发二进制被篡改 → KILL 级上报并拒绝解锁；
 * 临时哈希缓冲区用毕立即清零，不残留密钥材料。
 *
 * .vsec 节布局、缓存策略与调用时机见下方实现段。
 */
#include "integrity.h"
#include "verthys_crypto.h"   /* VERTHYS_HMAC_BYTES / VERTHYS_KEY_BYTES */
#include "verthys_internal.h"  /* verthys_secure_zero */
#include "emergency.h"       /* 验签失败 KILL 级上报 */
#include <sodium.h>          /* crypto_auth_hmacsha256_state（流式 HMAC） */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <io.h>              /* _open_osfhandle / _close / _fdopen */
#include <fcntl.h>           /* _O_RDONLY */

/* ===================================================================== *
 *        构建期签名 + 一次性验签（.vsec 机制）实现          *
 * ===================================================================== *
 *
 * .vsec 节布局（128 字节，只读节，由构建脚本在链接后补丁）：
 *   [0..3]   magic   = 0x43534556 ('VESV' 小端)
 *   [4..5]   version = 0x0002（版本 2：新增 .rhat 第三槽）
 *   [6..7]   flags   = 0（预留）
 *   [8..39]  HMAC(.text 文件内容)
 *   [40..71] HMAC(.rdata 文件内容)
 *   [72..103] HMAC(.rhat 文件内容)（运行时哈希表防文件级篡改）
 *   [104..127] 保留全零
 *
 * 全零节 = 未配置（开发构建）→ 验签跳过。构建脚本以相同域密钥补丁本节。
 * 版本兼容：version==1 仅校验 text+rdata（旧脚本产物）；version>=2 追加
 * .rhat 槽——.rhat 节缺失（理论上不可达，runtime_hash.c 恒编入）按
 * 基础设施异常跳过该槽，text/rdata 槽照常校验。
 */

/* .vsec 固定大小 */
#define VSEC_BLOB_BYTES   128u
#define VSEC_MAGIC        0x43534556u
#define VSEC_VERSION_2    0x0002u
#define VSEC_TEXT_HMAC_OFF    8u
#define VSEC_RDATA_HMAC_OFF  40u
#define VSEC_RHAT_HMAC_OFF   72u

/* .vsec 节定义（只读；verify_startup 引用其地址以保留符号防 /OPT:REF 剪除） */
#pragma section(".vsec", read)
__declspec(allocate(".vsec"))
const uint8_t g_vsec_blob[VSEC_BLOB_BYTES] = { 0 };

/* 域密钥：与 build_core.release.ps1 中的补丁密钥保持逐字节一致（非秘密） */
static const uint8_t K_VSEC_DOMAIN_KEY[VERTHYS_KEY_BYTES] = {
    'v', 'e', 'r', 't', 'h', 'y', 's', '/', 'v', 's', 'e', 'c', '-', 'v', '1', '/',
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15,
    0xbf, 0x61, 0x83, 0xd2, 0x55, 0x0a, 0x34, 0x6c
};

/* 从 PE 文件读取节表，输出指定节的文件偏移与原始大小 */
static int vsec_find_section(FILE *f, const char *name,
                             long *out_raw_ptr, DWORD *out_raw_size)
{
    uint8_t dos[64], nt[24], opt20[20];
    if (fread(dos, 1, sizeof(dos), f) != sizeof(dos)) return -1;
    if (dos[0] != 'M' || dos[1] != 'Z') return -1;

    long e_lfanew = (long)dos[0x3C] | ((long)dos[0x3D] << 8) |
                    ((long)dos[0x3E] << 16) | ((long)dos[0x3F] << 24);
    if (e_lfanew <= 0 || fseek(f, e_lfanew, SEEK_SET) != 0) return -1;
    if (fread(nt, 1, sizeof(nt), f) != sizeof(nt)) return -1;
    if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0) return -1;

    WORD nsections = (WORD)(nt[6] | (nt[7] << 8));
    WORD opt_size  = (WORD)(nt[20] | (nt[21] << 8));

    long opt_start = e_lfanew + 4 + 20;
    long sec_start = opt_start + opt_size;
    if (fseek(f, sec_start, SEEK_SET) != 0) return -1;

    for (WORD i = 0; i < nsections; i++) {
        uint8_t sh[40];
        if (fread(sh, 1, sizeof(sh), f) != sizeof(sh)) return -1;
        if (memcmp(sh, name, strlen(name)) == 0 && sh[strlen(name)] == '\0') {
            *out_raw_ptr = (long)((uint32_t)sh[20] | ((uint32_t)sh[21] << 8) |
                                  ((uint32_t)sh[22] << 16) | ((uint32_t)sh[23] << 24));
            *out_raw_size = (DWORD)((uint32_t)sh[16] | ((uint32_t)sh[17] << 8) |
                                    ((uint32_t)sh[18] << 16) | ((uint32_t)sh[19] << 24));
            return 0;
        }
        (void)opt20; (void)opt_start;
    }
    return -1;
}

/* 计算文件中 [raw_ptr, raw_ptr+raw_size) 的 HMAC-SHA256 */
static int vsec_hash_file_region(FILE *f, long raw_ptr, DWORD raw_size,
                                 uint8_t out[VERTHYS_HMAC_BYTES])
{
    if (raw_ptr <= 0 || raw_size == 0) return -1;
    if (fseek(f, raw_ptr, SEEK_SET) != 0) return -1;

    /* 流式 HMAC：分块读取（crypto_auth_hmacsha256 无流式接口，
     * 使用 crypto_auth_hmacsha256_state） */
    crypto_auth_hmacsha256_state st;
    if (crypto_auth_hmacsha256_init(&st, K_VSEC_DOMAIN_KEY, VERTHYS_KEY_BYTES) != 0) {
        return -1;
    }

    uint8_t buf[65536];
    DWORD remaining = raw_size;
    while (remaining > 0) {
        size_t chunk = (remaining > sizeof(buf)) ? sizeof(buf) : (size_t)remaining;
        if (fread(buf, 1, chunk, f) != chunk) {
            verthys_secure_zero(buf, sizeof(buf));
            return -1;
        }
        crypto_auth_hmacsha256_update(&st, buf, chunk);
        remaining -= (DWORD)chunk;
    }
    verthys_secure_zero(buf, sizeof(buf));

    if (crypto_auth_hmacsha256_final(&st, out) != 0) {
        return -1;
    }
    return 0;
}

/* ---------- 自身文件验签缓存（解锁热路径） ---------- */

/*
 * 指纹键：自身磁盘文件的卷序列号 + 文件索引 + 大小 + 最后写入时间。
 * 卷序列号与文件索引是替换型改动的硬指纹（rename 替换必变）；大小
 * 捕获追加/截断；最后写入时间捕获 in-place 改写（对抗者精确复位
 * 元数据的场景超出本层防御范围，由锚点校验与应急闭环纵深兜底）。
 */
typedef struct IvVerifyCache {
    int      valid;
    int      result;
    DWORD    volume_serial;
    uint64_t file_index;
    uint64_t file_size;
    uint64_t mtime_ft;
} IvVerifyCache;

static IvVerifyCache g_iv_cache;
static SRWLOCK        g_iv_cache_lock = SRWLOCK_INIT;
/* 冷路径重算次数（Interlocked；测试白盒观测缓存回放/失效） */
static volatile LONG  g_iv_recompute_count = 0;

static uint64_t iv_info_index(const BY_HANDLE_FILE_INFORMATION *info)
{
    return ((uint64_t)info->nFileIndexHigh << 32) | info->nFileIndexLow;
}

static uint64_t iv_info_size(const BY_HANDLE_FILE_INFORMATION *info)
{
    return ((uint64_t)info->nFileSizeHigh << 32) | info->nFileSizeLow;
}

static uint64_t iv_info_mtime(const BY_HANDLE_FILE_INFORMATION *info)
{
    ULARGE_INTEGER u;
    u.LowPart  = info->ftLastWriteTime.dwLowDateTime;
    u.HighPart = info->ftLastWriteTime.dwHighDateTime;
    return u.QuadPart;
}

/* 调用方须已持 g_iv_cache_lock（共享或独占） */
static int iv_cache_match(const BY_HANDLE_FILE_INFORMATION *info)
{
    if (!g_iv_cache.valid) return 0;
    return g_iv_cache.volume_serial == info->dwVolumeSerialNumber &&
           g_iv_cache.file_index    == iv_info_index(info) &&
           g_iv_cache.file_size     == iv_info_size(info) &&
           g_iv_cache.mtime_ft      == iv_info_mtime(info);
}

/* 调用方须已持独占锁 */
static void iv_cache_store(const BY_HANDLE_FILE_INFORMATION *info, int result)
{
    g_iv_cache.valid         = 1;
    g_iv_cache.result        = result;
    g_iv_cache.volume_serial = info->dwVolumeSerialNumber;
    g_iv_cache.file_index    = iv_info_index(info);
    g_iv_cache.file_size     = iv_info_size(info);
    g_iv_cache.mtime_ft      = iv_info_mtime(info);
}

long integrity_verify_recompute_count(void)
{
    return (long)g_iv_recompute_count;
}

void integrity_verify_cache_reset(void)
{
    AcquireSRWLockExclusive(&g_iv_cache_lock);
    g_iv_cache.valid = 0;
    ReleaseSRWLockExclusive(&g_iv_cache_lock);
}

/*
 * 对自身文件句柄执行完整 .vsec 验签（.vsec 基准读取 + 节重算 +
 * 常量时间比对）。句柄所有权转移给内部 FILE*（fclose 关闭），一切
 * 出口均释放文件，调用方不得再 CloseHandle。验签与指纹同源于一个
 * 文件对象：指纹对象与验签对象严格同一，无路径替换竞态。
 */
static int iv_verify_file(HANDLE hfile)
{
    int fd = _open_osfhandle((intptr_t)hfile, _O_RDONLY);
    if (fd == -1) {
        CloseHandle(hfile);   /* 移交失败：本地关闭 */
        return 0;             /* 基础设施异常不误报原则 */
    }
    FILE *f = _fdopen(fd, "rb");
    if (f == NULL) {
        _close(fd);           /* 关闭底层句柄 */
        return 0;             /* 基础设施异常不误报原则 */
    }

    /* 1. 读取 .vsec 基准（与签名阶段同一字节源） */
    long vsec_ptr = 0; DWORD vsec_size = 0;
    uint8_t baseline[VSEC_BLOB_BYTES];
    memset(baseline, 0, sizeof(baseline));
    int have_vsec = (vsec_find_section(f, ".vsec", &vsec_ptr, &vsec_size) == 0 &&
                     vsec_size >= VSEC_BLOB_BYTES &&
                     fseek(f, vsec_ptr, SEEK_SET) == 0 &&
                     fread(baseline, 1, VSEC_BLOB_BYTES, f) == VSEC_BLOB_BYTES);
    if (!have_vsec) {
        fclose(f);
        return 0;  /* 无 .vsec（开发构建）：跳过 */
    }

    uint32_t magic = (uint32_t)baseline[0] | ((uint32_t)baseline[1] << 8) |
                     ((uint32_t)baseline[2] << 16) | ((uint32_t)baseline[3] << 24);
    uint16_t vsec_version = (uint16_t)((uint16_t)baseline[4] |
                                       ((uint16_t)baseline[5] << 8));
    uint8_t all_zero = 0;
    for (size_t i = 0; i < VSEC_BLOB_BYTES; i++) all_zero |= baseline[i];
    if (magic != VSEC_MAGIC || all_zero == 0) {
        verthys_secure_zero(baseline, sizeof(baseline));
        fclose(f);
        return 0; /* 未配置（全零占位）或魔法不符：跳过 */
    }

    /* 2. 重算 .text / .rdata（版本 2 起 + .rhat）文件内容 HMAC */
    uint8_t text_mac[VERTHYS_HMAC_BYTES];
    uint8_t rdata_mac[VERTHYS_HMAC_BYTES];
    uint8_t rhat_mac[VERTHYS_HMAC_BYTES];
    long t_ptr = 0, r_ptr = 0, h_ptr = 0;
    DWORD t_size = 0, r_size = 0, h_size = 0;
    int have_rhat = 0;
    int ok = (vsec_find_section(f, ".text", &t_ptr, &t_size) == 0 &&
              vsec_find_section(f, ".rdata", &r_ptr, &r_size) == 0 &&
              vsec_hash_file_region(f, t_ptr, t_size, text_mac) == 0 &&
              vsec_hash_file_region(f, r_ptr, r_size, rdata_mac) == 0);
    if (ok && vsec_version >= VSEC_VERSION_2) {
        /* .rhat 节缺失/HMAC 计算失败：基础设施异常 → 跳过该槽不误报
         *（节被整体移除的场景必然改变其余节布局，已由 .text/.rdata 检出） */
        have_rhat = (vsec_find_section(f, ".rhat", &h_ptr, &h_size) == 0 &&
                     vsec_hash_file_region(f, h_ptr, h_size, rhat_mac) == 0);
    }
    fclose(f);

    if (!ok) {
        verthys_secure_zero(baseline, sizeof(baseline));
        return 0; /* 节解析失败：基础设施异常不误报 */
    }

    /* 3. 常量时间比对（版本 2 起追加 .rhat 槽） */
    uint8_t diff = 0;
    for (size_t i = 0; i < VERTHYS_HMAC_BYTES; i++) {
        diff |= (uint8_t)(text_mac[i] ^ baseline[VSEC_TEXT_HMAC_OFF + i]);
        diff |= (uint8_t)(rdata_mac[i] ^ baseline[VSEC_RDATA_HMAC_OFF + i]);
        if (have_rhat) {
            diff |= (uint8_t)(rhat_mac[i] ^ baseline[VSEC_RHAT_HMAC_OFF + i]);
        }
    }
    verthys_secure_zero(text_mac, sizeof(text_mac));
    verthys_secure_zero(rdata_mac, sizeof(rdata_mac));
    verthys_secure_zero(rhat_mac, sizeof(rhat_mac));
    verthys_secure_zero(baseline, sizeof(baseline));

    if (diff != 0) {
        /* 分发二进制被篡改（高置信度）→ KILL 级上报 + 拒绝解锁 */
        emergency_report(EMERG_LEVEL_KILL, EMERG_SIG_INTEGRITY_FAIL);
        return (int)VERTHYS_ERR_CORRUPT;
    }
    return 0;
}

int integrity_verify_startup(void)
{
    /* 常量时间引用 .vsec（防止 /OPT:REF 剪除只读节） */
    volatile const uint8_t *blob_ref = g_vsec_blob;
    (void)blob_ref;

    /* 1. 定位自身模块文件路径 */
    HMODULE hSelf = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)&integrity_verify_startup, &hSelf) ||
        hSelf == NULL) {
        return 0;  /* 无法定位自身模块：不阻断（基础设施异常不误报原则） */
    }
    wchar_t self_path[MAX_PATH];
    if (GetModuleFileNameW(hSelf, self_path, MAX_PATH) == 0) {
        return 0;
    }

    /* 2. 自身文件句柄 + 指纹（GetFileInformationByHandle 内核元数据，
     *    便宜且可靠；三向共享打开防互斥锁死） */
    HANDLE hf = CreateFileW(self_path, GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        return 0;  /* 文件打开失败：不阻断 */
    }
    BY_HANDLE_FILE_INFORMATION info;
    int have_info = GetFileInformationByHandle(hf, &info) ? 1 : 0;

    /* 3. 快路径：指纹命中 → 回放上次验签结论（零节 I/O）。
     *    共享锁只读，不阻塞并发解锁。 */
    {
        int hit = 0;
        int rc = 0;
        if (have_info) {
            AcquireSRWLockShared(&g_iv_cache_lock);
            hit = iv_cache_match(&info);
            if (hit) rc = g_iv_cache.result;
            ReleaseSRWLockShared(&g_iv_cache_lock);
        }
        if (hit) {
            CloseHandle(hf);
            return rc;
        }
    }

    /* 4. 冷路径：模块级单飞锁独占重算；双检拦截并发对手先完成的重算。
     *    验签与指纹同源于本句柄（iv_verify_file 转移所有权）。 */
    {
        int hit = 0;
        int rc = 0;
        AcquireSRWLockExclusive(&g_iv_cache_lock);
        if (have_info) {
            hit = iv_cache_match(&info);
            if (hit) rc = g_iv_cache.result;
        }
        if (!hit) {
            InterlockedIncrement(&g_iv_recompute_count);
            rc = iv_verify_file(hf);
            hf = INVALID_HANDLE_VALUE;
            if (have_info) iv_cache_store(&info, rc);
        }
        ReleaseSRWLockExclusive(&g_iv_cache_lock);
        if (hf != INVALID_HANDLE_VALUE) CloseHandle(hf);
        return rc;
    }
}
