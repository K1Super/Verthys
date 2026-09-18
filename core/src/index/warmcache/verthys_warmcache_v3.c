/*
 * verthys_warmcache_v3.c — V3 温启动缓存（.verthys.idx_cache，'V3IC' 格式）
 *
 * 设计依据：
 *   - docs/UNLOCK_OPTIMIZATION.md §7（温启动缓存 V3 版）/ §14.2（常量）
 *   - docs/V3_UPGRADE_PLAYBOOK.md WP-5（★index/verthys_warmcache.c 重写）
 *
 * 失败语义（红线）：温缓存为持久化优化，非数据正确性依赖——
 * 读取路径任何失败（不存在/超限/magic 不符/HMAC 不符/解密失败）一律
 * 按未命中处理（*out_hit=0，VERTHYS_OK），调用方（解锁流水线 S5）回退
 * 冷启动路径，绝不中断解锁流程。
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include "verthys_warmcache_v3.h"
#include "verthys_crypto.h"
#include "verthys_crypto_cng.h"
#include "verthys_internal.h"     /* verthys_secure_zero */

/* ---------- Header 字段偏移（160B 定长，与 verthys_warmcache_v3.h §7.1 对齐） ---------- */

#define V3IC_OFF_MAGIC          0u    /* u32le */
#define V3IC_OFF_VERSION        4u    /* u16le */
#define V3IC_OFF_CONTAINER_ID   6u    /* 32B */
#define V3IC_OFF_TXID           38u   /* u64le */
#define V3IC_OFF_HMAC           46u   /* 32B */
#define V3IC_OFF_MT_OFFSET      78u   /* u64le */
#define V3IC_OFF_MT_SIZE        86u   /* u64le */
#define V3IC_OFF_SST_OFFSET     94u   /* u64le */
#define V3IC_OFF_SST_SIZE       102u  /* u64le */
#define V3IC_OFF_KDF_SALT       110u  /* 16B */
#define V3IC_OFF_RESERVED       126u  /* 34B 零填充 */

/* 小端编码辅助（头文件约定全字段小端） */
static void v3ic_put_u16le(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

static void v3ic_put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void v3ic_put_u64le(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8));
}

static uint16_t v3ic_get_u16le(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t v3ic_get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t v3ic_get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) v |= (uint64_t)p[i] << (i * 8);
    return v;
}

/*
 * ★ 确定性 nonce 复现（与 verthys_crypto_cng.c encode_nonce 严格一致）：
 * 12 字节大端单调计数器。每次保存 kdf_salt 随机 → cache_key 独立 →
 * 计数器从 1 重新起算无跨保存复用风险；读取侧按写入顺序（MemTable 段
 * 在前、SSTable 段在后）确定性重建 nonce(1)/nonce(2)。
 */
static void v3ic_encode_nonce(uint8_t nonce[VERTHYS_CNG_NONCE_BYTES], uint64_t counter)
{
    for (unsigned i = 0; i < VERTHYS_CNG_NONCE_BYTES; i++) {
        unsigned shift = (VERTHYS_CNG_NONCE_BYTES - 1 - i) * 8;
        nonce[i] = (uint8_t)((shift >= 64) ? 0 : (counter >> shift));
    }
}

/* 常量时间比较（HMAC 校验，防时序侧信道） */
static int v3ic_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

/* ---------- 路径构建（verthys_path + ".idx_cache"，UTF-8 → 宽字符） ---------- */

static wchar_t *v3ic_utf8_to_wide(const char *s)
{
    if (s == NULL) return NULL;
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (w == NULL) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

static wchar_t *v3ic_build_path_w(const char *verthys_path)
{
    if (verthys_path == NULL) return NULL;
    size_t plen = strlen(verthys_path);
    size_t slen = strlen(VERTHYS_V3IC_SUFFIX);
    char *path = (char *)malloc(plen + slen + 1);
    if (path == NULL) return NULL;
    memcpy(path, verthys_path, plen);
    memcpy(path + plen, VERTHYS_V3IC_SUFFIX, slen + 1);
    wchar_t *w = v3ic_utf8_to_wide(path);
    verthys_secure_zero(path, plen + slen + 1);
    free(path);
    return w;
}

/* ---------- AEAD 段加密 / 解密（派生缓存密钥，私有上下文） ---------- */

/*
 * 派生 cache_key 并导入私有 CNG 上下文：
 *   cache_key = HKDF-SHA256-Expand(integrity_key,
 *               "verthys/warmcache-aead-v3" ‖ kdf_salt)
 * HKDF info 域分离保证与 integrity_key 的 HMAC 用途密码学独立；
 * 密钥导入后用户态副本立即清零（import_key 内部完成）。
 */
static VerthysResult v3ic_derive_cache_key(const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                                         const uint8_t kdf_salt[VERTHYS_V3IC_KDF_SALT_BYTES],
                                         VerthysCngAead *aead)
{
    uint8_t info[64];
    uint8_t cache_key[VERTHYS_KEY_BYTES];
    const size_t info_len = strlen(VERTHYS_V3IC_KDF_INFO) + VERTHYS_V3IC_KDF_SALT_BYTES;
    VerthysResult r;

    memcpy(info, VERTHYS_V3IC_KDF_INFO, strlen(VERTHYS_V3IC_KDF_INFO));
    memcpy(info + strlen(VERTHYS_V3IC_KDF_INFO), kdf_salt, VERTHYS_V3IC_KDF_SALT_BYTES);

    r = verthys_cng_aead_init(aead);
    if (r != VERTHYS_OK) return r;

    if (verthys_hkdf_expand(cache_key, integrity_key, info, info_len) != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    r = verthys_cng_aead_import_key(aead, cache_key, NULL);
    verthys_secure_zero(cache_key, sizeof(cache_key));
    return r;
}

/* ---------- 读取（解锁 S5 温缓存优先路径） ---------- */

VerthysResult verthys_warmcache_v3_try_load(const char *verthys_path,
                                        const uint8_t container_id[VERTHYS_V3IC_CONTAINER_ID_BYTES],
                                        uint64_t expected_txid,
                                        const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                                        uint8_t **out_tables_pt,
                                        size_t *out_tables_len,
                                        uint8_t **out_memtable_pt,
                                        size_t *out_memtable_len,
                                        int *out_hit)
{
    if (verthys_path == NULL || container_id == NULL || integrity_key == NULL ||
        out_tables_pt == NULL || out_tables_len == NULL ||
        out_memtable_pt == NULL || out_memtable_len == NULL || out_hit == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    *out_tables_pt = NULL;
    *out_tables_len = 0;
    *out_memtable_pt = NULL;
    *out_memtable_len = 0;
    *out_hit = 0;

    wchar_t *wpath = v3ic_build_path_w(verthys_path);
    if (wpath == NULL) return VERTHYS_OK;   /* 路径构建失败 = miss */

    HANDLE h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);
    if (h == INVALID_HANDLE_VALUE) return VERTHYS_OK;   /* 不存在 = miss */

    /* 容量上限（§14.2）：> 32MB 直接判非法（miss） */
    LARGE_INTEGER fsize;
    uint8_t *buf = NULL;
    uint64_t mt_off = 0, mt_size = 0, sst_off = 0, sst_size = 0;
    uint64_t saved_txid = 0;
    uint8_t stored_hmac[VERTHYS_V3IC_HMAC_BYTES];
    uint8_t calc_hmac[VERTHYS_V3IC_HMAC_BYTES];
    uint8_t kdf_salt[VERTHYS_V3IC_KDF_SALT_BYTES];
    int hit = 0;

    if (!GetFileSizeEx(h, &fsize) ||
        fsize.QuadPart < (LONGLONG)VERTHYS_V3IC_HEADER_BYTES ||
        fsize.QuadPart > (LONGLONG)VERTHYS_V3IC_MAX_BYTES) {
        CloseHandle(h);
        return VERTHYS_OK;   /* 超限/过短 = miss */
    }
    size_t file_len = (size_t)fsize.QuadPart;

    buf = (uint8_t *)malloc(file_len);
    if (buf == NULL) {
        CloseHandle(h);
        return VERTHYS_OK;   /* 内存耗尽 = miss（冷启动兜底） */
    }

    DWORD read_total = 0;
    if (!ReadFile(h, buf, (DWORD)file_len, &read_total, NULL) ||
        read_total != (DWORD)file_len) {
        CloseHandle(h);
        free(buf);
        return VERTHYS_OK;   /* 读失败 = miss */
    }
    CloseHandle(h);

    /* Header 前置校验：magic / version / container_id */
    if (v3ic_get_u32le(buf + V3IC_OFF_MAGIC) != VERTHYS_V3IC_MAGIC ||
        v3ic_get_u16le(buf + V3IC_OFF_VERSION) != VERTHYS_V3IC_VERSION ||
        memcmp(buf + V3IC_OFF_CONTAINER_ID, container_id,
               VERTHYS_V3IC_CONTAINER_ID_BYTES) != 0) {
        free(buf);
        return VERTHYS_OK;   /* 非本容器缓存 = miss */
    }

    /* HMAC 整文件校验（hmac 字段零化的 MAC 自排除模式） */
    memcpy(stored_hmac, buf + V3IC_OFF_HMAC, VERTHYS_V3IC_HMAC_BYTES);
    memset(buf + V3IC_OFF_HMAC, 0, VERTHYS_V3IC_HMAC_BYTES);
    if (verthys_hmac_sha256(calc_hmac, integrity_key, buf, file_len) != 0) {
        memset(stored_hmac, 0, sizeof(stored_hmac));
        free(buf);
        return VERTHYS_OK;   /* HMAC 计算失败 = miss */
    }
    if (!v3ic_ct_equal(stored_hmac, calc_hmac, VERTHYS_V3IC_HMAC_BYTES)) {
        memset(stored_hmac, 0, sizeof(stored_hmac));
        free(buf);
        return VERTHYS_OK;   /* 损坏/篡改/密钥不符 = miss（fail → 冷启动） */
    }

    /* 段定位（保存侧写入的确定性布局） */
    mt_off  = v3ic_get_u64le(buf + V3IC_OFF_MT_OFFSET);
    mt_size = v3ic_get_u64le(buf + V3IC_OFF_MT_SIZE);
    sst_off = v3ic_get_u64le(buf + V3IC_OFF_SST_OFFSET);
    sst_size = v3ic_get_u64le(buf + V3IC_OFF_SST_SIZE);
    saved_txid = v3ic_get_u64le(buf + V3IC_OFF_TXID);
    memcpy(kdf_salt, buf + V3IC_OFF_KDF_SALT, VERTHYS_V3IC_KDF_SALT_BYTES);

    /* 段边界严格校验（越界 = 结构非法 = miss） */
    if ((mt_size != 0 &&
         (mt_off < VERTHYS_V3IC_HEADER_BYTES ||
          mt_off > file_len || mt_size > file_len - mt_off)) ||
        (sst_size != 0 &&
         (sst_off < VERTHYS_V3IC_HEADER_BYTES ||
          sst_off > file_len || sst_size > file_len - sst_off)) ||
        mt_off + mt_size > sst_off) {
        free(buf);
        return VERTHYS_OK;
    }

    /* AEAD 解密（派生缓存密钥；AAD 域分离；nonce 确定性重建） */
    VerthysCngAead aead;
    if (v3ic_derive_cache_key(integrity_key, kdf_salt, &aead) == VERTHYS_OK) {
        uint8_t *mt_pt = NULL, *sst_pt = NULL;
        int mt_ok = 1, sst_ok = 1;
        uint64_t nonce_counter = 0;

        /* MemTable 段（存在时 nonce = ++counter，与保存序一致） */
        if (mt_size >= VERTHYS_CNG_TAG_BYTES) {
            size_t mt_ct_len = (size_t)mt_size;
            size_t mt_cap = mt_ct_len - VERTHYS_CNG_TAG_BYTES;
            mt_pt = (uint8_t *)malloc(mt_cap ? mt_cap : 1);
            if (mt_pt == NULL) {
                mt_ok = 0;
            } else {
                uint8_t nonce[VERTHYS_CNG_NONCE_BYTES];
                v3ic_encode_nonce(nonce, ++nonce_counter);
                size_t mt_pt_len = mt_cap;
                if (verthys_cng_aead_decrypt(&aead,
                                           buf + mt_off, mt_ct_len,
                                           (const uint8_t *)VERTHYS_V3IC_AAD_MEMTABLE,
                                           strlen(VERTHYS_V3IC_AAD_MEMTABLE),
                                           nonce, mt_pt, &mt_pt_len) != VERTHYS_OK) {
                    mt_ok = 0;
                } else {
                    *out_memtable_pt = mt_pt;
                    *out_memtable_len = mt_pt_len;
                }
                if (!mt_ok) {
                    verthys_secure_zero(mt_pt, mt_cap);
                    free(mt_pt);
                    mt_pt = NULL;
                }
            }
        }

        /* SSTable 表记录段 */
        if (sst_size >= VERTHYS_CNG_TAG_BYTES) {
            size_t sst_ct_len = (size_t)sst_size;
            size_t sst_cap = sst_ct_len - VERTHYS_CNG_TAG_BYTES;
            sst_pt = (uint8_t *)malloc(sst_cap ? sst_cap : 1);
            if (sst_pt == NULL) {
                sst_ok = 0;
            } else {
                uint8_t nonce[VERTHYS_CNG_NONCE_BYTES];
                v3ic_encode_nonce(nonce, ++nonce_counter);
                size_t sst_pt_len = sst_cap;
                if (verthys_cng_aead_decrypt(&aead,
                                           buf + sst_off, sst_ct_len,
                                           (const uint8_t *)VERTHYS_V3IC_AAD_SSTABLE_META,
                                           strlen(VERTHYS_V3IC_AAD_SSTABLE_META),
                                           nonce, sst_pt, &sst_pt_len) != VERTHYS_OK) {
                    sst_ok = 0;
                } else {
                    *out_tables_pt = sst_pt;
                    *out_tables_len = sst_pt_len;
                }
                if (!sst_ok) {
                    verthys_secure_zero(sst_pt, sst_cap);
                    free(sst_pt);
                    sst_pt = NULL;
                }
            }
        }
        verthys_cng_aead_destroy(&aead);

        /*
         * 命中判定：表记录段解密成功 = 命中（seq 键控 + 盘面 Manifest
         * 权威，跨过期安全可用）。
         * txid 门控（仅 MemTable 快照段）：过期快照可能缺已提交数据，
         * 丢弃（WAL 重放完整重建，语义无损）——计数未命中不构成 miss。
         */
        if (sst_ok) {
            hit = 1;
            if (saved_txid != expected_txid) {
                /* 过期快照：丢弃 MemTable 段，保留表记录段 */
                if (*out_memtable_pt != NULL) {
                    verthys_secure_zero(*out_memtable_pt, *out_memtable_len);
                    free(*out_memtable_pt);
                    *out_memtable_pt = NULL;
                    *out_memtable_len = 0;
                }
            }
        } else {
            /* 两段解密失败按未命中（缓存损坏，介质故障；HMAC 已排除伪造） */
            if (*out_memtable_pt != NULL) {
                verthys_secure_zero(*out_memtable_pt, *out_memtable_len);
                free(*out_memtable_pt);
                *out_memtable_pt = NULL;
                *out_memtable_len = 0;
            }
        }
    }

    memset(kdf_salt, 0, sizeof(kdf_salt));
    memset(stored_hmac, 0, sizeof(stored_hmac));
    memset(calc_hmac, 0, sizeof(calc_hmac));
    free(buf);
    *out_hit = hit;
    return VERTHYS_OK;
}

/* ---------- 写入（Lock 同步 / 事务提交后异步） ---------- */

VerthysResult verthys_warmcache_v3_save(const char *verthys_path,
                                    const uint8_t container_id[VERTHYS_V3IC_CONTAINER_ID_BYTES],
                                    uint64_t txid,
                                    const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                                    const uint8_t *tables_pt, size_t tables_len,
                                    const uint8_t *memtable_pt, size_t memtable_len)
{
    if (verthys_path == NULL || container_id == NULL || integrity_key == NULL ||
        (tables_pt == NULL && tables_len != 0) ||
        (memtable_pt == NULL && memtable_len != 0)) {
        return VERTHYS_ERR_INVALID;
    }

    /* 容量预算（§14.2）：Header + 两段密文（含 16B tag）≤ 32MB */
    size_t mt_ct_len = memtable_len ? memtable_len + VERTHYS_CNG_TAG_BYTES : 0;
    size_t sst_ct_len = tables_len ? tables_len + VERTHYS_CNG_TAG_BYTES : 0;
    if ((uint64_t)VERTHYS_V3IC_HEADER_BYTES + mt_ct_len + sst_ct_len >
        (uint64_t)VERTHYS_V3IC_MAX_BYTES) {
        return VERTHYS_ERR_RESOURCE_LIMIT;
    }
    size_t file_len = VERTHYS_V3IC_HEADER_BYTES + mt_ct_len + sst_ct_len;

    wchar_t *wpath = v3ic_build_path_w(verthys_path);
    if (wpath == NULL) return VERTHYS_ERR_IO;

    wchar_t *wtmp = (wchar_t *)malloc((wcslen(wpath) + 5) * sizeof(wchar_t));
    uint8_t *buf = NULL;
    VerthysResult r = VERTHYS_OK;
    if (wtmp == NULL) {
        free(wpath);
        return VERTHYS_ERR_INTERNAL;
    }
    wcscpy_s(wtmp, wcslen(wpath) + 5, wpath);
    wcscat_s(wtmp, wcslen(wpath) + 5, L".tmp");

    buf = (uint8_t *)malloc(file_len);
    if (buf == NULL) {
        free(wtmp);
        free(wpath);
        return VERTHYS_ERR_INTERNAL;
    }

    /* 1. Header 组装（HMAC 字段零化，reserved 零填充） */
    memset(buf, 0, file_len);
    v3ic_put_u32le(buf + V3IC_OFF_MAGIC, VERTHYS_V3IC_MAGIC);
    v3ic_put_u16le(buf + V3IC_OFF_VERSION, VERTHYS_V3IC_VERSION);
    memcpy(buf + V3IC_OFF_CONTAINER_ID, container_id,
           VERTHYS_V3IC_CONTAINER_ID_BYTES);
    v3ic_put_u64le(buf + V3IC_OFF_TXID, txid);
    v3ic_put_u64le(buf + V3IC_OFF_MT_OFFSET,
                   memtable_len ? VERTHYS_V3IC_HEADER_BYTES : 0);
    v3ic_put_u64le(buf + V3IC_OFF_MT_SIZE, mt_ct_len);
    v3ic_put_u64le(buf + V3IC_OFF_SST_OFFSET,
                   VERTHYS_V3IC_HEADER_BYTES + mt_ct_len);
    v3ic_put_u64le(buf + V3IC_OFF_SST_SIZE, sst_ct_len);
    verthys_random_bytes(buf + V3IC_OFF_KDF_SALT, VERTHYS_V3IC_KDF_SALT_BYTES);

    /* 2. 两段 AEAD 加密（派生缓存密钥；AAD 域分离；nonce = 1、2） */
    {
        VerthysCngAead aead;
        uint8_t kdf_salt_copy[VERTHYS_V3IC_KDF_SALT_BYTES];
        memcpy(kdf_salt_copy, buf + V3IC_OFF_KDF_SALT, VERTHYS_V3IC_KDF_SALT_BYTES);
        r = v3ic_derive_cache_key(integrity_key, kdf_salt_copy, &aead);
        if (r != VERTHYS_OK) {
            memset(kdf_salt_copy, 0, sizeof(kdf_salt_copy));
            goto fail;
        }

        if (memtable_len != 0) {
            uint8_t nonce[VERTHYS_CNG_NONCE_BYTES];
            size_t ct_len = mt_ct_len;
            v3ic_encode_nonce(nonce, 1);
            r = verthys_cng_aead_encrypt(&aead,
                                       memtable_pt, memtable_len,
                                       (const uint8_t *)VERTHYS_V3IC_AAD_MEMTABLE,
                                       strlen(VERTHYS_V3IC_AAD_MEMTABLE),
                                       buf + VERTHYS_V3IC_HEADER_BYTES, &ct_len,
                                       nonce);
            if (r != VERTHYS_OK || ct_len != mt_ct_len) {
                verthys_cng_aead_destroy(&aead);
                memset(kdf_salt_copy, 0, sizeof(kdf_salt_copy));
                if (r == VERTHYS_OK) r = VERTHYS_ERR_INTERNAL;
                goto fail;
            }
        }
        if (tables_len != 0) {
            uint8_t nonce[VERTHYS_CNG_NONCE_BYTES];
            size_t ct_len = sst_ct_len;
            v3ic_encode_nonce(nonce, memtable_len != 0 ? 2 : 1);
            r = verthys_cng_aead_encrypt(&aead,
                                       tables_pt, tables_len,
                                       (const uint8_t *)VERTHYS_V3IC_AAD_SSTABLE_META,
                                       strlen(VERTHYS_V3IC_AAD_SSTABLE_META),
                                       buf + VERTHYS_V3IC_HEADER_BYTES + mt_ct_len,
                                       &ct_len, nonce);
            if (r != VERTHYS_OK || ct_len != sst_ct_len) {
                verthys_cng_aead_destroy(&aead);
                memset(kdf_salt_copy, 0, sizeof(kdf_salt_copy));
                if (r == VERTHYS_OK) r = VERTHYS_ERR_INTERNAL;
                goto fail;
            }
        }
        verthys_cng_aead_destroy(&aead);
        memset(kdf_salt_copy, 0, sizeof(kdf_salt_copy));
    }

    /* 3. cache_hmac = HMAC-SHA256(integrity_key, 整文件) 原地写回 */
    {
        uint8_t hmac[VERTHYS_V3IC_HMAC_BYTES];
        if (verthys_hmac_sha256(hmac, integrity_key, buf, file_len) != 0) {
            r = VERTHYS_ERR_INTERNAL;
            goto fail;
        }
        memcpy(buf + V3IC_OFF_HMAC, hmac, VERTHYS_V3IC_HMAC_BYTES);
        memset(hmac, 0, sizeof(hmac));
    }

    /* 4. 写入临时文件 → fsync → MoveFileExW 原子替换 */
    DeleteFileW(wtmp);
    HANDLE hf = CreateFileW(wtmp, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        r = VERTHYS_ERR_IO;
        goto fail;
    }
    DWORD written = 0;
    int ok = WriteFile(hf, buf, (DWORD)file_len, &written, NULL) &&
             written == (DWORD)file_len;
    if (ok && !FlushFileBuffers(hf)) ok = 0;
    CloseHandle(hf);

    if (!ok) {
        DeleteFileW(wtmp);
        r = VERTHYS_ERR_IO;
        goto fail;
    }
    if (!MoveFileExW(wtmp, wpath,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(wtmp);
        r = VERTHYS_ERR_IO;
        goto fail;
    }

    verthys_secure_zero(buf, file_len);
    free(buf);
    free(wtmp);
    free(wpath);
    return VERTHYS_OK;

fail:
    if (buf != NULL) {
        verthys_secure_zero(buf, file_len);
        free(buf);
    }
    free(wtmp);
    free(wpath);
    return r;
}

/* ---------- 删除 ---------- */

VerthysResult verthys_warmcache_v3_delete(const char *verthys_path)
{
    if (verthys_path == NULL) return VERTHYS_ERR_INVALID;
    wchar_t *wpath = v3ic_build_path_w(verthys_path);
    if (wpath == NULL) return VERTHYS_ERR_IO;
    /* 幂等：不存在视为成功 */
    if (!DeleteFileW(wpath) && GetLastError() != ERROR_FILE_NOT_FOUND) {
        free(wpath);
        return VERTHYS_ERR_IO;
    }
    free(wpath);
    return VERTHYS_OK;
}
