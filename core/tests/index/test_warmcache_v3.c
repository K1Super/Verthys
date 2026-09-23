/*
 * test_warmcache_v3.c — V3 温缓存验收（保存/加载/段布局矩形校验）
 *
 * 覆盖（验收标准）：
 *   1. roundtrip：save（表记录 + MemTable 快照双段）→ try_load 命中，
 *      双段明文逐字节还原；
 *   2. 空 MemTable 规范形：memtable NULL 保存 → {off=0,size=0} 合法，
 *      表记录段照常命中（校验不过严，不误伤合法布局）；
 *   3. 段布局 fuzz：重算 HMAC 保持整文件自洽后注入非法布局
 *      （mt 下界越界、sst 下界/上界越界、sst 尺寸溢出、两段重叠、
 *      空段非规范形）→ 全部判 miss（hit=0 + VERTHYS_OK，
 *      不中断调用方，回退冷启动语义）。
 */
#include "verthys_test.h"
#include "verthys_warmcache_v3.h"
#include "verthys_crypto.h"
#include "verthys_internal.h"   /* verthys_secure_zero */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <io.h>                 /* _fseeki64 / _ftelli64 */

#define V3IC_T_BASE  "test_warmcache_v3"
#define V3IC_T_CACHE "test_warmcache_v3.idx_cache"

/* Header 字段偏移（与 160B 定长头布局一致，测试补丁专用） */
#define V3IC_T_OFF_HMAC     46u
#define V3IC_T_OFF_MT_OFF   78u
#define V3IC_T_OFF_MT_SIZE  86u
#define V3IC_T_OFF_SST_OFF  94u
#define V3IC_T_OFF_SST_SIZE 102u

static void v3ict_cleanup(void)
{
    verthys_warmcache_v3_delete(V3IC_T_BASE);
}

static void v3ict_put_u64le(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8));
}

static uint64_t v3ict_get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) v |= (uint64_t)p[i] << (i * 8);
    return v;
}

/*
 * 注入段布局 + HMAC 重算写回（自排除模式，与保存侧同款）：
 * 补丁后的文件 HMAC 自洽，唯一被触发的是 try_load 的段布局校验——
 * 隔离验证布局矩形约束本身。
 */
static int v3ict_patch_layout(const uint8_t key[VERTHYS_KEY_BYTES],
                              uint64_t mt_off, uint64_t mt_size,
                              uint64_t sst_off, uint64_t sst_size,
                              size_t *out_file_len)
{
    FILE *f = fopen(V3IC_T_CACHE, "rb");
    uint8_t *buf = NULL;
    long long flen;
    uint8_t mac[VERTHYS_HMAC_BYTES];
    int ok = -1;

    if (f == NULL) return -1;
    if (_fseeki64(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    flen = _ftelli64(f);
    if (flen <= 0 || flen > (long long)VERTHYS_V3IC_MAX_BYTES) {
        fclose(f);
        return -1;
    }
    buf = (uint8_t *)malloc((size_t)flen);
    if (buf == NULL) { fclose(f); return -1; }
    if (_fseeki64(f, 0, SEEK_SET) != 0 ||
        fread(buf, 1, (size_t)flen, f) != (size_t)flen) {
        fclose(f);
        free(buf);
        return -1;
    }
    fclose(f);

    v3ict_put_u64le(buf + V3IC_T_OFF_MT_OFF, mt_off);
    v3ict_put_u64le(buf + V3IC_T_OFF_MT_SIZE, mt_size);
    v3ict_put_u64le(buf + V3IC_T_OFF_SST_OFF, sst_off);
    v3ict_put_u64le(buf + V3IC_T_OFF_SST_SIZE, sst_size);

    memset(buf + V3IC_T_OFF_HMAC, 0, VERTHYS_V3IC_HMAC_BYTES);
    if (verthys_hmac_sha256(mac, key, buf, (size_t)flen) == 0) {
        memcpy(buf + V3IC_T_OFF_HMAC, mac, VERTHYS_V3IC_HMAC_BYTES);
        memset(mac, 0, sizeof(mac));
        f = fopen(V3IC_T_CACHE, "wb");
        if (f != NULL) {
            ok = (fwrite(buf, 1, (size_t)flen, f) == (size_t)flen) ? 0 : -1;
            fclose(f);
        }
    }
    free(buf);
    if (ok == 0) *out_file_len = (size_t)flen;
    return ok;
}

/* 期望 miss：VERTHYS_OK + hit=0 + 四出参全空（不中断、零残留） */
static int v3ict_expect_miss(const uint8_t cid[VERTHYS_V3IC_CONTAINER_ID_BYTES],
                             uint64_t txid, const uint8_t key[VERTHYS_KEY_BYTES])
{
    uint8_t *t_pt = NULL, *m_pt = NULL;
    size_t t_len = 0, m_len = 0;
    int hit = -1;

    if (verthys_warmcache_v3_try_load(V3IC_T_BASE, cid, txid, key,
                                      &t_pt, &t_len, &m_pt, &m_len, &hit) != VERTHYS_OK) {
        return -1;
    }
    if (hit != 0 || t_pt != NULL || m_pt != NULL || t_len != 0 || m_len != 0) {
        return -1;
    }
    return 0;
}

TEST(v3ic_roundtrip_and_layout_fuzz)
{
    uint8_t key[VERTHYS_KEY_BYTES];
    uint8_t cid[VERTHYS_V3IC_CONTAINER_ID_BYTES];
    const uint64_t txid = 1234;
    uint8_t tables_pt[128], mem_pt[64];
    uint8_t raw[VERTHYS_V3IC_HEADER_BYTES];
    uint8_t *t_out = NULL, *m_out = NULL;
    size_t t_len = 0, m_len = 0, file_len = 0;
    uint64_t o_mt_off, o_mt_size, o_sst_off, o_sst_size;
    int hit = -1;
    unsigned i;

    v3ict_cleanup();
    verthys_random_bytes(key, sizeof(key));
    verthys_random_bytes(cid, sizeof(cid));
    for (i = 0; i < sizeof(tables_pt); i++) tables_pt[i] = (uint8_t)(i * 7 + 1);
    for (i = 0; i < sizeof(mem_pt); i++) mem_pt[i] = (uint8_t)(i * 13 + 5);

    /* 1. roundtrip：双段保存 → 命中 + 明文逐字节还原 */
    CHECK_EQ(verthys_warmcache_v3_save(V3IC_T_BASE, cid, txid, key,
                                       tables_pt, sizeof(tables_pt),
                                       mem_pt, sizeof(mem_pt)), VERTHYS_OK);
    CHECK_EQ(verthys_warmcache_v3_try_load(V3IC_T_BASE, cid, txid, key,
                                           &t_out, &t_len, &m_out, &m_len, &hit),
             VERTHYS_OK);
    CHECK_EQ(hit, 1);
    CHECK_EQ(t_len, sizeof(tables_pt));
    CHECK(t_out != NULL && memcmp(t_out, tables_pt, sizeof(tables_pt)) == 0);
    CHECK_EQ(m_len, sizeof(mem_pt));
    CHECK(m_out != NULL && memcmp(m_out, mem_pt, sizeof(mem_pt)) == 0);

    /* 读取保存侧原始布局（补丁基准） */
    {
        FILE *f = fopen(V3IC_T_CACHE, "rb");
        size_t n = 0;
        CHECK(f != NULL);
        while (n < VERTHYS_V3IC_HEADER_BYTES) {
            size_t r = fread(raw + n, 1, VERTHYS_V3IC_HEADER_BYTES - n, f);
            if (r == 0) break;
            n += r;
        }
        fclose(f);
        CHECK_EQ(n, VERTHYS_V3IC_HEADER_BYTES);
    }
    o_mt_off  = v3ict_get_u64le(raw + V3IC_T_OFF_MT_OFF);
    o_mt_size = v3ict_get_u64le(raw + V3IC_T_OFF_MT_SIZE);
    o_sst_off = v3ict_get_u64le(raw + V3IC_T_OFF_SST_OFF);
    o_sst_size = v3ict_get_u64le(raw + V3IC_T_OFF_SST_SIZE);
    CHECK(o_mt_off == VERTHYS_V3IC_HEADER_BYTES);
    CHECK(o_mt_size == sizeof(mem_pt) + VERTHYS_CNG_TAG_BYTES);
    CHECK(o_sst_off == VERTHYS_V3IC_HEADER_BYTES + o_mt_size);
    CHECK(o_sst_size == sizeof(tables_pt) + VERTHYS_CNG_TAG_BYTES);
    file_len = VERTHYS_V3IC_HEADER_BYTES + o_mt_size + o_sst_size;

    verthys_secure_zero(t_out, t_len);
    free(t_out);
    verthys_secure_zero(m_out, m_len);
    free(m_out);
    t_out = m_out = NULL;
    t_len = m_len = 0;

    /* 3. 段布局 fuzz：非法布局（HMAC 重算保持自洽）一律 miss */
    {
        /* 初始值依赖运行期布局基值，须为自动存储期 */
        const struct {
            uint64_t mt_off, mt_size, sst_off, sst_size;
        } cases[] = {
            /* mt 段下界越界（非空段） */
            { VERTHYS_V3IC_HEADER_BYTES - 1, o_mt_size, o_sst_off, o_sst_size },
            /* sst 段下界越界（非空段） */
            { o_mt_off, o_mt_size, VERTHYS_V3IC_HEADER_BYTES - 1, o_sst_size },
            /* sst 段起点越过文件尾 */
            { o_mt_off, o_mt_size, file_len + 1, o_sst_size },
            /* sst 段起点恰在文件尾且非空 */
            { o_mt_off, o_mt_size, file_len, o_sst_size },
            /* sst 段尺寸越过文件尾 */
            { o_mt_off, o_mt_size, o_sst_off, o_sst_size + 8 },
            /* 两段重叠：mt 尾越过 sst 头（mt 起点仍合法） */
            { o_sst_off - o_mt_size + 4, o_mt_size, o_sst_off, o_sst_size },
            /* 空 mt 段非规范形（off 非零） */
            { VERTHYS_V3IC_HEADER_BYTES, 0, o_sst_off, o_sst_size },
            /* sst 下界约束无条件成立：双空段 + sst_off 低于 HEADER */
            { 0, 0, VERTHYS_V3IC_HEADER_BYTES - 1, 0 },
        };
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            size_t plen = 0;
            CHECK_EQ(v3ict_patch_layout(key, cases[i].mt_off, cases[i].mt_size,
                                        cases[i].sst_off, cases[i].sst_size,
                                        &plen), 0);
            CHECK_EQ(plen, file_len);
            CHECK_EQ(v3ict_expect_miss(cid, txid, key), 0);
        }
    }

    /* 2. 空 MemTable 规范形 {off=0,size=0} 仍命中（校验不过严） */
    {
        uint8_t *e_t = NULL, *e_m = NULL;
        size_t e_tl = 0, e_ml = 0;
        int e_hit = -1;
        CHECK_EQ(verthys_warmcache_v3_save(V3IC_T_BASE, cid, txid, key,
                                           tables_pt, sizeof(tables_pt),
                                           NULL, 0), VERTHYS_OK);
        CHECK_EQ(verthys_warmcache_v3_try_load(V3IC_T_BASE, cid, txid, key,
                                               &e_t, &e_tl, &e_m, &e_ml, &e_hit),
                 VERTHYS_OK);
        CHECK_EQ(e_hit, 1);
        CHECK_EQ(e_tl, sizeof(tables_pt));
        CHECK(e_t != NULL && memcmp(e_t, tables_pt, sizeof(tables_pt)) == 0);
        CHECK(e_m == NULL && e_ml == 0);
        if (e_t != NULL) {
            verthys_secure_zero(e_t, e_tl);
            free(e_t);
        }
    }

    verthys_secure_zero(key, sizeof(key));
    verthys_secure_zero(cid, sizeof(cid));
    v3ict_cleanup();
    return 0;
}