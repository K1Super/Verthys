/*
 * test_txn_recovery_inject.c — 配套测试：事务半写/损坏故障注入
 *
 * 以字节级文件手术模拟磁盘半写/损坏场景，验证事务恢复与防回滚链在
 * 异常输入下的行为闭环（不崩溃、错误码语义正确）：
 *   注入 1：超级块密文区比特翻转（模拟半写） → 解锁必须失败（AUTH/CORRUPT），
 *           且绝不静默解出错误数据
 *   注入 2：尾部事务日志区覆写（模拟 CONFIRM 落笔丢失） → 容器仍可解锁
 *           （超级块为准，日志仅辅助确认）
 *   注入 3：魔数破坏 → FORMAT 拒绝
 *   注入 4：双半区环形 WAL 换区第三圈残留 → 重开扫描不得将旧帧
 *           续链回放（换区须先清零新半区数据区）
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "verthys_container_v3.h"   /* V3 三副本布局（副本内密文翻转） */
#include "verthys_crypto.h"         /* CNG AEAD（WAL 帧密钥语境） */
#include "verthys_wal.h"            /* 双半区环形 WAL（换区注入） */
#include "verthys_lsm_internal.h"   /* 帧长度常量（WAL 帧与 LSM 帧同构） */
#include "verthys_io.h"             /* 位置读写（WAL 区预扩展） */
#include "verthys_api_utils.h"      /* verthys_backoff_reset（跨测试清退避记账） */
#include <string.h>
#include <stdlib.h>

#define INJ_VERTHYS "test_inject_tmp.verthys"

static void inj_cleanup(void) { remove(INJ_VERTHYS); }

/* 读整个文件到堆缓冲 */
static uint8_t *inj_read_all(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (buf == NULL) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static int inj_write_all(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "r+b");
    if (f == NULL) return -1;
    if (fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

/* 造一个含两条记录的已锁定容器 */
static int inj_make_locked_verthys(void)
{
    inj_cleanup();
    VerthysHandle h;
    if (Verthys_Init(&h) != VERTHYS_OK) return -1;
    if (Verthys_CreateWithPreset(h, INJ_VERTHYS, "inject-pass", 11,
                               VERTHYS_PRESET_BALANCED) != VERTHYS_OK) {
        Verthys_Deinit(h);
        return -1;
    }
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "svc", 3, (const uint8_t *)"pw", 2};
    uint64_t id = 0;
    if (Verthys_AddRecord(h, &r, &id) != VERTHYS_OK) {
        Verthys_Deinit(h);
        return -1;
    }
    if (Verthys_Lock(h) != VERTHYS_OK) {
        Verthys_Deinit(h);
        return -1;
    }
    Verthys_Deinit(h);
    return 0;
}

/* 注入 1：超级块密文区比特翻转 → 解锁失败（不崩溃、不静默错解） */
TEST(inject_sb_ciphertext_bitflip_rejected)
{
    CHECK_EQ(inj_make_locked_verthys(), 0);
    size_t len = 0;
    uint8_t *buf = inj_read_all(INJ_VERTHYS, &len);
    CHECK(buf != NULL);
    CHECK(len > VERTHYS_V3_SB_REGION_END);

    /* ★ V3（法定人数语义）：超级块为 3 副本 FlatBuffers 帧
     * （[0/16K/32K)×16KB，帧头 8B + 载荷 + 零填充）。单副本翻转会被
     * 2/3 多数派票决出局、解锁照常成功——原 V2 单超块语义（翻 2KB 处
     * = 密文区中部）在 V3 落入零填充区更是零效果。等价注入 = 三副本
     * 载荷各翻一字节（帧头 payload_len 定位，翻转点取载荷中部，必然
     * 落在 HMAC 覆盖域）→ 3 副本 HMAC 全败 → 0 有效 → 口令正确探针
     * 判真损坏 → CORRUPT。 */
    for (unsigned rep = 0; rep < VERTHYS_V3_SB_REPLICA_COUNT; rep++) {
        uint64_t slot = (uint64_t)rep * 0x4000u;
        uint32_t plen = (uint32_t)buf[slot + 4] |
                        ((uint32_t)buf[slot + 5] << 8) |
                        ((uint32_t)buf[slot + 6] << 16) |
                        ((uint32_t)buf[slot + 7] << 24);
        CHECK(plen > 16 && plen <= VERTHYS_V3_SB_REPLICA_BYTES - 8u);
        buf[slot + 8u + plen / 2] ^= 0x10;
    }
    CHECK_EQ(inj_write_all(INJ_VERTHYS, buf, len), 0);
    free(buf);

    /* 解锁必须拒绝（认证失败或格式/损坏），绝不返回 OK */
    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    VerthysResult rc = Verthys_Unlock(h, INJ_VERTHYS, "inject-pass", 11, 0);
    CHECK(rc == VERTHYS_ERR_AUTH || rc == VERTHYS_ERR_CORRUPT || rc == VERTHYS_ERR_FORMAT);
    /* AUTH 记账为进程级，主动清零避免退避窗口污染后续测试 */
    verthys_backoff_reset();
    Verthys_Deinit(h);
    inj_cleanup();
    return 0;
}

/* 注入 2：尾部事务日志区覆写（CONFIRM 落笔丢失模拟）→ 容器仍可解锁 */
TEST(inject_taillog_overwrite_still_unlockable)
{
    CHECK_EQ(inj_make_locked_verthys(), 0);
    size_t len = 0;
    uint8_t *buf = inj_read_all(INJ_VERTHYS, &len);
    CHECK(buf != NULL);

    /* 尾部区域在文件末尾（64KB 尾区：4KB 事务日志 + 60KB 审计）。
     * 覆写文件末尾 256 字节，模拟事务日志/审计区半写。 */
    CHECK(len > 256);
    memset(buf + len - 256, 0xAB, 256);
    CHECK_EQ(inj_write_all(INJ_VERTHYS, buf, len), 0);
    free(buf);

    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    /* 超级块完好 → 解锁成功（崩溃恢复语义：以超级块为准） */
    CHECK_EQ(Verthys_Unlock(h, INJ_VERTHYS, "inject-pass", 11, 0), VERTHYS_OK);
    VerthysRecord out;
    CHECK_EQ(Verthys_GetRecord(h, 1, &out), VERTHYS_OK);
    Verthys_Lock(h);
    Verthys_Deinit(h);
    inj_cleanup();
    return 0;
}

/* 注入 3：魔数破坏 → FORMAT 拒绝 */
TEST(inject_bad_magic_rejected)
{
    CHECK_EQ(inj_make_locked_verthys(), 0);
    size_t len = 0;
    uint8_t *buf = inj_read_all(INJ_VERTHYS, &len);
    CHECK(buf != NULL);
    buf[0] ^= 0xFF;  /* 破坏 magic 首字节 */
    CHECK_EQ(inj_write_all(INJ_VERTHYS, buf, len), 0);
    free(buf);

    VerthysHandle h;
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    VerthysResult rc = Verthys_Unlock(h, INJ_VERTHYS, "inject-pass", 11, 0);
    CHECK(rc == VERTHYS_ERR_FORMAT || rc == VERTHYS_ERR_IO);
    Verthys_Deinit(h);
    inj_cleanup();
    return 0;
}

/* ================== WAL 换区第三圈残留注入 ================== */

/*
 * 注入 4：双半区环形 WAL 换区第三圈残留（修复前必失败）。
 *
 * 换区只写新半区 24B 头、不清零数据区。第三圈换回旧半区时，新链
 * 首帧之后的旧帧残留仍是合法 AEAD 帧（同密钥、nonce 帧内记录），
 * 重开扫描按"自半区头逐帧解、magic 不符才停"续链——旧帧被当作
 * 当前链一部分扫描/回放。
 *
 * 构造（首帧同长对齐，保证新链必然短于旧链且无撕裂掩盖）：
 *   第一圈 A：首帧 53B BEGIN + 大帧（4219B INDEX）填满 → 换 B；
 *   B 圈：大帧 + 53B BEGIN 填至极限 → 末帧 BEGIN（新 txid）触发
 *   换回 A——第三圈首帧与第一圈首帧同长（完整覆盖），其后旧帧链
 *   必然完整续上（修复前红态的直接构造）。
 *
 * 修复后：换区时新半区数据区先清零，重开扫描止于第三圈首帧
 *（其后全零、magic 不符即停）。
 *
 * 失败防残留：观测值记录 + 清理先行 + 统一断言。
 */
#define W3R_TMP         "test_wal_inject.tmp"
#define W3R_KEY_BYTES   VERTHYS_CNG_KEY_BYTES
#define W3R_NAME_BYTES  VERTHYS_LSM_NAME_MAX_BYTES
#define W3R_BIG_PT      (9u + VERTHYS_LSM_ENTRY_HEADER_BYTES + W3R_NAME_BYTES)
#define W3R_BIG_FRAME   ((uint64_t)VERTHYS_LSM_FRAME_HEADER_BYTES + W3R_BIG_PT + \
                         VERTHYS_CNG_TAG_BYTES + VERTHYS_LSM_FRAME_TAIL_BYTES)
#define W3R_SMALL_FRAME ((uint64_t)VERTHYS_LSM_FRAME_HEADER_BYTES + 17u + \
                         VERTHYS_CNG_TAG_BYTES + VERTHYS_LSM_FRAME_TAIL_BYTES)
#define W3R_TXA         UINT64_C(100)
#define W3R_TXB         UINT64_C(300)

static void w3r_cleanup(void) { remove(W3R_TMP); }

static void w3r_make_begin(VerthysWalRecord *rec, uint64_t txid)
{
    memset(rec, 0, sizeof(*rec));
    rec->type = VERTHYS_WAL_REC_BEGIN;
    rec->txid = txid;
    rec->u.begin.timestamp = 0;
}

static void w3r_make_big_index(VerthysWalRecord *rec, uint8_t *name,
                               uint64_t txid)
{
    memset(rec, 0, sizeof(*rec));
    rec->type = VERTHYS_WAL_REC_INDEX;
    rec->txid = txid;
    rec->u.index.entry.lid = txid;
    rec->u.index.entry.name = name;
    rec->u.index.entry.name_len = W3R_NAME_BYTES;
}

TEST(inject_wal_third_round_residual_not_replayed)
{
    VerthysCngAead aead;
    uint8_t wk[W3R_KEY_BYTES], wk_copy[W3R_KEY_BYTES];
    uint8_t name[W3R_NAME_BYTES];
    FILE *f = NULL;
    VerthysWal *w = NULL;
    VerthysWalRecord rec;
    uint64_t ka = 0, kb = 0;
    uint64_t frames_open = 0xFFFFFFFFu, torn_open = 0xFFFFFFFFu;
    uint64_t frames_replay = 0xFFFFFFFFu, discarded = 0xFFFFFFFFu;
    int setup_ok = 1, g1_ok = 0, open_ok = 0, replay_ok = 0;

    w3r_cleanup();
    memset(name, 'x', sizeof(name));

    /* --- 序列执行（观测值记录，不中途断言） --- */
    if (verthys_cng_aead_init(&aead) != VERTHYS_OK) setup_ok = 0;
    if (setup_ok) {
        verthys_random_bytes(wk, W3R_KEY_BYTES);
        memcpy(wk_copy, wk, W3R_KEY_BYTES);
        if (verthys_cng_aead_import_key(&aead, wk_copy, NULL) != VERTHYS_OK) {
            setup_ok = 0;
        }
    }
    if (setup_ok) {
        fopen_s(&f, W3R_TMP, "w+b");
        if (f == NULL) setup_ok = 0;
        else {
            /* 预扩展至 WAL 区域满幅：空文件读半区头会因读越界失败 */
            uint8_t z = 0;
            if (vio_pwrite64(f, (uint64_t)VERTHYS_WAL_REGION_BYTES - 1u,
                             &z, 1u) != 0) {
                setup_ok = 0;
            }
        }
    }
    if (setup_ok) {
        w = verthys_wal_create();
        if (w == NULL ||
            verthys_wal_open(w, f, 0u, &aead, NULL, NULL) != VERTHYS_OK) {
            setup_ok = 0;
        }
    }

    if (setup_ok) {
        /* 第一圈 A：首帧 BEGIN(53B) + 大帧填充至触发换区（触发帧入 B） */
        w3r_make_begin(&rec, W3R_TXA);
        if (verthys_wal_append(w, &rec) != VERTHYS_OK) setup_ok = 0;
        ka = 1;
        w3r_make_big_index(&rec, name, W3R_TXA);
        while (setup_ok && verthys_wal_active_half(w) == 0u) {
            if (verthys_wal_append(w, &rec) != VERTHYS_OK) setup_ok = 0;
            else if (verthys_wal_active_half(w) == 0u) ka++;
            else kb++;                       /* 触发换区帧写入 B */
        }
        /* B 圈：大帧 + BEGIN 小帧填至极限（cursor 预判——触发帧必须
         * 是第三圈同长首帧，不得让大帧误入 A） */
        while (setup_ok && verthys_wal_active_half(w) == 1u &&
               verthys_wal_cursor(w) + W3R_BIG_FRAME
                   <= (uint64_t)VERTHYS_WAL_HALF_BYTES) {
            if (verthys_wal_append(w, &rec) != VERTHYS_OK) setup_ok = 0;
            else kb++;
        }
        w3r_make_begin(&rec, W3R_TXA);
        while (setup_ok && verthys_wal_active_half(w) == 1u &&
               verthys_wal_cursor(w) + W3R_SMALL_FRAME
                   <= (uint64_t)VERTHYS_WAL_HALF_BYTES) {
            if (verthys_wal_append(w, &rec) != VERTHYS_OK) setup_ok = 0;
            else kb++;
        }
        /* 第三圈：BEGIN(新 txid) 触发换回 A（与第一圈首帧同长） */
        w3r_make_begin(&rec, W3R_TXB);
        if (setup_ok && verthys_wal_append(w, &rec) == VERTHYS_OK &&
            verthys_wal_active_half(w) == 0u) {
            g1_ok = 1;
        }

        /* 崩溃模拟：close 只清内存态（盘面保留）→ 重开扫描 */
        if (g1_ok && verthys_wal_close(w) == VERTHYS_OK &&
            verthys_wal_open(w, f, 0u, &aead, &frames_open, &torn_open)
                == VERTHYS_OK) {
            open_ok = 1;
            if (verthys_wal_replay(w, 0, 0, NULL, NULL, &frames_replay,
                                   NULL, &discarded) == VERTHYS_OK) {
                replay_ok = 1;
            }
        }
    }

    /* --- 清理先行（断言失败不产生句柄/文件残留） --- */
    verthys_wal_destroy(w);
    if (f != NULL) fclose(f);
    verthys_cng_aead_destroy(&aead);
    w3r_cleanup();

    /* --- 统一断言 --- */
    printf("[wal-inject] obs: ka=%llu kb=%llu frames_open=%llu torn=%llu "
           "frames_replay=%llu discarded=%llu\n",
           (unsigned long long)ka, (unsigned long long)kb,
           (unsigned long long)frames_open, (unsigned long long)torn_open,
           (unsigned long long)frames_replay, (unsigned long long)discarded);

    CHECK(setup_ok == 1);
    CHECK(g1_ok == 1);                    /* 换回 A 确已发生（第三圈构造成立） */
    CHECK(open_ok == 1);
    CHECK(replay_ok == 1);
    /* 核心断言（修复前红：frames_open = ka + kb，残留帧被续链扫描；
     * 修复后 = 1 + kb，第三圈首帧之后全零即停） */
    CHECK(frames_open == 1u + kb);
    CHECK(torn_open == 0u);
    CHECK(frames_replay == frames_open);
    /* 回放丢弃计数（修复前红：ka + kb —— 残留旧组记录一并投递丢弃；
     * 修复后 = kb + 1 —— 仅 B 圈组 + 第三圈 BEGIN） */
    CHECK(discarded == kb + 1u);

    printf("[wal-inject] WAL 换区第三圈残留不再被回放\n");
    return 0;
}
