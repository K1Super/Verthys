/*
 * test_txn_recovery_inject.c — 方案 §8.2 配套测试：事务半写/损坏故障注入
 *
 * 以字节级文件手术模拟磁盘半写/损坏场景，验证事务恢复与防回滚链在
 * 异常输入下的行为闭环（不崩溃、错误码语义正确）：
 *   注入 1：超级块密文区比特翻转（模拟半写） → 解锁必须失败（AUTH/CORRUPT），
 *           且绝不静默解出错误数据
 *   注入 2：尾部事务日志区覆写（模拟 CONFIRM 落笔丢失） → 容器仍可解锁
 *           （超级块为准，日志仅辅助确认）
 *   注入 3：魔数破坏 → FORMAT 拒绝
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"
#include "verthys_container_v3.h"   /* V3 三副本布局（副本内密文翻转） */
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

    /* ★ V3（§6.3 法定人数语义）：超级块为 3 副本 FlatBuffers 帧
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
