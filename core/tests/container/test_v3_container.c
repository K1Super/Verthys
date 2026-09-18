/*
 * test_v3_container.c — WP-2 验收：V3 超级块（多副本法定人数）
 *
 * 覆盖（PLAYBOOK WP-2 步骤 + 验收标准）：
 *   1. 初始化默认值（§6.2 布局常量逐项）
 *   2. 序列化/反序列化 roundtrip（含 TLV 扩展区）+ HMAC 幂等校验
 *   3. HMAC 认证：载荷篡改拒绝、错误 integrity_key 拒绝、
 *      垃圾/截断/根偏移损坏全拒绝（safe_read 纪律）
 *   4. 副本槽位 I/O：帧头校验、参数校验
 *   5. 法定人数提交/读取 roundtrip
 *   6. 副本损坏注入矩阵（0/1/2/3 副本损坏）：
 *      单副本字节翻转自动切换 / 双副本损坏降级（QUORUM_FAILED）/
 *      三副本损坏（CORRUPT，WAL 恢复兜底语义）
 *   7. txid 多数派语义：≥2 一致优先于孤立最高 txid
 *   8. 写故障注入（fail_mask）：单副本写失败法定人数维持、双失败提交拒绝
 *   9. VsbTxnV3 事务原语：begin/commit/rollback 终态互斥
 */
#include "verthys_test.h"
/* flatcc 运行时（flatcc_builder_aligned_free 归还序列化缓冲）。
 * 必须先于 verthys_internal.h（<windows.h> → NTDDI_VERSION → pstdint.h
 * 走自定义 typedef 路径，与 MSVC <stdint.h> fast 类型冲突 C2371）。 */
#include "superblock_v3_builder.h"
#include "verthys_container_v3.h"
#include "verthys_crypto.h"
#include "verthys_io.h"
#include "verthys_internal.h"

#include <string.h>
#include <io.h>

#define V3C_TMP "test_v3_container.tmp"
#define V3C_FRAME_HEADER_BYTES 8u

static void v3c_cleanup(void) { remove(V3C_TMP); }

/* 构造已填充敏感字段的超级块（Argon2id 参数 + 密钥包装 + 扩展区） */
static void v3c_fill(VerthysSuperBlockV3 *sb)
{
    unsigned i;
    sb->argon2_mem_kib   = 65536;
    sb->argon2_iters     = 3;
    sb->argon2_parallel  = 4;
    sb->argon2_tier      = 1;
    sb->pepper_source    = 2;
    verthys_random_bytes(sb->salt, sizeof(sb->salt));
    for (i = 0; i < VERTHYS_V3_BENCHMARK_ITEMS; i++) {
        sb->argon2_benchmark_ms[i] = 100 + i * 37;
    }
    verthys_random_bytes(sb->wrapped_key_a, sizeof(sb->wrapped_key_a));
    verthys_random_bytes(sb->wrapped_key_b, sizeof(sb->wrapped_key_b));
    verthys_random_bytes(sb->wrapped_key_c, sizeof(sb->wrapped_key_c));
    verthys_random_bytes(sb->key_a_id, sizeof(sb->key_a_id));
    verthys_random_bytes(sb->key_b_id, sizeof(sb->key_b_id));
    verthys_random_bytes(sb->key_c_id, sizeof(sb->key_c_id));
    verthys_random_bytes(sb->state_chain, sizeof(sb->state_chain));
    verthys_random_bytes(sb->merkle_root, sizeof(sb->merkle_root));
    sb->extensions_len = 64;
    for (i = 0; i < sb->extensions_len; i++) {
        sb->extensions[i] = (uint8_t)(i * 11 + 3);
    }
}

/* 生成随机 integrity_key */
static void v3c_new_key(uint8_t key[VERTHYS_KEY_BYTES])
{
    verthys_random_bytes(key, VERTHYS_KEY_BYTES);
}

/*
 * 翻转副本载荷内一字节（payload_off ∈ [0, plen)）。
 * 文件偏移 = 副本槽位偏移 + 帧头 8B + payload_off。
 */
static int v3c_flip_replica_byte(const char *path, unsigned replica_idx,
                                 size_t payload_off)
{
    FILE *f = fopen(path, "r+b");
    if (f == NULL) return -1;
    long long off = (long long)vsb_v3_replica_offset(replica_idx) +
                    V3C_FRAME_HEADER_BYTES + (long long)payload_off;
    int c, rc = -1;
    if (_fseeki64(f, off, SEEK_SET) == 0) {
        c = fgetc(f);
        if (c != EOF && _fseeki64(f, off, SEEK_SET) == 0 &&
            fputc(c ^ 0x40, f) != EOF && fflush(f) == 0 &&
            _commit(_fileno(f)) == 0) {
            rc = 0;
        }
    }
    fclose(f);
    return rc;
}

/* 提交基线超级块（txid=txid）到临时文件并返回 FILE*（"rb"） */
static FILE *v3c_commit_baseline(const uint8_t key[VERTHYS_KEY_BYTES],
                                 VerthysSuperBlockV3 *sb_out, uint64_t txid)
{
    FILE *f;
    v3c_cleanup();
    if (vsb_v3_init_new(sb_out) != VERTHYS_OK) return NULL;
    v3c_fill(sb_out);
    sb_out->txid = txid;
    f = fopen(V3C_TMP, "wb+");
    if (f == NULL) return NULL;
    if (vsb_v3_commit_quorum(f, sb_out, key) != VERTHYS_OK) {
        fclose(f);
        return NULL;
    }
    return f;  /* 调用方 fclose */
}

/* ---------- 1. 初始化默认值 ---------- */

TEST(v3sb_init_new_defaults)
{
    VerthysSuperBlockV3 sb;
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    CHECK(sb.magic == VERTHYS_V3_SB_MAGIC);
    CHECK(sb.version == VERTHYS_V3_VERSION);
    CHECK(sb.txid == 0);
    CHECK(sb.created_at != 0);
    CHECK(sb.updated_at == sb.created_at);

    /* §6.2 分区布局默认值逐项 */
    CHECK(sb.partition_table_offset == VERTHYS_V3_PARTITION_TABLE_OFFSET);
    CHECK(sb.partition_table_size == VERTHYS_V3_PARTITION_TABLE_BYTES);
    CHECK(sb.index_partition_offset == VERTHYS_V3_INDEX_PARTITION_OFFSET);
    CHECK(sb.index_partition_size == VERTHYS_V3_DEFAULT_INDEX_PARTITION_BYTES);
    CHECK(sb.extent_partition_offset ==
          VERTHYS_V3_INDEX_PARTITION_OFFSET + VERTHYS_V3_DEFAULT_INDEX_PARTITION_BYTES);
    CHECK(sb.extent_partition_size == VERTHYS_V3_DEFAULT_EXTENT_PARTITION_BYTES);
    CHECK(sb.audit_partition_offset ==
          VERTHYS_V3_INDEX_PARTITION_OFFSET + VERTHYS_V3_DEFAULT_INDEX_PARTITION_BYTES +
          VERTHYS_V3_DEFAULT_EXTENT_PARTITION_BYTES);
    CHECK(sb.audit_partition_size == VERTHYS_V3_DEFAULT_AUDIT_PARTITION_BYTES);

    /* WAL 空日志状态 */
    CHECK(sb.wal_head_offset == VERTHYS_V3_WAL_REGION_OFFSET);
    CHECK(sb.wal_tail_offset == VERTHYS_V3_WAL_REGION_OFFSET);
    CHECK(sb.wal_committed_txid == 0);

    /* state_chain 全零（首次提交由 HMAC 链起算） */
    {
        uint8_t zero[VERTHYS_V3_STATE_CHAIN_BYTES] = {0};
        CHECK(memcmp(sb.state_chain, zero, sizeof(zero)) == 0);
    }
    CHECK(sb.extensions_len == 0);
    return 0;
}

TEST(v3sb_init_rejects_null)
{
    CHECK(vsb_v3_init_new(NULL) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_equals(NULL, NULL) == 0);
    return 0;
}

/* ---------- 2. 序列化 / 反序列化 ---------- */

TEST(v3sb_serialize_parse_roundtrip)
{
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint8_t *buf = NULL;
    size_t len = 0;

    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);
    sb.txid = 42;
    sb.wal_committed_txid = 41;

    CHECK(vsb_v3_serialize(&sb, key, &buf, &len) == VERTHYS_OK);
    CHECK(buf != NULL && len > 0);
    /* 载荷必须装入副本槽位（帧头 8B） */
    CHECK(len <= VERTHYS_V3_SB_REPLICA_BYTES - V3C_FRAME_HEADER_BYTES);

    CHECK(vsb_v3_parse(buf, len, key, &out) == VERTHYS_OK);
    CHECK(vsb_v3_equals(&sb, &out) == 1);
    /* 解析回填非零 HMAC（序列化产出已认证） */
    {
        uint8_t zero[VERTHYS_V3_SB_HMAC_BYTES] = {0};
        CHECK(memcmp(out.superblock_hmac, zero, sizeof(zero)) != 0);
    }

    flatcc_builder_aligned_free(buf);
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

TEST(v3sb_parse_idempotent)
{
    /* HMAC 自排除校验必须还原缓冲：同一缓冲可重复解析 */
    VerthysSuperBlockV3 sb, out1, out2;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint8_t *buf = NULL;
    size_t len = 0;

    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);
    CHECK(vsb_v3_serialize(&sb, key, &buf, &len) == VERTHYS_OK);

    CHECK(vsb_v3_parse(buf, len, key, &out1) == VERTHYS_OK);
    CHECK(vsb_v3_parse(buf, len, key, &out2) == VERTHYS_OK);
    CHECK(vsb_v3_equals(&out1, &out2) == 1);

    flatcc_builder_aligned_free(buf);
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

TEST(v3sb_hmac_tamper_rejected)
{
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint8_t *buf = NULL;
    size_t len = 0;

    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);
    CHECK(vsb_v3_serialize(&sb, key, &buf, &len) == VERTHYS_OK);

    /* 篡改载荷中部一字节 → HMAC 不符 → AUTH */
    buf[len / 2] ^= 0x01;
    CHECK(vsb_v3_parse(buf, len, key, &out) == VERTHYS_ERR_AUTH);
    buf[len / 2] ^= 0x01;
    /* 复原后可解析（篡改仅瞬时） */
    CHECK(vsb_v3_parse(buf, len, key, &out) == VERTHYS_OK);

    flatcc_builder_aligned_free(buf);
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

TEST(v3sb_hmac_wrong_key_rejected)
{
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES], other[VERTHYS_KEY_BYTES];
    uint8_t *buf = NULL;
    size_t len = 0;

    v3c_new_key(key);
    v3c_new_key(other);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);
    CHECK(vsb_v3_serialize(&sb, key, &buf, &len) == VERTHYS_OK);

    CHECK(vsb_v3_parse(buf, len, other, &out) == VERTHYS_ERR_AUTH);
    CHECK(vsb_v3_parse(buf, len, key, &out) == VERTHYS_OK);

    flatcc_builder_aligned_free(buf);
    verthys_secure_zero(key, sizeof(key));
    verthys_secure_zero(other, sizeof(other));
    return 0;
}

TEST(v3sb_parse_garbage_rejected)
{
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint8_t *buf = NULL;
    size_t len = 0;
    uint8_t garbage[512];

    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);
    CHECK(vsb_v3_serialize(&sb, key, &buf, &len) == VERTHYS_OK);

    /* 1) 全随机垃圾 */
    verthys_random_bytes(garbage, sizeof(garbage));
    CHECK(vsb_v3_parse(garbage, sizeof(garbage), key, &out)
          == VERTHYS_ERR_FORMAT);

    /* 2) 全零 */
    memset(garbage, 0, sizeof(garbage));
    CHECK(vsb_v3_parse(garbage, sizeof(garbage), key, &out)
          == VERTHYS_ERR_FORMAT);

    /* 3) 截断（半长） */
    CHECK(vsb_v3_parse(buf, len / 2, key, &out) == VERTHYS_ERR_FORMAT);

    /* 4) 根偏移损坏 */
    buf[0] ^= 0xFF;
    CHECK(vsb_v3_parse(buf, len, key, &out) == VERTHYS_ERR_FORMAT);
    buf[0] ^= 0xFF;

    /* 5) 零长度 */
    CHECK(vsb_v3_parse(buf, 0, key, &out) == VERTHYS_ERR_INVALID);

    /* 复原后合法 */
    CHECK(vsb_v3_parse(buf, len, key, &out) == VERTHYS_OK);

    flatcc_builder_aligned_free(buf);
    verthys_secure_zero(key, sizeof(key));
    return 0;
}

TEST(v3sb_serialize_null_and_overflow_rejected)
{
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint8_t *buf = NULL;
    size_t len = 0;

    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);

    CHECK(vsb_v3_serialize(NULL, key, &buf, &len) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_serialize(&sb, NULL, &buf, &len) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_serialize(&sb, key, NULL, &len) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_serialize(&sb, key, &buf, NULL) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_parse(NULL, 16, key, &out) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_parse((uint8_t *)&sb, 16, NULL, &out) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_parse((uint8_t *)&sb, 16, key, NULL) == VERTHYS_ERR_INVALID);

    /* 扩展区长度越界（> 256） */
    sb.extensions_len = VERTHYS_V3_EXTENSIONS_MAX + 1;
    CHECK(vsb_v3_serialize(&sb, key, &buf, &len) == VERTHYS_ERR_INVALID);
    sb.extensions_len = 0;

    verthys_secure_zero(key, sizeof(key));
    return 0;
}

/* ---------- 3. 副本槽位 I/O ---------- */

TEST(v3sb_replica_io_roundtrip)
{
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint8_t *payload = NULL;
    size_t plen = 0;
    uint8_t frame[VERTHYS_V3_SB_REPLICA_BYTES];
    size_t got_len = 0;
    FILE *f;
    unsigned i;

    v3c_cleanup();
    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);
    CHECK(vsb_v3_serialize(&sb, key, &payload, &plen) == VERTHYS_OK);

    f = fopen(V3C_TMP, "wb+");
    CHECK(f != NULL);
    for (i = 0; i < VERTHYS_V3_SB_REPLICA_COUNT; i++) {
        CHECK(vsb_v3_write_replica(f, i, payload, plen) == VERTHYS_OK);
    }
    /* 参数校验 */
    CHECK(vsb_v3_write_replica(NULL, 0, payload, plen) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_write_replica(f, 0, NULL, plen) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_write_replica(f, 0, payload, 0) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_write_replica(f, VERTHYS_V3_SB_REPLICA_COUNT, payload, plen)
          == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_write_replica(f, 0, payload, VERTHYS_V3_SB_REPLICA_BYTES)
          == VERTHYS_ERR_INVALID);

    for (i = 0; i < VERTHYS_V3_SB_REPLICA_COUNT; i++) {
        got_len = 0;
        CHECK(vsb_v3_read_replica(f, i, frame, &got_len) == VERTHYS_OK);
        CHECK(got_len == plen);
        /* 帧载荷解析闭环 */
        CHECK(vsb_v3_parse(frame + V3C_FRAME_HEADER_BYTES, got_len,
                           key, &out) == VERTHYS_OK);
        CHECK(vsb_v3_equals(&sb, &out) == 1);
        /* 16KB 槽位尾部零填充纪律 */
        {
            uint8_t zero[8] = {0};
            CHECK(memcmp(frame + VERTHYS_V3_SB_REPLICA_BYTES - sizeof(zero),
                         zero, sizeof(zero)) == 0);
        }
    }

    CHECK(vsb_v3_read_replica(NULL, 0, frame, &got_len) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_read_replica(f, 0, NULL, &got_len) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_read_replica(f, 0, frame, NULL) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_read_replica(f, VERTHYS_V3_SB_REPLICA_COUNT, frame, &got_len)
          == VERTHYS_ERR_INVALID);

    fclose(f);
    flatcc_builder_aligned_free(payload);
    verthys_secure_zero(key, sizeof(key));
    v3c_cleanup();
    return 0;
}

TEST(v3sb_replica_bad_frame_rejected)
{
    FILE *f;
    uint8_t frame[VERTHYS_V3_SB_REPLICA_BYTES];
    size_t got_len = 0;

    v3c_cleanup();
    f = fopen(V3C_TMP, "wb+");
    CHECK(f != NULL);
    /* 全零槽位：帧头 magic 非法 */
    memset(frame, 0, sizeof(frame));
    CHECK(vio_pwrite64(f, 0, frame, sizeof(frame)) == 0);
    fflush(f);
    CHECK(vsb_v3_read_replica(f, 0, frame, &got_len) == VERTHYS_ERR_FORMAT);

    /* magic 合法但 payload_len 越界（0xFFFF > 16KB-8） */
    frame[0] = 0x56; frame[1] = 0x33; frame[2] = 0x52; frame[3] = 0x50;
    frame[4] = 0xFF; frame[5] = 0xFF; frame[6] = 0x00; frame[7] = 0x00;
    CHECK(vio_pwrite64(f, 0, frame, sizeof(frame)) == 0);
    fflush(f);
    CHECK(vsb_v3_read_replica(f, 0, frame, &got_len) == VERTHYS_ERR_FORMAT);

    /* magic 合法但 payload_len = 0 */
    frame[4] = 0; frame[5] = 0; frame[6] = 0; frame[7] = 0;
    CHECK(vio_pwrite64(f, 0, frame, sizeof(frame)) == 0);
    fflush(f);
    CHECK(vsb_v3_read_replica(f, 0, frame, &got_len) == VERTHYS_ERR_FORMAT);

    /* 槽位越界 */
    CHECK(vsb_v3_read_replica(f, 99, frame, &got_len) == VERTHYS_ERR_INVALID);

    fclose(f);
    v3c_cleanup();
    return 0;
}

/* ---------- 4. 法定人数提交 / 读取 ---------- */

TEST(v3sb_commit_quorum_roundtrip)
{
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint32_t valid_mask = 0;
    FILE *f;

    v3c_cleanup();
    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);
    sb.txid = 7;

    f = fopen(V3C_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(vsb_v3_commit_quorum(f, &sb, key) == VERTHYS_OK);
    /* 提交后内存态 HMAC 已同步 */
    {
        uint8_t zero[VERTHYS_V3_SB_HMAC_BYTES] = {0};
        CHECK(memcmp(sb.superblock_hmac, zero, sizeof(zero)) != 0);
    }
    CHECK(vsb_v3_read_quorum(f, key, &out, &valid_mask) == VERTHYS_OK);
    CHECK(vsb_v3_equals(&sb, &out) == 1);
    CHECK(valid_mask == 0x7u);  /* 3 副本全部有效 */

    CHECK(vsb_v3_commit_quorum(NULL, &sb, key) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_commit_quorum(f, NULL, key) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_read_quorum(NULL, key, &out, &valid_mask) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_read_quorum(f, NULL, &out, &valid_mask) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_read_quorum(f, key, NULL, &valid_mask) == VERTHYS_ERR_INVALID);

    fclose(f);
    verthys_secure_zero(key, sizeof(key));
    v3c_cleanup();
    return 0;
}

TEST(v3sb_quorum_txid_advances)
{
    /* 连续两次提交：txid 递增后读回最新值 */
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    FILE *f;

    v3c_cleanup();
    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);

    f = fopen(V3C_TMP, "wb+");
    CHECK(f != NULL);
    sb.txid = 1;
    CHECK(vsb_v3_commit_quorum(f, &sb, key) == VERTHYS_OK);
    sb.txid = 2;
    sb.updated_at += 1;
    CHECK(vsb_v3_commit_quorum(f, &sb, key) == VERTHYS_OK);
    CHECK(vsb_v3_read_quorum(f, key, &out, NULL) == VERTHYS_OK);
    CHECK(out.txid == 2);

    fclose(f);
    verthys_secure_zero(key, sizeof(key));
    v3c_cleanup();
    return 0;
}

/* ---------- 5. 副本损坏注入矩阵（0/1/2/3 副本损坏） ---------- */

TEST(v3sb_quorum_one_replica_corrupt)
{
    /* 单副本字节翻转：法定人数自动切换到存活副本（验收：自动切换） */
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint32_t valid_mask = 0;
    FILE *f;

    v3c_new_key(key);
    f = v3c_commit_baseline(key, &sb, 7);
    CHECK(f != NULL);
    fclose(f);
    CHECK(v3c_flip_replica_byte(V3C_TMP, 1, 100) == 0);  /* 损坏副本 1 */

    f = fopen(V3C_TMP, "rb");
    CHECK(f != NULL);
    CHECK(vsb_v3_read_quorum(f, key, &out, &valid_mask) == VERTHYS_OK);
    CHECK(out.txid == 7);
    CHECK(vsb_v3_equals(&sb, &out) == 1);
    CHECK(valid_mask == 0x5u);  /* 副本 0/2 存活 */
    fclose(f);

    verthys_secure_zero(key, sizeof(key));
    v3c_cleanup();
    return 0;
}

TEST(v3sb_quorum_two_replicas_corrupt)
{
    /* 双副本损坏：仅 1 有效 → QUORUM_FAILED（降级告警，触发恢复流程） */
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint32_t valid_mask = 0;
    FILE *f;

    v3c_new_key(key);
    f = v3c_commit_baseline(key, &sb, 7);
    CHECK(f != NULL);
    fclose(f);
    CHECK(v3c_flip_replica_byte(V3C_TMP, 0, 100) == 0);
    CHECK(v3c_flip_replica_byte(V3C_TMP, 2, 120) == 0);

    f = fopen(V3C_TMP, "rb");
    CHECK(f != NULL);
    CHECK(vsb_v3_read_quorum(f, key, &out, &valid_mask)
          == VERTHYS_ERR_QUORUM_FAILED);
    CHECK(valid_mask == 0x2u);  /* 仅副本 1 有效 */
    fclose(f);

    verthys_secure_zero(key, sizeof(key));
    v3c_cleanup();
    return 0;
}

TEST(v3sb_quorum_three_replicas_corrupt)
{
    /* 三副本损坏：0 有效 → CORRUPT（WAL 恢复兜底，WP-5） */
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint32_t valid_mask = 0xFF;
    FILE *f;

    v3c_new_key(key);
    f = v3c_commit_baseline(key, &sb, 7);
    CHECK(f != NULL);
    fclose(f);
    CHECK(v3c_flip_replica_byte(V3C_TMP, 0, 100) == 0);
    CHECK(v3c_flip_replica_byte(V3C_TMP, 1, 110) == 0);
    CHECK(v3c_flip_replica_byte(V3C_TMP, 2, 120) == 0);

    f = fopen(V3C_TMP, "rb");
    CHECK(f != NULL);
    CHECK(vsb_v3_read_quorum(f, key, &out, &valid_mask) == VERTHYS_ERR_CORRUPT);
    CHECK(valid_mask == 0u);
    fclose(f);

    verthys_secure_zero(key, sizeof(key));
    v3c_cleanup();
    return 0;
}

TEST(v3sb_quorum_zero_replicas_written)
{
    /* 0 副本损坏等价场景：空文件（无任何有效帧）→ CORRUPT */
    VerthysSuperBlockV3 out;
    uint8_t key[VERTHYS_KEY_BYTES];
    FILE *f;

    v3c_cleanup();
    v3c_new_key(key);
    f = fopen(V3C_TMP, "wb");
    CHECK(f != NULL);
    fclose(f);

    f = fopen(V3C_TMP, "rb");
    CHECK(f != NULL);
    CHECK(vsb_v3_read_quorum(f, key, &out, NULL) == VERTHYS_ERR_CORRUPT);
    fclose(f);

    verthys_secure_zero(key, sizeof(key));
    v3c_cleanup();
    return 0;
}

TEST(v3sb_quorum_valid_but_split)
{
    /* 2 副本有效但 txid 互不一致 + 1 损坏：无 ≥2 一致 → QUORUM_FAILED */
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint8_t *p7 = NULL, *p8 = NULL;
    size_t l7 = 0, l8 = 0;
    FILE *f;

    v3c_cleanup();
    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);

    sb.txid = 7;
    CHECK(vsb_v3_serialize(&sb, key, &p7, &l7) == VERTHYS_OK);
    sb.txid = 8;
    CHECK(vsb_v3_serialize(&sb, key, &p8, &l8) == VERTHYS_OK);

    f = fopen(V3C_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(vsb_v3_write_replica(f, 0, p7, l7) == VERTHYS_OK);
    CHECK(vsb_v3_write_replica(f, 1, p8, l8) == VERTHYS_OK);
    /* 副本 2 留空（无效） */
    CHECK(vsb_v3_read_quorum(f, key, &out, NULL) == VERTHYS_ERR_QUORUM_FAILED);
    fclose(f);

    flatcc_builder_aligned_free(p7);
    flatcc_builder_aligned_free(p8);
    verthys_secure_zero(key, sizeof(key));
    v3c_cleanup();
    return 0;
}

TEST(v3sb_quorum_txid_majority_wins)
{
    /* 多数派语义：2 副本 txid=7、1 副本 txid=42（孤立更高）→ 取 7 */
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    uint8_t *p7 = NULL, *p42 = NULL;
    size_t l7 = 0, l42 = 0;
    FILE *f;

    v3c_cleanup();
    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);

    sb.txid = 7;
    CHECK(vsb_v3_serialize(&sb, key, &p7, &l7) == VERTHYS_OK);
    sb.txid = 42;
    sb.updated_at += 1;
    CHECK(vsb_v3_serialize(&sb, key, &p42, &l42) == VERTHYS_OK);

    f = fopen(V3C_TMP, "wb+");
    CHECK(f != NULL);
    CHECK(vsb_v3_write_replica(f, 0, p7, l7) == VERTHYS_OK);
    CHECK(vsb_v3_write_replica(f, 1, p7, l7) == VERTHYS_OK);
    CHECK(vsb_v3_write_replica(f, 2, p42, l42) == VERTHYS_OK);

    CHECK(vsb_v3_read_quorum(f, key, &out, NULL) == VERTHYS_OK);
    CHECK(out.txid == 7);
    fclose(f);

    flatcc_builder_aligned_free(p7);
    flatcc_builder_aligned_free(p42);
    verthys_secure_zero(key, sizeof(key));
    v3c_cleanup();
    return 0;
}

/* ---------- 6. 写故障注入（fail_mask） ---------- */

TEST(v3sb_commit_fail_injection)
{
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    VerthysResult status[3] = {VERTHYS_OK, VERTHYS_OK, VERTHYS_OK};
    FILE *f;

    v3c_cleanup();
    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);
    sb.txid = 9;

    f = fopen(V3C_TMP, "wb+");
    CHECK(f != NULL);

    /* 单副本写失败（bit0）：≥2 成功 → 提交成功，法定人数维持 */
    CHECK(vsb_v3_commit_quorum_ex(f, &sb, key, 0x1, status) == VERTHYS_OK);
    CHECK(status[0] == VERTHYS_ERR_IO);
    CHECK(status[1] == VERTHYS_OK);
    CHECK(status[2] == VERTHYS_OK);
    /* 读侧：仅副本 1/2 有效仍构成法定人数 */
    {
        uint32_t mask = 0;
        CHECK(vsb_v3_read_quorum(f, key, &out, &mask) == VERTHYS_OK);
        CHECK(out.txid == 9);
        CHECK(mask == 0x6u);
    }

    /* 双副本写失败（bit0|bit1）：法定人数不满足 → IO */
    sb.txid = 10;
    CHECK(vsb_v3_commit_quorum_ex(f, &sb, key, 0x3, status) == VERTHYS_ERR_IO);
    CHECK(status[0] == VERTHYS_ERR_IO);
    CHECK(status[1] == VERTHYS_ERR_IO);
    CHECK(status[2] == VERTHYS_OK);
    /* 三副本写失败：IO */
    sb.txid = 11;
    CHECK(vsb_v3_commit_quorum_ex(f, &sb, key, 0x7, status) == VERTHYS_ERR_IO);

    /*
     * 读侧：双副本失败提交后，有效副本为 {replica1: txid=9, replica2:
     * txid=10}——互不一致、无 ≥2 多数派 → QUORUM_FAILED（恢复流程介入，
     * 严禁静默采纳任一副本：法定人数语义的核心约束）。
     */
    CHECK(vsb_v3_read_quorum(f, key, &out, NULL) == VERTHYS_ERR_QUORUM_FAILED);

    fclose(f);
    verthys_secure_zero(key, sizeof(key));
    v3c_cleanup();
    return 0;
}

/* ---------- 7. VsbTxnV3 事务原语（§10.2） ---------- */

TEST(v3sb_txn_commit_rollback)
{
    VerthysSuperBlockV3 sb, out;
    uint8_t key[VERTHYS_KEY_BYTES];
    VsbTxnV3 txn;
    FILE *f;

    v3c_cleanup();
    v3c_new_key(key);
    CHECK(vsb_v3_init_new(&sb) == VERTHYS_OK);
    v3c_fill(&sb);

    f = fopen(V3C_TMP, "wb+");
    CHECK(f != NULL);

    /* 基线提交 txid=1 */
    sb.txid = 1;
    CHECK(vsb_v3_commit_quorum(f, &sb, key) == VERTHYS_OK);

    /* 事务 1：begin → 修改 → commit */
    CHECK(vsb_txn_v3_begin(&txn, &sb) == VERTHYS_OK);
    sb.txid = 2;
    sb.updated_at += 1;
    CHECK(vsb_txn_v3_commit(&txn, &sb, f, key) == VERTHYS_OK);
    CHECK(txn.committed == 1);
    /* 终态后不可回滚/不可复用 */
    CHECK(vsb_txn_v3_rollback(&txn, &sb) == VERTHYS_ERR_INVALID);
    CHECK(vsb_txn_v3_commit(&txn, &sb, f, key) == VERTHYS_ERR_INVALID);
    CHECK(vsb_v3_read_quorum(f, key, &out, NULL) == VERTHYS_OK);
    CHECK(out.txid == 2);

    /* 事务 2：begin → 修改 → rollback（内存态恢复备份，磁盘保持 txid=2） */
    CHECK(vsb_txn_v3_begin(&txn, &sb) == VERTHYS_OK);
    sb.txid = 3;
    sb.updated_at += 1;
    CHECK(vsb_txn_v3_rollback(&txn, &sb) == VERTHYS_OK);
    CHECK(txn.rolled_back == 1);
    CHECK(sb.txid == 2);  /* 备份恢复 */
    /* 终态后不可提交 */
    CHECK(vsb_txn_v3_commit(&txn, &sb, f, key) == VERTHYS_ERR_INVALID);
    CHECK(vsb_txn_v3_rollback(&txn, &sb) == VERTHYS_ERR_INVALID);
    /* 磁盘未受影响 */
    CHECK(vsb_v3_read_quorum(f, key, &out, NULL) == VERTHYS_OK);
    CHECK(out.txid == 2);

    /* 参数校验 */
    CHECK(vsb_txn_v3_begin(NULL, &sb) == VERTHYS_ERR_INVALID);
    CHECK(vsb_txn_v3_begin(&txn, NULL) == VERTHYS_ERR_INVALID);
    CHECK(vsb_txn_v3_commit(NULL, &sb, f, key) == VERTHYS_ERR_INVALID);
    CHECK(vsb_txn_v3_rollback(NULL, &sb) == VERTHYS_ERR_INVALID);

    fclose(f);
    verthys_secure_zero(key, sizeof(key));
    v3c_cleanup();
    return 0;
}
