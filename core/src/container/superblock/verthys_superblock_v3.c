/*
 * verthys_superblock_v3.c — V3 超级块：flatcc 序列化 + HMAC 认证 +
 * 三副本法定人数提交/读取 + 事务原语 VsbTxnV3
 *
 * 设计依据：docs/TARGET_ARCHITECTURE_V5.md §6.3 / §10.2
 * 落地依据：docs/V3_UPGRADE_PLAYBOOK.md WP-2
 *
 * 复用资产：
 *   - verthys_io.c（vio_pread64/vio_pwrite64 统一 64 位偏移 I/O）
 *   - verthys_crypto.c（verthys_hmac_sha256 / verthys_random_bytes）
 *   - verthys_superblock.c 的 vsb_txn 备份/回滚模式（扩展为 VsbTxnV3）
 *
 * HMAC 自排除模式（红线级）：
 *   序列化时 superblock_hmac 向量以 32 字节零构建 → 对整个 buffer 计算
 *   HMAC → 定长向量原地写回（覆盖不改布局）；校验时保存该 32B → 原地
 *   零化 → 重算 HMAC → 常量时间比较 → 还原。向量长度固定，缓冲布局
 *   在写回前后完全一致。
 */
#include "verthys_container_v3.h"

#include "superblock_v3_builder.h"
#include "superblock_v3_verifier.h"
#include "verthys_io.h"
#include "verthys_crypto.h"
#include "verthys_internal.h"     /* verthys_secure_zero（secure_mem.c 实现声明） */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>     /* _commit / _fileno — 物理落盘 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>  /* 调试诊断（fprintf） */

/* ---------- 内部工具 ---------- */

/* 常量时间字节比较（防时序侧信道；返回 0=相等） */
static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff != 0;
}

/* 副本帧头（8B）：magic + payload_len，小端 */
typedef struct V3ReplicaFrameHeader {
    uint32_t magic;
    uint32_t payload_len;
} V3ReplicaFrameHeader;

#define VERTHYS_V3_REPLICA_FRAME_HEADER_BYTES 8u

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * 定位 buffer 中 superblock_hmac 向量首元素地址（可写）。
 * 前置：buffer 已通过 verifier 结构校验。返回 VERTHYS_OK / FORMAT。
 */
static VerthysResult hmac_field_ptr(uint8_t *buf, size_t len, uint8_t **out)
{
    SuperBlockV3_table_t table = SuperBlockV3_as_root(buf);
    flatbuffers_uint8_vec_t vec;
    (void)len;
    if (table == NULL) return VERTHYS_ERR_FORMAT;
    vec = SuperBlockV3_superblock_hmac(table);
    if (vec == NULL) return VERTHYS_ERR_FORMAT;
    if (flatbuffers_uint8_vec_len(vec) != VERTHYS_V3_SB_HMAC_BYTES) {
        return VERTHYS_ERR_FORMAT;
    }
    *out = (uint8_t *)(uintptr_t)vec;
    return VERTHYS_OK;
}

/* 定长 ubyte 向量读出（长度漂移 → FORMAT，safe_read 纪律） */
static VerthysResult read_u8_vec(flatbuffers_uint8_vec_t vec, size_t expect,
                               uint8_t *out)
{
    if (vec == NULL) return VERTHYS_ERR_FORMAT;
    if (flatbuffers_uint8_vec_len(vec) != expect) return VERTHYS_ERR_FORMAT;
    for (size_t i = 0; i < expect; i++) {
        out[i] = flatbuffers_uint8_vec_at(vec, i);
    }
    return VERTHYS_OK;
}

/* ---------- 初始化 / 比较 ---------- */

VerthysResult vsb_v3_init_new(VerthysSuperBlockV3 *sb)
{
    if (sb == NULL) return VERTHYS_ERR_INVALID;

    FILETIME ft;
    ULARGE_INTEGER now;
    GetSystemTimeAsFileTime(&ft);
    now.LowPart  = ft.dwLowDateTime;
    now.HighPart = ft.dwHighDateTime;

    memset(sb, 0, sizeof(*sb));
    sb->magic   = VERTHYS_V3_SB_MAGIC;
    sb->version = VERTHYS_V3_VERSION;
    verthys_random_bytes(sb->container_id, sizeof(sb->container_id));
    sb->created_at = now.QuadPart;
    sb->updated_at = now.QuadPart;
    sb->txid       = 0;

    /* 分区布局默认值（§6.2） */
    sb->partition_table_offset = VERTHYS_V3_PARTITION_TABLE_OFFSET;
    sb->partition_table_size   = VERTHYS_V3_PARTITION_TABLE_BYTES;
    sb->index_partition_offset = VERTHYS_V3_INDEX_PARTITION_OFFSET;
    sb->index_partition_size   = VERTHYS_V3_DEFAULT_INDEX_PARTITION_BYTES;
    sb->extent_partition_offset = VERTHYS_V3_INDEX_PARTITION_OFFSET +
                                  VERTHYS_V3_DEFAULT_INDEX_PARTITION_BYTES;
    sb->extent_partition_size  = VERTHYS_V3_DEFAULT_EXTENT_PARTITION_BYTES;
    sb->audit_partition_offset = sb->extent_partition_offset +
                                 sb->extent_partition_size;
    sb->audit_partition_size   = VERTHYS_V3_DEFAULT_AUDIT_PARTITION_BYTES;

    /* WAL 状态：头/尾均指向区域起点（空日志） */
    sb->wal_head_offset     = VERTHYS_V3_WAL_REGION_OFFSET;
    sb->wal_tail_offset     = VERTHYS_V3_WAL_REGION_OFFSET;
    sb->wal_committed_txid  = 0;
    return VERTHYS_OK;
}

int vsb_v3_equals(const VerthysSuperBlockV3 *a, const VerthysSuperBlockV3 *b)
{
    if (a == NULL || b == NULL) return 0;
    if (a->magic != b->magic || a->version != b->version) return 0;
    if (a->created_at != b->created_at || a->updated_at != b->updated_at) return 0;
    if (a->txid != b->txid) return 0;
    if (memcmp(a->container_id, b->container_id, VERTHYS_V3_CONTAINER_ID_BYTES) != 0) return 0;
    if (memcmp(a->state_chain, b->state_chain, VERTHYS_V3_STATE_CHAIN_BYTES) != 0) return 0;
    if (a->argon2_mem_kib != b->argon2_mem_kib ||
        a->argon2_iters != b->argon2_iters ||
        a->argon2_parallel != b->argon2_parallel ||
        a->argon2_tier != b->argon2_tier ||
        a->pepper_source != b->pepper_source) return 0;
    if (memcmp(a->salt, b->salt, VERTHYS_V3_SALT_BYTES) != 0) return 0;
    if (memcmp(a->argon2_benchmark_ms, b->argon2_benchmark_ms,
               sizeof(a->argon2_benchmark_ms)) != 0) return 0;
    if (memcmp(a->wrapped_key_a, b->wrapped_key_a, VERTHYS_V3_WRAPPED_KEY_BYTES) != 0 ||
        memcmp(a->wrapped_key_b, b->wrapped_key_b, VERTHYS_V3_WRAPPED_KEY_BYTES) != 0 ||
        memcmp(a->wrapped_key_c, b->wrapped_key_c, VERTHYS_V3_WRAPPED_KEY_BYTES) != 0) return 0;
    if (memcmp(a->key_a_id, b->key_a_id, VERTHYS_V3_KEY_ID_BYTES) != 0 ||
        memcmp(a->key_b_id, b->key_b_id, VERTHYS_V3_KEY_ID_BYTES) != 0 ||
        memcmp(a->key_c_id, b->key_c_id, VERTHYS_V3_KEY_ID_BYTES) != 0) return 0;
    if (a->partition_table_offset != b->partition_table_offset ||
        a->partition_table_size != b->partition_table_size ||
        a->index_partition_offset != b->index_partition_offset ||
        a->index_partition_size != b->index_partition_size ||
        a->extent_partition_offset != b->extent_partition_offset ||
        a->extent_partition_size != b->extent_partition_size ||
        a->audit_partition_offset != b->audit_partition_offset ||
        a->audit_partition_size != b->audit_partition_size) return 0;
    if (a->wal_head_offset != b->wal_head_offset ||
        a->wal_tail_offset != b->wal_tail_offset ||
        a->wal_committed_txid != b->wal_committed_txid) return 0;
    if (memcmp(a->merkle_root, b->merkle_root, VERTHYS_V3_MERKLE_ROOT_BYTES) != 0) return 0;
    /* superblock_hmac 不参与语义比较（序列化侧重算） */
    if (a->extensions_len != b->extensions_len) return 0;
    if (memcmp(a->extensions, b->extensions, a->extensions_len) != 0) return 0;
    return 1;
}

/* ---------- 序列化 / 解析 ---------- */

VerthysResult vsb_v3_serialize(const VerthysSuperBlockV3 *sb,
                             const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                             uint8_t **out_buf, size_t *out_len)
{
    if (sb == NULL || integrity_key == NULL || out_buf == NULL || out_len == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    *out_buf = NULL;
    *out_len = 0;

    if (sb->extensions_len > VERTHYS_V3_EXTENSIONS_MAX) return VERTHYS_ERR_INVALID;

    flatcc_builder_t builder;
    flatbuffers_uint8_vec_ref_t container_id_ref, state_chain_ref, salt_ref;
    flatbuffers_uint8_vec_ref_t bench_ref;
    flatbuffers_uint8_vec_ref_t wka_ref, wkb_ref, wkc_ref;
    flatbuffers_uint8_vec_ref_t kaid_ref, kbid_ref, kcid_ref;
    flatbuffers_uint8_vec_ref_t merkle_ref, hmac_ref, ext_ref;
    uint8_t hmac_zero[VERTHYS_V3_SB_HMAC_BYTES];
    uint8_t *buf = NULL;
    size_t size = 0;
    VerthysResult result = VERTHYS_ERR_INTERNAL;

    memset(hmac_zero, 0, sizeof(hmac_zero));

    if (flatcc_builder_init(&builder) != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    do {
        if (SuperBlockV3_start_as_root(&builder) != 0) break;

        /* 标量字段 */
        if (SuperBlockV3_magic_add(&builder, sb->magic) != 0) break;
        if (SuperBlockV3_version_add(&builder, sb->version) != 0) break;
        if (SuperBlockV3_created_at_add(&builder, sb->created_at) != 0) break;
        if (SuperBlockV3_updated_at_add(&builder, sb->updated_at) != 0) break;
        if (SuperBlockV3_txid_add(&builder, sb->txid) != 0) break;
        if (SuperBlockV3_argon2_mem_kib_add(&builder, sb->argon2_mem_kib) != 0) break;
        if (SuperBlockV3_argon2_iters_add(&builder, sb->argon2_iters) != 0) break;
        if (SuperBlockV3_argon2_parallel_add(&builder, sb->argon2_parallel) != 0) break;
        if (SuperBlockV3_argon2_tier_add(&builder, sb->argon2_tier) != 0) break;
        if (SuperBlockV3_pepper_source_add(&builder, sb->pepper_source) != 0) break;

        /* 分区布局 */
        if (SuperBlockV3_partition_table_offset_add(&builder, sb->partition_table_offset) != 0) break;
        if (SuperBlockV3_partition_table_size_add(&builder, sb->partition_table_size) != 0) break;
        if (SuperBlockV3_index_partition_offset_add(&builder, sb->index_partition_offset) != 0) break;
        if (SuperBlockV3_index_partition_size_add(&builder, sb->index_partition_size) != 0) break;
        if (SuperBlockV3_extent_partition_offset_add(&builder, sb->extent_partition_offset) != 0) break;
        if (SuperBlockV3_extent_partition_size_add(&builder, sb->extent_partition_size) != 0) break;
        if (SuperBlockV3_audit_partition_offset_add(&builder, sb->audit_partition_offset) != 0) break;
        if (SuperBlockV3_audit_partition_size_add(&builder, sb->audit_partition_size) != 0) break;

        /* WAL 状态 */
        if (SuperBlockV3_wal_head_offset_add(&builder, sb->wal_head_offset) != 0) break;
        if (SuperBlockV3_wal_tail_offset_add(&builder, sb->wal_tail_offset) != 0) break;
        if (SuperBlockV3_wal_committed_txid_add(&builder, sb->wal_committed_txid) != 0) break;

        /* 向量字段 */
        container_id_ref = flatbuffers_uint8_vec_create(&builder,
                                sb->container_id, VERTHYS_V3_CONTAINER_ID_BYTES);
        state_chain_ref  = flatbuffers_uint8_vec_create(&builder,
                                sb->state_chain, VERTHYS_V3_STATE_CHAIN_BYTES);
        salt_ref         = flatbuffers_uint8_vec_create(&builder,
                                sb->salt, VERTHYS_V3_SALT_BYTES);
        bench_ref        = flatbuffers_uint32_vec_create(&builder,
                                sb->argon2_benchmark_ms, VERTHYS_V3_BENCHMARK_ITEMS);
        wka_ref = flatbuffers_uint8_vec_create(&builder, sb->wrapped_key_a, VERTHYS_V3_WRAPPED_KEY_BYTES);
        wkb_ref = flatbuffers_uint8_vec_create(&builder, sb->wrapped_key_b, VERTHYS_V3_WRAPPED_KEY_BYTES);
        wkc_ref = flatbuffers_uint8_vec_create(&builder, sb->wrapped_key_c, VERTHYS_V3_WRAPPED_KEY_BYTES);
        kaid_ref = flatbuffers_uint8_vec_create(&builder, sb->key_a_id, VERTHYS_V3_KEY_ID_BYTES);
        kbid_ref = flatbuffers_uint8_vec_create(&builder, sb->key_b_id, VERTHYS_V3_KEY_ID_BYTES);
        kcid_ref = flatbuffers_uint8_vec_create(&builder, sb->key_c_id, VERTHYS_V3_KEY_ID_BYTES);
        merkle_ref = flatbuffers_uint8_vec_create(&builder, sb->merkle_root, VERTHYS_V3_MERKLE_ROOT_BYTES);
        hmac_ref   = flatbuffers_uint8_vec_create(&builder, hmac_zero, VERTHYS_V3_SB_HMAC_BYTES);
        ext_ref    = flatbuffers_uint8_vec_create(&builder,
                                sb->extensions, sb->extensions_len);
        if (container_id_ref == 0 || state_chain_ref == 0 || salt_ref == 0 ||
            bench_ref == 0 || wka_ref == 0 || wkb_ref == 0 || wkc_ref == 0 ||
            kaid_ref == 0 || kbid_ref == 0 || kcid_ref == 0 ||
            merkle_ref == 0 || hmac_ref == 0 ||
            (sb->extensions_len > 0 && ext_ref == 0)) break;

        if (SuperBlockV3_container_id_add(&builder, container_id_ref) != 0) break;
        if (SuperBlockV3_state_chain_add(&builder, state_chain_ref) != 0) break;
        if (SuperBlockV3_salt_add(&builder, salt_ref) != 0) break;
        if (SuperBlockV3_argon2_benchmark_ms_add(&builder, bench_ref) != 0) break;
        if (SuperBlockV3_wrapped_key_a_add(&builder, wka_ref) != 0) break;
        if (SuperBlockV3_wrapped_key_b_add(&builder, wkb_ref) != 0) break;
        if (SuperBlockV3_wrapped_key_c_add(&builder, wkc_ref) != 0) break;
        if (SuperBlockV3_key_a_id_add(&builder, kaid_ref) != 0) break;
        if (SuperBlockV3_key_b_id_add(&builder, kbid_ref) != 0) break;
        if (SuperBlockV3_key_c_id_add(&builder, kcid_ref) != 0) break;
        if (SuperBlockV3_merkle_root_add(&builder, merkle_ref) != 0) break;
        if (SuperBlockV3_superblock_hmac_add(&builder, hmac_ref) != 0) break;
        if (sb->extensions_len > 0 &&
            SuperBlockV3_extensions_add(&builder, ext_ref) != 0) break;

        if (SuperBlockV3_end_as_root(&builder) == 0) break;

        buf = flatcc_builder_finalize_aligned_buffer(&builder, &size);
        if (buf == NULL || size == 0) break;

        /* 载荷须装入副本槽位（帧头 8B + 载荷 ≤ 16KB） */
        if (size > VERTHYS_V3_SB_REPLICA_BYTES - VERTHYS_V3_REPLICA_FRAME_HEADER_BYTES) {
            result = VERTHYS_ERR_INVALID;
            break;
        }

        /* HMAC 自排除：对全零 hmac 字段计算 → 原地写回 */
        {
            uint8_t *hmac_vec = NULL;
            uint8_t mac[VERTHYS_HMAC_BYTES];
            if (hmac_field_ptr(buf, size, &hmac_vec) != VERTHYS_OK) break;
            if (verthys_hmac_sha256(mac, integrity_key, buf, size) != 0) break;
            memcpy(hmac_vec, mac, VERTHYS_V3_SB_HMAC_BYTES);
            verthys_secure_zero(mac, sizeof(mac));
        }

        *out_buf = buf;
        *out_len = size;
        result = VERTHYS_OK;
    } while (0);

    flatcc_builder_clear(&builder);
    if (result != VERTHYS_OK && buf != NULL) {
        flatcc_builder_aligned_free(buf);
    }
    return result;
}

/* 内部：逐字段读入（verifier 已通过前提；向量长度漂移 → FORMAT） */
static VerthysResult vsb_v3_read_fields(uint8_t *buf, size_t len,
                                      VerthysSuperBlockV3 *out)
{
    (void)len;
    {
        SuperBlockV3_table_t table = SuperBlockV3_as_root(buf);
        if (table == NULL) return VERTHYS_ERR_FORMAT;

        out->magic   = SuperBlockV3_magic(table);
        out->version = SuperBlockV3_version(table);
        out->created_at = SuperBlockV3_created_at(table);
        out->updated_at = SuperBlockV3_updated_at(table);
        out->txid       = SuperBlockV3_txid(table);
        out->argon2_mem_kib    = SuperBlockV3_argon2_mem_kib(table);
        out->argon2_iters      = SuperBlockV3_argon2_iters(table);
        out->argon2_parallel   = SuperBlockV3_argon2_parallel(table);
        out->argon2_tier       = SuperBlockV3_argon2_tier(table);
        out->pepper_source     = SuperBlockV3_pepper_source(table);
        out->partition_table_offset = SuperBlockV3_partition_table_offset(table);
        out->partition_table_size   = SuperBlockV3_partition_table_size(table);
        out->index_partition_offset = SuperBlockV3_index_partition_offset(table);
        out->index_partition_size   = SuperBlockV3_index_partition_size(table);
        out->extent_partition_offset = SuperBlockV3_extent_partition_offset(table);
        out->extent_partition_size   = SuperBlockV3_extent_partition_size(table);
        out->audit_partition_offset  = SuperBlockV3_audit_partition_offset(table);
        out->audit_partition_size    = SuperBlockV3_audit_partition_size(table);
        out->wal_head_offset     = SuperBlockV3_wal_head_offset(table);
        out->wal_tail_offset     = SuperBlockV3_wal_tail_offset(table);
        out->wal_committed_txid  = SuperBlockV3_wal_committed_txid(table);

        VerthysResult r;
        if ((r = read_u8_vec(SuperBlockV3_container_id(table),
                             VERTHYS_V3_CONTAINER_ID_BYTES,
                             out->container_id)) != VERTHYS_OK) return r;
        if ((r = read_u8_vec(SuperBlockV3_state_chain(table),
                             VERTHYS_V3_STATE_CHAIN_BYTES,
                             out->state_chain)) != VERTHYS_OK) return r;
        if ((r = read_u8_vec(SuperBlockV3_salt(table),
                             VERTHYS_V3_SALT_BYTES, out->salt)) != VERTHYS_OK) return r;
        if ((r = read_u8_vec(SuperBlockV3_wrapped_key_a(table),
                             VERTHYS_V3_WRAPPED_KEY_BYTES,
                             out->wrapped_key_a)) != VERTHYS_OK) return r;
        if ((r = read_u8_vec(SuperBlockV3_wrapped_key_b(table),
                             VERTHYS_V3_WRAPPED_KEY_BYTES,
                             out->wrapped_key_b)) != VERTHYS_OK) return r;
        if ((r = read_u8_vec(SuperBlockV3_wrapped_key_c(table),
                             VERTHYS_V3_WRAPPED_KEY_BYTES,
                             out->wrapped_key_c)) != VERTHYS_OK) return r;
        if ((r = read_u8_vec(SuperBlockV3_key_a_id(table),
                             VERTHYS_V3_KEY_ID_BYTES, out->key_a_id)) != VERTHYS_OK) return r;
        if ((r = read_u8_vec(SuperBlockV3_key_b_id(table),
                             VERTHYS_V3_KEY_ID_BYTES, out->key_b_id)) != VERTHYS_OK) return r;
        if ((r = read_u8_vec(SuperBlockV3_key_c_id(table),
                             VERTHYS_V3_KEY_ID_BYTES, out->key_c_id)) != VERTHYS_OK) return r;
        if ((r = read_u8_vec(SuperBlockV3_merkle_root(table),
                             VERTHYS_V3_MERKLE_ROOT_BYTES,
                             out->merkle_root)) != VERTHYS_OK) return r;

        /* 基准向量：长度必须恰为 4 项 */
        {
            flatbuffers_uint32_vec_t bench = SuperBlockV3_argon2_benchmark_ms(table);
            if (bench == NULL ||
                flatbuffers_uint32_vec_len(bench) != VERTHYS_V3_BENCHMARK_ITEMS) {
                return VERTHYS_ERR_FORMAT;
            }
            for (size_t i = 0; i < VERTHYS_V3_BENCHMARK_ITEMS; i++) {
                out->argon2_benchmark_ms[i] = flatbuffers_uint32_vec_at(bench, i);
            }
        }

        /* 扩展区：长度受内存态容量约束 */
        {
            flatbuffers_uint8_vec_t ext = SuperBlockV3_extensions(table);
            size_t ext_len = (ext == NULL) ? 0 : flatbuffers_uint8_vec_len(ext);
            if (ext_len > VERTHYS_V3_EXTENSIONS_MAX) return VERTHYS_ERR_FORMAT;
            out->extensions_len = (uint32_t)ext_len;
            if (ext_len > 0) {
                for (size_t i = 0; i < ext_len; i++) {
                    out->extensions[i] = flatbuffers_uint8_vec_at(ext, i);
                }
            }
        }

        /* 语义校验：魔数与版本 */
        if (out->magic != VERTHYS_V3_SB_MAGIC || out->version != VERTHYS_V3_VERSION) {
            return VERTHYS_ERR_FORMAT;
        }
    }
    return VERTHYS_OK;
}

/*
 * ★ WP-5（UNLOCK_OPTIMIZATION §8 S1）：结构化无校验解析。
 * 仅执行 verifier 结构校验 + 逐字段读入，跳过 HMAC 验证。
 * 用途：解锁流水线 S1 阶段提取 salt / Argon2id 参数 / container_id /
 * wrapped 密钥——此时 integrity_key 尚未派生（依赖 S2 Argon2id）。
 * 安全边界：本函数产物仅作为派生输入候选；篡改的 salt/参数会导致
 * 错误 MEK → S3 密钥导入认证失败（VERTHYS_ERR_AUTH）或 S4 法定人数
 * HMAC 验证失败，最终仍被拒绝（认证闭环不被绕过）。
 * ★ WP-10（模糊测试）：失败路径静默（返回码承载语义）——S1 调用方
 * （verthys_unlock_pipeline）已带完整上下文记录失败（plen + 帧头 16B
 * 样本）；叶子层去重后本函数成为 fuzz_superblock 的纯边界入口，
 * 每迭代一次 fprintf 的诊断输出会吞掉模糊测试吞吐（10 分钟级运行）。
 */
VerthysResult vsb_v3_parse_unverified(uint8_t *buf, size_t len,
                                    VerthysSuperBlockV3 *out)
{
    if (buf == NULL || out == NULL || len == 0) {
        return VERTHYS_ERR_INVALID;
    }
    memset(out, 0, sizeof(*out));

    if (SuperBlockV3_verify_as_root(buf, len) != flatcc_verify_ok) {
        return VERTHYS_ERR_FORMAT;
    }
    return vsb_v3_read_fields(buf, len, out);
}

VerthysResult vsb_v3_parse(uint8_t *buf, size_t len,
                         const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                         VerthysSuperBlockV3 *out)
{
    if (buf == NULL || integrity_key == NULL || out == NULL || len == 0) {
        return VERTHYS_ERR_INVALID;
    }
    memset(out, 0, sizeof(*out));

    /* 1. verifier 结构校验（根偏移越界/截断/垃圾全拒绝） */
    if (SuperBlockV3_verify_as_root(buf, len) != flatcc_verify_ok) {
        return VERTHYS_ERR_FORMAT;
    }

    /* 2. HMAC 自排除验证：保存 → 零化 → 重算 → 常量时间比较 → 还原 */
    {
        uint8_t *hmac_vec = NULL;
        uint8_t saved[VERTHYS_V3_SB_HMAC_BYTES];
        uint8_t mac[VERTHYS_HMAC_BYTES];
        VerthysResult hr = hmac_field_ptr(buf, len, &hmac_vec);
        if (hr != VERTHYS_OK) return hr;

        memcpy(saved, hmac_vec, VERTHYS_V3_SB_HMAC_BYTES);
        memset(hmac_vec, 0, VERTHYS_V3_SB_HMAC_BYTES);
        int hmac_rc = verthys_hmac_sha256(mac, integrity_key, buf, len);
        if (hmac_rc != 0) {
            memcpy(hmac_vec, saved, VERTHYS_V3_SB_HMAC_BYTES);
            verthys_secure_zero(saved, sizeof(saved));
            return VERTHYS_ERR_INTERNAL;
        }
        int mismatch = ct_memcmp(mac, saved, VERTHYS_HMAC_BYTES);
        memcpy(hmac_vec, saved, VERTHYS_V3_SB_HMAC_BYTES);  /* 还原（幂等校验） */
        memcpy(out->superblock_hmac, saved, VERTHYS_V3_SB_HMAC_BYTES);
        verthys_secure_zero(saved, sizeof(saved));
        verthys_secure_zero(mac, sizeof(mac));
        if (mismatch) return VERTHYS_ERR_AUTH;
    }

    /* 3. 逐字段读入（向量长度漂移 → FORMAT） */
    return vsb_v3_read_fields(buf, len, out);
}

/* ---------- 副本 I/O ---------- */

VerthysResult vsb_v3_write_replica(FILE *f, unsigned replica_idx,
                                 const uint8_t *payload, size_t payload_len)
{
    if (f == NULL || payload == NULL || payload_len == 0) return VERTHYS_ERR_INVALID;
    if (replica_idx >= VERTHYS_V3_SB_REPLICA_COUNT) return VERTHYS_ERR_INVALID;
    if (payload_len > VERTHYS_V3_SB_REPLICA_BYTES - VERTHYS_V3_REPLICA_FRAME_HEADER_BYTES) {
        return VERTHYS_ERR_INVALID;
    }

    uint8_t frame[VERTHYS_V3_SB_REPLICA_BYTES];
    put_u32le(frame, VERTHYS_V3_REPLICA_FRAME_MAGIC);
    put_u32le(frame + 4, (uint32_t)payload_len);
    memcpy(frame + VERTHYS_V3_REPLICA_FRAME_HEADER_BYTES, payload, payload_len);
    memset(frame + VERTHYS_V3_REPLICA_FRAME_HEADER_BYTES + payload_len, 0,
           sizeof(frame) - VERTHYS_V3_REPLICA_FRAME_HEADER_BYTES - payload_len);

    if (vio_pwrite64(f, vsb_v3_replica_offset(replica_idx),
                     frame, sizeof(frame)) != 0) {
        return VERTHYS_ERR_IO;
    }
    /* fsync 语义：用户态刷新 + 物理落盘（§6.3 提交步骤） */
    if (fflush(f) != 0) return VERTHYS_ERR_IO;
    if (_commit(_fileno(f)) != 0) return VERTHYS_ERR_IO;
    return VERTHYS_OK;
}

VerthysResult vsb_v3_read_replica(FILE *f, unsigned replica_idx,
                                uint8_t *out_frame, size_t *out_payload_len)
{
    if (f == NULL || out_frame == NULL || out_payload_len == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (replica_idx >= VERTHYS_V3_SB_REPLICA_COUNT) return VERTHYS_ERR_INVALID;

    if (vio_pread64(f, vsb_v3_replica_offset(replica_idx),
                    out_frame, VERTHYS_V3_SB_REPLICA_BYTES) != 0) {
        return VERTHYS_ERR_FORMAT;  /* 槽位缺失/短读 */
    }
    if (get_u32le(out_frame) != VERTHYS_V3_REPLICA_FRAME_MAGIC) {
        return VERTHYS_ERR_FORMAT;
    }
    uint32_t plen = get_u32le(out_frame + 4);
    if (plen == 0 ||
        plen > VERTHYS_V3_SB_REPLICA_BYTES - VERTHYS_V3_REPLICA_FRAME_HEADER_BYTES) {
        return VERTHYS_ERR_FORMAT;
    }
    *out_payload_len = plen;
    return VERTHYS_OK;
}

/* ---------- 法定人数提交 / 读取 ---------- */

VerthysResult vsb_v3_commit_quorum_ex(FILE *f, VerthysSuperBlockV3 *sb,
                                    const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                                    uint32_t fail_mask,
                                    VerthysResult replica_status_out[3])
{
    if (f == NULL || sb == NULL || integrity_key == NULL) {
        return VERTHYS_ERR_INVALID;
    }

    /* 1. 序列化超级块到临时缓冲（含 HMAC 原地写回） */
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    VerthysResult r = vsb_v3_serialize(sb, integrity_key, &payload, &payload_len);
    if (r != VERTHYS_OK) return r;

    /* 同步内存态 HMAC（可观测性） */
    {
        uint8_t *hmac_vec = NULL;
        if (hmac_field_ptr(payload, payload_len, &hmac_vec) == VERTHYS_OK) {
            memcpy(sb->superblock_hmac, hmac_vec, VERTHYS_V3_SB_HMAC_BYTES);
        }
    }

    /* 2. 三副本逐一写入 + fsync */
    unsigned ok_count = 0;
    for (unsigned i = 0; i < VERTHYS_V3_SB_REPLICA_COUNT; i++) {
        VerthysResult st;
        if ((fail_mask >> i) & 1u) {
            st = VERTHYS_ERR_IO;  /* 故障注入：模拟该副本写失败 */
        } else {
            st = vsb_v3_write_replica(f, i, payload, payload_len);
        }
        if (replica_status_out != NULL) replica_status_out[i] = st;
        if (st == VERTHYS_OK) ok_count++;
    }
    flatcc_builder_aligned_free(payload);

    if (ok_count < 2) {
        return VERTHYS_ERR_IO;  /* 法定人数不满足：提交失败 */
    }

    /* 3. 验证读取：≥2 副本 HMAC 通过（§6.3 步骤 7） */
    {
        VERTHYS_V3_FLATBUF_ALIGN uint8_t frame[VERTHYS_V3_SB_REPLICA_BYTES];
        unsigned verify_ok = 0;
        for (unsigned i = 0; i < VERTHYS_V3_SB_REPLICA_COUNT; i++) {
            size_t plen = 0;
            if (vsb_v3_read_replica(f, i, frame, &plen) != VERTHYS_OK) continue;
            VerthysSuperBlockV3 tmp;
            if (vsb_v3_parse(frame + VERTHYS_V3_REPLICA_FRAME_HEADER_BYTES,
                             plen, integrity_key, &tmp) == VERTHYS_OK) {
                verify_ok++;
            }
        }
        if (verify_ok < 2) return VERTHYS_ERR_IO;
    }
    return VERTHYS_OK;
}

VerthysResult vsb_v3_commit_quorum(FILE *f, VerthysSuperBlockV3 *sb,
                                 const uint8_t integrity_key[VERTHYS_KEY_BYTES])
{
    return vsb_v3_commit_quorum_ex(f, sb, integrity_key, 0, NULL);
}

VerthysResult vsb_v3_read_quorum(FILE *f,
                               const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                               VerthysSuperBlockV3 *out,
                               uint32_t *valid_mask_out)
{
    if (f == NULL || integrity_key == NULL || out == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (valid_mask_out != NULL) *valid_mask_out = 0;

    VERTHYS_V3_FLATBUF_ALIGN uint8_t frame[VERTHYS_V3_SB_REPLICA_BYTES];
    VerthysSuperBlockV3 parsed[VERTHYS_V3_SB_REPLICA_COUNT];
    int valid[VERTHYS_V3_SB_REPLICA_COUNT] = {0, 0, 0};
    unsigned valid_count = 0;

    /* 1. 依次读取 3 副本，逐一 HMAC + verifier 验证 */
    for (unsigned i = 0; i < VERTHYS_V3_SB_REPLICA_COUNT; i++) {
        size_t plen = 0;
        if (vsb_v3_read_replica(f, i, frame, &plen) != VERTHYS_OK) continue;
        if (vsb_v3_parse(frame + VERTHYS_V3_REPLICA_FRAME_HEADER_BYTES,
                         plen, integrity_key, &parsed[i]) == VERTHYS_OK) {
            valid[i] = 1;
            valid_count++;
            if (valid_mask_out != NULL) *valid_mask_out |= (1u << i);
        }
    }

    if (valid_count == 0) return VERTHYS_ERR_CORRUPT;

    /* 2. txid 分组：取 ≥2 一致中的最高 txid */
    {
        int chosen = -1;
        uint64_t chosen_txid = 0;
        for (unsigned i = 0; i < VERTHYS_V3_SB_REPLICA_COUNT; i++) {
            if (!valid[i]) continue;
            unsigned agree = 0;
            for (unsigned j = 0; j < VERTHYS_V3_SB_REPLICA_COUNT; j++) {
                if (valid[j] && parsed[j].txid == parsed[i].txid) agree++;
            }
            if (agree >= 2 && (chosen < 0 || parsed[i].txid > chosen_txid)) {
                chosen = (int)i;
                chosen_txid = parsed[i].txid;
            }
        }

        if (chosen < 0) {
            /* 有效副本不足法定人数（恰 1 有效或互不一致）→ 恢复流程 */
            return VERTHYS_ERR_QUORUM_FAILED;
        }
        *out = parsed[chosen];
    }
    return VERTHYS_OK;
}

/* ---------- VsbTxnV3 事务原语（§10.2） ---------- */

VerthysResult vsb_txn_v3_begin(VsbTxnV3 *txn, const VerthysSuperBlockV3 *sb)
{
    if (txn == NULL || sb == NULL) return VERTHYS_ERR_INVALID;
    memset(txn, 0, sizeof(*txn));
    txn->backup = *sb;
    memcpy(txn->backup_hmac, sb->superblock_hmac, VERTHYS_V3_SB_HMAC_BYTES);
    return VERTHYS_OK;
}

VerthysResult vsb_txn_v3_commit(VsbTxnV3 *txn, VerthysSuperBlockV3 *sb,
                              FILE *f,
                              const uint8_t integrity_key[VERTHYS_KEY_BYTES])
{
    if (txn == NULL || sb == NULL || f == NULL || integrity_key == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (txn->committed || txn->rolled_back) return VERTHYS_ERR_INVALID;

    VerthysResult r = vsb_v3_commit_quorum_ex(f, sb, integrity_key, 0,
                                            txn->replica_status);
    if (r != VERTHYS_OK) return r;
    txn->committed = 1;
    return VERTHYS_OK;
}

VerthysResult vsb_txn_v3_rollback(VsbTxnV3 *txn, VerthysSuperBlockV3 *sb)
{
    if (txn == NULL || sb == NULL) return VERTHYS_ERR_INVALID;
    if (txn->committed || txn->rolled_back) return VERTHYS_ERR_INVALID;

    *sb = txn->backup;
    memcpy(sb->superblock_hmac, txn->backup_hmac, VERTHYS_V3_SB_HMAC_BYTES);
    txn->rolled_back = 1;
    return VERTHYS_OK;
}
