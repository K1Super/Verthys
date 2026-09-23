/*
 * verthys_container_v3.h — V3 容器格式：常量布局 + 超级块内存态 + 事务原语
 *
 * 文件布局：
 *   [0x00000 .. 0x10000)   超级块区（3 副本 × 16KB + 16KB 预留）
 *   [0x10000 .. 0x100000)  WAL 预写日志（环形，480KB 活跃 + 480KB 备份）
 *   [0x100000 .. 0x400000) 分区表（FlatBuffers + AEAD）
 *   [0x400000 .. N)        索引分区（LSM）
 *   [N .. M)               Extent 分区（内容寻址）
 *   [M .. 文件尾)           审计日志 + 尾部摘要
 *
 * 副本区帧布局（每 16KB 槽位）：
 *   [u32 frame_magic 'V3RP'][u32 payload_len][flatbuffer][零填充至 16KB]
 *
 * 认证语义（红线级）：
 *   - superblock_hmac = HMAC-SHA256(integrity_key, 序列化 buffer)，
 *     计算与校验时该字段向量被原地零化（MAC 自排除标准模式）；
 *   - 解析全程 safe_read 纪律：flatcc verifier 结构校验 + 向量长度
 *     逐项严格校验（拒绝长度漂移），杜绝手写边界错误。
 *
 * 法定人数语义：
 *   - 写：3 副本逐一写入 + fsync（_commit），≥2 成功 = 提交成功；
 *   - 读：3 副本逐一 HMAC 验证，取 txid 最高且 ≥2 副本一致者；
 *     仅 1 有效 → VERTHYS_ERR_QUORUM_FAILED（触发恢复）；
 *     0 有效 → VERTHYS_ERR_CORRUPT（WAL 恢复兜底）。
 */
#ifndef VERTHYS_CONTAINER_V3_H
#define VERTHYS_CONTAINER_V3_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "verthys.h"
#include "verthys_crypto.h"   /* VERTHYS_KEY_BYTES / VERTHYS_HMAC_BYTES */

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- V3 布局常量 ---------- */

#define VERTHYS_V3_SB_MAGIC               UINT32_C(0x42533356) /* 'V3SB' */
#define VERTHYS_V3_VERSION                3u
#define VERTHYS_V3_REPLICA_FRAME_MAGIC    UINT32_C(0x50523356) /* 'V3RP' */

#define VERTHYS_V3_CONTAINER_ID_BYTES     32u
#define VERTHYS_V3_STATE_CHAIN_BYTES      32u
#define VERTHYS_V3_SALT_BYTES             16u
#define VERTHYS_V3_BENCHMARK_ITEMS        4u
/* wrapped 布局统一为 CNG 内核态包装格式（keymanager_cng）：
 * [12B nonce || 32B 密文 || 16B tag] = 60B（与 VERTHYS_CNG_WRAPPED_BYTES
 * 一致；nonce 必须随密文持久化，import_batch 解包与 wrap_key 互逆）。 */
#define VERTHYS_V3_WRAPPED_KEY_BYTES      60u
#define VERTHYS_V3_KEY_ID_BYTES           16u
#define VERTHYS_V3_MERKLE_ROOT_BYTES      32u
#define VERTHYS_V3_SB_HMAC_BYTES          32u
#define VERTHYS_V3_EXTENSIONS_MAX         256u  /* TLV 扩展区容量（内存态） */

#define VERTHYS_V3_SB_REPLICA_COUNT       3u
#define VERTHYS_V3_SB_REPLICA_BYTES       (16u * 1024u)
#define VERTHYS_V3_SB_REPLICA0_OFFSET     UINT64_C(0x0000)
#define VERTHYS_V3_SB_REPLICA1_OFFSET     UINT64_C(0x4000)
#define VERTHYS_V3_SB_REPLICA2_OFFSET     UINT64_C(0x8000)
#define VERTHYS_V3_SB_RESERVED_OFFSET     UINT64_C(0xC000)  /* 预留 */
#define VERTHYS_V3_SB_REGION_END          UINT64_C(0x10000) /* 64KB */

/*
 * 对齐红线（flatcc verifier 物理地址对齐）：verifier 的字段校验基于
 * 缓冲区绝对地址（verify_field: k = buf + table + vte，k & (align-1)），
 * u64 标量字段要求 8 字节物理对齐。因此所有承载 FlatBuffers 载荷、
 * 传入 *_verify_as_root / vsb_v3_parse* 的缓冲区，其载荷起点
 * （帧头 8B 之后）必须 8 字节对齐 —— 即帧缓冲数组本身须 8 对齐。
 * 结构体内嵌数组（如解锁流水线 frames）的成员偏移不受自然对齐保证
 * （uint8_t 数组按 1 对齐），必须显式声明。违反表现为 verifier 报
 * "table field not aligned"（FORMAT），数据本身无损坏。
 */
#if defined(_MSC_VER)
#define VERTHYS_V3_FLATBUF_ALIGN  __declspec(align(8))
#else
#define VERTHYS_V3_FLATBUF_ALIGN  _Alignas(8)
#endif

/* 副本槽位偏移（idx ∈ [0,3)） */
static inline uint64_t vsb_v3_replica_offset(unsigned idx)
{
    return (uint64_t)idx * 0x4000u;
}

/* WAL 区（[0x10000, 0x100000) = 960KB，双 480KB 半区）。
 * 区域容量由布局边界推导（单一事实源，防漂移红线）：原设计描述
 * "512KB 活跃 + 512KB 备份"与其自身边界 [64KB,1MB)=960KB 矛盾
 * （64KB + 1MB 越界至 1MB+64KB，verthys_wal_reset 整区清零将覆写
 * 分区表区首帧——api_full_roundtrip 解锁 S4 magic=0 回归根因）；
 * 分区表 1MB 偏移为跨区引用的承重常量，以结构边界为准。 */
#define VERTHYS_V3_WAL_REGION_OFFSET      UINT64_C(0x10000)  /* 64KB */
#define VERTHYS_V3_WAL_REGION_END         UINT64_C(0x100000) /* 1MB */
#define VERTHYS_V3_WAL_REGION_BYTES       (VERTHYS_V3_WAL_REGION_END - \
                                         VERTHYS_V3_WAL_REGION_OFFSET)  /* 960KB */

/* 分区表区（1MB 起，3MB 容量，至 4MB） */
#define VERTHYS_V3_PARTITION_TABLE_OFFSET UINT64_C(0x100000) /* 1MB */
#define VERTHYS_V3_PARTITION_TABLE_BYTES  (3u * 1024u * 1024u)
#define VERTHYS_V3_PARTITION_TABLE_END    UINT64_C(0x400000) /* 4MB */

/* 索引分区默认起点/容量（Extent/审计分区偏移由分区表动态登记）。
 * 容量推导（verthys_lsm.h 内部布局硬约束，open 前置校验）：
 *   Manifest 帧区 1MB + LSM WAL 区 68MB（≥ MemTable 64MB 上限 + 帧开销）
 *   + SSTable 数据区 ≥ 91MB（覆盖最坏 64MB 单次 flush + compaction
 *   合并期新旧表并存的重叠空间）→ 160MB。 */
#define VERTHYS_V3_INDEX_PARTITION_OFFSET UINT64_C(0x400000) /* 4MB */
#define VERTHYS_V3_DEFAULT_INDEX_PARTITION_BYTES   (160u * 1024u * 1024u)
#define VERTHYS_V3_DEFAULT_EXTENT_PARTITION_BYTES  (16u * 1024u * 1024u)
#define VERTHYS_V3_DEFAULT_AUDIT_PARTITION_BYTES   (1u * 1024u * 1024u)

/* ---------- 超级块内存态（字段逐项） ---------- */

typedef struct VerthysSuperBlockV3 {
    uint32_t magic;
    uint16_t version;
    uint8_t  container_id[VERTHYS_V3_CONTAINER_ID_BYTES];
    uint64_t created_at;      /* FILETIME */
    uint64_t updated_at;
    uint64_t txid;            /* 单调递增 */
    uint8_t  state_chain[VERTHYS_V3_STATE_CHAIN_BYTES];

    /* Argon2id 参数 */
    uint32_t argon2_mem_kib;
    uint32_t argon2_iters;
    uint32_t argon2_parallel;
    uint8_t  salt[VERTHYS_V3_SALT_BYTES];
    uint32_t argon2_benchmark_ms[VERTHYS_V3_BENCHMARK_ITEMS];
    uint32_t argon2_tier;
    uint8_t  pepper_source;

    /* 密钥包装（MEK 内核态加密产物） */
    uint8_t  wrapped_key_a[VERTHYS_V3_WRAPPED_KEY_BYTES];
    uint8_t  wrapped_key_b[VERTHYS_V3_WRAPPED_KEY_BYTES];
    uint8_t  wrapped_key_c[VERTHYS_V3_WRAPPED_KEY_BYTES];
    uint8_t  key_a_id[VERTHYS_V3_KEY_ID_BYTES];
    uint8_t  key_b_id[VERTHYS_V3_KEY_ID_BYTES];
    uint8_t  key_c_id[VERTHYS_V3_KEY_ID_BYTES];

    /* 分区布局 */
    uint64_t partition_table_offset;
    uint64_t partition_table_size;
    uint64_t index_partition_offset;
    uint64_t index_partition_size;
    uint64_t extent_partition_offset;
    uint64_t extent_partition_size;
    uint64_t audit_partition_offset;
    uint64_t audit_partition_size;

    /* WAL 状态 */
    uint64_t wal_head_offset;
    uint64_t wal_tail_offset;
    uint64_t wal_committed_txid;

    /* 完整性 */
    uint8_t  merkle_root[VERTHYS_V3_MERKLE_ROOT_BYTES];
    uint8_t  superblock_hmac[VERTHYS_V3_SB_HMAC_BYTES]; /* 序列化时计算 */

    /* TLV 扩展区（≤ VERTHYS_V3_EXTENSIONS_MAX） */
    uint32_t extensions_len;
    uint8_t  extensions[VERTHYS_V3_EXTENSIONS_MAX];
} VerthysSuperBlockV3;

/*
 * 初始化新超级块（内存态默认值）：
 *   magic/version、container_id 随机、created_at/updated_at 当前 FILETIME、
 *   txid=0、state_chain 全零（首次提交时由 HMAC 链起算）、分区布局按
 *   默认常量、其余字段清零。调用方随后填充 Argon2id/密钥包装等。
 */
VerthysResult vsb_v3_init_new(VerthysSuperBlockV3 *sb);

/* 全字段语义相等比较（memcmp 定长字段 + 扩展区长度与内容）。
 * 返回 1 相等，0 不相等；任一为 NULL 返回 0。 */
int vsb_v3_equals(const VerthysSuperBlockV3 *a, const VerthysSuperBlockV3 *b);

/* ---------- 序列化 / 解析（safe_read 纪律） ---------- */

/*
 * 序列化 + HMAC 计算 + HMAC 原地写回：
 *   1. flatcc 构建完整 SuperBlockV3（superblock_hmac 向量 = 32 字节零）；
 *   2. HMAC-SHA256(integrity_key, buffer)；
 *   3. HMAC 原地写回 superblock_hmac 向量（定长 32B，就地覆盖不改布局）。
 * 出参 *out_buf 为 flatcc_builder_finalize_aligned_buffer 对齐缓冲，
 * 调用方以 flatcc_builder_aligned_free 归还；*out_len 为有效字节数。
 * 有效载荷 ≤ 副本槽位容量（VERTHYS_V3_SB_REPLICA_BYTES - 帧头 8B），
 * 超出返回 VERTHYS_ERR_INVALID。
 */
VerthysResult vsb_v3_serialize(const VerthysSuperBlockV3 *sb,
                             const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                             uint8_t **out_buf, size_t *out_len);

/*
 * 解析 + HMAC 验证 + verifier 结构校验 + 向量长度严格校验：
 *   1. flatcc verifier（结构合法性：根偏移/截断/垃圾全拒绝）；
 *   2. 定位 superblock_hmac 向量，保存 32B → 原地零化 →
 *      HMAC 重算 → 常量时间比较 → 还原；
 *   3. 逐字段读入 out（向量长度漂移 → VERTHYS_ERR_FORMAT）。
 * buf 必须可写（本模块产出/测试持有的可写缓冲）。
 * HMAC 不符 → VERTHYS_ERR_AUTH；结构非法 → VERTHYS_ERR_FORMAT。
 */
VerthysResult vsb_v3_parse(uint8_t *buf, size_t len,
                         const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                         VerthysSuperBlockV3 *out);

/*
 * 结构化无校验解析（解锁流水线 S1）。
 * 仅 verifier 结构校验 + 逐字段读入，跳过 HMAC 验证。
 * 用途：S1 阶段提取 salt / Argon2id 参数 / container_id / wrapped 密钥
 *（此时 integrity_key 尚未派生，依赖 S2 Argon2id）。
 * 安全边界：产物仅作派生输入候选；篡改 salt/参数 → 错误 MEK →
 * S3 导入认证失败 / S4 法定人数 HMAC 失败，认证闭环不被绕过。
 */
VerthysResult vsb_v3_parse_unverified(uint8_t *buf, size_t len,
                                    VerthysSuperBlockV3 *out);

/* ---------- 副本 I/O（统一经 verthys_io 64 位偏移层） ---------- */

/*
 * 写入单个副本槽位：帧头（magic + payload_len）+ 载荷 + 零填充至 16KB，
 * 随后 fflush + _commit 物理落盘（fsync 语义，法定人数提交步骤）。
 */
VerthysResult vsb_v3_write_replica(FILE *f, unsigned replica_idx,
                                 const uint8_t *payload, size_t payload_len);

/*
 * 读取单个副本槽位到 out_frame（容量 ≥ VERTHYS_V3_SB_REPLICA_BYTES）。
 * 返回 VERTHYS_OK 且 *out_payload_len 为载荷长度；槽位空/帧头非法 →
 * VERTHYS_ERR_FORMAT。
 */
VerthysResult vsb_v3_read_replica(FILE *f, unsigned replica_idx,
                                uint8_t *out_frame, size_t *out_payload_len);

/* ---------- 法定人数提交 / 读取 ---------- */

/*
 * 法定人数提交（3 副本逐一写入 + fsync，≥2 成功 = 提交成功）：
 *   1. 序列化超级块（含 HMAC）；
 *   2. 写 Replica-0 → fsync；写 Replica-1 → fsync；写 Replica-2 → fsync；
 *   3. 成功副本数 ≥2 → VERTHYS_OK；否则回写旧值不可行（半写由读侧
 *      法定人数与 HMAC 兜底），返回 VERTHYS_ERR_IO；
 *   4. 验证读取：读回并验证 ≥2 副本 HMAC 通过，否则 VERTHYS_ERR_IO。
 * fail_mask（bit i=1 模拟副本 i 写失败，仅测试故障注入用，生产传 0）；
 * replica_status_out（可 NULL）：[3] 各副本写入结果（VERTHYS_OK / IO）。
 */
VerthysResult vsb_v3_commit_quorum_ex(FILE *f, VerthysSuperBlockV3 *sb,
                                    const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                                    uint32_t fail_mask,
                                    VerthysResult replica_status_out[3]);

/* 法定人数提交（无故障注入封装） */
VerthysResult vsb_v3_commit_quorum(FILE *f, VerthysSuperBlockV3 *sb,
                                 const uint8_t integrity_key[VERTHYS_KEY_BYTES]);

/*
 * 法定人数读取（崩溃恢复路径）：
 *   1. 依次读取 3 副本，逐一 HMAC + verifier 验证；
 *   2. 有效副本按 txid 与完整内容分组：一致须 txid 相等且解析内容
 *      逐字节相同，取 ≥2 副本一致中的最高 txid → *out；
 *   3. 仅 1 副本有效或互不一致 → VERTHYS_ERR_QUORUM_FAILED（恢复流程）；
 *   4. 0 副本有效 → VERTHYS_ERR_CORRUPT（WAL 恢复兜底）；
 * valid_mask_out（可 NULL）：bit i=1 表示副本 i HMAC+结构有效。
 */
VerthysResult vsb_v3_read_quorum(FILE *f,
                               const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                               VerthysSuperBlockV3 *out,
                               uint32_t *valid_mask_out);

/* ---------- 超级块事务原语 VsbTxnV3 ---------- */

typedef struct VsbTxnV3 {
    VerthysSuperBlockV3 backup;         /* begin 时的完整超级块备份 */
    uint8_t           backup_hmac[VERTHYS_V3_SB_HMAC_BYTES];
    VerthysResult       replica_status[VERTHYS_V3_SB_REPLICA_COUNT];
    int               committed;      /* 1=已提交 */
    int               rolled_back;    /* 1=已回滚 */
} VsbTxnV3;

/*
 * 开启事务：完整备份当前超级块（含当前 HMAC 快照）。
 * 同一事务内 committed / rolled_back 互斥且终态后不可复用（返回
 * VERTHYS_ERR_INVALID）。
 */
__declspec(noinline) VerthysResult vsb_txn_v3_begin(VsbTxnV3 *txn, const VerthysSuperBlockV3 *sb);

/*
 * 提交事务：对可变超级块 sb 执行法定人数提交（全流程），
 * replica_status 记录于事务上下文；成功置 committed。
 */
__declspec(noinline) VerthysResult vsb_txn_v3_commit(VsbTxnV3 *txn, VerthysSuperBlockV3 *sb,
                              FILE *f,
                              const uint8_t integrity_key[VERTHYS_KEY_BYTES]);

/*
 * 回滚事务：将备份恢复到 sb（内存态），置 rolled_back。
 * 磁盘半写副本由后续提交/读侧法定人数 + HMAC 兜底。
 */
__declspec(noinline) VerthysResult vsb_txn_v3_rollback(VsbTxnV3 *txn, VerthysSuperBlockV3 *sb);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_CONTAINER_V3_H */
