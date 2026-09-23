/*
 * verthys_partition.h — V3 分区管理：独立 AEAD 密钥 + 分区表持久化
 *
 * 分区语义（红线级）：
 *   - 每分区独立 32B 密钥：创建时随机生成 → CNG 内核导入（用户态零残留：
 *     先包装持久化、后导入，import 清零密钥缓冲）；
 *   - 密钥持久化：wrapped_key = [32B 密钥 + 16B tag]，由 wrapping key
 *     （key_a 语境 VerthysCngAead）CNG 内核态加密，AAD 域分离
 *     "verthys/partition-key-wrap-v3"；
 *   - nonce 计数器：持久化于分区元数据，加载后经 restore 防回退；
 *   - 分区数据读写 AAD = partition_id(4B LE) ‖ txid(8B LE)。
 *     实现注记：GCM 中 nonce 本身即认证输入（GHASH 吸收 nonce，
 *     标签覆盖），显式入 AAD 属冗余；且 nonce 由封装层内部计数器在调用内
 *     原子递增生成的设计使调用方无法在加密前预知，故 AAD 绑定
 *     partition_id ‖ txid，nonce 的认证由 GCM 协议原生保证，无安全弱化。
 *
 * 分区表持久化帧布局（分区表区 [1MB, 4MB)）：
 *   [u32 magic 'V3PT'][u32 ct_len][AEAD 密文 ct_len 字节（含 16B tag）]
 *   [12B nonce]
 *   明文为 PartitionTableV3 FlatBuffers（schema/partition.fbs），
 *   AEAD 密钥 = wrapping key（域分离 AAD "verthys/partition-table-v3"）。
 */
#ifndef VERTHYS_PARTITION_H
#define VERTHYS_PARTITION_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "verthys.h"
#include "verthys_crypto_cng.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VERTHYS_PARTITION_MAX              8u
#define VERTHYS_PARTITION_TABLE_MAGIC      UINT32_C(0x54503356) /* 'V3PT' */
#define VERTHYS_PARTITION_TABLE_VERSION    3u
#define VERTHYS_PARTITION_FRAME_HEADER_BYTES 8u
#define VERTHYS_PARTITION_REGION_BYTES     (3u * 1024u * 1024u) /* 帧容量上限 */
#define VERTHYS_PARTITION_KEY_BYTES        VERTHYS_CNG_KEY_BYTES
#define VERTHYS_PARTITION_KEY_ID_BYTES     VERTHYS_CNG_KEY_ID_BYTES
#define VERTHYS_PARTITION_NONCE_BYTES      VERTHYS_CNG_NONCE_BYTES
#define VERTHYS_PARTITION_TAG_BYTES        VERTHYS_CNG_TAG_BYTES
#define VERTHYS_PARTITION_WRAPPED_BYTES    (VERTHYS_PARTITION_KEY_BYTES + \
                                          VERTHYS_PARTITION_TAG_BYTES)
/* 接线修复（nonce 防回退）：table_aead（key_a 语境）跨会话重导入后
 * 计数器归零，若不恢复则下次分区表保存将复用 nonce（GCM 红线违例）。
 * table_load 按帧 nonce 计数器下限 + 裕量恢复（覆盖同语境的密钥包装用途）。 */
#define VERTHYS_PARTITION_NONCE_RESTORE_MARGIN 64u

typedef uint32_t VerthysPartitionId;

typedef enum VerthysPartitionType {
    VERTHYS_PARTITION_INDEX = 0,
    VERTHYS_PARTITION_EXTENT = 1,
    VERTHYS_PARTITION_AUDIT = 2,
    VERTHYS_PARTITION_WAL = 3,
} VerthysPartitionType;

/* 域分离标签 */
#define VERTHYS_PARTITION_WRAP_AAD   "verthys/partition-key-wrap-v3"
#define VERTHYS_PARTITION_TABLE_AAD  "verthys/partition-table-v3"

/*
 * 分区（含内核态 AEAD 上下文）。
 * 生命周期纪律：create/load 导入内核句柄，destroy 销毁；按值拷贝即
 * 转移句柄归属（源须不再 destroy，避免双重销毁）。
 */
typedef struct VerthysPartition {
    VerthysPartitionId   id;
    VerthysPartitionType type;
    uint64_t           offset;        /* 起始偏移 */
    uint64_t           size;          /* 容量 */
    uint64_t           used;          /* 已用字节 */
    VerthysCngAead       aead;          /* 分区独立密钥（内核态句柄） */
    uint8_t            key_id[VERTHYS_PARTITION_KEY_ID_BYTES];
    uint64_t           created_txid;
    /* 持久化形态（wrapped by wrapping key） */
    uint8_t            wrapped_key[VERTHYS_PARTITION_WRAPPED_BYTES];
    size_t             wrapped_key_len;
    uint8_t            wrap_nonce[VERTHYS_PARTITION_NONCE_BYTES];
} VerthysPartition;

/* 分区表（内存态；条目按值持有分区含内核句柄） */
typedef struct VerthysPartitionTable {
    VerthysPartition entries[VERTHYS_PARTITION_MAX];
    size_t         count;
    uint64_t       txid;    /* 表快照事务 ID */
} VerthysPartitionTable;

/* ---------- 分区生命周期 ---------- */

/*
 * 创建分区：随机密钥 → wrapping key 包装（持久化形态）→ CNG 内核导入
 * （明文密钥随即清零）。前置：wrapping 已导入密钥（is_imported）。
 */
VerthysResult verthys_partition_create(VerthysPartition *p,
                                   VerthysPartitionId id,
                                   VerthysPartitionType type,
                                   uint64_t offset, uint64_t size,
                                   uint64_t created_txid,
                                   VerthysCngAead *wrapping);

/*
 * 加载分区：解包 wrapped_key → CNG 内核导入 → restore nonce 计数器
 * （防回退）。前置：wrapping 已导入且与创建时为同一密钥语境。
 */
VerthysResult verthys_partition_load(VerthysPartition *p,
                                 VerthysPartitionId id,
                                 VerthysPartitionType type,
                                 uint64_t offset, uint64_t size,
                                 uint64_t used,
                                 const uint8_t key_id[VERTHYS_PARTITION_KEY_ID_BYTES],
                                 uint64_t nonce_counter,
                                 uint64_t created_txid,
                                 const uint8_t *wrapped_key, size_t wrapped_key_len,
                                 const uint8_t wrap_nonce[VERTHYS_PARTITION_NONCE_BYTES],
                                 VerthysCngAead *wrapping);

/* 销毁分区：销毁内核句柄 + 清零内存态。幂等（NULL 直接返回）。 */
VerthysResult verthys_partition_destroy(VerthysPartition *p);

/* ---------- 分区数据 AEAD ---------- */

/*
 * 分区加密：AAD = partition_id ‖ txid（见文件头实现注记）；
 * nonce 由封装层内部计数器生成经 nonce_out 回传（调用方持久化/传递）。
 * ct 容量 ≥ pt_len + 16，实际长度经 *ct_len 回传。
 */
VerthysResult verthys_partition_encrypt(VerthysPartition *p, uint64_t txid,
                                    const uint8_t *pt, size_t pt_len,
                                    uint8_t *ct, size_t *ct_len,
                                    uint8_t nonce_out[VERTHYS_PARTITION_NONCE_BYTES]);

/*
 * 分区解密：认证失败返回 VERTHYS_ERR_AUTH 且输出清零；
 * txid 不符（AAD 绑定破坏）同样 AUTH 失败。
 */
VerthysResult verthys_partition_decrypt(VerthysPartition *p, uint64_t txid,
                                    const uint8_t nonce[VERTHYS_PARTITION_NONCE_BYTES],
                                    const uint8_t *ct, size_t ct_len,
                                    uint8_t *pt, size_t *pt_len);

/*
 * 分区扩展（按需增长，2x 策略）：
 * 新容量 = min(max(size × 2, size + min_bytes), region_limit - offset)；
 * region_limit 为该分区区域终点的绝对偏移（extent 分区即其后 audit
 * 分区起点）。最小需求（size + min_bytes）放不下 → VERTHYS_ERR_RESOURCE_LIMIT
 * 且内存态不变；2x 目标超出上限则截断于上限。
 */
VerthysResult verthys_partition_grow(VerthysPartition *p, uint64_t min_bytes,
                                 uint64_t region_limit);

/* 分区当前 nonce 计数器（持久化口径） */
uint64_t verthys_partition_nonce_counter(const VerthysPartition *p);

/* ---------- 分区表 ---------- */

/* 初始化空表（count=0，txid 快照） */
VerthysResult verthys_partition_table_init(VerthysPartitionTable *t, uint64_t txid);

/* 追加分区（按值转移句柄归属）；id 重复返回 VERTHYS_ERR_EXISTS。 */
VerthysResult verthys_partition_table_add(VerthysPartitionTable *t,
                                      const VerthysPartition *p);

/* 按 id 查找（找到返回 VERTHYS_OK 且 *out 为条目拷贝，注意句柄归属） */
VerthysResult verthys_partition_table_find(const VerthysPartitionTable *t,
                                       VerthysPartitionId id,
                                       VerthysPartition *out);

/* 销毁表：逐条目销毁内核句柄。幂等（NULL 直接返回）。 */
VerthysResult verthys_partition_table_destroy(VerthysPartitionTable *t);

/*
 * 分区表持久化（region_offset = 分区表区起始偏移，默认 1MB）：
 * flatcc 序列化 → table AEAD 加密 → 帧写入 + fsync。
 * 条目 nonce_counter 取各分区 aead 当前值。
 */
__declspec(noinline) VerthysResult verthys_partition_table_save(FILE *f, uint64_t region_offset,
                                       const VerthysPartitionTable *t,
                                       VerthysCngAead *table_aead);

/*
 * 分区表加载：帧读取 → AEAD 解密验证 → flatcc verifier + 长度校验 →
 * 逐条目 verthys_partition_load（解包密钥 + 导入 + nonce restore）。
 * 帧损坏/认证失败 → VERTHYS_ERR_AUTH / VERTHYS_ERR_FORMAT。
 */
__declspec(noinline) VerthysResult verthys_partition_table_load(FILE *f, uint64_t region_offset,
                                       VerthysCngAead *table_aead,
                                       VerthysCngAead *wrapping_aead,
                                       VerthysPartitionTable *t);

/* ---------- 解析层（模糊测试；纯验证+提取，无 CNG/IO 依赖） ---------- */

/*
 * 分区表条目原始材料（verifier 通过后的字段提取产物；不含内核态句柄）。
 * 生产路径由 verthys_partition_table_load 消费后逐条目走 verthys_partition_load
 * 完成解包与导入；fuzz/早期流水线阶段（此时 wrapping 密钥不可用）仅消费
 * 本结构做边界安全的元数据提取。
 */
typedef struct VerthysPartitionEntryRaw {
    VerthysPartitionId   id;
    VerthysPartitionType type;
    uint64_t           offset;
    uint64_t           size;
    uint64_t           used;
    uint64_t           created_txid;
    uint64_t           nonce_counter;   /* 持久化口径 */
    uint8_t            key_id[VERTHYS_PARTITION_KEY_ID_BYTES];
    uint8_t            wrapped_key[VERTHYS_PARTITION_WRAPPED_BYTES];
    uint8_t            wrap_nonce[VERTHYS_PARTITION_NONCE_BYTES];
} VerthysPartitionEntryRaw;

/*
 * 分区表明文帧解析（对齐 vsb_v3_parse_unverified 的分层模式）：
 *   flatcc verifier 结构校验 → magic/version/txid → 条目数上限 →
 *   逐条目向量长度严格校验（key_id 16B / wrapped 48B / wrap_nonce 12B）
 *   → 字段提取到 out_entries[VERTHYS_PARTITION_MAX]。
 * 安全边界：不触碰任何密钥材料（wrapped_key 仅透传，不解包不导入）；
 * 产物不构成信任输入——生产路径随后逐条目经 verthys_partition_load 完成
 * AEAD 认证（解包失败 → VERTHYS_ERR_AUTH，认证闭环不被绕过）。
 * buf 须可写（flatcc reader 约定）；结构非法/长度漂移 → VERTHYS_ERR_FORMAT。
 */
VerthysResult verthys_partition_table_parse_unverified(
    uint8_t *buf, size_t len,
    uint64_t *out_txid,
    VerthysPartitionEntryRaw out_entries[VERTHYS_PARTITION_MAX],
    size_t *out_count);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_PARTITION_H */
