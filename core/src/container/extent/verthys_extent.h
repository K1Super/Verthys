/*
 * verthys_extent.h — V3 内容寻址 Extent（去重 + 完整性）
 *
 * 复用资产：
 *   - verthys_generichash（libsodium BLAKE2b-256）
 *   - 分区管理（Extent 分区：独立 CNG 内核 AEAD 密钥）
 *
 * 内容寻址语义（红线级）：
 *   - 写入：明文 → BLAKE2b-256 → 索引查重 → 命中则 ref_count++（零重写）；
 *     未命中则 CNG 内核态加密追加写 + 索引更新；
 *   - 读取：索引查哈希 → 读密文 → 内核态解密 → 验证 BLAKE2b(明文) == hash
 *     （双重完整性：AEAD 认证 + 内容哈希校验，任一失败即拒绝）；
 *   - 释放：ref_count-- → 0 = GC 可回收标记（物理删除由 verthys_garbage.c
 *     承担；本模块只标记不回收）；
 *   - 去重防侧信道：相同明文同哈希——密码管理器场景可接受。
 *
 * Extent 分区布局（分区偏移基准）：
 *   [0 .. VERTHYS_EXTENT_INDEX_REGION_BYTES)   索引帧区（固定 1MB）
 *   [VERTHYS_EXTENT_INDEX_REGION_BYTES ..)     数据区（append-only，
 *                                             条目 offset 为数据区相对偏移）
 *
 * 索引帧布局（与分区表帧同构）：
 *   [u32 magic 'V3EX'][u32 ct_len][AEAD 密文 ct_len 字节（含 16B tag）]
 *   [12B nonce]
 *   明文为 ExtentIndexV3 FlatBuffers（schema/extent.fbs），
 *   AEAD 密钥 = Extent 分区密钥（AAD 域分离 "verthys/extent-index-v3"）。
 *
 * 线程安全性：本模块非线程安全——单写者纪律（FFI 单线程事务流水线），
 * 并发由上层事务层串行化。
 */
#ifndef VERTHYS_EXTENT_H
#define VERTHYS_EXTENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "verthys.h"
#include "verthys_partition.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 常量 ---------- */

#define VERTHYS_EXTENT_HASH_BYTES            32u   /* BLAKE2b-256 */
#define VERTHYS_EXTENT_NONCE_BYTES           VERTHYS_PARTITION_NONCE_BYTES
#define VERTHYS_EXTENT_TAG_BYTES             VERTHYS_PARTITION_TAG_BYTES
#define VERTHYS_EXTENT_INDEX_MAGIC           UINT32_C(0x58453356) /* 'V3EX' */
#define VERTHYS_EXTENT_INDEX_VERSION         3u
#define VERTHYS_EXTENT_INDEX_FRAME_HEADER_BYTES 8u
#define VERTHYS_EXTENT_INDEX_REGION_BYTES    (1u * 1024u * 1024u) /* 索引帧区 */
#define VERTHYS_EXTENT_INDEX_MAX             4096u /* 条目上限（索引帧区容量内） */

/* 索引帧 AEAD 域分离标签 */
#define VERTHYS_EXTENT_INDEX_AAD   "verthys/extent-index-v3"

/* ---------- 类型 ---------- */

/*
 * Extent 索引条目（内存态）。
 * 内容寻址键 = hash（BLAKE2b-256(明文)）；offset 为 Extent 分区数据区
 * 相对偏移；size 为密文长度（含 16B tag）。
 */
typedef struct VerthysExtent {
    uint8_t  hash[VERTHYS_EXTENT_HASH_BYTES]; /* 内容寻址键 */
    uint8_t  nonce[VERTHYS_EXTENT_NONCE_BYTES]; /* 数据块 AEAD nonce */
    uint64_t offset;        /* 数据区相对偏移 */
    uint32_t size;          /* 密文长度（含 tag） */
    uint32_t plaintext_size;
    uint32_t ref_count;     /* 引用计数（0 = GC 可回收） */
    uint64_t created_txid;
    uint64_t last_ref_txid; /* 最近引用变动事务 ID */
} VerthysExtent;

/* Extent 索引（内存态） */
typedef struct VerthysExtentIndex {
    VerthysExtent entries[VERTHYS_EXTENT_INDEX_MAX];
    size_t   count;
    uint64_t txid;         /* 索引快照事务 ID */
    uint64_t next_offset;  /* 数据区追加写游标（相对偏移） */
} VerthysExtentIndex;

/* ---------- 哈希 ---------- */

/*
 * 计算内容寻址哈希：BLAKE2b-256(data)。
 *
 * [out] out    32 字节 digest
 * [in]  data   数据（可为 NULL，仅当 data_len==0）
 * [in]  data_len 数据长度
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID（参数非法）/ VERTHYS_ERR_INTERNAL
 *（libsodium 失败，理论不发生）。
 * 线程安全：是（纯函数）。
 */
VerthysResult verthys_extent_hash(uint8_t out[VERTHYS_EXTENT_HASH_BYTES],
                              const uint8_t *data, size_t data_len);

/* ---------- 索引生命周期 ---------- */

/*
 * 初始化空索引（count=0，next_offset=0，txid 快照）。
 *
 * [out] idx   索引（须非 NULL）
 * [in]  txid  索引快照事务 ID
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID。
 */
VerthysResult verthys_extent_index_init(VerthysExtentIndex *idx, uint64_t txid);

/*
 * 按哈希查找索引条目。
 *
 * [in]  idx  索引（须非 NULL）
 * [in]  hash 内容寻址键（32B，须非 NULL）
 * [out] out  命中条目拷贝（可为 NULL=仅探测存在性）
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_NOTFOUND / VERTHYS_ERR_INVALID。
 */
VerthysResult verthys_extent_index_find(const VerthysExtentIndex *idx,
                                    const uint8_t hash[VERTHYS_EXTENT_HASH_BYTES],
                                    VerthysExtent *out);

/* ---------- 数据路径 ---------- */

/*
 * 写入路径：明文 → BLAKE2b-256 → 查重 →（命中）ref_count++ /（未命中）
 * CNG 内核态加密追加写 + 索引更新。数据块追加后 fsync（崩溃一致性：
 * 未持久化的追加块在恢复后不可达，由索引快照决定可见性）。
 *
 * [in]     f         容器文件（已打开，须非 NULL）
 * [in,out] part      Extent 分区（已导入密钥；nonce 计数器随写推进）
 * [in,out] idx       Extent 索引（查重 + 更新；条目数达上限返回
 *                    VERTHYS_ERR_RESOURCE_LIMIT）
 * [in]     txid      当前事务 ID（created/last_ref 记账）
 * [in]     pt        明文（可为 NULL，仅当 pt_len==0）
 * [in]     pt_len    明文长度
 * [out]    hash_out  实际内容哈希（可为 NULL；去重命中时仍回传，便于
 *                    调用方建立 key→hash 映射）
 * [out]    stored    可为 NULL；非 NULL 时回传 1=新写入 / 0=去重命中
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_LOCKED（分区未导入密钥）/
 * VERTHYS_ERR_RESOURCE_LIMIT（索引满）/ VERTHYS_ERR_IO / VERTHYS_ERR_INTERNAL。
 *
 * 注意：分区容量（part->size）不约束追加写——分区扩展（2x 策略）由
 * 上层事务层在索引持久化前统一决策；本函数只推进 used/next_offset。
 */
VerthysResult verthys_extent_put(FILE *f, VerthysPartition *part,
                             VerthysExtentIndex *idx, uint64_t txid,
                             const uint8_t *pt, size_t pt_len,
                             uint8_t hash_out[VERTHYS_EXTENT_HASH_BYTES],
                             int *stored);

/*
 * 读取路径：索引查哈希 → 读密文 → 内核态解密 → 验证 BLAKE2b(明文)==hash。
 * 双重完整性：AEAD 认证失败返回 VERTHYS_ERR_AUTH；解密成功但哈希不符返回
 * VERTHYS_ERR_CORRUPT（密文被"合法密钥下重放"替换的纵深防御）。
 *
 * [in]  f        容器文件（已打开，须非 NULL）
 * [in]  part     Extent 分区（已导入密钥）
 * [in]  idx      Extent 索引
 * [in]  hash     内容寻址键（32B）
 * [out] pt       明文输出缓冲（调用方拥有；容量 ≥ 条目 plaintext_size）
 * [in,out] pt_len [in] 容量 / [out] 实际明文长度
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_NOTFOUND / VERTHYS_ERR_INVALID /
 * VERTHYS_ERR_AUTH（篡改/认证失败，输出清零）/ VERTHYS_ERR_CORRUPT（哈希不符）/
 * VERTHYS_ERR_IO / VERTHYS_ERR_INTERNAL。
 */
VerthysResult verthys_extent_get(FILE *f, const VerthysPartition *part,
                             const VerthysExtentIndex *idx,
                             const uint8_t hash[VERTHYS_EXTENT_HASH_BYTES],
                             uint8_t *pt, size_t *pt_len);

/*
 * 释放引用：ref_count--（下限 0，不回绕）→ 0 = GC 可回收标记。
 *
 * [in,out] idx   索引
 * [in]     hash  内容寻址键
 * [in]     txid  当前事务 ID（last_ref 记账）
 * [out]    out_ref_count 可为 NULL；非 NULL 时回传释放后引用计数
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_NOTFOUND / VERTHYS_ERR_INVALID。
 */
VerthysResult verthys_extent_release(VerthysExtentIndex *idx,
                                 const uint8_t hash[VERTHYS_EXTENT_HASH_BYTES],
                                 uint64_t txid,
                                 uint32_t *out_ref_count);

/*
 * GC 标记扫描：统计 ref_count==0（可回收）的条目数。
 *
 * [in]  idx    索引
 * [out] count  可回收条目数（GC 时由 verthys_garbage.c 物理删除）
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID。
 */
VerthysResult verthys_extent_gc_eligible(const VerthysExtentIndex *idx,
                                     size_t *count);

/* ---------- 索引持久化 ---------- */

/*
 * 索引持久化：flatcc 序列化 → Extent 分区密钥 AEAD 加密（域分离 AAD）→
 * 索引帧区整帧覆写 + fsync。帧内含分区 nonce 计数器快照（
 * 保存后值约定：快照 = 序列化时计数器 + 1（索引帧加密恰消耗 1 个
 * nonce），重载 restore 后绝不复用帧自身 nonce）。
 *
 * [in] f              容器文件（须非 NULL）
 * [in] region_offset  索引帧区起始偏移（= Extent 分区 offset，默认）
 * [in] idx            索引（须非 NULL）
 * [in,out] part       Extent 分区（已导入密钥；加密推进 nonce 计数器）
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_LOCKED / VERTHYS_ERR_IO /
 * VERTHYS_ERR_INTERNAL。
 */
VerthysResult verthys_extent_index_save(FILE *f, uint64_t region_offset,
                                    const VerthysExtentIndex *idx,
                                    VerthysPartition *part);

/*
 * 索引加载：帧读取 → AEAD 解密验证 → flatcc verifier + 字段校验 →
 * 内存态重建 + 分区 nonce 计数器 restore（防回退；快照值小于当前
 * 值时拒绝，保证 nonce 不复用）。
 *
 * [in]  f              容器文件（须非 NULL）
 * [in]  region_offset  索引帧区起始偏移
 * [in,out] part        Extent 分区（已导入密钥；restore 推进计数器）
 * [out] idx            加载后的索引（调用方先 init 或可覆盖任意状态）
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_AUTH（帧篡改/密钥不符）/
 * VERTHYS_ERR_FORMAT（magic/version/字段校验失败）/ VERTHYS_ERR_IO /
 * VERTHYS_ERR_INTERNAL。
 */
VerthysResult verthys_extent_index_load(FILE *f, uint64_t region_offset,
                                    VerthysPartition *part,
                                    VerthysExtentIndex *idx);

/* ---------- 解析层（模糊测试；纯验证+提取，无 CNG/IO 依赖） ---------- */

/*
 * Extent 索引明文帧解析（对齐 vsb_v3_parse_unverified 分层模式）：
 *   flatcc verifier → magic/version/txid/next_offset → 条目数上限 →
 *   逐条目向量长度严格校验（hash 32B / nonce 12B）→ 字段提取 →
 *   字段一致性校验（密文长度 > tag、明文长度自洽、offset+size 不越过
 *   next_offset 追加游标——防越界读放大与 uint64 回绕）。
 * 安全边界：不触碰密钥材料；产物（idx）不构成信任输入——生产路径由
 * verthys_extent_index_load 在 AEAD 认证通过后调用，本函数只消费已认证
 * 明文。fuzz 直接调用时校验的是解析器自身的边界纪律。
 * buf 须可写；结构非法/长度漂移/一致性失配 → VERTHYS_ERR_FORMAT。
 * idx 由本函数整体重建（调用方无须预置）。
 */
VerthysResult verthys_extent_index_parse_unverified(uint8_t *buf, size_t len,
                                                VerthysExtentIndex *idx,
                                                uint64_t *out_nonce_counter);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_EXTENT_H */
