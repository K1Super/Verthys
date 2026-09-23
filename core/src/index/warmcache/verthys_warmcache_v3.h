/*
 * verthys_warmcache_v3.h — V3 温启动缓存（.verthys.idx_cache，'V3IC' 格式）
 *
 * 文件格式（160B 定长头）：
 *   ┌────────────────────────────────────────────────────┐
 *   │ Header（160B 定长，明文）                           │
 *   │  ├─ magic 'V3IC'（4B）                              │
 *   │  ├─ version: 1（2B）                                │
 *   │  ├─ container_id: 32B（与超级块一致）               │
 *   │  ├─ txid: 8B（保存时超级块已提交事务 ID）           │
 *   │  ├─ cache_hmac: 32B（HMAC-SHA256(integrity_key,     │
 *   │  │   整文件，hmac 字段自身零化——MAC 自排除模式）     │
 *   │  ├─ memtable_snapshot_offset: 8B                    │
 *   │  ├─ memtable_snapshot_size: 8B                      │
 *   │  ├─ sstable_meta_offset: 8B                         │
 *   │  ├─ sstable_meta_size: 8B                           │
 *   │  ├─ kdf_salt: 16B（每次保存随机——见密钥设计）       │
 *   │  └─ reserved: 34B（零填充）                         │
 *   ├────────────────────────────────────────────────────┤
 *   │ MemTable 快照段（AEAD 加密，派生缓存密钥）           │
 *   │  └─ [u32le count][count × verthys_lsm_entry_encode    │
 *   │      记录（与 LSM WAL 条目编码一致）]                │
 *   ├────────────────────────────────────────────────────┤
 *   │ SSTable 表记录段（AEAD 加密，派生缓存密钥）          │
 *   │  └─ verthys_lsm_export_warm 表记录编码（seq/Footer    │
 *   │      字段/Bloom 位图/块索引；verthys_lsm_open_warm     │
 *   │      消费；不含 Manifest——盘面帧为唯一权威）         │
 *   └────────────────────────────────────────────────────┘
 *
 * AEAD 密钥设计（红线级，防 GCM nonce 跨保存复用）：
 *   cache_key = HKDF-SHA256-Expand(integrity_key,
 *               "verthys/warmcache-aead-v3" ‖ kdf_salt)
 *   kdf_salt 每次保存随机生成 → 每次保存独立密钥 → 内部计数器 nonce
 *   （1、2）跨保存不复用（CNG 封装仅支持计数器 nonce，密钥组 A 角色
 *   上下文每会话归零、分区上下文有跨域簿记负担，均不可直接复用；
 *   HKDF info 域分离保证 cache_key 与 integrity_key 的 HMAC 用途
 *   密码学独立）。密钥经 verthys_cng_aead_import_key 导入私有上下文，
 *   用毕 destroy + 清零。
 *
 * 双重校验（读取路径，红线级）：
 *   1. HMAC 校验：cache_hmac = HMAC-SHA256(integrity_key, 整文件)——
 *      损坏/篡改/密钥不符一律 miss（fail → 冷启动路径，不中断解锁）；
 *   2. txid 校验：header.txid == 超级块已提交事务 ID——
 *      仅门控 MemTable 快照段（过期快照可能缺已提交数据，跳过；
 *      WAL 重放完整重建，语义无损）。表记录段不受门控：seq 键控 +
 *      表区域不可变 + 盘面 Manifest 权威 → 跨过期仍然安全可用。
 *
 * 写入时机：Lock 时同步写（时机 1）；事务提交后异步写
 * （时机 2，10s 防抖）；Compaction 完成后异步写（时机 3）。
 * 原子替换：临时文件 + fsync + MoveFileExW(REPLACE_EXISTING)。
 *
 * 容量上限：文件 > 32MB 直接判格式非法（fail → 冷启动）。
 *
 * 密钥语境：integrity_key 派生与 V3 解锁流水线对齐；缓存键派生
 * 由本模块独占实现，无跨版本缓存键复用。
 */
#ifndef VERTHYS_WARMCACHE_V3_H
#define VERTHYS_WARMCACHE_V3_H

#include <stdint.h>
#include <stddef.h>
#include "verthys.h"
#include "verthys_crypto.h"        /* VERTHYS_KEY_BYTES / VERTHYS_HMAC_BYTES */

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 常量 ---------- */

#define VERTHYS_V3IC_MAGIC             UINT32_C(0x43493356) /* 'V3IC' */
#define VERTHYS_V3IC_VERSION           1u
#define VERTHYS_V3IC_HEADER_BYTES      160u
#define VERTHYS_V3IC_CONTAINER_ID_BYTES 32u
#define VERTHYS_V3IC_HMAC_BYTES        32u
#define VERTHYS_V3IC_KDF_SALT_BYTES    16u
#define VERTHYS_V3IC_MAX_BYTES         (32u * 1024u * 1024u) /* 32MB 上限 */

/* 温缓存文件名后缀（verthys_path + ".idx_cache"） */
#define VERTHYS_V3IC_SUFFIX            ".idx_cache"

/* MemTable 快照条目数上限（容量防护：32MB / 最小条目 78B 裕量取整） */
#define VERTHYS_V3IC_MEMTABLE_MAX_ENTRIES  100000u

/* AEAD 域分离标签（HKDF info 前缀 + AAD，与 LSM 帧严格隔离） */
#define VERTHYS_V3IC_KDF_INFO          "verthys/warmcache-aead-v3"
#define VERTHYS_V3IC_AAD_MEMTABLE      "verthys/warmcache-memtable-v3"
#define VERTHYS_V3IC_AAD_SSTABLE_META  "verthys/warmcache-sstablemeta-v3"

/* ---------- 读取（解锁 S5 温缓存优先路径） ---------- */

/*
 * 尝试加载温缓存：
 *   1. 文件存在且 ≤ 32MB（超限/不存在 → miss）；
 *   2. Header：magic / container_id 前置校验（不匹配 → miss）；
 *   3. cache_hmac 整文件校验（integrity_key 语境；失败 → miss，
 *      冷启动兜底，绝不中断解锁流程）；
 *   4. txid 门控（见文件头）：不匹配 → 表记录段照常解密返回，
 *      MemTable 快照段置 NULL/0；
 *   5. 段布局矩形校验（空段规范形 + 两段 off/size 全约束 + 互不
 *      重叠，非法 → miss）后两段 AEAD 解密（派生缓存密钥；
 *      AAD 域分离）。
 *
 * [out] out_tables_pt     表记录段明文（heap，调用方 zero + free；
 *                         hit=0 时 NULL）
 * [out] out_tables_len    明文字节数
 * [out] out_memtable_pt   MemTable 快照段明文（heap；txid 过期或 hit=0
 *                         时 NULL/0）
 * [out] out_memtable_len  明文字节数
 * [out] out_hit           1 = 命中（表记录段有效）/ 0 = 未命中
 *
 * 返回：VERTHYS_OK（无论命中与否——未命中走冷启动是正常路径）/
 * VERTHYS_ERR_INVALID（参数非法）。段解密失败按未命中处理（缓存损坏，
 * HMAC 层已保证不会是伪造，损坏仅可能来自存储介质故障）。
 */
VerthysResult verthys_warmcache_v3_try_load(const char *verthys_path,
                                        const uint8_t container_id[VERTHYS_V3IC_CONTAINER_ID_BYTES],
                                        uint64_t expected_txid,
                                        const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                                        uint8_t **out_tables_pt,
                                        size_t *out_tables_len,
                                        uint8_t **out_memtable_pt,
                                        size_t *out_memtable_len,
                                        int *out_hit);

/* ---------- 写入（Lock 同步 / 事务提交后异步） ---------- */

/*
 * 写入温缓存（原子替换）：
 *   1. kdf_salt 随机生成 → HKDF 派生本次保存独立 cache_key →
 *      CNG 导入私有上下文；
 *   2. 两段 AEAD 加密（AAD 域分离）+ Header 组装（HMAC 字段零化）；
 *   3. cache_hmac = HMAC-SHA256(integrity_key, 整文件) 原地写回；
 *   4. 写入 <verthys_path>.idx_cache.tmp → fflush + _commit →
 *      MoveFileExW(REPLACE_EXISTING) 原子替换。
 *
 * tables_pt / memtable_pt 为 verthys_lsm_export_warm 产物（表记录段 +
 * MemTable 快照编码流；memtable_pt 可为 NULL/0 = 空快照段）。
 * 返回：VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_IO / VERTHYS_ERR_INTERNAL。
 * 失败不影响调用方语义（温缓存为持久化优化，非数据正确性依赖）。
 */
VerthysResult verthys_warmcache_v3_save(const char *verthys_path,
                                    const uint8_t container_id[VERTHYS_V3IC_CONTAINER_ID_BYTES],
                                    uint64_t txid,
                                    const uint8_t integrity_key[VERTHYS_KEY_BYTES],
                                    const uint8_t *tables_pt, size_t tables_len,
                                    const uint8_t *memtable_pt, size_t memtable_len);

/* 删除温缓存（容器删除/SECURE 预设切换时调用）。幂等。 */
VerthysResult verthys_warmcache_v3_delete(const char *verthys_path);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_WARMCACHE_V3_H */
