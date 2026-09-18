# Verthys 解锁流程优化方案 — 系统化工程文档

> **文档版本**: 1.0
> **配套架构**: 安全架构 v5.0 + 性能架构 v1.0
> **目标**: 将 BALANCED 预设解锁时间从当前 ≥3.5s 优化至 ≤2.5s（温启动 ≤1.2s），P95 稳定不抖动
> **核心手段**: 流水线并行 + 温启动缓存 + 渐进式解锁 + 阶段级耗时预算与监控

---

## 目录

1. [解锁流程全景与耗时建模](#1-解锁流程全景与耗时建模)
2. [阶段级耗时预算](#2-阶段级耗时预算)
3. [优化策略总览](#3-优化策略总览)
4. [P0：Argon2id 派生优化](#4-p0argon2id-派生优化)
5. [P1：超级块读取与法定人数优化](#5-p1超级块读取与法定人数优化)
6. [P2：密钥导入 CNG 优化](#6-p2密钥导入-cng-优化)
7. [P3：索引预热优化（温启动缓存核心）](#7-p3索引预热优化温启动缓存核心)
8. [P4：流水线调度器设计](#8-p4流水线调度器设计)
9. [P5：渐进式解锁与可操作性提前](#9-p5渐进式解锁与可操作性提前)
10. [P6：性能监控与自调节](#10-p6性能监控与自调节)
11. [代码级实现规范](#11-代码级实现规范)
12. [测试与验证方案](#12-测试与验证方案)
13. [故障注入与降级路径](#13-故障注入与降级路径)
14. [附录：状态机、常量与检查清单](#14-附录状态机常量与检查清单)

---

## 1. 解锁流程全景与耗时建模

### 1.1 解锁流程完整分解

`Verthys_Unlock` 从调用到容器可操作（`VERTHYS_OK` 返回），在目标态 V3 架构下包含以下子阶段：

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Verthys_Unlock 入口                             │
├─────────────────────────────────────────────────────────────────────┤
│  S0  前置检查（<1ms）                                                 │
│  ├── 参数验证 / 状态机检查 / emergency 门控                          │
│  ├── pepper 快速失败（来源错误立即返回，不做 Argon2id）               │
│  └── .vsec 验签（仅首次解锁）                                        │
├─────────────────────────────────────────────────────────────────────┤
│  S1  超级块读取 + 法定人数验证（IO，异步发起）                        │
│  ├── 并行读取 3 个副本（各 16KB）                                    │
│  ├── HMAC 验证，取最快有效 2 个                                      │
│  └── FlatBuffers 零拷贝解析                                          │
├─────────────────────────────────────────────────────────────────────┤
│  S2  Argon2id 口令派生（CPU 密集，与 S1 并行）                       │
│  ├── DKM = Argon2id(password ‖ pepper, salt, mem/iters/parallel)     │
│  ├── MEK = HKDF-Expand(DKM, "verthys/master-key-v3")                │
│  └── DKM 清零                                                        │
├─────────────────────────────────────────────────────────────────────┤
│  S3  密钥导入 CNG（系统调用，依赖 S2）                               │
│  ├── MEK → BCryptGenerateSymmetricKey → hkey_meK                     │
│  ├── hkey_meK 解包 wrapped_key_a/b/c → 内核态                        │
│  ├── hkey_a/b/c 创建（分别 BCryptGenerateSymmetricKey）              │
│  └── integrity_key 派生 + 导入                                       │
├─────────────────────────────────────────────────────────────────────┤
│  S4  分区表加载（IO，依赖 S1 的超级块内容）                          │
│  ├── 读取分区表（FlatBuffers）                                       │
│  ├── 验证分区完整性（AEAD，依赖 S3 的密钥）                          │
│  └── 构建分区内存结构                                                │
├─────────────────────────────────────────────────────────────────────┤
│  S5  LSM 索引预热（IO+CPU，依赖 S3/S4）                              │
│  ├── 路径 A：温启动缓存命中 → 直接加载 MemTable 快照 + SSTable 元数据 │
│  ├── 路径 B：缓存未命中 → 扫描 SSTable 构建索引                      │
│  └── Bloom Filter 加载（可选，按需）                                 │
├─────────────────────────────────────────────────────────────────────┤
│  S6  最终校验 + 状态切换（<5ms）                                     │
│  ├── Merkle 校验（如已重建）                                        │
│  ├── 防御闭环状态确认                                                │
│  ├── 活动句柄注册                                                    │
│  └── emergency_clear_signals + 安全模块启动                          │
└─────────────────────────────────────────────────────────────────────┘
                        Verthys_Unlock 返回 VERTHYS_OK
```

### 1.2 各阶段耗时基线（典型硬件：4C/16G/SATA SSD，BALANCED 预设）

| 阶段 | 冷启动（无缓存） | 温启动（缓存命中） | 优化后目标 |
|------|-----------------|-------------------|-----------|
| S0 前置检查 | <1ms | <1ms | <1ms |
| S1 超级块读取 | 2-5ms（SSD） | 1-2ms（OS 文件缓存） | ≤3ms |
| **S2 Argon2id** | **1100-1300ms** | **1100-1300ms** | **≤1000ms**（校准优化） |
| S3 CNG 导入 | 3-8ms | 3-8ms | ≤5ms |
| S4 分区表加载 | 3-10ms | 1-3ms | ≤5ms |
| S5 索引预热 | **80-150ms**（10 万条） | **15-30ms** | ≤30ms（温） |
| S6 最终校验 | 2-5ms | 2-5ms | ≤3ms |
| **总计** | **~1400ms** | **~1250ms** | **≤1200ms（温）** |

> **关键洞察**：Argon2id（S2）占总时间 85% 以上，是解锁延迟的绝对瓶颈。优化重点：
> 1. **S2 与其他阶段完全并行**——理想情况下总时间 ≈ max(S2, S1+S3+S4+S5)
> 2. **温启动缓存将 S5 从 100ms 级别降至 20ms 级别**
> 3. **S2 本身通过校准精确控制在 1.0-1.2s**

### 1.3 优化后时序图

```
时间轴 (ms):    0    100   200   300   400   500   600   700   800   900   1000  1100  1200
               ├─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┤

S1 超块读取:    ████ (2-3ms)
S2 Argon2id:    ██████████████████████████████████████████████████████████████████ (~1000ms)
S3 CNG 导入:                                                ████ (3-5ms, 依赖 S2)
S4 分区表:        ████ (2-4ms, 依赖 S1+S3)
S5 索引预热(温):                                            ██████████ (20-30ms, 依赖 S3+S4)
S6 最终校验:                                                                    ████ (2-3ms)

总时间: ~1030ms（温启动）
                    ↑ S2 是关键路径，其余阶段完全被 Argon2id 掩盖
```

---

## 2. 阶段级耗时预算

### 2.1 预算分配表

| 阶段 | 预算 | 超预算阈值 | 超限行为 |
|------|------|-----------|---------|
| S0 | 1ms | 10ms | 告警日志 |
| S1 | 5ms | 50ms | 降级：跳过法定人数，单副本读取 |
| S2 | 1100ms（BALANCED） | 1500ms | 触发 Argon2id 参数降档（最低 1 iter） |
| S3 | 10ms | 100ms | 告警 + 重试一次 → 返回 CNG_UNAVAILABLE |
| S4 | 10ms | 100ms | 降级：延迟加载分区 |
| S5 | 150ms（冷）/ 50ms（温） | 500ms | 降级：跳过预热，按需加载 |
| S6 | 5ms | 50ms | 告警日志 |
| **总预算** | **1200ms（温）** | **2500ms** | 返回超时错误 |

### 2.2 阶段耗时采集

每个阶段使用 `QueryPerformanceCounter` 精确计时：

```c
typedef struct UnlockTiming {
    uint64_t t_s0_precheck_ns;
    uint64_t t_s1_superblock_ns;
    uint64_t t_s2_argon2id_ns;
    uint64_t t_s3_cng_import_ns;
    uint64_t t_s4_partition_ns;
    uint64_t t_s5_index_preheat_ns;
    uint64_t t_s6_finalize_ns;
    uint64_t t_total_ns;
    uint32_t cache_hit;           /* 温缓存是否命中 */
    uint32_t argon2_iters_used;   /* 实际使用的迭代次数 */
    uint32_t parallel_benefit_ns; /* 并行节省的时间 */
} UnlockTiming;
```

存入 `VerthysDiagnosticsV3` 供 `Verthys_GetDiagnostics` 查询。

---

## 3. 优化策略总览

| 优先级 | 策略 | 预期收益 | 风险 |
|--------|------|---------|------|
| **P0** | Argon2id 精确校准（1.0-1.2s） | 从 1.3s → 1.0s | 安全强度降低（可接受范围内） |
| **P0** | 流水线并行（S2 与 S1/S4 并行） | 隐藏 20-150ms | 线程同步复杂度 |
| **P0** | 温启动缓存（索引快照） | 冷 150ms → 温 30ms | 缓存一致性需严格校验 |
| **P1** | 超级块副本并行读取 | 2-5ms | 实现简单 |
| **P1** | CNG 批量导入 | 3-8ms → 2-4ms | 低 |
| **P2** | 渐进式解锁（UI 可提前操作） | 用户感知大幅提升 | 状态机复杂度 |
| **P2** | 预取下一 SSTable | 首次查询提速 | 额外 IO |

---

## 4. P0：Argon2id 派生优化

### 4.1 问题分析

当前（v4.0）Argon2id 校准逻辑存在以下问题：

1. **校准目标 1200ms 偏高**：实际硬件上可安全降至 1000ms，感知差异极小（1.2s → 1.0s），安全强度下降在可接受范围内（32MiB × 2-3 iters 仍然远超民用水准）。
2. **校准算法保守**：两段式探测（初始测量 + 换算确认）存在 10-15% 的系统性高估。
3. **无硬件加速检测**：未显式检测 AVX2/AVX-512 并选择对应实现。

### 4.2 优化方案

#### 4.2.1 校准目标调整

```c
/* verthys_crypto.h */
#define VERTHYS_ARGON2_CALIBRATE_TARGET_MS      1000  /* 从 1200 降至 1000 */
#define VERTHYS_ARGON2_CALIBRATE_MIN_MS         800   /* 新增：最低可接受值 */
#define VERTHYS_ARGON2_CALIBRATE_MAX_MS         1200  /* 上限保持 */
#define VERTHYS_ARGON2_BALANCED_ITERS_MAX       3     /* 不变 */
```

#### 4.2.2 校准算法改进（三阶段精确校准）

```c
/* 改进的校准流程：测量 → 粗调 → 精调 */
VerthysResult verthys_argon2_calibrate_v3(
    uint32_t mem_kib,
    uint32_t parallelism,
    uint32_t *out_iters,
    uint32_t *out_benchmark_ms
) {
    /* 阶段 1：单次测量建立基准 */
    uint64_t t0 = qpc_now();
    verthys_argon2id_derive_ex(/* mem_kib, iters=1, parallelism */);
    uint64_t t1 = qpc_now();
    uint64_t base_ms = (t1 - t0) / 1000000;

    /* 阶段 2：粗算迭代数 */
    uint32_t target_ms = VERTHYS_ARGON2_CALIBRATE_TARGET_MS;
    uint32_t est_iters = (uint32_t)(target_ms / base_ms);
    if (est_iters < 1) est_iters = 1;
    if (est_iters > VERTHYS_ARGON2_BALANCED_ITERS_MAX) est_iters = VERTHYS_ARGON2_BALANCED_ITERS_MAX;

    /* 阶段 3：精调——测量 est_iters 实际耗时，微调 */
    t0 = qpc_now();
    verthys_argon2id_derive_ex(/* mem_kib, est_iters, parallelism */);
    t1 = qpc_now();
    uint64_t est_ms = (t1 - t0) / 1000000;

    /* 微调：如果偏差 >15%，向上或向下调整 */
    if (est_ms > target_ms + 150 && est_iters > 1) {
        est_iters--;  /* 超时太多，降一档 */
    } else if (est_ms < target_ms - 200 && est_iters < VERTHYS_ARGON2_BALANCED_ITERS_MAX) {
        est_iters++;  /* 太快，升一档（需重测确认） */
    }

    /* 验证最终参数（可选：仅在创建时做） */
    if (est_ms > VERTHYS_ARGON2_CALIBRATE_MAX_MS) {
        est_iters = 1;  /* 极端硬件，强制最低 */
    }

    *out_iters = est_iters;
    *out_benchmark_ms = (uint32_t)est_ms;
    return VERTHYS_OK;
}
```

#### 4.2.3 硬件加速检测

```c
/* 检测 CPU 能力，选择最优 Argon2id 实现 */
typedef enum Argon2Impl {
    ARGON2_IMPL_AUTO = 0,   /* 自动检测 */
    ARGON2_IMPL_REF = 1,    /* 参考实现（无 SIMD） */
    ARGON2_IMPL_AVX2 = 2,   /* AVX2 加速 */
    ARGON2_IMPL_AVX512 = 3, /* AVX-512 加速（如可用） */
} Argon2Impl;

/* libsodium 已内置 SIMD 检测，此处仅记录诊断信息 */
static Argon2Impl detect_argon2_impl(void) {
    /* 使用 __cpuidex 检测 */
    int cpu_info[4];
    __cpuidex(cpu_info, 7, 0);
    if (cpu_info[1] & (1 << 16)) return ARGON2_IMPL_AVX512; /* AVX512F */
    __cpuidex(cpu_info, 7, 0);
    if (cpu_info[1] & (1 << 5)) return ARGON2_IMPL_AVX2;   /* AVX2 */
    return ARGON2_IMPL_REF;
}
```

#### 4.2.4 解锁期 Argon2id 复用

```c
/* 解锁时使用超级块中存储的基准参数，不重复校准 */
/* 仅在以下情况触发重新校准： */
/* 1. 连续 3 次解锁超时 > 基准 130% */
/* 2. 连续 3 次解锁耗时 < 基准 70% */
/* 3. 手动触发（Verthys_TriggerRekey 附带 calibrate 标志） */
```

---

## 5. P1：超级块读取与法定人数优化

### 5.1 并行副本读取

```c
/* 并行读取 3 个超级块副本，取最快有效的 2 个 */
VerthysResult vsb_v3_read_quorum_parallel(
    VerthysFileHandle *fh,
    VerthysSuperBlockV3 *out_sb,
    uint32_t *out_replica_status  /* bitmask: bit0=rep0 ok, bit1=rep1 ok, bit2=rep2 ok */
) {
    /* 使用线程池并行发起 3 个异步读 */
    struct ReplicaRead {
        uint32_t index;
        uint8_t buffer[V3_SUPERBLOCK_BYTES];
        bool completed;
        bool hmac_valid;
        uint64_t elapsed_us;
    } replicas[3];

    /* 提交异步读任务 */
    for (int i = 0; i < 3; i++) {
        thread_pool_submit(read_replica_task, &replicas[i], fh, i * V3_SUPERBLOCK_REPLICA_OFFSET);
    }

    /* 等待至少 2 个有效副本返回（带超时 50ms） */
    uint32_t valid_count = 0;
    uint64_t deadline = qpc_now() + 50 * 1000; /* 50ms */

    while (valid_count < 2 && qpc_now() < deadline) {
        for (int i = 0; i < 3; i++) {
            if (replicas[i].completed && !replicas[i].hmac_valid) {
                /* 验证 HMAC */
                replicas[i].hmac_valid = verify_sb_hmac(replicas[i].buffer);
                if (replicas[i].hmac_valid) valid_count++;
            }
        }
        Sleep(0); /* 让步 */
    }

    /* 选择 txid 最高的有效副本 */
    if (valid_count >= 2) {
        select_best_replica(replicas, out_sb);
        *out_replica_status = compute_status_bitmask(replicas);
        return VERTHYS_OK;
    }

    /* 降级：只有 1 个有效副本 */
    for (int i = 0; i < 3; i++) {
        if (replicas[i].hmac_valid) {
            *out_sb = parse_sb(replicas[i].buffer);
            *out_replica_status = (1 << i);
            return VERTHYS_ERR_QUORUM_DEGRADED; /* 告警但继续 */
        }
    }

    return VERTHYS_ERR_CORRUPT;
}
```

### 5.2 超级块内存缓存

```c
/* 超级块内容缓存于内存，后续操作直接访问 */
typedef struct SuperBlockCache {
    VerthysSuperBlockV3 sb;
    uint8_t hmac[32];
    uint64_t last_read_tick;
    bool dirty;
    CRITICAL_SECTION lock;
} SuperBlockCache;

/* 读路径：优先内存缓存 */
/* 写路径：写穿（更新内存 + 异步写盘） */
```

### 5.3 OS 文件缓存利用

- 使用 `FILE_FLAG_SEQUENTIAL_SCAN` 提示 OS 预读超级块区域。
- 首次解锁后，超级块区域在 OS 文件缓存中，后续解锁读延迟从 5ms 降至 1-2ms。

---

## 6. P2：密钥导入 CNG 优化

### 6.1 批量导入

```c
/* 将 4 个密钥（MEK, A, B, C）的导入合并为批量操作 */
VerthysResult verthys_cng_import_keys_batch(
    const uint8_t mek[32],
    const uint8_t *wrapped_a, uint32_t wrapped_a_len,
    const uint8_t *wrapped_b, uint32_t wrapped_b_len,
    const uint8_t *wrapped_c, uint32_t wrapped_c_len,
    BCRYPT_KEY_HANDLE *out_hmeK,
    BCRYPT_KEY_HANDLE *out_hA,
    BCRYPT_KEY_HANDLE *out_hB,
    BCRYPT_KEY_HANDLE *out_hC
) {
    /* 1. 导入 MEK（仅此一步密钥明文在用户态栈帧） */
    BCRYPT_KEY_HANDLE hmeK = NULL;
    BCryptGenerateSymmetricKey(alg_handle, &hmeK, NULL, 0, (PUCHAR)mek, 32, 0);
    SecureZeroMemory((PVOID)mek, 32); /* 立即清零 */

    /* 2. 用 hmeK 解包 wrapped_key_a/b/c（解密在内核态完成） */
    uint8_t key_a[32], key_b[32], key_c[32];
    cng_decrypt_with_key(hmeK, wrapped_a, wrapped_a_len, key_a, NULL);
    cng_decrypt_with_key(hmeK, wrapped_b, wrapped_b_len, key_b, NULL);
    cng_decrypt_with_key(hmeK, wrapped_c, wrapped_c_len, key_c, NULL);

    /* 3. 分别导入 A/B/C（明文短暂存在于栈帧，导入后清零） */
    BCryptGenerateSymmetricKey(alg_handle, out_hA, NULL, 0, key_a, 32, 0);
    SecureZeroMemory(key_a, 32);
    BCryptGenerateSymmetricKey(alg_handle, out_hB, NULL, 0, key_b, 32, 0);
    SecureZeroMemory(key_b, 32);
    BCryptGenerateSymmetricKey(alg_handle, out_hC, NULL, 0, key_c, 32, 0);
    SecureZeroMemory(key_c, 32);

    *out_hmeK = hmeK;
    return VERTHYS_OK;
}
```

### 6.2 预创建算法句柄

```c
/* 算法句柄在 Verthys_Init 时创建一次，避免解锁时重复打开 */
static BCRYPT_ALG_HANDLE g_aes_gcm_alg = NULL;

VerthysResult verthys_cng_init_once(void) {
    if (g_aes_gcm_alg == NULL) {
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &g_aes_gcm_alg, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (!BCRYPT_SUCCESS(status)) return VERTHYS_ERR_CNG_UNAVAILABLE;
        BCryptSetProperty(g_aes_gcm_alg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    }
    return VERTHYS_OK;
}
```

### 6.3 nonce 计数器持久化

```c
/* 分区 nonce 计数器从超级块恢复，避免解锁后重新初始化 */
/* 超级块中存储各分区的 nonce_counter 当前值 */
/* 解锁时直接加载，加密操作从该值继续递增 */
```

---

## 7. P3：索引预热优化（温启动缓存核心）

### 7.1 温启动缓存格式（V3 版）

```
.verthys.idx_cache 文件格式:
┌──────────────────────────────────────────────┐
│ Header (128B)                                 │
│  ├─ magic: 'V3IC' (4B)                        │
│  ├─ version: 1 (2B)                           │
│  ├─ container_id: 32B                         │
│  ├─ txid: 8B                                  │
│  ├─ cache_hmac: 32B（覆盖整个文件）           │
│  ├─ memtable_snapshot_offset: 8B              │
│  ├─ memtable_snapshot_size: 8B                │
│  ├─ sstable_meta_offset: 8B                   │
│  ├─ sstable_meta_size: 8B                     │
│  └─ reserved: 24B                             │
├──────────────────────────────────────────────┤
│ MemTable 快照（跳表序列化，AEAD 加密）         │
│  └─ 包含所有未 flush 的 key→extent_hash 映射   │
├──────────────────────────────────────────────┤
│ SSTable 元数据（FlatBuffers，AEAD 加密）       │
│  └─ 每个 SSTable 的：                          │
│     ├─ 文件偏移 / 大小                         │
│     ├─ Bloom Filter（完整复制）                │
│     ├─ 最小/最大 key 范围                     │
│     └─ 条目数量                               │
└──────────────────────────────────────────────┘
```

### 7.2 写入时机

```c
/* 以下时机异步写入温缓存： */
/* 1. Verthys_Lock 时（同步，确保解锁可用）        */
/* 2. 事务提交后（异步，10 秒防抖）              */
/* 3. Compaction 完成后（异步）                  */

/* 写入采用原子文件替换：临时文件 + fsync + MoveFileEx */
```

### 7.3 读取路径（解锁时）

```c
VerthysResult warmcache_try_load(
    VerthysContext *ctx,
    const uint8_t *container_id,
    uint64_t expected_txid,
    VerthysLsmIndex **out_index,
    bool *out_cache_hit
) {
    *out_cache_hit = false;

    /* 1. 构造缓存文件路径 */
    char cache_path[MAX_PATH];
    snprintf(cache_path, MAX_PATH, "%s.idx_cache", ctx->verthys_path);

    /* 2. 检查文件存在且大小合理（≤ 32MB） */
    HANDLE fh = CreateFileA(cache_path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (fh == INVALID_HANDLE_VALUE) return VERTHYS_ERR_NOTFOUND;

    LARGE_INTEGER file_size;
    GetFileSizeEx(fh, &file_size);
    if (file_size.QuadPart > 32 * 1024 * 1024) {
        CloseHandle(fh);
        return VERTHYS_ERR_FORMAT;
    }

    /* 3. 读取整个文件（≤32MB，使用 mmap 或 ReadFile） */
    uint8_t *buffer = VirtualAlloc(NULL, (SIZE_T)file_size.QuadPart,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) { CloseHandle(fh); return VERTHYS_ERR_RESOURCE_LIMIT; }

    DWORD bytes_read;
    ReadFile(fh, buffer, (DWORD)file_size.QuadPart, &bytes_read, NULL);
    CloseHandle(fh);

    /* 4. 验证 Header：magic / container_id / txid / HMAC */
    V3IdxCacheHeader *hdr = (V3IdxCacheHeader *)buffer;
    if (memcmp(hdr->magic, "V3IC", 4) != 0) goto fail;
    if (memcmp(hdr->container_id, container_id, 32) != 0) goto fail;
    if (hdr->txid != expected_txid) goto fail;  /* txid 不匹配 = 缓存过期 */

    /* 5. 验证 HMAC（使用 integrity_key） */
    if (!verify_cache_hmac(buffer, file_size.QuadPart, ctx->hkey_integrity)) goto fail;

    /* 6. 解密并反序列化 MemTable 快照 */
    VerthysLsmMemTable *memtable = NULL;
    decrypt_and_deserialize_memtable(
        buffer + hdr->memtable_snapshot_offset,
        hdr->memtable_snapshot_size,
        ctx->hkey_a, &memtable);

    /* 7. 解密并反序列化 SSTable 元数据 */
    VerthysSSTableMeta *sst_meta = NULL;
    uint32_t sst_count = 0;
    decrypt_and_deserialize_sstable_meta(
        buffer + hdr->sstable_meta_offset,
        hdr->sstable_meta_size,
        ctx->hkey_a, &sst_meta, &sst_count);

    /* 8. 构建 LSM 索引（内存操作，极快） */
    *out_index = verthys_lsm_from_cache(memtable, sst_meta, sst_count);
    *out_cache_hit = true;

    VirtualFree(buffer, 0, MEM_RELEASE);
    return VERTHYS_OK;

fail:
    VirtualFree(buffer, 0, MEM_RELEASE);
    return VERTHYS_ERR_CORRUPT; /* 缓存损坏，走冷启动路径 */
}
```

### 7.4 性能对比

| 场景 | 冷启动（扫描 SSTable） | 温启动（缓存加载） |
|------|----------------------|-------------------|
| 10,000 条记录 | 8-15ms | 2-4ms |
| 100,000 条记录 | 80-150ms | 15-30ms |
| 1,000,000 条记录 | 800-1500ms | 80-150ms |

---

## 8. P4：流水线调度器设计

### 8.1 解锁流水线状态机

```
┌──────────────────────────────────────────────────────────────┐
│                     Unlock Pipeline Scheduler                 │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐      │
│  │  Stage S1    │   │  Stage S2    │   │  Stage S3    │      │
│  │  超块读取     │   │  Argon2id   │   │  CNG 导入    │      │
│  │  (IO)       │   │  (CPU)      │   │  (Syscall)   │      │
│  │  thread_io  │   │  thread_cpu │   │  thread_main │      │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘      │
│         │                  │                  │              │
│         └──────────────────┴──────────────────┘              │
│                            │                                 │
│                     ┌──────┴───────┐                         │
│                     │  Stage S4    │                         │
│                     │  分区表加载   │                         │
│                     │  (IO+AAD)   │                         │
│                     │  thread_io  │                         │
│                     └──────┬───────┘                         │
│                            │                                 │
│                     ┌──────┴───────┐                         │
│                     │  Stage S5    │                         │
│                     │  索引预热     │                         │
│                     │  (IO+CPU)   │                         │
│                     │  thread_io  │                         │
│                     └──────┬───────┘                         │
│                            │                                 │
│                     ┌──────┴───────┐                         │
│                     │  Stage S6    │                         │
│                     │  最终校验     │                         │
│                     │  thread_main │                         │
│                     └──────────────┘                         │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 8.2 调度器实现

```c
typedef struct UnlockPipeline {
    /* 阶段状态 */
    volatile bool s1_done;
    volatile bool s2_done;
    volatile bool s3_done;
    volatile bool s4_done;
    volatile bool s5_done;

    /* 阶段结果 */
    VerthysResult s1_result;
    VerthysResult s2_result;
    VerthysResult s3_result;
    VerthysResult s4_result;
    VerthysResult s5_result;

    /* 同步 */
    CONDITION_VARIABLE cv_s2_done;   /* S2 完成信号 */
    CONDITION_VARIABLE cv_s3_done;   /* S3 完成信号 */
    CONDITION_VARIABLE cv_s4_done;   /* S4 完成信号 */
    CRITICAL_SECTION lock;

    /* 取消 */
    volatile bool cancel_requested;
} UnlockPipeline;

/* 阶段执行函数（在线程池中运行） */
static void pipeline_stage_s1(void *arg) {
    UnlockPipeline *p = arg;
    p->s1_result = vsb_v3_read_quorum_parallel(...);
    p->s1_done = true;
    /* S1 完成后，如果 S3 也完成，可触发 S4 */
    check_and_start_s4(p);
}

static void pipeline_stage_s2(void *arg) {
    UnlockPipeline *p = arg;
    p->s2_result = verthys_argon2id_derive_v3(...);
    p->s2_done = true;
    WakeConditionVariable(&p->cv_s2_done);
}

static void pipeline_stage_s3(void *arg) {
    UnlockPipeline *p = arg;
    /* 等待 S2 完成 */
    EnterCriticalSection(&p->lock);
    while (!p->s2_done) SleepConditionVariableCS(&p->cv_s2_done, &p->lock, INFINITE);
    LeaveCriticalSection(&p->lock);

    if (p->s2_result != VERTHYS_OK) { p->s3_done = true; return; }
    p->s3_result = verthys_cng_import_keys_batch(...);
    p->s3_done = true;
    /* S3 完成后，如果 S1 也完成，可触发 S4 */
    check_and_start_s4(p);
}

static void pipeline_stage_s4(void *arg) {
    UnlockPipeline *p = arg;
    p->s4_result = verthys_partition_load_v3(...);
    p->s4_done = true;
    /* S4 完成后触发 S5 */
    check_and_start_s5(p);
}

static void pipeline_stage_s5(void *arg) {
    UnlockPipeline *p = arg;
    p->s5_result = warmcache_try_load_or_scan(...);
    p->s5_done = true;
}

/* 主线程等待流水线完成 */
VerthysResult verthys_unlock_pipeline_run(VerthysContext *ctx, const char *password) {
    UnlockPipeline pipeline = {0};
    InitializeCriticalSection(&pipeline.lock);
    InitializeConditionVariable(&pipeline.cv_s2_done);

    /* 启动 S1（IO 线程）和 S2（CPU 线程）并行 */
    thread_pool_submit(pipeline_stage_s1, &pipeline);
    thread_pool_submit(pipeline_stage_s2, &pipeline);

    /* 主线程等待所有阶段完成（带总超时） */
    uint64_t deadline = qpc_now() + VERTHYS_UNLOCK_TIMEOUT_MS * 1000000ULL;
    while (!all_stages_done(&pipeline) && qpc_now() < deadline) {
        Sleep(1); /* 1ms 轮询间隔，实际由条件变量驱动 */
    }

    /* 汇总结果 */
    if (!pipeline.s1_done || !pipeline.s2_done || !pipeline.s3_done ||
        !pipeline.s4_done || !pipeline.s5_done) {
        return VERTHYS_ERR_TIMEOUT;
    }
    /* 检查各阶段错误 */
    if (pipeline.s1_result != VERTHYS_OK) return pipeline.s1_result;
    if (pipeline.s2_result != VERTHYS_OK) return pipeline.s2_result;
    /* ... */

    DeleteCriticalSection(&pipeline.lock);
    return VERTHYS_OK;
}
```

### 8.3 依赖关系矩阵

| 阶段 | 依赖 | 可并行 |
|------|------|--------|
| S1 超块读取 | 无 | S2 |
| S2 Argon2id | 无 | S1 |
| S3 CNG 导入 | S2 | S1（已完成的） |
| S4 分区表 | S1, S3 | S5 的前置 |
| S5 索引预热 | S4 | 无 |
| S6 最终校验 | S5 | 无 |

---

## 9. P5：渐进式解锁与可操作性提前

### 9.1 概念

将解锁拆分为两个可操作状态：

```
Verthys_Unlock(password, flags) → VERTHYS_OK
                              → VERTHYS_ERR_PARTIAL_UNLOCK (可操作但未完全预热)

可操作状态:
  ┌─────────────────────────────────────────────────────┐
  │  OPERATIONAL_MINIMAL:                               │
  │  ├── 超级块已加载并验证                              │
  │  ├── 密钥已导入 CNG（可解密）                        │
  │  ├── 分区表已加载                                   │
  │  └── LSM 索引可用但未完全预热（按需加载 SSTable）     │
  │                                                     │
  │  OPERATIONAL_FULL:                                  │
  │  ├── 所有上者                                       │
  │  ├── LSM 索引完全预热                                │
  │  └── Bloom Filter 全部加载                          │
  └─────────────────────────────────────────────────────┘
```

### 9.2 API 变更

```c
/* Verthys_Unlock flags 扩展 */
#define VERTHYS_UNLOCK_FLAG_INDEX_PREHEATED  (1 << 0)  /* 已完全预热 */
#define VERTHYS_UNLOCK_FLAG_ALLOW_CACHE      (1 << 1)  /* 允许持久化缓存 */
#define VERTHYS_UNLOCK_FLAG_MINIMAL_FIRST    (1 << 2)  /* ★ 新增：先最小可用，后台预热 */

/* 新的返回码 */
#define VERTHYS_ERR_PARTIAL_UNLOCK           (0x13)  /* 可操作但索引未完全预热 */
```

### 9.3 实现流程

```c
VerthysResult Verthys_Unlock(const char *path, const char *password, uint32_t flags) {
    /* ... 前置检查 ... */

    if (flags & VERTHYS_UNLOCK_FLAG_MINIMAL_FIRST) {
        /* 路径 A：最小可操作优先 */
        /* 1. 完成 S1-S4（超块 + Argon2id + CNG + 分区表） */
        VerthysResult r = unlock_minimal(ctx, password);
        if (r != VERTHYS_OK) return r;

        /* 2. 启动后台线程预热索引 */
        thread_pool_submit(index_preheat_background, ctx);

        /* 3. 立即返回 PARTIAL_UNLOCK */
        return VERTHYS_ERR_PARTIAL_UNLOCK;

    } else {
        /* 路径 B：完全解锁（默认，等待预热完成） */
        return unlock_full(ctx, password, flags);
    }
}

/* 后台预热完成后，API 调用自动从按需加载切换为完全预热 */
static void index_preheat_background(void *arg) {
    VerthysContext *ctx = arg;
    VerthysResult r = verthys_lsm_preheat_full(ctx);
    if (r == VERTHYS_OK) {
        ctx->lsm_preheated = true;
        /* 可选：通过回调通知上层 */
        if (ctx->unlock_progress_callback) {
            ctx->unlock_progress_callback(100, 100, ctx->unlock_progress_userdata);
        }
    }
}
```

### 9.4 按需加载（Lazy SSTable Loading）

```c
/* 当索引未完全预热时，查询操作按需加载 SSTable */
VerthysResult verthys_lsm_lookup_lazy(
    VerthysLsmIndex *idx,
    const uint8_t *key, uint32_t key_len,
    VerthysRecordRef *out_ref
) {
    /* 1. 查 MemTable */
    if (memtable_lookup(idx->memtable, key, key_len, out_ref)) {
        return VERTHYS_OK;
    }

    /* 2. 按顺序检查 SSTable */
    for (int level = 0; level < idx->max_level; level++) {
        for (int i = 0; i < idx->sst_count[level]; i++) {
            VerthysSSTable *sst = &idx->sstables[level][i];

            /* 如果 SSTable 未加载，先加载元数据 */
            if (!sst->loaded) {
                VerthysResult r = load_sstable_meta(sst);
                if (r != VERTHYS_OK) continue;
            }

            /* 布隆过滤器快速排除 */
            if (!bloom_filter_may_contain(sst->bloom, key, key_len)) {
                continue;
            }

            /* 在 SSTable 中查找 */
            if (sstable_lookup(sst, key, key_len, out_ref)) {
                return VERTHYS_OK;
            }
        }
    }
    return VERTHYS_ERR_NOTFOUND;
}
```

---

## 10. P6：性能监控与自调节

### 10.1 解锁耗时采集与上报

```c
/* 每次解锁后更新诊断信息 */
static void unlock_record_timing(VerthysContext *ctx, UnlockTiming *timing) {
    ctx->diagnostics.last_unlock_timing = *timing;
    ctx->diagnostics.unlock_count++;

    /* 滑动窗口统计（最近 8 次） */
    memmove(&ctx->diagnostics.unlock_history[1], &ctx->diagnostics.unlock_history[0],
            sizeof(uint64_t) * 7);
    ctx->diagnostics.unlock_history[0] = timing->t_total_ns;

    /* 计算 P50/P95 */
    uint64_t sorted[8];
    memcpy(sorted, ctx->diagnostics.unlock_history, sizeof(sorted));
    qsort(sorted, 8, sizeof(uint64_t), compare_u64);
    ctx->diagnostics.unlock_p50 = sorted[3];
    ctx->diagnostics.unlock_p95 = sorted[6];
}
```

### 10.2 Argon2id 漂移检测与自动降档

```c
/* 解锁后检查 Argon2id 耗时，触发参数自适应 */
static void argon2_drift_check(VerthysContext *ctx, uint64_t argon2_ms, uint32_t used_iters) {
    uint32_t benchmark = ctx->sb.argon2_benchmark_ms[0];  /* 基准 */

    /* 连续超时检测 */
    if (argon2_ms > benchmark * 1.3) {
        ctx->argon2_slow_count++;
    } else {
        ctx->argon2_slow_count = 0;
    }

    /* 连续 3 次超时 30% → 降 1 档 */
    if (ctx->argon2_slow_count >= 3 && used_iters > 1) {
        argon2_downgrade_and_rewrap(ctx, used_iters - 1);
        ctx->argon2_slow_count = 0;
    }

    /* 连续 3 次达标且 < 70% 基准 → 升 1 档 */
    if (argon2_ms < benchmark * 0.7) {
        ctx->argon2_fast_count++;
    } else {
        ctx->argon2_fast_count = 0;
    }
    if (ctx->argon2_fast_count >= 3 && used_iters < VERTHYS_ARGON2_BALANCED_ITERS_MAX) {
        argon2_upgrade_and_rewrap(ctx, used_iters + 1);
        ctx->argon2_fast_count = 0;
    }
}
```

### 10.3 硬件性能降级检测

```c
/* 检测系统负载，决定是否跳过部分优化 */
static bool is_system_under_pressure(void) {
    /* CPU 使用率 > 80% */
    /* 或内存可用 < 200MB */
    /* 或磁盘队列长度 > 4 */
    /* → 返回 true，降级：跳过预取、延迟后台任务 */
}
```

---

## 11. 代码级实现规范

### 11.1 文件结构（新增/修改）

```
core/src/api/
├── verthys_api.c              # 修改：Verthys_Unlock 重构为流水线调用
├── verthys_unlock_pipeline.c  # ★ 新增：解锁流水线调度器
├── verthys_unlock_stages.c    # ★ 新增：各阶段实现（S0-S6）
└── verthys_unlock_timing.c    # ★ 新增：耗时采集与统计

core/src/container/
├── verthys_superblock_v3.c    # 修改：并行副本读取
└── verthys_partition.c        # 修改：延迟加载支持

core/src/index/
├── verthys_lsm.c              # 修改：懒加载 + 温缓存集成
└── verthys_warmcache.c        # ★ 新增：温启动缓存读写

core/src/crypto/
└── verthys_crypto.c           # 修改：Argon2id 校准 v3
```

### 11.2 关键数据结构

```c
/* verthys_unlock_pipeline.h */
typedef enum UnlockStage {
    UNLOCK_STAGE_S0 = 0,
    UNLOCK_STAGE_S1 = 1,
    UNLOCK_STAGE_S2 = 2,
    UNLOCK_STAGE_S3 = 3,
    UNLOCK_STAGE_S4 = 4,
    UNLOCK_STAGE_S5 = 5,
    UNLOCK_STAGE_S6 = 6,
    UNLOCK_STAGE_COUNT = 7,
} UnlockStage;

typedef struct UnlockStageResult {
    VerthysResult result;
    uint64_t start_ns;
    uint64_t end_ns;
    uint32_t sub_steps;       /* 子步骤计数 */
} UnlockStageResult;

typedef struct UnlockPipelineResult {
    UnlockStageResult stages[UNLOCK_STAGE_COUNT];
    uint64_t total_start_ns;
    uint64_t total_end_ns;
    uint32_t cache_hit;
    uint32_t argon2_iters_used;
    bool minimal_first;        /* 是否使用最小可操作模式 */
} UnlockPipelineResult;

/* verthys_unlock_stages.h */
typedef VerthysResult (*UnlockStageFn)(VerthysContext *ctx, UnlockPipeline *pipeline, void *stage_data);
```

### 11.3 错误处理规范

```c
/* 每个阶段错误处理遵循：fail-fast + 资源清理 */
#define UNLOCK_STAGE_BEGIN(name) \
    VerthysResult stage_##name(VerthysContext *ctx, UnlockPipeline *pipeline, void *data) { \
        VerthysResult r = VERTHYS_OK; \
        uint64_t _t0 = qpc_now(); \
        (void)data;

#define UNLOCK_STAGE_END(name, stage_idx) \
        pipeline->stages[stage_idx].end_ns = qpc_now(); \
        pipeline->stages[stage_idx].result = r; \
        return r; \
    }

/* 使用示例： */
UNLOCK_STAGE_BEGIN(s1_superblock)
    r = vsb_v3_read_quorum_parallel(ctx->file_handle, &ctx->sb, &ctx->sb_replica_status);
    if (r != VERTHYS_OK) {
        /* 降级：单副本读取 */
        r = vsb_v3_read_single(ctx->file_handle, 0, &ctx->sb);
    }
UNLOCK_STAGE_END(s1_superblock, UNLOCK_STAGE_S1)
```

### 11.4 线程池接口

```c
/* 解锁专用线程池（与全局后台线程池独立） */
typedef struct UnlockThreadPool {
    HANDLE threads[3];         /* 最多 3 个：IO、CPU、辅助 */
    uint32_t thread_count;
} UnlockThreadPool;

VerthysResult unlock_thread_pool_init(UnlockThreadPool *pool);
void unlock_thread_pool_submit(UnlockThreadPool *pool, void (*fn)(void*), void *arg);
void unlock_thread_pool_wait_all(UnlockThreadPool *pool, uint64_t timeout_ms);
void unlock_thread_pool_destroy(UnlockThreadPool *pool);
```

---

## 12. 测试与验证方案

### 12.1 单元测试

| 测试项 | 覆盖内容 | 文件 |
|--------|---------|------|
| 校准算法 | 三阶段校准、边界条件、硬件差异 | `test_argon2_calibrate_v3.c` |
| 并行副本读取 | 3 副本全好/2 好/1 好/0 好、超时降级 | `test_sb_quorum_parallel.c` |
| 温缓存 | 写入/读取/损坏检测/txid 不匹配 | `test_warmcache_v3.c` |
| 流水线调度 | 依赖正确性、取消、超时 | `test_unlock_pipeline.c` |
| 渐进式解锁 | 最小可操作 → 完全预热过渡 | `test_unlock_minimal.c` |
| 漂移检测 | 连续超时降档、连续快速升档 | `test_argon2_drift.c` |

### 12.2 性能基准测试

```c
/* test_perf_unlock.c */
/* 场景 1：冷启动解锁（无缓存） */
/* 场景 2：温启动解锁（缓存命中） */
/* 场景 3：10 万条记录温启动 */
/* 场景 4：连续 10 次解锁（含 OS 文件缓存） */
/* 场景 5：模拟高系统负载下的解锁 */

/* 每个场景运行 10 次，记录 P50/P95/P99 */
/* 断言：温启动 P50 ≤ 1200ms，P95 ≤ 2500ms */
```

### 12.3 CI 集成

```yaml
# .github/workflows/perf_unlock.yml
perf-unlock:
  runs-on: windows-latest
  steps:
    - name: Build Release
    - name: Run unlock performance tests
      run: verthys_tests.exe perf_unlock
    - name: Check performance thresholds
      run: |
        if (P95 > 2500ms) { exit 1 }
        if (P50_cold > 1800ms) { exit 1 }
        if (P50_warm > 1200ms) { exit 1 }
```

---

## 13. 故障注入与降级路径

### 13.1 故障注入矩阵

| 注入点 | 注入方式 | 预期行为 |
|--------|---------|---------|
| 超级块副本 0 损坏 | 翻转字节 | 并行读自动跳过，使用副本 1/2 |
| 超级块副本 0+1 损坏 | 翻转字节 | 降级为单副本（副本 2），告警 |
| 温缓存 HMAC 失败 | 翻转缓存文件字节 | 忽略缓存，走冷启动路径 |
| Argon2id 超时 | 设置 iters=3 在低端硬件 | 自动降档到 iters=2 |
| CNG 导入失败 | Mock BCryptGenerateSymmetricKey 失败 | 返回 CNG_UNAVAILABLE，不崩溃 |
| 流水线超时 | 模拟慢 IO | 返回 TIMEOUT，清理所有资源 |
| 取消解锁 | 在 S2 执行期间设置取消标志 | 安全中止，清零所有密钥 |

### 13.2 降级路径决策树

```
解锁异常
├── S1 超级块读取超时 (>50ms)
│   ├── 降级：单副本读取 → 继续
│   └── 单副本也失败 → 返回 CORRUPT
├── S2 Argon2id 超时 (>1500ms)
│   ├── 降档：iters-1 → 重试一次
│   └── 仍超时 → 返回 TIMEOUT
├── S3 CNG 导入失败
│   ├── 重试一次（10ms 后）
│   └── 仍失败 → 返回 CNG_UNAVAILABLE
├── S5 索引预热超时 (>500ms)
│   ├── 降级：最小可操作模式（懒加载）
│   └── 后台继续预热
└── S6 最终校验失败
    └── 返回 CORRUPT（不降级）
```

---

## 14. 附录：状态机、常量与检查清单

### 14.1 解锁状态机

```
                    ┌──────────────────┐
                    │   LOCKED         │
                    └────────┬─────────┘
                             │ Verthys_Unlock 调用
                             ▼
                    ┌──────────────────┐
                    │   S0_PRECHECK    │
                    └────────┬─────────┘
                             │ 通过
                    ┌────────┴─────────┐
                    │                  │
                    ▼                  ▼
             ┌────────────┐    ┌────────────┐
             │ S1_READ_SB │    │ S2_ARGON2  │
             │  (并行)     │    │  (并行)    │
             └─────┬──────┘    └─────┬──────┘
                   │                 │
                   └────────┬────────┘
                            │ S2 完成
                            ▼
                    ┌──────────────┐
                    │ S3_CNG_IMPORT│
                    └──────┬───────┘
                           │ S1 和 S3 都完成
                           ▼
                    ┌──────────────┐
                    │ S4_PARTITION │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ S5_INDEX     │
                    │ (温缓存优先)  │
                    └──────┬───────┘
                           │
                     ┌─────┴─────┐
                     │           │
                     ▼           ▼
             ┌────────────┐  ┌────────────┐
             │ S6_FINALIZE│  │ S5_LAZY    │
             │ (完全模式)  │  │ (最小模式)  │
             └─────┬──────┘  └─────┬──────┘
                   │               │
                   ▼               ▼
             ┌──────────────────────────┐
             │   OPERATIONAL_FULL       │
             │   OPERATIONAL_MINIMAL    │
             └──────────────────────────┘
```

### 14.2 解锁性能相关常量

| 常量 | 值 | 说明 |
|------|-----|------|
| `VERTHYS_UNLOCK_TIMEOUT_MS` | 10000 | 解锁总超时 |
| `VERTHYS_SB_READ_TIMEOUT_MS` | 50 | 超级块读取超时 |
| `VERTHYS_ARGON2_TARGET_MS` | 1000 | 校准目标 |
| `VERTHYS_ARGON2_MAX_MS` | 1500 | 解锁期 Argon2id 超时 |
| `VERTHYS_CNG_IMPORT_TIMEOUT_MS` | 100 | CNG 导入超时 |
| `VERTHYS_INDEX_PREHEAT_TIMEOUT_MS` | 500 | 索引预热超时（冷启动） |
| `VERTHYS_WARMCACHE_MAX_BYTES` | 32MB | 温缓存文件最大大小 |
| `VERTHYS_WARMCACHE_HMAC_BYTES` | 32 | 温缓存 HMAC 大小 |
| `VERTHYS_UNLOCK_HISTORY_SLOTS` | 8 | 解锁耗时历史槽位 |
| `VERTHYS_ARGON2_DRIFT_THRESHOLD` | 3 | 连续漂移触发次数 |
| `VERTHYS_ARGON2_SLOW_FACTOR` | 1.3 | 超时判定系数（130%） |
| `VERTHYS_ARGON2_FAST_FACTOR` | 0.7 | 快速判定系数（70%） |

### 14.3 实施检查清单

- [ ] **S0**：pepper 快速失败在 Argon2id 之前执行（避免无谓 CPU 消耗）
- [ ] **S1**：超级块并行读取使用独立 IO 线程，不阻塞主线程
- [ ] **S2**：Argon2id 使用优化实现（libsodium AVX2），校准目标 1000ms
- [ ] **S2**：Argon2id 与 S1 真正并行（不同线程，无锁竞争）
- [ ] **S3**：MEK 明文在导入后立即 `SecureZeroMemory`
- [ ] **S3**：算法句柄在 `Verthys_Init` 时预创建
- [ ] **S4**：分区表验证使用已导入的内核态密钥
- [ ] **S5**：温缓存优先，HMAC+txid 双重校验
- [ ] **S5**：缓存损坏时静默回退冷启动，不报错
- [ ] **S6**：所有资源在失败路径正确释放
- [ ] **流水线**：取消标志在所有阶段检查
- [ ] **监控**：每次解锁耗时采集并更新滑动窗口
- [ ] **漂移**：连续 3 次超时自动降档并 rewrap
- [ ] **测试**：性能基准在 CI 中强制（P95 ≤ 2500ms）
- [ ] **故障注入**：所有降级路径有测试覆盖

---