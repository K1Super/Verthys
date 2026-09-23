/*
 * verthys_v3_lifecycle.h — V3 容器生命周期（创建/打开/锁定）+ 运行时上下文
 *
 * VerthysContextV3 与 VerthysContext 的关系：
 *   - VerthysContext（verthys_internal.h）为 API 层统一句柄体；V3 容器打开后
 *     其 v3 指针指向本结构的堆实例（Init 分配 / Deinit 释放）；
 *   - f / km / verthys_path 为借用引用（生命周期归 VerthysContext）；
 *   - sb / ptable / lsm / ext_idx / wal / txn 为本结构拥有的子系统，
 *     verthys_v3_ctx_subsystems_close 统一收口（失败重试路径与 Lock 共用）。
 *
 * 密钥驻留纪律（红线级）：
 *   - MEK 仅在解锁流水线 S2→S3 交接栈帧瞬态存在（导入 CNG 后立即清零）；
 *   - integrity_key（超级块 HMAC 密钥）驻留本结构，Lock/Deinit 清零；
 *   - A/B/C 与分区密钥全部内核态驻留（km / ptable 内核句柄），
 *     Lock → verthys_cng_km_destroy_all + verthys_partition_table_destroy。
 */
#ifndef VERTHYS_V3_LIFECYCLE_H
#define VERTHYS_V3_LIFECYCLE_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "verthys.h"
#include "verthys_internal.h"          /* VerthysContext / VerthysPreset */
#include "verthys_container_v3.h"      /* VerthysSuperBlockV3 */
#include "verthys_partition.h"         /* VerthysPartitionTable */
#include "verthys_lsm.h"               /* VerthysLsm */
#include "verthys_extent.h"            /* VerthysExtentIndex */
#include "verthys_wal.h"               /* VerthysWal */
#include "verthys_transaction_v3.h"    /* VerthysTxnV3 */
#include "keymanager_cng.h"          /* VerthysCngKeyManager */
#include "verthys_unlock_pipeline.h"   /* UnlockPipelineResult */

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- V3 运行时上下文 ---------- */

typedef struct VerthysContextV3 {
    /* === 借用引用（归上层 VerthysContext 所有） === */
    FILE                *f;           /* 容器文件（"r+b"） */
    VerthysCngKeyManager  *km;          /* CNG 密钥组（= VerthysContext.cng_keys） */
    char                *verthys_path;  /* 容器路径（heap 副本，warmcache 路径用） */
    VerthysPreset          preset;      /* 安全策略预设（创建时持久化于扩展 TLV） */

    /* === 拥有的子系统（verthys_v3_ctx_subsystems_close 统一清理） === */
    VerthysSuperBlockV3    sb;                    /* 超级块内存态（法定人数裁决产物） */
    uint8_t              integrity_key[VERTHYS_KEY_BYTES]; /* 超级块 HMAC 密钥 */
    VerthysPartitionTable  ptable;                /* 分区表（含内核句柄） */
    VerthysLsm            *lsm;                   /* LSM 索引（堆分配） */
    VerthysExtentIndex    *ext_idx;               /* Extent 索引（堆分配） */
    VerthysWal            *wal;                   /* 事务 WAL（堆分配） */
    VerthysTxnV3           txn;                   /* 事务上下文（值嵌入） */
    int                  subsystems_open;       /* 1 = S5 已完成（子系统可用） */

    /* === 解锁流水线状态 === */
    UnlockPipelineResult pipeline;              /* 最近一次流水线结果（诊断） */
    uint32_t             unlock_flags;          /* 本次 Unlock flags 快照 */
    int                  preheated;             /* 1 = 索引完全预热（OPERATIONAL_FULL） */
    int                  minimal_mode;          /* 1 = 渐进式解锁返回（预热进行中） */
    HANDLE               bg_preheat_thread;     /* 后台预热线程（MINIMAL_FIRST） */
    volatile LONG        bg_preheat_running;    /* 后台预热运行标志（Lock 汇合依据） */

    /* === 诊断（Verthys_GetDiagnostics 映射；非敏感指标） === */
    uint64_t             diag_unlock_total_ms;  /* 解锁总耗时 */
    uint64_t             diag_cache_load_ms;    /* 温缓存加载耗时 */
    uint64_t             diag_warm_cache_hits;  /* 温缓存命中次数 */
    uint64_t             diag_warm_cache_misses;/* 温缓存未命中次数 */
    uint32_t             diag_argon2_last_ms;   /* 最近一次 Argon2id 耗时 */
} VerthysContextV3;

/* ---------- 上下文分配 / 释放 ---------- */

/*
 * 分配并初始化 V3 上下文（全部子系统零态；km 为 NULL 时由本函数初始化
 * 调用方提供的 VerthysCngKeyManager——verthys_cng_km_init）。
 * verthys_path 深拷贝（失败返回 NULL）。
 * 返回堆实例；失败（内存耗尽）返回 NULL。
 */
VerthysContextV3 *verthys_v3_ctx_create(VerthysCngKeyManager *km,
                                    FILE *f, const char *verthys_path);

/*
 * 释放 V3 上下文：等待后台预热线程退出 → 关闭全部子系统 →
 * integrity_key 清零 → 释放路径副本 → free。
 * 幂等（NULL 直接返回）。
 */
void verthys_v3_ctx_destroy(VerthysContextV3 *ctx3);

/*
 * 关闭全部子系统并回到可重试初态（失败路径资源纪律）：
 *   txn deinit → WAL close → LSM close → 分区表 destroy（内核句柄）→
 *   km destroy_all → integrity_key 清零 → subsystems_open=0。
 * 已打开的后台预热线程先汇合。幂等。
 */
void verthys_v3_ctx_subsystems_close(VerthysContextV3 *ctx3);

/* ---------- 容器生命周期 ---------- */

/*
 * 创建 V3 容器（系统唯一合法新建入口）：
 *   1. Argon2id 三档校准（目标 1s 预算跑分
 *      mem/iters/parallel，基准值记入 sb.argon2_benchmark_ms）；
 *   2. 密钥组生成：MEK/A/B/C 随机（A/B/C 由 MEK 内核态加密 wrap）；
 *   3. vsb_v3_init_new + 字段填充（salt/参数/密钥包装/分区布局默认值）；
 *   4. 分区表创建（INDEX/EXTENT/AUDIT 三分区，独立随机密钥）；
 *   5. 超级块法定人数提交（首版 txid=0）+ 分区表持久化；
 *   6. 子系统打开（LSM/WAL/Extent 索引空态初始化 + txn init）。
 * 成功后容器处于已解锁状态（subsystems_open=1）。
 *
 * 前置：文件不存在（CreateFileA CREATE_NEW 原子创建，TOCTOU 防护）。
 */
VerthysResult verthys_v3_create_new(VerthysContextV3 *ctx3,
                                const char *password, size_t pw_len,
                                VerthysPreset preset);

/*
 * 打开（解锁）V3 容器：verthys_unlock_pipeline_run 全权承担
 * （S0-S6 + 渐进式解锁 + 总超时）。本函数为流水线的编排薄壳：
 *   - 密码错误退避（连续失败指数退避）由上层 Verthys_Unlock
 *     统一处理，本层不感知；
 *   - 返回值透传流水线结果（VERTHYS_OK / PARTIAL_UNLOCK / 各阶段错误 /
 *     TIMEOUT）。
 */
__declspec(noinline) VerthysResult verthys_v3_open_existing(VerthysContextV3 *ctx3,
                                   const char *password, size_t pw_len,
                                   uint32_t flags,
                                   void (*progress_cb)(uint32_t stage,
                                                       uint32_t percent,
                                                       void *user),
                                   void *progress_user);

/*
 * 锁定 V3 容器：
 *   1. 等待后台预热线程退出（MINIMAL_FIRST 场景）；
 *   2. 事务 CONFIRM 收尾（若 COMMITTED 态）或回滚（ACTIVE/PREPARED 态）；
 *   3. LSM close（MemTable flush + Manifest 保存 + WAL 复位）；
 *   4. 温缓存写入（Lock 同步写；preset=SECURE 跳过）；
 *   5. subsystems_close（WAL/分区表/CNG 句柄全量销毁 + 密钥清零）。
 */
VerthysResult verthys_v3_lock(VerthysContextV3 *ctx3);

/*
 * V3 格式探测（Verthys_Unlock 分发用）：
 * 读取文件首 8 字节，帧头 magic == 'V3RP' 且 payload_len 合法 → 1；
 * 否则 0（非 V3 容器）。f 为已打开文件（只读探测，
 * 探测后由调用方 fseek 复位）。
 */
int verthys_v3_detect(FILE *f);

/* 温缓存是否被预设禁用（SECURE=1 → 禁用） */
int verthys_v3_warmcache_disabled_by_preset(VerthysPreset preset);

/* ---------- V3 单调用事务收口（API 编排层共享，export/import 复用） ---------- */

/*
 * V3 单调用事务收口：统一推进（PREPARE → COMMIT → CONFIRM）。
 * 返回 VERTHYS_OK = CONFIRM 完成（终态 CONFIRMED）；非 0 = 透传错误码。
 * COMMIT 后失败（confirm 失败）：数据已持久（法定人数语义），不可回滚，
 * 由下次 open 的崩溃恢复路径幂等收尾——错误直接上抛。
 */
VerthysResult verthys_v3_txn_finish(VerthysContextV3 *ctx3);

/*
 * V3 事务失败收口（AddRecord / DeleteRecord / DeleteRecords / Import 共用）：
 * ACTIVE/PREPARED → rollback（MemTable/WAL 精确撤销 + Extent 引用还原）；
 * COMMITTED → confirm 兜底（法定人数已持久，幂等补存）；IDLE → no-op。
 */
void verthys_v3_txn_abort(VerthysContextV3 *ctx3);

/*
 * V3 单记录事务内写入（AddRecord / Import 共用的事务写骨架）：
 *   WRITE_EXTENT（内容寻址去重，hash 回传供索引关联）→ 权威尺寸回查
 *   （verthys_extent_index_find）→ LID = max_lid + 1 顺序分配（LID 永不复用，
 *   红线语义）→ UPDATE_INDEX（created_txid 由事务层统一绑定当前事务）。
 * created_time 取当前 Unix 时间戳（前端排序字段）。
 * 前置：subsystems_open 且 txn 处于 ACTIVE（BEGIN 已完成）。
 * 失败语义：事务保持 ACTIVE（零收口），由调用方决定 abort——本函数
 * 不触碰 abort/finish，支持批量导入的"单事务多记录"编排。
 * out_lid 可为 NULL；name_len ≤ VERTHYS_NAME_MAX_BYTES（LSM 条目约束）。
 */
VerthysResult verthys_v3_add_record_in_txn(VerthysContextV3 *ctx3,
                                       uint8_t type,
                                       const uint8_t *name, size_t name_len,
                                       const uint8_t *data, size_t data_size,
                                       uint64_t *out_lid);

/*
 * 修改主密码（V3，ChangePassword 分支）：
 *   1. 旧口令验证：V3 域分离派生（超块参数，与解锁 S2 同函数同参数）→
 *      verthys_cng_km_verify_mek 对 wrapped_key_a 内核态解包试探（AEAD
 *      认证即口令正确；密钥仅瞬态，全程无驻留比对）；
 *   2. 新口令派生：新盐随机 + 沿用超块 Argon2id 参数（改密不调档，
 *      与 v2 路径语义一致）→ 新 MEK + 新 integrity_key；
 *   3. 密钥组重包裹：A/B/C 明文不变仅换 MEK 包装（verthys_cng_km_rekey，
 *      km 句柄零变更——三态一致的提交顺序约束）；
 *   4. 超级块事务（VsbTxnV3）：备份 → salt / wrapped_* / updated_at 变更
 *      → 法定人数原子提交（HMAC 以新 integrity_key 计算——新口令派生
 *      语境，下次解锁 S1-S4 恰好闭环）；任一步失败回滚内存态（盘面
 *      半写由读侧法定人数 + HMAC 兜底）；
 *   5. 提交成功收尾（盘面已持新口令语境，回滚不可行）：
 *      integrity_key 先行更新（驻留值 + 事务上下文拷贝——后续任何
 *      超级块提交必须以新口令语境签名）→ 温缓存失效（HMAC 绑定旧
 *      integrity_key）→ MEK 句柄轮换（旧销毁 → 新导入；失败仅致 MEK
 *      角色空缺，运行态 A/B/C 不受影响，下次解锁按新口令重建全组）。
 * 前置：subsystems_open 且 txn 处于终态（IDLE/CONFIRMED/ABORTED——
 * V3 单调用事务在 API 间隙的必然状态；COMMITTED 则幂等补 confirm 后
 * 拒绝本次改密，调用方重试即可）。
 * 返回：VERTHYS_OK / VERTHYS_ERR_AUTH（旧口令错误）/ VERTHYS_ERR_PEPPER_SOURCE /
 * VERTHYS_ERR_LOCKED / VERTHYS_ERR_IO（法定人数不满足）/ 各子系统错误透传。
 */
VerthysResult verthys_v3_change_password(VerthysContextV3 *ctx3,
                                      const char *old_pw, size_t old_len,
                                      const char *new_pw, size_t new_len);

/* ---------- 预设 TLV 扩展区（超级块 extensions） ---------- */

/*
 * TLV 布局：[u8 tag][u8 len][len × value]，顺序拼接至 extensions_len。
 *   tag 0x01 = 安全策略预设（len=1，value = VerthysPreset 枚举值）
 * 未知 tag 跳过（前向兼容）；len 越界（越过 extensions_len）→ FORMAT。
 */
#define VERTHYS_V3_TLV_TAG_PRESET   0x01u

/*
 * 编码预设 TLV 到 buf（容量 ≥ 3；*out_len 回传 3）。
 * preset 合法域 [0,3]，越界返回 VERTHYS_ERR_INVALID。
 */
VerthysResult verthys_v3_preset_encode(uint8_t *buf, size_t cap,
                                   uint32_t *out_len, VerthysPreset preset);

/*
 * 解码预设 TLV：扫描 extensions，tag 0x01 且 len=1 → *out = value；
 * 未找到（含空扩展区）→ VERTHYS_OK 且 *out = VERTHYS_PRESET_BALANCED（缺省）；
 * 结构非法（len 越界 / value 越域）→ VERTHYS_ERR_FORMAT。
 */
VerthysResult verthys_v3_preset_decode(const uint8_t *extensions, uint32_t len,
                                   VerthysPreset *out);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_V3_LIFECYCLE_H */
