/*
 * verthys_unlock_pipeline.h — V3 解锁流水线调度器（S0-S6）
 *
 * 阶段语义（状态机）：
 *   S0 前置检查      主线程   参数/状态机/emergency 门控/pepper 快速失败
 *   S1 超级块读取    IO 线程  3 副本并行读取（50ms 预算）+ 无校验结构化
 *                            解析（vsb_v3_parse_unverified——salt/Argon2
 *                            参数就绪即可唤醒 S2，HMAC 验证后置 S3）
 *   S2 Argon2id 派生 CPU 线程 DKM = Argon2id(pw‖pepper, salt, params) →
 *                            MEK = HKDF(DKM, "verthys/master-key-v3") →
 *                            DKM 清零（红线：明文仅本阶段栈帧瞬态）
 *   S3 CNG 导入+法定人数  主线程（等 S2）
 *                            integrity_key = HKDF(MEK, integrity-key) →
 *                            3 候选副本逐一 HMAC 验证 + 法定人数裁决
 *                            （≥2 一致）→ verthys_cng_km_import_batch
 *                            （MEK 导入后立即清零）
 *   S4 分区表加载    主线程（等 S1+S3）verthys_partition_table_load
 *   S5 索引预热      主线程（等 S4）温缓存优先（HMAC+txid 双校验，
 *                            命中走 verthys_lsm_open_warm）→ 未命中冷启动
 *                            verthys_lsm_open；WAL 打开 + Extent 索引加载 +
 *                            事务崩溃恢复（verthys_txn_v3_recover）
 *   S6 最终校验      主线程   子系统就绪标志 + 计时汇总
 *
 * 渐进式解锁（flags & VERTHYS_UNLOCK_FLAG_MINIMAL_FIRST）：
 *   S0-S4 完成即达 OPERATIONAL_MINIMAL（超块验证 + 密钥导入 + 分区表），
 *   S5 仅做最小可操作部分（WAL/LSM 惰性 open/Extent/恢复），全量索引
 *   预热（verthys_lsm_preheat_full）转后台线程，立即返回
 *   VERTHYS_ERR_PARTIAL_UNLOCK。
 *
 * 超时预算：总预算 VERTHYS_UNLOCK_TIMEOUT_MS = 10s；任一阶段
 * 未在预算内完成 → VERTHYS_ERR_TIMEOUT（无部分写入副作用，可安全重试）。
 *
 * 故障注入：fail_mask bit i = 阶段 i 强制失败（仅测试使用，生产传 0）。
 */
#ifndef VERTHYS_UNLOCK_PIPELINE_H
#define VERTHYS_UNLOCK_PIPELINE_H

#include <stdint.h>
#include <stddef.h>
#include "verthys.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 常量 ---------- */

#define VERTHYS_UNLOCK_TIMEOUT_MS          10000u  /* 解锁总超时 */
#define VERTHYS_SB_READ_TIMEOUT_MS         50u     /* 超级块读取（并行 3 副本） */
#define VERTHYS_ARGON2_TARGET_MS           1000u   /* 校准目标 */
#define VERTHYS_ARGON2_MAX_MS              1500u   /* 解锁期 Argon2id 超时 */
#define VERTHYS_CNG_IMPORT_TIMEOUT_MS      100u    /* CNG 导入超时 */
#define VERTHYS_INDEX_PREHEAT_TIMEOUT_MS   500u    /* 索引预热超时（冷启动） */
#define VERTHYS_WARMCACHE_MAX_BYTES        (32u * 1024u * 1024u) /* 32MB */
#define VERTHYS_WARMCACHE_HMAC_BYTES       32u

/* ---------- 阶段标识 ---------- */

typedef enum UnlockStage {
    UNLOCK_STAGE_S0 = 0,      /* 前置检查 */
    UNLOCK_STAGE_S1 = 1,      /* 超级块读取（并行副本 + 无校验解析） */
    UNLOCK_STAGE_S2 = 2,      /* Argon2id 派生 */
    UNLOCK_STAGE_S3 = 3,      /* CNG 导入 + 法定人数验证 */
    UNLOCK_STAGE_S4 = 4,      /* 分区表加载 */
    UNLOCK_STAGE_S5 = 5,      /* 索引预热（温缓存优先）+ 崩溃恢复 */
    UNLOCK_STAGE_S6 = 6,      /* 最终校验 */
    UNLOCK_STAGE_COUNT = 7
} UnlockStage;

typedef struct UnlockStageResult {
    VerthysResult result;
    uint64_t    start_ns;     /* QueryPerformanceCounter（ns 换算） */
    uint64_t    end_ns;
    uint32_t    sub_steps;    /* 子步骤计数（如 S1 有效副本数） */
} UnlockStageResult;

typedef struct UnlockPipelineResult {
    UnlockStageResult stages[UNLOCK_STAGE_COUNT];
    uint64_t    total_start_ns;
    uint64_t    total_end_ns;
    uint32_t    cache_hit;       /* 1 = 温缓存命中 */
    uint32_t    argon2_iters_used;
    int         minimal_first;   /* 是否使用最小可操作模式 */
} UnlockPipelineResult;

/* 前向声明（定义于 verthys_v3_lifecycle.h） */
struct VerthysContextV3;

/*
 * 运行解锁流水线（verthys_v3_open 调用；非公共 ABI）。
 *
 * [in,out] ctx           V3 上下文（f 已打开 "r+b"；sb/km/子系统由本函数填充）
 * [in]     password      口令（可为 NULL 仅当 pw_len==0）
 * [in]     pw_len        口令字节数
 * [in]     flags         VERTHYS_UNLOCK_FLAG_* 位域
 * [in]     fail_mask     故障注入（bit i = 阶段 i 失败；生产恒 0）
 * [in]     progress_cb   进度回调（可为 NULL）
 * [in]     progress_user 回调透传
 *
 * 返回：VERTHYS_OK / VERTHYS_ERR_PARTIAL_UNLOCK（MINIMAL_FIRST 且后台预热已
 * 排程）/ 各阶段错误透传 / VERTHYS_ERR_TIMEOUT（总预算耗尽）。
 *
 * 失败路径资源纪律：任一阶段失败 → 已导入 CNG 句柄销毁、
 * MEK/integrity_key 清零、已打开子系统关闭，ctx 回到可重试初态。
 */
__declspec(noinline) VerthysResult verthys_unlock_pipeline_run(struct VerthysContextV3 *ctx,
                                      const char *password, size_t pw_len,
                                      uint32_t flags,
                                      uint32_t fail_mask,
                                      void (*progress_cb)(uint32_t stage,
                                                          uint32_t percent,
                                                          void *user),
                                      void *progress_user);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_UNLOCK_PIPELINE_H */
