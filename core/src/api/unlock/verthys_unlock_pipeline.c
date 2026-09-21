/*
 * verthys_unlock_pipeline.c — V3 解锁流水线调度器实现（S0-S6）
 *
 * 调度模型（依赖关系矩阵的关键路径实现）：
 *   S1（IO 线程）与 S2（CPU 线程）并行——S2 经 S1 早期结果
 *   （vsb_v3_parse_unverified 产物：salt / Argon2 参数）唤醒后进入
 *   Argon2id 派生（~1s CPU 密集），S2 派生期间主线程空闲等待；
 *   S3-S6 依赖链严格串行（S3 等 S2、S4 等 S1+S3、S5 等 S4、S6 等 S5），
 *   于主线程顺序执行。两线程模型已覆盖全部可并行度：S4 无法与 S3
 *   重叠（分区表加载依赖 S3 导入的 A 角色密钥语境），S5/S6 依次依赖
 *   前序产物，并行化无收益（线程池形态与本模型
 *   在关键路径上等价）。
 *
 * FILE* 并发纪律：vio_pread64（_fseeki64 + fread）在同一 FILE* 上非
 * 线程安全——S1 线程运行期间主线程不触碰 f（S2 纯 CPU 不触盘），
 * S1 汇合后全部 I/O 回归主线程单线程序列。
 *
 * 密钥驻留纪律（红线级）：
 *   - DKM：keymanager_derive_master_v3 栈帧内瞬态（Argon2id 输出 →
 *     HKDF → MEK 后清零，模块内完成）；
 *   - MEK：pipeline.mek（S2 线程写 → S3 主线程读，CRITICAL_SECTION
 *     内存屏障）→ CNG 导入成功后立即清零；任一失败路径同样清零；
 *   - integrity_key：S3 派生 → HMAC 验证 + ctx3 驻留（Lock/Deinit
 *     由 verthys_v3_ctx_subsystems_close 清零）。
 *
 * 超时预算：总预算 VERTHYS_UNLOCK_TIMEOUT_MS=10s（QPC 单调），
 * 各等待点以剩余预算驱动（SleepConditionVariableCS 超时值）；阶段间
 * 检查总截止——超时返回 VERTHYS_ERR_TIMEOUT，S5 前无任何盘面写入
 * 副作用（S5 的 open 路径仅读 + Manifest 空区初始化），可安全重试。
 * Argon2id 不可中断：超时判定发生在派生返回后（拒绝使用其产物），
 * 线程汇合后才返回（栈上 pipeline 状态不被悬挂线程触碰）。
 */
#include "verthys_unlock_pipeline.h"
#include "verthys_v3_lifecycle.h"
#include "verthys_warmcache_v3.h"
#include "verthys_container_v3.h"
#include "verthys_extent.h"
#include "keymanager.h"
#include "keymanager_cng.h"
#include "verthys_pepper.h"
#include "verthys_crypto.h"
#include "verthys_internal.h"
#include "emergency.h"

#include <stdlib.h>
#include <string.h>

/* ---------- 内部常量 ---------- */

/* 副本帧头字节数（verthys_superblock_v3.c 帧惯例：[u32 magic][u32 payload_len]） */
#define UPL_REPLICA_FRAME_HEADER_BYTES 8u

/* 进度回调百分比（阶段粒度，v2 通知语义延续） */
#define UPL_PCT_S0_START    0u
#define UPL_PCT_S1_START    5u
#define UPL_PCT_S1_DONE     15u
#define UPL_PCT_S2_DONE     45u
#define UPL_PCT_S3_DONE     60u
#define UPL_PCT_S4_DONE     70u
#define UPL_PCT_S5_DONE     92u
#define UPL_PCT_S6_DONE     100u

/* ---------- 计时（QPC → ns，除法先做防溢出） ---------- */

static uint64_t upl_now_ns(void)
{
    static LARGE_INTEGER freq;
    static int freq_ready = 0;
    LARGE_INTEGER now;

    if (!freq_ready) {
        if (!QueryPerformanceFrequency(&freq) || freq.QuadPart <= 0) {
            freq.QuadPart = 10000000;   /* 兜底：100ns 粒度 */
        }
        freq_ready = 1;
    }
    if (!QueryPerformanceCounter(&now)) return 0;

    return (uint64_t)((now.QuadPart / freq.QuadPart) * 1000000000ULL) +
           (uint64_t)(((now.QuadPart % freq.QuadPart) * 1000000000ULL) /
                      (uint64_t)freq.QuadPart);
}

/* 距总预算截止的剩余毫秒（0 = 已耗尽） */
static uint64_t upl_remaining_ms(uint64_t deadline_ns)
{
    uint64_t now = upl_now_ns();
    if (now >= deadline_ns) return 0;
    return (deadline_ns - now) / 1000000ULL;
}

static void upl_emit(void (*cb)(uint32_t, uint32_t, void *), void *user,
                     uint32_t stage, uint32_t percent)
{
    if (cb != NULL) cb(stage, percent, user);
}

/* ---------- 流水线内部状态 ---------- */

typedef struct UnlockPipelineState {
    /* 输入（主线程设置；阶段线程只读） */
    VerthysContextV3  *ctx3;
    const char      *password;        /* 借用（调用方持有整个 run 期间） */
    size_t           pw_len;
    uint32_t         flags;
    uint32_t         fail_mask;
    void           (*progress_cb)(uint32_t stage, uint32_t percent, void *user);
    void            *progress_user;
    uint64_t         deadline_ns;     /* 总预算截止（QPC ns） */

    /* 同步（S1/S2 线程与主线程） */
    CRITICAL_SECTION    lock;
    CONDITION_VARIABLE  cv_s1;        /* S1 完成（早期结果就绪） */
    CONDITION_VARIABLE  cv_s2;        /* S2 完成 */
    int                 cs_valid;     /* 1 = lock 已初始化（Delete 依据） */
    int                 s1_done;
    int                 s2_done;

    /* S1 产物（S1 线程写 → cv_s1 屏障 → S2/S3 主线程读）。
     * ★ 对齐红线：载荷起点（frames[i]+8 帧头偏移）传入 flatcc verifier，
     * u64 字段按物理地址 8 字节对齐校验 —— 本数组在结构体内偏移不受
     * 自然对齐保证（uint8_t 按 1 对齐），必须显式 8 对齐声明。 */
    VERTHYS_V3_FLATBUF_ALIGN
    uint8_t           frames[VERTHYS_V3_SB_REPLICA_COUNT][VERTHYS_V3_SB_REPLICA_BYTES];
    size_t            frame_len[VERTHYS_V3_SB_REPLICA_COUNT];  /* 0 = 副本不可读 */
    int               frame_valid[VERTHYS_V3_SB_REPLICA_COUNT]; /* 结构有效 + 参数在域 */
    VerthysSuperBlockV3 sb_candidates[VERTHYS_V3_SB_REPLICA_COUNT];
    unsigned          valid_count;
    int               early_idx;      /* S2 派生候选（-1 = 无有效副本） */
    VerthysResult       s1_result;

    /* S2 产物（S2 线程写 → cv_s2 屏障 → S3 主线程读后立即清零） */
    uint8_t           mek[VERTHYS_KEY_BYTES];
    int               mek_valid;
    VerthysResult       s2_result;

    /* 阶段计时（ctx3->pipeline 的本地镜像，run 尾部整体回填） */
    UnlockPipelineResult res;
} UnlockPipelineState;

/* ---------- S1 前置校验 ---------- */

/* Argon2id 参数域校验（verthys_crypto.h 规范范围；防篡改参数 DoS） */
static int upl_sb_params_in_range(const VerthysSuperBlockV3 *sb)
{
    return sb->argon2_mem_kib >= VERTHYS_ARGON2_MEM_KIB_MIN &&
           sb->argon2_mem_kib <= VERTHYS_ARGON2_MEM_KIB_MAX &&
           sb->argon2_iters   >= VERTHYS_ARGON2_ITERS_MIN &&
           sb->argon2_parallel >= VERTHYS_ARGON2_PARALLEL_MIN &&
           sb->argon2_parallel <= VERTHYS_ARGON2_PARALLEL_MAX;
}

/* 派生输入一致性（salt + Argon2 参数 + pepper 来源） */
static int upl_sb_derive_params_equal(const VerthysSuperBlockV3 *a,
                                      const VerthysSuperBlockV3 *b)
{
    return a->argon2_mem_kib == b->argon2_mem_kib &&
           a->argon2_iters   == b->argon2_iters &&
           a->argon2_parallel == b->argon2_parallel &&
           a->pepper_source  == b->pepper_source &&
           memcmp(a->salt, b->salt, VERTHYS_V3_SALT_BYTES) == 0;
}

/*
 * S2 派生候选选择（法定人数精神的前置近似）：
 *   1. salt+参数多数派（≥2 一致）中取最高 txid；
 *   2. 无多数派 → 最高 txid 单副本（篡改场景由 S3 HMAC 闭环拒绝——
 *      错误 salt → 错误 MEK → 超块 HMAC 验证失败，认证不可绕过）。
 */
static void upl_select_early_candidate(UnlockPipelineState *p)
{
    int chosen = -1;

    for (unsigned i = 0; i < VERTHYS_V3_SB_REPLICA_COUNT; i++) {
        if (!p->frame_valid[i]) continue;
        unsigned agree = 0;
        for (unsigned j = 0; j < VERTHYS_V3_SB_REPLICA_COUNT; j++) {
            if (p->frame_valid[j] &&
                upl_sb_derive_params_equal(&p->sb_candidates[i],
                                           &p->sb_candidates[j])) {
                agree++;
            }
        }
        if (agree >= 2 &&
            (chosen < 0 || p->sb_candidates[i].txid > p->sb_candidates[chosen].txid)) {
            chosen = (int)i;
        }
    }
    if (chosen < 0) {
        for (unsigned i = 0; i < VERTHYS_V3_SB_REPLICA_COUNT; i++) {
            if (p->frame_valid[i] &&
                (chosen < 0 ||
                 p->sb_candidates[i].txid > p->sb_candidates[chosen].txid)) {
                chosen = (int)i;
            }
        }
    }
    p->early_idx = chosen;
}

/* ---------- S1：超级块读取（IO 线程） ---------- */

static DWORD WINAPI upl_stage_s1(LPVOID param)
{
    UnlockPipelineState *p = (UnlockPipelineState *)param;
    VerthysResult r = VERTHYS_OK;
    uint64_t t_start = upl_now_ns();

    p->res.stages[UNLOCK_STAGE_S1].start_ns = t_start;
    p->res.stages[UNLOCK_STAGE_S1].sub_steps = 0;

    if ((p->fail_mask >> UNLOCK_STAGE_S1) & 1u) {
        r = VERTHYS_ERR_INTERNAL;
        goto done;
    }

    /* 3 副本读取 + 无校验结构化解析（50ms 预算，逐副本截止检查） */
    for (unsigned i = 0; i < VERTHYS_V3_SB_REPLICA_COUNT; i++) {
        size_t plen = 0;
        p->frame_len[i] = 0;
        p->frame_valid[i] = 0;

        {
            VerthysResult rr = vsb_v3_read_replica(p->ctx3->f, i, p->frames[i], &plen);
            if (rr == VERTHYS_OK) {
                VerthysResult pr = vsb_v3_parse_unverified(
                    p->frames[i] + UPL_REPLICA_FRAME_HEADER_BYTES,
                    plen, &p->sb_candidates[i]);
                if (pr == VERTHYS_OK &&
                    upl_sb_params_in_range(&p->sb_candidates[i])) {
                    p->frame_len[i] = plen;
                    p->frame_valid[i] = 1;
                    p->valid_count++;
                }
            }
        }
        if (upl_remaining_ms(p->deadline_ns) == 0) {
            r = VERTHYS_ERR_TIMEOUT;
            goto done;
        }
    }
    p->res.stages[UNLOCK_STAGE_S1].sub_steps = p->valid_count;

    if (p->valid_count == 0) {
        /* 0 副本结构有效（槽位缺失/帧头非法/verifier 拒绝）→ CORRUPT
         *（与 vsb_v3_read_quorum 0 有效语义一致） */
        r = VERTHYS_ERR_CORRUPT;
        goto done;
    }

    upl_select_early_candidate(p);
    if (p->early_idx < 0) {
        r = VERTHYS_ERR_CORRUPT;
        goto done;
    }

done:
    p->s1_result = r;
    p->res.stages[UNLOCK_STAGE_S1].result = r;
    p->res.stages[UNLOCK_STAGE_S1].end_ns = upl_now_ns();

    EnterCriticalSection(&p->lock);
    p->s1_done = 1;
    WakeAllConditionVariable(&p->cv_s1);
    LeaveCriticalSection(&p->lock);
    return 0;
}

/* ---------- S2：Argon2id 派生（CPU 线程） ---------- */

static DWORD WINAPI upl_stage_s2(LPVOID param)
{
    UnlockPipelineState *p = (UnlockPipelineState *)param;
    uint64_t t_start = upl_now_ns();
    uint8_t salt[VERTHYS_V3_SALT_BYTES];
    uint32_t mem_kib, iters, parallel;
    int early_idx;
    int rc;

    p->res.stages[UNLOCK_STAGE_S2].start_ns = t_start;

    if ((p->fail_mask >> UNLOCK_STAGE_S2) & 1u) {
        p->s2_result = VERTHYS_ERR_INTERNAL;
        goto done;
    }

    /* 等 S1 早期结果（salt/参数就绪；总预算内等待） */
    EnterCriticalSection(&p->lock);
    for (;;) {
        if (p->s1_done) break;
        uint64_t rem = upl_remaining_ms(p->deadline_ns);
        if (rem == 0) {
            p->s2_result = VERTHYS_ERR_TIMEOUT;
            break;
        }
        if (!SleepConditionVariableCS(&p->cv_s1, &p->lock, (DWORD)rem)) {
            if (GetLastError() == ERROR_TIMEOUT) {
                p->s2_result = VERTHYS_ERR_TIMEOUT;
                break;
            }
        }
    }
    early_idx = p->early_idx;
    if (p->s2_result == VERTHYS_OK && p->s1_result != VERTHYS_OK) {
        p->s2_result = p->s1_result;    /* S1 失败透传（快速退出） */
    }
    if (p->s2_result == VERTHYS_OK && early_idx < 0) {
        p->s2_result = VERTHYS_ERR_CORRUPT;
    }
    if (p->s2_result == VERTHYS_OK) {
        memcpy(salt, p->sb_candidates[early_idx].salt, sizeof(salt));
        mem_kib  = p->sb_candidates[early_idx].argon2_mem_kib;
        iters    = p->sb_candidates[early_idx].argon2_iters;
        parallel = p->sb_candidates[early_idx].argon2_parallel;
    }
    LeaveCriticalSection(&p->lock);

    if (p->s2_result != VERTHYS_OK) goto done;

    /*
     * DKM = Argon2id(pw‖pepper, salt, params) → MEK = HKDF(DKM, v3 标签)。
     * DKM 在 keymanager 栈帧内瞬态清零；MEK 写入 pipeline.mek（S3 导入
     * CNG 后由主线程清零）。返回 -2 = pepper 来源错误。
     */
    rc = keymanager_derive_master_v3(p->mek, p->password, p->pw_len,
                                     salt, mem_kib, iters, parallel);
    verthys_secure_zero(salt, sizeof(salt));
    if (rc == -2) {
        p->s2_result = VERTHYS_ERR_PEPPER_SOURCE;
        goto done;
    }
    if (rc != 0) {
        p->s2_result = VERTHYS_ERR_INTERNAL;
        goto done;
    }
    p->mek_valid = 1;
    p->s2_result = VERTHYS_OK;
    p->res.argon2_iters_used = iters;

done:
    p->res.stages[UNLOCK_STAGE_S2].result = p->s2_result;
    p->res.stages[UNLOCK_STAGE_S2].end_ns = upl_now_ns();

    EnterCriticalSection(&p->lock);
    p->s2_done = 1;
    WakeAllConditionVariable(&p->cv_s2);
    LeaveCriticalSection(&p->lock);
    return 0;
}

/* ---------- 线程汇合工具 ---------- */

static void upl_join_thread(HANDLE *h)
{
    if (h == NULL || *h == NULL) return;
    WaitForSingleObject(*h, INFINITE);
    CloseHandle(*h);
    *h = NULL;
}

/* 主线程等待标志位（总预算内；超时返回 0） */
static int upl_wait_flag(UnlockPipelineState *p, CONDITION_VARIABLE *cv,
                         volatile int *flag)
{
    int ok = 0;
    EnterCriticalSection(&p->lock);
    while (!*flag) {
        uint64_t rem = upl_remaining_ms(p->deadline_ns);
        if (rem == 0) break;
        if (!SleepConditionVariableCS(cv, &p->lock, (DWORD)rem)) {
            if (GetLastError() == ERROR_TIMEOUT) break;
        }
    }
    ok = *flag;
    LeaveCriticalSection(&p->lock);
    return ok;
}

/* ---------- S3：CNG 导入 + 法定人数验证（主线程，等 S2） ---------- */

static VerthysResult upl_stage_s3(UnlockPipelineState *p)
{
    VerthysContextV3 *ctx3 = p->ctx3;
    VerthysSuperBlockV3 verified[VERTHYS_V3_SB_REPLICA_COUNT];
    int hmac_valid[VERTHYS_V3_SB_REPLICA_COUNT] = {0, 0, 0};
    unsigned valid_count = 0;
    int chosen = -1;
    uint8_t integrity_key[VERTHYS_KEY_BYTES];
    VerthysResult r;

    p->res.stages[UNLOCK_STAGE_S3].start_ns = upl_now_ns();

    if ((p->fail_mask >> UNLOCK_STAGE_S3) & 1u) {
        r = VERTHYS_ERR_INTERNAL;
        goto fail;
    }

    /* 1. integrity_key = HKDF-Expand(MEK, "verthys/integrity-key-v3") */
    if (keymanager_derive_integrity_key_v3(integrity_key, p->mek) != 0) {
        r = VERTHYS_ERR_INTERNAL;
        goto fail_zero_ik;   /* 派生中断可能残留部分密钥材料 */
    }

    /* 2. 3 候选副本逐一 HMAC 验证（vsb_v3_parse：verifier + 自排除 HMAC） */
    for (unsigned i = 0; i < VERTHYS_V3_SB_REPLICA_COUNT; i++) {
        if (!p->frame_valid[i]) continue;
        if (vsb_v3_parse(p->frames[i] + UPL_REPLICA_FRAME_HEADER_BYTES,
                         p->frame_len[i], integrity_key,
                         &verified[i]) == VERTHYS_OK) {
            hmac_valid[i] = 1;
            valid_count++;
        }
    }
    p->res.stages[UNLOCK_STAGE_S3].sub_steps = valid_count;

    if (valid_count == 0) {
        /*
         * 0/3 副本 HMAC 全败的语义判别（v2 API 契约延续，红线）：
         * S1 已对全部帧完成结构校验（帧头 + verifier），HMAC 全败仅两种
         * 成因——a) 口令错误（派生 integrity_key 全错）；b) 口令正确但
         * 超块密文/HMAC 被篡改。以 wrapped_key_a 内核态解包探针判别
         *（verthys_cng_km_verify_mek：AEAD 认证通过即口令正确）：
         *   探针 OK   → 口令正确 → 真损坏 → CORRUPT（0 有效语义）；
         *   探针 AUTH → 口令错误 → AUTH（用户应重试密码而非被告知损坏）。
         * 探针内部 import 消耗 p->mek（清零契约覆盖成功与失败路径），
         * 仅在本次失败路径执行——后续 goto fail 仅再清零（幂等），无二次使用。
         * 副本间 wrapped_key_a 同源（同一超块三副本），探 S1 早期候选
         * 一份即可判定。
         */
        r = verthys_cng_km_verify_mek(
                p->mek, p->sb_candidates[p->early_idx].wrapped_key_a,
                VERTHYS_V3_WRAPPED_KEY_BYTES);
        if (r == VERTHYS_OK) {
            r = VERTHYS_ERR_CORRUPT;          /* 口令正确 → 真损坏 */
        }
        /* 探针 AUTH → 口令错误（保持）；其余（CNG/内部）坦诚透传 */
        goto fail_zero_ik;
    }

    /* 3. 法定人数裁决：txid 分组取 ≥2 一致中的最高 txid */
    for (unsigned i = 0; i < VERTHYS_V3_SB_REPLICA_COUNT; i++) {
        if (!hmac_valid[i]) continue;
        unsigned agree = 0;
        for (unsigned j = 0; j < VERTHYS_V3_SB_REPLICA_COUNT; j++) {
            if (hmac_valid[j] && verified[j].txid == verified[i].txid) agree++;
        }
        if (agree >= 2 &&
            (chosen < 0 || verified[i].txid > verified[chosen].txid)) {
            chosen = (int)i;
        }
    }
    if (chosen < 0) {
        /* 有效副本不足法定人数 → 恢复流程入口（调用方裁决） */
        r = VERTHYS_ERR_QUORUM_FAILED;
        goto fail_zero_ik;
    }

    /* 4. pepper 来源一致性（迁移自旧版：记录非 0 时校验；漂移 →
     *    PEPPER_SOURCE 而非 AUTH，杜绝"来源漂移误报密码错误"） */
    if (verified[chosen].pepper_source != 0 &&
        (uint8_t)verthys_pepper_get_source() != verified[chosen].pepper_source) {
        r = VERTHYS_ERR_PEPPER_SOURCE;
        goto fail_zero_ik;
    }

    /* 5. CNG 批量导入：MEK（明文导入即清零）+ wrapped A/B/C 内核态解包 */
    r = verthys_cng_km_import_batch(ctx3->km, p->mek,
                                  verified[chosen].wrapped_key_a,
                                  VERTHYS_V3_WRAPPED_KEY_BYTES,
                                  verified[chosen].wrapped_key_b,
                                  VERTHYS_V3_WRAPPED_KEY_BYTES,
                                  verified[chosen].wrapped_key_c,
                                  VERTHYS_V3_WRAPPED_KEY_BYTES);
    if (r != VERTHYS_OK) goto fail_zero_ik;

    /* 6. 驻留产物（MEK 使命终结 → 立即清零；integrity_key 入 ctx3） */
    verthys_secure_zero(p->mek, sizeof(p->mek));
    p->mek_valid = 0;
    ctx3->sb = verified[chosen];
    memcpy(ctx3->integrity_key, integrity_key, VERTHYS_KEY_BYTES);
    verthys_secure_zero(integrity_key, sizeof(integrity_key));

    /* 预设 TLV 解码（扩展区；缺省 BALANCED） */
    {
        VerthysPreset preset = VERTHYS_PRESET_BALANCED;
        if (verthys_v3_preset_decode(ctx3->sb.extensions,
                                   ctx3->sb.extensions_len,
                                   &preset) == VERTHYS_OK) {
            ctx3->preset = preset;
        } else {
            r = VERTHYS_ERR_FORMAT;
            goto fail;
        }
    }

    p->res.stages[UNLOCK_STAGE_S3].result = VERTHYS_OK;
    p->res.stages[UNLOCK_STAGE_S3].end_ns = upl_now_ns();
    return VERTHYS_OK;

fail_zero_ik:
    verthys_secure_zero(integrity_key, sizeof(integrity_key));
fail:
    verthys_secure_zero(p->mek, sizeof(p->mek));   /* MEK 红线：失败路径同样清零 */
    p->mek_valid = 0;
    p->res.stages[UNLOCK_STAGE_S3].result = r;
    p->res.stages[UNLOCK_STAGE_S3].end_ns = upl_now_ns();
    return r;
}

/* ---------- S4：分区表加载（主线程，等 S1+S3） ---------- */

static VerthysResult upl_stage_s4(UnlockPipelineState *p)
{
    VerthysContextV3 *ctx3 = p->ctx3;
    VerthysCngAead *key_a;
    VerthysResult r;

    p->res.stages[UNLOCK_STAGE_S4].start_ns = upl_now_ns();

    if ((p->fail_mask >> UNLOCK_STAGE_S4) & 1u) {
        r = VERTHYS_ERR_INTERNAL;
        goto done;
    }

    key_a = verthys_cng_km_get(ctx3->km, VERTHYS_CNG_KEY_A);
    if (key_a == NULL) {
        r = VERTHYS_ERR_CNG_UNAVAILABLE;
        goto done;
    }

    /* 表帧 AEAD 与密钥包装共用 A 角色语境（分区模块约定）；
     * table_load 内部完成帧 nonce 计数器恢复（防回退） */
    r = verthys_partition_table_load(ctx3->f, ctx3->sb.partition_table_offset,
                                   key_a, key_a, &ctx3->ptable);
    p->res.stages[UNLOCK_STAGE_S4].sub_steps = (uint32_t)ctx3->ptable.count;

done:
    p->res.stages[UNLOCK_STAGE_S4].result = r;
    p->res.stages[UNLOCK_STAGE_S4].end_ns = upl_now_ns();
    return r;
}

/* ---------- S5：索引预热 + 崩溃恢复（主线程，等 S4） ---------- */

/* 后台预热线程（MINIMAL_FIRST；index_preheat_background） */
static DWORD WINAPI upl_bg_preheat_thread(LPVOID param)
{
    VerthysContextV3 *ctx3 = (VerthysContextV3 *)param;
    if (ctx3->lsm != NULL &&
        verthys_lsm_preheat_full(ctx3->lsm) == VERTHYS_OK) {
        ctx3->preheated = 1;
    }
    InterlockedExchange(&ctx3->bg_preheat_running, 0);
    return 0;
}

static VerthysResult upl_stage_s5(UnlockPipelineState *p)
{
    VerthysContextV3 *ctx3 = p->ctx3;
    VerthysPartition *index_part = NULL;
    VerthysPartition *extent_part = NULL;
    uint8_t *tables_pt = NULL, *memtable_pt = NULL;
    size_t tables_len = 0, memtable_len = 0;
    int cache_hit = 0;
    uint64_t t_cache;
    VerthysResult r;

    p->res.stages[UNLOCK_STAGE_S5].start_ns = upl_now_ns();

    if ((p->fail_mask >> UNLOCK_STAGE_S5) & 1u) {
        r = VERTHYS_ERR_INTERNAL;
        goto done;
    }

    /* 1. 分区定位（INDEX / EXTENT；运行时权威 = 分区表实条目） */
    for (size_t i = 0; i < ctx3->ptable.count; i++) {
        if (ctx3->ptable.entries[i].type == VERTHYS_PARTITION_INDEX) {
            index_part = &ctx3->ptable.entries[i];
        } else if (ctx3->ptable.entries[i].type == VERTHYS_PARTITION_EXTENT) {
            extent_part = &ctx3->ptable.entries[i];
        }
    }
    if (index_part == NULL || extent_part == NULL) {
        r = VERTHYS_ERR_FORMAT;   /* 容器缺基础分区（非法布局） */
        goto done;
    }

    /* 2. 温缓存优先（flags + preset 双门控；失败语义 = miss，红线） */
    if ((p->flags & VERTHYS_UNLOCK_FLAG_ALLOW_CACHE) != 0 &&
        !verthys_v3_warmcache_disabled_by_preset(ctx3->preset) &&
        ctx3->verthys_path != NULL) {
        t_cache = upl_now_ns();
        r = verthys_warmcache_v3_try_load(ctx3->verthys_path,
                                        ctx3->sb.container_id,
                                        ctx3->sb.txid,
                                        ctx3->integrity_key,
                                        &tables_pt, &tables_len,
                                        &memtable_pt, &memtable_len,
                                        &cache_hit);
        ctx3->diag_cache_load_ms = (upl_now_ns() - t_cache) / 1000000ULL;
        if (r != VERTHYS_OK) {
            /* 仅参数非法可达成；按 miss 处理（绝不中断解锁） */
            r = VERTHYS_OK;
            cache_hit = 0;
        }
    }
    if (cache_hit) {
        ctx3->diag_warm_cache_hits++;
    } else {
        ctx3->diag_warm_cache_misses++;
    }
    p->res.cache_hit = (uint32_t)cache_hit;

    /* 3. LSM 打开（温路径 → FORMAT 回退冷路径；盘面 Manifest 权威） */
    ctx3->lsm = verthys_lsm_create();
    if (ctx3->lsm == NULL) {
        r = VERTHYS_ERR_INTERNAL;
        goto done_free_cache;
    }
    if (cache_hit) {
        r = verthys_lsm_open_warm(ctx3->lsm, ctx3->f, index_part,
                                index_part->offset, index_part->size, 1,
                                tables_pt, tables_len,
                                memtable_pt, memtable_len);
        if (r == VERTHYS_ERR_FORMAT) {
            /* 缓存段结构非法 → 冷启动重入（open 幂等：入口 memset 复位） */
            r = verthys_lsm_open(ctx3->lsm, ctx3->f, index_part,
                               index_part->offset, index_part->size, 1);
        }
    } else {
        r = verthys_lsm_open(ctx3->lsm, ctx3->f, index_part,
                           index_part->offset, index_part->size, 1);
    }
    if (r != VERTHYS_OK) goto done_free_cache;

    /* 4. 事务 WAL 打开（C 角色语境；双半区扫描 + nonce 恢复） */
    ctx3->wal = verthys_wal_create();
    if (ctx3->wal == NULL) {
        r = VERTHYS_ERR_INTERNAL;
        goto done_free_cache;
    }
    {
        VerthysCngAead *key_c = verthys_cng_km_get(ctx3->km, VERTHYS_CNG_KEY_C);
        if (key_c == NULL) {
            r = VERTHYS_ERR_CNG_UNAVAILABLE;
            goto done_free_cache;
        }
        r = verthys_wal_open(ctx3->wal, ctx3->f, VERTHYS_V3_WAL_REGION_OFFSET,
                           key_c, NULL, NULL);
        if (r != VERTHYS_OK) goto done_free_cache;
    }

    /* 5. Extent 索引加载（分区偏移基准的索引帧区） */
    ctx3->ext_idx = (VerthysExtentIndex *)calloc(1, sizeof(VerthysExtentIndex));
    if (ctx3->ext_idx == NULL) {
        r = VERTHYS_ERR_INTERNAL;
        goto done_free_cache;
    }
    r = verthys_extent_index_load(ctx3->f, extent_part->offset,
                                extent_part, ctx3->ext_idx);
    if (r != VERTHYS_OK) goto done_free_cache;

    /* 6. 事务上下文绑定 + 崩溃恢复（WAL 回放 / 超块补提交 / MemTable 裁决） */
    r = verthys_txn_v3_init(&ctx3->txn, ctx3->f, ctx3->wal, &ctx3->sb,
                          ctx3->lsm, ctx3->ext_idx, extent_part,
                          &ctx3->ptable,
                          verthys_cng_km_get(ctx3->km, VERTHYS_CNG_KEY_A),
                          ctx3->integrity_key);
    if (r != VERTHYS_OK) goto done_free_cache;

    r = verthys_txn_v3_recover(&ctx3->txn, NULL, NULL);
    if (r != VERTHYS_OK) goto done_free_cache;

    ctx3->subsystems_open = 1;
    p->res.stages[UNLOCK_STAGE_S5].sub_steps = 1;

done_free_cache:
    if (tables_pt != NULL) {
        verthys_secure_zero(tables_pt, tables_len);
        free(tables_pt);
    }
    if (memtable_pt != NULL) {
        verthys_secure_zero(memtable_pt, memtable_len);
        free(memtable_pt);
    }
done:
    p->res.stages[UNLOCK_STAGE_S5].result = r;
    p->res.stages[UNLOCK_STAGE_S5].end_ns = upl_now_ns();
    return r;
}

/* ---------- S6：最终校验（主线程，等 S5） ---------- */

static VerthysResult upl_stage_s6(UnlockPipelineState *p)
{
    VerthysContextV3 *ctx3 = p->ctx3;
    VerthysResult r = VERTHYS_OK;

    p->res.stages[UNLOCK_STAGE_S6].start_ns = upl_now_ns();

    if ((p->fail_mask >> UNLOCK_STAGE_S6) & 1u) {
        r = VERTHYS_ERR_INTERNAL;
        goto done;
    }

    /* 子系统就绪标志核验 */
    if (!ctx3->subsystems_open || ctx3->lsm == NULL ||
        ctx3->wal == NULL || ctx3->ext_idx == NULL) {
        r = VERTHYS_ERR_INTERNAL;
        goto done;
    }

    /*
     * 渐进式解锁分叉：
     *   MINIMAL_FIRST —— OPERATIONAL_MINIMAL 已达成（S0-S5 最小可操作
     *   部分），全量索引预热转后台线程，立即返回 PARTIAL_UNLOCK；
     *   默认路径 —— 同步 verthys_lsm_preheat_full（幂等），返回 VERTHYS_OK。
     * 后台线程创建失败 → 同步预热兜底 + VERTHYS_OK（降级不失败）。
     */
    if ((p->flags & VERTHYS_UNLOCK_FLAG_MINIMAL_FIRST) != 0) {
        ctx3->minimal_mode = 1;
        InterlockedExchange(&ctx3->bg_preheat_running, 1);
        ctx3->bg_preheat_thread = CreateThread(NULL, 0,
                                               upl_bg_preheat_thread,
                                               ctx3, 0, NULL);
        if (ctx3->bg_preheat_thread == NULL) {
            InterlockedExchange(&ctx3->bg_preheat_running, 0);
            ctx3->minimal_mode = 0;
            if (verthys_lsm_preheat_full(ctx3->lsm) == VERTHYS_OK) {
                ctx3->preheated = 1;
            }
            r = VERTHYS_OK;
        } else {
            p->res.minimal_first = 1;
            r = VERTHYS_ERR_PARTIAL_UNLOCK;
        }
    } else {
        if (verthys_lsm_preheat_full(ctx3->lsm) == VERTHYS_OK) {
            ctx3->preheated = 1;
        }
        r = VERTHYS_OK;
    }

done:
    p->res.stages[UNLOCK_STAGE_S6].result = r;
    p->res.stages[UNLOCK_STAGE_S6].end_ns = upl_now_ns();
    return r;
}

/* ---------- 主编排 ---------- */

VerthysResult verthys_unlock_pipeline_run(struct VerthysContextV3 *ctx3,
                                      const char *password, size_t pw_len,
                                      uint32_t flags,
                                      uint32_t fail_mask,
                                      void (*progress_cb)(uint32_t stage,
                                                          uint32_t percent,
                                                          void *user),
                                      void *progress_user)
{
    UnlockPipelineState *p;
    HANDLE h_s1 = NULL, h_s2 = NULL;
    VerthysResult r = VERTHYS_OK;
    int cng_inited = 0;

    /* ---------- S0：前置检查（主线程） ---------- */
    if (ctx3 == NULL || ctx3->f == NULL || ctx3->km == NULL ||
        (password == NULL && pw_len != 0)) {
        return VERTHYS_ERR_INVALID;
    }

    p = (UnlockPipelineState *)calloc(1, sizeof(*p));
    if (p == NULL) return VERTHYS_ERR_INTERNAL;

    p->ctx3 = ctx3;
    p->password = password;
    p->pw_len = pw_len;
    p->flags = flags;
    p->fail_mask = fail_mask;
    p->progress_cb = progress_cb;
    p->progress_user = progress_user;
    p->deadline_ns = upl_now_ns() + (uint64_t)VERTHYS_UNLOCK_TIMEOUT_MS * 1000000ULL;
    p->res.total_start_ns = upl_now_ns();
    p->early_idx = -1;
    p->res.stages[UNLOCK_STAGE_S0].start_ns = p->res.total_start_ns;

    upl_emit(progress_cb, progress_user, UNLOCK_STAGE_S0, UPL_PCT_S0_START);

    do {
        if ((fail_mask >> UNLOCK_STAGE_S0) & 1u) {
            r = VERTHYS_ERR_INTERNAL;
            break;
        }

        /* 应急熔断门控（v2 惯例：触发态拒绝服务 = LOCKED） */
        if (emergency_is_triggered()) {
            r = VERTHYS_ERR_LOCKED;
            break;
        }

        /* pepper 快速失败（幂等初始化；全来源失败/来源错误 → PEPPER_SOURCE） */
        if (verthys_pepper_init() != 0 || verthys_pepper_source_error()) {
            r = VERTHYS_ERR_PEPPER_SOURCE;
            break;
        }

        /* CNG 密钥组就绪（幂等；UNINITIALIZED 态可重入） */
        r = verthys_cng_km_init(ctx3->km);
        if (r != VERTHYS_OK) break;
        cng_inited = 1;

        p->res.stages[UNLOCK_STAGE_S0].result = VERTHYS_OK;
        p->res.stages[UNLOCK_STAGE_S0].end_ns = upl_now_ns();

        /* ---------- S1 ∥ S2 启动 ---------- */
        upl_emit(progress_cb, progress_user, UNLOCK_STAGE_S1, UPL_PCT_S1_START);

        InitializeCriticalSection(&p->lock);
        InitializeConditionVariable(&p->cv_s1);
        InitializeConditionVariable(&p->cv_s2);
        p->cs_valid = 1;

        h_s1 = CreateThread(NULL, 0, upl_stage_s1, p, 0, NULL);
        h_s2 = CreateThread(NULL, 0, upl_stage_s2, p, 0, NULL);
        if (h_s1 == NULL || h_s2 == NULL) {
            /* 线程创建失败：唤醒等待方退出（S2 等 cv_s1 / 主线程等 cv_s2） */
            EnterCriticalSection(&p->lock);
            p->s1_done = 1;
            p->s1_result = VERTHYS_ERR_INTERNAL;
            p->s2_done = 1;
            p->s2_result = VERTHYS_ERR_INTERNAL;
            WakeAllConditionVariable(&p->cv_s1);
            WakeAllConditionVariable(&p->cv_s2);
            LeaveCriticalSection(&p->lock);
            r = VERTHYS_ERR_INTERNAL;
            break;
        }

        /* 主线程等 S2（Argon2id ~1s 为主时长；期间 S1 自行完成） */
        if (!upl_wait_flag(p, &p->cv_s2, &p->s2_done)) {
            r = VERTHYS_ERR_TIMEOUT;
            break;
        }
        /* S1 汇合检查（通常先于 S2 完成；显式等待保证 FILE* 单线程纪律） */
        if (!upl_wait_flag(p, &p->cv_s1, &p->s1_done)) {
            r = VERTHYS_ERR_TIMEOUT;
            break;
        }

        if (p->s2_result != VERTHYS_OK) {
            r = p->s2_result;
            break;
        }
        if (p->s1_result != VERTHYS_OK) {
            r = p->s1_result;
            break;
        }

        upl_emit(progress_cb, progress_user, UNLOCK_STAGE_S2, UPL_PCT_S2_DONE);
        ctx3->diag_argon2_last_ms =
            (uint32_t)((p->res.stages[UNLOCK_STAGE_S2].end_ns -
                        p->res.stages[UNLOCK_STAGE_S2].start_ns) / 1000000ULL);
        upl_emit(progress_cb, progress_user, UNLOCK_STAGE_S1, UPL_PCT_S1_DONE);

        /* 总预算检查（Argon2id 后：剩余预算不足以承载后继阶段时提前失败） */
        if (upl_remaining_ms(p->deadline_ns) == 0) {
            r = VERTHYS_ERR_TIMEOUT;
            break;
        }

        /* ---------- S3：CNG 导入 + 法定人数（主线程） ---------- */
        r = upl_stage_s3(p);
        if (r != VERTHYS_OK) break;
        upl_emit(progress_cb, progress_user, UNLOCK_STAGE_S3, UPL_PCT_S3_DONE);

        if (upl_remaining_ms(p->deadline_ns) == 0) {
            r = VERTHYS_ERR_TIMEOUT;
            break;
        }

        /* ---------- S4：分区表加载（主线程） ---------- */
        r = upl_stage_s4(p);
        if (r != VERTHYS_OK) break;
        upl_emit(progress_cb, progress_user, UNLOCK_STAGE_S4, UPL_PCT_S4_DONE);

        if (upl_remaining_ms(p->deadline_ns) == 0) {
            r = VERTHYS_ERR_TIMEOUT;
            break;
        }

        /* ---------- S5：索引预热 + 崩溃恢复（主线程） ---------- */
        r = upl_stage_s5(p);
        if (r != VERTHYS_OK) break;
        upl_emit(progress_cb, progress_user, UNLOCK_STAGE_S5, UPL_PCT_S5_DONE);

        if (r == VERTHYS_OK && upl_remaining_ms(p->deadline_ns) == 0) {
            r = VERTHYS_ERR_TIMEOUT;
            break;
        }

        /* ---------- S6：最终校验（主线程） ---------- */
        r = upl_stage_s6(p);
        if (r == VERTHYS_OK) {
            upl_emit(progress_cb, progress_user, UNLOCK_STAGE_S6, UPL_PCT_S6_DONE);
        }
    } while (0);

    /* ---------- 汇合 + 失败路径资源纪律 ---------- */

    /* 线程汇合（Argon2id 不可中断：超时路径同样等待返回，杜绝悬挂线程
     * 触碰本函数栈上状态；正常路径两线程均已 done） */
    upl_join_thread(&h_s2);
    upl_join_thread(&h_s1);

    /*
     * 失败清理（红线）：
     *   - CNG 已导入句柄销毁（km destroy_all，幂等）；
     *   - integrity_key / MEK 清零（MEK 已在 S3 全路径清零）；
     *   - 已打开子系统关闭（wal/lsm/ext_idx/txn）；
     *   - ctx3 回到可重试初态（subsystems_open=0）。
     * VERTHYS_ERR_PARTIAL_UNLOCK 非失败：子系统保持可用。
     */
    if (r != VERTHYS_OK && r != VERTHYS_ERR_PARTIAL_UNLOCK) {
        if (cng_inited) {
            verthys_v3_ctx_subsystems_close(ctx3);
        }
        verthys_secure_zero(p->mek, sizeof(p->mek));
        p->mek_valid = 0;
    }

    p->res.total_end_ns = upl_now_ns();
    ctx3->pipeline = p->res;
    ctx3->unlock_flags = flags;
    ctx3->diag_unlock_total_ms =
        (p->res.total_end_ns - p->res.total_start_ns) / 1000000ULL;

    if (p->cs_valid) DeleteCriticalSection(&p->lock);
    verthys_secure_zero(p->mek, sizeof(p->mek));
    free(p);
    return r;
}
