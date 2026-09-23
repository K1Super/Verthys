/*
 * verthys_api.c — 公共 C ABI 导出函数实现（瘦门面，V3-only）
 *
 *
 * 状态机：
 *   UNINIT  ──Unlock──→ UNLOCKED
 *   LOCKED  ──Unlock──→ UNLOCKED
 *   UNLOCKED──Lock────→ LOCKED
 *   任何非 UNLOCKED 状态下的增/查/删 → VERTHYS_ERR_LOCKED
 *
 * 内存安全：
 *   - 三密钥仅在 UNLOCKED 时驻留，Lock/Deinit 即刻 verthys_secure_zero
 *   - B+ 树/数据块管理器/Merkle 树同理
 *   - 局部密钥变量用后即擦
 */
#include "verthys_internal.h"

/* 拆分后的内部模块头 */
#include "verthys_api_utils.h"      /* 共享底层工具 */
#include "verthys_progress.h"       /* 进度回调环形缓冲区 */
/* V3：V3 容器生命周期 + 运行时上下文（传递包含
 * transaction_v3 / lsm / extent / wal / partition 全套接口；
 * 本文件 V3 分支直接编排六阶段事务）。 */
#include "verthys_v3_lifecycle.h"
#include "verthys_rekey_auto.h"      /* DEGRADE 强制轮换标志持久化 */

/* 项目头 */
#include "verthys_crypto.h"
#include "keymanager.h"
#include "verthys_pepper.h"
#include "anti_debug_v2.h"
#include "tls_loader.h"
#include "secure_allocator.h"   /* ctx 隔离堆生命周期 */
#include "job_isolation.h"
#include "cng_machine_key.h"
#include "system32_loader.h"
#include "hardware_binding.h"
#include "tamper_destroy.h"
#include "emergency.h"
#include "anti_inject.h"
#include "memory_guard.h"
#include "integrity.h"
#include "runtime_hash.h"      /* 解锁后 + 周期运行时函数哈希校验 */
#include "security_preset.h"   /* 运行时预设切换（双缓冲原子发布） */

/* ================================================================== *
 * 活动句柄注册表 —— 应急 DEGRADE 处理器的寻址基础。
 *
 * 应急体系是进程级全局模块，不持有任何 VerthysHandle；降级处理器需要
 * 找到全部已初始化句柄以执行"清密钥 + 锁定"。注册表在 Verthys_Init
 * 登记成功创建的上下文，Verthys_Deinit 注销，处理器遍历执行。
 * 注册表访问仅发生在 Init/Deinit（worker 单线程 FFI 语义）与应急
 * 触发路径（低频），以 SRWLOCK 保护的静态数组实现。
 * ================================================================== */
#define VERTHYS_MAX_CTXS 8

static struct VerthysContext *s_ctx_registry[VERTHYS_MAX_CTXS];
static SRWLOCK s_ctx_registry_lock;
static int s_ctx_registry_lock_init = 0;

static void verthys_ctx_registry_add(struct VerthysContext *ctx)
{
    if (!s_ctx_registry_lock_init) {
        InitializeSRWLock(&s_ctx_registry_lock);
        s_ctx_registry_lock_init = 1;
    }
    AcquireSRWLockExclusive(&s_ctx_registry_lock);
    for (int i = 0; i < VERTHYS_MAX_CTXS; i++) {
        if (s_ctx_registry[i] == NULL) {
            s_ctx_registry[i] = ctx;
            break;
        }
    }
    ReleaseSRWLockExclusive(&s_ctx_registry_lock);
}

static void verthys_ctx_registry_remove(struct VerthysContext *ctx)
{
    if (!s_ctx_registry_lock_init) return;
    AcquireSRWLockExclusive(&s_ctx_registry_lock);
    for (int i = 0; i < VERTHYS_MAX_CTXS; i++) {
        if (s_ctx_registry[i] == ctx) {
            s_ctx_registry[i] = NULL;
        }
    }
    ReleaseSRWLockExclusive(&s_ctx_registry_lock);
}

/*
 * 应急 DEGRADE 降级处理器（emergency_set_degrade_handler 注入）。
 *
 * 语义：对全部已解锁句柄执行"密钥与明文立即清零 + 状态置 LOCKED"，
 * 进程保持存活。不执行任何磁盘写入（与 Verthys_Lock 的差异：跳过事务
 * 提交与缓存刷盘——降级路径优先保证敏感数据不落盘、响应微秒级；
 * 未完成事务由下次解锁的 WAL 崩溃恢复路径接管，数据安全
 * 由事务日志与法定人数超级块保障）。恢复方式：用户正常 Verthys_Unlock。
 *
 * 唯一例外：清钥前 verthys_rekey_auto_note_degrade 持久化强制
 * 轮换标志（超级块 TLV 非敏感 HMAC 元数据，~ms 级 3 副本写）——
 * 旧 wrapped 形态可能已随内存泄露继续暴露，标志必须落盘方能在下次
 * 解锁兑现强制轮换；失败静默（轮换属纵深防御层，降级锁库语义不受
 * 影响，下次解锁按盘面缺省态处理）。
 */
static void verthys_emergency_lock_all(void)
{
    if (!s_ctx_registry_lock_init) return;

    AcquireSRWLockShared(&s_ctx_registry_lock);
    for (int i = 0; i < VERTHYS_MAX_CTXS; i++) {
        struct VerthysContext *ctx = s_ctx_registry[i];
        if (ctx == NULL || ctx->state != VERTHYS_STATE_UNLOCKED) continue;

#ifdef _WIN32
        if (ctx->api_mutex != NULL) {
            AcquireSRWLockExclusive(ctx->api_mutex);
        }
#endif
        if (ctx->state == VERTHYS_STATE_UNLOCKED) {
            if (ctx->v3 != NULL) {
                /* DEGRADE 强制轮换标志持久化（清钥前，best-effort） */
                (void)verthys_rekey_auto_note_degrade(ctx->v3);
                /* V3：V3 容器密钥清除（DEGRADE 红线——内核态句柄
                 * 销毁 + 驻留密钥清零 + LSM 中止式关闭不落盘）。后台预热线程
                 * 经 subsystems_close 内部汇合（线程持 ptable 内核句柄解密，
                 * 先销毁句柄将引发线程内 BCrypt 句柄 UAF——汇合是唯一安全序）。 */
                verthys_v3_ctx_subsystems_close(ctx->v3);
            }
            ctx_zero_sensitive(ctx);
            ctx->state = VERTHYS_STATE_LOCKED;
        }
#ifdef _WIN32
        if (ctx->api_mutex != NULL) {
            ReleaseSRWLockExclusive(ctx->api_mutex);
        }
#endif
    }
    ReleaseSRWLockShared(&s_ctx_registry_lock);
}
#include "process_sandbox.h"
#include "defense_closure.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

#include "verthys_diag.h"

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>               /* _O_RDWR/_O_BINARY（V3 创建路径 fd 转换） */
#else
#include <unistd.h>
#endif

/* 并行索引读取开关（原定义于 verthys_api.c L699，拆分后由本文件保留） */
#define USE_PARALLEL_INDEX_READ 1

/* 1. 创建未初始化的加密库上下文 */
VerthysResult Verthys_Init(VerthysHandle *out_handle)
{
    if (out_handle == NULL) return VERTHYS_ERR_INVALID;

    /* 阻塞 4 修复：AVX2 软性检测 — 设置全局标志，不拒绝启动
     * libsodium 内部自动选择最优指令集路径，无需项目层硬性要求 */
#ifdef _WIN32
    g_has_avx2 = verthys_check_avx2_support();
    if (g_has_avx2) {
        VERTHYS_DIAG_LOG("[VERTHYS] AVX2 detected: crypto operations will use AVX2-accelerated paths");
    } else {
        VERTHYS_DIAG_LOG("[VERTHYS] AVX2 not detected: falling back to SSE4.2/generic paths (libsodium handles runtime selection)");
    }
#else
    g_has_avx2 = 0;  /* 非 Windows 平台暂不支持 AVX2 检测 */
#endif

    if (verthys_crypto_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    /*
     * TLS 标志验证从 DllMain 移至此处
     *（tls_loader_init 在 LoaderLock 释放后调用，避免加载锁死锁）。
     * IAT 校验与 15s 种子定时器已删除，
     *   本调用现仅验证 TLS 回调标志（加载路径完整性）。
     */
    if (tls_loader_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    if (anti_debug_v2_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    if (anti_debug_v2_check() != 0) {
        /* 检测到调试器（高置信度）：KILL 信号已在 check 内部上报，
         * 此处不再作为初始化失败——应急体系将接管进程处置 */
        return VERTHYS_ERR_INTERNAL;
    }

    /*
     * Windows 加密 Worker 安全设计 — 动态防护初始化
     *
     * 加载顺序：
     *   1. TLS 回调（已在 DLL 加载时触发）→ 设置 g_tls_init_marker
     *   2. DllMain(DLL_PROCESS_ATTACH)（已在 DLL 加载时触发）→ DisableThreadLibraryCalls
     *   3. 此处 Verthys_Init → 防御模块 init + 闭环验证
     *
     * 失败处理：
     *   - 关键防御模块 init 失败 → 立即返回 VERTHYS_ERR_INTERNAL，Worker 拒绝启动
     *   - defense_closure_check 失败（有 FAILED 路径）→ 返回 VERTHYS_ERR_INTERNAL
     *
     * 注意：process_sandbox 必须由 Worker 进程本身在加载本 DLL 之前应用，
     *       此处不调用 process_sandbox_init（mitigation policy 是进程级，已应用即生效）。
     */
    /* Layer 1: 进程不可触碰化 */
    if (job_isolation_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    /* Layer 3: 固件与硬件绑定 */
    if (cng_machine_key_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    if (system32_loader_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    if (hardware_binding_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    /* Layer 4: Hook/注入对抗（联动销毁待命；TLS 标志已在上方验证） */
    if (tamper_destroy_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    /* Layer 6: 最终闭环防御能力验证（BOOT 模式 — 任一关键路径 FAILED 即拒绝启动） */
    if (defense_closure_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    if (defense_closure_check(DEFENSE_CHECK_BOOT, NULL) != 0) {
        /* 存在 FAILED 攻击路径，关键防御模块缺失，拒绝启动 */
        return VERTHYS_ERR_INTERNAL;
    }

    struct VerthysContext *ctx = (struct VerthysContext *)calloc(1, sizeof(struct VerthysContext));
    if (ctx == NULL) return VERTHYS_ERR_INTERNAL;
    ctx->state = VERTHYS_STATE_UNINIT;
    /* 分配并初始化 SRWLOCK 读写锁
     * 读操作以共享模式进入，写操作以独占模式进入，允许多个读取并发执行。
     * SRWLOCK 零初始化即可使用，无需 InitializeCriticalSection。 */
#ifdef _WIN32
    ctx->api_mutex = (SRWLOCK *)malloc(sizeof(SRWLOCK));
    if (ctx->api_mutex == NULL) {
        verthys_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return VERTHYS_ERR_INTERNAL;
    }
    InitializeSRWLock(ctx->api_mutex);
#endif

    /* 初始化胡椒托管框架
     * 按优先级加载胡椒：注入 > OS 托管(CNG/TPM) > 编译内嵌兜底。
     * 胡椒内存受 VirtualLock 保护，Deinit 时安全清零。
     * 失败不阻塞 Init（keymanager_derive_master 会再次尝试懒加载）。 */
    verthys_pepper_init();

    /* 密钥相关结构专用安全分配器。
     * 隔离堆 + PAGE_GUARD 边界页 + VirtualLock 锁页 + 释放前清零；
     * 全局预算记账（512MB 上限，80% 回收 / 95% 拒绝）。
     * 创建失败按资源上限处理（安全内存不可用则拒绝启动）。 */
    ctx->secure_alloc = secure_allocator_create();
    if (ctx->secure_alloc == NULL) {
        free(ctx->api_mutex);
        verthys_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return VERTHYS_ERR_INTERNAL;
    }
    secure_allocator_budget_init(SECURE_ALLOC_DEFAULT_BUDGET_BYTES,
                                 NULL, NULL);

    /* 注册应急 DEGRADE 降级处理器。
     * 应急体系判定降级（如中置信度远程内存读取、窗口内重复信号）时，
     * 回调 verthys_emergency_lock_all：清空全部句柄密钥并锁定容器，
     * 进程保持存活，用户重新解锁即可恢复。 */
    emergency_set_degrade_handler(verthys_emergency_lock_all);

    /* 登记活动句柄（应急 DEGRADE 处理器寻址基础） */
    verthys_ctx_registry_add(ctx);

    *out_handle = (VerthysHandle)ctx;  /* 显式 cast（VerthysHandleImpl* ← VerthysContext*） */
    return VERTHYS_OK;
}

/*
 * 1b. 通知 DLL 当前 Worker 进程已应用的沙盒属性
 *
 * Worker（Rust 端）在加载本 DLL 之前已通过 apply_process_sandbox()
 * 应用进程级 mitigation policy（ProcessSystemCallDisablePolicy、
 * ProcessChildProcessPolicy、SetDefaultDllDirectories、ProcessImageLoadPolicy）。
 *
 * Worker 在加载本 DLL 后、调用 Verthys_Init 之前调用本函数，
 * 将已应用的属性位掩码注入本模块，使后续 defense_closure_check
 * 能正确识别已生效的防御策略。
 *
 *   attrs: 已应用的属性位掩码（与 process_sandbox.h 中的 SANDBOX_ATTR_* 对齐）
 */
VerthysResult Verthys_NotifySandboxAttrs(uint32_t attrs)
{
    process_sandbox_set_active_attrs(attrs);
    return VERTHYS_OK;
}

/* 2. 销毁上下文 */


VerthysResult Verthys_Deinit(VerthysHandle handle)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;

    /* 先从活动句柄注册表注销（应急处理器不再寻址本句柄） */
    verthys_ctx_registry_remove(ctx);
    /* 停止防转储低频巡逻 */
    memory_guard_patrol_stop();

    /* V3：V3 上下文收口（先于 ctx_zero_sensitive——后者销毁
     * CNG 密钥组，而 verthys_v3_lock 需密钥在位完成事务收尾/LSM flush/温缓存）。
     *
     * UNLOCKED 态走完整锁定路径（数据完整性收尾 + 温缓存写入 + 子系统
     * 安全销毁）；LOCKED 态残留实例（应急 DEGRADE 遗留）子系统已收口，
     * 直接销毁。verthys_v3_lock 失败不阻断 Deinit：V3 崩溃一致性由 WAL
     * 重放兜底（下次 open 幂等恢复），销毁仍完整执行（密钥零残留红线）。
     * 文件句柄所有权：ctx3->f 为借用引用，本处统一 fclose。 */
    if (ctx->v3 != NULL) {
        FILE *f_v3 = ctx->v3->f;
        if (ctx->state == VERTHYS_STATE_UNLOCKED) {
            (void)verthys_v3_lock(ctx->v3);
        }
        verthys_v3_ctx_destroy(ctx->v3);
        ctx->v3 = NULL;
        if (f_v3 != NULL) fclose(f_v3);
    }

    if (ctx->state == VERTHYS_STATE_UNLOCKED) {
        ctx_zero_sensitive(ctx);
    }
    free(ctx->file_path);
    ctx->file_path = NULL;

    /* 销毁安全分配器——全部活跃区段清零 + 解锁 +
     * 归还内核（区段级销毁先于 ctx 清零，密钥材料零残留）。 */
    if (ctx->secure_alloc != NULL) {
        secure_allocator_destroy(ctx->secure_alloc);
        ctx->secure_alloc = NULL;
    }

    /* 销毁 SRWLOCK 读写锁
     * SRWLOCK 无需 DeleteCriticalSection，直接释放堆内存即可。 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) {
        free(ctx->api_mutex);
        ctx->api_mutex = NULL;
    }
    /* 销毁进度回调环形缓冲区 + 停止消费线程
     *   等待消费线程最多 3 秒退出，确保残留进度条目消费完毕 */
    if (ctx->progress_ring != NULL) {
        verthys_progress_ring_destroy((VerthysProgressRing *)ctx->progress_ring);
        ctx->progress_ring = NULL;
    }
#endif

    verthys_secure_zero(ctx, sizeof(*ctx));
    free(ctx);
    return VERTHYS_OK;
}
/* 注册解锁进度回调（公共 API，对应 verthys.h 声明）
 *
 * 注册后对当前句柄的所有后续 Verthys_Unlock / Verthys_CreateWithPreset 调用生效。
 * 传 NULL callback 可取消进度通知。
 *
 * 首次注册时创建无锁环形缓冲区 + 启动独立消费线程，
 *   verthys_emit_unlock_progress 写入缓冲区（O(1) <1μs），
 *   消费线程异步调用回调，主解锁链路零阻塞。
 *   重复注册时仅更新回调指针（消费线程读取新值）。
 *   创建失败时回退到同步回调模式（兼容性保障）。
 *
 * 线程安全：MT-Unsafe（与 Unlock 共享同一调用线程语义） */
VerthysResult Verthys_RegisterUnlockProgressCallback(VerthysHandle handle,
                                                 VerthysUnlockProgressCallback callback,
                                                 void *user_data)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;

#ifdef _WIN32
    if (ctx->progress_ring != NULL) {
        /* 环形缓冲区已存在：更新回调指针（消费线程会读取新值）
         * MemoryBarrier 确保指针更新对消费线程可见 */
        VerthysProgressRing *ring = (VerthysProgressRing *)ctx->progress_ring;
        ring->user_data = user_data;
        MemoryBarrier();
        ring->callback = callback;
    } else if (callback != NULL) {
        /* 首次注册：创建环形缓冲区 + 启动消费线程 */
        ctx->progress_ring = verthys_progress_ring_create(callback, user_data);
        /* 创建失败时 progress_ring == NULL，下方同步回退生效 */
    }
    /* 同步回退字段：progress_ring == NULL 时 verthys_emit_unlock_progress 使用 */
#endif

    ctx->unlock_progress_cb        = callback;
    ctx->unlock_progress_user_data = user_data;
    /* unlock_progress_start_ms 在每次 Unlock 入口处重置，此处不设置 */
    return VERTHYS_OK;
}

/* ================================================================== *
 * V3：V3 分发辅助段                                        *
 *                                                                    *
 * 编排层级：本段为 V3 容器的 API 层业务封装，六阶段事务语义     *
 * 由 transaction_v3 模块承担，本段只做：                           *
 *   1. 进度回调适配（流水线 S0-S6 → 公共 VerthysUnlockStage 映射）；    *
 *   2. 单调用事务骨架（BEGIN→…→CONFIRM 全链 + 失败回滚收口）；         *
 *   3. Unlock/Create 的上下文装配与文件句柄所有权管理。                *
 *                                                                    *
 * 文件句柄所有权纪律（红线）：ctx3->f 为借用引用——失败路径由本段     *
 * fclose，成功路径所有权延伸至 Lock/Deinit（那时统一 fclose）。       *
 * ================================================================== */

/*
 * 流水线进度适配器（pipeline progress_cb → verthys_emit_unlock_progress）。
 * user 恒为 VerthysContext*（注册点经本文件保证）。
 * 阶段映射（S0-S6 → 公共 VerthysUnlockStage，语义最近邻）：
 *   S0 前置检查     → READ_SUPERBLOCK（5%）
 *   S1 超级块读取   → READ_SUPERBLOCK（5%）
 *   S2 Argon2id     → ARGON2_START（10%）
 *   S3 CNG+法定人数 → ARGON2_DONE（50%）
 *   S4 分区表加载   → CACHE_CHECK（55%）
 *   S5 索引预热     → BTREE_DECRYPT（60%）
 *   S6 最终校验     → BTREE_DONE（85%）
 */
static void verthys_api_v3_progress_cb(uint32_t stage, uint32_t percent, void *user)
{
    static const uint32_t stage_map[UNLOCK_STAGE_COUNT] = {
        VERTHYS_UNLOCK_STAGE_READ_SUPERBLOCK,   /* S0 */
        VERTHYS_UNLOCK_STAGE_READ_SUPERBLOCK,   /* S1 */
        VERTHYS_UNLOCK_STAGE_ARGON2_START,      /* S2 */
        VERTHYS_UNLOCK_STAGE_ARGON2_DONE,       /* S3 */
        VERTHYS_UNLOCK_STAGE_CACHE_CHECK,       /* S4 */
        VERTHYS_UNLOCK_STAGE_BTREE_DECRYPT,     /* S5 */
        VERTHYS_UNLOCK_STAGE_BTREE_DONE,        /* S6 */
    };
    struct VerthysContext *ctx = (struct VerthysContext *)user;

    if (ctx == NULL || stage >= UNLOCK_STAGE_COUNT) return;
    verthys_emit_unlock_progress(ctx, stage_map[stage], percent,
                               "V3 unlock pipeline");
}

/*
 * V3：V3 残留上下文清理（Unlock / Create 入口统一收口）。
 *
 * 残留来源：应急 DEGRADE（subsystems_close 后 state=LOCKED，堆实例与
 * 文件句柄仍挂在 ctx->v3）。本函数在装配新 V3 上下文前销毁残留实例
 * 并关闭其文件句柄，杜绝堆/句柄泄漏与悬挂引用。幂等（无残留 = no-op）；
 * destroy 内部对已关闭子系统为幂等收口。
 */
static void verthys_api_v3_residual_cleanup(struct VerthysContext *ctx)
{
    FILE *f;

    if (ctx->v3 == NULL) return;

    f = ctx->v3->f;                       /* 借用引用，本函数负责关闭 */
    verthys_v3_ctx_destroy(ctx->v3);
    ctx->v3 = NULL;
    if (f != NULL) fclose(f);
}

/*
 * V3 解锁编排（Verthys_Unlock 的 V3 分支目标；调用方已持 api_mutex 独占）：
 *   1. "r+b" 打开容器（解锁后可读写）；
 *   2. 装配 VerthysContextV3（借用 ctx->cng_keys 与文件句柄）；
 *   3. verthys_v3_open_existing → 解锁流水线 S0-S6 全权承担；
 *   4. 成功（含 PARTIAL_UNLOCK——渐进式解锁的最小可操作态）：上下文移交
 *      （fmt_version=V3 / v3 挂载 / state=UNLOCKED / backoff 复位）；
 *   5. 失败：ctx3 完整销毁 + 文件句柄关闭（可重试初态），AUTH 失败计入
 *      退避（与 v2 路径同一治理）。
 */
static VerthysResult verthys_api_v3_unlock(struct VerthysContext *ctx,
                                       const char *verthys_path,
                                       const char *password, size_t pw_len,
                                       uint32_t flags)
{
    FILE *f = NULL;
    VerthysContextV3 *v3 = NULL;
    VerthysResult rc;

    /* 残留清理（应急 DEGRADE 遗留实例：销毁 + 关闭其文件句柄） */
    verthys_api_v3_residual_cleanup(ctx);

#ifdef _WIN32
    /* 共享语义（deny-none）：会话期持久句柄必须 FILE_SHARE_READ|WRITE。
     * MSVC CRT fopen/fopen_s 默认仅 FILE_SHARE_READ（拒绝写共享）——实测
     * CRT "r+b" 句柄使后续 CreateFileA(GENERIC_WRITE) 全部 SHARING_VIOLATION，
     * 阻塞一切合法第二句柄（字节范围锁故障注入、热备/维护工具）。V2 会话
     * 不持有持久写句柄（按需重开），V3 持久句柄若拒绝写共享则可达性不对等。
     * 容器完整性由 AEAD+HMAC+法定人数的密码学保证，不依赖共享模式拒写。
     * 所有权链：CreateFileA → _open_osfhandle → _fdopen → fclose 全链关闭。 */
    {
        HANDLE hFile = CreateFileA(verthys_path,
                                   GENERIC_READ | GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, NULL);
        int fd;
        if (hFile == INVALID_HANDLE_VALUE) return VERTHYS_ERR_IO;
        fd = _open_osfhandle((intptr_t)hFile, _O_RDWR | _O_BINARY);
        if (fd < 0) {
            CloseHandle(hFile);
            return VERTHYS_ERR_IO;
        }
        f = _fdopen(fd, "r+b");
        if (f == NULL) {
            _close(fd);
            return VERTHYS_ERR_IO;
        }
    }
#else
    f = fopen(verthys_path, "r+");
    if (f == NULL) return VERTHYS_ERR_IO;
#endif

    /* 结构尺寸下限：V3 固定布局区（超块 64KB +
     * WAL 960KB + 分区表 3MB = 4MB）为容器必备结构，文件小于该下限
     * 即不可能为合法 V3 容器。detect_format 仅校验首帧头 8 字节——
     * 截断文件（如 fuzz_truncated_header 的 56 字节样本）会携带合法
     * 帧头进入流水线，S1 三副本读取全败后按 "0 有效"语义返回
     * CORRUPT；但"从未具备固定布局结构"属格式非法而非内容损坏，
     * 应在进入流水线前以 FORMAT 拒绝（与 v2 读侧截断语义对齐）。 */
    {
        int64_t fsz;
        if (vio_fseek64(f, 0, SEEK_END) != 0 ||
            (fsz = vio_ftell64(f)) < 0 ||
            (uint64_t)fsz < VERTHYS_V3_PARTITION_TABLE_END ||
            vio_fseek64(f, 0, SEEK_SET) != 0) {
            fclose(f);
            return VERTHYS_ERR_FORMAT;
        }
    }

    v3 = verthys_v3_ctx_create(&ctx->cng_keys, f, verthys_path);
    if (v3 == NULL) {
        fclose(f);
        return VERTHYS_ERR_INTERNAL;
    }

    rc = verthys_v3_open_existing(v3, password, pw_len, flags,
                                verthys_api_v3_progress_cb, ctx);
    if (rc == VERTHYS_OK || rc == VERTHYS_ERR_PARTIAL_UNLOCK) {
        free(ctx->file_path);
        ctx->file_path = dup_string(verthys_path);
        ctx->fmt_version = VERTHYS_FMT_V3;
        ctx->v3 = v3;
        ctx->preset = v3->preset;   /* 扩展 TLV 裁决产物（GetContainerInfo 源） */
        ctx->warm_cache_enabled =
            !verthys_v3_warmcache_disabled_by_preset(v3->preset);
        ctx->state = VERTHYS_STATE_UNLOCKED;
        verthys_backoff_reset();
        /* 诊断映射（GetDiagnostics 的 V3 数据源）：
         * unlock_derive_ms ← 流水线 S2 Argon2id 实测耗时（测试
         * perf_diagnostics_metrics_complete 契约：派生耗时必 >0），
         * argon2_last_derive_ms ← 同源（漂移监控）。 */
        ctx->diag_unlock_total_ms = v3->diag_unlock_total_ms;
        ctx->diag_unlock_derive_ms = v3->diag_argon2_last_ms;
        ctx->diag_cache_load_ms   = v3->diag_cache_load_ms;
        ctx->diag_warm_cache_hits  = v3->diag_warm_cache_hits;
        ctx->diag_warm_cache_misses = v3->diag_warm_cache_misses;
        ctx->argon2_last_derive_ms = v3->diag_argon2_last_ms;
        return rc;
    }

    /* 失败路径可重试初态：ctx3 销毁（内含密钥清零 + 子系统
     * abort 式关闭）后关闭文件句柄（借用引用，本函数拥有） */
    if (rc == VERTHYS_ERR_AUTH) verthys_backoff_record_failure();
    verthys_v3_ctx_destroy(v3);
    fclose(f);
    return rc;
}

/*
 * V3 创建编排（Verthys_CreateWithPreset 目标；系统唯一合法新建入口，
 * 新建一律 V3——唯一容器格式）：
 *   1. CreateFileA(CREATE_NEW) 原子创建（TOCTOU 防护）；
 *   2. 装配 VerthysContextV3 → verthys_v3_create_new（三档校准 + 密钥组生成
 *      + 法定人数提交 + 分区创建 + 子系统空态初始化）；
 *   3. 成功：容器即处于解锁态（subsystems_open=1），上下文移交同 unlock。
 */
static VerthysResult verthys_api_v3_create(struct VerthysContext *ctx,
                                       const char *verthys_path,
                                       const char *password, size_t pw_len,
                                       VerthysPreset preset)
{
    FILE *f = NULL;
    VerthysContextV3 *v3 = NULL;
    VerthysResult rc;

    /* 残留清理（应急 DEGRADE 遗留实例：销毁 + 关闭其文件句柄） */
    verthys_api_v3_residual_cleanup(ctx);

#ifdef _WIN32
    /* 原子创建（CREATE_NEW：文件已存在则 ERROR_FILE_EXISTS，不截断）。
     * 共享语义 deny-none（FILE_SHARE_READ|WRITE）：创建成功后句柄即整个
     * 会话的持久容器句柄（容器创建后立即处于解锁态），与解锁路径
     * verthys_api_v3_unlock 的会话句柄共享语义保持一致。
     * 所有权链：CreateFileA → _open_osfhandle → _fdopen → fclose 全链关闭。 */
    {
        HANDLE hFile = CreateFileA(verthys_path,
                                   GENERIC_READ | GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL,
                                   CREATE_NEW,
                                   FILE_ATTRIBUTE_NORMAL,
                                   NULL);
        int fd;
        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            return (err == ERROR_FILE_EXISTS) ? VERTHYS_ERR_EXISTS : VERTHYS_ERR_IO;
        }
        fd = _open_osfhandle((intptr_t)hFile, _O_RDWR | _O_BINARY);
        if (fd < 0) {
            CloseHandle(hFile);
            return VERTHYS_ERR_IO;
        }
        f = _fdopen(fd, "r+b");
        if (f == NULL) {
            _close(fd);
            return VERTHYS_ERR_IO;
        }
    }
#else
    {
        int fd = open(verthys_path, O_RDWR | O_CREAT | O_EXCL | O_BINARY, 0600);
        if (fd < 0) {
            return (errno == EEXIST) ? VERTHYS_ERR_EXISTS : VERTHYS_ERR_IO;
        }
        f = fdopen(fd, "r+b");
        if (f == NULL) {
            close(fd);
            return VERTHYS_ERR_IO;
        }
    }
#endif

    v3 = verthys_v3_ctx_create(&ctx->cng_keys, f, verthys_path);
    if (v3 == NULL) {
        fclose(f);
        return VERTHYS_ERR_INTERNAL;
    }

    /* 进度契约（CreateWithPreset 亦受注册回调约束）：
     * create_new 为整体调用（内部 Argon2id 校准约占时长），编排层
     * 发射起 / 终两级；阶段细分归流水线（unlock 路径）。 */
    ctx->unlock_progress_start_ms = verthys_monotonic_ms();
    verthys_emit_unlock_progress(ctx, VERTHYS_UNLOCK_STAGE_READ_SUPERBLOCK, 5,
                               "正在创建 V3 容器");

    rc = verthys_v3_create_new(v3, password, pw_len, preset);
    if (rc == VERTHYS_OK) {
        free(ctx->file_path);
        ctx->file_path = dup_string(verthys_path);
        ctx->fmt_version = VERTHYS_FMT_V3;
        ctx->preset = preset;       /* 创建语境（GetContainerInfo 源） */
        ctx->warm_cache_enabled =
            !verthys_v3_warmcache_disabled_by_preset(preset);
        ctx->v3 = v3;
        ctx->state = VERTHYS_STATE_UNLOCKED;
        verthys_emit_unlock_progress(ctx, VERTHYS_UNLOCK_STAGE_MERKLE_DONE, 100,
                                   "V3 容器创建完成");
        return VERTHYS_OK;
    }

    /* 失败路径：半写文件留待调用方决策（创建失败不删除——上层可提示
     * 重试或手动清理；盘面由法定人数 + HMAC + WAL 兜底不可误开）。 */
    verthys_v3_ctx_destroy(v3);
    fclose(f);
    return rc;
}

/*
 * V3 单调用事务收口 / 失败收口：公共实现已上移至 verthys_v3_lifecycle
 *（verthys_v3_txn_finish / verthys_v3_txn_abort，export/import 复用）。
 */

/*
 * V3 子系统就绪断言（调用方已持 api_mutex；未就绪 = 状态机违规） */
static int verthys_api_v3_ready(const struct VerthysContext *ctx,
                               VerthysContextV3 **out)
{
    if (ctx->fmt_version != VERTHYS_FMT_V3 || ctx->v3 == NULL) return 0;
    if (!ctx->v3->subsystems_open) return 0;
    *out = ctx->v3;
    return 1;
}

/*
 * V3 精确存活记录数（归并快照计数，调用方已持 api_mutex）：
 * verthys_lsm_estimate_records 为近似值（SSTable 逐表计数 + MemTable 非墓碑，
 * 不做跨层遮蔽归并——MemTable 墓碑遮蔽 SSTable 条目、L0 重叠表同键多版本
 * 均重复计入），record_count / GetSummaryCount 契约要求精确值，此处以与
 * Export 第一遍相同的快照迭代器归并计数（迭代器内建"最新版本胜出 +
 * 墓碑消费全源"语义）。索引结构级损坏整体上抛，不返回部分计数。
 */
static VerthysResult verthys_api_v3_count_records(VerthysContextV3 *v,
                                              uint64_t *out_count)
{
    VerthysLsmScanIter *it = NULL;
    VerthysResult rc;
    uint64_t n = 0;

    rc = verthys_lsm_scan_open(v->lsm, &it);
    if (rc != VERTHYS_OK) return rc;
    for (;;) {
        rc = verthys_lsm_scan_next(it, NULL, NULL, 0, NULL);
        if (rc == VERTHYS_ERR_NOTFOUND) break;    /* 全源耗尽 */
        if (rc != VERTHYS_OK) {
            verthys_lsm_scan_close(it);
            return rc;
        }
        n++;
    }
    verthys_lsm_scan_close(it);
    *out_count = n;
    return VERTHYS_OK;
}

/* ================================================================== *
 * V3：V3 CRUD 编排（api_mutex 已由公共入口独占持有）       *
 *                                                                    *
 * 单调用事务骨架：BEGIN → WRITE_EXTENT → UPDATE_INDEX → PREPARE →    *
 * COMMIT → CONFIRM，失败路径按事务状态机精确收口（rollback / confirm *
 * 兜底（verthys_v3_txn_abort）。尺寸/哈希等 Extent 布局知识经       *
 * verthys_extent_index_find 权威回查——本层不复述密文布局（高内聚）。    *
 * ================================================================== */

/*
 * 新增记录（V3）：单调用事务骨架——BEGIN → verthys_v3_add_record_in_txn
 *（WRITE_EXTENT + UPDATE_INDEX，LID = max_lid + 1 顺序
 * 分配，LID 永不复用红线语义；数据经内容寻址去重，同明文零重写）→
 * PREPARE → COMMIT → CONFIRM。单记录写入逻辑与 Import 批量路径共用
 *（verthys_v3_add_record_in_txn，）。
 */
static VerthysResult verthys_api_v3_add(struct VerthysContext *ctx,
                                    const VerthysRecord *record,
                                    uint64_t *out_id)
{
    VerthysContextV3 *v;
    VerthysResult rc;
    uint64_t lid = 0;

    if (!verthys_api_v3_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    rc = verthys_txn_v3_begin(&v->txn);
    if (rc != VERTHYS_OK) return rc;

    rc = verthys_v3_add_record_in_txn(v, (uint8_t)record->type,
                                    (const uint8_t *)record->name,
                                    record->name_len,
                                    record->data, record->data_len, &lid);
    if (rc != VERTHYS_OK) {
        verthys_v3_txn_abort(v);
        return rc;
    }

    /* PREPARE → COMMIT → CONFIRM（COMMIT 后不可回滚，
     * confirm 失败由下次 open 的崩溃恢复幂等收尾——错误直接上抛） */
    rc = verthys_v3_txn_finish(v);
    if (rc != VERTHYS_OK) return rc;

    *out_id = lid;
    return VERTHYS_OK;
}

/*
 * 读取记录（V3）：LSM 索引查找（MemTable → L0 → L1..，墓碑遮蔽旧值）
 * → Extent 内核态解密（双重完整性：AEAD 认证 + BLAKE2b 内容哈希）。
 * 深拷贝结果缓存于 ctx（借用指针契约与 v1/v2 一致：下次 GetRecord /
 * 写操作 / Lock 前有效）。
 */
static VerthysResult verthys_api_v3_get(struct VerthysContext *ctx,
                                    uint64_t id, VerthysRecord *out_record)
{
    VerthysContextV3 *v;
    VerthysLsmEntry e;
    uint8_t name_buf[VERTHYS_NAME_MAX_BYTES];
    uint8_t *data = NULL;
    uint8_t *name = NULL;
    size_t name_len = 0;
    size_t cap;
    VerthysResult rc;

    if (!verthys_api_v3_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    rc = verthys_lsm_get(v->lsm, id, &e, name_buf, sizeof(name_buf), &name_len);
    if (rc != VERTHYS_OK) return rc;   /* NOTFOUND 透传；AUTH/CORRUPT/IO 原样 */

    /* 索引不变量：Extent 明文长度 == 记录数据长度（AddRecord 写入约定；
     * 背离 = 索引/Extent 交叉损坏 → CORRUPT，杜绝向调用方返回越界长度） */
    if (e.data_size != (uint64_t)e.plaintext_size) return VERTHYS_ERR_CORRUPT;

    /* 解密缓冲（extent_get 契约要求 pt 非 NULL：空数据走 1 字节哑缓冲，
     * 成功后清零丢弃，输出 data=NULL / data_len=0，与 v1/v2 语义一致） */
    cap = (e.plaintext_size > 0) ? (size_t)e.plaintext_size : 1u;
    data = (uint8_t *)malloc(cap);
    if (data == NULL) return VERTHYS_ERR_INTERNAL;

    rc = verthys_extent_get(v->f, v->txn.extent_part, v->ext_idx, e.hash,
                          data, &cap);
    if (rc != VERTHYS_OK) {
        verthys_secure_zero(data, cap);
        free(data);
        return rc;
    }
    if (cap != (size_t)e.plaintext_size) {
        verthys_secure_zero(data, cap);
        free(data);
        return VERTHYS_ERR_CORRUPT;
    }

    if (e.name_len > 0) {
        name = (uint8_t *)malloc(e.name_len);
        if (name == NULL) {
            verthys_secure_zero(data, cap);
            free(data);
            return VERTHYS_ERR_INTERNAL;
        }
        memcpy(name, name_buf, e.name_len);
    }

    /* 借用指针缓存交接（公共入口持 api_mutex，缓存指针仅此处变更；
     * 先备妥新缓存再整体替换——替换原子于锁内，无中间窗口） */
    ctx_free_getrecord_cache(ctx);
    if (e.plaintext_size > 0) {
        ctx->last_getrecord_data       = data;
        ctx->last_getrecord_data_size  = cap;
    } else {
        verthys_secure_zero(data, cap);          /* 哑缓冲清零后丢弃 */
        free(data);
        ctx->last_getrecord_data       = NULL;
        ctx->last_getrecord_data_size  = 0;
    }
    ctx->last_getrecord_name      = name;
    ctx->last_getrecord_name_len  = e.name_len;

    out_record->type     = (VerthysRecordType)e.type;
    out_record->name     = (const char *)name;
    out_record->name_len = e.name_len;
    out_record->data     = (e.plaintext_size > 0) ? data : NULL;
    out_record->data_len = cap;    /* == plaintext_size == data_size（上方校验） */
    return VERTHYS_OK;
}

/*
 * 删除记录（V3）：先探测存在性（API 契约 NOTFOUND；LSM 墓碑本身幂等），
 * 单事务 DELETE（现值 Extent 引用释放 + 墓碑写入 + WAL INDEX 记录）。
 * 同事务内重复删除同一 LID 安全（第二次查找命中墓碑 → NOTFOUND 容忍，
 * 不重复释放引用（verthys_txn_v3_delete）。
 */
static VerthysResult verthys_api_v3_delete(struct VerthysContext *ctx, uint64_t id)
{
    VerthysContextV3 *v;
    VerthysResult rc;

    if (!verthys_api_v3_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    rc = verthys_lsm_get(v->lsm, id, NULL, NULL, 0, NULL);
    if (rc != VERTHYS_OK) return rc;   /* NOTFOUND 透传（契约语义） */

    rc = verthys_txn_v3_begin(&v->txn);
    if (rc != VERTHYS_OK) return rc;

    rc = verthys_txn_v3_delete(&v->txn, id);
    if (rc != VERTHYS_OK) {
        verthys_v3_txn_abort(v);
        return rc;
    }

    return verthys_v3_txn_finish(v);
}

/*
 * 批量删除（V3，单次 flush 刚性要求）：先全量探测（任一不存在 → 整体
 * NOTFOUND，零副作用返回），单事务内逐条 DELETE，一次 PREPARE → COMMIT
 * → CONFIRM 收口——磁盘写入量与条目数解耦（与 v2 批量语义对齐）。
 */
static VerthysResult verthys_api_v3_delete_many(struct VerthysContext *ctx,
                                            const uint64_t *ids, size_t count)
{
    VerthysContextV3 *v;
    VerthysResult rc;

    if (!verthys_api_v3_ready(ctx, &v)) return VERTHYS_ERR_LOCKED;

    /* 预探测（读快照；探测与删除间无并发写者——单写者纪律 + api_mutex） */
    for (size_t i = 0; i < count; i++) {
        rc = verthys_lsm_get(v->lsm, ids[i], NULL, NULL, 0, NULL);
        if (rc != VERTHYS_OK) return rc;   /* 任一 NOTFOUND → 整体拒绝 */
    }

    rc = verthys_txn_v3_begin(&v->txn);
    if (rc != VERTHYS_OK) return rc;

    for (size_t i = 0; i < count; i++) {
        rc = verthys_txn_v3_delete(&v->txn, ids[i]);
        if (rc != VERTHYS_OK) {
            verthys_v3_txn_abort(v);
            return rc;
        }
    }

    return verthys_v3_txn_finish(v);
}

/* 3. 解锁 */
VerthysResult Verthys_Unlock(VerthysHandle handle,
                         const char *verthys_path,
                         const char *password,
                         size_t      password_len,
                         uint32_t    flags)
{
    if (handle == NULL || verthys_path == NULL) return VERTHYS_ERR_INVALID;
    if (password == NULL && password_len != 0) return VERTHYS_ERR_INVALID;
    /* 空口令策略（禁止）：password_len==0 显式拒绝——产品不支持
     * "无口令/纯硬件绑定"形态，空口令容器一律视为不合法输入（含
     * password==NULL 且 len==0）。此策略与前端提交校验一致。 */
    if (password_len == 0) return VERTHYS_ERR_INVALID;

    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;
    if (verthys_backoff_remaining_ms() > 0) return VERTHYS_ERR_RATE;

    /* pepper 来源已确定失败时快速失败（跳过 Argon2id 重计算），
     * 前端得到 VERTHYS_ERR_PEPPER_SOURCE → 提示"保险库安全源已变更"。 */
    if (verthys_pepper_source_error()) return VERTHYS_ERR_PEPPER_SOURCE;

    /* 分发二进制验签（构建期 .vsec 签名比对）。进程内按自身文件
     * 元数据指纹缓存结论：指纹不变直接回放（解锁热路径零节 I/O），
     * 指纹变化（自更新/篡改）强制重算。未配置（开发构建）时为空操作；
     * 验签失败 = 二进制被篡改（高置信度）→ KILL 级上报已发出，
     * 此处返回 VERTHYS_ERR_CORRUPT 拒绝解锁。 */
    if (integrity_verify_startup() != 0) return VERTHYS_ERR_CORRUPT;

    /* 记录本次解锁起始时间戳（单调时钟），供进度回调计算 elapsed_ms
     * 即使未注册回调也无开销（仅一次 64 位赋值） */
    ctx->unlock_progress_start_ms = verthys_monotonic_ms();

    /* （API 版本 0x0005）：解析 flags 位域，设置预热状态
     * 上层 Rust 调度层通过 flags 透传预热完成状态，C 层据此选择最优读取路径：
     *   - prefetch_done=1：索引区已在 OS 页缓存中，可走内存映射零拷贝路径
     *   - prefetch_done=0：未预热，走原有磁盘同步读取路径（向下兼容）
     * 同时更新诊断指标的预热状态枚举。 */
    ctx->unlock_flags = flags;
    ctx->prefetch_done = (flags & VERTHYS_UNLOCK_FLAG_INDEX_PREHEATED) ? 1 : 0;
    ctx->diag_preheat_status = ctx->prefetch_done ? 2 : 0;  /* 2=预热完成, 0=未预热 */

    /* 递归互斥锁保护，防止并发重入
     * 埋点采集读写锁等待耗时（diag_lock_wait_ms） */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) {
        uint64_t _lock_wait_start = verthys_monotonic_ms();
        AcquireSRWLockExclusive(ctx->api_mutex);
        ctx->diag_lock_wait_ms = verthys_monotonic_ms() - _lock_wait_start;
    }
#endif

    VerthysContainerVersion fmt;

    {
        FILE *peek = fopen(verthys_path, "rb");
        if (peek == NULL) {
#ifdef _WIN32
            if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
            return VERTHYS_ERR_IO;
        }
        uint8_t header[128];
        size_t hdr_read = fread(header, 1, sizeof(header), peek);
        fclose(peek);

        if (hdr_read == 0) {
#ifdef _WIN32
            if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
            return VERTHYS_ERR_FORMAT;
        }
        fmt = detect_format(header, hdr_read);
    }

    /* 非 V3 容器 → FORMAT 拒绝（V3 唯一容器格式；旧容器无应用内
     * 迁移路径，数据保全经旧版本导出 / 新版导入完成）。 */
    if (fmt != VERTHYS_FMT_V3) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_FORMAT;
    }

    /* V3：V3 解锁编排 — 流水线 S0-S6（api_mutex 已持，
     * 由 verthys_api_v3_unlock 路径负责释放）。检测头之外零冗余 I/O：
     * 流水线 S1 线程自读 3 副本法定人数裁决。 */
    {
        VerthysResult rc = verthys_api_v3_unlock(ctx, verthys_path, password,
                                             password_len, flags);
        /* 解锁成功（含渐进式 PARTIAL_UNLOCK——最小可操作态）触发
         * 进程级安全钩子：应急信号窗口复位 + 模块巡检 + 防转储巡逻。 */
        if (rc == VERTHYS_OK || rc == VERTHYS_ERR_PARTIAL_UNLOCK) {
            /* V3：运行时函数级哈希
             * 全量校验（.rhat 真表，防内存补丁注入跳转）。失配 = 进程
             * 内存被篡改（高置信度）→ KILL 级应急（进程终止，绝不带着
             * 已解锁密钥继续运行）。置于信号复位之前：篡改态不做任何
             * "恢复性"钩子。 */
            runtime_hash_verify();
            emergency_clear_signals();
            (void)anti_inject_check_modules();
            memory_guard_patrol_start();
        }
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
        /* 修复修复：排空进度环形缓冲区，防止陈旧心跳消息
         * 在最终响应之后到达 stdout 污染 IPC 通信 */
        if (ctx->progress_ring != NULL) {
            verthys_progress_ring_flush((VerthysProgressRing *)ctx->progress_ring);
        }
#endif
        return rc;
    }
}

/* 3a. 显式创建新加密库（V3，可选预设） */
/*
 * V3 新建（新建一律走 V3 路径）：
 * 本接口为系统唯一合法新建入口，新建容器全部走 V3 编排
 * （CNG 内核托管密钥组 + LSM 索引 + 六阶段事务 + 法定人数超级块）。
 */
VerthysResult Verthys_CreateWithPreset(VerthysHandle handle,
                                    const char *verthys_path,
                                    const char *password,
                                    size_t      password_len,
                                    VerthysPreset preset)
{
    if (handle == NULL || verthys_path == NULL) return VERTHYS_ERR_INVALID;
    if (password == NULL && password_len != 0) return VERTHYS_ERR_INVALID;
    /* 空口令策略（禁止）：与解锁入口一致，password_len==0 显式拒绝 */
    if (password_len == 0) return VERTHYS_ERR_INVALID;
    /* 预设合法域：BALANCED / SECURE / PERFORMANCE（V3 三档校准的
     * 三级目标态）。CUSTOM 需安全中心逐项配置，非本接口合法入参。 */
    if (preset != VERTHYS_PRESET_BALANCED && preset != VERTHYS_PRESET_SECURE &&
        preset != VERTHYS_PRESET_PERFORMANCE) {
        return VERTHYS_ERR_INVALID;
    }

    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;

    /* 此 fopen("rb") 仅作 UX 快速失败（避免无谓进入 Argon2id 派生），
     * 真正的 TOCTOU 防护由 verthys_api_v3_create 内的 CreateFileA(CREATE_NEW) 原子创建保障。
     * 即使此处检查通过后恶意进程抢占创建同名文件，原子创建仍会返回 ERROR_FILE_EXISTS。 */
    FILE *probe = fopen(verthys_path, "rb");
    if (probe != NULL) {
        fclose(probe);
        return VERTHYS_ERR_EXISTS;
    }

    return verthys_api_v3_create(ctx, verthys_path, password, password_len, preset);
}

/* 运行时切换安全预设档位。
 *
 * SecurityPreset 与 VerthysPreset 数值一致（0=BALANCED/1=SECURE/
 * 2=PERFORMANCE），此处显式映射不依赖枚举值巧合。
 * security_preset_switch 内部以双缓冲填充 + InterlockedExchangePointer
 * 原子发布：任何时刻读者看到的都是完整配置快照，无全零窗口。
 * 本接口不触碰容器句柄状态（仅校验非 NULL），切换为进程级运行时
 * 配置变更，不要求容器已解锁——应用层在此之前完成会话授权裁决。 */
VerthysResult Verthys_SwitchSecurityPreset(VerthysHandle handle, VerthysPreset preset)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;

    SecurityPreset sp;
    switch (preset) {
        case VERTHYS_PRESET_BALANCED:    sp = SEC_PRESET_BALANCED;    break;
        case VERTHYS_PRESET_SECURE:      sp = SEC_PRESET_SECURE;      break;
        case VERTHYS_PRESET_PERFORMANCE: sp = SEC_PRESET_PERFORMANCE; break;
        /* CUSTOM 无 C 层档位定义，由应用层组合各子系统开关实现 */
        default: return VERTHYS_ERR_INVALID;
    }

    if (security_preset_switch(sp) != 0) {
        return VERTHYS_ERR_INVALID;
    }
    return VERTHYS_OK;
}

/* 4. 锁定（V3-only） */
/*
 * Lock 同步路径的三项必要操作（数据完整性 / 下次解锁性能 / 安全）：
 *   1. 事务收尾（CONFIRM 兜底 / 回滚——数据完整性，必须同步）；
 *   2. LSM 正常关闭 + 温缓存落盘（下次解锁性能，必须同步）；
 *   3. 敏感内存清零（内核态密钥句柄销毁 + 驻留密钥清零，必须同步）。
 *
 * 耗时任务（碎片整理 / 全盘校验）不在 Lock 同步路径——V3 中前者由
 * LSM compaction 后台线程常态承担，后者经 Verthys_VerifyIntegrity 按需执行。
 *
 * 关闭响应指标：窗口隐藏≤100ms，后台完整退出≤1.5s（UI 层配合 window.hide()）
 */
VerthysResult Verthys_Lock(VerthysHandle handle)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->file_path == NULL) return VERTHYS_ERR_INVALID;

    /* V3：V3 锁定路径。
     *
     * verthys_v3_lock 全权承担：
     *   1. 后台预热线程汇合（渐进式解锁场景）；
     *   2. 事务收尾（CONFIRM 兜底 / 回滚——数据完整性，必须同步）；
     *   3. LSM 正常关闭（MemTable flush + Manifest 终态）+
     *      温缓存写入（下次解锁性能，必须同步；SECURE 预设跳过）+
     *      子系统销毁（内核态密钥句柄 + 驻留密钥清零——安全，必须同步）。
     * 返回事务收尾结果（r_txn）：锁定动作本身无条件完成（密钥清除不可
     * 逆转），错误上抛供上层感知数据完整性异常（坦诚直报原则）。
     */
    if (ctx->fmt_version == VERTHYS_FMT_V3) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) {
            AcquireSRWLockExclusive(ctx->api_mutex);
        }
#endif
        VerthysResult rc = VERTHYS_OK;
        if (ctx->v3 != NULL) {
            FILE *f = ctx->v3->f;              /* 借用引用，本分支负责关闭 */
            rc = verthys_v3_lock(ctx->v3);
            verthys_v3_ctx_destroy(ctx->v3);     /* 幂等（子系统已收口） */
            ctx->v3 = NULL;
            if (f != NULL) fclose(f);
        }
        /* GetRecord 借用指针缓存释放（V3 密钥清理已由 subsystems_close
         * 完成，此处仅清缓存） */
        ctx_free_getrecord_cache(ctx);
        ctx->state = VERTHYS_STATE_LOCKED;
#ifdef _WIN32
        if (ctx->api_mutex != NULL) {
            ReleaseSRWLockExclusive(ctx->api_mutex);
        }
#endif
        return rc;
    }

    return VERTHYS_ERR_INTERNAL;
}

/* 5. 新增记录 */
VerthysResult Verthys_AddRecord(VerthysHandle handle,
                            const VerthysRecord *record,
                            uint64_t *out_id)
{
    if (handle == NULL || record == NULL || out_id == NULL) return VERTHYS_ERR_INVALID;
    if (record->name == NULL && record->name_len != 0) return VERTHYS_ERR_INVALID;
    if (record->data == NULL && record->data_len != 0) return VERTHYS_ERR_INVALID;
    /*
     * 名称长度在 API 边界钳制。
     * 索引条目 name_len 为 uint16 存储（verthys_transaction.c 截断赋值），
     * 超 4096 字节的名称会导致"块以全名派生记录密钥、索引以截断名存储"
     * 的密钥/索引分裂 → 重载后记录不可解。上限取 4096（产品语义内
     * 足够宽松，且为索引体积留出确定性上界）。
     */
    if (record->name_len > VERTHYS_NAME_MAX_BYTES) return VERTHYS_ERR_INVALID;

    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* 递归互斥锁保护 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif

    /* 写操作入口统一失效查询缓存，防止 UAF
     * 所有写入操作（增/删/改/导入/改密/刷盘）在持锁后立即清空 getrecord_cache，
     * 消除外部借用指针在 GC 回收旧数据块后变为野指针的 UAF 窗口。
     * 统一收口缓存销毁，写入事务提交前强制清空历史查询缓存。 */
    ctx_free_getrecord_cache(ctx);

    /* V3 写路径周期重算关键函数
     * 运行时哈希（时间门控，距上次全量 <30min 直接返回；首调立即全量）。 */
    runtime_hash_verify_periodic();

    /* V3：V3 新增走六阶段事务编排（api_mutex 已持有） */
    if (ctx->fmt_version != VERTHYS_FMT_V3) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_INTERNAL;
    }
    {
        VerthysResult rc = verthys_api_v3_add(ctx, record, out_id);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc;
    }
}

/* 6. 读取记录 */
VerthysResult Verthys_GetRecord(VerthysHandle handle,
                            uint64_t id,
                            VerthysRecord *out_record)
{
    if (handle == NULL || out_record == NULL) return VERTHYS_ERR_INVALID;

    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* 递归互斥锁保护（借用指针缓存受锁保护） */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif

    /* V3：V3 分发——LSM 索引查找 + Extent 内核态解密；
     * 深拷贝结果经 ctx 借用指针缓存（契约保持，辅助层内
     * 先失效旧缓存再整体替换） */
    if (ctx->fmt_version != VERTHYS_FMT_V3) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_INTERNAL;
    }
    {
        VerthysResult rc3 = verthys_api_v3_get(ctx, id, out_record);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc3;
    }
}

/* 7. 删除记录 */
VerthysResult Verthys_DeleteRecord(VerthysHandle handle, uint64_t id)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;

    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* 递归互斥锁保护 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif

    /* 写操作入口统一失效查询缓存，防止 UAF */
    ctx_free_getrecord_cache(ctx);
    /* V3：写路径周期运行时哈希校验（30min 门控） */
    runtime_hash_verify_periodic();

    /* V3：V3 分发——单事务 DELETE（Extent 引用释放 +
     * LSM 墓碑 + WAL INDEX 记录）；NOTFOUND 契约语义由辅助层透传 */
    if (ctx->fmt_version != VERTHYS_FMT_V3) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_INTERNAL;
    }
    {
        VerthysResult rc3 = verthys_api_v3_delete(ctx, id);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc3;
    }
}

/* 7a. 批量删除记录（单次 flush 刚性要求）
 *
 * 核心收益（V3 语义）：N 条删除仅触发一次事务收口（一次 PREPARE →
 *   COMMIT → CONFIRM），而非 N 次。无论删除多少条记录，磁盘写入量
 *   恒定，仅与索引结构大小相关——连续单条 DeleteRecord 是 N 次完整
 *   事务提交（WAL + 超级块法定人数 + LSM 提交），是 IO 风暴的直接根因。
 *
 * 本函数在单次事务内循环 verthys_txn_v3_delete（墓碑写入 + Extent 引用
 * 释放 + WAL INDEX 记录），最后一次 CONFIRM 统一收口，彻底消除 IO 风暴。
 *
 * @param handle  Verthys 句柄
 * @param ids     待删除记录 ID 数组
 * @param count   数组长度
 * @returns VERTHYS_OK 全部成功；VERTHYS_ERR_NOTFOUND 任一 ID 不存在（整体回滚）
 */
VerthysResult Verthys_DeleteRecords(VerthysHandle handle, const uint64_t *ids, size_t count)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;
    if (ids == NULL && count != 0) return VERTHYS_ERR_INVALID;
    if (count == 0) return VERTHYS_OK;

    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* 递归互斥锁保护 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif

    /* 写操作入口统一失效查询缓存，防止 UAF */
    ctx_free_getrecord_cache(ctx);
    /* V3：写路径周期运行时哈希校验（30min 门控） */
    runtime_hash_verify_periodic();

    /* V3：V3 分发——单事务批量 DELETE（一次 PREPARE → COMMIT
     * → CONFIRM 收口，磁盘写入量与条目数解耦；
     * 任一 ID 不存在 → 整体 NOTFOUND 零副作用返回） */
    if (ctx->fmt_version != VERTHYS_FMT_V3) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_INTERNAL;
    }
    {
        VerthysResult rc3 = verthys_api_v3_delete_many(ctx, ids, count);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc3;
    }
}

/* 获取存活记录总数（V3-only）
 *
 * V3 语义：LSM 归并快照精确计数（无摘要缓存，现值直读，与
 * GetContainerInfo.record_count 同源同值）。前端可据此直接渲染列表。
 * 索引结构级损坏整体拒绝，不返回部分计数。
 */
VerthysResult Verthys_GetSummaryCount(VerthysHandle handle, uint64_t *out_count)
{
    if (handle == NULL || out_count == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* 收尾：LSM 归并快照精确计数（无摘要缓存，现值直读，与
     * GetContainerInfo.record_count 同源同值）。索引结构级损坏整体
     * 拒绝，不返回部分计数。 */
    {
        VerthysContextV3 *v = ctx->v3;
        uint64_t live = 0;
        VerthysResult rc;
        if (v == NULL || !v->subsystems_open) return VERTHYS_ERR_INTERNAL;
#ifdef _WIN32
        if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif
        rc = verthys_api_v3_count_records(v, &live);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        if (rc != VERTHYS_OK) return rc;
        *out_count = live;
        return VERTHYS_OK;
    }
}

/* ================================================================== *
 * 内建诊断接口             *
 *                                                                    *
 * 返回结构化性能与状态指标（解锁耗时分解/缓存命中率/GC 触发次数等）， *
 * 供安全中心展示和问题定位。所有指标均为非敏感数据。                  *
 *                                                                    *
 * 线程安全：MT-Const（只读操作，可与其它只读操作并发）               *
 * ================================================================== */
VerthysResult Verthys_GetDiagnostics(VerthysHandle handle, VerthysDiagnostics *out_diag)
{
    if (handle == NULL || out_diag == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;

    /* 读操作使用共享锁（AcquireSRWLockShared），允许多个读取并发执行
     *   诊断数据为非敏感指标，可与 GetRecord/GetContainerInfo/VerifyIntegrity/Export 并发 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif

    memset(out_diag, 0, sizeof(*out_diag));

    /* 解锁耗时分解（最近一次解锁） */
    out_diag->unlock_total_ms       = ctx->diag_unlock_total_ms;
    out_diag->unlock_read_ms        = ctx->diag_unlock_read_ms;
    out_diag->unlock_derive_ms      = ctx->diag_unlock_derive_ms;
    out_diag->unlock_index_load_ms  = ctx->diag_unlock_index_load_ms;
    out_diag->unlock_summary_load_ms= ctx->diag_unlock_summary_load_ms;
    out_diag->unlock_merkle_ms      = ctx->diag_unlock_merkle_ms;

    /* 缓存指标 */
    out_diag->warm_cache_hits       = ctx->diag_warm_cache_hits;
    out_diag->warm_cache_misses     = ctx->diag_warm_cache_misses;
    out_diag->warm_cache_evictions  = ctx->diag_warm_cache_evictions;

    /* 事务与 GC 指标 */
    out_diag->gc_trigger_count      = ctx->diag_gc_trigger_count;
    out_diag->gc_reclaimed_slots    = ctx->diag_gc_reclaimed_slots;
    out_diag->commit_count          = ctx->diag_commit_count;
    out_diag->rollback_count        = ctx->diag_rollback_count;

    /* 扫描指标 */
    out_diag->scan_open_count       = ctx->diag_scan_open_count;
    out_diag->scan_snapshot_stale   = ctx->diag_scan_snapshot_stale;

    /* 胡椒来源（诊断，不暴露胡椒值） */
    out_diag->pepper_source         = (uint8_t)verthys_pepper_get_source();

    /* 可观测性指标扩展（5 项新增指标） */
    out_diag->lock_wait_ms          = ctx->diag_lock_wait_ms;
    out_diag->cache_load_ms         = ctx->diag_cache_load_ms;
    out_diag->disk_bytes_read       = ctx->diag_disk_bytes_read;
    out_diag->page_cache_hit_ratio  = (uint32_t)ctx->diag_page_cache_hit_ratio;
    out_diag->preheat_status        = ctx->diag_preheat_status;

    /* 索引内存映射失败告警累计指标（运维可观测性闭环） */
    out_diag->idx_mmap_fallback_count = ctx->diag_idx_mmap_fallback_count;

    /* 自适应 Argon2id 漂移监控指标 */
    out_diag->argon2_baseline_ms    = ctx->argon2_baseline_ms;
    out_diag->argon2_last_derive_ms = ctx->argon2_last_derive_ms;
    out_diag->argon2_drift_count    = ctx->argon2_drift_count;
    out_diag->argon2_auto_degraded  = (uint32_t)ctx->argon2_auto_degraded;

#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
    return VERTHYS_OK;
}

/* ================================================================== *
 * V3（API 版本 0x000B）：
 * 动态防护状态查询
 *
 * 每次调用执行 RUNTIME 级实时复检（defense_closure_check 内部
 * SRWLOCK 串行化，并发调用安全）；防御状态为进程级事实，不依赖
 * 容器解锁状态，锁定态/未挂载态均可查询。
 *
 * 线程安全：MT-Safe
 * ================================================================== */

/* 公共枚举镜像与内部枚举值域对齐的编译期契约
 * （Verthys_GetSecurityStatus 逐字段映射的正确性依赖此对齐） */
_Static_assert((int)VERTHYS_DEFENSE_NOT_CHECKED == (int)DEFENSE_STATE_NOT_CHECKED &&
               (int)VERTHYS_DEFENSE_BLOCKED     == (int)DEFENSE_STATE_BLOCKED &&
               (int)VERTHYS_DEFENSE_DEGRADED    == (int)DEFENSE_STATE_DEGRADED &&
               (int)VERTHYS_DEFENSE_FAILED      == (int)DEFENSE_STATE_FAILED,
               "public VerthysDefenseState out of sync with internal DefenseState");
_Static_assert((int)VERTHYS_DEFENSE_PATH_COUNT == (int)DEFENSE_PATH_COUNT,
               "public VerthysDefensePath count out of sync with internal DefensePath");

VerthysResult Verthys_GetSecurityStatus(VerthysHandle handle,
                                    VerthysSecurityStatus *out_status)
{
    if (handle == NULL || out_status == NULL) return VERTHYS_ERR_INVALID;

    /* handle 仅作调用方身份校验：防御状态为进程级，不触碰句柄可变
     * 状态，无需进入句柄锁，锁定态（含应急 DEGRADE 遗留）可查询。 */
    DefenseStatusReport report;
    if (defense_closure_check(DEFENSE_CHECK_RUNTIME, &report) != 0) {
        /* RUNTIME 模式契约恒返回 0；此分支为防御性顶层错误映射 */
        return VERTHYS_ERR_INTERNAL;
    }

    memset(out_status, 0, sizeof(*out_status));
    for (int i = 0; i < DEFENSE_PATH_COUNT; i++) {
        out_status->path_state[i] = (VerthysDefenseState)report.path_state[i];
    }
    out_status->blocked_count        = report.blocked_count;
    out_status->degraded_count       = report.degraded_count;
    out_status->failed_count         = report.failed_count;
    out_status->all_critical_blocked = (uint8_t)report.all_critical_blocked;
    out_status->has_degraded         = (uint8_t)report.has_degraded;
    return VERTHYS_OK;
}

/* ================================================================== *
 * Verthys_Flush 显式刷盘接口
 *                                                                    *
 * 在不锁定的情况下主动将内存中的索引变更刷写到磁盘，                *
 * 保证崩溃恢复一致性。                                               *
 *                                                                    *
 * V3（V3-only）：MemTable 强制 flush（冻结落盘 L0 SSTable → Manifest  *
 * 原子提交 → WAL 复位，全链 _commit 物理落盘）；空 MemTable 为 no-op  *
 *                                                                    *
 * 线程安全：MT-Safe（内部递归互斥锁保护）                            *
 * ================================================================== */
VerthysResult Verthys_Flush(VerthysHandle handle)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* 递归互斥锁保护 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif

    /* 写操作入口统一失效查询缓存，防止 UAF */
    ctx_free_getrecord_cache(ctx);
    /* V3：写路径周期运行时哈希校验（30min 门控） */
    runtime_hash_verify_periodic();

    /* V3：V3 刷盘路径。
     *
     * V3 无长事务（单调用事务以 CONFIRM 收口），Flush 的持久化对象是
     * LSM MemTable 中已提交条目：verthys_lsm_flush 冻结当前表 → 落盘 L0
     * SSTable（fsync）→ Manifest 原子提交（fsync）→ WAL 复位（提交
     * 边界语义同 verthys_lsm.h）；空 MemTable 幂等 no-op。
     * 事务状态机保护：ACTIVE 态调用 Flush = 调用方在事务中途触碰
     * 独立入口（API 单调用事务契约下不可达），拒绝并保持现场。 */
    if (ctx->fmt_version != VERTHYS_FMT_V3) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_INTERNAL;
    }
    {
        VerthysResult rc3;
        VerthysContextV3 *v3 = ctx->v3;

        if (v3 == NULL || !v3->subsystems_open) {
#ifdef _WIN32
            if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
            return VERTHYS_ERR_LOCKED;
        }
        /* 事务状态机保护：仅拒绝事务中途态（ACTIVE/PREPARED/COMMITTED——
         * 调用方在单调用事务未收口时触碰独立入口，API 契约下不可达）。
         * 静息态（IDLE/CONFIRMED/ABORTED）与 verthys_txn_v3_begin 的可开新
         * 事务状态集一致：CONFIRMED 是已确认事务的正常终态（begin 接受），
         * MemTable 中已提交条目正是 Flush 的持久化对象。 */
        {
            VerthysTxnV3State st = verthys_txn_v3_state(&v3->txn);
            if (st != VERTHYS_TXN_V3_IDLE && st != VERTHYS_TXN_V3_CONFIRMED &&
                st != VERTHYS_TXN_V3_ABORTED) {
#ifdef _WIN32
                if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
                return VERTHYS_ERR_INTERNAL;
            }
        }

        rc3 = verthys_lsm_flush(v3->lsm);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc3;
    }
}

/* ================================================================== *
 * Verthys_GetContainerInfo 诊断接口                     *
 *                                                                    *
 * 获取容器元数据（只读，不暴露密钥），供安全中心/状态指示器使用。    *
 *                                                                    *
 * 线程安全：MT-Const（只读操作，可与其它只读操作并发）               *
 * ================================================================== */
VerthysResult Verthys_GetContainerInfo(VerthysHandle handle, VerthysContainerInfo *out_info)
{
    if (handle == NULL || out_info == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* 读操作使用共享锁（AcquireSRWLockShared），允许多个读取并发执行
     *   容器元数据为只读访问，可与 GetDiagnostics/VerifyIntegrity/Export 并发 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif

    memset(out_info, 0, sizeof(*out_info));
    out_info->api_version = VERTHYS_API_VERSION;
    out_info->fmt_version = 3;
    out_info->preset = (uint16_t)ctx->preset;
    out_info->last_fullscan_time = ctx->last_fullscan_time;
    out_info->warm_cache_enabled = (uint8_t)ctx->warm_cache_enabled;

    /* 收尾：V3 唯一数据通路——超级块/LSM/分区表为权威数据源
     * （无 ctx 镜像字段依赖，全部现值直读，杜绝解锁时快照过期）。
     * 就绪断言与 CRUD 同规：UNLOCKED 且 subsystems_open 方可报告。 */
    {
        VerthysContextV3 *v = ctx->v3;
        uint64_t live = 0;
        if (v == NULL || !v->subsystems_open || v->lsm == NULL) {
#ifdef _WIN32
            if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
            return VERTHYS_ERR_INTERNAL;
        }
        out_info->txid = v->sb.txid;
        /* record_count：归并快照精确计数（estimate 为近似值，见
         * verthys_api_v3_count_records 注记）；索引结构级损坏整体拒绝 */
        {
            VerthysResult cr = verthys_api_v3_count_records(v, &live);
            if (cr != VERTHYS_OK) {
#ifdef _WIN32
                if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
                return cr;
            }
        }
        out_info->record_count = live;
        out_info->index_region_size = v->sb.index_partition_size;
        out_info->data_region_size = v->sb.extent_partition_size;
        /* Extent 分区已用字节（含待 GC 回收块，与 v2 data_used_bytes 语义
         * 对齐：写路径随追加推进，GC 前单调不减） */
        out_info->data_used_bytes =
            (v->txn.extent_part != NULL) ? v->txn.extent_part->used : 0;
        /* last_modified_time：sb.updated_at（FILETIME，事务提交点更新）
         * → Unix 秒。FILETIME(1601 纪元,100ns) → Unix(1970 纪元,秒)。 */
        out_info->last_modified_time =
            (v->sb.updated_at > UINT64_C(116444736000000000))
                ? (v->sb.updated_at - UINT64_C(116444736000000000))
                      / UINT64_C(10000000)
                : 0;
        /* V3 无 mount_count / cumulative_write_bytes 记账（挂载审计属
         * Audit 分区职责；防回滚由超级块 state_chain 密码学承担）——
         * 如实报告 0，不伪造数据。merkle_pending 同理为 0：V3 超级块
         * merkle_root 为提交点同步锚定，无后台重建窗口。 */
        out_info->mount_count = 0;
        out_info->cumulative_write_bytes = 0;
        out_info->merkle_pending = 0;
        /* container_id：V3 为 32B（VERTHYS_V3_CONTAINER_ID_BYTES），公共
         * 结构体契约 16B——截取前 16B（展示标识，非完整性键） */
        memcpy(out_info->container_id, v->sb.container_id, 16);
    }

#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
    return VERTHYS_OK;
}

/* ================================================================== *
 * Verthys_VerifyIntegrity 独立完整性校验接口             *
 *                                                                    *
 * 执行全量 Merkle 树校验 + 数据块 AEAD 标签验证，                   *
 * 返回校验结果与损坏 LID 列表。                                      *
 *                                                                    *
 * 标准化错误模型                  *
 *   采用"检查类 API 惯例"：                                          *
 *   - 校验操作成功完成 → 返回 VERTHYS_OK（无论是否发现损坏）           *
 *   - 发现损坏记录 → 通过 out_failed_count > 0 表明，out_failed_lids  *
 *     输出对应 LID 列表，前端据此标记损坏条目并支持跳过/修复         *
 *   - 仅当参数非法、库未解锁、内部状态错误时返回错误码               *
 *   VERTHYS_ERR_CORRUPT 保留给读取类接口（GetRecord/ScanFetch）在      *
 *   单条记录遭遇损坏时使用，本接口不返回此码。                       *
 *                                                                    *
 * 耗时较长（万级记录约数秒），建议在后台线程调用。                   *
 *                                                                    *
 * 线程安全：MT-Unsafe（遍历期间不可并发写操作）                      *
 * ================================================================== */
VerthysResult Verthys_VerifyIntegrity(VerthysHandle handle,
                                  uint64_t *out_failed_lids,
                                  uint64_t max_failed,
                                  uint64_t *out_failed_count)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;
    if (out_failed_count == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    uint64_t local_failed_count = 0;

    /* 递归互斥锁保护（遍历期间阻止并发写） */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif

    if (ctx->fmt_version != VERTHYS_FMT_V3) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        return VERTHYS_ERR_INTERNAL;
    }

    /* 收尾：V3 唯一数据通路——LSM 快照全量遍历 + 逐条 Extent 双重
     * 完整性验证（AEAD 认证 + BLAKE2b 内容哈希，verthys_extent_get
     * 内建）。语义（检查类 API 惯例）：
     *   - 单条数据损坏（AUTH/CORRUPT/NOTFOUND/长度不符/索引不变量
     *     破坏）→ 记入 failed LID，遍历继续（检查类 API 惯例：
     *     返回 VERTHYS_OK，损坏经 out_failed_count 表明）；
     *   - 索引结构级损坏（迭代器中途 AUTH/IO，无法继续枚举）→
     *     整体拒绝上抛（与 Export 同纪律：杜绝静默不完整校验）。 */
    {
        VerthysContextV3 *v = ctx->v3;
        VerthysLsmScanIter *it = NULL;
        VerthysResult src;
        if (v == NULL || !v->subsystems_open || v->lsm == NULL ||
            v->ext_idx == NULL || v->txn.extent_part == NULL) {
#ifdef _WIN32
            if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
            return VERTHYS_ERR_INTERNAL;
        }

        src = verthys_lsm_scan_open(v->lsm, &it);
        if (src != VERTHYS_OK) {
#ifdef _WIN32
            if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
            return src;
        }
        {
            VerthysLsmEntry e;
            uint8_t name_buf[VERTHYS_NAME_MAX_BYTES];
            size_t name_len = 0;
            for (;;) {
                src = verthys_lsm_scan_next(it, &e, name_buf,
                                          sizeof(name_buf), &name_len);
                if (src == VERTHYS_ERR_NOTFOUND) break;    /* 全源耗尽 */
                if (src != VERTHYS_OK) {
                    /* 结构级损坏：校验未完成，不可伪报干净结果 */
                    verthys_lsm_scan_close(it);
#ifdef _WIN32
                    if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
                    return src;
                }
                /* FREE 槽位跳过（与 v2 分支 / FindFirstLidByType 同规） */
                if (e.slot_state == VERTHYS_SLOT_FREE) continue;

                /* 索引不变量（与 GetRecord 同规）：背离即索引/Extent
                 * 交叉损坏，按损坏条目记账 */
                if (e.data_size != (uint64_t)e.plaintext_size) {
                    if (out_failed_lids != NULL &&
                        local_failed_count < max_failed) {
                        out_failed_lids[local_failed_count] = e.lid;
                    }
                    local_failed_count++;
                    continue;
                }
                {
                    /* 解密缓冲（extent_get 契约 pt 非 NULL：空数据走
                     * 1 字节哑缓冲，与 GetRecord 同规） */
                    size_t alloc_len =
                        (e.plaintext_size > 0) ? (size_t)e.plaintext_size : 1u;
                    size_t cap = alloc_len;
                    uint8_t *data = (uint8_t *)malloc(alloc_len);
                    VerthysResult r2;
                    if (data == NULL) {
                        verthys_lsm_scan_close(it);
#ifdef _WIN32
                        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
                        return VERTHYS_ERR_INTERNAL;
                    }
                    r2 = verthys_extent_get(v->f, v->txn.extent_part,
                                          v->ext_idx, e.hash, data, &cap);
                    if (r2 != VERTHYS_OK || cap != (size_t)e.plaintext_size) {
                        if (out_failed_lids != NULL &&
                            local_failed_count < max_failed) {
                            out_failed_lids[local_failed_count] = e.lid;
                        }
                        local_failed_count++;
                    }
                    /* 仅校验不留存：明文即读即清（敏感数据不驻留） */
                    verthys_secure_zero(data, alloc_len);
                    free(data);
                }
            }
        }
        verthys_lsm_scan_close(it);
        it = NULL;

        /* 更新全量校验时间戳（Verthys_VerifyIntegrity 提交点记账） */
        ctx->last_fullscan_tx = v->sb.txid;
        ctx->last_fullscan_time = (uint64_t)time(NULL);
        ctx->incremental_count = 0;
    }

#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif

    if (out_failed_count != NULL) {
        *out_failed_count = local_failed_count;
    }

    /* 检查类 API 惯例
     * 校验操作本身成功完成即返回 VERTHYS_OK；
     * 是否发现损坏由 *out_failed_count > 0 表明（调用方必填此参数）。
     * 不再返回 VERTHYS_ERR_CORRUPT，该错误码保留给读取类接口使用。 */
    return VERTHYS_OK;
}
