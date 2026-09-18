/*
 * verthys_internal.h — DLL 内部共享头（不导出，不暴露给外部）
 *
 * 定义 VerthysContext 内部结构、内部状态、内部工具函数原型。
 * 外部仅见 verthys.h 的不透明句柄；此头仅供 src/ 内部使用。
 *
 * ★ V3 架构（§1.4 V2 退役后唯一支持的容器格式）：
 *   - CNG 内核托管密钥组（MEK/A/B/C 句柄化，用户态零密钥数组）
 *   - 法定人数三副本超级块（FlatBuffers 帧 + state_chain 防回滚）
 *   - LSM 索引（MemTable 跳表 + SSTable + 分级 Compaction）
 *   - Extent 内容寻址数据区（BLAKE2b 去重 + AEAD）
 *   - 六 Phase 事务（WAL 环形双缓冲 + CONFIRM 收口）
 *   - V3 温启动缓存（'V3IC'，HMAC + txid 双校验）
 *
 * ★ §1.4 V2 退役（V3_UPGRADE_PLAYBOOK）：V1/V2 字段（salt/dek/
 *   key_a/b/c/master_key、records 数组、superblock、btree、dblock_mgr、
 *   merkle、txn、watcher、mount_watcher、summary_records 等）随删除清单
 *   整体摘除。V3 权威数据源全部位于 VerthysContextV3（api/verthys_v3_lifecycle.h），
 *   本结构仅保留 API 层编排状态、诊断指标与安全治理字段。
 */
#ifndef VERTHYS_INTERNAL_H
#define VERTHYS_INTERNAL_H

#include "verthys.h"
#include "keymanager_cng.h"
#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
#endif

/* 加密库状态机 */
typedef enum {
    VERTHYS_STATE_UNINIT   = 0,  /* 仅 Init 后，未关联文件 */
    VERTHYS_STATE_LOCKED   = 1,  /* 已关联文件，密钥不在内存 */
    VERTHYS_STATE_UNLOCKED = 2   /* 已解锁，密钥驻留受保护内存 */
} VerthysState;

/* 容器格式版本（运行时检测）。
 * §1.4 V2 退役：V3 为唯一合法容器格式——V1/V2 枚举随删除清单移除，
 * Unlock 格式门禁对非 V3 头一律 VERTHYS_ERR_FORMAT（"V3 不读 V2 文件"）。 */
typedef enum {
    VERTHYS_FMT_NONE = 0,  /* 未挂载容器（Init 零态）或未知/非法格式 */
    VERTHYS_FMT_V3   = 3   /* V3：CNG 内核托管 + LSM + 法定人数超级块 */
} VerthysContainerVersion;

/* 前向声明：V3 运行时上下文（api/verthys_v3_lifecycle.h） */
struct VerthysContextV3;

/* ★ V3 升级 WP-7：安全分配器（v5.0 §5.2 VerthysContext 目标态字段）
 * 密钥相关结构专用隔离堆：VirtualAlloc 区段 + PAGE_GUARD 边界页 +
 * VirtualLock 锁页 + 释放前清零；全局预算记账（性能架构 §4.1）。
 * Verthys_Init 创建 / Verthys_Deinit 销毁。 */
typedef struct SecureAllocator SecureAllocator;

/* ★ P1-9：记录名称长度上限（API 边界钳制，杜绝 uint16 截断导致的
 * 密钥派生/索引存储分裂） */
#define VERTHYS_NAME_MAX_BYTES 4096u

/*
 * VerthysContext — 句柄背后的真实结构。
 * 所有敏感字段在 Lock/Deinit 时经 verthys_secure_zero / CNG 句柄销毁清理。
 *
 * V3 数据源纪律：超级块 / LSM / Extent / 分区表 / 事务全部位于
 * ctx->v3（VerthysContextV3 堆实例），本结构不持有任何容器数据镜像——
 * GetContainerInfo / GetDiagnostics 类接口一律现值直读权威源。
 */
struct VerthysContext {
    VerthysState state;

    /* 文件路径（heap 副本，Lock 时写回） */
    char *file_path;

    /* 容器格式版本（运行时检测；§1.4 退役后仅 VERTHYS_FMT_V3 合法） */
    VerthysContainerVersion fmt_version;

    /* ★ V3 升级 WP-5：V3 运行时上下文（堆实例）。
     * fmt_version == VERTHYS_FMT_V3 时非 NULL；Init 分配 / Deinit 释放
     * （verthys_v3_ctx_create / verthys_v3_ctx_destroy）。
     * 容器 Lock/再解锁后本指针更换堆实例——借用方（扫描游标等）经
     * 实例身份锚点检测失效。 */
    struct VerthysContextV3 *v3;

    /* ★ V3 升级 WP-1：CNG 内核托管密钥组（v5.0 §5.2 目标态）
     * MEK/A/B/C 全部经 BCryptGenerateSymmetricKey 导入内核，用户态仅持
     * BCRYPT_KEY_HANDLE 句柄（不可导出）。经 verthys_cng_km_* 接口访问；
     * Lock/Deinit/紧急熔断 → verthys_cng_km_destroy_all（内核态密钥
     * 不可恢复）。 */
    VerthysCngKeyManager cng_keys;    /* CNG 内核密钥组 + 生命周期状态机 */

    /* ★ V3 升级 WP-7：密钥相关结构专用隔离堆（v5.0 §5.2）。
     * Init 创建 / Deinit 销毁。 */
    SecureAllocator *secure_alloc;

    /* 用户预设（公共枚举 VerthysPreset；V3 权威值持久化于超级块扩展 TLV，
     * 解锁时裁决回填——GetContainerInfo 数据源） */
    VerthysPreset preset;

    /* 温启动缓存启用标志（V3：由预设裁决——SECURE 禁用） */
    int warm_cache_enabled;

    /* 全量校验状态（Verthys_VerifyIntegrity 提交点记账） */
    uint64_t last_fullscan_tx;      /* 上次全量校验时的 TxID */
    uint64_t last_fullscan_time;    /* 上次全量校验时间戳 */
    uint64_t incremental_count;     /* 自上次全量校验以来的增量提交次数 */

    /* 暴力破解退避（project.md 5.3：指数退避，2^k 秒，最长 1 小时）
     * 基于单调时钟（GetTickCount64），不受系统时间篡改影响。 */
    uint32_t failed_attempts;   /* 连续失败次数 */
    uint64_t last_failed_tick;  /* 最近一次失败时的单调毫秒计数，0=无失败 */

    /* GetRecord 借用指针缓存（API 契约：下次调用或 Lock 前有效）
     * V3 路径返回深拷贝数据，缓存在此，下次 GetRecord 或 Lock 时释放。
     * 借用指针语义要求 GetRecord 独占访问（api_mutex 写锁）。 */
    uint8_t *last_getrecord_data;   /* 上次 GetRecord 返回的数据（heap） */
    size_t   last_getrecord_data_size;
    uint8_t *last_getrecord_name;   /* 上次 GetRecord 返回的名称（heap） */
    size_t   last_getrecord_name_len;

    /* ★ Comprehensive_optimization 第八部分 四.1：读写锁（SRWLock）
     * ★ 方案三：细粒度读写锁 — 读共享锁 / 写独占锁，锁域隔离
     *
     *   共享读锁（AcquireSRWLockShared，并发放行）：
     *     - Verthys_GetDiagnostics   — 诊断指标读取（非敏感数据）
     *     - Verthys_GetContainerInfo — 容器元数据读取
     *     - Verthys_VerifyIntegrity  — 全量校验（只读遍历）
     *     - Verthys_Export           — 导出读取全部记录
     *
     *   独占写锁（AcquireSRWLockExclusive，排他阻塞）：
     *     - Verthys_AddRecord / Verthys_DeleteRecord / Verthys_DeleteRecords
     *     - Verthys_Flush / Verthys_Import / Verthys_ChangePassword
     *     - Verthys_Unlock / Verthys_Lock（状态切换）
     *
     *   特殊独占读（AcquireSRWLockExclusive）：
     *     - Verthys_GetRecord — 借用指针缓存（ctx->last_getrecord_data）
     *       序列化访问，杜绝并发释放引发的 use-after-free。
     *
     * 生命周期：Verthys_Init 时分配并 InitializeSRWLock（零初始化），
     *           Verthys_Deinit 时直接释放（SRWLOCK 无需 Delete）。 */
#ifdef _WIN32
    SRWLOCK *api_mutex;          /* 读写锁（heap 分配，SRWLOCK） */
    /* ★ 方案六：进度回调无锁环形缓冲区（异步解耦）
     *   verthys_emit_unlock_progress 写入环形缓冲区（O(1) <1μs），
     *   独立低优先级消费线程读取并调用 unlock_progress_cb。
     *   主解锁链路零阻塞，彻底杜绝回调阻塞（D-010 修复）。
     *   NULL = 未注册回调或非 Windows 平台（verthys_emit_unlock_progress 为空操作）。 */
    void *progress_ring;         /* VerthysProgressRing*（opaque，定义在 verthys_api.c） */
#endif

    /* ★ Comprehensive_optimization 第八部分 八.1/八.3：诊断指标 + 性能遥测
     *
     * 解锁耗时分解：每次 Verthys_Unlock 时采集，Verthys_GetDiagnostics
     * 返回给安全中心展示。计数器在事务提交/回滚/扫描时递增，供性能
     * 分析与问题定位。全部为非敏感指标，不含任何密钥或用户数据。 */
    uint64_t diag_unlock_total_ms;        /* 解锁总耗时 */
    uint64_t diag_unlock_read_ms;         /* 文件读取耗时 */
    uint64_t diag_unlock_derive_ms;       /* 密钥派生耗时 */
    uint64_t diag_unlock_index_load_ms;   /* 索引加载耗时 */
    uint64_t diag_unlock_summary_load_ms; /* 摘要索引加载耗时 */
    uint64_t diag_unlock_merkle_ms;       /* Merkle 树创建耗时 */
    uint64_t diag_warm_cache_hits;        /* 温缓存命中次数 */
    uint64_t diag_warm_cache_misses;      /* 温缓存未命中次数 */
    uint64_t diag_warm_cache_evictions;   /* 温缓存淘汰次数 */
    uint64_t diag_gc_trigger_count;       /* GC 触发次数 */
    uint64_t diag_gc_reclaimed_slots;     /* GC 回收槽位总数 */
    uint64_t diag_commit_count;           /* 事务提交总次数 */
    uint64_t diag_rollback_count;         /* 事务回滚次数 */
    uint64_t diag_scan_open_count;        /* 扫描游标打开次数 */
    uint64_t diag_scan_snapshot_stale;    /* 快照过期次数 */

    /* ★ 方案5：解锁进度回调（API 版本 0x0004）
     *
     * 由 Verthys_RegisterUnlockProgressCallback 注册，在解锁流水线
     * 各阶段经环形缓冲区异步调用。回调函数指针与 user_data 透传，
     * DLL 不解析 user_data 内容。
     *
     * 生命周期：Verthys_Init 时 calloc 清零（NULL），Verthys_Deinit 时随 ctx 释放。
     * 注册后对所有后续 Unlock / CreateWithPreset 调用生效，传 NULL 取消通知。
     *
     * 线程安全：与 Unlock 共享同一调用线程，无需额外同步（MT-Unsafe 语义保证）。 */
    VerthysUnlockProgressCallback unlock_progress_cb;   /* 进度回调函数（NULL=不通知） */
    void                       *unlock_progress_user_data;  /* 透传用户数据 */
    uint64_t                    unlock_progress_start_ms;   /* 本次解锁起始时间戳（单调时钟） */

    /* ★ 方案九（API 版本 0x0005）：预热状态跨层透传
     *
     * 由 Verthys_Unlock 的 flags 参数设置，记录上层调度层的预热状态，
     * 供解锁流水线选择预热线程参数。
     *
     * 生命周期：每次 Verthys_Unlock 入口重置，由 flags 参数设置。 */
    uint32_t unlock_flags;           /* 本次解锁的 flags 位域（VERTHYS_UNLOCK_FLAG_*） */
    int      prefetch_done;          /* 索引区是否已预热（flags & 0x01），1=是 0=否 */

    /* ★ 方案八：可观测性指标扩展（5 项新增指标）
     *
     * 在解锁路径埋点采集，Verthys_GetDiagnostics 输出。 */
    uint64_t diag_page_cache_hit_ratio;   /* 页缓存命中率（百分比，0~100） */
    uint64_t diag_lock_wait_ms;           /* 读写锁平均等待耗时（毫秒） */
    uint64_t diag_cache_load_ms;          /* 持久化缓存加载耗时（毫秒） */
    uint64_t diag_disk_bytes_read;        /* 本次解锁磁盘实际读取字节数 */
    uint32_t diag_preheat_status;         /* 预热状态枚举（0=未预热/1=预热中/2=预热完成/3=预热失败） */

    /* ★ 方案二：索引内存映射失败告警计数（跨多次解锁累计）
     *
     * 预热完成但映射失败回退同步读取时递增，上报
     * idx_mmap_fallback_count 字段（环境异常的运维可观测性闭环）。 */
    uint32_t diag_idx_mmap_fallback_count;  /* 索引内存映射失败回退次数（累计） */

    /* ★ 方案七：自适应 Argon2id 运行时漂移监控
     *
     * 基准值从容器参数读取（创建时跑分记录）。
     * 每次解锁记录 Argon2id 派生耗时，与基准比较：
     *   - 超基准 30%（elapsed * 100 > baseline * 130）：drift_count++
     *   - 连续 VERTHYS_ARGON2_DRIFT_THRESHOLD(3) 次漂移：标记 auto_degraded=1
     *   - 连续 VERTHYS_ARGON2_RECOVER_THRESHOLD(3) 次达标：清除 auto_degraded
     *
     * auto_degraded=1 时通过 Verthys_GetDiagnostics 上报安全中心，
     * 建议下次创建容器使用更低档位（SECURE→BALANCED→PERFORMANCE）。
     * 不改变当前容器的 Argon2id 参数（密钥派生结果不变，安全性不降级）。 */
    uint32_t argon2_baseline_ms;          /* 基准派生耗时（毫秒，0=未建立） */
    uint32_t argon2_last_derive_ms;       /* 最近一次 Argon2id 派生耗时（毫秒） */
    uint32_t argon2_drift_count;          /* 连续漂移次数（超基准 30%） */
    uint32_t argon2_normal_count;         /* 连续达标次数（用于恢复判定） */
    int      argon2_auto_degraded;        /* 自动降级标志（0=正常, 1=已降级） */
};

/* ---------- 内部安全内存工具（不导出） ---------- */

/* 安全清零：编译器不可优化掉的内存擦除 */
void verthys_secure_zero(void *ptr, size_t len);

/* 锁定内存页，防止换页到磁盘。返回 0 成功，非 0 失败 */
int  verthys_lock_memory(void *ptr, size_t len);

/* 解锁内存页 */
int  verthys_unlock_memory(void *ptr, size_t len);

/* ================================================================== *
 * ★ Comprehensive_optimization 第八部分 八.2：安全内存清零编译期强化     *
 *                                                                    *
 * VERTHYS_SECURE_FREE(ptr, size) 统一管理敏感堆内存的释放：              *
 *   1. verthys_secure_zero 擦除内容（SecureZeroMemory，编译器不可优化）  *
 *   2. free 释放堆内存                                                *
 *   3. 置 ptr = NULL（防 use-after-free / double-free）               *
 *                                                                    *
 * 使用 volatile 函数指针调用 memset，确保编译器不会将清零优化消除。   *
 * 静态分析工具可通过此宏统一审计所有敏感内存释放路径。                 *
 *                                                                    *
 * 用法：                                                              *
 *   uint8_t *secret = malloc(32);                                    *
 *   ... 使用 secret ...                                              *
 *   VERTHYS_SECURE_FREE(secret, 32);   // 擦除+释放+置NULL              *
 *                                                                    *
 * 对于结构体数组：                                                    *
 *   VERTHYS_SECURE_FREE(arr, count * sizeof(arr[0]));                  *
 * ================================================================== */
#define VERTHYS_SECURE_FREE(ptr, size) do { \
    if ((ptr) != NULL) { \
        verthys_secure_zero((void *)(ptr), (size)); \
        free((void *)(ptr)); \
        (ptr) = NULL; \
    } \
} while (0)

/* VERTHYS_SECURE_FREE_LEN：释放以元素大小计算的数组（语法糖） */
#define VERTHYS_SECURE_FREE_ARR(ptr, count, elem_size) \
    VERTHYS_SECURE_FREE((ptr), (size_t)(count) * (size_t)(elem_size))

#endif /* VERTHYS_INTERNAL_H */
