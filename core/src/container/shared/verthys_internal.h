/*
 * verthys_internal.h — DLL 内部共享头（不导出，不暴露给外部）
 *
 * 定义 VerthysContext 内部结构、内部状态、内部工具函数原型。
 * 外部仅通过 verthys.h 的不透明句柄；此头仅供 src/ 内部使用。
 *
 *
 */
#ifndef VERTHYS_INTERNAL_H
#define VERTHYS_INTERNAL_H

#include "verthys.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

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
 * Unlock 格式门禁对非 VRTY 固定头一律 VERTHYS_ERR_FORMAT。 */
typedef enum {
    VERTHYS_FMT_NONE = 0,  /* 未挂载容器（Init 零态）或未知/非法格式 */
    VERTHYS_FMT_CONTAINER   = 4   /* 双包裹 AND + A/B 元数据 + 追加数据区 */
} VerthysContainerVersion;

/* 前向声明：会话（crypto/vty_keymanager.h） */
struct VtyVault;
/* 前向声明：轮换作业（crypto/vty_rotate.h） */
struct VtyRotateJob;

/* 记录名称长度上限（API 边界钳制，杜绝 uint16 截断导致的
 * 密钥派生/索引存储分裂） */
#define VERTHYS_NAME_MAX_BYTES 4096u

/* 单条记录明文数据长度上限（字节，API 边界钳制）。
 * 与二次序列化能力对齐：导出/导入格式的 data_len 为 32 位字段
 *（容量上限 0xFFFFFFFF），入口侧提前拒绝超限写入，避免"写入成功
 * 但永久不可导出"的不可弥补不一致；下沉层（记录仓库写入）复用同
 * 常量做纵深校验。 */
#define VERTHYS_RECORD_DATA_MAX_BYTES ((size_t)0xFFFFFFFFu)

/*
 * VerthysContext — 句柄背后的真实结构。
 * 所有敏感字段在 Lock/Deinit 时经 verthys_secure_zero 清零。
 *
 * 容器会话数据全部位于 ctx->vault（VtyVault 堆实例），本结构不持有任何
 * 容器数据镜像——GetContainerInfo / GetDiagnostics 类接口一律现值直读
 * 权威源。
 */
struct VerthysContext {
    VerthysState state;

    /* 文件路径（heap 副本，Lock 时写回） */
    char *file_path;

    VerthysContainerVersion fmt_version;

    /* 容器会话（堆实例）。fmt_version == VERTHYS_FMT_CONTAINER 且已解锁时非 NULL；
     * Lock/Deinit 负责清零并释放。 */
    struct VtyVault *vault;

    /* 全库 DEK 轮换作业（堆实例）。非 NULL 时源库处于只读态；
     * Lock/Deinit/紧急熔断/adopt 必须调用 vty_rotate_abort 释放。 */
    struct VtyRotateJob *rotate;

    /* 用户预设（公共枚举 VerthysPreset） */
    VerthysPreset preset;

    /* 温启动缓存启用标志（容器会话固定 0，保留字段供 ContainerInfo 回读） */
    int warm_cache_enabled;

    /* 全量校验状态（Verthys_VerifyIntegrity 提交点记账） */
    uint64_t last_fullscan_tx;      /* 上次全量校验时的 TxID */
    uint64_t last_fullscan_time;    /* 上次全量校验时间戳 */
    uint64_t incremental_count;     /* 自上次全量校验以来的增量提交次数 */

    /* GetRecord 借用指针缓存（API 契约：下次调用或 Lock 前有效）
     * 返回深拷贝数据，缓存在此，下次 GetRecord 或 Lock 时释放。
     * 借用指针语义要求 GetRecord 独占访问（api_mutex 写锁）。 */
    uint8_t *last_getrecord_data;   /* 上次 GetRecord 返回的数据（heap） */
    size_t   last_getrecord_data_size;
    uint8_t *last_getrecord_name;   /* 上次 GetRecord 返回的名称（heap） */
    size_t   last_getrecord_name_len;

    /* 读写锁（SRWLock）：细粒度读写锁 — 读共享锁 / 写独占锁，锁域隔离
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
     *     - Verthys_V4Unlock / Verthys_Lock（状态切换）
     *
     *   特殊独占读（AcquireSRWLockExclusive）：
     *     - Verthys_GetRecord — 借用指针缓存（ctx->last_getrecord_data）
     *       序列化访问，杜绝并发释放引发的 use-after-free。
     *
     * 生命周期：Verthys_Init 时分配并 InitializeSRWLock（零初始化），
     *           Verthys_Deinit 时直接释放（SRWLOCK 无需 Delete）。 */
#ifdef _WIN32
    SRWLOCK *api_mutex;          /* 读写锁（heap 分配，SRWLOCK） */
#endif

    /* 诊断指标 + 性能遥测（实际采集项）
     *
     * 扫描游标打开次数与读写锁等待耗时在解锁/扫描路径埋点采集，
     * Verthys_GetDiagnostics 返回给安全中心展示。全部为非敏感指标，
     * 不含任何密钥或用户数据。 */
    uint64_t diag_scan_open_count;        /* 扫描游标打开次数 */

    /* 可观测性指标（当前容器实际采集项） */
    uint64_t diag_lock_wait_ms;           /* 读写锁平均等待耗时（毫秒） */
};

/* ---------- 内部安全内存工具（不导出） ---------- */

/* 安全清零：编译器不可优化掉的内存擦除 */
void verthys_secure_zero(void *ptr, size_t len);

/* 锁定内存页，防止换页到磁盘。返回 0 成功，非 0 失败 */
int  verthys_lock_memory(void *ptr, size_t len);

/* 解锁内存页 */
int  verthys_unlock_memory(void *ptr, size_t len);

/* ================================================================== *
 * 安全内存清零编译期强化     *
 *                                                                    *
 * VERTHYS_SECURE_FREE(ptr, size) 统一管理敏感堆内存的释放：              *
 *   1. verthys_secure_zero 擦除内容（SecureZeroMemory，编译器不可优化）  *
 *   2. free 释放堆内存                                                *
 *   3. 置 ptr = NULL（防 use-after-free / double-free）               *
 *                                                                    *
 * 清零由 verthys_secure_zero 完成（SecureZeroMemory），编译器不会优化消除。   *
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

/* ================================================================== *
 * 内部不变量断言                                                       *
 *                                                                    *
 * 用于表达"按当前代码路径不可能为假"的内部不变量（区别于外部输入       *
 * 校验——外部输入一律走显式错误码分支）。条件为假即内建缺陷，照常      *
 * 按错误码中止，绝不带病继续。Debug 配置额外打印出错点；Release       *
 * 仅返回错误码（零日志成本），防御力度两者一致。                       *
 * ================================================================== */
#ifdef _DEBUG
#define VERTHYS_INTERNAL_ASSERT(cond, rc) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "VERTHYS_ASSERT %s:%d: %s\n", \
                    __FILE__, __LINE__, #cond); \
            return (rc); \
        } \
    } while (0)
#else
#define VERTHYS_INTERNAL_ASSERT(cond, rc) \
    do { \
        if (!(cond)) return (rc); \
    } while (0)
#endif

#endif /* VERTHYS_INTERNAL_H */
