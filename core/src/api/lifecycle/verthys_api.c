/*
 * verthys_api.c — 公共 C ABI 导出函数实现
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
#include "vty_lockout.h"            /* 库级熔断只读查询 */
#include "vty_secure_state.h"       /* N2：安全状态目录预检 */
#include "vty_keymanager.h"       /* 会话（A/B 元数据 + 数据区） */
#include "vty_rotate.h"           /* 全库 DEK 轮换作业 */
#include "verthys_api_container.h"          /* 记录/计数/校验/改密适配 */

/* 项目头 */
#include "verthys_crypto.h"
#include "verthys_pepper.h"
#include "anti_debug.h"
#include "tls_loader.h"
#include "secure_allocator.h"   /* ctx 隔离堆生命周期 */
#include "job_isolation.h"
#include "cng_machine_key.h"
#include "system32_loader.h"
#include "hardware_binding.h"
#include "emergency.h"
#include "anti_inject.h"
#include "memory_guard.h"
#include "integrity.h"         /* 解锁入口 .vsec 验签 */
#include "runtime_hash.h"      /* 解锁后 + 周期运行时函数哈希校验 */
#include "hook_scan.h"         /* ntdll 导出基线/Hook 扫描（BOOT 判据） */
#include "security_preset.h"   /* 运行时预设切换（双缓冲原子发布） */

/* 安全巡检周期（60s）：反调试每拍执行；反注入每 5 拍（300s）执行一次。
 * 回调在独立定时器线程运行，不持有任何句柄锁；禁用启动失败不阻断 BOOT。
 * 停止使用 DeleteTimerQueueEx 等待在途回调退出。 */
static HANDLE s_sec_timer_queue = NULL;
static HANDLE s_sec_timer = NULL;
static volatile LONG s_sec_periodic_tick = 0;

static VOID CALLBACK verthys_security_periodic_cb(PVOID param, BOOLEAN fired)
{
    LONG tick;
    (void)param;
    (void)fired;

    if (emergency_is_triggered()) return;
    (void)anti_debug_check();
    tick = InterlockedIncrement(&s_sec_periodic_tick);
    if (tick % 5 == 0) {
        (void)anti_inject_check_all();
    }
}

static void verthys_security_periodic_start(void)
{
    HANDLE queue;
    HANDLE timer = NULL;

    if (s_sec_timer_queue != NULL) return;
    queue = CreateTimerQueue();
    if (queue == NULL) return;
    if (!CreateTimerQueueTimer(&timer, queue, verthys_security_periodic_cb,
                               NULL, 60000u, 60000u, 0)) {
        CloseHandle(queue);
        return;
    }
    InterlockedExchange(&s_sec_periodic_tick, 0);
    s_sec_timer_queue = queue;
    s_sec_timer = timer;
}

static void verthys_security_periodic_stop(void)
{
    HANDLE queue = s_sec_timer_queue;
    HANDLE timer = s_sec_timer;

    s_sec_timer_queue = NULL;
    s_sec_timer = NULL;
    if (queue == NULL) return;
    if (timer != NULL) {
        (void)DeleteTimerQueueTimer(NULL, timer, NULL);
        CloseHandle(timer);
    }
    (void)DeleteTimerQueueEx(queue, INVALID_HANDLE_VALUE);
}

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
/* 静态初始化即就绪：消除首次注册/查询时的初始化竞态；SRWLOCK 无需析构。 */
static SRWLOCK s_ctx_registry_lock = SRWLOCK_INIT;

static void verthys_ctx_registry_add(struct VerthysContext *ctx)
{
    AcquireSRWLockExclusive(&s_ctx_registry_lock);
    for (int i = 0; i < VERTHYS_MAX_CTXS; i++) {
        if (s_ctx_registry[i] == NULL) {
            s_ctx_registry[i] = ctx;
            break;
        }
    }
    ReleaseSRWLockExclusive(&s_ctx_registry_lock);
}

static int verthys_ctx_registry_remove(struct VerthysContext *ctx)
{
    int removed = 0;
    AcquireSRWLockExclusive(&s_ctx_registry_lock);
    for (int i = 0; i < VERTHYS_MAX_CTXS; i++) {
        if (s_ctx_registry[i] == ctx) {
            s_ctx_registry[i] = NULL;
            removed = 1;
        }
    }
    ReleaseSRWLockExclusive(&s_ctx_registry_lock);
    return removed;
}

/* 句柄是否仍处于活动注册表。
 *
 * 公共 API 在解引用调用方传入的 handle 前必须先经本函数确认，
 * 防止已释放指针被二次传入时形成 Use-After-Free。 */
static int verthys_ctx_registry_contains(struct VerthysContext *ctx)
{
    int found = 0;
    AcquireSRWLockShared(&s_ctx_registry_lock);
    for (int i = 0; i < VERTHYS_MAX_CTXS; i++) {
        if (s_ctx_registry[i] == ctx) {
            found = 1;
            break;
        }
    }
    ReleaseSRWLockShared(&s_ctx_registry_lock);
    return found;
}

/* 注册表是否仍有空位。
 *
 * 在 Init 分配任何资源之前检查，避免注册失败后留下无法注销的上下文。 */
static int verthys_ctx_registry_has_capacity(void)
{
    int has = 0;
    AcquireSRWLockShared(&s_ctx_registry_lock);
    for (int i = 0; i < VERTHYS_MAX_CTXS; i++) {
        if (s_ctx_registry[i] == NULL) {
            has = 1;
            break;
        }
    }
    ReleaseSRWLockShared(&s_ctx_registry_lock);
    return has;
}

/*
 * 应急 DEGRADE 降级处理器（emergency_set_degrade_handler 注入）。
 *
 * 语义：对全部已解锁句柄执行"密钥与明文立即清零 + 状态置 LOCKED"，
 * 进程保持存活。不执行任何磁盘写入（与 Verthys_Lock 的差异：跳过
 * 会话提交与缓存刷盘——降级路径优先保证敏感数据不落盘）。
 * 恢复方式：用户正常 Verthys_V4Unlock。
 */
static void verthys_emergency_lock_all(void)
{
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
#include "vty_caller_auth.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>            /* _fstat64 / st_mtime（落盘自查文件元数据） */

#include "verthys_diag.h"

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>               /* _O_RDWR/_O_BINARY */
#else
#include <unistd.h>
#endif

/* 并行索引读取开关（原定义于 verthys_api.c L699，拆分后由本文件保留） */
#define USE_PARALLEL_INDEX_READ 1

/* 1. 创建未初始化的加密库上下文 */
VerthysResult Verthys_Init(VerthysHandle *out_handle)
{
    if (out_handle == NULL) return VERTHYS_ERR_INVALID;
    /* 调用方签名校验必须先于任何初始化副作用。
     * 否则未授权进程仍可通过 Init 触发环境探测/防御模块初始化，
     * 把“拒绝”变成“拒绝但已泄漏宿主信息”。 */
    if (vty_caller_auth_check() != 0) return VERTHYS_ERR_UNAUTHORIZED;
    /* 先确认注册表有空位，避免分配完成后无法登记而泄漏上下文 */
    if (!verthys_ctx_registry_has_capacity()) return VERTHYS_ERR_RESOURCE_LIMIT;

    /* N2：安全状态目录预检必须先于任何状态相关副作用。失败返回专用错误码，
     * 避免运行期把“目录不可加固”折叠成通用的“安全模块不可用”。 */
    if (vty_secure_state_preflight() != VTY_OK) return VERTHYS_ERR_SECURITY_STATE;

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

    if (anti_debug_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    if (anti_debug_check() != 0) {
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

    /* Layer 4: Hook/注入对抗基线（TLS 标志已在上方验证） */
    /* 防注入基线：在所有模块与内部线程就绪之后采样，避免早期线程
     * 尚未建立时把基线记小。 */
    if (anti_inject_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    /* Layer 6: 最终闭环防御能力验证（BOOT 模式 — 任一关键路径 FAILED 即拒绝启动） */
    /* Hook 基线必须在 BOOT 闭环之前完成解析与首次扫描：闭环读取的是
     * 真实扫描结论，而不是"模块已加载"的名义状态。初始化/首次扫描
     * 失败只降级为 UNAVAILABLE，不拒绝启动。 */
    (void)hook_scan_init();
    (void)hook_scan_run_once();
    if (defense_closure_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    if (defense_closure_check(DEFENSE_CHECK_BOOT, NULL) != 0) {
        /* 存在 FAILED 攻击路径，关键防御模块缺失，拒绝启动 */
        return VERTHYS_ERR_INTERNAL;
    }
    /* BOOT 闭环通过后启动 60s 周期扫描；启动失败只降级，不拒绝启动。 */
    (void)hook_scan_start_periodic();
    /* 反调试 60s / 反注入 300s 周期巡检（BOOT 成功后启动）。 */
    verthys_security_periodic_start();

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

    /* 密钥相关结构专用安全分配器的进程级预算。
     * 分配器实例由 密钥对象经 secure_allocator_shared 懒创建：
     * 会话生命周期可能跨越 Deinit，不能绑定到单个上下文。 */
    (void)secure_allocator_budget_init(SECURE_ALLOC_DEFAULT_BUDGET_BYTES,
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

/*
 * 通知运行时守卫状态（API 版本 0x0014）
 *
 * 完整掩码写入（非累加 OR）：worker 每次心跳/守卫变更都提交当前全量
 * 掩码，停止守卫时提交 0。未知位在 C 层丢弃，防止调用方污染判据。
 */
VerthysResult Verthys_NotifyRuntimeGuards(uint32_t flags)
{
    uint32_t before = defense_closure_get_runtime_guards();
    defense_closure_set_runtime_guards(flags);
    uint32_t after = defense_closure_get_runtime_guards();

    /* 心跳位首次置位：worker 心跳线程晚于 anti_inject_init 创建，
     * 必须刷新外部线程基线，否则 300s 周期巡检会把常驻心跳线程
     * 误判为远程注入。 */
    if ((before & DEFENSE_GUARD_HEARTBEAT) == 0 &&
        (after & DEFENSE_GUARD_HEARTBEAT) != 0) {
        anti_inject_refresh_baseline();
    }
    return VERTHYS_OK;
}

/* 2. 销毁上下文 */


VerthysResult Verthys_Deinit(VerthysHandle handle)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;

    /* 先原子注销：只有成功移除的调用方才拥有释放权。
     *
     * 重复 Deinit 的入参已不在注册表，禁止继续解引用或释放；
     * 否则会形成双重释放/堆破坏。 */
    if (!verthys_ctx_registry_remove(ctx)) return VERTHYS_ERR_INVALID;
    /* 停止防转储低频巡逻 */
    memory_guard_patrol_stop();
    /* 停止 Hook 周期扫描（等待在途回调退出） */
    hook_scan_stop_periodic();
    /* 停止反调试/反注入周期巡检（等待在途回调退出） */
    verthys_security_periodic_stop();


    /* 会话收口：先释放轮换作业（其持有库引用），再清零并释放会话。 */
    if (ctx->rotate != NULL) {
        vty_rotate_abort(ctx->rotate);
        ctx->rotate = NULL;
    }
    vault_session_detach(ctx);

    if (ctx->state == VERTHYS_STATE_UNLOCKED) {
        ctx_zero_sensitive(ctx);
    }
    free(ctx->file_path);
    ctx->file_path = NULL;

    /* 销毁 SRWLOCK 读写锁
     * SRWLOCK 无需 DeleteCriticalSection，直接释放堆内存即可。 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) {
        free(ctx->api_mutex);
        ctx->api_mutex = NULL;
    }
#endif

    verthys_secure_zero(ctx, sizeof(*ctx));
    free(ctx);
    return VERTHYS_OK;
}
/* 内部错误码 → 公共返回码。对外不区分“口令错/缺槽/TPM 状态”，
 * 只把可行动的类别（格式、损坏、IO、限流）暴露给调用方。 */
static VerthysResult verthys_container_map(int rc)
{
    switch (rc) {
    case VTY_OK:                  return VERTHYS_OK;
    case VTY_E_VERSION:           return VERTHYS_ERR_FORMAT;
    case VTY_E_SLOT_UNKNOWN:      return VERTHYS_ERR_FORMAT;
    case VTY_E_SLOT_MISSING:      return VERTHYS_ERR_FORMAT;
    case VTY_E_KDF_WEAK:          return VERTHYS_ERR_FORMAT;
    case VTY_E_KEY_INVALID:       return VERTHYS_ERR_AUTH;
    case VTY_E_AEAD:              return VERTHYS_ERR_AUTH;
    case VTY_E_TPM:               return VERTHYS_ERR_TPM;
    case VTY_E_POLICY:            return VERTHYS_ERR_POLICY;
    case VTY_E_LOCKED:            return VERTHYS_ERR_RATE;
    case VTY_E_CORRUPT:           return VERTHYS_ERR_CORRUPT;
    case VTY_E_ROLLBACK:          return VERTHYS_ERR_ROLLBACK;
    case VTY_E_IO:                return VERTHYS_ERR_IO;
    case VTY_E_RESOURCE:          return VERTHYS_ERR_RESOURCE_LIMIT;
    case VTY_E_KEYFILE_REQUIRED:  return VERTHYS_ERR_KEYFILE_REQUIRED;
    case VTY_E_KEYFILE_INVALID:   return VERTHYS_ERR_KEYFILE_INVALID;
    case VTY_E_EXISTS:            return VERTHYS_ERR_EXISTS;
    case VTY_E_ROTATE_PENDING:    return VERTHYS_ERR_ROTATE_PENDING;
    case VTY_E_MODULE_LOCKED:     return VERTHYS_ERR_MODULE_LOCKED;
    case VTY_E_NO_SPACE:          return VERTHYS_ERR_NO_SPACE;
    case VTY_E_VERIFY:            return VERTHYS_ERR_VERIFY;
    default:                      return VERTHYS_ERR_INVALID;
    }
}

/* 公共 API 接受显式长度；本层按 NUL 终结串取口令，长度不符时复制一份，
 * 避免调用方传入的长度与内存内容不一致导致越界或截断语义漂移。 */
static char *password_copy(const char *password, size_t len)
{
    char *copy;

    if (password == NULL || len == 0) return NULL;
    copy = (char *)malloc(len + 1u);
    if (copy == NULL) return NULL;
    memcpy(copy, password, len);
    copy[len] = '\0';
    return copy;
}

static void password_free(char *copy, size_t len)
{
    if (copy == NULL) return;
    verthys_secure_zero(copy, len + 1u);
    free(copy);
}

static VerthysResult verthys_api_container_adopt(struct VerthysContext *ctx,
                                         const char *path, VtyVault *v)
{
    char *new_path;
    /* 旧会话若仍有轮换作业，先释放作业再释放库，避免悬空引用。 */
    if (ctx->rotate != NULL) {
        vty_rotate_abort(ctx->rotate);
        ctx->rotate = NULL;
    }
    /* 先准备新路径再替换会话：路径分配失败时旧会话保持完整，不出现
     * "库已释放但挂载点未更新"的中间态。 */
    new_path = dup_string(path);
    if (new_path == NULL) {
        vty_vault_free(v);
        return VERTHYS_ERR_RESOURCE_LIMIT;
    }
    free(ctx->file_path);
    ctx->file_path = new_path;
    vault_session_attach(ctx, v);
    ctx->fmt_version = VERTHYS_FMT_CONTAINER;
    ctx->preset = VERTHYS_PRESET_BALANCED;
    ctx->warm_cache_enabled = 0;
    ctx->state = VERTHYS_STATE_UNLOCKED;
    return VERTHYS_OK;
}

/* 容器专用入口必须先确认 magic：把异种格式文件交给解析器会产生
 * 误导性的槽错误，而且不利于把“拒绝旧格式”作为独立攻击面验证。 */
static VerthysResult verthys_api_container_require_magic(const char *path)
{
    FILE *peek;
    uint8_t header[8];
    size_t n;

    if (path == NULL) return VERTHYS_ERR_INVALID;
    peek = fopen(path, "rb");
    if (peek == NULL) return VERTHYS_ERR_IO;
    n = fread(header, 1, sizeof(header), peek);
    fclose(peek);
    if (n < sizeof(header)) return VERTHYS_ERR_FORMAT;
    if (detect_format(header, n) != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;
    return VERTHYS_OK;
}

static VerthysResult verthys_api_container_unlock(struct VerthysContext *ctx,
                                           const char *path,
                                           const char *password, size_t len,
                                           const char *keyfile_path)
{
    VtyVault *v = NULL;
    char *pw;
    int rc;

    if (password == NULL || len == 0) return VERTHYS_ERR_INVALID;
    /* 公共契约只保证 password 指向 len 字节，不保证 NUL 终结；
     * 本层按 NUL 串取口令，必须先复制再调用，避免越界读。 */
    pw = password_copy(password, len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;
    /* keyfile 由 C 层在本进程内读取；路径只是入参，字节不进入调用方。 */
    rc = (keyfile_path != NULL)
             ? vty_vault_open_keyfile(path, pw, keyfile_path, &v)
             : vty_vault_open(path, pw, &v);
    password_free(pw, len);
    if (rc != VTY_OK) return verthys_container_map(rc);
    return verthys_api_container_adopt(ctx, path, v);
}

/*
 * 解锁入口二进制验签。
 * 构建期 .vsec 基准比对：进程内按自身文件元数据指纹缓存结论，
 * 指纹不变直接回放（解锁热路径零节 I/O），指纹变化（自更新/篡改）
 * 强制重算。未配置（开发构建）时为空操作；验签失败 = 二进制被篡改
 * （高置信度）→ KILL 级上报已发出，返回 CORRUPT 拒绝解锁。
 */
static VerthysResult verthys_api_unlock_integrity_precheck(void)
{
    if (integrity_verify_startup() != 0) return VERTHYS_ERR_CORRUPT;
    return VERTHYS_OK;
}

/*
 * 解锁成功后的进程级安全钩子：
 * 运行时函数级哈希全量校验（.rhat 真表，防内存补丁注入跳转）。
 * 失配 = 进程内存被篡改（高置信度）→ KILL 级应急（进程终止，
 * 绝不带着已解锁密钥继续运行）。置于信号复位之前：篡改态不做任何
 * "恢复性"钩子。
 */
static void verthys_api_unlock_post_hooks(void)
{
    runtime_hash_verify();
    emergency_clear_signals();
    /* 解锁后一次完整注入巡检（线程/APC/窗口钩子/模块白名单）。 */
    (void)anti_inject_check_all();
    (void)hook_scan_run_once();   /* 解锁后立即刷新 Hook 证据 */
    memory_guard_patrol_start();
}

/* 新建：只创建 容器。恢复码在创建响应里
 * 一次性返回，调用方确认后必须清零自己的副本。 */
VerthysResult Verthys_V4Create(VerthysHandle handle,
                               const char *verthys_path,
                               const char *password,
                               size_t password_len,
                               char *recovery_text,
                               size_t recovery_cap)
{
    struct VerthysContext *ctx;
    VtyVault *v = NULL;
    char *pw = NULL;
    FILE *probe;
    int rc;

    if (handle == NULL || verthys_path == NULL || password == NULL ||
        recovery_text == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (password_len == 0 || recovery_cap < VTY_RECOVERY_TEXT_BUF) {
        return VERTHYS_ERR_INVALID;
    }
    ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;

    probe = fopen(verthys_path, "rb");
    if (probe != NULL) {
        fclose(probe);
        return VERTHYS_ERR_EXISTS;
    }

    /* 同 Unlock：显式长度参数不保证 NUL 终结，统一复制后再进入 层。 */
    pw = password_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;
    rc = vty_vault_create(verthys_path, pw, &v, recovery_text, recovery_cap);
    password_free(pw, password_len);
    if (rc != VTY_OK) return verthys_container_map(rc);
    return verthys_api_container_adopt(ctx, verthys_path, v);
}

VerthysResult Verthys_V4CreateKeyfile(VerthysHandle handle,
                                      const char *verthys_path,
                                      const char *password,
                                      size_t password_len,
                                      const char *keyfile_path,
                                      char *recovery_text,
                                      size_t recovery_cap)
{
    struct VerthysContext *ctx;
    VtyVault *v = NULL;
    char *pw = NULL;
    FILE *probe;
    int rc;

    if (handle == NULL || verthys_path == NULL || password == NULL ||
        keyfile_path == NULL || recovery_text == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (password_len == 0 || recovery_cap < VTY_RECOVERY_TEXT_BUF) {
        return VERTHYS_ERR_INVALID;
    }
    ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;

    /* 库路径先做快速失败：避免先落一个 keyfile 再发现库已存在。 */
    probe = fopen(verthys_path, "rb");
    if (probe != NULL) {
        fclose(probe);
        return VERTHYS_ERR_EXISTS;
    }

    pw = password_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;
    rc = vty_vault_create_keyfile_file(verthys_path, pw, keyfile_path, &v,
                                       recovery_text, recovery_cap);
    password_free(pw, password_len);
    if (rc != VTY_OK) return verthys_container_map(rc);
    return verthys_api_container_adopt(ctx, verthys_path, v);
}

VerthysResult Verthys_V4Unlock(VerthysHandle handle,
                               const char *verthys_path,
                               const char *password,
                               size_t password_len)
{
    struct VerthysContext *ctx;
    VerthysResult rc;
    VerthysResult ir;

    if (handle == NULL || verthys_path == NULL || password == NULL ||
        password_len == 0) {
        return VERTHYS_ERR_INVALID;
    }
    ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;

    ir = verthys_api_unlock_integrity_precheck();
    if (ir != VERTHYS_OK) return ir;

#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif
    rc = verthys_api_container_require_magic(verthys_path);
    if (rc == VERTHYS_OK) {
        rc = verthys_api_container_unlock(ctx, verthys_path, password, password_len,
                                   NULL);
        if (rc == VERTHYS_OK) {
            verthys_api_unlock_post_hooks();
        }
    }
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
    return rc;
}

VerthysResult Verthys_V4UnlockKeyfile(VerthysHandle handle,
                                      const char *verthys_path,
                                      const char *password,
                                      size_t password_len,
                                      const char *keyfile_path)
{
    struct VerthysContext *ctx;
    VerthysResult rc;
    VerthysResult ir;

    if (handle == NULL || verthys_path == NULL || password == NULL ||
        keyfile_path == NULL || password_len == 0) {
        return VERTHYS_ERR_INVALID;
    }
    ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;

    ir = verthys_api_unlock_integrity_precheck();
    if (ir != VERTHYS_OK) return ir;

#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif
    rc = verthys_api_container_require_magic(verthys_path);
    if (rc == VERTHYS_OK) {
        rc = verthys_api_container_unlock(ctx, verthys_path, password, password_len,
                                   keyfile_path);
        if (rc == VERTHYS_OK) {
            verthys_api_unlock_post_hooks();
        }
    }
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
    return rc;
}

VerthysResult Verthys_V4UnlockRecovery(VerthysHandle handle,
                                       const char *verthys_path,
                                       const char *recovery_text)
{
    struct VerthysContext *ctx;
    VtyVault *v = NULL;
    VerthysResult rc;
    VerthysResult ir;
    int vrc;

    if (handle == NULL || verthys_path == NULL || recovery_text == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;

    ir = verthys_api_unlock_integrity_precheck();
    if (ir != VERTHYS_OK) return ir;

#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif
    rc = verthys_api_container_require_magic(verthys_path);
    if (rc != VERTHYS_OK) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc;
    }
    vrc = vty_vault_open_recovery(verthys_path, recovery_text, &v);
    rc = (vrc == VTY_OK) ? verthys_api_container_adopt(ctx, verthys_path, v)
                         : verthys_container_map(vrc);
    if (rc == VERTHYS_OK) {
        verthys_api_unlock_post_hooks();
    }
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
    return rc;
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

/* 运行时查询活跃安全预设档位。
 *
 * 取自活跃配置快照，供调用方做切档回读校验：切档后读回值与请求值
 * 不一致即可判定切换未生效（宿主据此回滚持久化并报错）。
 * 线程安全：MT-Safe（快照读取，无锁）。 */
VerthysResult Verthys_GetSecurityPreset(VerthysHandle handle, uint32_t *out_preset)
{
    if (handle == NULL || out_preset == NULL) return VERTHYS_ERR_INVALID;

    SecurityPreset sp = security_runtime_preset();
    if (sp != SEC_PRESET_BALANCED && sp != SEC_PRESET_SECURE &&
        sp != SEC_PRESET_PERFORMANCE) {
        return VERTHYS_ERR_INVALID;
    }
    *out_preset = (uint32_t)sp;
    return VERTHYS_OK;
}

/* 只读查询库级熔断剩余秒数：供宿主在 VERTHYS_ERR_RATE 响应后展示
 * “已锁定 X 秒”。不消耗尝试额度、不改变计数；查询失败按 0 返回，不
 * 改变既有错误链。 */
VerthysResult Verthys_GetLibLockoutRemaining(uint32_t *out_secs)
{
    if (out_secs == NULL) return VERTHYS_ERR_INVALID;
    *out_secs = 0;
    if (!vty_lockout_enabled()) return VERTHYS_OK;
    if (vty_lockout_init() != VTY_OK) return VERTHYS_ERR_TPM;
    (void)vty_lockout_remaining_secs(out_secs);
    return VERTHYS_OK;
}

/* 运行时查询指定预设档位的特性位投影（11 位跨层特性契约）。
 *
 * 投影是档位矩阵的唯一权威输出：宿主展示与执行均以此为准，
 * 消除多端各自维护特性表导致的语义漂移。
 * 线程安全：MT-Safe。 */
VerthysResult Verthys_GetPresetFeatureBits(VerthysHandle handle,
                                           VerthysPreset preset,
                                           uint32_t *out_bits)
{
    if (handle == NULL || out_bits == NULL) return VERTHYS_ERR_INVALID;

    SecurityPreset sp;
    switch (preset) {
        case VERTHYS_PRESET_BALANCED:    sp = SEC_PRESET_BALANCED;    break;
        case VERTHYS_PRESET_SECURE:      sp = SEC_PRESET_SECURE;      break;
        case VERTHYS_PRESET_PERFORMANCE: sp = SEC_PRESET_PERFORMANCE; break;
        default: return VERTHYS_ERR_INVALID;
    }

    if (security_preset_feature_bits(sp, out_bits) != 0) {
        return VERTHYS_ERR_INVALID;
    }
    return VERTHYS_OK;
}

/* 4. 锁定 */
/*
 * Lock 同步路径的必要操作：
 *   1. 释放轮换作业（其持有库引用）；
 *   2. 会话释放（密钥与明文清零——安全，必须同步）；
 *   3. 借用指针缓存释放。
 *
 * 耗时任务（全盘校验）不在 Lock 同步路径——经 Verthys_VerifyIntegrity 按需执行。
 *
 * 关闭响应指标：窗口隐藏≤100ms，后台完整退出≤1.5s（UI 层配合 window.hide()）
 */
VerthysResult Verthys_Lock(VerthysHandle handle)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->file_path == NULL) return VERTHYS_ERR_INVALID;

    /* 锁定路径：
     *   1. 释放轮换作业（其持有库引用）；
     *   2. 会话释放（密钥与明文清零）；
     *   3. GetRecord 借用指针缓存释放。 */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) {
            AcquireSRWLockExclusive(ctx->api_mutex);
        }
#endif
        if (ctx->rotate != NULL) {
            vty_rotate_abort(ctx->rotate);
            ctx->rotate = NULL;
        }
        vault_session_detach(ctx);
        ctx_free_getrecord_cache(ctx);
        ctx->state = VERTHYS_STATE_LOCKED;
#ifdef _WIN32
        if (ctx->api_mutex != NULL) {
            ReleaseSRWLockExclusive(ctx->api_mutex);
        }
#endif
        return VERTHYS_OK;
    }

    return VERTHYS_ERR_FORMAT;
}

/* 记录写入的统一入口校验（AddRecord / AddRecords 共用）。
 *
 * 名称长度在 API 边界钳制：索引条目 name_len 为 uint16 存储，超 4096
 * 字节的名称会导致"块以全名派生记录密钥、索引以截断名存储"的分裂 →
 * 重载后记录不可解。数据长度同时受导出格式 32 位容量与单条 IPC 预算
 * （12MiB base64 的 4/3 解码上界 9MiB）约束。 */
static VerthysResult validate_record_write(const VerthysRecord *record)
{
    if (record == NULL) return VERTHYS_ERR_INVALID;
    if (record->name == NULL && record->name_len != 0) return VERTHYS_ERR_INVALID;
    if (record->data == NULL && record->data_len != 0) return VERTHYS_ERR_INVALID;
    if (record->name_len > VERTHYS_NAME_MAX_BYTES) return VERTHYS_ERR_INVALID;
    if (record->data_len > VERTHYS_RECORD_DATA_MAX_BYTES) return VERTHYS_ERR_INVALID;
    if (record->data_len > (9u * 1024u * 1024u)) return VERTHYS_ERR_RESOURCE_LIMIT;
    return VERTHYS_OK;
}

/* 5. 新增记录 */
VerthysResult Verthys_AddRecord(VerthysHandle handle,
                            const VerthysRecord *record,
                            uint64_t *out_id)
{
    VerthysResult vrc;

    if (handle == NULL || record == NULL || out_id == NULL) return VERTHYS_ERR_INVALID;
    vrc = validate_record_write(record);
    if (vrc != VERTHYS_OK) return vrc;

    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* 写路径入口反调试复检（60s 周期之外的高价值动作补点）。
     * check 内部命中高置信度调试器时已上报 KILL；此处不改变返回语义。 */
    (void)anti_debug_check();

    /* 递归互斥锁保护 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif

    /* 写操作入口统一失效查询缓存，防止 UAF
     * 所有写入操作（增/删/改/导入/改密/刷盘）在持锁后立即清空 getrecord_cache，
     * 消除外部借用指针在 GC 回收旧数据块后变为野指针的 UAF 窗口。
     * 统一收口缓存销毁，写入事务提交前强制清空历史查询缓存。 */
    ctx_free_getrecord_cache(ctx);

    /* 写路径周期重算关键函数
     * 运行时哈希（时间门控，距上次全量 <30min 直接返回；首调立即全量）。 */
    runtime_hash_verify_periodic();

    /* 仓库写入 + 单次 DataRoot/元数据提交（api_mutex 已持有） */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        VerthysResult rc_vault = verthys_api_container_add(ctx, record, out_id);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc_vault;
    }
    /* 非容器格式不存在可写路径 */
    return VERTHYS_ERR_FORMAT;
}

/* 5.1 批量新增记录（API 版本 0x0013）：单次事务提交，全有或全无 */
VerthysResult Verthys_AddRecords(VerthysHandle handle,
                            const VerthysRecord *records,
                            uint32_t count,
                            uint64_t *out_ids)
{
    struct VerthysContext *ctx;
    uint32_t i;

    if (handle == NULL) return VERTHYS_ERR_INVALID;
    if (records == NULL || out_ids == NULL) return VERTHYS_ERR_INVALID;
    if (count == 0u || count > VERTHYS_ADD_RECORDS_MAX) return VERTHYS_ERR_INVALID;

    /* IDs 先归零：任何失败路径（含逐条校验拒绝）都不向调用方暴露
     * 未初始化或部分分配结果。 */
    memset(out_ids, 0, (size_t)count * sizeof(uint64_t));

    /* 逐条边界校验：任一非法即整批拒绝，避免部分写入与事务半成品 */
    for (i = 0u; i < count; i++) {
        VerthysResult vrc = validate_record_write(&records[i]);
        if (vrc != VERTHYS_OK) return vrc;
    }

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif

    /* 写操作入口统一失效查询缓存（与 AddRecord 同一 UAF 纪律） */
    ctx_free_getrecord_cache(ctx);
    runtime_hash_verify_periodic();

    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        VerthysResult rc_vault = verthys_api_container_add_many(ctx, records, count, out_ids);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc_vault;
    }

    /* 非容器格式无批量写入路径，避免逐条语义与原子性漂移 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
    return VERTHYS_ERR_FORMAT;
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

    /* 目录叶查找 + 记录段校验/AEAD 解密，结果复制进借用缓存 */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        VerthysResult rc_vault = verthys_api_container_get(ctx, id, out_record);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc_vault;
    }
    /* 非容器格式无读取路径 */
    return VERTHYS_ERR_FORMAT;
}

/* 6.1 显式释放 GetRecord 借用缓存
 *
 * 借用指针契约要求调用方在使用完返回记录后主动释放缓存；worker 在把
 * 记录复制到自有缓冲并完成 base64 后调用本接口，避免 C 层明文跨请求驻留。 */
VerthysResult Verthys_ClearRecordCache(VerthysHandle handle)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;

    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (!verthys_ctx_registry_contains(ctx)) return VERTHYS_ERR_INVALID;

#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif
    ctx_free_getrecord_cache(ctx);
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
    return VERTHYS_OK;
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
    /* 写路径周期运行时哈希校验（30min 门控） */
    runtime_hash_verify_periodic();

    /* 记录叶/名称/类型三处墓碑 + 单次提交 */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        VerthysResult rc_vault = verthys_api_container_delete(ctx, id);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc_vault;
    }
    /* 非容器格式无删除路径 */
    return VERTHYS_ERR_FORMAT;
}

/* 7a. 批量删除记录（单次提交刚性要求）
 *
 * 本函数在单事务内统一写墓碑，末尾一次 DataRoot/元数据提交收口，
 * 磁盘写入量与条目数解耦。
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
    /* 写路径周期运行时哈希校验（30min 门控） */
    runtime_hash_verify_periodic();

    /* 先全量探测再统一写墓碑，一次提交收口 */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        VerthysResult rc_vault = verthys_api_container_delete_many(ctx, ids, count);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc_vault;
    }
    /* 非容器格式无批量删除路径 */
    return VERTHYS_ERR_FORMAT;
}

/* 获取存活记录总数
 *
 * 语义：目录叶全量遍历精确计数（跳过分配器与墓碑）。
 */
VerthysResult Verthys_GetSummaryCount(VerthysHandle handle, uint64_t *out_count)
{
    if (handle == NULL || out_count == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    /* 目录叶全量遍历精确计数（跳过分配器与墓碑） */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        VerthysResult rc_vault;
#ifdef _WIN32
        if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif
        rc_vault = verthys_api_container_count(ctx, out_count);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        return rc_vault;
    }

    return VERTHYS_ERR_FORMAT;
}

/* ================================================================== *
 * 内建诊断接口             *
 *                                                                    *
 * 返回 运行时采集的结构化状态指标（扫描游标/锁等待/预热状态），   *
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

    /* 扫描指标 */
    out_diag->scan_open_count       = ctx->diag_scan_open_count;
    /* 胡椒来源（诊断，不暴露胡椒值） */
    out_diag->pepper_source         = (uint8_t)verthys_pepper_get_source();
    /* 可观测性指标 */
    out_diag->lock_wait_ms          = ctx->diag_lock_wait_ms;
    /* preheat_status 保留 ABI 字段；当前容器格式无预热状态，保持 0。 */

#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
    return VERTHYS_OK;
}

/* ================================================================== *
 * 动态防护状态查询（API 版本 0x000B）：
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
_Static_assert((int)VERTHYS_DEFENSE_REASON_NONE == (int)DEFENSE_REASON_NONE &&
               (int)VERTHYS_DEFENSE_REASON_NO_RESIDENT_KEY ==
                   (int)DEFENSE_REASON_NO_RESIDENT_KEY &&
               (int)VERTHYS_DEFENSE_REASON_V4_KEYS_USER_RESIDENT ==
                   (int)DEFENSE_REASON_KEYS_USER_RESIDENT &&
               (int)VERTHYS_DEFENSE_REASON_HIBERNATION_ENABLED ==
                   (int)DEFENSE_REASON_HIBERNATION_ENABLED &&
               (int)VERTHYS_DEFENSE_REASON_HIBERNATION_UNKNOWN ==
                   (int)DEFENSE_REASON_HIBERNATION_UNKNOWN &&
               (int)VERTHYS_DEFENSE_REASON_SUSPEND_UNPREVENTABLE ==
                   (int)DEFENSE_REASON_SUSPEND_UNPREVENTABLE &&
               (int)VERTHYS_DEFENSE_REASON_SUSPEND_GUARD_INACTIVE ==
                   (int)DEFENSE_REASON_SUSPEND_GUARD_INACTIVE &&
               (int)VERTHYS_DEFENSE_REASON_HOOK_SCAN_CLEAN ==
                   (int)DEFENSE_REASON_HOOK_SCAN_CLEAN &&
               (int)VERTHYS_DEFENSE_REASON_HOOK_SCAN_UNAVAILABLE ==
                   (int)DEFENSE_REASON_HOOK_SCAN_UNAVAILABLE &&
               (int)VERTHYS_DEFENSE_REASON_HOOK_DETECTED ==
                   (int)DEFENSE_REASON_HOOK_DETECTED &&
               (int)VERTHYS_DEFENSE_REASON_SANDBOX_VERIFIED ==
                   (int)DEFENSE_REASON_SANDBOX_VERIFIED &&
               (int)VERTHYS_DEFENSE_REASON_SANDBOX_PARTIAL ==
                   (int)DEFENSE_REASON_SANDBOX_PARTIAL &&
               (int)VERTHYS_DEFENSE_REASON_SANDBOX_UNVERIFIED ==
                   (int)DEFENSE_REASON_SANDBOX_UNVERIFIED &&
               (int)VERTHYS_DEFENSE_REASON_JOB_ACTIVE ==
                   (int)DEFENSE_REASON_JOB_ACTIVE &&
               (int)VERTHYS_DEFENSE_REASON_DEVICE_BOUND ==
                   (int)DEFENSE_REASON_DEVICE_BOUND &&
               (int)VERTHYS_DEFENSE_REASON_NO_SESSION_FACTS ==
                   (int)DEFENSE_REASON_NO_SESSION_FACTS &&
               (int)VERTHYS_DEFENSE_REASON_MODULE_INIT_FAILED ==
                   (int)DEFENSE_REASON_MODULE_INIT_FAILED &&
               (int)VERTHYS_DEFENSE_REASON_POLICY_DISABLED ==
                   (int)DEFENSE_REASON_POLICY_DISABLED &&
               (int)VERTHYS_DEFENSE_REASON_EVIDENCE_STALE ==
                   (int)DEFENSE_REASON_EVIDENCE_STALE &&
               (int)VERTHYS_DEFENSE_REASON_ARCH_LIMIT_KERNEL_DEFERRED ==
                   (int)DEFENSE_REASON_ARCH_LIMIT_KERNEL_DEFERRED &&
               (int)VERTHYS_DEFENSE_REASON_HIBERNATION_DISABLED ==
                   (int)DEFENSE_REASON_HIBERNATION_DISABLED,
               "public VerthysDefenseReason out of sync with internal DefenseReason");

/* 追加式 ABI：既有 48 字节前缀保持不变；新字段偏移与总大小锁定，
 * 防止 C/Rust/TS 三方布局漂移。 */
_Static_assert(offsetof(VerthysSecurityStatus, path_reason) == 48u,
               "VerthysSecurityStatus.path_reason offset drift");
_Static_assert(offsetof(VerthysSecurityStatus, limited_count) == 76u,
               "VerthysSecurityStatus.limited_count offset drift");
_Static_assert(offsetof(VerthysSecurityStatus, policy_flags) == 80u,
               "VerthysSecurityStatus.policy_flags offset drift");
_Static_assert(offsetof(VerthysSecurityStatus, checked_at_unix_ms) == 88u,
               "VerthysSecurityStatus.checked_at_unix_ms offset drift");
_Static_assert(sizeof(VerthysSecurityStatus) == 104u,
               "VerthysSecurityStatus size drift");

VerthysResult Verthys_GetSecurityStatus(VerthysHandle handle,
                                    VerthysSecurityStatus *out_status)
{
    struct VerthysContext *ctx;
    DefenseFacts facts;
    DefenseStatusReport report;

    if (handle == NULL || out_status == NULL) return VERTHYS_ERR_INVALID;

    ctx = (struct VerthysContext *)handle;

    memset(&facts, 0, sizeof(facts));
    defense_closure_fill_process_facts(&facts);

    /* 快照锁序：registry → ctx。
     *
     * registry 共享锁保证 Verthys_Deinit 的注销与释放不会发生在复制期间
     *（注销本身持 registry 独占锁）；ctx 共享锁保证 会话指针与绑定
     * 事实一致。复制完成后立即释放两把锁，随后才获取 defense_closure
     * 的检查锁——禁止嵌套 ctx 锁与检查锁。
     *
     * 状态查询无副作用：不调用任何 *_init、不创建句柄、不启动定时器；
     * 仅读取已初始化模块与 OS 查询结果。 */
    AcquireSRWLockShared(&s_ctx_registry_lock);
    {
        int found = 0;
        for (int i = 0; i < VERTHYS_MAX_CTXS; i++) {
            if (s_ctx_registry[i] == ctx) {
                found = 1;
                break;
            }
        }
        if (!found) {
            ReleaseSRWLockShared(&s_ctx_registry_lock);
            return VERTHYS_ERR_INVALID;
        }
    }
#ifdef _WIN32
    if (ctx->api_mutex != NULL) {
        AcquireSRWLockShared(ctx->api_mutex);
    }
#endif

    facts.any_unlocked_session = vault_session_resident_count();
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER && ctx->vault != NULL) {
        VtyVaultBindingInfo binding;
        if (vty_vault_binding_info(ctx->vault, &binding) == VTY_OK) {
            facts.queried_unlocked_session  = binding.unlocked;
            facts.queried_device_bound = binding.device_bound;
            facts.queried_pcr_bound    = binding.pcr_bound;
        }
    }

#ifdef _WIN32
    if (ctx->api_mutex != NULL) {
        ReleaseSRWLockShared(ctx->api_mutex);
    }
#endif
    ReleaseSRWLockShared(&s_ctx_registry_lock);

    if (defense_closure_check_facts(DEFENSE_CHECK_RUNTIME,
                                    &facts, &report) != 0) {
        /* RUNTIME 模式契约恒返回 0；此分支为防御性顶层错误映射 */
        return VERTHYS_ERR_INTERNAL;
    }

    memset(out_status, 0, sizeof(*out_status));
    for (int i = 0; i < DEFENSE_PATH_COUNT; i++) {
        out_status->path_state[i]  = (VerthysDefenseState)report.path_state[i];
        out_status->path_reason[i] = (uint32_t)report.path_reason[i];
    }
    out_status->blocked_count        = report.blocked_count;
    out_status->degraded_count       = report.degraded_count;
    out_status->failed_count         = report.failed_count;
    out_status->all_critical_blocked = (uint8_t)report.all_critical_blocked;
    out_status->has_degraded         = (uint8_t)report.has_degraded;
    out_status->limited_count        = report.limited_count;
    out_status->policy_flags         = facts.policy_flags;
    out_status->reserved2            = 0;
    out_status->checked_at_unix_ms   = report.checked_at_unix_ms;
    out_status->reserved3[0]         = 0;
    out_status->reserved3[1]         = 0;
    return VERTHYS_OK;
}

/* ================================================================== *
 * Verthys_Flush 显式刷盘接口
 *                                                                    *
 * 在不锁定的情况下主动将内存中的索引变更刷写到磁盘，                *
 * 保证崩溃恢复一致性。                                               *
 *                                                                    *
 * 提交 DataRoot/元数据变更并物理落盘。                          *
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
    /* 写路径周期运行时哈希校验（30min 门控） */
    runtime_hash_verify_periodic();

    /* 刷盘：DataRoot/元数据提交（api_mutex 已持有）。 */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        VerthysResult rc_vault = verthys_api_container_flush(ctx);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return rc_vault;
    }
    return VERTHYS_ERR_FORMAT;
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

    /* 版本探测语义（worker 启动预检）：api_version/fmt_version/preset
     * 三个头部字段在任何状态（含 LOCKED/未解锁）均可读——供加载方在
     * 首个解锁操作前校准 ABI/格式兼容性，早于任何布局敏感调用。 */

    /* 读操作使用共享锁（AcquireSRWLockShared），允许多个读取并发执行
     *   容器元数据为只读访问，可与 GetDiagnostics/VerifyIntegrity/Export 并发 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif

    memset(out_info, 0, sizeof(*out_info));
    out_info->api_version = VERTHYS_API_VERSION;
    /* 编译期能力：本实现唯一支持的容器格式版本。 */
    out_info->fmt_version = (uint16_t)VERTHYS_CONTAINER_FORMAT_VERSION;
    out_info->preset = (uint16_t)ctx->preset;
    out_info->last_fullscan_time = ctx->last_fullscan_time;
    out_info->warm_cache_enabled = (uint8_t)ctx->warm_cache_enabled;

    /* 未解锁态：仅版本头部有意义，统计字段全部如实归零并提前返回
     * （不伪造数据；容器未打开时不存在可报告的运行时统计） */
    if (ctx->state != VERTHYS_STATE_UNLOCKED) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        return VERTHYS_OK;
    }

    /* 数据区尚未提交记录（当前只交付格式与会话），统计字段按
     * DataRoot 高水位如实报告，不伪造 record_count。 */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        if (ctx->vault == NULL) {
#ifdef _WIN32
            if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
            return VERTHYS_ERR_INTERNAL;
        }
        out_info->txid = ctx->vault->header.generation;
        out_info->data_region_size =
            ctx->vault->data_root.data_end - VTY_DATA_OFFSET;
        out_info->data_used_bytes = out_info->data_region_size;
        {
            uint64_t live = 0;
            VerthysResult cr = verthys_api_container_count(ctx, &live);
            if (cr != VERTHYS_OK) {
#ifdef _WIN32
                if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
                return cr;
            }
            out_info->record_count = live;
        }
        out_info->index_region_size = 0;
        out_info->mount_count = 0;
        out_info->cumulative_write_bytes = 0;
        out_info->merkle_pending = 0;
        out_info->has_keyfile =
            (uint8_t)((ctx->vault->header.flags & VTY_FLAG_KEYFILE) != 0);
        memcpy(out_info->container_id, ctx->vault->header.vault_uuid,
               VTY_UUID_BYTES);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        return VERTHYS_OK;
    }

    return VERTHYS_ERR_FORMAT;
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

    /* 递归互斥锁保护（遍历期间阻止并发写） */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif

    /* 目录/DataRoot 结构校验 + 逐条记录段 hash/AEAD 校验。
     * 单条损坏记入 failed_lids，结构级损坏整体拒绝。 */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        VerthysResult rc_vault = verthys_api_container_verify(ctx, out_failed_lids,
                                                  max_failed,
                                                  out_failed_count);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        return rc_vault;
    }

    /* 非容器格式无校验路径 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
    return VERTHYS_ERR_FORMAT;
}

/* ================================================================== *
 * Verthys_VerifyPersist 落盘自查接口
 *
 * 会话在解锁态持有 库句柄；自查读取 DataRoot 指向的根段并复核摘要，
 * 不改会话状态、不写盘、无副作用。
 * ================================================================== */
/* 写入静态错误文案：last_error 仅承载稳定短文案（no printf family——
 * 数值细节由结构体的 header_magic / header_version / file_size /
 * wal_offset 字段承载，避免命中输出函数红线） */
static void ver_persist_set_error(VerPersistVerifyResult *out, const char *msg)
{
    size_t n;
    if (out == NULL || msg == NULL) return;
    n = strlen(msg);
    if (n >= sizeof(out->last_error)) n = sizeof(out->last_error) - 1u;
    memcpy(out->last_error, msg, n);
    out->last_error[n] = '\0';
}

VerPersistStatus Verthys_VerifyPersist(VerthysHandle handle,
                                       VerPersistVerifyResult *out_result)
{
    struct VerthysContext *ctx;

    if (out_result == NULL) return VERTHYS_PERSIST_E_INTERNAL;
    memset(out_result, 0, sizeof(*out_result));

    /* 无可用会话（未解锁 / 锁定态 / 句柄为空）→ INTERNAL：
     * 此时不存在持锁句柄，外部读路径才是唯一选择，本接口无从自查。 */
    ctx = (struct VerthysContext *)handle;
    if (ctx == NULL || ctx->state != VERTHYS_STATE_UNLOCKED) {
        out_result->status = VERTHYS_PERSIST_E_INTERNAL;
        ver_persist_set_error(out_result, "no active unlocked session");
        return out_result->status;
    }

    /* 校验会话 DataRoot 指向的根段仍在盘上且摘要一致。
     * 旧实现以 WAL/超级块自查达成同语义，当前持久化对象为 DataRoot。 */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        VtyPersistCheck chk;
        int rc;

        memset(&chk, 0, sizeof(chk));
        if (ctx->vault == NULL || !ctx->vault->unlocked || ctx->vault->store == NULL) {
            out_result->status = VERTHYS_PERSIST_E_INTERNAL;
            ver_persist_set_error(out_result, "no active session");
            return out_result->status;
        }
#ifdef _WIN32
        if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif
        rc = vty_vault_verify_persist(ctx->vault, &chk);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        out_result->file_size = chk.file_size;
        out_result->mtime_ms = chk.mtime_ms;
        out_result->header_magic = chk.header_magic;
        out_result->header_version = chk.header_version;
        out_result->wal_offset = 0u;
        if (rc == VTY_OK) {
            out_result->status = VERTHYS_PERSIST_OK;
        } else if (rc == VTY_E_IO) {
            out_result->status = VERTHYS_PERSIST_E_IO;
            ver_persist_set_error(out_result, "data root read io failed");
        } else if (rc == VTY_E_CORRUPT) {
            out_result->status =
                (chk.file_size < ctx->vault->data_root.data_end)
                    ? VERTHYS_PERSIST_E_SIZE_MISMATCH
                    : VERTHYS_PERSIST_E_HEADER_INVALID;
            ver_persist_set_error(out_result, "data root verification failed");
        } else {
            out_result->status = VERTHYS_PERSIST_E_INTERNAL;
            ver_persist_set_error(out_result, "data root verification internal error");
        }
        return out_result->status;
    }

    /* 非容器格式无持久化自查路径 */
    out_result->status = VERTHYS_PERSIST_E_INTERNAL;
    ver_persist_set_error(out_result, "no active unlocked session");
    return out_result->status;
}
