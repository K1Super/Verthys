/*
 * verthys_security_runtime.c — 进程级安全运行时
 *
 * 三个进程级单例在此收口：周期巡检定时器、活动句柄注册表、应急降级
 * 处理器。它们不绑定任何 VerthysHandle，不得放入容器会话或门面文件。
 */
#include "verthys_security_runtime.h"
#include "verthys_api_utils.h"
#include "vty_util.h"            /* vty_secure_zero */

#include "anti_debug.h"
#include "anti_inject.h"
#include "emergency.h"

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

void verthys_security_periodic_start(void)
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

void verthys_security_periodic_stop(void)
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
 * 找到全部已初始化句柄以执行“清密钥 + 锁定”。注册表在 Verthys_Init
 * 登记成功创建的上下文，Verthys_Deinit 注销，处理器遍历执行。
 * 注册表访问仅发生在 Init/Deinit（worker 单线程 FFI 语义）与应急
 * 触发路径（低频），以 SRWLOCK 保护的静态数组实现。
 * ================================================================== */
#define VERTHYS_MAX_CTXS 8

static struct VerthysContext *s_ctx_registry[VERTHYS_MAX_CTXS];
/* 静态初始化即就绪：消除首次注册/查询时的初始化竞态；SRWLOCK 无需析构。 */
static SRWLOCK s_ctx_registry_lock = SRWLOCK_INIT;

void verthys_ctx_registry_add(struct VerthysContext *ctx)
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

int verthys_ctx_registry_remove(struct VerthysContext *ctx)
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
int verthys_ctx_registry_contains(struct VerthysContext *ctx)
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

/* pin 与 contains 的差异：pin 成功时不释放共享锁，使“确认在册 → 复制
 * 上下文事实”成为原子区间；Deinit 的注销需要独占锁，因此被挡在区间外。 */
int verthys_ctx_registry_pin(struct VerthysContext *ctx)
{
    int found = 0;

    AcquireSRWLockShared(&s_ctx_registry_lock);
    for (int i = 0; i < VERTHYS_MAX_CTXS; i++) {
        if (s_ctx_registry[i] == ctx) {
            found = 1;
            break;
        }
    }
    if (!found) {
        ReleaseSRWLockShared(&s_ctx_registry_lock);
    }
    return found;
}

void verthys_ctx_registry_unpin(void)
{
    ReleaseSRWLockShared(&s_ctx_registry_lock);
}

/* 注册表是否仍有空位。
 *
 * 在 Init 分配任何资源之前检查，避免注册失败后留下无法注销的上下文。 */
int verthys_ctx_registry_has_capacity(void)
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

/* 最后一个上下文是否已注销（此时才可停止进程级预置线程）。 */
int verthys_ctx_registry_empty(void)
{
    int empty = 1;
    AcquireSRWLockShared(&s_ctx_registry_lock);
    for (int i = 0; i < VERTHYS_MAX_CTXS; i++) {
        if (s_ctx_registry[i] != NULL) {
            empty = 0;
            break;
        }
    }
    ReleaseSRWLockShared(&s_ctx_registry_lock);
    return empty;
}

/*
 * 应急 DEGRADE 降级处理器（emergency_set_degrade_handler 注入）。
 *
 * 语义：对全部已解锁句柄执行“密钥与明文立即清零 + 状态置 LOCKED”，
 * 进程保持存活。不执行任何磁盘写入（与 Verthys_Lock 的差异：跳过
 * 会话提交与缓存刷盘——降级路径优先保证敏感数据不落盘）。
 * 恢复方式：用户正常 Verthys_V4Unlock。
 */
void verthys_emergency_lock_all(void)
{
    AcquireSRWLockShared(&s_ctx_registry_lock);
    for (int i = 0; i < VERTHYS_MAX_CTXS; i++) {
        struct VerthysContext *ctx = s_ctx_registry[i];
        if (ctx == NULL || ctx->state != VERTHYS_STATE_UNLOCKED) continue;

        verthys_ctx_lock_exclusive(ctx);
        if (ctx->state == VERTHYS_STATE_UNLOCKED) {
            ctx_zero_sensitive(ctx);
            ctx->state = VERTHYS_STATE_LOCKED;
        }
        verthys_ctx_unlock_exclusive(ctx);
    }
    ReleaseSRWLockShared(&s_ctx_registry_lock);
}
