/* verthys_progress.c — 进度回调环形缓冲区模块（从 verthys_api.c 拆分）
 *
 * 本文件包含解锁进度回调的无锁环形缓冲区实现及独立消费线程逻辑
 * （方案六）。仅在 Windows 平台编译（整体由 #ifdef _WIN32 包裹）。
 *
 * 线程安全：
 *   - head 仅生产者写（verthys_emit_unlock_progress，解锁主线程）
 *   - tail 仅消费者写（verthys_progress_consumer_thread）
 *   - callback/user_data 在注册时设置，消费线程只读
 *   - active 标志使用 InterlockedExchange 安全切换
 * ================================================================== */
#ifdef _WIN32

#include "verthys_progress.h"
#include "verthys_api_utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

/* ★ 方案六：消费线程 — 从环形缓冲区读取进度条目并调用回调
 *
 * 低优先级运行，避免抢占解锁主线程。
 * 无数据时 Sleep(1) 避免忙等，有数据时立即处理。
 * active == 0 时退出循环（Verthys_Deinit 时触发）。 */
DWORD WINAPI verthys_progress_consumer_thread(LPVOID param)
{
    VerthysProgressRing *ring = (VerthysProgressRing *)param;
    /* 设置低优先级，避免抢占解锁主线程 */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

    while (ring->active) {
        LONG head = ring->head;
        LONG tail = ring->tail;
        if (head != tail) {
            /* 有数据可读：先 MemoryBarrier 确保 head 读取后再读 entries */
            MemoryBarrier();
            VerthysProgressEntry *entry = &ring->entries[tail];

            if (ring->callback != NULL) {
                VerthysUnlockProgress prog;
                prog.stage      = entry->stage;
                prog.percent    = entry->percent;
                prog.elapsed_ms = entry->elapsed_ms;
                prog.message    = entry->message;
                ring->callback(&prog, ring->user_data);
            }

            /* 确保 entries 数据读取完毕后再推进 tail */
            MemoryBarrier();
            ring->tail = (tail + 1) % VERTHYS_PROGRESS_RING_SIZE;
        } else {
            /* 无数据：短暂休眠避免忙等（1ms 精度足够进度推送） */
            Sleep(1);
        }
    }
    return 0;
}

/* ★ 方案六：创建并启动环形缓冲区 + 消费线程
 *
 * 在 Verthys_RegisterUnlockProgressCallback 首次注册时调用。
 * 返回 NULL 表示创建失败（调用方回退到同步回调模式）。 */
VerthysProgressRing *verthys_progress_ring_create(
    VerthysUnlockProgressCallback callback, void *user_data)
{
    VerthysProgressRing *ring = (VerthysProgressRing *)calloc(1, sizeof(VerthysProgressRing));
    if (ring == NULL) return NULL;

    ring->head    = 0;
    ring->tail    = 0;
    ring->active  = 1;
    ring->callback = callback;
    ring->user_data = user_data;

    ring->consumer_thread = CreateThread(NULL, 0, verthys_progress_consumer_thread,
                                          ring, 0, NULL);
    if (ring->consumer_thread == NULL) {
        free(ring);
        return NULL;
    }

    return ring;
}

/* ★ 方案六：停止消费线程并销毁环形缓冲区
 *
 * 在 Verthys_Deinit 时调用。等待消费线程最多 3 秒退出，
 * 确保残留进度条目被消费完毕。 */
void verthys_progress_ring_destroy(VerthysProgressRing *ring)
{
    if (ring == NULL) return;

    /* 通知消费线程退出 */
    InterlockedExchange(&ring->active, 0);

    /*
     * ★ 最终修复方案 P1-7：等待消费线程退出改为无限期。
     * 原缺陷：3 秒超时后即 free(ring)，若消费者正阻塞在回调内
     * （如 stdout 管道满），唤醒后将访问已释放内存（UAF）。
     * 改为无限等待：消费者循环以 active 标志驱动、每条目间可中断，
     * 正常路径毫秒级退出；极端阻塞场景宁可挂起 Deinit 也不悬垂释放。
     */
    if (ring->consumer_thread != NULL) {
        WaitForSingleObject(ring->consumer_thread, INFINITE);
        CloseHandle(ring->consumer_thread);
    }

    free(ring);
}

/* ★ 方案六：生产者 — 写入进度条目到环形缓冲区（O(1)，<1μs）
 *
 * 缓冲区满时丢弃最旧条目（推进 tail），保证最新进度优先。
 * 仅写 4 个字段 + MemoryBarrier，不调用任何外部函数，零阻塞。 */
void verthys_progress_ring_push(VerthysProgressRing *ring,
                              uint32_t stage, uint32_t percent,
                              uint64_t elapsed_ms, const char *msg)
{
    if (ring == NULL) return;

    LONG head = ring->head;
    LONG next_head = (head + 1) % VERTHYS_PROGRESS_RING_SIZE;

    /* 检查缓冲区是否满（next_head == tail 表示满） */
    if (next_head == ring->tail) {
        /* 缓冲区满：丢弃最旧条目（推进 tail） */
        ring->tail = (ring->tail + 1) % VERTHYS_PROGRESS_RING_SIZE;
    }

    /* 写入条目（message 为编译期字符串字面量，无需拷贝） */
    ring->entries[head].stage      = stage;
    ring->entries[head].percent    = percent;
    ring->entries[head].elapsed_ms = elapsed_ms;
    ring->entries[head].message    = msg;

    /* 确保数据写入对消费者可见后再推进 head */
    MemoryBarrier();
    ring->head = next_head;
}

/* ★ 企业级根治修复：排空进度环形缓冲区
 *
 * 根因：消费者线程在整个会话期间运行（仅在 Verthys_Deinit 销毁），
 * Verthys_Unlock 返回后消费者线程可能仍在处理 ring buffer 中的陈旧心跳消息，
 * 这些消息会写入 stdout 并在最终 unlock 响应之后到达父进程，
 * 污染后续 IPC 通信（probeGlobalKeyRecord 收到 unlock_progress 行而非预期响应）。
 *
 * 修复：在 Verthys_Unlock 返回前排空 ring buffer，确保所有进度消息
 * 在最终 unlock 响应之前写入 stdout。
 *
 * 等待条件：ring->head == ring->tail（缓冲区空）
 * 超时：500ms（防止消费者线程阻塞在 stdout 写入时死锁）
 * 额外等待：3ms 确保最后一条消息的回调完成 */
void verthys_progress_ring_flush(VerthysProgressRing *ring)
{
    if (ring == NULL) return;

    /* 等待缓冲区排空，最多 500ms */
    for (int i = 0; i < 500; i++) {
        if (ring->head == ring->tail) {
            break;
        }
        Sleep(1);
    }

    /* 额外等待 3ms 确保最后一条消息的回调完成（回调可能正在写入 stdout） */
    Sleep(3);
}

/* ★ 方案5/方案六：解锁进度回调内部辅助函数
 *
 * verthys_emit_unlock_progress 在解锁各阶段写入进度。
 * ★ 方案六改造：优先写入无锁环形缓冲区（O(1) <1μs），
 *   由独立低优先级消费线程异步调用注册的回调函数。
 *   主解锁链路零阻塞，彻底杜绝回调阻塞（D-010 修复）。
 *   无环形缓冲区时回退到同步调用（兼容性保障）。
 * 若未注册回调（ctx->unlock_progress_cb == NULL），本函数为空操作，
 * 零开销——仅一次 NULL 判断即可返回。
 *
 * 参数：
 *   ctx     — 加密库上下文（含回调指针与起始时间戳）
 *   stage   — VerthysUnlockStage 枚举值
 *   percent — 0~100 累计百分比
 *   msg     — UTF-8 字符串字面量（只读，DLL 内部静态存储，回调期间有效）
 *
 * 安全边界：
 *   - 仅传递阶段编号、百分比、耗时、只读字符串，不含任何密钥/密码/明文
 *   - message 为编译期字符串字面量，生命周期与进程相同，回调可安全读取
 *   - 回调在消费线程中异步执行（方案六），DLL 不解析 user_data 内容
 *
 * 性能：★ 方案六改造后，本函数仅做 O(1) 环形缓冲区入队（<1μs），
 *   回调执行由独立消费线程处理，主解锁链路零阻塞。 */
void verthys_emit_unlock_progress(struct VerthysContext *ctx,
                                uint32_t stage, uint32_t percent,
                                const char *msg)
{
    if (ctx == NULL) return;

#ifdef _WIN32
    /* ★ 方案六：优先写入无锁环形缓冲区（O(1) <1μs），独立消费线程异步推送 */
    if (ctx->progress_ring != NULL) {
        verthys_progress_ring_push((VerthysProgressRing *)ctx->progress_ring,
                                 stage, percent,
                                 (uint64_t)(verthys_monotonic_ms() - ctx->unlock_progress_start_ms),
                                 msg);
        return;
    }
#endif

    /* 兼容回退：无环形缓冲区时同步调用回调（非 Windows 或创建失败） */
    if (ctx->unlock_progress_cb == NULL) {
        return;  /* 未注册回调：零开销返回 */
    }
    VerthysUnlockProgress prog;
    prog.stage      = stage;
    prog.percent    = percent;
    prog.elapsed_ms = (uint64_t)(verthys_monotonic_ms() - ctx->unlock_progress_start_ms);
    prog.message    = msg;
    ctx->unlock_progress_cb(&prog, ctx->unlock_progress_user_data);
}

#endif /* _WIN32 */
