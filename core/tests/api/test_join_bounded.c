/*
 * test_join_bounded.c — 工作线程有界汇合原语验证
 *
 * 验证目标：verthys_join_thread_bounded 以 VERTHYS_JOIN_TIMEOUT_MS 为
 * 上限等待线程退出——被外部阻塞点卡死的线程不得让 Deinit/Lock/销毁
 * 路径永久挂起（等待必须有界）；正常退出线程立即汇合（无额外延迟）；
 * 无效句柄稳定返回 WAIT_FAILED 不阻断调用方。
 *
 * 隔离设计：以手动复位事件作为"可解除阻塞"的线程驻留点——线程阻塞于
 * 事件等待（等价于被 I/O 卡死的不可取消阻塞），主线程借此确定性观测
 * 超时行为，再释放事件完成收口。断言后置：全部句柄回收与线程汇合
 * 完成后统一断言，红态下也零残留（Windows 打开句柄不可删除纪律）。
 */
#include "verthys_test.h"
#include "verthys_api_utils.h"   /* verthys_join_thread_bounded / verthys_monotonic_ms */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <process.h>

/* 线程驻留点：等待手动复位事件，事件置位后即返回 */
static unsigned __stdcall jb_event_waiter(void *arg)
{
    HANDLE ev = (HANDLE)arg;
    WaitForSingleObject(ev, INFINITE);
    return 0;
}

static unsigned __stdcall jb_quick_exit(void *arg)
{
    (void)arg;
    return 0;
}

/* 1. 阻塞线程 → WAIT_TIMEOUT 且耗时有界（不挂起）；释放后 → 即时汇合 */
TEST(join_bounded_timeout_then_release)
{
    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(ev != NULL);

    HANDLE th = (HANDLE)_beginthreadex(NULL, 0, jb_event_waiter, (void *)ev, 0, NULL);
    CHECK(th != NULL);

    uint64_t t0 = verthys_monotonic_ms();
    DWORD wr_timeout = verthys_join_thread_bounded(th);
    uint64_t elapsed_to = verthys_monotonic_ms() - t0;

    /* 释放驻留点后二次汇合（线程退出成为可预期事件） */
    DWORD ev_ok = SetEvent(ev);
    uint64_t t1 = verthys_monotonic_ms();
    DWORD wr_release = verthys_join_thread_bounded(th);
    uint64_t elapsed_rel = verthys_monotonic_ms() - t1;

    CloseHandle(th);
    CloseHandle(ev);

    /* ---- 以下为收口后统一断言 ---- */
    CHECK_EQ(wr_timeout, WAIT_TIMEOUT);             /* 被阻塞：超时而非假成功 */
    CHECK(ev_ok != 0);                              /* 事件置位成功 */
    CHECK_EQ(wr_release, WAIT_OBJECT_0);            /* 释放后再汇合：即时成功 */

    /* 耗时有界：至少走完超时窗口，且远小于无界挂起（双保险判据） */
    CHECK(elapsed_to >= VERTHYS_JOIN_TIMEOUT_MS);
    CHECK(elapsed_to < VERTHYS_JOIN_TIMEOUT_MS + 10000u);
    CHECK(elapsed_rel < 2000u);                     /* 事件置位后近瞬时汇合 */
    return 0;
}

/* 2. 正常退出线程 → WAIT_OBJECT_0（无额外满窗口等待） */
TEST(join_bounded_exited_thread)
{
    HANDLE th = (HANDLE)_beginthreadex(NULL, 0, jb_quick_exit, NULL, 0, NULL);
    CHECK(th != NULL);

    uint64_t t0 = verthys_monotonic_ms();
    DWORD wr = verthys_join_thread_bounded(th);
    uint64_t elapsed = verthys_monotonic_ms() - t0;

    CloseHandle(th);

    /* ---- 收口后统一断言 ---- */
    CHECK_EQ(wr, WAIT_OBJECT_0);
    CHECK(elapsed < VERTHYS_JOIN_TIMEOUT_MS);       /* 已退出：立即汇合 */
    return 0;
}

/* 3. NULL 句柄 → WAIT_FAILED（不崩溃、不误报成功） */
TEST(join_bounded_null_handle)
{
    DWORD wr = verthys_join_thread_bounded(NULL);
    CHECK_EQ(wr, WAIT_FAILED);
    return 0;
}