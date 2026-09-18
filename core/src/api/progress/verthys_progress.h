#ifndef VERTHYS_PROGRESS_H
#define VERTHYS_PROGRESS_H

#include "verthys_internal.h"
#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32

#define VERTHYS_PROGRESS_RING_SIZE 32  /* 必须是 2 的幂 */

typedef struct {
    uint32_t    stage;
    uint32_t    percent;
    uint64_t    elapsed_ms;
    const char *message;  /* 编译期字符串字面量，生命周期与进程相同 */
} VerthysProgressEntry;

typedef struct VerthysProgressRing {
    VerthysProgressEntry        entries[VERTHYS_PROGRESS_RING_SIZE];
    volatile LONG             head;             /* 生产者写位置（仅生产者写） */
    volatile LONG             tail;             /* 消费者读位置（仅消费者写） */
    volatile LONG             active;           /* 消费线程运行标志 */
    HANDLE                    consumer_thread;
    VerthysUnlockProgressCallback callback;       /* 注册时设置，消费线程读取 */
    void                     *user_data;
} VerthysProgressRing;

VerthysProgressRing *verthys_progress_ring_create(VerthysUnlockProgressCallback callback, void *user_data);
void verthys_progress_ring_destroy(VerthysProgressRing *ring);
void verthys_progress_ring_push(VerthysProgressRing *ring,
                              uint32_t stage, uint32_t percent,
                              uint64_t elapsed_ms, const char *msg);
void verthys_progress_ring_flush(VerthysProgressRing *ring);
void verthys_emit_unlock_progress(struct VerthysContext *ctx, uint32_t stage, uint32_t percent, const char *msg);

#else

static inline void verthys_emit_unlock_progress(struct VerthysContext *ctx, uint32_t stage, uint32_t percent, const char *msg) { (void)ctx; (void)stage; (void)percent; (void)msg; }

#endif

#endif /* VERTHYS_PROGRESS_H */
