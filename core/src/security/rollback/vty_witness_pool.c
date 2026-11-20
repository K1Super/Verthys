/*
 * vty_witness_pool.c — TPM 见证密钥预置池实现
 *
 * 单一后台线程串行建键；每个见证域至多一个预置键。
 * 后台建键持有跨进程 RollbackState 互斥量，避免同名 TPM 键并发覆盖。
 */
#include "vty_witness_pool.h"
#include "vty_rollback.h"
#include "vty_util.h"

#include <windows.h>
#include <string.h>

#define POOL_MAX_ENTRIES 8

enum {
    PE_FREE = 0,
    PE_CREATING = 1,
    PE_READY = 2
};

typedef struct {
    int used;
    uint8_t wid[VTY_UUID_BYTES];
    int state;
    int target_slot;
    int current_slot;
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
} pool_entry;

static pool_entry g_entries[POOL_MAX_ENTRIES];
static SRWLOCK g_lock = SRWLOCK_INIT;
static HANDLE g_stop_event = NULL;
static HANDLE g_work_event = NULL;
static HANDLE g_thread = NULL;
static int g_started = 0;
static volatile LONG g_stat_hits = 0;
static volatile LONG g_stat_fallbacks = 0;
static volatile LONG g_stat_waits = 0;

static pool_entry *find_locked(const uint8_t wid[VTY_UUID_BYTES])
{
    int i;

    for (i = 0; i < POOL_MAX_ENTRIES; i++) {
        if (g_entries[i].used &&
            memcmp(g_entries[i].wid, wid, VTY_UUID_BYTES) == 0) {
            return &g_entries[i];
        }
    }
    return NULL;
}

/* create=1 时分配空闲项；全部占用（CREATING/READY）则返回 NULL，
 * 调用方走同步建键。 */
static pool_entry *find_or_alloc_locked(const uint8_t wid[VTY_UUID_BYTES],
                                        int create)
{
    pool_entry *e = find_locked(wid);
    int i;

    if (e != NULL || !create) return e;
    for (i = 0; i < POOL_MAX_ENTRIES; i++) {
        if (!g_entries[i].used || g_entries[i].state == PE_FREE) {
            memset(&g_entries[i], 0, sizeof(g_entries[i]));
            g_entries[i].used = 1;
            g_entries[i].state = PE_FREE;
            g_entries[i].current_slot = -1;
            g_entries[i].target_slot = -1;
            memcpy(g_entries[i].wid, wid, VTY_UUID_BYTES);
            return &g_entries[i];
        }
    }
    return NULL;
}

static DWORD WINAPI pool_worker(LPVOID param)
{
    HANDLE waits[2];

    (void)param;
    waits[0] = g_stop_event;
    waits[1] = g_work_event;
    for (;;) {
        DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);

        if (w == WAIT_OBJECT_0) break;
        if (w != WAIT_OBJECT_0 + 1) break;

        for (;;) {
            uint8_t wid[VTY_UUID_BYTES];
            uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
            int slot = -1;
            int found = 0;
            int valid = 0;
            int rc;
            int i;
            HANDLE state;
            pool_entry *e;

            /* 关闭请求优先于继续建键：避免 shutdown 等待建键批次。 */
            if (WaitForSingleObject(g_stop_event, 0) == WAIT_OBJECT_0) break;

            AcquireSRWLockExclusive(&g_lock);
            for (i = 0; i < POOL_MAX_ENTRIES; i++) {
                if (g_entries[i].used &&
                    g_entries[i].state == PE_CREATING) {
                    memcpy(wid, g_entries[i].wid, VTY_UUID_BYTES);
                    slot = g_entries[i].target_slot;
                    found = 1;
                    break;
                }
            }
            ReleaseSRWLockExclusive(&g_lock);
            if (!found) break;

            /* 与提交共享同一跨进程互斥量：同名键的创建/覆盖必须串行。 */
            state = vty_rollback_lock_state();
            if (state == NULL) {
                AcquireSRWLockExclusive(&g_lock);
                e = find_locked(wid);
                if (e != NULL && e->state == PE_CREATING) {
                    e->state = PE_FREE;
                }
                ReleaseSRWLockExclusive(&g_lock);
                continue;
            }

            /* 建键前在状态锁内复核：槽位必须仍是非当前槽。 */
            AcquireSRWLockExclusive(&g_lock);
            e = find_locked(wid);
            if (e != NULL && e->state == PE_CREATING &&
                e->target_slot == slot && slot != e->current_slot &&
                slot >= 0 && slot < (int)VTY_TPM_WITNESS_SLOTS) {
                valid = 1;
            }
            ReleaseSRWLockExclusive(&g_lock);

            if (!valid) {
                /* 目标槽已变成当前槽（另一进程先推进）：本条目不可能再
                 * 产出可用键，必须复位为 FREE，否则内层循环会永远选中
                 * 同一条 CREATING 项并自旋，shutdown 随之挂死。 */
                AcquireSRWLockExclusive(&g_lock);
                e = find_locked(wid);
                if (e != NULL && e->state == PE_CREATING &&
                    e->target_slot == slot) {
                    e->state = PE_FREE;
                }
                ReleaseSRWLockExclusive(&g_lock);
                vty_rollback_unlock_state(state);
                continue;
            }

            memset(fp, 0, sizeof(fp));
            rc = vty_tpm_witness_create(wid, (uint8_t)slot, fp);

            AcquireSRWLockExclusive(&g_lock);
            e = find_locked(wid);
            if (e != NULL && e->state == PE_CREATING &&
                e->target_slot == slot) {
                if (rc == VTY_OK) {
                    e->state = PE_READY;
                    memcpy(e->fp, fp, VTY_TPM_WITNESS_FP_BYTES);
                } else {
                    e->state = PE_FREE;
                }
            } else if (rc == VTY_OK) {
                /* 登记已作废：新键未被任何状态引用，立即清理。 */
                (void)vty_tpm_witness_delete(wid, (uint8_t)slot);
            }
            ReleaseSRWLockExclusive(&g_lock);

            vty_secure_zero(fp, sizeof(fp));
            vty_rollback_unlock_state(state);
        }
    }
    return 0;
}

int vty_witness_pool_start(void)
{
    int rc = VTY_OK;

    AcquireSRWLockExclusive(&g_lock);
    if (!g_started) {
        if (g_stop_event == NULL) {
            g_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
        }
        if (g_work_event == NULL) {
            g_work_event = CreateEventW(NULL, FALSE, FALSE, NULL);
        }
        if (g_stop_event != NULL && g_work_event != NULL) {
            ResetEvent(g_stop_event);
            g_thread = CreateThread(NULL, 0, pool_worker, NULL, 0, NULL);
        }
        if (g_thread != NULL) {
            g_started = 1;
        } else {
            rc = VTY_E_RESOURCE;
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
    return rc;
}

void vty_witness_pool_shutdown(void)
{
    HANDLE thread = NULL;
    HANDLE stop_ev = NULL;
    HANDLE work_ev = NULL;

    AcquireSRWLockExclusive(&g_lock);
    if (g_started) {
        stop_ev = g_stop_event;
        g_started = 0;
        thread = g_thread;
    }
    ReleaseSRWLockExclusive(&g_lock);

    if (thread != NULL && stop_ev != NULL) {
        SetEvent(stop_ev);
        /* 建键最长约 640ms；TPM 偶发卡顿也不 TerminateThread，
         * 否则会在 CNG 调用中途卸载代码。 */
        (void)WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }

    AcquireSRWLockExclusive(&g_lock);
    work_ev = g_work_event;
    stop_ev = g_stop_event;
    g_thread = NULL;
    g_work_event = NULL;
    g_stop_event = NULL;
    memset(g_entries, 0, sizeof(g_entries));
    ReleaseSRWLockExclusive(&g_lock);

    if (work_ev != NULL) CloseHandle(work_ev);
    if (stop_ev != NULL) CloseHandle(stop_ev);
}

void vty_witness_pool_schedule(const uint8_t wid[VTY_UUID_BYTES],
                               int current_slot)
{
    pool_entry *e;

    if (wid == NULL || current_slot < 0 ||
        current_slot >= (int)VTY_TPM_WITNESS_SLOTS) {
        return;
    }
    AcquireSRWLockExclusive(&g_lock);
    e = find_or_alloc_locked(wid, 1);
    if (e != NULL) {
        e->current_slot = current_slot;
        if (e->state == PE_READY && e->target_slot == current_slot) {
            /* 当前槽的键被状态引用，不能删除；只丢弃本进程的预置登记。 */
            e->state = PE_FREE;
        }
        if (e->state == PE_FREE && g_work_event != NULL) {
            e->state = PE_CREATING;
            e->target_slot = (current_slot == 0) ? 1 : 0;
            SetEvent(g_work_event);
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}

int vty_witness_pool_take(const uint8_t wid[VTY_UUID_BYTES], int current_slot,
                          int *slot,
                          uint8_t fp[VTY_TPM_WITNESS_FP_BYTES])
{
    uint8_t local[VTY_TPM_WITNESS_FP_BYTES];
    pool_entry *e;
    int s = -1;
    int creating = 0;

    if (wid == NULL || slot == NULL || fp == NULL) return VTY_E_INVALID;

    AcquireSRWLockExclusive(&g_lock);
    e = find_or_alloc_locked(wid, 0);
    if (e != NULL && e->state == PE_READY &&
        e->target_slot != current_slot &&
        e->target_slot >= 0 &&
        e->target_slot < (int)VTY_TPM_WITNESS_SLOTS) {
        s = e->target_slot;
        memcpy(local, e->fp, sizeof(local));
        e->state = PE_FREE;
    } else if (e != NULL && e->state == PE_CREATING) {
        creating = 1;
    } else if (e != NULL && e->state == PE_READY) {
        /* 预置登记落在当前槽：该键可能正是状态引用的那一把，
         * 不能删除，只丢弃登记；调用方走同步回退。 */
        e->state = PE_FREE;
    }
    ReleaseSRWLockExclusive(&g_lock);

    if (creating) return VTY_E_POLICY;
    if (s < 0) return VTY_E_TPM;

    /* F3：内存指纹不能替代“TPM 中确实存在匹配键”。 */
    if (vty_tpm_witness_verify(wid, (uint8_t)s, local) != VTY_OK) {
        (void)vty_tpm_witness_delete(wid, (uint8_t)s);
        InterlockedIncrement(&g_stat_fallbacks);
        vty_secure_zero(local, sizeof(local));
        return VTY_E_TPM;
    }

    memcpy(fp, local, VTY_TPM_WITNESS_FP_BYTES);
    *slot = s;
    vty_secure_zero(local, sizeof(local));
    InterlockedIncrement(&g_stat_hits);
    return VTY_OK;
}

void vty_witness_pool_return(const uint8_t wid[VTY_UUID_BYTES], int slot,
                             const uint8_t fp[VTY_TPM_WITNESS_FP_BYTES])
{
    pool_entry *e;
    int stored = 0;

    if (wid == NULL || fp == NULL) return;
    if (slot < 0 || slot >= (int)VTY_TPM_WITNESS_SLOTS) return;

    AcquireSRWLockExclusive(&g_lock);
    e = find_or_alloc_locked(wid, 1);
    if (e != NULL && e->state == PE_FREE) {
        e->state = PE_READY;
        e->target_slot = slot;
        memcpy(e->fp, fp, VTY_TPM_WITNESS_FP_BYTES);
        stored = 1;
    }
    ReleaseSRWLockExclusive(&g_lock);

    /* 池已满或登记冲突：该键未被任何状态引用，删除避免遗留。 */
    if (!stored) {
        (void)vty_tpm_witness_delete(wid, (uint8_t)slot);
    }
}

void vty_witness_pool_invalidate(const uint8_t wid[VTY_UUID_BYTES], int slot)
{
    pool_entry *e;

    if (wid == NULL) return;
    AcquireSRWLockExclusive(&g_lock);
    e = find_or_alloc_locked(wid, 0);
    if (e != NULL && e->target_slot == slot) {
        e->state = PE_FREE;
    }
    ReleaseSRWLockExclusive(&g_lock);
}

int vty_witness_pool_wait_idle(const uint8_t wid[VTY_UUID_BYTES],
                               unsigned timeout_ms)
{
    DWORD start = GetTickCount();

    if (wid == NULL) return VTY_E_INVALID;
    InterlockedIncrement(&g_stat_waits);
    for (;;) {
        pool_entry *e;
        int creating;

        AcquireSRWLockExclusive(&g_lock);
        e = find_locked(wid);
        creating = (e != NULL && e->state == PE_CREATING);
        ReleaseSRWLockExclusive(&g_lock);

        if (!creating) return VTY_OK;
        if ((DWORD)(GetTickCount() - start) >= timeout_ms) return VTY_E_TPM;
        Sleep(10);
    }
}

int vty_witness_pool_test_wait_ready(const uint8_t wid[VTY_UUID_BYTES],
                                     unsigned timeout_ms)
{
    DWORD start = GetTickCount();

    if (wid == NULL) return 0;
    for (;;) {
        pool_entry *e;
        int state = PE_FREE;

        AcquireSRWLockExclusive(&g_lock);
        e = find_locked(wid);
        state = (e != NULL) ? e->state : PE_FREE;
        ReleaseSRWLockExclusive(&g_lock);

        if (state == PE_READY) return 1;
        if (state != PE_CREATING) return 0;
        if ((DWORD)(GetTickCount() - start) >= timeout_ms) return 0;
        Sleep(10);
    }
}

void vty_witness_pool_test_stats(unsigned *hits, unsigned *fallbacks,
                                 unsigned *waits)
{
    if (hits != NULL) *hits = (unsigned)g_stat_hits;
    if (fallbacks != NULL) *fallbacks = (unsigned)g_stat_fallbacks;
    if (waits != NULL) *waits = (unsigned)g_stat_waits;
}

void vty_witness_pool_test_reset_stats(void)
{
    InterlockedExchange(&g_stat_hits, 0);
    InterlockedExchange(&g_stat_fallbacks, 0);
    InterlockedExchange(&g_stat_waits, 0);
}
