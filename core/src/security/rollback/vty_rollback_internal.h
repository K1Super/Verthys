/*
 * vty_rollback_internal.h — 回退锚点实现的跨文件契约
 *
 * 集中状态布局常量、共享类型、进程级状态声明与内部函数声明；不对外
 * 导出，不属于公共 ABI。
 */
#ifndef VTY_ROLLBACK_INTERNAL_H
#define VTY_ROLLBACK_INTERNAL_H

#include "vty_rollback.h"
#include "vty_types.h"
#include "vty_secure_state.h"
#include "vty_device_root.h"
#include "vty_tpm_witness.h"
#include "vty_util.h"

#include <windows.h>
#define RB_MAGIC          0x42525456u   /* 'VTRB'（小端） */
#define RB_VERSION        2u
#define RB_HDR_BYTES      16u
#define RB_ENTRY_BYTES    57u
#define RB_MAC_BYTES      32u
#define RB_KEY_BYTES      VTY_KEY_BYTES
#define RB_BLOB_BYTES     VTY_DEVICE_BLOB_BYTES
#define RB_ENTRIES_OFFSET RB_HDR_BYTES
#define RB_ENTRY_WITNESS_OFFSET (VTY_UUID_BYTES + 8u)
#define RB_ENTRY_FP_OFFSET      (RB_ENTRY_WITNESS_OFFSET + 1u)

#define RB_ENTRIES_BYTES    (VTY_ROLLBACK_MAX_ENTRIES * RB_ENTRY_BYTES)
#define RB_MAC_OFFSET       (RB_HDR_BYTES + RB_ENTRIES_BYTES)
#define RB_BLOB_OFFSET      (RB_MAC_OFFSET + RB_MAC_BYTES)
#define RB_TOTAL_BYTES      (RB_BLOB_OFFSET + RB_BLOB_BYTES)
#define RB_MSG_BYTES        (RB_HDR_BYTES + RB_ENTRIES_BYTES + RB_BLOB_BYTES)


/* 待清理的 DEAD 锚点 UUID 列表。只在持锁调用链内使用，容量固定 64，
 * 不分配堆内存。 */
typedef struct {
    uint8_t uuids[VTY_ROLLBACK_MAX_ENTRIES][VTY_UUID_BYTES];
    uint32_t count;
} rb_dead_list;
#define RB_G0A_VERIFIED_MAX 4
#define RB_G0A_DIRTY_MAX 8

typedef struct {
    int valid;
    uint8_t uuid[VTY_UUID_BYTES];
    uint64_t generation;
    uint8_t slot;
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
} rb_verified_entry;

/* 进程级状态：只在基础文件定义一次，其余文件按声明访问，禁止另建副本。 */
extern char g_state_path[VTY_SECURE_STATE_PATH_BYTES];
extern int g_test_path;
extern int g_initialized;
extern int g_enabled;

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
void vty_rb_apply_test_disable(void);
extern int g_crash_point;
#else
#define vty_rb_apply_test_disable() ((void)0)
#endif

extern rb_verified_entry g_verified[RB_G0A_VERIFIED_MAX];
extern uint8_t g_dirty[RB_G0A_DIRTY_MAX][VTY_UUID_BYTES];
extern int g_dirty_used[RB_G0A_DIRTY_MAX];

/* 基础：逻辑容量、见证身份与跨进程状态锁 */
uint32_t vty_rb_max_entries(void);
int vty_rb_witness_id(const uint8_t vault_uuid[VTY_UUID_BYTES],
                      uint8_t id[VTY_UUID_BYTES]);
HANDLE vty_rb_lock_state(void);
void vty_rb_unlock_state(HANDLE mutex);

/* 状态存储：条目访问与认证读写 */
int vty_rb_load_authenticated(uint8_t buf[RB_TOTAL_BYTES], int *is_new);
int vty_rb_store_state(uint8_t buf[RB_TOTAL_BYTES]);
int vty_rb_store(uint8_t buf[RB_TOTAL_BYTES]);
int vty_rb_find_entry(const uint8_t buf[RB_TOTAL_BYTES],
                      const uint8_t uuid[VTY_UUID_BYTES]);
uint8_t *vty_rb_entry_at(uint8_t buf[RB_TOTAL_BYTES], uint32_t index);
uint64_t vty_rb_entry_gen(const uint8_t *e);
int vty_rb_entry_witness_valid(const uint8_t *e);
int vty_rb_upsert(uint8_t buf[RB_TOTAL_BYTES],
                  const uint8_t uuid[VTY_UUID_BYTES], uint64_t generation,
                  int allow_decrease, int witness_slot,
                  const uint8_t fp[VTY_TPM_WITNESS_FP_BYTES], int *changed);

/* 见证：轮换、退役、回收与进程内缓存/脏标记 */
uint32_t vty_rb_collect_dead_locked(uint8_t buf[RB_TOTAL_BYTES],
                                    rb_dead_list *dead);
void vty_rb_invalidate_dead_pool_locked(const rb_dead_list *dead);
void vty_rb_delete_dead_witnesses(const rb_dead_list *dead,
                                  uint32_t *out_failed);
int vty_rb_rotate_witness(const uint8_t wid[VTY_UUID_BYTES], int current_slot,
                          int *next_slot,
                          uint8_t fp[VTY_TPM_WITNESS_FP_BYTES]);
int vty_rb_retire_witness(const uint8_t wid[VTY_UUID_BYTES], int old_slot,
                          int new_slot);
int vty_rb_cleanup_stale_witness(const uint8_t wid[VTY_UUID_BYTES],
                                 int current_slot);
void vty_rb_cache_store(const uint8_t uuid[VTY_UUID_BYTES],
                        uint64_t generation, int slot,
                        const uint8_t fp[VTY_TPM_WITNESS_FP_BYTES]);
void vty_rb_cache_clear(void);
int vty_rb_verify_entry_cached(const uint8_t uuid[VTY_UUID_BYTES],
                               const uint8_t wid[VTY_UUID_BYTES],
                               const uint8_t *e);
int vty_rb_dirty_contains(const uint8_t wid[VTY_UUID_BYTES]);
void vty_rb_dirty_mark(const uint8_t wid[VTY_UUID_BYTES]);
void vty_rb_dirty_clear(const uint8_t wid[VTY_UUID_BYTES]);

#endif /* VTY_ROLLBACK_INTERNAL_H */
