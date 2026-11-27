/*
 * vty_rollback_anchor.c — 锚点生命周期：校验、提交、重设、列举与批量释放
 *
 * 组织状态锁、状态读写与见证操作的顺序，保证先写状态后删旧键；任何
 * 失败路径都折叠为 fail-closed。
 */
#include "vty_rollback_internal.h"

#include <string.h>

#include "vty_witness_pool.h"

/* 容器已建立回滚锚点的最小代：创建成功后至少有一次 save_meta，
 * 磁盘代 >= 2；generation == 1 是未完成创建，允许首次运行。 */
#define RB_ANCHOR_MIN_GENERATION 2u

/* 分类快照：锁内只复制条目，解锁后再做 TPM 探测，避免维护列表
 * 长时间占用跨进程状态互斥量。 */
typedef struct {
    uint8_t  uuid[VTY_UUID_BYTES];
    uint64_t generation;
    uint8_t  slot;
    uint8_t  fp[VTY_TPM_WITNESS_FP_BYTES];
} rb_probe_entry;

int vty_rollback_check(const uint8_t vault_uuid[VTY_UUID_BYTES],
                       uint64_t generation)
{
    uint8_t buf[RB_TOTAL_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    int is_new = 0;
    int idx;
    uint64_t stored;
    int rc = VTY_OK;
    int any_new;
    HANDLE lock;
    vty_rb_apply_test_disable();
    if (!g_enabled) return VTY_OK;
    if (vault_uuid == NULL) return VTY_E_INVALID;
    if (vty_rb_witness_id(vault_uuid, wid) != VTY_OK) return VTY_E_ROLLBACK;
    if (vty_rollback_init() != VTY_OK) return VTY_E_ROLLBACK;

    lock = vty_rb_lock_state();
    if (lock == NULL) return VTY_E_ROLLBACK;

    rc = vty_rb_load_authenticated(buf, &is_new);
    if (rc != VTY_OK) goto out;

    any_new = vty_tpm_witness_any_usable(wid);
    if (is_new) {
        /* 状态缺失：见证仍在 = 删除/回滚；容器已有锚点（generation>=2）
         * 即使见证也被删除，仍拒绝，恢复码是唯一逃生通道。 */
        if (any_new != 0 || generation >= (uint64_t)RB_ANCHOR_MIN_GENERATION) {
            rc = VTY_E_ROLLBACK;
        }
        goto out;
    }

    idx = vty_rb_find_entry(buf, vault_uuid);
    if (idx >= 0) {
        const uint8_t *e = vty_rb_entry_at(buf, (uint32_t)idx);
        /* 条目必须引用合法见证槽；字段非法的条目一律拒绝，不能因为
         * “当前没有任何见证键”就当作首次运行放行。 */
        if (!vty_rb_entry_witness_valid(e)) {
            rc = VTY_E_ROLLBACK;
            goto out;
        }
        if (vty_rb_verify_entry_cached(vault_uuid, wid, e) != VTY_OK) {
            rc = VTY_E_ROLLBACK;
            goto out;
        }
    } else {
        /* 状态存在但该库没有条目：等同缺失状态 */
        if (any_new != 0 || generation >= (uint64_t)RB_ANCHOR_MIN_GENERATION) {
            rc = VTY_E_ROLLBACK;
            goto out;
        }
        rc = VTY_OK;
        goto out;
    }

    stored = vty_rb_entry_gen(vty_rb_entry_at(buf, (uint32_t)idx));
    rc = (generation < stored) ? VTY_E_ROLLBACK : VTY_OK;

    if (rc == VTY_OK) {
        const uint8_t *e = vty_rb_entry_at(buf, (uint32_t)idx);

        /* 只有已建立见证的条目才允许清理/预置；无见证条目没有可引用的槽。 */
        if (vty_rb_entry_witness_valid(e)) {
            int current_slot = (int)e[RB_ENTRY_WITNESS_OFFSET];

            /* 启动/解锁清理非当前槽。清理失败不得继续，否则旧状态
             * 仍可能持有匹配的旧键。 */
            if (vty_rb_cleanup_stale_witness(wid, current_slot) != VTY_OK) {
                vty_rb_dirty_mark(wid);
                rc = VTY_E_ROLLBACK;
            } else if (vty_witness_pool_start() == VTY_OK) {
                /* 条目已存在，允许预置下一把（新库首次提交前不预置）。 */
                vty_witness_pool_schedule(wid, current_slot);
            }
        }
    }

out:
    vty_rb_unlock_state(lock);
    return rc;
}

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
void vty_rollback_set_crash_point_for_test(int point)
{
    g_crash_point = point;
}

/* 直接结束进程，模拟断电：不做任何清理，磁盘与 TPM 状态保持当前时刻。 */
static void rb_crash_if(int point)
{
    if (g_crash_point != point) return;
    FlushProcessWriteBuffers();
    TerminateProcess(GetCurrentProcess(), 0xC0DE0000u | (unsigned)point);
}

#define RB_CRASH(point) rb_crash_if(point)
#else
#define RB_CRASH(point) ((void)0)
#endif

/* 提交：优先取预置键；无预置时等待后台或同步回退。
 * 旧键删除失败必须撤销；撤销也失败则标记锚点脏并 fail-closed。 */
static int rb_commit_with_preset(const uint8_t vault_uuid[VTY_UUID_BYTES],
                                 uint64_t generation)
{
    uint8_t buf[RB_TOTAL_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
    int is_new = 0;
    int changed = 0;
    int idx;
    int rc;
    int current_slot;
    int next_slot;
    int attempt;
    int pool_ok;
    HANDLE lock;
    const uint8_t *e;
    rb_dead_list dead;
    uint32_t cleanup_failed = 0;

    vty_rb_apply_test_disable();
    if (!g_enabled) return VTY_OK;
    if (vault_uuid == NULL) return VTY_E_INVALID;
    if (vty_rb_witness_id(vault_uuid, wid) != VTY_OK) return VTY_E_ROLLBACK;
    if (vty_rollback_init() != VTY_OK) return VTY_E_ROLLBACK;

    for (attempt = 0; attempt < 3; attempt++) {
        current_slot = -1;
        next_slot = -1;
        changed = 0;
        memset(fp, 0, sizeof(fp));
        dead.count = 0;

        lock = vty_rb_lock_state();
        if (lock == NULL) return VTY_E_ROLLBACK;

        rc = vty_rb_load_authenticated(buf, &is_new);
        if (rc != VTY_OK) {
            vty_rb_unlock_state(lock);
            return rc;
        }
        if (vty_rb_dirty_contains(wid)) {
            vty_rb_unlock_state(lock);
            return VTY_E_ROLLBACK;
        }
        RB_CRASH(VTY_RB_CRASH_COMMIT_ENTER);

        idx = vty_rb_find_entry(buf, vault_uuid);
        if (idx < 0) {
            /* 新库首次提交：不允许已有见证密钥（否则状态被删/回滚）。
             * 预置只在首次提交成功后开始（F2）。 */
            if (vty_tpm_witness_any_usable(wid) != 0) {
                vty_rb_unlock_state(lock);
                return VTY_E_ROLLBACK;
            }
            /* 容量预检：只在需要新增条目、且逻辑表已满时回收 DEAD。
             * 回收只修改内存缓冲；只有本次 vty_rb_store 成功后才删除其见证。
             * ACTIVE/TAMPERED/UNKNOWN 一律保留，绝不自动淘汰。 */
            if (vty_get_u32(buf + 8) >= vty_rb_max_entries()) {
                if (vty_rb_collect_dead_locked(buf, &dead) == 0) {
                    vty_rb_unlock_state(lock);
                    return VTY_E_ANCHOR_FULL;
                }
                vty_rb_invalidate_dead_pool_locked(&dead);
            }
            pool_ok = (vty_witness_pool_start() == VTY_OK);
            if (pool_ok) {
                vty_witness_pool_invalidate(wid, 0);
                vty_witness_pool_invalidate(wid, 1);
            }
            rc = vty_rb_rotate_witness(wid, -1, &next_slot, fp);
            if (rc != VTY_OK) {
                vty_rb_unlock_state(lock);
                return rc;
            }
            rc = vty_rb_upsert(buf, vault_uuid, generation, 0, next_slot, fp, &changed);
            if (rc == VTY_E_RESOURCE) {
                (void)vty_tpm_witness_delete(wid, (uint8_t)next_slot);
                vty_rb_unlock_state(lock);
                return VTY_E_ANCHOR_FULL;
            }
            if (rc == VTY_OK) rc = vty_rb_store(buf);
            if (rc != VTY_OK) {
                (void)vty_tpm_witness_delete(wid, (uint8_t)next_slot);
                vty_rb_unlock_state(lock);
                return VTY_E_ROLLBACK;
            }
            rc = vty_rb_retire_witness(wid, -1, next_slot);
            if (rc != VTY_OK) {
                vty_rb_dirty_mark(wid);
                vty_rb_unlock_state(lock);
                vty_rb_delete_dead_witnesses(&dead, &cleanup_failed);
                return rc;
            }
            vty_rb_cache_store(vault_uuid, generation, next_slot, fp);
            if (pool_ok) vty_witness_pool_schedule(wid, next_slot);
            vty_rb_unlock_state(lock);
            vty_rb_delete_dead_witnesses(&dead, &cleanup_failed);
            return VTY_OK;
        }

        e = vty_rb_entry_at(buf, (uint32_t)idx);
        if (vty_rb_entry_witness_valid(e)) {
            current_slot = (int)e[RB_ENTRY_WITNESS_OFFSET];
            if (vty_rb_verify_entry_cached(vault_uuid, wid, e) != VTY_OK) {
                vty_rb_unlock_state(lock);
                return VTY_E_ROLLBACK;
            }
            if (vty_rb_entry_gen(e) == generation) {
                /* 已是最新且见证有效：无需轮换，但预热下一把。 */
                if (vty_witness_pool_start() == VTY_OK) {
                    vty_witness_pool_schedule(wid, current_slot);
                }
                vty_rb_unlock_state(lock);
                return VTY_OK;
            }
        }
        if (generation < vty_rb_entry_gen(e)) {
            vty_rb_unlock_state(lock);
            return VTY_E_ROLLBACK;
        }

        pool_ok = (vty_witness_pool_start() == VTY_OK);

        if (pool_ok && current_slot >= 0) {
            rc = vty_witness_pool_take(wid, current_slot, &next_slot, fp);
            if (rc == VTY_E_POLICY) {
                /* 后台建键进行中：释放状态锁等待（见 5.2），
                 * 随后重新加载并复核 generation。 */
                vty_rb_unlock_state(lock);
                (void)vty_witness_pool_wait_idle(wid, 5000);
                continue;
            }
            if (rc == VTY_OK) {
                RB_CRASH(VTY_RB_CRASH_AFTER_NEW_KEY);
                rc = vty_rb_upsert(buf, vault_uuid, generation, 0, next_slot, fp,
                            &changed);
                if (rc == VTY_OK) rc = vty_rb_store(buf);
                if (rc != VTY_OK) {
                    /* 状态未写：预置键仍未被引用，归还池中。 */
                    vty_witness_pool_return(wid, next_slot, fp);
                    vty_rb_unlock_state(lock);
                    return VTY_E_ROLLBACK;
                }
                RB_CRASH(VTY_RB_CRASH_AFTER_STORE);
                rc = vty_rb_retire_witness(wid, current_slot, next_slot);
                if (rc != VTY_OK) {
                    vty_rb_dirty_mark(wid);
                    vty_rb_unlock_state(lock);
                    return rc;
                }
                RB_CRASH(VTY_RB_CRASH_AFTER_RETIRE);
                vty_rb_cache_store(vault_uuid, generation, next_slot, fp);
                vty_witness_pool_schedule(wid, next_slot);
                vty_rb_unlock_state(lock);
                return VTY_OK;
            }
            /* VTY_E_TPM：无预置或预置键校验失败，走同步回退。 */
        }

        {
            int sync_slot = (current_slot == 0) ? 1 : 0;

            if (pool_ok) vty_witness_pool_invalidate(wid, sync_slot);
            /* 先建新键，再写状态，最后删旧键：写失败时旧状态仍指向旧键，
             * 不会把库永久锁死。 */
            rc = vty_rb_rotate_witness(wid, current_slot, &next_slot, fp);
            if (rc != VTY_OK) {
                vty_rb_unlock_state(lock);
                return rc;
            }
            RB_CRASH(VTY_RB_CRASH_AFTER_NEW_KEY);
            rc = vty_rb_upsert(buf, vault_uuid, generation, 0, next_slot, fp, &changed);
            if (rc == VTY_OK) rc = vty_rb_store(buf);
            if (rc != VTY_OK) {
                (void)vty_tpm_witness_delete(wid, (uint8_t)next_slot);
                vty_rb_unlock_state(lock);
                return VTY_E_ROLLBACK;
            }
            RB_CRASH(VTY_RB_CRASH_AFTER_STORE);
            rc = vty_rb_retire_witness(wid, current_slot, next_slot);
            if (rc != VTY_OK) {
                vty_rb_dirty_mark(wid);
                vty_rb_unlock_state(lock);
                return rc;
            }
            RB_CRASH(VTY_RB_CRASH_AFTER_RETIRE);
            vty_rb_cache_store(vault_uuid, generation, next_slot, fp);
            if (pool_ok) vty_witness_pool_schedule(wid, next_slot);
            vty_rb_unlock_state(lock);
            return VTY_OK;
        }
    }
    /* 连续三轮都被后台建键打断：不绕过锚点，fail-closed。 */
    return VTY_E_ROLLBACK;
}

int vty_rollback_commit(const uint8_t vault_uuid[VTY_UUID_BYTES],
                        uint64_t generation)
{
    return rb_commit_with_preset(vault_uuid, generation);
}

int vty_rollback_reset_anchor(const uint8_t vault_uuid[VTY_UUID_BYTES],
                              uint64_t generation)
{
    uint8_t buf[RB_TOTAL_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    int is_new = 0;
    int changed = 0;
    int idx;
    int rc;
    int current_slot = -1;
    int next_slot = 0;
    int had_witness = 0;
    uint8_t fp[VTY_TPM_WITNESS_FP_BYTES];
    HANDLE lock;
    rb_dead_list dead;
    uint32_t cleanup_failed = 0;

    vty_rb_apply_test_disable();
    if (!g_enabled) return VTY_OK;
    if (vault_uuid == NULL) return VTY_E_INVALID;
    if (vty_rb_witness_id(vault_uuid, wid) != VTY_OK) return VTY_E_ROLLBACK;
    if (vty_rollback_init() != VTY_OK) return VTY_E_ROLLBACK;

    lock = vty_rb_lock_state();
    if (lock == NULL) return VTY_E_ROLLBACK;

    memset(fp, 0, sizeof(fp));
    dead.count = 0;
    rc = vty_rb_load_authenticated(buf, &is_new);
    if (rc != VTY_OK) {
        vty_rb_unlock_state(lock);
        return rc;
    }

    idx = vty_rb_find_entry(buf, vault_uuid);
    if (idx >= 0) {
        const uint8_t *e = vty_rb_entry_at(buf, (uint32_t)idx);
        had_witness = vty_rb_entry_witness_valid(e);
        if (had_witness) {
            current_slot = (int)e[RB_ENTRY_WITNESS_OFFSET];
            /* 恢复码是显式逃生通道：见证缺失（DEAD）或指纹不符
             * （TAMPERED）不得阻断重设。旧见证已无法证明任何东西，
             * 拒绝重设只会让持有恢复码的用户永久失去访问权。 */
            if (vty_tpm_witness_verify(wid, e[RB_ENTRY_WITNESS_OFFSET],
                                       e + RB_ENTRY_FP_OFFSET) != VTY_OK) {
                current_slot = -1;
            }
        }
    } else if (vty_get_u32(buf + 8) >= vty_rb_max_entries()) {
        /* 恢复码新增条目同样受容量约束；先回收可证明失效的 DEAD，
         * 绝不为腾位删除 ACTIVE/TAMPERED/UNKNOWN。 */
        if (vty_rb_collect_dead_locked(buf, &dead) == 0) {
            vty_rb_unlock_state(lock);
            return VTY_E_ANCHOR_FULL;
        }
        vty_rb_invalidate_dead_pool_locked(&dead);
    }

    /* 恢复流程每次重设锚点都轮换见证，使此前所有状态副本失效 */
    /* 同步建键会覆盖目标槽；先作废两个槽的预置登记。 */
    vty_witness_pool_invalidate(wid, 0);
    vty_witness_pool_invalidate(wid, 1);
    rc = vty_rb_rotate_witness(wid, current_slot, &next_slot, fp);
    if (rc != VTY_OK) {
        vty_rb_unlock_state(lock);
        return rc;
    }
    rc = vty_rb_upsert(buf, vault_uuid, generation, 1, next_slot, fp, &changed);
    if (rc == VTY_E_RESOURCE) {
        (void)vty_tpm_witness_delete(wid, (uint8_t)next_slot);
        vty_rb_unlock_state(lock);
        return VTY_E_ANCHOR_FULL;
    }
    if (rc == VTY_OK) rc = vty_rb_store(buf);
    if (rc != VTY_OK) {
        (void)vty_tpm_witness_delete(wid, (uint8_t)next_slot);
        vty_rb_unlock_state(lock);
        return VTY_E_ROLLBACK;
    }
    if (current_slot >= 0) {
        rc = vty_rb_retire_witness(wid, current_slot, next_slot);
        if (rc != VTY_OK) {
            vty_rb_dirty_mark(wid);
            vty_rb_unlock_state(lock);
            vty_rb_delete_dead_witnesses(&dead, &cleanup_failed);
            return rc;
        }
    } else {
        /* 旧槽未知或不可用：状态已指向新槽，非当前槽的残留键按
         * 启动清理同规则处理；失败不阻断恢复，后续 check 会重试。 */
        (void)vty_rb_cleanup_stale_witness(wid, next_slot);
    }
    /* 恢复码是显式逃生通道：重设成功后清除脏标记并更新缓存。 */
    vty_rb_dirty_clear(wid);
    vty_rb_cache_store(vault_uuid, generation, next_slot, fp);
    if (vty_witness_pool_start() == VTY_OK) {
        vty_witness_pool_schedule(wid, next_slot);
    }
    vty_rb_unlock_state(lock);
    vty_rb_delete_dead_witnesses(&dead, &cleanup_failed);
    return VTY_OK;
}


int vty_rollback_anchor_list(VtyAnchorInfo *out, uint32_t capacity,
                             uint32_t *out_count, int *out_state_missing)
{
    uint8_t buf[RB_TOTAL_BYTES];
    rb_probe_entry snap[VTY_ROLLBACK_MAX_ENTRIES];
    uint32_t count;
    uint32_t i;
    int is_new = 0;
    int rc;
    HANDLE lock;

    if (out_count == NULL || out_state_missing == NULL) return VTY_E_INVALID;
    *out_count = 0;
    *out_state_missing = 0;
    if (capacity > 0 && out == NULL) return VTY_E_INVALID;
    vty_rb_apply_test_disable();
    if (!g_enabled) {
        *out_state_missing = 1;
        return VTY_OK;
    }
    if (vty_rollback_init() != VTY_OK) return VTY_E_TPM;

    lock = vty_rb_lock_state();
    if (lock == NULL) return VTY_E_IO;

    rc = vty_rb_load_authenticated(buf, &is_new);
    if (rc != VTY_OK) {
        vty_rb_unlock_state(lock);
        return VTY_E_CORRUPT;
    }
    if (is_new) {
        *out_state_missing = 1;
        vty_rb_unlock_state(lock);
        return VTY_OK;
    }
    count = vty_get_u32(buf + 8);
    if (count > VTY_ROLLBACK_MAX_ENTRIES) {
        vty_rb_unlock_state(lock);
        return VTY_E_CORRUPT;
    }
    *out_count = count;
    if (out == NULL || capacity == 0) {
        vty_rb_unlock_state(lock);
        return VTY_OK;
    }
    if (capacity < count) {
        vty_rb_unlock_state(lock);
        return VTY_E_RESOURCE;
    }

    memset(snap, 0, sizeof(snap));
    for (i = 0; i < count; i++) {
        const uint8_t *e = vty_rb_entry_at(buf, i);

        memcpy(snap[i].uuid, e, VTY_UUID_BYTES);
        snap[i].generation = vty_rb_entry_gen(e);
        snap[i].slot = e[RB_ENTRY_WITNESS_OFFSET];
        memcpy(snap[i].fp, e + RB_ENTRY_FP_OFFSET, VTY_TPM_WITNESS_FP_BYTES);
        memset(&out[i], 0, sizeof(out[i]));
        memcpy(out[i].uuid, snap[i].uuid, VTY_UUID_BYTES);
        out[i].generation = snap[i].generation;
        out[i].state = VTY_ANCHOR_UNKNOWN;
    }
    vty_rb_unlock_state(lock);

    /* 分类在锁外执行：列表是快照，不参与状态推进；释放/回收仍按
     * UUID 在锁内重新校验，因此这里的短暂过期不会造成误删。 */
    for (i = 0; i < count; i++) {
        uint8_t wid[VTY_UUID_BYTES];
        VtyWitnessProbe probe = VTY_WITNESS_PROBE_UNKNOWN;

        if (snap[i].slot >= VTY_TPM_WITNESS_SLOTS ||
            vty_rb_witness_id(snap[i].uuid, wid) != VTY_OK) {
            out[i].state = VTY_ANCHOR_UNKNOWN;
            continue;
        }
        if (vty_tpm_witness_probe(wid, snap[i].slot, snap[i].fp, &probe) != VTY_OK) {
            out[i].state = VTY_ANCHOR_UNKNOWN;
            continue;
        }
        switch (probe) {
        case VTY_WITNESS_PROBE_ACTIVE:   out[i].state = VTY_ANCHOR_ACTIVE; break;
        case VTY_WITNESS_PROBE_MISSING:  out[i].state = VTY_ANCHOR_DEAD; break;
        case VTY_WITNESS_PROBE_TAMPERED: out[i].state = VTY_ANCHOR_TAMPERED; break;
        default:                         out[i].state = VTY_ANCHOR_UNKNOWN; break;
        }
    }
    return VTY_OK;
}

int vty_rollback_anchor_release(const uint8_t vault_uuid[VTY_UUID_BYTES],
                                uint32_t flags, uint32_t *out_released,
                                uint32_t *out_cleanup_failed)
{
    uint8_t buf[RB_TOTAL_BYTES];
    uint8_t wid[VTY_UUID_BYTES];
    int is_new = 0;
    int idx;
    int rc;
    HANDLE lock;

    if (vault_uuid == NULL || out_released == NULL ||
        out_cleanup_failed == NULL) {
        return VTY_E_INVALID;
    }
    if ((flags & VTY_ROLLBACK_ANCHOR_CONFIRM) == 0) return VTY_E_INVALID;
    *out_released = 0;
    *out_cleanup_failed = 0;
    vty_rb_apply_test_disable();
    if (!g_enabled) return VTY_E_POLICY;
    if (vty_rb_witness_id(vault_uuid, wid) != VTY_OK) return VTY_E_INVALID;
    if (vty_rollback_init() != VTY_OK) return VTY_E_TPM;

    lock = vty_rb_lock_state();
    if (lock == NULL) return VTY_E_IO;

    rc = vty_rb_load_authenticated(buf, &is_new);
    if (rc != VTY_OK) {
        vty_rb_unlock_state(lock);
        return VTY_E_CORRUPT;
    }
    if (!is_new) {
        idx = vty_rb_find_entry(buf, vault_uuid);
        if (idx >= 0) {
            uint32_t count = vty_get_u32(buf + 8);

            vty_witness_pool_invalidate(wid, 0);
            vty_witness_pool_invalidate(wid, 1);
            if (idx != (int)count - 1) {
                memmove(vty_rb_entry_at(buf, (uint32_t)idx),
                        vty_rb_entry_at(buf, count - 1u), RB_ENTRY_BYTES);
            }
            memset(vty_rb_entry_at(buf, count - 1u), 0, RB_ENTRY_BYTES);
            vty_put_u32(buf + 8, count - 1u);
            rc = vty_rb_store_state(buf);
            if (rc != VTY_OK) {
                /* 状态未成功落盘：条目仍在，见证不得删除。 */
                vty_rb_unlock_state(lock);
                return VTY_E_IO;
            }
            *out_released = 1;
        }
    }
    if (*out_released == 0) {
        vty_witness_pool_invalidate(wid, 0);
        vty_witness_pool_invalidate(wid, 1);
    }
    vty_rb_unlock_state(lock);

    /* 状态已不再引用该 UUID；两槽见证统一清理。删除失败不影响已完成的
     * 释放，调用方可对同一 UUID 重试释放（幂等）。 */
    {
        int a = vty_tpm_witness_delete(wid, 0);
        int b = vty_tpm_witness_delete(wid, 1);

        *out_cleanup_failed = (a != VTY_OK || b != VTY_OK) ? 1u : 0u;
    }
    return VTY_OK;
}

int vty_rollback_anchor_release_batch(const uint8_t *uuids, uint32_t count,
                                      uint32_t flags,
                                      VtyAnchorReleaseResult *out_results,
                                      uint32_t capacity, uint32_t *out_count)
{
    uint8_t buf[RB_TOTAL_BYTES];
    uint8_t wids[VTY_ROLLBACK_MAX_ENTRIES][VTY_UUID_BYTES];
    uint8_t hit[VTY_ROLLBACK_MAX_ENTRIES];
    uint32_t total = 0;
    uint32_t write = 0;
    uint32_t released_count = 0;
    uint32_t i;
    uint32_t j;
    int is_new = 0;
    int rc;
    HANDLE lock;

    if (uuids == NULL || out_results == NULL || out_count == NULL) {
        return VTY_E_INVALID;
    }
    *out_count = 0;
    if ((flags & VTY_ROLLBACK_ANCHOR_CONFIRM) == 0) return VTY_E_INVALID;
    if (count == 0 || count > VTY_ROLLBACK_MAX_ENTRIES) return VTY_E_INVALID;
    if (capacity < count) return VTY_E_INVALID;

    /* 重复与全零 UUID 在入口一次拒绝：n<=64，O(n^2) 比较，无堆分配。
     * 见证身份同样在入口一次派生，锁外清理不再重复访问设备根。 */
    memset(hit, 0, sizeof(hit));
    for (i = 0; i < count; i++) {
        const uint8_t *u = uuids + (size_t)i * VTY_UUID_BYTES;
        int all_zero = 1;

        for (j = 0; j < VTY_UUID_BYTES; j++) {
            if (u[j] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) return VTY_E_INVALID;
        for (j = 0; j < i; j++) {
            if (memcmp(u, uuids + (size_t)j * VTY_UUID_BYTES,
                       VTY_UUID_BYTES) == 0) {
                return VTY_E_INVALID;
            }
        }
        if (vty_rb_witness_id(u, wids[i]) != VTY_OK) return VTY_E_INVALID;
        memset(&out_results[i], 0, sizeof(out_results[i]));
        memcpy(out_results[i].uuid, u, VTY_UUID_BYTES);
    }

    vty_rb_apply_test_disable();
    if (!g_enabled) return VTY_E_POLICY;
    if (vty_rollback_init() != VTY_OK) return VTY_E_TPM;

    lock = vty_rb_lock_state();
    if (lock == NULL) return VTY_E_IO;

    rc = vty_rb_load_authenticated(buf, &is_new);
    if (rc != VTY_OK) {
        vty_rb_unlock_state(lock);
        return VTY_E_CORRUPT;
    }

    if (!is_new) {
        total = vty_get_u32(buf + 8);
        if (total > VTY_ROLLBACK_MAX_ENTRIES) {
            vty_rb_unlock_state(lock);
            return VTY_E_CORRUPT;
        }
        /* 单次原地压缩：未命中条目写回前部，命中条目丢弃并标记。
         * 请求集合与表条目均不超过 64，比较开销有界。 */
        for (i = 0; i < total; i++) {
            const uint8_t *e = vty_rb_entry_at(buf, i);
            int matched = 0;

            for (j = 0; j < count; j++) {
                if (memcmp(e, uuids + (size_t)j * VTY_UUID_BYTES,
                           VTY_UUID_BYTES) == 0) {
                    hit[j] = 1;
                    matched = 1;
                    break;
                }
            }
            if (matched) {
                released_count++;
                continue;
            }
            if (write != i) {
                memmove(vty_rb_entry_at(buf, write), e, RB_ENTRY_BYTES);
            }
            write++;
        }
        if (released_count > 0) {
            for (i = 0; i < count; i++) {
                if (hit[i] == 0) continue;
                vty_witness_pool_invalidate(wids[i], 0);
                vty_witness_pool_invalidate(wids[i], 1);
            }
            for (i = write; i < total; i++) {
                memset(vty_rb_entry_at(buf, i), 0, RB_ENTRY_BYTES);
            }
            vty_put_u32(buf + 8, write);
            rc = vty_rb_store_state(buf);
            if (rc != VTY_OK) {
                /* 状态未成功落盘：条目与见证均保持原样。 */
                vty_rb_unlock_state(lock);
                return VTY_E_IO;
            }
        }
    }
    vty_rb_unlock_state(lock);

    /* 状态已不再引用任何请求 UUID：锁外逐条清理两槽见证。未命中条目
     * 同样清理，保证“重复释放”幂等。删除失败逐条记账，不影响其它条目。 */
    for (i = 0; i < count; i++) {
        int a;
        int b;

        vty_witness_pool_invalidate(wids[i], 0);
        vty_witness_pool_invalidate(wids[i], 1);
        a = vty_tpm_witness_delete(wids[i], 0);
        b = vty_tpm_witness_delete(wids[i], 1);
        out_results[i].released = hit[i];
        out_results[i].cleanup_failed = (a != VTY_OK || b != VTY_OK) ? 1u : 0u;
    }
    *out_count = count;
    return VTY_OK;
}
