/*
 * vty_rollback_witness.c — 见证键轮换、退役与进程内验证缓存
 *
 * 负责见证槽的建立/退役/清理、DEAD 条目回收、已验证条目缓存与锚点
 * 脏标记；状态写入与锁顺序由调用方在持锁路径内组织。
 */
#include "vty_rollback_internal.h"

#include <string.h>

#include "vty_witness_pool.h"

/* 在已加载、已认证的状态缓冲内压缩 DEAD 条目。
 *
 * 只把“引用槽确定不存在（exists==0）”的条目移出；滚动查询返回 -1、
 * 条目字段非法、或键存在但指纹不符（TAMPERED）一律保留。函数只修改
 * 内存缓冲，不写盘、不删键；调用方必须在成功 vty_rb_store 后才清理见证，
 * 从而保证“状态未落盘时绝不删除任何真实锚点”。 */
uint32_t vty_rb_collect_dead_locked(uint8_t buf[RB_TOTAL_BYTES],
                                    rb_dead_list *dead)
{
    uint32_t count = vty_get_u32(buf + 8);
    uint32_t keep = 0;
    uint32_t i;

    dead->count = 0;
    for (i = 0; i < count; i++) {
        uint8_t *e = vty_rb_entry_at(buf, i);
        int is_dead = 0;

        if (vty_rb_entry_witness_valid(e)) {
            uint8_t wid[VTY_UUID_BYTES];

            if (vty_rb_witness_id(e, wid) == VTY_OK &&
                vty_tpm_witness_exists(wid,
                                       e[RB_ENTRY_WITNESS_OFFSET]) == 0) {
                is_dead = 1;
            }
        }
        if (is_dead) {
            if (dead->count < VTY_ROLLBACK_MAX_ENTRIES) {
                memcpy(dead->uuids[dead->count], e, VTY_UUID_BYTES);
                dead->count++;
            }
        } else {
            if (keep != i) {
                memmove(vty_rb_entry_at(buf, keep), e, RB_ENTRY_BYTES);
            }
            keep++;
        }
    }
    if (dead->count > 0) {
        vty_put_u32(buf + 8, keep);
        memset(vty_rb_entry_at(buf, keep), 0,
               (size_t)(count - keep) * RB_ENTRY_BYTES);
    }
    return dead->count;
}

/* 持状态锁作废预置池登记：池线程建键前必须取同一把状态锁，因此在
 * 锁内作废后不可能再为这些 UUID 生成新键。 */
void vty_rb_invalidate_dead_pool_locked(const rb_dead_list *dead)
{
    uint32_t i;

    for (i = 0; i < dead->count; i++) {
        uint8_t wid[VTY_UUID_BYTES];

        if (vty_rb_witness_id(dead->uuids[i], wid) != VTY_OK) continue;
        vty_witness_pool_invalidate(wid, 0);
        vty_witness_pool_invalidate(wid, 1);
    }
}

/* 解锁后执行：删除 DEAD 条目的两槽残留键。失败计数返回给调用方审计，
 * 不影响已经成功的状态压缩。 */
void vty_rb_delete_dead_witnesses(const rb_dead_list *dead,
                                  uint32_t *out_failed)
{
    uint32_t i;

    *out_failed = 0;
    for (i = 0; i < dead->count; i++) {
        uint8_t wid[VTY_UUID_BYTES];
        int a;
        int b;

        if (vty_rb_witness_id(dead->uuids[i], wid) != VTY_OK) {
            (*out_failed)++;
            continue;
        }
        vty_witness_pool_invalidate(wid, 0);
        vty_witness_pool_invalidate(wid, 1);
        a = vty_tpm_witness_delete(wid, 0);
        b = vty_tpm_witness_delete(wid, 1);
        if (a != VTY_OK || b != VTY_OK) (*out_failed)++;
    }
}

int vty_rb_rotate_witness(const uint8_t wid[VTY_UUID_BYTES], int current_slot,
                          int *next_slot,
                          uint8_t fp[VTY_TPM_WITNESS_FP_BYTES])
{
    int next = (current_slot == 0) ? 1 : 0;

    if (vty_tpm_witness_create(wid, (uint8_t)next, fp) != VTY_OK) {
        return VTY_E_ROLLBACK;
    }
    *next_slot = next;
    return VTY_OK;
}

/* ------------------------------------------------------------------ *
 * 提交快路径：预置见证键、已验证条目缓存、旧键撤销与 fail-closed。
 *
 * 所有提交共用此路径；缓存只在状态 MAC 校验通过后生效，命中缓存
 * 不跳过状态文件校验，旧状态回放不会命中旧缓存。
 * ------------------------------------------------------------------ */

static int cache_match(const uint8_t uuid[VTY_UUID_BYTES],
                       const uint8_t *e)
{
    int i;

    for (i = 0; i < RB_G0A_VERIFIED_MAX; i++) {
        if (g_verified[i].valid &&
            vty_ct_equal(g_verified[i].uuid, uuid, VTY_UUID_BYTES) == 0 &&
            g_verified[i].generation == vty_rb_entry_gen(e) &&
            g_verified[i].slot == e[RB_ENTRY_WITNESS_OFFSET] &&
            vty_ct_equal(g_verified[i].fp, e + RB_ENTRY_FP_OFFSET,
                         VTY_TPM_WITNESS_FP_BYTES) == 0) {
            return 1;
        }
    }
    return 0;
}

void vty_rb_cache_store(const uint8_t uuid[VTY_UUID_BYTES], uint64_t generation,
                        int slot,
                        const uint8_t fp[VTY_TPM_WITNESS_FP_BYTES])
{
    int i;
    int idx = -1;
    int free_idx = -1;

    /* 每个库只保留最新一条：若保留历史条目，回放旧状态会命中旧缓存，
     * 从而绕过指纹校验（旧键可能残留或已被撤销键占位）。 */
    for (i = 0; i < RB_G0A_VERIFIED_MAX; i++) {
        if (g_verified[i].valid &&
            vty_ct_equal(g_verified[i].uuid, uuid, VTY_UUID_BYTES) == 0) {
            idx = i;
            break;
        }
        if (!g_verified[i].valid && free_idx < 0) free_idx = i;
    }
    if (idx < 0) idx = (free_idx >= 0) ? free_idx : 0;
    memset(&g_verified[idx], 0, sizeof(g_verified[idx]));
    g_verified[idx].valid = 1;
    memcpy(g_verified[idx].uuid, uuid, VTY_UUID_BYTES);
    g_verified[idx].generation = generation;
    g_verified[idx].slot = (uint8_t)slot;
    memcpy(g_verified[idx].fp, fp, VTY_TPM_WITNESS_FP_BYTES);
}

void vty_rb_cache_clear(void)
{
    vty_secure_zero(g_verified, sizeof(g_verified));
}

/* 缓存命中时仍探测键是否存在并复核公钥指纹：TPM 被清除后必须维持
 * fail-closed；键被同槽覆盖为不同公钥时也必须识别为 TAMPERED，不能
 * 因为进程内缓存把缺失或替换的当前见证“补”回来。 */
int vty_rb_verify_entry_cached(const uint8_t uuid[VTY_UUID_BYTES],
                               const uint8_t wid[VTY_UUID_BYTES],
                               const uint8_t *e)
{
    int slot = (int)e[RB_ENTRY_WITNESS_OFFSET];

    if (cache_match(uuid, e)) {
        if (vty_tpm_witness_exists(wid, (uint8_t)slot) != 1) {
            return VTY_E_ROLLBACK;
        }
        if (vty_tpm_witness_verify(wid, (uint8_t)slot,
                                   e + RB_ENTRY_FP_OFFSET) != VTY_OK) {
            return VTY_E_ROLLBACK;
        }
        return VTY_OK;
    }
    if (vty_tpm_witness_verify(wid, (uint8_t)slot,
                               e + RB_ENTRY_FP_OFFSET) != VTY_OK) {
        return VTY_E_ROLLBACK;
    }
    vty_rb_cache_store(uuid, vty_rb_entry_gen(e), slot, e + RB_ENTRY_FP_OFFSET);
    return VTY_OK;
}

int vty_rb_dirty_contains(const uint8_t wid[VTY_UUID_BYTES])
{
    int i;

    for (i = 0; i < RB_G0A_DIRTY_MAX; i++) {
        if (g_dirty_used[i] &&
            vty_ct_equal(g_dirty[i], wid, VTY_UUID_BYTES) == 0) {
            return 1;
        }
    }
    return 0;
}

void vty_rb_dirty_mark(const uint8_t wid[VTY_UUID_BYTES])
{
    int i;
    int free_idx = -1;

    for (i = 0; i < RB_G0A_DIRTY_MAX; i++) {
        if (g_dirty_used[i] &&
            vty_ct_equal(g_dirty[i], wid, VTY_UUID_BYTES) == 0) {
            return;
        }
        if (!g_dirty_used[i] && free_idx < 0) free_idx = i;
    }
    if (free_idx >= 0) {
        memcpy(g_dirty[free_idx], wid, VTY_UUID_BYTES);
        g_dirty_used[free_idx] = 1;
    }
    /* 表满时无法记录：本次提交仍已失败，后续提交会重新探测删除/撤销。 */
}

void vty_rb_dirty_clear(const uint8_t wid[VTY_UUID_BYTES])
{
    int i;

    for (i = 0; i < RB_G0A_DIRTY_MAX; i++) {
        if (g_dirty_used[i] &&
            vty_ct_equal(g_dirty[i], wid, VTY_UUID_BYTES) == 0) {
            vty_secure_zero(g_dirty[i], VTY_UUID_BYTES);
            g_dirty_used[i] = 0;
        }
    }
}

/* 提交成功后使旧键不可再作为有效见证：删除失败时用 OVERWRITE 撤销；
 * 两者都失败返回错误，由调用方标记锚点脏并 fail-closed。 */
int vty_rb_retire_witness(const uint8_t wid[VTY_UUID_BYTES], int old_slot,
                          int new_slot)
{
    uint8_t junk[VTY_TPM_WITNESS_FP_BYTES];

    if (old_slot < 0 || old_slot == new_slot) return VTY_OK;
    if (vty_tpm_witness_delete(wid, (uint8_t)old_slot) == VTY_OK) {
        return VTY_OK;
    }
    memset(junk, 0, sizeof(junk));
    if (vty_tpm_witness_create(wid, (uint8_t)old_slot, junk) != VTY_OK) {
        vty_secure_zero(junk, sizeof(junk));
        return VTY_E_TPM;
    }
    /* 撤销键未被引用；删除失败会留下孤儿，由下次启动清理。 */
    (void)vty_tpm_witness_delete(wid, (uint8_t)old_slot);
    vty_secure_zero(junk, sizeof(junk));
    return VTY_OK;
}

/* 启动/解锁清理：当前状态引用一个槽，另一个槽的键一律不得保留
 * （可能是崩溃前的旧键，也可能是本进程的预置键；删除两者都安全）。 */
int vty_rb_cleanup_stale_witness(const uint8_t wid[VTY_UUID_BYTES],
                                 int current_slot)
{
    int other = 1 - current_slot;
    uint8_t junk[VTY_TPM_WITNESS_FP_BYTES];

    vty_witness_pool_invalidate(wid, other);
    if (vty_tpm_witness_delete(wid, (uint8_t)other) == VTY_OK) {
        return VTY_OK;
    }
    memset(junk, 0, sizeof(junk));
    if (vty_tpm_witness_create(wid, (uint8_t)other, junk) == VTY_OK) {
        (void)vty_tpm_witness_delete(wid, (uint8_t)other);
        vty_secure_zero(junk, sizeof(junk));
        return VTY_OK;
    }
    vty_secure_zero(junk, sizeof(junk));
    return VTY_E_TPM;
}
