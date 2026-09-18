/*
 * verthys_rekey_auto.c — 自动密钥轮换状态机实现（★ WP-6）
 *
 * 设计依据：
 *   - docs/TARGET_ARCHITECTURE_V5.md §4.3 / §5.1 / §5.3
 *   - docs/V3_UPGRADE_PLAYBOOK.md WP-6（复用 rewrap 的 vsb_txn 保护模式）
 *
 * 轮换流程（单写者纪律，与 change_password 同序）：
 *   守卫（终态/驻留/防震荡）→ 新密钥生成（双副本：wrap 与 import 各
 *   消耗一份，E-5 红线）→ 分区密钥内核态重包装 → 备用槽位分区表帧
 *   落盘（fsync）→ VsbTxnV3 法定人数提交 → 原位句柄切换（借用指针
 *   wal/txn 续期有效）→ 内存态分区表同步。
 *
 * 失败原子性：
 *   - 提交前任何失败：km 句柄零变更，盘面仅可能残留备用槽位孤儿帧
 *     （sb 仍指旧槽位，下次轮换覆写），内存 sb 经 vsb_txn_rollback
 *     完整恢复；
 *   - 提交后句柄切换失败（理论不可达——仅结构拷贝）：盘面已持新
 *     语境，按 change_password 5.3 同语义上抛，下次解锁重建全组。
 */
#include "verthys_rekey_auto.h"
#include "keymanager_cng.h"
#include "verthys_partition.h"
#include "verthys_crypto.h"          /* verthys_random_bytes */
#include "verthys_internal.h"        /* verthys_secure_zero */

#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>               /* GetSystemTimeAsFileTime */

/* ---------- 内部工具 ---------- */

static uint64_t rekey_now_ft(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

static void put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8));
}

static uint64_t get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* ---------- TLV 状态读写 ---------- */

void verthys_rekey_auto_state_get(const VerthysSuperBlockV3 *sb,
                                 VerthysRekeyState *out)
{
    uint32_t off;

    if (out == NULL) return;
    out->last_rekey_ft   = (sb != NULL) ? sb->created_at : 0;
    out->last_rekey_txid = 0;
    out->flags           = 0;
    if (sb == NULL) return;

    off = 0;
    while (off + 2u <= sb->extensions_len) {
        uint8_t tag  = sb->extensions[off];
        uint8_t vlen = sb->extensions[off + 1u];
        if (off + 2u + (uint32_t)vlen > sb->extensions_len) break;
        if (tag == (uint8_t)VERTHYS_V3_TLV_TAG_REKEY &&
            vlen == (uint8_t)VERTHYS_REKEY_TLV_BYTES) {
            const uint8_t *v = sb->extensions + off + 2u;
            out->last_rekey_ft   = get_u64le(v);
            out->last_rekey_txid = get_u64le(v + 8);
            out->flags           = v[16];
            return;
        }
        off += 2u + (uint32_t)vlen;
    }
}

VerthysResult verthys_rekey_auto_state_set(VerthysSuperBlockV3 *sb,
                                       const VerthysRekeyState *st)
{
    uint8_t buf[VERTHYS_V3_EXTENSIONS_MAX];
    uint32_t len = 0;
    uint32_t off;

    if (sb == NULL || st == NULL) return VERTHYS_ERR_INVALID;
    if (sb->extensions_len > sizeof(sb->extensions)) return VERTHYS_ERR_INVALID;

    /* 1. 保留既有非 0x02 TLV（预设等）——前向兼容合并 */
    off = 0;
    while (off + 2u <= sb->extensions_len) {
        uint8_t tag  = sb->extensions[off];
        uint8_t vlen = sb->extensions[off + 1u];
        if (off + 2u + (uint32_t)vlen > sb->extensions_len) {
            return VERTHYS_ERR_FORMAT;   /* 既有区结构非法，拒绝盲写 */
        }
        if (tag != (uint8_t)VERTHYS_V3_TLV_TAG_REKEY) {
            if (len + 2u + (uint32_t)vlen > sizeof(buf)) {
                return VERTHYS_ERR_INVALID;
            }
            memcpy(buf + len, sb->extensions + off, 2u + (size_t)vlen);
            len += 2u + (uint32_t)vlen;
        }
        off += 2u + (uint32_t)vlen;
    }

    /* 2. 追加新 0x02 TLV */
    if (len + 2u + VERTHYS_REKEY_TLV_BYTES > sizeof(buf)) {
        return VERTHYS_ERR_INVALID;
    }
    buf[len++] = (uint8_t)VERTHYS_V3_TLV_TAG_REKEY;
    buf[len++] = (uint8_t)VERTHYS_REKEY_TLV_BYTES;
    put_u64le(buf + len, st->last_rekey_ft);     len += 8;
    put_u64le(buf + len, st->last_rekey_txid);    len += 8;
    buf[len++] = st->flags;

    memcpy(sb->extensions, buf, len);
    sb->extensions_len = len;
    return VERTHYS_OK;
}

/* ---------- 触发评估 ---------- */

uint32_t verthys_rekey_auto_check(const VerthysContextV3 *ctx3)
{
    VerthysRekeyState rs;
    uint64_t now_ft;
    uint64_t interval_ft = (uint64_t)VERTHYS_REKEY_INTERVAL_DAYS *
                           VERTHYS_REKEY_FT_PER_DAY;
    uint32_t triggers = 0;

    if (ctx3 == NULL || !ctx3->subsystems_open) return 0;

    verthys_rekey_auto_state_get(&ctx3->sb, &rs);
    now_ft = rekey_now_ft();

    /* 时间触发（时钟回拨至上次轮换前 → 不触发，仅推迟） */
    if (rs.last_rekey_ft != 0 && now_ft > rs.last_rekey_ft &&
        now_ft - rs.last_rekey_ft >= interval_ft) {
        triggers |= VERTHYS_REKEY_TRIGGER_TIME;
    }

    /* 操作计数触发（写事务 txid 单调增量代理，无符号安全：
     * last_rekey_txid 由轮换时快照，恒 ≤ sb.txid） */
    if (ctx3->sb.txid >= rs.last_rekey_txid + VERTHYS_REKEY_OPS_THRESHOLD) {
        triggers |= VERTHYS_REKEY_TRIGGER_OPS;
    }

    /* DEGRADE 强制（note_degrade 持久化标志） */
    if ((rs.flags & VERTHYS_REKEY_FLAG_FORCE) != 0) {
        triggers |= VERTHYS_REKEY_TRIGGER_DEGRADE;
    }

    return triggers;
}

/* ---------- 终态守卫（change_password 同款） ---------- */

static VerthysResult rekey_txn_terminal_guard(VerthysContextV3 *ctx3)
{
    VerthysTxnV3State st = verthys_txn_v3_state(&ctx3->txn);

    if (st == VERTHYS_TXN_V3_ACTIVE || st == VERTHYS_TXN_V3_PREPARED) {
        return VERTHYS_ERR_INTERNAL;      /* 单调用事务间隙必为终态 */
    }
    if (st == VERTHYS_TXN_V3_COMMITTED) {
        return verthys_txn_v3_confirm(&ctx3->txn);  /* 幂等补收尾 */
    }
    return VERTHYS_OK;
}

/* ---------- 轮换核心 ---------- */

VerthysResult verthys_rekey_auto_rotate(VerthysContextV3 *ctx3, int force,
                                     int *out_rotated)
{
    VerthysResult r;
    VerthysRekeyState rs;
    uint64_t now_ft;
    uint64_t min_ft = (uint64_t)VERTHYS_REKEY_MIN_INTERVAL_HOURS *
                      VERTHYS_REKEY_FT_PER_HOUR;
    VsbTxnV3 sb_txn;
    VerthysCngAead new_a, new_b, new_c;
    uint8_t ka_wrap[VERTHYS_CNG_KEY_BYTES], ka_imp[VERTHYS_CNG_KEY_BYTES];
    uint8_t kb_wrap[VERTHYS_CNG_KEY_BYTES], kb_imp[VERTHYS_CNG_KEY_BYTES];
    uint8_t kc_wrap[VERTHYS_CNG_KEY_BYTES], kc_imp[VERTHYS_CNG_KEY_BYTES];
    uint8_t id_a[VERTHYS_CNG_KEY_ID_BYTES];
    uint8_t id_b[VERTHYS_CNG_KEY_ID_BYTES];
    uint8_t id_c[VERTHYS_CNG_KEY_ID_BYTES];
    uint8_t new_wa[VERTHYS_V3_WRAPPED_KEY_BYTES];
    uint8_t new_wb[VERTHYS_V3_WRAPPED_KEY_BYTES];
    uint8_t new_wc[VERTHYS_V3_WRAPPED_KEY_BYTES];
    uint64_t alt_offset;
    int contexts_live = 0;
    int committed = 0;
    VerthysCngAead *old_key_a;
    VerthysPartitionTable local_pt;
    size_t i;

    if (out_rotated != NULL) *out_rotated = 0;

    if (ctx3 == NULL || !ctx3->subsystems_open) return VERTHYS_ERR_LOCKED;
    if (ctx3->km == NULL || ctx3->f == NULL) return VERTHYS_ERR_INVALID;
    if (verthys_cng_km_state(ctx3->km) != VERTHYS_CNG_KM_KERNEL_RESIDENT) {
        return VERTHYS_ERR_CNG_UNAVAILABLE;
    }

    r = rekey_txn_terminal_guard(ctx3);
    if (r != VERTHYS_OK) return r;

    /* 防震荡：距上次轮换 < 24h 且非强制 → 拒绝（非错误） */
    verthys_rekey_auto_state_get(&ctx3->sb, &rs);
    now_ft = rekey_now_ft();
    if (!force && now_ft >= rs.last_rekey_ft &&
        now_ft - rs.last_rekey_ft < min_ft) {
        return VERTHYS_OK;
    }

    /* 备用槽位（ping-pong：默认 1MB ↔ 2MB，帧容量 ≤ 8 条目 ≈ 1KB，
     * 远小于 1MB 槽距，互不覆盖；槽位均在 [1MB,4MB) 分区表区内） */
    alt_offset = (ctx3->sb.partition_table_offset ==
                  VERTHYS_V3_PARTITION_TABLE_OFFSET)
                  ? VERTHYS_V3_PARTITION_TABLE_OFFSET + UINT64_C(0x100000)
                  : VERTHYS_V3_PARTITION_TABLE_OFFSET;

    /* ---- 1. 新密钥材料（双副本：wrap 与 import 各消耗一份，E-5） ---- */
    verthys_random_bytes(ka_wrap, sizeof(ka_wrap));
    verthys_random_bytes(kb_wrap, sizeof(kb_wrap));
    verthys_random_bytes(kc_wrap, sizeof(kc_wrap));
    memcpy(ka_imp, ka_wrap, sizeof(ka_imp));
    memcpy(kb_imp, kb_wrap, sizeof(kb_imp));
    memcpy(kc_imp, kc_wrap, sizeof(kc_imp));
    verthys_random_bytes(id_a, sizeof(id_a));
    verthys_random_bytes(id_b, sizeof(id_b));
    verthys_random_bytes(id_c, sizeof(id_c));

    r = verthys_cng_aead_init(&new_a);
    if (r != VERTHYS_OK) goto fail_zero;
    r = verthys_cng_aead_init(&new_b);
    if (r != VERTHYS_OK) goto fail_ctx;
    r = verthys_cng_aead_init(&new_c);
    if (r != VERTHYS_OK) goto fail_ctx;
    contexts_live = 1;

    /* 新 wrapped 形态（MEK 语境内核态加密，与解锁 S3 import 互逆） */
    r = verthys_cng_km_wrap_key(ctx3->km, VERTHYS_CNG_KEY_A, ka_wrap,
                              new_wa, (uint32_t)sizeof(new_wa));
    if (r != VERTHYS_OK) goto fail_ctx;
    r = verthys_cng_km_wrap_key(ctx3->km, VERTHYS_CNG_KEY_B, kb_wrap,
                              new_wb, (uint32_t)sizeof(new_wb));
    if (r != VERTHYS_OK) goto fail_ctx;
    r = verthys_cng_km_wrap_key(ctx3->km, VERTHYS_CNG_KEY_C, kc_wrap,
                              new_wc, (uint32_t)sizeof(new_wc));
    if (r != VERTHYS_OK) goto fail_ctx;

    /* 新句柄导入模块本地上下文（km 记账由 rotate_abc 移交时补齐） */
    r = verthys_cng_aead_import_key(&new_a, ka_imp, id_a);
    if (r != VERTHYS_OK) goto fail_ctx;
    r = verthys_cng_aead_import_key(&new_b, kb_imp, id_b);
    if (r != VERTHYS_OK) goto fail_ctx;
    r = verthys_cng_aead_import_key(&new_c, kc_imp, id_c);
    if (r != VERTHYS_OK) goto fail_ctx;

    /* ---- 2. 分区密钥内核态重包装（旧 key_a 解密 → 新 key_a' 加密，
     *          分区密钥明文仅本栈帧瞬态；分区密钥本身不变 → 数据零重写） ---- */
    old_key_a = verthys_cng_km_get(ctx3->km, VERTHYS_CNG_KEY_A);
    if (old_key_a == NULL) {
        r = VERTHYS_ERR_CNG_UNAVAILABLE;
        goto fail_ctx;
    }

    local_pt = ctx3->ptable;   /* 浅拷贝借用句柄（本函数不 destroy） */
    for (i = 0; i < local_pt.count; i++) {
        VerthysPartition *p = &local_pt.entries[i];
        uint8_t pkey[VERTHYS_PARTITION_KEY_BYTES];
        size_t pkey_len = sizeof(pkey);
        size_t nlen = VERTHYS_PARTITION_WRAPPED_BYTES;
        uint8_t nwrapped[VERTHYS_PARTITION_WRAPPED_BYTES];
        uint8_t nnonce[VERTHYS_PARTITION_NONCE_BYTES];

        if (p->wrapped_key_len != VERTHYS_PARTITION_WRAPPED_BYTES) {
            r = VERTHYS_ERR_INTERNAL;
            goto fail_ctx;
        }
        r = verthys_cng_aead_decrypt(old_key_a,
                                   p->wrapped_key, p->wrapped_key_len,
                                   (const uint8_t *)VERTHYS_PARTITION_WRAP_AAD,
                                   strlen(VERTHYS_PARTITION_WRAP_AAD),
                                   p->wrap_nonce,
                                   pkey, &pkey_len);
        if (r != VERTHYS_OK || pkey_len != VERTHYS_PARTITION_KEY_BYTES) {
            verthys_secure_zero(pkey, sizeof(pkey));
            r = (r != VERTHYS_OK) ? r : VERTHYS_ERR_INTERNAL;
            goto fail_ctx;
        }
        r = verthys_cng_aead_encrypt(&new_a,
                                   pkey, pkey_len,
                                   (const uint8_t *)VERTHYS_PARTITION_WRAP_AAD,
                                   strlen(VERTHYS_PARTITION_WRAP_AAD),
                                   nwrapped, &nlen, nnonce);
        verthys_secure_zero(pkey, sizeof(pkey));
        if (r != VERTHYS_OK || nlen != VERTHYS_PARTITION_WRAPPED_BYTES) {
            r = (r != VERTHYS_OK) ? r : VERTHYS_ERR_INTERNAL;
            goto fail_ctx;
        }
        memcpy(p->wrapped_key, nwrapped, sizeof(nwrapped));
        memcpy(p->wrap_nonce, nnonce, sizeof(nnonce));
        /* key_id / offset / aead 句柄 / nonce_counter 沿用现值 */
    }

    /* ---- 3. 新分区表帧落盘（备用槽位 + fsync，崩溃协议前置腿） ---- */
    r = verthys_partition_table_save(ctx3->f, alt_offset, &local_pt, &new_a);
    if (r != VERTHYS_OK) goto fail_ctx;

    /* ---- 4. 超级块法定人数原子提交（vsb_txn 保护，rewrap 模式） ---- */
    r = vsb_txn_v3_begin(&sb_txn, &ctx3->sb);
    if (r != VERTHYS_OK) goto fail_ctx;

    memcpy(ctx3->sb.wrapped_key_a, new_wa, sizeof(new_wa));
    memcpy(ctx3->sb.wrapped_key_b, new_wb, sizeof(new_wb));
    memcpy(ctx3->sb.wrapped_key_c, new_wc, sizeof(new_wc));
    memcpy(ctx3->sb.key_a_id, id_a, sizeof(id_a));
    memcpy(ctx3->sb.key_b_id, id_b, sizeof(id_b));
    memcpy(ctx3->sb.key_c_id, id_c, sizeof(id_c));
    ctx3->sb.partition_table_offset = alt_offset;
    ctx3->sb.updated_at = now_ft;
    {
        VerthysRekeyState st;
        st.last_rekey_ft   = now_ft;
        st.last_rekey_txid = ctx3->sb.txid;
        st.flags           = 0;          /* DEGRADE 标志随轮换兑现清除 */
        r = verthys_rekey_auto_state_set(&ctx3->sb, &st);
        if (r != VERTHYS_OK) {
            (void)vsb_txn_v3_rollback(&sb_txn, &ctx3->sb);
            goto fail_ctx;
        }
    }

    r = vsb_txn_v3_commit(&sb_txn, &ctx3->sb, ctx3->f, ctx3->integrity_key);
    if (r != VERTHYS_OK) {
        (void)vsb_txn_v3_rollback(&sb_txn, &ctx3->sb);
        goto fail_ctx;
    }
    committed = 1;

    /* ---- 5. 原位句柄切换（借用指针 wal/txn 续期有效） ---- */
    r = verthys_cng_km_rotate_abc(ctx3->km, &new_a, &new_b, &new_c);
    if (r != VERTHYS_OK) goto fail_committed;

    /* ---- 6. 内存态分区表同步（后续 table_save 序列化一致） ---- */
    for (i = 0; i < ctx3->ptable.count; i++) {
        memcpy(ctx3->ptable.entries[i].wrapped_key,
               local_pt.entries[i].wrapped_key,
               VERTHYS_PARTITION_WRAPPED_BYTES);
        memcpy(ctx3->ptable.entries[i].wrap_nonce,
               local_pt.entries[i].wrap_nonce,
               VERTHYS_PARTITION_NONCE_BYTES);
        ctx3->ptable.entries[i].wrapped_key_len =
            VERTHYS_PARTITION_WRAPPED_BYTES;
    }

    verthys_secure_zero(ka_wrap, sizeof(ka_wrap));
    verthys_secure_zero(kb_wrap, sizeof(kb_wrap));
    verthys_secure_zero(kc_wrap, sizeof(kc_wrap));
    verthys_secure_zero(ka_imp, sizeof(ka_imp));
    verthys_secure_zero(kb_imp, sizeof(kb_imp));
    verthys_secure_zero(kc_imp, sizeof(kc_imp));
    verthys_secure_zero(id_a, sizeof(id_a));
    verthys_secure_zero(id_b, sizeof(id_b));
    verthys_secure_zero(id_c, sizeof(id_c));
    if (out_rotated != NULL) *out_rotated = 1;
    return VERTHYS_OK;

fail_committed:
    /* 提交后失败：盘面已持新语境（回滚不可行），按 change_password
     * 5.3 同语义上抛；下次解锁按盘面重建全组，无数据影响 */
    verthys_secure_zero(ka_wrap, sizeof(ka_wrap));
    verthys_secure_zero(kb_wrap, sizeof(kb_wrap));
    verthys_secure_zero(kc_wrap, sizeof(kc_wrap));
    verthys_secure_zero(ka_imp, sizeof(ka_imp));
    verthys_secure_zero(kb_imp, sizeof(kb_imp));
    verthys_secure_zero(kc_imp, sizeof(kc_imp));
    verthys_secure_zero(id_a, sizeof(id_a));
    verthys_secure_zero(id_b, sizeof(id_b));
    verthys_secure_zero(id_c, sizeof(id_c));
    return r;

fail_ctx:
    if (contexts_live) {
        verthys_cng_aead_destroy(&new_a);
        verthys_cng_aead_destroy(&new_b);
        verthys_cng_aead_destroy(&new_c);
    }
fail_zero:
    verthys_secure_zero(ka_wrap, sizeof(ka_wrap));
    verthys_secure_zero(kb_wrap, sizeof(kb_wrap));
    verthys_secure_zero(kc_wrap, sizeof(kc_wrap));
    verthys_secure_zero(ka_imp, sizeof(ka_imp));
    verthys_secure_zero(kb_imp, sizeof(kb_imp));
    verthys_secure_zero(kc_imp, sizeof(kc_imp));
    verthys_secure_zero(id_a, sizeof(id_a));
    verthys_secure_zero(id_b, sizeof(id_b));
    verthys_secure_zero(id_c, sizeof(id_c));
    return r;
}

/* ---------- 编排 / DEGRADE 标志 ---------- */

VerthysResult verthys_rekey_auto_maybe_rotate(VerthysContextV3 *ctx3,
                                           int *out_rotated)
{
    uint32_t triggers;

    if (out_rotated != NULL) *out_rotated = 0;
    if (ctx3 == NULL) return VERTHYS_ERR_INVALID;

    triggers = verthys_rekey_auto_check(ctx3);
    if (triggers == VERTHYS_REKEY_TRIGGER_NONE) return VERTHYS_OK;

    return verthys_rekey_auto_rotate(
        ctx3, (triggers & VERTHYS_REKEY_TRIGGER_DEGRADE) != 0, out_rotated);
}

VerthysResult verthys_rekey_auto_note_degrade(VerthysContextV3 *ctx3)
{
    VerthysResult r;
    VerthysRekeyState rs;
    VsbTxnV3 sb_txn;

    if (ctx3 == NULL || !ctx3->subsystems_open) return VERTHYS_ERR_LOCKED;
    if (ctx3->km == NULL || ctx3->f == NULL) return VERTHYS_ERR_INVALID;
    if (verthys_cng_km_state(ctx3->km) != VERTHYS_CNG_KM_KERNEL_RESIDENT) {
        return VERTHYS_ERR_CNG_UNAVAILABLE;
    }

    r = rekey_txn_terminal_guard(ctx3);
    if (r != VERTHYS_OK) return r;

    verthys_rekey_auto_state_get(&ctx3->sb, &rs);
    rs.flags |= VERTHYS_REKEY_FLAG_FORCE;

    r = vsb_txn_v3_begin(&sb_txn, &ctx3->sb);
    if (r != VERTHYS_OK) return r;

    r = verthys_rekey_auto_state_set(&ctx3->sb, &rs);
    if (r != VERTHYS_OK) {
        (void)vsb_txn_v3_rollback(&sb_txn, &ctx3->sb);
        return r;
    }

    r = vsb_txn_v3_commit(&sb_txn, &ctx3->sb, ctx3->f, ctx3->integrity_key);
    if (r != VERTHYS_OK) {
        (void)vsb_txn_v3_rollback(&sb_txn, &ctx3->sb);
    }
    return r;
}
