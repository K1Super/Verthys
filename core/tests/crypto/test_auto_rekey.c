/*
 * test_auto_rekey.c — 自动密钥轮换验收（触发 / 防震荡 / 崩溃一致性）
 *
 * 验收标准全覆盖：
 *   1. 三种触发：
 *      a. TIME  —— 距上次轮换 ≥ 90 天（白盒 TLV 注入，时钟回拨仅推迟）；
 *      b. OPS   —— 写事务增量 ≥ 10,000（txid 单调计数代理，边界 9999/10000）；
 *      c. DEGRADE —— 强制标志持久化（note_degrade 落盘 → 下次解锁兑现）。
 *   2. 防震荡：轮换后 24h 内 force=0 拒绝（非错误，rotated=0）；
 *      force=1（DEGRADE/手动）旁路。
 *   3. 轮换中途崩溃一致性（ping-pong 槽位协议两窗口）：
 *      a. 提交前崩溃（新分区表帧已落备用槽、超级块未提交）——孤儿帧
 *         无害：解锁仍走旧槽位旧密钥，数据完整；后续真实轮换覆写孤儿；
 *      b. 提交后崩溃（法定人数已持久、句柄切换在内存）——重开走新
 *         槽位新密钥闭环，数据完整、TLV 轮换状态持久化。
 *
 * 白盒纪律：触发条件与 TLV 状态经 verthys_rekey_auto_state_get/set
 * 注入（测试专用白盒入口）；轮换本体走真实 verthys_rekey_auto_rotate /
 * maybe_rotate / note_degrade 全链路（含 vsb_txn 法定人数提交与
 * verthys_cng_km_rotate_abc 原位句柄切换）。
 *
 * 借用句柄续期验证（原子指针切换句柄）：轮换后同会话 AddRecord
 * 成功——wal/txn 借用的 VerthysCngAead 指针（&km->keys[role]）经原位
 * 替换后指向新句柄，零重接线。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "verthys_internal.h"          /* VerthysContext / VerthysState */
#include "verthys_v3_lifecycle.h"       /* VerthysContextV3 / preset TLV */
#include "verthys_rekey_auto.h"         /* 被测模块 */
#include "verthys_container_v3.h"       /* VERTHYS_V3_PARTITION_TABLE_OFFSET */
#include "keymanager_cng.h"           /* verthys_cng_km_get / handle_count */
#include "verthys_partition.h"          /* verthys_partition_table_save */

#include <string.h>
#include <stdio.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>                 /* GetSystemTimeAsFileTime */

#define AREKEY_VERTHYS  "test_rekey.verthys"
#define AREKEY_CACHE  "test_rekey.verthys.idx_cache"
#define AREKEY_PW     "rekey-pass"
#define AREKEY_PW_LEN 10

/* FILETIME 100ns 单位：10 分钟（时间戳邻近性判定裕量） */
#define AREKEY_FT_10MIN  UINT64_C(6000000000)

/* 备用槽位（ping-pong 另一侧；与 verthys_rekey_auto.c 同式推导） */
#define AREKEY_ALT_OFFSET(off) \
    (((off) == VERTHYS_V3_PARTITION_TABLE_OFFSET) \
      ? (VERTHYS_V3_PARTITION_TABLE_OFFSET + UINT64_C(0x100000)) \
      : VERTHYS_V3_PARTITION_TABLE_OFFSET)

static void arekey_cleanup(void)
{
    remove(AREKEY_VERTHYS);
    remove(AREKEY_CACHE);
}

static uint64_t arekey_now_ft(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

/*
 * 崩溃模拟（同 test_v3_lifecycle.c 语义）：中止式拆除 V3 上下文——
 * 盘面 WAL / 分区表帧 / 超级块半写现场原样保留，等价进程死亡。
 */
static void arekey_crash_abort(struct VerthysContext *ctx)
{
    VerthysContextV3 *v3 = ctx->v3;
    FILE *f = v3->f;

    ctx->v3 = NULL;
    ctx->state = VERTHYS_STATE_LOCKED;
    verthys_v3_ctx_destroy(v3);    /* 中止式：盘面现场保留 */
    if (f != NULL) fclose(f);
}

/*
 * 造一个已锁定的 V3 容器（1 条记录 "data-0"，PERFORMANCE 预设——
 * 固定 Argon2id 参数，测试时延可控）。返回 0 成功。
 */
static int arekey_make_locked(const char *path, uint64_t *out_id)
{
    VerthysHandle h;
    VerthysRecord r = {VERTHYS_RECORD_ACCOUNT, "rec-0", 5,
                     (const uint8_t *)"data-0", 6};

    arekey_cleanup();
    if (Verthys_Init(&h) != VERTHYS_OK) return -1;
    if (Verthys_CreateWithPreset(h, path, AREKEY_PW, AREKEY_PW_LEN,
                               VERTHYS_PRESET_PERFORMANCE) != VERTHYS_OK) {
        Verthys_Deinit(h);
        return -1;
    }
    if (Verthys_AddRecord(h, &r, out_id) != VERTHYS_OK || *out_id == 0) {
        Verthys_Deinit(h);
        return -1;
    }
    if (Verthys_Lock(h) != VERTHYS_OK) {
        Verthys_Deinit(h);
        return -1;
    }
    Verthys_Deinit(h);
    return 0;
}

/* ================== 1. 触发条件矩阵（TLV 白盒） ================== */

/*
 * 缺省态 / TIME / OPS（9999 边界拒绝 + 10000 触发）/ DEGRADE /
 * 时钟回拨推迟语义 / TLV 与预设共存（tag 0x01 不被 0x02 覆写）。
 */
TEST(arekey_trigger_matrix)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRekeyState st;
    uint64_t id = 0;
    uint64_t now = arekey_now_ft();
    VerthysPreset preset = VERTHYS_PRESET_BALANCED;

    CHECK_EQ(arekey_make_locked(AREKEY_VERTHYS, &id), 0);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open == 1);

    /* --- 缺省态：无 TLV → 不触发；缺省值 = created_at / 0 / 0 --- */
    CHECK_EQ(verthys_rekey_auto_check(v3), 0u);
    verthys_rekey_auto_state_get(&v3->sb, &st);
    CHECK_EQ(st.last_rekey_ft, v3->sb.created_at);
    CHECK_EQ(st.last_rekey_txid, 0u);
    CHECK_EQ(st.flags, 0u);

    /* --- TIME：91 天前轮换 → 触发；1 天前 → 不触发 --- */
    st.last_rekey_ft   = now - 91ULL * VERTHYS_REKEY_FT_PER_DAY;
    st.last_rekey_txid = v3->sb.txid;
    st.flags           = 0;
    CHECK_EQ(verthys_rekey_auto_state_set(&v3->sb, &st), VERTHYS_OK);
    CHECK_EQ(verthys_rekey_auto_check(v3), VERTHYS_REKEY_TRIGGER_TIME);
    st.last_rekey_ft = now - VERTHYS_REKEY_FT_PER_DAY;
    CHECK_EQ(verthys_rekey_auto_state_set(&v3->sb, &st), VERTHYS_OK);
    CHECK_EQ(verthys_rekey_auto_check(v3), 0u);

    /* --- 时钟回拨（last 在未来）→ 无符号保护，TIME 仅推迟 --- */
    st.last_rekey_ft = now + VERTHYS_REKEY_FT_PER_DAY;
    CHECK_EQ(verthys_rekey_auto_state_set(&v3->sb, &st), VERTHYS_OK);
    CHECK_EQ(verthys_rekey_auto_check(v3), 0u);

    /* --- OPS：txid 增量 9999 → 不触发；10000 → 触发 --- */
    st.last_rekey_ft   = now - VERTHYS_REKEY_FT_PER_DAY;
    st.last_rekey_txid = 0;
    CHECK_EQ(verthys_rekey_auto_state_set(&v3->sb, &st), VERTHYS_OK);
    v3->sb.txid = 9999;
    CHECK_EQ(verthys_rekey_auto_check(v3), 0u);
    v3->sb.txid = 10000;
    CHECK_EQ(verthys_rekey_auto_check(v3), VERTHYS_REKEY_TRIGGER_OPS);

    /* --- DEGRADE：强制标志 → 触发（旁路防震荡） --- */
    st.last_rekey_ft   = now;           /* 刚轮换过：防震荡窗口内 */
    st.last_rekey_txid = 10000;
    st.flags           = VERTHYS_REKEY_FLAG_FORCE;
    CHECK_EQ(verthys_rekey_auto_state_set(&v3->sb, &st), VERTHYS_OK);
    CHECK_EQ(verthys_rekey_auto_check(v3), VERTHYS_REKEY_TRIGGER_DEGRADE);

    /* --- TLV 共存：rekey 注入后预设（tag 0x01）不丢失 --- */
    CHECK_EQ(verthys_v3_preset_decode(v3->sb.extensions,
                                    v3->sb.extensions_len, &preset), VERTHYS_OK);
    CHECK_EQ(preset, VERTHYS_PRESET_PERFORMANCE);

    /* --- 未解锁 / NULL 上下文 → NONE（守卫） --- */
    CHECK_EQ(verthys_rekey_auto_check(NULL), 0u);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);
    arekey_cleanup();
    return 0;
}

/* ================== 2. 轮换全闭环 + 防震荡 + 借用句柄续期 ================== */

/*
 * OPS 触发 → maybe_rotate 真实轮换（槽位翻转 / 密钥 ID 与 wrapped 形态
 * 更新 / TLV 快照 / 句柄计数不变）→ 同会话数据可读 + 新写入成功
 * （wal/txn 借用句柄原位续期）→ 防震荡拒绝 → force 旁路 → 锁定重开
 * 走新密钥语境闭环。
 */
TEST(arekey_rotate_full_cycle)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRekeyState st;
    VerthysRecord out;
    VerthysRecord nr = {VERTHYS_RECORD_ACCOUNT, "post-rot", 8,
                      (const uint8_t *)"after-rotate", 12};
    uint64_t id = 0, nid = 0;
    uint64_t now = arekey_now_ft();
    uint64_t old_offset;
    uint8_t old_key_id[VERTHYS_V3_KEY_ID_BYTES];
    uint8_t old_wa[VERTHYS_V3_WRAPPED_KEY_BYTES];
    int rotated = 0;
    int km_handles;

    CHECK_EQ(arekey_make_locked(AREKEY_VERTHYS, &id), 0);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open == 1);

    old_offset = v3->sb.partition_table_offset;
    CHECK_EQ(old_offset, VERTHYS_V3_PARTITION_TABLE_OFFSET);   /* 创建缺省 1MB */
    memcpy(old_key_id, v3->sb.key_a_id, sizeof(old_key_id));
    memcpy(old_wa, v3->sb.wrapped_key_a, sizeof(old_wa));
    km_handles = verthys_cng_km_handle_count(v3->km);

    /* 注入 OPS 触发条件（48h 前轮换 → 防震荡放行；txid 增量达标） */
    st.last_rekey_ft   = now - 2ULL * VERTHYS_REKEY_FT_PER_DAY;
    st.last_rekey_txid = 0;
    st.flags           = 0;
    CHECK_EQ(verthys_rekey_auto_state_set(&v3->sb, &st), VERTHYS_OK);
    v3->sb.txid = 10000;
    CHECK_EQ(verthys_rekey_auto_check(v3), VERTHYS_REKEY_TRIGGER_OPS);

    /* 轮换（maybe 编排：OPS → force=0，防震荡 48h > 24h 放行） */
    CHECK_EQ(verthys_rekey_auto_maybe_rotate(v3, &rotated), VERTHYS_OK);
    CHECK_EQ(rotated, 1);

    /* 槽位 ping-pong 翻转 + 密钥形态更新 + TLV 快照 */
    CHECK_EQ(v3->sb.partition_table_offset,
             (uint64_t)AREKEY_ALT_OFFSET(old_offset));
    CHECK(memcmp(v3->sb.key_a_id, old_key_id, sizeof(old_key_id)) != 0);
    CHECK(memcmp(v3->sb.wrapped_key_a, old_wa, sizeof(old_wa)) != 0);
    verthys_rekey_auto_state_get(&v3->sb, &st);
    CHECK_EQ(st.last_rekey_txid, 10000u);   /* 轮换时 txid 快照 */
    CHECK_EQ(st.flags, 0u);                /* DEGRADE 标志随兑现清除 */
    CHECK(st.last_rekey_ft >= now);        /* 轮换时间戳 = 本测试窗口内 */
    CHECK(v3->sb.updated_at >= now);

    /* km 原位切换：计数/状态不变（MEK + A/B/C = 4，KERNEL_RESIDENT） */
    CHECK_EQ(verthys_cng_km_handle_count(v3->km), km_handles);
    CHECK(verthys_cng_km_state(v3->km) == VERTHYS_CNG_KM_KERNEL_RESIDENT);

    /* 触发条件复位（快照后无增量 → 不再触发） */
    CHECK_EQ(verthys_rekey_auto_check(v3), 0u);

    /* 同会话数据可读（运行态零扰动） */
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);

    /* 借用句柄续期：轮换后新写入（WAL=key_c / 索引=key_b 新句柄）成功 */
    CHECK_EQ(Verthys_AddRecord(h, &nr, &nid), VERTHYS_OK);
    CHECK_EQ(nid, id + 1);

    /* --- 防震荡：24h 内 force=0 拒绝（非错误） --- */
    CHECK_EQ(verthys_rekey_auto_rotate(v3, 0, &rotated), VERTHYS_OK);
    CHECK_EQ(rotated, 0);
    CHECK_EQ(v3->sb.partition_table_offset,
             (uint64_t)AREKEY_ALT_OFFSET(old_offset));  /* 状态零变更 */

    /* --- force=1 旁路（DEGRADE/手动场景）→ 二次轮换回原槽 --- */
    CHECK_EQ(verthys_rekey_auto_rotate(v3, 1, &rotated), VERTHYS_OK);
    CHECK_EQ(rotated, 1);
    CHECK_EQ(v3->sb.partition_table_offset, old_offset);
    CHECK(memcmp(v3->sb.key_a_id, old_key_id, sizeof(old_key_id)) != 0);

    /* 锁定 → 重开：盘面新语境（wrapped + 槽位 + TLV）闭环 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK_EQ(v3->sb.partition_table_offset, old_offset);  /* 二次轮换落盘值 */
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);
    CHECK_EQ(Verthys_GetRecord(h, nid, &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "after-rotate", 12) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);
    arekey_cleanup();
    return 0;
}

/* ================== 3. DEGRADE 端到端（标志持久化 → 解锁兑现） ================== */

/*
 * note_degrade（标志落盘）→ Lock → 重开：Unlock 内部接线自动强制轮换
 * （force 旁路防震荡）→ 标志清除 + 槽位翻转 + 数据完整。
 */
TEST(arekey_degrade_force_persist)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRekeyState st;
    VerthysRecord out;
    uint64_t id = 0;
    uint64_t t_before = arekey_now_ft();

    CHECK_EQ(arekey_make_locked(AREKEY_VERTHYS, &id), 0);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open == 1);

    /* DEGRADE 标志持久化（内存态 + 法定人数落盘） */
    CHECK_EQ(verthys_rekey_auto_note_degrade(v3), VERTHYS_OK);
    verthys_rekey_auto_state_get(&v3->sb, &st);
    CHECK_EQ(st.flags & VERTHYS_REKEY_FLAG_FORCE, VERTHYS_REKEY_FLAG_FORCE);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);

    /* 重开：open_existing 接线在解锁成功后兑现强制轮换 */
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open == 1);

    verthys_rekey_auto_state_get(&v3->sb, &st);
    CHECK_EQ(st.flags, 0u);                       /* 兑现即清除 */
    CHECK(st.last_rekey_ft >= t_before);          /* 本次解锁内轮换 */
    CHECK_EQ(v3->sb.partition_table_offset,
             (uint64_t)AREKEY_ALT_OFFSET(VERTHYS_V3_PARTITION_TABLE_OFFSET));
    CHECK_EQ(verthys_rekey_auto_check(v3), 0u);     /* 不再触发 */

    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);
    arekey_cleanup();
    return 0;
}

/* ================== 4. 崩溃窗口 a：提交前（孤儿帧无害） ================== */

/*
 * ping-pong 前置腿崩溃模拟：新分区表帧已落备用槽、超级块未提交
 * （等价 rotate 在 table_save 之后、vsb commit 之前断电）。
 * 重开走旧槽位旧密钥 → 孤儿帧无害；后续真实轮换覆写孤儿槽位。
 */
TEST(arekey_crash_orphan_frame)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysCngAead *ka;
    VerthysRecord out;
    uint64_t id = 0;
    uint64_t alt;
    int rotated = 0;

    CHECK_EQ(arekey_make_locked(AREKEY_VERTHYS, &id), 0);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open == 1);

    /* 复刻崩溃现场：新帧写备用槽（sb 未提交——仍指 1MB 旧槽） */
    alt = AREKEY_ALT_OFFSET(v3->sb.partition_table_offset);
    ka = verthys_cng_km_get(v3->km, VERTHYS_CNG_KEY_A);
    CHECK(ka != NULL);
    CHECK_EQ(verthys_partition_table_save(v3->f, alt, &v3->ptable, ka),
             VERTHYS_OK);

    arekey_crash_abort(ctx);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);

    /* 重开：sb（旧值）指 1MB 旧槽 + 旧 wrapped 密钥 → 解锁闭环 */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);

    /* 后续真实轮换：覆写孤儿槽位（协议自愈） */
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK_EQ(verthys_rekey_auto_rotate(v3, 1, &rotated), VERTHYS_OK);
    CHECK_EQ(rotated, 1);
    CHECK_EQ(v3->sb.partition_table_offset, alt);

    /* 提交后崩溃：重开走新槽位新密钥闭环 */
    arekey_crash_abort(ctx);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);
    arekey_cleanup();
    return 0;
}

/* ================== 5. 轮换在途互斥（REKEYING 态） ================== */

/*
 * 在途守卫：km 已处于 REKEYING（另一轮换在准备期）→ rotate 入口被
 * 状态守卫拒绝（CNG_UNAVAILABLE），rotated=0、盘面零变更。状态恢复后
 * 轮换可正常执行——守卫拒绝不粘滞、不破坏运行态。
 */
TEST(arekey_inflight_guard_rejects)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    uint64_t id = 0;
    int rotated = -1;
    VerthysResult r;

    CHECK_EQ(arekey_make_locked(AREKEY_VERTHYS, &id), 0);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open == 1);
    CHECK(verthys_cng_km_state(v3->km) == VERTHYS_CNG_KM_KERNEL_RESIDENT);

    /* 白盒注入在途态（模拟另一轮换准备期中） */
    v3->km->state = VERTHYS_CNG_KM_REKEYING;
    r = verthys_rekey_auto_rotate(v3, 1, &rotated);
    v3->km->state = VERTHYS_CNG_KM_KERNEL_RESIDENT;   /* 先恢复再断言 */

    CHECK_EQ(r, VERTHYS_ERR_CNG_UNAVAILABLE);          /* 在途：入口拒绝 */
    CHECK_EQ(rotated, 0);                              /* 零副作用 */
    CHECK(verthys_cng_km_state(v3->km) == VERTHYS_CNG_KM_KERNEL_RESIDENT);

    /* 状态恢复后轮换照常执行（守卫不粘滞） */
    CHECK_EQ(verthys_rekey_auto_rotate(v3, 1, &rotated), VERTHYS_OK);
    CHECK_EQ(rotated, 1);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);
    arekey_cleanup();
    return 0;
}

/*
 * 准备期失败状态恢复：白盒破坏分区 wrapped 长度（重包装阶段前置检查
 * 拒绝）→ rotate 在已入态 REKEYING 的中途失败（INTERNAL）。断言返回后
 * km 状态恢复 KERNEL_RESIDENT（不被失败粘滞），rotated=0、旧密钥组零
 * 变更，复原破坏字段后轮换与数据读写全链正常。
 */
TEST(arekey_prep_failure_restores_state)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRecord out;
    uint64_t id = 0;
    int rotated = -1;
    size_t saved_len;
    VerthysResult r;

    CHECK_EQ(arekey_make_locked(AREKEY_VERTHYS, &id), 0);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open == 1);
    CHECK(v3->ptable.count >= 1);

    /* 白盒破坏：wrapped 长度错值 → 重包装第一步即 INTERNAL（已入态） */
    saved_len = v3->ptable.entries[0].wrapped_key_len;
    v3->ptable.entries[0].wrapped_key_len = 0;
    r = verthys_rekey_auto_rotate(v3, 1, &rotated);
    v3->ptable.entries[0].wrapped_key_len = saved_len;   /* 先复原再断言 */

    CHECK_EQ(r, VERTHYS_ERR_INTERNAL);
    CHECK_EQ(rotated, 0);
    CHECK(verthys_cng_km_state(v3->km) == VERTHYS_CNG_KM_KERNEL_RESIDENT);

    /* 复原后：旧密钥组可用（数据可读），轮换照常执行 */
    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);
    CHECK_EQ(verthys_rekey_auto_rotate(v3, 1, &rotated), VERTHYS_OK);
    CHECK_EQ(rotated, 1);
    CHECK(verthys_cng_km_state(v3->km) == VERTHYS_CNG_KM_KERNEL_RESIDENT);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);
    arekey_cleanup();
    return 0;
}

/* ================== 6. 崩溃窗口 b：提交后（重开闭环） ================== */

/*
 * 法定人数提交成功后立即崩溃（句柄切换为内存态，盘面已完成）：
 * 重开走新槽位 + 新 wrapped 密钥 + 新分区表帧，数据完整可解密，
 * TLV 轮换状态（时间戳 / txid 快照 / 标志清除）跨进程持久化。
 */
TEST(arekey_crash_after_commit)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VerthysContextV3 *v3;
    VerthysRekeyState st;
    VerthysRecord out;
    VerthysRecord nr = {VERTHYS_RECORD_ACCOUNT, "postcrash", 9,
                      (const uint8_t *)"post-crash-data", 15};
    uint64_t id = 0, nid = 0;
    uint64_t t_rotate = arekey_now_ft();
    uint64_t new_offset;
    int rotated = 0;

    CHECK_EQ(arekey_make_locked(AREKEY_VERTHYS, &id), 0);
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK(v3 != NULL && v3->subsystems_open == 1);

    /* 真实轮换（force：新容器防震荡窗口内旁路）→ 立即崩溃 */
    CHECK_EQ(verthys_rekey_auto_rotate(v3, 1, &rotated), VERTHYS_OK);
    CHECK_EQ(rotated, 1);
    new_offset = v3->sb.partition_table_offset;
    CHECK_EQ(new_offset,
             (uint64_t)AREKEY_ALT_OFFSET(VERTHYS_V3_PARTITION_TABLE_OFFSET));

    arekey_crash_abort(ctx);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);

    /* 重开：新语境闭环 + 数据完整 + TLV 持久化 */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_Unlock(h, AREKEY_VERTHYS, AREKEY_PW, AREKEY_PW_LEN, 0),
             VERTHYS_OK);
    ctx = (struct VerthysContext *)h;
    v3 = ctx->v3;
    CHECK_EQ(v3->sb.partition_table_offset, new_offset);
    verthys_rekey_auto_state_get(&v3->sb, &st);
    CHECK_EQ(st.flags, 0u);
    CHECK_EQ(st.last_rekey_txid, v3->sb.txid);   /* 快照值跨会话持久 */
    CHECK(st.last_rekey_ft >= t_rotate);
    CHECK(st.last_rekey_ft - t_rotate < AREKEY_FT_10MIN);

    CHECK_EQ(Verthys_GetRecord(h, id, &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "data-0", 6) == 0);

    /* 轮换后落盘语境上继续写入（LID 严格递增） */
    CHECK_EQ(Verthys_AddRecord(h, &nr, &nid), VERTHYS_OK);
    CHECK_EQ(nid, id + 1);
    CHECK_EQ(Verthys_GetRecord(h, nid, &out), VERTHYS_OK);
    CHECK(memcmp(out.data, "post-crash-data", 15) == 0);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Verthys_Deinit(h);
    arekey_cleanup();
    return 0;
}
