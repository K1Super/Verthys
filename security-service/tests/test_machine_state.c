/*
 * test_machine_state.c — 令牌桶与每用户配额
 */
#include "test_common.h"
#include "machine_state.h"
#include "service_util.h"

#include <process.h>
#include <string.h>

static uint8_t g_key[32];
static wchar_t g_dir[VTY_PATH_MAX];
static VtyMachineState g_state;

static int state_setup(int ignore_quota)
{
    size_t i;

    for (i = 0; i < 32u; i++) {
        g_key[i] = (uint8_t)(i * 7u + 0x31u);
    }
    if (test_make_temp_dir(g_dir, VTY_PATH_MAX) != 0) return -1;
    if (vty_machine_state_init(&g_state, g_dir, g_key, 0) != 0) return -1;
#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
    vty_machine_state_set_test_ignore_user_quota(&g_state, ignore_quota);
#else
    (void)ignore_quota;
#endif
    if (vty_machine_state_create_new(&g_state) != 0) return -1;
    return 0;
}

static void state_teardown(void)
{
    vty_machine_state_destroy(&g_state);
    test_remove_tree(g_dir);
}

static void fill_sid(uint8_t sid[32], uint8_t seed)
{
    size_t i;
    for (i = 0; i < 32u; i++) sid[i] = (uint8_t)(seed + (uint8_t)i);
}

static void test_refill(void)
{
    VtyMachineStateFields f;
    VtyMachineDecision d;
    uint8_t sid[32];
    uint64_t t0;
    int i;

    printf("[ U3 ] token refill / clock rollback\n");
    if (state_setup(1) != 0) {
        CHECK(0);
        return;
    }
    fill_sid(sid, 0x11u);
    vty_machine_state_snapshot(&g_state, &f);
    t0 = f.last_refill_100ns;
    CHECK_EQ_U64(f.tokens, VTY_MS_CAPACITY);

    for (i = 0; i < (int)VTY_MS_CAPACITY; i++) {
        CHECK_EQ_INT(vty_machine_state_record_failure_at(
                         &g_state, sid, t0, 1000u, &d),
                     0);
        CHECK_EQ_INT(d.status, VTY_SVC_STATUS_OK);
        CHECK_EQ_U64(d.remaining_tokens, VTY_MS_CAPACITY - (uint32_t)i - 1u);
    }
    CHECK_EQ_INT(vty_machine_state_record_failure_at(&g_state, sid, t0, 1000u,
                                                     &d),
                 0);
    CHECK_EQ_INT(d.status, VTY_SVC_STATUS_LOCKED);

    CHECK_EQ_INT(vty_machine_state_check_at(
                     &g_state, sid, t0 + VTY_MS_REFILL_INTERVAL_100NS, 2000u,
                     &d),
                 0);
    CHECK_EQ_INT(d.status, VTY_SVC_STATUS_OK);
    CHECK_EQ_U64(d.remaining_tokens, 1u);

    CHECK_EQ_INT(vty_machine_state_check_at(
                     &g_state, sid,
                     t0 + 10u * VTY_MS_REFILL_INTERVAL_100NS, 3000u, &d),
                 0);
    CHECK_EQ_U64(d.remaining_tokens, VTY_MS_CAPACITY);

    CHECK_EQ_INT(vty_machine_state_check_at(&g_state, sid, t0 - 10000000ULL,
                                            4000u, &d),
                 0);
    CHECK_EQ_U64(d.remaining_tokens, VTY_MS_CAPACITY);
    state_teardown();
}

static void test_reset_semantics(void)
{
    VtyMachineStateFields f;
    VtyMachineDecision d;
    uint8_t sid[32];

    printf("[ U5 ] reset only audits, never restores tokens\n");
    if (state_setup(1) != 0) {
        CHECK(0);
        return;
    }
    fill_sid(sid, 0x22u);
    vty_machine_state_snapshot(&g_state, &f);
    CHECK_EQ_U64(f.tokens, VTY_MS_CAPACITY);
    CHECK_EQ_INT(vty_machine_state_reset_at(&g_state, sid,
                                            f.last_refill_100ns, 1000u, &d),
                 0);
    CHECK_EQ_INT(d.status, VTY_SVC_STATUS_OK);
    vty_machine_state_snapshot(&g_state, &f);
    CHECK_EQ_U64(f.tokens, VTY_MS_CAPACITY);
    CHECK_EQ_U64(f.total_success, 1u);

    CHECK_EQ_INT(vty_machine_state_record_failure_at(
                     &g_state, sid, f.last_refill_100ns, 1000u, &d),
                 0);
    CHECK_EQ_U64(d.remaining_tokens, VTY_MS_CAPACITY - 1u);
    CHECK_EQ_INT(vty_machine_state_reset_at(&g_state, sid,
                                            f.last_refill_100ns, 1000u, &d),
                 0);
    vty_machine_state_snapshot(&g_state, &f);
    CHECK_EQ_U64(f.tokens, VTY_MS_CAPACITY - 1u);
    CHECK_EQ_U64(f.total_success, 2u);
    CHECK_EQ_U64(f.total_failures, 1u);
    state_teardown();
}

static void test_user_quota(void)
{
    VtyMachineStateFields f;
    VtyMachineDecision d;
    uint8_t sid_a[32];
    uint8_t sid_b[32];
    uint64_t t0;
    uint64_t ms0;
    int i;

    printf("[ U6 ] per-user minute and global quotas\n");
    if (state_setup(0) != 0) {
        CHECK(0);
        return;
    }
    fill_sid(sid_a, 0x33u);
    fill_sid(sid_b, 0x44u);
    vty_machine_state_snapshot(&g_state, &f);
    t0 = f.last_refill_100ns;
    ms0 = 100000ULL;

    for (i = 0; i < 6; i++) {
        CHECK_EQ_INT(vty_machine_state_record_failure_at(
                         &g_state, sid_a, t0, ms0 + (uint64_t)i * 1000u, &d),
                     0);
        CHECK_EQ_INT(d.status, VTY_SVC_STATUS_OK);
    }
    CHECK_EQ_INT(vty_machine_state_record_failure_at(
                     &g_state, sid_a, t0, ms0 + 6000u, &d),
                 0);
    CHECK_EQ_INT(d.status, VTY_SVC_STATUS_LOCKED);
    vty_machine_state_snapshot(&g_state, &f);
    CHECK_EQ_U64(f.tokens, VTY_MS_CAPACITY - 6u);

    CHECK_EQ_INT(vty_machine_state_record_failure_at(&g_state, sid_b, t0,
                                                     ms0 + 6000u, &d),
                 0);
    CHECK_EQ_INT(d.status, VTY_SVC_STATUS_OK);
    vty_machine_state_snapshot(&g_state, &f);
    CHECK_EQ_U64(f.tokens, VTY_MS_CAPACITY - 7u);
    state_teardown();

    printf("[ U6 ] per-user 10-minute global token quota\n");
    if (state_setup(0) != 0) {
        CHECK(0);
        return;
    }
    vty_machine_state_snapshot(&g_state, &f);
    t0 = f.last_refill_100ns;
    ms0 = 100000ULL;
    for (i = 0; i < 6; i++) {
        CHECK_EQ_INT(vty_machine_state_record_failure_at(
                         &g_state, sid_a, t0, ms0 + (uint64_t)i * 61000u, &d),
                     0);
        CHECK_EQ_INT(d.status, VTY_SVC_STATUS_OK);
    }
    CHECK_EQ_INT(vty_machine_state_record_failure_at(
                     &g_state, sid_a, t0, ms0 + 6u * 61000u, &d),
                 0);
    CHECK_EQ_INT(d.status, VTY_SVC_STATUS_LOCKED);
    CHECK_EQ_INT(vty_machine_state_check_at(&g_state, sid_a, t0,
                                             ms0 + 6u * 61000u, &d),
                 0);
    CHECK_EQ_INT(d.status, VTY_SVC_STATUS_LOCKED);
    CHECK_EQ_INT(vty_machine_state_check_at(&g_state, sid_b, t0,
                                             ms0 + 6u * 61000u, &d),
                 0);
    CHECK_EQ_INT(d.status, VTY_SVC_STATUS_OK);
    vty_machine_state_snapshot(&g_state, &f);
    CHECK_EQ_U64(f.tokens, VTY_MS_CAPACITY - 6u);
    state_teardown();
}

static void test_fairness(void)
{
    VtyMachineStateFields f;
    VtyMachineDecision d;
    uint8_t sid_a[32];
    uint8_t sid_b[32];
    uint64_t t0;
    uint64_t ms0;
    int i;
    int ok_count = 0;
    int locked_count = 0;

    printf("[ U6b ] one SID cannot drain the whole machine budget\n");
    if (state_setup(0) != 0) {
        CHECK(0);
        return;
    }
    fill_sid(sid_a, 0x55u);
    fill_sid(sid_b, 0x66u);
    vty_machine_state_snapshot(&g_state, &f);
    t0 = f.last_refill_100ns;
    ms0 = 100000ULL;
    for (i = 0; i < 10; i++) {
        CHECK_EQ_INT(vty_machine_state_record_failure_at(
                         &g_state, sid_a, t0, ms0 + (uint64_t)i * 61000u, &d),
                     0);
        if (d.status == (uint16_t)VTY_SVC_STATUS_OK) {
            ok_count++;
        } else if (d.status == (uint16_t)VTY_SVC_STATUS_LOCKED) {
            locked_count++;
        }
    }
    CHECK_EQ_INT(ok_count, 6);
    CHECK_EQ_INT(locked_count, 4);
    vty_machine_state_snapshot(&g_state, &f);
    CHECK_EQ_U64(f.total_failures, 6u);
    CHECK_EQ_U64(f.tokens, VTY_MS_CAPACITY - 6u);
    CHECK(f.tokens >= 4u);

    CHECK_EQ_INT(vty_machine_state_check_at(
                     &g_state, sid_b, t0, ms0 + 9u * 61000u, &d),
                 0);
    CHECK_EQ_INT(d.status, VTY_SVC_STATUS_OK);
    CHECK_EQ_U64(d.remaining_tokens, VTY_MS_CAPACITY - 6u);
    state_teardown();
}

typedef struct ThreadCtx {
    VtyMachineState *state;
    uint8_t sid[32];
    uint64_t now_utc;
    uint64_t now_ms;
    int status;
    int rc;
} ThreadCtx;

static unsigned __stdcall record_thread(void *arg)
{
    ThreadCtx *ctx = (ThreadCtx *)arg;
    VtyMachineDecision d;

    memset(&d, 0, sizeof(d));
    ctx->rc = vty_machine_state_record_failure_at(
        ctx->state, ctx->sid, ctx->now_utc, ctx->now_ms, &d);
    ctx->status = (int)d.status;
    return 0;
}

static void run_threads(ThreadCtx *ctx, size_t count)
{
    HANDLE threads[VTY_MS_QUOTA_SLOTS];
    size_t i;

    memset(threads, 0, sizeof(threads));
    for (i = 0; i < count; i++) {
        threads[i] = (HANDLE)_beginthreadex(NULL, 0, record_thread, &ctx[i],
                                            0, NULL);
        CHECK(threads[i] != NULL);
    }
    for (i = 0; i < count; i++) {
        if (threads[i] != NULL) {
            WaitForSingleObject(threads[i], INFINITE);
            CloseHandle(threads[i]);
        }
    }
}

static void test_concurrency(void)
{
    VtyMachineStateFields f;
    ThreadCtx ctx[32];
    uint64_t t0;
    size_t i;
    int ok_count;
    int locked_count;
    int bad_count;

    printf("[ U10 ] concurrent record_failure\n");
    if (state_setup(1) != 0) {
        CHECK(0);
        return;
    }
    vty_machine_state_snapshot(&g_state, &f);
    t0 = f.last_refill_100ns;
    memset(ctx, 0, sizeof(ctx));
    for (i = 0; i < 32u; i++) {
        fill_sid(ctx[i].sid, (uint8_t)(0x70u + (uint8_t)i));
        ctx[i].state = &g_state;
        ctx[i].now_utc = t0;
        ctx[i].now_ms = 100000ULL;
    }
    run_threads(ctx, 32u);
    ok_count = 0;
    locked_count = 0;
    bad_count = 0;
    for (i = 0; i < 32u; i++) {
        CHECK_EQ_INT(ctx[i].rc, 0);
        if (ctx[i].status == (int)VTY_SVC_STATUS_OK) {
            ok_count++;
        } else if (ctx[i].status == (int)VTY_SVC_STATUS_LOCKED) {
            locked_count++;
        } else {
            bad_count++;
        }
    }
    CHECK_EQ_INT(ok_count, (int)VTY_MS_CAPACITY);
    CHECK_EQ_INT(locked_count, 32 - (int)VTY_MS_CAPACITY);
    CHECK_EQ_INT(bad_count, 0);
    vty_machine_state_snapshot(&g_state, &f);
    CHECK_EQ_U64(f.tokens, 0u);
    state_teardown();

    printf("[ U10 ] same SID concurrent quota enforcement\n");
    if (state_setup(0) != 0) {
        CHECK(0);
        return;
    }
    vty_machine_state_snapshot(&g_state, &f);
    t0 = f.last_refill_100ns;
    memset(ctx, 0, sizeof(ctx));
    for (i = 0; i < 32u; i++) {
        fill_sid(ctx[i].sid, 0x90u);
        ctx[i].state = &g_state;
        ctx[i].now_utc = t0;
        ctx[i].now_ms = 100000ULL;
    }
    run_threads(ctx, 32u);
    ok_count = 0;
    locked_count = 0;
    bad_count = 0;
    for (i = 0; i < 32u; i++) {
        CHECK_EQ_INT(ctx[i].rc, 0);
        if (ctx[i].status == (int)VTY_SVC_STATUS_OK) {
            ok_count++;
        } else if (ctx[i].status == (int)VTY_SVC_STATUS_LOCKED) {
            locked_count++;
        } else {
            bad_count++;
        }
    }
    CHECK_EQ_INT(ok_count, (int)VTY_MS_USER_MINUTE_LIMIT);
    CHECK_EQ_INT(locked_count,
                 32 - (int)VTY_MS_USER_MINUTE_LIMIT);
    CHECK_EQ_INT(bad_count, 0);
    vty_machine_state_snapshot(&g_state, &f);
    CHECK_EQ_U64(f.tokens, VTY_MS_CAPACITY - VTY_MS_USER_MINUTE_LIMIT);
    state_teardown();
}

int test_machine_state_run(void)
{
    test_refill();
    test_reset_semantics();
    test_user_quota();
    test_fairness();
    test_concurrency();
    return g_test_failures;
}
