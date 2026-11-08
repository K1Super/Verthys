/*
 * test_defense_closure.c — 防御闭环状态事实化验证
 *
 * 覆盖维度：
 *   - 公共状态查询参数校验与句柄校验（NULL / 已注销句柄）
 *   - BOOT 语义：Verthys_Init 成功 ⟹ 无 FAILED 路径
 *   - 锁定态：无驻留密钥 ⟹ 挂起/内存转储/休眠取证 BLOCKED + NO_RESIDENT_KEY
 *   - 解锁态：密钥驻留用户态 ⟹ 上述路径如实降级，不得虚假阻断
 *   - 七路径判定矩阵（合成 facts，不依赖真实容器）：休眠三态、Hook 扫描
 *     四态、沙盒回读三态、跨设备绑定事实
 *   - limited_count 只统计架构限制原因（2/5），不混入可修复降级
 *   - 沙盒自报位不进入判据（DLL 劫持不得因 Verthys_NotifySandboxAttrs 变 BLOCKED）
 *   - 驻留会话计数在创建/锁定/轮换提交/销毁四个节点保持一致
 *   - 状态查询与 Lock/Deinit 并发无死锁、无 UAF
 */
#include "verthys_test.h"
#include "verthys.h"
#include "defense_closure.h"
#include "verthys_api_utils.h"   /* vault_session_resident_count */
#include "process_sandbox.h"     /* SANDBOX_ATTR_* */
#include "syscall_direct.h"      /* 合成 IAT 用例的守卫条件 */
#include "tls_loader.h"          /* g_tls_init_marker：TLS 缺失用例 */
#include "hardware_binding.h"
#include "cng_machine_key.h"
#include "vty_lockout.h"         /* 轮换用例关闭持久化熔断 */
#include "secure_allocator.h"    /* 安全分配统计 */
#include "memory_guard.h"        /* 应急零化覆盖 Vault/Store */
#include "vty_keymanager.h"   /* VtyVault 字段（安全分配/清钥断言） */
#include "hibernation_state.h"   /* 真实休眠状态下的期望值裁决 */
#include "hook_scan.h"           /* 真实 Hook 证据下的期望值裁决 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>            /* remove */
#include <stddef.h>            /* offsetof */

#define DCL_VERTHYS   "test_dcl.verthys"
#define DCL_PURGE     "test_dcl_purge.verthys"
#define DCL_ROTATE    "test_dcl_rotate.verthys"
#define DCL_ROTATE_TMP "test_dcl_rotate.tmp.verthys"
#define DCL_PW        "dcl-pass-2026"
#define DCL_PW_LEN    (sizeof(DCL_PW) - 1)
#define DCL_PRESET    VERTHYS_PRESET_PERFORMANCE

/* 路径名（仅用于失败诊断输出，与 VerthysDefensePath 下标对应） */
static const char *dcl_path_names[VERTHYS_DEFENSE_PATH_COUNT] = {
    "SUSPEND_BYPASS", "MEM_DUMP", "HIBERNATION", "IAT_HOOK",
    "DLL_HIJACK", "PROCESS_READ", "CROSS_DEVICE",
};

/* 沙盒核心位（与 defense_closure.c 的"OS 可回读核心"同口径） */
#define DCL_SANDBOX_CORE (SANDBOX_ATTR_PROCESS_CREATE_DISABLE | \
                          SANDBOX_ATTR_IMAGE_NO_REMOTE | \
                          SANDBOX_ATTR_IMAGE_NO_LOW_LABEL | \
                          SANDBOX_ATTR_ACG)

/* 失败诊断：打印非 BLOCKED 路径明细（定位断言失败根因） */
static void dcl_dump_not_blocked(const VerthysSecurityStatus *st)
{
    for (int i = 0; i < VERTHYS_DEFENSE_PATH_COUNT; i++) {
        if (st->path_state[i] != VERTHYS_DEFENSE_BLOCKED) {
            printf("  [PATH NOT BLOCKED] %-14s = %d\n",
                   dcl_path_names[i], (int)st->path_state[i]);
            fflush(stdout);
        }
    }
}

/* 合成 facts：进程级事实先按真实环境填充（策略位/采样时间），
 * 会话与检测状态由用例显式指定。 */
static void dcl_facts_init(DefenseFacts *f)
{
    memset(f, 0, sizeof(*f));
    defense_closure_fill_process_facts(f);
    f->now_ms = 1700000000000ull;
    /* 合成用例不依赖容器：显式保证机器密钥/指纹前置可用，避免
     * 用例顺序影响跨设备判定。 */
    (void)cng_machine_key_init();
    (void)hardware_binding_init();
}

static int dcl_run_facts(DefenseFacts *f, DefenseStatusReport *r)
{
    memset(r, 0, sizeof(*r));
    return defense_closure_check_facts(DEFENSE_CHECK_RUNTIME, f, r);
}

/* 真实环境下的接口挂钩期望：干净扫描 + 直连系统调用才 BLOCKED；
 * 扫描不可用/过期降级；审计发现 Hook 时 FAILED（此时 BOOT 本应拒绝）。 */
static int dcl_iat_expected_state(void)
{
    uint32_t hs = hook_scan_get_state();
    if (hs == HOOK_SCAN_ANOMALY) return (int)VERTHYS_DEFENSE_FAILED;
    if (hs == HOOK_SCAN_CLEAN && syscall_direct_available()) {
        return (int)VERTHYS_DEFENSE_BLOCKED;
    }
    return (int)VERTHYS_DEFENSE_DEGRADED;
}

/* ================== 1. 参数与句柄校验 ================== */

TEST(dcl_status_invalid_params)
{
    VerthysSecurityStatus st;
    VerthysHandle h;

    CHECK_EQ(Verthys_GetSecurityStatus(NULL, &st), VERTHYS_ERR_INVALID);

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_GetSecurityStatus(h, NULL), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);

    /* 已注销句柄：注册表校验必须拒绝，禁止解引用已释放指针 */
    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_ERR_INVALID);
    return 0;
}

/* ================== 2. BOOT 语义回归 ================== */

TEST(dcl_boot_check_no_failed_paths)
{
    VerthysHandle h;
    VerthysSecurityStatus st;

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_OK);
    CHECK_EQ(st.failed_count, 0u);
    CHECK_EQ(st.all_critical_blocked, 0);
    for (int i = 0; i < VERTHYS_DEFENSE_PATH_COUNT; i++) {
        CHECK(st.path_state[i] == VERTHYS_DEFENSE_BLOCKED ||
              st.path_state[i] == VERTHYS_DEFENSE_DEGRADED);
    }

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    return 0;
}

/* ================== 3. 锁定 / 解锁语义 ================== */

TEST(dcl_locked_state_no_resident_key)
{
    VerthysHandle h;
    VerthysSecurityStatus st;
    int iat = dcl_iat_expected_state();
    int blocked;

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_OK);

    /* 无驻留密钥：挂起/内存转储/休眠取证必须 BLOCKED（不可报降级），
     * 进程读取由真实 Job 隔离闭合；接口挂钩取决于最近一次 Hook 证据；
     * 动态劫持取决于 OS 回读（测试进程通常无 mitigation → 降级）；
     * 跨设备无会话事实降级。 */
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_SUSPEND_BYPASS], VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_MEM_DUMP],       VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_HIBERNATION],    VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_IAT_HOOK],       iat);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_DLL_HIJACK],     VERTHYS_DEFENSE_DEGRADED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_PROCESS_READ],   VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_CROSS_DEVICE],   VERTHYS_DEFENSE_DEGRADED);
    CHECK_EQ(st.failed_count, 0u);
    blocked = 4 + (iat == (int)VERTHYS_DEFENSE_BLOCKED ? 1 : 0);
    CHECK_EQ(st.blocked_count, (uint32_t)blocked);
    CHECK_EQ(st.degraded_count,
             VERTHYS_DEFENSE_PATH_COUNT - (uint32_t)blocked);
    CHECK_EQ(st.all_critical_blocked, 0);

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    return 0;
}

TEST(dcl_unlocked_honest_state)
{
    VerthysHandle h;
    VerthysSecurityStatus st;
    char code[256];
    uint32_t hibernation;
    int iat;
    int hib_blocked;
    int blocked;

    remove(DCL_VERTHYS);
    memset(code, 0, sizeof(code));
    hibernation = hibernation_state_query();
    iat = dcl_iat_expected_state();
    hib_blocked = (hibernation == HIBERNATION_STATE_DISABLED) ? 1 : 0;

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, DCL_VERTHYS, DCL_PW, DCL_PW_LEN,
                              code, sizeof(code)), VERTHYS_OK);

    /* 解锁态：密钥驻留用户态堆，内存转储/休眠取证/挂起绕过必须如实降级；
     * 进程读取与跨设备绑定由真实事实闭合。任何 7/7 全阻断结论都是虚假的。 */
    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_OK);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_SUSPEND_BYPASS], VERTHYS_DEFENSE_DEGRADED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_MEM_DUMP],       VERTHYS_DEFENSE_DEGRADED);
    /* 休眠禁用时 hiberfil 不存在，该路径按"无资产"阻断；启用/未知才降级。 */
    if (hib_blocked) {
        CHECK_EQ(st.path_state[VERTHYS_DEFENSE_HIBERNATION], VERTHYS_DEFENSE_BLOCKED);
    } else {
        CHECK_EQ(st.path_state[VERTHYS_DEFENSE_HIBERNATION], VERTHYS_DEFENSE_DEGRADED);
    }
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_IAT_HOOK],       iat);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_DLL_HIJACK],     VERTHYS_DEFENSE_DEGRADED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_PROCESS_READ],   VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_CROSS_DEVICE],   VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.failed_count, 0u);
    blocked = 2 + hib_blocked +
              (iat == (int)VERTHYS_DEFENSE_BLOCKED ? 1 : 0);
    CHECK_EQ(st.blocked_count, (uint32_t)blocked);
    CHECK_EQ(st.degraded_count,
             VERTHYS_DEFENSE_PATH_COUNT - (uint32_t)blocked);
    CHECK_EQ(st.all_critical_blocked, 0);
    dcl_dump_not_blocked(&st);

    /* 锁定后密钥清零释放：三条"无资产"路径回到 BLOCKED。 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_OK);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_SUSPEND_BYPASS], VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_MEM_DUMP],       VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_HIBERNATION],    VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.blocked_count,
             (uint32_t)(4 + (iat == (int)VERTHYS_DEFENSE_BLOCKED ? 1 : 0)));

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(DCL_VERTHYS);
    return 0;
}

/* ================== 4. 七路径判定矩阵（合成 facts） ================== */

TEST(dcl_facts_locked_matrix)
{
    DefenseFacts f;
    DefenseStatusReport r;

    dcl_facts_init(&f);
    CHECK_EQ(dcl_run_facts(&f, &r), 0);

    CHECK_EQ(r.path_state[DEFENSE_PATH_SUSPEND_BYPASS], DEFENSE_STATE_BLOCKED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_SUSPEND_BYPASS], DEFENSE_REASON_NO_RESIDENT_KEY);
    CHECK_EQ(r.path_state[DEFENSE_PATH_MEM_DUMP], DEFENSE_STATE_BLOCKED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_MEM_DUMP], DEFENSE_REASON_NO_RESIDENT_KEY);
    CHECK_EQ(r.path_state[DEFENSE_PATH_HIBERNATION], DEFENSE_STATE_BLOCKED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_HIBERNATION], DEFENSE_REASON_NO_RESIDENT_KEY);
    CHECK_EQ(r.path_state[DEFENSE_PATH_PROCESS_READ], DEFENSE_STATE_BLOCKED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_PROCESS_READ], DEFENSE_REASON_JOB_ACTIVE);
    CHECK_EQ(r.path_state[DEFENSE_PATH_CROSS_DEVICE], DEFENSE_STATE_DEGRADED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_CROSS_DEVICE], DEFENSE_REASON_NO_SESSION_FACTS);
    CHECK_EQ(r.limited_count, 0u);
    CHECK_EQ(r.failed_count, 0u);
    CHECK_EQ(r.checked_at_unix_ms, f.now_ms);
    return 0;
}

TEST(dcl_facts_suspend_and_mem_matrix)
{
    DefenseFacts f;
    DefenseStatusReport r;

    /* 有驻留密钥：挂起绕过/内存转储降级，内存转储计入架构限制。 */
    dcl_facts_init(&f);
    f.any_unlocked_session = 1;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_MEM_DUMP], DEFENSE_STATE_DEGRADED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_MEM_DUMP],
             DEFENSE_REASON_KEYS_USER_RESIDENT);
    CHECK_EQ(r.path_state[DEFENSE_PATH_SUSPEND_BYPASS], DEFENSE_STATE_DEGRADED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_SUSPEND_BYPASS],
             DEFENSE_REASON_SUSPEND_GUARD_INACTIVE);
    CHECK(r.limited_count >= 1u);

    /* 看门狗接线后：仅剩管理员挂起这一架构限制（原因 5，计入 limited）。 */
    f.policy_flags |= DEFENSE_GUARD_HEARTBEAT | DEFENSE_GUARD_SUSPEND_LOCK;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_SUSPEND_BYPASS],
             DEFENSE_REASON_SUSPEND_UNPREVENTABLE);
    CHECK_EQ(r.limited_count, 2u);   /* 挂起 + 内存转储 */
    return 0;
}

TEST(dcl_facts_hibernation_matrix)
{
    DefenseFacts f;
    DefenseStatusReport r;

    /* 解锁 + 休眠禁用：hiberfil 不存在，休眠取证 BLOCKED（原因 20）。 */
    dcl_facts_init(&f);
    f.any_unlocked_session = 1;
    f.hibernation_state = 0;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_HIBERNATION], DEFENSE_STATE_BLOCKED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_HIBERNATION],
             DEFENSE_REASON_HIBERNATION_DISABLED);

    /* 解锁 + 休眠启用：降级原因 3，属于环境缺口，不计入架构限制。 */
    f.hibernation_state = 1;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_HIBERNATION], DEFENSE_STATE_DEGRADED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_HIBERNATION],
             DEFENSE_REASON_HIBERNATION_ENABLED);

    /* 解锁 + 状态未知：降级原因 4，同样不计入架构限制。 */
    f.hibernation_state = 2;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_HIBERNATION], DEFENSE_STATE_DEGRADED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_HIBERNATION],
             DEFENSE_REASON_HIBERNATION_UNKNOWN);
    return 0;
}

TEST(dcl_facts_hook_scan_matrix)
{
    DefenseFacts f;
    DefenseStatusReport r;
    int syscall_ok;

    dcl_facts_init(&f);

    f.hook_scan_state = 2;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_IAT_INLINE_HOOK], DEFENSE_STATE_FAILED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_IAT_INLINE_HOOK], DEFENSE_REASON_HOOK_DETECTED);

    f.hook_scan_state = 3;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_IAT_INLINE_HOOK], DEFENSE_STATE_DEGRADED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_IAT_INLINE_HOOK], DEFENSE_REASON_EVIDENCE_STALE);

    f.hook_scan_state = 0;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_IAT_INLINE_HOOK], DEFENSE_STATE_DEGRADED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_IAT_INLINE_HOOK],
             DEFENSE_REASON_HOOK_SCAN_UNAVAILABLE);

    /* 干净扫描 + 直连系统调用激活才允许 BLOCKED；未激活时检测器查询
     * 重新暴露于可 Hook 的 ntdll 导出，只能降级。 */
    f.hook_scan_state = 1;
    syscall_ok = syscall_direct_available();
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    if (syscall_ok) {
        CHECK_EQ(r.path_state[DEFENSE_PATH_IAT_INLINE_HOOK], DEFENSE_STATE_BLOCKED);
        CHECK_EQ(r.path_reason[DEFENSE_PATH_IAT_INLINE_HOOK],
                 DEFENSE_REASON_HOOK_SCAN_CLEAN);
    } else {
        CHECK_EQ(r.path_state[DEFENSE_PATH_IAT_INLINE_HOOK], DEFENSE_STATE_DEGRADED);
        CHECK_EQ(r.path_reason[DEFENSE_PATH_IAT_INLINE_HOOK],
                 DEFENSE_REASON_HOOK_SCAN_UNAVAILABLE);
    }

    /* TLS 加载标志缺失：加载路径异常，按 FAILED。测试进程的 TLS 回调
     * 已置位，此处临时改写并在用例结束恢复，避免污染后续用例。 */
    InterlockedExchange(&g_tls_init_marker, 0);
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    InterlockedExchange(&g_tls_init_marker, 1);
    CHECK_EQ(r.path_state[DEFENSE_PATH_IAT_INLINE_HOOK], DEFENSE_STATE_FAILED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_IAT_INLINE_HOOK],
             DEFENSE_REASON_MODULE_INIT_FAILED);
    return 0;
}

TEST(dcl_facts_sandbox_matrix)
{
    DefenseFacts f;
    DefenseStatusReport r;

    dcl_facts_init(&f);

    f.sandbox_verified_mask = 0;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_DLL_HIJACK], DEFENSE_STATE_DEGRADED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_DLL_HIJACK],
             DEFENSE_REASON_SANDBOX_UNVERIFIED);

    f.sandbox_verified_mask = SANDBOX_ATTR_IMAGE_NO_REMOTE;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_DLL_HIJACK], DEFENSE_STATE_DEGRADED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_DLL_HIJACK],
             DEFENSE_REASON_SANDBOX_PARTIAL);

    f.sandbox_verified_mask = DCL_SANDBOX_CORE;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_DLL_HIJACK], DEFENSE_STATE_BLOCKED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_DLL_HIJACK],
             DEFENSE_REASON_SANDBOX_VERIFIED);
    return 0;
}

TEST(dcl_facts_cross_device_matrix)
{
    DefenseFacts f;
    DefenseStatusReport r;

    dcl_facts_init(&f);

    f.queried_unlocked_session = 1;
    f.queried_device_bound = 1;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_CROSS_DEVICE], DEFENSE_STATE_BLOCKED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_CROSS_DEVICE], DEFENSE_REASON_DEVICE_BOUND);

    /* 会话未解锁：没有可校验的绑定事实 */
    f.queried_unlocked_session = 0;
    f.queried_device_bound = 0;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_CROSS_DEVICE], DEFENSE_STATE_DEGRADED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_CROSS_DEVICE],
             DEFENSE_REASON_NO_SESSION_FACTS);

    /* 解锁但无设备根/PCR 槽：绑定事实不成立 */
    f.queried_unlocked_session = 1;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_CROSS_DEVICE], DEFENSE_STATE_DEGRADED);
    CHECK_EQ(r.path_reason[DEFENSE_PATH_CROSS_DEVICE],
             DEFENSE_REASON_NO_SESSION_FACTS);

    /* PCR 槽同样构成有效绑定 */
    f.queried_pcr_bound = 1;
    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_CROSS_DEVICE], DEFENSE_STATE_BLOCKED);
    return 0;
}

TEST(dcl_facts_limited_count)
{
    DefenseFacts f;
    DefenseStatusReport r;
    int syscall_ok;

    dcl_facts_init(&f);
    f.any_unlocked_session = 1;
    f.queried_unlocked_session = 1;
    f.queried_device_bound = 1;
    f.hibernation_state = 0;
    f.hook_scan_state = 1;
    f.sandbox_verified_mask = DCL_SANDBOX_CORE;
    f.policy_flags |= DEFENSE_GUARD_HEARTBEAT | DEFENSE_GUARD_SUSPEND_LOCK;

    CHECK_EQ(dcl_run_facts(&f, &r), 0);
    CHECK_EQ(r.path_state[DEFENSE_PATH_HIBERNATION], DEFENSE_STATE_BLOCKED);
    CHECK_EQ(r.path_state[DEFENSE_PATH_DLL_HIJACK], DEFENSE_STATE_BLOCKED);
    CHECK_EQ(r.path_state[DEFENSE_PATH_PROCESS_READ], DEFENSE_STATE_BLOCKED);
    CHECK_EQ(r.path_state[DEFENSE_PATH_CROSS_DEVICE], DEFENSE_STATE_BLOCKED);
    CHECK_EQ(r.limited_count, 2u);   /* 挂起不可阻止 + 密钥用户态驻留 */
    CHECK_EQ(r.failed_count, 0u);
    CHECK_EQ(r.all_critical_blocked, 0);

    /* 休眠禁用场景的阻断数：IAT 取决于直连系统调用是否激活，
     * 两种环境都必须保持 limited_count=2 且无 FAILED。 */
    syscall_ok = syscall_direct_available();
    CHECK_EQ(r.blocked_count, syscall_ok ? 5u : 4u);
    return 0;
}

/* ================== 5. 沙盒自报不进入判据 ================== */

TEST(dcl_sandbox_self_report_not_trusted)
{
    VerthysHandle h;
    VerthysSecurityStatus st;

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* worker 自报"全部 mitigation 已应用"只是诊断输入，OS 未回读前
     * 不能据此宣称 DLL 劫持已阻断（否则状态可被自报污染）。 */
    (void)Verthys_NotifySandboxAttrs(SANDBOX_ATTR_ALL);
    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_OK);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_DLL_HIJACK], VERTHYS_DEFENSE_DEGRADED);
    CHECK_EQ(st.failed_count, 0u);

    (void)Verthys_NotifySandboxAttrs(0);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    return 0;
}

/* ================== 6. 驻留会话计数与轮换接管 ================== */

TEST(dcl_session_count_lifecycle)
{
    VerthysHandle h;
    VerthysRotateInfo info;
    char code[256];
    uint32_t before;

    vty_lockout_set_enabled(0);
    remove(DCL_ROTATE);
    remove(DCL_ROTATE_TMP);
    memset(code, 0, sizeof(code));
    memset(&info, 0, sizeof(info));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(vault_session_resident_count(), 0u);

    CHECK_EQ(Verthys_V4Create(h, DCL_ROTATE, DCL_PW, DCL_PW_LEN,
                              code, sizeof(code)), VERTHYS_OK);
    CHECK_EQ(vault_session_resident_count(), 1u);

    /* 全库轮换只允许从恢复会话发起：先锁定再用恢复码打开。 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(vault_session_resident_count(), 0u);
    CHECK_EQ(Verthys_V4UnlockRecovery(h, DCL_ROTATE, code), VERTHYS_OK);
    CHECK_EQ(vault_session_resident_count(), 1u);

    /* RotateCommit：vty_rotate_commit 已释放旧库并返回新库，计数必须保持 1；
     * 若误用 attach 会 +1 漂移，误用旧指针会二次释放。 */
    before = vault_session_resident_count();
    CHECK_EQ(Verthys_V4RotateBegin(h, DCL_ROTATE_TMP, DCL_PW, DCL_PW_LEN,
                                   0u, &info), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateRun(h, NULL, NULL), VERTHYS_OK);
    CHECK_EQ(Verthys_V4RotateCommit(h, 0u), VERTHYS_OK);
    CHECK_EQ(vault_session_resident_count(), before);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(vault_session_resident_count(), 0u);

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    CHECK_EQ(vault_session_resident_count(), 0u);

    remove(DCL_ROTATE);
    remove(DCL_ROTATE_TMP);
    return 0;
}

/* ================== 7. 状态 ABI 与运行时守卫位 ================== */

TEST(dcl_status_abi_layout)
{
    /* 追加式布局：既有 48 字节前缀不变，新字段偏移与总大小锁定。
     * C 编译期断言已覆盖，此处在运行期再验一次，防止测试构建与
     * 产品构建的宏差异掩盖漂移。 */
    CHECK_EQ(VERTHYS_API_VERSION, 0x0014u);
    CHECK_EQ(offsetof(VerthysSecurityStatus, path_reason), 48u);
    CHECK_EQ(offsetof(VerthysSecurityStatus, limited_count), 76u);
    CHECK_EQ(offsetof(VerthysSecurityStatus, policy_flags), 80u);
    CHECK_EQ(offsetof(VerthysSecurityStatus, checked_at_unix_ms), 88u);
    CHECK_EQ(sizeof(VerthysSecurityStatus), 104u);
    CHECK_EQ((int)VERTHYS_DEFENSE_REASON_SANDBOX_UNVERIFIED, 12);
    CHECK_EQ((int)VERTHYS_DEFENSE_REASON_HIBERNATION_DISABLED, 20);
    return 0;
}

TEST(dcl_runtime_guards_flag)
{
    VerthysHandle h;
    VerthysSecurityStatus st;

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 未知位被丢弃；bit0/bit1 进入 policy_flags。 */
    CHECK_EQ(Verthys_NotifyRuntimeGuards(0xFFFFFFFFu), VERTHYS_OK);
    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_OK);
    CHECK_EQ(st.policy_flags & (VERTHYS_DEFENSE_GUARD_HEARTBEAT |
                                VERTHYS_DEFENSE_GUARD_SUSPEND_LOCK),
             (uint32_t)(VERTHYS_DEFENSE_GUARD_HEARTBEAT |
                        VERTHYS_DEFENSE_GUARD_SUSPEND_LOCK));
    CHECK_EQ(st.policy_flags & 0xFFFFFFF8u, 0u);
    CHECK(st.checked_at_unix_ms > 0u);

    /* 停止守卫下发 0：守卫位必须整体清零（完整掩码语义，非累加）。 */
    CHECK_EQ(Verthys_NotifyRuntimeGuards(0u), VERTHYS_OK);
    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_OK);
    CHECK_EQ(st.policy_flags & (VERTHYS_DEFENSE_GUARD_HEARTBEAT |
                                VERTHYS_DEFENSE_GUARD_SUSPEND_LOCK), 0u);

    /* 追加原因码与既有状态一一对应：锁定态无驻留密钥。 */
    CHECK_EQ(st.path_reason[VERTHYS_DEFENSE_SUSPEND_BYPASS],
             (uint32_t)VERTHYS_DEFENSE_REASON_NO_RESIDENT_KEY);
    CHECK_EQ(st.path_reason[VERTHYS_DEFENSE_MEM_DUMP],
             (uint32_t)VERTHYS_DEFENSE_REASON_NO_RESIDENT_KEY);
    CHECK_EQ(st.path_reason[VERTHYS_DEFENSE_PROCESS_READ],
             (uint32_t)VERTHYS_DEFENSE_REASON_JOB_ACTIVE);

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    return 0;
}

/* ================== 8. 密钥安全分配与应急清钥 ================== */

TEST(dcl_secure_alloc_lifecycle)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    char code[256];
    SecureAllocator *shared;
    SecureAllocatorStats st;
    size_t base_live;
    size_t base_bytes;

    remove(DCL_VERTHYS);
    memset(code, 0, sizeof(code));

    shared = secure_allocator_shared();
    CHECK(shared != NULL);
    secure_allocator_get_stats(shared, &st);
    base_live  = st.live_count;
    base_bytes = st.live_bytes;

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, DCL_VERTHYS, DCL_PW, DCL_PW_LEN,
                              code, sizeof(code)), VERTHYS_OK);

    /* Vault + Store 必须经进程级安全分配器（普通堆不再承载密钥块）。 */
    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->vault != NULL);
    secure_allocator_get_stats(shared, &st);
    CHECK_EQ(st.live_count, base_live + 2u);
    CHECK(st.live_bytes > base_bytes);

    /* 锁定释放会话后，两条安全区段必须全部归还（live_count 回落）。 */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    secure_allocator_get_stats(shared, &st);
    CHECK_EQ(st.live_count, base_live);
    CHECK_EQ(st.live_bytes, base_bytes);

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(DCL_VERTHYS);
    return 0;
}

TEST(dcl_secure_alloc_failure)
{
    VerthysHandle h;
    char code[256];
    VerthysResult rc;

    remove(DCL_VERTHYS);
    memset(code, 0, sizeof(code));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 预算压到一页以下：Vault 安全区段必然被拒。失败必须显式返回
     * 资源上限，禁止回退普通堆。 */
    CHECK_EQ(secure_allocator_budget_init(4096u, NULL, NULL), VERTHYS_OK);
    rc = Verthys_V4Create(h, DCL_VERTHYS, DCL_PW, DCL_PW_LEN,
                          code, sizeof(code));
    CHECK_EQ(secure_allocator_budget_init(SECURE_ALLOC_DEFAULT_BUDGET_BYTES,
                                          NULL, NULL), VERTHYS_OK);

    CHECK_EQ(rc, VERTHYS_ERR_RESOURCE_LIMIT);
    /* 失败路径不得留下半成品容器文件。 */
    CHECK(fopen(DCL_VERTHYS, "rb") == NULL);

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(DCL_VERTHYS);
    return 0;
}

TEST(dcl_emergency_purge)
{
    VerthysHandle h;
    struct VerthysContext *ctx;
    VtyVault *v;
    VtyStore *saved_store;
    const uint8_t *store_raw;
    char code[256];
    SecureAllocator *shared;
    SecureAllocatorStats st;
    size_t base_live;
    int nonzero = 0;
    int i;

    remove(DCL_PURGE);
    memset(code, 0, sizeof(code));

    shared = secure_allocator_shared();
    CHECK(shared != NULL);
    secure_allocator_get_stats(shared, &st);
    base_live = st.live_count;

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, DCL_PURGE, DCL_PW, DCL_PW_LEN,
                              code, sizeof(code)), VERTHYS_OK);

    ctx = (struct VerthysContext *)h;
    CHECK(ctx != NULL && ctx->vault != NULL);
    v = ctx->vault;
    saved_store = v->store;
    CHECK(saved_store != NULL);
    /* Store 结构不透明：以首字节（路径字符串）证明该页已写入；应急
     * 零化按注册长度覆盖整页，含同页 kdir。 */
    store_raw = (const uint8_t *)saved_store;
    CHECK(store_raw[0] != 0);
    for (i = 0; i < (int)sizeof(v->kc); i++) {
        if (v->kc[i] != 0) nonzero = 1;
    }
    CHECK(nonzero);   /* 前置：解锁会话确有驻留密钥 */

    /* 应急 KILL 的内存绝育步骤：注册区（Vault/Store）统一零化。 */
    memory_guard_emergency_purge();

    for (i = 0; i < (int)sizeof(v->kc); i++) {
        CHECK_EQ(v->kc[i], 0);
    }
    for (i = 0; i < 16; i++) {
        CHECK_EQ(store_raw[i], 0);
    }
    /* 整页零化后会话结构同时失去 store 指针与解锁标志——KILL 路径进程
     * 随即退出；测试进程需手工回收被零化的 Store 区段。 */
    CHECK(v->store == NULL);
    CHECK_EQ(v->unlocked, 0);
    vty_store_close(saved_store);

    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    secure_allocator_get_stats(shared, &st);
    CHECK_EQ(st.live_count, base_live);

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(DCL_PURGE);
    return 0;
}

/* ================== 9. 并发查询与 Lock/Deinit ================== */
typedef struct {
    VerthysHandle h;
    volatile LONG stop;
    volatile LONG ok;
    volatile LONG invalid;
    volatile LONG other;
} DclQueryCtx;

static DWORD WINAPI dcl_query_thread(LPVOID param)
{
    DclQueryCtx *q = (DclQueryCtx *)param;

    while (InterlockedCompareExchange(&q->stop, 0, 0) == 0) {
        VerthysSecurityStatus st;
        VerthysResult rc = Verthys_GetSecurityStatus(q->h, &st);
        if (rc == VERTHYS_OK) {
            InterlockedIncrement(&q->ok);
        } else if (rc == VERTHYS_ERR_INVALID) {
            InterlockedIncrement(&q->invalid);
        } else {
            InterlockedIncrement(&q->other);
        }
    }
    return 0;
}

TEST(dcl_status_concurrent_lock)
{
    VerthysHandle h;
    char code[256];
    DclQueryCtx q;
    HANDLE threads[3];
    int i;

    remove(DCL_VERTHYS);
    memset(code, 0, sizeof(code));
    memset(&q, 0, sizeof(q));

    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_V4Create(h, DCL_VERTHYS, DCL_PW, DCL_PW_LEN,
                              code, sizeof(code)), VERTHYS_OK);

    q.h = h;
    for (i = 0; i < 3; i++) {
        threads[i] = CreateThread(NULL, 0, dcl_query_thread, &q, 0, NULL);
        CHECK(threads[i] != NULL);
    }

    /* 查询线程持 registry 共享锁做快照；Lock 独占句柄锁释放会话；
     * Deinit 独占 registry 锁注销并释放上下文。三层锁序不得死锁，
     * 注销后的查询必须安全返回 INVALID 而不是解引用悬空指针。 */
    Sleep(60);
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    Sleep(60);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    /* 注销后的句柄必须安全返回 INVALID（注册表校验，不解引用悬空指针）。
     * 查询线程可能已看到该状态，也可能在下一轮循环前被停止，断言以
     * 主线程这次调用为准，避免依赖调度时序。 */
    {
        VerthysSecurityStatus st_after;
        CHECK_EQ(Verthys_GetSecurityStatus(h, &st_after), VERTHYS_ERR_INVALID);
    }

    InterlockedExchange(&q.stop, 1);
    CHECK_EQ(WaitForMultipleObjects(3, threads, TRUE, 5000), WAIT_OBJECT_0);
    for (i = 0; i < 3; i++) CloseHandle(threads[i]);

    CHECK_EQ(q.other, 0);
    CHECK(q.ok > 0);

    remove(DCL_VERTHYS);
    return 0;
}
