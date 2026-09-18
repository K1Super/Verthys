/*
 * test_defense_closure.c — ★ V3 升级 WP-11：防御闭环状态查询
 *
 * 覆盖（M3 里程碑验收信号"defense_closure 7/7 BLOCKED（运行时验证）"）：
 *   - Verthys_GetSecurityStatus 参数校验（NULL 句柄 / NULL 出参）
 *   - BOOT 语义回归：Verthys_Init 成功 ⟹ 复检无 FAILED 路径
 *     （任一 FAILED 会使 Verthys_Init 本身拒绝启动）
 *   - 7/7 BLOCKED：worker 沙盒属性就位（NotifySandboxAttrs，模拟
 *     worker 加载 DLL 前的 mitigation policy 应用）+ V3 容器解锁
 *     （密钥组 CNG 内核托管）⟹ 全部 7 条攻击路径 BLOCKED
 *   - 实时性（活复检而非缓存）：Verthys_Lock 销毁 CNG 密钥组后，
 *     MEM_DUMP 回落至解锁前基线
 *
 * 判据依据（v5.0 §11.3"防御状态可查询"+ 手册 WP-11 卡片）：
 *   P1 挂起绕过=反调试就绪；P2 内存 Dump=密钥 CNG 托管；P3 休眠取证=
 *   密钥托管+锁页（WP-11 判据重构）；P4 API Hook=TLS 标志+完整性+
 *   直接系统调用（WP-9 落地）；P5 DLL 劫持=Sys32 优先+镜像策略；
 *   P6 进程读取=Job 隔离；P7 跨设备=机器密钥+硬件指纹。
 */
#include "verthys_test.h"
#include "verthys.h"
#include "process_sandbox.h"   /* SANDBOX_ATTR_*（worker 位掩码语义） */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>            /* remove */

#define DCL_VERTHYS "test_dcl.verthys"
#define DCL_PW    "dcl-pass-2026"
#define DCL_PW_LEN (sizeof(DCL_PW) - 1)
/* PERFORMANCE 预设：固定 Argon2id 参数（跳过校准），创建时延可控 */
#define DCL_PRESET VERTHYS_PRESET_PERFORMANCE

/* 路径名（仅用于失败诊断输出，与 VerthysDefensePath 下标对应） */
static const char *dcl_path_names[VERTHYS_DEFENSE_PATH_COUNT] = {
    "SUSPEND_BYPASS", "MEM_DUMP", "HIBERNATION", "IAT_HOOK",
    "DLL_HIJACK", "PROCESS_READ", "CROSS_DEVICE",
};

/*
 * 模拟 worker 在加载本 DLL 之前已应用的进程级 mitigation policy
 * 位掩码（verthys-worker apply_process_sandbox 同款全集）。
 * 本接口仅做记录注入，不在测试进程内真实施加策略。
 */
static void dcl_notify_worker_sandbox(void)
{
    (void)Verthys_NotifySandboxAttrs(SANDBOX_ATTR_ALL);
}

/* 失败诊断：打印非 BLOCKED 路径明细（定位 7/7 断言失败根因） */
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

/* ================== 1. 参数校验 ================== */

TEST(dcl_status_invalid_params)
{
    VerthysSecurityStatus st;
    VerthysHandle h;

    /* NULL 句柄 */
    CHECK_EQ(Verthys_GetSecurityStatus(NULL, &st), VERTHYS_ERR_INVALID);

    /* NULL 出参 */
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);
    CHECK_EQ(Verthys_GetSecurityStatus(h, NULL), VERTHYS_ERR_INVALID);
    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    return 0;
}

/* ================== 2. BOOT 语义回归 ================== */

/*
 * Verthys_Init 成功 ⟹ BOOT 校验通过（任一 FAILED 路径拒绝启动）。
 * RUNTIME 复检必须维持该不变式：状态机仅在解锁/锁定间迁移，
 * 防御模块初始化后不可逆退化（ FAILED 只能来自 init 失败）。
 */
TEST(dcl_boot_check_no_failed_paths)
{
    VerthysHandle h;
    VerthysSecurityStatus st;

    dcl_notify_worker_sandbox();
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_OK);
    CHECK_EQ(st.failed_count, 0u);
    CHECK_EQ(st.all_critical_blocked, 1);
    /* BOOT 已执行：无 NOT_CHECKED；无 FAILED ⟹ 每条路径 ∈ {BLOCKED, DEGRADED} */
    for (int i = 0; i < VERTHYS_DEFENSE_PATH_COUNT; i++) {
        CHECK(st.path_state[i] == VERTHYS_DEFENSE_BLOCKED ||
              st.path_state[i] == VERTHYS_DEFENSE_DEGRADED);
    }

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    return 0;
}

/* ================== 3. 7/7 BLOCKED（M3 里程碑验收信号） ================== */

TEST(dcl_all_seven_blocked_when_unlocked)
{
    VerthysHandle h;
    VerthysSecurityStatus st;
    VerthysDefenseState mem_dump_baseline;

    remove(DCL_VERTHYS);
    dcl_notify_worker_sandbox();
    CHECK_EQ(Verthys_Init(&h), VERTHYS_OK);

    /* 基线：未挂载容器（无密钥托管）时 MEM_DUMP 的状态 */
    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_OK);
    mem_dump_baseline = st.path_state[VERTHYS_DEFENSE_MEM_DUMP];

    /* V3 创建：密钥组导入 CNG 内核托管（verthys_cng_km_import_batch） */
    CHECK_EQ(Verthys_CreateWithPreset(h, DCL_VERTHYS, DCL_PW, DCL_PW_LEN,
                                    DCL_PRESET), VERTHYS_OK);

    /* 7/7 BLOCKED —— 逐路径显式断言 + 汇总一致性 */
    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_OK);
    dcl_dump_not_blocked(&st);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_SUSPEND_BYPASS], VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_MEM_DUMP],       VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_HIBERNATION],    VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_IAT_HOOK],       VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_DLL_HIJACK],     VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_PROCESS_READ],   VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_CROSS_DEVICE],   VERTHYS_DEFENSE_BLOCKED);
    CHECK_EQ(st.blocked_count, VERTHYS_DEFENSE_PATH_COUNT);
    CHECK_EQ(st.degraded_count, 0u);
    CHECK_EQ(st.failed_count, 0u);
    CHECK_EQ(st.all_critical_blocked, 1);
    CHECK_EQ(st.has_degraded, 0);

    /*
     * 实时性：Lock 收口销毁 CNG 密钥组（verthys_v3_ctx_subsystems_close
     * 第 6 步）→ MEM_DUMP 回落至本测试基线。证明状态为每次调用活复检，
     * 而非 BOOT 缓存快照；同时验证锁定态可查询（进程级状态语义）。
     */
    CHECK_EQ(Verthys_Lock(h), VERTHYS_OK);
    CHECK_EQ(Verthys_GetSecurityStatus(h, &st), VERTHYS_OK);
    CHECK_EQ(st.path_state[VERTHYS_DEFENSE_MEM_DUMP], mem_dump_baseline);

    CHECK_EQ(Verthys_Deinit(h), VERTHYS_OK);
    remove(DCL_VERTHYS);
    return 0;
}
