/*
 * test_runner.c — 测试入口，汇总所有测试文件
 * 新增测试文件后，在此 extern 声明并 RUN_TEST 即可。
 */
#include "verthys_test.h"
#include "verthys_crypto.h"
#include <string.h>
#include <stdlib.h>

/* ★ WP-13（K-1）：状态快照实现 — Windows API 收敛于本翻译单元 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include "emergency.h"

int g_tests_passed = 0;
int g_tests_failed = 0;

/* test_init.c */
TEST(init_deinit_roundtrip);
TEST(init_rejects_null);
TEST(deinit_rejects_null);
TEST(init_independent_handles);

/* test_crypto.c */
TEST(aead_roundtrip);
TEST(aead_tamper_fails);
TEST(aead_tamper_mac_fails);
TEST(aead_wrong_key_fails);
TEST(aead_wrong_ad_fails);
TEST(random_bytes_unique);
TEST(aead_empty_plaintext);

/* test_keymanager.c */
TEST(master_key_derive_deterministic);
TEST(master_key_password_sensitive);
TEST(master_key_salt_sensitive);
TEST(master_key_rejects_null);
TEST(dek_generate_random);
TEST(dek_wrap_roundtrip);
TEST(dek_unwrap_wrong_master_fails);
TEST(dek_unwrap_tampered_fails);
TEST(dek_unwrap_tampered_mac_fails);
TEST(dek_wrap_nonce_unique);
TEST(record_key_derive_deterministic);
TEST(record_key_id_and_dek_sensitive);
TEST(record_key_rejects_null);

/* test_verthys_format.c */
TEST(format_roundtrip_single);
TEST(format_roundtrip_empty);
TEST(format_roundtrip_multiple);
TEST(format_bad_magic_rejected);
TEST(format_bad_version_rejected);
TEST(format_too_small_rejected);
TEST(format_wrong_master_fails);
TEST(format_tampered_metadata_fails);
TEST(format_tampered_header_mac_fails);
TEST(format_wrong_dek_fails);
TEST(format_tampered_data_block_fails);
TEST(format_tampered_mac_fails);
TEST(format_write_rejects_null);

/* test_verthys_api.c */
TEST(api_full_roundtrip);
TEST(api_delete_record);
TEST(api_get_not_found);
TEST(api_wrong_password);
TEST(api_rate_limit_exponential);
TEST(api_operations_require_unlock);
TEST(api_locked_after_lock);
TEST(api_invalid_params);
TEST(api_add_delete_add_cycle);
TEST(api_empty_password);
TEST(api_lock_unlock_same_file);
TEST(api_create_with_preset_balanced);
TEST(api_create_with_preset_secure);
TEST(api_create_with_preset_exists);
TEST(api_create_with_preset_invalid);
TEST(api_create_with_preset_survives_cp);

/* test_verthys_export.c */
TEST(cp_then_unlock_new);
TEST(cp_wrong_old);
TEST(cp_preserves_records);
TEST(cp_invalid_params);
TEST(cp_requires_unlock);
TEST(export_import_roundtrip);
TEST(export_separate_password);
TEST(export_invalid_params);
TEST(export_requires_unlock);
TEST(import_merges_records);
TEST(import_wrong_password);
TEST(import_bad_file);
TEST(import_invalid_params);
TEST(import_requires_unlock);

/* ★ 模块化重构：test_anti_debug.c（v1 反调试，死代码）随 runtime/ 删除清单移除 */

/* test_memory_safety.c */
TEST(mem_lock_zeroes_keys);
TEST(mem_lock_frees_records);
TEST(mem_lock_retains_file_path);
TEST(mem_failed_unlock_keeps_locked);
TEST(mem_failed_unlock_bad_format);
TEST(mem_deinit_from_unlocked);
TEST(mem_deinit_from_locked);
TEST(mem_deinit_from_uninit);
/* ★ P0 缺陷1企业级方案 — UAF 回归测试（8 项） */
TEST(mem_uaf_getrecord_populates_borrow_cache);
TEST(mem_uaf_addrecord_invalidates_cache);
TEST(mem_uaf_deleterecord_invalidates_cache);
TEST(mem_uaf_deleterecords_invalidates_cache);
TEST(mem_uaf_flush_invalidates_cache);
TEST(mem_uaf_import_invalidates_cache);
TEST(mem_uaf_changepassword_invalidates_cache);
TEST(mem_uaf_getrecord_overwrites_previous_borrow);

/* test_format_fuzz.c */
TEST(fuzz_empty_file);
TEST(fuzz_too_small);
TEST(fuzz_all_zero_file);
TEST(fuzz_random_garbage);
TEST(fuzz_bit_flip_magic);
TEST(fuzz_bit_flip_version);
TEST(fuzz_truncated_header);
TEST(fuzz_truncated_metadata);
TEST(fuzz_bit_flip_metadata);
TEST(fuzz_bit_flip_mac);
TEST(fuzz_bit_flip_index);
TEST(fuzz_bit_flip_data_block);
TEST(fuzz_extended_file);

/* test_key_separation.c — ★ 方案 §8.2：CNG 内核托管密钥（3 项） */
TEST(keysep_aead_roundtrip);
TEST(keysep_commit_sleep_enforced);
TEST(keysep_purge_invalidates);

/* test_emergency.c — ★ 方案 §8.2：应急响应分级（3 项） */
TEST(emergency_telemetry_no_trigger);
TEST(emergency_degrade_requires_window_threshold);
TEST(emergency_handler_swap_and_null);

/* test_integrity_verify.c — ★ 方案 §8.2：构建期签名验签（2 项） */
TEST(integrity_verify_unconfigured_passes);
TEST(integrity_init_idempotent);

/* test_txn_recovery_inject.c — ★ 方案 §8.2：事务半写/损坏故障注入（3 项） */
TEST(inject_sb_ciphertext_bitflip_rejected);
TEST(inject_taillog_overwrite_still_unlockable);
TEST(inject_bad_magic_rejected);

/* test_perf_prefetch.c — ★ P0 缺陷2企业级方案：性能回归测试（8 项） */
TEST(perf_balanced_enables_warm_cache);
TEST(perf_secure_disables_warm_cache);
TEST(perf_warm_cache_hit_on_second_unlock);
TEST(perf_corrupt_cache_falls_back_to_disk);
TEST(perf_corrupt_cache_header_skips_cache);
TEST(perf_diagnostics_metrics_complete);
TEST(perf_no_cache_cold_start);
TEST(perf_argon2_drift_metrics_collected);
TEST(perf_baseline_unlock_write_read);

/* test_final_repair.c — ★ 最终修复方案 §6.1 回归测试（12 项） */
TEST(repair_pool_extend_boundary);
TEST(repair_lsm_large_insert);
TEST(repair_changepw_fail_rollback);
TEST(repair_large_file_offset);
TEST(repair_v1_mac_offset_overflow);
TEST(repair_vfmt_write_fail_cleanup);
TEST(repair_vsb_txn_v3_rollback);
TEST(repair_tail_log_commit_regression);
TEST(repair_export_too_many);
TEST(repair_name_len_clamp);
TEST(repair_thread_shutdown_cycles);

/* test_flatcc_demo.c — ★ WP-0 验收：vendored flatcc 工具链全链路（demo schema） */
TEST(flatcc_demo_roundtrip);
TEST(flatcc_demo_tamper_rejected);

/* test_cng_kernel.c — ★ WP-1 验收：CNG 内核托管全量接线 */
TEST(cng_aead_roundtrip);
TEST(cng_aead_init_contract);
TEST(cng_aead_empty_plaintext);
TEST(cng_aead_nonce_unique_monotonic);
TEST(cng_aead_nonce_counter_restore);
TEST(cng_aead_tamper_rejected);
TEST(cng_aead_wrong_key_rejected);
TEST(cng_aead_destroy_invalidates);
TEST(cng_aead_null_params_rejected);
TEST(km_batch_import_roundtrip);
TEST(km_import_wrong_mek_rolls_back);
TEST(km_wrapped_role_binding);
TEST(km_reimport_replaces_handles);
TEST(km_null_params_rejected);
TEST(km_global_handle_tracking);

/* test_secure_allocator.c — ★ WP-7 验收：安全分配器 + 全局内存预算记账 */
TEST(sec_alloc_basic_roundtrip);
TEST(sec_alloc_guard_pages);
TEST(sec_alloc_locked);
TEST(sec_alloc_budget_reject_and_reclaim);
TEST(sec_alloc_error_paths);
TEST(sec_alloc_destroy_releases_all);

/* test_v3_container.c — ★ WP-2 验收：V3 超级块（多副本 + 法定人数 + 事务） */
TEST(v3sb_init_new_defaults);
TEST(v3sb_init_rejects_null);
TEST(v3sb_serialize_parse_roundtrip);
TEST(v3sb_parse_idempotent);
TEST(v3sb_hmac_tamper_rejected);
TEST(v3sb_hmac_wrong_key_rejected);
TEST(v3sb_parse_garbage_rejected);
TEST(v3sb_serialize_null_and_overflow_rejected);
TEST(v3sb_replica_io_roundtrip);
TEST(v3sb_replica_bad_frame_rejected);
TEST(v3sb_commit_quorum_roundtrip);
TEST(v3sb_quorum_txid_advances);
TEST(v3sb_quorum_one_replica_corrupt);
TEST(v3sb_quorum_two_replicas_corrupt);
TEST(v3sb_quorum_three_replicas_corrupt);
TEST(v3sb_quorum_zero_replicas_written);
TEST(v3sb_quorum_valid_but_split);
TEST(v3sb_quorum_txid_majority_wins);
TEST(v3sb_commit_fail_injection);
TEST(v3sb_txn_commit_rollback);

/* test_v3_partition.c — ★ WP-2 验收：V3 分区管理（独立 AEAD 密钥 + 分区表持久化） */
TEST(v3part_create_defaults);
TEST(v3part_create_rejects_invalid);
TEST(v3part_encrypt_decrypt_roundtrip);
TEST(v3part_decrypt_txid_binding_rejected);
TEST(v3part_tamper_rejected);
TEST(v3part_key_isolation);
TEST(v3part_null_params_rejected);
TEST(v3part_grow_strategy);
TEST(v3part_load_nonce_no_reuse);
TEST(v3part_load_rejects_invalid);
TEST(v3part_table_add_find_limits);
TEST(v3part_table_save_load_roundtrip);
TEST(v3part_table_load_tamper_rejected);
TEST(v3part_table_load_empty_region_rejected);
TEST(v3part_table_save_rejects_invalid);

/* test_v3_lsm.c — ★ WP-4 验收：V3 LSM 索引（MemTable + SSTable + Compaction） */
TEST(v3lsm_open_close_roundtrip);
TEST(v3lsm_put_get_roundtrip);
TEST(v3lsm_put_overwrite);
TEST(v3lsm_delete_tombstone);
TEST(v3lsm_flush_to_sstable);
TEST(v3lsm_reopen_persistence);
TEST(v3lsm_wal_crash_recovery);
TEST(v3lsm_compaction_l0_merge);
TEST(v3lsm_compaction_shadowing);
TEST(v3lsm_compaction_tombstone);
TEST(v3lsm_manifest_tamper_rejected);
TEST(v3lsm_get_notfound_and_invalid);
TEST(v3lsm_null_params_rejected);

/* test_v3_extent.c — ★ WP-3 验收：V3 内容寻址 Extent（去重 + 完整性） */
TEST(v3ext_hash_basics);
TEST(v3ext_index_init_and_find);
TEST(v3ext_put_get_roundtrip);
TEST(v3ext_put_empty_plaintext);
TEST(v3ext_dedup_no_rewrite);
TEST(v3ext_release_refcount_and_gc);
TEST(v3ext_resource_limit_rejected);
TEST(v3ext_locked_rejected);
TEST(v3ext_data_tamper_rejected);
TEST(v3ext_block_move_rejected);
TEST(v3ext_wrong_partition_key_rejected);
TEST(v3ext_index_save_load_roundtrip);
TEST(v3ext_index_load_nonce_rollback_rejected);
TEST(v3ext_index_tamper_rejected);
TEST(v3ext_index_load_empty_region_rejected);
TEST(v3ext_null_params_rejected);

/* test_v3_lifecycle.c — ★ WP-5 验收：V3 生命周期全链路 + 流水线 + 温缓存 + WAL 崩溃恢复 */
TEST(v3life_full_chain_roundtrip);
TEST(v3life_cp_old_password_rejected);
TEST(v3life_container_info_v3);
TEST(v3life_verify_integrity_tamper);
TEST(v3life_scan_family_v3);
TEST(v3life_pipeline_fail_mask_stages);
TEST(v3life_unlock_minimal_first);
TEST(v3life_warmcache_hit_miss_tamper);
TEST(v3life_crash_uncommitted_discarded);
TEST(v3life_crash_committed_replayed);
TEST(v3life_crash_prepare_only_replayed);
TEST(arekey_trigger_matrix);
TEST(arekey_rotate_full_cycle);
TEST(arekey_degrade_force_persist);
TEST(arekey_crash_orphan_frame);
TEST(arekey_crash_after_commit);

/* test_v3_property.c — ★ V3 升级 WP-12：属性测试（自研 harness：
 * 随机序列 + 不变式断言，种子可复现）+ 缺陷②/②b 定向回归 */
TEST(prop_lsm_insert_find_delete);
TEST(prop_extent_refcount_conservation);
TEST(prop_txn_commit_rollback_consistency);
TEST(prop_txn_crash_no_resurrection);
TEST(prop_txn_rollback_delete_restores_original);
TEST(prop_txn_crash_discard_delete_restores_original);

/* test_auto_rekey.c — ★ V3 升级 WP-6：自动密钥轮换（见 test_v3_lifecycle 组） */

/* test_runtime_hash.c — ★ V3 升级 WP-8：运行时函数级哈希校验（.rhat 真表） */
TEST(rhat_table_configured);
TEST(rhat_real_table_scan_clean);
TEST(rhat_lookup_covered);
TEST(rhat_virtualprotect_patch_detected);
TEST(rhat_overlay_install_detect_clear);
TEST(rhat_verify_periodic_clean_state);

/* test_syscall_direct.c — ★ V3 升级 WP-9：直接系统调用传输
 * （SSN 排序法提取 + W^X stub + 降级；激活/降级两态均须过） */
TEST(scd_init_idempotent);
TEST(scd_process_query_matches_ntdll);
TEST(scd_system_query_basic_info);
TEST(scd_error_code_passthrough);
TEST(scd_detector_wiring_clean);

/* test_defense_closure.c — ★ V3 升级 WP-11：防御闭环 7 路径状态查询
 * （M3 里程碑验收信号：解锁态 7/7 BLOCKED 运行时验证） */
TEST(dcl_status_invalid_params);
TEST(dcl_boot_check_no_failed_paths);
TEST(dcl_all_seven_blocked_when_unlocked);

/* ★ 最终修复方案 §6.2：argv 过滤器——`verthys_tests.exe <子串>` 仅运行
 * 名称含该子串的测试（故障定位用；无参数时全量运行，行为不变） */
static int g_filter_active = 0;
static char g_filter[128] = {0};
static int g_argc = 0;
static char **g_argv = NULL;

int test_filter_match(const char *test_name)
{
    if (!g_filter_active) return 1;
    return strstr(test_name, g_filter) != NULL;
}

/* ★ §6.2 扩展：argv[2..] 作为额外 OR 过滤器（多组联合运行） */
int test_filter_match_extra(const char *test_name)
{
    if (!g_filter_active) return 1;
    if (strstr(test_name, g_filter) != NULL) return 1;
    for (int i = 2; i < g_argc; i++) {
        if (strstr(test_name, g_argv[i]) != NULL) return 1;
    }
    return 0;
}

static void test_filter_save(int argc, char **argv)
{
    g_argc = argc;
    g_argv = argv;
}

/* ------------------------------------------------------------------ *
 * ★ 测试文件沙箱（2026-09-19 根治：测试残留文件统一管理与自动清除）
 *
 * 问题：各测试用相对路径创建临时文件（test_*.verthys / *.idx_cache /
 * WAL / manifest 等），测试进程的 CWD 决定落盘位置——从项目根直接运行
 * verthys_tests.exe 时，残留文件散落源码树根目录。
 *
 * 方案：main() 入口将 CWD 切换到构建树内专属沙箱目录
 *   <exe_dir>\test_scratch_<pid>
 * 全部测试的相对路径文件统一收口于此；正常退出时递归删除沙箱。
 * 硬崩溃（清理无法执行）时沙箱残留于 git-ignored 构建树内供事后取证，
 * 随 -Clean / 构建目录删除一并消失。
 *
 * 安全性：已核实全部测试无运行期源码树相对路径读取（fopen("../..")）
 * 与子进程派生，切换 CWD 不影响任何现有用例。
 * ------------------------------------------------------------------ */
static char g_scratch_cwd_backup[MAX_PATH];
static char g_scratch_dir[MAX_PATH];

/* 递归删除目录（仅沙箱自用） */
static void scratch_rm_rf(const char *dir)
{
    char pattern[MAX_PATH + 8];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    h = FindFirstFileA(pattern, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            char child[MAX_PATH];
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            snprintf(child, sizeof(child), "%s\\%s", dir, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                scratch_rm_rf(child);
            else
                DeleteFileA(child);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(dir);
}

/* atexit 清理：先切回原 CWD（进程无法删除自己的工作目录），再删沙箱 */
static void scratch_cleanup(void)
{
    if (g_scratch_dir[0] == '\0') return;
    if (g_scratch_cwd_backup[0] != '\0')
        SetCurrentDirectoryA(g_scratch_cwd_backup);
    scratch_rm_rf(g_scratch_dir);
    printf("[sandbox] test scratch dir cleaned\n");
    fflush(stdout);
    g_scratch_dir[0] = '\0';
}

/* 建立沙箱并切换 CWD；失败回退旧行为（绝不阻断测试本身） */
static void scratch_setup(void)
{
    char exe[MAX_PATH];
    char *slash;

    if (GetModuleFileNameA(NULL, exe, MAX_PATH) == 0) return;
    slash = strrchr(exe, '\\');
    if (slash == NULL) return;
    *slash = '\0';
    snprintf(g_scratch_dir, sizeof(g_scratch_dir), "%s\\test_scratch_%lu",
             exe, (unsigned long)GetCurrentProcessId());

    if (GetCurrentDirectoryA(sizeof(g_scratch_cwd_backup),
                             g_scratch_cwd_backup) == 0)
        return;

    /* 清掉同 PID 复用的历史残留，确保沙箱内无过期状态：
     * 陈旧 idx_cache 会污染温缓存命中类用例的冷启动前提 */
    scratch_rm_rf(g_scratch_dir);
    if (!CreateDirectoryA(g_scratch_dir, NULL)) {
        printf("[sandbox] !! scratch create failed (fall back to CWD, "
               "tests continue): %s\n", g_scratch_dir);
        fflush(stdout);
        g_scratch_dir[0] = '\0';
        return;
    }
    if (!SetCurrentDirectoryA(g_scratch_dir)) {
        printf("[sandbox] !! scratch chdir failed (fall back to CWD, "
               "tests continue): %s\n", g_scratch_dir);
        fflush(stdout);
        g_scratch_dir[0] = '\0';
        return;
    }
    atexit(scratch_cleanup);
    printf("[sandbox] test scratch dir: %s\n", g_scratch_dir);
    fflush(stdout);
}

/* ------------------------------------------------------------------ *
 * ★ WP-13（K-1）：测试间状态快照实现
 *
 * 采集维度（手册 §5 WP-13 步骤1 全量落地）：
 *   - 线程数  ：CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) 枚举本 PID
 *   - 句柄数  ：GetProcessHandleCount（内核句柄）
 *   - GDI 句柄：GetGuiResources（GR_GDIOBJECTS）
 *   - emergency：emergency_get_signals / emergency_is_triggered
 * ------------------------------------------------------------------ */
static long count_process_threads(void)
{
    DWORD pid = GetCurrentProcessId();
    long count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) count++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return count;
}

void test_state_capture(TestStateSnapshot *snap)
{
    if (snap == NULL) return;
    snap->threads = count_process_threads();

    DWORD handles = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &handles)) {
        snap->handles = -1;
    } else {
        snap->handles = (long)handles;
    }

    snap->gdi_handles = (long)GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);

    snap->emergency_signals = (unsigned long)emergency_get_signals();
    snap->emergency_triggered = emergency_is_triggered();
}

void test_state_report_diff(const char *test_name,
                            const TestStateSnapshot *before,
                            const TestStateSnapshot *after)
{
    if (test_name == NULL || before == NULL || after == NULL) return;

    long d_threads = after->threads - before->threads;
    long d_handles = after->handles - before->handles;
    long d_gdi     = after->gdi_handles - before->gdi_handles;
    unsigned long sig = after->emergency_signals;
    int trig = after->emergency_triggered;

    if (d_threads == 0 && d_handles == 0 && d_gdi == 0 && sig == 0 && trig == 0) {
        return; /* 快照零差异 — 干净 */
    }

    printf("  [LEAK?] %s: threads %+ld, handles %+ld, gdi %+ld, "
           "emergency_signals=0x%lx, triggered=%d\n",
           test_name, d_threads, d_handles, d_gdi, sig, trig);
    fflush(stdout);
}

static TestStateSnapshot g_baseline_snapshot;
static int g_baseline_valid = 0;

void test_state_checkpoint(const char *group_label)
{
    TestStateSnapshot now;
    test_state_capture(&now);

    if (!g_baseline_valid) {
        g_baseline_snapshot = now;
        g_baseline_valid = 1;
    }

    printf("[ CHECKPOINT ] %s: threads=%ld (baseline %+ld), handles=%ld "
           "(baseline %+ld), emergency_signals=0x%lx\n",
           group_label, now.threads, now.threads - g_baseline_snapshot.threads,
           now.handles, now.handles - g_baseline_snapshot.handles,
           now.emergency_signals);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    /* ★ 沙箱先行：CWD 切换必须先于任何测试执行（含过滤参数解析输出），
     * 保证所有相对路径临时文件统一落入构建树内沙箱并在结束时清除 */
    scratch_setup();

    test_filter_save(argc, argv);
    if (argc > 1 && argv[1] != NULL && argv[1][0] != '\0') {
        g_filter_active = 1;
        strncpy_s(g_filter, sizeof(g_filter), argv[1], _TRUNCATE);
        printf("=== filter: '%s' ===\n", g_filter);
    }
    /*
     * 入口文件单一职责（  第 1 节）
     *
     * 本入口仅涉及 3 项允许职责：
     *   1. 环境初始化 — verthys_crypto_init() 初始化密码库运行时
     *   2. 控制器派发 — RUN_TEST 宏调用各测试函数
     *   3. 结果汇总 — TEST_SUMMARY 宏输出统计
     *
     * 红线遵守：无直接 printf/fprintf（通过 verthys_test.h 宏封装输出）
     */
    TEST_LOG("=== Verthys Phase 1 Tests ===\n\n");

    /* 环境初始化：底层密码库（crypto 测试依赖） */
    if (verthys_crypto_init() != 0) {
        TEST_FATAL("verthys_crypto_init failed\n");
    }

    /* ★ WP-8：rhat 组置于全量首组——真表等价性（构建期文件哈希 ≡ 运行期
     * 内存哈希）若断裂，此处先出显式 CHECK 失败，早于任何 Verthys_Unlock
     * 解锁路径的 KILL 应急（进程存活，诊断信息完整）。 */
    RUN_TEST(rhat_table_configured);
    RUN_TEST(rhat_real_table_scan_clean);
    RUN_TEST(rhat_lookup_covered);
    RUN_TEST(rhat_virtualprotect_patch_detected);
    RUN_TEST(rhat_overlay_install_detect_clear);
    RUN_TEST(rhat_verify_periodic_clean_state);
    test_state_checkpoint("runtime_hash");

    /* ★ WP-9：直接系统调用传输组——紧随 rhat 组：传输正确性是后续
     * 全部检测器（anti_debug/memory_guard）行为的底层前提。 */
    RUN_TEST(scd_init_idempotent);
    RUN_TEST(scd_process_query_matches_ntdll);
    RUN_TEST(scd_system_query_basic_info);
    RUN_TEST(scd_error_code_passthrough);
    RUN_TEST(scd_detector_wiring_clean);
    test_state_checkpoint("syscall_direct");

    /* ★ V3 升级 WP-11：防御闭环 7 路径状态查询（7/7 BLOCKED 运行时验证） */
    RUN_TEST(dcl_status_invalid_params);
    RUN_TEST(dcl_boot_check_no_failed_paths);
    RUN_TEST(dcl_all_seven_blocked_when_unlocked);
    test_state_checkpoint("defense_closure");

    RUN_TEST(init_deinit_roundtrip);
    RUN_TEST(init_rejects_null);
    RUN_TEST(deinit_rejects_null);
    RUN_TEST(init_independent_handles);
    test_state_checkpoint("init");

    RUN_TEST(aead_roundtrip);
    RUN_TEST(aead_tamper_fails);
    RUN_TEST(aead_tamper_mac_fails);
    RUN_TEST(aead_wrong_key_fails);
    RUN_TEST(aead_wrong_ad_fails);
    RUN_TEST(random_bytes_unique);
    RUN_TEST(aead_empty_plaintext);
    test_state_checkpoint("crypto");

    /* keymanager 测试含 Argon2id 64MiB/3iter，单次约 0.5–1s */
    RUN_TEST(master_key_derive_deterministic);
    RUN_TEST(master_key_password_sensitive);
    RUN_TEST(master_key_salt_sensitive);
    RUN_TEST(master_key_rejects_null);
    RUN_TEST(dek_generate_random);
    RUN_TEST(dek_wrap_roundtrip);
    RUN_TEST(dek_unwrap_wrong_master_fails);
    RUN_TEST(dek_unwrap_tampered_fails);
    RUN_TEST(dek_unwrap_tampered_mac_fails);
    RUN_TEST(dek_wrap_nonce_unique);
    RUN_TEST(record_key_derive_deterministic);
    RUN_TEST(record_key_id_and_dek_sensitive);
    RUN_TEST(record_key_rejects_null);
    test_state_checkpoint("keymanager");

    RUN_TEST(format_roundtrip_single);
    RUN_TEST(format_roundtrip_empty);
    RUN_TEST(format_roundtrip_multiple);
    RUN_TEST(format_bad_magic_rejected);
    RUN_TEST(format_bad_version_rejected);
    RUN_TEST(format_too_small_rejected);
    RUN_TEST(format_wrong_master_fails);
    RUN_TEST(format_tampered_metadata_fails);
    RUN_TEST(format_tampered_header_mac_fails);
    RUN_TEST(format_wrong_dek_fails);
    RUN_TEST(format_tampered_data_block_fails);
    RUN_TEST(format_tampered_mac_fails);
    RUN_TEST(format_write_rejects_null);
    test_state_checkpoint("format");

    /* verthys_api 测试含 Argon2id 64MiB/3iter，单次约 0.5–1s */
    RUN_TEST(api_full_roundtrip);
    RUN_TEST(api_delete_record);
    RUN_TEST(api_get_not_found);
    RUN_TEST(api_wrong_password);
    RUN_TEST(api_rate_limit_exponential);
    RUN_TEST(api_operations_require_unlock);
    RUN_TEST(api_locked_after_lock);
    RUN_TEST(api_invalid_params);
    RUN_TEST(api_add_delete_add_cycle);
    RUN_TEST(api_empty_password);
    RUN_TEST(api_lock_unlock_same_file);
    RUN_TEST(api_create_with_preset_balanced);
    RUN_TEST(api_create_with_preset_secure);
    RUN_TEST(api_create_with_preset_exists);
    RUN_TEST(api_create_with_preset_invalid);
    RUN_TEST(api_create_with_preset_survives_cp);
    test_state_checkpoint("verthys_api");

    /* Export/Import/ChangePassword 测试含 Argon2id 64MiB/3iter */
    RUN_TEST(cp_then_unlock_new);
    RUN_TEST(cp_wrong_old);
    RUN_TEST(cp_preserves_records);
    RUN_TEST(cp_invalid_params);
    RUN_TEST(cp_requires_unlock);
    RUN_TEST(export_import_roundtrip);
    RUN_TEST(export_separate_password);
    RUN_TEST(export_invalid_params);
    RUN_TEST(export_requires_unlock);
    RUN_TEST(import_merges_records);
    RUN_TEST(import_wrong_password);
    RUN_TEST(import_bad_file);
    RUN_TEST(import_invalid_params);
    RUN_TEST(import_requires_unlock);
    test_state_checkpoint("export_import");

    /* 内存安全测试 */
    RUN_TEST(mem_lock_zeroes_keys);
    RUN_TEST(mem_lock_frees_records);
    RUN_TEST(mem_lock_retains_file_path);
    RUN_TEST(mem_failed_unlock_keeps_locked);
    RUN_TEST(mem_failed_unlock_bad_format);
    RUN_TEST(mem_deinit_from_unlocked);
    RUN_TEST(mem_deinit_from_locked);
    RUN_TEST(mem_deinit_from_uninit);

    /* ★ P0 缺陷1企业级方案 — UAF 回归测试（查询→修改→旧指针失效） */
    RUN_TEST(mem_uaf_getrecord_populates_borrow_cache);
    RUN_TEST(mem_uaf_addrecord_invalidates_cache);
    RUN_TEST(mem_uaf_deleterecord_invalidates_cache);
    RUN_TEST(mem_uaf_deleterecords_invalidates_cache);
    RUN_TEST(mem_uaf_flush_invalidates_cache);
    RUN_TEST(mem_uaf_import_invalidates_cache);
    RUN_TEST(mem_uaf_changepassword_invalidates_cache);
    RUN_TEST(mem_uaf_getrecord_overwrites_previous_borrow);
    test_state_checkpoint("memory_safety");

    /* 文件格式变异 / 篡改检测测试 */
    RUN_TEST(fuzz_empty_file);
    RUN_TEST(fuzz_too_small);
    RUN_TEST(fuzz_all_zero_file);
    RUN_TEST(fuzz_random_garbage);
    RUN_TEST(fuzz_bit_flip_magic);
    RUN_TEST(fuzz_bit_flip_version);
    RUN_TEST(fuzz_truncated_header);
    RUN_TEST(fuzz_truncated_metadata);
    RUN_TEST(fuzz_bit_flip_metadata);
    RUN_TEST(fuzz_bit_flip_mac);
    RUN_TEST(fuzz_bit_flip_index);
    RUN_TEST(fuzz_bit_flip_data_block);
    RUN_TEST(fuzz_extended_file);
    test_state_checkpoint("format_fuzz");

    /* ★ P0 缺陷2企业级方案 — 性能回归测试（缓存命中/损坏/慢IO/温启动） */
    RUN_TEST(perf_balanced_enables_warm_cache);
    RUN_TEST(perf_secure_disables_warm_cache);
    RUN_TEST(perf_warm_cache_hit_on_second_unlock);
    RUN_TEST(perf_corrupt_cache_falls_back_to_disk);
    RUN_TEST(perf_corrupt_cache_header_skips_cache);
    RUN_TEST(perf_diagnostics_metrics_complete);
    RUN_TEST(perf_no_cache_cold_start);
    RUN_TEST(perf_argon2_drift_metrics_collected);
    RUN_TEST(perf_baseline_unlock_write_read);
    test_state_checkpoint("perf");

    /* ★ 方案 §8.2：CNG 内核托管密钥测试 */
    RUN_TEST(keysep_aead_roundtrip);
    RUN_TEST(keysep_commit_sleep_enforced);
    RUN_TEST(keysep_purge_invalidates);
    test_state_checkpoint("key_separation");

    /* ★ 方案 §8.2：应急响应分级测试 */
    RUN_TEST(emergency_telemetry_no_trigger);
    RUN_TEST(emergency_degrade_requires_window_threshold);
    RUN_TEST(emergency_handler_swap_and_null);
    test_state_checkpoint("emergency");

    /* ★ 方案 §8.2：构建期签名验签测试 */
    RUN_TEST(integrity_verify_unconfigured_passes);
    RUN_TEST(integrity_init_idempotent);
    test_state_checkpoint("integrity");

    /* ★ 方案 §8.2：事务半写/损坏故障注入测试 */
    RUN_TEST(inject_sb_ciphertext_bitflip_rejected);
    RUN_TEST(inject_taillog_overwrite_still_unlockable);
    RUN_TEST(inject_bad_magic_rejected);
    test_state_checkpoint("txn_inject");

    /* ★ 最终修复方案 §6.1 回归测试（12 项） */
    RUN_TEST(repair_pool_extend_boundary);
    RUN_TEST(repair_lsm_large_insert);
    RUN_TEST(repair_changepw_fail_rollback);
    RUN_TEST(repair_large_file_offset);
    RUN_TEST(repair_v1_mac_offset_overflow);
    RUN_TEST(repair_vfmt_write_fail_cleanup);
    RUN_TEST(repair_vsb_txn_v3_rollback);
    RUN_TEST(repair_tail_log_commit_regression);
    RUN_TEST(repair_export_too_many);
    RUN_TEST(repair_name_len_clamp);
    RUN_TEST(repair_thread_shutdown_cycles);
    test_state_checkpoint("final_repair");

    /* ★ WP-0 验收：vendored flatcc 工具链（schema codegen + flatccrt 编解码闭环） */
    RUN_TEST(flatcc_demo_roundtrip);
    RUN_TEST(flatcc_demo_tamper_rejected);
    test_state_checkpoint("flatcc_demo");

    /* ★ WP-1 验收：CNG 内核托管（AEAD 封装层 + 密钥组生命周期） */
    RUN_TEST(cng_aead_roundtrip);
    RUN_TEST(cng_aead_init_contract);
    RUN_TEST(cng_aead_empty_plaintext);
    RUN_TEST(cng_aead_nonce_unique_monotonic);
    RUN_TEST(cng_aead_nonce_counter_restore);
    RUN_TEST(cng_aead_tamper_rejected);
    RUN_TEST(cng_aead_wrong_key_rejected);
    RUN_TEST(cng_aead_destroy_invalidates);
    RUN_TEST(cng_aead_null_params_rejected);
    RUN_TEST(km_batch_import_roundtrip);
    RUN_TEST(km_import_wrong_mek_rolls_back);
    RUN_TEST(km_wrapped_role_binding);
    RUN_TEST(km_reimport_replaces_handles);
    RUN_TEST(km_null_params_rejected);
    RUN_TEST(km_global_handle_tracking);
    test_state_checkpoint("cng_kernel");

    /* ★ WP-7 验收：安全分配器（隔离堆 + PAGE_GUARD 边界页 + 锁页 + 预算记账） */
    RUN_TEST(sec_alloc_basic_roundtrip);
    RUN_TEST(sec_alloc_guard_pages);
    RUN_TEST(sec_alloc_locked);
    RUN_TEST(sec_alloc_budget_reject_and_reclaim);
    RUN_TEST(sec_alloc_error_paths);
    RUN_TEST(sec_alloc_destroy_releases_all);
    test_state_checkpoint("secure_allocator");

    /* ★ WP-2 验收：V3 超级块（flatcc 序列化 + HMAC + 三副本法定人数 + 事务） */
    RUN_TEST(v3sb_init_new_defaults);
    RUN_TEST(v3sb_init_rejects_null);
    RUN_TEST(v3sb_serialize_parse_roundtrip);
    RUN_TEST(v3sb_parse_idempotent);
    RUN_TEST(v3sb_hmac_tamper_rejected);
    RUN_TEST(v3sb_hmac_wrong_key_rejected);
    RUN_TEST(v3sb_parse_garbage_rejected);
    RUN_TEST(v3sb_serialize_null_and_overflow_rejected);
    RUN_TEST(v3sb_replica_io_roundtrip);
    RUN_TEST(v3sb_replica_bad_frame_rejected);
    RUN_TEST(v3sb_commit_quorum_roundtrip);
    RUN_TEST(v3sb_quorum_txid_advances);
    RUN_TEST(v3sb_quorum_one_replica_corrupt);
    RUN_TEST(v3sb_quorum_two_replicas_corrupt);
    RUN_TEST(v3sb_quorum_three_replicas_corrupt);
    RUN_TEST(v3sb_quorum_zero_replicas_written);
    RUN_TEST(v3sb_quorum_valid_but_split);
    RUN_TEST(v3sb_quorum_txid_majority_wins);
    RUN_TEST(v3sb_commit_fail_injection);
    RUN_TEST(v3sb_txn_commit_rollback);
    test_state_checkpoint("v3_superblock");

    /* ★ WP-2 验收：V3 分区管理（独立 AEAD 密钥 + nonce 防回退 + 分区表持久化） */
    RUN_TEST(v3part_create_defaults);
    RUN_TEST(v3part_create_rejects_invalid);
    RUN_TEST(v3part_encrypt_decrypt_roundtrip);
    RUN_TEST(v3part_decrypt_txid_binding_rejected);
    RUN_TEST(v3part_tamper_rejected);
    RUN_TEST(v3part_key_isolation);
    RUN_TEST(v3part_null_params_rejected);
    RUN_TEST(v3part_grow_strategy);
    RUN_TEST(v3part_load_nonce_no_reuse);
    RUN_TEST(v3part_load_rejects_invalid);
    RUN_TEST(v3part_table_add_find_limits);
    RUN_TEST(v3part_table_save_load_roundtrip);
    RUN_TEST(v3part_table_load_tamper_rejected);
    RUN_TEST(v3part_table_load_empty_region_rejected);
    RUN_TEST(v3part_table_save_rejects_invalid);
    test_state_checkpoint("v3_partition");

    /* ★ WP-3 验收：V3 内容寻址 Extent（去重 + 引用计数 + GC 标记 +
     * 双重完整性 + 索引持久化 + E-7 防回退） */
    RUN_TEST(v3ext_hash_basics);
    RUN_TEST(v3ext_index_init_and_find);
    RUN_TEST(v3ext_put_get_roundtrip);
    RUN_TEST(v3ext_put_empty_plaintext);
    RUN_TEST(v3ext_dedup_no_rewrite);
    RUN_TEST(v3ext_release_refcount_and_gc);
    RUN_TEST(v3ext_resource_limit_rejected);
    RUN_TEST(v3ext_locked_rejected);
    RUN_TEST(v3ext_data_tamper_rejected);
    RUN_TEST(v3ext_block_move_rejected);
    RUN_TEST(v3ext_wrong_partition_key_rejected);
    RUN_TEST(v3ext_index_save_load_roundtrip);
    RUN_TEST(v3ext_index_load_nonce_rollback_rejected);
    RUN_TEST(v3ext_index_tamper_rejected);
    RUN_TEST(v3ext_index_load_empty_region_rejected);
    RUN_TEST(v3ext_null_params_rejected);
    test_state_checkpoint("v3_extent");

    /* ★ WP-4 验收：V3 LSM 索引（MemTable 跳表 + SSTable + Bloom +
     * WAL 崩溃恢复 + Manifest 原子提交 + 分级 Compaction） */
    RUN_TEST(v3lsm_open_close_roundtrip);
    RUN_TEST(v3lsm_put_get_roundtrip);
    RUN_TEST(v3lsm_put_overwrite);
    RUN_TEST(v3lsm_delete_tombstone);
    RUN_TEST(v3lsm_flush_to_sstable);
    RUN_TEST(v3lsm_reopen_persistence);
    RUN_TEST(v3lsm_wal_crash_recovery);
    RUN_TEST(v3lsm_compaction_l0_merge);
    RUN_TEST(v3lsm_compaction_shadowing);
    RUN_TEST(v3lsm_compaction_tombstone);
    RUN_TEST(v3lsm_manifest_tamper_rejected);
    RUN_TEST(v3lsm_get_notfound_and_invalid);
    RUN_TEST(v3lsm_null_params_rejected);
    test_state_checkpoint("v3_lsm");

    /* ★ WP-5 验收：V3 生命周期全链路（创建→写→读→删→改密→导出→导入重开）
     * + 解锁流水线（fail_mask 逐阶段注入 / MINIMAL_FIRST 渐进式）
     * + 温缓存（命中/未命中/篡改回退）+ WAL 崩溃恢复矩阵（三分支回放规则） */
    RUN_TEST(v3life_full_chain_roundtrip);
    RUN_TEST(v3life_cp_old_password_rejected);
    RUN_TEST(v3life_container_info_v3);
    RUN_TEST(v3life_verify_integrity_tamper);
    RUN_TEST(v3life_scan_family_v3);
    RUN_TEST(v3life_pipeline_fail_mask_stages);
    RUN_TEST(v3life_unlock_minimal_first);
    RUN_TEST(v3life_warmcache_hit_miss_tamper);
    RUN_TEST(v3life_crash_uncommitted_discarded);
    RUN_TEST(v3life_crash_committed_replayed);
    RUN_TEST(v3life_crash_prepare_only_replayed);
    RUN_TEST(arekey_trigger_matrix);
    RUN_TEST(arekey_rotate_full_cycle);
    RUN_TEST(arekey_degrade_force_persist);
    RUN_TEST(arekey_crash_orphan_frame);
    RUN_TEST(arekey_crash_after_commit);
    test_state_checkpoint("v3_lifecycle");

    /* ★ WP-12 验收：属性测试（LSM/Extent/事务三大不变式族 + 回滚耐久性回归） */
    RUN_TEST(prop_lsm_insert_find_delete);
    RUN_TEST(prop_extent_refcount_conservation);
    RUN_TEST(prop_txn_commit_rollback_consistency);
    RUN_TEST(prop_txn_crash_no_resurrection);
    RUN_TEST(prop_txn_rollback_delete_restores_original);
    RUN_TEST(prop_txn_crash_discard_delete_restores_original);
    test_state_checkpoint("v3_property");

    TEST_SUMMARY();
    return g_tests_failed > 0 ? 1 : 0;
}
