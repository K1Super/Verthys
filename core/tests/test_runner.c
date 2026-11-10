/*
 * test_runner.c — 测试入口，汇总所有测试文件
 * 新增测试文件后，在此 extern 声明并 RUN_TEST 即可。
 */
#include "verthys_test.h"
#include "verthys_crypto.h"
#include "vty_lockout.h"
#include "vty_device_root.h"
#include "vty_rollback.h"
#include <string.h>
#include <stdlib.h>

/* 状态快照实现 — Windows API 收敛于本翻译单元 */
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
TEST(format_data_size_guard_rejects);



/* test_export_path_guard.c — Export/Import 路径纵深防御（C 层） */
TEST(pg_export_rejects_dotdot_path);
TEST(pg_export_rejects_system_dir_path);
TEST(pg_import_rejects_system_dir_path);
TEST(pg_export_accepts_temp_path);

/* test_scan_concurrent.c */
TEST(scan_concurrent_readers_vs_writer);

/* test_join_bounded.c — 工作线程有界汇合原语 */
TEST(join_bounded_timeout_then_release);
TEST(join_bounded_exited_thread);
TEST(join_bounded_null_handle);


/* test_format_fuzz.c */
TEST(fuzz_empty_file);
TEST(fuzz_too_small);
TEST(fuzz_all_zero_file);
TEST(fuzz_random_garbage);
TEST(fuzz_bit_flip_magic);
TEST(fuzz_truncated_header);
TEST(fuzz_truncated_metadata);
TEST(fuzz_bit_flip_metadata);
TEST(fuzz_bit_flip_mac);
TEST(fuzz_bit_flip_index);
TEST(fuzz_bit_flip_data_block);
TEST(fuzz_extended_file);


/* test_security_preset.c — 三档预设配置与快照读取（3 项） */
TEST(preset_feature_bits_matrix);
TEST(preset_switch_readback_idempotent);
TEST(preset_snapshot_concurrent_stress);

/* test_emergency.c — 应急响应分级（3 项） */
TEST(emergency_telemetry_no_trigger);
TEST(emergency_degrade_requires_window_threshold);
TEST(emergency_handler_swap_and_null);

/* test_integrity_verify.c — 构建期签名验签（2 项） */
TEST(integrity_verify_unconfigured_passes);
TEST(integrity_verify_startup_cache_replay_invalidate);




/* test_flatcc_demo.c — 验收：vendored flatcc 工具链全链路（demo schema） */
TEST(flatcc_demo_roundtrip);
TEST(flatcc_demo_tamper_rejected);


/* test_secure_allocator.c — 验收：安全分配器 + 全局内存预算记账 */
TEST(sec_alloc_basic_roundtrip);
TEST(sec_alloc_guard_pages);
TEST(sec_alloc_locked);
TEST(sec_alloc_budget_reject_and_reclaim);
TEST(sec_alloc_error_paths);
TEST(sec_alloc_destroy_releases_all);
TEST(sec_alloc_shared_lifecycle);










/* 密钥体系 —— 原语 / 恢复码（test_primitives.c） */
TEST(blake3_known_vectors);
TEST(hkdf_rfc5869_case1);
TEST(hmac_deterministic_and_key_sensitive);
TEST(argon2id_deterministic_and_salt_sensitive);
TEST(kdf_param_floor_rejected);
TEST(wrap_key32_roundtrip_and_tamper);
TEST(recovery_code_roundtrip);
TEST(recovery_checksum_error_rejected);
TEST(recovery_suffix_rejected);
TEST(keyring_serialize_parse_roundtrip);
TEST(keyring_parse_invalid_rejected);
TEST(recovery_slot_seal_open);

/* keyfile 因子（test_keyfile.c） */
TEST(keyfile_generate_parse_roundtrip);
TEST(keyfile_tamper_rejected);
TEST(keyfile_vault_create_open_and_rotate);

/* 容器 —— 头部与密钥槽（test_container.c） */
TEST(header_write_parse_roundtrip);
TEST(header_tamper_rejected);
TEST(slot_seal_serialize_parse);
TEST(slots_parse_all_roundtrip);
TEST(slot_policy_check);
TEST(header_generation_and_minor_frozen);
TEST(data_root_locator_codec);
TEST(segment_header_codec);

/* 公共 API 会话（test_api.c） */
TEST(api_create_save_lock_unlock_roundtrip);
TEST(api_recovery_unlock_roundtrip);
TEST(api_keyfile_create_unlock_disable_roundtrip);
TEST(api_keyfile_recovery_rebind);
TEST(api_keyfile_create_rejects_existing_targets);

/* 数据区与目录树（test_store.c） */
TEST(store_empty_root_binds_uuid_epoch);
TEST(store_put_get_and_cow_snapshot);
TEST(store_split_and_verify);
TEST(store_segment_append_read_and_cursor);
TEST(store_tamper_and_truncate_rejected);

/* 记录仓库（test_repo.c） */
TEST(repo_add_get_delete_and_id_monotonic);
TEST(repo_file_chunk_manifest);
TEST(repo_empty_name_and_tombstone_count);
TEST(repo_system_domain_survives_module_enable_and_delete);
TEST(repo_legacy_security_record_migrates_on_module_enable);

/* 仓库扫描与类型索引（test_repo_scan.c） */
TEST(repo_scan_cursor_and_start_id);
TEST(repo_scan_skips_tombstone_and_type_index);

/* 公共 API 记录链路（test_api_container.c） */
TEST(api_records_roundtrip_and_scan);
TEST(api_list_ids_by_type_and_verify_persist);
TEST(api_add_records_batch_roundtrip);
TEST(api_records_require_unlock);

/* 公共 API 模块 M1（test_api_modules.c） */
TEST(api_modules_roundtrip_and_policy);
TEST(api_module_delete);
TEST(api_recovery_rotate);

/* 公共 API PCR 策略（test_api_pcr.c） */
TEST(api_pcr_policy_roundtrip);
/* 恢复会话容器槽重绑（test_reseal_device.c） */
TEST(reseal_device_roundtrip_restores_normal_unlock);
TEST(reseal_device_rejects_normal_session);
TEST(reseal_device_keyfile_required_and_roundtrip);
/* 公共 API 分片（test_api_content.c） */
TEST(api_content_chunk);
TEST(api_product_e2e);
/* 内部错误码映射（test_error_map.c） */
TEST(error_map_d9_codes_are_distinct);
TEST(error_map_r10_slot_errors_lock_format_policy);

/* 记录 —— 加密与盲索引（test_records.c） */
TEST(record_roundtrip);
TEST(record_aad_binding);
TEST(record_size_guard_rejected);
TEST(name_index_nfkc_and_separation);
TEST(record_plaintext_fallback_forbidden);

/* 分片与清单（test_chunks.c） */
TEST(chunk_roundtrip);
TEST(chunk_aad_binding);
TEST(chunk_id_unlinkable);
TEST(manifest_roundtrip);
TEST(manifest_tamper_rejected);
TEST(large_file_1gb_roundtrip);

/* 库与模块（test_modules.c） */
TEST(vault_create_open_e2e);
TEST(vault_wrong_recovery_rejected);
TEST(vault_rotate_password);
TEST(vault_header_tamper_rejected);
TEST(module_table_create_and_tamper);
TEST(module_m1_enable_rewrite_and_policy);
TEST(module_m1_chunks_rekey);
TEST(module_delete_purge_and_recreate);
TEST(module_lifecycle_disable_then_delete);
TEST(module_recovery_bind_rotate_reseal);
TEST(module_crash_rekey_rollback);
TEST(module_enable_rewraps_sealed_record_content);

/* 熔断（test_lockout.c） */
TEST(secure_state_paths_and_identity);
TEST(secure_state_preflight_and_handle_budget);
TEST(secure_state_rejects_object_ace_grant);
TEST(lockout_first_run_and_counting);
TEST(lockout_backoff_window);
TEST(lockout_tampered_state_locked);
TEST(lockout_state_replay_rejected);
TEST(lockout_path_change_locked);
TEST(lockout_begin_attempt_min_interval);
TEST(lockout_module_isolation);
TEST(lockout_missing_witness_recovers);
TEST(lockout_witness_mismatch_stays_locked);
TEST(lockout_pipeline_persistent);

/* 机器级预算客户端（test_machine_limiter.c，仅测试钩子构建） */
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
TEST(machine_limiter_uninstalled_fail_closed);
TEST(machine_limiter_test_default_fail_closed);
TEST(machine_limiter_pipe_unreachable);
TEST(machine_limiter_pubkey_missing);
TEST(machine_limiter_bad_signature);
TEST(machine_limiter_nonce_mismatch);
TEST(machine_limiter_status_mapping);
TEST(machine_limiter_timeout);
TEST(v4_unlock_machine_gate_fail_closed);
TEST(v4_module_unlock_machine_gate_fail_closed);
#endif

/* 库文件回退（test_rollback.c） */
TEST(create_failure_removes_partial_and_keeps_error);
TEST(rollback_module_monotonic_anchor);
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
TEST(rollback_env_hook_vault_flow);
TEST(rollback_env_hook_isolated);
#endif
TEST(rollback_restored_old_copy_rejected);
TEST(rollback_rotated_copy_rejected);
TEST(rollback_tampered_anchor_fails_closed);
TEST(rollback_recovery_resets_anchor);
TEST(rollback_forged_generation_rejected);
TEST(rollback_state_replay_rejected);
TEST(rollback_missing_state_anchor_fail_closed);
TEST(rollback_disabled_allows_old_copy);

/* PCR 槽与解锁策略（test_pcr.c） */
TEST(pcr_select_validation);
TEST(pcr_slot_codec);
TEST(tpm_pcr_key_roundtrip);
TEST(tpm_pcr_key_wrong_digest_rejected);
TEST(pcr_create_open_roundtrip);
TEST(pcr_tampered_digest_fails_closed);
TEST(pcr_wrong_tpm_key_fails_closed);
TEST(pcr_foreign_ciphertext_rejected);
TEST(pcr_recovery_reseal);
TEST(pcr_enable_disable);

/* TPM 持久化密钥见证（test_witness.c） */
TEST(witness_rotation_and_verify);

/* 崩溃注入（test_crash.c） */
TEST(crash_injection_100_cuts);
TEST(crash_keyfile_create_truncation);
TEST(crash_keyfile_file_tamper);
TEST(crash_keyfile_enable_rollback);
TEST(crash_keyfile_disable_rollback);
TEST(crash_record_data_truncation_rejected);

/* 导出/导入（test_transfer.c） */
TEST(transfer_export_import_roundtrip);

/* 全库 DEK 轮换（test_rotate.c） */
TEST(rotate_recovery_gate_and_readonly);
TEST(rotate_full_roundtrip_preserves_records_and_files);
TEST(rotate_rewraps_module_content);
TEST(rotate_modules_require_password_and_rebind_recovery);
TEST(rotate_create_from_kc_never_deletes_foreign_target);
TEST(rotate_rollback_anchor_advances);
TEST(rotate_keyfile_session_rejected);
TEST(rotate_run_cancel_callback);
TEST(rotate_pcr_binding_preserved);
TEST(rotate_pcr_journal_crash_recovery);
TEST(rotate_keep_old_pcr_backup_requires_recovery);
TEST(rotate_keep_old_preserves_backup);
TEST(rotate_cancel_during_chunk_copy);
TEST(rotate_password_attempts_follow_lockout);
TEST(rotate_with_deleted_file_module);
TEST(module_recreate_and_delete_tolerates_tombstones);
TEST(rotate_preserves_id_allocator_watermark);

/* 解析器模糊（test_fuzz.c） */
TEST(fuzz_header_parsers_never_crash);
TEST(fuzz_keyfile_parser_never_crash);
TEST(fuzz_slot_keyring_parsers_never_crash);
TEST(fuzz_recovery_and_manifest_never_crash);
TEST(fuzz_header_bitflip_always_rejected);

/* 性能基准（test_perf.c） */
TEST(perf_chunk_throughput);
TEST(perf_vault_unlock_latency);
TEST(perf_module_switch_latency);

/* test_pepper.c — 胡椒持久化格式与密钥槽闭环 */
TEST(pepper_first_seal_roundtrip);
TEST(pepper_cipher_tamper_rejected);
TEST(pepper_fingerprint_tamper_rejected);
TEST(pepper_level_forgery_rejected);
TEST(pepper_foreign_size_rejected);
TEST(pepper_bad_magic_rejected);
TEST(pepper_inject_bypasses_os);
TEST(pepper_no_compiled_fallback);

/* test_runtime_hash.c — 运行时函数级哈希校验（.rhat 真表） */
TEST(rhat_table_configured);
TEST(rhat_real_table_scan_clean);
TEST(rhat_lookup_covered);
TEST(rhat_virtualprotect_patch_detected);
TEST(rhat_overlay_install_detect_clear);
TEST(rhat_overlay_concurrent_install_scan);
TEST(rhat_verify_periodic_clean_state);

/* test_syscall_direct.c — 直接系统调用传输
 * （SSN 排序法提取 + W^X stub + 降级；激活/降级两态均须过） */
TEST(scd_init_idempotent);
TEST(scd_process_query_matches_ntdll);
TEST(scd_system_query_basic_info);
TEST(scd_error_code_passthrough);
TEST(scd_detector_wiring_clean);

/* test_defense_closure.c — 防御闭环状态事实化验证
 * （七路径判定矩阵 / 锁定态无资产 / 并发快照） */
TEST(dcl_status_invalid_params);
TEST(dcl_boot_check_no_failed_paths);
TEST(dcl_locked_state_no_resident_key);
TEST(dcl_unlocked_honest_state);
TEST(dcl_facts_locked_matrix);
TEST(dcl_facts_suspend_and_mem_matrix);
TEST(dcl_facts_hibernation_matrix);
TEST(dcl_facts_hook_scan_matrix);
TEST(dcl_facts_sandbox_matrix);
TEST(dcl_facts_cross_device_matrix);
TEST(dcl_facts_limited_count);
TEST(dcl_sandbox_self_report_not_trusted);
TEST(dcl_session_count_lifecycle);
TEST(dcl_secure_alloc_lifecycle);
TEST(dcl_secure_alloc_failure);
TEST(dcl_emergency_purge);
TEST(dcl_status_abi_layout);
TEST(dcl_runtime_guards_flag);
TEST(dcl_status_concurrent_lock);

/* test_hibernation_state.c — 系统休眠三态映射与真实查询 */
TEST(hibernation_state_parse_map);
TEST(hibernation_state_query_real);

/* test_hook_scan.c — Hook 扫描状态机与真实基线冒烟 */
TEST(hook_scan_evaluate_clean);
TEST(hook_scan_evaluate_baseline_unavailable);
TEST(hook_scan_evaluate_stale_stub);
TEST(hook_scan_evaluate_hook_two_strikes);
TEST(hook_scan_evaluate_iat_two_strikes);
TEST(hook_scan_real_baseline_smoke);

/* test_anti_inject.c — 防注入线程基线重采样（白名单）单元验证 */
TEST(ai_thread_internal_address_in_own_module);
TEST(ai_thread_external_dll_address_not_in_own_module);
TEST(ai_thread_unmapped_address_not_in_own_module);

/* test_system32_loader.c — System32 目录前缀边界校验 */
TEST(sys32_prefix_boundary_rejects_sibling);

/* argv 过滤器——`verthys_tests.exe <子串>` 仅运行
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

/* 扩展：argv[2..] 作为额外 OR 过滤器（多组联合运行） */
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
 * 测试文件沙箱（测试残留文件统一管理与自动清除）
 *
 * 理由：各测试以相对路径创建临时文件与附属目录（test_*.verthys、
 * <base>.d/ 等），落盘位置由测试进程的 CWD 决定——从项目根直接运行
 * 测试可执行文件时，残留文件会散落源码树根目录。
 *
 * 做法：main() 入口将 CWD 切换到构建树内专属沙箱目录
 *   <exe_dir>\test_scratch_<pid>
 * 全部测试的相对路径文件统一收口于此；正常退出时递归删除沙箱。
 * 硬崩溃（atexit 清理无法执行）的残留由下次运行启动清扫回收：枚举同
 * 目录下 test_scratch_<pid> 前缀沙箱，pid 已不存在的整目录删除——残留
 * 最多暂留到下一次测试运行，不随运行次数无限累积。
 *
 * 安全性：全部测试只用相对路径创建自有工件，不读取源码树相对路径，
 * 也不派生进程，切换 CWD 不影响任何现有用例。
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

/* 启动清扫：回收硬崩溃残留的沙箱目录。枚举 exe 目录下 test_scratch_<pid>
 * 前缀目录，pid 已不存在的整目录删除；pid 存活（并发运行的另一测试进程）
 * 或存活状态无法判定的目录一律不动，避免误删活跃沙箱。 */
static void scratch_sweep_stale(const char *exe_dir)
{
    char pattern[MAX_PATH + 8];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    snprintf(pattern, sizeof(pattern), "%s\\test_scratch_*", exe_dir);
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        char dir[MAX_PATH];
        char *end = NULL;
        unsigned long pid;
        HANDLE proc;

        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strncmp(fd.cFileName, "test_scratch_", 13) != 0) continue;
        pid = strtoul(fd.cFileName + 13, &end, 10);
        if (end == fd.cFileName + 13 || *end != '\0') continue;

        /* 存活判定：SYNCHRONIZE 可打开 = 进程在跑（含自身）。打开失败且
         * 错误为坏 pid（ERROR_INVALID_PARAMETER）= 进程已死 → 垃圾回收；
         * 其余失败视为无法判定（可能存活但受限），保守跳过。 */
        proc = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
        if (proc != NULL) {
            CloseHandle(proc);
            continue;
        }
        if (GetLastError() != ERROR_INVALID_PARAMETER) continue;

        snprintf(dir, sizeof(dir), "%s\\%s", exe_dir, fd.cFileName);
        scratch_rm_rf(dir);
        printf("[sandbox] swept stale scratch: %s\n", fd.cFileName);
        fflush(stdout);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

/* 建立沙箱并切换 CWD；失败时保留原 CWD（绝不阻断测试本身） */
static void scratch_setup(void)
{
    char exe[MAX_PATH];
    char *slash;

    if (GetModuleFileNameA(NULL, exe, MAX_PATH) == 0) return;
    slash = strrchr(exe, '\\');
    if (slash == NULL) return;
    *slash = '\0';

    scratch_sweep_stale(exe);

    snprintf(g_scratch_dir, sizeof(g_scratch_dir), "%s\\test_scratch_%lu",
             exe, (unsigned long)GetCurrentProcessId());

    if (GetCurrentDirectoryA(sizeof(g_scratch_cwd_backup),
                             g_scratch_cwd_backup) == 0)
        return;

    /* 清掉同 PID 复用的历史残留，确保沙箱内无过期状态：
     * 陈旧附属文件会污染首次创建/锁定类用例的前提 */
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
    /* 测试构建的熔断/回滚状态覆盖到沙箱目录；生产构建不编译该钩子，
     * 此处设置的环境变量被忽略。 */
    (void)SetEnvironmentVariableA("VERTHYS_TEST_STATE_DIR", g_scratch_dir);
    printf("[sandbox] test scratch dir: %s\n", g_scratch_dir);
    fflush(stdout);
}

/* ------------------------------------------------------------------ *
 * 测试间状态快照实现
 *
 * 采集维度：
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
    /* 沙箱先行：CWD 切换必须先于任何测试执行（含过滤参数解析输出），
     * 保证所有相对路径临时文件统一落入构建树内沙箱并在结束时清除 */
    scratch_setup();
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    /*
     * 本地熔断与持久化回归测试不启动真实服务；测试构建显式旁路机器预算调用。
     * 产品构建不编译该分支，生产路径始终 fail-closed。
     */
    SetEnvironmentVariableW(L"VERTHYS_TEST_MACHINE_LIMITER_BYPASS", L"1");
#endif

    test_filter_save(argc, argv);
    if (argc > 1 && argv[1] != NULL && argv[1][0] != '\0') {
        g_filter_active = 1;
        strncpy_s(g_filter, sizeof(g_filter), argv[1], _TRUNCATE);
        printf("=== filter: '%s' ===\n", g_filter);
    }
    /*
     * 入口单一职责：环境初始化（verthys_crypto_init）、RUN_TEST 派发、
     * TEST_SUMMARY 汇总；用例输出经 verthys_test.h 宏封装。
     */
    TEST_LOG("=== Verthys Phase 1 Tests ===\n\n");

    /* 环境初始化：底层密码库（crypto 测试依赖） */
    if (verthys_crypto_init() != 0) {
        TEST_FATAL("verthys_crypto_init failed\n");
    }

    /* 持久化熔断的默认状态文件位于真实用户目录，而全套用例包含大量
     * 错误口令路径；测试进程默认关闭持久化，仅专用用例显式开启并
     * 注入沙箱状态路径，避免污染本机状态。 */
    vty_lockout_set_enabled(0);
    /* 回退锚点同理会写入用户目录：默认关闭，专用用例开启并注入路径 */
    vty_rollback_set_enabled(0);

    /* rhat 组置于全量首组——真表等价性（构建期文件哈希 ≡ 运行期
     * 内存哈希）若断裂，此处先出显式 CHECK 失败，早于任何 Verthys_V4Unlock
     * 解锁路径的 KILL 应急（进程存活，诊断信息完整）。 */
    RUN_TEST(rhat_table_configured);
    RUN_TEST(rhat_real_table_scan_clean);
    RUN_TEST(rhat_lookup_covered);
    RUN_TEST(rhat_virtualprotect_patch_detected);
    RUN_TEST(rhat_overlay_install_detect_clear);
    RUN_TEST(rhat_overlay_concurrent_install_scan);
    RUN_TEST(rhat_verify_periodic_clean_state);
    test_state_checkpoint("runtime_hash");

    /* 直接系统调用传输组——紧随 rhat 组：传输正确性是后续
     * 全部检测器（anti_debug/memory_guard）行为的底层前提。 */
    RUN_TEST(scd_init_idempotent);
    RUN_TEST(scd_process_query_matches_ntdll);
    RUN_TEST(scd_system_query_basic_info);
    RUN_TEST(scd_error_code_passthrough);
    RUN_TEST(scd_detector_wiring_clean);
    test_state_checkpoint("syscall_direct");

    /* 三档预设配置与快照读取（特性位契约 / 回读一致性 / 并发快照） */
    RUN_TEST(preset_feature_bits_matrix);
    RUN_TEST(preset_switch_readback_idempotent);
    RUN_TEST(preset_snapshot_concurrent_stress);
    test_state_checkpoint("security_preset");

    /* 防御闭环状态事实化（七路径判定矩阵 / 锁定态 / 并发快照） */
    RUN_TEST(dcl_status_invalid_params);
    RUN_TEST(dcl_boot_check_no_failed_paths);
    RUN_TEST(dcl_locked_state_no_resident_key);
    RUN_TEST(dcl_unlocked_honest_state);
    RUN_TEST(dcl_facts_locked_matrix);
    RUN_TEST(dcl_facts_suspend_and_mem_matrix);
    RUN_TEST(dcl_facts_hibernation_matrix);
    RUN_TEST(dcl_facts_hook_scan_matrix);
    RUN_TEST(dcl_facts_sandbox_matrix);
    RUN_TEST(dcl_facts_cross_device_matrix);
    RUN_TEST(dcl_facts_limited_count);
    RUN_TEST(dcl_sandbox_self_report_not_trusted);
    RUN_TEST(dcl_session_count_lifecycle);
    RUN_TEST(dcl_secure_alloc_lifecycle);
    RUN_TEST(dcl_secure_alloc_failure);
    RUN_TEST(dcl_emergency_purge);
    RUN_TEST(dcl_status_abi_layout);
    RUN_TEST(dcl_runtime_guards_flag);
    RUN_TEST(dcl_status_concurrent_lock);
    RUN_TEST(hibernation_state_parse_map);
    RUN_TEST(hibernation_state_query_real);
    RUN_TEST(hook_scan_evaluate_clean);
    RUN_TEST(hook_scan_evaluate_baseline_unavailable);
    RUN_TEST(hook_scan_evaluate_stale_stub);
    RUN_TEST(hook_scan_evaluate_hook_two_strikes);
    RUN_TEST(hook_scan_evaluate_iat_two_strikes);
    RUN_TEST(hook_scan_real_baseline_smoke);
    test_state_checkpoint("defense_closure");

    /* 防注入线程基线重采样（自身模块内线程白名单判定） */
    RUN_TEST(ai_thread_internal_address_in_own_module);
    RUN_TEST(ai_thread_external_dll_address_not_in_own_module);
    RUN_TEST(ai_thread_unmapped_address_not_in_own_module);
    test_state_checkpoint("anti_inject");

    /* System32 目录前缀边界校验（加载函数已无生产调用点并删除） */
    RUN_TEST(sys32_prefix_boundary_rejects_sibling);
    test_state_checkpoint("system32_loader");

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

    /* 胡椒持久化格式与密钥槽闭环（含存储路径覆盖隔离） */
    RUN_TEST(pepper_first_seal_roundtrip);
    RUN_TEST(pepper_cipher_tamper_rejected);
    RUN_TEST(pepper_fingerprint_tamper_rejected);
    RUN_TEST(pepper_level_forgery_rejected);
    RUN_TEST(pepper_foreign_size_rejected);
    RUN_TEST(pepper_bad_magic_rejected);
    RUN_TEST(pepper_inject_bypasses_os);
    RUN_TEST(pepper_no_compiled_fallback);
    test_state_checkpoint("pepper");

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
    RUN_TEST(format_data_size_guard_rejects);
    test_state_checkpoint("format");


    /* Export/Import 路径纵深防御（目录穿越 / 系统目录 / 临时目录） */
    RUN_TEST(pg_export_rejects_dotdot_path);
    RUN_TEST(pg_export_rejects_system_dir_path);
    RUN_TEST(pg_import_rejects_system_dir_path);
    RUN_TEST(pg_export_accepts_temp_path);
    test_state_checkpoint("export_path_guard");

    /* 扫描并发压力测试（读游标 vs 写入竞争） */
    RUN_TEST(scan_concurrent_readers_vs_writer);
    test_state_checkpoint("scan_concurrent");

    /* 工作线程有界汇合（Deinit/Lock 等待不得被阻塞点永久挂起） */
    RUN_TEST(join_bounded_timeout_then_release);
    RUN_TEST(join_bounded_exited_thread);
    RUN_TEST(join_bounded_null_handle);
    test_state_checkpoint("join_bounded");


    /* 文件格式变异 / 篡改检测测试 */
    RUN_TEST(fuzz_empty_file);
    RUN_TEST(fuzz_too_small);
    RUN_TEST(fuzz_all_zero_file);
    RUN_TEST(fuzz_random_garbage);
    RUN_TEST(fuzz_bit_flip_magic);
    RUN_TEST(fuzz_truncated_header);
    RUN_TEST(fuzz_truncated_metadata);
    RUN_TEST(fuzz_bit_flip_metadata);
    RUN_TEST(fuzz_bit_flip_mac);
    RUN_TEST(fuzz_bit_flip_index);
    RUN_TEST(fuzz_bit_flip_data_block);
    RUN_TEST(fuzz_extended_file);
    test_state_checkpoint("format_fuzz");



    /* 应急响应分级测试 */
    RUN_TEST(emergency_telemetry_no_trigger);
    RUN_TEST(emergency_degrade_requires_window_threshold);
    RUN_TEST(emergency_handler_swap_and_null);
    test_state_checkpoint("emergency");

    /* 构建期签名验签测试 */
    RUN_TEST(integrity_verify_unconfigured_passes);
    RUN_TEST(integrity_verify_startup_cache_replay_invalidate);
    test_state_checkpoint("integrity");



    /* 验收：vendored flatcc 工具链（schema codegen + flatccrt 编解码闭环） */
    RUN_TEST(flatcc_demo_roundtrip);
    RUN_TEST(flatcc_demo_tamper_rejected);
    test_state_checkpoint("flatcc_demo");


    /* 验收：安全分配器（隔离堆 + PAGE_GUARD 边界页 + 锁页 + 预算记账） */
    RUN_TEST(sec_alloc_basic_roundtrip);
    RUN_TEST(sec_alloc_guard_pages);
    RUN_TEST(sec_alloc_locked);
    RUN_TEST(sec_alloc_budget_reject_and_reclaim);
    RUN_TEST(sec_alloc_error_paths);
    RUN_TEST(sec_alloc_destroy_releases_all);
    RUN_TEST(sec_alloc_shared_lifecycle);
    test_state_checkpoint("secure_allocator");



    /* 密钥体系：原语与恢复码 → 容器槽 → 记录/分片 → 库与模块 → 熔断 */
    RUN_TEST(blake3_known_vectors);
    RUN_TEST(hkdf_rfc5869_case1);
    RUN_TEST(hmac_deterministic_and_key_sensitive);
    RUN_TEST(argon2id_deterministic_and_salt_sensitive);
    RUN_TEST(kdf_param_floor_rejected);
    RUN_TEST(wrap_key32_roundtrip_and_tamper);
    RUN_TEST(recovery_code_roundtrip);
    RUN_TEST(recovery_checksum_error_rejected);
    RUN_TEST(recovery_suffix_rejected);
    RUN_TEST(keyring_serialize_parse_roundtrip);
    RUN_TEST(keyring_parse_invalid_rejected);
    RUN_TEST(recovery_slot_seal_open);
    RUN_TEST(keyfile_generate_parse_roundtrip);
    RUN_TEST(keyfile_tamper_rejected);
    RUN_TEST(keyfile_vault_create_open_and_rotate);
    test_state_checkpoint("primitives");

    RUN_TEST(header_write_parse_roundtrip);
    RUN_TEST(header_tamper_rejected);
    RUN_TEST(slot_seal_serialize_parse);
    RUN_TEST(slots_parse_all_roundtrip);
    RUN_TEST(slot_policy_check);
    RUN_TEST(header_generation_and_minor_frozen);
    RUN_TEST(data_root_locator_codec);
    RUN_TEST(segment_header_codec);
    test_state_checkpoint("container");

    RUN_TEST(record_roundtrip);
    RUN_TEST(record_aad_binding);
    RUN_TEST(record_size_guard_rejected);
    RUN_TEST(name_index_nfkc_and_separation);
    RUN_TEST(record_plaintext_fallback_forbidden);
    test_state_checkpoint("records");

    RUN_TEST(chunk_roundtrip);
    RUN_TEST(chunk_aad_binding);
    RUN_TEST(chunk_id_unlinkable);
    RUN_TEST(manifest_roundtrip);
    RUN_TEST(manifest_tamper_rejected);
    RUN_TEST(large_file_1gb_roundtrip);
    test_state_checkpoint("chunks");

    /* 设备根封装会在进程内建立持久的 CNG 密钥句柄（进程级、一次性）：
     * 先预热，避免首个用例把这次初始化误报成句柄泄漏。 */
    (void)vty_device_root_init();
    if (vty_device_root_available()) {
        uint8_t probe[VTY_KEY_BYTES];
        uint8_t probe_blob[VTY_DEVICE_BLOB_BYTES];
        size_t probe_len = sizeof(probe_blob);
        memset(probe, 0, sizeof(probe));
        if (vty_device_key_seal(probe, probe_blob, &probe_len) == VTY_OK) {
            (void)vty_device_key_unseal(probe_blob, probe_len, probe);
        }
    }
    RUN_TEST(vault_create_open_e2e);
    RUN_TEST(vault_wrong_recovery_rejected);
    RUN_TEST(vault_rotate_password);
    RUN_TEST(vault_header_tamper_rejected);
    RUN_TEST(module_table_create_and_tamper);
    RUN_TEST(module_m1_enable_rewrite_and_policy);
    RUN_TEST(module_m1_chunks_rekey);
    RUN_TEST(module_delete_purge_and_recreate);
    RUN_TEST(module_lifecycle_disable_then_delete);
    RUN_TEST(module_recovery_bind_rotate_reseal);
    RUN_TEST(module_crash_rekey_rollback);
    RUN_TEST(module_enable_rewraps_sealed_record_content);
    test_state_checkpoint("vault_module");

    RUN_TEST(api_create_save_lock_unlock_roundtrip);
    RUN_TEST(api_recovery_unlock_roundtrip);
    RUN_TEST(api_keyfile_create_unlock_disable_roundtrip);
    RUN_TEST(api_keyfile_recovery_rebind);
    RUN_TEST(api_keyfile_create_rejects_existing_targets);

    RUN_TEST(store_empty_root_binds_uuid_epoch);
    RUN_TEST(store_put_get_and_cow_snapshot);
    RUN_TEST(store_split_and_verify);
    RUN_TEST(store_segment_append_read_and_cursor);
    RUN_TEST(store_tamper_and_truncate_rejected);
    test_state_checkpoint("store");

    /* 记录仓库 / 扫描 / 公共 API / 导出导入 */
    RUN_TEST(repo_add_get_delete_and_id_monotonic);
    RUN_TEST(repo_file_chunk_manifest);
    RUN_TEST(repo_empty_name_and_tombstone_count);
    RUN_TEST(repo_system_domain_survives_module_enable_and_delete);
    RUN_TEST(repo_legacy_security_record_migrates_on_module_enable);
    RUN_TEST(repo_scan_cursor_and_start_id);
    RUN_TEST(repo_scan_skips_tombstone_and_type_index);
    RUN_TEST(api_records_roundtrip_and_scan);
    RUN_TEST(api_list_ids_by_type_and_verify_persist);
    RUN_TEST(api_add_records_batch_roundtrip);
    RUN_TEST(api_records_require_unlock);
    RUN_TEST(api_modules_roundtrip_and_policy);
    RUN_TEST(api_module_delete);
    RUN_TEST(api_recovery_rotate);
    RUN_TEST(api_pcr_policy_roundtrip);
    RUN_TEST(reseal_device_roundtrip_restores_normal_unlock);
    RUN_TEST(reseal_device_rejects_normal_session);
    RUN_TEST(reseal_device_keyfile_required_and_roundtrip);
    RUN_TEST(api_content_chunk);
    RUN_TEST(api_product_e2e);
    RUN_TEST(error_map_d9_codes_are_distinct);
    RUN_TEST(error_map_r10_slot_errors_lock_format_policy);
    RUN_TEST(transfer_export_import_roundtrip);
    RUN_TEST(rotate_recovery_gate_and_readonly);
    RUN_TEST(rotate_full_roundtrip_preserves_records_and_files);
    RUN_TEST(rotate_rewraps_module_content);
    RUN_TEST(rotate_modules_require_password_and_rebind_recovery);
    RUN_TEST(rotate_create_from_kc_never_deletes_foreign_target);
    RUN_TEST(rotate_rollback_anchor_advances);
    RUN_TEST(rotate_keyfile_session_rejected);
    RUN_TEST(rotate_run_cancel_callback);
    RUN_TEST(rotate_pcr_binding_preserved);
    RUN_TEST(rotate_pcr_journal_crash_recovery);
    RUN_TEST(rotate_keep_old_pcr_backup_requires_recovery);
    RUN_TEST(rotate_keep_old_preserves_backup);
    RUN_TEST(rotate_cancel_during_chunk_copy);
    RUN_TEST(rotate_password_attempts_follow_lockout);
    RUN_TEST(rotate_with_deleted_file_module);
    RUN_TEST(module_recreate_and_delete_tolerates_tombstones);
    RUN_TEST(rotate_preserves_id_allocator_watermark);
    test_state_checkpoint("rotate");

    RUN_TEST(secure_state_paths_and_identity);
    RUN_TEST(secure_state_preflight_and_handle_budget);
    RUN_TEST(secure_state_rejects_object_ace_grant);
    RUN_TEST(lockout_first_run_and_counting);
    RUN_TEST(lockout_backoff_window);
    RUN_TEST(lockout_tampered_state_locked);
    RUN_TEST(lockout_state_replay_rejected);
    RUN_TEST(lockout_path_change_locked);
    RUN_TEST(lockout_begin_attempt_min_interval);
    RUN_TEST(lockout_module_isolation);
    RUN_TEST(lockout_missing_witness_recovers);
    RUN_TEST(lockout_witness_mismatch_stays_locked);
    RUN_TEST(lockout_pipeline_persistent);
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    /* 进入机器预算客户端用例前撤销旁路，验证服务缺失时强制 fail-closed。 */
    SetEnvironmentVariableW(L"VERTHYS_TEST_MACHINE_LIMITER_BYPASS", NULL);
    RUN_TEST(machine_limiter_uninstalled_fail_closed);
    RUN_TEST(machine_limiter_test_default_fail_closed);
    RUN_TEST(machine_limiter_pipe_unreachable);
    RUN_TEST(machine_limiter_pubkey_missing);
    RUN_TEST(machine_limiter_bad_signature);
    RUN_TEST(machine_limiter_nonce_mismatch);
    RUN_TEST(machine_limiter_status_mapping);
    RUN_TEST(machine_limiter_timeout);
    RUN_TEST(v4_unlock_machine_gate_fail_closed);
    RUN_TEST(v4_module_unlock_machine_gate_fail_closed);
    /* 机器预算客户端用例组结束，恢复其余用例的测试旁路并清空服务钩子。 */
    SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_INSTALLED", NULL);
    SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_PIPE", NULL);
    SetEnvironmentVariableW(L"VERTHYS_TEST_SERVICE_PUBKEY_PATH", NULL);
    SetEnvironmentVariableW(L"VERTHYS_TEST_MACHINE_LIMITER_BYPASS", L"1");
#endif
    test_state_checkpoint("lockout");

    RUN_TEST(create_failure_removes_partial_and_keeps_error);
    RUN_TEST(rollback_module_monotonic_anchor);
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    RUN_TEST(rollback_env_hook_vault_flow);
    RUN_TEST(rollback_env_hook_isolated);
#endif
    RUN_TEST(rollback_restored_old_copy_rejected);
    RUN_TEST(rollback_rotated_copy_rejected);
    RUN_TEST(rollback_tampered_anchor_fails_closed);
    RUN_TEST(rollback_recovery_resets_anchor);
    RUN_TEST(rollback_forged_generation_rejected);
    RUN_TEST(rollback_state_replay_rejected);
    RUN_TEST(rollback_missing_state_anchor_fail_closed);
    RUN_TEST(rollback_disabled_allows_old_copy);
    /* 组内用例会开启回退检测；显式恢复默认关闭，避免影响后续用例 */
    vty_rollback_set_enabled(0);
    test_state_checkpoint("rollback");

    RUN_TEST(pcr_select_validation);
    RUN_TEST(pcr_slot_codec);
    RUN_TEST(tpm_pcr_key_roundtrip);
    RUN_TEST(tpm_pcr_key_wrong_digest_rejected);
    RUN_TEST(pcr_create_open_roundtrip);
    RUN_TEST(pcr_tampered_digest_fails_closed);
    RUN_TEST(pcr_wrong_tpm_key_fails_closed);
    RUN_TEST(pcr_foreign_ciphertext_rejected);
    RUN_TEST(pcr_recovery_reseal);
    RUN_TEST(pcr_enable_disable);
    RUN_TEST(witness_rotation_and_verify);
    test_state_checkpoint("pcr");

    RUN_TEST(crash_injection_100_cuts);
    RUN_TEST(crash_keyfile_create_truncation);
    RUN_TEST(crash_keyfile_file_tamper);
    RUN_TEST(crash_keyfile_enable_rollback);
    RUN_TEST(crash_keyfile_disable_rollback);
    RUN_TEST(crash_record_data_truncation_rejected);
    test_state_checkpoint("crash");

    RUN_TEST(fuzz_header_parsers_never_crash);
    RUN_TEST(fuzz_keyfile_parser_never_crash);
    RUN_TEST(fuzz_slot_keyring_parsers_never_crash);
    RUN_TEST(fuzz_recovery_and_manifest_never_crash);
    RUN_TEST(fuzz_header_bitflip_always_rejected);
    test_state_checkpoint("fuzz");

    RUN_TEST(perf_chunk_throughput);
    RUN_TEST(perf_vault_unlock_latency);
    RUN_TEST(perf_module_switch_latency);
    test_state_checkpoint("perf");

    TEST_SUMMARY();
    return g_tests_failed > 0 ? 1 : 0;
}
