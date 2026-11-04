# core/tests/CMakeLists.txt
# 测试 exe：链接共享对象库 + v3 容器对象库 + 测试 API 对象库（V3 分支启用），
# 直接调用实现（不走 DLL 边界）；产品 verthys_core_obj（v4-only）不参与测试链接。
# 模块化重构：测试区按被测子域镜像组织（api/container/crypto/index/
#   property/regression/schema/security/transaction/perf），test_runner.c
#   与 verthys_test.h 保留在 tests 根作为测试入口与框架。

add_executable(verthys_tests
    test_runner.c
    api/test_init.c
    crypto/test_crypto.c
    crypto/test_keymanager.c
    container/test_verthys_format.c
    api/test_verthys_api.c
    api/test_verthys_export.c
    api/test_export_path_guard.c
    api/test_scan_concurrent.c
    api/test_join_bounded.c
    security/test_memory_safety.c
    container/test_format_fuzz.c
    perf/test_perf_prefetch.c
    security/test_key_separation.c
    security/test_emergency.c
    security/test_integrity_verify.c
    transaction/test_txn_recovery_inject.c
    transaction/test_txn_delete_retry.c
    transaction/test_txn_force_abort.c
    transaction/test_txn_extent_reloc.c
    perf/test_perf_baseline.c
    regression/test_final_repair.c
    schema/test_flatcc_demo.c
    crypto/test_cng_kernel.c
    security/test_secure_allocator.c
    security/test_backoff_process_wide.c
    container/test_v3_container.c
    container/test_container_lock.c
    container/test_v3_partition.c
    container/test_v3_extent.c
    index/test_v3_lsm.c
    index/test_sstable_budget.c
    index/test_warmcache_v3.c
    api/test_v3_lifecycle.c
    api/test_v4_api.c
    property/test_v3_property.c
    crypto/test_auto_rekey.c
    crypto/test_pepper_v3.c
    crypto/test_v4_primitives.c
    crypto/test_v4_keyfile.c
    container/test_v4_container.c
    index/test_v4_records.c
    index/test_v4_store.c
    index/test_v4_repo.c
    index/test_v4_repo_scan.c
    api/test_v4_api_v4.c
    api/test_v4_api_modules.c
    api/test_v4_api_pcr.c
    api/test_v4_reseal_device.c
    api/test_v4_api_content.c
    api/test_v4_api_product.c
    api/test_v4_error_map.c
    api/test_v4_transfer.c
    api/test_v4_rotate.c
    container/test_v4_chunks.c
    container/test_v4_modules.c
    security/test_v4_lockout.c
    security/test_v4_lockout_pipeline.c
    security/test_v4_rollback.c
    security/test_v4_pcr.c
    security/test_v4_witness.c
    security/test_v4_crash.c
    security/test_v4_fuzz.c
    perf/test_v4_perf.c
    security/test_runtime_hash.c
    security/test_syscall_direct.c
    security/test_security_preset.c
    security/test_defense_closure.c
    security/test_hibernation_state.c
    security/test_hook_scan.c
    security/test_anti_inject.c
    security/test_system32_loader.c
)
target_link_libraries(verthys_tests PRIVATE
    verthys_core_shared_obj
    verthys_core_v3_obj
    verthys_core_legacy_api_obj)
# flatcc 运行时（demo schema 编解码验收）+ codegen 顺序依赖
target_link_libraries(verthys_tests PRIVATE flatccrt)
add_dependencies(verthys_tests flatcc_generate)
# 状态快照 GetGuiResources 需要 user32（对象库为
# PRIVATE 链接不传递，此处显式补齐）
target_link_libraries(verthys_tests PRIVATE user32)
# 模块化重构：源子目录 include 表复用 core/CMakeLists.txt 的
#   VERTHYS_SRC_SUBDIRS（单一事实源——目录结构调整只改一处）
target_include_directories(verthys_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/core/include
    ${CMAKE_SOURCE_DIR}/core/src
    ${VERTHYS_SRC_SUBDIRS}
    ${CMAKE_SOURCE_DIR}/core/schema/generated
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# 测试需在 Debug 可调试：不应用 Release 剥离
if(MSVC)
    target_compile_options(verthys_tests PRIVATE /utf-8)
    # 创建路径栈帧较深（Argon2id + 超级块序列化 + 文件创建），
    # 增大栈尺寸到 16MB 避免 STATUS_STACK_OVERFLOW
    target_link_options(verthys_tests PRIVATE /STACK:16777216)
endif()

#   verthys_tests.exe 的 .rhat 真表链路
#   /INCREMENTAL:NO：杜绝 ILT 增量链接 thunk（Debug 默认增量开启，
#     thunk 符号会让 map RVA 指向 6 字节跳板而非函数体）；
#   /MAP：供 rhash_gen 解析符号 RVA；
#   POST_BUILD 补丁：每轮构建的测试 EXE 携带真 .rhat 表——
#     "构建期文件哈希 ≡ 运行期内存哈希（含重定位掩码）"在每轮
#     开发测试中持续验证（rhat 系列测试的硬前提）。
target_link_options(verthys_tests PRIVATE /INCREMENTAL:NO)
target_link_options(verthys_tests PRIVATE
    /MAP:$<TARGET_FILE_DIR:verthys_tests>/verthys_tests.map)
add_dependencies(verthys_tests rhash_gen)
add_custom_command(TARGET verthys_tests POST_BUILD
    COMMAND $<TARGET_FILE:rhash_gen> --patch $<TARGET_FILE:verthys_tests>
    COMMENT "rhash_gen: verthys_tests.exe .rhat 运行时哈希表补丁"
    VERBATIM
)

add_test(NAME verthys_tests COMMAND verthys_tests)

# ACG 专项验证：策略为进程级且不可撤销，必须使用独立进程。
add_executable(verthys_scd_acg_test
    security/test_scd_acg.c
)
target_link_libraries(verthys_scd_acg_test PRIVATE
    verthys_core_shared_obj verthys_core_v3_obj verthys_core_legacy_api_obj
    flatccrt user32)
target_include_directories(verthys_scd_acg_test PRIVATE
    ${CMAKE_SOURCE_DIR}/core/include
    ${CMAKE_SOURCE_DIR}/core/src
    ${VERTHYS_SRC_SUBDIRS}
)
if(MSVC)
    target_compile_options(verthys_scd_acg_test PRIVATE /utf-8)
endif()
add_test(NAME verthys_scd_acg COMMAND verthys_scd_acg_test)

# 生产 DLL 端到端验证：独立进程启用 ACG 后加载 verthys.dll，
# 直接检查 defense_closure 的 IAT/Inline Hook 路径状态。
add_executable(verthys_scd_dll_acg_test
    security/test_scd_dll_acg.c
)
target_include_directories(verthys_scd_dll_acg_test PRIVATE
    ${CMAKE_SOURCE_DIR}/core/include
)
if(MSVC)
    target_compile_options(verthys_scd_dll_acg_test PRIVATE /utf-8)
endif()
add_dependencies(verthys_scd_dll_acg_test verthys_core)
add_test(NAME verthys_scd_dll_acg
    COMMAND verthys_scd_dll_acg_test $<TARGET_FILE:verthys_core>)

# v4 攻击探针：独立进程直接驱动 v4 原语，供 tests/attack/run.ps1
# 生成可复核证据（不扩大生产 DLL 导出面）。
add_executable(vty_probe
    tools/vty_probe.c
)
target_link_libraries(vty_probe PRIVATE
    verthys_core_shared_obj verthys_core_v3_obj verthys_core_legacy_api_obj
    flatccrt user32)
target_include_directories(vty_probe PRIVATE
    ${CMAKE_SOURCE_DIR}/core/include
    ${CMAKE_SOURCE_DIR}/core/src
    ${VERTHYS_SRC_SUBDIRS}
)
if(MSVC)
    target_compile_options(vty_probe PRIVATE /utf-8)
    target_link_options(vty_probe PRIVATE /STACK:16777216)
endif()
# 攻击回归以探针为证据来源：构建测试目标即产出探针
add_dependencies(verthys_tests vty_probe)

# TPM 2.0 能力探针：独立进程经 TBS 读取 PCR 与操作可清理的测试 NV 索引。
# 产物只供验收机取证，不进入生产 DLL，也不随 verthys_tests 默认构建。
add_executable(vty_tpm_probe
    tools/vty_tpm_probe.c
)
target_include_directories(vty_tpm_probe PRIVATE
    ${CMAKE_SOURCE_DIR}/core/include
)
if(MSVC)
    target_compile_options(vty_tpm_probe PRIVATE /utf-8)
    target_link_libraries(vty_tpm_probe PRIVATE tbs bcrypt)
endif()

# A8 内存残留测试宿主：hold 解锁并等待转储 / dump 生成完整内存转储 /
# crash 制造异常退出。与 vty_probe 同一边界（直接链接对象库），
# 仅存在于测试产物，不扩大生产 DLL 导出面。
add_executable(vty_mem_host
    tools/vty_mem_host.c
)
target_link_libraries(vty_mem_host PRIVATE
    verthys_core_shared_obj verthys_core_v3_obj verthys_core_legacy_api_obj
    flatccrt user32 dbghelp)
target_include_directories(vty_mem_host PRIVATE
    ${CMAKE_SOURCE_DIR}/core/include
    ${CMAKE_SOURCE_DIR}/core/src
    ${VERTHYS_SRC_SUBDIRS}
)
if(MSVC)
    target_compile_options(vty_mem_host PRIVATE /utf-8)
    target_link_options(vty_mem_host PRIVATE /STACK:16777216)
endif()
add_dependencies(verthys_tests vty_mem_host)

# A2 正向对照宿主：链接生产 DLL（而非对象库），只做 Init/Deinit，
# 用于验证“签名宿主 + 签名 DLL”放行、其余组合拒绝。
add_executable(vty_signed_host
    tools/vty_signed_host.c
)
target_link_libraries(vty_signed_host PRIVATE verthys_core)
target_include_directories(vty_signed_host PRIVATE
    ${CMAKE_SOURCE_DIR}/core/include
)
if(MSVC)
    target_compile_options(vty_signed_host PRIVATE /utf-8)
endif()
add_dependencies(verthys_tests vty_signed_host)
