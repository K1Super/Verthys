# core/tests/CMakeLists.txt
# 测试 exe：链接 verthys_core_obj 对象，直接调用实现（不走 DLL 边界）
# ★ 模块化重构：测试区按被测子域镜像组织（api/container/crypto/index/
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
    security/test_memory_safety.c
    container/test_format_fuzz.c
    perf/test_perf_prefetch.c
    security/test_key_separation.c
    security/test_emergency.c
    security/test_integrity_verify.c
    transaction/test_txn_recovery_inject.c
    perf/test_perf_baseline.c
    regression/test_final_repair.c
    schema/test_flatcc_demo.c
    crypto/test_cng_kernel.c
    security/test_secure_allocator.c
    container/test_v3_container.c
    container/test_v3_partition.c
    container/test_v3_extent.c
    index/test_v3_lsm.c
    api/test_v3_lifecycle.c
    property/test_v3_property.c
    crypto/test_auto_rekey.c
    security/test_runtime_hash.c
    security/test_syscall_direct.c
    security/test_defense_closure.c
)
target_link_libraries(verthys_tests PRIVATE verthys_core_obj)
# ★ WP-0：flatcc 运行时（demo schema 编解码验收）+ codegen 顺序依赖
target_link_libraries(verthys_tests PRIVATE flatccrt)
add_dependencies(verthys_tests flatcc_generate)
# ★ WP-13（K-1）：状态快照 GetGuiResources 需要 user32（verthys_core_obj 为
# PRIVATE 链接不传递，此处显式补齐）
target_link_libraries(verthys_tests PRIVATE user32)
# ★ 模块化重构：源子目录 include 表复用 core/CMakeLists.txt 的
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
    # v2 容器创建路径栈帧较深（Argon2id + 超级块序列化 + 文件创建），
    # 增大栈尺寸到 16MB 避免 STATUS_STACK_OVERFLOW
    target_link_options(verthys_tests PRIVATE /STACK:16777216)
endif()

# ★ V3 升级 WP-8：verthys_tests.exe 的 .rhat 真表链路
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
    COMMENT "[WP-8] rhash_gen: verthys_tests.exe .rhat 运行时哈希表补丁"
    VERBATIM
)

add_test(NAME verthys_tests COMMAND verthys_tests)
