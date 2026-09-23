# core/tests/fuzz/CMakeLists.txt
#
# 进入条件：VERTHYS_ENABLE_FUZZ=ON（core/CMakeLists.txt 门控）。
# 工具链：MSVC /fsanitize=address /fsanitize=fuzzer（两个独立开关）。
#
# 勘误：本文件早期版本仅用
#   /fsanitize=fuzzer 并注释"隐含 ASAN"——该假设错误。MSVC 的
#   fuzzer 开关只嵌入 clang_rt.fuzzer + libsancov（覆盖率反馈），
#   不含内存安全插桩。实测症状：fuzz_partition.exe 导入表无
#   clang_rt.asan_dynamic-x86_64.dll、libFuzzer 启动告警
#   "Failed to find function __sanitizer_*"、堆越界由 CRT 调试堆
#   （而非 ASAN 红区）检出。修正：显式叠加 /fsanitize=address，
#   编译器在对象内嵌入 /DEFAULTLIB:clang_rt.fuzzer +
#   clang_rt.asan_dynamic-x86_64，链接期自动引入 ASAN 动态运行库
#   （本文件已负责将 DLL 随行拷贝至目标目录）。
#   注意：本工具链（MSVC 19.51）不接受逗号组合形式
#   /fsanitize=address,fuzzer（实测 D9002 整项忽略 → fuzzer 运行库
#   未链接 → LNK2019 main 缺失）——必须写成两个独立选项。
#
# 架构（覆盖率完整性红线）：
#   verthys_core_fuzz_obj —— 与 verthys_core_obj 同源的核心代码，整体以
#   /fsanitize=address + /fsanitize=fuzzer 重编译。仅把"未插桩的 verthys_core_obj +
#   插桩的 harness"链接为 fuzz 目标是无效配置：解析器无覆盖率反馈，
#   libFuzzer 退化为随机字节生成器（对深结构解析器接近零发现率）。
#
#   gen_seeds —— 非插桩工具（链 verthys_core_obj），按生产序列化路径
#   镜像生成合法明文帧语料
#
# 互斥约束：MSVC ASAN 与 /GL（LTCG）互斥 → fuzz 对象库不套用
#   VERTHYS_RELEASE_FLAGS，仅保留 VERTHYS_SAFETY_FLAGS + VERTHYS_LINK_BASE。
#   （/RTC1 共存：本工具链 VS 2026 14.51 实测接受 /RTC1 与
#   /fsanitize=address 同用——build_asan Debug 全量对象为证；ASAN
#   拦截分配器后应用堆走红区，/RTC 栈检查继续生效，二者互补。）
#
# 运行：
#   冒烟（ctest，每次构建自动执行）：
#     fuzz_<target>.exe corpus/<target> -runs=2000
#   持续（CI / scripts/build_core.fuzz.ps1，每目标 10 分钟）：
#     fuzz_<target>.exe corpus/<target> -max_total_time=600

if(NOT MSVC)
    message(FATAL_ERROR "VERTHYS_ENABLE_FUZZ 需要 MSVC /fsanitize=fuzzer（VS 2019 16.9+）")
endif()

set(VERTHYS_FUZZ_CORPUS_DIR ${CMAKE_CURRENT_BINARY_DIR}/corpus)

# ---------- 插桩版核心对象库 ----------

add_library(verthys_core_fuzz_obj OBJECT ${VERTHYS_CORE_SOURCES})
add_dependencies(verthys_core_fuzz_obj flatcc_generate)
# /FS：并行编译 PDB 写入（与主对象库同策略）
# 安全基线（/GS /guard:cf 等）保留；/GL 与 ASAN 互斥故不套 Release 优化集
target_compile_options(verthys_core_fuzz_obj PRIVATE
    /FS
    /fsanitize=address
    /fsanitize=fuzzer
    ${VERTHYS_SAFETY_FLAGS}
)
target_include_directories(verthys_core_fuzz_obj PRIVATE
    ${CMAKE_SOURCE_DIR}/core/include
    ${CMAKE_SOURCE_DIR}/core/src
    ${VERTHYS_SRC_SUBDIRS}
    ${VERTHYS_SCHEMA_GEN_DIR}
    ${VERTHYS_XXHASH_INCLUDE_DIR}
)
target_link_libraries(verthys_core_fuzz_obj PRIVATE flatccrt libsodium)
if(WIN32)
    target_link_libraries(verthys_core_fuzz_obj PRIVATE
        user32 wintrust crypt32 shlwapi psapi bcrypt ncrypt)
endif()
target_link_options(verthys_core_fuzz_obj PRIVATE ${VERTHYS_LINK_BASE})
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_link_options(verthys_core_fuzz_obj PRIVATE ${VERTHYS_LINK_X64})
endif()

# ---------- 种子生成器（非插桩，复用生产对象库） ----------

add_executable(gen_seeds gen_seeds.c)
target_link_libraries(gen_seeds PRIVATE verthys_core_obj flatccrt)
add_dependencies(gen_seeds flatcc_generate)
if(MSVC)
    target_compile_options(gen_seeds PRIVATE /utf-8)
endif()
target_include_directories(gen_seeds PRIVATE
    ${CMAKE_SOURCE_DIR}/core/include
    ${CMAKE_SOURCE_DIR}/core/src
    ${VERTHYS_SRC_SUBDIRS}
    ${CMAKE_SOURCE_DIR}/core/schema/generated
    ${CMAKE_CURRENT_SOURCE_DIR}
)
# 构建即生成语料（幂等覆写；退出码非 0 = 构建失败——禁静默降级）
add_custom_command(TARGET gen_seeds POST_BUILD
    COMMAND $<TARGET_FILE:gen_seeds> ${VERTHYS_FUZZ_CORPUS_DIR}
    COMMENT "gen_seeds: 生成语料种子 -> ${VERTHYS_FUZZ_CORPUS_DIR}"
    VERBATIM
)

# ---------- 5 个 fuzz 目标 + ASAN 运行库随行 ----------

# ASAN 动态运行库定位（本地 + CI 双环境稳健）：
#   CMAKE_C_COMPILER_DIRECTORY 在 VS 生成器下不会由 CMake 填充（实测为空），
#   故从 CMAKE_C_COMPILER 全路径自行派生 cl.exe 所在目录；CI（Ninja +
#   msvc-dev-cmd）下 CMAKE_C_COMPILER 同样是全路径，VCToolsInstallDir 作兜底。
get_filename_component(VERTHYS_FUZZ_CL_DIR "${CMAKE_C_COMPILER}" DIRECTORY)
find_file(VERTHYS_FUZZ_ASAN_DLL
    NAMES clang_rt.asan_dynamic-x86_64.dll
    PATHS "${VERTHYS_FUZZ_CL_DIR}"
          "$ENV{VCToolsInstallDir}/bin/Hostx64/x64"
    NO_DEFAULT_PATH
)

foreach(VERTHYS_FUZZ_TGT superblock partition extent sstable import)
    add_executable(fuzz_${VERTHYS_FUZZ_TGT} fuzz_${VERTHYS_FUZZ_TGT}.c)
    target_link_libraries(fuzz_${VERTHYS_FUZZ_TGT} PRIVATE verthys_core_fuzz_obj)
    add_dependencies(fuzz_${VERTHYS_FUZZ_TGT} gen_seeds)
    if(MSVC)
        target_compile_options(fuzz_${VERTHYS_FUZZ_TGT} PRIVATE
            /utf-8 /fsanitize=address /fsanitize=fuzzer)
    endif()
    target_include_directories(fuzz_${VERTHYS_FUZZ_TGT} PRIVATE
        ${CMAKE_SOURCE_DIR}/core/include
        ${CMAKE_SOURCE_DIR}/core/src
        ${VERTHYS_SRC_SUBDIRS}
        ${CMAKE_SOURCE_DIR}/core/schema/generated
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_options(fuzz_${VERTHYS_FUZZ_TGT} PRIVATE ${VERTHYS_LINK_BASE})
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(fuzz_${VERTHYS_FUZZ_TGT} PRIVATE ${VERTHYS_LINK_X64})
    endif()
    if(NOT VERTHYS_FUZZ_ASAN_DLL)
        message(FATAL_ERROR
            "未找到 ASAN 运行库 clang_rt.asan_dynamic-x86_64.dll\n"
            "  已搜索: ${VERTHYS_FUZZ_CL_DIR}\n"
            "          $ENV{VCToolsInstallDir}/bin/Hostx64/x64\n"
            "  （CMAKE_C_COMPILER = ${CMAKE_C_COMPILER}）")
    endif()
    add_custom_command(TARGET fuzz_${VERTHYS_FUZZ_TGT} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${VERTHYS_FUZZ_ASAN_DLL} $<TARGET_FILE_DIR:fuzz_${VERTHYS_FUZZ_TGT}>
            COMMENT "ASAN 运行库随行: fuzz_${VERTHYS_FUZZ_TGT}"
            VERBATIM
        )
    # 冒烟门（ctest；-runs 有界，秒级；崩溃/ASAN 报告 → 非零退出 → 门红）
    # TIMEOUT 300s：CRT 弹窗/挂起等异常场景下 ctest 强杀进程判负而非
    # 无限挂死 CI（fuzz_msvc_prepare 已禁 CRT 对话框，此为第二道保险）
    add_test(NAME fuzz_${VERTHYS_FUZZ_TGT}_smoke
        COMMAND $<TARGET_FILE:fuzz_${VERTHYS_FUZZ_TGT}>
                ${VERTHYS_FUZZ_CORPUS_DIR}/${VERTHYS_FUZZ_TGT}
                -runs=2000 -max_len=1048576 -timeout=25
    )
    set_tests_properties(fuzz_${VERTHYS_FUZZ_TGT}_smoke PROPERTIES TIMEOUT 300)
endforeach()

# 探索引导文档：语料目录随构建生成，不落入版本库
file(MAKE_DIRECTORY ${VERTHYS_FUZZ_CORPUS_DIR})
