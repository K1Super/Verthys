# third_party/Flatcc.cmake
# 构建 vendored flatcc（third_party/flatcc，commit a2515daa948c1ae42ba95b3a904363169dff147c）
#
# 产出两个目标：
#   - flatccrt  : flatcc 运行时静态库（builder/emitter/refmap/verifier/json_*），
#                 链入 verthys_core_obj（V3 容器 FlatBuffers 编解码运行时）
#   - flatcc_cli: flatc 编译器可执行文件（构建宿主工具，schema codegen 专用，
#                 不进入产物、不进入 verthys.dll）
#
# 集成方式：直接定义目标（与 Libsodium.cmake 同模式），不 add_subdirectory
# flatcc 自带 CMakeLists —— 其 project() 会污染全局 CMAKE_C_FLAGS、
# CMAKE_DEBUG_POSTFIX（"_d" 后缀会破坏 verthys_tests.exe 命名）与
# LIBRARY_OUTPUT_PATH，故仅照搬其官方源文件清单与编译定义。
#
# 官方 MSVC 配置对等性（third_party/flatcc/CMakeLists.txt）：
#   - FLATCC_PORTABLE（MSVC 下官方强制开启）
#   - FLATCC_REFLECTION=1（flatc 生成 .bfbs 能力，schema 工具链完整性）
#   - _CRT_SECURE_NO_WARNINGS（第三方源码内使用 fopen 等 ISO C 函数）
#   - -W3 噪声等级（第三方代码不适用本项目 /W 级别与 /sdl）

set(_fcc_root ${CMAKE_CURRENT_LIST_DIR}/flatcc)

# ---------- 运行时库 flatccrt（链入 verthys.dll） ----------
add_library(flatccrt STATIC
    ${_fcc_root}/src/runtime/builder.c
    ${_fcc_root}/src/runtime/emitter.c
    ${_fcc_root}/src/runtime/refmap.c
    ${_fcc_root}/src/runtime/verifier.c
    ${_fcc_root}/src/runtime/json_parser.c
    ${_fcc_root}/src/runtime/json_printer.c
)
target_include_directories(flatccrt PUBLIC
    ${_fcc_root}/include
)
# PUBLIC：生成头（flatcc/flatcc_*.h）的消费者必须与运行时库使用一致的可移植配置
target_compile_definitions(flatccrt PUBLIC FLATCC_PORTABLE)

if(MSVC)
    target_compile_definitions(flatccrt PRIVATE _CRT_SECURE_NO_WARNINGS)
    # 抑制第三方源码在 /W3 下的已知噪声（对齐官方 MSVC 构建不启用 -Werror）
    target_compile_options(flatccrt PRIVATE
        /wd4244   # 转换可能丢失数据
        /wd4267   # size_t->int 转换
        /wd4018   # signed/unsigned 比较
        /wd4146   # unsigned 的一元减
        /wd4334   # 32 位移位结果转换为 64 位
    )
endif()

# ---------- flatc 编译器（构建宿主工具，仅用于 schema codegen） ----------
add_executable(flatcc_cli
    ${_fcc_root}/src/cli/flatcc_cli.c
    # 编译器主体（照搬官方 src/compiler/CMakeLists.txt 源清单）
    ${_fcc_root}/external/hash/str_set.c
    ${_fcc_root}/external/hash/ptr_set.c
    ${_fcc_root}/src/compiler/hash_tables/symbol_table.c
    ${_fcc_root}/src/compiler/hash_tables/scope_table.c
    ${_fcc_root}/src/compiler/hash_tables/name_table.c
    ${_fcc_root}/src/compiler/hash_tables/schema_table.c
    ${_fcc_root}/src/compiler/hash_tables/value_set.c
    ${_fcc_root}/src/compiler/fileio.c
    ${_fcc_root}/src/compiler/parser.c
    ${_fcc_root}/src/compiler/semantics.c
    ${_fcc_root}/src/compiler/coerce.c
    ${_fcc_root}/src/compiler/flatcc.c
    ${_fcc_root}/src/compiler/codegen_c.c
    ${_fcc_root}/src/compiler/codegen_c_reader.c
    ${_fcc_root}/src/compiler/codegen_c_sort.c
    ${_fcc_root}/src/compiler/codegen_c_builder.c
    ${_fcc_root}/src/compiler/codegen_c_verifier.c
    ${_fcc_root}/src/compiler/codegen_c_sorter.c
    ${_fcc_root}/src/compiler/codegen_c_json_parser.c
    ${_fcc_root}/src/compiler/codegen_c_json_printer.c
    ${_fcc_root}/src/compiler/codegen_schema.c
    # 编译器自身内嵌的运行时（官方源清单：builder/emitter/refmap）
    ${_fcc_root}/src/runtime/builder.c
    ${_fcc_root}/src/runtime/emitter.c
    ${_fcc_root}/src/runtime/refmap.c
)
set_target_properties(flatcc_cli PROPERTIES OUTPUT_NAME flatc)
target_include_directories(flatcc_cli PRIVATE
    ${_fcc_root}/external
    ${_fcc_root}/include
    ${_fcc_root}/config
)
target_compile_definitions(flatcc_cli PRIVATE
    FLATCC_REFLECTION=1
    FLATCC_PORTABLE
)
if(MSVC)
    target_compile_definitions(flatcc_cli PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(flatcc_cli PRIVATE
        /wd4244
        /wd4267
        /wd4018
        /wd4146
        /wd4334
    )
endif()

# ---------- vendored xxHash（单头文件，XXH_INLINE_ALL 消费方定义） ----------
# third_party/xxhash/xxhash.h — v0.8.3（tag e626a72bc2321cd320e953a0ccf1584cad60f363）
# SHA-256: 17973C0DC49D9854CA26CAA191F0E12F7A424B68858D9A78DE3860D959D85E4B
# 用法：#define XXH_INLINE_ALL 后 #include "xxhash.h"（LSM Bloom Filter，WP-4）
set(VERTHYS_XXHASH_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/xxhash CACHE INTERNAL "vendored xxHash include dir")
