# third_party/Libsodium.cmake
# 构建 vendored libsodium（third_party/libsodium）为静态库，链入 verthys.dll。
# 自包含：无外部 DLL 依赖，符合 project.md 核心 DLL 黑盒设计。
#
# 照搬官方 MSVC 构建（builds/msvc/vs2026）的策略：
#   - 仅 SSE2 指令集（EnableEnhancedInstructionSet=StreamingSIMDExtensions2）
#   - SIMD 优化文件靠 sodium_runtime 运行时检测择优，编译时不设 /arch:AVX2 等
#   - MSVC 允许 intrinsic 不带 /arch 编译（生成对应指令，由运行时 CPUID 守护）
#   - 静态构建定义 SODIUM_STATIC（export.h 将 SODIUM_EXPORT 置空）
#   - Windows RNG：RtlGenRandom（advapi32，源码内 #pragma comment 已自动链接）

set(_ls_root ${CMAKE_CURRENT_LIST_DIR}/libsodium)
set(_ls_src  ${_ls_root}/src/libsodium)

# 生成 version.h（从 version.h.in 替换 @VAR@）
set(VERSION                       "1.0.20")
set(SODIUM_LIBRARY_VERSION_MAJOR  26)
set(SODIUM_LIBRARY_VERSION_MINOR  2)
set(SODIUM_LIBRARY_MINIMAL_DEF    "")  # 非精简构建
configure_file(
    ${_ls_src}/include/sodium/version.h.in
    ${CMAKE_BINARY_DIR}/libsodium/include/sodium/version.h
    @ONLY)

# 收集所有 .c（与官方 vcxproj 一致，glob + CONFIGURE_DEPENDS 便于维护）
file(GLOB_RECURSE LIBSODIUM_SOURCES CONFIGURE_DEPENDS ${_ls_src}/*.c)

add_library(libsodium STATIC ${LIBSODIUM_SOURCES})

# 公共头路径：
#   include          —— 伞头 <sodium.h>
#   include/sodium   —— 源码内相对包含 "core.h" / "private/common.h" 等
#   生成目录         —— version.h（从 .in 渲染）
target_include_directories(libsodium PUBLIC
    ${_ls_src}/include
    ${_ls_src}/include/sodium
    ${CMAKE_BINARY_DIR}/libsodium/include
    ${CMAKE_BINARY_DIR}/libsodium/include/sodium
)

# 静态构建：SODIUM_STATIC 让 export.h 把 SODIUM_EXPORT 置空。
# PUBLIC 传播给所有消费者（verthys_core_obj / 测试），否则头文件按 dllimport 生成 __imp_ 符号
target_compile_definitions(libsodium PUBLIC SODIUM_STATIC)

if(WIN32)
    target_compile_definitions(libsodium PRIVATE _WIN32 _WIN64 WIN32 WIN64)
    # RtlGenRandom 在 advapi32（源码内 pragma 也会自动链接，显式更稳）
    target_link_libraries(libsodium PUBLIC advapi32)
endif()

if(MSVC)
    # 抑制 libsodium 在 /W 级别下的常见噪声（转换、unsigned 一元减、常量比较）
    target_compile_options(libsodium PRIVATE
        /wd4244   # 转换可能丢失数据
        /wd4146   # unsigned 的一元减
        /wd4267   # size_t->int 转换
        /wd4305   # 截断
        /wd4018   # signed/unsigned 比较
        /wd4334   # 32 位移位
    )
    # 仅 SSE2，与官方一致；不开 /arch:AVX2
    target_compile_options(libsodium PRIVATE /arch:SSE2)
endif()
