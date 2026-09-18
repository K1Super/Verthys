cmake_minimum_required(VERSION 3.20)

# Verthys - 私密数据管理器
# 四层架构：UI 交互层 / 应用调度层 / 核心 DLL 层 / 持久化存储层
# 第一阶段：核心安全 DLL（本 CMake 构建 core 与其测试）
project(Verthys
    VERSION 2.6.1
    LANGUAGES C CXX
    DESCRIPTION "Private data manager with encrypted .verthys container"
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 默认 Release（安全核心不开 Debug 给用户）
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# 平台判断
set(VERTHYS_WINDOWS OFF)
if(WIN32)
    set(VERTHYS_WINDOWS ON)
    # Windows：Unicode API
    add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

# 编译加固选项（见 cmake/VerthysHardening.cmake）
include(${CMAKE_SOURCE_DIR}/cmake/VerthysHardening.cmake)

# vendored libsodium（静态库，链入核心 DLL）
include(${CMAKE_SOURCE_DIR}/third_party/Libsodium.cmake)

# ★ WP-0：vendored flatcc（运行时 flatccrt + flatc 编译器）与 xxHash 单头文件
#   - flatccrt 链入核心 DLL（V3 容器 FlatBuffers 编解码运行时）
#   - flatcc_cli（flatc）为构建宿主工具，仅用于 schema codegen
include(${CMAKE_SOURCE_DIR}/third_party/Flatcc.cmake)

# ★ WP-10：测试注册上提至根（原在 core/CMakeLists.txt 内）——
#   enable_testing() 所在目录才生成 CTestTestfile.cmake；置于子目录时
#   构建根无该文件，ctest --test-dir <build_root> 报 "No tests were
#   found" 且退出码 0（假绿）。上提后 fuzz 冒烟门（脚本 + CI）从
#   构建根即可发现全部测试。须在 add_subdirectory(core) 之前调用
#   （仅对其后处理的子目录生效）。
enable_testing()

add_subdirectory(core)

# UI 层与应用调度层由 verthys-tauri（Tauri + Vue3）实现，不再使用 Qt6
