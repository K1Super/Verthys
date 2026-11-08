# security-service/CMakeLists.txt — 特权安全服务独立工程
#
# 与根工程解耦：独立配置、独立构建目录、独立测试与安装产物。
# 产品版本唯一来源仍是仓库根 VERSION；本工程只读取，不复制版本字面量。
cmake_minimum_required(VERSION 3.20)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../VERSION" VERTHYS_VERSION_LINE)
string(STRIP "${VERTHYS_VERSION_LINE}" VERTHYS_VERSION_LINE)
if(NOT VERTHYS_VERSION_LINE MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR "Root VERSION must be a single semver line, got '${VERTHYS_VERSION_LINE}'")
endif()

project(VerthysSecurityService
    VERSION ${VERTHYS_VERSION_LINE}
    LANGUAGES C
    DESCRIPTION "Verthys SYSTEM security service"
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
# 静态 CRT：服务与安装器不在用户可写目录加载 CRT DLL，阻断 DLL 劫持面。
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(VERTHYS_SERVICE_TEST_HOOKS
    "Build test-only console hooks and auth bypass switches" OFF)
option(VERTHYS_REQUIRE_SERVICE_SIG
    "Require Authenticode publisher pinning for the service executable" OFF)
set(VERTHYS_SERVICE_PUBLISHER_SHA256 "" CACHE STRING
    "Pinned publisher certificate SHA-256 (64 lowercase hex chars)")
set(VERTHYS_ROOT_CA_SHA256 "" CACHE STRING
    "Pinned root CA DER SHA-256 (64 lowercase hex chars); production must set it")

if(NOT "${VERTHYS_SERVICE_PUBLISHER_SHA256}" STREQUAL "")
    string(TOLOWER "${VERTHYS_SERVICE_PUBLISHER_SHA256}" VERTHYS_SERVICE_PUBLISHER_SHA256)
    string(LENGTH "${VERTHYS_SERVICE_PUBLISHER_SHA256}" VERTHYS_PUBLISHER_PIN_LENGTH)
    if(NOT VERTHYS_PUBLISHER_PIN_LENGTH EQUAL 64 OR
       NOT VERTHYS_SERVICE_PUBLISHER_SHA256 MATCHES "^[0-9a-f]+$")
        message(FATAL_ERROR "VERTHYS_SERVICE_PUBLISHER_SHA256 must be 64 hex chars")
    endif()
endif()
if(NOT "${VERTHYS_ROOT_CA_SHA256}" STREQUAL "")
    string(TOLOWER "${VERTHYS_ROOT_CA_SHA256}" VERTHYS_ROOT_CA_SHA256)
    string(LENGTH "${VERTHYS_ROOT_CA_SHA256}" VERTHYS_ROOT_CA_PIN_LENGTH)
    if(NOT VERTHYS_ROOT_CA_PIN_LENGTH EQUAL 64 OR
       NOT VERTHYS_ROOT_CA_SHA256 MATCHES "^[0-9a-f]+$")
        message(FATAL_ERROR "VERTHYS_ROOT_CA_SHA256 must be 64 hex chars")
    endif()
endif()
if(VERTHYS_REQUIRE_SERVICE_SIG AND "${VERTHYS_SERVICE_PUBLISHER_SHA256}" STREQUAL "")
    message(FATAL_ERROR "VERTHYS_REQUIRE_SERVICE_SIG=ON requires VERTHYS_SERVICE_PUBLISHER_SHA256")
endif()

if(NOT MSVC)
    message(FATAL_ERROR "security-service requires MSVC x64")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "security-service requires x64")
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/VerthysHardening.cmake")

# 版本资源：产品版本只从根 VERSION 派生；协议版本来自协议头常量。
string(REPLACE "." ";" VERTHYS_VERSION_PARTS "${VERTHYS_VERSION_LINE}")
list(GET VERTHYS_VERSION_PARTS 0 VERTHYS_VERSION_MAJOR)
list(GET VERTHYS_VERSION_PARTS 1 VERTHYS_VERSION_MINOR)
list(GET VERTHYS_VERSION_PARTS 2 VERTHYS_VERSION_PATCH)
set(VERTHYS_FILEVERSION
    "${VERTHYS_VERSION_MAJOR},${VERTHYS_VERSION_MINOR},${VERTHYS_VERSION_PATCH},0")
set(VERTHYS_PROTOCOL_VERSION "1")

set(VERTHYS_FILE_DESC "Verthys Security Service")
set(VERTHYS_INTERNAL_NAME "VerthysSecuritySvc")
set(VERTHYS_ORIGINAL_NAME "VerthysSecuritySvc.exe")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/resources/version.rc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/service_version.rc" @ONLY)

# 事件日志消息表：mc.exe 生成 .rc 与 MSGxxxxx.bin，由服务 exe 内嵌；
# 安装器把 EventMessageFile 指向该 exe，Event Viewer 才能解析描述。
find_program(VERTHYS_MC_EXE NAMES mc mc.exe REQUIRED)
set(VERTHYS_MSG_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/messages")
file(MAKE_DIRECTORY "${VERTHYS_MSG_BUILD_DIR}")
add_custom_command(
    OUTPUT
        "${VERTHYS_MSG_BUILD_DIR}/messages.rc"
        "${VERTHYS_MSG_BUILD_DIR}/messages.h"
    COMMAND "${VERTHYS_MC_EXE}"
        -h "${VERTHYS_MSG_BUILD_DIR}"
        -r "${VERTHYS_MSG_BUILD_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/resources/messages.mc"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/resources/messages.mc"
    WORKING_DIRECTORY "${VERTHYS_MSG_BUILD_DIR}"
    BYPRODUCTS
        "${VERTHYS_MSG_BUILD_DIR}/MSG00001.bin"
        "${VERTHYS_MSG_BUILD_DIR}/MSG00002.bin"
        "${VERTHYS_MSG_BUILD_DIR}/MSG00003.bin"
        "${VERTHYS_MSG_BUILD_DIR}/MSG00004.bin"
        "${VERTHYS_MSG_BUILD_DIR}/MSG00005.bin"
        "${VERTHYS_MSG_BUILD_DIR}/MSG00006.bin"
        "${VERTHYS_MSG_BUILD_DIR}/MSG00007.bin"
        "${VERTHYS_MSG_BUILD_DIR}/MSG00008.bin"
        "${VERTHYS_MSG_BUILD_DIR}/MSG00009.bin"
        "${VERTHYS_MSG_BUILD_DIR}/MSG00010.bin"
    COMMENT "Compiling security service event messages"
    VERBATIM
)

set(VERTHYS_SERVICE_SOURCES
    src/service_util.c
    src/state_crypto.c
    src/machine_state.c
    src/protocol.c
    src/service_state.c
    src/client_auth.c
)

add_library(verthys_service_core STATIC ${VERTHYS_SERVICE_SOURCES})
target_include_directories(verthys_service_core
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_compile_definitions(verthys_service_core PRIVATE
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)
if(VERTHYS_SERVICE_TEST_HOOKS)
    target_compile_definitions(verthys_service_core PRIVATE
        VERTHYS_SERVICE_TEST_HOOKS=1)
else()
    target_compile_definitions(verthys_service_core PRIVATE
        VERTHYS_SERVICE_TEST_HOOKS=0)
endif()
if(VERTHYS_REQUIRE_SERVICE_SIG)
    target_compile_definitions(verthys_service_core PRIVATE
        VERTHYS_REQUIRE_SERVICE_SIG=1)
else()
    target_compile_definitions(verthys_service_core PRIVATE
        VERTHYS_REQUIRE_SERVICE_SIG=0)
endif()
target_compile_definitions(verthys_service_core PRIVATE
    "VERTHYS_SERVICE_PUBLISHER_SHA256=\"${VERTHYS_SERVICE_PUBLISHER_SHA256}\"")
target_link_libraries(verthys_service_core PRIVATE
    advapi32 shell32 ole32 bcrypt wintrust crypt32 psapi)
verthys_apply_hardening(verthys_service_core)

add_executable(verthys_security_svc
    src/service_main.c
    src/pipe_server.c
    setup/setup_main.c
    "${CMAKE_CURRENT_BINARY_DIR}/service_version.rc"
    "${VERTHYS_MSG_BUILD_DIR}/messages.rc"
)
set_target_properties(verthys_security_svc PROPERTIES
    OUTPUT_NAME "VerthysSecuritySvc"
)
target_include_directories(verthys_security_svc PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/setup"
)
target_compile_definitions(verthys_security_svc PRIVATE
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)
if(VERTHYS_SERVICE_TEST_HOOKS)
    target_compile_definitions(verthys_security_svc PRIVATE
        VERTHYS_SERVICE_TEST_HOOKS=1)
else()
    target_compile_definitions(verthys_security_svc PRIVATE
        VERTHYS_SERVICE_TEST_HOOKS=0)
endif()
if(VERTHYS_REQUIRE_SERVICE_SIG)
    target_compile_definitions(verthys_security_svc PRIVATE
        VERTHYS_REQUIRE_SERVICE_SIG=1)
else()
    target_compile_definitions(verthys_security_svc PRIVATE
        VERTHYS_REQUIRE_SERVICE_SIG=0)
endif()
target_compile_definitions(verthys_security_svc PRIVATE
    "VERTHYS_SERVICE_PUBLISHER_SHA256=\"${VERTHYS_SERVICE_PUBLISHER_SHA256}\""
    "VERTHYS_ROOT_CA_SHA256=\"${VERTHYS_ROOT_CA_SHA256}\"")
target_link_libraries(verthys_security_svc PRIVATE
    verthys_service_core
    advapi32 shell32 ole32 bcrypt wintrust crypt32 psapi version)
verthys_apply_hardening(verthys_security_svc)

# 集成测试/攻击回归探针：不安装、不分发。
add_executable(verthys_service_probe tools/probe_main.c)
target_include_directories(verthys_service_probe PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_compile_definitions(verthys_service_probe PRIVATE
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE)
target_link_libraries(verthys_service_probe PRIVATE
    verthys_service_core
    advapi32 shell32 ole32 bcrypt wintrust crypt32 psapi)
verthys_apply_hardening(verthys_service_probe)

add_executable(verthys_fake_service tools/fake_server_main.c)
target_include_directories(verthys_fake_service PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_compile_definitions(verthys_fake_service PRIVATE
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE)
target_link_libraries(verthys_fake_service PRIVATE
    verthys_service_core
    advapi32 shell32 ole32 bcrypt wintrust crypt32 psapi)
verthys_apply_hardening(verthys_fake_service)

enable_testing()
add_subdirectory(tests)
