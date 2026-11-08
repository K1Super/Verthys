# security-service/tests/CMakeLists.txt
# 单元测试依赖测试钩子（时钟注入/配额旁路）；生产构建不编译测试。
if(NOT VERTHYS_SERVICE_TEST_HOOKS)
    message(STATUS "security-service tests disabled: VERTHYS_SERVICE_TEST_HOOKS=OFF")
    return()
endif()

add_executable(verthys_service_tests
    test_main.c
    test_common.c
    test_protocol.c
    test_signing.c
    test_machine_state.c
    test_state_store.c
    test_service_state.c
    test_client_auth.c
    test_event_messages.c
    test_acl.c
)
target_include_directories(verthys_service_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src"
)
target_link_libraries(verthys_service_tests PRIVATE
    verthys_service_core
    advapi32 shell32 ole32 bcrypt
)
target_compile_definitions(verthys_service_tests PRIVATE
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE)
if(VERTHYS_SERVICE_TEST_HOOKS)
    target_compile_definitions(verthys_service_tests PRIVATE
        VERTHYS_SERVICE_TEST_HOOKS=1)
endif()
verthys_apply_hardening(verthys_service_tests)
add_test(NAME verthys_service_tests COMMAND verthys_service_tests)