/*
 * test_main.c — 测试入口
 */
#include "test_common.h"

int g_test_failures = 0;
int g_test_checks = 0;
int g_test_skipped = 0;

int test_protocol_run(void);
int test_signing_run(void);
int test_machine_state_run(void);
int test_state_store_run(void);
int test_service_state_run(void);
int test_client_auth_run(void);
int test_event_messages_run(void);
int test_acl_run(void);

int main(void)
{
    printf("=== Verthys security service unit tests ===\n");
    test_protocol_run();
    test_signing_run();
    test_machine_state_run();
    test_state_store_run();
    test_service_state_run();
    test_client_auth_run();
    test_event_messages_run();
    test_acl_run();
    printf("=== Summary: %d passed, %d failed, %d skipped ===\n",
           g_test_checks - g_test_failures, g_test_failures, g_test_skipped);
    return g_test_failures == 0 ? 0 : 1;
}
