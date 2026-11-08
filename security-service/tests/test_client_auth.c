/*
 * test_client_auth.c — 负向认证路径（正向认证由集成/攻击回归覆盖）
 */
#include "test_common.h"
#include "client_auth.h"

#include <string.h>

static void test_authenticode_rejects(void)
{
    wchar_t missing[VTY_PATH_MAX];
    wchar_t empty_pin[65];
    wchar_t bad_pin[65];
    size_t i;

    printf("[ AUTH ] Authenticode negative paths\n");
    (void)vty_wide_copy(missing, VTY_PATH_MAX,
                        L"Z:\\definitely-missing-verthys-test.exe");
    memset(empty_pin, 0, sizeof(empty_pin));
    for (i = 0; i < 64u; i++) bad_pin[i] = L'g';
    bad_pin[64] = L'\0';

    CHECK(vty_auth_verify_authenticode(missing, bad_pin) != 0);
    CHECK(vty_auth_verify_authenticode(missing, empty_pin) != 0);
    CHECK(vty_auth_verify_authenticode(NULL, bad_pin) != 0);
}

static void test_module_and_pipe_negative(void)
{
    wchar_t pin[65];
    size_t i;

    printf("[ AUTH ] unsigned process has no trusted verthys.dll\n");
    for (i = 0; i < 64u; i++) pin[i] = L'0';
    pin[64] = L'\0';
    CHECK(vty_auth_check_module(GetCurrentProcess(), pin) != 0);
    CHECK(vty_auth_check_module(NULL, pin) != 0);
}

static void test_client_process_negative(void)
{
    VtyClientIdentity identity;
    HANDLE process = (HANDLE)0x1;

    printf("[ AUTH ] invalid pipe handle\n");
    memset(&identity, 0, sizeof(identity));
    CHECK(vty_auth_client_process(INVALID_HANDLE_VALUE, L"", 1, &identity,
                                  &process) != 0);
    CHECK(process == NULL);
    CHECK(vty_auth_client_process(NULL, L"", 1, &identity, &process) != 0);
}

int test_client_auth_run(void)
{
    test_authenticode_rejects();
    test_module_and_pipe_negative();
    test_client_process_negative();
    return g_test_failures;
}
