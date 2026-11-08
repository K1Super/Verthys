/*
 * test_acl.c — U9：目录 ACL 轮廓与重解析点拒绝
 *
 * 说明：设置 owner=SYSTEM 需要 SeRestorePrivilege；非管理员测试进程无法
 * 验证该路径。测试在非管理员环境跳过 ACL 施加，仅保留重解析点检查。
 */
#include "test_common.h"
#include "service_util.h"

#include <string.h>

static int current_user_is_admin(void)
{
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = NULL;
    BOOL member = FALSE;

    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &admins)) {
        return 0;
    }
    if (!CheckTokenMembership(NULL, admins, &member)) {
        member = FALSE;
    }
    FreeSid(admins);
    return member ? 1 : 0;
}

static void test_reparse(void)
{
    wchar_t dir[VTY_PATH_MAX];
    wchar_t missing[VTY_PATH_MAX];

    printf("[ U9 ] reparse point policy\n");
    if (test_make_temp_dir(dir, VTY_PATH_MAX) != 0) {
        CHECK(0);
        return;
    }
    CHECK_EQ_INT(vty_path_has_reparse(dir, 0), 1);
    CHECK_EQ_INT(vty_path_has_reparse(dir, 1), 1);
    CHECK_EQ_INT(vty_path_join(missing, VTY_PATH_MAX, dir,
                               L"does-not-exist"),
                 0);
    CHECK_EQ_INT(vty_path_has_reparse(missing, 1), 1);
    CHECK_EQ_INT(vty_path_has_reparse(missing, 0), 0);
    test_remove_tree(dir);
}

static void test_acl_profiles(void)
{
    wchar_t dir_a[VTY_PATH_MAX];
    wchar_t dir_b[VTY_PATH_MAX];

    printf("[ U9 ] directory ACL profiles\n");
    if (!current_user_is_admin()) {
        SKIP("requires administrator token to apply and clean SECURITY_DIR ACL");
        return;
    }
    if (test_make_temp_dir(dir_a, VTY_PATH_MAX) != 0 ||
        test_make_temp_dir(dir_b, VTY_PATH_MAX) != 0) {
        CHECK(0);
        return;
    }

    CHECK_EQ_INT(vty_acl_verify_path_ex(dir_a, VTY_ACL_PROFILE_SECURITY_DIR, 0),
                 0);
    CHECK_EQ_INT(vty_acl_apply_path_ex(dir_a, VTY_ACL_PROFILE_SECURITY_DIR, 0),
                 0);
    CHECK_EQ_INT(vty_acl_verify_path_ex(dir_a, VTY_ACL_PROFILE_SECURITY_DIR, 0),
                 1);
    CHECK_EQ_INT(vty_acl_verify_path_ex(dir_a, VTY_ACL_PROFILE_PARENT, 0),
                 0);

    CHECK_EQ_INT(vty_acl_apply_path_ex(dir_b, VTY_ACL_PROFILE_PARENT, 0), 0);
    CHECK_EQ_INT(vty_acl_verify_path_ex(dir_b, VTY_ACL_PROFILE_PARENT, 0), 1);
    CHECK_EQ_INT(vty_acl_verify_path_ex(dir_b, VTY_ACL_PROFILE_SECURITY_DIR, 0),
                 0);

    (void)vty_acl_force_admin_full(dir_a);
    (void)vty_acl_force_admin_full(dir_b);
    test_remove_tree(dir_a);
    test_remove_tree(dir_b);
}

static void test_sid_log_hex(void)
{
    uint8_t hash[32];
    wchar_t hex[VTY_SID_LOG_HEX_CHARS + 1u];
    wchar_t hex2[VTY_SID_LOG_HEX_CHARS + 1u];
    size_t i;

    printf("[ U12 ] SID log hex is truncated and key-free\n");
    for (i = 0; i < 32u; i++) hash[i] = (uint8_t)i;
    CHECK_EQ_INT(vty_sid_hash_log_hex(hash, hex), 0);
    CHECK_EQ_U64(wcslen(hex), VTY_SID_LOG_HEX_CHARS);
    for (i = 0; i < VTY_SID_LOG_HEX_CHARS; i++) {
        CHECK((hex[i] >= L'0' && hex[i] <= L'9') ||
              (hex[i] >= L'a' && hex[i] <= L'f'));
    }
    hash[0] ^= 0x01u;
    CHECK_EQ_INT(vty_sid_hash_log_hex(hash, hex2), 0);
    CHECK(wcscmp(hex, hex2) != 0);
    CHECK(wcschr(hex, L'-') == NULL);
    CHECK(wcschr(hex, L'S') == NULL);
}

int test_acl_run(void)
{
    test_reparse();
    test_acl_profiles();
    test_sid_log_hex();
    return g_test_failures;
}
