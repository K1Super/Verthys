/*
 * test_secure_state.c — 安全状态路径与见证身份验收
 *
 * 覆盖：
 *   - LOCALAPPDATA 环境变量被改写时，状态路径仍落在 KnownFolder；
 *   - 安全目录路径格式正确，非法 basename 被拒绝；
 *   - 见证身份稳定、域分离：熔断与回滚不同，不同容器 UUID 不同。
 *
 * 说明：本用例会触发安全目录创建与 ACL 加固（产品首次运行同样会创建），
 * 但不写入任何状态文件，也不删除既有目录。
 */
#include "verthys_test.h"
#include "vty_types.h"
#include "vty_device_root.h"
#include "vty_secure_state.h"

#include <windows.h>
#include <aclapi.h>
#include <accctrl.h>
#include <stdio.h>
#include <string.h>

static void restore_env(const char *name, const char *value)
{
    if (value != NULL && value[0] != '\0') {
        (void)SetEnvironmentVariableA(name, value);
    } else {
        (void)SetEnvironmentVariableA(name, NULL);
    }
}

TEST(secure_state_paths_and_identity)
{
    char old_env[512];
    char path[VTY_SECURE_STATE_PATH_BYTES];
    uint8_t lock_id1[VTY_UUID_BYTES];
    uint8_t lock_id2[VTY_UUID_BYTES];
    uint8_t rb_a[VTY_UUID_BYTES];
    uint8_t rb_b[VTY_UUID_BYTES];
    uint8_t uuid_a[VTY_UUID_BYTES];
    uint8_t uuid_b[VTY_UUID_BYTES];
    DWORD old_len;

    CHECK_EQ(vty_device_root_init(), VTY_OK);

    memset(old_env, 0, sizeof(old_env));
    old_len = GetEnvironmentVariableA("LOCALAPPDATA", old_env, sizeof(old_env));
    if (old_len >= sizeof(old_env)) old_env[0] = '\0';

    /* 把环境变量指向攻击者可控目录；安全状态路径必须忽略它。 */
    CHECK_EQ(SetEnvironmentVariableA("LOCALAPPDATA",
                                     "C:\\Windows\\Temp\\vty_env_redirect"), TRUE);
    CHECK_EQ(vty_secure_state_file_path("lockout.state", path, sizeof(path)),
             VTY_OK);
    CHECK(strstr(path, "\\Verthys\\Security\\lockout.state") != NULL);
    CHECK(strstr(path, "vty_env_redirect") == NULL);
    CHECK_EQ(vty_secure_state_validate_path(path, 1), VTY_OK);

    /* 非法 basename 必须拒绝，防止把外部输入拼进安全目录。 */
    CHECK_EQ(vty_secure_state_file_path("..\\evil", path, sizeof(path)),
             VTY_E_INVALID);
    CHECK_EQ(vty_secure_state_file_path("a/b", path, sizeof(path)),
             VTY_E_INVALID);
    CHECK_EQ(vty_secure_state_file_path("", path, sizeof(path)),
             VTY_E_INVALID);

    /* 见证身份稳定且域分离。 */
    CHECK_EQ(vty_secure_state_identity_lockout(lock_id1), VTY_OK);
    CHECK_EQ(vty_secure_state_identity_lockout(lock_id2), VTY_OK);
    CHECK(memcmp(lock_id1, lock_id2, sizeof(lock_id1)) == 0);

    memset(uuid_a, 0x21, sizeof(uuid_a));
    memset(uuid_b, 0x22, sizeof(uuid_b));
    CHECK_EQ(vty_secure_state_identity_rollback(uuid_a, rb_a), VTY_OK);
    CHECK_EQ(vty_secure_state_identity_rollback(uuid_b, rb_b), VTY_OK);
    CHECK(memcmp(rb_a, rb_b, sizeof(rb_a)) != 0);
    CHECK(memcmp(lock_id1, rb_a, sizeof(lock_id1)) != 0);

    restore_env("LOCALAPPDATA", old_env);
    return 0;
}

/* 路径预检与句柄预算：路径生成不泄漏句柄。 */
TEST(secure_state_preflight_and_handle_budget)
{
    char path[VTY_SECURE_STATE_PATH_BYTES];
    size_t i;
    DWORD before = 0;
    DWORD after = 0;
    HANDLE proc = GetCurrentProcess();

    CHECK_EQ(vty_device_root_init(), VTY_OK);

    /* 预检：已安全目录直通（重复调用不重建 ACL） */
    CHECK_EQ(vty_secure_state_preflight(), VTY_OK);
    GetProcessHandleCount(proc, &before);
    for (i = 0; i < 1000u; i++) {
        CHECK_EQ(vty_secure_state_file_path("lockout.state", path, sizeof(path)),
                 VTY_OK);
    }
    GetProcessHandleCount(proc, &after);
    CHECK(after <= before + 4u);
    return 0;
}

/* 构造测试目录 ACL：用户/SYSTEM 完全控制、Administrators 只读，
 * 再追加一个 Everyone 的对象 ACE。object_mask=GENERIC_READ 时合法，
 * GENERIC_WRITE 时必须被判定为未加固。 */
static int apply_object_ace_acl(const wchar_t *dir, PSID user, PSID system,
                                PSID admins, PSID everyone, DWORD object_mask)
{
    BYTE acl_buf[1024];
    ACL *acl = (ACL *)acl_buf;
    BYTE object_buf[sizeof(ACCESS_ALLOWED_OBJECT_ACE) + SECURITY_MAX_SID_SIZE];
    PACCESS_ALLOWED_OBJECT_ACE object_ace = (PACCESS_ALLOWED_OBJECT_ACE)object_buf;
    DWORD everyone_len = GetLengthSid(everyone);
    DWORD object_off = (DWORD)FIELD_OFFSET(ACCESS_ALLOWED_OBJECT_ACE, ObjectType);

    memset(object_buf, 0, sizeof(object_buf));
    /* 对象 ACE 要求 ACL_REVISION_DS；普通 ACE 也兼容该修订。 */
    if (!InitializeAcl(acl, sizeof(acl_buf), ACL_REVISION_DS)) return -1;
    if (!AddAccessAllowedAceEx(acl, ACL_REVISION_DS,
                               SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                               FILE_ALL_ACCESS, user)) return -1;
    if (!AddAccessAllowedAceEx(acl, ACL_REVISION_DS,
                               SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                               FILE_ALL_ACCESS, system)) return -1;
    if (!AddAccessAllowedAceEx(acl, ACL_REVISION_DS,
                               SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                               FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
                               admins)) return -1;

    /* 无 ObjectType/InheritedObjectType GUID 时，SID 紧跟在 Mask/Flags 后；
     * 结构体的 SidStart 位于两个可选 GUID 之后，不能用于此处。 */
    object_ace->Header.AceType = ACCESS_ALLOWED_OBJECT_ACE_TYPE;
    object_ace->Header.AceFlags = 0;
    object_ace->Header.AceSize = (WORD)(object_off + everyone_len);
    object_ace->Mask = object_mask;
    object_ace->Flags = 0;
    memcpy(object_buf + object_off, everyone, everyone_len);
    if (!AddAce(acl, ACL_REVISION_DS, MAXDWORD, object_ace,
                object_ace->Header.AceSize)) return -1;

    if (SetNamedSecurityInfoW((LPWSTR)dir, SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION |
                                  PROTECTED_DACL_SECURITY_INFORMATION,
                              NULL, NULL, acl, NULL) != ERROR_SUCCESS) {
        return -1;
    }
    return 0;
}

TEST(secure_state_rejects_object_ace_grant)
{
    wchar_t temp[MAX_PATH];
    wchar_t dir[MAX_PATH];
    char dir_u8[VTY_SECURE_STATE_PATH_BYTES];
    char file_u8[VTY_SECURE_STATE_PATH_BYTES];
    union {
        TOKEN_USER user;
        BYTE bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } token_data;
    union {
        SID sid;
        BYTE bytes[SECURITY_MAX_SID_SIZE];
    } system_sid, admins_sid, everyone_sid;
    PSID user = NULL;
    PSID system = NULL;
    PSID admins = NULL;
    PSID everyone = NULL;
    HANDLE token = NULL;
    DWORD len;
    LARGE_INTEGER now;
    int rc = 1;

    if (GetTempPathW(MAX_PATH, temp) == 0) return 1;
    QueryPerformanceCounter(&now);
    if (swprintf_s(dir, MAX_PATH, L"%sverthys_acl_%lu_%lld", temp,
                   (unsigned long)GetCurrentProcessId(),
                   (long long)now.QuadPart) < 0) {
        return 1;
    }
    if (!CreateDirectoryW(dir, NULL)) return 1;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto cleanup;
    len = (DWORD)sizeof(token_data.bytes);
    if (!GetTokenInformation(token, TokenUser, token_data.bytes, len, &len)) {
        goto cleanup;
    }
    user = token_data.user.User.Sid;
    CloseHandle(token);
    token = NULL;

    len = SECURITY_MAX_SID_SIZE;
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, system_sid.bytes, &len)) {
        goto cleanup;
    }
    system = (PSID)&system_sid;
    len = SECURITY_MAX_SID_SIZE;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL,
                            admins_sid.bytes, &len)) {
        goto cleanup;
    }
    admins = (PSID)&admins_sid;
    len = SECURITY_MAX_SID_SIZE;
    if (!CreateWellKnownSid(WinWorldSid, NULL, everyone_sid.bytes, &len)) {
        goto cleanup;
    }
    everyone = (PSID)&everyone_sid;

    if (WideCharToMultiByte(CP_UTF8, 0, dir, -1, dir_u8, sizeof(dir_u8),
                            NULL, NULL) <= 0) {
        goto cleanup;
    }
    if (sprintf_s(file_u8, sizeof(file_u8), "%s\\probe.state", dir_u8) < 0) {
        goto cleanup;
    }

    /* 只读对象 ACE 不应误伤合法加固目录。 */
    if (apply_object_ace_acl(dir, user, system, admins, everyone,
                             GENERIC_READ) != 0) {
        goto cleanup;
    }
    if (vty_secure_state_validate_path(file_u8, 1) != VTY_OK) goto cleanup;

    /* 对象 ACE 授予 GENERIC_WRITE 必须拒绝。 */
    if (apply_object_ace_acl(dir, user, system, admins, everyone,
                             GENERIC_WRITE) != 0) {
        goto cleanup;
    }
    if (vty_secure_state_validate_path(file_u8, 1) != VTY_E_POLICY) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (token != NULL) CloseHandle(token);
    /* 归还未保护 DACL 后再删除，避免测试残留带 Everyone 写权限的目录。 */
    (void)SetNamedSecurityInfoW((LPWSTR)dir, SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION |
                                    UNPROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, NULL, NULL);
    (void)RemoveDirectoryW(dir);
    return rc;
}
