/*
 * util_acl.c — 路径与注册表 ACL 应用及完整性校验（fail-closed）
 */

#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

#ifndef SECURITY_MAX_SID_SIZE
#define SECURITY_MAX_SID_SIZE 68u
#endif

#define VTY_ACL_DANGEROUS_FILE \
    (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | \
     DELETE | WRITE_DAC | WRITE_OWNER)
#define VTY_ACL_DANGEROUS_REG \
    (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | \
     WRITE_OWNER)
#define VTY_ACL_USERS_DIR (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)

const wchar_t *vty_acl_sddl(VtyAclProfile profile)
{
    switch (profile) {
    case VTY_ACL_PROFILE_PARENT:
        return L"O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
               L"(A;OICI;FRFX;;;BU)";
    case VTY_ACL_PROFILE_SECURITY_DIR:
        return L"O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FR;;;BA)";
    case VTY_ACL_PROFILE_INSTALL_DIR:
        return L"O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
               L"(A;OICI;FRFX;;;BU)";
    case VTY_ACL_PROFILE_STATE_FILE:
        return L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;BA)";
    case VTY_ACL_PROFILE_REGISTRY:
        return L"O:SYG:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)";
    default:
        return NULL;
    }
}

typedef struct VtyAclExpect {
    DWORD system_full;
    DWORD admin_required;
    DWORD admin_max;
    DWORD users_max;
    DWORD dangerous;
    int registry;
} VtyAclExpect;

static int acl_expect_for(VtyAclProfile profile, VtyAclExpect *out)
{
    if (out == NULL) return -1;
    memset(out, 0, sizeof(*out));
    switch (profile) {
    case VTY_ACL_PROFILE_PARENT:
    case VTY_ACL_PROFILE_INSTALL_DIR:
        out->system_full = FILE_ALL_ACCESS;
        out->admin_required = FILE_ALL_ACCESS;
        out->admin_max = FILE_ALL_ACCESS;
        out->users_max = VTY_ACL_USERS_DIR;
        out->dangerous = VTY_ACL_DANGEROUS_FILE;
        out->registry = 0;
        return 0;
    case VTY_ACL_PROFILE_SECURITY_DIR:
        out->system_full = FILE_ALL_ACCESS;
        out->admin_required = FILE_GENERIC_READ;
        out->admin_max = FILE_GENERIC_READ;
        out->users_max = 0;
        out->dangerous = VTY_ACL_DANGEROUS_FILE;
        out->registry = 0;
        return 0;
    case VTY_ACL_PROFILE_STATE_FILE:
        out->system_full = FILE_ALL_ACCESS;
        out->admin_required = FILE_GENERIC_READ;
        out->admin_max = FILE_GENERIC_READ;
        out->users_max = 0;
        out->dangerous = VTY_ACL_DANGEROUS_FILE;
        out->registry = 0;
        return 0;
    case VTY_ACL_PROFILE_REGISTRY:
        out->system_full = KEY_ALL_ACCESS;
        out->admin_required = KEY_ALL_ACCESS;
        out->admin_max = KEY_ALL_ACCESS;
        out->users_max = KEY_READ;
        out->dangerous = VTY_ACL_DANGEROUS_REG;
        out->registry = 1;
        return 0;
    default:
        return -1;
    }
}

static PSID ace_sid(ACE_HEADER *hdr, DWORD *mask_out)
{
    ACCESS_ALLOWED_ACE *ace;

    switch (hdr->AceType) {
    case ACCESS_ALLOWED_ACE_TYPE:
        ace = (ACCESS_ALLOWED_ACE *)hdr;
        *mask_out = ace->Mask;
        return (PSID)&ace->SidStart;
    case ACCESS_ALLOWED_OBJECT_ACE_TYPE: {
        ACCESS_ALLOWED_OBJECT_ACE *obj = (ACCESS_ALLOWED_OBJECT_ACE *)hdr;
        *mask_out = obj->Mask;
        return (PSID)&obj->SidStart;
    }
    default:
        return NULL;
    }
}

static int current_user_sid_copy(PSID out, DWORD cap)
{
    HANDLE token = NULL;
    BYTE buf[VTY_SID_BUF_BYTES];
    DWORD got = 0;
    PSID sid = NULL;
    int rc = -1;

    if (out == NULL || cap == 0) return -1;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return -1;
    if (GetTokenInformation(token, TokenUser, buf, sizeof(buf), &got)) {
        sid = ((TOKEN_USER *)buf)->User.Sid;
        if (sid != NULL && CopySid(cap, out, sid)) {
            rc = 0;
        }
    }
    CloseHandle(token);
    vty_secure_zero(buf, sizeof(buf));
    return rc;
}

static int acl_walker(PSECURITY_DESCRIPTOR sd, VtyAclProfile profile,
                      int require_system_owner)
{
    VtyAclExpect expect;
    ACL *dacl = NULL;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    WORD control = 0;
    DWORD revision = 0;
    BYTE system_buf[VTY_SID_BUF_BYTES];
    BYTE admin_buf[VTY_SID_BUF_BYTES];
    BYTE user_buf[VTY_SID_BUF_BYTES];
    BYTE current_buf[VTY_SID_BUF_BYTES];
    PSID system = (PSID)system_buf;
    PSID admins = (PSID)admin_buf;
    PSID users = (PSID)user_buf;
    PSID current = (PSID)current_buf;
    PSID owner = NULL;
    BOOL owner_defaulted = FALSE;
    DWORD system_len = VTY_SID_BUF_BYTES;
    DWORD admin_len = VTY_SID_BUF_BYTES;
    DWORD user_len = VTY_SID_BUF_BYTES;
    DWORD current_len = VTY_SID_BUF_BYTES;
    DWORD i;
    int system_ok = 0;
    int admin_ok = 0;

    if (sd == NULL || acl_expect_for(profile, &expect) != 0) return 0;
    if (!GetSecurityDescriptorControl(sd, &control, &revision)) return 0;
    if ((control & SE_DACL_PROTECTED) == 0) return 0;
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)) return 0;
    if (!present || dacl == NULL) return 0;
    if (!GetSecurityDescriptorOwner(sd, &owner, &owner_defaulted)) return 0;

    if (vty_get_well_known_sid(WinLocalSystemSid, system, &system_len) != 0 ||
        vty_get_well_known_sid(WinBuiltinAdministratorsSid, admins,
                               &admin_len) != 0 ||
        vty_get_well_known_sid(WinBuiltinUsersSid, users, &user_len) != 0) {
        return 0;
    }
    if (require_system_owner) {
        if (!vty_sid_equal(owner, system)) return 0;
    } else {
        if (current_user_sid_copy(current, current_len) != 0) return 0;
        if (!vty_sid_equal(owner, system) && !vty_sid_equal(owner, admins) &&
            !vty_sid_equal(owner, current)) {
            return 0;
        }
    }

    for (i = 0; i < (DWORD)dacl->AceCount; i++) {
        ACE_HEADER *hdr = NULL;
        PSID sid;
        DWORD mask = 0;

        if (!GetAce(dacl, i, (LPVOID *)&hdr) || hdr == NULL) return 0;
        if (hdr->AceType == ACCESS_DENIED_ACE_TYPE ||
            hdr->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE) {
            continue;
        }
        sid = ace_sid(hdr, &mask);
        if (sid == NULL) return 0;

        if (vty_sid_equal(sid, system)) {
            if ((mask & expect.system_full) != expect.system_full) return 0;
            if ((mask & ~expect.system_full) != 0) return 0;
            system_ok = 1;
        } else if (vty_sid_equal(sid, admins)) {
            if ((mask & expect.admin_required) != expect.admin_required) return 0;
            if ((mask & ~expect.admin_max) != 0) return 0;
            admin_ok = 1;
        } else if (vty_sid_equal(sid, users)) {
            if (expect.users_max == 0) return 0;
            if ((mask & ~expect.users_max) != 0) return 0;
            if ((mask & expect.dangerous) != 0) return 0;
        } else {
            return 0;
        }
    }
    return (system_ok && admin_ok) ? 1 : 0;
}

int vty_acl_apply_path_ex(const wchar_t *path, VtyAclProfile profile,
                          int require_system_owner)
{
    const wchar_t *sddl;
    PSECURITY_DESCRIPTOR sd = NULL;
    PSID owner = NULL;
    ACL *dacl = NULL;
    BOOL owner_defaulted = FALSE;
    BOOL present = FALSE;
    BOOL dacl_defaulted = FALSE;
    DWORD flags;
    DWORD rc;

    if (path == NULL) return -1;
    sddl = vty_acl_sddl(profile);
    if (sddl == NULL) return -1;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sd, NULL)) {
        return -1;
    }
    (void)GetSecurityDescriptorOwner(sd, &owner, &owner_defaulted);
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &dacl_defaulted) ||
        !present || dacl == NULL) {
        LocalFree(sd);
        return -1;
    }
    flags = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if (require_system_owner) {
        (void)vty_enable_privilege(SE_RESTORE_NAME);
        flags |= OWNER_SECURITY_INFORMATION;
    }
    rc = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, flags,
                               require_system_owner ? owner : NULL,
                               NULL, dacl, NULL);
    LocalFree(sd);
    if (rc != ERROR_SUCCESS) return -1;
    return vty_acl_verify_path_ex(path, profile, require_system_owner) ? 0 : -1;
}

int vty_acl_verify_path_ex(const wchar_t *path, VtyAclProfile profile,
                           int require_system_owner)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PSID owner = NULL;
    ACL *dacl = NULL;
    int ok = 0;

    if (path == NULL) return 0;
    if (GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION |
                                  DACL_SECURITY_INFORMATION,
                              &owner, NULL, &dacl, NULL, &sd) != ERROR_SUCCESS) {
        return 0;
    }
    ok = acl_walker(sd, profile, require_system_owner);
    if (sd != NULL) LocalFree(sd);
    return ok;
}

int vty_acl_apply_path(const wchar_t *path, VtyAclProfile profile)
{
    return vty_acl_apply_path_ex(path, profile, 1);
}

int vty_acl_verify_path(const wchar_t *path, VtyAclProfile profile)
{
    return vty_acl_verify_path_ex(path, profile, 1);
}

int vty_acl_apply_registry_ex(HKEY key, VtyAclProfile profile,
                              int require_system_owner)
{
    const wchar_t *sddl;
    PSECURITY_DESCRIPTOR sd = NULL;
    PSID owner = NULL;
    BOOL owner_defaulted = FALSE;
    SECURITY_INFORMATION flags;
    LONG rc;

    if (key == NULL) return -1;
    sddl = vty_acl_sddl(profile);
    if (sddl == NULL) return -1;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sd, NULL)) {
        return -1;
    }
    (void)GetSecurityDescriptorOwner(sd, &owner, &owner_defaulted);
    flags = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if (require_system_owner) {
        (void)vty_enable_privilege(SE_RESTORE_NAME);
        flags |= OWNER_SECURITY_INFORMATION;
    }
    rc = RegSetKeySecurity(key, flags, sd);
    LocalFree(sd);
    if (rc != ERROR_SUCCESS) return -1;
    return vty_acl_verify_registry_ex(key, profile, require_system_owner) ? 0 : -1;
}

int vty_acl_verify_registry_ex(HKEY key, VtyAclProfile profile,
                               int require_system_owner)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_INFORMATION info = OWNER_SECURITY_INFORMATION |
                                DACL_SECURITY_INFORMATION;
    DWORD len = 0;
    int ok = 0;

    if (key == NULL) return 0;
    RegGetKeySecurity(key, info, NULL, &len);
    if (len == 0) return 0;
    sd = (PSECURITY_DESCRIPTOR)LocalAlloc(LMEM_FIXED, len);
    if (sd == NULL) return 0;
    if (RegGetKeySecurity(key, info, sd, &len) == ERROR_SUCCESS) {
        ok = acl_walker(sd, profile, require_system_owner);
    }
    LocalFree(sd);
    return ok;
}

int vty_acl_apply_registry(HKEY key, VtyAclProfile profile)
{
    return vty_acl_apply_registry_ex(key, profile, 1);
}

int vty_acl_verify_registry(HKEY key, VtyAclProfile profile)
{
    return vty_acl_verify_registry_ex(key, profile, 1);
}

int vty_acl_force_admin_full(const wchar_t *path)
{
    const wchar_t *sddl = L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    PSECURITY_DESCRIPTOR sd = NULL;
    PSID owner = NULL;
    ACL *dacl = NULL;
    BOOL owner_defaulted = FALSE;
    BOOL present = FALSE;
    BOOL dacl_defaulted = FALSE;
    BYTE admin_buf[VTY_SID_BUF_BYTES];
    DWORD admin_len = VTY_SID_BUF_BYTES;
    PSID admins = (PSID)admin_buf;
    DWORD rc;

    if (path == NULL || !vty_path_exists(path)) return -1;
    (void)vty_enable_privilege(SE_TAKE_OWNERSHIP_NAME);
    (void)vty_enable_privilege(SE_RESTORE_NAME);
    if (vty_get_well_known_sid(WinBuiltinAdministratorsSid, admins,
                               &admin_len) != 0) {
        return -1;
    }
    (void)SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                                OWNER_SECURITY_INFORMATION, admins, NULL, NULL,
                                NULL);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sd, NULL)) {
        return -1;
    }
    (void)GetSecurityDescriptorOwner(sd, &owner, &owner_defaulted);
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &dacl_defaulted) ||
        !present || dacl == NULL) {
        LocalFree(sd);
        return -1;
    }
    rc = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                               OWNER_SECURITY_INFORMATION |
                                   DACL_SECURITY_INFORMATION |
                                   PROTECTED_DACL_SECURITY_INFORMATION,
                               owner, NULL, dacl, NULL);
    LocalFree(sd);
    return rc == ERROR_SUCCESS ? 0 : -1;
}
