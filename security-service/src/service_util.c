/*
 * service_util.c — 路径/ACL/注册表/事件日志实现
 *
 * ACL 校验为完整语义：protected DACL、owner 校验、允许 ACE 主体与掩码
 * 白名单；任何未知主体或超额权限一律 fail-closed。
 */
#include "service_util.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

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

int vty_wide_copy(wchar_t *dst, size_t cap, const wchar_t *src)
{
    size_t len;

    if (dst == NULL || cap == 0 || src == NULL) return -1;
    len = wcslen(src);
    if (len >= cap) return -1;
    memcpy(dst, src, (len + 1u) * sizeof(wchar_t));
    return 0;
}

int vty_path_join(wchar_t *out, size_t cap, const wchar_t *dir,
                  const wchar_t *name)
{
    size_t dlen;
    size_t nlen;
    int need_sep;
    size_t total;

    if (out == NULL || cap == 0 || dir == NULL || name == NULL) return -1;
    dlen = wcslen(dir);
    nlen = wcslen(name);
    need_sep = (dlen > 0 && dir[dlen - 1u] != L'\\' && dir[dlen - 1u] != L'/');
    total = dlen + (size_t)need_sep + nlen + 1u;
    if (total > cap) return -1;
    memcpy(out, dir, dlen * sizeof(wchar_t));
    if (need_sep) {
        out[dlen] = L'\\';
    }
    memcpy(out + dlen + (size_t)need_sep, name, (nlen + 1u) * sizeof(wchar_t));
    return 0;
}

int vty_known_folder(REFKNOWNFOLDERID folder, wchar_t *out, size_t cap)
{
    PWSTR wide = NULL;
    int rc = -1;

    if (out == NULL || cap == 0) return -1;
    if (SHGetKnownFolderPath(folder, KF_FLAG_CREATE, NULL, &wide) == S_OK &&
        wide != NULL) {
        if (vty_wide_copy(out, cap, wide) == 0) {
            rc = 0;
        }
    }
    if (wide != NULL) {
        CoTaskMemFree(wide);
    }
    return rc;
}

int vty_path_exists(const wchar_t *path)
{
    if (path == NULL || path[0] == L'\0') return 0;
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES ? 1 : 0;
}

int vty_path_is_directory(const wchar_t *path)
{
    DWORD attr;

    if (path == NULL || path[0] == L'\0') return 0;
    attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return 0;
    return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0 ? 1 : 0;
}

int vty_path_has_reparse(const wchar_t *path, int allow_missing)
{
    DWORD attr;

    if (path == NULL || path[0] == L'\0') return 0;
    attr = GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return allow_missing ? 1 : 0;
    }
    return (attr & FILE_ATTRIBUTE_REPARSE_POINT) == 0 ? 1 : 0;
}

int vty_read_file_exact(const wchar_t *path, uint8_t *buf, DWORD expected,
                        DWORD cap)
{
    HANDLE file;
    LARGE_INTEGER size;
    DWORD got = 0;
    DWORD total = 0;
    int rc = -1;

    if (path == NULL || buf == NULL || expected > cap || expected == 0) {
        return -1;
    }
    if (!vty_path_has_reparse(path, 0) || vty_path_is_directory(path)) {
        return -1;
    }
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    if (!GetFileSizeEx(file, &size) || size.QuadPart != (LONGLONG)expected) {
        goto done;
    }
    while (total < expected) {
        if (!ReadFile(file, buf + total, expected - total, &got, NULL) ||
            got == 0) {
            goto done;
        }
        total += got;
    }
    rc = 0;

done:
    CloseHandle(file);
    if (rc != 0) {
        vty_secure_zero(buf, cap);
    }
    return rc;
}

int vty_read_file_any(const wchar_t *path, uint8_t *buf, DWORD cap, DWORD *len)
{
    HANDLE file;
    LARGE_INTEGER size;
    DWORD got = 0;
    DWORD total = 0;
    int rc = -1;

    if (path == NULL || buf == NULL || len == NULL || cap == 0) return -1;
    *len = 0;
    if (!vty_path_has_reparse(path, 0) || vty_path_is_directory(path)) {
        return -1;
    }
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > (LONGLONG)cap) {
        goto done;
    }
    while (total < (DWORD)size.QuadPart) {
        if (!ReadFile(file, buf + total, (DWORD)size.QuadPart - total, &got,
                      NULL) ||
            got == 0) {
            goto done;
        }
        total += got;
    }
    *len = total;
    rc = 0;

done:
    CloseHandle(file);
    if (rc != 0) {
        vty_secure_zero(buf, cap);
    }
    return rc;
}

int vty_write_file_atomic_named(const wchar_t *dir, const wchar_t *final_name,
                                const wchar_t *temp_name,
                                const uint8_t *data, DWORD len)
{
    wchar_t temp[VTY_PATH_MAX];
    wchar_t final_path[VTY_PATH_MAX];
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD total = 0;
    DWORD written = 0;
    int attempt;
    int rc = -1;

    if (dir == NULL || final_name == NULL || temp_name == NULL ||
        data == NULL || len == 0) {
        return -1;
    }
    if (vty_path_join(final_path, VTY_PATH_MAX, dir, final_name) != 0) {
        return -1;
    }
    if (vty_path_join(temp, VTY_PATH_MAX, dir, temp_name) != 0) return -1;

    for (attempt = 0; attempt < 2; attempt++) {
        file = CreateFileW(temp, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_TEMPORARY, NULL);
        if (file != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_FILE_EXISTS || attempt != 0) return -1;
        if (!DeleteFileW(temp)) return -1;
    }
    if (file == INVALID_HANDLE_VALUE) return -1;

    while (total < len) {
        if (!WriteFile(file, data + total, len - total, &written, NULL) ||
            written == 0) {
            goto done;
        }
        total += written;
    }
    if (!FlushFileBuffers(file)) goto done;
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(temp, final_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        goto done;
    }
    rc = 0;

done:
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    if (rc != 0) {
        DeleteFileW(temp);
    }
    return rc;
}

int vty_write_file_atomic(const wchar_t *dir, const wchar_t *name,
                          const uint8_t *data, DWORD len)
{
    wchar_t temp_name[VTY_PATH_MAX];
    size_t nlen;

    if (name == NULL) return -1;
    nlen = wcslen(name);
    if (nlen + 5u >= VTY_PATH_MAX) return -1;
    memcpy(temp_name, name, nlen * sizeof(wchar_t));
    memcpy(temp_name + nlen, L".tmp", 5u * sizeof(wchar_t));
    return vty_write_file_atomic_named(dir, name, temp_name, data, len);
}

uint64_t vty_utc_now_100ns(void)
{
    FILETIME ft;

    GetSystemTimePreciseAsFileTime(&ft);
    return ((uint64_t)ft.dwHighDateTime << 32) | (uint64_t)ft.dwLowDateTime;
}

uint64_t vty_unix_seconds_now(void)
{
    const uint64_t epoch_offset = 116444736000000000ULL;
    uint64_t ticks = vty_utc_now_100ns();

    if (ticks <= epoch_offset) return 0;
    return (ticks - epoch_offset) / 10000000ULL;
}

void vty_secure_zero(void *p, size_t n)
{
    if (p != NULL && n > 0) {
        SecureZeroMemory(p, n);
    }
}

int vty_get_well_known_sid(WELL_KNOWN_SID_TYPE type, PSID sid, DWORD *len)
{
    DWORD cap;

    if (sid == NULL || len == NULL) return -1;
    cap = *len;
    if (cap < SECURITY_MAX_SID_SIZE) return -1;
    if (!CreateWellKnownSid(type, NULL, sid, &cap)) return -1;
    *len = cap;
    return 0;
}

int vty_sid_equal(PSID a, PSID b)
{
    return (a != NULL && b != NULL && EqualSid(a, b)) ? 1 : 0;
}

int vty_sid_hash(PSID sid, uint8_t out[32])
{
    DWORD len;

    if (sid == NULL || out == NULL) return -1;
    len = GetLengthSid(sid);
    if (len == 0) return -1;
    return vty_sha256((const uint8_t *)sid, (size_t)len, out);
}

int vty_sid_hash_log_hex(const uint8_t hash[32],
                         wchar_t out[VTY_SID_LOG_HEX_CHARS + 1u])
{
    static const wchar_t hex[] = L"0123456789abcdef";
    size_t i;

    if (hash == NULL || out == NULL) return -1;
    for (i = 0; i < VTY_SID_LOG_HEX_CHARS / 2u; i++) {
        out[i * 2u] = hex[(hash[i] >> 4) & 0x0Fu];
        out[i * 2u + 1u] = hex[hash[i] & 0x0Fu];
    }
    out[VTY_SID_LOG_HEX_CHARS] = L'\0';
    return 0;
}

int vty_enable_privilege(const wchar_t *name)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    DWORD err;

    if (name == NULL) return -1;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return -1;
    }
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        CloseHandle(token);
        return -1;
    }
    memset(&tp, 0, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(token);
        return -1;
    }
    err = GetLastError();
    CloseHandle(token);
    return err == ERROR_SUCCESS ? 0 : -1;
}

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

int vty_registry_read_dword(HKEY key, const wchar_t *name, DWORD *out)
{
    DWORD type = 0;
    DWORD size = 0;
    DWORD value = 0;

    if (key == NULL || name == NULL || out == NULL) return -1;
    size = sizeof(value);
    if (RegQueryValueExW(key, name, NULL, &type, (LPBYTE)&value, &size) !=
            ERROR_SUCCESS ||
        type != REG_DWORD || size != sizeof(value)) {
        return -1;
    }
    *out = value;
    return 0;
}

int vty_registry_write_dword(HKEY key, const wchar_t *name, DWORD value)
{
    if (key == NULL || name == NULL) return -1;
    return RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE *)&value,
                          sizeof(value)) == ERROR_SUCCESS
               ? 0
               : -1;
}

int vty_registry_read_qword(HKEY key, const wchar_t *name, uint64_t *out)
{
    DWORD type = 0;
    DWORD size = 0;
    uint64_t value = 0;

    if (key == NULL || name == NULL || out == NULL) return -1;
    size = sizeof(value);
    if (RegQueryValueExW(key, name, NULL, &type, (LPBYTE)&value, &size) !=
            ERROR_SUCCESS ||
        type != REG_QWORD || size != sizeof(value)) {
        return -1;
    }
    *out = value;
    return 0;
}

int vty_registry_write_qword(HKEY key, const wchar_t *name, uint64_t value)
{
    if (key == NULL || name == NULL) return -1;
    return RegSetValueExW(key, name, 0, REG_QWORD, (const BYTE *)&value,
                          sizeof(value)) == ERROR_SUCCESS
               ? 0
               : -1;
}

int vty_registry_read_string(HKEY key, const wchar_t *name,
                             wchar_t *out, size_t cap)
{
    DWORD type = 0;
    DWORD size = 0;

    if (key == NULL || name == NULL || out == NULL || cap == 0) return -1;
    size = (DWORD)(cap * sizeof(wchar_t));
    if (RegQueryValueExW(key, name, NULL, &type, (LPBYTE)out, &size) !=
            ERROR_SUCCESS ||
        type != REG_SZ || size < sizeof(wchar_t) ||
        size > cap * sizeof(wchar_t)) {
        return -1;
    }
    out[cap - 1u] = L'\0';
    return 0;
}

int vty_registry_write_string(HKEY key, const wchar_t *name,
                              const wchar_t *value)
{
    DWORD size;

    if (key == NULL || name == NULL || value == NULL) return -1;
    size = (DWORD)((wcslen(value) + 1u) * sizeof(wchar_t));
    return RegSetValueExW(key, name, 0, REG_SZ, (const BYTE *)value, size) ==
                   ERROR_SUCCESS
               ? 0
               : -1;
}

int vty_registry_read_binary(HKEY key, const wchar_t *name,
                             uint8_t *out, DWORD cap, DWORD *len)
{
    DWORD type = 0;
    DWORD size = cap;

    if (key == NULL || name == NULL || out == NULL || len == NULL) return -1;
    if (RegQueryValueExW(key, name, NULL, &type, out, &size) != ERROR_SUCCESS ||
        type != REG_BINARY || size > cap) {
        return -1;
    }
    *len = size;
    return 0;
}

int vty_registry_write_binary(HKEY key, const wchar_t *name,
                              const uint8_t *data, DWORD len)
{
    if (key == NULL || name == NULL || data == NULL || len == 0) return -1;
    return RegSetValueExW(key, name, 0, REG_BINARY, data, len) == ERROR_SUCCESS
               ? 0
               : -1;
}

int vty_registry_delete_value(HKEY key, const wchar_t *name)
{
    LONG rc;

    if (key == NULL || name == NULL) return -1;
    rc = RegDeleteValueW(key, name);
    return (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND) ? 0 : -1;
}

int vty_get_process_image_path(HANDLE process, wchar_t *out, size_t cap)
{
    DWORD size;

    if (process == NULL || out == NULL || cap == 0) return -1;
    size = (DWORD)cap;
    if (!QueryFullProcessImageNameW(process, 0, out, &size)) return -1;
    out[cap - 1u] = L'\0';
    return 0;
}

int vty_get_self_image_path(wchar_t *out, size_t cap)
{
    DWORD size;

    if (out == NULL || cap == 0) return -1;
    size = GetModuleFileNameW(NULL, out, (DWORD)cap);
    if (size == 0 || size >= cap) return -1;
    out[cap - 1u] = L'\0';
    return 0;
}

typedef struct VtyEventGate {
    DWORD id;
    ULONGLONG last_ms;
    DWORD suppressed;
} VtyEventGate;

#define VTY_EVENT_GATE_COUNT 8u
#define VTY_EVENT_GATE_WINDOW_MS 10000ULL

static SRWLOCK g_event_gate_lock = SRWLOCK_INIT;
static VtyEventGate g_event_gates[VTY_EVENT_GATE_COUNT];

static int event_gate_should_log(DWORD id, DWORD *suppressed)
{
    ULONGLONG now = GetTickCount64();
    size_t i;
    size_t free_slot = VTY_EVENT_GATE_COUNT;

    *suppressed = 0;
    AcquireSRWLockExclusive(&g_event_gate_lock);
    for (i = 0; i < VTY_EVENT_GATE_COUNT; i++) {
        if (g_event_gates[i].id == id &&
            g_event_gates[i].last_ms != 0) {
            if (now - g_event_gates[i].last_ms < VTY_EVENT_GATE_WINDOW_MS) {
                g_event_gates[i].suppressed++;
                ReleaseSRWLockExclusive(&g_event_gate_lock);
                return 0;
            }
            *suppressed = g_event_gates[i].suppressed;
            g_event_gates[i].suppressed = 0;
            g_event_gates[i].last_ms = now;
            ReleaseSRWLockExclusive(&g_event_gate_lock);
            return 1;
        }
        if (g_event_gates[i].id == 0 && free_slot == VTY_EVENT_GATE_COUNT) {
            free_slot = i;
        }
    }
    if (free_slot == VTY_EVENT_GATE_COUNT) {
        free_slot = (size_t)(id % VTY_EVENT_GATE_COUNT);
        *suppressed = g_event_gates[free_slot].suppressed;
    }
    g_event_gates[free_slot].id = id;
    g_event_gates[free_slot].last_ms = now;
    g_event_gates[free_slot].suppressed = 0;
    ReleaseSRWLockExclusive(&g_event_gate_lock);
    return 1;
}

void vty_event_log(WORD type, DWORD id, const wchar_t *detail)
{
    HANDLE source;
    const wchar_t *strings[1];
    wchar_t buffer[256];
    DWORD suppressed = 0;
    DWORD count = 0;

    if (!event_gate_should_log(id, &suppressed)) return;

    if (detail != NULL && suppressed > 0) {
        if (swprintf_s(buffer, 256, L"[suppressed %lu] %s",
                       (unsigned long)suppressed, detail) > 0) {
            detail = buffer;
        }
    } else if (detail == NULL && suppressed > 0) {
        if (swprintf_s(buffer, 256, L"[suppressed %lu]",
                       (unsigned long)suppressed) > 0) {
            detail = buffer;
        }
    }

    source = RegisterEventSourceW(NULL, VTY_SVC_EVENT_SOURCE);
    if (source == NULL) return;
    if (detail != NULL) {
        strings[0] = detail;
        count = 1;
    }
    ReportEventW(source, type, 0, id, NULL, (WORD)count, 0,
                 count > 0 ? strings : NULL, NULL);
    DeregisterEventSource(source);
}
