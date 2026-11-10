/*
 * vty_secure_state.c — 安全状态固定位置、ACL 加固与见证身份派生
 *
 * 设计取舍：
 *   - 目录只从 KnownFolder 解析：环境变量可以被同一用户的任意进程改写，
 *     一旦参与状态定位，删除状态即可把熔断/回滚重置为首次运行。
 *   - 目录 DACL 设置为 protected（阻断父目录继承），只授予当前用户与
 *     SYSTEM 完全控制、Administrators 只读；同用户进程仍可删除文件，
 *     这是本层的残余边界，严格机器级隔离由后续特权组件承担。
 *   - 见证身份只绑定设备根 + 用户 SID（熔断）或设备根 + 容器 UUID
 *     （回滚），不得包含状态文件路径。
 *
 * 编码约定：本文件为 Windows 专用实现，路径统一用 UTF-8 入参、W 系列
 * API 执行，避免 ANSI 代码页把非 ASCII 目录名截断。
 */
#define _WIN32_WINNT 0x0A00
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <shlobj.h>
#include <aclapi.h>
#include <objbase.h>
#include <stdio.h>
#include <string.h>

#include "vty_secure_state.h"
#include "vty_util.h"
#include "vty_kdf.h"
#include "hardware_binding.h"
#include "vty_tpm_witness.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "advapi32.lib")

#define VSS_SID_BUF_BYTES 256u
#define VSS_DOMAIN_MAX 64u
#define VSS_SUBJECT_MAX 32u
#define VSS_MSG_MAX 160u

#ifndef SECURITY_MAX_SID_SIZE
#define SECURITY_MAX_SID_SIZE 68u
#endif

/* 只允许固定 basename：拒绝分隔符、上跳与空名，防止调用方把外部输入
 * 拼进安全目录。 */
static int valid_state_name(const char *name)
{
    if (name == NULL || name[0] == '\0' || strlen(name) >= 64u) return 0;
    if (strchr(name, '\\') != NULL || strchr(name, '/') != NULL) return 0;
    if (strstr(name, "..") != NULL) return 0;
    return 1;
}

static int utf8_to_wide(const char *in, wchar_t *out, size_t cap_chars)
{
    int n;
    if (in == NULL || out == NULL || cap_chars == 0) return 0;
    n = MultiByteToWideChar(CP_UTF8, 0, in, -1, out, (int)cap_chars);
    return (n > 0) ? 1 : 0;
}

/* KnownFolder + 后缀；只在解析失败时返回 0，不读取任何环境变量。 */
static int known_subpath(const char *suffix, char *out, size_t cap)
{
    PWSTR wide = NULL;
    char base[VTY_SECURE_STATE_PATH_BYTES];
    int n;
    size_t len;

    if (suffix == NULL || out == NULL || cap == 0) return 0;
    if (SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_CREATE, NULL, &wide)
        != S_OK || wide == NULL) {
        if (wide != NULL) CoTaskMemFree(wide);
        return 0;
    }
    n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, base, (int)sizeof(base),
                            NULL, NULL);
    CoTaskMemFree(wide);
    if (n <= 0) return 0;
    len = strlen(base);
    while (len > 0 && (base[len - 1] == '\\' || base[len - 1] == '/')) {
        base[--len] = '\0';
    }
    if (sprintf_s(out, cap, "%s\\%s", base, suffix) < 0) return 0;
    return 1;
}

static int path_has_reparse(const char *path, int allow_missing)
{
    wchar_t w[VTY_SECURE_STATE_PATH_BYTES];
    DWORD attr;

    if (!utf8_to_wide(path, w, VTY_SECURE_STATE_PATH_BYTES)) return 0;
    attr = GetFileAttributesW(w);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return allow_missing ? 1 : 0;
    }
    return ((attr & FILE_ATTRIBUTE_REPARSE_POINT) == 0) ? 1 : 0;
}

static int get_current_user_sid(BYTE *buf, DWORD buf_len, PSID *sid)
{
    HANDLE token = NULL;
    DWORD got = 0;
    int ok = 0;

    if (buf == NULL || sid == NULL || buf_len < sizeof(TOKEN_USER)) return 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
    if (GetTokenInformation(token, TokenUser, buf, buf_len, &got)) {
        *sid = ((TOKEN_USER *)buf)->User.Sid;
        ok = (*sid != NULL) ? 1 : 0;
    }
    CloseHandle(token);
    return ok;
}

static int well_known_sid(WELL_KNOWN_SID_TYPE type, BYTE *buf, PSID *sid)
{
    DWORD len = SECURITY_MAX_SID_SIZE;

    if (buf == NULL || sid == NULL) return 0;
    if (!CreateWellKnownSid(type, NULL, (PSID)buf, &len)) return 0;
    *sid = (PSID)buf;
    return 1;
}

static int sid_equal(PSID a, PSID b)
{
    return (a != NULL && b != NULL && EqualSid(a, b)) ? 1 : 0;
}

/* DACL 必须：protected、非 NULL、当前用户与 SYSTEM 通过标准允许 ACE
 * 获得完全控制，其它 SID 不得持有写/删/改权限。
 *
 * 对象 ACE 的对象类型/继承对象类型 GUID 是条件字段：结构体中的
 * SidStart 固定位于两个 GUID 之后，而实际 ACE 只包含 Flags 声明的 GUID。
 * 因此 SID 必须按 ACE 起始地址 + Flags 计算，不能直接取 SidStart；
 * 同时校验 ACE 尺寸与 SID 长度，避免越界读取。 */
static int allowed_ace_info(ACE_HEADER *hdr, PSID *sid, ACCESS_MASK *mask,
                            int *standard_allow)
{
    if (hdr == NULL || sid == NULL || mask == NULL || standard_allow == NULL) {
        return -1;
    }
    *sid = NULL;
    *mask = 0;
    *standard_allow = 0;

    if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
        ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)hdr;
        size_t off = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart);
        size_t sid_len;

        /* 最小 SID 头部 8 字节，确保 SidStart 可读且完整落在 ACE 内。 */
        if (hdr->AceSize < off + sizeof(DWORD) * 2u) return -1;
        if (!IsValidSid((PSID)&ace->SidStart)) return -1;
        sid_len = GetLengthSid((PSID)&ace->SidStart);
        if (sid_len == 0 || off + sid_len > hdr->AceSize) return -1;
        *sid = (PSID)&ace->SidStart;
        *mask = ace->Mask;
        *standard_allow = 1;
        return 0;
    }

    if (hdr->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE) {
        ACCESS_ALLOWED_OBJECT_ACE *ace = (ACCESS_ALLOWED_OBJECT_ACE *)hdr;
        size_t off = FIELD_OFFSET(ACCESS_ALLOWED_OBJECT_ACE, ObjectType);
        size_t sid_len;
        DWORD flags;

        /* ObjectType 之前必须已包含 Header + Mask + Flags。 */
        if (hdr->AceSize < off) return -1;
        flags = ace->Flags;
        if ((flags & ~(ACE_OBJECT_TYPE_PRESENT |
                       ACE_INHERITED_OBJECT_TYPE_PRESENT)) != 0) {
            return -1;
        }
        if ((flags & ACE_OBJECT_TYPE_PRESENT) != 0) off += sizeof(GUID);
        if ((flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0) off += sizeof(GUID);
        if (hdr->AceSize < off + sizeof(DWORD) * 2u) return -1;
        if (!IsValidSid((PSID)((PBYTE)hdr + off))) return -1;
        sid_len = GetLengthSid((PSID)((PBYTE)hdr + off));
        if (sid_len == 0 || off + sid_len > hdr->AceSize) return -1;
        *sid = (PSID)((PBYTE)hdr + off);
        *mask = ace->Mask;
        return 0;
    }

    return -1;
}

static int dacl_is_hardened(PSECURITY_DESCRIPTOR sd, PSID user, PSID system,
                            PSID admins)
{
    ACL *dacl = NULL;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    WORD control = 0;
    DWORD revision = 0;
    DWORD i;
    int user_full = 0;
    int system_full = 0;
    /* 目录级别还必须禁止删除子项（FILE_DELETE_CHILD）与等价通用写位；
     * 对象 ACE 同样按该掩码判定，避免按对象类型条件授权绕过。 */
    const ACCESS_MASK dangerous =
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
        FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | WRITE_DAC |
        WRITE_OWNER | ACCESS_SYSTEM_SECURITY | GENERIC_WRITE | GENERIC_ALL |
        MAXIMUM_ALLOWED;

    if (sd == NULL) return 0;
    if (!GetSecurityDescriptorControl(sd, &control, &revision)) return 0;
    if ((control & SE_DACL_PROTECTED) == 0) return 0;
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted)) return 0;
    if (!present || dacl == NULL) return 0;

    for (i = 0; i < (DWORD)dacl->AceCount; i++) {
        ACE_HEADER *hdr = NULL;
        PSID sid = NULL;
        ACCESS_MASK mask = 0;
        int standard_allow = 0;

        if (!GetAce(dacl, i, (LPVOID *)&hdr) || hdr == NULL) return 0;

        switch (hdr->AceType) {
        case ACCESS_DENIED_ACE_TYPE:
        case ACCESS_DENIED_OBJECT_ACE_TYPE:
        case SYSTEM_AUDIT_ACE_TYPE:
        case SYSTEM_ALARM_ACE_TYPE:
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
        case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
        case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
        case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:
        case SYSTEM_ACCESS_FILTER_ACE_TYPE:
            /* 拒绝/审计/标签/资源属性/过滤类 ACE 不授予访问权限。 */
            continue;
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            if (allowed_ace_info(hdr, &sid, &mask, &standard_allow) != 0) {
                return 0;
            }
            break;
        default:
            /* 回调 ACE 与未知类型无法静态判定，按未加固处理。 */
            return 0;
        }

        if (sid_equal(sid, user)) {
            if (standard_allow &&
                ((mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS ||
                 (mask & GENERIC_ALL) != 0)) {
                user_full = 1;
            }
        } else if (sid_equal(sid, system)) {
            if (standard_allow &&
                ((mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS ||
                 (mask & GENERIC_ALL) != 0)) {
                system_full = 1;
            }
        } else if (sid_equal(sid, admins)) {
            /* 只读授权；即使带写权限也按危险 ACE 拒绝 */
            if ((mask & dangerous) != 0) return 0;
        } else if ((mask & dangerous) != 0) {
            return 0;
        }
    }
    return (user_full && system_full) ? 1 : 0;
}

/* 校验既有目录：owner 必须是当前用户、SYSTEM 或 Administrators（预创建
 * 目录常见），DACL 必须保持加固形态。 */
static int validate_secure_dir(const char *path, PSID user, PSID system,
                               PSID admins)
{
    wchar_t w[VTY_SECURE_STATE_PATH_BYTES];
    PSECURITY_DESCRIPTOR sd = NULL;
    PSID owner = NULL;
    ACL *dacl = NULL;
    int ok = 0;

    if (!utf8_to_wide(path, w, VTY_SECURE_STATE_PATH_BYTES)) return 0;
    if (GetNamedSecurityInfoW(w, SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION |
                                  DACL_SECURITY_INFORMATION,
                              &owner, NULL, &dacl, NULL, &sd) != ERROR_SUCCESS) {
        return 0;
    }
    if ((sid_equal(owner, user) || sid_equal(owner, system) ||
         sid_equal(owner, admins)) &&
        dacl_is_hardened(sd, user, system, admins)) {
        ok = 1;
    }
    if (sd != NULL) LocalFree(sd);
    return ok;
}

/* 创建/加固目录；已存在时重设 DACL 并复核，任何失败 fail-closed。 */
static int ensure_secure_dir(const char *path)
{
    wchar_t w[VTY_SECURE_STATE_PATH_BYTES];
    BYTE user_buf[VSS_SID_BUF_BYTES];
    BYTE system_buf[VSS_SID_BUF_BYTES];
    BYTE admins_buf[VSS_SID_BUF_BYTES];
    PSID user = NULL;
    PSID system = NULL;
    PSID admins = NULL;
    EXPLICIT_ACCESS_W ea[3];
    ACL *new_acl = NULL;
    DWORD set_rc;
    int ok;

    if (!utf8_to_wide(path, w, VTY_SECURE_STATE_PATH_BYTES)) return 0;
    if (!path_has_reparse(path, 1)) return 0;
    if (!CreateDirectoryW(w, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return 0;
    }
    if (!path_has_reparse(path, 0)) return 0;
    if (!get_current_user_sid(user_buf, sizeof(user_buf), &user)) return 0;
    if (!well_known_sid(WinLocalSystemSid, system_buf, &system)) return 0;
    if (!well_known_sid(WinBuiltinAdministratorsSid, admins_buf, &admins)) return 0;

    /* 既有目录已验证安全则直接通过，不重复设置 ACL（避免企业环境
     * 中 WRITE_DAC 受限时把已安全目录判为不可用）。 */
    if (validate_secure_dir(path, user, system, admins)) return 1;

    memset(ea, 0, sizeof(ea));
    ea[0].grfAccessPermissions = FILE_ALL_ACCESS;
    ea[0].grfAccessMode = GRANT_ACCESS;
    ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName = (LPWSTR)user;

    ea[1].grfAccessPermissions = FILE_ALL_ACCESS;
    ea[1].grfAccessMode = GRANT_ACCESS;
    ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = (LPWSTR)system;

    ea[2].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    ea[2].grfAccessMode = GRANT_ACCESS;
    ea[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[2].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[2].Trustee.ptstrName = (LPWSTR)admins;

    if (SetEntriesInAclW(3, ea, NULL, &new_acl) != ERROR_SUCCESS) return 0;
    set_rc = SetNamedSecurityInfoW(
        w, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
            PROTECTED_DACL_SECURITY_INFORMATION,
        user, NULL, new_acl, NULL);
    LocalFree(new_acl);
    if (set_rc != ERROR_SUCCESS) return 0;

    ok = validate_secure_dir(path, user, system, admins);
    return ok;
}

int vty_secure_state_file_path(const char *name, char *out, size_t cap)
{
    char dir[VTY_SECURE_STATE_PATH_BYTES];
    char verthys_dir[VTY_SECURE_STATE_PATH_BYTES];
    wchar_t w[VTY_SECURE_STATE_PATH_BYTES];

    if (!valid_state_name(name) || out == NULL || cap == 0) return VTY_E_INVALID;
    if (!known_subpath("Verthys", verthys_dir, sizeof(verthys_dir))) {
        return VTY_E_POLICY;
    }
    if (!utf8_to_wide(verthys_dir, w, VTY_SECURE_STATE_PATH_BYTES)) {
        return VTY_E_POLICY;
    }
    if (!CreateDirectoryW(w, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return VTY_E_IO;
    }
    if (!path_has_reparse(verthys_dir, 0)) return VTY_E_POLICY;

    if (!known_subpath("Verthys\\Security", dir, sizeof(dir))) {
        return VTY_E_POLICY;
    }
    if (!ensure_secure_dir(dir)) return VTY_E_POLICY;
    if (sprintf_s(out, cap, "%s\\%s", dir, name) < 0) return VTY_E_INVALID;
    if (!path_has_reparse(out, 1)) return VTY_E_POLICY;
    return VTY_OK;
}

/* 安全状态目录预检。只做目录解析/创建/ACL 加固与复核，不写状态文件；
 * 供 Verthys_Init 与安装期预检工具复用。失败返回 VTY_E_POLICY/VTY_E_IO。 */
int vty_secure_state_preflight(void)
{
    char probe[VTY_SECURE_STATE_PATH_BYTES];

    return vty_secure_state_file_path("lockout.state", probe, sizeof(probe));
}

int vty_secure_state_validate_path(const char *path, int allow_missing)
{
    char parent[VTY_SECURE_STATE_PATH_BYTES];
    const char *slash;
    size_t n;
    BYTE user_buf[VSS_SID_BUF_BYTES];
    BYTE system_buf[VSS_SID_BUF_BYTES];
    BYTE admins_buf[VSS_SID_BUF_BYTES];
    PSID user = NULL;
    PSID system = NULL;
    PSID admins = NULL;

    if (path == NULL || path[0] == '\0') return VTY_E_INVALID;
    slash = strrchr(path, '\\');
    if (slash == NULL || slash == path) return VTY_E_POLICY;
    n = (size_t)(slash - path);
    if (n >= sizeof(parent)) return VTY_E_INVALID;
    memcpy(parent, path, n);
    parent[n] = '\0';

    if (!path_has_reparse(parent, 0)) return VTY_E_POLICY;
    if (!get_current_user_sid(user_buf, sizeof(user_buf), &user)) return VTY_E_POLICY;
    if (!well_known_sid(WinLocalSystemSid, system_buf, &system)) return VTY_E_POLICY;
    if (!well_known_sid(WinBuiltinAdministratorsSid, admins_buf, &admins)) return VTY_E_POLICY;
    if (!validate_secure_dir(parent, user, system, admins)) return VTY_E_POLICY;
    if (!path_has_reparse(path, allow_missing ? 1 : 0)) return VTY_E_POLICY;
    return VTY_OK;
}

/* 域分离派生：长度前缀 + domain + 设备根 + 主体，取 SHA-256 前 16 字节。 */
static int witness_id_derive(const char *domain,
                             const uint8_t device[VTY_HASH_BYTES],
                             const uint8_t *subject, size_t subject_len,
                             uint8_t id[VTY_UUID_BYTES])
{
    uint8_t msg[VSS_MSG_MAX];
    uint8_t digest[VTY_HASH_BYTES];
    size_t n = 0;
    size_t domain_len;

    if (domain == NULL || device == NULL || subject == NULL || id == NULL) {
        return VTY_E_INVALID;
    }
    domain_len = strlen(domain);
    if (domain_len > VSS_DOMAIN_MAX || subject_len > VSS_SUBJECT_MAX) {
        return VTY_E_INVALID;
    }
    vty_put_u32(msg + n, (uint32_t)domain_len); n += 4;
    memcpy(msg + n, domain, domain_len); n += domain_len;
    memcpy(msg + n, device, VTY_HASH_BYTES); n += VTY_HASH_BYTES;
    vty_put_u32(msg + n, (uint32_t)subject_len); n += 4;
    memcpy(msg + n, subject, subject_len); n += subject_len;

    if (vty_sha256(digest, msg, n) != VTY_OK) {
        vty_secure_zero(msg, sizeof(msg));
        return VTY_E_TPM;
    }
    memcpy(id, digest, VTY_UUID_BYTES);
    vty_secure_zero(digest, sizeof(digest));
    vty_secure_zero(msg, sizeof(msg));
    return VTY_OK;
}

static int device_root_hash(uint8_t out[VTY_HASH_BYTES])
{
    if (hardware_binding_get_hash(out) != 0) return VTY_E_TPM;
    return VTY_OK;
}

static int current_user_sid_hash(uint8_t out[VTY_HASH_BYTES])
{
    BYTE buf[VSS_SID_BUF_BYTES];
    PSID sid = NULL;
    DWORD sid_len;
    int rc;

    if (!get_current_user_sid(buf, sizeof(buf), &sid)) return VTY_E_POLICY;
    sid_len = GetLengthSid(sid);
    if (sid_len == 0 || sid_len > sizeof(buf)) return VTY_E_POLICY;
    rc = vty_sha256(out, (const uint8_t *)sid, (size_t)sid_len);
    vty_secure_zero(buf, sizeof(buf));
    return (rc == VTY_OK) ? VTY_OK : VTY_E_TPM;
}

int vty_secure_state_identity_lockout(uint8_t id[VTY_UUID_BYTES])
{
    uint8_t device[VTY_HASH_BYTES];
    uint8_t user[VTY_HASH_BYTES];
    int rc;

    if (id == NULL) return VTY_E_INVALID;
    if (device_root_hash(device) != VTY_OK) return VTY_E_TPM;
    if (current_user_sid_hash(user) != VTY_OK) {
        vty_secure_zero(device, sizeof(device));
        return VTY_E_POLICY;
    }
    rc = witness_id_derive("verthys/lockout/witness/v2", device, user,
                           sizeof(user), id);
    vty_secure_zero(device, sizeof(device));
    vty_secure_zero(user, sizeof(user));
    return rc;
}

int vty_secure_state_identity_rollback(const uint8_t vault_uuid[VTY_UUID_BYTES],
                                       uint8_t id[VTY_UUID_BYTES])
{
    uint8_t device[VTY_HASH_BYTES];
    int rc;

    if (vault_uuid == NULL || id == NULL) return VTY_E_INVALID;
    if (device_root_hash(device) != VTY_OK) return VTY_E_TPM;
    rc = witness_id_derive("verthys/rollback/witness/v2", device, vault_uuid,
                           VTY_UUID_BYTES, id);
    vty_secure_zero(device, sizeof(device));
    return rc;
}

