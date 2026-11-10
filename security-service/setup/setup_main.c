/*
 * setup_main.c — VerthysSecuritySvc.exe 的安装/卸载子命令实现
 *
 * 支持 /install（默认）、/uninstall、/repair、/reset-state、/repair-keys、
 * /status、/quiet、/keep-state。由服务 exe 的 wmain 依据首参分发。
 * 降级一律拒绝。
 *
 * 安全边界：
 *   - 安装逻辑不生成私钥；私钥只由服务首次启动生成。
 *   - 安装前按固定指纹校验随包根 CA 并导入，再校验服务 exe 的
 *     Authenticode 发布者指纹（生产构建）。
 *   - 任一步失败必须回滚到上一服务版本，返回对应退出码。
 */
#define _WIN32_WINNT 0x0A00
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <winver.h>

#include "client_auth.h"
#include "protocol.h"
#include "service_state.h"
#include "service_util.h"
#include "setup_entry.h"
#include "state_crypto.h"
#include "vty_svc_protocol.h"

#pragma comment(lib, "version.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")

#define SETUP_EXIT_OK 0
#define SETUP_EXIT_ARGS 2
#define SETUP_EXIT_NOT_ADMIN 3
#define SETUP_EXIT_SIGNATURE 4
#define SETUP_EXIT_INSTALL 5
#define SETUP_EXIT_START 6
#define SETUP_EXIT_READY 7
#define SETUP_EXIT_ROLLBACK 8

#define SETUP_SERVICE_DACL L"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)" \
    L"(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)" \
    L"(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)" \
    L"S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"

#ifndef VERTHYS_SERVICE_PUBLISHER_SHA256
#define VERTHYS_SERVICE_PUBLISHER_SHA256 ""
#endif
#ifndef VERTHYS_ROOT_CA_SHA256
#define VERTHYS_ROOT_CA_SHA256 ""
#endif

#define SETUP_REG_ROOT_CA_SHA256 L"RootCaSha256"
#define SETUP_EVENT_SOURCE_KEY \
    L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" \
    L"VerthysSecuritySvc"

typedef enum SetupCommand {
    SETUP_INSTALL = 0,
    SETUP_UNINSTALL = 1,
    SETUP_REPAIR = 2,
    SETUP_RESET_STATE = 3,
    SETUP_REPAIR_KEYS = 4,
    SETUP_STATUS = 5
} SetupCommand;

typedef struct SetupOptions {
    SetupCommand command;
    int quiet;
    int keep_state;
    int test_allow_unsigned;
    int test_skip_ping;
} SetupOptions;

typedef struct SetupRegistryBackup {
    int installed_present;
    DWORD installed;
    int version_present;
    wchar_t version[64];
    int install_path_present;
    wchar_t install_path[VTY_PATH_MAX];
} SetupRegistryBackup;

static void read_registry_backup(HKEY key, SetupRegistryBackup *backup)
{
    memset(backup, 0, sizeof(*backup));
    if (key == NULL) return;
    if (vty_registry_read_dword(key, VTY_SVC_REG_INSTALLED,
                                &backup->installed) == 0) {
        backup->installed_present = 1;
    }
    if (vty_registry_read_string(key, VTY_SVC_REG_VERSION, backup->version,
                                 64) == 0) {
        backup->version_present = 1;
    }
    if (vty_registry_read_string(key, VTY_SVC_REG_INSTALL_PATH,
                                 backup->install_path, VTY_PATH_MAX) == 0) {
        backup->install_path_present = 1;
    }
}

static void restore_registry_backup(HKEY key,
                                   const SetupRegistryBackup *backup)
{
    if (key == NULL || backup == NULL) return;
    if (backup->installed_present) {
        (void)vty_registry_write_dword(key, VTY_SVC_REG_INSTALLED,
                                       backup->installed);
    } else {
        (void)vty_registry_delete_value(key, VTY_SVC_REG_INSTALLED);
    }
    if (backup->version_present) {
        (void)vty_registry_write_string(key, VTY_SVC_REG_VERSION,
                                        backup->version);
    } else {
        (void)vty_registry_delete_value(key, VTY_SVC_REG_VERSION);
    }
    if (backup->install_path_present) {
        (void)vty_registry_write_string(key, VTY_SVC_REG_INSTALL_PATH,
                                        backup->install_path);
    } else {
        (void)vty_registry_delete_value(key, VTY_SVC_REG_INSTALL_PATH);
    }
}

static int g_quiet = 0;

static void setup_print(const wchar_t *format, ...)
{
    va_list args;

    if (g_quiet) return;
    va_start(args, format);
    vwprintf(format, args);
    va_end(args);
    fflush(stdout);
}

static int is_admin(void)
{
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admins = NULL;
    BOOL member = FALSE;

    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &admins)) {
        return 0;
    }
    if (!CheckTokenMembership(NULL, admins, &member)) member = FALSE;
    FreeSid(admins);
    return member ? 1 : 0;
}

static DWORD os_build_number(void)
{
    typedef NTSTATUS(WINAPI *RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
    RTL_OSVERSIONINFOW info;
    HMODULE ntdll;
    RtlGetVersionFn fn;

    memset(&info, 0, sizeof(info));
    info.dwOSVersionInfoSize = sizeof(info);
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) return 0;
    fn = (RtlGetVersionFn)(void *)GetProcAddress(ntdll, "RtlGetVersion");
    if (fn == NULL) return 0;
    if (fn(&info) != 0) return 0;
    return info.dwBuildNumber;
}

static int get_file_version(const wchar_t *path, DWORD *major, DWORD *minor,
                            DWORD *patch)
{
    DWORD size = 0;
    BYTE *data = NULL;
    VS_FIXEDFILEINFO *fixed = NULL;
    UINT fixed_len = 0;
    int rc = -1;

    if (path == NULL || major == NULL || minor == NULL || patch == NULL) {
        return -1;
    }
    *major = *minor = *patch = 0;
    size = GetFileVersionInfoSizeW(path, NULL);
    if (size == 0) return -1;
    data = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
    if (data == NULL) return -1;
    if (GetFileVersionInfoW(path, 0, size, data) &&
        VerQueryValueW(data, L"\\", (void **)&fixed, &fixed_len) &&
        fixed != NULL && fixed_len >= sizeof(VS_FIXEDFILEINFO)) {
        *major = HIWORD(fixed->dwFileVersionMS);
        *minor = LOWORD(fixed->dwFileVersionMS);
        *patch = HIWORD(fixed->dwFileVersionLS);
        rc = 0;
    }
    HeapFree(GetProcessHeap(), 0, data);
    return rc;
}

static int parse_version_text(const wchar_t *text, DWORD *major, DWORD *minor,
                              DWORD *patch)
{
    unsigned long a = 0;
    unsigned long b = 0;
    unsigned long c = 0;

    if (text == NULL || major == NULL || minor == NULL || patch == NULL) {
        return -1;
    }
    if (swscanf_s(text, L"%lu.%lu.%lu", &a, &b, &c) != 3) return -1;
    *major = (DWORD)a;
    *minor = (DWORD)b;
    *patch = (DWORD)c;
    return 0;
}

static int version_compare(DWORD a1, DWORD a2, DWORD a3, DWORD b1, DWORD b2,
                           DWORD b3)
{
    if (a1 != b1) return (a1 > b1) ? 1 : -1;
    if (a2 != b2) return (a2 > b2) ? 1 : -1;
    if (a3 != b3) return (a3 > b3) ? 1 : -1;
    return 0;
}

static int setup_dir(wchar_t *out, size_t cap)
{
    wchar_t self[VTY_PATH_MAX];
    wchar_t *slash;

    if (vty_get_self_image_path(self, VTY_PATH_MAX) != 0) return -1;
    slash = wcsrchr(self, L'\\');
    if (slash == NULL) return -1;
    *slash = L'\0';
    return vty_wide_copy(out, cap, self);
}

static int build_paths(wchar_t *setup_dir_out, VtyServicePaths *paths)
{
    if (setup_dir_out == NULL || paths == NULL) return -1;
    if (setup_dir(setup_dir_out, VTY_PATH_MAX) != 0) return -1;
    memset(paths, 0, sizeof(*paths));
    if (vty_service_paths_resolve(paths) != 0) return -1;
    if (vty_service_paths_resolve_install(paths) != 0) return -1;
    return 0;
}

static int wait_for_state(SC_HANDLE service, DWORD desired, DWORD timeout_ms)
{
    DWORD waited = 0;
    SERVICE_STATUS_PROCESS status;
    DWORD needed = 0;

    while (waited < timeout_ms) {
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                  (LPBYTE)&status, sizeof(status), &needed)) {
            return -1;
        }
        if (status.dwCurrentState == desired) return 0;
        if (status.dwCurrentState == SERVICE_STOPPED && desired == SERVICE_RUNNING) {
            /* 继续轮询：StartService 之后可能存在 START_PENDING 抖动。 */
        }
        Sleep(200);
        waited += 200;
    }
    return -1;
}

static int stop_service(SC_HANDLE service)
{
    SERVICE_STATUS status;

    if (service == NULL) return 0;
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) return 0;
        return -1;
    }
    return wait_for_state(service, SERVICE_STOPPED, 30000u);
}

static int start_service(SC_HANDLE service)
{
    if (!StartServiceW(service, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) return -1;
    }
    return wait_for_state(service, SERVICE_RUNNING, 30000u);
}

static int set_service_dacl(SC_HANDLE service)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    BOOL ok;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            SETUP_SERVICE_DACL, SDDL_REVISION_1, &sd, NULL)) {
        return -1;
    }
    ok = SetServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    return ok ? 0 : -1;
}

static int configure_service(SC_HANDLE service, const wchar_t *exe_path)
{
    SERVICE_DESCRIPTIONW desc;
    SERVICE_FAILURE_ACTIONSW actions;
    SC_ACTION action_list[3];
    wchar_t description[256];

    memset(&desc, 0, sizeof(desc));
    memset(&actions, 0, sizeof(actions));
    memset(action_list, 0, sizeof(action_list));
    if (swprintf_s(description, 256,
                   L"Verthys machine-level security budget service") < 0) {
        return -1;
    }
    desc.lpDescription = description;
    if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &desc)) {
        return -1;
    }

    action_list[0].Type = SC_ACTION_RESTART;
    action_list[0].Delay = 5000;
    action_list[1].Type = SC_ACTION_RESTART;
    action_list[1].Delay = 10000;
    action_list[2].Type = SC_ACTION_RESTART;
    action_list[2].Delay = 30000;
    actions.dwResetPeriod = 86400;
    actions.cActions = 3;
    actions.lpsaActions = action_list;
    if (!ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS,
                               &actions)) {
        return -1;
    }

    if (set_service_dacl(service) != 0) {
        return -1;
    }
    (void)exe_path;
    return 0;
}

static int register_event_source(const wchar_t *exe_path)
{
    const wchar_t *event_key =
        L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\"
        L"VerthysSecuritySvc";
    HKEY key = NULL;
    DWORD types = 7u;
    int rc = -1;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, event_key, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                        NULL, &key, NULL) != ERROR_SUCCESS) {
        return -1;
    }
    if (RegSetValueExW(key, L"EventMessageFile", 0, REG_EXPAND_SZ,
                       (const BYTE *)exe_path,
                       (DWORD)((wcslen(exe_path) + 1u) * sizeof(wchar_t))) ==
            ERROR_SUCCESS &&
        RegSetValueExW(key, L"TypesSupported", 0, REG_DWORD,
                       (const BYTE *)&types, sizeof(types)) == ERROR_SUCCESS) {
        rc = 0;
    }
    RegCloseKey(key);
    return rc;
}

static int backup_existing_exe(const wchar_t *exe_path, wchar_t *backup_path,
                               size_t cap, int *had_exe)
{
    wchar_t bak[VTY_PATH_MAX];
    size_t len;

    *had_exe = 0;
    if (vty_wide_copy(bak, VTY_PATH_MAX, exe_path) != 0) return -1;
    len = wcslen(bak);
    if (len + 5u >= VTY_PATH_MAX) return -1;
    memcpy(bak + len, L".bak", 5u * sizeof(wchar_t));
    if (vty_wide_copy(backup_path, cap, bak) != 0) return -1;
    if (!vty_path_exists(exe_path)) return 0;
    *had_exe = 1;
    DeleteFileW(bak);
    if (!CopyFileW(exe_path, bak, FALSE)) return -1;
    return 0;
}

static int replace_service_exe(const wchar_t *source, const wchar_t *dest)
{
    wchar_t temp[VTY_PATH_MAX];
    size_t len;

    if (!vty_path_exists(source)) return -1;
    if (vty_wide_copy(temp, VTY_PATH_MAX, dest) != 0) return -1;
    len = wcslen(temp);
    if (len + 5u >= VTY_PATH_MAX) return -1;
    memcpy(temp + len, L".tmp", 5u * sizeof(wchar_t));
    DeleteFileW(temp);
    if (!CopyFileW(source, temp, FALSE)) return -1;
    if (!MoveFileExW(temp, dest,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temp);
        return -1;
    }
    return 0;
}

static int read_pubkey_registry(HKEY key, uint8_t *pub, DWORD cap, DWORD *len)
{
    return vty_registry_read_binary(key, VTY_SVC_REG_SERVER_PUBKEY, pub, cap,
                                    len) == 0 &&
                   *len > 0
               ? 0
               : -1;
}

static int setup_ping(HKEY key, DWORD timeout_ms)
{
    uint8_t pub[VTY_ECC_BLOB_MAX];
    DWORD pub_len = 0;
    uint8_t request[VTY_SVC_REQUEST_BYTES];
    uint8_t response[VTY_SVC_RESPONSE_BYTES];
    DWORD response_len = 0;
    VtySvcResponseFields fields;
    uint32_t request_id = 0;
    uint64_t nonce_lo = 0;
    uint64_t nonce_hi = 0;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    OVERLAPPED ov;
    HANDLE event;
    BOOL ok;
    DWORD transferred = 0;
    int rc = -1;

    memset(pub, 0, sizeof(pub));
    memset(&fields, 0, sizeof(fields));
    if (read_pubkey_registry(key, pub, sizeof(pub), &pub_len) != 0) {
        return -1;
    }
    if (BCryptGenRandom(NULL, (PUCHAR)&request_id, sizeof(request_id),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
        BCryptGenRandom(NULL, (PUCHAR)&nonce_lo, sizeof(nonce_lo),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
        BCryptGenRandom(NULL, (PUCHAR)&nonce_hi, sizeof(nonce_hi),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        goto done;
    }
    vty_svc_request_encode(request, (uint16_t)VTY_SVC_CMD_PING, request_id,
                           nonce_lo, nonce_hi);

    pipe = CreateFileW(VTY_SVC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (pipe == INVALID_HANDLE_VALUE &&
        GetLastError() == ERROR_PIPE_BUSY) {
        (void)WaitNamedPipeW(VTY_SVC_PIPE_NAME,
                             VTY_SVC_CLIENT_CONNECT_TIMEOUT_MS);
        pipe = CreateFileW(VTY_SVC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0,
                           NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    }
    if (pipe == INVALID_HANDLE_VALUE) goto done;
    {
        DWORD mode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(pipe, &mode, NULL, NULL)) goto done;
    }

    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (event == NULL) goto done;
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = event;

    ok = WriteFile(pipe, request, VTY_SVC_REQUEST_BYTES, &transferred, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(event, timeout_ms) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            CloseHandle(event);
            goto done;
        }
        ok = GetOverlappedResult(pipe, &ov, &transferred, FALSE);
    }
    if (!ok || transferred != VTY_SVC_REQUEST_BYTES) {
        CloseHandle(event);
        goto done;
    }

    memset(&ov, 0, sizeof(ov));
    ResetEvent(event);
    ov.hEvent = event;
    ok = ReadFile(pipe, response, VTY_SVC_RESPONSE_BYTES, &transferred, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(event, timeout_ms) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            CloseHandle(event);
            goto done;
        }
        ok = GetOverlappedResult(pipe, &ov, &transferred, FALSE);
    }
    CloseHandle(event);
    if (!ok || transferred != VTY_SVC_RESPONSE_BYTES) goto done;
    response_len = transferred;

    if (vty_svc_response_decode(response, response_len, request_id, nonce_lo,
                                nonce_hi, &fields) !=
        (uint16_t)VTY_SVC_STATUS_OK) {
        goto done;
    }
    {
        uint8_t hash[VTY_HASH_BYTES];
        if (vty_sha256(response, VTY_SVC_RESPONSE_HEADER_BYTES, hash) != 0) {
            goto done;
        }
        if (vty_ecc_verify(pub, pub_len, hash,
                           response + VTY_SVC_RESPONSE_HEADER_BYTES) != 0) {
            vty_secure_zero(hash, sizeof(hash));
            goto done;
        }
        vty_secure_zero(hash, sizeof(hash));
    }
    rc = (fields.status == (uint16_t)VTY_SVC_STATUS_OK) ? 0 : -1;

done:
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    vty_secure_zero(pub, sizeof(pub));
    vty_secure_zero(request, sizeof(request));
    vty_secure_zero(response, sizeof(response));
    return rc;
}

static int readiness(HKEY key, int skip_ping)
{
    DWORD waited = 0;
    DWORD value = 0;
    DWORD pub_len = 0;
    uint8_t pub[VTY_ECC_BLOB_MAX];

    while (waited < 30000u) {
        if (vty_registry_read_dword(key, VTY_SVC_REG_STATE_INITIALIZED,
                                    &value) == 0 &&
            value == 1u && read_pubkey_registry(key, pub, sizeof(pub), &pub_len) == 0) {
            if (skip_ping) return 0;
            if (setup_ping(key, VTY_SVC_CLIENT_REPLY_TIMEOUT_MS) == 0) return 0;
        }
        Sleep(200);
        waited += 200;
    }
    return -1;
}

static void delete_tree_inner(const wchar_t *path)
{
    wchar_t pattern[VTY_PATH_MAX];
    WIN32_FIND_DATAW fd;
    HANDLE find;

    if (vty_path_join(pattern, VTY_PATH_MAX, path, L"*") != 0) {
        RemoveDirectoryW(path);
        return;
    }
    find = FindFirstFileW(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE) {
        RemoveDirectoryW(path);
        return;
    }
    do {
        wchar_t full[VTY_PATH_MAX];
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0) {
            continue;
        }
        if (vty_path_join(full, VTY_PATH_MAX, path, fd.cFileName) != 0) continue;
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                RemoveDirectoryW(full);
            } else {
                delete_tree_inner(full);
            }
        } else {
            SetFileAttributesW(full, FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(full);
        }
    } while (FindNextFileW(find, &fd));
    FindClose(find);
    RemoveDirectoryW(path);
}

static void delete_tree(const wchar_t *path)
{
    if (path == NULL || !vty_path_exists(path)) return;
    (void)vty_acl_force_admin_full(path);
    delete_tree_inner(path);
}

static void hash_to_hex(const uint8_t hash[VTY_HASH_BYTES], wchar_t out[65])
{
    for (size_t i = 0; i < VTY_HASH_BYTES; i++) {
        out[i * 2u] = (wchar_t)(L"0123456789abcdef"[(hash[i] >> 4) & 0x0Fu]);
        out[i * 2u + 1u] =
            (wchar_t)(L"0123456789abcdef"[hash[i] & 0x0Fu]);
    }
    out[64] = L'\0';
}

static int sha256_file_hex(const wchar_t *path, wchar_t out[65])
{
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD size = 0;
    DWORD read = 0;
    uint8_t *data = NULL;
    uint8_t hash[VTY_HASH_BYTES];
    int rc = -1;

    if (path == NULL || out == NULL) return -1;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    size = GetFileSize(file, NULL);
    if (size == 0 || size > 65536u) goto done;
    data = (uint8_t *)malloc(size);
    if (data == NULL) goto done;
    if (!ReadFile(file, data, size, &read, NULL) || read != size) goto done;
    if (vty_sha256(data, size, hash) != 0) goto done;
    hash_to_hex(hash, out);
    rc = 0;

done:
    if (data != NULL) {
        vty_secure_zero(data, size);
        free(data);
    }
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return rc;
}

static int root_ca_pin_matches(const wchar_t *sha_hex)
{
    const char *pin = VERTHYS_ROOT_CA_SHA256;
    if (pin == NULL || pin[0] == '\0') return 1;
    if (sha_hex == NULL) return 0;
    for (size_t i = 0; i < 64u; i++) {
        if ((char)sha_hex[i] != pin[i]) return 0;
    }
    return pin[64] == '\0';
}

static int delete_root_cert_by_sha256(const wchar_t *sha_hex)
{
    HCERTSTORE store = NULL;
    PCCERT_CONTEXT cert = NULL;
    int rc = 0;

    if (sha_hex == NULL || sha_hex[0] == L'\0') return 0;
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                          CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");
    if (store == NULL) return -1;
    while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL) {
        uint8_t hash[VTY_HASH_BYTES];
        wchar_t hex[65];
        if (vty_sha256(cert->pbCertEncoded, cert->cbCertEncoded, hash) != 0) {
            continue;
        }
        hash_to_hex(hash, hex);
        if (_wcsicmp(hex, sha_hex) == 0) {
            if (!CertDeleteCertificateFromStore(cert)) rc = -1;
            cert = NULL;
            break;
        }
    }
    CertCloseStore(store, 0);
    return rc;
}

static int unregister_event_source(void)
{
    HKEY key = NULL;
    wchar_t value[VTY_PATH_MAX];
    DWORD value_type = 0;
    DWORD value_size = sizeof(value);
    int match = 0;
    int rc = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SETUP_EVENT_SOURCE_KEY, 0,
                      KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return 0;
    }
    if (RegQueryValueExW(key, L"EventMessageFile", NULL, &value_type,
                         (BYTE *)value, &value_size) == ERROR_SUCCESS &&
        (value_type == REG_SZ || value_type == REG_EXPAND_SZ) &&
        wcsstr(value, L"VerthysSecuritySvc.exe") != NULL) {
        match = 1;
    }
    RegCloseKey(key);
    if (match) {
        rc = (RegDeleteTreeW(HKEY_LOCAL_MACHINE, SETUP_EVENT_SOURCE_KEY) ==
              ERROR_SUCCESS)
                 ? 0
                 : -1;
    }
    return rc;
}

static void remove_parent_if_empty(const wchar_t *security_dir)
{
    wchar_t parent[VTY_PATH_MAX];
    const wchar_t *slash;

    if (security_dir == NULL) return;
    slash = wcsrchr(security_dir, L'\\');
    if (slash == NULL || (size_t)(slash - security_dir) >= VTY_PATH_MAX) return;
    memcpy(parent, security_dir, (size_t)(slash - security_dir));
    parent[slash - security_dir] = L'\0';
    (void)RemoveDirectoryW(parent);
}

static int fail_with_ca(PCCERT_CONTEXT *ctx, int newly_added, int code)
{
    if (ctx != NULL && *ctx != NULL) {
        if (newly_added) {
            (void)CertDeleteCertificateFromStore(*ctx);
        } else {
            CertFreeCertificateContext(*ctx);
        }
        *ctx = NULL;
    }
    return code;
}

static int archive_security_dir(const wchar_t *security_dir, const wchar_t *suffix)
{
    wchar_t parent[VTY_PATH_MAX];
    wchar_t target[VTY_PATH_MAX];
    wchar_t stamp[64];
    size_t len;
    const wchar_t *slash;

    if (!vty_path_exists(security_dir)) return 0;
    len = wcslen(security_dir);
    slash = wcsrchr(security_dir, L'\\');
    if (slash == NULL) return -1;
    if ((size_t)(slash - security_dir) >= VTY_PATH_MAX) return -1;
    memcpy(parent, security_dir, (size_t)(slash - security_dir));
    parent[slash - security_dir] = L'\0';
    if (swprintf_s(stamp, 64, L"%llu", (unsigned long long)vty_utc_now_100ns()) <
        0) {
        return -1;
    }
    if (swprintf_s(target, VTY_PATH_MAX, L"%ls\\%ls-%ls", parent, suffix, stamp) <
        0) {
        return -1;
    }
    (void)vty_acl_force_admin_full(security_dir);
    if (!MoveFileExW(security_dir, target, 0)) {
        return -1;
    }
    return 0;
}

static int ensure_install_dir(const VtyServicePaths *paths)
{
    int rc;

    /*
     * SHCreateDirectoryExW 会创建缺失的中间目录（%ProgramFiles%\Verthys），
     * 普通 CreateDirectoryW 在父目录缺失时返回 ERROR_PATH_NOT_FOUND。
     */
    rc = SHCreateDirectoryExW(NULL, paths->install_dir, NULL);
    if (rc != ERROR_SUCCESS && rc != ERROR_ALREADY_EXISTS) {
        return -1;
    }
    if (!vty_path_is_directory(paths->install_dir) ||
        !vty_path_has_reparse(paths->install_dir, 0)) {
        return -1;
    }
    return vty_acl_apply_path(paths->install_dir,
                              VTY_ACL_PROFILE_INSTALL_DIR);
}

static int install_or_update_service(SC_HANDLE scm, const wchar_t *exe_path,
                                     SC_HANDLE *service, int *created)
{
    SC_HANDLE svc = OpenServiceW(scm, VTY_SVC_SERVICE_NAME, SERVICE_ALL_ACCESS);
    *created = 0;
    if (svc != NULL) {
        if (stop_service(svc) != 0) {
            CloseServiceHandle(svc);
            return -1;
        }
        if (!ChangeServiceConfigW(svc, SERVICE_WIN32_OWN_PROCESS,
                                  SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                  exe_path, NULL, NULL, NULL, L"LocalSystem",
                                  NULL, NULL)) {
            /* 配置失败：恢复旧服务运行，避免把既有服务留在停止状态。 */
            (void)start_service(svc);
            CloseServiceHandle(svc);
            return -1;
        }
    } else {
        svc = CreateServiceW(scm, VTY_SVC_SERVICE_NAME,
                             L"Verthys Security Service",
                             SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                             SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, exe_path,
                             NULL, NULL, NULL, L"LocalSystem", NULL);
        if (svc == NULL) return -1;
        *created = 1;
    }
    if (configure_service(svc, exe_path) != 0) {
        if (*created) {
            (void)DeleteService(svc);
        } else {
            (void)start_service(svc);
        }
        CloseServiceHandle(svc);
        return -1;
    }
    *service = svc;
    return 0;
}

static void rollback_service(SC_HANDLE scm, SC_HANDLE service, int created,
                             const wchar_t *exe_path,
                             const wchar_t *backup_path, int had_exe, HKEY key,
                             const SetupRegistryBackup *registry_backup,
                             const wchar_t *security_dir, int had_anchor,
                             PCCERT_CONTEXT *ca_ctx, int ca_new)
{
    (void)scm;
    if (service != NULL) {
        (void)stop_service(service);
    }
    if (had_exe && vty_path_exists(backup_path)) {
        (void)MoveFileExW(backup_path, exe_path,
                          MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    if (created && service != NULL) {
        (void)DeleteService(service);
        (void)unregister_event_source();
        if (!had_anchor && security_dir != NULL) {
            /* 首次安装失败：不留下本次新建的机器状态与锚点。 */
            delete_tree(security_dir);
            remove_parent_if_empty(security_dir);
            if (key != NULL) {
                (void)vty_registry_delete_value(key, VTY_SVC_REG_STATE_INITIALIZED);
                (void)vty_registry_delete_value(key, VTY_SVC_REG_STATE_GENERATION);
                (void)vty_registry_delete_value(key, VTY_SVC_REG_STATE_CREATED);
                (void)vty_registry_delete_value(key, VTY_SVC_REG_SERVER_PUBKEY);
                (void)vty_registry_delete_value(key, VTY_SVC_REG_PROTOCOL_VERSION);
            }
        }
    } else if (service != NULL && had_exe) {
        (void)ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                   SERVICE_NO_CHANGE, exe_path, NULL, NULL,
                                   NULL, NULL, NULL, NULL);
        (void)start_service(service);
    }
    if (key != NULL) {
        if (ca_new) {
            (void)vty_registry_delete_value(key, SETUP_REG_ROOT_CA_SHA256);
        }
        restore_registry_backup(key, registry_backup);
    }
    (void)fail_with_ca(ca_ctx, ca_new, 0);
}

static int import_bundled_root_ca(const wchar_t *setup_dir,
                                  wchar_t root_sha[65],
                                  PCCERT_CONTEXT *added_ctx,
                                  int *newly_added)
{
    wchar_t cer_path[VTY_PATH_MAX];
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD size = 0;
    DWORD read = 0;
    uint8_t *data = NULL;
    uint8_t hash[VTY_HASH_BYTES];
    HCERTSTORE store = NULL;
    PCCERT_CONTEXT cert = NULL;
    PCCERT_CONTEXT existing = NULL;
    PCCERT_CONTEXT stored = NULL;
    int rc = -1;

    if (root_sha != NULL) root_sha[0] = L'\0';
    if (added_ctx != NULL) *added_ctx = NULL;
    if (newly_added != NULL) *newly_added = 0;
    if (vty_path_join(cer_path, VTY_PATH_MAX, setup_dir,
                      L"VerthysRootCA.cer") != 0) {
        return -1;
    }
    /* 公网 CA 签发时无需随包根证书；文件缺失按“已受信”处理。 */
    if (!vty_path_exists(cer_path)) return 0;

    file = CreateFileW(cer_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    size = GetFileSize(file, NULL);
    if (size == 0 || size > 65536u) goto done;
    data = (uint8_t *)malloc(size);
    if (data == NULL) goto done;
    if (!ReadFile(file, data, size, &read, NULL) || read != size) goto done;
    if (vty_sha256(data, size, hash) != 0) goto done;
    if (root_sha != NULL) hash_to_hex(hash, root_sha);
    if (!root_ca_pin_matches(root_sha)) {
        setup_print(L"[setup] bundled root CA fingerprint mismatch\n");
        goto done;
    }

    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                          CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");
    if (store == NULL) goto done;
    cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        data, size);
    if (cert == NULL) goto done;

    existing = CertFindCertificateInStore(
        store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_EXISTING,
        cert, NULL);
    if (existing != NULL) {
        CertFreeCertificateContext(existing);
        existing = NULL;
        rc = 0;
        goto done;
    }
    if (!CertAddCertificateContextToStore(store, cert, CERT_STORE_ADD_NEW,
                                          &stored)) {
        existing = CertFindCertificateInStore(
            store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_EXISTING, cert, NULL);
        if (existing == NULL) goto done;
        CertFreeCertificateContext(existing);
        existing = NULL;
        stored = NULL;
        rc = 0;
        goto done;
    }
    if (added_ctx != NULL) *added_ctx = stored;
    if (newly_added != NULL) *newly_added = 1;
    stored = NULL;
    rc = 0;

done:
    if (stored != NULL) CertFreeCertificateContext(stored);
    if (cert != NULL) CertFreeCertificateContext(cert);
    if (store != NULL) CertCloseStore(store, 0);
    if (data != NULL) {
        vty_secure_zero(data, size);
        free(data);
    }
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return rc;
}

static int do_install(const SetupOptions *options)
{
    VtyServicePaths paths;
    wchar_t setup_path[VTY_PATH_MAX];
    wchar_t source_exe[VTY_PATH_MAX];
    wchar_t backup[VTY_PATH_MAX];
    wchar_t version_text[64];
    wchar_t install_path_text[VTY_PATH_MAX];
    wchar_t root_sha[65];
    VtyServiceAnchors anchors;
    SetupRegistryBackup registry_backup;
    PCCERT_CONTEXT ca_ctx = NULL;
    int ca_new = 0;
    HKEY key = NULL;
    SC_HANDLE scm = NULL;
    SC_HANDLE service = NULL;
    int created = 0;
    int had_exe = 0;
    int had_anchor = 0;
    int rc = SETUP_EXIT_INSTALL;
    DWORD new_major = 0;
    DWORD new_minor = 0;
    DWORD new_patch = 0;
    DWORD old_major = 0;
    DWORD old_minor = 0;
    DWORD old_patch = 0;

    memset(root_sha, 0, sizeof(root_sha));
    if (build_paths(setup_path, &paths) != 0) return SETUP_EXIT_INSTALL;
    if (vty_path_join(source_exe, VTY_PATH_MAX, setup_path,
                      VTY_SERVICE_EXE_NAME) != 0) {
        return SETUP_EXIT_INSTALL;
    }
    /* 源与目标必须不同：目标服务 exe 可能正在运行，禁止原地覆盖自身。 */
    if (_wcsicmp(source_exe, paths.service_exe) == 0) {
        setup_print(L"[setup] run /install from the payload directory, not the installed service path\n");
        return SETUP_EXIT_INSTALL;
    }
    /* 自签名发布链：服务以 LocalSystem 运行，WinVerifyTrust 只认机器根证书。
     * 必须在服务自检之前把随包根 CA 写入 LocalMachine\Root，否则服务启动
     * 自检失败（Event 3003），安装器会以“启动失败”回滚。干净机上也可先
     * 导入固定指纹的根，再校验服务 exe 签名。 */
    if (import_bundled_root_ca(setup_path, root_sha, &ca_ctx, &ca_new) != 0) {
        setup_print(L"[setup] failed to import bundled root CA into LocalMachine\\Root\n");
        return SETUP_EXIT_SIGNATURE;
    }
    if (vty_path_exists(source_exe)) {
        if (options->test_allow_unsigned) {
            /* 测试构建允许未签名产物。 */
        } else {
            wchar_t expected[65];
            size_t i;
            const char *pin = VERTHYS_SERVICE_PUBLISHER_SHA256;
            for (i = 0; i < 64u && pin[i] != '\0'; i++) {
                expected[i] = (wchar_t)pin[i];
            }
            expected[i] = L'\0';
            if (i == 0 || vty_auth_verify_authenticode(source_exe, expected) != 0) {
                setup_print(L"[setup] service Authenticode publisher check failed\n");
                return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_SIGNATURE);
            }
        }
    } else {
        setup_print(L"[setup] missing VerthysSecuritySvc.exe next to setup\n");
        return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_INSTALL);
    }

    if (vty_service_paths_ensure_dirs(&paths, 0) != 0) {
        setup_print(L"[setup] failed to create/harden ProgramData directories\n");
        return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_INSTALL);
    }
    if (ensure_install_dir(&paths) != 0) {
        setup_print(L"[setup] failed to create/harden install directory\n");
        return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_INSTALL);
    }

    {
        VtyRegistryLocation location;
        vty_service_registry_location_production(&location);
        if (vty_service_registry_open(&location, 1, &key) != 0) {
            setup_print(L"[setup] failed to open service registry key\n");
            return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_INSTALL);
        }
        if (vty_service_registry_harden(key) != 0) {
            setup_print(L"[setup] failed to harden service registry key\n");
            RegCloseKey(key);
            return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_INSTALL);
        }
        (void)vty_service_anchors_read(key, &anchors);
        read_registry_backup(key, &registry_backup);
        had_anchor = anchors.state_initialized_present &&
                     anchors.state_initialized == 1u;
        if (!had_anchor && (vty_path_exists(paths.state_file) ||
                            vty_path_exists(paths.state_key_file) ||
                            vty_path_exists(paths.signing_key_file))) {
            if (archive_security_dir(paths.security_dir,
                                     L"Security.orphan") != 0) {
                setup_print(L"[setup] failed to archive unanchored state\n");
                RegCloseKey(key);
                return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_INSTALL);
            }
            if (vty_service_paths_ensure_dirs(&paths, 0) != 0) {
                RegCloseKey(key);
                return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_INSTALL);
            }
        }
        if (vty_registry_read_string(key, VTY_SVC_REG_VERSION, version_text,
                                     64) == 0 &&
            parse_version_text(version_text, &old_major, &old_minor,
                               &old_patch) == 0) {
            if (get_file_version(source_exe, &new_major, &new_minor,
                                 &new_patch) == 0 &&
                version_compare(new_major, new_minor, new_patch, old_major,
                                old_minor, old_patch) < 0) {
                setup_print(L"[setup] downgrade refused\n");
                RegCloseKey(key);
                return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_INSTALL);
            }
        }
    }

    if (backup_existing_exe(paths.service_exe, backup, VTY_PATH_MAX,
                            &had_exe) != 0) {
        RegCloseKey(key);
        return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_INSTALL);
    }

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        RegCloseKey(key);
        return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_INSTALL);
    }
    if (install_or_update_service(scm, paths.service_exe, &service, &created) !=
        0) {
        CloseServiceHandle(scm);
        RegCloseKey(key);
        return fail_with_ca(&ca_ctx, ca_new, SETUP_EXIT_INSTALL);
    }
    if (replace_service_exe(source_exe, paths.service_exe) != 0) {
        rollback_service(scm, service, created, paths.service_exe, backup,
                         had_exe, key, &registry_backup, paths.security_dir,
                         had_anchor, &ca_ctx, ca_new);
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        RegCloseKey(key);
        return SETUP_EXIT_INSTALL;
    }
    (void)register_event_source(paths.service_exe);

    if (start_service(service) != 0) {
        setup_print(L"[setup] service failed to start\n");
        rollback_service(scm, service, created, paths.service_exe, backup,
                         had_exe, key, &registry_backup, paths.security_dir,
                         had_anchor, &ca_ctx, ca_new);
        rc = SETUP_EXIT_START;
        goto done;
    }
    if (readiness(key, options->test_skip_ping) != 0) {
        setup_print(L"[setup] readiness check failed\n");
        rollback_service(scm, service, created, paths.service_exe, backup,
                         had_exe, key, &registry_backup, paths.security_dir,
                         had_anchor, &ca_ctx, ca_new);
        rc = SETUP_EXIT_READY;
        goto done;
    }

    if (get_file_version(source_exe, &new_major, &new_minor, &new_patch) != 0 ||
        swprintf_s(version_text, 64, L"%lu.%lu.%lu", (unsigned long)new_major,
                   (unsigned long)new_minor, (unsigned long)new_patch) < 0 ||
        vty_wide_copy(install_path_text, VTY_PATH_MAX, paths.install_dir) != 0) {
        rollback_service(scm, service, created, paths.service_exe, backup,
                         had_exe, key, &registry_backup, paths.security_dir,
                         had_anchor, &ca_ctx, ca_new);
        rc = SETUP_EXIT_INSTALL;
        goto done;
    }
    if (vty_registry_write_string(key, VTY_SVC_REG_VERSION, version_text) != 0 ||
        vty_registry_write_string(key, VTY_SVC_REG_INSTALL_PATH,
                                  install_path_text) != 0 ||
        vty_registry_write_dword(key, VTY_SVC_REG_INSTALLED, 1u) != 0 ||
        (root_sha[0] != L'\0' &&
         vty_registry_write_string(key, SETUP_REG_ROOT_CA_SHA256, root_sha) !=
             0)) {
        rollback_service(scm, service, created, paths.service_exe, backup,
                         had_exe, key, &registry_backup, paths.security_dir,
                         had_anchor, &ca_ctx, ca_new);
        rc = SETUP_EXIT_INSTALL;
        goto done;
    }
    setup_print(L"[setup] installed VerthysSecuritySvc %ls\n", version_text);
    rc = SETUP_EXIT_OK;

done:
    if (service != NULL) CloseServiceHandle(service);
    if (scm != NULL) CloseServiceHandle(scm);
    if (key != NULL) RegCloseKey(key);
    if (rc == SETUP_EXIT_OK) {
        if (ca_ctx != NULL) {
            CertFreeCertificateContext(ca_ctx);
            ca_ctx = NULL;
        }
    } else if (ca_ctx != NULL) {
        (void)fail_with_ca(&ca_ctx, ca_new, 0);
    }
    return rc;
}

static int do_uninstall(const SetupOptions *options)
{
    VtyServicePaths paths;
    wchar_t setup_path[VTY_PATH_MAX];
    wchar_t root_sha[65];
    SC_HANDLE scm = NULL;
    SC_HANDLE service = NULL;
    VtyRegistryLocation location;
    HKEY key = NULL;
    int rc = SETUP_EXIT_OK;

    memset(root_sha, 0, sizeof(root_sha));
    if (build_paths(setup_path, &paths) != 0) return SETUP_EXIT_INSTALL;
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) return SETUP_EXIT_INSTALL;
    service = OpenServiceW(scm, VTY_SVC_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service != NULL) {
        if (stop_service(service) != 0) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return SETUP_EXIT_START;
        }
        if (!DeleteService(service)) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return SETUP_EXIT_INSTALL;
        }
        for (DWORD i = 0; i < 50u; i++) {
            SC_HANDLE probe = OpenServiceW(scm, VTY_SVC_SERVICE_NAME,
                                           SERVICE_QUERY_STATUS);
            if (probe == NULL) break;
            CloseServiceHandle(probe);
            Sleep(100);
        }
        CloseServiceHandle(service);
        service = NULL;
    }
    CloseServiceHandle(scm);

    vty_service_registry_location_production(&location);
    if (vty_service_registry_open(&location, 0, &key) == 0) {
        (void)vty_registry_read_string(key, SETUP_REG_ROOT_CA_SHA256, root_sha,
                                      65);
        if (!options->keep_state) {
            (void)vty_registry_delete_value(key, VTY_SVC_REG_INSTALLED);
            RegCloseKey(key);
            key = NULL;
            (void)RegDeleteTreeW(HKEY_LOCAL_MACHINE, VTY_SVC_REGISTRY_KEY);
        } else {
            (void)vty_registry_delete_value(key, VTY_SVC_REG_INSTALLED);
            (void)vty_registry_delete_value(key, VTY_SVC_REG_VERSION);
            (void)vty_registry_delete_value(key, VTY_SVC_REG_INSTALL_PATH);
        }
    }
    if (key != NULL) {
        RegCloseKey(key);
        key = NULL;
    }

    if (!options->keep_state) {
        /* 锚点缺失时用当前载荷 CA 指纹兜底，清理旧安装遗留。 */
        if (root_sha[0] == L'\0') {
            wchar_t cer_path[VTY_PATH_MAX];
            if (vty_path_join(cer_path, VTY_PATH_MAX, setup_path,
                              L"VerthysRootCA.cer") == 0 &&
                sha256_file_hex(cer_path, root_sha) == 0 &&
                root_ca_pin_matches(root_sha)) {
                /* 使用载荷指纹继续删除。 */
            } else {
                root_sha[0] = L'\0';
            }
        }
        if (root_sha[0] != L'\0' &&
            delete_root_cert_by_sha256(root_sha) != 0) {
            setup_print(L"[setup] warning: root CA could not be removed\n");
            rc = SETUP_EXIT_INSTALL;
        }
        if (unregister_event_source() != 0) {
            setup_print(L"[setup] warning: event source could not be removed\n");
            rc = SETUP_EXIT_INSTALL;
        }
    }

    delete_tree(paths.install_dir);
    if (!options->keep_state) {
        delete_tree(paths.parent_dir);
        if (vty_path_exists(paths.parent_dir)) {
            setup_print(L"[setup] warning: machine state could not be fully removed\n");
            rc = SETUP_EXIT_INSTALL;
        }
    }
    setup_print(L"[setup] uninstalled VerthysSecuritySvc\n");
    return rc;
}

static int do_reset_state(void)
{
    VtyServicePaths paths;
    wchar_t setup_path[VTY_PATH_MAX];
    VtyRegistryLocation location;
    HKEY key = NULL;
    SC_HANDLE scm = NULL;
    SC_HANDLE service = NULL;
    int rc = SETUP_EXIT_OK;

    if (build_paths(setup_path, &paths) != 0) return SETUP_EXIT_INSTALL;
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) return SETUP_EXIT_INSTALL;
    service = OpenServiceW(scm, VTY_SVC_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service == NULL) {
        CloseServiceHandle(scm);
        return SETUP_EXIT_INSTALL;
    }
    if (stop_service(service) != 0) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return SETUP_EXIT_START;
    }
    if (archive_security_dir(paths.security_dir, L"Security.corrupt") != 0 &&
        vty_path_exists(paths.security_dir)) {
        if (service != NULL) CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return SETUP_EXIT_INSTALL;
    }
    if (vty_service_paths_ensure_dirs(&paths, 0) != 0) {
        if (service != NULL) CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return SETUP_EXIT_INSTALL;
    }
    vty_service_registry_location_production(&location);
    if (vty_service_registry_open(&location, 1, &key) != 0) {
        if (service != NULL) CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return SETUP_EXIT_INSTALL;
    }
    (void)vty_registry_delete_value(key, VTY_SVC_REG_STATE_INITIALIZED);
    (void)vty_registry_delete_value(key, VTY_SVC_REG_STATE_GENERATION);
    (void)vty_registry_delete_value(key, VTY_SVC_REG_STATE_CREATED);
    (void)vty_registry_delete_value(key, VTY_SVC_REG_SERVER_PUBKEY);
    (void)vty_registry_delete_value(key, VTY_SVC_REG_PROTOCOL_VERSION);
    if (service != NULL && start_service(service) != 0) {
        rc = SETUP_EXIT_START;
    } else if (readiness(key, 0) != 0) {
        rc = SETUP_EXIT_READY;
    } else {
        setup_print(L"[setup] state reset and service reinitialized\n");
    }
    if (key != NULL) RegCloseKey(key);
    if (service != NULL) CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return rc;
}

static int do_repair_keys(void)
{
    VtyServicePaths paths;
    wchar_t setup_path[VTY_PATH_MAX];
    VtyRegistryLocation location;
    HKEY key = NULL;
    SC_HANDLE scm = NULL;
    SC_HANDLE service = NULL;
    int rc = SETUP_EXIT_OK;

    if (build_paths(setup_path, &paths) != 0) return SETUP_EXIT_INSTALL;
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) return SETUP_EXIT_INSTALL;
    service = OpenServiceW(scm, VTY_SVC_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service == NULL) {
        CloseServiceHandle(scm);
        return SETUP_EXIT_INSTALL;
    }
    if (stop_service(service) != 0) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return SETUP_EXIT_START;
    }
    DeleteFileW(paths.signing_key_file);
    vty_service_registry_location_production(&location);
    if (vty_service_registry_open(&location, 1, &key) != 0) {
        if (service != NULL) CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return SETUP_EXIT_INSTALL;
    }
    (void)vty_registry_delete_value(key, VTY_SVC_REG_SERVER_PUBKEY);
    if (service != NULL && start_service(service) != 0) {
        rc = SETUP_EXIT_START;
    } else if (readiness(key, 0) != 0) {
        rc = SETUP_EXIT_READY;
    } else {
        setup_print(L"[setup] signing keys regenerated\n");
    }
    if (key != NULL) RegCloseKey(key);
    if (service != NULL) CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return rc;
}

static int do_repair(void)
{
    VtyServicePaths paths;
    wchar_t setup_path[VTY_PATH_MAX];
    SC_HANDLE scm = NULL;
    SC_HANDLE service = NULL;
    int created = 0;

    if (build_paths(setup_path, &paths) != 0) return SETUP_EXIT_INSTALL;
    if (vty_service_paths_ensure_dirs(&paths, 0) != 0 ||
        ensure_install_dir(&paths) != 0) {
        return SETUP_EXIT_INSTALL;
    }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) return SETUP_EXIT_INSTALL;
    if (install_or_update_service(scm, paths.service_exe, &service, &created) !=
        0) {
        CloseServiceHandle(scm);
        return SETUP_EXIT_INSTALL;
    }
    if (start_service(service) != 0) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return SETUP_EXIT_START;
    }
    setup_print(L"[setup] service definition repaired\n");
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return SETUP_EXIT_OK;
}

static int do_status(void)
{
    VtyServicePaths paths;
    wchar_t setup_path[VTY_PATH_MAX];
    VtyRegistryLocation location;
    HKEY key = NULL;
    VtyServiceAnchors anchors;
    SC_HANDLE scm = NULL;
    SC_HANDLE service = NULL;
    SERVICE_STATUS_PROCESS status;
    DWORD needed = 0;
    DWORD state = SERVICE_STOPPED;
    wchar_t version_text[64];
    wchar_t install_path_text[VTY_PATH_MAX];

    if (build_paths(setup_path, &paths) != 0) return SETUP_EXIT_INSTALL;
    memset(&anchors, 0, sizeof(anchors));
    memset(version_text, 0, sizeof(version_text));
    memset(install_path_text, 0, sizeof(install_path_text));
    vty_service_registry_location_production(&location);
    if (vty_service_registry_open(&location, 0, &key) == 0) {
        (void)vty_service_anchors_read(key, &anchors);
        (void)vty_registry_read_string(key, VTY_SVC_REG_VERSION, version_text,
                                       64);
        (void)vty_registry_read_string(key, VTY_SVC_REG_INSTALL_PATH,
                                       install_path_text, VTY_PATH_MAX);
    }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm != NULL) {
        service = OpenServiceW(scm, VTY_SVC_SERVICE_NAME, SERVICE_QUERY_STATUS);
        if (service != NULL &&
            QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                 (LPBYTE)&status, sizeof(status), &needed)) {
            state = status.dwCurrentState;
        }
    }
    setup_print(L"Installed        : %ls\n",
                (anchors.installed_present && anchors.installed == 1u)
                    ? L"yes" : L"no");
    setup_print(L"Service state    : %lu\n", (unsigned long)state);
    setup_print(L"Version          : %ls\n",
                version_text[0] != L'\0' ? version_text : L"unknown");
    setup_print(L"Install path     : %ls\n",
                install_path_text[0] != L'\0' ? install_path_text : L"unknown");
    setup_print(L"State initialized: %ls\n",
                (anchors.state_initialized_present &&
                 anchors.state_initialized == 1u) ? L"yes" : L"no");
    setup_print(L"Protocol version : %lu\n",
                (unsigned long)(anchors.protocol_present ? anchors.protocol : 0u));
    setup_print(L"State dir ACL    : %ls\n",
                vty_acl_verify_path(paths.security_dir,
                                    VTY_ACL_PROFILE_SECURITY_DIR)
                    ? L"ok" : L"fail");
    setup_print(L"State file       : %ls\n",
                vty_path_exists(paths.state_file) ? L"present" : L"missing");
    setup_print(L"HMAC key file    : %ls\n",
                vty_path_exists(paths.state_key_file) ? L"present" : L"missing");
    setup_print(L"Signing key file : %ls\n",
                vty_path_exists(paths.signing_key_file) ? L"present" : L"missing");
    setup_print(L"Registry ACL     : %ls\n",
                (key != NULL &&
                 vty_acl_verify_registry(key, VTY_ACL_PROFILE_REGISTRY))
                    ? L"ok" : L"fail");
    if (service != NULL) CloseServiceHandle(service);
    if (scm != NULL) CloseServiceHandle(scm);
    if (key != NULL) RegCloseKey(key);
    return SETUP_EXIT_OK;
}

int vty_service_setup_main(int argc, wchar_t **argv)
{
    SetupOptions options;

    memset(&options, 0, sizeof(options));
    options.command = SETUP_INSTALL;
    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"/install") == 0) {
            options.command = SETUP_INSTALL;
        } else if (wcscmp(argv[i], L"/uninstall") == 0) {
            options.command = SETUP_UNINSTALL;
        } else if (wcscmp(argv[i], L"/repair") == 0) {
            options.command = SETUP_REPAIR;
        } else if (wcscmp(argv[i], L"/reset-state") == 0) {
            options.command = SETUP_RESET_STATE;
        } else if (wcscmp(argv[i], L"/repair-keys") == 0) {
            options.command = SETUP_REPAIR_KEYS;
        } else if (wcscmp(argv[i], L"/status") == 0) {
            options.command = SETUP_STATUS;
        } else if (wcscmp(argv[i], L"/quiet") == 0) {
            options.quiet = 1;
        } else if (wcscmp(argv[i], L"/keep-state") == 0) {
            options.keep_state = 1;
#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
        } else if (wcscmp(argv[i], L"/test-allow-unsigned") == 0) {
            options.test_allow_unsigned = 1;
        } else if (wcscmp(argv[i], L"/test-skip-ping") == 0) {
            options.test_skip_ping = 1;
#endif
        } else {
            fwprintf(stderr, L"[setup] unknown argument: %ls\n", argv[i]);
            return SETUP_EXIT_ARGS;
        }
    }
    g_quiet = options.quiet;

    if (os_build_number() < 17763u) {
        fwprintf(stderr, L"[setup] Windows 10 1809 or newer required\n");
        return SETUP_EXIT_INSTALL;
    }
    if (!is_admin()) {
        fwprintf(stderr, L"[setup] administrator privileges required\n");
        return SETUP_EXIT_NOT_ADMIN;
    }

    /*
     * 不在入口做 Authenticode 自校验：干净机上发布根尚未受信，
     * WinVerifyTrust 会必然失败。do_install 先按固定指纹导入根 CA，
     * 再校验服务 exe 的发布者；/uninstall 不做链校验，保证根缺失或
     * 链损坏时仍能完成卸载。
     */
    switch (options.command) {
    case SETUP_INSTALL:
        return do_install(&options);
    case SETUP_UNINSTALL:
        return do_uninstall(&options);
    case SETUP_REPAIR:
        return do_repair();
    case SETUP_RESET_STATE:
        return do_reset_state();
    case SETUP_REPAIR_KEYS:
        return do_repair_keys();
    case SETUP_STATUS:
        return do_status();
    default:
        return SETUP_EXIT_ARGS;
    }
}
