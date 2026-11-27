/*
 * setup_common.c — 输出、管理员判定、版本与路径解析、注册表备份
 */

#include "setup_internal.h"

void read_registry_backup(HKEY key, SetupRegistryBackup *backup)
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

void restore_registry_backup(HKEY key,
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

int g_quiet = 0;

void setup_print(const wchar_t *format, ...)
{
    va_list args;

    if (g_quiet) return;
    va_start(args, format);
    vwprintf(format, args);
    va_end(args);
    fflush(stdout);
}

int is_admin(void)
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

DWORD os_build_number(void)
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

int get_file_version(const wchar_t *path, DWORD *major, DWORD *minor,
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

int parse_version_text(const wchar_t *text, DWORD *major, DWORD *minor,
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

int version_compare(DWORD a1, DWORD a2, DWORD a3, DWORD b1, DWORD b2,
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

int build_paths(wchar_t *setup_dir_out, VtyServicePaths *paths)
{
    if (setup_dir_out == NULL || paths == NULL) return -1;
    if (setup_dir(setup_dir_out, VTY_PATH_MAX) != 0) return -1;
    memset(paths, 0, sizeof(*paths));
    if (vty_service_paths_resolve(paths) != 0) return -1;
    if (vty_service_paths_resolve_install(paths) != 0) return -1;
    return 0;
}
