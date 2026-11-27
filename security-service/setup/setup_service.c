/*
 * setup_service.c — 服务生命周期、事件源、exe 备份替换、安装目录
 */

#include "setup_internal.h"

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

int stop_service(SC_HANDLE service)
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

int start_service(SC_HANDLE service)
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

int register_event_source(const wchar_t *exe_path)
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

int backup_existing_exe(const wchar_t *exe_path, wchar_t *backup_path,
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

int replace_service_exe(const wchar_t *source, const wchar_t *dest)
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

int unregister_event_source(void)
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

int ensure_install_dir(const VtyServicePaths *paths)
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

int install_or_update_service(SC_HANDLE scm, const wchar_t *exe_path,
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

void rollback_service(SC_HANDLE scm, SC_HANDLE service, int created,
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
