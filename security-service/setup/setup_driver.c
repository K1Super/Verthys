/*
 * setup_driver.c — 内核驱动载荷安装/移除与状态文本
 */

#include "setup_internal.h"

typedef struct SetupDriverPayload {
    int present;
    wchar_t dir[VTY_PATH_MAX];
    wchar_t sys[VTY_PATH_MAX];
    wchar_t cat[VTY_PATH_MAX];
    wchar_t inf[VTY_PATH_MAX];
} SetupDriverPayload;

static int driver_payload_probe(const wchar_t *setup_dir,
                                SetupDriverPayload *payload)
{
    int any = 0;

    if (setup_dir == NULL || payload == NULL) return -1;
    memset(payload, 0, sizeof(*payload));
    if (vty_path_join(payload->dir, VTY_PATH_MAX, setup_dir,
                      SETUP_DRIVER_DIR_NAME) != 0) {
        return -1;
    }
    if (!vty_path_is_directory(payload->dir)) return 0;
    if (!vty_path_has_reparse(payload->dir, 0)) return -1;
    if (vty_path_join(payload->sys, VTY_PATH_MAX, payload->dir,
                      SETUP_DRIVER_SYS_NAME) != 0 ||
        vty_path_join(payload->cat, VTY_PATH_MAX, payload->dir,
                      SETUP_DRIVER_CAT_NAME) != 0 ||
        vty_path_join(payload->inf, VTY_PATH_MAX, payload->dir,
                      SETUP_DRIVER_INF_NAME) != 0) {
        return -1;
    }

    any = vty_path_exists(payload->sys) || vty_path_exists(payload->cat) ||
          vty_path_exists(payload->inf);
    if (!any) return 0;
    payload->present = 1;
    if (!vty_path_exists(payload->sys) || !vty_path_exists(payload->cat)) {
        return -1;
    }
    return 0;
}

static int driver_service_is_kernel(SC_HANDLE service)
{
    DWORD needed = 0;
    LPQUERY_SERVICE_CONFIGW config;
    int kernel = 0;

    if (service == NULL) return 0;
    (void)QueryServiceConfigW(service, NULL, 0, &needed);
    if (needed == 0) return 0;
    config = (LPQUERY_SERVICE_CONFIGW)HeapAlloc(GetProcessHeap(), 0, needed);
    if (config == NULL) return 0;
    if (QueryServiceConfigW(service, config, needed, &needed)) {
        kernel = (config->dwServiceType & SERVICE_KERNEL_DRIVER) != 0;
    }
    HeapFree(GetProcessHeap(), 0, config);
    return kernel;
}

/*
 * 返回：0 已停止或不存在；1 同名服务不是内核驱动（外部服务，拒绝触碰）；
 *       -1 停止失败。
 */
static int driver_stop_existing(SC_HANDLE scm, int *had_kernel)
{
    SC_HANDLE service;

    if (had_kernel != NULL) *had_kernel = 0;
    service = OpenServiceW(scm, SETUP_DRIVER_SERVICE_NAME,
                           SERVICE_ALL_ACCESS | SERVICE_QUERY_CONFIG);
    if (service == NULL) {
        return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? 0 : -1;
    }
    if (!driver_service_is_kernel(service)) {
        CloseServiceHandle(service);
        return 1;
    }
    if (stop_service(service) != 0) {
        CloseServiceHandle(service);
        return -1;
    }
    CloseServiceHandle(service);
    if (had_kernel != NULL) *had_kernel = 1;
    return 0;
}

/* 返回：0 已删除或不存在；1 同名服务不是内核驱动；-1 删除失败。 */
static int driver_remove_service(SC_HANDLE scm)
{
    SC_HANDLE service;
    int rc = 0;

    service = OpenServiceW(scm, SETUP_DRIVER_SERVICE_NAME,
                           SERVICE_ALL_ACCESS | SERVICE_QUERY_CONFIG);
    if (service == NULL) {
        return GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? 0 : -1;
    }
    if (!driver_service_is_kernel(service)) {
        CloseServiceHandle(service);
        return 1;
    }
    if (stop_service(service) == 0 && DeleteService(service)) {
        rc = 0;
    } else {
        rc = -1;
    }
    CloseServiceHandle(service);
    return rc;
}

static int driver_copy_file(const wchar_t *source, const wchar_t *target,
                            int required)
{
    wchar_t temp[VTY_PATH_MAX];
    size_t len;

    if (!vty_path_exists(source)) return required ? -1 : 0;
    if (vty_wide_copy(temp, VTY_PATH_MAX, target) != 0) return -1;
    len = wcslen(temp);
    if (len + 5u >= VTY_PATH_MAX) return -1;
    memcpy(temp + len, L".tmp", 5u * sizeof(wchar_t));
    DeleteFileW(temp);
    if (!CopyFileW(source, temp, FALSE)) return -1;
    if (!MoveFileExW(temp, target,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temp);
        return -1;
    }
    return 0;
}

static int driver_backup_file(const wchar_t *target, const wchar_t *backup,
                              int *had)
{
    if (had != NULL) *had = 0;
    DeleteFileW(backup);
    if (!vty_path_exists(target)) return 0;
    if (!CopyFileW(target, backup, FALSE)) return -1;
    if (had != NULL) *had = 1;
    return 0;
}

static void driver_restore_file(const wchar_t *target, const wchar_t *backup,
                                int had)
{
    if (had) {
        (void)MoveFileExW(backup, target,
                          MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    } else {
        DeleteFileW(target);
    }
}

static int driver_install_service(SC_HANDLE scm, const wchar_t *sys_path,
                                  int *created)
{
    wchar_t nt_path[VTY_PATH_MAX];
    SC_HANDLE service;

    if (created != NULL) *created = 0;
    if (swprintf_s(nt_path, VTY_PATH_MAX, L"\\??\\%ls", sys_path) < 0) {
        return -1;
    }

    service = OpenServiceW(scm, SETUP_DRIVER_SERVICE_NAME,
                           SERVICE_ALL_ACCESS | SERVICE_QUERY_CONFIG);
    if (service != NULL) {
        if (!driver_service_is_kernel(service)) {
            CloseServiceHandle(service);
            return -1;
        }
        if (!ChangeServiceConfigW(service, SERVICE_KERNEL_DRIVER,
                                  SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                  nt_path, NULL, NULL, NULL, NULL, NULL,
                                  NULL)) {
            CloseServiceHandle(service);
            return -1;
        }
    } else {
        if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST) return -1;
        service = CreateServiceW(
            scm, SETUP_DRIVER_SERVICE_NAME, L"Verthys Kernel Guard",
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL, nt_path, NULL, NULL, NULL, NULL, NULL);
        if (service == NULL) return -1;
        if (created != NULL) *created = 1;
    }

    if (start_service(service) != 0) {
        if (created != NULL && *created) {
            (void)DeleteService(service);
        }
        CloseServiceHandle(service);
        return -1;
    }
    CloseServiceHandle(service);
    return 0;
}

static int driver_ensure_dir(const VtyServicePaths *paths,
                             wchar_t out[VTY_PATH_MAX])
{
    int rc;

    if (vty_path_join(out, VTY_PATH_MAX, paths->install_dir,
                      SETUP_DRIVER_DIR_NAME) != 0) {
        return -1;
    }
    rc = SHCreateDirectoryExW(NULL, out, NULL);
    if (rc != ERROR_SUCCESS && rc != ERROR_ALREADY_EXISTS) return -1;
    if (!vty_path_is_directory(out) || !vty_path_has_reparse(out, 0)) {
        return -1;
    }
    return vty_acl_apply_path(out, VTY_ACL_PROFILE_INSTALL_DIR);
}

/*
 * 安装或升级驱动载荷。
 * 返回：0 成功或载荷不存在；1 非致命失败（已回滚，应用继续安装）；
 *       -1 载荷损坏或签名不受信（致命，中止安装）。
 * result 回填给注册表的诊断值，不含路径。
 */
int driver_install_payload(const VtyServicePaths *paths,
                                  const wchar_t *setup_dir, int allow_unsigned,
                                  wchar_t *result, size_t result_cap)
{
    SetupDriverPayload payload;
    wchar_t dir[VTY_PATH_MAX];
    wchar_t sys_target[VTY_PATH_MAX];
    wchar_t cat_target[VTY_PATH_MAX];
    wchar_t inf_target[VTY_PATH_MAX];
    wchar_t sys_backup[VTY_PATH_MAX];
    wchar_t cat_backup[VTY_PATH_MAX];
    wchar_t inf_backup[VTY_PATH_MAX];
    SC_HANDLE scm = NULL;
    int had_sys = 0;
    int had_cat = 0;
    int had_inf = 0;
    int had_service = 0;
    int created = 0;
    int stop_rc;
    int rc = 1;

    if (result != NULL && result_cap > 0) result[0] = L'\0';
    if (driver_payload_probe(setup_dir, &payload) != 0) {
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap, L"payload-incomplete");
        }
        return -1;
    }
    if (!payload.present) {
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap, L"absent");
        }
        return 0;
    }
    if (!allow_unsigned &&
        (vty_auth_verify_trusted_signature(payload.sys) != 0 ||
         vty_auth_verify_trusted_signature(payload.cat) != 0)) {
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap, L"signature-rejected");
        }
        return -1;
    }

    if (driver_ensure_dir(paths, dir) != 0) {
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap, L"install-dir-failed");
        }
        return 1;
    }
    if (vty_path_join(sys_target, VTY_PATH_MAX, dir,
                      SETUP_DRIVER_SYS_NAME) != 0 ||
        vty_path_join(cat_target, VTY_PATH_MAX, dir,
                      SETUP_DRIVER_CAT_NAME) != 0 ||
        vty_path_join(inf_target, VTY_PATH_MAX, dir,
                      SETUP_DRIVER_INF_NAME) != 0 ||
        vty_path_join(sys_backup, VTY_PATH_MAX, dir,
                      SETUP_DRIVER_SYS_NAME L".bak") != 0 ||
        vty_path_join(cat_backup, VTY_PATH_MAX, dir,
                      SETUP_DRIVER_CAT_NAME L".bak") != 0 ||
        vty_path_join(inf_backup, VTY_PATH_MAX, dir,
                      SETUP_DRIVER_INF_NAME L".bak") != 0) {
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap, L"path-too-long");
        }
        return 1;
    }

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap, L"scm-open-failed");
        }
        return 1;
    }

    stop_rc = driver_stop_existing(scm, &had_service);
    if (stop_rc != 0) {
        CloseServiceHandle(scm);
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap,
                                stop_rc == 1 ? L"foreign-service"
                                             : L"stop-failed");
        }
        return 1;
    }

    if (driver_backup_file(sys_target, sys_backup, &had_sys) != 0 ||
        driver_backup_file(cat_target, cat_backup, &had_cat) != 0 ||
        driver_backup_file(inf_target, inf_backup, &had_inf) != 0) {
        CloseServiceHandle(scm);
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap, L"backup-failed");
        }
        return 1;
    }

    if (driver_copy_file(payload.sys, sys_target, 1) != 0 ||
        driver_copy_file(payload.cat, cat_target, 1) != 0 ||
        driver_copy_file(payload.inf, inf_target, 0) != 0) {
        driver_restore_file(sys_target, sys_backup, had_sys);
        driver_restore_file(cat_target, cat_backup, had_cat);
        driver_restore_file(inf_target, inf_backup, had_inf);
        CloseServiceHandle(scm);
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap, L"copy-failed");
        }
        return 1;
    }

    if (driver_install_service(scm, sys_target, &created) != 0) {
        driver_restore_file(sys_target, sys_backup, had_sys);
        driver_restore_file(cat_target, cat_backup, had_cat);
        driver_restore_file(inf_target, inf_backup, had_inf);
        if (had_service) {
            SC_HANDLE service = OpenServiceW(
                scm, SETUP_DRIVER_SERVICE_NAME,
                SERVICE_ALL_ACCESS | SERVICE_QUERY_CONFIG);
            if (service != NULL) {
                (void)start_service(service);
                CloseServiceHandle(service);
            }
        } else if (created) {
            SC_HANDLE service = OpenServiceW(
                scm, SETUP_DRIVER_SERVICE_NAME,
                SERVICE_ALL_ACCESS | SERVICE_QUERY_CONFIG);
            if (service != NULL) {
                (void)DeleteService(service);
                CloseServiceHandle(service);
            }
        }
        CloseServiceHandle(scm);
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap, L"start-failed");
        }
        return 1;
    }

    DeleteFileW(sys_backup);
    DeleteFileW(cat_backup);
    DeleteFileW(inf_backup);
    CloseServiceHandle(scm);
    rc = 0;
    if (result != NULL) {
        (void)vty_wide_copy(result, result_cap, L"installed");
    }
    return rc;
}

int driver_remove_payload(const VtyServicePaths *paths, wchar_t *result,
                                 size_t result_cap)
{
    wchar_t dir[VTY_PATH_MAX];
    SC_HANDLE scm;
    int remove_rc;

    if (result != NULL && result_cap > 0) result[0] = L'\0';
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap, L"scm-open-failed");
        }
        return -1;
    }
    remove_rc = driver_remove_service(scm);
    CloseServiceHandle(scm);
    if (remove_rc < 0) {
        if (result != NULL) {
            (void)vty_wide_copy(result, result_cap, L"remove-failed");
        }
        return -1;
    }

    /* 同名外部服务未触碰时，也不删除可能被其引用的驱动目录。 */
    if (remove_rc == 0 &&
        vty_path_join(dir, VTY_PATH_MAX, paths->install_dir,
                      SETUP_DRIVER_DIR_NAME) == 0) {
        delete_tree(dir);
    }
    if (result != NULL) {
        (void)vty_wide_copy(result, result_cap,
                            remove_rc == 1 ? L"skipped-foreign" : L"removed");
    }
    return 0;
}

const wchar_t *driver_state_text(void)
{
    SC_HANDLE scm;
    SC_HANDLE service;
    const wchar_t *text = L"missing";

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) return L"unknown";
    service = OpenServiceW(scm, SETUP_DRIVER_SERVICE_NAME,
                           SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (service != NULL) {
        SERVICE_STATUS status;
        if (!driver_service_is_kernel(service)) {
            text = L"foreign";
        } else if (QueryServiceStatus(service, &status)) {
            if (status.dwCurrentState == SERVICE_RUNNING) {
                text = L"running";
            } else if (status.dwCurrentState == SERVICE_STOPPED) {
                text = L"stopped";
            } else {
                text = L"pending";
            }
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);
    return text;
}
