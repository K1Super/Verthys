/*
 * setup_commands.c — /install /uninstall /repair /reset-state /repair-keys /status 子命令
 */

#include "setup_internal.h"

int do_install(const SetupOptions *options)
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

    /*
     * 驱动载荷随同一提权流程安装；缺失时行为与无驱动构建完全一致。
     * 启动失败属于环境问题（HVCI/签名/资源），回滚驱动并记录降级结果，
     * 应用与服务继续安装；载荷损坏或签名不受信则中止安装。
     */
    {
        wchar_t driver_result[64];
        int driver_rc = driver_install_payload(
            &paths, setup_path, options->test_allow_unsigned, driver_result,
            64);
        (void)vty_registry_write_string(key, SETUP_REG_DRIVER_RESULT,
                                        driver_result);
        if (driver_rc < 0) {
            setup_print(L"[setup] driver payload rejected: %ls\n",
                        driver_result);
            rollback_service(scm, service, created, paths.service_exe, backup,
                             had_exe, key, &registry_backup,
                             paths.security_dir, had_anchor, &ca_ctx, ca_new);
            rc = SETUP_EXIT_SIGNATURE;
            goto done;
        }
        if (driver_rc > 0) {
            setup_print(L"[setup] driver install degraded: %ls\n",
                        driver_result);
        } else if (_wcsicmp(driver_result, L"installed") == 0) {
            setup_print(L"[setup] kernel driver installed\n");
        }
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

int do_uninstall(const SetupOptions *options)
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

    /*
     * 驱动服务必须先于应用目录删除：运行中的内核驱动会锁定 .sys。
     * 同名非内核服务不触碰，避免误删用户/第三方服务。
     */
    {
        wchar_t driver_result[64];
        if (driver_remove_payload(&paths, driver_result, 64) != 0) {
            setup_print(L"[setup] kernel driver removal failed: %ls\n",
                        driver_result);
            return SETUP_EXIT_INSTALL;
        }
    }

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
            (void)vty_registry_delete_value(key, SETUP_REG_DRIVER_RESULT);
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

int do_reset_state(void)
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

int do_repair_keys(void)
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

int do_repair(void)
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
    {
        wchar_t driver_result[64];
        int driver_rc = driver_install_payload(&paths, setup_path, 0,
                                               driver_result, 64);
        if (driver_rc < 0) {
            setup_print(L"[setup] driver payload rejected: %ls\n",
                        driver_result);
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return SETUP_EXIT_SIGNATURE;
        }
        if (driver_rc > 0) {
            setup_print(L"[setup] driver repair degraded: %ls\n",
                        driver_result);
        }
    }
    setup_print(L"[setup] service definition repaired\n");
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return SETUP_EXIT_OK;
}

int do_status(void)
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
    wchar_t driver_result[64];

    if (build_paths(setup_path, &paths) != 0) return SETUP_EXIT_INSTALL;
    memset(&anchors, 0, sizeof(anchors));
    memset(version_text, 0, sizeof(version_text));
    memset(install_path_text, 0, sizeof(install_path_text));
    memset(driver_result, 0, sizeof(driver_result));
    vty_service_registry_location_production(&location);
    if (vty_service_registry_open(&location, 0, &key) == 0) {
        (void)vty_service_anchors_read(key, &anchors);
        (void)vty_registry_read_string(key, VTY_SVC_REG_VERSION, version_text,
                                       64);
        (void)vty_registry_read_string(key, VTY_SVC_REG_INSTALL_PATH,
                                       install_path_text, VTY_PATH_MAX);
        (void)vty_registry_read_string(key, SETUP_REG_DRIVER_RESULT,
                                       driver_result, 64);
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
    setup_print(L"Driver result    : %ls\n",
                driver_result[0] != L'\0' ? driver_result : L"none");
    setup_print(L"Driver service   : %ls\n", driver_state_text());
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
