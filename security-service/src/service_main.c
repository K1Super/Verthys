/*
 * service_main.c — SCM 入口、进程加固、控制处理与测试控制台模式
 *
 * 生产构建不包含任何 --test-* 分支；控制台模式只在
 * VERTHYS_SERVICE_TEST_HOOKS=1 的测试构建中编译。
 */
#include "client_auth.h"
#include "pipe_server.h"
#include "service_state.h"
#include "service_util.h"
#include "setup_entry.h"

#include <stdio.h>
#include <string.h>

static VtyServiceContext g_context;
static SERVICE_STATUS_HANDLE g_status_handle;
static SERVICE_STATUS g_status;
static DWORD g_checkpoint = 1;

static void set_status(DWORD state, DWORD win32_exit_code,
                       DWORD service_exit_code, DWORD wait_hint)
{
    if (g_status_handle == NULL) return;
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted =
        (state == SERVICE_RUNNING)
            ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN)
            : 0;
    g_status.dwWin32ExitCode = win32_exit_code;
    g_status.dwServiceSpecificExitCode = service_exit_code;
    g_status.dwCheckPoint =
        (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
            ? g_checkpoint++
            : 0;
    g_status.dwWaitHint = wait_hint;
    (void)SetServiceStatus(g_status_handle, &g_status);
}

static int apply_process_mitigations(void)
{
    PROCESS_MITIGATION_DEP_POLICY dep;
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg;
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic_code;
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extension;
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY image_load;

    memset(&dep, 0, sizeof(dep));
    dep.Enable = 1;
    /*
     * Permanent=1 在部分 Windows 构建返回 ERROR_NOT_SUPPORTED；DEP 已由
     * 链接期 /NXCOMPAT 在 PE 上强制，运行期只做非永久增强。
     */
    dep.Permanent = 0;
    {
        PROCESS_MITIGATION_DEP_POLICY dep_current;
        memset(&dep_current, 0, sizeof(dep_current));
        if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDEPPolicy,
                                       &dep_current, sizeof(dep_current)) &&
            dep_current.Enable) {
            /* 已启用；不重复设置。 */
        } else if (!SetProcessMitigationPolicy(ProcessDEPPolicy, &dep,
                                               sizeof(dep))) {
            DWORD dep_error = GetLastError();
            if (dep_error == ERROR_NOT_SUPPORTED) {
                /* PE 已由 /NXCOMPAT 强制 DEP；运行期策略在部分构建不可用。 */
                vty_event_log(EVENTLOG_WARNING_TYPE, 3005,
                              L"runtime DEP policy unsupported; "
                              L"PE NXCOMPAT remains enforced");
                fprintf(stderr,
                        "DEP policy unsupported; PE NXCOMPAT in effect\n");
                fflush(stderr);
            } else {
                fprintf(stderr, "DEP mitigation failed: %lu\n",
                        (unsigned long)dep_error);
                fflush(stderr);
                vty_event_log(EVENTLOG_WARNING_TYPE, 3005,
                              L"runtime DEP policy unavailable; "
                              L"PE NXCOMPAT remains enforced");
            }
        }
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.EnableControlFlowGuard = 1;
    {
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg_current;
        memset(&cfg_current, 0, sizeof(cfg_current));
        if (GetProcessMitigationPolicy(GetCurrentProcess(),
                                       ProcessControlFlowGuardPolicy,
                                       &cfg_current, sizeof(cfg_current)) &&
            cfg_current.EnableControlFlowGuard) {
            /* PE /guard:cf 已生效；不重复设置。 */
        } else if (!SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy,
                                               &cfg, sizeof(cfg))) {
            DWORD cfg_error = GetLastError();
            if (cfg_error == ERROR_NOT_SUPPORTED) {
                vty_event_log(EVENTLOG_WARNING_TYPE, 3005,
                              L"runtime CFG policy unsupported; "
                              L"PE CFG remains enforced");
                fprintf(stderr, "CFG policy unsupported; PE CFG in effect\n");
                fflush(stderr);
            } else {
                fprintf(stderr, "CFG mitigation failed: %lu\n",
                        (unsigned long)cfg_error);
                fflush(stderr);
                vty_event_log(EVENTLOG_WARNING_TYPE, 3005,
                              L"runtime CFG policy unavailable; "
                              L"PE CFG remains enforced");
            }
        }
    }

    memset(&dynamic_code, 0, sizeof(dynamic_code));
    dynamic_code.ProhibitDynamicCode = 1;
    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamic_code,
                                    sizeof(dynamic_code))) {
        vty_event_log(EVENTLOG_WARNING_TYPE, 3005,
                      L"dynamic code policy not applied");
    }

    memset(&extension, 0, sizeof(extension));
    extension.DisableExtensionPoints = 1;
    if (!SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy,
                                    &extension, sizeof(extension))) {
        vty_event_log(EVENTLOG_WARNING_TYPE, 3005,
                      L"extension point policy not applied");
    }

    memset(&image_load, 0, sizeof(image_load));
    image_load.NoRemoteImages = 1;
    image_load.NoLowMandatoryLabelImages = 1;
    image_load.PreferSystem32Images = 1;
    if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy, &image_load,
                                    sizeof(image_load))) {
        vty_event_log(EVENTLOG_WARNING_TYPE, 3005,
                      L"image load policy not applied");
    }
    return 0;
}

static int verify_self_signature(const wchar_t *publisher_sha256)
{
    wchar_t path[VTY_PATH_MAX];

    if (publisher_sha256 == NULL || publisher_sha256[0] == L'\0') {
        /* 本地构建未注入发布者指纹；生产构建由 CMake 强制非空。 */
        return 0;
    }
    if (vty_get_self_image_path(path, VTY_PATH_MAX) != 0) return -1;
    return vty_auth_verify_authenticode(path, publisher_sha256);
}

static DWORD WINAPI service_control_handler(DWORD control, DWORD event_type,
                                            LPVOID event_data,
                                            LPVOID context)
{
    (void)event_type;
    (void)event_data;
    (void)context;
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        if (g_context.stop_event != NULL) {
            SetEvent(g_context.stop_event);
        }
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static VOID WINAPI service_main(DWORD argc, LPWSTR *argv)
{
    VtyServiceRuntimeConfig cfg;
    VtyServiceInitResult init_result;
    int pipe_rc;

    (void)argc;
    (void)argv;
    g_status_handle = RegisterServiceCtrlHandlerExW(
        VTY_SVC_SERVICE_NAME, service_control_handler, NULL);
    if (g_status_handle == NULL) return;
    set_status(SERVICE_START_PENDING, NO_ERROR, 0, 10000);

    if (apply_process_mitigations() != 0) {
        set_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 1, 0);
        return;
    }

    vty_service_runtime_config_production(&cfg);
    if (verify_self_signature(cfg.publisher_sha256) != 0) {
        vty_event_log(EVENTLOG_ERROR_TYPE, 3003,
                      L"self signature verification failed; refuse start");
        set_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 2, 0);
        return;
    }

    init_result = vty_service_context_init(&g_context, &cfg);
    if (init_result == VTY_SERVICE_INIT_REFUSE) {
        vty_event_log(EVENTLOG_ERROR_TYPE, 3001,
                      L"service initialization refused; stopping");
        vty_service_context_cleanup(&g_context);
        set_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 3, 0);
        return;
    }
    if (init_result == VTY_SERVICE_INIT_FAIL_CLOSED) {
        vty_event_log(EVENTLOG_ERROR_TYPE, 3001,
                      L"service running fail-closed");
    }

    set_status(SERVICE_RUNNING, NO_ERROR, 0, 0);
    vty_event_log(EVENTLOG_INFORMATION_TYPE, 1000,
                  L"service started");

    pipe_rc = vty_pipe_server_run(&g_context);

    set_status(SERVICE_STOP_PENDING, NO_ERROR, 0, 10000);
    if (vty_machine_state_flush(&g_context.state) != 0) {
        vty_event_log(EVENTLOG_ERROR_TYPE, 3005,
                      L"state flush failed during shutdown");
    }
    vty_service_context_cleanup(&g_context);
    vty_event_log(EVENTLOG_INFORMATION_TYPE, 1001, L"service stopped");
    set_status(SERVICE_STOPPED,
               pipe_rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR,
               pipe_rc == 0 ? 0 : 4, 0);
}

#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
static BOOL WINAPI console_control_handler(DWORD control)
{
    if (control == CTRL_C_EVENT || control == CTRL_BREAK_EVENT) {
        if (g_context.stop_event != NULL) {
            SetEvent(g_context.stop_event);
        }
        return TRUE;
    }
    return FALSE;
}

static int arg_value(int argc, wchar_t **argv, int *index, wchar_t *out,
                     size_t cap)
{
    if (*index + 1 >= argc) return -1;
    (*index)++;
    return vty_wide_copy(out, cap, argv[*index]);
}

static int run_console(int argc, wchar_t **argv)
{
    VtyServiceRuntimeConfig cfg;
    VtyServiceInitResult init_result;
    wchar_t state_dir[VTY_PATH_MAX];
    wchar_t pipe_name[128];
    wchar_t registry_root[VTY_REGISTRY_TEXT_MAX];
    wchar_t publisher[65];
    wchar_t value[VTY_PATH_MAX];
    int have_state_dir = 0;
    int have_registry = 0;
    int apply_mitigations = 0;
    int i;
    int pipe_rc;

    memset(state_dir, 0, sizeof(state_dir));
    memset(pipe_name, 0, sizeof(pipe_name));
    memset(registry_root, 0, sizeof(registry_root));
    memset(publisher, 0, sizeof(publisher));
    memset(&cfg, 0, sizeof(cfg));
    vty_service_runtime_config_production(&cfg);
    cfg.test_mode = 1;

    for (i = 2; i < argc; i++) {
        if (wcscmp(argv[i], L"--test-state-dir") == 0) {
            if (arg_value(argc, argv, &i, state_dir, VTY_PATH_MAX) != 0) return 2;
            have_state_dir = 1;
        } else if (wcscmp(argv[i], L"--test-pipe") == 0) {
            if (arg_value(argc, argv, &i, pipe_name, 128) != 0) return 2;
        } else if (wcscmp(argv[i], L"--test-registry-root") == 0) {
            if (arg_value(argc, argv, &i, registry_root,
                          VTY_REGISTRY_TEXT_MAX) != 0) {
                return 2;
            }
            have_registry = 1;
        } else if (wcscmp(argv[i], L"--test-clock-offset-sec") == 0) {
            long sec;
            if (arg_value(argc, argv, &i, value, VTY_PATH_MAX) != 0) return 2;
            sec = wcstol(value, NULL, 10);
            cfg.test_utc_offset_100ns = (int64_t)sec * 10000000LL;
            cfg.test_ms_offset = (int64_t)sec * 1000LL;
        } else if (wcscmp(argv[i], L"--test-run-seconds") == 0) {
            unsigned long sec;
            if (arg_value(argc, argv, &i, value, VTY_PATH_MAX) != 0) return 2;
            sec = wcstoul(value, NULL, 10);
            cfg.test_run_seconds = (int)sec;
        } else if (wcscmp(argv[i], L"--test-ignore-user-quota") == 0) {
            cfg.test_ignore_user_quota = 1;
        } else if (wcscmp(argv[i], L"--test-ignore-client-auth") == 0) {
            cfg.test_ignore_client_auth = 1;
        } else if (wcscmp(argv[i], L"--test-publisher-sha256") == 0) {
            if (arg_value(argc, argv, &i, publisher, 65) != 0) return 2;
        } else if (wcscmp(argv[i], L"--test-apply-mitigations") == 0) {
            apply_mitigations = 1;
        } else {
            fprintf(stderr, "unknown argument: %ls\n", argv[i]);
            return 2;
        }
    }

    if (!have_state_dir) {
        fprintf(stderr, "--test-state-dir is required in console mode\n");
        return 2;
    }
    if (!have_registry) {
        if (swprintf_s(registry_root, VTY_REGISTRY_TEXT_MAX,
                       L"Software\\VerthysTest\\SecurityService-%lu",
                       (unsigned long)GetCurrentProcessId()) < 0) {
            return 2;
        }
    }

    cfg.test_ignore_client_auth = cfg.test_ignore_client_auth ? 1 : 0;
    (void)vty_wide_copy(cfg.test_state_dir, VTY_PATH_MAX, state_dir);
    (void)vty_wide_copy(cfg.registry_root, VTY_REGISTRY_TEXT_MAX,
                        registry_root);
    if (pipe_name[0] != L'\0') {
        (void)vty_wide_copy(cfg.pipe_name, 128, pipe_name);
    } else if (swprintf_s(cfg.pipe_name, 128,
                          L"\\\\.\\pipe\\VerthysSecuritySvcTest-%lu",
                          (unsigned long)GetCurrentProcessId()) < 0) {
        return 2;
    }
    if (publisher[0] != L'\0') {
        (void)vty_wide_copy(cfg.publisher_sha256, 65, publisher);
    }

    SetConsoleCtrlHandler(console_control_handler, TRUE);
    if (apply_mitigations && apply_process_mitigations() != 0) {
        fprintf(stderr, "MITIGATION_FAILED\n");
        return 5;
    }
    init_result = vty_service_context_init(&g_context, &cfg);
    if (init_result == VTY_SERVICE_INIT_REFUSE) {
        fprintf(stderr, "REFUSE\n");
        vty_service_context_cleanup(&g_context);
        return 3;
    }
    if (init_result == VTY_SERVICE_INIT_FAIL_CLOSED) {
        fprintf(stderr, "FAIL_CLOSED\n");
    }

    pipe_rc = vty_pipe_server_run(&g_context);
    (void)vty_machine_state_flush(&g_context.state);
    vty_service_context_cleanup(&g_context);
    fprintf(stderr, "STOPPED rc=%d\n", pipe_rc);
    fflush(stderr);
    return pipe_rc == 0 ? 0 : 4;
}
#endif

int wmain(int argc, wchar_t **argv)
{
#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
    if (argc > 1 && wcscmp(argv[1], L"--test-console") == 0) {
        return run_console(argc, argv);
    }
#endif

    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    (void)SetDllDirectoryW(L"");
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                 SEM_NOOPENFILEERRORBOX);

    /* 安装/卸载/修复子命令：由提权后的应用安装器或管理员调用。
     * SCM 启动时 argc 为 1，不会进入此分支。 */
    if (argc > 1 && argv[1][0] == L'/') {
        return vty_service_setup_main(argc, argv);
    }
    if (argc > 1) {
        fwprintf(stderr, L"[VerthysSecuritySvc] unknown argument: %ls\n",
                 argv[1]);
        return 2;
    }

    {
        SERVICE_TABLE_ENTRYW table[2];
        table[0].lpServiceName = (LPWSTR)VTY_SVC_SERVICE_NAME;
        table[0].lpServiceProc = service_main;
        table[1].lpServiceName = NULL;
        table[1].lpServiceProc = NULL;
        if (!StartServiceCtrlDispatcherW(table)) {
            fprintf(stderr,
                    "[VerthysSecuritySvc] StartServiceCtrlDispatcher failed: %lu\n",
                    (unsigned long)GetLastError());
            return 1;
        }
    }
    return 0;
}
