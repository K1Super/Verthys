/*
 * setup_main.c — VerthysSecuritySvc.exe 的安装/卸载子命令入口
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

#include "setup_internal.h"
#include "setup_entry.h"

#pragma comment(lib, "version.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")

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
