#ifndef VTY_SETUP_ENTRY_H
#define VTY_SETUP_ENTRY_H

/*
 * 服务安装子命令入口。由 VerthysSecuritySvc.exe 依据首参分发；
 * 参数语义与原独立安装器一致：/install /uninstall /repair
 * /reset-state /repair-keys /status /quiet /keep-state。
 */
int vty_service_setup_main(int argc, wchar_t **argv);

#endif
