/*
 * dllmain.c — verthys.dll 动态链接库入口函数 DllMain
 *
 * 模块加载执行流程：
 *   1. TLS 回调函数（持有加载锁期间最先触发）
 *      → 仅执行状态标记原子赋值操作，不执行任何IAT导入表与镜像文件相关操作
 *   2. DllMain 进程附加事件（加载锁仍处于占用状态）
 *      → 关闭线程库回调通知，降低线程回调性能开销与潜在攻击面
 *      → 执行内嵌CRC校验初始化，仅完成内部状态表赋值，不创建任何线程
 *      → 不在此处执行TLS加载器初始化，避免内部定时器接口在加载锁环境下引发死锁
 *   3. Verthys_Init 模块初始化（加载锁释放后执行业务层初始化）
 *      → TLS加载器初始化：包含IAT合法性校验、混淆数据表构建、定时器对象创建
 *      → 依次调用所有安全防御模块的初始化接口
 *      → 启动启动阶段防御闭环检测，校验全部攻击路径拦截有效性
 *
 * 安全执行约束：
 *   - DllMain 内部禁止调用 LoadLibrary、LdrGetProcedureAddress 等会触发模块递归加载的接口
 *   - DllMain 内部禁止调用依赖CRT运行时未完成初始化的函数
 *   - DllMain 内部禁止创建线程、定时器、内核同步对象，规避加载锁死锁风险
 *   - DllMain 函数仅允许完成模块状态标记注册与关闭线程回调两项操作
 */
#include "tls_loader.h"
#include "verthys_pepper.h"    /* 胡椒托管框架资源清理逻辑 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/*
 * DllMain — DLL标准入口函数
 *
 * 核心设计规范：
 *   1. 将含定时器创建的重量级初始化移出DllMain，延后至加载锁释放后执行
 *   2. 关闭线程附加/分离回调通知，减少无效系统回调触发
 *   3. 进程分离事件中区分进程正常退出与手动卸载两种场景做差异化处理
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
    switch (dwReason) {
    case DLL_PROCESS_ATTACH: {
        /*
         * 关闭线程附加、线程分离的系统回调通知
         * 减少线程新建与销毁带来的频繁回调损耗，缩减可被利用的攻击入口
         */
        DisableThreadLibraryCalls(hinstDLL);

        /*
         * 原 inline_crc_init 随 inline_crc 模块删除；
         * TLS 回调（tls_callbacks.c）已在此前的加载阶段置位
         * g_tls_init_marker，无其他加载锁内工作。
         */
        break;
    }
    case DLL_PROCESS_DETACH: {
        /*
         * 根据入参区分模块卸载场景做不同资源回收逻辑
         * lpvReserved != NULL：进程强制终止，操作系统已回收堆内存，不可访问内部资源
         * lpvReserved == NULL：主动调用FreeLibrary卸载模块，可安全执行自定义资源释放
         *
         * 加载锁约束核查结论（固化）：本分支实际调用链为
         *   tls_loader_shutdown（空实现）+ verthys_pepper_deinit
         *   （VirtualUnlock 内核接口 + 进程内内存清零 + 状态标志赋值，
         *   无锁获取、无堆分配、无 CRT 依赖）——
         *   不触发模块递归加载、不依赖加载锁外的任何同步对象，
         *   故无需推迟到后台线程，保持在 DETACH 内同步执行。
         */
        if (lpvReserved == NULL) {
            tls_loader_shutdown();
            /* 模块主动卸载时清空胡椒内存区域并解除内存页保护锁定
             * 胡椒数据为进程全局变量，仅在DLL手动卸载时执行销毁，不跟随句柄生命周期释放 */
            verthys_pepper_deinit();
        }
        /* 进程直接退出时跳过手动资源释放，交由操作系统自动回收所有资源 */
        break;
    }
    case DLL_THREAD_ATTACH:
        /* 全局已禁用线程附加回调，该分支理论上不会被执行 */
        break;
    case DLL_THREAD_DETACH:
        /* 全局已禁用线程分离回调，该分支理论上不会被执行 */
        break;
    default:
        break;
    }

    return TRUE;
}