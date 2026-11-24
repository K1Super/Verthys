#ifndef VTY_KERNEL_GUARD_H
#define VTY_KERNEL_GUARD_H

#include <windows.h>
#include <stdint.h>

#include "vty_svc_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 服务侧内核防护状态与生命周期命令。
 *
 * 状态与原因枚举在 vty_svc_protocol.h 中定义，供服务、核心与 worker 共用。
 *
 * 安全约束：
 *   - 受保护对象只能是已认证客户端进程，或宿主目录下白名单 worker；
 *     客户端不能提交任意受保护路径；
 *   - 宿主预 ARM 模式要求调用方映像基名为 verthys.exe；
 *   - REGISTER 的宿主模式必须提交目标 PID 与创建时间，服务重新读取
 *     创建时间和映像路径并与已 ARM 路径比对；
 *   - 驱动只接受 SYSTEM 服务访问，服务是唯一客户端；
 *   - 所有命令返回服务状态码，并回填驱动当前状态。
 */

typedef struct VtyKernelGuardStatus {
    uint32_t state;
    uint32_t reason;
    uint32_t capabilities;
    uint16_t protocol_major;
    uint16_t protocol_minor;
} VtyKernelGuardStatus;

/*
 * 查询生产设备 \\.\VerthysGuard。
 * 返回 0 表示状态已确定（包括未安装/未运行）；返回 -1 仅表示参数或资源错误。
 */
int vty_kernel_guard_query(VtyKernelGuardStatus *out);

/* 测试入口：允许指向不存在的设备路径，验证不可用状态映射。 */
int vty_kernel_guard_query_path(const wchar_t *device_path,
                                VtyKernelGuardStatus *out);

/*
 * ARM 受保护路径。
 *   - mode=VTY_SVC_ARM_MODE_WORKER_SELF：保护已认证 worker 自身；
 *   - mode=VTY_SVC_ARM_MODE_HOST_PREARM：调用方必须是宿主，服务从宿主
 *     映像目录与 worker_image 选择的白名单基名派生受保护路径。
 * client_process 必须是由客户端认证持有的进程句柄（查询权限）。
 * 返回 VTY_SVC_STATUS_*；out 始终回填当前内核状态。
 */
uint16_t vty_kernel_guard_arm(DWORD client_pid, HANDLE client_process,
                              uint32_t mode, uint32_t worker_image,
                              VtyKernelGuardStatus *out);

/*
 * 登记受保护进程。
 *   - worker self / 已绑定 worker：target_pid 与 target_creation 必须为 0；
 *   - 宿主预 ARM 模式：提交 worker PID 与创建时间，服务校验后登记目标。
 */
uint16_t vty_kernel_guard_register(DWORD client_pid, HANDLE client_process,
                                   uint32_t target_pid,
                                   uint64_t target_creation,
                                   VtyKernelGuardStatus *out);

/* 解除保护；调用方须为 ARM owner 或已登记 worker，已 NOT_ARMED 视为成功。 */
uint16_t vty_kernel_guard_disarm(DWORD client_pid, HANDLE client_process,
                                 VtyKernelGuardStatus *out);

/*
 * 测试入口：把 DOS 路径转换为 SeLocateProcessImageName 使用的
 * \Device\HarddiskVolumeN\... 形式。
 */
int vty_kernel_guard_dos_to_nt_path(const wchar_t *dos_path, wchar_t *out,
                                    size_t cap);

/* 测试入口：判断映像基名是否为 Verthys worker。 */
int vty_kernel_guard_is_worker_image(const wchar_t *image_path);

/* 测试入口：判断映像基名是否为 Verthys 宿主。 */
int vty_kernel_guard_is_host_image(const wchar_t *image_path);

/* 测试入口：按选择器输出白名单 worker 基名。 */
int vty_kernel_guard_worker_basename(uint32_t selector, wchar_t *out,
                                     size_t cap);

/*
 * 测试入口：从宿主映像路径派生同目录白名单 worker 路径（DOS 形式）。
 * 仅拼接路径，不检查文件是否存在；ARM 时会另行校验文件。
 */
int vty_kernel_guard_build_sibling_path(const wchar_t *host_image,
                                        uint32_t selector, wchar_t *out,
                                        size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* VTY_KERNEL_GUARD_H */
