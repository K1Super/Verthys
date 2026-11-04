/*
 * hibernation_state.h — 系统休眠状态查询（内部模块，不导出）
 *
 * 休眠文件（hiberfil.sys）保存物理内存镜像；系统启用休眠时，解锁进程的
 * 用户态密钥可能随镜像落盘。防御状态需要区分"禁用 / 启用 / 未知"三态：
 * 禁用时无可取证资产，启用或有疑义时如实降级。
 *
 * 查询只读注册表，不创建句柄以外的资源；读取失败一律按"未知"处理，
 * 不猜测、不默认禁用。
 */
#ifndef VERTHYS_HIBERNATION_STATE_H
#define VERTHYS_HIBERNATION_STATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HIBERNATION_STATE_DISABLED 0u
#define HIBERNATION_STATE_ENABLED  1u
#define HIBERNATION_STATE_UNKNOWN  2u

/*
 * 纯解析：present=0 表示注册表值缺失 → UNKNOWN；present!=0 时
 * value 非 0 → ENABLED，0 → DISABLED。
 * 供单元测试注入，不触碰注册表。
 */
uint32_t hibernation_state_parse(int present, uint32_t value);

/*
 * 查询当前系统休眠状态。
 *   依次读取 HKLM\SYSTEM\CurrentControlSet\Control\Power 下
 *   HibernateEnabled、HibernateEnabledDefault；任一读取成功即返回结论。
 * 返回 HIBERNATION_STATE_*；读取失败/值缺失 → UNKNOWN。
 * 线程安全：只读注册表，MT-Safe。
 */
uint32_t hibernation_state_query(void);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_HIBERNATION_STATE_H */
