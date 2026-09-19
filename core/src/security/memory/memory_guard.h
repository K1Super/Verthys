/*
 * memory_guard.h — 内存防转储与防交换（内部模块，不导出）
 *
 */
#ifndef VERTHYS_MEMORY_GUARD_H
#define VERTHYS_MEMORY_GUARD_H

#include <stdint.h>
#include <stddef.h>

/*
 * 初始化内存防护模块。
 * 根据安全配置决定是否启用 VirtualLock / 防转储。
 */
int memory_guard_init(void);

/*
 * 锁定内存页（禁止交换到磁盘）。
 *   ptr: 内存区域起始地址
 *   len: 区域长度
 * Windows: VirtualLock
 * Linux: mlock
 * 返回 0 成功，非 0 失败。
 */
int memory_guard_lock(void *ptr, size_t len);

/*
 * 解锁内存页。
 *   ptr: 内存区域起始地址
 *   len: 区域长度
 */
int memory_guard_unlock(void *ptr, size_t len);

/*
 * 安全多轮覆写零化（0x00 → 0xFF → 0x00）。
 *   ptr: 内存区域起始地址
 *   len: 区域长度
 * 使用 SecureZeroMemory 确保编译器不会优化掉写入操作。
 * 不依赖 GC / 延迟释放。
 */
void memory_guard_secure_zero(void *ptr, size_t len);

/*
 * 检测远程内存读取行为。
 * 检查是否有非系统进程打开了当前进程的 VM_READ 权限句柄。
 * 返回 0=安全，非 0=检测到可疑读取。
 */
int memory_guard_check_remote_read(void);

/*
 * 触发紧急内存零化。
 * 对所有已注册的敏感内存区域执行多轮覆写清零。
 * 应急响应时调用（同 emergency.h）。
 */
void memory_guard_emergency_purge(void);

/*
 * 注册敏感内存区域（用于紧急零化时遍历）。
 *   ptr: 内存区域起始地址
 *   len: 区域长度
 *   name: 区域名称（用于内部日志，不含敏感数据）
 * 返回 0 成功，非 0 失败（已达最大注册数）。
 */
int memory_guard_register(void *ptr, size_t len, const char *name);

/*
 * 注销敏感内存区域（区域释放前调用）。
 */
int memory_guard_unregister(void *ptr);

/*
 * 防转储低频巡逻（解锁成功时启动）。
 * 每 ≥60 秒执行一次 memory_guard_check_remote_read（一次性定时器链，
 * 事件外零唤醒），检测到非信任进程句柄 → DEGRADE 级上报。
 * 性能模式（anti_dump=0）下启动调用为空操作。幂等：已运行返回 0。
 * 返回 0 成功，非 0 失败（定时器创建失败）。
 */
int memory_guard_patrol_start(void);

/*
 * 停止巡逻（锁定/销毁句柄时调用）。幂等。
 */
void memory_guard_patrol_stop(void);

#endif /* VERTHYS_MEMORY_GUARD_H */
