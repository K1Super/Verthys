/*
 * verthys_container_lock.h — 容器文件跨进程互斥打开（单写者语义）
 *
 * 职责：为容器会话句柄提供两层跨进程写互斥——
 *   1. 硬互斥：CreateFile 共享模式 FILE_SHARE_READ（本会话持写句柄，
 *      任何其他进程再以写访问打开同一容器即 ERROR_SHARING_VIOLATION，
 *      在句柄层被内核直接拒绝）；
 *   2. 协作互斥：打开成功后对超级块区 [0, 64KB) 加
 *      LockFileEx 独占字节范围锁（FAIL_IMMEDIATELY），另一 Verthys
 *      实例以只读方式打开并发起写入前会被该锁显式拒绝。
 *
 * 单靠 AEAD+HMAC 只能事后检测篡改，无法阻止并发写者互相覆盖造成
 * 结构损坏，因此互斥必须落在 OS 句柄/锁层。
 *
 * 诊断旁路：持有者把自己的 PID 写入 <path>.lock 旁路文件；竞争者
 * 被拒时读取旁路 PID 输出诊断，便于定位持有进程。旁路文件仅承载
 * 诊断信息，不参与互斥判定（互斥由句柄共享模式与字节范围锁保证）。
 *
 * 契约：
 *   - open_exclusive 返回的 FILE* 是会话唯一容器句柄，关闭必须走
 *     verthys_container_close_exclusive（释放字节范围锁 + 清理旁路文件），
 *     不得直接 fclose；
 *   - 非 Windows 平台退化为普通 fopen 语义（无跨进程锁）。
 */
#ifndef VERTHYS_CONTAINER_LOCK_H
#define VERTHYS_CONTAINER_LOCK_H

#include <stdio.h>
#include "verthys.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 以单写者语义打开容器并获得超级块区独占锁。
 *   path       : 容器文件路径
 *   create_new : 1=CREATE_NEW（仅新建，文件已存在返回 VERTHYS_ERR_EXISTS），
 *                0=OPEN_EXISTING
 *   out_f      : 输出会话句柄（调用方持有，须经 close_exclusive 关闭）
 * 返回：VERTHYS_OK / VERTHYS_ERR_EXISTS / VERTHYS_ERR_CONTAINER_BUSY /
 *       VERTHYS_ERR_IO。失败时 out_f 保持 NULL，无句柄泄漏。
 */
VerthysResult verthys_container_open_exclusive(const char *path,
                                               int create_new,
                                               FILE **out_f);

/*
 * 关闭会话句柄：释放超级块区字节范围锁（随句柄关闭由 OS 回收）、
 * 尽力删除 PID 旁路文件、fclose。path 为 NULL 时跳过旁路清理
 * （仅注销句柄）；函数幂等（f == NULL 为空转）。
 */
void verthys_container_close_exclusive(FILE *f, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_CONTAINER_LOCK_H */