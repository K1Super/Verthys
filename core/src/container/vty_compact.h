/*
 * vty_compact.h — 容器空间压缩作业（内部，不导出）
 *
 * 只重排活数据：同一 K_c/epoch/uuid/slots/keyring，原样搬运记录/分片
 * 密文，重建紧凑目录树，然后用 ReplaceFileW 原子替换。不换密钥、不重
 * 加密、不需要用户口令；删除后遗留的墓碑、旧 COW 节点与旧段在替换后
 * 从文件中消失。
 */
#ifndef VTY_COMPACT_H
#define VTY_COMPACT_H

#include "vty_types.h"
#include "vty_keymanager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VTY_COMPACT_STAGE_BEGUN     1u
#define VTY_COMPACT_STAGE_COPIED    2u
#define VTY_COMPACT_STAGE_COMMITTED 3u
#define VTY_COMPACT_STAGE_FAILED    4u

typedef struct {
    uint32_t stage;            /* VTY_COMPACT_STAGE_* */
    uint64_t before_bytes;     /* 压缩前容器文件大小 */
    uint64_t after_bytes;      /* 压缩后容器文件大小（COPIED 后有效） */
    uint64_t reclaimed_bytes;  /* before - after（after 更小时） */
    uint64_t records;          /* 已复制的活记录数 */
    uint64_t chunks;           /* 已复制的活分片数 */
    uint64_t bytes;            /* 已复制的活段字节数 */
    uint64_t live_bytes;       /* 压缩前活字节统计 */
} VtyCompactStats;

/* 进度回调：返回非 0 取消本次 Run（作业进入失败态，只能 Abort）。 */
typedef int (*VtyCompactProgressFn)(void *user, const VtyCompactStats *stats);

typedef struct VtyCompactJob VtyCompactJob;

/* 前置：src 已解锁、无轮换作业、无批量导入窗口；tmp_path 必须与源库
 * 同目录且不存在。成功返回作业，源库保持打开、不受影响。 */
int vty_compact_begin(VtyVault *src, const char *tmp_path,
                      VtyCompactJob **out);

/* 复制活数据到临时库并复核。成功进入 COPIED；失败进入 FAILED。 */
int vty_compact_run(VtyCompactJob *job, VtyCompactProgressFn cb, void *user);

/* 原子替换并推进回退锚点。成功返回新会话（*out_new），作业被释放，
 * 源库实例被释放；调用方负责把 *out_new 接管到句柄。 */
int vty_compact_commit(VtyCompactJob *job, VtyVault **out_new);

/* 丢弃临时库并释放作业；源库保持原状。返回 VTY_OK 表示临时文件已
 * 不存在；删除失败返回 VTY_E_IO（作业仍被释放）。 */
int vty_compact_abort(VtyCompactJob *job);

void vty_compact_free(VtyCompactJob *job);

const VtyCompactStats *vty_compact_stats(const VtyCompactJob *job);

/* 解锁/启动维护：删除崩溃遗留的 .vtycompact.tmp。备份文件不在此处
 * 删除——必须等源库成功打开后才能确认新文件可用。 */
int vty_compact_cleanup_stale(const char *container_path);

/* 源库成功打开后调用：删除上次替换遗留的 .vtycompact.bak。 */
int vty_compact_drop_backup(const char *container_path);

#ifdef __cplusplus
}
#endif

#endif /* VTY_COMPACT_H */
