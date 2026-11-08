/*
 * pipe_server.h — 命名管道服务端
 */
#ifndef VTY_PIPE_SERVER_H
#define VTY_PIPE_SERVER_H

#include "service_state.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 创建 8 个管道实例并启动工作线程，阻塞直到 stop_event 被置位。
 * 返回 0 表示正常停止；-1 表示实例创建失败或线程未在 10 秒内退出。
 */
int vty_pipe_server_run(VtyServiceContext *ctx);

#ifdef __cplusplus
}
#endif

#endif /* VTY_PIPE_SERVER_H */
