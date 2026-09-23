/*
 * verthys_persist_guard.h — 持久化写侧口径守卫
 *
 * 用途：所有持久化结构的写路径在把运行期值收缩进盘面定宽字段
 * （u32 等）之前，必须先经本文件宏断言口径——写路径禁止截断。
 * 截断会产出"写成功但读回结构不完整"的损坏帧（尺寸字段与实际
 * 密文长度不符 → 索引不可恢复），必须在上游拒绝而非落盘后暴露。
 * 宏失败统一返回 VERTHYS_ERR_INVALID（调用方协议：入参超界）。
 */
#ifndef VERTHYS_PERSIST_GUARD_H
#define VERTHYS_PERSIST_GUARD_H

#include <stdint.h>
#include "verthys.h"

/* 值须可无损存入盘面 u32 字段 */
#define VERTHYS_GUARD_U32(val) \
    do { if ((uint64_t)(val) > UINT32_MAX) return VERTHYS_ERR_INVALID; } while (0)

/* 值 + 附加字节（尾部 tag 长度）之和须可无损存入盘面 u32 字段 */
#define VERTHYS_GUARD_U32_PLUS(val, tag) \
    do { \
        if ((uint64_t)(val) > (uint64_t)UINT32_MAX - (uint64_t)(tag)) { \
            return VERTHYS_ERR_INVALID; \
        } \
    } while (0)

#endif /* VERTHYS_PERSIST_GUARD_H */