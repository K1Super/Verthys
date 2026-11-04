/*
 * verthys_api_v4.h — v4 记录链路的 API 内部辅助（不导出）
 *
 * 公共入口只做参数/锁/借用缓存管理，v4 语义全部收敛在本层，避免
 * verthys_api.c 同时承载 v3 事务编排与 v4 仓库细节。
 */
#ifndef VERTHYS_API_V4_H
#define VERTHYS_API_V4_H

#include "verthys_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* v4 内部错误码 → 公共返回码（与解锁路径同一映射）。 */
VerthysResult verthys_api_v4_map(int vty_rc);

VerthysResult verthys_api_v4_add(struct VerthysContext *ctx,
                                 const VerthysRecord *record,
                                 uint64_t *out_id);

/* 批量新增：单次仓库提交（全有或全无），供大文件导入消除逐条提交开销。 */
VerthysResult verthys_api_v4_add_many(struct VerthysContext *ctx,
                                      const VerthysRecord *records,
                                      uint32_t count,
                                      uint64_t *out_ids);

VerthysResult verthys_api_v4_get(struct VerthysContext *ctx, uint64_t id,
                                 VerthysRecord *out_record);

VerthysResult verthys_api_v4_delete(struct VerthysContext *ctx, uint64_t id);

VerthysResult verthys_api_v4_delete_many(struct VerthysContext *ctx,
                                         const uint64_t *ids, size_t count);

VerthysResult verthys_api_v4_count(struct VerthysContext *ctx,
                                   uint64_t *out_count);

VerthysResult verthys_api_v4_verify(struct VerthysContext *ctx,
                                    uint64_t *out_failed_lids,
                                    uint64_t max_failed,
                                    uint64_t *out_failed_count);

VerthysResult verthys_api_v4_change_password(struct VerthysContext *ctx,
                                             const char *old_pw, size_t old_len,
                                             const char *new_pw, size_t new_len);

/* 添加/删除后由仓库内部保存；Flush 只需提交已写入的目录变更。 */
VerthysResult verthys_api_v4_flush(struct VerthysContext *ctx);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_API_V4_H */
