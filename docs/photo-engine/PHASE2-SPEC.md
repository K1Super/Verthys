# Phase 2 — 预览优先查看规格（执行版）

> 状态：实现完成 · 默认启用原生预览 · 最后更新：2026-11-19 · 维护人：K1Super
>
> 预览记录随原生导入生成；查看先读预览，原图按需分块读取。旧 JS 查看链路保留为回滚路径，Phase 4 删除。GUI 手测由用户在全部改造完成后执行。
>
> 关联文档：[01-architecture.md](01-architecture.md)、[02-data-model.md](02-data-model.md)、[04-view-export.md](04-view-export.md)、[05-implementation.md](05-implementation.md)、[06-verification.md](06-verification.md)、[PHASE1-SPEC.md](PHASE1-SPEC.md)。

## 1. 目标与验收判据

目标：照片首屏只读 2048px 预览，不再为查看一张照片解密并解码整幅原图；原图仅在动图、放大或导出时按块读取；预览失败不阻断照片可用性。

可判定完成的条件：

1. 原生导入在缩略图同一次解码中生成预览，并与 meta 同一批次落库；预览失败不阻断导入。
2. 预览记录按确定性名称定位，命中时直接解密返回；缺失/损坏/头哈希不匹配时懒生成并写回，二次打开命中。
3. 原图通过 `photo_full_begin/next/cancel` 按 4MiB 块返回明文；末块返回前完成整图 BLAKE3 校验。
4. 快速切换照片或关闭查看器时取消在途原图 job；过期结果不落地。
5. 预览/原图 Blob URL 有界 LRU，锁定、登出、删除、卸载时释放。
6. 删除照片级联删除预览记录；预览删除失败不阻断照片删除。
7. 瘦身布局（`wrappedFileKey` / `fmt==2`）返回 `E_PHOTO_LAYOUT_UNSUPPORTED`，前端回退旧 JS 链路。

## 2. 非目标

- 不改变容器格式、记录布局、`rollback.state` 布局。
- 不实现 Phase 3 原生导出、Phase 4 网格缩略图二进制化。
- 不实现自定义协议 `verthys-photo://` 与 HTTP Range。
- 不实现瘦身布局的原生读取。
- 不做后台批量预生成历史照片预览；仅按需懒生成。
- 不删除旧 JS 查看/解密链路。

## 3. 权威决策

### D1 预览记录命名与头格式

- 记录类型 `TYPE_PHOTO_PREVIEW = 0x0B`，内容种类 `preview = 9`。
- 名称：`preview_<entryKey>`；meta 无 `entryKey` 时退回 `preview_<metaId>`。
- 原因：新导入的 meta 与预览在同一批次写入，此时 metaId 尚未分配；`entryKey` 在导入时已知且跨重启稳定。历史记录若已带 `entryKey`，沿用同一规则；更早记录退回 metaId。
- 明文头为 32 字节 BLAKE3 原始 `fileHash`，不含 metaId：读取侧用当前 meta 的 `fileHash` 校验，头不匹配即视为缺失并重生成，防止记录 ID 复用与孤儿预览错配。
- 预览为派生缓存，不进入 VENC 备份清单，不重写旧 meta。

### D2 预览生成与写回

- 导入：`decoder::generate_assets` 一次解码同时产出 400px 缩略图与 2048px 预览；预览编码档位 2048/0.82 → 2048/0.70 → 1600/0.75 → 1280/0.70，512KB 预算内取首个符合档位。
- 收尾：`photo_import_job_finish` 返回预览密文与记录名；宿主把 meta 与预览放入同一 `AppendPending` 批次，共用 `entryKey`。
- 懒生成：读取侧解密原图块、原生解码、封装预览；宿主通过 `WriterCommand::AppendDerived` 写回，写者按记录名幂等（写者线程内 find → add），预览不在块台账中。
- 写回失败只告警，本次已生成的 JPEG 仍返回给前端。

### D3 worker 读取 job

- 协议：`photo_read_job_begin/next/cancel/end`；`mode=preview|full`，`meta_id` 必填。
- 预览为一次性操作：`begin` 直接返回整张 JPEG 与可选 `photo_record`，不注册 job。
- 原图为有状态 job：并发上限 4，空闲 120s 回收；每次 `next` 解密一个 4MiB 块并返回 `chunk_index`/`chunk_total`/`data_b64`，末块状态为 `done`。
- 块序号与总数必须与 meta 声明一致；全部块完成后以整图 BLAKE3 与 meta `fileHash` 比对，不符即报错。
- 取消后 `next` 返回 `cancelled`；`end` 幂等释放 job。
- 明文只存在于响应与前端 Blob；worker 不落盘、不跨请求缓存。

### D4 布局边界

- 原生读取覆盖：`meta` + `chunk`，块引用支持内联 `chunkDataB64` 与外置 `chunkIds`。
- `wrappedFileKey` 非空或 `fmt==2` 视为瘦身布局，返回 `E_PHOTO_LAYOUT_UNSUPPORTED`；前端捕获后继续旧 JS 解密链路。
- 无块引用、大小越界、非照片 meta 记录均返回明确错误。

### D5 名称索引

- C 新增 `Verthys_FindLidByName(handle, name, name_len, out_found, out_lid)`，API 版本 `0x0015`。
- 索引键为 `name_index(32) || be64(record_id)`；查询使用 `VTY_KS_NAME` 前缀游标，跳过墓碑，返回首个存活 ID。
- 名称先按 NFKC 归一化再计算盲索引；查询不读取记录密文。
- 未命中返回 `VERTHYS_OK + found=0`，不是错误。

### D6 删除级联

- worker `photo_preview_ids` 按 meta 解析预览记录 ID（与读取侧同一命名规则），宿主在删除事务前并入同一批 ID。
- 预览定位失败或解密 meta 失败只告警，不阻断照片删除。
- 预览不在块台账，孤儿块 GC 不涉及预览记录。

### D7 前端查看器

- `photo.nativePreview` 默认启用；关闭时跳过原生预览与原图路径。
- 打开流程：命中 LRU 直接显示；未命中先显示 400px 缩略图占位，再请求预览并替换。
- 原图加载：动图必拉；静态图 ≤32MiB 自动拉取；>32MiB 置为待定，用户缩放超过 1.01 时触发。
- 快速切换：请求代际递增，旧预览/原图结果丢弃；关闭查看器取消在途原图 job。
- LRU：64MB / 5 项，键 `preview:<metaId>` 与 `full:<metaId>`；淘汰、删除、锁定、登出、模块卸载时释放。
- 原生预览失败（非布局不支持）记录告警并回退旧链路；布局不支持不重复刷告警。

### D8 回滚

- 关闭 `photo.nativePreview` 即恢复旧 JS 查看链路；已写入的预览记录对旧路径是未知类型，旧路径忽略即可。
- 预览可保留；再次启用后直接命中。

## 4. 实现落点

| 层 | 文件 | 内容 |
|---|---|---|
| C | `core/include/verthys.h`、`core/verthys.def`、`core/include/verthys_version.h` | `Verthys_FindLidByName`、API `0x0015` |
| C | `core/src/index/vty_repo.{h,c}`、`core/src/api/scan/verthys_scan.c` | 名称前缀游标查询与会话/锁校验 |
| worker | `runtime/media/preview.rs` | 头编解码、命名规则 |
| worker | `runtime/media/decoder.rs` | 缩略图 + 预览一次解码；预览编码档位 |
| worker | `runtime/media/import_job.rs` | 收尾返回预览密文与记录名 |
| worker | `runtime/media/read_job.rs` | 预览命中/懒生成、原图分块、取消、TTL |
| worker | `runtime/module_keys.rs`、`protocol.rs`、`dispatch.rs`、`worker.rs`、`ffi_types.rs` | 种类 9、读取响应、`FindLidByName` |
| 宿主 | `controller/photo_media_controller.rs` | `photo_preview_get`、`photo_full_begin/next/cancel` |
| 宿主 | `state/import_writer.rs` | `AppendDerived`、名称幂等 |
| 宿主 | `controller/verthys_controller.rs` | 删除前并入预览 ID |
| 前端 | `lib/verthys.ts`、`types/verthys.ts` | 命令封装与类型 |
| 前端 | `composables/photo-album/usePhotoViewer.ts` | 预览优先、原图按需、取消、代际 |
| 前端 | `composables/photo-album/photoBlobCache.ts` | Blob LRU |
| 前端 | `composables/photo-album/usePhotoDelete.ts`、`usePhotoData.ts` | 删除与密钥失效清理 |
| 前端 | `app/photo-flags.ts` | `nativePreview` 默认启用 |

## 5. 验证与未覆盖

验证证据见 [06-verification.md](06-verification.md) 的 G2 小节。未覆盖项：

- 预览首屏 P95、原图 P95 的 GUI 实测；E2E 只验证字节正确性与块数，不测渲染时延。
- 100 张快速切换、锁定中查看、动图播放的 GUI 行为。
- 自定义协议与 Range（未实现）。
- 瘦身布局原生读取（未实现，回退旧链路）。
- GUI 全流程手测由用户在全部改造完成后执行。
