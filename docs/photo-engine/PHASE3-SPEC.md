# Phase 3 — 原生导出与备份还原规格（执行版）

> 状态：实现完成 · 默认启用原生导出/还原 · 最后更新：2026-11-19 · 维护人：K1Super
>
> worker 负责解密、VENC 打包/解析、PNG 编码与逐块重封装；宿主负责暂存写盘、原子替换与单写者落库。旧 JS 链路保留为回滚路径，Phase 4 删除。GUI 手测由用户在全部改造完成后执行。
>
> 关联文档：[02-data-model.md](02-data-model.md)、[04-view-export.md](04-view-export.md)、[05-implementation.md](05-implementation.md)、[06-verification.md](06-verification.md)、[PHASE2-SPEC.md](PHASE2-SPEC.md)。

## 1. 目标与验收判据

目标：原始文件、`.venc`、PNG 导出与 `.venc` 还原不再经过 JS 字节面；worker 只产出字节，宿主完成原子写盘与记录落库。

可判定完成的条件：

1. `original` / `venc-single` / `venc-multiple` / `png` 四种导出字节正确，失败不产生半截目标文件。
2. `.venc` 与现有 JS 实现双向兼容：worker 产物可被前端 `unpackVenc` 解析，前端 `packVenc` 产物可被 worker 还原。
3. 单文件容器超 2GB 返回 `E_EXPORT_TOO_LARGE`，宿主中止暂存。
4. 还原沿用 `sha256("parsed|" + fileHash)` 条目键、`parsed_<ts>_<index>` 记录名与导入写入链；结果满足 `imported + failed + skipped === total`。
5. 预览扫描后容器被替换必须失败；错误令牌归因为认证失败。
6. 动图 PNG 导出跳过并记 `animated-unsupported`；加密导出保留动画。
7. 路径授权、日志、临时文件清理、取消与重试语义与导入一致。

## 2. 非目标

- 不改变容器格式、记录布局、`rollback.state` 布局。
- 不实现瘦身布局（`wrappedFileKey` / `fmt==2`）的原生导出；命中返回 `E_PHOTO_LAYOUT_UNSUPPORTED`，前端整批回退旧 JS 导出（原始文件格式无旧链路，直接报错）。
- 不实现自定义协议与 Range。
- 不删除旧 JS 导出/解包链路（Phase 4）。
- 不把导出目标路径授权下发给 worker：worker 不打开用户目标文件。

## 3. 权威决策

### D1 worker 产出字节，宿主写盘

- worker 事件：`file_begin` / `segment` / `file_end` / `photo` / `done`；`segment` 解码后 ≤4MiB，base64 响应约 ≤5.59MB。
- 宿主复用 `file_controller.rs` 的暂存会话：`create_new` 独占创建 → 追加 → `fsync` → `rename`；失败走 `abort` 删除暂存，目标文件保持旧完整版。
- create / finalize / abort 边界写入 `FileWrite` 审计事件（路径经哈希，不含文件内容）。
- 文件名净化与唯一化在宿主完成，规则与前端 `sanitizeFileName` / `uniqueFileName` 一致：非法字符替换、首尾空白/点裁剪、Windows 设备名加 `_`、UTF-8 200 字节（含扩展名）、批次内大小写不敏感唯一化。

### D2 导出来源与完整性

- 仅支持 `meta` + 内联 `chunkDataB64` 或外置 `chunkIds`；预检阶段一次性确认全部选中照片布局可用，任何一张不支持即整批结构化拒绝，避免部分文件已落盘后才回退。
- 每张照片先逐块 `ChunkOpen` 并累计整图 BLAKE3；块序号/总数、总字节与 `fileHash` 任一不符即该张失败，不产出该张文件内容。
- `venc-single` 单张失败只跳过该张（不产生帧），尾部帧按实际产出计数；容器整体超限中止整个容器。
- 动图 PNG：已确认动图直接跳过；历史记录按解密后字节探测 GIF/WebP/APNG，命中即记 `animated-unsupported`。

### D3 VENC 逐字节复刻

- 外层头 42B、包裹密钥 48B、帧头 9B、nonce 24B、tag 16B、salt 16B、iv 12B；版本 3、flags 0、KDF id 1、iterations 600000。
- 令牌 KDF：PBKDF2-SHA256(token, salt, 600000, 32)；包裹密钥 AES-256-GCM，nonce=iv，AD=外层头。
- 帧密钥 XChaCha20-Poly1305；AD = 帧头 9B + salt 16B；帧类型 1=清单、2=块、3=尾部。
- 清单字段严格 7 个：`chunkCount / createdAt / fileHash / mime / name / size / thumbB64`；未知字段、越界名称/类型/缩略图/块数一律拒绝。
- 尾部帧 12B：`frame_count u32 BE + body_bytes u64 BE`，只统计清单帧与块帧；尾部帧必须是最后一帧。
- 帧负载上限 64MiB、帧数上限 100000、容器上限 2,147,483,648 字节。

### D4 还原链路

- 宿主 `verthys_import_begin` 建立会话并取得 committed 条目键；worker 经 job grant 读取 `.venc`，流式解析并逐块用当前 MDEK `seal_photo_chunk` 重封装。
- 宿主逐块 `AppendChunks`；末块后调用 `photo_restore_photo_finish(chunk_ids)` 取回已封装 meta，再 `AppendPending` 写 meta。
- 去重：条目键已在 committed 集合中则 worker 只校验不落库（`skip_photo=true`），宿主计 skipped；后端按条目键幂等跳过同样计 skipped。
- 预览不进入备份；还原后首次查看懒生成。
- 开始还原时携带预览扫描的逐张 fileHash；清单哈希不一致立即失败。
- 授权 TTL 600s：还原循环每 300s 对同一路径滚动续期。

### D5 前端切换与回滚

- `photo.nativeExport` 默认 `true`，同时控制原生导出与原生还原；关闭时导出走旧 JS 打包链路、还原走 `runContainer`。
- 原生导出返回 `E_PHOTO_LAYOUT_UNSUPPORTED` 时，`venc-single` / `venc-multiple` / `png` 整批回退旧 JS 导出一次并记录告警；`original` 无旧链路，直接提示不支持。
- 导出对话框新增“原始文件”格式，仅在原生导出可用时展示；该格式为明文导出，需要令牌的格式才展示令牌输入。

### D6 并发与取消

- 导入、导出、还原共享 AppState 单任务槽位；同一时刻只允许一个重型媒体任务。
- 取消为本地标志权威 + worker 侧 best-effort；宿主在每个事件前检查并 abort 暂存。
- worker 导出/还原 job 上限 2、空闲 120s 回收；`end` 幂等释放并撤销路径授权。

## 4. 实现落点

| 层 | 文件 | 内容 |
|---|---|---|
| worker | `runtime/media/venc.rs` | VENC 打包/解析、KDF、帧校验、清单校验 |
| worker | `runtime/media/export_job.rs` | 四种格式导出 job、PNG 编码、2GB 上限 |
| worker | `runtime/media/restore_job.rs` | 流式解析、逐块重封装、meta 收尾、哈希比对 |
| worker | `runtime/media/source.rs` | meta/块引用读取（查看/导出/还原共用） |
| worker | `runtime/media/decoder.rs`、`animated.rs` | 字节解码/PNG 编码、按字节动图探测 |
| worker | `runtime/protocol.rs`、`dispatch.rs`、`media/mod.rs` | 请求字段、导出事件、路由 |
| worker | `runtime/path_grants.rs` | `photo_restore` 只读 job 授权 |
| 宿主 | `controller/photo_media_controller.rs` | `photo_export_start/cancel`、`photo_restore_start/cancel` |
| 宿主 | `controller/file_controller.rs` | 暂存写入函数内部可见化 |
| 前端 | `lib/verthys.ts`、`types/verthys.ts` | 命令封装与结果类型 |
| 前端 | `usePhotoExport.ts`、`usePhotoParse.ts`、`PhotoAlbum.vue` | 原生分支、回退与“原始文件”格式 |
| 前端 | `app/photo-flags.ts` | `nativeExport` 默认启用 |

## 5. 验证

证据见 [06-verification.md](06-verification.md) 的 G3 小节：worker/宿主/前端单测、真实 worker+DLL 导出还原 E2E、worker 产物→前端解析、前端产物→worker 还原。未覆盖项：

- GUI 导出/还原交互、进度渲染、取消按钮与锁库行为由用户手测。
- 导出吞吐未做磁盘上限对比；E2E 只验证字节正确性与事件流。
- 瘦身布局回退路径未在 E2E 中覆盖。
- worker 崩溃、磁盘满、容器容量耗尽的故障注入留待 Phase 5。
