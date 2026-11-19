# Phase 4–5 收口与加固报告

> 状态：已执行 · 最后更新：2026-11-19 · 维护人：K1Super
>
> 覆盖 Phase 4（网格、4MiB 收口、删除桌面 JS 数据面）与 Phase 5（故障/安全、依赖、文档、回滚）。
> 结论按「已验证 / 未验证」分级；未执行项不写成通过。

---

## 1. 结论

- 桌面端照片数据面已完全下沉 Rust/C：网格元数据、缩略图、预览、原图、导出、
  备份预览与还原均由 `photo_*` 命令完成；桌面 JS 解密/打包/VENC 解析链路已删除。
- 索引瘦身布局（`fmt==2` / `wrappedFileKey`）由原生读取覆盖：`meta`/`slim_meta`
  双标签、`chunkSetId` 块集记录、独立 `thumb` 记录、`chunk`/`slim_chunk` 双标签。
- 浏览器开发模式保留独立回退：内存导入、`parse-crypto.worker` VENC 预览、
  `lib/crypto.ts` VENC 打包/解析、Canvas PNG。
- 4MiB 已作为唯一照片写入口径；旧 1MiB 块与旧容器仍可读。
- 未验证项：GUI 手测、worker 进程被强杀、磁盘满、1k 张批量导入压测、P95 指标。

---

## 2. 改动摘要

### 2.1 Worker

- `media/source.rs`：`PhotoMetaIn` 增加 `thumb_id` / `chunk_set_id` / `chunk_count`；
  `read_meta` 双标签；`resolve_chunk_refs`；`load_thumb_b64`。
- `module_keys.rs`：`open_photo_chunk_any`（`chunk` → `slim_chunk`）。
- 新增 `media/meta_job.rs`：`photo_meta_get`（≤64/批）、`photo_meta_probe`
  （≤4096，Auth 且非历史明文 JSON 才判损坏）。
- `read_job.rs` / `export_job.rs`：接入块集解析，删除瘦身布局拒绝。
- `restore_job.rs`：新增 `photo_venc_inspect`（流式清单预览、尾部校验）。
- `protocol.rs`：`MediaMetaItem`、`MediaDamageScan`、`MediaVencPreview` 与响应字段。

### 2.2 宿主

- 新增 `photo_meta_get`（32 条/批，30s）、`photo_meta_probe`（512 条/批，120s）、
  `photo_parse_start`（路径授权 `photo_parse`，600s）。
- `lib.rs` 注册三个命令。

### 2.3 前端

- `usePhotoData`：`decryptPhotoMeta` 改 `photoMetaGet`；损坏扫描改 `photoMetaProbe`。
- `usePhotoViewer`：删除 JS 解密回退，桌面仅原生预览/原图。
- `usePhotoImport`：桌面仅 `photoImportStart`；删除 `ImportPipeline` 与开关。
- `usePhotoParse`：桌面 `photoParseStart` + `photoRestoreStart`；浏览器保留 Worker。
- `usePhotoExport`：桌面仅 `photoExportStart`；浏览器保留 VENC/PNG 下载。
- `PhotoAlbum.vue`：删除 `getPipeline` 传递。

### 2.4 删除

`importPipeline.ts`、`chunkUploadCoordinator.ts`、`chunk-refs.ts`、`damage.ts`、
`photo-crypto.worker.ts`、`photo-crypto-protocol.ts`、`photoWorkerPool.ts`、
`photo-decrypt-bridge.ts`、`container-import.worker.ts`、`app/photo-flags.ts`
及对应 spec。

---

## 3. 验证证据

| 项 | 命令 | 结果 | 结论 |
|---|---|---|---|
| Worker 单测 | `cargo test`（verthys-worker） | 107 passed / 0 failed | 已验证 |
| Worker 构建 | `cargo build` | 成功，无警告 | 已验证 |
| 宿主单测 | `cargo test --lib`（src-tauri） | 584 passed / 2 ignored | 已验证 |
| 前端类型 | `npx vue-tsc --noEmit` | PASS | 已验证 |
| 前端测试 | `npx vitest run` | 82 文件 / 832 用例 passed | 已验证 |
| 文档门禁 | `ci/check_docs.ps1` | 50 文件 / 197 链接 PASS | 已验证 |
| 导出/还原 E2E | `worker_native_export_restore_e2e` | original 10,485,760B；PNG 11,522,543B；venc-single 29,136,046B 还原 2 张；2 个独立容器；取消/替换/错误令牌通过；264.66s | 已验证 |
| 读取 E2E | `worker_native_read_e2e` | 10MiB 预览 572,861B、原图 3 块 10,485,760B；100MiB 预览命中、原图 25 块 104,857,600B；懒生成/取消通过；瘦身布局 `photo_meta_get` 通过；244.49s | 已验证 |
| 导入 E2E | `worker_native_import_e2e` | 15 文件 / 214 块 / 883,068,764B，1,282,183ms；混合 3 文件、超限、移动、取消通过 | 已验证 |
| 静态删除检查 | `rg` 旧符号 | 桌面 `src` 零引用 | 已验证 |

### 3.1 导入 E2E

完整执行通过：10/17.73/24.43/30/50/100MiB JPEG、100MiB PNG/WebP/GIF/APNG，
混合批量 3 文件，超限 `over_100.jpg` 跳过、移动源文件失败、50MiB 取消；
共 15 文件 / 214 块 / 883,068,764 字节，耗时 1,282,183ms。

---

## 4. 4MiB 全链路审计

| 链路 | 证据 | 结果 |
|---|---|---|
| 原生导入 | `PB_PHOTO_CHUNK_SIZE_BYTES = 4_194_304`（`photo_budget.rs`） | 4MiB |
| 原生读取 | `read_job` 按 `meta.chunk_total` 逐块，无固定块长 | 通过 |
| 预览 | `generate_preview` 逐块累加，上限 `PB_PHOTO_MAX_BYTES` | 通过 |
| 原始导出 | `SEGMENT_BYTES = PB_PHOTO_CHUNK_SIZE_BYTES` | 4MiB 段 |
| VENC | 帧上限 64MiB（`PARSE_MAX_FRAME_BYTES`），不按 1MiB 切帧 | 通过 |
| 还原 | 单块 ≤4MiB，`chunkCount` 交叉校验 | 通过 |
| 旧容器 | `crypto-venc.spec` 覆盖 1MiB 旧帧与 4MiB 新帧同容器解析 | 已验证 |
| 旧数据 | 读取按 `chunkIds` 数量，不依赖 `chunkSize` | 代码审查 + E2E |

---

## 5. Phase 5 故障与安全

| 场景 | 覆盖 | 结果 |
|---|---|---|
| 错误令牌 | worker `venc::wrong_token_fails_authentication`；导出 E2E | 已验证 |
| 截断/尾随字节 | `venc::truncated_and_trailing_bytes_are_rejected` | 已验证 |
| 帧篡改 | `venc::tampering_any_frame_byte_fails_authentication` | 已验证 |
| 尾部计数不符 | `venc::trailer_counts_mismatch_is_rejected` | 已验证 |
| 帧序不连续 | `venc::sequential_frame_sequence_is_enforced` | 已验证 |
| 容器超限 | `venc::oversized_container_is_rejected_before_parsing` | 已验证 |
| 块集项数不符 | `source::resolve_chunk_refs` 校验 + 单测 | 已验证（逻辑）/未覆盖真实坏数据 |
| 种类错配 | `module_keys::content_tag_binds_kind_and_strips_cleanly`；`open_photo_chunk_any` 双标签 | 已验证 |
| 路径未授权 | `path_grants` 单测；restore 路径校验 | 已验证（单测） |
| 预览后替换容器 | 导出/还原 E2E | 已验证 |
| worker 强杀 | 无自动化注入 | 未验证 |
| 磁盘满 | 无自动化注入 | 未验证 |
| SHM 篡改 | 照片数据面未使用 SHM（仅扫描） | 不适用 |

未验证项的人工步骤：

1. worker 强杀：导入/导出进行中在任务管理器结束 `verthys-worker.exe`，预期宿主
   返回会话失败、已提交块保留、重启后 WAL 可续传；不得留下半截目标文件。
2. 磁盘满：将导出目标置于小容量卷并填满，预期 `storage-full`/`write-failed`，
   暂存文件被 abort，原文件不受影响。

---

## 6. 文档门禁

执行 `powershell -ExecutionPolicy Bypass -File ci\check_docs.ps1`：PASS（50 文件 /
197 链接）。本报告已登记到 `docs/README.md` 与 `docs/photo-engine/README.md`。

---

## 7. 回滚演练

- 运行时开关已删除；回滚单位为上一版本安装包。
- 数据向前兼容：新记录仍是 `TYPE_PHOTO_META` + `TYPE_PHOTO_CHUNK`（4MiB），
  旧版本按 `chunkIds` 顺序读取；`TYPE_PHOTO_PREVIEW=0x0B` 对旧版本是未知类型，
  列表/删除/导出均按 `TYPE_PHOTO_META` 枚举，不遍历预览类型。
- 本次未安装旧版本实机验证，回滚演练结论为「设计兼容 + 代码审查」，
  实机回滚标注未验证。

---

## 8. 依赖与供应链

- 新增 worker 依赖的许可证与用途已写入 `docs/THIRD_PARTY.md` §3.1。
- 关键结论：无 Git 依赖；`image` 仅启用 jpeg/png/gif/webp；`cargo tree -d`
  仅见 feature 合并与 `miniz_oxide` 0.8/0.9 双版本。
- 调试 worker 体积约 6.7MB；发布体积以构建脚本产物为准。

---

## 9. 全链路审查治理（2026-11-19）

发布前对 C 核心、worker、宿主与前端做了独立审查，修复以下缺陷并补测试：

| 级别 | 缺陷 | 修复 |
|---|---|---|
| P1 | 桌面「开始解析」按钮依赖 `parseFileData`，而 Tauri 路径只保留路径，按钮永久禁用 | `PhotoAlbum.vue` 改为按 `isTauri ? parseFilePath : parseFileData` 判定 |
| P1 | 锁库不清照片任务与导入会话，解锁后 `E_IMPORT_SESSION_BUSY`，删除级联可能误用旧台账 | 锁库时置取消标志并丢弃会话；照片导入/还原遇跨容器残留会话时丢弃重试 |
| P1 | 原图加载共享 `viewerFullJobId`，旧请求误取消新任务并清空加载态 | 改为局部 jobId，catch/finally 只清理本次请求 |
| P2 | Blob LRU 写入超大原图后立即自我淘汰并 revoke，查看器破图 | `evict` 保护本次写入键；单条超大条目为软上限 |
| P2 | 浏览器还原只写 `rawBytes`，查看器只认 `blobUrl` | 还原时创建并登记 `blobUrl` |
| P2 | venc-single 取消/会话错误仍累计 `exported`，目标文件不存在却显示已导出 | 未 finalize 时 exported=0，已通过照片转 `write-failed` |
| P3 | 导入/还原取消或失败不回收孤儿块 | 收尾后始终 best-effort GC |
| 高 | 还原接受尾部帧后的尾随字节 | 尾部校验后要求 `next_frame()==None` |
| 高 | 备份预览 64MiB 预算超过 24MiB 响应行上限 | 缩略图预算降至 16MiB，超出降级为空缩略图 |
| 高 | 导入 job 无 TTL，异常宿主可永久占槽 | 600s 空闲回收 |
| 高 | GIF 动图探测无解码限额 | `image::Limits` 限制尺寸/分配 |
| 中 | 缩略图记录损坏导致整条照片元数据失败 | 缩略图失败降级为空，元数据仍返回 |
| 中 | 末块哈希失败后 read job 仍返回 done | job 毒化，后续 `next` 返回错误 |
| 中 | venc-single 打包中途失败仍继续追加帧 | job 毒化并终止 |
| 中 | 块数无硬上限 | 单张 100,000 块硬限 |
| 中 | 响应 scrub 未覆盖 photo/photo_finish；种类标签剥离后尾部残留明文 | 补 scrub 与尾部清零 |
| 中 | 路径授权未绑定操作，导入授权可跨用于还原/预览 | grant 存 `target_op`，`job_contains_for` 校验 |
| 高 | witness pool 目标槽失效时自旋，Deinit 永久阻塞 | 复位条目为 FREE 并每轮检查 stop 事件 |
| 高 | TPM 建键失败路径泄漏 NCRYPT 句柄 | 失败/成功均 `NCryptFreeObject` |
| 严重 | FindLidByName 遇模块锁定中止并返回未声明错误码 | 跳过 `E_POLICY` 继续查询其余模块 |
| 阻断 | C ABI 测试仍断言 0x0014 | 同步为 0x0015 |
| 测试 | E2E 每次创建容器都消耗真实 `rollback.state` 槽位，最终占满 | E2E 使用临时 `VERTHYS_TEST_STATE_DIR` 隔离 |

审查后回归：worker 107、宿主 584 passed / 2 ignored、前端 832、C ABI 与
FindLidByName、G0A 池关闭/并发用例通过；读取 E2E 244.49s、导出/还原 E2E
264.66s，字节与块数不变。

## 10. 未覆盖 / 风险

- GUI 手测（首屏、快速切换、锁库、动图、删除残留、1k 张网格）留给用户。
- 预览/原图 P95 未实测；E2E 只证明字节、块数与路径正确。
- 1k 张批量导入、100 张快速查看、批量导出压测未执行；已有单张/百 MB 证据。
- worker 强杀、磁盘满未自动注入。
- `src-tauri/verthys.dll` 与 `src-tauri/binaries/verthys-worker-*.exe` 仍是旧版，
  最终打包前必须重建并拷贝。
