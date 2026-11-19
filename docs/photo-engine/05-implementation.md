# 05 — 实施计划、改动面与回滚

> 状态：评审中 · 最后更新：2026-11-19 · 维护人：K1Super
>
> 本文定义分阶段实施、文件级改动、删除清单、功能开关、回滚与风险登记。未过门禁不得进入下一阶段。

---

## 1. 阶段总览

| 阶段 | 目标 | 门禁 |
|---|---|---|
| G0 可行性 | 验证 C 线程安全/块长、worker 媒体线程、解码器覆盖、SHM、批量授权、长任务协议、基线测量 | G0 报告通过，方案不变更或已更新 |
| Phase 1 原生导入 | 新导入走原生管线（缩略图内联；预览在 Phase 2 随导入生成）；旧数据仍可读；导入性能达标 | **G0-A（C 批量提交/回退锚点摊销）通过** + G1 导入功能/性能/恢复/安全 |
| Phase 2 预览查看 | 导入时生成预览；查看预览优先、历史照片懒生成、原图按需、LRU | G2 查看功能/性能/安全 |
| Phase 3 原生导出 | 原始/`.venc`/PNG/备份还原原生流式 | G3 导出字节正确/性能/安全 |
| Phase 4 网格与收口 | 缩略图二进制（可选）、4MiB 全面兼容、旧 JS 桌面管线删除 | G4 全链路回归/性能 |
| Phase 5 加固 | 压测、崩溃注入、安全审计、文档收敛 | G5 发布级验收 |

## 2. G0 可行性验证

必须先回答，不能边写边猜：

1. `Verthys_V4ChunkSeal/Open` 是否 MT-Safe；最大 `plain_len`；4MiB 是否允许。
2. worker 现有单线程主循环中加入媒体 job 线程是否安全；C 句柄跨线程调用约束。
3. WIC 对 JPEG/PNG/BMP/GIF/APNG 的覆盖；worker 沙箱内 WIC/COM 可用性；WebP 是否需要兼容解码器；libjpeg-turbo 缩放解码收益。
4. 现有扫描 SHM 能否抽象为 media SHM；认证/`VirtualLock`/零化/销毁是否满足。
5. 批量路径 grant（10k 路径）与 job TTL 的可行性与安全评审。
6. 名称盲索引精确查 ID（`FindLidByName`）可行性与性能；预览 `preview_<metaId>` 定位。
7. 长任务 job 协议与现有 15s IPC 超时、锁定/退出闸门的兼容。
8. 基线：10/17.73/24.43/50MiB 照片在当前链路的读取、哈希、缩略图、加密、上传、flush、查看分段耗时；10MiB 只是样本。

G0 已执行结果（详见 `G0-REPORT.md`）：

- 4MiB 块允许；seal/open 约 800MB/s；16MiB 上限；同一句柄并发被 SRW 锁串行化。
- WIC 覆盖 JPEG/PNG/GIF/BMP/WebP；24MP 热解码约 34ms；worker 沙箱内 WIC 待补验。
- **每次 `AddRecords/Flush` 固定约 450ms；根因是 `vty_rollback_commit` 每次轮换 TPM 回退见证密钥。**
- G0-A 隔离原型：预置快路径提交约 15.7ms，首次同步 447ms；两槽在连续提交下会饥饿，导入必须批量提交。
- 原有“单一 10MiB 样本导入 ≤250ms”指标在现有 C 事务语义下不可达；Phase 1 前必须完成 G0-A 生产化验证。
- 名称盲索引存在，新增 `FindLidByName` 可行；SHM/批量 grant/长任务协议方向可行，待原型。

产出：`G0-REPORT`（数据、结论、风险、是否调整方案）。G0 不进入生产代码；原型代码隔离在测试/原型目录，验证后删除或转正。

## 3. Phase 1 — 原生批量导入

### 3.1 新增模块

**主进程（Rust）**

```text
src-tauri/src/media/
├── mod.rs                 媒体域入口
├── job.rs                 job 注册/生命周期/取消/进度
├── import.rs              导入编排（预检、会话、源文件删除）
├── shm.rs                 media SHM 桥
├── grants.rs              批量路径授权
└── tests/
src-tauri/src/controller/photo_media_controller.rs
```

**worker（Rust）**

```text
verthys-worker/src/runtime/media/
├── mod.rs
├── job.rs                  worker 侧 job 状态机/取消/进度
├── import_job.rs           读盘/哈希/分块/缩略图/预览
├── decoder.rs              原生解码/编码（WIC/libjpeg-turbo/兼容解码）
├── animated.rs             GIF/WebP/APNG 动图三态探测
├── shm.rs                  SHM 生产/消费
└── tests/
```

**协议与常量**

- `src-tauri/src/worker/protocol.rs`：新增 `photo_import_start/cancel`、`photo_job_progress/end`、`add_chunk_batch_raw`、`add_records_raw`。
- `src-tauri/src/state/import_writer.rs`：新增 `AppendChunksRaw`、`AppendMetaRaw`、`AppendDerivedRecord`；批量 128–512，且单批密文 ≤64MiB。
- `src-tauri/src/security` / worker `path_grants.rs`：批量 job grant。
- `src/constants/record_types.ts`、`src-tauri/src/constants.rs`：`TYPE_PHOTO_PREVIEW=0x0B`；Rust 块类型白名单。
- `core/include/verthys.h`、`verthys.def`、`core/src/index/vty_repo.c`：新增
  `Verthys_FindLidByName`（名称盲索引精确查 ID），供 `preview_<metaId>` 定位；
  若 G0 否决该 API，改用 `ListIdsByType` + 索引投影会话映射。
- `verthys-worker/src/runtime/module_keys.rs`：新增 `preview` 种类码 9、`kind_code`/`open_inner`；新增 raw-buffer seal/open 入口（复用同一 `photo_file_uuid`/`tag_content`/C 调用，不经 base64）；`module_crypto_controller.rs` 的 `CRYPT_KINDS` 同步。禁止绕过既有封装。
- `src-tauri/Cargo.toml`、`verthys-worker/Cargo.toml`：解码依赖（经 G0/许可证评审后确定）。
- `THIRD_PARTY.md`：新增依赖许可证与来源。

### 3.2 前端

- `src/composables/photo-album/usePhotoImport.ts` 改为：
  - 选路径 → `photo_import_start`；
  - 订阅进度事件；
  - 取消/错误/完成状态机；
  - 不再引用 `ImportPipeline`、`photoWorkerPool`、`readUserFile` 照片字节。
- 新增 `src/composables/photo-album/usePhotoMedia.ts`（Tauri 命令/事件封装）或等价模块。
- `src/composables/photo-album/importPipeline.ts`、`chunkUploadCoordinator.ts`、`photo-crypto.worker.ts`、`container-import.worker.ts` 在桌面路径停用；浏览器回退逻辑单独保留。
- `PhotoAlbum.vue` 进度 UI 复用现有组件；导入文案/取消入口按 job 状态更新。

### 3.3 兼容补丁（在 Phase 1 前完成）

- 审计所有固定 1MiB 假设；至少更新 `container-import.worker.ts` 的单块长度校验，使旧桌面路径可读取 4MiB 块。
- 旧 JS 查看/导出路径确认不依赖固定块长；补测试。
- `PhotoMeta.chunkSize` 读取侧仅作诊断，不参与强校验。
- 审计类型迁移/记录枚举/删除级联：`TYPE_PHOTO_PREVIEW` 对旧路径必须是可忽略的未知类型，不得导致列表/删除/导出失败；新路径删除照片时级联预览。
- 预览记录名 `preview_<metaId>` 与 ID 复用场景补测试：预览头 `{metaId, fileHash}` 不匹配时重生成。

### 3.4 G1 验收

- 10/30/50MB JPEG、PNG、WebP、GIF/APNG 导入成功。
- 新旧读取路径均可查看/导出新导入照片。
- 取消、崩溃、重启续传、去重跳过、移动语义、容量不足场景通过。
- 导入性能达到目标；主线程无长任务。
- 路径授权、SHM、日志无泄露。
- 现有全量测试 + 新增 Rust/前端测试通过。

### 3.5 Phase 1 实施结果（与本章计划的差异）

以仓库当前代码为准，Phase 1 的落地方式与 3.1–3.3 的计划存在以下差异；差异均为已评估的工程取舍，不改变容器格式、记录布局与 `rollback.state`：

| 计划项 | 实际落点 | 说明 |
|---|---|---|
| 主进程 `media/` + 媒体 SHM | `controller/photo_media_controller.rs` 直接拉取 worker job | Phase 1 不引入媒体 SHM；宿主单 job 串行，按块拉取密文后经现有单写者通道落库 |
| `AppendChunksRaw` / `AppendMetaRaw` | 复用 `WriterCommand::AppendChunks` / `AppendPending` | 块键台账、会话幂等、WAL、外置引用校验全部复用，避免第二套写入协议 |
| WIC / COM 解码 | worker `image` 0.25（jpeg/png/gif/webp） | 纯 Rust 解码，无 COM 依赖；缩略图 JPEG 编码前统一转 RGB8（GIF 等 RGBA8 输入） |
| 批量 grant | `path_grants::authorize_job` | ≤10,000 路径、只读、600s TTL、job_id 绑定、成员校验；宿主每 300s 用剩余路径滚动续期 |
| 预览记录 | 未实现（Phase 2） | Phase 1 缩略图内联 meta；`photo_preview_*` 与预览记录不在本阶段 |
| 前端开关 | `photo.nativeImport`，默认 `true` | Phase 1 默认走原生导入；该开关已在 Phase 4 删除，桌面仅保留原生链路 |
| 4MiB 分块 | `photo_chunk_size = 4,194,304` 单一权威 | 生产加密路径、VENC 帧上限与 E2E 同源；存量 1MiB 块与旧容器继续可读 |

Phase 1 新增的宿主命令：

- `photo_import_start(paths, onProgress)`：建立导入会话 → 批量授权 → worker job 拉取 → 块写入 → meta 收尾 → 结束会话；成功且零失败后 best-effort 触发孤儿块 GC。
- `photo_import_cancel()`：本地取消标志为权威信号，worker 侧取消尽力而为；已提交 meta 保留，会话以 `success=false` 结束。

## 4. Phase 2 — 预览查看

### 4.1 新增/修改

- worker `media/read_job.rs`：预览记录读取/解密/懒生成；原图分片/范围读取。
- `photo_media_controller.rs`：`photo_preview_get`、`photo_full_get`、`photo_preview_cancel`。
- `usePhotoViewer.ts`：
  - 打开即显示缩略图占位；
  - 请求预览 → Blob → 交叉淡入；
  - 放大/动画/导出时请求原图；
  - 前端 Blob URL LRU（按字节/最近项）。
- `PhotoAlbum.vue`：预览加载层/占位样式；不新增冗余说明文案。
- 大图自定义协议（可选在 Phase 2 后段）：
  - `verthys-photo://` 注册、token、Range、CSP；
  - 协议 handler 通过 SHM 向 worker 取范围。
- 旧照片懒预览：`preview_<entryKey>`（无 entryKey 用 `preview_<metaId>`）缺失时生成并落库。

### 4.2 G2 验收

- 预览 P95 ≤120ms；重复打开 ≤50ms；旧照片首次懒生成后二次秒开。
- 原图 10MiB 样本 P95 ≤350ms；17.73/24.43/50MiB 等大图走 Range 流式首段可交互。
- 快速切换照片取消过期 job；锁/登出释放缓存。
- 动图播放/APNG 不受影响。
- 自定义协议（若启用）token/IDOR/Range 测试通过。

### 4.3 Phase 2 实施结果（与本章计划的差异）

| 计划项 | 实际落点 | 说明 |
|---|---|---|
| worker `media/read_job.rs` | 已实现 | `photo_read_job_begin/next/cancel/end`；预览一次性返回，原图 job 逐块产出；并发上限 4、空闲 120s 回收 |
| `photo_preview_get` / `photo_full_get` / `photo_preview_cancel` | `photo_preview_get` / `photo_full_begin` / `photo_full_next` / `photo_full_cancel` | 原图拆为 begin/next/cancel，前端按块拼 Blob |
| 预览写回 | 导入同批次 + 懒生成 `AppendDerived` | 派生写入按名称幂等；写回失败只告警 |
| 删除级联 | `photo_preview_ids` | 删除事务前解析预览 ID 并入同一批；解析失败只告警 |
| `usePhotoViewer.ts` | 预览优先 + 原图按需 | 缩略图占位 → 预览替换 → 动图/≤32MiB 自动原图；>32MiB 等放大；关闭/切换取消 |
| Blob LRU | `photoBlobCache.ts` | 64MB / 5 项；`preview:<metaId>` / `full:<metaId>`；锁定、登出、删除、卸载释放 |
| `PhotoAlbum.vue` 预览加载层 | 复用现有查看器状态 | 不新增样式或文案 |
| 自定义协议 | 不实现 | Phase 4 评估后维持 4MiB 分块 IPC；100MiB 读取已由 E2E 覆盖 |
| 瘦身布局原生读取 | Phase 4 已实现 | `meta`/`slim_meta`、`chunkSetId`、`chunk`/`slim_chunk`、独立 `thumb`；不再回退 JS |
| 功能开关 | `photo.nativePreview`，默认 `true` | Phase 2 默认原生；该开关已在 Phase 4 删除，桌面无 JS 查看回退 |

## 5. Phase 3 — 原生导出与备份还原

### 5.1 新增/修改

- worker `media/export_job.rs`：原始/`.venc`/PNG 导出；流式解密/打包/编码。
- worker `media/venc.rs`：原生 VENC 打包/解析；令牌 KDF；帧校验。
- `photo_media_controller.rs`：`photo_export_start/cancel`、`photo_restore_start/cancel`。
- `usePhotoExport.ts` / `usePhotoParse.ts`：改为命令/进度；删除 JS `packVenc`/逐块解密/Canvas 转码。
- `file_controller.rs` 的原子写协议复用；导出目标批量 grant。
- 动图 PNG 跳过与提示沿用。

### 5.2 G3 验收

- 原始/`.venc`/PNG 导出字节正确；BLAKE3/容器校验通过；失败无半截文件。
- 旧/新 `.venc` 还原成功；4MiB 块往返一致。
- 导出吞吐接近磁盘写入上限；取消/失败/重试正确。
- 导出路径授权、日志、临时文件清理通过。

### 5.3 Phase 3 实施结果（与本章计划的差异）

| 计划项 | 实际落点 | 说明 |
|---|---|---|
| worker `media/export_job.rs` | 已实现 | `photo_export_job_begin/next/cancel/end`；original / venc-single / venc-multiple / png |
| worker `media/venc.rs` | 已实现 | 外层头/包裹密钥/帧/尾部逐字节复刻；清单 7 字段严格校验；2GB/64MiB/100000 上限 |
| 导出写盘 | 宿主暂存 + 原子替换 | worker 不打开用户目标文件；复用 `stream_create/append/finalize/abort` |
| 导出目标批量 grant | 未启用 | 宿主写盘，不需要向 worker 授权；目标路径仍走字符校验、canonicalize 与系统目录拒绝 |
| `photo_media_controller.rs` | `photo_export_start/cancel`、`photo_restore_start/cancel` | 导入/导出/还原共享单任务槽位 |
| 还原链路 | 已实现 | worker 流式解析 + `seal_photo_chunk` 重封装；宿主 `AppendChunks` + `AppendPending` |
| 还原去重 | 已实现 | `sha256("parsed|"+fileHash)`；worker 侧跳过只校验不落库 |
| 预览哈希比对 | 已实现 | 开始还原携带预览 fileHash；清单不一致立即失败 |
| 动图 PNG | 已实现 | `animated-unsupported`；历史记录按解密字节补判 |
| 前端开关 | `photo.nativeExport`，默认 `true` | Phase 3 默认原生；该开关已在 Phase 4 删除，桌面无 JS 导出/还原回退 |
| 原始文件导出 | 新增“原始文件”格式 | 仅原生链路可用；明文导出，不要求令牌 |
| 瘦身布局 | Phase 3 整批拒绝；Phase 4 原生覆盖 | 原生读取块集记录与 `slim_chunk` 标签，不再返回 `E_PHOTO_LAYOUT_UNSUPPORTED` |

## 6. Phase 4 — 网格、4MiB 收口与删除

- 缩略图/meta 二进制批量下发（可选）：`thumb_<metaId>` + `photo_thumbs_get`/`photo_meta_get`，旧内联 fallback。
- 4MiB 块全链路审计：导入、查看、导出、VENC、备份还原、旧路径兼容。
- 删除桌面端旧照片数据面：
  - `importPipeline.ts` 加密/分块/上传逻辑；
  - `photo-crypto.worker.ts` 照片加解密；
  - `container-import.worker.ts` 重加密；
  - `photoWorkerPool.ts` 照片加密任务；
  - `photo-decrypt-bridge.ts` / `chunk-refs.ts` 的逐块 RPC 读取；
  - `module_crypto.ts` 照片逐记录 RPC；
  - JS VENC 打包/解析、Canvas PNG 转码。
- 保留浏览器开发模式回退，不与桌面路径混用。

### 6.1 Phase 4 实施结果（与本章计划的差异）

| 计划项 | 实际落点 | 说明 |
|---|---|---|
| 缩略图/meta 二进制批量下发 | `photo_meta_get` | 不做 `thumb_<metaId>` 拆分；worker 直接解密既有 meta 或瘦身 `thumb` 记录，返回展示字段 + base64 缩略图；宿主 32 条/批 |
| 损坏扫描 | `photo_meta_probe` | Auth 且非历史明文 JSON 才判损坏；锁定/读取失败计入 inconclusive |
| 瘦身布局 | 原生覆盖 | `meta`/`slim_meta` 双标签、`chunkSetId` → 块集记录、`chunk`/`slim_chunk` 双标签、独立 `thumb` 记录 |
| 删除桌面旧数据面 | 已删除 | `importPipeline`、`chunkUploadCoordinator`、`chunk-refs`、`damage`、`photo-crypto.worker`、`photo-crypto-protocol`、`photoWorkerPool`、`photo-decrypt-bridge`、`container-import.worker`、`photo-flags` |
| 浏览器回退 | 保留 | 内存导入、`parse-crypto.worker`、`lib/crypto.ts` VENC、Canvas PNG；不与桌面路径混用 |
| 功能开关 | 已删除 | 桌面不再支持运行时回退，回滚单位改为安装包 |
| 1k 张压测 | 未执行 | 已有 100MiB 单张导入/读取与多文件导出 E2E；1k 张留给 GUI/后续压测 |

### G4 验收（实测）

- Worker 107、宿主 586、前端 82 文件/831 用例、`vue-tsc` 全绿。
- 静态检查：桌面 `src` 无旧照片数据面符号引用。
- 导入/读取/导出/还原真实 worker+DLL E2E 通过（见 `06-verification.md` §5.4）。
- 1k 批量导入、100 张快速查看压测未执行，标注未验证。

## 7. Phase 5 — 加固与发布

### 7.1 Phase 5 实施结果

| 计划项 | 实际落点 | 结论 |
|---|---|---|
| 性能压测与基线 | 复用 Phase 1–3 E2E 数据；未做 1k/P95 | 未完成项如实标注 |
| 崩溃注入 / worker kill / 磁盘满 | 无自动化注入；提供人工步骤 | 未验证 |
| 源文件变化 | 导入 E2E 覆盖移动/超限；大小/mtime 校验沿用 Phase 1 | 已验证 |
| SHM 篡改 | 照片数据面未使用 SHM | 不适用 |
| 路径越权 | `path_grants` 单测；restore/parse 作业授权 | 已验证（单测） |
| 依赖审计 | `cargo metadata` + `cargo tree -d`；`THIRD_PARTY.md` §3.1 | 已验证 |
| 文档收敛 | `ARCHITECTURE` §8、`DATA_FLOW` §7、`SECURITY_DESIGN` §10、`CORE_API` 备注 | 已验证 |
| 发布回滚演练 | 数据向前兼容论证 + 代码审查；未安装旧版本实机 | 部分验证 |

详细证据与未验证项见 `PHASE4-5-REPORT.md`。

## 8. 回滚边界

Phase 4 起桌面端不再提供运行时旧链路开关，`photo.nativeImport` /
`photo.nativePreview` / `photo.nativeExport` 已删除。回滚要求：

- 回滚单位为上一版本安装包；回滚前先确认该版本可读取 4MiB 块与预览记录。
- 新数据仍写入标准 `TYPE_PHOTO_META` 与 `TYPE_PHOTO_CHUNK`；旧版本按
  `chunkIds` 数量读取，不依赖固定块长。
- `TYPE_PHOTO_PREVIEW=0x0B` 对旧版本是未知类型；旧版本列表/删除/导出按
  `TYPE_PHOTO_META` 枚举，不遍历预览类型。
- 回滚不清除已写入数据；预览可保留或按需重新生成。
- 浏览器开发模式保留独立 JS 回退，不与桌面路径混用。

## 9. 风险登记

| 风险 | 影响 | 缓解 |
|---|---|---|
| C 块接口非线程安全 | 并发崩溃/数据损坏 | G0 验证；必要时 FFI 串行；媒体线程只做 I/O/解码 |
| WIC 不覆盖 WebP/GIF/APNG | 缩略图/预览失败 | 兼容解码器 fallback；G0 覆盖矩阵 |
| worker 沙箱限制 WIC/COM/解码器 | 解码不可用 | G0 验证；优先纯 Rust 解码器；未经安全评审不把解码迁到主进程 |
| 4MiB 块旧路径不兼容 | 回滚后无法查看/还原 | Phase 1 前修兼容；开关回退 1MiB |
| worker 主循环被长任务阻塞 | 控制/取消/锁延迟 | 媒体 job 线程 + 有界 channel；主循环只做控制 |
| SHM 泄露/篡改 | 明文泄露/越权 | 认证、VirtualLock、job 级销毁、零化、安全测试 |
| 批量 grant 权限过大 | 越权读写/删除 | 作业级 grant、路径集合、TTL、操作/模式绑定、一次性激活 + 成员校验、审计 |
| WAL/台账与原生任务不一致 | 数据丢失/重复 | 复用单写者/WAL/台账；G1 崩溃/续传测试 |
| TPM 回退见证每次保存约 450ms | 单张导入无法达标 | G0-A 首选预置见证密钥（把 377ms 建键移出关键路径）+ 批量提交；备选延迟锚点；安全评审与崩溃/断电测试 |
| 预览占存储 | 约 0.5–4% 额外空间（按原图大小） | 用户可关；按需生成；LRU/清理策略 |
| 旧照片无预览 | 首次仍慢 | 懒生成；之后秒开；不重写 meta |
| 依赖体积/许可证 | 构建/合规 | G0 评估；优先系统 WIC；必要时最小解码依赖 |
| 长任务超时/锁冲突 | job 失败/数据不一致 | job 心跳 + 取消 + session epoch；不压缩 WAL |

## 10. Definition of Done（总）

1. 桌面端照片导入/查看/导出/备份还原不再经过 JS 字节面。
2. 性能、功能、安全、恢复、兼容全部过 G1–G5。
3. 旧 1MiB/旧布局/旧 `.venc` 可读；新 4MiB/预览记录可用。
4. 单写者、WAL、台账、GC、锁/退出语义保持。
5. 文档、测试、基准、回滚演练完成。
6. 代码审查（含安全）通过，无未闭环 P0/P1 缺陷。
