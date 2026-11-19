# Phase 1 — 原生批量导入规格（执行版）

> 状态：实现完成 · 默认启用原生导入 · 最后更新：2026-11-19 · 维护人：K1Super
>
> 原生管线已落地并通过 worker + DLL 的 G1 数据面验证。按项目改造要求，旧导入链路属于待淘汰实现，`photo.nativeImport` 默认启用；旧前端流水线仅保留为回滚路径，待全部改造完成后删除。GUI 手测由用户在全部改造完成后执行。
>
> 用户已明确授权按最高工程标准自主推进至 Phase 1 完成；除产品取舍外不再逐步确认。
>
> 关联文档：[01-architecture.md](01-architecture.md)、[02-data-model.md](02-data-model.md)、[03-import.md](03-import.md)、[05-implementation.md](05-implementation.md)、[06-verification.md](06-verification.md)、[BOUNDARY-AUDIT.md](BOUNDARY-AUDIT.md)。

## 1. 目标与验收判据

目标：新增照片导入走 worker 原生管线，单张照片 1B–100MiB 全部可用；导入性能、恢复、取消、移动、容量与路径授权达到 G1 验收；存量数据与旧容器保持可读。

可判定完成的条件：

1. 生产照片存储分块为 4MiB，且由跨层预算单一权威来源生成。
2. 100MiB 照片接受，100MiB + 1 字节拒绝；17.73/24.43/50MiB 与混合批量通过真实 worker + DLL E2E。
3. 导入不经过 JS 逐块 Promise/base64 主线程往返；worker 负责读文件、解码、缩略图、分块、封装。
4. 取消、worker 崩溃、应用崩溃、源文件移动、容器容量不足均有明确恢复行为，且不删除源文件。
5. 路径授权为 job 级批量授权，1,000 张可用，10,000 张上限明确，过期/跨 job 复用拒绝。
6. 旧 1MiB 块照片可读取、导出、删除；VENC 容器格式版本不变，帧上限与存储分块同源。

## 2. 非目标

- 不改变容器格式、记录布局、`rollback.state` 布局。
- 不实现 Phase 2 预览后台生成、Phase 3 原生导出、Phase 4 网格。
- 不删除前端 JS 导入回退路径；通过功能开关切换。
- 不引入与 Phase 1 无关的 UI/样式改动。
- 不提交、不推送、不切换分支。

## 3. 权威决策

### D1 照片存储分块 = 4MiB

- 单一权威来源：`verthys-tauri/constants/photo_budget.schema.json` 新增 `photo_chunk_size = 4,194,304`。
- 生成物：前端 `PHOTO_CHUNK_SIZE_BYTES`，Rust `PB_PHOTO_CHUNK_SIZE_BYTES`。
- 生产照片加密路径与 VENC 容器帧上限使用 `PHOTO_CHUNK_SIZE`；`payload_chunk_size = 1MiB` 仅作为旧 1MiB 数据兼容与块集最坏情况上界的推导口径。
- C 层 `VTY_CHUNK_MAX_PT = 16MiB`，4MiB 在安全范围内。
- 读取侧不依赖固定块长，按 `PhotoMeta.chunkIds` 顺序解密；存量 1MiB 块继续可读。

### D2 边界规则

按 [BOUNDARY-AUDIT.md](BOUNDARY-AUDIT.md) 执行：只有产品上限可以拒绝用户输入；协议预算必须切批；安全限制只能拒绝越权/损坏/攻击；样本尺寸禁止进入生产判定。

### D3 G0-A 半完成键

- 在 `NCryptCreatePersistedKey` 与 `NCryptFinalizeKey` 之间增加仅测试构建的崩溃注入点。
- 创建路径必须先清理同槽残留键；崩溃后下一次提交必须成功，当前有效锚点不受影响。
- 不新增状态文件字段，不改变 `rollback.state` 布局。
- 若实测表明首次提交半键会导致不可恢复的 fail-closed，默认策略为：状态缺失且无有效锚点时允许重建；状态存在且指纹不符时仍然 fail-closed。该策略需由测试证据确认后落地。

### D4 Phase 1 数据面协议（宿主拉取式）

worker 新增 `runtime/media/`，主循环内同步处理以下 op：

- `photo_import_job_begin`：接收 `job_id`、`grant_id`、绝对路径列表、选项；校验 grant、路径成员、扩展名/MIME、文件可读与大小；建立 job 队列。
- `photo_import_job_next`：返回一个有界工作单元（块批次或文件完成事件），宿主拉取后写入；无工作时返回 `done`。
- `photo_import_job_finish`：回填块记录 ID、entryKey、记录名，worker 组装并封装 `PhotoMeta`，返回 meta 密文与元信息。
- `photo_import_job_skip`：单文件失败跳过，记录原因，不中止整批。
- `photo_import_job_cancel`：在块/文件边界停止，保留已提交块与 meta。
- `photo_import_job_end`：释放 job、清理 grant、返回统计。

宿主通过 `WriterCommand::AppendChunksRaw` / `AppendMetaRaw` 写记录；worker 不直接写容器。进度由宿主拉取节奏与 Tauri `Channel` 推送，不依赖 worker 主动事件。

### D5 路径授权

- 新增 job 级 grant：`job_id`、只读模式、最多 10,000 路径、TTL 10 分钟、绑定目标 op。
- worker 打开文件前做成员校验，不逐路径消费；同一文件可因重试重复打开。
- 路径必须为绝对路径；规范化后校验越界、符号链接与短路径逃逸。
- 超过 10,000 路径由宿主分批建 job；不把数量上限转化为单张照片限制。

### D6 数据模型

沿用现有 `PhotoMeta` 字段与记录命名：

- meta 记录 `meta_${fileName}`；块记录 `chunk_${chunk_key}`。
- 条目键 `sha256("file|" + name + "|" + size + "|" + mtime_ms)`；块键 `sha256("chunk|" + entryKey + "|" + seq)`。
- 块哈希为 `BLAKE3(密文块)`，写入 `chunkHashes`。
- 新导入块始终外置（`MAX_INLINE_META_BYTES = 0`），meta 只含引用与缩略图。
- 缩略图 Phase 1 内联 `thumbB64`；预览默认关闭。

### D7 功能开关与回滚

- `photo.nativeImport`：默认启用原生导入；关闭开关即回滚旧 JS 导入。旧链路属于待淘汰实现，全部改造完成后删除。
- `photo.chunkSize`：只读诊断值，取自生成常量，不允许运行时改小/改大。
- 回滚：关闭 `photo.nativeImport` 即恢复旧路径；已写入记录与旧路径兼容，无需数据迁移。

### D8 验收

- 功能：10/17.73/24.43/30/50/100MiB JPEG/PNG/WebP/GIF/APNG；100MiB 接受、100MiB+1 拒绝；混合批量；同文件重复导入；源文件移动；取消；worker 崩溃；应用崩溃；容量不足。
- 性能：矩阵实测，记录数与 IPC 轮次符合 4MiB 公式；批量吞吐接近磁盘顺序吞吐。
- 安全：路径授权越权/过期/跨 job 复用拒绝；SHM 认证与零化；日志无路径/凭据泄露。
- 兼容：旧 1MiB 块照片读取/导出/删除；旧 VENC 容器（1MiB 帧）导入；新导出按 4MiB 帧输出并被当前解析器接受。
- 门禁：预算生成器 `--check`、前端单测、Rust 单测、C 测试、真实 worker + DLL E2E、文档门禁全部通过。

## 4. 风险与对策

| 风险 | 对策 |
| --- | --- |
| 4MiB 块导致单批只能 1 块，IPC 轮次增加 | 原生导入由 worker 内部批量产出；前端回退路径保持 80% 水位，不追求满批 |
| 旧 1MiB 块与 4MiB 新块并存 | 读取按 meta 引用逐块解析；导出按存储块序列打包，容器帧上限 4MiB；旧 1MiB 帧容器继续可读 |
| 半完成 TPM 键导致提交失败 | 创建前清理同槽残留；崩溃注入测试验证下一次提交成功 |
| 批量 grant 放大越权面 | 绑定 job_id、只读、TTL 10 分钟、成员校验、结束即销毁、审计日志脱敏 |
| 原生解码器覆盖不足 | G0 已验证解码路径；Phase 1 先支持 JPEG/PNG/WebP/GIF/APNG，失败文件跳过并记录原因 |

## 5. 待产品决策（不阻塞工程默认执行）

- 100MiB 单文件上限是否覆盖真实最大照片；默认保持 100MiB，超过拒绝并提示。
- 首次提交半键崩溃若无法自动恢复，是否接受 fail-closed + 恢复码；默认先尝试自动重建，仅在指纹不符时 fail-closed。
