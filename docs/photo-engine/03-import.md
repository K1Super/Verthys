# 03 — 原生批量导入

> 状态：评审中 · 最后更新：2026-11-19 · 维护人：K1Super
>
> 实施说明：Phase 1 实际命令为 `photo_import_start(paths, onProgress)`，不含本文设计稿中的 `mode` / `skipCommitted` / `previewMode` 参数；本阶段不删除或移动源文件，缩略图内联 meta，重复项由写者按 `entry_key` 幂等跳过。接口与数据布局以 `05-implementation.md` 3.5 和 `src-tauri/src/controller/photo_media_controller.rs` 为准。
>
> 本文定义照片批量导入的原生任务、并发/背压、会话与台账、缩略图/预览、取消/崩溃恢复与移动语义。

---

## 1. 目标

- 批量导入的耗时由磁盘吞吐与加密吞吐决定，不再由 JS/Worker/base64/逐块 Promise 决定。
- 单张导入目标按尺寸矩阵验收：10MiB、17.73MiB、24.43MiB、50MiB 与 100MiB
  边界；10MiB 只是样本，不是产品上限。
- 100 张混合尺寸批量接近磁盘顺序吞吐。
- 导入期间主线程无 >50ms 长任务；进度平滑。
- 失败不丢数据、不删源文件、可续传。

## 2. 入口与参数

前端只发一个命令：

```text
photo_import_start(
  paths: string[],          // 用户通过文件/文件夹对话框选择的本地路径
  mode: "copy" | "move",    // move: 成功后删除源文件
  options: {
    skipCommitted: boolean   // 默认 true，沿用 entry_key 续传
    previewMode: "background" | "inline" | "off" // 默认 background
  }
) -> { job_id }
```

约束：

- 仅 Windows 桌面端；浏览器模式继续走旧 JS 管线，不属于本方案性能验收。
- 路径必须是绝对路径；主进程签发**批量作业级 grant**，worker 只消费该 grant。
- 不接收目录递归展开结果以外的隐式路径；目录由前端/主进程先展开并去重。

## 3. 批量路径授权

现有 `path_grants` 是单路径、TTL 30s、最多 32 条，无法承载批量导入。扩展为：

```text
authorize_job(target_op, mode, paths[]) -> grant_id
consume_job(target_op, mode, grant_id, path) -> bool
```

- `target_op`：`photo_import`（read）、`photo_move`（write/delete）、`photo_export`（write）、`photo_restore`（read）。
- 一个 grant 绑定作业与规范化路径集合；TTL 与 job 生命周期绑定（默认 30 分钟，可续期）。
- 单 grant 路径上限 10,000；超过则分批 job；路径列表超过控制行预算时经 SHM 传输。
- 路径规范化、拒绝 NUL/设备命名空间/全局根前缀、拒绝系统关键目录，沿用现有规则。
- grant 只存在内存，不落盘、不日志；job 结束/取消/超时即销毁。
- 授权在 job 启动时一次性激活并绑定 job_id；worker 每次打开文件前只做**成员校验**，不逐路径消费，允许同一文件在重试/重读时再次打开；未授权立即失败关闭。

## 4. Job 生命周期

```text
photo_import_start
  → 主进程：会话/密钥检查 → 批量 grant → 展开路径 → 预检 → import_begin
  → worker：photo_import_job(job_id, grant_id, paths, options)
      → 逐文件：stat → 读 → 哈希 → 分块 seal → 缩略图/预览 → SHM 投递
      → 主进程：AppendChunksRaw → 块记录 ID → 台账/WAL → AppendMeta → 预览记录
  → import_end(success) → 台账落盘 → GC → move 删除源文件
```

### 4.1 预检

- `stat` 每个文件：存在、常规文件、大小、mtime。
- 拒绝：空文件、超过 `MAX_PHOTO_BYTES`（当前 100MB）、不支持的扩展名/MIME。
- 按 `entry_key = SHA-256("file" | name | size | mtime)` 查询已提交集合，命中即跳过（续传幂等）。
- 统计总文件数、总字节、跳过数、拒绝数；空集直接返回。
- 可选：检查目标容器剩余空间；不足时提前拒绝，不进入加密。

### 4.2 单文件流水

worker 内顺序执行：

1. `stat` 基线 `(size, mtime)`。
2. 以 4MiB 缓冲流式读取；每块：
   - 增量 BLAKE3 更新整文件哈希；
   - `Verthys_V4ChunkSeal(handle, module, file_uuid, seq, total, plain, len, out, cap, out_len)`；
   - 密文写入 job SHM 的 chunk 区，附带 `seq/total/entry_key/file_hash`。
3. 主进程消费 chunk 批次：
   - 块键沿用 `chunk_key = SHA-256("chunk" | entry_key | seq)`，Rust 侧生成；记录名 `chunk_<chunk_key>`；重试幂等；
   - `WriterCommand::AppendChunksRaw` → worker `add_chunk_batch_raw`（SHM）→ 块记录 ID；
   - 台账 `owner=0` → 元数据提交后改写 owner；WAL 追加 pending/committed。
4. 读取完成后再次 `stat`，`(size, mtime)` 变化则该文件失败（防止读到半文件）。
5. 缩略图/预览：
   - 导入关键路径只生成 400px 缩略图（缩放解码，快）；缩略图内联 meta；
   - 2048px 预览默认进入后台 preview 队列（`previewMode=background`），不阻塞导入完成；`inline` 时随文件生成；`off` 时仅查看阶段懒生成；
   - 任一预览失败不阻断照片导入，只记录 warning。
6. 主进程把块记录 ID、entryKey、记录名回传 worker；worker 组装 `PhotoMeta`（含 thumbB64/尺寸/方向/动画标记/fileHash/chunkIds）并用模块密钥封装 meta，回传密文；主进程通过 `AppendMetaRaw` 写入 meta 记录，获得 `metaId` 并更新 WAL；原图明文不进入主进程。
7. 预览任务（inline 或后台）拿到 `metaId` 后生成并封装 `preview_<metaId>`；主进程写入预览记录；登记预览索引。后台任务失败不影响照片，查看时懒生成。
8. 展示缩略图仅作为输出字节经二进制/SHM 下发前端；不进入 meta 之外的持久化路径。
9. 汇报该文件完成（导入完成不等同于预览完成）。

### 4.3 解码与缩略图/预览

- JPEG：优先 libjpeg-turbo 缩放解码（1/2、1/4、1/8 DCT 缩放）→ 直接得到小图，避免全图 RGBA。
- PNG/BMP/GIF/APNG：WIC 或兼容解码器；GIF/APNG 只取首帧用于缩略图/预览。
- WebP：WIC 不保证覆盖，使用兼容解码器（静态/动态首帧）。
- EXIF 方向：解码时应用；`PhotoMeta.orientation` 记录原值。
- 像素炸弹防护：最大像素数、最大边长、最大解码内存；超限则跳过缩略图/预览，不导入失败。
- 编码：缩略图 JPEG 0.85、400px；预览 JPEG 0.82、2048px；体积预算见 `02-data-model.md`。
- 动图三态检测（GIF/WebP/APNG）在 worker 内以 Rust 实现，不依赖 JS；结果写入 `PhotoMeta.animated`。
- 加密必须复用 `module_keys.rs` 的既有内容封装规则：`photo_file_uuid`（由 fileHash 派生）、`tag_content` 种类域标签、`module_position`；不得直接裸调 C `V4ChunkSeal` 跳过种类标签，否则读取侧无法解密或产生种类混用漏洞。
- 复用“规则”而不是复用 base64 命令入口：在 `module_keys` 增加 raw-buffer seal/open 变体（输入/输出 `&[u8]`/`Vec<u8>`），内部仍走同一 `tag_content` + C 调用；禁止把照片字节重新送回 base64 JSON。
- 新增 `kind="preview"`（种类码 9）并同步 `kind_code`/`open_inner`/`CRYPT_KINDS`；预览与 thumb/meta/chunk 不可互换。
- 解码器选择在 Gate G0 完成覆盖与性能验证，包括 worker 沙箱内 WIC/COM 可用性；依赖许可证同步写入 `THIRD_PARTY.md`。

### 4.4 元数据写入与预览任务

- 缩略图仍内联 `thumbB64`，保持旧读取路径；meta 由 worker 组装并封装，主进程只写密文。
- 预览记录类型 `TYPE_PHOTO_PREVIEW`，名称 `preview_<metaId>`；通过导入写者的派生记录通道写入（`AppendDerivedRecord` 或等价命令），不进入 WAL committed 集合（派生缓存）。
- 预览生成是独立的低优先级任务（后台 1–2 并发）：不阻塞导入完成；查看命中缺失时同步懒生成该张。
- 预览明文头携带 `{metaId, fileHash}`；写入前若索引命中同一 metaId 的旧预览，先删除/覆盖。
- 预览写入成功后将 `metaId → previewId` 登记到 worker 预览索引；重启后由类型索引重建。
- 若预览写入失败：照片已可用；记录 warning；首次查看时懒生成。
- 删除照片时按预览索引/类型扫描级联删除预览；孤儿预览由 GC/删除级联兜底。

## 5. 并发与背压

| 维度 | 默认 | 说明 |
|---|---|---|
| 文件级并发 | 4–8 | 大文件降低并发，小文件提高并发 |
| 单文件块并发 | 1–2 | 受 C 线程安全与内存预算约束 |
| 全局字节预算 | 256MiB | 读缓冲 + 解码位图 + 密文 + SHM 在途 |
| ImportWriter 批量 | 128–512 条/事务，且单批密文 ≤64MiB | 减少 fsync；不超过 `VERTHYS_ADD_RECORDS_MAX` 与内存预算 |
| 进度频率 | 10Hz | 合并为每文件/总字节进度 |
| SHM 在途 | 1–2 个 job buffer | 主进程消费后才继续投递 |

背压：

- worker 的 chunk 投递在 SHM 未消费时等待；主进程写者通道满时 worker 暂停。
- 解码并发受内存预算约束；超出时降低并发或跳过预览。
- 不因单个文件失败中止整批；会话级致命错误（容量不足、容器损坏）才终止。

## 6. 会话、WAL 与台账

复用现有 Rust 导入域：

- `verthys_import_begin/checkpoint/end`；
- `ImportWriter` 单写者 + `import.wal` 快照/检查点；
- `verthys_chunks` 块归属台账；
- 成功结束前先落盘台账；失败保留 WAL 供续传；
- 删除成功后释放 entry_key；
- GC 只回收归属为空且已结算的块。

新增：

- `AppendChunksRaw`：密文经 SHM 进入写者，不经过 base64。
- `AppendRecordsRaw`（可选）：预览等派生记录直接写原始密文；meta 因体积小可继续 base64。
- 批量大小从 50 提升到 128–512；写者心跳与长事务看门狗保留。
- 写者命令携带 `job_id`，便于取消与审计；WAL 批次序仍单调。

不变量：

- 同一时刻只有一个写者线程提交容器变更。
- 块记录先于 meta 可见；meta 引用的块必须已在台账中记账。
- 预览记录可缺失，不得被 meta 强依赖。
- 取消/崩溃后，已提交块与 meta 可被台账结算；未提交块由 GC 回收。

### 6.1 容器事务与回退锚点（G0 关键发现）

G0 实测：每次 `AddRecords`/`Flush` 都有约 450ms 固定成本，根因是
`vty_rollback_commit` 每次保存都轮换 TPM 持久化见证密钥（CNG 对照：
`NCryptFinalizeKey` 约 377ms + `NCryptCreatePersistedKey` 约 50ms）；
普通 fsync 仅约 3ms。

因此原生导入必须：

- **禁止按照片提交**；把多张照片的块与 meta 合并到尽量少的容器事务中。
- 首选 G0-A：TPM 见证密钥预置——后台提前创建 2–3 把见证密钥，
  提交路径只切换到已就绪密钥；把 `NCryptFinalizeKey` 的 377ms 移出关键路径，
  同时保留每次锚点推进的回退保护语义。
- 备选 G0-A：批量会话延迟锚点（导入会话内批量写入，结束一次性推进）；
  仅在预置方案被 TPM 限制否决时启用，必须安全评审并明确回退窗口。
- 锚点推进频率调整必须保持回退保护：容器 generation 低于锚点仍拒绝；
  锚点落后于容器时下次解锁可补推进；崩溃/断电场景必须测试。
- 未通过 G0-A/G0-A2 安全评审前，不能承诺任何单一尺寸（含 10MiB 样本）的
  ≤250ms；必须按尺寸矩阵分别给出证据。
- G0-A 隔离原型已测：预置快路径提交约 15.7ms，首次同步约 447ms；两槽在连续提交下会饥饿，
  因此导入写者必须把块/meta/锚点合并为尽量少的提交，禁止按照片提交。
- G0-A2 隔离原型：会话内推迟锚点，32 代/30s 硬上限；worker 数据面在
  10/17.73/24.43/50MiB 样本上平均 419/702/978/1861ms，相对默认 DLL 降幅
  78.9%–84.7%。导入写者按块数 `ceil(size/4MiB)` 切分，不假设固定照片大小；
  100MiB 上限样本实测 3661ms，超过 2.0s，需按尺寸档位设定目标。

提交批量同时受条数与字节约束：128–512 条且单批密文 ≤64MiB；`AddRecords` 上限 512。

## 7. 进度与取消

进度事件：

```json
{
  "job_id": "photo-import-...",
  "stage": "read|hash|seal|decode|write|flush",
  "file_index": 3,
  "files": 100,
  "bytes": 31457280,
  "total_bytes": 1048576000,
  "skipped": 2,
  "failed": 0,
  "elapsed_ms": 4200
}
```

- 阶段用于 UI 文案；总进度以字节为主、文件数为辅。
- 进度 10Hz 合并；不逐块发送。

取消：

- 主进程 `photo_job_cancel(job_id)` → worker `cancel=true`。
- worker 在块边界/文件边界停止投递；已提交块与 meta 保留。
- `import_end(false)` 不压缩 WAL；不删除源文件。
- 取消后允许重新导入，entry_key 命中已提交项自动跳过。

## 8. 移动语义

`mode=move`：

1. 文件成功导入并 `import_end(true)` 且台账落盘成功后，才允许删除源文件。
2. 删除使用 `photo_move` 批量 grant；逐文件删除，失败进入重试列表，不阻断其他文件。
3. 删除前可做一次大小/哈希核对（默认核对 size；可选全量哈希）。
4. 任何失败（导入、落盘、台账、删除）都不得删除源文件。
5. 删除记录写入审计日志（只记录数量/job_id，不记录路径）。

物理边界：

- 加密必须读源、写密文，无法同盘 rename 绕过。
- “秒级”来自原生流式 + 并行 + 4MiB 块 + 批量事务；“大文件不可能 1 秒”是物理限制，方案不承诺违反 I/O 物理。

## 9. 失败与恢复

| 场景 | 行为 |
|---|---|
| 单文件读取失败 | 该文件失败；其他继续；源文件保留 |
| 单文件被修改 | 该文件失败；已写入块由台账结算/GC |
| 缩略图/预览失败 | 照片成功；预览懒生成 |
| ImportWriter 繁忙/通道满 | 背压等待；超时按可重试失败 |
| 容器容量不足 | 终止会话；不可重试失败；保留 WAL |
| worker 崩溃 | job 失败；WAL 保留；重启续传 |
| 应用崩溃 | 同上；台账结算已提交块 |
| 取消 | 块/文件边界停止；WAL 保留；源文件保留 |
| 预览记录写入失败 | 照片成功；首次查看再生成 |

## 10. 验收

1. 单张 10 / 17.73 / 24.43 / 50MiB 与 100MiB 边界按 [06-verification.md](06-verification.md)
   的尺寸矩阵验收；不得只测 10MiB。100 张混合尺寸批量吞吐接近磁盘顺序吞吐。
2. 导入期间主线程无 >50ms 长任务；进度 10Hz 平滑。
3. 4MiB 块照片可被查看、导出、`.venc` 备份/还原完整读取。
4. 取消/崩溃/重启后续传，已提交项不重复、不丢失。
5. `mode=move` 仅在完整成功后删除源；失败源文件保留。
6. 旧 1MiB 照片仍可导入/查看/导出；新导入不读取旧 JS 加密链路。
7. 批量 1,000 张路径授权不触发 32 条限制；授权过期/跨 job 复用被拒绝。
8. 缩略图/预览失败不影响照片可用性；预览懒生成成功。
