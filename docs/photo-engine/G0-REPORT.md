# G0 — 可行性验证报告

> 状态：已完成 · 最后更新：2026-11-18 · 维护人：K1Super
>
> 结论：架构方向可行；原定“单一 10MiB 样本单张导入 P95 ≤250ms、批量接近磁盘吞吐”在**现有每次保存同步创建 TPM 见证键**的实现下不成立。必须先完成 G0-A：TPM 见证密钥预置（首选）+ 批量提交；通过原型与安全评审后才能冻结导入指标并进入 Phase 1。
>
> 尺寸口径：本报告的 10MB 均为 10MiB 基准样本，产品单文件上限是 100MiB；
> 大图（17.73/24.43/50MiB）实测见 [G0-A2-PROTOTYPE-REPORT.md](G0-A2-PROTOTYPE-REPORT.md)。

---

## 1. 验证环境

| 项 | 值 |
|---|---|
| OS | Windows 11 23H2（10.0.22631） |
| 编译器 | MSVC 19.51.36231（Visual Studio 18 2026） |
| 被测库 | `build/core/Release/verthys.dll`（2026-11-18 构建） |
| 测试程序 | 独立 C 程序，链接 `verthys.lib`，位于系统临时目录，不进入仓库 |
| 测试容器 | `%TEMP%\verthys_g0\*.vty` |
| 说明 | 未运行完整 Tauri 应用；端到端 UI 基线仍需后续埋点 |

## 2. 实测结果

### 2.1 分块加解密

| 用例 | 结果 |
|---|---|
| 4MiB seal ×8 | 39.6ms，约 808 MB/s |
| 4MiB open ×8 | 38.8ms，约 826 MB/s，明文一致 |
| 16MiB seal | 成功（`VTY_CHUNK_MAX_PT = 16MiB`） |
| 16MiB + 1 seal | 拒绝（`VERTHYS_ERR_INVALID`） |
| 4 线程 × 4 次 4MiB seal | 64MiB / 75.8ms，约 844 MB/s |

结论：

- 4MiB 块完全可行，上限 16MiB 足够。
- `V4ChunkSeal/Open` 是 MT-Safe，但每个调用持有容器 `SRWLockExclusive`；**同一句柄的并发不会提升吞吐**，4 线程结果与单线程同量级。并发应放在文件 I/O/解码层，C 调用保持串行或批量。

### 2.2 记录写入/落盘

| 用例 | AddRecords | Flush |
|---|---|---|
| 1KB ×1 | 450ms | 447ms |
| 4MiB ×1 | 446ms | 391ms |
| 1MiB ×10 | 476ms | 513ms |
| 4MiB ×3 | 594ms | 405ms |
| 4MiB ×25（100MB） | 1.17s | 438ms |
| 4MiB 读回 | 23ms（4MiB） | — |

结论：

- `AddRecords` 存在**约 450ms 固定成本**，与数据量几乎无关；100MB 批量的边际吞吐约 150MB/s。
- `Flush` 另有一次约 400–500ms 固定成本。
- 1KB 记录也慢，说明问题不在记录大小或磁盘吞吐。

### 2.3 固定成本定位

| 对照 | 结果 |
|---|---|
| 原生 `FlushFileBuffers`（1KB） | 2.8ms |
| `MoveFileExW(WRITE_THROUGH)` | <1ms |
| 空容器 `Verthys_Flush` | 431ms |
| 1KB `AddRecords` | 450ms |
| 每次保存调用链 | `vty_vault_save_meta` → `vty_rollback_commit` → TPM 持久化见证密钥轮换 |
| 直接 TPM 对照（CNG） | `NCryptOpenStorageProvider` 1.44ms；`NCryptCreatePersistedKey` 49.97ms；`NCryptFinalizeKey` **377.03ms**；`NCryptDeleteKey` 0.09ms |

代码证据：

- `vty_rollback_commit` 在每次保存时执行；若已有见证，会校验并轮换 TPM 见证。
- `vty_tpm_witness_rotate` 使用 `NCryptCreatePersistedKey` + `NCryptFinalizeKey` 创建/持久化 ECDSA P-256 密钥。
- 直接 CNG 对照实测创建 + 持久化约 427ms，与 `AddRecords/Flush` 的固定 450ms 吻合；普通 fsync 与原子替换均 <3ms，已排除磁盘/杀软是主因。

结论（已验证）：**瓶颈是每次容器保存都轮换 TPM 回退见证，不是加密、不是磁盘、不是 base64**。

### 2.4 WIC 解码

| 格式 | 结果 |
|---|---|
| JPEG | 成功；64×64 约 1ms |
| PNG | 成功；64×64 约 1ms |
| GIF | 成功；静态帧 |
| BMP | 成功 |
| WebP | 成功（本机 WIC 已注册 WebP 解码器），550×368 首帧约 77ms（首次加载 codec） |
| 24MP JPEG 6000×4000 | 首次解码+CopyPixels 124ms，热解码约 34ms |

结论：

- WIC 在目标 Windows 11 环境覆盖 JPEG/PNG/GIF/BMP/WebP；APNG 未单独验证，但 PNG 解码器可解首帧。
- 热态 24MP 解码约 34ms，满足缩略图/预览生成需求；首次 codec 加载有一次性开销。
- **尚未在 worker 沙箱内验证 WIC/COM 可用性**；这是 Phase 1 前必须补的 G0 项。

### 2.5 Worker 线程模型

代码核验：

- `main_loop.rs` 为单线程：stdin 行 → `handle_request` → stdout。
- C 分块接口 MT-Safe，但被 `module_lock_ctx` 的独占 SRW 锁串行化；批量写入 `AddRecords` 也有内部事务锁。
- 因此 worker 媒体 job 应采用：
  - 文件 I/O、WIC 解码、哈希、预览编码：独立媒体线程池；
  - C seal/open、记录写入：单线程串行或批量提交，不追求同句柄并行；
  - 所有 stdout/进度经有界 channel 回主循环，禁止媒体线程直接写 stdout。

结论：线程模型可行，但“多线程加密”不会带来吞吐提升；收益来自去 JS/base64、流式 I/O、批量事务和 WIC 原生解码。

### 2.6 SHM、批量授权、名称索引

- 现有扫描 SHM 已具备随机命名、认证、`VirtualLock`、销毁语义，可抽象为 media SHM。
- `path_grants` 当前单路径/TTL 30s/最多 32 条，无法承载批量导入；扩展为作业级批量 grant 可行，但需安全评审。
- 容器已有名称盲索引（`vty_name_index` / repo leaf `name_index`），新增精确名称查 ID API 可行；`preview_<metaId>` 定位不必全表扫描。
- `ListIdsByType` 可按类型枚举预览记录，可作为名称 API 的兜底。

## 3. Go / No-Go

### GO

- Rust 数据面、media SHM、4MiB 分块、WIC 原生解码、预览优先查看、原生导出、worker 媒体线程模型均可行。
- 去 JS/base64/逐块 Promise 后，读路径和查看路径会显著改善；4MiB 块加解密不是瓶颈。

### NO-GO（按原指标）

- “单一 10MiB 样本单张导入 P95 ≤250ms”在当前 C 事务语义下不可达：每次保存固定约 450ms，单张至少一次保存。
- “批量接近磁盘吞吐（1GB/s 级）”不可达：当前记录写入边际约 150MB/s，且每个事务还有 TPM 见证成本。
- 因此不能把性能希望全部寄托在“去掉 JS 层”；必须改 C 层提交模型。

## 4. 必须补的 C 层设计（Phase 1 前置）

### 4.1 TPM 见证密钥预置（首选）+ 批量提交

目标：

- 把 `NCryptFinalizeKey` 的 377ms 从提交关键路径移走，而不是简单关闭回退保护。
- 保留每次锚点推进的见证轮换语义；旧状态引用已删除/退役密钥仍被拒绝。
- 配合批量提交，减少锚点推进次数与 TPM 总工作量。

首选方案：

1. 在 `vty_tpm_witness` 中维护 2–3 个**预创建**的见证密钥槽；后台线程提前
   `NCryptCreatePersistedKey` + `NCryptFinalizeKey`。
2. `vty_rollback_commit` 优先切换到已就绪的下一把密钥；状态文件写入与旧密钥退役
   是快速路径，不再在提交线程里等待 TPM 建键。
3. 后台补充下一把密钥；TPM 建键吞吐不足时，提交路径可阻塞等待或回退同步建键，
   但不静默关闭回退保护。
4. 导入仍按批量事务提交（128–512 条 / ≤64MiB），减少锚点推进次数与 TPM 总建键量。
5. 启动时清理未引用的预置密钥；崩溃/断电后状态文件与密钥槽一致性必须可验证。

预置池实测（CNG 对照）：

| 操作 | 耗时 |
|---|---|
| 预创建 A | 396.9ms |
| 预创建 B | 386.8ms |
| 打开 A / 导出公钥 | 12.6ms / 15.2ms |
| 打开 B / 导出公钥 | 1.4ms / 13.8ms |
| 后台创建 C（与主路径并行） | 639ms |
| 主路径 20 次 open+export（与后台建键并行） | 949.7ms（约 47ms/次） |

结论：

- 预置方案可行：把 397–639ms 的建键放到后台；提交路径只做密钥切换与状态文件更新。
- **提交路径必须使用建键时缓存的指纹，不能每次重新 `NCryptOpenKey`/`NCryptExportKey` 验证**；
  否则仍有 15–50ms/次、且与后台建键互相争用。
- 后台建键在争用下可到 639ms；因此仍需批量提交，保证 TPM 建键速率跟得上锚点推进速率。
- 该方案保留每次锚点推进的回退保护，不需要延迟锚点。

为什么优于“延迟锚点”：

- 延迟锚点会扩大“容器已更新、锚点未推进”的回退窗口；预置密钥保留每次提交的
  锚点新鲜度，不降低回退保护强度。
- 单张照片也能在提交路径上快速完成，不需要牺牲安全换取速度。

备选（仅在预置方案被 TPM 限制否决时）：

- `Verthys_BulkImportBegin/Commit`：会话内批量写入，`import_end` 一次性推进锚点；
- `AddRecords` 可选 `defer_anchor`；
- 必须做安全评审、崩溃/断电测试，并明确回退窗口。

安全约束：

- 不得关闭回退保护；只优化建键时机与提交频率。
- 预置密钥不得被旧状态引用；旧状态回滚必须仍然 fail-closed。
- 崩溃窗口必须可证明：锚点落后于容器时，下次解锁必须接受并补推进；容器回退仍必须拒绝。
- 需要专门的回退/崩溃/断电测试与安全评审。

### 4.2 批量块写入吞吐

- 当前 100MB AddRecords 约 1.17s（含固定 450ms），边际约 150MB/s；若要 1GB 级批量真正“秒级”，需要更快的块写入路径。
- 评估专用 `BulkAppendChunks`：连续写数据区、一次性更新目录/索引，避免逐记录 COW/Merkle/提交开销。
- 若只做事务摊销，1GB 批量预计仍在数秒级；需要明确产品目标。

## 5. 修订后的性能目标（待 C 方案确认）

| 场景 | 原目标 | G0 后判断 |
|---|---|---|
| 单张 10MiB 样本导入 | ≤250ms | 现有实现不可达；worker 端到端实测（真实 worker + 真实 DLL）默认 5.04s、G0-A 3.85s；G0-A2 推迟后 419ms（10MiB），17.73/24.43/50MiB 为 702/978/1861ms |
| 100 张 10MiB 样本批量 | 接近磁盘吞吐 | 预置键消除固定 450ms 后，当前记录写入边际约 150MB/s；G0-A2 把锚点提交降到每 32 代/30s 一次，大图批量仍需按尺寸矩阵复测 |
| 4MiB seal/open | — | 已验证约 800MB/s，非瓶颈 |
| 24MP WIC 解码 | — | 热态约 34ms，非瓶颈 |
| 查看预览 | ≤120ms | 可行（预览生成后） |
| 查看原图 10MiB 样本 | ≤350ms | 读路径约 23ms/4MiB + 解码，可行；50MiB+ 走 Range 首段 |

建议在 C 方案确认后重新冻结目标，不在 G0 阶段承诺具体毫秒数。冻结时必须
同时给出 10 / 17.73 / 24.43 / 50MiB 与 100MiB 边界的结果，10MiB 只是样本。

## 6. G0 剩余项

| 编号 | 内容 | 状态 |
|---|---|---|
| G0-A | C 批量导入提交 / TPM 见证密钥预置设计与安全评审 | 设计、安全评审、隔离原型、生产化原型均完成（有条件通过）：快路径 15–78ms，首次/无预置 406–531ms；6 个提交窗口的进程级崩溃注入通过；10MiB 单样本端到端 5.04s→3.85s，锚点推进速率被 TPM 建键封顶；后续由 G0-A2 扩展到大图矩阵 |
| G0-A2 | 批量导入锚点推迟（C 层设计与安全评审） | 设计与安全评审完成（有条件通过原型），隔离原型完成：13/13 用例；worker 数据面 10/17.73/24.43/50MiB 平均 419/702/978/1861ms，较默认 DLL 降幅 78.9%–84.7%；100MiB 上限实测 3661ms（降幅 77.6%，需分档目标）；默认构建不变 |
| G0-B | worker 媒体线程原型（I/O/解码线程 + 单线程 C 提交 + 进度 channel） | 静态可行，原型待执行 |
| G0-C | worker 沙箱内 WIC/COM 可用性；APNG/GIF 帧覆盖 | 环境 WIC 已验证；worker 沙箱待执行 |
| G0-D | media SHM 原型；批量 grant；`FindLidByName` | 静态可行，原型待执行 |
| G0-E | 现有 Tauri 应用端到端基线埋点（导入/查看/导出） | 待执行 |

## 7. 结论

1. 数据面下沉 Rust 的方向正确，但**不能按原性能承诺直接进入 Phase 1**。
2. 首选 G0-A：TPM 见证密钥预置 + 批量提交，把约 397–639ms 建键移出提交关键路径，同时保留回退保护；设计、安全评审与隔离原型已完成，生产化原型在 `VERTHYS_G0A_PROTOTYPE` 构建中通过（快路径 15–78ms；连续提交第二次 438–531ms）。worker 端到端实测只改善约 24%（10MiB 样本 5.04s→3.85s）：每次 `add_records` 都推进锚点，推进速率被 TPM 建键封顶。预置池是必要条件，不是充分条件；后续由 G0-A2 的锚点推迟解决。
3. 延迟锚点/提交合并已完成 C 层设计与安全评审（[G0-A2-DEFERRED-ANCHOR-DESIGN.md](G0-A2-DEFERRED-ANCHOR-DESIGN.md)、[G0-A2-SECURITY-REVIEW.md](G0-A2-SECURITY-REVIEW.md)），判定“有条件通过原型”；隔离原型已通过 13 项用例（32 代/30s 上限、Begin 预提交、失败收口与崩溃注入），并在 10/17.73/24.43/50/100MiB 尺寸矩阵上验证。
4. G0-B/C/D 可并行推进；G0-E 用于量化现有链路，作为对比基线。
5. G0-A 的断电/`FinalizeKey` 半完成键注入、完整 Tauri UI 链路测量、`ANCHOR_DIRTY` 恢复流程未完成前，不进入 Phase 1、不改默认构建。100MiB 边界已实测 3661ms，需按尺寸档位冻结目标。若方案都不可行，则必须下调导入性能目标并向产品明确物理边界。
