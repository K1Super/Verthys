# 06 — 验证、性能基线与验收门禁

> 状态：评审中 · 最后更新：2026-11-19 · 维护人：K1Super
>
> 本文定义性能测量方法、功能/安全测试矩阵、回归门禁与各阶段证据要求。没有证据不得宣称达标。

---

## 1. 性能测量方法

### 1.1 参考环境

- Windows 11 x64，8 核以上 CPU，32GB 内存，NVMe SSD。
- WebView2 Evergreen，Tauri 版本以仓库依赖为准。
- 测试期间关闭其他磁盘/CPU 密集任务；记录 CPU/磁盘/内存型号与 WebView2 版本。

### 1.2 样本集

尺寸统一按 MiB（1024²）计。10MiB 只是样本之一，不是产品边界；产品单文件
上限为 100MiB。任何导入/查看/导出门禁都必须给出矩阵结果，不得只报 10MiB。

| 样本 | 用途 |
|---|---|
| 10MiB / 24MP JPEG | 基准样本 A（最小主样本） |
| 17.73MiB JPEG | 基准样本 B（实拍大图） |
| 24.43MiB JPEG | 基准样本 C（实拍大图） |
| 30MiB / 50MP JPEG | 基准样本 D（高像素大图） |
| 50MiB PNG | 非 JPEG 解码 + 大文件基准 |
| 100MiB 边界 | 上限接受/拒绝与内存峰值边界 |
| 100 张混合（5/10/17.73/24.43MiB） | 批量吞吐基准 |
| 1,000 张 2–24.43MiB 混合 | 列表/批量压力 |
| 旧 1MiB 块照片、旧 `.venc` | 兼容基准 |

### 1.3 分段计时

导入：

```text
stat → read → hash → decode(thumb/preview) → seal → add_chunk → add_meta → preview_write → flush
```

查看：

```text
preview_record_read → preview_decrypt → preview_decode/encode → blob → first_paint
full_record_read → chunk_open × N → assemble → blob → first_paint
```

导出：

```text
chunk_open × N → pack/encode → write → flush
```

工具：

- Rust `Instant`/`tracing` 结构化计时；worker 与主进程分别记录。
- 前端 `performance.mark/measure`；长任务用 PerformanceObserver 记录。
- 基准结果落 JSON/CSV（不含路径/文件名/明文），作为门禁证据。

### 1.4 采样与统计

- 每项冷启动 10 次、热缓存 20 次，报告 P50/P95/P99、均值、吞吐、峰值内存。
- 批量场景报告总耗时、照片/秒、MB/秒、失败/跳过数。
- UI 场景记录主线程长任务（>50ms）次数与最长任务。
- 结果必须附命令、样本、环境、原始数据。

## 2. 性能目标

| 指标 | 目标 | 说明 |
|---|---|---|
| 导入 P95（10 / 17.73 / 24.43 / 50MiB） | Phase 1 冻结 | G0-A2 worker 数据面原型仅均值 419 / 702 / 978 / 1861ms（3 轮），相对默认 DLL 降幅 78.9%–84.7%；不含前端加密/缩略图/WAL，不能当作 P95 或全链路指标 |
| 100 张混合批量导入（5/10/17.73/24.43MiB） | Phase 1 冻结 | 需批量事务/锚点摊销；G0-A2 会话内按 32 代/30s 提交，100MiB 记录写入约 1.17s（含固定 450ms） |
| 100MiB 单张边界 | Phase 1 分档冻结 | G0-A2 实测 3661ms（25 块），默认 DLL 16372ms；超过 2.0s，需按档位设定目标 |
| 导入主线程长任务 | 0 个 >50ms | 10Hz 进度合并 |
| 预览首屏 P95 | ≤120ms | 首次（无预览）懒生成除外；生成后 ≤50ms |
| 原图 10MiB 样本 P95 | ≤350ms | 中小图直接响应；10MiB 仅为样本 |
| 原图 50MiB+ 首段 | 可交互 ≤500ms | 大图 Range/分片流式，不整图驻留 |
| 重复查看（LRU） | ≤50ms | Blob URL 命中 |
| 原始/`.venc`/PNG 导出 | 接近磁盘写入上限 | 报告 MB/s |
| 导入峰值内存 | ≤256MB + 单文件必要缓冲 | 不随批量总数线性增长 |
| 查看峰值内存 | 预览 ≤2× 预览体积；原图流式有界 | 不出现整图多份副本 |
| 列表滚动 | 无 >16ms 长帧（参考机） | 缩略图批量二进制后复测 |

说明：

- 导入目标在 G0-A/G0-A2 通过前不冻结；不得以“去掉 JS”替代 C 层事务成本优化。
- 尺寸矩阵是门禁的一部分：只测 10MiB 不能证明大图可用；必须至少覆盖 17.73/24.43/50MiB 与 100MiB 边界。
- G0 实测固定成本：`AddRecords` 约 450ms（1KB 与 4MiB 同量级）、`Flush` 约 400–500ms；根因是 TPM 回退见证轮换。
- 目标是参考机上的工程目标，不是所有硬件的保证；不达标必须给出证据与优化项。
- JPEG 导入/预览目标以 libjpeg-turbo 缩放解码为前提；若 G0 证明只能全图解码，目标按实测调整，不得用降低安全/功能换指标。
- “秒移动”按批量吞吐与 UI 响应定义，不承诺违反磁盘/加密物理上限。

## 3. 功能测试矩阵

### 3.1 导入

| 维度 | 用例 |
|---|---|
| 格式 | JPEG / PNG / WebP 静态 / 动态 WebP / GIF / APNG / BMP；HEIC 等不支持格式拒绝 |
| 大小 | 1KB / 1MB / 10MiB / 17.73MiB / 24.43MiB / 30MB / 50MiB / 100MiB 边界；>100MiB 拒绝；空文件拒绝；每个通过项校验块数 = ceil(size/4MiB) |
| 批量 | 1 / 10 / 100 / 1000；混合大小；同名不同路径；同内容不同路径（保持现有语义） |
| 续传 | 中断后重导；已提交跳过；WAL 恢复；检查点 |
| 取消 | 文件边界/块边界取消；已提交保留；源文件不删 |
| 移动 | copy/move；成功删除源；失败保留；删除失败重试 |
| 崩溃 | 导入中 kill worker/应用；重启续传；无孤儿/丢失 |
| 容量 | 磁盘/容器满；不可重试失败；提示 |
| 源变化 | 导入中修改/截断源文件；该文件失败，其他继续 |
| 缩略图/预览 | 生成失败不阻断；懒生成成功 |

### 3.2 查看

| 维度 | 用例 |
|---|---|
| 预览 | 新照片/旧照片首次/二次；缺失/损坏；快速切换取消 |
| 原图 | 小图直接响应；大图 Range；放大触发；关闭/重开 |
| 动图 | GIF/动态 WebP/APNG 播放；PNG 导出跳过 |
| 缓存 | LRU 命中/淘汰；锁定/登出/卸载释放；删除释放 |
| 锁定 | 查看中锁库；请求失败关闭；缓存清除 |
| 兼容 | 旧 1MiB、旧瘦身布局、旧缩略图 |

### 3.3 导出/还原

| 维度 | 用例 |
|---|---|
| 原始 | 单张/多张；字节一致；BLAKE3 |
| `.venc` | 单文件/多文件；旧/新容器；令牌错误；2GB 上限；取消/失败清理 |
| PNG | 静态；动图跳过；EXIF 方向；大图 |
| 还原 | 旧/新 `.venc`；4MiB 块；预览懒生成；容器损坏/篡改 |
| 并发 | 导出与导入/查看并发；锁/退出 |

### 3.4 授权与安全

| 维度 | 用例 |
|---|---|
| 路径 | 未授权路径拒绝；跨 job grant 拒绝；过期 grant 拒绝；目录遍历/设备命名空间拒绝 |
| SHM | 篡改/重放/跨 job/超长/超时；零化与销毁 |
| 协议 | token 无效/过期/跨照片；Range 越界/滥用；锁定后失效 |
| 内容种类 | preview ↔ thumb/meta/chunk 密文互换必须认证失败；未知 kind 拒绝 |
| 解码 | 超大像素/畸形图片；内存/超时上限；不 OOM |
| 日志 | 无路径/文件名/明文/令牌 |
| 密钥边界 | 前端/主进程不出现密钥；worker 锁后拒绝 |

### 3.5 回归

- 现有前端全量测试（当前 941 项）必须通过。
- Rust `cargo test`、构建、`ci/check_docs.ps1`。
- 旧 JS 浏览器回退路径不回归。
- 文档链接/索引检查通过。

## 4. 安全验收

1. 路径授权表/批量 grant 通过安全评审；越权/重放/过期测试通过。
2. SHM 认证、`VirtualLock`、job 级销毁、零化测试通过。
3. 查看/导出无明文临时文件；崩溃转储/日志不含明文。
4. 自定义协议 token/IDOR/Range 测试通过；CSP 收敛。
5. 解码器解压炸弹/畸形输入测试通过。
6. 锁定/登出/worker kill 后旧 job/token/缓存全部失效。
7. 依赖许可证与供应链审计通过，`THIRD_PARTY.md` 更新。

## 5. Gate 与证据

| Gate | 必须提交的证据 |
|---|---|
| G0 | C 线程安全/块长报告；worker 线程原型；解码器覆盖/性能；SHM/批量 grant/长任务协议原型；当前链路基线 |
| G1 | 导入功能矩阵、10/100 张性能、续传/崩溃/取消/移动、旧路径兼容、安全测试 |
| G2 | 预览/原图性能、LRU、旧照片懒预览、动图、协议（若启用）、锁定 |
| G3 | 导出/还原字节正确性、性能、取消/失败、旧/新 VENC、授权 |
| G4 | 全量回归、静态检查（桌面无 JS 字节面）、压测、旧管线删除审查 |
| G5 | 发布级压测、崩溃注入、安全审计、文档收敛、回滚演练 |

## 5.1 G1 证据（Phase 1 原生导入）

> 执行日期：2026-11-19。以下均为实际命令与结果；未执行项单独标注。

| 门禁 | 命令 | 结果 |
|---|---|---|
| 预算生成器 | `node constants/generate.mjs --check` | PASS；17 条不变式通过；`PB_CHUNK_RECORD_B64_MAX = 5,592,504` |
| 前端类型检查 | `npx vue-tsc --noEmit` | PASS |
| 前端全量单测 | `npx vitest run` | 89 文件 / 947 用例通过 |
| worker 单测 | `cargo test`（`verthys-worker`） | 82 passed |
| 宿主单测 | `cargo test --lib`（`src-tauri`） | 577 passed / 2 ignored |
| C 半完成键 | `verthys_tests.exe g0a_crash_halfkey` | 2 passed |
| C 回退锚点 | `verthys_tests.exe rollback` | 15 passed |
| C TPM 见证 | `verthys_tests.exe witness` | 3 passed |
| 文档门禁 | `ci/check_docs.ps1` | PASS（47 文件 / 179 链接） |

真实 worker + DLL E2E（`worker_native_import_e2e`，`VERTHYS_NATIVE_E2E=1`）：

- 环境：Windows 11 x64；debug `verthys-worker.exe`；`build/core/Release/verthys.dll`。
- 样本：Pillow 13 生成的确定性噪声图，按目标字节数补齐尾部；图片解码器忽略尾部补齐数据，因此文件大小、哈希、分块、封装与元数据路径均按真实字节数执行。
- 矩阵与结果：
  - JPEG 10 / 17.73 / 24.43 / 30 / 50 / 100MiB → 3 / 5 / 7 / 8 / 13 / 25 块，全部成功。
  - PNG / WebP / GIF / APNG 各 100MiB → 各 25 块，全部成功。
  - 混合批量 3 文件（JPEG + PNG + GIF）→ 3/3 成功。
  - 100MiB + 1 字节 → `skipped`，原因“文件超过单张照片上限（104857601 > 104857600 字节）”。
  - 源文件在 job 建立后改名 → `skipped`，原因“读取文件属性失败”。
  - 50MiB 文件读取首块后取消 → `status=cancelled`，job_end 成功。
- 断言：每块 `chunk_b64` ≤ `PB_CHUNK_RECORD_B64_MAX`（实测恒定 5,592,504）；`chunk_total == ceil(size / 4MiB)`；块序号连续；finish 后 `module_open` 解密 meta，校验 `chunkIds` 顺序与数量、`size`、`name`、64 位 hex `fileHash`、非空 `thumbB64`、`chunkHashes` 长度。
- 汇总：15 文件 / 214 块 / 883,068,764 字节 / 1,193,594ms；`failures=[]`、`violations=[]`。
- 命令：

```powershell
$env:VERTHYS_NATIVE_E2E="1"
$env:VERTHYS_WORKER_E2E_WORKER="<repo>\verthys-tauri\verthys-worker\target\debug\verthys-worker.exe"
$env:VERTHYS_WORKER_E2E_DLL="<repo>\build\core\Release\verthys.dll"
$env:VERTHYS_NATIVE_E2E_DIR="<fixture-dir>"
$env:VERTHYS_NATIVE_E2E_JSON="<report.json>"
cargo test worker_native_import_e2e -- --nocapture
```

### 5.1.1 样本边界复核

- 生产代码检索 `10485760`、`10 * 1024 * 1024`、`17.73`、`24.43`：`verthys-tauri/src`、`verthys-worker/src`、`src-tauri/src`、`core/src` 均无命中；仅测试、基准与验收文档出现。
- 唯一照片产品上限为 `photo_max_bytes = 104,857,600`；100MiB 接受、100MiB + 1 拒绝，拒绝发生在 worker 打开文件阶段，早于 MIME/解码/分块。
- 协议预算（12MiB IPC、16/24MiB 行、32 块/批）只用于切批，不产生照片大小上限。

### 5.1.2 未覆盖与已知限制

- **测试隔离**：C TPM 测试与 worker 真实 E2E 不得并行运行；两者共享持久化 TPM 见证键，并行会产生 `ERR_00000019`（ROLLBACK）与后续 `Locked` 的假失败。本次验证已改为串行执行。
- 宿主控制器 GUI 运行时路径（真实窗口选图、进度渲染、取消按钮）未自动化。按项目改造要求，`photo.nativeImport` 默认启用，GUI 手测由用户在全部改造完成后执行；命令/写者接驳由编译、单测与 worker E2E 间接覆盖。
- worker 崩溃、应用崩溃、磁盘/容器容量耗尽的故障注入未在 E2E 中执行；WAL/台账/孤儿 GC 语义由既有测试覆盖。
- 大批量 1,000/10,000 张端到端吞吐未测；job 级授权上限与分批逻辑由单测覆盖。
- 同文件重复导入当前仍会执行 worker 侧读取/哈希/缩略图/分块，最终由写者按 `entry_key` 在 meta 写入时跳过（安全但耗时）；后续可将已 committed 条目键集合传入 worker 以提前跳过。
- 导入结果一次性返回全部成功项的缩略图，与旧流水线口径一致；10,000 张时响应体较大，后续应改为 Channel 流式下发或二进制缩略图。

## 5.2 G2 证据（Phase 2 预览优先查看）

> 执行日期：2026-11-19。以下均为实际命令与结果；未执行项在 5.2.2 单独标注。

| 门禁 | 命令 | 结果 |
|---|---|---|
| C 构建 | `cmake --build build --config Release --target verthys_core` | PASS；`build/core/Release/verthys.dll` 重建 |
| C 名称索引 | `verthys_tests.exe api_find_lid_by_name` | 1 passed；命中/未命中/非法参数/墓碑跳过/同名/重启/锁态 |
| worker 单测 | `cargo test`（`verthys-worker`） | 88 passed |
| 宿主单测 | `cargo test --lib`（`src-tauri`） | 578 passed / 2 ignored |
| 前端类型 | `npx vue-tsc --noEmit` | PASS |
| 前端全量单测 | `npx vitest run` | 90 文件 / 952 用例通过 |
| 文档门禁 | `ci/check_docs.ps1` | PASS（48 文件 / 188 链接） |

真实 worker + DLL 读取 E2E（`worker_native_read_e2e`，`VERTHYS_NATIVE_READ_E2E=1`）：

- 环境：Windows 11 x64；debug `verthys-worker.exe`；`build/core/Release/verthys.dll`（含 `Verthys_FindLidByName`）。
- 样本：沿用 G1 夹具 `jpeg_10.jpg`（10,485,760 字节）与 `jpeg_100.jpg`（104,857,600 字节）。
- 覆盖与结果：
  - 导入生成预览：`photo_import_job_finish` 返回预览密文与 `preview_<entryKey>` 记录名；meta 与预览同一 `add_records` 批次写入。
  - 名称索引：`find_lid_by_name` 命中预览记录并返回写者分配的 ID。
  - 预览命中：10MiB 与 100MiB 均返回 572,861 字节完整 JPEG（SOI/EOI 校验通过），`preview_cached=true`，不再读取原图。
  - 懒生成：删除预览记录后再次读取，`preview_cached=false` 且返回待写回记录；写回后再次读取命中，记录 ID 与已删除 ID 不同。
  - 删除级联：`photo_preview_ids` 按 meta 返回预览记录 ID。
  - 原图读取：10MiB → 3 块 / 10,485,760 字节；100MiB → 25 块 / 104,857,600 字节；逐块明文与源文件对应区间逐字节一致，末块 `done` 前 worker 完成整图 BLAKE3 校验。
  - 取消：读到首块后 `photo_read_job_cancel`，后续 `next` 返回 `cancelled`，`end` 正常释放。
  - 布局边界：`wrappedFileKey` + `fmt=2` 的 meta 返回 `ok=false` 且 `error_code=E_PHOTO_LAYOUT_UNSUPPORTED`。
  - 汇总：2 个尺寸、28 个原图块、115,343,360 字节、总耗时 242.10s。
- 命令：

```powershell
$env:VERTHYS_NATIVE_READ_E2E="1"
$env:VERTHYS_WORKER_E2E_WORKER="<repo>\verthys-tauri\verthys-worker\target\debug\verthys-worker.exe"
$env:VERTHYS_WORKER_E2E_DLL="<repo>\build\core\Release\verthys.dll"
$env:VERTHYS_NATIVE_E2E_DIR="<fixture-dir>"
cargo test worker_native_read_e2e -- --nocapture
```

### 5.2.1 测试隔离

C TPM 测试与 worker 真实 E2E 仍不得并行运行：两者共享持久化 TPM 见证键，并行会产生 `ERR_00000019`（ROLLBACK）与后续 `Locked` 的假失败。本次 C 测试、Rust 单测与读取 E2E 均串行执行。

### 5.2.2 未覆盖与已知限制

- **性能指标未测**：预览首屏 P95 ≤120ms、重复打开 ≤50ms、原图 P95 ≤350ms 均未在 GUI 中实测。读取 E2E 只验证字节正确性、块数与取消语义，不提供时延结论。
- **GUI 行为未自动化**：预览占位/替换、快速切换、查看中锁库、动图播放、32MiB 自动原图阈值由用户手测。
- **自定义协议与 Range**：未实现，属 Phase 4 评估项。
- **瘦身布局**：原生读取返回 `E_PHOTO_LAYOUT_UNSUPPORTED` 并由前端回退旧 JS 链路；该回退路径未在 E2E 中覆盖。
- **读取期故障注入**：worker 崩溃、磁盘满、查看中锁库未注入；由既有故障语义与后续 Phase 5 压测覆盖。
- **压力**：100 张快速切换、1,000 张网格滚动未测；LRU 与取消逻辑由前端单测覆盖。

## 5.3 G3 证据（Phase 3 原生导出与备份还原）

> 执行日期：2026-11-19。以下均为实际命令与结果；未执行项在 5.3.2 单独标注。

| 门禁 | 命令 | 结果 |
|---|---|---|
| worker 单测 | `cargo test`（`verthys-worker`） | 106 passed |
| worker 构建 | `cargo build`（`verthys-worker`） | PASS（debug） |
| 宿主单测 | `cargo test --lib`（`src-tauri`） | 584 passed / 2 ignored |
| 前端类型 | `npx vue-tsc --noEmit` | PASS |
| 前端全量单测 | `npx vitest run` | 90 文件 / 955 用例通过 |
| 文档门禁 | `ci/check_docs.ps1` | PASS（49 文件 / 195 链接） |

真实 worker + DLL 导出/还原 E2E（`worker_native_export_restore_e2e`，`VERTHYS_NATIVE_EXPORT_E2E=1`）：

- 环境：Windows 11 x64；debug `verthys-worker.exe`；`build/core/Release/verthys.dll`。
- 样本：`jpeg_10.jpg`（10,485,760 字节）与 `jpeg_17.73.jpg`（18,591,252 字节）。
- 覆盖与结果：
  - `original`：10MiB 照片导出 10,485,760 字节，与源文件逐字节一致。
  - `png`：10MiB 照片导出 11,522,543 字节，PNG 签名正确。
  - `venc-single`：两张照片一个容器 29,136,046 字节；魔数 `VENC`、版本 3；还原 2 张后按块读取与源文件逐字节一致。
  - `venc-multiple`：两个容器 10,515,302 / 18,620,895 字节；各还原 1 张并与源文件逐字节一致。
  - 取消：`photo_export_job_cancel` 后 `next` 返回 `cancelled`；`photo_restore_job_cancel` 同样收敛，`end` 正常释放。
  - 容器替换：预览 fileHash 顺序反转后，`next` 立即失败并提示“备份文件在预览后已变更”。
  - 错误令牌：`photo_restore_job_begin` 返回失败，错误归因 `TAG_VERIFICATION_FAILED`。
  - 总耗时：275.44s。
- 命令：

```powershell
$env:VERTHYS_NATIVE_EXPORT_E2E="1"
$env:VERTHYS_WORKER_E2E_WORKER="<repo>\verthys-tauri\verthys-worker\target\debug\verthys-worker.exe"
$env:VERTHYS_WORKER_E2E_DLL="<repo>\build\core\Release\verthys.dll"
$env:VERTHYS_NATIVE_E2E_DIR="<fixture-dir>"
cargo test worker_native_export_restore_e2e -- --nocapture
```

VENC 双向兼容：

- worker → 前端：E2E 落盘 `single.venc` / `multi_*.venc` 后，用前端 `unpackVencPreview` 与 `unpackVenc` 解析；`single.venc` 解析出 2 张、清单 fileHash 与导入哈希一致；`multi_*.venc` 各解析出 1 张，块字节总数等于清单 `size`。
- 前端 → worker：前端 `packVenc` 生成 579 字节容器（3 块，BLAKE3 `fdc026cf…`），worker `photo_restore_job_*` 还原 1 张并逐块读回一致；耗时 6.35s。
- 说明：帧 nonce 随机，容器字节不可能跨实现逐字节相等；兼容性判据为双向解析/还原成功与清单/块内容一致。

### 5.3.1 测试隔离

C TPM 测试与 worker 真实 E2E 仍不得并行运行：两者共享持久化 TPM 见证键，并行会产生 `ERR_00000019`（ROLLBACK）与后续 `Locked` 的假失败。本轮 worker 单测、宿主单测、E2E 串行执行。

### 5.3.2 未覆盖与已知限制

- **GUI 交互未自动化**：导出格式切换、进度渲染、取消、锁库、失败提示由用户手测。
- **吞吐指标未测**：导出吞吐未与磁盘写入上限对比；E2E 只验证字节正确性与事件流。
- **瘦身布局回退**：原生导出整批返回 `E_PHOTO_LAYOUT_UNSUPPORTED` 后，前端旧 JS 导出回退路径未在 E2E 中覆盖。
- **故障注入**：worker 崩溃、磁盘满、容器容量耗尽、2GB 边界未注入；2GB 上限由 worker 单测与代码路径覆盖。
- **去重性能**：还原时已 committed 条目仍会逐块解密/重封装以完成容器校验；正确性优先，后续可提前跳过。
- **大容器授权续期**：300s 滚动续期逻辑已实现，但未在 >600s 的真实大容器上实测。

## 5.4 G4/G5 证据（Phase 4 收口与 Phase 5 加固）

| 项 | 命令/操作 | 结果 | 结论 |
|---|---|---|---|
| Worker 回归 | `cargo test`（verthys-worker） | 107 passed | 已验证 |
| 宿主回归 | `cargo test --lib` | 584 passed / 2 ignored | 已验证 |
| 前端类型 | `npx vue-tsc --noEmit` | PASS | 已验证 |
| 前端回归 | `npx vitest run` | 82 文件 / 832 用例 | 已验证 |
| 导入 E2E | `worker_native_import_e2e` | 15 文件 / 214 块 / 883,068,764B；1,282,183ms；混合/超限/移动/取消通过 | 已验证 |
| 读取 E2E | `worker_native_read_e2e` | 10MiB 预览 572,861B、原图 3 块；100MiB 预览命中、原图 25 块；瘦身 `photo_meta_get` 通过；244.49s | 已验证 |
| 导出/还原 E2E | `worker_native_export_restore_e2e` | original 10,485,760B；PNG 11,522,543B；venc-single 29,136,046B 还原 2 张；取消/替换/错误令牌通过；264.66s | 已验证 |
| 静态零 JS 字节面 | `rg` 旧链路符号 | 桌面 `src` 零引用 | 已验证 |
| 4MiB 审计 | 常量与分段审查 | 写入/读取/导出/还原均 4MiB；旧 1MiB 可读 | 已验证 |
| worker kill / 磁盘满 | 无自动化注入 | 未执行 | 未验证 |
| SHM 篡改 | 照片数据面未使用 SHM | 不适用 | 不适用 |
| 1k 批量 / P95 | 未执行 | 未执行 | 未验证 |

未验证项的人工步骤见 `PHASE4-5-REPORT.md` §5。

## 6. 不达标处理

- 性能不达标：先归因（I/O、解码、C 调用、SHM、写者、UI），再优化；不得用降低功能/安全换取指标。
- 安全不达标：阻断发布；修复并复审。
- 兼容不达标：保留 1MiB/旧路径回退，4MiB 延后。
- 恢复不达标：阻断；先修 WAL/台账/取消语义。

## 7. 证据规范

- 每条结论必须指向：命令、样本、环境、原始数据、代码位置或测试用例。
- 禁止用“应该更快”“大致完成”作为验收结论。
- 未执行/无法执行的项必须显式标注为未验证，并说明原因与影响。
