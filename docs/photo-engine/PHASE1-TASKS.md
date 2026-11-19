# Phase 1 — 执行任务清单

> 状态：已完成 · 最后更新：2026-11-19 · 维护人：K1Super
>
> 顺序即依赖顺序。每项完成必须有实际命令与结果；未验证项标注原因。
> 完整门禁证据见 [06-verification.md](06-verification.md) 的 G1 证据节。

## T0 预算与分块口径整改（P0）

- [x] `verthys-tauri/constants/photo_budget.schema.json`
  - 新增 `photo_chunk_size = 4194304`。
  - 保留 `payload_chunk_size = 1048576`，仅作为旧 1MiB 数据兼容与块集最坏情况上界的推导口径。
- [x] `verthys-tauri/constants/generate.mjs`
  - `chunk_record_b64_max` 改由 `photo_chunk_size` 推导。
  - 新增 TS `PHOTO_CHUNK_SIZE_BYTES`、Rust `PB_PHOTO_CHUNK_SIZE_BYTES`。
  - 新增不变式：单条 4MiB 块密文 + JSON 头 ≤ 单次 IPC；两块同批 ≤ 单次 IPC；`photo_chunk_size` ≤ C 层 16MiB 明文上限。
  - `chunk_set_plain_max` 保留 1MiB 最坏情况推导，并注释原因。
  - 修正 `chunk_crypto_overhead`：64 → 74（内容标签 6 + 分片头 28 + nonce 24 + 认证标签 16）。
- [x] 运行 `node constants/generate.mjs`，再运行 `--check`。
- [x] `verthys-tauri/src/constants/crypto_const.ts`
  - 新增 `PHOTO_CHUNK_SIZE = PHOTO_CHUNK_SIZE_BYTES`。
  - `CHUNK_SIZE` 注释改为 VENC/容器帧口径。
- [x] `verthys-tauri/src/workers/photo-crypto.worker.ts`
  - `processPhoto` 与 `processSlimRepack` 改用 `PHOTO_CHUNK_SIZE`。
  - 注释同步为照片存储分块。
- [x] `verthys-tauri/src-tauri/src/worker/e2e_measure.rs`
  - 本地 `PHOTO_CHUNK_BYTES` 改为引用 `PB_PHOTO_CHUNK_SIZE_BYTES`，或增加编译期相等断言。
- 验证：`node constants/generate.mjs --check` PASS；前端相关单测 PASS；E2E 4MiB 矩阵 PASS。

## T1 边界回归测试

- [x] 分块公式测试：1B、4MiB、4MiB+1、17.73MiB、24.43MiB、50MiB、100MiB 的块数。
- [x] 100MiB 接受、100MiB+1 拒绝；确认拒绝来自 `photo_max_bytes` 而非协议预算。
- [x] 4MiB 块密文 base64 长度 ≤ `PB_CHUNK_RECORD_B64_MAX`；两块之和 ≤ `PB_IPC_MAX_PAYLOAD_BYTES`。
- [x] 存量 1MiB 块读取/导出回归（前端 mock + worker 单测）。
- 验证：前端全量 89 文件 / 947 用例通过；worker 81 用例通过；E2E 实测 `chunk_b64_max = 5,592,504`，无超限。

## T2 G0-A 半完成键

- [x] `core/src/security/tpm/vty_tpm_witness.c/.h`
  - 测试构建新增 `vty_tpm_witness_set_crash_after_create_for_test(int)`。
  - 创建路径在 `NCryptCreatePersistedKey` 前清理同槽残留；`NTE_EXISTS` 时删除并重试一次。
- [x] `core/tests/tools/vty_g0a_crash.c`
  - 新增 `halfkey` 模式：完成 create 后、finalize 前 `TerminateProcess`。
- [x] `core/tests/security/test_g0a_crash.c`
  - 新增半键崩溃用例：父进程重启后当前锚点仍有效，下一次提交成功；旧状态回放仍拒绝。
- 验证：`verthys_tests.exe g0a_crash_halfkey` → 2 passed；`witness` → 3 passed；`rollback` → 15 passed。

## T3 worker 媒体导入模块

- [x] `verthys-tauri/verthys-worker/src/runtime/media/mod.rs`
- [x] `verthys-tauri/verthys-worker/src/runtime/media/import_job.rs`
  - job 注册、队列、取消、统计、块级拉取状态机。
- [x] `verthys-tauri/verthys-worker/src/runtime/media/mime.rs`
  - 扩展名/MIME/文件头判定；拒绝非图片。
- [x] `verthys-tauri/verthys-worker/src/runtime/media/decoder.rs`
  - 尺寸、方向、缩略图输入；失败显式返回；RGBA8 统一转 RGB8 后编码 JPEG。
- [x] `verthys-tauri/verthys-worker/src/runtime/media/animated.rs`
  - GIF/WebP/APNG 三态检测。
- [x] `verthys-tauri/verthys-worker/src/runtime/mod.rs` 注册 `media`。
- [x] `verthys-tauri/verthys-worker/src/runtime/module_keys.rs`
  - 公开 `seal_photo_chunk` / `seal_photo_meta`，复用既有 `seal_inner` 语义。
- [x] `verthys-tauri/verthys-worker/src/runtime/dispatch.rs`
  - 新增 `photo_import_job_begin/next/finish/cancel/end`。
- 验证：worker `cargo test` 82 passed；真实 worker+DLL E2E 覆盖 JPEG/PNG/WebP/GIF/APNG、取消、超限、源移动。

## T4 job 级路径授权

- [x] `verthys-tauri/verthys-worker/src/runtime/path_grants.rs`
  - 新增 `JobGrant`：`job_id`、只读、≤10,000 路径、TTL 10 分钟、目标 op。
  - 成员校验；结束/取消/过期销毁。
- [x] 宿主签发入口（`src-tauri` 对应模块）批量签发，不逐路径 IPC。
- 验证：`path_grants` 单测覆盖 job 绑定、不消费、跨 job 拒绝、结束销毁、空/超 10k/相对路径拒绝。

## T5 宿主控制器与写者

- [x] `verthys-tauri/src-tauri/src/controller/photo_media_controller.rs`
  - `photo_import_start/cancel` 命令；job 注册、进度 Channel、结束回调。
  - 单 job 串行；≤10,000 路径切批；授权每 300s 滚动续期；成功且零失败触发孤儿块 GC。
- [x] `verthys-tauri/src-tauri/src/controller/mod.rs`、`lib.rs` 注册命令。
- [x] `verthys-tauri/src-tauri/src/state/mod.rs`
  - 新增照片导入 job 槽位与取消标志。
- [x] `verthys-tauri/src-tauri/src/state/import_writer.rs`
  - 复用现有 `AppendChunks` / `AppendPending`（台账、WAL、幂等块键无需第二套协议）。
- [x] `verthys-tauri/src-tauri/src/worker/protocol.rs`
  - 请求/响应类型与行上限校验由 worker 侧 `protocol.rs` 与既有会话读取上限承担；宿主仅发送 JSON 行并解析投影。
- 验证：`cargo check`、`cargo check --tests`、`cargo test --lib`（577 passed / 2 ignored）。

## T6 前端切换

- [x] `verthys-tauri/src/composables/photo-album/usePhotoImport.ts`
  - Tauri 分支切到 `photo_import_start`；浏览器分支保留现有 JS。
  - 进度、取消、失败列表、完成后刷新列表与缓存。
- [x] `verthys-tauri/src/lib/verthys.ts`
  - 新增命令封装与类型。
- [x] 功能开关 `photo.nativeImport`，默认启用；关闭即回滚旧前端流水线（旧链路待全部改造完成后删除）。
- 验证：`npx vue-tsc --noEmit` PASS；前端全量 89 文件 / 947 用例通过；新增开关关闭/开启两条用例。

## T7 G1 验证与文档

- [x] 真实 worker + DLL E2E：10/17.73/24.43/30/50/100MiB、五种格式、混合批量。
  - 结果：15 文件 / 214 块 / 883,068,764 字节 / 1,193,594ms；无超限违规。
- [x] 取消、源文件移动、100MiB+1 拒绝；worker 崩溃/应用崩溃/容量不足见下方未覆盖说明。
- [x] 旧 1MiB 块与旧 VENC 容器兼容（前端 VENC 1MiB/4MiB 帧往返测试 + 读取侧 `chunkIds` 逐块解析）。
- [x] 性能矩阵与 4MiB 记录数/公式核对（`chunks = ceil(size / 4MiB)` 全部吻合）。
- [x] 更新 `05-implementation.md`、`06-verification.md`、`BOUNDARY-AUDIT.md`；文档门禁与预算生成器门禁通过。

### T7 未覆盖（明确标注）

- 宿主 `photo_media_controller` 的 GUI 运行时路径（真实窗口选择文件、进度渲染）未自动化；其命令/写者接驳由编译、单测与 worker E2E 间接覆盖。
- worker 进程崩溃、应用崩溃、磁盘/容器容量耗尽的故障注入未在 E2E 中执行；现有 WAL/台账/孤儿 GC 语义由既有测试覆盖。
- 大批量（1,000/10,000 张）端到端吞吐未测；job 级授权上限与分批逻辑由单测覆盖。
