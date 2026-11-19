# G0-A2 — 批量导入锚点推迟：隔离原型报告

> 状态：原型完成（隔离构建，默认关闭） · 最后更新：2026-11-19 · 维护人：K1Super
>
> 设计依据：[G0-A2-DEFERRED-ANCHOR-DESIGN.md](G0-A2-DEFERRED-ANCHOR-DESIGN.md)
>
> 安全评审：[G0-A2-SECURITY-REVIEW.md](G0-A2-SECURITY-REVIEW.md)（有条件通过原型）
>
> 结论：方案 A 已按评审前置条件落地，C/API 层、worker 接驳、崩溃注入与
> 端到端测量均可复现；未进入 Phase 1，未合并默认构建。

---

## 1. 交付范围

| 层 | 内容 |
|---|---|
| 构建 | `VERTHYS_G0A2_PROTOTYPE`（默认 OFF，强制依赖 `VERTHYS_G0A_PROTOTYPE=ON`） |
| C 层 | `VtyVault` 推迟状态、保存路径上限判定、`vty_vault_bulk_begin/commit/flush`、Lock/Deinit 收口 |
| 公共 API | `Verthys_BulkImportBegin/Commit`，API 版本 0x0015（仅原型构建可见） |
| 导出 | 原型构建在生成目录追加两个导出；默认构建仍使用仓库 `verthys.def` |
| 拒绝清单 | 删除/导入/改密/PCR/keyfile/模块/恢复码轮换/全库轮换返回 `VERTHYS_ERR_POLICY` |
| worker | `bulk_import_begin/commit` op，可选符号解析，缺符号返回 `unsupported` |
| 宿主 | 导入开始 Begin、结束/取消/失败 Commit；60s 看门狗；旧 DLL 回退逐次提交 |
| 用例 | `core/tests/security/test_g0a2_defer.c`（13 项）+ `tools/vty_g0a2_crash.c` |

不改动：容器格式、`rollback.state` 布局、TPM 槽数量、G0-A 预置池调度。

## 2. C 层实现要点

### 2.1 状态与判定

`VtyVault` 新增（仅原型构建编译）：

- `defer_anchor`：会话标志；
- `anchor_floor_gen`：最近一次已提交锚点的代；
- `anchor_defer_since_ms`：窗口起点（`GetTickCount64`）。

`save_internal` 在容器元数据落盘并回读认证后判定：

```text
no_rollback_anchor=1                → 不推进（轮换临时库，现状）
defer_anchor=0                      → 正常推进（现状）
lag >= 32 或 elapsed >= 30s         → 强制推进并重置窗口
否则                                → 跳过推进
```

上限常量 `VTY_ANCHOR_DEFER_MAX_GENS=32`、`VTY_ANCHOR_DEFER_MAX_MS=30000`
编译进 C 层，无运行期放大接口。

### 2.2 Begin / Commit / Flush

- Begin：先 `vty_rollback_commit(当前代)`，成功后才置会话；重复 Begin 幂等且不重置计时。
- Commit：提交到当前代；失败清除会话、`unlocked=0` 并返回原始错误。
- Flush：提交锚点、保留会话并重置窗口；锚点已最新时只重置计时。
- Lock：提交失败仍清零密钥，返回错误；Deinit 失败输出固定诊断串（不含路径/UUID）。
- 打开路径成功提交后同步 `anchor_floor_gen`，`vty_vault_lock` 清零全部推迟字段。

### 2.3 公共 API 与拒绝清单

- 未解锁返回 `VERTHYS_ERR_LOCKED`；非容器返回 `VERTHYS_ERR_FORMAT`。
- 已存在轮换作业时 Begin 返回 `VERTHYS_ERR_POLICY`。
- 会话内拒绝下列入口（均在 `api_mutex` 内判定）：
  `DeleteRecord(s)`、`Import`、`ChangePassword`、PCR 启停/重密封、
  keyfile 启停、设备重封、模块启用/改密/禁用/删除/绑定恢复/重封、
  恢复码轮换、轮换 Begin/AttachKeyfile/UnlockModule/Run/Commit。
- `GetRecord`/扫描/`AddRecord(s)`/`Flush` 保持可用。

## 3. 验证证据

### 3.1 构建与用例

| 构建 | 结果 |
|---|---|
| `build_g0a`（G0A=ON + G0A2=ON + TEST_HOOKS=ON，Release） | 编译通过 |
| `g0a2` 用例组 | **13 passed / 0 failed** |
| `g0a` 用例组 | 16 passed / 0 failed |
| `rollback` | 15 passed / 0 failed |
| `witness` | 3 passed / 0 failed |
| `build_verify`（G0A=OFF + G0A2=OFF，Release） | 编译通过 |
| 默认构建 `rollback` / `witness` | 15/15、3/3 |

导出面（dumpbin）：

- 原型 DLL：`Verthys_BulkImportBegin`、`Verthys_BulkImportCommit` 存在。
- 默认 DLL：两符号均不存在；导出白名单未变。

### 3.2 用例覆盖

- Begin 预提交后窗口打开；Commit 后旧代回放被拒绝。
- Begin/Commit 幂等、未解锁、非容器（白盒构造 `UNLOCKED + FMT_NONE`）。
- 第 32 代未推进保存触发提交（31 代滞后时窗口仍开放）。
- 时长上限：白盒把窗口起点回拨 31s 后首次保存触发提交（未真实等待 31s）。
- 会话内 19 个非导入写入口全部返回 `VERTHYS_ERR_POLICY`，且不改变会话状态。
- Flush 提交锚点并保留会话；Lock 提交后旧代被拒绝。
- Commit 失败（删除 + 撤销/建键注入失败）→ `VERTHYS_ERR_TPM`、会话锁定；
  清除注入并模拟重启（`vty_rollback_shutdown`）后重新解锁补推进成功。
- 并发：2 线程各 8 次 `AddRecord` 与会话边界串行，最终 16 条记录一致。
- 崩溃注入（子进程 `vty_g0a2_crash.exe`）：
  - 导入中（gen5）被杀：锚点仍为 2，窗口开放；重开后锚点补推进到 5。
  - 第 32 次保存触发上限提交，在“新键已建、状态未写”被杀：锚点仍为 2。
  - Commit 在“状态已写、旧键未退役”被杀：锚点 4 有效，gen3 回放被拒绝。

### 3.3 worker 端到端：尺寸矩阵（3 轮，batch=0，flush=1）

**尺寸口径**：产品单文件上限为 100MiB（`photo_budget.schema.json` 的
`photo_max_bytes`），10MiB 只是样本之一，不是产品边界。分块固定 4MiB，
块数 = `ceil(字节数 / 4MiB)`。本矩阵同时覆盖用户实际存在的 17.73MiB 与
24.43MiB，并覆盖 50MiB 与 100MiB 产品上限验证线性扩展。

| 照片（MiB） | 字节数 | 4MiB 块数 | 默认 DLL 平均 | G0-A2 推迟平均 | 降幅 | G0-A2 各轮 total |
|---|---|---|---|---|---|---|
| 10.00 | 10,485,760 | 3 | 2737 ms | **419 ms** | 84.7% | 418 / 433 / 407 |
| 17.73 | 18,591,252 | 5 | 3975 ms | **702 ms** | 82.3% | 717 / 698 / 693 |
| 24.43 | 25,616,712 | 7 | 5010 ms | **978 ms** | 80.5% | 981 / 993 / 962 |
| 50.00 | 52,428,800 | 13 | 8805 ms | **1861 ms** | 78.9% | 1849 / 1866 / 1870 |
| 100.00（上限） | 104,857,600 | 25 | 16372 ms | **3661 ms** | 77.6% | 3650 / 3656 / 3677 |

- 每轮写入一张完整照片（全部块记录 + meta）后 flush；平均值为 3 轮算术平均，
  不含建库与解锁耗时。
- G0-A2 的 `add_records` 耗时随块数近似线性：10MiB 3 块约 348ms（≈116ms/块），
  50MiB 13 块约 1715ms（≈132ms/块）。默认 DLL 每次 `add_records` 都推进锚点，
  耗时同样随块数线性增长，因此大图差距不会因样本变大而消失。
- 两次独立矩阵运行：10MiB 419–443ms、24.43MiB 956–993ms，波动 <6%。
- 设计中的 ≤2.0s 目标原以 10MiB 样本定义；17.73/24.43/50MiB 均低于 2.0s。
  100MiB 上限样本实测 3661ms，超过 2.0s；大尺寸不能用单一样本目标衡量，
  Phase 1 需按尺寸分档冻结（例如 ≤50MiB 与 100MiB 分档）。
- 默认 DLL 下 Begin 返回 `unsupported: Verthys_BulkImportBegin`，宿主回退后
  耗时与默认基线一致，未出现静默降级。

产物（构建产物，未入库）：

- `build_g0a/worker_e2e/result_g0a2_defer_sizes.json`（10/17.73/24.43/50MiB）
- `build_verify/worker_e2e/result_default_sizes.json`（同上）
- `build_g0a/worker_e2e/result_g0a2_defer_100mib.json`（100MiB 上限）
- `build_verify/worker_e2e/result_default_100mib.json`（100MiB 上限）

早期的单尺寸结果（2893ms）使用旧测量口径，与本次 4MiB 生产分块矩阵不可
直接比较；该结果已废弃，不作为结论依据。

### 3.4 大尺寸照片路径审计（生产代码）

结论：生产代码不存在 10MiB 硬上限或“10MiB 照片”分支；10MiB 只出现在基准
样本与历史报告中。10/17.73/24.43/50/100MiB 走同一条分块、批量与写入路径。

| 层 | 实际约束 | 证据 |
|---|---|---|
| 前端上限 | 单文件 100MiB，超限拒绝；未知大小的内存预算按 100MiB 保守占用 | [photo_budget.schema.json](file:///c:/Users/Administrator/Desktop/Verthys/verthys-tauri/constants/photo_budget.schema.json#L19)、[importPipeline.ts](file:///c:/Users/Administrator/Desktop/Verthys/verthys-tauri/src/composables/photo-album/importPipeline.ts#L1375-L1381) |
| 分块 | 4MiB 明文块；块数由 `ceil(size / CHUNK_SIZE)` 计算，无固定张数假设 | [photo-crypto.worker.ts](file:///c:/Users/Administrator/Desktop/Verthys/verthys-tauri/src/workers/photo-crypto.worker.ts#L274-L285) |
| 前端块上传 | 每批 ≤32 块且 ≤IPC 预算 80%，按块数/载荷双预算贪心切批 | [chunkUploadCoordinator.ts](file:///c:/Users/Administrator/Desktop/Verthys/verthys-tauri/src/composables/photo-album/chunkUploadCoordinator.ts#L94-L101) |
| 宿主批量写入 | 每子批 ≤128 条且 ≤IPC 预算 80%，超限自动切子批 | [import_writer.rs](file:///c:/Users/Administrator/Desktop/Verthys/verthys-tauri/src-tauri/src/state/import_writer.rs#L366-L376) |
| C/worker | 只接收块记录与 meta；G0-A2 只改变锚点推进时机，不限制照片大小 | 本报告 §2 与 13 项用例 |

因此本次整改不引入新的“大图特例”：测量、报告与门禁都以尺寸矩阵为准，
禁止再用单一 10MiB 结果代替大尺寸结论。

## 4. 复现命令

```powershell
cmake -S . -B build_g0a -G "Visual Studio 18 2026" -A x64 `
      -DVERTHYS_G0A_PROTOTYPE=ON -DVERTHYS_G0A2_PROTOTYPE=ON -DVERTHYS_TEST_HOOKS=ON
cmake --build build_g0a --config Release --target verthys_tests --parallel
build_g0a\core\tests\Release\verthys_tests.exe g0a2

cmake -S . -B build_verify -G "Visual Studio 18 2026" -A x64 `
      -DVERTHYS_TEST_HOOKS=ON -DVERTHYS_G0A_PROTOTYPE=OFF -DVERTHYS_G0A2_PROTOTYPE=OFF
cmake --build build_verify --config Release --target verthys_tests --parallel
build_verify\core\tests\Release\verthys_tests.exe rollback
```

worker E2E：按目标 DLL 重建 worker（原型 DLL 需额外设置
`VERTHYS_WORKER_API_VERSION=0x0015`，使 worker 接受 0x0015）。宿主 Release
构建会校验 `src-tauri/binaries` 与 `verthys-worker/target/release` 的产物哈希，
测量前需把原型 worker 临时复制到这两个位置，测完恢复原基线。

```powershell
cargo test --release --manifest-path verthys-tauri/src-tauri/Cargo.toml `
      worker_import_e2e_measure --no-run

# release 安装目录守卫要求宿主位于 target\release 根目录：
# 把 target\release\deps\verthys_tauri_lib-*.exe 复制到 target\release\ 后运行
$env:VERTHYS_TEST_MACHINE_LIMITER_BYPASS="1"  # 仅 TEST_HOOKS 构建；生产无此分支
$env:VERTHYS_WORKER_E2E="1"
$env:VERTHYS_WORKER_E2E_WORKER="<仓库>\build_g0a\worker_e2e\verthys-worker.exe"
$env:VERTHYS_WORKER_E2E_DLL="<仓库>\build_g0a\worker_e2e\verthys.dll"
$env:VERTHYS_WORKER_E2E_PHOTO_SIZES_MB="10,17.73,24.43,50"
$env:VERTHYS_WORKER_E2E_ROUNDS="3"
$env:VERTHYS_WORKER_E2E_DEFER="1"
$env:VERTHYS_WORKER_E2E_JSON="<仓库>\build_g0a\worker_e2e\result_g0a2_defer_sizes.json"
& "<仓库>\verthys-tauri\src-tauri\target\release\verthys_tauri_lib-<hash>.exe" `
  worker_import_e2e_measure --nocapture
```

精确字节数可用 `VERTHYS_WORKER_E2E_PHOTO_BYTES`；默认基线把 `DEFER` 置 0 并
换用默认 DLL/worker。机器级限流旁路只存在于 `VERTHYS_TEST_HOOKS` 构建，
用于避免反复测量消耗开发机服务预算；生产构建仍 fail-closed。

## 5. 残余风险与限制

| 项 | 说明 |
|---|---|
| 窗口内可回放新增记录 | 最多 32 代 / 30s；只覆盖新增，删除/改密等在会话中被拒绝 |
| 进程空闲延长窗口时间 | 宿主 60s 看门狗强制 Commit；空闲不扩大滞后代数 |
| 上限触发提交失败 | 容器已落盘但 API 报错；会话锁定，下次解锁补推进（与既有语义一致） |
| 时长上限用例 | 使用白盒回拨窗口起点，未真实等待 31s；生产上限值未被修改 |
| 宿主看门狗 | 已实现 60s 异步任务，但未做自动化宿主级用例 |
| Deinit 失败可见性 | 无结构化日志设施，仅输出固定 `OutputDebugStringA` 串 |
| 数据区吞吐 | 未优化；G0-A2 下 4MiB 块约 110–137ms，50MiB 约 1.9s，100MiB 上限约 3.7s；大尺寸仍慢于交互级目标，Phase 1 需按档位优化 |
| 多进程写同一 vault | 超出设计范围；导入写者必须保持单写者 |
| 旧 DLL 兼容 | 缺符号返回 `unsupported`，宿主逐次提交；无静默降级 |

## 6. 决策与剩余门禁

已决策（2026-11-19）：

1. 原型范围：C/API 层 + worker 接驳。
2. 接受 32 代 / 30s 固定上限。
3. `Lock` 在锚点提交失败时返回错误，密钥仍清零。
4. 推迟会话中拒绝删除，返回 `VERTHYS_ERR_POLICY`。

进入 Phase 1 前仍需：

1. G0-A 断电 / `FinalizeKey` 半完成键注入与恢复验证。
2. 完整 Tauri UI 链路端到端测量（前端加密、缩略图、宿主 WAL）。
3. `ANCHOR_DIRTY` 恢复流程产品确认。
