# G0-A2 — 批量导入的锚点推迟：C 层设计

> 状态：原型已实现（隔离构建，默认关闭） · 最后更新：2026-11-19 · 维护人：K1Super
>
> 目标：把回退锚点的推进从每次 `AddRecords` 中解耦，使一次批量导入只产生
> 少量锚点提交；在不关闭回退保护的前提下，把 TPM 建键速率从导入关键路径上移除。
>
> 前置依据：[G0-A-PROTOTYPE-REPORT.md](G0-A-PROTOTYPE-REPORT.md) 7.3.2 的 worker
> 端到端测量：默认 5.04s / G0-A 3.85s（10MiB 单样本，历史数据），预置池只把
> “同步建键”变成“等待建键”，锚点推进速率被 TPM 建键（约 0.5–0.65s/把）封顶。
> 本设计的尺寸矩阵实测见 [G0-A2-PROTOTYPE-REPORT.md](G0-A2-PROTOTYPE-REPORT.md)：
> 10/17.73/24.43/50MiB 全部验证，不以单一 10MiB 样本代替大图结论。
>
> 本文件只定义设计，不包含生产代码改动。

---

## 1. 现状

### 1.1 每次写入都推进锚点

```text
Verthys_AddRecords
  → verthys_api_container_add_many
      → vty_repo_add_many
          → repo_commit
              → vty_vault_commit_store
              → vty_vault_save_meta
                  → header.generation++
                  → 写非活动元数据副本 + 回读认证
                  → vty_rollback_commit(uuid, generation)   // TPM 建键/切键
```

- [verthys_api_container.c](file:///c:/Users/Administrator/Desktop/Verthys/core/src/api/verthys_api_container.c#L302-L313)
  的 `flush` 也调用 `vty_vault_save`，因此一次导入的每次批量写入与最终 Flush
  都会推进锚点。
- [vty_keymanager.c](file:///c:/Users/Administrator/Desktop/Verthys/core/src/crypto/vty_keymanager.c#L2455-L2493)
  在写元数据之后调用 `vty_rollback_commit`；轮换临时库通过
  `v->no_rollback_anchor = 1` 跳过该调用。
- 单张 S MiB 照片按 4MiB 分块会产生 `ceil(S/4)` 次块写入 + 1 次 meta/flush，
  即 `ceil(S/4)+1` 次锚点推进。例如 10MiB=4 次、17.73MiB=6 次、
  24.43MiB=8 次、50MiB=14 次；100 张 10MiB 约 400 次，100 张 24.43MiB 约 800 次。

### 1.2 已有的安全容忍

- `vty_rollback_check` 只拒绝 `container_generation < anchor_generation`，
  允许容器代**高于**锚点（[vty_rollback.c](file:///c:/Users/Administrator/Desktop/Verthys/core/src/security/rollback/vty_rollback.c#L541-L542)）。
- 打开流程在 `check` 之后立即 `commit`，把锚点推进到当前容器代
  （[vty_keymanager.c](file:///c:/Users/Administrator/Desktop/Verthys/core/src/crypto/vty_keymanager.c#L1599-L1615)）。
- 因此“锚点暂时落后于容器、下次解锁补推进”是既有语义；当前崩溃窗口最多
  落后 1 代（元数据写完、锚点未提交时崩溃）。

### 1.3 可复用机制

`VtyVault.no_rollback_anchor` 已经用于轮换临时库：保存元数据但不推进锚点。
本设计不改变该字段语义，新增独立的“批量导入推迟”状态，避免与轮换路径互相污染。

## 2. 目标与非目标

### 目标

1. 一次批量导入只产生少量锚点提交（由硬上限约束），导入数据写入不再逐次等待 TPM。
2. 保留“旧于锚点的容器必须拒绝”的回退保护；不关闭锚点、不延迟到“每次会话一次”之外。
3. 锚点滞后的深度与时长有硬上限，由 C 层强制，调用方不可突破。
4. 失败可见、可恢复；不静默降级为“无回退保护”。
5. 不改变容器格式、`rollback.state` 布局与 TPM 槽数量。

### 非目标

- 不引入 TPM NV 单调计数器。
- 不改变 G0-A 预置池的调度与安全约束。
- 不优化数据区写入吞吐（BulkAppend 另议）。
- 不放宽删除/改密/轮换等非导入写入的锚点推进语义。

## 3. 方案选项

| 选项 | 描述 | 结论 |
|---|---|---|
| A 显式导入会话 + 硬上限 | 新增 `Verthys_BulkImportBegin/Commit`；会话内保存不推进锚点，超过代数/时长上限时强制提交 | **推荐** |
| B `AddRecords` 隐式推迟 | 所有批量写入默认不推进锚点，由 Flush/Lock 或上限兜底 | 不推荐：把非导入批量写入也纳入回退窗口，调用方无法预期 |
| C 仅合并请求 | 只把多条记录合并进更少的 `add_records` | 不充分：12MiB IPC 预算下，单张 S MiB 仍需约 `S/4MiB` 次提交（10MiB 3 次、24.43MiB 7 次、50MiB 13 次），100 张放大到数百次 |
| D 会话内完全不推进 | 解锁后到锁定前只在结束时提交 | 拒绝：窗口不可控；除非产品明确接受且安全评审通过 |

推荐 A 的理由：推迟范围可被调用方精确限定在一次导入内；C 层仍保留硬上限，
即使宿主忘记结束会话也不会无限扩大窗口。

## 4. 语义与状态机

### 4.1 新状态

在 `VtyVault` 增加：

```c
uint8_t  defer_anchor;          /* 1=批量导入会话中，保存不推进锚点 */
uint64_t anchor_floor_gen;      /* 最近一次已提交锚点的 generation */
uint64_t anchor_defer_since_ms; /* 本次会话开始时刻（GetTickCount64） */
```

`no_rollback_anchor` 保持轮换专用；`vty_vault_save_meta` 的判定顺序：

```text
if (!rollback_enabled || no_rollback_anchor)         → 不推进（现状）
else if (!defer_anchor)                              → 正常推进
else if (generation - anchor_floor_gen >= MAX_GENS)  → 强制推进
else if (now - anchor_defer_since_ms >= MAX_MS)      → 强制推进
else                                                 → 跳过推进，更新滞后计数
```

`anchor_floor_gen` 在创建/打开成功后初始化为当前 generation（此时锚点已提交），
`Begin` 预提交成功后再次同步为当前 generation。

### 4.2 API

```c
/* 开始一次批量导入锚点推迟会话。
 * - 先把当前容器代推进到锚点（关闭导入前的窗口）；
 * - 置 defer_anchor；记录起始代与时刻；
 * - 已处于会话中时幂等返回 OK（不重置上限计时）。 */
VerthysResult Verthys_BulkImportBegin(VerthysHandle handle);

/* 结束会话并强制推进锚点到当前容器代。
 * - 未处于会话中：幂等返回 OK；
 * - 提交失败：清除会话并把库置为锁定（与 save_meta 失败路径一致），
 *   返回 VTY_E_ROLLBACK / VTY_E_TPM；下次解锁时补推进。 */
VerthysResult Verthys_BulkImportCommit(VerthysHandle handle);
```

新增 API 版本 `0x0015`；`.def` 增加两个导出；worker 侧按可选符号解析，
老 DLL 缺失时回退为“每次写入推进锚点”的现状路径。

### 4.3 允许与拒绝的操作

| 操作 | 推迟会话中 |
|---|---|
| `AddRecord` / `AddRecords` | 允许；保存时跳过锚点（受硬上限约束） |
| `Flush` | 强制推进锚点并保留会话（重置计时与 floor） |
| `BulkImportCommit` | 推进锚点并结束会话 |
| `DeleteRecord(s)` / `Import` / `ChangePassword` / PCR / keyfile / 模块 / 轮换 | 拒绝，返回 `VERTHYS_ERR_POLICY`；调用方应先结束会话 |
| `Lock` / `Deinit` | 尝试强制推进；失败仍释放密钥，并返回/记录错误 |
| `GetRecord` / 扫描 / 查询 | 允许 |

拒绝非导入写入的目的：把回退窗口严格限制在“新增记录”上，避免删除/改密被
窗口覆盖。

### 4.4 硬上限

| 常量 | 建议值 | 说明 |
|---|---|---|
| `VTY_ANCHOR_DEFER_MAX_GENS` | 32 | 最多滞后 32 代；按 4MiB 块，10MiB 照片 4 次保存约 8 张一次提交，24.43MiB 照片 8 次约 4 张，50MiB 照片 14 次约 2 张 |
| `VTY_ANCHOR_DEFER_MAX_MS` | 30000 | 单次会话最长 30s 不提交；超时在下一次保存时强制提交 |

上限编译进 C 层，不提供运行期放大接口。两个上限任一触发即提交，提交失败走
`v->unlocked = 0` 的既有 fail-closed 路径。

### 4.5 强制提交的时机

1. `Verthys_BulkImportBegin`：导入前把当前代推进到锚点。代数未变化时只做
   见证校验（约 15–47ms）；确实存在未推进的写入时才建键。
2. 保存路径超过代数/时长上限。
3. `Verthys_Flush`。
4. `Verthys_BulkImportCommit`。
5. `Verthys_Lock` / `Verthys_Deinit`：释放密钥前尽力提交；失败按 4.6 处理。
6. 任何被拒绝的非导入写入之前**不**隐式提交，直接拒绝，避免隐藏的长耗时操作。

### 4.6 失败处理

- 强制提交失败：会话锁定（`v->unlocked = 0`），返回错误；容器数据已落盘，
  下次解锁时 `check` 接受“容器代 >= 锚点”并补推进。
- `BulkImportCommit` 失败：清除会话、置库锁定并返回错误；不得继续写入。
  调用方需重新解锁（解锁路径会补推进锚点）。
- `Lock` 失败：密钥仍清零、句柄进入锁定态；返回错误让调用方提示“回退锚点
  未推进”。`Deinit` 无法返回错误，记录结构化日志。
- 不得在提交失败后继续接受写入。

## 5. C 层改动面

| 文件 | 改动 |
|---|---|
| `core/src/crypto/vty_keymanager.h` | `VtyVault` 新增推迟状态字段 |
| `core/src/crypto/vty_keymanager.c` | `vty_vault_save_meta` 按 4.1 判定；新增 `vty_vault_bulk_begin/commit`；初始化/清零字段 |
| `core/src/api/verthys_api_container.c/.h` | 新增 `verthys_api_container_bulk_begin/commit` |
| `core/src/api/lifecycle/verthys_api.c` | 新增公共入口；非导入写入的拒绝检查；`Lock` 强制提交 |
| `core/include/verthys.h` | 新增两个 ABI 声明；API 版本 0x0015 |
| `core/verthys.def` | 新增两个导出 |
| `core/src/api/shared/verthys_api_utils.c` | 会话释放前兜底（防御性） |
| `core/tests/security/test_g0a2_defer.c` | 新用例（见 8） |

不改动：容器格式、`rollback.state`、TPM 模块、G0-A 预置池、WAL/台账。

## 6. 跨层契约

- **worker**：新增 `bulk_import_begin` / `bulk_import_commit` 两个 op；按可选符号
  解析新 API，缺失时返回“不支持”，宿主回退旧路径。
- **宿主 import writer**：导入开始调用 begin，正常结束/取消/失败在 finally 中
  调用 commit；看门狗对超过 60s 未结束的会话强制 commit。
- **前端**：无新增命令；仍以导入开始/结束为边界。

## 7. 崩溃一致性矩阵

| 崩溃点 | 磁盘 | 锚点 | 恢复行为 |
|---|---|---|---|
| Begin 前 | 容器 G、锚点 G | G | 正常 |
| Begin 强制提交后 | 容器 G、锚点 G | G | 正常 |
| 导入中第 N 次保存后 | 容器 G+N、锚点 G | G | `check(G+N)` 通过；解锁补推进到 G+N |
| 触发上限的强制提交中 | 容器新代已写、锚点未写 | G | 同上；窗口 ≤ 上限 |
| Commit 成功后 | 容器 G+N、锚点 G+N | G+N | 正常 |
| Commit 失败 | 容器 G+N、锚点 G | G | 会话锁定；下次解锁补推进 |
| 导入中进程被杀 | 容器 G+N、锚点 G | G | 下次解锁补推进；G 之前的状态仍被拒绝 |

不变量：

- 容器代始终 ≥ 锚点代。
- 滞后 ≤ `MAX_GENS` 且 ≤ `MAX_MS`（除进程已退出、等待下次解锁的窗口）。
- 锚点提交失败后不再接受写入。
- 锚点代之前的状态一律拒绝。

## 8. 测试计划

### 功能

- Begin/Commit 幂等、未解锁、非容器格式、恢复会话。
- 会话中 `AddRecords` 不推进锚点；`Flush` 推进并保留会话。
- 非导入写入在会话中被拒绝。
- 代数上限：第 32 代未推进保存触发提交（diff ≥ 32）；时长上限：31s 后首次保存触发提交。
- `Lock`/`Deinit` 强制提交；提交失败注入 → 锁定/错误。
- 旧 DLL 缺失新符号时 worker 回退路径不变。

### 安全

- 回放：Commit 之前的容器副本在 Commit 后必须被拒绝。
- 回放：Commit 之前的容器副本在 Commit 前（窗口内）可以通过——确认这是
  设计允许的窗口，并记录窗口深度。
- 崩溃注入：导入中 kill、上限提交中 kill、Commit 中 kill；恢复后锚点补推进。
- 失败注入：`vty_tpm_witness_create/delete` 失败时不得返回成功。
- 并发：多线程 AddRecords 与会话边界。

### 性能

- worker 端到端尺寸矩阵：10 / 17.73 / 24.43 / 50 / 100MiB，
  对比关闭/开启推迟；记录每张照片的保存次数与锚点提交次数。
- 原型实测（2026-11-19，3 轮）：平均 419 / 702 / 978 / 1861ms，相对默认 DLL
  降幅 78.9%–84.7%。会话内单张照片通常不提交锚点；上限触发时按 32 代切分，
  100 张导入的提交次数 ≈ ⌈总保存次数/32⌉ + 1。100MiB 上限样本实测 3661ms（25 块），
  2.0s 目标不适用于该档，需按尺寸分档。

## 9. 开放问题

1. ~~上限取值（32 代 / 30s）~~：已接受固定值（2026-11-19）。
2. `BulkImportCommit` 失败后重新解锁即可补推进；是否需要专门的产品提示与
   恢复工具。
3. ~~`Lock` 提交失败是否返回错误~~：已决定返回错误，密钥仍清零。
4. 新 API 是否需要限制调用方（仅 worker）或按预设档位禁用。
5. ~~是否允许在推迟会话中执行删除~~：已决定拒绝，返回 `VERTHYS_ERR_POLICY`。

## 10. 结论

- 方案 A 可把锚点提交次数从“每次写入”降到“每个导入会话 + 每 32 代/30s”。
- 预置池与推迟提交互补：稀疏提交让后台建键有充足时间，提交走快路径。
- 方案 A 已在隔离原型落地：13 项用例通过，尺寸矩阵 10/17.73/24.43/50/100MiB
  相对默认 DLL 降幅 77.6%–84.7%；默认构建未合并。
- 进入 Phase 1 前仍需 G0-A 断电/FinalizeKey、完整 UI E2E 与 `ANCHOR_DIRTY`
  产品确认；100MiB 边界已实测 3661ms，需按尺寸档位设定目标。
