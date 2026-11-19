# G0-A — 隔离原型报告

> 状态：原型通过（有条件）；生产化原型（隔离构建）通过（有条件） · 最后更新：2026-11-18 · 维护人：K1Super
>
> 原型位置：第 1–6 节为系统临时目录中的独立 C 程序；第 7 节为仓库内 `VERTHYS_G0A_PROTOTYPE` 隔离构建。
> 两者都不改变默认构建行为，不进入 Phase 1 生产实现。
>
> 目的：验证 TPM 见证密钥预置的提交快路径、旧键失效、撤销回退、新库门禁、清理与两槽吞吐。
>
> 尺寸说明：本报告的 10MB 为当次测量样本（10MiB），不是产品上限；17.73/24.43/50MiB
> 矩阵见 [G0-A2-PROTOTYPE-REPORT.md](G0-A2-PROTOTYPE-REPORT.md)。

---

## 1. 原型范围

实现了一个最小见证池：

- 真实 TPM 持久化 ECDSA P-256 键（CNG Platform Crypto Provider）
- A/B 两槽：当前槽 + 预置槽
- 后台线程预创建下一把键，提交路径切换已就绪键
- 状态文件原子写（临时文件 + fsync + rename）
- 提交后删除旧键；删除失败路径提供 revoke（OVERWRITE 原槽）
- 新库首次提交前不预置
- 停止后台线程后清理未引用槽

原型不包含：真实 `rollback.state` MAC/设备密钥封装、已验证条目缓存、并发多库、故障注入删除失败、真实容器提交。生产集成仍需补这些项。

## 2. 实测结果

环境：Windows 11，真实 TPM/CNG，临时目录状态文件。

| 用例 | 结果 |
|---|---|
| 新库首次提交（同步建键） | 447.43ms |
| 后台预置完成 | 389.16ms |
| 预置快路径提交 ×5 | 15.38 / 15.42 / 15.70 / 15.72 / 16.58ms，平均 15.76ms |
| 快路径是否使用同步回退 | 0 次 |
| 旧键提交后仍匹配 | 0（已失效） |
| revoke 前旧指纹匹配 | 1 |
| revoke 后旧指纹匹配 | 0 |
| 清理后当前槽仍匹配 | 1 |
| 清理后非当前槽仍匹配 | 0 |
| 清理后当前键删除 | 0（已不存在） |

### 两槽饥饿

| 提交间隔 | 预置命中 | 同步回退 |
|---|---|---|
| 0ms | 2 | 2 |
| 300ms | 2 | 2 |
| 600ms | 3 | 1 |

结论：预置建键约 389–640ms；两槽在连续提交下会饥饿。**导入必须批量提交，不能按照片/每小批推进锚点**；若一次导入有 AddRecords + Flush 两次连续提交，第二次可能回退到同步建键，需要在导入写者层合并提交。

## 3. 验证结论

### 通过

1. 预置键可把提交路径从约 447ms 降到约 15.7ms；约 28 倍改善。
2. 预置键真实存在、Finalize 成功、指纹可用；提交后旧键失效。
3. 删除失败时的 revoke 逻辑可以立即使旧指纹失效（错误路径验证）。
4. 新库首次提交不依赖预置，预置在首次提交后启动；不会触发 `any_new` 误判。
5. 停止后台线程后可清理非当前槽，当前状态仍有效。
6. 真实 TPM 上 A/B 两槽 + 后台建键可行。

### 未通过/未覆盖

1. **15.7ms 仍高于设计预估 5–10ms**；主要来自状态文件 fsync/rename 与当前进程环境。生产需重新测量并优化到目标或调整目标。
2. **未实现已验证条目缓存**；生产提交若每次 TPM 校验，可能再增加 15–47ms，并加剧后台建键争用。
3. **未注入真实删除失败**；revoke 是单独验证的，生产必须做故障注入并证明 fail-closed。
4. **未接入真实 `rollback.state` MAC/设备密钥封装**；原型状态文件无 MAC，不能替代生产安全验证。
5. **未验证并发多库、进程崩溃/断电、后台线程关闭竞态**。
6. 两槽饥饿证明批量提交是硬约束，不是可选优化。

## 4. 对设计的修订

1. 提交快路径目标从“5–10ms”改为“≤20ms（原型 15.7ms）”；生产验证后再冻结。
2. 导入写者必须把 AddRecords + Flush + 锚点推进合并为尽量少的提交；禁止每张照片提交。
3. 两槽足够的前提是提交间隔 >~600ms 或批量足够大；否则同步回退，性能退化到 447ms。
4. 生产实现必须包含：
   - 已验证条目缓存（完整字段比较）
   - 旧键删除失败注入 + revoke/fail-closed
   - 真实状态 MAC/设备密钥封装
   - 并发多库/锁顺序
   - 崩溃矩阵与上传前清理
   - shutdown/join 与孤儿键清理
5. 10MB 导入理论值需在接入真实容器后复测；原型只证明提交段可降到 ~16ms，不证明端到端 250ms。

## 5. 原型判定

**有条件通过**：

- 设计可行，预置快路径收益明确。
- 允许进入 G0-A 生产化原型（隔离分支/测试目标），补齐未覆盖项。
- 在真实容器 + 真实 `rollback.state` + 故障注入 + 端到端导入测量通过前，不进入 Phase 1 生产实现。

## 6. 证据

- 原型源码与构建产物位于系统临时目录，不纳入仓库。
- 关键输出：

```text
first_commit_sync 447.43ms
first_ready bg_ok=1 last_bg_ms=389.16
commit avg 15.76ms min 15.38ms max 16.58ms sync=0
old_key_after_commit matches=0
revoke_test before=1 after=0
starvation interval=0 ready=2 sync=2
starvation interval=300 ready=2 sync=2
starvation interval=600 ready=3 sync=1
cleanup current=1 other=0
```

## 7. 生产化原型（仓库内隔离构建）

### 7.1 隔离方式

| 项 | 实现 |
|---|---|
| 编译开关 | `VERTHYS_G0A_PROTOTYPE`，默认 `OFF`；打开后仅向两个对象库与测试目标注入同名宏 |
| 源文件 | 新增 `vty_witness_pool.c/.h`，仅在开关打开时加入 `VERTHYS_SHARED_SOURCES` |
| 代码隔离 | `vty_rollback.c` 的预置/缓存/撤销/清理/shutdown 路径全部包在 `#if VERTHYS_G0A_PROTOTYPE` 内；默认构建保留原提交函数体 |
| 核心钩子 | `Verthys_Deinit` 在最后一个上下文注销后调用 `vty_rollback_shutdown()`，同样受开关保护 |
| 测试 | 新增 `test_g0a_prototype.c`，仅在开关 + `VERTHYS_TEST_HOOKS` 构建编译并注册 |
| 构建目录 | `build_g0a`（原型）；`build_verify`（默认关闭，用于对照） |

默认构建未定义该宏时，不编译预置池、不创建后台线程、不改变 `vty_rollback_commit` 的执行路径。

复现命令：

```text
cmake -S . -B build_g0a -G "Visual Studio 18 2026" -A x64 \
      -DVERTHYS_G0A_PROTOTYPE=ON -DVERTHYS_TEST_HOOKS=ON
cmake --build build_g0a --config Release --target verthys_tests
build_g0a\core\tests\Release\verthys_tests.exe g0a
```

### 7.2 已补齐的安全评审前置条件

| 评审项 | 实现与证据 |
|---|---|
| F1 旧键删除失败 | 删除失败 → `NCryptCreatePersistedKey(OVERWRITE)` 撤销原槽，使旧指纹立即失效；撤销也失败 → `ANCHOR_DIRTY`，提交返回错误且后续提交 fail-closed。故障注入用例 `g0a_delete_failure_revokes_old_key`、`g0a_delete_and_revoke_failure_fails_closed` 通过 |
| F2 新库首次提交前不预置 | 预置只在状态已存在该库条目且当前见证验证通过后调度；新库首次提交仍同步建键。用例 `g0a_new_vault_has_no_preset_before_first_commit` 通过 |
| F3 预置键使用前验证 | `vty_witness_pool_take` 在返回前重新 `NCryptOpenKey + ExportKey` 比对指纹；失败则删除该键并同步回退 |
| F4 已验证条目缓存 | 每库只保留最新一条 `uuid + generation + slot + fingerprint`，逐字段比较；状态 MAC 先于缓存判断；回放旧状态不会命中旧缓存。用例 `g0a_cached_verify_rejects_state_replay`、`g0a_cache_never_bypasses_state_mac` 通过 |
| F5/F6 槽位与崩溃清理 | 后台只写非当前槽；`vty_rollback_check` 在验证通过后删除/撤销非当前槽，失败即 fail-closed；锁顺序固定 `RollbackState → pool lock` |
| F7 两槽饥饿 | 后台建键进行中时提交释放状态锁等待（上限 5s），随后重新加载复核 generation；无预置且无建键时同步回退 |
| F8 shutdown | `vty_rollback_shutdown` 停止事件 + join，随后清空池、缓存与脏标记；不在 `DllMain` 内做 TPM/线程操作 |

### 7.3 实测结果

环境：Windows 11，真实 TPM/CNG，真实 `rollback.state`（含设备根 MAC），真实容器。

| 用例 | 结果 |
|---|---|
| 首次提交（同步建键） | 406–438ms |
| 预置就绪后提交（模块级） | 31–47ms（含预置键指纹复核） |
| 真实容器 `vty_vault_save`（预置就绪） | 15–78ms（多次运行的首次 save） |
| 紧随其后的第二次 save（后台建键未完成） | 406–531ms（等待后台建键，非同步建键） |
| 解锁后立即提交（后台建键中） | 438–531ms，提交成功且未跳过锚点 |
| shutdown 后提交 | 422–515ms（同步回退，池可重启） |
| 删除失败一次后的旧状态回放 | 拒绝（撤销生效） |
| 删除 + 撤销同时失败 | 提交返回 `VTY_E_TPM`，后续提交 `VTY_E_ROLLBACK` |
| 三库并发提交（每库两次） | 全部成功，最终状态校验通过 |
| 进程级崩溃注入（6 个窗口） | 全部恢复通过；旧状态回放按窗口预期拒绝 |

### 7.3.1 崩溃注入

实现：`vty_g0a_crash.exe`（仅原型 + 测试钩子构建）在独立进程中推进锚点，
到达指定提交阶段后直接 `TerminateProcess`；父测试进程校验退出码
`0xC0DE0000|point`，再模拟重启完成恢复断言。

| 崩溃点 | 崩溃时磁盘/TPM 状态 | 恢复断言 | 结果 |
|---|---|---|---|
| 同步：新键已建、状态未写 | 旧状态 gen2/slot1；slot0 残留新键 | `check(2)` 通过；无脏标记 | 通过 |
| 同步：状态已写、旧键未退役 | 新状态 gen3/slot0；slot1 旧键残留 | `check(3)` 通过；回放 gen2 状态被拒绝 | 通过 |
| 同步：旧键已退役 | 新状态 gen3/slot0；两槽仅新键 | `check(3)` 通过；回放 gen2 状态被拒绝 | 通过 |
| 预置：已就绪、提交未取用 | 旧状态 gen2/slot1；slot0 预置键 | `check(2)` 通过；残留预置键不影响恢复 | 通过 |
| 预置：已取用、状态未写 | 旧状态 gen2/slot1；slot0 预置键仍在 | `check(2)` 通过 | 通过 |
| 预置：状态已写、旧键未退役 | 新状态 gen3/slot0；slot1 旧键残留 | `check(3)` 通过；回放 gen2 状态被拒绝 | 通过 |
| 半完成键：create 后、Finalize 前 | 旧状态 gen2/slot1；slot0 残留不可导出键 | `check(2)` 通过；`commit(3)` 成功；回放 gen2 被拒绝 | 通过 |
| 首次提交半完成键 | 状态缺失；slot0 残留不可导出键 | `check(1)` 通过；`commit(1)` 成功 | 通过 |

说明：

- 崩溃点覆盖 `VTY_RB_CRASH_COMMIT_ENTER`、`AFTER_NEW_KEY`、`AFTER_STORE`、
  `AFTER_RETIRE`；子进程被强制终止，不做任何清理。
- “回放 gen2 被拒绝”在恢复后的 `check` 中验证：启动清理已删除/撤销旧槽键。
- 半完成键通过 `vty_tpm_witness_set_crash_after_create_for_test` 在
  `NCryptCreatePersistedKey` 成功后、`FinalizeKey` 前终止进程；残留键不可导出
  公钥，因此不计为有效见证。创建路径在失败时清理同槽并重试一次，下一次提交
  可正常覆盖，不再永久 fail-closed。

### 7.3.2 worker 端到端

测量方式：真实 `verthys-worker.exe` + 真实 `verthys.dll`，经签名 IPC、JSON、
base64 执行 `v4_create` → `unlock` → `add_records` → `flush`。worker 以
release 构建，并分别按 G0-A / 默认 DLL 的 SHA-256 基线重新构建；
宿主测试运行在 debug 构建（注入测试机预算旁路）。

不包含：前端加密、缩略图生成、宿主 WAL 与命令层调度。

| 场景 | 默认 | G0-A | 改善 |
|---|---|---|---|
| 10MB 照片：4 次 `add_records` + `flush`（5 次锚点推进） | 5041ms | 3854ms | 23.5% |
| 4MB 照片：1 次批量 `add_records` + `flush`（2 次） | 2073ms | 1654ms | 20.2% |
| 4MB 照片：1 次批量 `add_records`，无 flush（1 次） | 1619ms | 1218ms | 24.8% |

分阶段（G0-A）：worker 就绪 53–68ms，建库 535–642ms，解锁 771–1074ms。
默认：就绪 50–66ms，建库 563–577ms，解锁 387–465ms。

关键结论：

1. **G0-A 在 worker 端到端只有约 20–25% 改善，不是提交级的 10 倍。**
2. 原因：`add_records` 内部经 `verthys_api_container_add_many` 调用
   `vty_vault_save`（[verthys_api_container.c](file:///c:/Users/Administrator/Desktop/Verthys/core/src/api/verthys_api_container.c#L311)），
   每次批量写入都推进锚点。一张 10MB 照片产生 5 次推进。
3. 预置键创建约 0.5–0.65s/把，锚点推进速率被 TPM 建键速率封顶在约
   1.5–2 次/秒；下一次提交若在后台建键完成前到达，必须等待。预置池把
   “同步建键”变成“等待建键”，提高不了这个上限。
4. 仅把多条记录合并进一次 `add_records` 不足以解决：12MiB base64 IPC 预算下，
   10MB 照片仍需 2–3 次写入，100 张照片约 200–300 次锚点推进，按当前上限
   需要 100–200s 的纯等待。
5. 因此 Phase 1 导入写者必须把锚点推进从每次 `add_records` 中解耦
   （会话结束/每 N 秒/每批一次），或者引入可控的延迟锚点语义。后者会扩大
   “容器已更新、锚点未推进”的回退窗口，必须单独安全评审并证明崩溃后
   “容器代高于锚点可补推进、容器回退仍拒绝”。
6. 本测量是 worker 数据面基线；接入前端加密、缩略图与宿主 WAL 后，端到端
   导入只会更慢。原“10MB ≤250ms”在现有提交模型下仍不可达。

复现：

```text
# 1) 按目标 DLL 重建 release worker（构建期固化 DLL SHA-256 基线）
$env:VERTHYS_DLL_PATH="<dll 绝对路径>"
cargo build --release --manifest-path verthys-tauri/verthys-worker/Cargo.toml
# worker 与 DLL 拷贝到同一目录后运行

# 2) 宿主 debug 测试执行测量（VERTHYS_WORKER_E2E_* 见模块头注释）
$env:VERTHYS_WORKER_E2E="1"
$env:VERTHYS_WORKER_E2E_WORKER="<worker exe>"
$env:VERTHYS_WORKER_E2E_DLL="<verthys.dll>"
$env:VERTHYS_WORKER_E2E_LABEL="g0a"
$env:VERTHYS_WORKER_E2E_PHOTO_MB="10"
$env:VERTHYS_WORKER_E2E_ROUNDS="3"
cargo test --manifest-path verthys-tauri/src-tauri/Cargo.toml --lib \
    worker_import_e2e_measure -- --nocapture --test-threads=1
```


测试结果（Release，真实 TPM）：

```text
build_g0a: g0a 16 passed, 0 failed（含 6 个崩溃注入）
build_g0a: rollback 15 passed, 0 failed; witness 3 passed, 0 failed
build_verify (VERTHYS_G0A_PROTOTYPE=OFF): rollback 15 passed; witness 3 passed
```

关键输出：

```text
g0a fast: sync=406ms fast=31ms hits=1 fallbacks=0 waits=0
g0a fast: sync=407ms fast=32ms hits=1 fallbacks=0 waits=0
g0a fast: sync=421ms fast=47ms hits=1 fallbacks=0 waits=0
g0a fast: sync=438ms fast=47ms hits=1 fallbacks=0 waits=0
g0a wait: second=438ms / 531ms
g0a shutdown: post-shutdown commit=422ms / 437ms / 515ms
g0a vault: create=641ms save1=63ms save2=406ms
g0a vault: create=734ms save1=62ms save2=531ms
g0a vault: create=735ms save1=15ms save2=469ms
```

### 7.4 与设计的偏差

1. **后台建键持有跨进程 `RollbackState` 互斥量**，与设计 3.1“建键不持锁”不同。
   原因：两个进程可同时对同一 TPM 键名执行 `OVERWRITE`；后完成者会让先完成者的
   状态指纹失配，甚至删除对方仍在引用的键。原型选择串行化建键以保证不变量。
   代价：其他进程/同进程提交可能等待最多约 640ms；已由 `g0a_wait` 用例量化。
   若后续要消除该等待，需要跨进程“建键租约”或第三槽，且必须单独安全评审。

2. **预置键使用前重新验证指纹**（F3），与 G0-REPORT 4.1 中“提交路径只使用
   建键时缓存指纹”的早期建议冲突。以安全评审为准；代价是快路径从约 16ms
   上升到 32–47ms，但仍比同步建键低一个数量级。

3. **缓存命中时仍执行 `NCryptOpenKey` 存在性探测**，用于在 TPM 被清除时维持
   fail-closed；不做重复导出公钥。该探测不能识别“同槽键被替换但键仍存在”，
   这是当前缓存的残余局限——旧状态回放不受影响（条目字段不匹配会强制完整校验）。

4. **等待策略**：设计写“有界等待 ≤100ms 后同步回退”。实测建键 400–640ms，
   100ms 必然回退；原型改为等待在途建键完成（上限 5s），无在途建键时立即
   同步回退。

### 7.5 残余风险与未覆盖

1. 删除与撤销都失败时，已写入的新状态与残留旧键会短暂共存；立即回放上一版
   状态仍可能通过。此为“先写状态、后删旧键”的固有窗口，撤销是唯一缓解；
   原型通过 `ANCHOR_DIRTY` 阻断后续提交并返回错误。需要产品明确恢复提示。
2. 后台建键持有跨进程互斥量，多进程同时保存时提交延迟可能回到数百毫秒；
   导入侧必须合并提交，避免连续推进锚点。
3. 崩溃注入已覆盖 8 个窗口（进程级 `TerminateProcess`），包含
   `NCryptCreatePersistedKey` 与 `FinalizeKey` 之间的半完成键。仍未模拟：
   内核级断电（文件系统缓存丢失）、崩溃后攻击者在启动清理前同时替换
   `rollback.state` 为旧的合法副本。最后一项是“先写状态、后删旧键”的固有
   窗口，需 TPM NV 单调计数器才能彻底消除（P2 平台阻断项），本原型不承诺消除。
4. 已在真实 worker 进程测量导入数据面（7.3.2）：10MB 照片 5.04s→3.85s，
   改善约 24%，远低于提交级的 10 倍。瓶颈从“同步建键”转为“锚点推进速率
   被 TPM 建键封顶”。测量不含前端加密、缩略图与宿主 WAL，也未跑完整
   Tauri UI 链路。
5. **延迟锚点/提交合并已完成设计**：[G0-A2-DEFERRED-ANCHOR-DESIGN.md](G0-A2-DEFERRED-ANCHOR-DESIGN.md)
   与 [G0-A2-SECURITY-REVIEW.md](G0-A2-SECURITY-REVIEW.md) 判定“有条件通过原型”；
   尚未实现。核心约束是 Begin 先提交、C 层硬上限（32 代/30s）、会话中拒绝
   非导入写入、Commit/Lock/Deinit 收口。
6. `vty_witness_pool_return` 在池满且状态写失败时直接删除预置键：该键未被任何
   状态引用，删除是安全兜底，但会增加一次 TPM 调用。
7. 关闭采用无限期 join（建键最长约 640ms）；TPM 卡死时退出会阻塞。未使用
   `TerminateThread`，避免卸载后仍执行 CNG 代码。

### 7.6 判定

生产化原型**有条件通过**：

- 安全评审列出的 F1–F6、F8 均已在隔离构建中实现并通过故障注入用例。
- 提交快路径实测 31–47ms（模块级）/ 15–78ms（真实容器 save）；首次与无预置提交保持约 420ms，不劣于现状。
- worker 端到端仅改善约 20–25%：锚点推进速率被 TPM 建键（约 0.5–0.65s/把）
  封顶。**G0-A 预置池是必要条件，不是充分条件**；Phase 1 必须先完成
  “延迟锚点/提交合并”设计与安全评审，才能兑现提交级收益。
- 两槽饥饿仍是硬约束：连续提交的第二次会等待后台建键（实测 438–531ms），
  导入写者必须合并提交。
- 8 个提交窗口的进程级崩溃注入已通过（含 `FinalizeKey` 半完成键）；G0-A2
  隔离原型已完成。进入 Phase 1 前仍需完成完整 Tauri UI 链路测量，以及产品对
  `ANCHOR_DIRTY` 与锚点滞后窗口上限的确认。

