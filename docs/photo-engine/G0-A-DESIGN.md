# G0-A — TPM 见证密钥预置：C 层设计

> 状态：设计完成；隔离原型有条件通过 · 最后更新：2026-11-18 · 维护人：K1Super
>
> 目标：把每次容器保存约 450ms 的 TPM 建键成本移出提交关键路径，同时不降低回退保护强度。
>
> 本文件只定义设计，不包含生产代码改动。

---

## 1. 现状与根因

当前保存链：

```text
vty_vault_save_meta
  → vty_rollback_commit
      → lock_state()                         // Local\Verthys.RollbackState
      → load_authenticated()
      → vty_tpm_witness_verify()             // 打开当前槽并导出公钥
      → rotate_witness()
          → vty_tpm_witness_create()         // NCryptCreatePersistedKey + FinalizeKey
      → upsert() + store()                   // 写 rollback.state（fsync + rename）
      → drop_stale_witness()                 // 删除旧槽
      → unlock_state()
```

关键事实：

- `vty_rollback_commit` 在整个 TPM 建键期间持有跨进程 `RollbackState` 互斥量
  （[vty_rollback.c](file:///c:/Users/Administrator/Desktop/Verthys/core/src/security/rollback/vty_rollback.c#L549-L627)）。
- `rotate_witness` 同步调用 `vty_tpm_witness_create`，每次都创建/持久化一把新的
  TPM ECDSA P-256 密钥（[vty_tpm_witness.c](file:///c:/Users/Administrator/Desktop/Verthys/core/src/security/tpm/vty_tpm_witness.c#L86-L121)）。
- G0 实测：建键 + Finalize 约 397–427ms；`AddRecords`/`Flush` 固定约 450ms。
- 当前设计用 A/B 两槽交替：先建新键 → 写状态 → 删旧键，保证崩溃时旧状态仍可打开。
- 状态文件保存每个库的 `generation + witness slot + public-key fingerprint`，并用设备密钥
  MAC 保护（[vty_rollback.c](file:///c:/Users/Administrator/Desktop/Verthys/core/src/security/rollback/vty_rollback.c#L290-L364)）。

## 2. 设计目标与非目标

### 目标

1. 提交关键路径不再等待 TPM 建键。
2. 保持“每次锚点推进轮换见证”的语义；旧状态回滚仍 fail-closed。
3. 不改变 `rollback.state` 布局，不迁移旧数据。
4. 不新增公网/前端 API；只改内部 C 模块。
5. 失败可见、可恢复；不得静默关闭回退保护。

### 非目标

- 不引入 TPM NV 单调计数器（P2 平台阻断项）。
- 不改变容器 generation、WAL、台账、密钥层级。
- 不把回退锚点更新频率降为“每次会话一次”（备选方案，非首选）。
- 不在本阶段优化 `AddRecords` 的数据区吞吐（另见 BulkAppend）。

## 3. 总体方案

### 3.1 见证密钥池

在现有 A/B 两槽基础上，把“当前槽”之外的槽变成**预置槽**：

```text
当前槽：rollback.state 当前 generation 引用的密钥
预置槽：已创建、已 Finalize、指纹已缓存，但未被任何状态引用
```

- 预置槽只允许一把密钥；不扩到第三槽，避免依赖 TPM 持久化键容量。
- 预置槽由后台线程创建：
  1. 取池锁，确认槽为空且不是当前槽；
  2. 释放池锁；
  3. `vty_tpm_witness_create`（约 400–640ms）；
  4. 取池锁，校验指纹，标记 READY。
- 建键期间不持有 `RollbackState` 互斥量，不阻塞其他库提交。

### 3.2 提交快路径

```text
vty_rollback_commit
  1. lock_state()
  2. load_authenticated() + 查条目
  3. 校验当前见证（缓存命中则跳过 TPM 打开）
  4. 取预置槽（pool lock，O(1)）；使用前验证槽内键存在且指纹匹配
  5. upsert() + store()                 // 状态文件原子写，约 3–5ms
  6. 删除/撤销旧槽密钥                 // 约 0.1ms；失败必须 fail-closed
  7. unlock_state()
  8. 通知后台补下一把预置密钥
```

- 状态仍然“先引用新键、后删旧键”；崩溃时旧状态仍指向仍存在的旧键。
- 旧键删除成功后，旧状态回放必然指纹不符。
- 如果预置槽为空：
  - 首选：短暂等待后台完成（有界，例如 ≤100ms）；
  - 超时后回退同步建键（当前行为），保证功能可用；
  - 不允许跳过锚点推进。

### 3.3 已验证条目缓存

每次提交都 `NCryptOpenKey + ExportKey` 校验当前见证，约 15–47ms，且与后台建键争用。
增加进程内缓存：

```c
struct verified_entry {
    uint8_t vault_uuid[16];
    uint64_t generation;
    uint8_t slot;
    uint8_t fp[32];
    int valid;
};
```

- `vty_rollback_check` 验证成功后写入缓存。
- `vty_rollback_commit` 加载状态后：
  - 若条目与缓存完全一致 → 跳过 TPM 校验；
  - 不一致 → 执行 TPM 校验并更新缓存。
- 缓存不落盘；锁库/登出/Deinit 清空。
- 若另一个进程推进了 generation，缓存不匹配，自动回退到 TPM 校验。

### 3.4 旧键撤销与删除失败

旧键必须失效，否则旧状态文件可回放。设计：

1. 正常路径：`vty_tpm_witness_delete(old_slot)`；实测约 0.1ms。
2. 删除失败：调用新增 `vty_tpm_witness_revoke(id, slot)`，用
   `NCRYPT_OVERWRITE_KEY_FLAG` 在原槽创建一把新键，使旧指纹立即失效；
   新键标记为“未引用”，交给后台清理。
3. 撤销也失败：返回 `VTY_E_TPM`，并将该库锚点标记为 `ANCHOR_DIRTY`；
   后续提交 fail-closed，直到修复/重新解锁。
4. 启动/解锁时清理未引用槽；清理失败同样 fail-closed。

当前 `drop_stale_witness` 忽略删除错误，这是必须修的安全缺陷。

### 3.5 启动、解锁与关闭

- `vty_rollback_check` 成功验证且 rollback.state 中**已存在该库条目**后，才触发后台预置。
- 新库首次提交前不得预置：首次提交仍同步建键；完成后再补预置，避免被现有
  `any_new != 0` 检查误判为回退。
- 每次成功提交后，旧槽变为空，后台补下一把。
- 新增 `vty_rollback_shutdown()`：
  - 由核心 `Deinit` 调用；
  - 设置停止事件、等待后台线程退出、清空池与缓存；
  - 未引用的预置键尽量删除；失败留下启动清理。
- 不在 `DllMain` 内做 TPM/线程操作；使用显式生命周期函数。

### 3.6 多库与并发

- 预置只针对当前活动库；其他库提交时若无预置键，走同步回退。
- 池按 `witness_id`（设备根 + 容器 UUID）分区；不同库不共享密钥。
- 全局后台线程串行建键；不为每个库创建线程。
- 锁顺序固定：`RollbackState` → pool lock（禁止反向持有）。
- 后台建键不持有 `RollbackState`；提交不在持有 pool lock 时写状态。

## 4. 状态格式与兼容

- `rollback.state` 布局不变：
  - 条目仍为 `uuid + generation + witness_slot + fp`；
  - `witness_slot` 仍只使用 0/1；
  - 预置键不写入状态文件。
- `VTY_TPM_WITNESS_SLOTS` 保持 2。
- 旧状态、旧密钥、旧容器无需迁移。
- 新增的“预置/未引用”状态只存在于进程内存与 TPM 键名，不进入磁盘格式。

## 5. 关键序列

### 5.1 正常提交（预置就绪）

```text
lock_state
  load state
  cache match? skip TPM verify : verify TPM
  pool_take → slot B, fpB
  upsert generation G+1, slot B, fpB
  store (atomic)
  delete slot A (old current)
unlock_state
signal pool → create next key in slot A
return OK
```

### 5.2 预置未就绪

```text
lock_state → load/verify → pool_take miss
unlock_state
create slot B synchronously (or wait bounded for background)
lock_state → reload → 若 current 未变则继续；否则丢弃 B 重试
store → delete old → unlock
```

同步回退保持当前 450ms 行为，但不改变语义；导入批量提交应尽量避免走到这里。

### 5.3 提交失败

- `upsert/store` 失败：保留预置键为 READY，旧键仍是当前；状态未变。
- 旧键删除失败：按 3.4 撤销/失败关闭。
- 后台建键失败：池为空；下一次提交同步回退；记录结构化错误。

## 6. 崩溃一致性矩阵

| 崩溃点 | 磁盘状态 | TPM 状态 | 恢复行为 |
|---|---|---|---|
| 预置键创建中 | 旧状态 | 旧键 + 半成品新键 | 启动清理未引用槽；旧状态可用 |
| 预置键完成、未提交 | 旧状态 | 旧键 + 未引用新键 | 可复用或清理；旧状态可用 |
| 状态写入中 | 原子旧/新 | 两把键均存在 | 按实际状态引用对应键 |
| 状态写完、旧键未删 | 新状态 | 新键 + 旧键 | 启动清理旧键；旧状态回放应失败 |
| 旧键删除中 | 新状态 | 新键 + 旧键可能残留 | 启动撤销/删除；失败 fail-closed |
| 删除完成、未补池 | 新状态 | 仅新键 | 下次提交同步回退或等待后台 |

不变量：任何时刻，磁盘上的最新状态都必须引用一把存在的、指纹匹配的 TPM 键；
旧 generation 的状态不得同时具备“存在的匹配键”。

## 7. 性能模型

| 路径 | 预估 |
|---|---|
| 状态加载 + MAC | 1–3ms |
| 缓存命中校验 | 0ms |
| 缓存未命中 TPM 校验 | 15–47ms |
| 状态原子写 + fsync | 3–5ms |
| 旧键删除 | 0.1ms |
| 提交快路径合计 | 约 5–10ms（缓存命中） |
| 后台建键 | 397–639ms（关键路径外） |

导入 10MiB 样本的理论路径：数据 ~100–150ms + 提交 ~5–10ms + 缩略图 ~34ms + seal ~15ms
≈ 150–220ms；需 G0-A 原型实测确认，不能直接写入验收承诺。大图按块数
`ceil(size/4MiB)` 线性放大，10MiB 只是样本。

## 8. 测试计划

### 功能/一致性

- 正常提交使用预置键；无预置键时同步回退。
- 连续提交、并发多库提交、锁超时。
- 启动清理未引用键；崩溃矩阵逐项注入。
- 状态回放到旧 generation → fail-closed。
- 旧键删除失败 → 撤销成功/失败两条路径。
- 预置键被覆盖/删除 → 提交前校验失败并回退。
- 关闭时后台线程停止；DLL 卸载无 TPM 调用。

### 性能

- 提交快路径 P50/P95（目标 ≤10ms/≤20ms，缓存命中）。
- 无预置键回退 P95（应回到当前 ~450ms，不得更差）。
- 后台建键吞吐、与读/解锁的争用。
- 导入 10/17.73/24.43/50MiB 与 100 张批量端到端；100MiB 边界单独覆盖。

### 故障注入

- `NCryptCreatePersistedKey` / `FinalizeKey` 失败。
- `NCryptOpenKey` / `ExportKey` 失败。
- `NCryptDeleteKey` 失败、`OVERWRITE` 撤销失败。
- 状态文件写失败、rename 失败、fsync 失败。
- TPM 不存在/被禁用/PCR 变化。
- 进程在状态写前后、删键前后被 kill。

## 9. 改动面（仅内部）

| 文件 | 改动 |
|---|---|
| `core/src/security/tpm/vty_tpm_witness.h/.c` | 预置槽 API、撤销 API、指纹缓存、槽状态 |
| `core/src/security/rollback/vty_rollback.c` | 提交快路径、预置/回退、已验证条目缓存、删除失败处理、shutdown |
| `core/src/security/rollback/vty_rollback.h` | `shutdown`/测试钩子（内部） |
| `core/src/api/...` / `core/src/core.c` | Deinit 调用 rollback shutdown |
| `core/tests/security/...` | 并发、崩溃、故障注入、回放测试 |
| `core/CMakeLists.txt` | 新增测试目标/线程库（如需要） |

不涉及前端、Tauri 命令、容器格式、WAL/台账。

## 10. 开放问题

1. 预置建键在 TPM 争用下约 639ms；两槽是否足够，取决于导入提交频率。若不足，需提交合并或评估第三槽。
2. 已验证条目缓存的跨进程一致性：依赖 `RollbackState` 互斥量与状态文件 entry 比较；需安全评审确认。
3. 旧键删除失败的撤销路径会增加 400ms 错误路径；是否需要独立恢复工具/提示。
4. 立即导入（解锁后 <400ms）可能没有预置键，是否允许同步回退，或在 UI 上等待预置完成。
5. 后台线程关闭时最长等待 639ms；是否接受退出延迟，或需要可中断建键。

## 11. 结论

- 设计可行，且不降低回退保护强度。
- 先做 G0-A 原型（隔离分支/测试），验证提交快路径、删除失败撤销、崩溃矩阵与性能。
- 原型通过安全评审与测试后，才允许进入 Phase 1 生产实现。
