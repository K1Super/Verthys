# Wave 1 — 存储完整性批施行细则

> 目标：消除 C 核心存储引擎的三项 P1 数据完整性缺陷与两项 P1 安全/并发缺陷。
> 范围：只动 `core/src`（事务/WAL/LSM/扫描 API/退避计数）。Rust 层不参与本批（唯 FIX-1-5 的机器级持久化论证与 Wave 0 的 L3 熔断衔接）。
> 前置：
> - T0 核查（开工前）：确认 L3 worker 命令调度是否已串行化「写事务」与「扫描读」。若已串行化，FIX-1-4 按纵深防御实施；若未串行化，本批开工前先向用户呈报该结论并调整 FIX-1-4 优先级（可能上移为批内首项）。
> - FIX-1-5 的工艺论证依赖 Wave 0 的 FIX-0-3 已交付（L3 权威熔断就位后，C 层计数定位为纵深）。
> 纪律：所有 P1 项先落"修复前必红的故障注入测试"（红 → 修 → 绿），并提交行为等价性论证。编号（P1-x、FIX-x-y）只存在于本文档，**不得进入代码注释**。

---

## FIX-1-1 SSTable 写入改「写前预算」（P1-4：溢出字节覆写 extent 密文）

### 现状事实（已核验）

`core/src/index/lsm/verthys_lsm_sstable.c` 的写入函数（~352-558 行）：
- 数据块（403/415 行经 `blockbuilder_flush`）、Bloom（430 前后）、索引块（481 前后）、footer（528 `verthys_lsm_frame_write`）、trailer（545 `vio_pwrite64`）**全部先物理落盘**；
- 唯一的容量检查在 552 行（事后）：`(abs_cursor - (data_base + start_rel)) > data_limit - start_rel`。
- 后果：溢出字节已经写到 LSM 数据区之外（紧邻的 extent 数据区），覆写 extent 密文后函数才返回 `RESOURCE_LIMIT`——损坏已在磁盘上发生。

### 修复设计

**核心改造：把"区段预算"提到每个物理写点之前，事后检查降级为防御性断言。**

1. 函数开头建立边界常量：

```c
const uint64_t data_end_abs = data_base + data_limit;   /* 绝对软边界 */
```

2. 新增该文件内部的单点辅助函数（就近放置，不跨文件）：

```c
/* 写前预算校验：越界即拒绝，绝不落盘。
 * 返回 0 表示放行；返回 VERTHYS_ERR_RESOURCE_LIMIT 表示越界。 */
static VerthysResult sstable_budget_check(uint64_t abs_cursor, size_t write_len,
                                          uint64_t data_end_abs)
{
    if (write_len > (size_t)(data_end_abs - abs_cursor)) {
        return VERTHYS_ERR_RESOURCE_LIMIT;
    }
    return VERTHYS_OK;
}
```

（前置断言：`abs_cursor <= data_end_abs` 由调用纪律保证，函数内先做一次 `abs_cursor > data_end_abs` 的防御判断，防止下溢。）

3. 五个写入点全部接入（每处先 `sstable_budget_check` 再写，失败 `goto fail`）：

| 写入点 | 预算长度来源 |
|---|---|
| 数据块 `blockbuilder_flush` 调用（403/415） | 精确值：`VERTHYS_LSM_FRAME_HEADER_BYTES + bb.len + VERTHYS_CNG_TAG_BYTES + VERTHYS_LSM_FRAME_TAIL_BYTES`（写前 bb.len 已知） |
| Bloom 写入 | 精确值：`VERTHYS_LSM_FRAME_HEADER_BYTES + bloom.bytes + VERTHYS_CNG_TAG_BYTES + VERTHYS_LSM_FRAME_TAIL_BYTES` |
| 索引块各块写入 | 与数据块同法（构建中的索引块编码缓冲长度已知） |
| footer `verthys_lsm_frame_write`（528） | 精确值：帧头 + `pt_len`（flatcc finalize 后已知）+ tag + 帧尾 |
| trailer（545） | 常量 `sizeof(trailer)`（24B） |

4. 越界行为：返回 `VERTHYS_ERR_RESOURCE_LIMIT`，**该次 flush/compaction 整体中止**；`fail` 路径保持现有行为（不推进 `*rel_cursor`、不写 Manifest；LSM 数据区内已写入的残缺字节因未被 Manifest 登记而不可达，下次复用覆盖——此为其既有设计，无需新增回滚）。
5. **保留** 552 行的事后总量检查为最终防御断言（写前预算若未来被破坏，事后检查仍能阻止 meta 填充/Manifest 引用；事后已无法阻止的物理越界由写前预算负责根除）。两层同时存在，注释各自说明分工。
6. 同类核查（实施时顺手确认，不扩大改动）：`blockbuilder_flush` 内部若有自分段写入，确认其相对游标推进与调用方 `abs_cursor` 传参一致性，避免预算长度与实际写入字节数脱节（`flen` 输出必须真实）。

### 行为等价性论证

- 正常路径（预算充足）：所有写入点的字节序列、偏移、AAD、seq、meta 与修复前完全一致，仅多若干次整数比较（无 IO）。
- 越界路径：修复前"写穿边界后返回错误"变为"未写穿即返回同样错误码"——对调用方可见行为等价（同样的错误码、同样的回滚语义），磁盘状态由"已损坏"变为"未损坏、未被登记"。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 单测（修复前必红） | `core/tests/index/test_v3_lsm.c`（或新增 `test_sstable_budget.c`） | 构造"内存表 flush 产物恰好超过 LSM 数据区剩余空间"的场景，断言：返回 RESOURCE_LIMIT 且 **LSM 数据区末尾之后的第一页（extent 数据区首部）字节与写前完全一致**（修复前该断言红：首部被 trailer/块覆写） |
| 模糊回归 | `core/tests/fuzz/fuzz_sstable.c` | 现有 smoke + 持续门保持全绿 |
| 集成 | `verthys_tests.exe` 全量 | 全绿 |

### 验收标准

- Grep 该函数体内五个写入点均先于物理写调用预算检查。
- 新增单测在修复前代码上运行确实为红（留档），修复后为绿。

---

## FIX-1-2 delete 重排为「先墓碑、后账本与释放」（P1-5：extent 引用计数多减）

### 现状事实（已核验）

`core/src/transaction/txn/verthys_transaction_v3.c:317-345`（`verthys_txn_v3_delete`）当前顺序：
1. `verthys_lsm_get`（319）——查出当前值 hash；
2. `txn_ledger_record(-1)`（321）;
3. `verthys_extent_release`（323，内存 refcount--）；
4. `verthys_lsm_delete`（329，写墓碑）；
5. WAL append（341）。

故障场景：323 成功、329 失败 → 上层按"幂等"重试 delete：lsm_get 又命中（墓碑未生效）→ 再次 ledger(-1)（净 -2）→ 再次 release（refcount 少 1 于实际删除数）→ extent 被 GC 误判 eligible → 回收仍被引用的数据块。

### 修复设计

**区间顺序重排 + 错误路径契约硬化（双管齐下）。**

1. 新顺序（墓碑先行，账本与释放只在墓碑成功后执行且互相紧随）：

```
lsm_get(lid)             -- 查现值（NOTFOUND 正常；其他错误直接返回）
lsm_delete(lid, tombstone) -- 第一步副作用：墓碑生效 -- 失败 => 返回错误（零副作用）
若 lsm_get 曾命中:
    txn_ledger_record(-1)   -- 失败 => 返回错误（由下方契约 abort，不重试）
    verthys_extent_release  -- 失败 => 返回错误（同上）
WAL append（INDEX 墓碑帧）
```

2. **错误路径契约**（配合顺序重排的语义前提，写入函数注释与调用方约定）：`verthys_txn_v3_delete` 返回任何错误后，**调用方必须 abort 该事务，不得在同一事务内重试本操作**。理由：墓碑已写时重试不再触发 ledger/release（lsm_get 变 NOTFOUND），墓碑未写时重试零副作用——两种情形下重试都无法保持"账本与 refcount 严格同步"，唯一安全语义是 abort 后重开事务。
3. 排查现有调用方：Grep `verthys_txn_v3_delete` 调用点（预期在事务执行层/命令分发层），将"delete 失败即 abort"落实为调用方行为；若某调用方当前语义是"继续执行后续操作"，需评估改为 abort（若继续执行的语义依赖原"写前失败无副作用"假设，则必须改）。
4. `txn_ledger_record(-1)` 与 `verthys_extent_release` 之间保持原先行顺序（先记账后释放），不做进一步交换。

### 行为等价性论证

- 正常路径：最终效果同修复前（墓碑 + 账本净 -1 + refcount -1）。
- 原故障窗口（release 成功后 lsm_delete 失败）在新顺序下不再存在：release 前墓碑已生效，任何重放/重看路径都不会重复 release。
- 新故障窗口（墓碑成功后 ledger/release 失败）：由 abort 契约封闭——账本在事务内,abort 回滚按既有回滚路径反向结算（ledger 已记的部分被撤销），release 的引用恢复由回滚路径负责（实施时核对回滚路径对 INDEX 墓碑 op 的既有处理，确保"墓碑写入了内存但 WAL 未 append"的回滚语义不变——该场景与修复前"lsm_delete 成功但 WAL append 失败"的回滚完全相同，等价）。
- 崩溃重放路径（不走本函数）：WAL 中 INDEX 墓碑帧的重放逻辑不变。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 单测（修复前必红） | `core/tests/transaction/`（扩展 `test_txn_recovery_inject.c` 或新增 `test_txn_delete_retry.c`） | mock/注入 `verthys_lsm_delete` 首次失败：断言返回错误后 refcount 与账本净额均为 0（未变化）；断言第二次新事务 delete 成功时净额为 -1 且 refcount 恰好 -1（修复前此处为 -2） |
| 单测 | 同上 | 注入 `verthys_extent_release` 失败：断言事务 abort 后回滚使 refcount 恢复、账本净额归零、无幽灵引用 |
| 集成 | `verthys_tests.exe` 全量 | 全绿 |

### 验收标准

- 调用方全部改为"delete 失败即 abort"（Grep 复查 0 处重试语义）。
- 注入测试在修复前代码为红，修复后为绿。

---

## FIX-1-3 WAL 换区先清零新区数据区（P1-3：第三圈后残留旧帧可能被回放）

### 现状事实（已核验）

`core/src/transaction/wal/verthys_wal.c:475-487`（`wal_append` 换区分支）：

```c
if (w->cursor + frame_len > VERTHYS_WAL_HALF_BYTES) {
    unsigned nh = 1u - w->active_half;
    uint64_t nseq = w->half_seq + 1;
    r = wal_write_half_header(w, nh, nseq);   /* 只写 24B 头 */
    ...
    w->cursor = VERTHYS_WAL_HALF_HEADER_BYTES;
    w->frame_count = 0;
}
```

新区数据区（offset 24 ~ 半区尾）若有上一轮残留帧，`wal_foreach_frame` 自 offset 24 起逐帧解 AES-GCM、遇 magic 不符才停——第三圈后新写入链若未完全物理覆盖旧链，扫描会把旧帧当新链继续解并被候选重放。

### 修复设计

**方案：换区时先清零新区数据区再写头。不改半区头格式（V3 容器格式冻结，不能为记录 high-water 扩头字段）。**

1. 在换区分支内、`wal_write_half_header` **之前**调用新函数：

```c
static VerthysResult wal_clear_half_data(VerthysWal *w, unsigned nh)
```

   实现要点（遵循本文件现有清零风格，参考 `wal_reset` 的 pwrite 零模式）：
   - 单次 `pwrite` 写 `VERTHYS_WAL_HALF_BYTES - VERTHYS_WAL_HALF_HEADER_BYTES` 字节的零缓冲到 `wal_half_base(w, nh) + VERTHYS_WAL_HALF_HEADER_BYTES`（半区 480KB 单次写可；若担心超大单次写，按 64KB 块循环，实施时二选一并保持与本文件风格一致）；
   - 后续 `wal_fsync(w->f)`；
   - 失败直接返回错误，**不切换** `active_half`（保持旧区仍为活动区，事务帧可继续追加/或上层重试——与现行为"头写失败即返回"对齐）。

2. 顺序保证：**清零+fsync → 写头 → （既有后续）**。若清零成功后崩溃、头未写：replay 扫描该半区时头 seq 仍旧值，数据区全零 → magic 不符即停，无残留链可解——安全。
3. 明确该清零只清理"被换入的一半"；被换出的半区数据**保持不动**（上一轮未 flush 的事务帧仍要靠它重放，此为该函数既有注释语义"旧区转备份（数据保留）"）。
4. `wal_foreach_frame` 扫描逻辑不动（不需要 high-water）。

### 性能论证

- 额外成本发生在换区时：每次 480KB 写 + 一次 fsync。换区频率 = 半区写满频率（每半区容纳约数百至数千事务帧），与 `wal_reset` 在 flush 时的 960KB 清零同级或更低，可接受。
- 正常容量下换区本就不频繁；不引入逐帧成本。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 单测（修复前必红） | `core/tests/transaction/test_txn_recovery_inject.c` 扩展 | 构造第三圈场景：写满 A→切 B→写满 B→切回 A（复位清零逻辑被绕过为"修复前行为"注入残留旧帧），掉电恢复后断言 replay 未将残留旧帧 redrive（修复前红） |
| 单测 | 同上 | 换区中途"清零后写头失败"注入：断言 active_half 未切换、后续 append 仍落在旧半区且 replay 一致 |
| 集成 | `verthys_tests.exe` 全量 | 全绿 |

### 验收标准

- `wal_append` 换区分支含"先清零→fsync→再写头"序列。
- 注入测试修复前红、修复后绿。

---

## FIX-1-4 扫描游标系列接口加 SRW 共享锁（P1-2：与写路径竞争同一 FILE*）

### 现状事实（已核验）

- `core/src/api/scan/verthys_scan.c`：`Verthys_ScanFetch`（461）、`Verthys_ScanSummaryFetch`（581）、`Verthys_HasRecordByType`（636）、`Verthys_ScanFindFirstLidByType`（后文）四个函数体内 0 命中 `AcquireSRW`。
- 它们经 `scan_v3_fetch` → `verthys_extent_get` 读取共享 `v->f`（`FILE*`，`vio_pread64` 内部 `_fseeki64+fread`，同一 `FILE*` 非线程安全）；写路径 `Verthys_AddRecord`（`verthys_api.c:1154`）持 `AcquireSRWLockExclusive`。
- 已核验的关键前提：`api_mutex` 为 `ctx` 内的指针字段，全仓已有标准样板 `if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);`（如 `verthys_api.c:1324/1352/1542/1641`、`verthys_export_import.c:151`），本修复照抄该样板。
- 游标结构 `struct VerthysScanCursor` 内已有 `v3_ctx`（借用 `struct VerthysContext *`）——Fetch 系列经 `cursor->v3_ctx->api_mutex` 取锁；`HasRecordByType`/`FindFirstLidByType` 经 handle 解引用 ctx 取锁。

### 修复设计

1. 锁样板（Fetch 系列，处理所有提前 return 的释放）：

```c
VerthysResult Verthys_ScanFetch(...)
{
    /* 现有参数/游标有效性检查 */
    ...
    if (cursor->v3_ctx != NULL && cursor->v3_ctx->api_mutex != NULL) {
        AcquireSRWLockShared(cursor->v3_ctx->api_mutex);
    }
    ... /* 熔断检测 + scan_v3_fetch 调用 */
    /* 所有出口统一到此处释放（函数改造为单出口或 goto out） */
    if (cursor->v3_ctx != NULL && cursor->v3_ctx->api_mutex != NULL) {
        ReleaseSRWLockShared(cursor->v3_ctx->api_mutex);
    }
    return r;
}
```

   实施要求：
   - 每个被改函数改为**单出口**（`goto` 到释放点）或包裹函数，禁止在共享锁内遗留提前 return。
   - 锁保护范围仅覆盖 `scan_v3_fetch`/等价核心读路径（含 extent `FILE*` 读）；参数校验、游标失效检测放锁外或锁内皆可，但必须保证"释放对称"。
2. `HasRecordByType`/`ScanFindFirstLidByType` 同样加共享锁（经 handle 取 ctx）。若这两个函数内部**调用了** `Verthys_ScanFetch`（复用同一实现），则只在外层加即可，**禁止嵌套加锁**——实施时先画调用图（SRW 共享锁同线程递归获取在"无独占介入"下可放行，但纪律上禁止依赖该性质，保持"每函数最多一层"）。
3. `Verthys_ScanOpen`/`Verthys_ScanSummaryOpen` 的核查项：若 open 路径也直接读 `v->f`（而非仅经内部持锁的 LSM 层），open 同样加共享锁；若 open 全程在 LSM 内部锁之内且不触碰无锁 FILE* 读,则不动（实施时以代码事实为准，本文档不预设）。
4. **锁层级核查**（实施时必做，防死锁）：确认 extent 读路径内部不反向获取 `api_mutex` 独占、不在共享持锁区间调用任何"持独占再等共享"的函数；`AddRecord`（独占）内部锁序与扫描区间锁序一致为 `api_mutex → lsm 内部锁` 单向。
5. 与 T0 核查结论的关系：若 T0 证实 L3 已串行化（worker 单线程消费命令），本修复定位为"纵深防御"（C 层自保，A API 直接用户也安全）；若未串行化，本修复为本批关键项，需优先完成并加并发压力测试。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 压力测试 | `core/tests/api/`（新增 `test_scan_concurrent.c`） | 游标开启期间，双线程跑 `Verthys_AddRecord` + `Verthys_ScanFetch`（多轮），断言无崩溃、无校验和不一致、无 extent 错乱（建议配合 ASan/页堆构建） |
| 单测 | 同上 | 锁对称性：每个改造函数所有分支后 `api_mutex` 不再被持有（可加计数断言或走压力测试间接验证） |
| 集成 | `verthys_tests.exe` 全量 | 全绿 |

### 验收标准

- 四个函数体内 `AcquireSRWLockShared` 命中数 ≥1 且与释放点对称。
- 并发压力测试在修复前代码上可复现错乱/崩溃（留档），修复后稳定通过。

---

## FIX-1-5 C 层暴力破解退避改为进程级聚合（P1-1 的 C 侧）

### 现状事实（已核验）

- `core/src/api/shared/verthys_api_utils.c:40-61`：`failed_attempts/last_failed_tick` 存于 `VerthysContext`（堆,进程私有、按句柄）；
- `verthys_api.c:247`：`Verthys_Init` `calloc` 清零；`:939`：解锁前查 `verthys_backoff_remaining_ms(ctx)`；`:587`：仅 AUTH 失败 `record_failure(ctx)`。
- 攻击者反复 `Verthys_Init`（新句柄计数=0）→ `Verthys_Unlock(guess)` 即可无限错误尝试，指数退避只看当前句柄史。

### 修复设计

**第一层（本批实施）：进程内跨句柄聚合。**

1. 将退避计数从 `VerthysContext` 迁至 `verthys_api_utils.c` 模块级全局：

```c
/* 进程级失败计数（跨句柄聚合；见并发注释） */
static uint32_t g_brute_failures = 0;      /* 只增不减，成功时清零 */
static uint64_t g_brute_last_fail_ms = 0;
```

   宽度取 uint64/uint32 与既有字段一致；读写以原子内建完成（Windows 用 `InterlockedExchange`/`InterlockedIncrement`；读取用 `InterlockedCompareExchange` 取快照或加轻量互斥——实施时按文件现有并发纪律选择，且必须与"读不持锁"的 P3-1 一并处置：把 P3-1（C 片）的"backoff 读不持锁"用同一机制收敛掉，不再单独开项）。
2. 三个函数签名改造（调用方随之更新）：
   - `verthys_backoff_remaining_ms()` — 改为无参版本（保留旧签名给内部迁移期？不——**一次改净**，全仓 Grep 更新调用点，`VerthysContext` 字段删除）；
   - `verthys_backoff_record_failure()`；
   - `verthys_backoff_reset()`。
3. 语义变化点（在函数注释里写清楚，不引用本文档）：
   - 计数按进程聚合（不区分容器文件路径），同一进程内对任意容器的失败尝试共享计数——方向保守（更严格），只可能多锁不会少锁；
   - `Verthys_Init` 不再清零计数（新句柄延续进程累积）；
   - 成功解锁仍调用 `reset`（清连续失败语义保留）；
   - 进程重启后清零——继续由 **L3 Rust 层 DPAPI 持久化（Wave 0 FIX-0-3 已接入咽喉点）** 兜住跨进程场景；C 层本层定位为纵深（防"绕过 L3 直连 DLL"）。

**第二层（设计批复，实施排 Wave 3 评估）：机器级持久化。**

- 方案：将失败计数落到机器级不可删改位置（候选：CNG 不透明 blob / MachineGuid 派生的 HMAC 计数文件 / 注册表仅 SYSTEM 可写键）。
- 推迟论证：L3 已用 DPAPI 提供跨进程权威计数；C 层再加机器级持久化会引入"用户重装系统/重置机器后计数残留"的产品决策与格式问题，需与产品方确认再实施。本批交付时在文档留痕，不做代码。

### 行为要点

- `VERTHYS_ERR_RATE` 判定逻辑（`backoff_remaining_ms` 的指数退避公式）数值不变。
- 多线程解锁同一进程时计数更新原子，退避判定最多偏差一次计数（可接受，注释记录）。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 单测（修复前必红） | `core/tests/api/`（新增 `test_backoff_process_wide.c`） | `Init→Unlock(错误)→Init→Unlock(错误)`：第二次会话立即返回 RATE 或退避时间 > 0（修复前恒为 0）；多次错误后 `backoff_remaining_ms > 0` 且随次数指数增长；成功 unlock 后 reset 为 0 |
| 集成 | `verthys_tests.exe` 全量 | 全绿 |

### 验收标准

- `VerthysContext` 中不再有失败计数字段；`verthys_api_utils.c` 中计数为模块级全局且读写原子。
- 注入测试修复前红、修复后绿。
- 机器级持久化决策留痕（设计文档段落 + 产品决策待办）。

---

## 本批验证门

1. Ninja 构建（Debug）通过，WarningsAsErrors（若本地已启）无误
2. `verthys_tests.exe` 全量绿（含本批新增 4 组测试；修复前红的两个测试留档说明）
3. 5 个 fuzz 目标 smoke 门通过；`fuzz_sstable` 持续 10 分钟无崩溃
4. 行为等价性论证随各修复写入提交说明
5. `git status` 干净；无 Cargo.lock/无关文件变更

**git 纪律**：每项修复独立提交；先提交"红测试"再提交"修复"（同一 PR 内两个 commit）；提交说明描述行为变化与等价性论证，不引用本文档编号。