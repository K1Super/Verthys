# Verthys v2.6.1 全栈工程化代码评审报告

> **评审日期**：2026-09-20
> **评审范围**：L2 C11 加密核心 DLL / L3 Rust 控制器+worker 子进程 / L4 Tauri+Vue3 前端 / 构建+CI+依赖+配置
> **评审方法**：沿调用链/数据流/控制流/资源生命周期逐层深审，每项发现均含真实文件行号（Grep/Read 定位）
> **操作红线**：未执行破坏性命令、未修改源码、未泄露任何真实密钥/pepper/口令字节
> **源文件总量**：~500 个（84 .c / 61 .h / 154 .rs / 119 .ts / 52 .vue）

---

## 一、项目概览

### 1.1 架构分层（单向依赖，上层不接触密钥）

| 层 | 技术 | 位置 | 职责 |
|---|---|---|---|
| L4 UI | Tauri + Vue 3 + TypeScript | `verthys-tauri/src/` | 纯渲染，口令/密码不出前端 |
| L3 调度 | Rust（控制器 + worker 子进程） | `verthys-tauri/src-tauri/`, `verthys-worker/` | 进程隔离/会话策略/安全命令，零密钥接触 |
| L2 核心 | C11（verthys.dll） | `core/src/` | 六大子域：api/crypto/container/index/transaction/security |
| L1 持久化 | .verthys 加密容器 | 磁盘文件 | 超块 3 副本 2/3 法定数 + 分区 AEAD + WAL |

### 1.2 关键技术参数

- **ABI**：0x000B；**容器版本**：V3
- **密钥体系**：口令 → Argon2id(64MiB/3/1) → DKM → CNG MEK → KeyA/B/C 三权分立
- **轮换策略**：90 天 / 10k ops / DEGRADE 三类触发
- **外部依赖**：libsodium（vendored 静态）、flatcc（codegen）、xxHash、Tauri 2.11.5、windows 0.58

### 1.3 风险总览

| 级别 | 数量 | 含义 |
|---|---|---|
| **P0** | **1** | 阻断/高危 — 运行时必现功能失效 |
| **P1** | **12** | 严重 — 安全防护失效/数据损坏/明文泄露 |
| **P2** | **35** | 中等 — 窄触发风险/降级/一致性问题 |
| **P3** | **33** | 改进 — 健壮性/性能/卫生/死代码 |
| **合计** | **81** | |

---

## 二、P0 — 阻断性缺陷

### P0-1 `write_user_file` IPC 协议错配：拾光模块导出照片 100% 失败

- **文件**：`verthys-tauri/src/composables/photo-album/usePhotoExport.ts:69-72`（调用点 322/350/400/461）
- **对照**：Rust 端 `file_controller.rs:1056-1074`
- **问题**：前端仍用旧 base64 JSON-args 协议调用 `write_user_file`，但 Rust 端已迁移到 raw IPC（`x-path` 头 + raw body）。
- **证据**：前端 `invoke("write_user_file", { path, dataB64: b64 })`；Rust 签名为 `write_user_file(app, request: Request<'_>)`，路径从 `x-path` HTTP 头解码，字节从 `InvokeBody::Raw` 提取。正确实现见 `verthys.ts:1188-1196` 的 `writeUserFile()`。
- **触发**：Tauri 模式下用户执行任意照片导出操作。
- **影响**：导出写盘必然失败，Rust 返回 `Err`，前端抛错，功能完全不可用。
- **置信度**：确认
- **修复**：将 `writeVencFile` 改为调用 `writeUserFile(path, bytes)`，删除本地 `invoke` 与 `bytesToBase64` 编码。
- **验证**：Tauri 模式导出一张照片，确认文件落盘。

---

## 三、P1 — 严重缺陷

### P1-1 暴力破解退避为 RAM 内、按句柄记账，新句柄/进程重启即清零

- **文件**：
  - `core/src/api/shared/verthys_api_utils.c:40-61`
  - `core/src/api/lifecycle/verthys_api.c:587, 247, 939`
- **问题**：`failed_attempts/last_failed_tick` 存在 `VerthysContext`（堆，进程私有），无持久化、无跨句柄聚合。
- **触发**：攻击者持有 `.verthys`，反复 `Verthys_Init`（新句柄，计数=0）→ `Verthys_Unlock(guess)`，或直接重启 worker 进程。
- **影响**：`VERTHYS_ERR_RATE` 设计的暴力破解防护在主威胁模型（离线本地穷举）下失效；Argon2id 惩罚开销是唯一实际减速。
- **置信度**：确认
- **修复**：将错误次数落到机器级持久化位置（CNG 不透明 blob / 注册表 ACL 保护项），使重启不重置；或在 L3 维护跨句柄/跨进程计数。
- **验证**：脚本化 `Init→Unlock(错误)→Init→Unlock(错误)`，观察第二次仍未触发 `RATE`。

### P1-2 扫描游标接口完全不持 `api_mutex`，与写路径在同一 `FILE*` 上竞争

- **文件**：`core/src/api/scan/verthys_scan.c`（`Verthys_ScanFetch`、`Verthys_ScanSummaryFetch`、`Verthys_HasRecordByType`、`Verthys_ScanFindFirstLidByType` 全函数体内 `AcquireSRW` 命中 0 次）
- **对照**：写路径 `verthys_api.c:1154`（`Verthys_AddRecord` 取 `AcquireSRWLockExclusive`）
- **问题**：扫描内部读 `v->f`（流水线文件 `FILE*`），而 `AddRecord/Commit` 经同一 `f` 写入。同一 `FILE*` 非线程安全。
- **触发**：游标打开期间，另一线程并发 `Verthys_AddRecord`。
- **影响**：`FILE*` 内部指针竞争 → 读到错乱 extent、崩溃（UB），极端下脏读解密记录。
- **置信度**：疑似（C 层确凿无锁；是否可达取决于 L3 是否串行化）
- **修复**：给扫描接口加 `AcquireSRWLockShared(&ctx->api_mutex)`；或 extent 读改用独立 `FILE*`/pread 原生句柄。
- **验证**：游标开启时双线程跑 AddRecord + ScanFetch，ASan 观察崩溃。

### P1-3 WAL 双区换区时不清零新区残留旧帧，第三圈后可能被回放扫描

- **文件**：`core/src/transaction/wal/verthys_wal.c:475-487`
- **问题**：换区时只写新区头（24B），不清零新区残留旧帧；`wal_foreach_frame` 自 offset 24 起逐帧解 AES-GCM，仅遇 magic 不符才停。
- **触发**：A 区写满→切 B→B 区写满→切回 A（第三次换区）。A 区残留上一轮旧帧，若新写入末尾偏移恰好落在旧帧头对齐处，扫描会把旧帧当新链继续解。
- **影响**：旧帧按 txid 分组重放，最坏导致索引重放/extent 重复登记。
- **置信度**：疑似（对齐概率低，但环形第三圈后旧帧必然物理残留）
- **修复**：换区时先对新区全数据区 pwrite 零 + fsync 再写头；或每半区记录 high-water，扫描仅到 water 处停。
- **验证**：构造第三圈换区后掉电，gdb 看 replay 是否把残留旧帧解出。

### P1-4 SSTable 容量上界为"写后检查"，溢出字节已物理覆盖 extent 分区

- **文件**：`core/src/index/lsm/verthys_lsm_sstable.c:352-552`
- **问题**：所有块/bloom/索引/footer/trailer 都先 `pwrite` 落盘，最后才比对是否溢出 data_limit（552 行）。
- **触发**：单次 flush/compaction 合并多表后总大小超过 LSM 数据区剩余空间。
- **影响**：溢出字节已物理写入 LSM 数据区之外 → 落在相邻分区（extent 数据区）→ 覆写 extent 密文；返回 RESOURCE_LIMIT 但损坏已发生。
- **置信度**：确认
- **修复**：把上界预算提到写入前：按块大小累计预估，或每块写前 `abs_cursor+frame_len > data_base+data_limit` 预校验，溢出即中止不写。
- **验证**：造一个 memtable 刚好略超数据区的 flush，检查 extent 区首块是否被 SSTable trailer 覆盖。

### P1-5 delete 错误路径导致 extent 引用计数多减一次

- **文件**：`core/src/transaction/txn/verthys_transaction_v3.c:321-329`
- **问题**：321 行 `txn_ledger_record(-1)`；323 行 `extent_release`(refcount--)；329 行 `lsm_delete`。若 323 成功但 329 失败，上层重试 delete：319 行 `lsm_get` 又命中（墓碑未生效）→ 321 行再记 -1 → 323 行再 release 一次。
- **影响**：提交路径 net=-2 实际只删 1 键 → refcount 少 1 → extent 被 GC 误判 eligible → 回收仍被引用的数据块。
- **置信度**：确认
- **修复**：delete 拆成"先 lsm_delete 墓碑、成功后再 release+账本"的顺序；或错误路径禁止上层同 txn 重试 delete 而必须 abort。
- **验证**：单测 mock lsm_delete 首次失败，断言 refcount 与账本净额。

### P1-6 IPC 超时把整条请求 JSON 原样写日志，含明文密码

- **文件**：`verthys-tauri/src-tauri/src/worker/actor.rs:184-190, 246-251`
- **问题**：`log::error!("[worker] IPC 超时... 请求: {} ...", json, ...)`；`json` 含 `"password": *password`、`"bin_password": bin_password`。
- **触发**：unlock/derive/verify/change_password/export/import 等任何一次 IPC 读超时。
- **影响**：主密码/密钥口令明文落盘到日志文件，直接违反"密钥材料不进日志"设计红线。
- **置信度**：确认
- **修复**：超时分支只记录 `op`、`pid`、`stderr_snippet`，绝不记录整个 `json`；或对 json 做脱敏。
- **验证**：模拟 worker 60s 不响应，检查日志文件不含密码串。

### P1-7 暴力破解熔断不在服务端强制：`verthys_unlock` 不调用 `BruteForceGuard`

- **文件**：`verthys-tauri/src-tauri/src/controller/verthys_controller.rs:600-728`；`lib.rs:444-445`
- **问题**：unlock 全程不调用 `BruteForceGuard::check()/record_failure()`，失败计数仅由前端主动 invoke `security_brute_record_failure/success` 维护。
- **触发**：攻击者直接 Tauri invoke `verthys_unlock`，不调用 `security_brute_record_failure`。
- **影响**：10 次锁定 / 20 次 purge 的熔断形同虚设。
- **置信度**：确认
- **修复**：在 `verthys_unlock` 入口先 `BruteForceGuard::check()`；FFI 失败后由后端自身 `record_failure()`，成功后 `record_success()`。
- **验证**：连续 invoke unlock 错误口令，验证第 10 次后端返回 Locked。

### P1-8 `bin_password` 裸 `String` 未零化，明文残留控制器堆

- **文件**：`verthys-tauri/src-tauri/src/controller/key_controller.rs:189,283,285,287`
- **问题**：`bin_password: String` 被移入 `json!` 后 `req.to_string()` 形成含明文口令的普通 `String`，发送后仅 `drop(password)` 零化了主密码，`bin_password` 与 `req_str` 均未零化。
- **影响**：bin 口令明文残留在控制器堆，崩溃转储/内存取证可恢复。
- **置信度**：确认
- **修复**：`bin_password` 用 `Zeroizing<String>` 接收；发送后 `req_str.zeroize()`。
- **验证**：heap dump 检查无残留。

### P1-9 SHM 写入失败时跳过明文记录零化循环

- **文件**：`verthys-tauri/verthys-worker/src/runtime/worker.rs:399, 402-415`
- **问题**：399 行 `shm.write_records(&result, exhausted).map_err(|_| 0xFFFFFFFFu32)?;`，零化循环在 402-415。`?` 命中即 `return Err`，`result` 中 `name`/`data`（解密后明文）按普通 Vec/String drop，不零化。
- **触发**：单批记录总字节数超过 SHM 容量。
- **影响**：解密后的记录名/数据明文残留在 worker 堆。
- **置信度**：确认
- **修复**：把零化循环移到 `?` 之前的统一清理块；或用 RAII guard 持有 result 并 Drop 擦除。
- **验证**：构造超容量批次，检查错误路径后 result 缓冲已被覆写。

### P1-10 生产环境致命错误上报通道完全静默

- **文件**：`verthys-tauri/src/app/error-handler.ts:58`；`vite.config.ts:33`
- **问题**：前端 `invoke("log_fatal", ...)` 在生产分支执行，但全仓 Rust 源码 Grep `log_fatal` 0 匹配——命令未注册。且生产构建 `javascript-obfuscator` 设 `disableConsoleOutput: true`，`console.error` fallback 也被吞。
- **影响**：应用崩溃时完全无诊断信息，对安全产品是可观测性黑洞。
- **置信度**：确认
- **修复**：在 Rust 侧补 `#[tauri::command] fn log_fatal(entry: String)` 并加入 generate_handler；或前端改为已存在的日志通道。
- **验证**：触发一个 `throw`，确认后端日志文件出现 FATAL 记录。

### P1-11 README.md 未解决的 git 合并冲突标记残留

- **文件**：`README.md:1, 322, 324`
- **问题**：第 1 行 `<<<<<<< HEAD`，第 322 行 `=======`，第 324 行 `>>>>>>> c6ba26a8...`。冲突块覆盖整份文档。
- **影响**：对外交付文档损坏，说明上次合并未真正解决。
- **置信度**：确认
- **修复**：保留 HEAD 版（1-321 行），删除三行标记与对侧空壳行。
- **验证**：Grep 确认 README 无冲突标记。

### P1-12 编译内嵌兜底胡椒为 DLL 内全局固定常量

- **文件**：`core/src/crypto/pepper/verthys_pepper.c:39-44`
- **问题**：`static const uint8_t VERTHYS_PEPPER_COMPILED[VERTHYS_KEY_BYTES]={...}`，init 优先级 3 回退。
- **触发**：OS 托管不可用且未 inject/未重建 Shamir 时。
- **影响**：走 COMPILED 源的容器，pepper 对任意拿到 DLL 的人已知 → 离线口令爆破退化为纯口令熵。
- **置信度**：确认
- **修复**：兜底改为编译期开关关闭/仅调试构建启用；或对 COMPILED 源容器强制告警并拒绝新建。
- **验证**：mock load_from_os=UNAVAILABLE，断言默认构建不产生 COMPILED 源容器。

---

## 四、P2 — 中等严重（35 项摘要）

### 安全与加密类

| # | 文件:行 | 问题 |
|---|---|---|
| P2-1 | `verthys_crypto_cng.c:163-166` | `verthys_cng_aead_import_key` 失败路径不清零调用方 key |
| P2-2 | `verthys_crypto_cng.c:31-56` | 共享 AES-GCM 提供者 init 无锁，并发 open 可能句柄泄漏 |
| P2-3 | `keymanager_cng.c:433-439` | `rotate_mek` 先销毁旧 MEK 再 import 新 MEK；新 import 失败时槽位置空不回滚 |
| P2-4 | `key_separation.c:371-504` | 旧版 AEAD 的 12B nonce 由调用方外部提供，无重放保护 |
| P2-5 | `verthys_crypto_cng.c:202,229` | `size_t`→`ULONG` 强制截断无范围检查 |
| P2-6 | `verthys_rekey_auto.c:132-163` | 自动 rekey 无进行中互斥，并发写事务可能双 rotate |
| P2-7 | `verthys_export_import.c:341,454` | 导出/导入路径在 C 层不做规范化/沙箱，可写任意路径 |
| P2-8 | `defense_closure.c:228` | `all_critical_blocked` 把"无 FAILED"误报成"全部 BLOCKED" |
| P2-9 | `anti_inject.c:521-527` | 线程数启发式误报：解锁期内部线程合法增长 >2× 基线 |
| P2-10 | `v3_lifecycle.c:94` | Deinit/Lock 以 INFINITE 等待做 I/O 的工作线程，I/O 挂起即永久卡死 |
| P2-11 | `verthys_api.c:935,1050` | 允许空口令（password=NULL 且 len=0）创建/解锁 |
| P2-12 | `integrity.c:109-112` | 完整性/运行时哈希在基础设施异常时 fail-open（返回"通过"） |
| P2-13 | `runtime_hash.c:69-70,369` | `s_hbuf` 静态共享在 test_install 路径未走单飞锁 |
| P2-14 | `system32_loader.c:114-115` | 加载位置校验缺分隔符边界 |

### Rust 层 / FFI / 进程间通信类

| # | 文件:行 | 问题 |
|---|---|---|
| P2-15 | `worker.rs:357-361` | 前端可控的 `req.id` 作为 max_count，worker 一次性分配无上限（OOM DoS） |
| P2-16 | `worker.rs:169,229,722,740` | `CString::new(path).unwrap()` 对含嵌入 NUL 的路径直接 panic |
| P2-17 | `actor.rs:200; main_loop.rs:78` | 对 `BufReader::read_line` 无单行长度上限（内存耗尽） |
| P2-18 | `scan_shm.rs:338-358` | SHM 随机名与擦除用 PRNG 非 CSPRNG（墙钟 nanos+PID 种子） |
| P2-19 | `secured_string.rs:48` | `#[derive(Debug)]` 用在 SecuredString 上，Debug 会打印明文内容 |
| P2-20 | `gmk.rs:98,130-132,264` | GMK 派生中间量与导出子密钥未彻底零化 |
| P2-21 | `verthys_controller.rs:1458+` | 敏感业务命令在 Rust 侧不校验会话/解锁态，仅靠 C DLL 拒绝 |
| P2-22 | `progress_cb.rs:29-66` | `extern "C"` 回调未包 `catch_unwind`，panic 跨 FFI 边界 = UB |
| P2-23 | `key_controller.rs:607` | 响应 JSON 解析失败时把整段 `resp_json` 写日志（含 base64 子密钥） |

### 存储 / 事务 / 索引类

| # | 文件:行 | 问题 |
|---|---|---|
| P2-24 | `verthys_lsm.c:571-583` | flush 成功后新建 active memtable 失败，旧表不替换导致重复 SSTable |
| P2-25 | `verthys_lsm.c:1077-1085` | close() 在 flush_locked 失败时仍无条件销毁 memtable |
| P2-26 | `superblock_v3.c:623-643` | 读法定选举只比较 txid，不比较整块内容 |
| P2-27 | `warmcache_v3.c:250-260` | 段边界校验不完整，未校验两段不重叠反向 |

### 构建 / CI / 配置类

| # | 文件:行 | 问题 |
|---|---|---|
| P2-28 | `dep-versions.txt:561` | 快照过期：serde_json 记录 1.0.150，实际 1.0.151 |
| P2-29 | `build_production.ps1:155` | 本地构建脚本与 CI 使用完全不同的 MSVC 环境注入机制 |
| P2-30 | `ci/run_ci.ps1` | AST 双引擎门未接入 GitHub Actions（门控形同虚设） |
| P2-31 | `.clang-tidy:15,196` | clang-tidy 已配置但 CI 从不启用 |
| P2-32 | `lib.rs:389-466` | 5 个 Tauri 命令已注册但前端从不调用（死命令，扩大攻击面） |
| P2-33 | `build_dev.ps1:126` | 本地用 `npm install`，CI 用 `npm ci`，依赖解析不对齐 |
| P2-34 | `build_dev.ps1:152` | 每次构建都执行 `cargo update -p keyboard-types`，破坏 lockfile 可复现性 |
| P2-35 | `verthys_api.c:948` | 每次解锁都重开整个 DLL 文件做全段 HMAC（性能） |

---

## 五、P3 — 改进建议（33 项，分类摘要）

### 密钥/内存卫生（10 项）
- `verthys_crypto.c:112` — `combined_len = pw_len + KEY_BYTES` 无溢出守卫
- `secure_allocator.c:331-341` — free 未校验登记 magic
- `secure_allocator.c:216-218` — destroy 失败时跳过 budget_unaccount，口径不一致
- `verthys_rekey_auto.c:198-200` — 栈上 wrapped 子密钥缓冲未显式清零
- `verthys_pepper.c:49-53` — 全局 pepper 无锁非原子
- `verthys_pepper.c:391-394` — 硬件绑定失败时静默用全零 OAEP label
- `memory_guard.c:94-100` — 双重检查锁非原子
- `memory_guard.c:541-545` — 巡逻定时器重排未 CloseHandle
- `verthys_crypto.c:17-21` — `verthys_random_bytes` 返回 void，失败不可传播
- `key_separation.c:451` — 两 AEAD 实现空明文语义不一致

### API 表面 / 防御层（10 项）
- `verthys_api_utils.c:42-48` — backoff 读不持锁
- `verthys_export_import.c:156-163` — derive_master_export 失败未 zero 栈上 mek
- `v3_lifecycle.c:756-757` — change_password 失败未 zero old_mek
- `verthys_unlock_pipeline.c:401` — integrity_key 失败路径未 zero
- `verthys_progress.c:116-126` — 环形缓冲 tail 竞争
- `anti_inject.c:107-113` — TEB 偏移硬编码
- `emergency.c:39,96-124` — 看门狗事件名可预测
- `anti_debug_v2.c` — 硬件断点仅查当前线程，非持续监控
- `dllmain.c` DETACH — 加载器锁内调用 shutdown 风险
- `verthys_wal.c:724-752` — wal_reset 每笔提交全量 960KB 写+fsync（性能）

### Rust 层 / 基础设施（4 项）
- `crypto.rs:64` — 加密路径留 expect
- `shared_memory.rs:124-128` — reader 边界校验不完整
- `shared_memory.rs:67-69` — 关闭句柄错误一律 `let _ =`
- `dispatch.rs:253,280` — enumerate_records 硬编码 100k 上界

### 文档 / 配置 / 卫生（5 项）
- `CONTRIBUTING.md:68` — 悬空引用不存在的 `vcpkg.json`
- `tauri.conf.json:29` — CSP `connect-src` 放行未使用的本地端口 7778
- `rust-frontend.yml:37` — Rust 工具链未钉版本
- `rust-frontend.yml:44` — CI Node 22 vs `@types/node ^26` 不一致
- `CONTRIBUTING.md:24` — PR CI 门描述不全

---

## 六、冲突矩阵

| 冲突类别 | 具体发现 | 严重级别 |
|---|---|---|
| **接口/协议冲突** | 前端 `write_user_file` 旧 JSON-args vs Rust raw IPC（P0-1） | P0 |
| **接口/协议冲突** | 前端调 `log_fatal` 但 Rust 未注册该命令（P1-10） | P1 |
| **接口/协议冲突** | 5 个 Tauri 命令已注册但前端从不调用（死命令）（P2-32） | P2 |
| **依赖版本冲突** | `serde_json`：主应用 `=1.0.151` vs worker `"1"`（范围） | P2 |
| **依赖版本冲突** | `windows = "0.58"`（主应用）vs `windows-sys = "0.59"`（worker）— 不同 crate | 设计内 |
| **依赖版本冲突** | `zeroize`：主应用 `1.4` vs worker `1`（范围） | P2 |
| **依赖快照过期** | `dep-versions.txt` 与 Cargo.lock 不一致（serde_json）（P2-28） | P2 |
| **构建环境冲突** | 本地 `env.load.ps1` vs CI `ilammy/msvc-dev-cmd` 完全不同机制（P2-29） | P2 |
| **包管理冲突** | 本地 `npm install` vs CI `npm ci`（P2-33） | P2 |
| **锁文件污染** | 每次构建执行 `cargo update -p keyboard-types` 改写 lock（P2-34） | P2 |
| **CI 门控缺失** | AST 红线检查未接入 GitHub Actions（P2-30） | P2 |
| **CI 门控缺失** | clang-tidy 已配置但 CI 从不启用（P2-31） | P2 |
| **状态一致性冲突** | 暴力破解熔断：前端驱动 vs 服务端未强制（P1-7） | P1 |
| **状态一致性冲突** | `all_critical_blocked` 语义与实际不符（P2-8） | P2 |
| **空口令语义** | 允许空口令创建/解锁（P2-11） | P2 |
| **fail-open 冲突** | 完整性校验基础设施异常时静默通过（P2-12） | P2 |
| **文档冲突** | README 合并冲突标记残留（P1-11） | P1 |
| **文档冲突** | CONTRIBUTING 引用不存在的 vcpkg.json（P3） | P3 |
| **配置冲突** | CSP 放行未使用的 7778 端口（P3） | P3 |
| **Node 版本冲突** | CI Node 22 vs @types/node ^26（P3） | P3 |

---

## 七、修复优先级

### 第一优先级（立即修，阻断/安全红线）
1. **P0-1**：修复 `write_user_file` IPC 协议 — 照片导出功能完全不可用
2. **P1-6**：IPC 超时日志脱敏 — 密码明文落盘
3. **P1-7**：`verthys_unlock` 服务端强制 `BruteForceGuard` — 熔断形同虚设
4. **P1-12**：COMPILED pepper 兜底策略 — 离线爆破防护失效
5. **P1-11**：解决 README 合并冲突标记

### 第二优先级（本周修，数据完整性/明文泄露）
6. **P1-4**：SSTable 上界写后检查 → 溢出覆写 extent 密文
7. **P1-5**：delete 错误路径 refcount 多减 → 可能 GC 误删数据
8. **P1-3**：WAL 换区不清零 → 第三圈后旧帧重放风险
9. **P1-8**：`bin_password` 裸 String 未零化
10. **P1-9**：SHM 写入失败跳过明文零化
11. **P1-2**：扫描游标不持锁 → FILE* 竞争
12. **P1-10**：生产 fatal 日志通道静默

### 第三优先级（迭代修，纵深防御/可复现性）
13. P2-15/P2-16/P2-17：worker OOM/panic/无界读 — 进程隔离下 DoS
14. P2-19：SecuredString Debug 泄露
15. P2-22：FFI 回调未 catch_unwind
16. P2-29/P2-30/P2-31：CI 门控对齐与左移
17. P2-1/P2-3/P2-4：密钥生命周期边角

---

## 八、回归测试建议

### 必须新增的测试用例
1. **P0-1**：Tauri 模式导出照片 → 验证文件落盘
2. **P1-1**：`Init→Unlock(错误)→Init→Unlock(错误)` → 验证第二次仍触发 RATE
3. **P1-3**：WAL 第三圈换区后掉电 → 验证 replay 不重放旧帧
4. **P1-4**：memtable 刚好略超 LSM 数据区 → 验证 extent 区未被覆盖
5. **P1-5**：mock lsm_delete 首次失败 → 断言 refcount 与账本净额正确
6. **P1-6**：模拟 worker 超时 → 验证日志不含密码串
7. **P1-7**：连续 invoke unlock 错误口令 10 次 → 验证后端返回 Locked
8. **P1-9**：构造超 SHM 容量批次 → 验证错误路径后 result 已零化

### 应补充的 CI 门
9. GitHub Actions 接入 `ci/run_ci.ps1` AST 检查
10. GitHub Actions 启用 clang-tidy
11. CI 增加 `build_production.ps1` 本地脚本验证 job
12. Rust 工具链钉版本（`rust-toolchain.toml`）

---

## 九、工程化改进路线

### 短期（1-2 周）
- 修复 P0 + P1 全部项
- 解决 README 冲突标记
- 清理 5 个死 Tauri 命令（或补前端调用）
- 统一 `npm ci` / `cargo update` 脚本行为

### 中期（1 个月）
- 暴力破解计数持久化（机器级，跨句柄/跨进程）
- WAL 换区清零 + high-water 机制
- SSTable 写前预算检查
- FFI 回调 `catch_unwind` 全覆盖
- SecuredString 手动 Debug 实现
- CI 补齐 AST + clang-tidy + 构建脚本验证

### 长期（季度级）
- 统一 AEAD 空明文语义与 nonce 管理（下线旧 `key_separation_aead_*`）
- 扫描路径改为 pread 原生句柄或加读锁
- SHM 名称与擦除改用 BCryptGenRandom
- 完整性校验 fail-open 改为可观测（基础设施异常也上报）
- 建立 fuzz 测试集（索引解析、WAL replay、SSTable 写入）

---

## 十、已核对为正确/无问题的重点项（避免误报）

- **rekey 结构拷贝**：`VerthysPartitionTable.entries` 是内联定长数组，按值拷贝 → 失败路径栈副本不污染活态 ptable
- **secure_zero 实现**：用 `SecureZeroMemory`，不存在被编译器优化消除
- **pepper 文件原子写**：tmp+fflush/_commit+MoveFileEx(REPLACE|WRITE_THROUGH) 正确
- **superblock 写后读验证**：三副本 2/3 法定数读路径正确
- **LSM 原子切换**：新表落盘后才插 Manifest，失败回滚 next_data_offset
- **SHM 协议双端同源**：`shm_schema.rs` `include!` + `const_assert_eq` 编译期布局校验
- **worker 孤儿进程防护**：Job Object `KILL_ON_JOB_CLOSE` + kill_on_drop + 超时 graceful shutdown
- **GMK 主密钥隔离**：确实锁在 worker 进程 thread_local，控制器侧未持有 GMK 字节
- **v-html XSS**：4 处 `v-html` 数据源均为硬编码 SVG，无 XSS
- **localStorage**：仅存 feature-flags，未存密码/密钥
- **CMake 加固**：/GS、/guard:cf、/sdl、/DYNAMICBASE、/NXCOMPAT、/CETCOMPAT、/LTCG 真实生效
- **版本号一致性**：package.json / Cargo.toml / tauri.conf.json / CMakeLists 均为 2.6.1

---

*报告结束。所有行号均经实际 Grep/Read 定位；未实际验证处标注"疑似"或"需验证"。*
