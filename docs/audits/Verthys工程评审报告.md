# Verthys v2.6.1 全量工程化代码评审报告

- 评审日期：2026-09-20
- 评审范围：`C:\Users\Administrator\Desktop\Verthys`（L2 C 核心 84 .c / 61 .h；L3 Rust src-tauri 87 .rs + worker 13 .rs；L4 Vue3/TS 146 文件；构建/CI/配置/依赖）
- 评审方法：按「层 + 域」分 5 片并行深审（A 密钥与安全内存 / B 容器事务索引 / C API 与防御层 / D Rust 控制器与 worker / E 前端与构建 CI），每片端到端完成"读取→分析→定级→证据收集"，本报告合并去重、构建冲突矩阵与修复优先级。
- 红线遵守：全程只读，未修改源码、未执行破坏性命令、未复述任何真实密钥/pepper/口令字节（硬编码项仅报位置与类型）。
- 证据规则：所有行号均经 Grep/Read 实际定位；未独立验证处标注「需验证」。

---

## 一、项目概览

Verthys 是面向 Windows 的私密数据管理器 v2.6.1，敏感数据封装进加密容器 `.verthys`，C11 编写的 `verthys.dll`（L2）承担密码守护、解密、运行时完整性校验与抗窥探。**核心设计红线：密钥材料只存 L2，UI/调度层从设计上不接触密钥。**

| 维度 | 事实 |
|---|---|
| 语言/运行时 | L2 C11/C++17；L3 Rust（Tauri 2 控制器 + 独立 worker 子进程）；L4 Vue 3 + TypeScript 5 + Vite |
| 四层架构 | L4 前端（纯渲染）→ L3 Rust 控制器+worker（进程隔离/会话/安全命令，零密钥接触）→ L2 `verthys.dll`（黑盒）→ L1 `.verthys` 容器 + pepper.bin + idx_cache |
| 通信 | 控制器↔worker：stdin/stdout JSON 行协议；扫描结果：命名共享内存（shm）零拷贝；前端↔控制器：Tauri invoke |
| 容器格式 | V3，超块 3 副本 2/3 法定，6 阶段事务，WAL 环形双区，LSM 索引 + warmcache，4 级密钥层级，90d/10k ops 自动轮换，ABI 0x000B |
| 构建 | 根 CMake（Release/UNICODE/NOMINMAX）+ `cmake/VerthysHardening.cmake` 编译加固 + vendored libsodium/flatcc；PowerShell 脚本 `build_dev.ps1` / `build_production.ps1` |
| CI | `.github/workflows/core.yml` + `rust-frontend.yml`；本地 `ci/run_ci.ps1`（AST 红线门） |
| 依赖锁定 | 两个 `Cargo.lock` 均存在；`package-lock.json` 存在；`dep-versions.txt` 为人工快照 |

**架构上值得肯定的骨架**（多片独立复核确认成立，不展开为缺陷）：超块写后读验证 + 读法定丢弃半写；LSM 新表落盘后才插 Manifest 且失败回滚；extent"先落数据块后改索引"保证孤儿不可达；warmcache 任意失败静默回退冷启动；GMK 锁在 worker thread_local 并随 Drop 清零；worker 孤儿进程靠 Job Object `KILL_ON_JOB_CLOSE`；SHM 双端同源布局有编译期 `const_assert_eq`；emergency 三级响应、syscall_direct SSN 提取/W^X/Strict CFG、job_isolation 精确回滚、CNG 机器密钥不覆盖既有密钥、security_preset 双缓冲原子切换——均为自洽实现。

---

## 二、风险总览

| 级别 | A 密钥/内存 | B 容器/事务/索引 | C API/防御 | D Rust/worker | E 前端/构建/CI | 合计 |
|---|---|---|---|---|---|---|
| **P0** 阻断/高危 | 0 | 0 | 0 | 0 | **1** | **1** |
| **P1** 严重 | 1 | 3 | 2 | 4 | 2 | **12** |
| **P2** 中等 | 6 | 4 | 9 | 9 | 7 | **35** |
| **P3** 改进 | 10 | 4 | 10 | 4 | 5 | **33** |
| 小计 | 17 | 11 | 21 | 17 | 15 | **82** |

**一句话结论**：无远程 RCE 级 P0；唯一 P0 是前后端 IPC 协议漂移导致的功能必现故障。真正高危的是**跨层设计冲突**——暴力破解防护在三层各自实现但无一在真实咽喉点强制、密钥/明文零化在错误路径系统性缺失、日志同时"泄密"与"失明"——这些叠加后使产品安全主张与实际防护之间存在明显缺口。

### P0 清单（1 项，必须立即修）

| # | 文件:行 | 问题 | 影响 | 置信度 |
|---|---|---|---|---|
| P0-1 | `verthys-tauri/src/composables/photo-album/usePhotoExport.ts:71` ↔ `src-tauri/src/controller/file_controller.rs:1057-1074` | `writeVencFile` 仍用旧 `invoke("write_user_file", { path, dataB64 })` JSON-args 协议；Rust 端已迁移 raw IPC（`x-path` 头 + `InvokeBody::Raw` body），无 `x-path` 头直接返回 `InvalidPath`。正确范式见 `verthys.ts:1188` 的 `writeUserFile()` | Tauri 模式下拾光模块导出照片到磁盘 **100% 失败**（功能不可用） | 确认（已实测定位双端代码） |

---

## 三、P1 详细发现（12 项）

### 安全红线类

**P1-1 【跨层·最严重】暴力破解防护三层断裂，真实威胁模型下不构成减速**
- 证据链：
  - `core/src/api/shared/verthys_api_utils.c:40-61` + `core/src/api/lifecycle/verthys_api.c:247/587/939`：C 层指数退避计数 `failed_attempts` 存于 `VerthysContext` 堆，**按句柄记账、不持久化、不跨句柄**；`Verthys_Init` 新句柄即 `calloc` 清零；进程重启即清零。
  - `src-tauri/src/controller/verthys_controller.rs:600-728`：Rust `BruteForceGuard` 已实现（冻结/不可逆累计/DPAPI 持久化/抖动均正确），但 `verthys_unlock` 全程**不调用** `check()/record_failure()/record_success()`；失败计数仅靠前端主动 invoke `security_brute_record_failure` 维护。
- 触发：攻击者拿到 `.verthys` 后在受控环境反复 `Verthys_Init → Unlock(guess)`，或直接 Tauri invoke `verthys_unlock` 而不调记录命令。
- 影响：10 次锁定/20 次 purge 形同虚设；在线绕过 + 离线穷举均无实际减速，唯一成本是 Argon2id 算力。
- 置信度：确认（代码事实）。
- 修复：① `verthys_unlock` 入口先 `BruteForceGuard::check()`，失败由后端自身 `record_failure()`/成功 `record_success()`，不依赖前端；② C 层错误计数落到机器级不可删改位置（CNG 不透明 blob / MachineGuid-HMAC 持久计数），重启不重置。

**P1-2 【跨层】IPC 超时把含明文口令的整条请求 JSON 写日志**
- `src-tauri/src/worker/actor.rs:185 / 247`：`log::error!("[worker] IPC 超时... 请求: {} | stderr: {}", ..., json, ...)`，`json` 即 `req.to_string()`，内含 `"password"` / `"bin_password"` 明文。
- 触发：unlock/derive/verify/change_password/export/import 任一 IPC 读超时（worker 挂起、FFI 阻塞、stdin 写入后无响应）。
- 影响：主密码明文落盘，直接击穿"密钥材料不进日志"红线。
- 修复：超时分支只记 `op/pid/stderr_snippet`；或对 json 脱敏（password/bin_password 值替换 `***`）。

**P1-3 `bin_password` 与请求串未零化**
- `src-tauri/src/controller/key_controller.rs:189/283-287`：`bin_password: String` 是裸 `String`（非 `Zeroizing`），移入 `json!` 后 `req.to_string()` 形成含明文口令的普通 `String`，发送后只 `drop(password)` 零化主密码，`bin_password` 与 `req_str` 均未零化（verify 路径同构：352/461/464/466）。
- 影响：bin 口令明文残留在控制器堆，崩溃转储/内存取证可恢复。
- 修复：`Zeroizing<String>` 接收；`req_str.zeroize()`；序列化走一次性临时缓冲。

**P1-4 SHM 写失败提前返回，跳过硬明文记录零化循环**
- `verthys-worker/src/runtime/worker.rs:399`（全量）/ `:610`（摘要）：`shm.write_records(...).map_err(...)?;` 命中即 `return Err`，紧随其后的明文记录 `name/data` 零化循环（402-415 / 613-624）被跳过，按普通 Vec/String drop 不零化。
- 触发：单批记录总字节超过 SHM 容量。
- 影响：解密后记录名/数据明文残留 worker 堆。
- 修复：零化移到 `?` 之前的统一清理块，或 RAII guard 持有 result 并在 Drop 擦除。

**P1-5 编译内嵌兜底 pepper 是 DLL 内全局固定常量**
- `core/src/crypto/pepper/verthys_pepper.c:39-44`：`static const uint8_t VERTHYS_PEPPER_COMPILED[32] = {...}`，init 优先级 3 回退（:535-540）。
- 触发：OS 托管不可用（无 APPDATA/非标准路径）且未 inject/未重建 Shamir 时。
- 影响：走 COMPILED 源的容器对任何拿到 DLL 的人等于无 pepper，离线爆破退化为纯口令熵。
- 修复：默认构建禁用该兜底（仅 debug 启用）；或对 COMPILED 源容器解锁时强告警/拒绝新建；文档标注其强度等同无 pepper。

### 存储引擎数据完整性类

**P1-6 WAL 双区换区不清零，第三圈后残留旧帧可能被回放**
- `core/src/transaction/wal/verthys_wal.c:475-487`：换区只写 24B 新区头，不清零新区数据区；`wal_foreach_frame`（251-330）自 offset 24 起逐帧解 AES-GCM 直到 magic 不符。
- 触发：A 写满→B→A（第三次换区）后掉电，新写入末尾偏移恰好落在旧帧对齐处。
- 影响：靠 `committed_txid` 水位（:604）兜底；但旧组 `has_prepare` 且水位未推高时会被 redrive → 索引重放/extent 重复登记。
- 置信度：疑似（对齐概率低，但环形第三圈后旧帧必然物理残留）。
- 修复：换区时先 pwrite 零 + fsync 新区数据区再写头；或每半区记 high-water，扫描只到 water。

**P1-7 SSTable 容量上界是"写后检查"，溢出字节已物理覆写 extent 密文**
- `core/src/index/lsm/verthys_lsm_sstable.c:352-552`：块/bloom/索引/footer/trailer 全部 `vio_pwrite64` 落盘后，:552 才比对是否溢出 `data_limit`。
- 触发：单次 flush/compaction 合并多表后总大小超过 LSM 数据区剩余。
- 影响：溢出字节已写到 LSM 数据区之外 → 落在相邻 extent 数据区 → 覆写 extent 密文（HMAC 仍可过）→ 解密 AUTH。
- 置信度：确认（顺序明确）。
- 修复：上界预算提到写入前，每块写前 `abs_cursor+frame_len > data_base+data_limit` 预校验，溢出即中止不写。

**P1-8 delete 在 `extent_release` 与 `lsm_delete` 之间失败重试，extent 引用计数多减**
- `core/src/transaction/txn/verthys_transaction_v3.c:321-329`：321 记账本 -1；323 `extent_release`（refcount--）；329 `lsm_delete`。若 323 成功 329 失败，上层按幂等重试：319 `lsm_get` 又命中（墓碑未生效）→ 再记 -1、再 release → net=-2。
- 影响：提交路径 refcount 少 1 → extent 被 GC 误回收仍被引用的数据块；回滚路径幽灵引用永久泄漏。
- 修复：改为"先 lsm_delete 墓碑、成功后再 release+账本"；或错误路径禁止同 txn 重试 delete，必须 abort。

### 并发与功能类

**P1-9 扫描游标系列接口完全不持 `api_mutex`，与写路径竞争同一 `FILE*`**
- `core/src/api/scan/verthys_scan.c`：`Verthys_ScanFetch/ScanSummaryFetch/HasRecordByType/ScanFindFirstLidByType` 函数体内 `AcquireSRW` 命中 0 次；却经 `scan_v3_fetch → verthys_extent_get` 读共享 `v->f`。写路径 `verthys_api.c:1154` `Verthys_AddRecord` 持 `AcquireSRWLockExclusive`。`vio_pread64` 内部 `_fseeki64+fread`，同一 `FILE*` 非线程安全。
- 触发：游标打开期间另一线程并发 AddRecord。
- 影响：读到错乱 extent/崩溃（UB），极端下脏读解密记录。
- 置信度：疑似（取决于 L3 worker 是否串行化扫描与写——需验证）。
- 修复：游标读接口加 `AcquireSRWLockShared`，或 extent 读改用独立句柄/原生 pread。

**P1-10 生产致命错误上报通道完全静默**
- `verthys-tauri/src/app/error-handler.ts:58` 调 `invoke("log_fatal", ...)`，但全仓 Rust 源码 `log_fatal` 0 匹配，`generate_handler!`（`src-tauri/src/lib.rs:388-467`）未注册；生产混淆 `vite.config.ts:33` `disableConsoleOutput: true` 又吞掉 `console.error` 兜底。
- 影响：未捕获异常/unhandledrejection 既不写后端日志也不显示 console，崩溃时无诊断——对安全产品是可观测性黑洞。
- 修复：补 Rust `#[command] fn log_fatal` 并入 generate_handler，或前端改走已存在的日志通道。

**P1-11 README.md 残留未解决的 git 合并冲突**
- `README.md:1` `<<<<<<< HEAD`、`:322` `=======`、`:324` `>>>>>>> c6ba26…`，冲突块覆盖整份文档（HEAD 侧 1-321，对侧仅 323 一行 `# Verthys`）。全仓 grep 确认冲突标记仅存在于 README，未污染源码。
- 影响：对外交付文档损坏，说明上次合并未真正解决。
- 修复：保留 HEAD 版，删除三处标记与对侧空壳行。

**P1-12 （见 P1-1 的 C 层侧）退避按句柄 RAM 记账——独立列出以便追踪**
- 即 P1-1 的 C 侧证据，此处不重复。

---

## 四、P2 详细发现（35 项，按主题分组）

### A. 密钥/内存/密码学（片 A，6 项）

| 文件:行 | 问题 | 置信度 |
|---|---|---|
| `crypto/cipher/verthys_crypto_cng.c:163-166`（+ `keymanager_cng.c:278-283`） | `import_key` 失败路径不清零调用方 key，而 `verify_mek` 注释却声称已清——改密时候选 MEK 在 CNG 故障下泄漏到调用方栈/堆 | 确认 |
| `crypto/cipher/verthys_crypto_cng.c:58-78` | 共享 AES-GCM provider init 仅靠 refcount 幂等、无锁，存在双重 open/句柄泄漏与 refs 失配竞态（启动单线程时不可达） | 疑似 |
| `crypto/keymanager/keymanager_cng.c:433-439` | `rotate_mek` 先毁旧 MEK 再 import 新 MEK，新 import 失败留空槽不回滚（头文件已声明为已接受降级） | 确认（已接受） |
| `security/memory/key_separation.c:371-504` | 旧版 AEAD 的 12B nonce 完全由外部传入、无内部计数器/重放保护；GCM nonce 复用风险全靠调用方纪律 | 疑似 |
| `crypto/cipher/verthys_crypto_cng.c:202/229/234/283/288` 等 | `size_t`→`ULONG` 强制截断无范围检查；`pt_len+TAG` 相加无溢出守卫 | 确认 |
| `crypto/rekey/verthys_rekey_auto.c:132-163/182-225` | 自动 rekey 无 in-progress 互斥；24h 防震荡仅看时间不看"已在轮换"，并发写可能双次 rotate | 疑似 |

### B. 容器/事务/索引（片 B，4 项）

| 文件:行 | 问题 | 置信度 |
|---|---|---|
| `index/lsm/verthys_lsm.c:571-583` | flush 成功后新建 active memtable 失败直接返回，旧 memtable 不替换 → 后续 put 重复写已持久化条目，下次 flush 产生重复 SSTable | 疑似 |
| `index/lsm/verthys_lsm.c:1077-1085` | close() 在 flush 失败时仍无条件销毁 memtable；WAL 未 reset，数据靠下次 open 重放兜底，语义依赖调用方 | 疑似 |
| `container/superblock/verthys_superblock_v3.c:623-643` | 读法定选举只比 txid 不比内容（当前被整块 HMAC 兜底，属纵深缺口） | 改进 |
| `index/warmcache/verthys_warmcache_v3.c:250-260` | 段边界校验允许 `mt_off==file_len`、未双向校验两段不重叠（被整文件 HMAC 保护） | 改进 |

### C. API/防御层（片 C，9 项）

| 文件:行 | 问题 | 置信度 |
|---|---|---|
| `security/layer6_closure/defense_closure.c:228` | `all_critical_blocked = (failed_count==0)` 把"全 DEGRADED"误报成"全部 BLOCKED"，安全姿态失真 | 确认 |
| `api/transfer/verthys_export_import.c:341/454`（+136/435） | 导出/导入路径在 C 层不做规范化/沙箱，可写/读任意路径（可利用性取决于 L3 约束） | 确认 |
| `security/anti_inject.c:521-527` | 线程数启发式 `>=2×基线` 即报 INJECT；解锁期内部线程合法增长易误报 → 累计后 DEGRADE 锁库 | 疑似 |
| `api/lifecycle/verthys_v3_lifecycle.c:94`（+ progress destroy） | Deinit/Lock 以 `WaitForSingleObject(..., INFINITE)` 等做 I/O 的工作线程；I/O 挂起即永久卡死 | 确认 |
| `api/lifecycle/verthys_api.c:935/1050` | 允许空口令（NULL 且 len=0）建库/解锁，Argon2id 输入空串，主密钥熵近乎零 | 疑似（可能为有意硬件绑定免密） |
| `security/integrity/integrity.c:109-112/235/241/255/647` + `runtime_hash.c:295` | 完整性/运行时哈希在基础设施异常时 fail-open（返回"通过"），攻击者诱发失败可绕过篡改检测 | 确认（设计如此） |
| `api/lifecycle/verthys_api.c:948` + `integrity.c:579-672` | 每次解锁都重开整个 DLL 做全段 HMAC，解锁延迟显著增加 | 确认（性能） |
| `security/integrity/runtime_hash.c:69-70/184-185/369` | `s_hbuf` 静态共享；scan 有单飞锁但 `test_install` 不持，生产误调会哈希错 → 误判篡改 → emergency KILL | 疑似 |
| `security/layer3_hw_binding/system32_loader.c:114-115` | 加载位置前缀比较缺分隔符边界（与已修的 anti_inject 同款缺陷）；`LOAD_LIBRARY_SEARCH_SYSTEM32` 已强制真 System32，故为纵深缺口 | 确认 |

### D. Rust/worker（片 D，9 项）

| 文件:行 | 问题 | 置信度 |
|---|---|---|
| `worker/runtime/worker.rs:357-361/558-569`（+ dispatch.rs:320/368） | 前端可控 `req.id` 作为 `max_count`，`(0..mc).collect()` 无上限 → 恶意 invoke 传超大 id 使 worker OOM | 确认 |
| `worker/runtime/worker.rs:169/229/722/740` | `CString::new(path).unwrap()` 对含嵌入 NUL 路径直接 panic → worker 崩溃（DoS） | 确认 |
| `worker/actor.rs:200` + `worker/runtime/main_loop.rs:78` | `read_line`/`lines()` 无单行长度上限，对端不换行超长流可致内存耗尽 | 确认 |
| `worker/runtime/scan_shm.rs:338-378` | SHM 随机名与擦除 PRNG 均以 wall-nanos+PID 为种子的 xorshift64*，非 CSPRNG；同用户 malware 可猜名称 | 确认 |
| `src-tauri/src/util/secured_string.rs:48` | `#[derive(Debug)]` 包 `Zeroizing<String>`，`{:?}` 会打印明文内容，违背同文件 27 行自定红线 | 确认 |
| `worker/runtime/gmk.rs:98/130-132/264` + `worker.rs:147/723/741` | GMK 派生 PRK、模块子密钥 okm、password 透传 FFI 后未显式 zeroize | 疑似 |
| `src-tauri/src/controller/verthys_controller.rs:1458/1478/1619/1686/1710/1734` | 敏感业务命令（add/get/delete/export/import/change_password/derive_subkey）Rust 侧不校验解锁态，全靠 C 层 LOCKED 拒绝，缺第二道闸门 | 确认（设计层） |
| `worker/runtime/progress_cb.rs:29-66` + worker FFI 调用 | `extern "C"` 回调与 FFI 调用未包 `catch_unwind`，panic 跨 FFI 边界 = UB，通常 abort worker | 确认 |
| `src-tauri/src/controller/key_controller.rs:607`（+303/482/669） | 响应 JSON 解析失败时把整段 `resp_json` 写日志；derive_subkey 响应含 base64 模块子密钥 | 确认 |

### E. 前端/构建/CI（片 E，7 项）

| 文件:行 | 问题 | 置信度 |
|---|---|---|
| `dep-versions.txt:561`（+ Cargo.lock:2954 / Cargo.toml:118） | 快照过期：记 `serde_json 1.0.150`，实际 lock 为 `1.0.151` | 确认 |
| `build_production.ps1:155` + `scripts/env.load.ps1:47-50` vs `.github/workflows/core.yml:35` | 本地用 `env.load.ps1` 强依赖 4 个自定义 env；CI 用 `ilammy/msvc-dev-cmd`，两套 MSVC 注入路径不互通，CI 绿≠本地脚本通 | 确认 |
| `ci/run_ci.ps1`（对照两个 workflow） | 架构红线 AST 双引擎门（regex_scan + ast_analyze）未接入 GitHub Actions，PR 合入不强制 | 确认 |
| `.clang-tidy:15/196`（对照 workflow） | clang-tidy 已配 `WarningsAsErrors` 但 CI 从不启用；示例路径 `build_ninja` 与实际 `build_ci` 不符 | 确认 |
| `src-tauri/src/lib.rs:389-466` | 5 个 Tauri 命令注册后前端从不调用（`diag_info`/`verthys_scan_abort`/`verthys_scan_summary_abort`/`verthys_derive_subkey`/`security_generate_auth_token`），无谓扩大 IPC 攻击面 | 确认 |
| `build_dev.ps1:126` / `build_production.ps1:178` | 本地 `npm install` 可升级 semver 范围，CI `npm ci` 严格按 lock，依赖解析不对齐 | 确认 |
| `build_dev.ps1:152` / `build_production.ps1:215` | 每次构建都 `cargo update -p keyboard-types` 改写 Cargo.lock，破坏可复现性 | 确认 |

---

## 五、P3 摘要（33 项，完整明细见各分片文件）

- **片 A（10 项）**：`verthys_crypto.c:112` pw_len 加法无溢出守卫；`secure_allocator.c:331` free 未校 magic（文档声称有）；`secure_allocator.c:216/333` destroy/free 记账口径不一；`rekey_auto.c:198/370/403` 栈上 wrapped 子密钥未 zero；`verthys_pepper.c:49` 全局非原子；`pepper.c:391` 硬件绑定失败静默用全零 OAEP label；`memory_guard.c:94` 双重检查锁非原子；`memory_guard.c:541` 巡逻定时器重排未 CloseHandle；`crypto.c:17` `random_bytes` 无返回值；`key_separation.c:451` 新旧 AEAD 空明文语义不一致。
- **片 B（4 项）**：`wal.c:724-752` 每笔 commit 都 pwrite 960KB 再 fsync（性能）；`partition.c:258-271` grow 只更内存 size 不校验越界；`lsm.c:1792` scan_next 死变量；`format.c:752` 索引条目 name_len 无业务上限（被 AEAD 兜底）。
- **片 C（10 项）**：`api_utils.c:42` backoff 读取不持锁（best-effort）；`export_import.c:156` derive 失败仅 zero salt 未 zero 栈上 mek；`v3_lifecycle.c:756` change_password 失败未 zero old_mek；`unlock_pipeline.c` S3 失败未 zero integrity_key；`progress.c:116` 环形缓冲 tail 竞争（偶发丢/重条目）；`anti_inject.c:107` TEB 偏移硬编码；`emergency.c:39/96` 看门狗事件名可预测且无 DACL；`anti_debug_v2` 硬件断点只查当前线程非持续监控；`v3_lifecycle.c` S5 资源回收（**经核对为正确闭环，非缺陷**）；`dllmain.c` DETACH 在加载器锁内调 shutdown（当前较轻）。
- **片 D（4 项）**：`util/crypto.rs:64` 加密路径留 `expect`；`infrastructure/shared_memory.rs:124` reader 边界校验未查 offset 落在哪个区；`shared_memory.rs` 多处 `let _ =` 吞清理错误；`worker/dispatch.rs:253/280` enumerate 硬编码上界 `100_000`。
- **片 E（5 项）**：`CONTRIBUTING.md:68` 悬空引用不存在的 `vcpkg.json`；`tauri.conf.json:29` CSP 放行未使用的 7778 端口；`rust-frontend.yml:37` Rust 工具链未钉版；`rust-frontend.yml:44` CI Node 22 vs `@types/node ^26`；`CONTRIBUTING.md:24` PR 门描述漏列 rust-frontend.yml。

---

## 六、冲突矩阵（用户重点要求）

| 冲突维度 | 发现 | 证据位置 |
|---|---|---|
| **业务规则冲突（最严重）** | 暴力破解防护在 C 层（按句柄 RAM 记账）、Rust 层（BruteForceGuard 已实现但 unlock 不调）、前端层（唯一实际驱动方）三处各做各的，**无任何一层在真实咽喉点强制** | C: `verthys_api_utils.c:40`；Rust: `verthys_controller.rs:600-728`；前端: `security_brute_record_failure` |
| **接口冲突（前后端契约）** | `write_user_file` 前端用 JSON-args、后端已迁 raw IPC（x-path 头 + raw body）→ 导出必挂（P0）；`log_fatal` 前端调用、后端未注册 → 致命错误丢失；5 个后端命令前端从不调用（死命令+攻击面） | E/P0, E/P1, E/P2 |
| **错误处理冲突** | 成功路径普遍做了 zeroize，但**错误路径系统性漏 zeroize**（CNG import_key、C 栈上 mek/integrity_key、Rust bin_password、SHM 写失败、GMK 中间量）——同一类问题跨 A/C/D 三片重复出现 | A/P2, C/P3-2/3/4, D/P1-3/4/P2 |
| **日志策略冲突** | 同一代码库既把秘密写进日志（password/subkey/SecuredString Debug），又把致命错误堵在日志外（log_fatal 未注册 + 混淆器禁 console） | D/P1-1, D/P2, E/P1 |
| **并发/锁冲突** | 写路径持 `api_mutex` 独占，但 scan 游标系列完全不持锁却读共享 `FILE*`；provider init/rekey/runtime_hash 各自的共享状态无统一互斥纪律 | C/P1-2, A/P2, C/P2-8 |
| **配置/构建冲突** | 本地 MSVC 注入（env.load.ps1）与 CI（ilammy/msvc-dev-cmd）两套路径；`npm install` vs `npm ci`；每次构建 `cargo update` 改 lock；dep-versions 快照过期；Rust 工具链未钉版 | E/P2 系列 |
| **门控缺失冲突** | 设计文档宣称的 AST 红线门、clang-tidy `WarningsAsErrors` 均未接入 CI，PR 合入不强制 | E/P2 |
| **命名/版本冲突** | 版本号 2.6.1 全仓一致（无冲突）；serde_json 快照 1.0.150 vs 实际 1.0.151（轻微漂移）；CI Node 22 vs `@types/node ^26` | E/P2, E/P3 |
| **路径安全冲突** | C 层 export/import 不做路径规范化/沙箱，安全性完全寄托 L3 先约束（纵深缺口） | C/P2-2 |
| **文档冲突** | README 未解决合并冲突；CONTRIBUTING 引用不存在的 vcpkg.json、漏列 rust-frontend.yml | E/P1, E/P3 |

---

## 七、修复优先级（建议执行顺序）

**第 0 批（立即，阻断功能/击穿红线）**
1. **P0-1** `write_user_file` 协议错配 → `usePhotoExport.ts:71` 改调已有的 `writeUserFile(path, bytes)`。
2. **P1-2** worker IPC 超时日志脱敏（password/bin_password/subkey）。
3. **P1-1** `verthys_unlock` 服务端强制 `BruteForceGuard::check()/record_failure()/record_success()`；C 层错误计数改机器级持久化。
4. **P1-10** 补 Rust `log_fatal` 命令注册，恢复致命错误上报通道。
5. **P1-11** 解决 README 合并冲突。

**第 1 批（本迭代，数据完整性 + 密钥零化）**
6. **P1-7** SSTable 容量检查改为写前预算（防止覆写 extent 密文）。
7. **P1-8** delete 改"先墓碑后 release+账本"，错误路径禁止同 txn 重试。
8. **P1-6** WAL 换区清零新区数据区或记 high-water。
9. **P1-3/4** bin_password 改 `Zeroizing`、SHM 失败路径统一 zeroize。
10. **P1-5** 编译内嵌兜底 pepper 默认构建禁用。
11. **P1-9** scan 游标接口加共享读锁（先验证 L3 worker 是否已串行化）。

**第 2 批（下个迭代，纵深 + 稳定性）**
12. D 片 P2：worker max_count 上限、`CString::new` 不 panic、read_line 上限、SHM 名称/擦除改 BCryptGenRandom、SecuredString 手动 Debug、FFI 回调 catch_unwind。
13. A 片 P2：CNG import_key 失败清零、provider init 用 InitOnceExecuteOnce、旧 AEAD nonce 加计数器、size_t→ULONG 范围检。
14. C 片 P2：export/import 路径沙箱、anti_inject 基线重采样/自有线程白名单、Deinit 等待改超时、integrity fail-open 改遥测。
15. B 片 P2：flush 后 memtable 替换失败处置、close 失败 dirty 语义。
16. E 片 P2：CI 接入 `ci/run_ci.ps1` AST 门与 clang-tidy；统一 npm ci；去掉 `cargo update`；更新 dep-versions；清理 5 个死命令。

**第 3 批（持续改进，P3 与卫生项）**：按第五节清单逐项消化。

---

## 八、回归测试建议

| 主题 | 测试方法 |
|---|---|
| 导出写盘 | Tauri 模式导出单张/多张/PNG 照片，断言文件落盘且内容正确（覆盖 P0-1） |
| 口令爆破 | 连续 invoke unlock 错误口令，断言第 10 次后端自返 Locked、第 20 次 Purge；重启进程后计数不重置（覆盖 P1-1） |
| 日志脱敏 | 模拟 worker 60s 不响应，grep 日志文件不含 password/bin_password/subkey 明文（覆盖 P1-2） |
| 密钥零化 | heap/stack dump 或 ASAN 检查 unlock/derive/change_password 成功与失败路径后，敏感缓冲全 0（覆盖 P1-3/4、A/C 各 zeroize 项） |
| SSTable 越界 | 构造 memtable 略超 LSM 数据区的 flush，断言 extent 区首块未被 SSTable trailer 覆盖（覆盖 P1-7） |
| delete 重试 | mock `lsm_delete` 首次失败，断言 refcount 与账本净额一致、无幽灵引用（覆盖 P1-8） |
| WAL 换区 | 第三圈换区后掉电，gdb 验证 replay 未把残留旧帧 redrive（覆盖 P1-6） |
| scan 并发 | 游标开启时双线程 AddRecord + ScanFetch，ASan/压力跑无崩溃无校验和不一致（覆盖 P1-9） |
| worker 健壮性 | 传含 `\0` 路径、1e8 max_count、100MB 无换行流，断言均优雅返回错误而非 panic/OOM（覆盖 D 片 P2） |
| CI 红线 | 提一个含 AST 红线违规与 clang-tidy 告警的 PR，断言 CI 变红（覆盖 E 片 P2 门控） |

---

## 九、工程化改进路线

1. **把安全强制点收到 L3 咽喉**：所有"是否允许/是否锁定/失败计数"的决策在 Rust 控制器入口统一判定，不信任前端上报、不依赖 C 层单点——当前 P1-1 就是反面教材。
2. **建立"错误路径零化"静态检查**：对所有持有 `Zeroizing`/`SecureZeroMemory` 的函数，要求所有 return 分支都经过统一清理块；可在 CI 加一条 grep 规则（函数内有 zeroize 但存在未 zeroize 的 early return）。
3. **前后端契约自动校验**：把 Rust `#[command]` 函数名与 TS `ipc<T>("...")` 字符串抽取成清单，在 CI 做 diff（本次 P0/P1/E/P2 死命令全靠人肉 grep 发现）。
4. **统一构建环境**：本地 `build_production.ps1` 与 CI 走同一套 MSVC 注入（或 CI 直接跑该脚本），统一 `npm ci`、去掉 `cargo update`、钉 Rust 工具链到 `rust-toolchain.toml`。
5. **门控真接入 CI**：`ci/run_ci.ps1`（AST 双引擎）+ clang-tidy `WarningsAsErrors` 作为 PR 阻断 job。
6. **可观测性修复**：`log_fatal` 注册 + 日志分级脱敏约定 + 生产构建保留致命错误通道（`disableConsoleOutput` 不应吞 fatal 兜底）。
7. **存储引擎专项 fuzz**：对 WAL 换区/SSTable 写入/delete 重试三条 P1 路径补故障注入测试（IO 错误、半写、同 txid 多副本）。
8. **文档治理**：解决 README 冲突；删除 vcpkg.json 悬空引用；CONTRIBUTING 补齐 rust-frontend.yml。

---

## 附录：分片明细文件位置

- 片 A（密钥与安全内存）：`artifacts/shard-A-findings.md`（P0=0/P1=1/P2=6/P3=10）
- 片 B（容器事务索引）：`artifacts/shard-B-findings.md`（P0=0/P1=3/P2=4/P3=4）
- 片 C（API 与防御层）：`artifacts/shard-C-findings.md`（P0=0/P1=2/P2=9/P3=10）
- 片 D（Rust 控制器与 worker）：`artifacts/shard-D-findings.md`（P0=0/P1=4/P2=9/P3=4）
- 片 E（前端与构建 CI）：`artifacts/shard-E-findings.md`（P0=1/P1=2/P2=7/P3=5）

每片明细含完整文件:行、代码片段、触发条件、修复建议与验证方式；本报告为合并去重后的工程化视图。
