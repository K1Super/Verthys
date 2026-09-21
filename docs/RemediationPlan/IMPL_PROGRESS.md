# 缺陷修复工程进度记录（Remediation IMPL_PROGRESS）

> 本文件为 81 项缺陷修复工程的分批实施变更记录，随时更新，供中断后快速接手。
> 总纲与批次细则见本目录 `00_MASTER_PLAN.md` ~ `06_TEST_GATE_MATRIX.md`。
> 时间均为本机本地时间（Asia/Shanghai）。
> 编号（FIX-x-y、P1-x 等）仅存在于工程文档，按项目硬约束不得进入代码注释。

## 恢复指引（接手时先读这里）

- 当前进度：Wave 0 已由用户确认。Wave 1 存储完整性批、Wave 2 密钥卫生批
  **全部完成**——Wave 1（FIX-1-1 ~ 1-5，C 层 263，5 fuzz smoke 全过）；
  Wave 2（FIX-2-1 ~ 2-10，C 层 267 / src-tauri 304 / worker 8 / 前端 50，
  批次验证门通过，含构建产物过期假绿纠偏）。下一步为 Wave 3（进入前需
  用户确认验收）。全部改动未提交 git，待用户评审（Wave 0/1/2 同批）。
- 验证命令：
  - C 层（项目根执行）：`powershell -ExecutionPolicy Bypass -File scripts\build_core.dev.ps1 -NoPause`
    ——构建 + verthys_tests.exe 全量测试一体；注意**红测试同样使脚本 exit 1**，
    判读须 grep 日志 `Summary`（勿把预期红误判为构建失败）；增量构建须用
    VS 自带 cmake 全路径（PATH 前置的 D:\Deps\CMake 4.4 会与缓存配置混载，
    详见"已失败且勿重试"）；跑测试前核对产物 mtime 晚于 core 源码 mtime
    （防过期产物假绿）；
  - 前端类型：`npx vue-tsc --noEmit`（0 错）
  - 前端单测：`npx vitest run`（50 用例全绿）
  - 前端构建：`npm run build`
  - Rust 测试：`cargo test`（src-tauri：304 通过；verthys-worker：8 通过，
    纯 bin crate 的测试位于 `#[cfg(test)] mod tests`）
  - Rust 静态：`cargo clippy --all-targets -- -D warnings`（两 crate 均 0 告警）
- 关键架构事实（Wave 0 后成立）：
  - 口令类命令（`verthys_unlock` / `verthys_verify_global_key` / `verthys_derive_global_key`）的服务端入口均接入暴力熔断闸门（fail-closed）；
  - 失败计数唯一权威在服务端（`security_commands/brute_force_bridge.rs`），前端所有计数调用已移除；
  - 认证域错误码常量 `AUTH_DOMAIN_ERROR = "ERR_00000002"` 定义于 bridge，两处控制器共用；
  - 前端 `securityBruteRecordFailure/Success` 封装已删除，仅保留 `securityBruteCheck` 纯查询。
- 关键架构事实（Wave 1 后成立）：
  - T0 结论：L3 worker 为单线程 stdin loop + `&mut worker` 独占借用（编译期不可重入），
    全仓无 FFI 并发线程访问 C 层——C API 已串行化，FIX-1-4 按纵深防御实施；
  - SSTable 写前预算：五写点（数据块 ×2 / Bloom / Index / Footer / Trailer）先预算后
    落盘，事后总量检查保留为第二道防线（`verthys_lsm_sstable.c`）；
  - 事务 DELETE 顺序纪律：墓碑先行（失败零副作用）→ 账本先于引用释放（回滚
    "多归还一次引用"只多不少，方向安全）；
  - WAL 双半区换区纪律：清零新半区数据区 → fsync → 写头，失败不切换 active_half；
    被换出半区数据保留（旧区转备份语义）；
  - 扫描读路径锁纪律：六游标接口（ScanOpen/ScanFetch/ScanSummaryOpen/
    ScanSummaryFetch/HasRecordByType/FindFirstLidByType）核心读全程持
    `api_mutex` 共享锁（锁内单出口），锁序恒为 `api_mutex → lsm 内部锁` 单向；
  - 暴力破解退避记账为进程级模块全局（`verthys_api_utils.c` 原子维护，三函数
    无参），跨句柄聚合、独立句柄不可绕过；容器创建成功不再清零退避计数。
- 关键架构事实（Wave 2 后成立）：
  - 敏感请求构造为类型化借用结构体（`&'a str` 字段 + `serde_json::to_string`
    直写 `Zeroizing<String>`），`json!` 宏弃用——宏对 `&str` 也产生 owned
    Value 拷贝且 Drop 不清零；unlock step3 无 flags 线格式经
    `Option<u32>` + `skip_serializing_if` 精确保持；
  - worker `Request` 六敏感字段（password/data/old_password/new_password/
    bin_data/bin_password）为 `Zeroizing<String>`，`#[serde(default)]` 依赖
    zeroize 1.9 derived Default；main_loop 行缓冲同 Zeroizing；
  - GMK 派生链中间量（binKey PRK / GMK PRK / okm）拷入 Zeroizing 后对
    extract 输出缓冲 volatile 清零；GMK 持有为 thread_local
    `Zeroizing<[u8;32]>`；
  - worker 批量扫描明文/摘要缓冲为 RAII 守卫（Drop 三轮覆写
    0x00→0xFF→0x00，提前 return 自动覆盖）；`SecuredString` 手动 Debug
    只暴露 len 与 `<REDACTED>`；
  - COMPILED 胡椒为编译期门控（CMake option 默认 OFF）；旧
    key_separation AEAD 实现与导出已删除，空明文语义统一。
- 已失败且勿重试的方案：
  - bridge 测试在默认配置下紧密循环 `record_failure`（速率限制 1000ms 会吞掉计数，测试必须 `rate_limit_ms: 0`）；
  - 测试名含大写英文（如 JSON）会触发 clippy `non-snake-case`（`-D warnings` 下必红）；
  - C 测试 CHECK 为"失败立即 return 1"：中途断言会跳过清理，泄漏的 FILE*/句柄将
    连坐后续测试（Windows 打开文件不可删除）——新测试一律"先完成操作与清理，
    再统一断言"模式，红态下也零残留；
  - 直接对 WAL 区域新建空文件跑 `verthys_wal_open` 会因读半区头越界失败
    （`vio_pread64` 对空文件 fread 0 字节判错）——测试须先 `vio_pwrite64`
    预扩展文件至 `VERTHYS_WAL_REGION_BYTES` 满幅；
  - FIX-1-3 红测试构造若用"cursor 预判循环"填充活动半区，触发换区的帧会误入
    下一圈打乱对齐——A 圈填充须用"active_half 翻转检测"（触发帧计入 B），
    只在 B 圈末尾用 cursor 预判（保证触发帧恰为第三圈同长首帧）；
  - 无锁扫描的红态表现为**病态挂起**（读写定位竞争下 90s+ 不完成，绿态数秒
    完成），而非错误计数——红态判据须含 watchdog 超时维度；
  - `git stash push -- <file>` 回退修复验证红态时，若仓库启用 autocrlf，pop 会
    因行尾假差异冲突——先 `git diff HEAD --stat -- <file>` 确认无实质差异，
    `git checkout -- <file>` 清行尾噪音后再 pop；
  - 本机无独立 ninja 安装，fuzz 构建须先把 VS 自带 Ninja 目录前置 PATH
    （`Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja`）；
  - 多线程测试内禁止 CHECK（立即 return 跳过 join/句柄清理，残留句柄连坐
    后续测试）——线程内只原子累计错误码，join 后统一断言（test_scan_concurrent
    为样板）；
  - PATH 前置的 D:\Deps\CMake（4.4）与 build 缓存配置用的 VS 自带 cmake-4.3
    混载：CMakeLists 变更触发再配置时报 "No preprocessor test for PellesC"
    且 configure incomplete——增量构建必须显式调用 VS 自带 cmake.exe 全路径；
  - 构建产物可能落后源码（Wave 2 门禁实证：产物 09/19 22:18 vs 源码
    09/21 14:10，旧产物跑出 257/0 假绿）——跑 C 测试前必须核对
    build 产物 mtime 晚于 core/src 与 core/tests 最新 mtime。

## 进度条目

### 2026-09-20 Wave 0：止血批（代码与自动化门完成，待手工验收）

**范围**：FIX-0-1 ~ FIX-0-5 + 范围外同模式缺陷处置 + 5 处既有类型错误修复。

#### FIX-0-1 照片导出 IPC 协议错配（P0-1）

- 文件：`src/composables/photo-album/usePhotoExport.ts`
- 变更：`writeVencFile` 原以 JSON+`dataB64` 载荷调用 `write_user_file`，与命令签名
  （Raw body + `x-path` 头 + `encodeURIComponent`）不符，导出必现失败。改为
  `writeUserFile(path, bytes)`（`lib/verthys.ts` 既有正确封装），移除对
  `@tauri-apps/api/core` invoke 的直接依赖；`bytesToBase64` 保留供缩略图路径使用。
- 测试：新增 `usePhotoExport.spec.ts`（3 用例：路径/字节引用直传、无 base64 编码调用、异常上抛），全绿。

#### FIX-0-2 日志脱敏设施（P1-6 + P2-23 同模式）

- 新增 `src-tauri/src/util/log_sanitizer.rs`：`json_log_summary(json, keep_fields)`
  纯函数——合法 JSON 输出结构等价摘要（白名单仅限标量，嵌套递归脱敏），
  非 JSON 输出长度占位，绝不回显原文。util 层零日志权限（纯函数红线）。
- 接入 6 处日志点：`controller/actor.rs` 两处超时日志（原 `json: &str` 明文入日志）；
  `controller/key_controller.rs` 与 `controller/verthys_controller.rs` 各两处
  响应解析失败日志（原 `raw={}` 明文入日志）。
- 测试：5 个单测（敏感字段脱敏/非 JSON 长度占位/嵌套递归/结构化白名单/数组顶层）。

#### FIX-0-3 服务端强制暴力熔断（P1-7，含范围扩展）

- 新增 `src-tauri/src/security_commands/brute_force_bridge.rs`：
  `gate_check`（入口闸门，四态 Allowed/Locked/PurgeRequired/Unavailable，fail-closed）、
  `record_auth_failure`（认证域失败计数+持久化+审计）、
  `record_auth_success`（成功重置+持久化+审计）、
  `AUTH_DOMAIN_ERROR` 常量。桥接与命令版共享同一守卫与 DPAPI 持久化层。
- **范围扩展（执行中工程决策）**：原方案仅接 `verthys_unlock`；核验发现
  `verthys_verify_global_key` / `verthys_derive_global_key` 同为口令入口且仅前端计数
  （或无闸门），按"咽喉点强制"原则同批接入：
  - `verthys_unlock`（verthys_controller.rs）：入口闸门 + 认证域失败计数 + 成功重置；
  - `verthys_verify_global_key`（key_controller.rs）：入口闸门 + 认证域失败计数 + 成功重置
    （与既有进程内冷却并行：内存级快速反馈与持久化权威互补）；
  - `verthys_derive_global_key`（key_controller.rs）：仅入口闸门不计数——NoKey 态是
    首次设置新秘密，无既有秘密可暴破，派生失败若计数会误锁首次设置用户。
- **前端去计数（防双重计数）**：`key/global-verthys.ts` 的
  `verifyGlobalKeyWithBruteForce` 移除 `securityBruteRecordSuccess/Failure` 调用，
  失败态改用 `securityBruteCheck()` 纯查询映射锁定/清空；`initUnlock` 在
  verthys_unlock 前新增门禁预检（纯查询，避免锁定态进入 Argon2id 长运算）；
  `lib/verthys.ts` 删除两个计数封装（防未来误用恢复双重计数）；
  `session/security-session.ts` 清理失效 import 与过时注释。
- 计数判定纪律：仅 `ERR_00000002`（worker 统一化 AUTH 域）计失败；通信层失败、
  功能性状态码（CNG 不可用、超时等）不计数，防止非口令因素误锁正常用户。
- 测试：bridge 单测 1 项（禁用速率限制下连续失败必入锁定/清空态、成功重置恢复 Allow）。

#### FIX-0-4 log_fatal 命令注册（P1-10）

- 文件：`src-tauri/src/controller/diag_controller.rs`（命令已存在：16KB 上限 +
  UTF-8 边界截断 + `log::error!` 落盘）、`src-tauri/src/lib.rs`
  （generate_handler! 列表补登记）。
- 效果：前端致命错误上报通道恢复（原命令未注册，调用必现"未知命令"）。

#### FIX-0-5 README 合并冲突标记

- 文件：`README.md`。移除 `<<<<<<< HEAD` / `=======` / `>>>>>>>` 三段标记，
  修复过程误删的尾部闭合结构已补齐。

#### 附加修复：5 处既有类型错误（阻塞交付门）

- `ManagementHub.vue`：`gateDt` 未定义 → 改用同作用域 `wStep`（未钳制墙钟增量，
  与注释语义一致）；
- `ParticleBackground.vue`：`applyDprNow` 补 `scene` 空值守卫（`Scene | null` 收窄）；
- `useQuantumField.ts`：补 `lastWallClock` 声明（首帧守卫），并在 `start()`
  与 `applySize` 尺寸有效跃迁两处重置——循环重启/冻结恢复首帧 wStep=0，
  杜绝暂停期间累积的墙钟跳变。

#### 验证结果（自动化门全过）

| 门 | 命令 | 结果 |
|---|---|---|
| 前端类型 | `npx vue-tsc --noEmit` | 0 错误 |
| 前端单测 | `npx vitest run` | 26 通过（23 既有 + 3 新增） |
| 前端构建 | `npm run build` | 4.83s 成功 |
| Rust 测试 | `cargo test`（src-tauri） | 302 通过 / 0 失败 |
| Rust 测试 | `cargo test`（verthys-worker） | 0 测试（纯 bin crate，既有状态） |
| Rust 静态 | `cargo clippy --all-targets -- -D warnings`（两 crate） | 0 告警 |

#### 遗留项（不阻塞代码交付，需明示）

1. **三项手工验收待执行**（自动化无法覆盖，需 Tauri 运行时）：
   - Tauri 模式导出一张照片落盘成功；
   - 模拟 worker 不响应后，日志文件 grep 无口令明文；
   - 连续错误口令第 10 次后端返回 Locked（熔断闸门端到端实证）。
2. `cargo test` 构建期存在 1 条工具链级 `linker_messages` 警告（链接期产生，
   clippy check 阶段不出现，与本次改动无关，未治理）。
3. `npm audit` 5 条传递依赖告警（既有，与本次改动无关，Wave 4 依赖治理范围）。
4. 全部改动未提交 git，待用户评审。

### 2026-09-20 Wave 1：存储完整性批（FIX-1-1 ~ 1-3 完成，FIX-1-4 进行中）

**范围**：FIX-1-1 SSTable 写前预算、FIX-1-2 DELETE 先墓碑后账本+释放、
FIX-1-3 WAL 换区清零、FIX-1-4 扫描游标 SRW 共享锁、FIX-1-5 退避计数进程级聚合。
批次细则见 `02_WAVE1_STORAGE_INTEGRITY.md`。

#### T0 前置核查：L3 worker 调度是否串行化（结论：已串行化）

- 事实：`verthys-worker/src/runtime/main_loop.rs` 为单线程 `stdin.lock().lines()`
  循环 + `handle_request(&mut worker, &req)` 同步调用；`&mut` 独占借用为编译期
  不可重入保证；全仓无其他 FFI 并发线程（唯一额外线程是 C 层进度消费线程，
  只写 stdout）；src-tauri 无直接加载 verthys.dll 的并发路径。
- 结论：C API 单写者纪律在 L3 已成立，FIX-1-4 定位为纵深防御（C 层自保，
  直接使用 A API 的用户也安全），维持批次顺序实施。

#### FIX-1-1 SSTable 写前预算（越界字节不落盘）

- 文件：`core/src/index/lsm/verthys_lsm_sstable.c`
- 变更：新增静态函数 `sstable_budget_check(abs_cursor, write_len, data_end_abs)`
  ——写前预算（帧头+载荷+tag+帧尾 ≤ 数据区剩余），越界返回 RESOURCE_LIMIT；
  `blockbuilder_flush` 签名新增 `data_end_abs` 参数，函数体开头先预算再
  `verthys_lsm_frame_write`；`verthys_lsm_sstable_write` 五写点（两处数据块
  flush、Bloom、Index、Footer、Trailer）全部接入预算；原事后总量检查保留并
  注释更新为"容量复核（最终防线）"——双防线分工明确。
- 测试：新增 `core/tests/index/test_sstable_budget.c`（2 用例）：
  `sstb_budget_rejects_before_physical_write`（SSTB_TIGHT_LIMIT=64 逼迫首块越界，
  断言 RESOURCE_LIMIT、游标不回退、meta 不登记、边界后 512B 0xA5 哨兵完好）、
  `sstb_budget_normal_write_unaffected`（64KB 容量正常写 + find 读回 + 哨兵完好）。
  两用例均"先完成操作与清理、再统一断言"。已登记 `core/tests/CMakeLists.txt`
  与 `test_runner.c`（checkpoint "sstable_budget"）。
- 红绿证据：红 = 哨兵被覆写（越界写已物理发生），1 failed / 258 passed；
  绿 = 哨兵完好 + 全量 259 passed / 0 failed。

#### FIX-1-2 DELETE 先墓碑后 ledger+release

- 文件：`core/src/transaction/txn/verthys_transaction_v3.c`（`verthys_txn_v3_delete`）
- 变更：重排为 `lsm_get`（记 had_value）→ `lsm_delete` 墓碑先行（失败即零副作用
  返回）→ had_value 时 `txn_ledger_record(-1)` → `verthys_extent_release` → WAL
  append（与旧序"ledger→release→delete"相逆）。函数注释写明顺序纪律与安全方向
  论证：引用先于墓碑释放会在失败与回滚之间留"索引存活但引用已清零"的悬挂窗口
  （GC 误回收）；账本先于释放使 release 失败时回滚"多归还一次引用"——计数只多
  不少，空间泄漏换数据安全。
- 调用方核查：`verthys_api.c` 的 v3 delete / delete_many 均已"失败即 abort"，
  0 处重试语义，无需改动；回滚路径（`txn_ledger_apply_rollback` 净额反向 +
  `verthys_lsm_rollback_txid` 的 `memtable_rebuild_locked` 重建解冻）与重排兼容。
- 测试：新增 `core/tests/transaction/test_txn_delete_retry.c`（1 用例）：
  冻结活跃 memtable 注入（`verthys_lsm_memtable_freeze`，墓碑 WAL 帧已落盘、
  跳表插入被拒 = 确定性"删除半程"）→ 断言失败瞬间 refcount==1、账本 0 记账、
  lsm_get 仍存活 → 回滚复原（回滚后 rebuild 的 memtable 天然解冻，一次性注入）→
  新事务全链提交后 refcount==0、GetRecord NOTFOUND、账本弃置。登记 CMakeLists
  与 test_runner（checkpoint "txn_delete_retry"）。
- 红绿证据：红 = `ref_fail=0 ledger_fail=1 alive=1`（旧序损坏窗口），
  [txn-del-retry] obs 行留档，259 passed / 1 failed；绿 = `ref_fail=1
  ledger_fail=0` + 全量 260 passed / 0 failed。

#### FIX-1-3 WAL 换区先清零新区数据区

- 文件：`core/src/transaction/wal/verthys_wal.c`
- 变更：新增静态函数 `wal_clear_half_data(w, half)`——calloc 零缓冲单次
  `vio_pwrite64` 清目标半区数据区（半区尾前 480KB-24B）+ `wal_fsync`；
  `verthys_wal_append` 换区分支改为"清零+fsync → 写头 → 切换"序列，
  清零或写头失败直接返回、**不切换 active_half**（旧区保持活动可重试）。
  被换出半区数据保留（"旧区转备份"语义），`wal_foreach_frame` 扫描逻辑不动。
- 测试：扩展 `core/tests/transaction/test_txn_recovery_inject.c` 注入 4
  `inject_wal_third_round_residual_not_replayed`——三圈构造：A 圈首帧 53B BEGIN +
  4219B INDEX 大帧填充（active_half 翻转检测，触发帧计入 B）→ B 圈大帧 + 53B
  BEGIN 填至极限（cursor 预判）→ 第三圈 BEGIN（新 txid）触发换回 A，与第一圈
  首帧同长完整覆盖。close 模拟崩溃（只清内存态）→ 重开扫描 + replay 断言
  `frames_open == 1 + kb`（残留旧帧不得续链）、`torn == 0`、`discarded == kb + 1`。
  登记 test_runner（checkpoint "txn_inject" 内）。
- 红绿证据：红 = `ka=117 kb=155 frames_open=272 discarded=272`（旧帧链被完整
  续上回放），260 passed / 1 failed；绿 = `frames_open=156=1+kb torn=0` + 全量
  261 passed / 0 failed。

#### FIX-1-4 扫描游标接口加 SRW 共享锁（已完成）

- 文件：`core/src/api/scan/verthys_scan.c`
- 变更：六游标读接口全部接入 `api_mutex` 共享锁，每函数锁内单出口、
  Acquire/Release 严格对称、零嵌套（每函数最多一层锁）：
  1. `Verthys_ScanOpen`——锁覆盖 diag 原子计数（`InterlockedIncrement64`，
     共享锁下多 ScanOpen 并发计数不丢）+ 警告日志 + `scan_v3_open`
     （其内部解引用 `ctx->v3`，Lock 换实例 TOCTOU 消除）；
  2. `Verthys_ScanFetch`——前置校验/熔断检测在锁外，锁覆盖 `scan_v3_fetch`
     （Extent 解密 `verthys_extent_get` 的共享 FILE* 读取 + LSM 推进 +
     实例存活性检测），ctx 经 `cursor->v3_ctx` 防御性判空取锁；
  3. `Verthys_ScanSummaryOpen`——同 ScanOpen 模式（`scan_v3_open` 共用骨架）；
  4. `Verthys_ScanSummaryFetch`——同 ScanFetch 模式（锁覆盖元数据直读 +
     Extent 索引内存回查）；
  5. `Verthys_HasRecordByType` / 6. `Verthys_FindFirstLidByType`——独立加锁
     覆盖 `scan_v3_find_by_type`（两者不经 ScanFetch 复用实现，各持一层锁）。
- 锁层级核查（代码事实）：extent/lsm 层无反向获取 api_mutex 的路径；
  `verthys_lsm_scan_next` 内部持 `lsm->lock` 独占锁与外层 api_mutex 共享锁
  同向（写路径 api_mutex 独占 → lsm lock 同序），无死锁环；文件头辅助段
  注明 `api_mutex 共享锁纪律`（锁序单向 + 持锁区间禁获取 api_mutex）。
- 测试：新增 `core/tests/api/test_scan_concurrent.c`（1 用例，三线程拓扑：
  writer 循环 AddRecord 唯一记录 ×256 + reader 交替摘要/全量游标周期 +
  prober 循环按类型探测；线程内原子累计错误，join 后统一断言——写侧零失败、
  读侧零未预期错误码、零解密失败条目、计数一致 seed+writes、末条内容完整
  往返）。登记 CMakeLists 与 test_runner（checkpoint "scan_concurrent"）。
- 红绿证据：红 = 回退修复（git stash）后测试**病态挂起**——90s watchdog
  超时不结束，三次观测一致（最长一次 CPU 340s+ 未完成）；绿 = 修复在位
  `[ OK ] scan_concurrent_readers_vs_writer`，数秒完成。红态行为证明无锁
  竞争真实暴露（读写定位交错致病态交互），而非概率性偶发。

#### FIX-1-5 退避计数进程级聚合（已完成）

- 文件与变更：
  - `core/src/api/shared/verthys_api_utils.c/.h`——计数自 `VerthysContext`
    字段迁至模块级原子全局 `g_brute_failures` / `g_brute_last_fail_ms`
    （InterlockedIncrement64 / Exchange64 / CompareExchange64 维护，饱和
    封顶 32 防移位溢出）；三函数（`verthys_backoff_record_failure` /
    `verthys_backoff_reset` / `verthys_backoff_remaining_ms`）改无参一次改净；
  - `core/src/container/shared/verthys_internal.h`——`VerthysContext` 的
    `failed_attempts` / `last_failed_tick` 字段删除（Init 为 calloc 零初始化，
    无需改动）；
  - `core/src/api/lifecycle/verthys_api.c`——Unlock 成功 reset（L571）、AUTH
    失败记账（L587）、Unlock 入口门禁（L939，位于 Argon2id 之前快速拒绝）
    三处改无参调用；**CreateWithPreset 成功路径的 reset（原 L680）整体删除**
    ——安全决策：创建新容器不构成对既有容器口令知识的证明，保留该调用
    会让攻击者以"新建容器"无限重置进程级计数完全绕过指数退避（方向保守
    即更严格）；已核实无测试依赖创建重置语义；
  - `ctx_zero_sensitive` 注释同步更新（退避记账为进程级全局，与上下文
    生命周期无关）。
- 测试污染全量审计结论：verthys_tests.exe 单进程跑全部测试，进程级计数
  跨句柄持久——盘点全部 Unlock 调用点后确认仅 3 处既有测试会因 AUTH 残留
  计数被退避窗口破坏，均已加 `verthys_backoff_reset()` 修补：
  1. `test_verthys_export.c` `cp_then_unlock_new`（AUTH 后 Deinit → 下个
     `cp_wrong_old` 的 OK 解锁会被 RATE 拦截）；
  2. `test_txn_recovery_inject.c` `inject_sb_ciphertext_bitflip_rejected`
     （Unlock 结果接受 AUTH → 下个 `inject_taillog` 的 OK 解锁会被拦截）；
  3. `test_v3_lifecycle.c` `v3life_cp_old_password_rejected`（原注释
     "独立句柄规避退避冷却跨句柄污染"依赖旧 per-ctx 语义，进程级聚合后
     必破——同测试内 AUTH 断言后主动清零，函数头注释同步改写）。
  其余测试自含（以成功解锁收尾触发 571 行 reset）或失败路径不产生 AUTH
  记账，无需改动。
- 新测试：`core/tests/security/test_backoff_process_wide.c`（1 用例：
  句柄 A 错误口令 AUTH → 独立句柄 B 正确口令必须 RATE → 记账清零后 B
  正常解锁 OK；断言后置模式，开头防御性清零保证时序确定性）。登记
  CMakeLists 与 test_runner（checkpoint "backoff_process_wide"）。
- 红绿证据：红（per-ctx 旧实现）= `[FAIL] independent handle bypasses
  backoff: expect RATE, got 0`（got 0 = VERTHYS_OK，独立句柄成功绕过
  退避）；绿（进程级聚合）= backoff + 三组修补测试 6 passed / 0 failed。

#### 验证结果（Wave 1 最终）

| 门 | 命令 | 结果 |
|---|---|---|
| C 层构建+全量测试 | `build_core.dev.ps1` 构建 + `verthys_tests.exe` 全量 | **263 passed / 0 failed**（原 261 + scan_concurrent + backoff 两新增） |
| FIX-1-4 红证据 | 回退修复后跑 scan_concurrent | 90s watchdog 超时病态挂起 ×3 次观测（最长 CPU 340s+） |
| FIX-1-5 红证据 | per-ctx 实现下跑 backoff_process_wide | `expect RATE, got 0`（独立句柄绕过），0 passed / 1 failed |
| fuzz 构建 | `cmake -S . -B build_fuzz -G Ninja -DCMAKE_BUILD_TYPE=Debug -DVERTHYS_ENABLE_FUZZ=ON` | 构建通过（ASAN + fuzzer 全量插桩） |
| 5 fuzz 目标 smoke（含 fuzz_sstable 回归） | `ctest --test-dir build_fuzz -C Debug -R "fuzz_.*_smoke"` | **5/5 Passed**（superblock/partition/extent/sstable/import 各 -runs=2000） |

#### Wave 1 收尾交接清单

1. FIX-1-1 ~ FIX-1-5 全部完成，红→绿证据与验证表已补全（上文）；
2. 全部改动未提交 git，待用户评审（Wave 0/1 同批）；
3. 下一步：Wave 2 密钥卫生批（FIX-2-1 ~ FIX-2-10，T1 密钥流盘点先行），
   细则见 `02` 批次文档同目录 Wave 2 部分。

### 2026-09-21 Wave 2：密钥卫生批（FIX-2-1 ~ 2-10 全部完成，批次验证门通过）

**范围**：FIX-2-1 敏感请求零中间副本、FIX-2-2 扫描批量缓冲 RAII 擦除、
FIX-2-3 COMPILED 胡椒编译期门控、FIX-2-4 CNG key 失败清零 + 栈缓冲补零、
FIX-2-5 AES-GCM provider 生命周期锁化、FIX-2-6 rotate_mek 原子切换、
FIX-2-7 ULONG 溢出守卫、FIX-2-8 SecuredString Debug 脱敏、FIX-2-9 worker
敏感链全量 Zeroizing、FIX-2-10 旧 AEAD 下线。批次细则见 `03_WAVE2_SECRET_HYGIENE.md`。

#### T1 前置盘点（密钥流清单）

- COMPILED 胡椒存量判定 + `key_separation_aead_` 调用点清单，产出 FIX-2-3
  门控范围与 FIX-2-10 下线清单。

#### C 层（FIX-2-3 / 2-4 / 2-5 / 2-6 / 2-7 / 2-10）

- `core/src/crypto/cipher/verthys_crypto_cng.c/.h`——FIX-2-4（import_key
  失败清零调用方 key、三处 P3 栈缓冲补零）、FIX-2-5（provider open 路径
  SRWLOCK + state 化，refs 只做计数，deinit 互斥序列化）、FIX-2-7
  （size_t→ULONG 溢出守卫 + pt_len+TAG 减法形式判定，只修新 AEAD 路径）；
- `core/src/crypto/keymanager/keymanager_cng.c/.h`——FIX-2-6（rotate_mek
  先写临时槽验证后原子切换，失败旧槽不动）；
- FIX-2-3——COMPILED 胡椒编译期门控（CMake option，默认 OFF）；
  红→绿：门控路径 1 failed（证明拦截真实）→ 8/8 通过；
- FIX-2-10——旧 AEAD 实现与导出删除、测试重构、空明文语义统一；
- P3 栈缓冲补零另覆盖 `verthys_export_import.c` / `verthys_v3_lifecycle.c` /
  `verthys_unlock_pipeline.c`；
- 测试：`core/tests/crypto/test_cng_kernel.c` 新增 4 测试；C 全量
  **267 passed / 0 failed**（Wave 1 后 263 + 净增 4）。

#### Rust 层（FIX-2-1 / 2-2 / 2-8 / 2-9）

- FIX-2-1（`src-tauri/src/controller/key_controller.rs` +
  `verthys_controller.rs`）：
  - 弃用 `json!` 宏——宏对 `&str` 也经 `From<&str> for Value` 产生 owned
    拷贝且 Drop 不清零；新增类型化借用结构体（`DeriveGlobalKeyReq` /
    `VerifyGlobalKeyReq` / `UnlockReq` / `CreateWithPresetReq` /
    `PathPasswordReq` / `ChangePasswordReq` / `AddRecordReq`，`&'a str`
    字段），`serde_json::to_string` 直写 `Zeroizing<String>`，全程零中间
    副本；
  - `UnlockReq.flags: Option<u32>` + `skip_serializing_if`——unlock step3
    传 None 精确复现无 flags 线格式（worker 端 serde default=0 兼容）；
  - 发送后按各路径敏感集合显式 drop（req_str / password / bin_password /
    bin_data_b64 / record_b64）；`send_with_timeout` /
    `send_with_unlock_progress` 均为 `&str` 借用签名；
  - 行为等价性由既有测试覆盖（key_controller 15 项 + verthys_controller
    套件全绿）。
- FIX-2-2（`verthys-worker/src/runtime/worker.rs`）：`PlainBatchGuard` /
  `SummaryBatchGuard` RAII 守卫——Drop 三轮覆写（0x00→0xFF→0x00），`?`
  提前返回自动覆盖；`scrub()` 公开幂等 + `rows()` 只读切片视图；替换
  `fetch_into_shm` / `fetch_summary_into_shm` 两处手工零化循环。
  新增 3 测试（plain scrub 覆写 + 幂等 / summary scrub 覆写 name+merkle /
  rows 契约）；Drop 后内存已释放不可观测，改为直测 scrub() 效果，
  Drop→scrub 单行委托由审查保证（测试模块注释记录该决策）。
- FIX-2-8（`src-tauri/src/util/secured_string.rs`）：derive 行移除
  Debug，手动实现只暴露 `len` 与 `<REDACTED>`；全仓 `{:?}` 排查无敏感
  泄露点。新增 2 测试（明文不出现且含 REDACTED+len / 派生结构体场景
  同样脱敏）——红态可推演（derive Debug 时 `{:?}` 会输出明文内容）。
- FIX-2-9（`verthys-worker`：`runtime/protocol.rs` / `runtime/main_loop.rs` /
  `runtime/gmk.rs` + `Cargo.toml`）：
  - `Request` 六敏感字段（password/data/old_password/new_password/
    bin_data/bin_password）改 `Zeroizing<String>`，`#[serde(default)]`
    依赖 zeroize 1.9 derived Default（Cargo.toml 补 serde feature）；
  - main_loop 行缓冲 `Zeroizing::new(l)`（BOM strip 分支同构）；
  - GMK 派生链：binKey/GMK 的 PRK 经 `Hkdf::extract` 返回后拷入
    `Zeroizing<[u8;32]>` 并对原缓冲 `prk[..].zeroize()` volatile 清零；
    okm 同构；gmk_arr move 进 thread_local `Zeroizing` 无残留副本；
  - 新增 5 测试（make_request 辅助构造：roundtrip 124B record + 32B
    subkey / 错误口令拒绝 / 跨派生 record 拒绝 / 无 GMK LOCKED
    `ERR_00000007` / 子密钥确定性）——行为回归维度，等价性全绿。

#### 验证结果（Wave 2 最终）

| 门 | 命令 | 结果 |
|---|---|---|
| C 层全量 | VS 自带 cmake 重建 + `verthys_tests.exe` | **267 passed / 0 failed**（过期产物 257 不可信，见下文教训） |
| worker 测试 | `cargo test`（verthys-worker） | **8 passed / 0 failed**（3 守卫 + 5 gmk） |
| worker 静态 | `cargo clippy --all-targets` | 0 告警 |
| worker release | `cargo build --release` + exe 同步 `src-tauri/binaries/` | 完成（build.rs 三规则门禁全过） |
| src-tauri 测试 | `cargo test`（src-tauri） | **304 passed / 0 failed**（含 2 新 Debug 脱敏测试） |
| src-tauri 静态 | `cargo clippy --all-targets` | 0 告警（DLL 素材同步后复跑确认） |
| 前端类型+构建 | `npm run build`（vue-tsc --noEmit && vite build） | 0 错误，4.10s 成功 |
| 前端单测 | `npm run test`（vitest run） | **50 passed / 0 failed** |
| 打包素材 | DLL / worker exe 哈希 vs 最新构建产物 | 一致（DLL 082AC27E…） |

#### Wave 2 门禁重大教训（已固化到"恢复指引"）

1. **构建产物过期假绿**：门禁复跑时发现 build/core 产物（09/19 22:18）落后
   源码（09/21 14:10）两天——此前旧产物跑出的 257/0 为旧代码结果，非当前
   状态。重新构建后 267/0。判据：产物 mtime 必须晚于 core/src 与
   core/tests 最新 mtime，再跑测试。
2. **cmake 混载失败**：PATH 前置 D:\Deps\CMake 4.4 与缓存配置的 VS 自带
   cmake-4.3 在 CMakeLists 变更触发再配置时模块混载（"No preprocessor
   test for PellesC"）——增量构建必须显式用 VS 自带 cmake.exe 全路径。
3. **素材级联同步**：C 重建 → verthys.dll 变化 → 必须同步
   `src-tauri/verthys.dll` 并复跑 src-tauri clippy（dll_hash.rs 重新生成
   触发重编译），本批已按序完成且门禁干净。

#### Wave 2 收尾交接清单

1. FIX-2-1 ~ FIX-2-10 全部完成，批次验证门通过（上表）；
2. 全部改动未提交 git，待用户评审（Wave 0/1/2 同批）；
3. 下一步：Wave 3（进入前需用户确认验收），细则见批次文档。
