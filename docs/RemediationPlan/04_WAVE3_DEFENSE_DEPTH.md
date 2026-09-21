# Wave 3 — 纵深防御批施行细则

> 目标：封闭 L3/IPC 输入边界、FFI 边界、服务端授权闸门与防御层语义失真；消化存储引擎遗留边角。
> 范围：src-tauri（controller/worker/util）、verthys-worker（runtime）、`core/src/security/`（除 memory/）、`core/src/index/`、`core/src/container/`。
> 前置：Wave 0/1/2 已交付（FIX-3-6 解锁态闸门依赖 FIX-0-3 接入点；FIX-3-3 与 FIX-0-2 同文件）。
> 纪律：编号（P2-x、P3、FIX-x-y）只存在于本文档，**不得进入代码注释**。本批条目多、单条改动小，按 FIX 独立提交，任何一条可单独 revert。

---

## A. L3/IPC 输入边界（拒绝恶意输入，而非崩溃）

### FIX-3-1 枚举 max_count 硬上限（P2-15）

- 现状：`verthys-worker/src/runtime/worker.rs:357-361`（另 558-569）`(0..mc).map(...).collect()`，mc 来自前端可控 `req.id`（dispatch.rs:320/368 无上限）。
- 修复：在 dispatch 与 worker 双端 clamp：`const MAX_ENUM_COUNT: u64 = 5000; let mc = req.id.min(MAX_ENUM_COUNT);`（双端防单一侧被绕过）；注释写明上限值来源为单批内存预算，不引用本文档。
- 测试：worker 测试传 `id=1e8`，断言分配被截断且不 OOM。
- 验收：双端 clamp 存在；恶意大 id 优雅返回。

### FIX-3-2 `CString::new` 不 panic（P2-16）

- 现状：`worker.rs:169/229/722/740` 等 4 处 `CString::new(path).unwrap()`，嵌入 NUL 直接 panic。
- 修复：改为 `match CString::new(path) { Ok(c) => c, Err(_) => return 错误码（0xFFFFFFFF / 协议 INVALID） }`；错误码走 worker 既有错误映射（与 dispatch 错误同通道）；含 NUL 路径的日志走 sanitize（不打印原始路径，防日志注入）。
- 测试：单测传入 `"C:\\x00evil.bin"`，断言返回错误而非 panic。
- 验收：4 处 unwrap 清零。

### FIX-3-3 管道行读取长度上限（P2-17）

- 现状：`actor.rs:200` `read_line`、`main_loop.rs:78` `lines()` 均无单行上限。
- 修复：统一常量 `MAX_LINE_BYTES = 16MB`；实现带限读取（`read_until` 计数超限即截断并报协议错误断开，避免无界 String）；两端（actor 读 worker stdout 与 main_loop 读 stdin）同款保护。
- 测试：发送 100MB 无换行流（或 mock），断言触发上限错误且进程内存平稳。
- 验收：两端读路径均有上限检查。

### FIX-3-4 SHM 随机名与擦除改 CSPRNG（P2-18）

- 现状：`scan_shm.rs:338-378` 以墙钟 nanos+PID 种子 xorshift64*，非 CSPRNG；同用户恶意进程可猜 SHM 名。
- 修复：改用 `BCryptGenRandom`（"BCRYPT_USE_SYSTEM_PREFERRED_RNG",项目内 `brute_force.rs:160` 已有可用样板，抽公共 util）；SHM 擦除同样改用 CSPRNG 填充（保留三轮覆写策略，值源换成 CSPRNG）。
- 测试：两次创建名称不可预测（统计/唯一性断言）；种子生成路径单测桩验证调用 CSPRNG。
- 验收：xorshift 实现删除；CSPRNG 样板复用。

---

## B. FFI 边界安全

### FIX-3-5 extern "C" 回调与 FFI 调用包 catch_unwind（P2-22）

- 现状：`progress_cb.rs:29-66` 回调未包 catch_unwind；worker 各 `Sym::<Fn>` 调用点直接 `func(...)`——panic 跨 FFI = UB。
- 修复（三层）：
  1. **回调体**：`progress_cb` 函数体外层 `std::panic::catch_unwind(AssertUnwindSafe(|| ...))`，panic 转为错误日志并返回失败值（回调 signature 允许的失败形态），绝不 unwind 进 C。
  2. **worker FFI 调用统一收口**：把所有对 C 函数的调用集中到既有 util（若已存在 call_* 族则改造；否则新建 `ffi_call`），内部 catch_unwind。
  3. **panic hook 兜底**：worker main 安装 panic hook——若仍有遗漏跨边界 panic，hook 内标记并从后备路径 exit（避免静默 UB），并记录致命日志。
- 测试：人为在回调内 panic（受控 feature 注入），断言 worker 不 abort、日志有记录、C 调用方拿到失败返回。
- 验收：全仓 `extern "C" fn` 回调签名 Grep 逐一确认已包或为纯转发；FFI 调用点全经 `ffi_call`。

---

## C. 服务端授权闸门

### FIX-3-6 敏感业务命令解锁态断言（P2-21）

- 现状：add/get/delete/export/import/change_password/derive_subkey 等命令体直接 forward worker，无 Rust 侧解锁态校验，唯一闸门在 C DLL 的 LOCKED。
- 修复：在 `verthys_controller.rs`（或统一中间件函数）为这些命令入口加统一断言：`state.key_lifecycle.current_state()` 非 Unlocked（具体以需要 Unlocked 的命令清单为准）→ 直接返回 `ERR_LOCKED` 文案并 audit Denied。实现为一个 `require_unlocked(&state) -> Result<(), String>` 帮助函数，各命令入口一行调用。
- 注意：命令清单要精确——导出/导入在"仅锁定（未验证 GMK）"态是否允许？按现有业务语义核对后固化到清单（实施时以各命令当前 C 层语义为准，不擅自收紧/放宽）。
- 测试：未解锁态调用 add_record，断言后端拒绝；已解锁态回归全绿。
- 验收：清单内命令 100% 有断言；审计可见 Denied 事件。

### FIX-3-7 未调用 Tauri 命令清理（P2-32）

- 现状：`lib.rs:389-466` 中 `diag_info`、`verthys_scan_abort`、`verthys_scan_summary_abort`、`verthys_derive_subkey`、`security_generate_auth_token` 前端零调用（已核验 Grep）。
- 修复决策（每命令二选一，按需定夺）：
  - 确无前端需求 → 从 `generate_handler!` 移除注册（函数实现按同级清理：无其他调用方即删除；有内部调用则保留函数去注册）；
  - 属未来能力保留（如 derive_subkey 若计划接入）→ 移除注册 + 函数标注 `#[allow(dead_code)]` 注明保留意图；
  - 决策表随 PR 提交留档（哪些删、哪些保留及理由）。
- 测试：移除后 `cargo build` 无未使用告警；前端回归无损；导出面/命令契约检查（Wave 4 门）通过。
- 验收：generate_handler 列表与前端实际调用契约一致。

---

## D. 防御层语义与健壮性（C 核心 security 域）

### FIX-3-8 export/import 路径规范化（P2-7）

- 现状：`verthys_export_import.c:341/454` 直接 fopen 外部给的路径，无规范化/前缀约束/符号链接拒绝。
- 修复（两段式，C 层自保 + L3 约束）：
  1. C 层：`vfmt_write_streaming`/`read_file` 入口 canonicalize（Windows `GetFullPathName`+`CreateFile` 属性校验），拒绝符号链接（FILE_FLAG_OPEN_REPARSE_POINT 探测）、拒绝同名活动容器路径与其他关键系统目录前缀；违规返回 INVALID。
  2. L3：控制器侧已有"用户对话框选择位置 + 白名单跳过 + 系统关键目录拒绝"策略（`file_controller.rs` write_user_file 同款），确认 export/import 命令同样经过该策略后才允许进入 worker→C。
- 测试：传入 `C:\Windows\System32\..\evil.bin` 类路径断言被拒；符号链接目标断言被拒。
- 验收：C 层 canonicalize + L3 约束双段就位，测试绿。

### FIX-3-9 defense_closure 语义修正（P2-8）

- 现状：`defense_closure.c:228` `all_critical_blocked = (failed_count == 0)`，把"无 FAILED"误报为"全部 BLOCKED"。
- 修复：`all_critical_blocked = (failed_count==0 && degraded_count==0 && blocked_count==DEFENSE_PATH_COUNT)`；同文件对 `has_degraded` 语义一并核对（若 defined 口径不清，随本项统一）。
- 测试：构造 sandbox_attrs 全缺场景断言标志为 0；全通过场景断言为 1；`test_defense_closure.c` 扩展。
- 验收：三态（全通/部分降级/全缺）断言绿。

### FIX-3-10 anti_inject 线程基线重采样（P2-9）

- 现状：`anti_inject.c:521-527` 基线在 Init 早期捕获，解锁期内部线程合法增长超过 2× 即误报 APC。
- 修复：基线改为"解锁完成后稳定窗口"重采样（或对 Verthys 自有模块线程起始地址白名单排除，复用 `address_in_any_module` 判定 verthys.dll 内线程不计入可疑增长）；二选一以实测误报率决定，优先白名单方案（对攻击者注入线程仍有效）。
- 测试：完整解锁后运行 `anti_inject_check_all`，断言无 APC 误报；注入假线程仍能检出。
- 验收：解锁后检查稳定无误报。

### FIX-3-11 Deinit/Lock 有限等待（P2-10）

- 现状：`verthys_v3_lifecycle.c:94` `WaitForSingleObject(bg_preheat_thread, INFINITE)`；progress destroy 同款——I/O 挂起即永久卡死。
- 修复：改带超时等待（2~5s，常量集中定义），超时记录诊断并继续（接受线程残存由进程退出回收）；preheat 线程内部对可取消点增加检查（若有阻塞读，评估 `CancelSynchronousIo` 可行性，不做则文档注明限界）。
- 测试：mock 一次阻塞的 preheat 读，断言 Deinit 在超时后返回而非挂起。
- 验收：无 INFINITE 等待 I/O 工作线程路径。

### FIX-3-12 完整性校验 fail-open 改可观测（P2-12）

- 现状：`integrity.c:109-112/235/241/255` 等 HMAC/解析失败一律返回"通过"——诱发失败可绕过篡改检测且无痕。
- 修复：区分「基础设施异常」与「哈希不匹配」两类计数：基础设施异常不再静默通过——上报遥测/日志（TELEMETRY 通道既有），连续 N 次关键路径异常升级告警；判定结果对"因异常未完成校验"显式标记（调用方可见降级态而非"通过"）。
- 测试：mock HMAC 初始化失败，断言有遥测上报且校验结果标"未完成"，而非通过。
- 验收：三类路径（通过/不匹配/基础设施异常）可区分、可观测。

### FIX-3-13 runtime_hash 共享缓冲并发保护（P2-13）

- 现状：`runtime_hash.c:69-70` `s_hbuf` 静态共享；`test_install`（:369）不持 `s_scanning` 单飞锁。
- 修复：`runtime_hash_test_install` 进入同一 `s_scanning` 临界区（或 release 构建剔除 test_install 入口——优先做后者：测试入口不进生产二进制；若因依赖关系暂不可剔除，先加锁）。
- 测试：双线程并发 test_install+verify 无错乱。
- 验收：共享缓冲所有写入路径持同一临界区。

### FIX-3-14 system32_loader 分隔符边界（P2-14）

- 现状：`system32_loader.c:114-115` 前缀 `_wcsnicmp` 无分隔符边界（与 anti_inject.c:242 已修的 `dir_prefix_matches` 同款缺陷）。
- 修复：改调 `dir_prefix_matches` 同款带边界比较（后随 `\0`/`\`/`/`）。
- 测试：构造伪前缀路径 `C:\Windows\System32Malware\evil.dll` 单测被拒。
- 验收：比较逻辑与 anti_inject 一致。

### FIX-3-15 自动 rekey in-progress 互斥（P2-6）

- 现状：`verthys_rekey_auto.c:132-225` 无进行中标志；两个并发写事务同时跨阈值可能双 rotate（靠 vsb_txn 回滚兜底但浪费+误差）。
- 修复：rotate 入口设置/检查 `VERTHYS_CNG_KM_REKEYING` 态（头文件已有该状态枚举，此处未用）；入态即独占，出态恢复；失败路径恢复状态。
- 测试：并发触发压测，断言仅单次 rotate 生效。
- 验收：状态互斥就位，压测绿。

### FIX-3-16 空口令策略决策（P2-11）

- 现状：`verthys_api.c:935/1050` 允许空口令建库/解锁（Argon2id 空串,靠 CNG 机器密钥兜）。
- 修复（产品决策 + 代码对齐，二选一，随 PR 留档决策理由）：
  - A. 不支持空口令：`password_len==0` 显式拒绝（INVALID），前端同步禁用空口令提交；
  - B. 支持（有意硬件绑定免密）：在 `GetContainerInfo` 暴露"无口令/纯硬件绑定"状态，前端显著标注，文档写明强度。
  默认推荐 A（与"私密数据管理器"定位一致）；若现有用户数据依赖空口令则选 B。
- 测试：按所选策略断言建库/解锁行为。
- 验收：代码行为与文档化策略一致。

---

## E. 存储引擎边角

### FIX-3-17 flush 后 memtable 重建失败处置（P2-24）

- 现状：`verthys_lsm.c:571-583`：flush 成功持久化新 SSTable+Manifest 后，`memtable_create()` 失败直接返回；旧 memtable（内容已全部持久化）仍挂载，后续 put 又写旧表 → 下次 flush 重复条目。
- 修复：重建失败时把 `lsm->memtable` 置为不可写状态（`memtable_readonly` 标志），后续 put 返回 RESOURCE_LIMIT/重开引导，拒绝再写入已持久化的旧表；或重建为最小空表失败则整体进入"需 reopen"状态。
- 测试：注入 create 失败，断言后续 put 被拒且无重复 flush 条目。
- 验收：失败路径不产生重复 SSTable 内容。

### FIX-3-18 close 失败 dirty 语义（P2-25）

- 现状：`verthys_lsm.c:1077-1085`：close 时 flush_locked 失败仍无条件销毁 memtable（WAL 未 reset，靠下次 open 重放兜底——语义隐性依赖调用方）。
- 修复：close 失败路径置 dirty 标志并通过返回值语义显式化（返回错误码 + 文档函数注释写明"返回错误时必须 reopen-replay，不得当作干净关闭"）；若上层存在当作干净关闭的处理，一并修正。
- 测试：断言 close 失败后 open 能从 WAL 完整重建全部条目。
- 验收：错误语义显式化，重建测试绿。

### FIX-3-19 superblock 读法定内容比对（P2-26）

- 现状：`verthys_superblock_v3.c:623-643` 只比 txid 不比整块内容（当前被整块 HMAC 兜底，属纵深缺口）。
- 修复：agree 判定除 txid 外增加关键字段指纹比对（或整个 parsed 结构 memcmp），防未来字段未入 HMAC 域时静默选错。
- 测试：构造两副本同 txid 不同内容的单测（绕过 HMAC 的合成解析），断言判不一致。
- 验收：纵深断言绿。

### FIX-3-20 warmcache 段边界补全（P2-27）

- 现状：`verthys_warmcache_v3.c:250-260` 未校验 sst 段自身下界与两段反向不重叠。
- 修复：补齐 `sst_off>=HEADER`、`sst_off+sst_size<=file_len`、两段互不重叠完整矩形校验；非法布局判 miss（回退冷启动，既有降级语义不变）。
- 测试：合法布局外偏移 fuzz 判 miss。
- 验收：边界校验完整。

### FIX-3-21 解锁全段 HMAC 缓存（P2-35）

- 现状：`verthys_api.c:948` 每次解锁重开整个 DLL 流式 HMAC（integrity.c:579-672），解锁延迟显著。
- 修复：进程内缓存一次基准 + 文件 mtime/size 指纹，指纹不变即跳过重算；文件变化（自更新/被篡改）重算。缓存条目用模块级单飞锁保护。
- 注意：不可因缓存而降低防篡改灵敏度——指纹比较本身要便宜且可靠（GetFileInformationByHandle）。
- 测试：连续两次解锁计时对比，第二次显著缩短；修改文件时间戳后触发重算。
- 验收：缓存生效且指纹失效时重算。

---

## F. D/C 片 P3 卫生（本批顺带消化）

| 项 | 位置 | 修复要点 |
|---|---|---|
| crypto.rs:64 expect | `src-tauri/src/util/crypto.rs` | 加密路径 `Hmac::new_from_slice(...).expect(...)` 改返回 Result，去掉 expect |
| shared_memory reader 边界 | `src-tauri/src/infrastructure/shared_memory.rs:124-128` | 增加 name/data offset 所属区间校验，坏 offset 拒绝 |
| 句柄清理错误吞没 | `shared_memory.rs` 多处 `let _ =` | debug 构建记录失败码（不改变 release 行为） |
| enumerate 100k 上界 | `worker/dispatch.rs:253/280` | 上界改常量并与 C 端实际 lid 上限对齐（与 FIX-3-1 共用常量） |
| TEB 硬编码偏移 | `anti_inject.c:107-113` | 注释标注系统版本快照基线；失效降级为遥测（不改逻辑） |
| 看门狗事件名 | `emergency.c:39/96-124` | 事件名加随机后缀或 DACL 限制 |
| 硬件断点监控范围 | `anti_debug_v2.c` | 文档标注"入口点检查"语义，勿宣称持续监控（注释修正） |
| dllmain DETACH | `dllmain.c` | 确认 shutdown 路径无 LoadLibrary/锁依赖；若有则推迟到线程（先行核查，若当前实现确较轻则仅加注释固化结论） |

---

## 本批验证门

1. Wave 0/2 门复跑（cargo test × 2、clippy 双零、vue-tsc、vitest、npm build）
2. Ninja 构建 + `verthys_tests.exe` 全量绿
3. 恶意输入注入测试全绿（NUL 路径 / 超大 id / 超长行 / 符号链接路径 / 伪前缀）
4. 命令契约检查（Wave 4 将引入的脚本，本批先行手工跑一遍）：generate_handler 与前端 invoke 双向 diff 无孤儿
5. `git status` 干净

**git 纪律**：每项独立提交；删除死命令的提交单独成 PR 便于评审与回滚。