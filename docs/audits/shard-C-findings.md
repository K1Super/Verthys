# Shard-C 深审发现：API 表面 + 安全防御层（L2 C11）

审查范围：`core/src/api/`（lifecycle / unlock / scan / transfer / progress / shared）+ `core/src/security/`（排除 `memory/`）+ `core/include/verthys.h`。
审查日期：2026-09-20。排除 `**/target/**`。
每条均含真实文件行号（Grep/Read 实际定位）。未执行任何修改/破坏性操作。

---

## 计数总览

| 级别 | 数量 |
|------|------|
| P0 | 0 |
| P1 | 2 |
| P2 | 9 |
| P3 | 10 |

**最高级别发现（一句话）：** 暴力破解退避计数仅存活于单句柄 RAM、随 `Verthys_Init` 新句柄与进程重启即清零——对"离线拿到 `.verthys` 后本地穷举口令"这一真正威胁模型几乎不构成减速。

---

## P0

无。未发现可直接远程代码执行、密钥材料明文出 DLL、或可稳定触发的内存越界/RCE。C 层在边界校验、`secure_zero`、CNG 句柄 W^X、PE 解析越界防护上整体质量较高。

---

## P1

### P1-1 暴力破解退避为 RAM 内、按句柄记账，新句柄/进程重启即清零
- 文件:行：
  - `core/src/api/shared/verthys_api_utils.c:40-61`（`verthys_backoff_remaining_ms` / `record_failure` / `reset`）
  - `core/src/api/lifecycle/verthys_api.c:587`（仅 `VERTHYS_ERR_AUTH` 才 `record_failure`）
  - `core/src/api/lifecycle/verthys_api.c:247`（`Verthys_Init` 用 `calloc(1, sizeof(VerthysContext))` → `failed_attempts=0`）
  - `core/src/api/lifecycle/verthys_api.c:939`（解锁前查 `backoff_remaining_ms>0` → `VERTHYS_ERR_RATE`）
- 证据：`wait_secs = (k >= 12) ? VERTHYS_BACKOFF_MAX_SECS : (1ull << k)`，指数退避本身正确（2s→…→cap 3600s）；但 `failed_attempts/last_failed_tick` 字段在 `VerthysContext`（堆，进程私有），无持久化、无全局/跨句柄聚合。
- 触发条件：攻击者持有 `.verthys`，在受控环境反复：`Verthys_Init`（新句柄，计数=0）→ `Verthys_Unlock(guess)`。或直接重启 worker 进程。每次都获得"干净"的 0 次错误窗口，Argon2id 惩罚开销才是唯一实际减速。
- 影响：`VERTHYS_ERR_RATE`(0x0A) 设计的暴力破解防护在主威胁模型（离线本地穷举）下失效；只对同一长生命周期句柄内的在线重试有意义。
- 置信度：确认（代码事实）；"是否需持久化/全局化"属产品决策。
- 修复：(a) 将错误次数落到一个仅追加、对用户不可删改的机器级位置（如 CNG 不透明 blob / 注册表 ACL 保护项 / 基于 MachineGuid 的 HMAC 持久化计数），使重启不重置；(b) 或在 L3 维护跨句柄/跨进程的失败计数并在 L2 启动时强制读取；(c) 至少对同一文件路径做进程内全局（而非句柄级）记账。
- 验证：脚本化 `Init→Unlock(错误)→Init→Unlock(错误)`，观察第二次仍未触发 `RATE`，且 `failed_attempts` 恒为 1。

### P1-2 扫描游标系列接口完全不持 `api_mutex`，与写路径在同一 `FILE*` 上竞争
- 文件:行：`core/src/api/scan/verthys_scan.c`（`Verthys_ScanFetch`、`Verthys_ScanSummaryFetch`、`Verthys_HasRecordByType`、`Verthys_ScanFindFirstLidByType` 全函数体内 `AcquireSRW` 命中 0 次——Grep 实证）。对比：写路径 `core/src/api/lifecycle/verthys_api.c:1154`（`Verthys_AddRecord` 取 `AcquireSRWLockExclusive`）。
- 证据：扫描内部 `scan_v3_fetch` → `verthys_extent_get` 读 `v->f`（流水线文件 `FILE*`）；而 `AddRecord/Commit` 经同一 `f` 写入。`vio_pread64`=内部 `_fseeki64+fread`，同一 `FILE*` 非线程安全（pipeline 头注释亦自述）。LSM 快照只隔离索引层，不隔离 extent 文件读。
- 触发条件：游标打开期间，调用方在另一线程并发 `Verthys_AddRecord`（契约只禁止"游标内并发 Lock"，未禁止并发写）。
- 影响：`FILE*` 内部指针/data 区竞争 → 读到错乱 extent、崩溃（UB），极端下脏读解密记录。
- 置信度：疑似（C 层确凿无锁；是否真正可触发取决于 L3 worker 是否串行化扫描与写——需验证 L3 调用调度）。
- 修复：给 `Verthys_ScanFetch/SummaryFetch/HasRecordByType/FindFirstLidByType` 加 `AcquireSRWLockShared(&ctx->api_mutex)`（与 `GetContainerInfo`/`VerifyIntegrity` 一致）；或让 extent 读使用独立 `FILE*`/pread(2) 原生句柄而非共享 `FILE*`。
- 验证：游标开启时双线程跑 AddRecord + ScanFetch，ASan/压力跑观察崩溃或校验和不一致。

---

## P2

### P2-1 `all_critical_blocked` 把"无 FAILED"误报成"全部 BLOCKED"，安全姿态失真
- 文件:行：`core/src/security/layer6_closure/defense_closure.c:228`
- 证据：`report->all_critical_blocked = (report->failed_count == 0) ? 1 : 0;`。当 7 条路径全为 DEGRADED（failed_count=0）时仍置 1。
- 触发：BOOT/RUNTIME 检查后经 `Verthys_GetSecurityStatus` 上报。
- 影响：前端/用户被误导为"关键防护全部落地"，实际可能全部降级。
- 置信度：确认。
- 修复：`all_critical_blocked = (report->failed_count==0 && report->degraded_count==0 && blocked_count==DEFENSE_PATH_COUNT);`
- 验证：构造 sandbox_attrs 全缺场景，断言该标志应为 0 而非 1。

### P2-2 导出/导入路径在 C 层不做规范化/沙箱，可写任意路径
- 文件:行：`core/src/api/transfer/verthys_export_import.c:341`（`vfmt_write_streaming(... export_path)`）、`:454`（`read_file(import_path,...)`）；参数校验仅 `export_path==NULL`（:136）/`import_path==NULL`（:435）。
- 证据：无 realpath/前缀白名单/符号链接拒绝/拒绝指向库自身容器的判断；`write_file` 用 `"wb"`（截断覆盖）。
- 触发：L4/Tauri 可影响导出/导入路径参数并传至 L3→L2 时，导出会把加密 blob 写到任意可写绝对路径（覆盖配置/计划启动项等）；导入从任意路径读。
- 影响：越界文件写（内容受控但可触达任意位置）/任意文件读喂给解析器。
- 置信度：确认（C 层无校验）；可利用性取决于 L3 是否先做路径约束。
- 修复：C 层对 export 目标做 canonicalize 并限制在 L3 声明的导出目录前缀内、拒绝符号链接、拒绝覆盖同名活动库；导入同理限制在允许目录。
- 验证：传 `C:\Windows\System32\..\evil.bin` 类路径，断言被拒。

### P2-3 anti_inject 线程数启发式误报：解锁期内部线程合法增长 >2× 基线
- 文件:行：`core/src/security/anti_analysis/anti_inject.c:521-527`（`current >= s_baseline_thread_count * 2` → `INJECT_THREAT_APC`）；基线在 `anti_inject_init`（:880）捕获。
- 证据：解锁期 Verthys 自起 `bg_preheat_thread`、Argon2 线程、progress consumer 线程、反调试定时器线程等；基线在 Init 早期只有主线程少数。
- 影响：解锁后线程数过基线 2 倍 → 误报注入 → TELEMETRY/累计后 DEGRADE 锁库。
- 置信度：疑似（阈值与实际线程数需实测）。
- 修复：基线改为"解锁稳定后"重新采样，或对已知 Verthys 自有线程起始地址做排除白名单（`address_in_any_module` 命中 verthys.dll 的不计入可疑增长）。
- 验证：完整解锁后跑 `anti_inject_check_all`，观察是否稳定报 APC。

### P2-4 Deinit/Lock 路径以 INFINITE 等待做 I/O 的工作线程，I/O 挂起即永久卡死
- 文件:行：`core/src/api/lifecycle/verthys_v3_lifecycle.c:94`（`WaitForSingleObject(ctx3->bg_preheat_thread, INFINITE)`）；`core/src/api/progress/verthys_progress.c`（destroy 等待 consumer，头注释自述"极端阻塞宁可挂起 Deinit"）。
- 证据：bg_preheat 线程内 `verthys_lsm_preheat_full` 做磁盘读；若磁盘/句柄挂起，`verthys_v3_ctx_subsystems_close`（Lock/Deinit 必经）在此 INFINITE 阻塞。
- 影响：进程无法干净退出/锁库；看门狗若也依赖被卡死线程，形成挂起而非自毁。
- 置信度：确认（代码事实）；触发需 I/O 挂起这一前置条件。
- 修复：用带超时的等待（如 2–5s），超时则记录并继续（接受线程随后由进程退出回收），或对 preheat 用可取消标志。
- 验证：mock 一次阻塞的 preheat 读，断言 Deinit 不无限挂起。

### P2-5 允许空口令（password=NULL 且 len=0）创建/解锁
- 文件:行：`core/src/api/lifecycle/verthys_api.c:935`、`:1050`（`if (password == NULL && password_len != 0) return INVALID;` —— 反向放行空口令）
- 证据：空口令传入 `keymanager_derive_master_v3(NULL,0)` → Argon2id 输入为空串，主密钥熵几乎为零，仅靠 CNG 机器密钥兜绑定。
- 影响：若非有意的"本机自动解锁"模式，则等同无口令加密。
- 置信度：疑似（可能为有意的硬件绑定免密模式）。
- 修复：若不支持空口令，显式拒绝 `password_len==0`；若支持，在文档/`GetContainerInfo` 暴露"无口令/纯硬件绑定"状态。
- 验证：空口令建库后用错误/空口令解锁，观察行为并确认是否符合设计。

### P2-6 完整性/运行时哈希在基础设施异常时 fail-open（返回"通过"）
- 文件:行：`core/src/security/integrity/integrity.c:109-112`（HMAC 计算失败 `return 0` 即通过）、`:235/:241/:255`（计算失败均不阻断）、`:647-649`（节解析失败不阻断）；`runtime_hash.c:295`（单条计算失败"不计失配"）。
- 证据："不阻断不误报"惯例在 HMAC/PE 解析失败时一律放行。
- 影响：攻击者若能诱发 HMAC 初始化失败/节解析失败，可绕过篡改检测而不留失配。
- 置信度：确认（设计如此）；实际可利用性低（libsodium 失效会同时破坏自身加密）。
- 修复：对"基础设施异常"与"哈希不匹配"分别计数；连续/关键路径异常也上报 TELEMETRY，而非静默通过。
- 验证：mock HMAC 返回失败，断言有遥测而非仅返回通过。

### P2-7 `integrity_verify_startup` 每次解锁都重开整个 DLL 文件做全段 HMAC
- 文件:行：`core/src/api/lifecycle/verthys_api.c:948`（Unlock 前调用）；`core/src/security/integrity/integrity.c:579-672`（`_wfopen(self_path,"rb")` 流式 HMAC `.text/.rdata/.rhat`）。
- 影响：每次解锁额外做一次整 DLL 磁盘读 + HMAC，解锁延迟显著增加；若 DLL 在杀软/网络盘上更明显。
- 置信度：确认。
- 修复：进程内缓存一次基准与"文件 mtime/大小指纹"，仅在文件变化时重算；或降频。
- 验证：计时对比开启/关闭该调用的解锁耗时。

### P2-8 runtime_hash 共享静态 `s_hbuf` 在 test_install 路径未走单飞锁
- 文件:行：`core/src/security/integrity/runtime_hash.c:69-70`（`s_hbuf` 静态共享）、`:184-185`（`masked_hash` 写它）；`runtime_hash_scan` 有 `s_scanning` 单飞（:227），但 `runtime_hash_test_install`（:369）调 `masked_hash` 不持该锁。
- 影响：若生产误调 test_install，与 scan 并发写 `s_hbuf` → 哈希错 → 误判篡改 → emergency KILL（自 DoS）。
- 置信度：疑似（仅测试入口可达；生产应剥离）。
- 修复：release 构建剔除 `runtime_hash_test_install/overlay`，或其内部也进入 `s_scanning` 临界。
- 验证：双线程并发 test_install + verify，观察 KILL。

### P2-9 `system32_loader` 加载位置校验缺分隔符边界（与 anti_inject 已修缺陷同款）
- 文件:行：`core/src/security/layer3_hw_binding/system32_loader.c:114-115`（`_wcsnicmp(loaded_path, s_system32_dir, wcslen(s_system32_dir)) != 0`）
- 证据：前缀一致即放行，未像 `anti_inject.c:242 dir_prefix_matches` 那样要求后随 `\0`/`\`/`/`。
- 影响：理论上 `C:\Windows\System32Malware\evil.dll` 前缀伪通过（实际 `LOAD_LIBRARY_SEARCH_SYSTEM32` 已强制真 System32，故为纵深防御缺口而非直接利用）。
- 置信度：确认（不一致）。
- 修复：改用 `dir_prefix_matches` 同款带边界比较。
- 验证：构造伪前缀路径单测。

---

## P3

| 编号 | 文件:行 | 问题 | 置信度 | 修复 |
|------|---------|------|--------|------|
| P3-1 | `verthys_api_utils.c:42-48` | `backoff_remaining_ms` 读 `failed_attempts/last_failed_tick` 不持锁；并发读存在撕裂（仅最坏多读一次，无安全后果） | 确认 | 读端用 `InterlockedOr` 或接受 best-effort 注释 |
| P3-2 | `verthys_export_import.c:156-163` | `derive_master_export` 失败时仅 zero `salt`，未 zero 栈上 `mek`（未初始化/半写密钥残留在栈） | 确认 | 失败路径统一 zero `salt/mek/dek` |
| P3-3 | `verthys_v3_lifecycle.c:756-757` | `change_password` 旧口令 derive 失败/pepper 失败 return 前未 zero 栈上 `old_mek` | 确认 | 失败出口前 `verthys_secure_zero(old_mek,...)` |
| P3-4 | `verthys_unlock_pipeline.c` S3 | derive `integrity_key` 失败走 `goto fail`（:401）未 zero 栈上 `integrity_key`（未初始化栈残留） | 疑似 | `fail_zero_ik` 覆盖该入口 |
| P3-5 | `verthys_progress.c:116-126` | 环形缓冲满时"生产者推进 tail"，与消费者写 `tail` 竞争；索引有界故无内存破坏，仅偶发丢/重条目 | 确认 | 固定单一消费者推进 tail，满时仅丢 head |
| P3-6 | `anti_inject.c:107-113` | TEB `SameTebFlags`/`Win32ThreadInfo` 偏移硬编码（x64 0x17EE/0x78），Windows 更新后漂移；有 SEH 兜底故仅误报/漏报 | 确认 | 注释标注"按 Win10/11 快照"，版本失效时降级为遥测 |
| P3-7 | `emergency.c:39,96-124` | 看门狗事件名 `Verthys_Emergency_<PID>` 可预测；本地低权进程可 OpenEvent 监听 | 确认 | 加随机后缀或 DACL 限制（当前无安全描述符） |
| P3-8 | `anti_debug_v2.c` | 硬件断点仅查当前线程 DR0-DR3，他线程断点漏检；且仅在 Init/改密/导出等入口检查，非持续监控 | 确认 | 文档标注"入口点检查"，勿宣称持续 |
| P3-9 | `v3_lifecycle.c` S5 | 失败经 `done_free_cache` 后由调用方 `verthys_v3_ctx_subsystems_close` 兜底；该 close 已 NULL 守卫全部分配项——**经核对为正确闭环，非缺陷**，记录为已验证 | 确认（非缺陷） | 无需改；注释显式说明 close 负责回收 |
| P3-10 | `dllmain.c` DETACH | `DLL_PROCESS_DETACH`(手工 FreeLibrary) 内调 `tls_loader_shutdown`+`verthys_pepper_deinit`，处于加载器锁；若二者做同步/文件 I/O 则有加载器锁重入风险（当前实现较轻） | 疑似 | 确认二者不持其它锁/不 LoadLibrary；否则推迟到 worker 线程 |

---

## 已核对为正确、非缺陷的设计点（避免误报）
- **S5 部分分配资源泄漏**：`verthys_v3_ctx_subsystems_close`（v3_lifecycle.c:87-124）对 wal/lsm/ext_idx/ptable/km/integrity_key 全部 NULL 守卫销毁，S5 中途失败调用方仍会调用它 → 无泄漏。
- **emergency 三级响应/滑动窗口**：TELEMETRY 只记、DEGRADE 需同信号窗口≥2 次、KILL 高置信直杀；`TerminateProcess` 自终止后忙等兜底——设计自洽。
- **syscall_direct SSN 提取**：仿射一致性 + 双锚点插值互证 + W^X stub + Strict CFG 检测 + 提取失败降级 GetProcAddress——健壮。
- **job_isolation**：5 步挂载 + 任步失败精确回滚、白名单 DACL（无 Deny ACE 避免自我拒绝）——正确。
- **cng_machine_key**：仅 `NTE_BAD_KEYSET` 才建容器、不覆盖既有、导出策略=0、机器级 only-SYSTEM DACL——正确。
- **security_preset 双缓冲**：`InterlockedExchangePointer` 原子切换，读端只见完整快照——正确。
- **lock 层级**：emergency 持 registry(shared)→api_mutex(exclusive)；无反向持锁路径（Deinit 先取 registry、不持 api_mutex）→ 无死锁。
