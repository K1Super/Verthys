# Shard-D 深审报告：L3 Rust 层（Tauri 控制器 + worker 子进程 + FFI/SHM 边界）

- 审查范围：`verthys-tauri/src-tauri/src/`（controller/infrastructure/middleware/repository/service/state/security/security_commands/util）与 `verthys-tauri/verthys-worker/src/`（runtime/worker）。
- 排除：Cargo.toml 依赖版本一致性（归 E 片）、L2 C 源码、L1 容器、`target/` 产物。
- 红线复核：密钥材料（GMK/密码）设计上只在 L2；本报告重点验证 Rust 层是否泄漏/未零化/未授权调用。
- 行号均为本次实际 Read/Grep 定位；未实际验证处标注「需验证」。

## 计数

| 级别 | 数量 |
|------|------|
| P0 | 0 |
| P1 | 4 |
| P2 | 9 |
| P3 | 4 |

## 发现明细表

| 级别 | 文件:行 | 问题 | 证据 | 触发 | 影响 | 置信度 | 修复 | 验证 |
|------|---------|------|------|------|------|--------|------|------|
| P1 | src-tauri/src/worker/actor.rs:184-190；246-251 | IPC 超时把整条请求 JSON 原样写日志，请求体含明文 `password`/`bin_password` | `log::error!("[worker] IPC 超时（{}s）... 请求: {} ...", ..., json, ...)`；`json` 即 verthys_controller.rs:674-679 / key_controller.rs:285 构造的 `req.to_string()`，内含 `"password": *password`、`"bin_password": bin_password` | unlock/derive/verify/change_password/export/import 等任何一次 IPC 读超时或本轮 deadline 超时（worker 挂起、FFI 阻塞、stdin 写入后 worker 无响应） | 主密码/密钥口令明文落盘到日志文件，直接违反「密钥材料不进日志」设计红线 | 确认 | 超时分支只记录 `op`、`pid`、`stderr_snippet`，绝不记录整个 `json`；或对 json 做脱敏（正则替换 password/bin_password 值为 `***`） | 复现：模拟 worker 60s 不响应，检查日志文件不含密码串；单测对脱敏函数 |
| P1 | src-tauri/src/controller/verthys_controller.rs:600-728；src-tauri/src/lib.rs:444-445 | 暴力破解熔断不在服务端强制：`verthys_unlock` 全程不调用 `BruteForceGuard::check()/record_failure()`，失败计数仅由前端主动 invoke `security_brute_record_failure/success` 维护 | grep 全 controller 无 `brute_force/BruteForceGuard` 引用；unlock 仅做密码复杂度、文件存在、文件锁、preheat 校验后直发 worker | 攻击者（或被前端脚本绕过的调用方）直接 Tauri invoke `verthys_unlock`，不调用 `security_brute_record_failure`，即可对 Verthys_Unlock 无限制尝试口令 | 10 次锁定 / 20 次 purge 的熔断形同虚设，离线/在线口令爆破不受限 | 确认（「熔断计数由前端驱动」需验证是否另有中间件钩子，但现有代码路径未见） | 在 `verthys_unlock` 入口先 `BruteForceGuard::check()`，Locked/PurgeRequired 直接拒绝；FFI 失败后由后端自身 `record_failure()`，成功后 `record_success()`，不依赖前端上报 | 单测：连续 invoke unlock 错误口令，验证第 10 次后端返回 Locked；grep 确认 controller 持有 guard 实例 |
| P1 | src-tauri/src/controller/key_controller.rs:189,283,285,287（verify 同构：352,461,464,466） | `bin_password` 是裸 `String`（非 Zeroizing），被移入 `json!` 后 `req.to_string()` 形成含明文口令的普通 `String`，发送后仅 `drop(password)` 零化了主密码，`bin_password` 与 `req_str` 均未零化 | 第 189 行 `bin_password: String`；283 `"bin_password": bin_password`；285 `let req_str = req.to_string();`；287 `drop(password);`（未触及 bin_password/req_str） | 每次 derive_global_key / verify_global_key | bin 口令明文残留在控制器堆（直到分配器复用），崩溃转储/内存取证可恢复 | 确认 | `bin_password` 用 `Zeroizing<String>` 接收；发送后 `req_str.zeroize()`；序列化用一次性临时缓冲并显式 zeroize | 审查 zeroize 覆盖；ASAN/Valgrind 或 heap dump 检查无残留 |
| P1 | verthys-worker/src/runtime/worker.rs:399（全量）；610（摘要） | SHM 写入失败时 `?` 提前返回，跳过紧随其后的明文记录零化循环 | 399 行 `let count = shm.write_records(&result, exhausted).map_err(|_| 0xFFFFFFFFu32)?;`；零化循环在 402-415（摘要 613-624）。`?` 命中即 `return Err`，`result` 中 `name`/`data`（解密后明文）按普通 Vec/String drop，不零化 | 单批记录总字节数超过 SHM 容量（`needed > self.size`），write_records 返回 Err | 解密后的记录名/数据明文残留在 worker 堆 | 确认 | 把零化循环移到 `?` 之前的统一清理块（即使 Err 也先擦除 result 再 return）；或用 RAII guard 持有 result 并 Drop 擦除 | 构造超容量批次，检查错误路径后 result 缓冲已被覆写 |
| P2 | verthys-worker/src/runtime/worker.rs:357-361；558-569（dispatch.rs:320,368 未上限） | 前端可控的 `req.id` 作为 max_count，worker 用 `(0..mc).map(...).collect()` 一次性分配 `mc` 条记录结构，无上限 | 357 `let mut records: Vec<VerthysRecordC> = (0..mc).map(...).collect();`；mc 来自 dispatch `max_count = req.id`（dispatch.rs:320/368） | 前端/恶意 invoke 传超大 id（如 10_000_000） | worker 进程 OOM / 内存暴涨（DoS） | 确认 | 在 dispatch 对 max_count 做硬上限（如 `min(req.id, 5000)`），worker 内再 clamp | 传 1e8 id，验证被截断且不 OOM |
| P2 | verthys-worker/src/runtime/worker.rs:169,229,722,740 | `CString::new(path).unwrap()` 对含嵌入 NUL 的路径直接 panic | 169 `let path_c = std::ffi::CString::new(path).unwrap();`（create/add_record/export/import 同） | 前端传入含 `\0` 的路径字符串 | worker 子进程 panic → 整个 worker 崩溃（进程隔离下不传染控制器，但该次操作全失败，反复触发=DoS） | 确认 | 改为 `?`/match 返回 0xFFFFFFFF 错误码，不 panic | 传 `"C:\x00evil.bin"`，验证返回错误而非 panic |
| P2 | src-tauri/src/worker/actor.rs:200；verthys-worker/src/runtime/main_loop.rs:78 | 对 `BufReader::read_line` 无单行长度上限 | actor.rs:200 `stdout.read_line(&mut line)`；main_loop.rs:78 `stdin.lock().lines()` | 对端发送不换行的超长流（畸形/被污染的 worker stdout 或父进程写入） | `line` String 无界增长，内存耗尽 | 确认 | 读入前设上限（如 16MB），超过即报协议错误并断开 | 发送 100MB 无换行，验证触发上限错误 |
| P2 | verthys-worker/src/runtime/scan_shm.rs:338-358（random_hex_name）；362-378（fill_random_bytes） | SHM 随机名与擦除用 PRNG 均以墙钟 nanos+PID 为种子的 xorshift64*，非 CSPRNG；注释自称「随机不可猜测/安全擦除」 | 340 种子 `SystemTime::now()...^pid.rotate_left(17)`；364 同样种子；LCG/xorshift 递推 | 同机恶意进程按创建时间窗口枚举 `verthys_scan_*` 名称（SDACL 虽限当前用户 SID，同用户 malware 仍可猜）；擦除强度不足 | SHM 名称可预测，同用户侧信道探测；「随机覆写擦除」强度弱于 OS CSPRNG | 确认 | 名称与擦除改用 `BCryptGenRandom`/`RtlGenRandom`（brute_force.rs:160 已用 BCryptGenRandom，可复用） | 两次创建名称不可预测；对照种子不重复 |
| P2 | src-tauri/src/util/secured_string.rs:48 | `#[derive(Debug)]` 用在 SecuredString 上；`Zeroizing<String>` 的 Debug 会打印明文内容，违背同文件 27 行「不实现 Display 避免打印明文」红线 | 48 行 `#[derive(Debug, Default, Clone, PartialEq, Eq, TS)]`；类型包裹 `Zeroizing<String>` | 任何对含 SecuredString 的记录/结构做 `{:?}`/`{:#?}`/debug 日志 | 记录名/数据明文进日志 | 确认 | 手动实现 `Debug`，只打印类型名/长度，不打印内容 | `format!("{:?}", secured)` 不含明文 |
| P2 | verthys-worker/src/runtime/gmk.rs:98,130-132,264；worker.rs:147,723,741 | GMK 派生中间量与导出子密钥未彻底零化 | 98 `let gmk = Hkdf::...extract(...)` 的 PRK 拷入 gmk_arr(131) 后 gmk 未显式 zeroize；264 `let mut okm=[0u8;32]` 派生模块子密钥后经 274 base64 编码，okm 栈数组未 zeroize；worker.rs 中 password/bin_password 以 `&str` 透传 FFI，调用后无 zeroize | 每次 derive/verify/derive_module_subkey | 派生密钥/子密钥字节在堆/栈残留 | 疑似（需验证 hkdf crate Prk 是否自零化） | 显式 `.zeroize()` 所有敏感临时数组；子密钥用完后 zeroize okm | heap/stack dump 无残留 |
| P2 | src-tauri/src/controller/verthys_controller.rs:1458,1478,1619,1686,1710,1734 等 | 敏感业务命令（add/get/delete/export/import/change_password/derive_subkey）在 Rust 侧不校验会话/解锁态，全部直接 forward worker，仅靠 C DLL 的 LOCKED 拒绝 | 上述命令体均为构造 req → `state.send(...)`，无 `KeyLifecycleState::Unlocked` 判定 | C 层状态机出现 bug 或 stale-UNLOCKED（dispatch.rs:109 已自述存在级联 INVALID 恢复路径）时 Rust 无第二道闸门 | 防御纵深缺失；C 侧一旦放过，Rust 无法兜底 | 确认（设计层） | 在需要 Unlocked 的命令入口统一断言 `lifecycle.current_state()==Unlocked`，否则返回 `ERR_LOCKED` | 未解锁态调用 add_record，验证后端拒绝 |
| P2 | verthys-worker/src/runtime/progress_cb.rs:29-66；worker.rs:62,117,200 等 FFI 调用 | `extern "C"` 回调与 FFI 调用未包 `catch_unwind`，panic 将跨 FFI 边界展开进 C | progress_cb 内做 `CStr::from_ptr`/`format!`/`replace`，无 catch_unwind；worker 各 call_* 直接 `func(...)` | 回调内任意 panic（如 message 构造异常）或 Rust 侧 FFI 触发 panic | panic 跨语言边界 = UB，通常导致进程 abort，worker 崩溃 | 确认 | 回调体用 `std::panic::catch_unwind` 包裹，panic 转成错误日志并返回；worker 入口安装 panic hook 不跨边界 unwind | 强制回调 panic，验证不 abort C 调用方 |
| P2 | src-tauri/src/controller/key_controller.rs:607（另 303,482,669） | 响应 JSON 解析失败时把整段 `resp_json` 写日志；derive_subkey 的 resp_json 含 `data` 字段=base64 模块子密钥 | 607 `log::error!("[verthys_derive_subkey] 解析响应失败: {} | raw={}", e, resp_json)` | subkey 响应 JSON 畸形/解析失败 | 派生子密钥落日志 | 确认 | 解析失败只记 `e`，不记 raw 整包；或脱敏 data 字段 | 构造畸形 subkey 响应，验证日志不含子密钥 |
| P3 | src-tauri/src/util/crypto.rs:64 | `Hmac::new_from_slice(...).expect("HMAC key length error")` 在加密路径留 expect | 64 行 expect | 理论上 HMAC-SHA256 任意长度 key 合法，永不触发 | 仅防御性，实际不会 panic；但加密路径不应留 expect | 确认 | 改为返回 Result，去掉 expect | clippy/单测 |
| P3 | src-tauri/src/infrastructure/shared_memory.rs:124-128 | reader 边界校验只查 `name_end/data_end <= SHM_MAX_SIZE`，未校验 name_offset/data_offset 是否落在 names/data 区（entries_start+entries_size 区间） | 124 `if name_end > SHM_MAX_SIZE || data_end > SHM_MAX_SIZE` | worker 崩溃/被污染，把 name_offset 指向 entries 区 | 不会越界崩溃（外层有界），但读到错误数据，协议鲁棒性不足 | 疑似 | 增加区间校验：`name_offset >= entries_start+entries_size && name_offset < names_start+total_name_bytes` | 构造坏 offset，验证拒绝 |
| P3 | src-tauri/src/infrastructure/shared_memory.rs:67-69,80-82,94-96,161-163,214-216 | 关闭句柄/Unmap/VirtualUnlock 错误一律 `let _ =` | 多处 `let _ = UnmapViewOfFile(...)` 等 | 清理失败被静默吞 | 句柄泄漏被掩盖，难以诊断 | 确认（可接受，记录即可） | 至少在 debug 构建下记录失败码 | debug 日志可见 |
| P3 | verthys-worker/src/runtime/dispatch.rs:253,280 | enumerate_records 硬编码 `start_id..=100_000` 上界 | 253 `for id in start_id..=100_000`；280 `if last_id >= 100_000` | 记录 lid 超过 100k | 枚举提前终止（逻辑缺陷，非安全） | 确认 | 上限改为常量或由 C 端返回的实际 lid 上限推导 | lid>100k 记录可被枚举 |

## 正面结论（设计红线整体）

- GMK 主密钥确实锁在 worker 进程 thread_local（gmk.rs:36-39 `GMK: RefCell<Option<Zeroizing<[u8;32]>>>`），Drop/clear_global_key 清零（worker.rs:812, gmk.rs:284）；控制器侧未发现持有 GMK 字节。
- worker 孤儿进程防护到位：session.rs Job Object `KILL_ON_JOB_CLOSE` + kill_on_drop + 超时 graceful shutdown；worker Drop 执行 Lock→Deinit→清零 GMK（worker.rs:805-814）。
- SHM 协议双端同源（shm_schema.rs `include!` + `const_assert_eq` 编译期布局校验），魔数/版本/偏移自洽；SHM 名称做了字符白名单（is_valid_shm_name）。
- brute_force 计数逻辑本身（冻结/不可逆累计/抖动/DPAPI 持久化）实现正确，问题仅在「服务端未强制接入 unlock」。

## 优先修复建议

1. 先修 P1-1（日志脱敏）与 P1-2（unlock 服务端强制熔断）——两者直接让口令爆破/口令泄漏门槛归零。
2. 再修 P1-3/P1-4（口令与明文记录的零化覆盖）。
3. P2 中 OOM（worker 分配无界）与 panic-across-FFI 建议紧随其后。
