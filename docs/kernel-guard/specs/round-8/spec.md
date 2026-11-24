# Round 8 规格：宿主预创建 ARM、运行中丢失自动锁定

| 项目 | 内容 |
| --- | --- |
| 轮次 | Round 8 |
| 目标 | 关闭 A14「worker 创建到 ARM 之间的同用户预开句柄窗口」；实现运行中内核丢失自动锁定 |
| 依据 | `docs/kernel-guard/10-execution-rounds.md` Round 8、`05-test-and-verification.md` A14/S6 |
| 状态 | 已批准，代码与单测完成（运行期门禁未验证） |

---

## 1. 目标与验收判据

**目标**：SECURE 档下，宿主在 `CreateProcess` 之前完成驱动 ARM；worker 以挂起态创建后由宿主向服务提交 PID + 创建时间完成 REGISTER，再恢复执行。运行中已 ACTIVE 的保护一旦丢失，宿主在有限窗口内锁定会话，而不是只更新 UI。

**验收判据**（可在本机执行的部分）：

1. 服务 Debug/Release 构建成功，`ctest` 通过；新增协议与路径派生单测覆盖非法输入。
2. C 核心 `-TestHooks` 全量测试通过，新增用例证明：内核状态 ACTIVE 时只 REGISTER 不 ARM；非 ACTIVE 时走 ARM+REGISTER；REGISTER 失败时回滚 DISARM。
3. 宿主 `cargo check` 通过；宿主请求编码、响应解码、签名校验路径有可执行单测；A14 预 ARM 在 worker 目录与宿主不同根时被明确跳过（开发树），同根时在 spawn 前调用 ARM。
4. 运行中锁定：worker 侧 `kernel_status` 操作可用；宿主看门狗在「SECURE 且曾观察到 ACTIVE」后连续 2 次非 ACTIVE 时调用 `perform_external_lock("kernel_lost")`；从未 ACTIVE 时不误锁。
5. 无驱动/无服务环境下，预 ARM 与看门狗均为 `preferred` 降级：解锁不受阻断，日志记录原因。

**不可在本机验证**（必须标注未验证，不得声称通过）：驱动实际加载后的 A14 攻击回归、REGISTER 端到端、服务重启与驱动 LOST 的运行期行为、安装器一次 UAC、VM 攻击回归。

---

## 2. 范围

### 2.1 本轮实现

1. 服务协议：为 `KERNEL_ARM` 增加宿主预 ARM 模式与 worker 映像选择；为 `KERNEL_REGISTER` 增加宿主提交的 worker PID/创建时间载荷。
2. 服务 `kernel_guard`：宿主身份识别、同目录 worker 路径派生、宿主 PREARM 状态、REGISTER 目标校验、DISARM 双主体（宿主/worker）。
3. 宿主 Rust 服务 IPC 客户端：注册表公钥、消息管道、64B 请求 / 128B 响应、ECDSA P-256 验签、超时与失败关闭。
4. `WorkerSession::spawn`：ARM → spawn suspended → REGISTER → Job/DACL → resume；失败按 `preferred` 降级并记录。
5. C 核心：SECURE 激活时先查内核状态，ACTIVE/ARMED 则只 REGISTER，避免清空宿主预登记的保护。
6. 运行中丢失自动锁定：worker 新增轻量 `kernel_status` 操作；宿主新增看门狗线程。
7. 文档更新与回归记录。

### 2.2 明确不做

- 不新增第 12 个特性位；不改变 SECURE=`preferred` 的产品语义。
- 不引入应用直连驱动；驱动仍只接受 SYSTEM 服务。
- 不做 L2/L3 内核能力；不把密钥、加密、容器解析下沉内核。
- 不改驱动协议与驱动代码。
- 安装器一次 UAC、驱动打包、VM 攻击回归：本机无签名驱动与 VM，本轮**不实现代码**，在文档中记为发布门禁阻塞项；如用户要求静态实现，需另行批准并接受「无法验证」。

---

## 3. 协议设计（`security-service/include/vty_svc_protocol.h`）

请求仍为 64 字节，版本仍为 1。非内核命令继续要求 32..63 全 0。

新增常量：

```c
#define VTY_SVC_REQUEST_PAYLOAD_OFF 32u

#define VTY_SVC_ARM_MODE_WORKER_SELF 0u   /* 兼容：worker 自身 ARM */
#define VTY_SVC_ARM_MODE_HOST_PREARM 1u   /* 宿主在 worker 创建前 ARM */

#define VTY_SVC_WORKER_IMAGE_DEFAULT 0u   /* verthys-worker.exe */
#define VTY_SVC_WORKER_IMAGE_SIDECAR 1u   /* verthys-worker-x86_64-pc-windows-msvc.exe */
```

载荷结构（仅内存表示，不上线）：

```c
typedef struct VtySvcKernelPayload {
    uint32_t mode;             /* ARM: 0/1；REGISTER: 0 */
    uint32_t worker_image;     /* ARM 宿主模式: 0/1 */
    uint32_t target_pid;       /* REGISTER: worker PID；0 表示 self */
    uint64_t target_creation;  /* REGISTER: FILETIME 四字；self 时为 0 */
} VtySvcKernelPayload;
```

线格式：

| 命令 | 32..35 | 36..39 | 40..43 | 44..47 | 48..63 |
| --- | --- | --- | --- | --- | --- |
| 6 ARM | mode | worker_image | 0 | 0 | 0 |
| 7 REGISTER | target_pid | target_creation[31:0] | target_creation[63:32] | 0 | 0 |
| 8 DISARM | 0 | 0 | 0 | 0 | 0 |

新增函数：

- `void vty_svc_request_encode_kernel(uint8_t raw[64], uint16_t command, uint32_t request_id, uint64_t nonce_lo, uint64_t nonce_hi, const VtySvcKernelPayload *payload)`
  - `payload == NULL` 等价于全 0（worker self）。
- `uint16_t vty_svc_request_decode_kernel(const uint8_t *raw, size_t len, VtySvcRequestFields *fields, VtySvcKernelPayload *payload)`
  - 仅接受命令 6/7/8；公共头校验同现有解码。
  - ARM：`mode ∈ {0,1}`；`mode==0` 时 `worker_image` 必须为 0；40..63 必须全 0。
  - REGISTER：44..63 必须全 0；`target_pid==0` 时 `target_creation` 必须为 0。
  - DISARM：32..63 必须全 0。
  - 任一不满足返回 `BAD_REQUEST`。

现有 `vty_svc_request_decode` 不改，供非内核命令使用。

`security-service/src/pipe_server.c`：请求解码处按命令分支，命令 6/7/8 使用 `vty_svc_request_decode_kernel`；分发时把 `payload.mode/worker_image/target_pid/target_creation` 传给 `kernel_guard`。其他命令行为不变。

---

## 4. 服务侧（`security-service/src/kernel_guard.h/.c`）

### 4.1 状态

以单一状态块替换现有 `g_armed_pid/g_armed_creation`：

```c
static DWORD g_mode;                 /* 0 无 / 1 worker self / 2 host prearm */
static DWORD g_owner_pid;            /* host(mode2) 或 worker(mode1) */
static ULONGLONG g_owner_creation;
static DWORD g_bound_pid;            /* 已 REGISTER 的 worker；0 未登记 */
static ULONGLONG g_bound_creation;
static WCHAR g_armed_path[VTG_MAX_IMAGE_PATH_CHARS]; /* NT 路径 */
```

`g_kg_lock` 继续保护上述字段与设备 I/O 序列。

### 4.2 新增纯函数（可单测）

- `int vty_kernel_guard_is_host_image(const wchar_t *image_path)`
  - 基名忽略大小写等于 `verthys.exe`。
- `int vty_kernel_guard_worker_basename(uint32_t selector, wchar_t *out, size_t cap)`
  - 0 → `verthys-worker.exe`；1 → `verthys-worker-x86_64-pc-windows-msvc.exe`；其他 → -1。
- `int vty_kernel_guard_build_sibling_path(const wchar_t *host_image, uint32_t selector, wchar_t *out, size_t cap)`
  - 取宿主映像最后一个 `\` 之前目录，拼接白名单基名。
  - 无目录分隔符、超长、非法 selector 返回 -1。
- 保留并复用 `vty_kernel_guard_dos_to_nt_path`、`vty_kernel_guard_is_worker_image`。

### 4.3 ARM

签名改为：

```c
uint16_t vty_kernel_guard_arm(DWORD client_pid, HANDLE client_process,
                              uint32_t mode, uint32_t worker_image,
                              VtyKernelGuardStatus *out);
```

- `mode==0`（worker self）：保持 Round 7 行为；客户端必须是 worker；受保护路径为客户端自身；成功后 `g_mode=1`、`g_owner=*client`、`g_bound=0`。
- `mode==1`（host prearm）：
  1. 客户端必须是 `verthys.exe`（签名认证已由管道入口完成）。
  2. `vty_kernel_guard_build_sibling_path(client.ImagePath, worker_image, dos_path)` 派生；`GetFileAttributesW` 必须存在且非目录，否则 `DENIED`。
  3. `dos_to_nt` 写入 `nt_path`；长度必须落在 `VTG_MAX_IMAGE_PATH_CHARS` 内。
  4. 单所有者：若 `g_owner` 或 `g_bound` 对应进程仍存活且与当前客户端不一致 → `DENIED`；已退出则清理后接管。
  5. 驱动 ARM 使用 `nt_path`；成功后 `g_mode=2`、`g_owner=*host`、`g_bound=0`，并保存 `g_armed_path`。
- 任一失败不写状态；驱动失败时清空状态。

### 4.4 REGISTER

签名改为：

```c
uint16_t vty_kernel_guard_register(DWORD client_pid, HANDLE client_process,
                                   uint32_t target_pid, uint64_t target_creation,
                                   VtyKernelGuardStatus *out);
```

- `g_mode==1`：客户端必须等于 owner；忽略 target 载荷（必须为 0，服务侧再校验）；驱动登记客户端自身；成功 `g_bound=owner`。
- `g_mode==2`：
  - 客户端等于 `g_bound`（worker 解锁时补登记）：驱动登记客户端自身；幂等成功。
  - 客户端等于 `g_owner`（宿主）：`target_pid != 0 && target_creation != 0`；以 `PROCESS_QUERY_LIMITED_INFORMATION` 打开目标；`GetProcessTimes` 创建时间必须等于载荷；映像 NT 路径必须等于 `g_armed_path`；驱动登记目标身份；成功 `g_bound=target`。
  - 其他客户端 → `DENIED`。
- `g_mode==0` → `LOCKED`。
- 驱动返回非 OK 时不更新 `g_bound`。

### 4.5 DISARM

- 允许调用者等于 `g_owner` 或 `g_bound`（按 PID + 创建时间）。
- 驱动 DISARM 成功后清空全部状态；驱动 `NOT_ARMED` 视为成功。
- 其他调用者且存在存活 owner/bound → `DENIED`。

### 4.6 竞争与失败

- 所有状态读写与设备 I/O 仍在 `g_kg_lock` 独占区内，防止 ARM/REGISTER/DISARM 交错。
- 服务重启丢失状态：已登记保护在驱动侧继续生效；新 worker 的 REGISTER 会 `LOCKED`，C 核心回退 ARM+REGISTER 重建。该行为写入文档风险项。

---

## 5. 宿主服务 IPC 客户端

新文件：`verthys-tauri/src-tauri/src/infrastructure/security_service_client.rs`。

```rust
pub enum WorkerImage { Default, Sidecar }

pub fn kernel_arm_host(image: WorkerImage) -> Result<(), String>;
pub fn kernel_register(pid: u32, creation: u64) -> Result<(), String>;
pub fn kernel_disarm() -> Result<(), String>;
```

内部 `request_kernel(command, payload) -> Result<(), String>`：

1. 打开 `HKLM\SOFTWARE\Verthys\SecurityService`（`KEY_READ | KEY_WOW64_64KEY`）。
2. 读 `Installed`（REG_DWORD==1）与 `ServerPubKey`（REG_BINARY，1..256 字节）；缺失即 Err。
3. `CreateFileW("\\.\pipe\VerthysSecuritySvc.v1", GENERIC_READ|GENERIC_WRITE, 0, OPEN_EXISTING, FILE_FLAG_OVERLAPPED)`；`ERROR_PIPE_BUSY` 时 `WaitNamedPipeW(250ms)` 重试一次。
4. `SetNamedPipeHandleState(PIPE_READMODE_MESSAGE)`。
5. `BCryptGenRandom` 生成 request_id / nonce_lo / nonce_hi；按 §3 线格式构造 64 字节请求。
6. Overlapped `WriteFile`/`ReadFile`，各 1000ms；超时 `CancelIoEx` 并 Err。
7. 校验 128 字节响应：magic、version、状态范围、request_id、nonce、36..47 保留区；内核命令使用允许 48..63 的解码规则。
8. 验签：SHA-256（前 64 字节）→ `BCryptOpenAlgorithmProvider(ECDSA_P256)` → `BCryptImportKeyPair(ECCPUBLIC_BLOB)` → `BCryptVerifySignature`（签名取 64..127）。失败 Err。
9. 状态非 `OK` 返回 Err（含数值状态，不含内部路径/堆栈）。
10. 所有缓冲区用后清零；任何错误只返回固定描述。

常量在 Rust 侧集中定义（请求/响应长度、偏移、命令号、状态号），不依赖 C 头文件。

---

## 6. 宿主 spawn 集成（`worker/session.rs`、`worker/platform.rs`）

新增 `platform::process_creation_time_quad(handle: HANDLE) -> Result<u64, String>`（`GetProcessTimes`）。

`WorkerSession::spawn` 顺序：

1. `verify_install_paths`。
2. 判定预 ARM 资格（新函数 `prearm_image(worker_exe) -> Option<WorkerImage>`）：
   - worker 基名必须是两个白名单名之一（忽略大小写）。
   - `worker_exe` 父目录与 `current_exe()` 父目录规范化后必须相等。
   - 不满足 → `None`（开发树/异常布局），跳过预 ARM。
3. 若 `Some(image)`：在 `cmd.spawn()` **之前**调用 `kernel_arm_host(image)`；失败只记录 warn，不阻断。
4. `cmd.spawn()`；失败且已预 ARM → `kernel_disarm()` 尽力清理。
5. 取得 PID 与子进程句柄创建时间。
6. 若预 ARM 成功：`kernel_register(pid, creation)`；失败记录 warn，不禁用路径保护、不 Disarm。
7. `harden_suspended_worker(pid)`（Job/DACL + NtResumeProcess）；失败 → kill 子进程 + `kernel_disarm()` 尽力清理 + Err。
8. 其余流程（心跳、Actor、会话构建）不变。

日志只记录模式与结果，不记录完整路径。

`worker/session.rs` 现有测试中 `spawn` 无 tokio 上下文用例不受影响；新增纯函数单测覆盖 `prearm_image` 的基名/同目录判定。

---

## 7. C 核心（`core/src/security/state/vty_machine_limiter.c`）

`vty_machine_limiter_kernel_guard_apply_preset` 在 `g_kernel_guard_lock` 内改为：

```
if (kernel_status(&st) == VTY_OK && (st.state == ACTIVE || st.state == ARMED)) {
    if (kernel_register() == VTY_OK) { acquired = 1; return; }
}
if (kernel_arm() == VTY_OK && kernel_register() == VTY_OK) acquired = 1;
else (void)kernel_disarm();
```

理由：宿主预 ARM 后驱动在 worker 创建通知中已加入受保护表并把状态置为 ACTIVE；此时再次 ARM 会 `VtgStateDisarm` 清空宿主预登记，必须只补 REGISTER。状态查询失败或服务状态丢失时回退 Round 7 的 ARM+REGISTER。

`VtyKernelStatus` 与公共 API 不变；不新增导出符号。

---

## 8. 运行中丢失自动锁定

### 8.1 worker 轻量状态操作

`verthys-tauri/verthys-worker/src/runtime/dispatch.rs`：

- 新增 `"kernel_status"` 分支：调用 `Worker::call_kernel_status()`，返回 `{ok, op, kernel_status:{state,reason,capabilities,protocolMajor,protocolMinor}}`；符号缺失或调用失败返回错误码，不影响既有操作。

`verthys-tauri/verthys-worker/src/runtime/protocol.rs`：

- `Response` 新增 `kernel_status: Option<KernelStatusReport>`，序列化命名与现有字段一致；既有构造点补 `None`。
- `call_kernel_status` 提升为 `pub(crate)`。

### 8.2 宿主看门狗

新文件：`verthys-tauri/src-tauri/src/worker/kernel_watchdog.rs`：

```rust
pub fn start(session: WorkerSession, app: tauri::AppHandle);
```

线程名 `verthys-kernel-watchdog`，每 2s：

1. `session.is_alive()` 为 false → 退出。
2. `preset_persistence::read_preset_persist(&app)`：
   - `Ok(Some(p)) && p.code == 1`（SECURE）→ 继续。
   - 其他（含读取失败）→ `seen_active = false`、`misses = 0`，继续（无法确认 SECURE 时不误锁）。
3. `session.send_json_with_timeout(r#"{"op":"kernel_status"}"#, 2s)`，解析 `kernel_status.state`；请求失败/超时视为「无样本」，**不累计丢失次数**（避免大批量导入/轮换占用 Actor 时误锁）。
4. `state == ACTIVE` → `seen_active = true`、`misses = 0`。
5. `seen_active && state` 明确非 ACTIVE → `misses += 1`；`misses >= 2` → 记录 error，`tauri::async_runtime::spawn(perform_external_lock(app, "kernel_lost"))`，退出线程。

在 `worker_init` 就绪成功后启动一次（每次 worker 重建各启动一个，旧线程随旧会话退出）。

不锁定「从未 ACTIVE」的会话，保持 SECURE=`preferred` 的降级语义。

---

## 9. 测试与验证

### 9.1 服务

- `security-service/tests/test_protocol.c`：编码/解码线格式、mode/selector 越界、REGISTER PID/创建时间布局、保留区非零拒绝、旧 64B 全零请求仍被 self 模式接受。
- `security-service/tests/test_kernel_guard.c`：宿主/worker 基名识别、worker 基名选择、同目录路径派生（含超长与无分隔符拒绝）、现有生命周期拒绝路径适配新签名。
- 命令：

```powershell
pwsh -NoProfile -File scripts\build\build_security_service.ps1 -Profile local -Config Debug -TestHooks -RunTests -NoSign
pwsh -NoProfile -File scripts\build\build_security_service.ps1 -Profile local -Config Release -TestHooks -RunTests -NoSign
```

### 9.2 C 核心

- `core/tests/security/test_machine_limiter.c`：伪服务端新增 KERNEL_STATUS=ACTIVE 场景，断言序列为 REGISTER（无 ARM）；KERNEL_STATUS=UNARMED 场景断言 ARM→REGISTER；REGISTER 失败断言 DISARM 回滚。
- 命令：

```powershell
pwsh -NoProfile -File scripts\build\build_core.dev.ps1 -TestHooks -NoPause
pwsh -NoProfile -File scripts\build\build_core.dev.ps1 -NoPause
```

### 9.3 Rust

- `security_service_client`：请求编码字节布局、响应头校验（错误 magic/version/request_id/保留区）、状态映射单测；CNG 验签使用测试内生成的 P-256 密钥对覆盖成功/篡改失败。
- `prearm_image`：同目录 + 白名单基名返回 Some；异目录/非白名单返回 None。
- 命令：

```powershell
cargo check --manifest-path verthys-tauri\src-tauri\Cargo.toml
cargo test --manifest-path verthys-tauri\src-tauri\Cargo.toml security_service_client
cargo test --manifest-path verthys-tauri\verthys-worker\Cargo.toml
```

### 9.4 关键路径（本机可执行部分）

- 未安装服务：worker 启动成功；日志显示预 ARM 因服务/驱动不可用降级，解锁不被阻断。
- 开发树（worker 与宿主不同根）：日志显示跳过预 ARM，worker 走既有路径。
- 已安装服务且驱动未加载：ARM 返回 `UNAVAILABLE`，预 ARM 降级；看门狗未观察到 ACTIVE，不误锁。
- 无驱动环境无法触发 `kernel_lost` 锁定，此路径标注未验证。

### 9.5 不可验证

- 驱动加载后的 A14 攻击回归、REGISTER 身份校验、LOST 自动锁定端到端。
- 服务重启、驱动卸载、VM 攻击回归、HVCI/Secure Boot/Driver Verifier。
- 安装器一次 UAC：本轮不实现。

---

## 10. 兼容性、风险与回滚

| 项 | 结论 |
| --- | --- |
| 新服务 + 旧 worker | 旧请求 32..63 全 0 → mode=0、target=0，按 self 处理，行为不变 |
| 旧服务 + 新宿主 | 旧服务拒绝带载荷请求 → 宿主记录 warn，降级为 worker 自 ARM |
| 新宿主 + 无驱动 | 预 ARM 失败，不阻断解锁；A14 保护不可用 |
| 开发树布局 | 跳过预 ARM，不误保护其他目录的同名进程 |
| 路径约束 | 服务只派生「宿主目录 + 白名单 worker 基名」，且要求文件存在；不接受任意路径 |
| 主体约束 | REGISTER 只接受 ARM owner（宿主）或已绑定 worker；目标 PID/创建时间/映像路径三重校验 |
| 回滚 | 协议新增字段对旧请求保持全 0 兼容；移除宿主预 ARM 调用即回到 Round 7 行为，服务状态无需迁移 |

**已知风险**：

- 宿主二进制若被重命名（非 `verthys.exe`），预 ARM 被拒绝，退回 worker 自 ARM；不报错阻断。
- 服务重启后 owner 状态丢失，既有会话的 REGISTER 可能失败；C 核心回退 ARM+REGISTER，期间受保护表被重建。
- 看门狗 2s×2 的检测窗口内，丢失后仍可能有短时间未锁定；这是可用性与 fail-closed 的折中，需在文档中注明。

---

## 11. 交付物

- 代码：`vty_svc_protocol.h`、`pipe_server.c`、`kernel_guard.h/.c`、服务测试；`security_service_client.rs`、`worker/session.rs`、`worker/platform.rs`、`worker/kernel_watchdog.rs`、`worker/mod.rs`；`vty_machine_limiter.c`、C 测试；worker `dispatch.rs`、`protocol.rs`。
- 文档：`docs/kernel-guard/10-execution-rounds.md` 新增 Round 8 章节与变更记录；`README.md`、`04-service-and-preset.md`、`05-test-and-verification.md`、`08-roadmap-adr.md` 状态同步。
- 汇报：构建/测试证据、覆盖范围、未验证项、风险。

---

## 12. 审批

请确认以下决策后进入实现：

1. **A14 路径派生**：服务从宿主映像目录 + 白名单 worker 基名派生受保护路径，不接受客户端任意路径。同目录不成立时跳过预 ARM。
2. **REGISTER 载荷**：使用请求 32..63 区携带 PID + FILETIME 创建时间；`target_pid==0` 保留为 worker self 兼容。
3. **运行中锁定**：宿主看门狗 2s 轮询、连续 2 次非 ACTIVE 锁定；从未 ACTIVE 不锁定；SECURE 档位读取失败时不锁定。
4. **安装器与 VM 门禁**：本轮不实现安装器一次 UAC，不伪造 VM 攻击结果，作为发布门禁阻塞项记录。
