# Round 8 任务清单

> 规格见 [spec.md](spec.md)。状态：已批准，T1–T7 完成。
> 执行顺序固定；每项完成并验证后才能进入下一项。

---

## [x] T1 协议扩展

**文件**

- `security-service/include/vty_svc_protocol.h`
- `security-service/src/pipe_server.c`
- `security-service/tests/test_protocol.c`

**内容**

1. 新增 `VTY_SVC_REQUEST_PAYLOAD_OFF`、ARM 模式、worker 映像选择常量与 `VtySvcKernelPayload`。
2. 实现 `vty_svc_request_encode_kernel` / `vty_svc_request_decode_kernel`，按 spec §3 校验。
3. `pipe_server.c` 对命令 6/7/8 改用内核解码器，并把载荷传入 `kernel_guard`。
4. 测试：合法编码/解码、越界 mode/selector、保留区非零、REGISTER PID/创建时间布局、旧全零请求兼容。

**完成判据**：服务 Debug 构建通过；协议测试通过。

---

## [x] T2 服务 kernel_guard

**文件**

- `security-service/src/kernel_guard.h`
- `security-service/src/kernel_guard.c`
- `security-service/tests/test_kernel_guard.c`

**内容**

1. 状态块改为 mode/owner/bound/armed_path，仍在 `g_kg_lock` 内读写。
2. 新增 `vty_kernel_guard_is_host_image`、`vty_kernel_guard_worker_basename`、`vty_kernel_guard_build_sibling_path`。
3. `vty_kernel_guard_arm` 支持 mode 0/1；宿主模式校验客户端、派生路径、文件存在、单所有者。
4. `vty_kernel_guard_register` 支持 worker self、宿主提交目标、worker 补登记幂等。
5. `vty_kernel_guard_disarm` 允许 owner 或 bound。
6. 测试覆盖纯函数与拒绝路径；适配新函数签名。

**完成判据**：服务 Debug/Release `ctest` 通过；静态审查无未加锁状态访问。

---

## [x] T3 宿主服务 IPC 客户端

**文件**

- 新建 `verthys-tauri/src-tauri/src/infrastructure/security_service_client.rs`
- `verthys-tauri/src-tauri/src/infrastructure/mod.rs`

**内容**

1. 实现 `WorkerImage`、`kernel_arm_host`、`kernel_register`、`kernel_disarm`。
2. 注册表公钥读取、消息管道、overlapped 读写超时、响应头校验、ECDSA P-256 验签。
3. 固定错误描述，不泄露路径与堆栈。
4. 单测：请求编码布局、响应拒绝路径、测试密钥对验签成功/篡改失败。

**完成判据**：`cargo check` 与客户端单测通过。

---

## [x] T4 宿主 spawn 预 ARM 接入

**文件**

- `verthys-tauri/src-tauri/src/worker/session.rs`
- `verthys-tauri/src-tauri/src/worker/platform.rs`

**内容**

1. `platform::process_creation_time_quad`。
2. `prearm_image(worker_exe)`：白名单基名 + 与宿主同目录。
3. spawn 顺序：ARM → spawn suspended → 读取创建时间 → REGISTER → Job/DACL/resume。
4. 失败路径：spawn 失败或加固失败时尽力 DISARM；REGISTER 失败只降级记录。
5. 单测覆盖 `prearm_image` 判定。

**完成判据**：`cargo check`、相关单测通过；日志不输出完整路径。

---

## [x] T5 C 核心 SECURE 激活顺序

**文件**

- `core/src/security/state/vty_machine_limiter.c`
- `core/tests/security/test_machine_limiter.c`

**内容**

1. `apply_preset` 在锁内先查状态：ACTIVE/ARMED → REGISTER-only；失败回退 ARM+REGISTER。
2. 伪服务端新增 ACTIVE 场景与序列断言；补充 REGISTER 失败回滚断言。
3. 保持导出 API 不变。

**完成判据**：`build_core.dev.ps1 -TestHooks` 全量通过；dev DLL 构建通过。

---

## [x] T6 运行中丢失自动锁定

**文件**

- 新建 `verthys-tauri/src-tauri/src/worker/kernel_watchdog.rs`
- `verthys-tauri/src-tauri/src/worker/mod.rs`
- `verthys-tauri/src-tauri/src/controller/worker_controller.rs`
- `verthys-tauri/verthys-worker/src/runtime/dispatch.rs`
- `verthys-tauri/verthys-worker/src/runtime/protocol.rs`
- `verthys-tauri/verthys-worker/src/runtime/worker.rs`

**内容**

1. worker 新增 `kernel_status` 操作与响应字段。
2. 宿主看门狗：2s 轮询、SECURE 判定、ACTIVE 记忆、连续 2 次「明确非 ACTIVE」锁定；查询失败/超时不计入。
3. `worker_init` 就绪后启动看门狗；旧线程随旧会话退出。
4. 单测：worker 响应序列化；宿主判定函数（活跃/丢失/无样本/未激活/非 SECURE）抽为纯函数并测试。

**完成判据**：宿主与 worker `cargo check`/`cargo test` 通过；无 ACTIVE 时不锁定有单测证明。

---

## [x] T7 回归审查与文档

**文件**

- `docs/kernel-guard/10-execution-rounds.md`
- `docs/kernel-guard/README.md`
- `docs/kernel-guard/04-service-and-preset.md`
- `docs/kernel-guard/05-test-and-verification.md`
- `docs/kernel-guard/08-roadmap-adr.md`

**内容**

1. 新增 Round 8 章节：实现范围、文件、验证证据、未验证项、风险。
2. 更新状态行与变更记录；明确安装器/VM 仍为发布门禁阻塞。
3. A14/S6 状态改为「代码完成，运行期未验证」。

**完成判据**：文档与代码一致；验证证据包含实际命令与结果。

---

## 验证汇总（执行后填写）

| 项 | 命令 | 结果 |
| --- | --- | --- |
| 服务 Debug | `build_security_service.ps1 -Profile local -Config Debug -TestHooks -RunTests -NoSign` | 通过（ctest 1/1） |
| 服务 Release | 同上 `-Config Release` | 通过（ctest 1/1） |
| C 全量 | `build_core.dev.ps1 -TestHooks -NoPause` | 通过（332 通过 / 0 失败） |
| C dev DLL | `build_core.dev.ps1 -NoPause` | 通过 |
| 宿主 | `cargo check` / 定向 `cargo test` | 通过（客户端 5、看门狗 5） |
| worker | `cargo test` | 通过（128 通过 / 0 失败 / 1 忽略） |

## 未验证（不得声称通过）

- 驱动加载后的 A14 攻击回归与 REGISTER 端到端。
- 内核 LOST 自动锁定真实链路。
- 安装器一次 UAC、VM 攻击回归、HVCI/Secure Boot/Driver Verifier、72 小时稳定性。
