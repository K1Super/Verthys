# 任务清单：加密库创建/打开失败根因修复

- [x] T1 复现与证据固化
  - 读取 `session.rs` worker spawn 现状，确认单一收口点。
  - 复核 `dispatch.rs` 的 `retry_after_secs` 填充逻辑，确认控制器可直接消费。
  - 记录：本机 `Verthys_GetLibLockoutRemaining` = 0；服务事件 3002 `image-auth`。

- [x] T2 实现开发旁路注入
  - 文件：`verthys-tauri/src-tauri/src/worker/session.rs`
  - 新增 `dev_machine_limiter_bypass()`（仅 `cfg!(debug_assertions)` 返回 `Some`）。
  - 在 worker `Command` 上应用 `cmd.env(...)`。
  - 新增单元测试：spawn `cmd /C echo %VERTHYS_TEST_MACHINE_LIMITER_BYPASS%`，断言 `1`。

- [x] T3 修正创建步骤 3 失败诊断
  - 文件：`verthys-tauri/src-tauri/src/controller/verthys_controller.rs`
  - 日志输出 `retry_after_secs`。
  - RATE 文案按“退避秒数 > 0 / = 0”拆分，覆盖未签名开发构建提示。
  - 保持回滚行为不变。
  - 同时补齐 `verthys-worker/src/runtime/dispatch.rs` 的 `v4_unlock_keyfile` 分支：
    RATE 时与 `unlock` 一致附带本地退避剩余秒数（否则 keyfile 库无法区分两种原因）。

- [x] T4 构建与单测
  - `cargo build`：成功。
  - `cargo test --lib dev_machine_limiter_bypass`：1 passed / 0 failed。
  - worker `cargo build --release`：成功，并同步 Tauri 暂存 worker（SHA256 一致）。

- [x] T5 Worker 端到端回归
  - `tests/e2e/worker-smoke.ps1`（pwsh 7）：创建、照片/文件内容链路全部 PASS。
  - 复现与反证（临时探针，非仓库脚本）：
    - 有旁路：`v4_create_keyfile` → `lock` → `v4_unlock_keyfile` = PASS。
    - 无旁路：创建成功、锁定成功、重开返回 `ERR_0000000A` = 与线上失败一致。
  - 备注：完整 smoke 后续“模块口令轮换”步骤在错误口令后 1 秒内重试，命中
    模块级最小尝试间隔返回 `ERR_0000001D`；与本次容器创建/打开修复无关，
    属既有测试时序假设，未改仓库用例。

- [x] T6 应用关键路径验证
  - 清空 shell 的 `VERTHYS_TEST_MACHINE_LIMITER_BYPASS` 后，用 debug 构建
    直接运行宿主层 e2e（`VERTHYS_E2E_ROTATE=1`）。
  - 结果文件：`PASS`，步骤含 `worker_init / create / add_record / module_enable /
    lock / unlock_recovery / rotate_* / cleanup`，退出码 0。
  - 证明：应用 spawn 的 worker 已由宿主注入旁路，create→lock→unlock 不再依赖
    启动脚本预设环境变量。

- [x] T7 回归检查
  - `git diff --stat`：本任务仅改 3 个 Rust 文件（+ 新增 Spec 文档）。
  - 无新增依赖、无格式漂移、无无关文件；无残留 Verthys 进程。
  - 暂存 worker 与 release 产物 SHA256 一致（F4CB5E4E…）。
