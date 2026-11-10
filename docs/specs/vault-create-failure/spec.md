# 加密库创建/打开失败根因修复 Spec

## 1. 结论（已验证）

创建流程并非容器写入失败，而是“创建成功后的自检解锁”被机器级预算服务 fail-closed 拒绝，随后整个创建被回滚删除。

证据链：

| 证据 | 来源 | 结论 |
| --- | --- | --- |
| `步骤 1/3: v4_create 成功` / `步骤 2/3: lock 成功` / `步骤 3/3 失败: error=ERR_0000000A` | `%LOCALAPPDATA%\com.verthys.app\logs\main_ui.log`（2026-11-09T17:23:49Z，PID 26536） | 容器已创建并落盘，失败发生在重新打开 |
| `创建失败，已回滚 ... 创建加密库失败（步骤3重开失败）` | 同上 + `%APPDATA%\com.verthys.app\audit.log` | 前端只能看到“创建加密库失败”，且 .verthys 被删除 |
| `VERTHYS_ERR_RATE = 0x0A`，由 `VTY_E_LOCKED` 映射 | `core/src/api/lifecycle/verthys_api.c:480` | 0x0A 是“锁定/限流”统一码 |
| `Verthys_GetLibLockoutRemaining` 实测 `rc=0x00000000 secs=0` | 本机 P/Invoke 调用当前 `build/core/Release/verthys.dll` | 本地库级熔断未锁定，排除本地退避 |
| Event 3002 `Client request denied ... reason=image-auth` | Windows 应用日志，Provider `VerthysSecuritySvc` | P2 机器预算服务拒绝未签名的开发客户端镜像 |
| `vty_machine_limiter_check()` 在解锁入口先于密码校验 | `core/src/crypto/vty_keymanager.c:1484` | 机器预算失败直接返回 `VTY_E_LOCKED` |
| DLL 含 `VERTHYS_TEST_MACHINE_LIMITER_BYPASS`，CMakeCache `VERTHYS_TEST_HOOKS:BOOL=ON` | 当前产物 + `build/CMakeCache.txt` | 测试旁路已编译，只差运行期环境变量 |
| `build_dev.ps1` 第 381 行设置旁路，仅作用于该启动 shell | `build_dev.ps1` | IDE / 直接 `npx tauri dev` / 测试宿主启动时丢失旁路 |

根因表述：

> 开发构建未签名，P2 机器预算服务按 `image-auth` 拒绝客户端，C 层把该拒绝映射为 `VTY_E_LOCKED`；只有在进程环境显式携带 `VERTHYS_TEST_MACHINE_LIMITER_BYPASS=1` 时才会跳过服务调用。旁路目前只由 `build_dev.ps1` 注入启动 shell，任何其他启动方式都会让创建的自检解锁失败并回滚，打开已有库也会以同一错误失败。

## 2. 目标与验收

- 任一开发启动方式（`build_dev.ps1`、IDE、直接 `npx tauri dev`、debug 构建产物）下，创建加密库与打开加密库都成功。
- 生产构建（`VERTHYS_TEST_HOOKS=OFF` + Release）行为不变：机器预算服务仍强制 fail-closed，不注入任何旁路。
- 创建步骤 3 失败时，日志与用户提示能区分“服务拒绝/不可用（含未签名开发构建提示）”与“本地熔断退避（含剩余秒数）”。

## 3. 非目标

- 不修改 P2 服务的客户端镜像验签策略（安全边界）。
- 不修改 C 层机器预算/本地熔断语义。
- 不自动重置本地熔断状态（实测未锁定，且会削弱防暴力破解语义）。
- 不在本轮修复“未签名 dev 主程序触发 background_patrol 应急销毁 Worker”的误报，作为已知风险记录。

## 4. 修改方案

### 4.1 `verthys-tauri/src-tauri/src/worker/session.rs`

在 worker 子进程创建处（`Command::new(worker_exe)` 附近）注入开发旁路，作为应用内唯一 worker 启动收口点：

```rust
/// 开发构建向 worker 注入 P2 机器预算测试旁路。
/// 仅 debug 构建注入；生产构建不设置，生产 DLL 也不包含该分支。
fn dev_machine_limiter_bypass() -> Option<(&'static str, &'static str)> {
    if cfg!(debug_assertions) {
        Some(("VERTHYS_TEST_MACHINE_LIMITER_BYPASS", "1"))
    } else {
        None
    }
}

// spawn：
if let Some((key, value)) = dev_machine_limiter_bypass() {
    cmd.env(key, value);
}
```

单元测试（`#[cfg(test)]`，与 `session.rs` 同文件）：

- 通过同一 helper 配置 `Command`，spawn `cmd /C echo %VERTHYS_TEST_MACHINE_LIMITER_BYPASS%`，断言输出 `1`。
- 该测试在 debug（测试）构建下必须为 `Some(("VERTHYS_TEST_MACHINE_LIMITER_BYPASS","1"))`。

影响面：仅调试构建的 worker 环境；release 分支为 `None`。`build_dev.ps1` 的既有设置保留为纵深防御，不删除。

### 4.2 `verthys-tauri/src-tauri/src/controller/verthys_controller.rs`（步骤 3 失败分支，约 1481–1491 行）

- 日志追加 `retry_after_secs`（`unlock_resp2.retry_after_secs`）。
- 文案按条件拆分：
  - `retry_after_secs > 0`：`创建加密库失败（步骤3重开失败）：本机安全退避中，请 N 秒后重试；库文件尚未保留`。
  - `retry_after_secs == 0` 或缺失：`创建加密库失败（步骤3重开失败）：本机安全服务拒绝或不可用。未签名的开发构建请使用 build_dev.ps1 启动；已安装服务时请确认客户端签名与 VerthysSecuritySvc 状态`。
- 不改变回滚行为（保持原子性：创建不完整就不留下无法承诺会话的库）。

### 4.3 测试与门禁

- 新增 Rust 单元测试（4.1）。
- 不新增依赖，不改公共契约，不改数据库/容器格式。

## 5. 验证计划

| 项 | 命令 / 操作 | 期望 |
| --- | --- | --- |
| 构建 | `cargo build`（`verthys-tauri/src-tauri`） | 成功 |
| 单元测试 | `cargo test --lib dev_machine_limiter_bypass`（包名以 Cargo.toml 为准） | 通过，子进程读到 `1` |
| Worker 链路 | `powershell -NoProfile -ExecutionPolicy Bypass -File tests/e2e/worker-smoke.ps1` | 创建→锁定→旧码拒绝→新码解锁 全部 PASS |
| 反证（可选） | 临时复制 worker-smoke 并移除旁路环境变量，保留 `VERTHYS_TEST_STATE_DIR` | 自检解锁返回 `0x0A`，证明失败机制 |
| 关键路径 | 清除 shell 中的 `VERTHYS_TEST_MACHINE_LIMITER_BYPASS`，用 debug 构建启动应用并执行创建；如 UI 自动化不可用，则以“spawn 环境测试 + worker-smoke 通过”作为组合证据并标注 UI 点击未执行 | 创建返回恢复码，随后锁定/解锁成功 |
| 回归 | `npx vue-tsc --noEmit`（如本轮未改前端可略）；C 侧无改动 | 无新增错误 |

## 6. 风险与回滚

- 安全：仅 `cfg!(debug_assertions)` 注入；生产 DLL 不含旁路代码，生产构建不设置变量。无发布面弱化。
- 兼容：无格式、无 IPC 契约变更。
- 回滚：还原 `session.rs` / `verthys_controller.rs` 两处改动即可。
- 已知风险（不在本轮修复）：未签名 dev 主程序可能被 `background_patrol` 判为未知模块并销毁 Worker；若复现，另立任务。

## 7. 决策记录

| 备选 | 结论 | 理由 |
| --- | --- | --- |
| 仅依赖 `build_dev.ps1` 设置环境变量 | 否决 | IDE/直接 Tauri/测试宿主会丢失，问题复发 |
| 测试钩子 DLL 无条件跳过机器预算 | 否决 | 失去测试对 fail-closed 的可控性；显式 env 更清晰 |
| 步骤 3 失败仍保留库并返回成功 | 否决 | 违反“创建即承诺可解锁会话”的契约，且恢复码交付路径会分裂 |
| 自动重置本地熔断状态 | 否决 | 实测未锁定；且会削弱防暴力破解语义 |
| 修改 P2 服务放行未签名客户端 | 否决 | 突破安全边界 |

## 8. 审批

本 Spec 需用户确认后执行。确认即表示同意在 debug 构建中由应用向 worker 注入 `VERTHYS_TEST_MACHINE_LIMITER_BYPASS=1`，并接受生产构建行为不变。

## 9. 追加根因（第二层）：本地熔断见证丢失导致永久 fail-closed

第一层修复完成后，创建/打开仍返回 `ERR_0000000A`。进一步用真实状态复现（不改写测试态）得到：

- worker 已带 `VERTHYS_TEST_MACHINE_LIMITER_BYPASS=1`（机器预算已旁路）；
- `v4_create_keyfile`、`lock` 成功，`v4_unlock_keyfile` 仍返回 `ERR_0000000A`；
- `%LOCALAPPDATA%\Verthys\Security\lockout.state` 存在且 magic/version 正常（slot=0）；
- 用 CNG 枚举 140 个 `VerthysWit_*_A` 见证密钥，逐一导出公钥并 SHA-256，**没有**一个与状态记录指纹匹配；
- 结论：状态文件本体有效（MAC 可通过），但其绑定的 TPM 见证密钥已丢失；`vty_lockout_begin_attempt()` 在 `load_authenticated()` 中 fail-closed → 任何口令都在认证前被拒绝，且 `Verthys_GetLibLockoutRemaining` 返回 0 秒，掩盖了真实原因。

### 修复

- 新增 `vty_tpm_witness_exists()`：区分“见证密钥不存在”与“存在但指纹不符”。
- `vty_lockout.c`：把 `load_authenticated` 拆为纯查询与可恢复两条路径：
  - 只有**状态 MAC/结构有效、且该见证域两槽均不存在**时，认证入口（`begin_attempt` / `record_failure` / 模块认证入口）才把旧状态重命名为 `lockout.state.invalid<pid><tick>` 并重建；
  - MAC 篡改、跨机复制、见证指纹不符、状态回放（旧槽已删但当前槽仍存在）一律保持 fail-closed；
  - `check` / `remaining` / `failures` 保持纯查询、无副作用。
- 测试防线：`VerthysTestHygiene.psm1` 改为**先核对真实状态指纹，再回收测试见证**；一旦真实状态被测试改写，立即中止回收，避免把真实状态的新见证删掉造成永久锁死。
- 新增用例：`lockout_missing_witness_recovers`（缺失→重建）、`lockout_witness_mismatch_stays_locked`（指纹不符→仍锁定）；既有篡改/回放用例全部保持通过。

### 验证

- 恢复真实损坏状态文件后，用真实状态探针执行 `v4_create_keyfile → lock → v4_unlock_keyfile`：PASS，并生成隔离文件；
- `worker-smoke.ps1` 19 步全 PASS；
- 宿主层 headless e2e（`create / add_record / module_enable / lock / unlock_recovery / rotate_*`）PASS；
- 熔断测试组 10 项全 PASS（含篡改、回放、指纹不符、缺失恢复）；
- 生产接口 e2e `api_product_e2e` PASS（pwsh 7）。

