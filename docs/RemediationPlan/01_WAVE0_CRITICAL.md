# Wave 0 — 止血批施行细则

> 目标：恢复唯一 P0 功能故障 + 止血三项安全红线 + 修复对外文档。
> 范围：只动 TypeScript、Rust（src-tauri）、README。不触碰 C 核心、不触碰 worker 二进制协议。
> 前置：无。本批是全部后续批次的地基（尤其 FIX-0-3 是 Wave 1「C 层计数工艺」与 Wave 3「解锁态闸门」的前置）。
> 编号说明：本文档中 `FIX-x-y` 编号仅存在于工程文档，**不得进入任何代码注释**；代码注释只写代码自身可验证的用途与约束。

---

## FIX-0-1 修复 `write_user_file` IPC 协议错配（P0：照片导出 100% 失败）

### 现状事实（已核验）

- `verthys-tauri/src/composables/photo-album/usePhotoExport.ts:69-72`：

```ts
const writeVencFile = async (path: string, bytes: Uint8Array): Promise<void> => {
  const b64 = bytesToBase64(bytes);
  await invoke("write_user_file", { path, dataB64: b64 });
};
```

- Rust 端 `src-tauri/src/controller/file_controller.rs:1057-1074` 的 `write_user_file` 签名是 `(app, request: Request<'_>)`：路径取自 `x-path` HTTP 头（`decode_x_path_header`），数据取自 `InvokeBody::Raw`。前端未发送 `x-path` 头、body 是 JSON 对象 → `InvalidPath` 必然失败。
- 正确的封装已存在：`verthys-tauri/src/lib/verthys.ts:1188` 的 `writeUserFile(path, data)`，且 `PasswordTools.vue:431`、`FileVerthys.vue:570`、`useGlobalKey.ts:490` 三处在正确使用——即协议迁移时只有照片导出这一处漏改。

### 修复设计

1. `usePhotoExport.ts` 顶部 import 增加 `writeUserFile`（从 `../../lib/verthys`），与既有 `verthysGetRecord, bytesToBase64` 同源。
2. `writeVencFile` 函数体替换为：

```ts
const writeVencFile = async (path: string, bytes: Uint8Array): Promise<void> => {
  await writeUserFile(path, bytes);
};
```

3. **保留** `bytesToBase64` 的 import 与 `invoke` 的 import：`bytesToBase64` 仍被 `:226`（chunkB64List 行内加密元数据）使用；`invoke` 若仅 `writeVencFile` 使用则需要移除，实施时以 `vue-tsc` 未使用告警为准清理，不得保留死 import。
4. 不删除本地 `invoke` 语句之外的任何逻辑（错误处理/进度/对话框行为全部不动）。

### 行为要点

- 浏览器（非 Tauri）模式不经过 `writeVencFile`（走 `downloadBlob` 分支），本次改动只影响 Tauri 写盘路径。
- type 检查即验：旧代码 `invoke("write_user_file", {...})` 无类型约束，新代码走 `writeUserFile(path: string, data: Uint8Array)` 强类型签名。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 手工 | Tauri Dev 模式拾光模块 | 导出 single 打包 / multiple 多文件 / PNG 各一次，文件落盘且字节与源一致 |
| 自动化 | 新增 vitest：`usePhotoExport.spec.ts` | mock `../../lib/verthys.writeUserFile`，断言 `writeVencFile` 调用时以 `(path, bytes)` 直传且 bytes 为原始 Uint8Array（无 base64 转换） |
| 静态 | `npx vue-tsc --noEmit` | 0 错 |

### 验收标准

- Tauri 模式三种导出格式全部落盘成功。
- `usePhotoExport.ts` 中不再存在 `invoke("write_user_file", ...)` 字样。

---

## FIX-0-2 IPC 超时/解析失败日志脱敏（P1-6 + 同模式 P2-23）

### 现状事实（已核验）

- `src-tauri/src/worker/actor.rs:184-190` 与 `:246-251`：两处 `log::error!(... "请求: {}", json ...)`，`json` 即 `req.to_string()`（unlock/derive/change_password 等请求体含明文 `password`/`bin_password`）。
- 同模式相邻缺陷：
  - `src-tauri/src/controller/key_controller.rs:607`（另 303/482/669）：响应解析失败时 `log::error!(... "raw={}", resp_json)`，derive_subkey 响应含 base64 子密钥。
  - `src-tauri/src/controller/verthys_controller.rs:719`：`log::error!("... raw={}", resp_json)`（unlock 响应）。

### 修复设计（统一设施，避免复制粘贴式修复）

1. 在 `src-tauri/src/util/`（或现有日志工具模块）新增**单一脱敏函数**，供四处调用：

```rust
/// 生成请求/响应 JSON 的日志安全摘要：仅保留长度与白名单字段值。
/// 除白名单外的所有字段值一律替换为占位符，绝不落入日志。
pub(crate) fn json_log_summary(json: &str, keep_fields: &[&str]) -> String
```

实现要点：
- `serde_json::from_str::<Value>` 成功 → 递归遍历，仅 `keep_fields` 中的键（如 `op`）保留原值，其余值以 `"{len} 字节"` 形式摘要（字符串）或类型名摘要（数字/布尔/数组长度）。
- 解析失败（非 JSON）→ 返回 `"<非 JSON 负载，长度 N>"`。
- 数组/嵌套对象同样递归，任何层级都不保留未白名单的值。

2. 调用点改造：
- `actor.rs` 两处超时日志：`json` 参数替换为 `json_log_summary(json, &["op"])`；日志文案去掉"请求:"原文，改为"请求摘要:"。stderr_snippet 保留（worker 诊断必要，可信进程输出，非秘密）。
- `key_controller.rs` 607/303/482/669、`verthys_controller.rs:719`：`raw={}` 换为 `json_log_summary(&resp_json, &["op"])`。

3. 白名单只放 `op`——这是四处场景下唯一对排障有用的字段。禁止把 `data`/`name`/`password`/`bin_password` 等加入白名单。

### 行为要点

- 反 Oracle 设计不受影响：脱敏发生在日志层，不改变对前端/worker 的返回值。
- `req.to_string()` 产生含明文的临时 String 本身（发送缓冲）不在本项修复范围——其零化由 Wave 2 的 FIX-2-1 处理。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| Rust 单测 | `actor.rs` `#[cfg(test)]` 或 util 模块测试 | 对含 `"password":"secret"`,`"bin_password":"secret2"` 的 JSON 断言 summary 输出不含两值、含 `op` 值 |
| Rust 单测 | 同上 | 对非 JSON 输入断言返回长度摘要且不含原文 |
| 集成 | 手工/脚本模拟 worker 不响应（如 worker 挂起注入） | 检查后端日志文件：grep 口令明文 0 命中 |

### 验收标准

- 全仓 `src-tauri/src` 内 Grep `raw={}` 与"请求: {} | stderr"超时原样 JSON 日志 0 命中。
- 日志脱敏函数有单测覆盖白名单/递归/非 JSON 三分支。

---

## FIX-0-3 `verthys_unlock` 服务端强制接入 BruteForceGuard（P1-7）

### 现状事实（已核验，比报告更严重）

- `src-tauri/src/controller/verthys_controller.rs:597-728` 的 `verthys_unlock` 全程无任何暴力破解守卫调用。
- `src-tauri/src/security/brute_force.rs` 的 `BruteForceGuard`（check/record_failure/record_success、DPAPI 持久化、抖动、锁定/递增熔断）实现完备。
- `security_commands/state.rs:58` 中它以 `Mutex<BruteForceGuard>` 存在于 `SecurityState`（`.manage()` 于 `lib.rs:327`）。
- **额外发现（本次核验）**：全前端 Grep 确认没有任何组件调用 `security_brute_check/record_failure/record_success/clear_purge/status` 的封装（`verthys.ts:1242-1264` 只有定义，零 .vue 引用）——熔断机制当前完全静默，从未生效。

### 修复设计

**第 1 步：在 `security_commands` 模块内建立 `pub(crate)` 桥接 API**（收敛持久化与审计责任到安全模块自身，控制器只调语义化接口）。
新增文件 `src-tauri/src/security_commands/brute_force_bridge.rs`（或并入 `mod.rs`），暴露三个函数，内部复用既有 `ensure_brute_force_loaded` / `lock_brute_force_or_recover` / `persist_brute_force_state` 与审计写入：

```rust
pub(crate) fn unlock_check(app: &AppHandle, state: &SecurityState) -> Result<(), String>
  // BruteForceCheck::Allow => Ok(())
  // Locked(secs)   => Err(锁定文案, 附剩余秒数)
  // PurgeRequired  => Err(触发索引清空与完整性校验文案)
pub(crate) fn unlock_failed(app: &AppHandle, state: &SecurityState)
  // guard.record_failure() + 持久化 + 审计（锁定/递增事件）
pub(crate) fn unlock_succeeded(app: &AppHandle, state: &SecurityState)
  // guard.record_success() + 持久化
```

需要把 `SecurityState.brute_force`、`lock_brute_force_or_recover`、`ensure_brute_force_loaded`、`persist_brute_force_state` 的可见性由 `pub(super)` 放开到 `pub(crate)`（最小可见性变更，不改为 pub）。

**第 2 步：`verthys_unlock` 签名与三处接入**。

- 签名增加 `security_state: State<'_, SecurityState>` 参数（与既有 `state: State<'_, AppState>` 并列；Tauri 对多 State 参数原生支持，前端无感知）。
- 接入点 A（入口，函数体最开始，早于文件存在检查之外的一切业务逻辑之前）：调用 `unlock_check`，`Err` 时 `write_verthys_audit(AuditResult::Denied, 文案)` 后直接返回。**保证第 10 次失败触发锁定时，第 11 次请求在入口即被拒，口令根本不进入 FFI。**
- 接入点 B（失败）：`if !resp.ok` 分支内，仅当 `resp.error == Some("ERR_00000002")`（worker 统一化后的认证域错误码）时调用 `unlock_failed`。规则：
  - `ERR_00000002` → 计失败（worker 侧已将口令错误/格式/损坏统一映射为 AUTH，语义上全部属于认证域结果）；
  - `ERR_0000000C`(PEPPER_SOURCE)、`ERR_0000000E`(CNG_UNAVAILABLE)、`ERR_00000012`(TIMEOUT)、`ERR_00000007`(LOCKED) 等独立功能码 → **不计失败**（非口令错误，避免误锁）；
  - 通信层错误（`send_with_unlock_progress` 返回 `Err`，含超时销毁 worker 分支）→ 不计失败。
- 接入点 C（成功）：`resp.ok == true` 的最终成功路径（`write_verthys_audit(AuditResult::Success)` 同处）调用 `unlock_succeeded`。
- 密码复杂度校验失败（本地校验，未进 FFI）→ 不计失败，保持现 audit 行为。

**第 3 步：前端清零遗留职责**。
- `verthys.ts:1242-1264` 的五个封装保留（`security_brute_check`/`status` 供 UI 展示锁定态、`clear_purge` 供处理 Purge 后恢复），但前端**不再承担任何计数触发的职责**。
- UI 接线（可选但建议同批完成）：解锁入口调用点（负责调用 `verthysUnlock` 的 composable/视图，如 security-center 解锁流程）在发起解锁前调用 `securityBruteCheck()`，`Locked` 时直接展示剩余秒数、`PurgeRequired` 时走既有完整性校验流程，不再发起解锁。若无前端接线，锁定态只表现为后端返回拒绝文案（功能正确性不受影响，体验受损）。

### 行为要点

- `BruteForceGuard` 计数是进程内全局（不区分容器文件），本次保持其既有语义，不引入按路径分桶。
- `record_failure` 内部速率限制（RateLimited）与冻结（Frozen）语义保持，桥接层原样返回，控制器将 RateLimited/Frozen 视为"本次不计入但检查结果以 check() 现状为准"——具体以桥接函数返回值为准，控制器不做二次决策。
- 持久化：DPAPI 落盘在桥接函数内完成（与 `security_brute_record_failure` 命令相同的调用序列），进程重启后计数不丢——Wave 1 的 C 层计数工艺只需在此基础上做进程内聚合与纵深。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| Rust 单测 | `security_commands/brute_force_bridge.rs` 或既有 `brute_force.rs` 测试模块 | 连续 `unlock_failed` 至阈值后 `unlock_check` 返回锁定；`unlock_succeeded` 重置连续计数 |
| Rust 集成 | src-tauri 已有测试设施（复用 security tests） | 模拟响应 `ERR_00000002` 时计数递增；`ERR_0000000E` 不递增 |
| 手工 | Dev 模式连续 10 次错误口令 invoke unlock | 第 10 次后入口直接拒绝（日志可见 Denied 审计且不带 FFI 请求日志）；重启应用后计数保持 |

### 验收标准

- Grep 确认 `verthys_unlock` 函数体内出现 `security_state` 且三个接入点齐全。
- 前端无任何组件再调用计数型封装（仅 UI 查询类允许）。
- 连续错误口令第 10 次后端返回锁定，重启后锁定状态保持（DPAPI）。

---

## FIX-0-4 补注册 `log_fatal` 命令（P1-10：生产致命错误静默）

### 现状事实（已核验）

- 前端 `verthys-tauri/src/app/error-handler.ts:58` 生产分支 `invoke("log_fatal", { entry: JSON.stringify(entry) })`；全仓 Rust 无 `log_fatal` 定义/注册（`lib.rs:388-467` 78 项命令列表中无此项）。
- 生产构建 `vite.config.ts:33` `javascript-obfuscator` 的 `disableConsoleOutput: true` 使 `console.error` 兜底同样静默 → 双重失明。

### 修复设计

1. 新增 Rust 命令（放在既有日志/诊断命令所在模块，或 `lib.rs` 同域的诊断模块）：

```rust
#[tauri::command]
pub fn log_fatal(entry: String) {
    // 长度上限：拒绝超长输入，防日志注入/撑爆日志文件
    let hard_max = 16 * 1024;
    let snippet: &str = if entry.len() > hard_max { &entry[..hard_max] } else { &entry };
    log::error!("[frontend-fatal] {}", snippet);
}
```

  要点：
  - 直接走 `log::error!`（写后端日志文件），不用 payload 解析再拼装（前端已构造结构化 JSON 字符串）。
  - 长度截断按字节边界，UTF-8 截断风险可接受（日志可读性优先；如需严格可在 `char_indices` 上取整字符边界）。
  - 不做任何 panic、不返回错误（error-handler 的 `.catch()` 已处理失败）。

2. `lib.rs` 的 `generate_handler!` 列表加入 `log_fatal`。
3. 前端 `error-handler.ts` 不动（协议 `invoke("log_fatal", { entry: ... })` 与命令参数名 `entry` 一致，Tauri 自动 camelCase 映射成立）。
4. 生产混淆 `disableConsoleOutput` 保持 `true`（正式策略：生产日志走后端通道，前端 console 保持关闭以缩小信息面）；IPC 失败时的 console 兜底被吞是已知次级缺口，记录到 Wave 3「可观测性」条目一并评估（不扩大本项范围）。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 手工 | 生产构建中触发一次未捕获异常（如临时 `setTimeout(() => { throw new Error })`） | 后端日志文件出现含 `[frontend-fatal]` 的 FATAL 内容 |
| 静态 | 增加 IPC 契约一致性检查（Wave 4 硬化为 CI 门） | `log_fatal` 出现在 Rust 命令清单且前端调用清单匹配 |

### 验收标准

- 全仓 `src-tauri` Grep `log_fatal` 命中定义与注册各一处；前端仍为 `invoke("log_fatal", ...)`。
- 生产构建触发异常后日志文件有记录。

---

## FIX-0-5 解决 README.md 合并冲突（P1-11）

### 现状事实（已核验）

- `README.md:1` `<<<<<<< HEAD`；`:322` `=======`；`:324` `>>>>>>> c6ba26a8...`。HEAD 侧 1-321 行为完整内容，对侧仅 323 行 `# Verthys` 一行。

### 修复设计

1. 删除第 1 行、322 行、323 行、324 行（三行标记 + 对侧空壳行），保留 2-321 行 HEAD 版内容为最终文档。
2. 操作方式：直接编辑文件解决，不以 git 命令"解决冲突"绕过（当前工作树已非冲突状态，只是标记残留）。

### 回归测试

- 全仓 Grep `^(<<<<<<<|=======|>>>>>>>)` 0 命中。
- 可选：Markdown 渲染自查（标题层级、图片引用 `assets/verthys-hero.svg` 存在）。

### 验收标准

- README 无任何冲突标记；文档结构完整（摘要→架构→构建→安全声明连贯）。

---

## 本批验证门（全部通过才进入 Wave 1）

1. `npx vue-tsc --noEmit` 0 错（verthys-tauri 目录）
2. `npx vitest run` 全绿
3. `npm run build` 成功
4. `cargo test --manifest-path verthys-tauri/src-tauri/Cargo.toml` 全绿
5. `cargo test --manifest-path verthys-tauri/verthys-worker/Cargo.toml` 全绿
6. `cargo clippy --all-targets -- -D warnings` 0 告警（两侧）
7. 手工验证三项：照片导出落盘；错误口令第 10 次锁定；worker 超时日志无口令明文
8. README Grep 无冲突标记

**git 纪律**：每项修复独立提交（FIX-0-1 ~ FIX-0-5 共 5 个提交）；提交信息描述"改了什么、为何"，不引用本文档编号；本批结束为稳定点。