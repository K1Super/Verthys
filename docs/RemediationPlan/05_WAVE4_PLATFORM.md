# Wave 4 — 平台工程批施行细则

> 目标：使构建/CI/依赖/文档达到「本地与 CI 同环境、同解析、同门控」的可复现标准；消化剩余 P3 卫生项。
> 范围：`.github/workflows/`、`ci/`、`scripts/`、`build_dev.ps1`、`build_production.ps1`、`dep-versions.txt`、`.clang-tidy`、`tauri.conf.json`、`CONTRIBUTING.md`、`vite.config.ts`。
> 前置：无硬依赖，可与 Wave 2/3 并行；但 CI 门控的新增步骤需在各 Wave 的 PR 上同步生效（先行合入本批的 workflow 改动）。编号（P2-x、P3、FIX-x-y）只存在于本文档，**不得进入代码注释**。

---

## A. 依赖与构建可复现

### FIX-4-1 dep-versions.txt 再生成 + CI 机制化（P2-28）

- 现状：`dep-versions.txt:561` 记 `serde_json 1.0.150`，Cargo.lock 实际 `1.0.151`（Cargo.toml 钉 `=1.0.151`）——人工快照已漂移。
- 修复：
  1. 以 `cargo tree`（对应两个 Cargo 工程）+ `npm ls` 实际值重新生成快照；生成脚本落 `ci/refresh_dep_versions.ps1`（幂等）。
  2. CI 增加比对 job：快照与 lockfile 不一致即红（core.yml 或独立 workflow），此后依赖升级必须同时更新快照。
  3. 快照文件头部注明"由脚本生成，勿手改"。
- 测试：故意改坏一行，CI 该 job 变红（验证后还原）。
- 验收：快照与实际一致；CI 门有效。

### FIX-4-2 MSVC 环境注入机制统一（P2-29）

- 现状：本地 `build_*.ps1` dot-source `scripts/env.load.ps1` 强制 4 个自定义 env（缺失 fail-fast）；CI 用 `ilammy/msvc-dev-cmd@v1`——两套机制互不相通，CI 绿 ≠ 本地脚本通。
- 修复（收敛方向：**一切以 CI 机制为准，本地脚本兼容运行**）：
  1. 本地脚本改为**先探测** `ilammy/msvc-dev-cmd` 注入的既有环境（VCToolsInstallDir/INCLUDE/LIB/PATH 已就绪则直接沿用），缺失时才 fallback 到 `env.load.ps1`；彻底移除"4 个自定义 env 缺失即 throw"的硬性前置。
  2. CI 增加「本地脚本路径验证」job：在 runner 上直接跑 `build_production.ps1 -SkipTauri -NoPause`（覆盖"本地一键脚本可在干净环境跑通"的诉求）。
  3. README/构建文档写明新探测顺序。
- 验收：干净 runner 上本地脚本直接可跑（CI 验证 job 绿）；env.load.ps1 降级为可选增强。

### FIX-4-3 AST 双引擎红线门接入 CI（P2-30）

- 现状：`ci/run_ci.ps1`（regex_scan + ast_analyze 双引擎）未被任何 workflow 调用；`CONTRIBUTING.md:53-57` 声称其为"CI 静态校验第一级+第二级"。
- 修复：core.yml 增加 step `pwsh: ci\run_ci.ps1 -Level2Only`（或按现有 run_ci 参数拆分 Level1/Level2 到独立 job；先修 `run_ci.ps1` 使其在纯 runner 上可自举编译 ast_analyze 工具，消除本地依赖）。
- 测试：提一个含红线违规（如 UAF 模式）的临时 PR，断言 CI 红；还原。
- 验收：PR 门生效；CONTRIBUTING 表述与实际一致。

### FIX-4-4 clang-tidy 启用（P2-31）

- 现状：`.clang-tidy` 已配 `WarningsAsErrors`（UAF/StackAddressEscape/Malloc）但 CI 从不启用；示例路径 `build_ninja` 与实际 `build_ci` 不符。
- 修复：
  1. core.yml 配置步骤加 `-DVERTHYS_ENABLE_CLANG_TIDY=ON`（或独立 job，避免拖慢主构建——优先独立 job，复用 C 缓存）。
  2. 修正 `.clang-tidy` 注释路径 `build_ninja` → `build_ci`。
  3. 首次启用会产生存量告警——以"新增代码零告警"为基线过渡（存量告警清单入豁免表，限期清理），避免一次性爆炸。
- 验收：故意引入一个 tidy 可检告警的 PR 变红；存量豁免表留档。

### FIX-4-5 npm 依赖解析统一 `npm ci`（P2-33）

- 现状：`build_dev.ps1:126`、`build_production.ps1:178` 用 `npm install`（可漂移），CI 用 `npm ci`。
- 修复：本地两脚本改 `npm ci`（首次全量安装耗时增加可接受；文档说明 `npm install` 仅用于主动升级依赖的显式场景）。
- 验收：本地删除 node_modules 后跑脚本，安装版本与 package-lock 完全一致（`npm ls` 无 extraneous）。

### FIX-4-6 移除构建期 `cargo update`（P2-34）

- 现状：`build_dev.ps1:152`、`build_production.ps1:215` 每次执行 `cargo update -p keyboard-types` 改写 Cargo.lock。
- 修复：替换为 `cargo metadata --no-deps`（或 `cargo check --offline` 前置）验证 `[patch]` 生效，不再写 lock；锁文件纳入 CI 比对（`git diff --exit-code -- Cargo.lock Cargo.lock`）。
- 验收：跑一次构建脚本后 `git status` 无 Cargo.lock 变更。

### FIX-4-7 Rust 工具链钉版（P3 → 上升为本批必修）

- 现状：`rust-frontend.yml:37` `dtolnay/rust-toolchain@stable` 浮动版本。
- 修复：仓库根新增 `rust-toolchain.toml` 钉具体版本（含 components: clippy, rustfmt）；workflow 改 `@stable` 依赖 toolchain 文件的注释说明（dtolnay action 会读取 rust-toolchain.toml；或 action 参数指定版本，二选一并保持本地 CI 一致）。
- 验收：runner 上 `rustc --version` 与本地一致。

### FIX-4-8 CI Node 与 @types/node 对齐（P3）

- 现状：CI Node 22 vs devDependencies `@types/node ^26.0.1`。
- 修复：二选一——CI `node-version` 升到与 @types/node 匹配的版本，或 @types/node 降到 Node 22 大版本；以「CI 与本地 `node --version` 一致」为验收；优先升 CI 与本地开发环境（改动面小、向前兼容）。
- 验收：vue-tsc 在双端同版本 Node 下通过。

---

## B. 文档与配置治理

### FIX-4-9 CONTRIBUTING.md 修正（P3 ×2）

- 修复：删除悬空 `vcpkg.json` 引用（`:68`，改为 Cargo.toml/package.json/dep-versions.txt 三个真实来源）；PR 门描述（`:24`）补 `rust-frontend.yml`。
- 验收：Grep 文档无 vcpkg 字样；门描述覆盖两个 workflow。

### FIX-4-10 CSP 移除未使用端口（P3）

- 修复：`tauri.conf.json:29` `connect-src` 删除 `http://127.0.0.1:7778 http://localhost:7778`（全仓已核验该端口无任何连接代码）。
- 验收：CSP 审查无业务依赖残留；构建通过。

### FIX-4-11 生产混淆与致命错误通道复核（P1-10 遗留收尾）

- 现状：`vite.config.ts:33` `disableConsoleOutput: true` 使 IPC 失败时的 `console.error` 兜底被吞（Wave 0 的 FIX-0-4 已恢复主通道，此为次级缺口）。
- 修复决策：保持生产 console 关闭；在 `error-handler.ts` 的 `.catch()` 分支增加肉眼不可见的最终手段（如保留一次 console.error 仅限 FATAL-IPC-FAIL 场景并在混淆器配置中对该函数做不混淆/不去 console 标记——若混淆器不支持粒度控制，则文档记录"主通道失败时静默"为已知残余风险并归档产品决策）。实施时若混淆器可配置 allowlist，优先粒度方案。
- 验收：主通道（log_fatal）已验证可达；次级兜底策略留档。

---

## C. 剩余 P3 卫生项清单（本批或季度消化）

### C 核心（A 片剩余）

| 位置 | 项 | 要点 |
|---|---|---|
| `verthys_crypto.c:112` | 长度加法溢出守卫 | `pw_len > SIZE_MAX - VERTHYS_KEY_BYTES` 前置 |
| `secure_allocator.c:331-341` | free 未校 magic | 补 magic 校验或修头注释（与文档口径一致） |
| `secure_allocator.c:216/333` | destroy/free 记账口径不一 | 统一"清零+解锁成功即 unaccount，VirtualFree 失败仅记诊断" |
| `verthys_rekey_auto.c:198-200/370-403` | 栈上 wrapped 子密钥未清零 | 统一 secure_zero（与 FIX-2-4 同批模式，此处收尾） |
| `verthys_pepper.c:49-53` | 全局 pepper 无锁 | 文档明确 MT 纪律或加可读保护（与 g_pepper 生命周期一并审查） |
| `verthys_pepper.c:391-394` | 硬件绑定失败静默全零 label | 失败上升为来源错误而非零 label |
| `memory_guard.c:94-100` | 双重检查锁非原子 | InitializeOnce / 编译期初始化 |
| `memory_guard.c:541-545` | 巡逻定时器重排未收句柄 | 重排前 DeleteTimerQueueTimer 旧句柄 |
| `verthys_crypto.c:17-21` | random_bytes 无返回值 | 文档约定默认 RNG 失败即 abort，或改返回 int |

### C 核心（B 片剩余）

| 位置 | 项 | 要点 |
|---|---|---|
| `verthys_wal.c:724-752` | wal_reset 每提交全量 960KB 清零 | 只清 active 半区数据区（与 FIX-1-3 机制复用） |
| `verthys_partition.c:258-271` | grow 只更内存 size | 断言末分区或显式截断 |
| `verthys_lsm.c:1792` | scan_next 死变量 | 删除或真正用于 tie-break |
| `verthys_format.c:752-756` | name_len 无业务上限 | 加业务上限（如 4096） |

### C 核心（C 片剩余）

| 位置 | 项 | 要点 |
|---|---|---|
| `verthys_api_utils.c:42` | backoff 读不持锁 | 随 FIX-1-5 的原子化一并收敛（已并入） |
| `verthys_progress.c:116-126` | 环形缓冲 tail 竞争 | 单一消费者推进 tail，满时只丢 head |
| `anti_inject.c:107-113` | TEB 偏移硬编码 | Wave 3 F 表已列，此处归档 |
| `emergency.c:39/96` | 看门狗事件名 | Wave 3 F 表已列 |
| `anti_debug_v2.c` | 硬件断点监控声明 | Wave 3 F 表已列（注释修正） |
| `dllmain.c` DETACH | 加载器锁内 shutdown | 核查后注释固化（Wave 3 F 表已列） |

### Rust 层（D 片剩余）

- `crypto.rs:64` expect、`shared_memory.rs` 边界/`let _`、`dispatch.rs` 100k 上界——已并入 Wave 3 F 表。

### 前端/CI（E 片剩余）

- 全部已由本批 A/B 节覆盖（工具链、Node、CONTRIBUTING、CSP、dep-versions）。

---

## 本批验证门

1. 两个 workflow 全绿（含新增的本地脚本验证 job、AST 门、clang-tidy、dep-versions 比对、lock 比对）
2. 反向验证：违规 PR（AST 红线 / tidy 告警 / 快照漂移）逐一使 CI 变红后还原
3. 本地「干净环境模拟」：删除 build 产物与 node_modules 后 `build_production.ps1` 与 `build_dev.ps1` 各跑通一次
4. `git status` 干净；Cargo.lock/package-lock 零意外变更
5. 文档 Grep：无 vcpkg、无 7778、无冲突标记、无过期 CI 描述

**git 纪律**：workflow/脚本改动单独成批 PR；每个 CI 门先以"验证它确实能红"的方式合入（违规样本临时提交 → 红 → 还原 → 门保留）。