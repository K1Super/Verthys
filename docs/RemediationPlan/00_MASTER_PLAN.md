# Verthys v2.6.1 全栈缺陷修复工程 — 总纲与实施路线图

> 本文档是 81 项缺陷修复工程的唯一入口与总纲。
> 上游输入：`docs/audits/` 下的全量审计报告与五个分片发现（P0×1 / P1×12 / P2×35 / P3×33）。
> 配套文档：本目录下的 `01`~`06` 号文档，每一批的实施细则见对应文档，测试与门控矩阵见 `06`。

---

## 一、工程定位与目标

### 1.1 修复目标（验收态定义）

| 维度 | 修复后应达到的状态 |
|---|---|
| 功能完整性 | 拾光模块导出照片 100% 可用（当前 P0 必现失败） |
| 安全强制点 | 暴力破解熔断由服务端（L3）强制，不依赖任何前端行为；失败计数跨进程存活 |
| 密钥卫生 | 口令/明文/子密钥在所有成功与失败路径零化，日志零秘密 |
| 数据完整性 | 存储引擎（WAL/SSTable/事务 delete）在越界、重试、崩溃三条路径上无静默损坏 |
| 可观测性 | 生产环境致命错误有后端落盘通道；日志分级脱敏有硬约束 |
| 工程可复现 | 本地构建与 CI 同环境、同依赖解析、同门控；锁文件稳定 |

### 1.2 缺陷资产总账（81 项 → 批次映射）

| 批次 | 范围 | 项数 | 说明 |
|---|---|---|---|
| Wave 0 | P0-1、P1-6、P1-7、P1-10、P1-11（+同模式 P2-23） | 6 | 止血：功能恢复 + 红线止血，只动 Rust/TS/文档 |
| Wave 1 | P1-1、P1-2、P1-3、P1-4、P1-5 | 5 | 存储完整性：C 核心事务/索引/WAL |
| Wave 2 | P1-8、P1-9、P1-12、P2-1~P2-5、P2-19、P2-20 + P3 零化类 | 16 | 密钥卫生：zeroize 纪律与密码学边界 |
| Wave 3 | P2-6~P2-18、P2-21、P2-22、P2-24~P2-27、P2-32、P2-35 + D/C 片部分 P3 | 27 | 纵深防御：L3/IPC 边界、防御层、存储边角 |
| Wave 4 | P2-28~P2-31、P2-33、P2-34 + E 片 P3、B 片 P3（性能类） | 12 | 平台工程：CI/构建/依赖/文档治理 |
| 持续项 | 其余 P3 卫生项 | ~15 | 按季度消化，具体清单见 05 号文档 |

> 注：P2 编号采用全量审计报告（VERTHYS_FULL_AUDIT_REPORT.md）的全局编号 P2-1~P2-35。

### 1.3 批次间依赖关系（决定执行顺序的唯一依据）

```
Wave 0（无前置）
   │
   ├──► Wave 1（P1-1 的 C 层侧依赖 Wave 0 的 L3 权威熔断落地后再定工艺；
   │            P1-2 扫描锁依赖 L3 worker 串行化结论，见前置任务 T0）
   │
   ├──► Wave 2（P1-12 pepper 策略与容器兼容性决策依赖现有容器盘点，见前置任务 T1）
   │
   ├──► Wave 3（P2-21 解锁态闸门依赖 Wave 0 的熔断接入点已就位）
   │
   └──► Wave 4（无依赖，可与 Wave 2/3 并行推进，但 CI 门控新增需在各 Wave 提交时同步）
```

**两个前置核查任务（先于对应 Wave 开工）**：
- **T0（Wave 1 前）**：核实 L3 worker 调度是否已串行化「扫描读」与「写事务」。若已串行化，P1-2 的 C 层加锁按"纵深防御"实施（不改优先级）；若未串行化，P1-2 升为 Wave 1 首项。核查方式：通读 `verthys-worker/src/runtime/dispatch.rs` 的命令调度结构（是否单线程 loop 消费 + 命令级互斥）。
- **T1（Wave 2 前）**：盘点存量 .verthys 容器是否可能存在 COMPILED 胡椒源（影响 P1-12 的禁用策略：硬禁用 vs 拒绝新建+解锁告警）。核查方式：`verthys_pepper.c` 中 COMPILED 源的产生与记录路径 + pepper V3 头字段能否区分来源。

---

## 二、修复方法论（本工程强制执行的八条原则）

1. **咽喉点强制**：所有安全决策（熔断、锁定、权限）在 L3 服务端强制执行，前端仅做展示。禁止"前端驱动、后端信任"的架构（P1-7 即反面教材，本工程将其反转）。
2. **写前防御**：资源上界（缓冲区、容量、计数、行长度）在消耗动作发生前校验，杜绝"写后检查"（P1-4 类）。这一原则适用于本工程所有修复点。
3. **错误路径与成功路径同权**：任何持有敏感缓冲的函数，所有 return 分支必须经过统一清理块；RAII/作用域守卫优先。禁止 `?` 提前返回跳过清理（P1-9 类）。
4. **日志双红线**：秘密不进日志（写入端脱敏）+ 致命错误必达日志（通道保活）。二者同时成立，缺一即缺陷。
5. **最小差异修复**：每项修复只改缺陷本身，不顺手重构、不扩功能；跨项共享的基础设施（如日志脱敏工具）提前单列，避免复制粘贴式修复。
6. **先测试后修复**：P1 级存储缺陷先落"失败复现测试"（故障注入/断言现状行为），再实施修复，最后让同一测试转绿。保证测试确实覆盖缺陷路径。
7. **注释纪律（项目硬约束）**：所有新增/修改的代码注释只写代码可验证的用途、行为、约束与设计意图；**严禁出现任何外部文档名称/路径、章节号、缺陷编号（P0-1 之类）及"见/参考/依据 XXX"式溯源表述**。本方案中的编号（FIX-x-y、P1-4 等）仅存在于工程文档，不得进入代码注释。
8. **可回滚交付**：每项修复 = 独立提交（或同批内可独立 revert 的提交序列），每批结束为可构建、可测试的稳定点。

---

## 三、批次总览与执行纪律

### 3.1 Wave 0 — 止血批（详情见 01 号文档）

| 条目 | 目标 | 层 |
|---|---|---|
| FIX-0-1 | 修复 `write_user_file` IPC 协议错配，恢复照片导出 | TS |
| FIX-0-2 | IPC 超时/解析失败日志脱敏（含 P2-23 同模式） | Rust |
| FIX-0-3 | `verthys_unlock` 服务端强制接入 BruteForceGuard | Rust |
| FIX-0-4 | 补注册 `log_fatal` 命令，恢复致命错误上报 | Rust |
| FIX-0-5 | 解决 README 合并冲突标记 | 文档 |

**本批额外发现（核验现场确认，超出原报告）**：全前端代码 Grep 证实**没有任何组件**调用 `security_brute_check/record_failure/record_success` 等五个熔断命令的封装函数——熔断机制当前处于完全静默状态（比"前端驱动"更严重）。FIX-0-3 的交割内容因此明确为：后端成为唯一权威计数方，前端相关封装保留但不再承担计数职责，UI 通过 `security_brute_check` 展示锁定态（若前端计划展示锁定提示，需在 FIX-0-3 内一并接入 `securityBruteCheck` 调用）。

### 3.2 Wave 1 — 存储完整性批（详情见 02 号文档）

| 条目 | 目标 | 层 |
|---|---|---|
| FIX-1-1 | SSTable 写入改为"写前预算"（P1-4） | C |
| FIX-1-2 | delete 重排为"先墓碑、后 ledger+release"（P1-5） | C |
| FIX-1-3 | WAL 换区先清零新区数据区（P1-3） | C |
| FIX-1-4 | 扫描游标接口加 SRW 共享锁（P1-2） | C |
| FIX-1-5 | C 层退避计数进程级聚合 + 机器级可选持久化设计（P1-1 C 侧） | C |

**本批纪律**：三项 P1 均为崩溃一致性路径，每项必须先落故障注入测试（复用 `core/tests/transaction/test_txn_recovery_inject.c` 的既有注入机制），评审要点是"行为等价性论证"——修复前后正常路径的落盘序列必须等价或严格更安全，且回滚/重放语义不得改变。

### 3.3 Wave 2 — 密钥卫生批（详情见 03 号文档）

| 条目 | 目标 | 层 |
|---|---|---|
| FIX-2-1 | `bin_password`/`req_str` 零化（P1-8） | Rust |
| FIX-2-2 | SHM 写失败路径统一零化（P1-9） | Rust |
| FIX-2-3 | COMPILED 兜底胡椒策略整改（P1-12，依赖 T1 结论） | C |
| FIX-2-4 | CNG import_key 失败路径清零调用方 key（P2-1）+ C 层 P3 零化项 | C |
| FIX-2-5 | AES-GCM provider 初始化加 once 保护（P2-2） | C |
| FIX-2-6 | rotate_mek 先临时槽 import 后切换（P2-3） | C |
| FIX-2-7 | size_t→ULONG 与长度加法溢出守卫（P2-5） | C |
| FIX-2-8 | SecuredString 手动实现 Debug（P2-19） | Rust |
| FIX-2-9 | GMK 派生中间量与子密钥零化（P2-20） | Rust |
| FIX-2-10 | 旧版 AEAD nonce 治理：下线或加计数器（P2-4） | C |

### 3.4 Wave 3 — 纵深防御批（详情见 04 号文档）

覆盖 P2-6~P2-18、P2-21、P2-22、P2-24~P2-27、P2-32、P2-35 及 D/C 片部分 P3。核心类是：
- L3/IPC 输入边界（max_count clamp、嵌入 NUL 路径、read_line 上限、SHM CSPRNG）
- FFI 边界安全（catch_unwind 全覆盖、panic hook）
- 服务端授权闸门（业务命令解锁态断言、死命令清理）
- 防御层语义修正（defense_closure、anti_inject 基线、Deinit 有限等待、integrity fail-open 改可观测）
- 存储边角（flush 后 memtable 重建失败、close dirty 语义、superblock 内容比对、warmcache 边界、解锁全段 HMAC 缓存）

### 3.5 Wave 4 — 平台工程批（详情见 05 号文档）

覆盖 P2-28~P2-31、P2-33、P2-34 与 E 片/B 片 P3 卫生项，主题：
- 依赖快照再生成与机制化（dep-versions.txt 由 CI 校验而不再人肉维护）
- 构建环境统一（本地 `env.load.ps1` 与 CI `ilammy/msvc-dev-cmd` 收敛为单一机制）
- 门控真接入（`ci/run_ci.ps1` AST 双引擎门、clang-tidy `WarningsAsErrors` 进入 PR 阻断 job）
- 锁文件纪律（本地 `npm ci`、移除 `cargo update -p keyboard-types`、`rust-toolchain.toml` 钉版）
- 文档治理（CONTRIBUTING 悬空引用与 CI 门描述、CSP 端口清理、README 已由 Wave 0 处理）

---

## 四、验证门（每批交割的硬性关卡）

| 批次 | 验证门（全部通过才视为批完成） |
|---|---|
| Wave 0 | `npx vue-tsc --noEmit` 0 错；`npx vitest run` 全绿；`npm run build` 通过；`cargo test`（src-tauri + worker）全绿；`cargo clippy --all-targets -D warnings` 0 告警；手工：Tauri 模式导出一张照片落盘成功；模拟 worker 不响应后日志文件 grep 无口令明文；连续错误口令第 10 次后端返回 Locked |
| Wave 1 | Ninja 构建通过；`verthys_tests.exe` 全绿（含新增注入测试）；5 个 fuzz 目标 smoke 门通过；新增测试对修复前代码是红的（反向验证留档） |
| Wave 2 | 同 Wave 0 的 Rust/TS 门 + C 测试全绿；对每条零化修复有对应内存/单测断言 |
| Wave 3 | 同上全部门 + 注入 mock 测试（CString NUL、超大 max_count、超长行）通过 |
| Wave 4 | 两个 workflow 在 PR 上全绿；故意提交一个违规 PR（AST 红线 / tidy 告警）验证 CI 变红后 revert |

每批完成时的 git 状态要求：`git status` 干净、Cargo.lock / package-lock.json 无意外变更（Wave 4 落地前由临时脚本检查）。

---

## 五、防回归体系（六层，与修复同步落地）

1. **单元层**：C 测试（`core/tests/**`）、Rust `#[cfg(test)]`、前端 vitest——每个 FIX 至少绑定一个断言。
2. **故障注入层**：`test_txn_recovery_inject.c` 扩展 WAL 换区 × 掉电、delete 重试、SSTable 越界三个场景。
3. **模糊层**：既有 5 fuzz 目标（superblock/partition/extent/sstable/import）保持 10 分钟/目标；SSTable 写前预算修复后回归 fuzz_sstable。
4. **静态层**：
   - clang-tidy `WarningsAsErrors`（Wave 4 接入 CI，UAF/越界类长期把关）；
   - `ci/run_ci.ps1` AST 双引擎红线门（Wave 4 接入 CI）；
   - 新增一条 grep 规则门：含 `Zeroizing`/`SecureZeroMemory`/`secure_zero` 的函数若存在未清理的提前 return，CI 变红（覆盖"错误路径零化"纪律的自动化）。
5. **契约层**：新增 IPC 契约一致性检查脚本——抽取 Rust `generate_handler!` 命令名与 TS `ipc<T>("...")` 字符串分别排序 diff，双向未命中即为死命令/幽灵命令（覆盖 P0-1、P1-10、P2-32 三类契约漂移的复发）。
6. **审计层**：`dep-versions.txt` 改由 CI 对照 `cargo tree` 自动再生成比对（Wave 4）。

---

## 六、风险与回滚

| 风险 | 缓解 |
|---|---|
| Wave 1 改崩溃一致性路径可能引入新回归 | 每项先落"修复前必红的注入测试"；正常路径等价性论证写入提交说明；批量合并前跑 5 目标 fuzz |
| COMPILED 胡椒禁用可能锁死存量容器 | T1 盘点先行；采用"拒绝新建 + 存量告警"而非一刀切拒绝解锁（结论取决于盘点结果） |
| 熔断接入后误锁正常用户 | 引入 BruteForceGuard 既有 jitter/速率限制语义；错误计数仅记 FFI 认证失败，不记 IO/通信类错误 |
| IPC 契约检查误报（命令名大小写/自动转换） | 脚本首版按"双向集合差 + 人工复核清单"落地，稳定后再收紧为硬门 |
| 各 Wave 并行交付引起合并面冲突 | Wave 4 可与 2/3 并行但 CI 门改动单独成批；每批基于上一批稳定点切分支 |

---

## 七、文档索引

| 文档 | 内容 |
|---|---|
| `01_WAVE0_CRITICAL.md` | Wave 0 五项止血的完整施行细则 |
| `02_WAVE1_STORAGE_INTEGRITY.md` | Wave 1 存储完整性修复细则（含行为等价性论证要点） |
| `03_WAVE2_SECRET_HYGIENE.md` | Wave 2 零化纪律与密码学边界细则 |
| `04_WAVE3_DEFENSE_DEPTH.md` | Wave 3 纵深防御细则（L3/IPC/防御层/存储边角） |
| `05_WAVE4_PLATFORM.md` | Wave 4 CI/构建/依赖/文档治理细则 + P3 卫生项清单 |
| `06_TEST_GATE_MATRIX.md` | 全缺陷→测试→CI 门的映射矩阵与验收清单 |

实施顺序：T0/T1 前置核查 → Wave 0 → Wave 1 → Wave 2 → Wave 3 → Wave 4 → 季度消化 P3。