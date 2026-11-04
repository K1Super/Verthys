# 开发夹具填充生产执行方案（手动配置版）

> 状态：已实施（自动化门禁通过；真实夹具手动验证待用户）
> 修订（2026-11-03）：移除 `--data-dir` / `.devfixture` 会话门，debug 构建即可用；删除 `scripts/dev/fixture.ps1`；容器与密钥文件路径不再限制在夹具根内；配置改存 `app_config_dir\devfixture\profile.bin`；页签与面板名称改为“填充”
> 需求基线：方便好用、便于测试、安全可靠、不进入生产、默认零参数零泄露、不过度设计
> 方案定级：轻量版——手动创建容器 + 手动配置 + 点击填充；不做自动创建、自动打开、自动提交、全量 provisioning、不强制独立 identifier
> 执行闸门：用户已确认按轻量版执行；本轮编码与测试已完成
> 适用范围：Verthys 桌面端开发期夹具填充工具；不改变生产解锁流程
> 方案目标：用户手动创建并初始化测试容器；在 DevDock 夹具面板手动填入容器路径、密钥与密钥文件路径；工具加密保存后用于自动填充当前表单；不自动创建、不自动打开、不自动提交

---

## 0. 执行闸门与纪律

| 闸门 | 条件 | 未满足时的动作 |
| --- | --- | --- |
| G0 方案评审 | 用户确认本方案与待决项 | 停止，不进入代码修改 |
| G1 基线采集 | 改动前类型检查、单测、构建、Rust 测试通过，或既有偏差已记录 | 停止，先修基线或记录 |
| G2 配置存储 | DPAPI 加密落盘；无明文密钥进入仓库、localStorage、日志 | 不进入填充接入 |
| G3 填充接入 | 当前表单全部因子可填；keyfile 字节真实加载；无自动提交 | 不进入 UI 完善 |
| G4 安全门禁 | 会话守卫、路径守卫、生产剔除全部通过 | 视为交付失败 |
| G5 验证门禁 | 构建、测试、关键路径、安全负例独立实测 | 不得声称完成 |

纪律：

- 未读不改：执行前复核所有改动点与表单状态引用。
- 先证后修：每个阶段先跑基线或静态证据。
- 最小改动：只改本方案列出的文件；不顺手重构、不批量格式化。
- 不硬编码任何测试密钥、容器路径或密钥文件路径；所有值由用户在夹具面板手动填入。
- 只填充，不自动提交、不自动打开、不自动创建。
- 不删除测试换通过；新增契约测试锁定安全边界。

---

## 1. 目标与验收判据

### 1.1 目标

1. 用户手动创建并初始化一个测试容器，工具不参与创建。
2. 用户在 DevDock 夹具面板手动填入测试参数，工具加密保存。
3. 点击填充后，当前打开的解锁/初始化/验证/模块密钥/恢复码表单立即填入全部可用因子。
4. 工具自身没有任何硬编码参数；所有参数来自用户手动输入。
5. 工具只在开发夹具会话可用，生产构建不存在。

### 1.2 可判定验收判据

| # | 判据 | 判定方式 |
| --- | --- | --- |
| A1 | 夹具配置可保存、读取、清空；重启后仍在 | 手动 + 单测 |
| A2 | 当前表单可一次填入容器路径、访问密钥、密钥口令、keyfile 路径 | 手动 + 组件测试 |
| A3 | keyfile 字节真实加载，不是只改文件名 | 单测 + 解锁验证 |
| A4 | 模块密钥弹窗、恢复码弹窗可填 | 组件测试 + 手动 |
| A5 | 不自动提交、不自动打开容器、不自动创建容器 | 源码扫描 + 负例测试 |
| A6 | 非夹具会话填充按钮禁用；真实路径被拒绝 | 负例测试 |
| A7 | 配置落盘为 DPAPI 密文；无明文密钥 | 文件检查 + 源码扫描 |
| A8 | 生产构建不含夹具面板与填充通道；配置命令在 release 调用必败 | 构建门禁 + 反向注入 + 发布检查 |
| A9 | 构建、测试、关键路径全部实测通过 | 第 7 节门禁矩阵 |

---

## 2. 范围与非目标

### 2.1 本期范围

- DevDock 增加“夹具”页签与配置表单。
- 用户手动填入：容器路径、访问密钥、密钥口令、全局密钥 .bin 文件路径、容器 .vkf 文件路径、模块密钥、恢复码。
- DPAPI 加密的本地夹具配置保存/读取/清空；显示密钥指纹与路径。
- 夹具会话守卫与路径守卫。
- 填充当前表单：`UnlockView` 容器路径、`InitKeyView`/`VerifyView` 全局密钥因子、`ModuleKeyDialog` 模块密钥、`RecoveryUnlockDialog` 恢复码。
- DEV-only 填充事件通道；产品表单内仅注册 DEV 分支监听。
- 测试、负例、生产剔除验证。

### 2.2 非目标

- 不自动创建测试容器、全局密钥、模块密钥、密钥文件或恢复码。
- 不自动打开容器、不自动点击解锁/初始化/验证。
- 不新增生产可用的免校验解锁接口。
- 不改变 `app_config_dir` 隔离策略；若要求审计/锁定状态绝对隔离，另立独立 identifier 方案。
- 不自动填充未打开的隐藏弹窗；只填当前可见表单，后续弹窗按需填充。
- 不导入业务文件、照片等测试数据；本期只处理容器与密钥因子。

---

## 3. 现状证据

| 事实 | 证据 |
| --- | --- |
| 容器路径与 keyfile 路径由解锁感知层持有 | `useUnlockFlow.ts:146`（`verthysPath`）、`:254`（`keyfilePath`）；`:330/:354/:376/:391` 把 keyfile 路径传入创建/解锁 |
| 全局密钥表单状态由核心密钥层持有 | `useGlobalKey.ts:170-173`（`initPassword` / `verifyPassword` / `binPassword` / `binFileName`） |
| keyfile 字节通过现有读取器加载 | `useGlobalKey.ts:87`（`readBinBytes`）、`:190`（`browseBin`）；底层 `lib/verthys.ts:1756` 的 `readUserFile` 做路径校验 |
| 初始化/验证视图绑定这些模型 | `InitKeyView.vue:39-67`、`VerifyView.vue:39-69`；`SecurityCenter.vue:38-55` 透传 |
| 解锁页只选容器路径，不输密钥 | `UnlockView.vue:47-82`；`@unlock` 交给 `SecurityCenter` |
| 模块密钥由导航组合层持有 | `useModuleNavigation.ts:177`（`moduleKeyInput`）；`ModuleKeyDialog.vue:23-31` 受控输入 |
| 恢复码是弹窗本地状态 | `RecoveryUnlockDialog.vue:53`（`code`） |
| DPAPI 工具已存在 | `util/crypto.rs:177`（`dpapi_protect`）、`:238`（`dpapi_unprotect`）；`Cargo.toml:142-154` 已启用 Cryptography |
| 敏感内存清零依赖已存在 | `Cargo.toml:182`（`zeroize`） |
| 最近容器路径与审计/锁定状态仍在真实 config | `verthys_state.rs:6-8/88`、`audit.rs:7/26`、`persistence.rs:28/36` |
| 数据目录可被 `--data-dir` 覆盖 | `lib.rs:242`；`app_paths.rs:21-22` 真实 identifier 常量 |
| DevDock 已 DEV-only 且生产剔除 | `App.vue:76-79`；`scripts/verify-devtools-excluded.mjs` |

---

## 4. 总体设计

### 4.1 三层结构

| 层 | 内容 | 禁止 |
| --- | --- | --- |
| 配置层 | Rust dev-only 夹具配置读写；DPAPI 加密；字段校验、路径守卫、指纹 | 明文落盘、日志、localStorage |
| 填充层 | DEV-only `verthys:devfixture-fill` 事件；各表单监听并写入自己的响应式状态 | 自动提交、自动打开、DOM 直接改 input |
| UI 层 | DevDock “夹具”页签；手动输入、保存、填充、清空、状态提示 | 硬编码测试参数、展示密钥明文 |

### 4.2 夹具会话守卫

- 必须同时满足：
  1. 当前 `AppPaths.data_dir` 由受信 `--data-dir` 指向 `<fixtureRoot>/data`；
  2. `<fixtureRoot>/.devfixture` 标记存在且 schema 有效；
  3. `data_dir` canonical 路径在 `fixtureRoot` 下；
  4. 当前构建为 debug（前端 `import.meta.env.DEV`、Rust `cfg!(debug_assertions)`）。
- 夹具根由标记文件确定：Rust 从 `data_dir.parent()` 推导，不读取环境变量路径、不猜仓库路径、不回落到真实数据目录。读取 `--data-dir` 是既有受信启动参数，标记文件是显式开发期 opt-in。
- 任一条件不满足：夹具状态为 `disabled`，填充、保存、清空按钮全部禁用并显示原因。
- 若 `app_config_dir` 仍是真实 `%APPDATA%\com.verthys.app`，状态中标记 `configShared: true` 并显示警告：
  - 测试解锁尝试可能写真实审计/锁定状态；
  - 按用户需求接受该残余风险；路径守卫保证不打开真实容器，且只填不提交降低触发概率；
  - 若后续不能接受该残余，再升级为独立 fixture identifier。
- 标记文件示例：`<fixtureRoot>/.devfixture`，内容含 `schemaVersion` 与 `createdAt`；缺失或损坏即 `disabled`。

### 4.3 路径守卫

- 允许的路径：容器路径、全局密钥 `.bin` 路径、容器 `.vkf` 路径必须：
  - 绝对路径；
  - canonical 后位于 `fixtureRoot` 下；
  - 普通文件，拒绝符号链接；
  - 扩展名分别符合 `.verthys` / `.bin` / `.vkf`。
- 拒绝：真实 `%LOCALAPPDATA%\com.verthys.app`、`%APPDATA%\com.verthys.app`、仓库源码目录、系统关键目录。
- 路径校验失败时，保存与填充均拒绝，不降级、不猜测。

### 4.4 夹具配置模型

```ts
interface DevFixtureProfile {
  schemaVersion: 1;
  updatedAt: string;
  containerPath: string;
  containerKeyfilePath: string;
  /** 初始化与验证沿用同一访问密钥，因此只保留一个字段 */
  globalPassword: string;
  binPassword: string;
  binKeyfilePath: string;
  moduleKeys: Record<string, string>;
  recoveryCode: string;
}
```

- 整体经 DPAPI 加密后写入 `<fixtureRoot>/profile.bin`；文件权限仅当前用户。
- DPAPI 密文绑定当前 Windows 用户；换用户或换机器无法解密，需要重新填入。
- 读取后只在内存使用；序列化与解密后的字节用 `zeroize` 清理。
- 密钥指纹由 Rust 在保存/读取时计算并返回，前端只展示，不自行散列；不显示密钥明文。
- 清空配置删除 `<fixtureRoot>/profile.bin`，并清零内存引用。
- 配置文件中不允许出现真实密钥；UI 明确标注“仅限一次性测试夹具”。

### 4.5 填充契约

```ts
type DevFixtureFillTarget =
  | "unlock-path"
  | "global-init"
  | "global-verify"
  | "module-key"
  | "recovery";

interface DevFixtureFillPayload {
  target: DevFixtureFillTarget;
  containerPath?: string;
  initPassword?: string;
  verifyPassword?: string;
  binPassword?: string;
  binKeyfilePath?: string;
  containerKeyfilePath?: string;
  moduleKey?: string;
  recoveryCode?: string;
}
```

- 事件名：`verthys:devfixture-fill`，仅当前窗口；DEV-only 监听。
- 每个表单只消费自己的 target：
  - `unlock-path`：`useUnlockFlow.verthysPath` / `keyfilePath`
  - `global-init` / `global-verify`：`useGlobalKey.initPassword` / `verifyPassword` / `binPassword` / `binFileName` / `binBytes`
  - `module-key`：`useModuleNavigation.moduleKeyInput`
  - `recovery`：`RecoveryUnlockDialog.code`
- **keyfile 字节**：`useGlobalKey` 增加 DEV-only `loadFixtureKeyfile(path)`，复用 `readBinBytes`（内部 `readUserFile` 校验）设置 `binBytes` 与 `binFileName`；禁止只设文件名。
- **容器 keyfile 路径**：`useUnlockFlow.keyfilePath` 直接设置；`doUnlock` 已把它传入 C 层。
- **创建模式**：若当前为新建流程，同时置位 `keyfileCreateEnabled` 并设置 `keyfilePath`；解锁模式只设置路径，不改变开关。
- **模块密钥**：仅在 `pendingModule` 存在且模块弹窗可见时写入 `moduleKeyInput`；不可见时不写。
- **不自动提交**：事件处理只赋值，不调用 `doUnlock` / `onInitKey` / `onVerify` / `confirm`。
- **不自动打开**：不调用 `openExisting` / `createNew` / `ensureSession`。
- **只填当前表单**：若目标表单未挂载，返回明确状态，不写入隐藏状态。
- **打包约束**：产品组件不得静态 import `devtools/fixture/*` 运行时模块；只允许在 `if (import.meta.env.DEV)` 内联事件名或动态 import，类型可用 `import type`。生产包不得出现 `verthys:devfixture-fill` 事件名、夹具组件或标记。
- 填充后显示 Toast 或夹具状态提示；密钥字段保持掩码。

### 4.6 UI 形态

- 四个分组卫星保持不变；控制台新增第五个“夹具”页签，不与四分组卫星绑定。
- 控制台新增 `activeTab: DevToolGroupId | "fixture"`：分组页签渲染工具组，夹具页签渲染 `FixturePanel`；四枚卫星仍只打开四个分组页签。
- 夹具页签内容：
  - 会话状态：enabled / disabled、夹具根、dataDir、configShared 警告
  - 表单：容器路径、访问密钥、密钥口令、`.bin` 路径、`.vkf` 路径、模块密钥（可折叠）、恢复码
  - 按钮：保存配置、填充当前表单、清空配置、重新检测
  - 只读展示：密钥指纹、更新时间、文件存在性
- 密钥输入默认 `type="password"`，可切换显示；不把明文写入 DOM 属性或日志。
- 非夹具会话：整个表单只读，按钮禁用，显示具体原因。

### 4.7 生产隔离

- 前端：`FixturePanel` 与填充通道只由 DevDock 引用；`DevDock` 仍由 `import.meta.env.DEV` 动态加载；生产构建剔除。
- Rust：配置命令入口加 `cfg!(debug_assertions)` 运行时拒绝；不复制整张 `generate_handler!` 表。
- 构建门禁：`verify-devtools-excluded.mjs` 继续扫描 `DevDock` / 标记；新增夹具组件不得进入生产产物。
- 禁止在 release 注册任何“夹具自动填充”入口。

---

## 5. 改动面清单

### 5.1 新增

| 文件 | 职责 | 预估 |
| --- | --- | --- |
| `src-tauri/src/devfixture/mod.rs` | 夹具模块入口、路径守卫、状态模型 | 80-120 行 |
| `src-tauri/src/devfixture/profile_store.rs` | DPAPI 加密读写、schema 校验、zeroize、清空 | 150-220 行 |
| `src-tauri/src/controller/devfixture_controller.rs` | `devfixture_status` / `save` / `get` / `clear` 命令；debug 拒绝 | 150-220 行 |
| `src/devtools/fixture/fill_bus.ts` | 填充事件常量、payload 类型、发布函数 | 30-50 行 |
| `src/devtools/fixture/FixturePanel.vue` | 夹具配置表单、状态、保存/填充/清空 | 200-300 行 |
| `src/devtools/fixture/profile_client.ts` | 调用 Rust 配置命令、指纹展示、错误归一 | 60-100 行 |
| 测试 | Rust 路径/加密测试；Vitest 填充契约测试 | 200-350 行 |

### 5.2 修改

| 文件 | 改动 | 预估 |
| --- | --- | --- |
| `src-tauri/src/lib.rs` | 注册夹具命令 | ~5 行 |
| `src-tauri/src/controller/mod.rs` | 模块声明 | ~2 行 |
| `src/composables/security-center/useGlobalKey.ts` | DEV-only 动态 import/内联事件监听；`loadFixtureKeyfile` 复用 `readBinBytes` | 50-80 行 |
| `src/composables/security-center/useUnlockFlow.ts` | DEV-only 动态 import/内联事件监听：设置 `verthysPath` / `keyfilePath`；创建模式同步 `keyfileCreateEnabled` | 30-50 行 |
| `src/composables/useModuleNavigation.ts` | DEV-only 动态 import/内联事件监听：仅在模块弹窗可见且存在 `pendingModule` 时设置 `moduleKeyInput` | 30-50 行 |
| `src/components/dialogs/RecoveryUnlockDialog.vue` | DEV-only 动态 import/内联事件监听：设置 `code` | 20-40 行 |
| `src/devtools/DevDock.vue` | 第五个“夹具”页签与 `FixturePanel` 挂载 | 80-120 行 |
| `src/devtools/devdock.css` | 夹具页签/表单样式，沿用现有控制台语言 | 60-100 行 |
| `docs` | 本方案与验证记录 | 100-200 行（非代码） |

---

## 6. 实施步骤

### Phase 0：基线（不改代码）

1. 复核第 3 节证据与当前行号。
2. 执行 `npx vue-tsc --noEmit`、`npx vitest run`、`npm run build`。
3. 执行 `cargo test --lib --quiet`、`cargo clippy --all-targets -- -D warnings`、`cargo check --release`。
4. 记录既有偏差；基线不绿则停止或记录。

### Phase 1：配置存储与状态

1. 新增 `devfixture` 模块与配置 schema。
2. 使用 `dpapi_protect` / `dpapi_unprotect` 加密落盘；读取后 `zeroize`。
3. 实现路径守卫与会话状态；非夹具会话返回 `disabled`。
4. 命令入口加 debug 拒绝；注册命令。
5. 单测：加密落盘、路径拒绝、schema 校验、清空。

### Phase 2：填充通道（全局密钥）

1. 新增 `fill_bus.ts`，定义事件与 payload。
2. `useGlobalKey` 增加 DEV-only 监听；`loadFixtureKeyfile` 复用 `readBinBytes`。
3. `useUnlockFlow` 增加 DEV-only 监听，设置 `verthysPath` / `keyfilePath`。
4. 只赋值，不调用解锁/初始化/验证函数。
5. 单测：payload target 过滤、keyfile 字节加载、不触发提交。

### Phase 3：模块密钥与恢复码

1. `useModuleNavigation` 增加 DEV-only 监听，设置 `moduleKeyInput`。
2. `RecoveryUnlockDialog` 增加 DEV-only 监听，设置 `code`。
3. 仅当目标弹窗可见时填充；不可见时不写入隐藏状态。
4. 单测：模块密钥填充、恢复码填充、不可见拒绝。

### Phase 4：夹具面板

1. 新增 `FixturePanel.vue` 与 `profile_client.ts`。
2. DevDock 控制台新增第五个“夹具”页签；四枚卫星保持不变。
3. 表单字段、掩码、指纹、状态、警告、保存/填充/清空。
4. 非夹具会话禁用并显示原因。
5. 手动验证：保存、重启、填充、清空。

### Phase 5：安全与生产门禁

1. 负例：真实路径、符号链接、仓库路径、系统目录全部拒绝。
2. 负例：非夹具会话填充/保存/清空全部拒绝。
3. 生产构建：确认夹具组件、事件、命令不在产物；反向注入验证。
4. 源码扫描：无明文密钥、无 `console.log(key)`、无 localStorage 存储。
5. 四视角自审。

### Phase 6：文档与全量复核

1. 更新本方案执行记录。
2. 执行第 7 节全部门禁。
3. 输出验证证据与未覆盖项。

---

## 7. 验证门禁矩阵

### 7.1 静态与测试

| 门 | 命令（工作目录） | 通过标准 |
| --- | --- | --- |
| 前端类型 | `npx vue-tsc --noEmit`（`verthys-tauri`） | exit 0 |
| 前端单测 | `npx vitest run`（`verthys-tauri`） | 零失败 |
| 生产构建 | `npm run build`（`verthys-tauri`） | exit 0；剔除门禁 PASS |
| 打包扫描 | 扫描 `dist` 中 `verthys:devfixture-fill` / 夹具组件 / 标记 | 零命中 |
| Rust 单测 | `cargo test --lib --quiet`（`src-tauri`） | 零失败 |
| Rust 静态 | `cargo clippy --all-targets -- -D warnings` | 零告警（既有偏差单独记录） |
| Rust 发布检查 | `cargo check --release` | exit 0 |
| 体系门禁 | `powershell -ExecutionPolicy Bypass -File ci\run_ci.ps1` | 与本方案相关项全绿 |

### 7.2 安全负例

| # | 操作 | 期望 |
| --- | --- | --- |
| N1 | 配置真实容器路径 | 保存/填充拒绝 |
| N2 | 配置夹具根外路径 | 保存/填充拒绝 |
| N3 | 配置符号链接 | 拒绝 |
| N4 | 非夹具会话点击填充 | 按钮禁用，命令拒绝 |
| N5 | 填充后不自动提交 | 无解锁/初始化/验证调用 |
| N6 | 生产构建搜索夹具标记/组件 | 零命中 |
| N7 | 保存后检查 profile 文件 | DPAPI 密文，无明文密钥 |
| N8 | 清空配置 | 文件删除，内存引用清空 |
| N9 | 缺失/伪造 `.devfixture` 标记 | 夹具状态 disabled，保存/填充拒绝 |

### 7.3 关键路径实测

| # | 操作 | 期望 |
| --- | --- | --- |
| M1 | 夹具会话保存配置并重启 | 配置仍在，状态显示 enabled |
| M2 | 解锁页点击填充 | 容器路径填入，未自动打开/解锁 |
| M3 | 初始化/验证页点击填充 | 访问密钥、密钥口令、keyfile 路径与字节填入 |
| M4 | 模块密钥弹窗点击填充 | 模块密钥填入 |
| M5 | 恢复码弹窗点击填充 | 恢复码填入 |
| M6 | 手动点击解锁/验证 | 使用夹具密钥正常走真实流程 |
| M7 | 清空配置 | 再次填充提示未配置 |
| M8 | 非夹具会话 | 夹具页签禁用并显示原因 |

---

## 8. 风险与对策

| # | 风险 | 等级 | 对策 |
| --- | --- | --- | --- |
| R1 | 配置明文泄露 | 高 | DPAPI 加密；不写 localStorage/日志；zeroize |
| R2 | 真实容器被填充 | 高 | 会话守卫 + 路径守卫 + 只填不提交 |
| R3 | 真实审计/锁定被污染 | 中高 | 本期残余：config 未隔离；状态中明确警告；后续独立 identifier |
| R4 | keyfile 只填文件名导致验证失败 | 中 | 复用 `readBinBytes` 加载字节；单测锁定 |
| R5 | 路径被沙箱/授权拒绝 | 中 | 复用 `readUserFile` 校验；必要时仅对夹具根加 DEV-only 授权，必须测试 |
| R6 | 自动提交/自动打开 | 高 | 事件处理只赋值；源码扫描 + 负例 |
| R7 | 生产泄漏 | 高影响 | DEV-only chunk + 生产门禁 + Rust debug 拒绝 + 产品组件禁止静态运行时 import 夹具模块 |
| R8 | 模块密钥/恢复码弹窗未打开时误填 | 中 | 只填当前可见表单；不可见返回明确状态 |
| R9 | 夹具配置被误提交 | 中 | 夹具根 gitignore；路径守卫拒绝仓库源码目录 |
| R10 | 设备/PCR 变化导致夹具失效 | 运营 | 手动重建夹具；不绕过校验 |

---

## 9. 回滚方案

| 场景 | 回滚动作 |
| --- | --- |
| 配置存储异常 | 回退 Phase 1；删除夹具配置文件 |
| 填充接入异常 | 回退 Phase 2/3；产品表单恢复原状 |
| UI 异常 | 回退 Phase 4；DevDock 恢复四页签 |
| 安全门禁失败 | 整批回退；不删除/放宽门禁 |
| 生产泄漏 | 整批回退并重新评审 |

回滚不涉及数据迁移、不删除真实容器、不改动生产解锁流程。

---

## 10. 人格合规自检

| 条款 | 方案落点 |
| --- | --- |
| 先读后判 | 第 3 节逐项证据；执行前复核行号 |
| 先证后修 | Phase 0 基线；G0 方案评审 |
| 最小改动 | 第 5 节文件清单；不做无关重构 |
| 证据说话 | 第 7 节门禁与负例 |
| 宁慢不错 | 未评审不写代码；路径守卫优先 |
| 安全底线 | 无硬编码密钥；DPAPI；不绕过校验；不碰真实容器 |
| 不可逆操作 | 无删除/迁移/部署；清空仅夹具配置 |
| 诚实 | 不删测试换通过；未实测项明确标注 |
| 验证门禁 | 构建、测试、关键路径独立执行 |
| 注释规范 | 新增注释只解释 Why；不写外部文档名/编号/链接 |

---

## 11. 待确认项与默认判断

| # | 待确认 | 默认判断 |
| --- | --- | --- |
| Q1 | 夹具根位置 | 已修订：不再要求夹具根；任意绝对路径均可配置，仅校验存在性、普通文件、非符号链接与扩展名 |
| Q2 | 配置存储 | DPAPI 加密 `app_config_dir\devfixture\profile.bin`；不使用 localStorage |
| Q3 | 是否做完整 `app_config_dir` 隔离 | 按用户需求不做；路径自由 + 只填不提交；不再显示 `configShared` 警告 |
| Q4 | 填充范围 | 分两阶段：阶段 1 全局解锁路径 + 访问密钥/密钥口令 + `.bin` / `.vkf`；阶段 2 模块密钥 + 恢复码。业务文件不在本期 |
| Q5 | 第五页签 vs 第五卫星 | 第五控制台页签“夹具”；四枚分组卫星保持不变 |
| Q6 | 自动填充开关 | 默认关闭；只做点击填充，不自动在表单打开时填充 |
| Q7 | 模块密钥存储 | 夹具配置中可选；默认全部模块可填，空值跳过 |
| Q8 | 是否自动提交 | 否；只填充，不触发解锁/初始化/验证 |

确认方式：以上默认全部采纳时回复“按默认执行”；任一调整请指明条目。

---

## 12. 交付物

1. 本方案文档。
2. 代码变更（已实施）。
3. 验证证据：命令输出、负例结果、手动操作记录。
4. 未覆盖项清单与原因。

## 13. 实施记录（本轮）

- 新增 Rust：`src-tauri/src/devfixture/mod.rs`、`src-tauri/src/controller/devfixture_controller.rs`。
- 注册命令：`devfixture_status` / `devfixture_profile_get` / `devfixture_profile_save` / `devfixture_profile_clear`。
- 新增前端：`src/devtools/fixture/profile_client.ts`、`fill_bus.ts`、`FixturePanel.vue`。
- DevDock 控制台新增第五页签“夹具”；四枚分组卫星保持不变。
- 表单接入：`useGlobalKey`、`useUnlockFlow`、`useModuleNavigation`、`RecoveryUnlockDialog`，均在 DEV 分支内监听，只赋值不提交。
- 新增启动脚本：`scripts/dev/fixture.ps1`，创建 `build_dev/devfixture/.devfixture` 并以独立 `--data-dir` 启动。
- 生产剔除门禁扩展：扫描 `verthys:devfixture-fill`、`FixturePanel`、`fixture-panel`。
- 验证：`vue-tsc` 通过；`vitest` 70 文件 / 759 例通过；`cargo test --lib` 566 通过 / 2 忽略；`npm run build` 通过且 `[devtools-exclusion] PASS`；`cargo check --release` 通过。
- 未覆盖：真实 Tauri 夹具会话中的手动创建容器、`.bin` / `.vkf` 填充与保存重启流程需用户按第 9 节手动验证；`configShared` 残余风险按用户需求接受。

### 2026-11-03 修订记录

- 删除会话门：移除对 `--data-dir`、`.devfixture` 标记、`data_dir.parent()` 推导的依赖；只保留 Rust `cfg!(debug_assertions)` 与前端 DEV 入口。
- 删除启动脚本 `scripts/dev/fixture.ps1` 及空目录 `scripts/dev`；改用现有 `build_dev.ps1` 正常启动即可。
- 配置存储改为 `app_config_dir\devfixture\profile.bin`，仍为 DPAPI 密文，保存后清零明文。
- 路径校验改为任意绝对路径：仅要求存在、普通文件、非符号链接、扩展名匹配；移除“必须位于夹具根内”的限制。
- 面板改为“填充”页签，按容器 / 全局密钥 / 模块密钥 / 恢复码分组；三个路径字段提供“选择”“清除”，留空项跳过填充。
- 验证：`vue-tsc` 通过；`vitest` 相关 2 文件 / 7 例通过；`cargo test --lib devfixture` 1 例通过；`npm run build` 通过且 `[devtools-exclusion] PASS`。
- 未覆盖：`build_dev.ps1` 正常启动后的 UI 手动填充验证由用户执行。
