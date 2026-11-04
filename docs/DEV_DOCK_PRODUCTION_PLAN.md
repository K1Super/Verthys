# 开发悬浮球生产执行方案

> 状态：已执行（待验收）
> 执行闸门：用户已确认“按默认执行”；本轮已完成 Phase 0-5，Phase 6 验收记录见第 13 节
> 适用范围：Verthys 桌面端前端；涉及两条既有日志导出命令的发布态门禁
> 方案目标：用户界面零入口；开发期通过 DEV-only 悬浮球统一调用；生产构建强制剔除，发布态不可调用

---

## 0. 执行闸门与纪律

| 闸门 | 条件 | 未满足时的动作 |
| --- | --- | --- |
| G0 方案评审 | 用户确认本方案全部条目与待决项 | 停止，不进入任何代码修改 |
| G1 基线采集 | 改动前跑通现有类型检查、单测、构建、Rust 测试 | 停止，先修基线或记录偏差 |
| G2 业务界面入口移除 | 中枢与更新弹窗的导出入口、文案、事件链全部清除，静态扫描为零 | 不进入开发悬浮球实现 |
| G3 开发悬浮球 | DEV-only 挂载；拖拽、面板、工具注册表、工具动作全部可用 | 不进入发布门禁 |
| G4 发布隔离 | 生产构建不含悬浮球代码；两条导出命令在发布态拒绝执行 | 视为交付失败，整批回退 |
| G5 验证门禁 | 构建、测试、关键路径三项独立实测通过 | 不得声称完成 |

纪律：

- 未读不改：执行前复核所有改动点的当前行号与调用链，行号漂移以文件内容为准。
- 先证后修：每个阶段先跑基线或静态证据，再动手。
- 最小改动：只改本方案列出的文件；不顺手重构、不批量格式化、不动无关文案。
- 一次一个关注点：用户入口移除与开发悬浮球分阶段提交，任一阶段可独立回退。
- 不删测试换通过：只移除因契约变更失效的夹具，新增契约测试锁定新行为。
- 发布隔离优先：任何“开发期方便”的实现，只要可能泄漏到发布包，一律否决。

---

## 1. 目标与验收判据

### 1.1 目标

1. 删除所有面向用户的日志/诊断导出入口。
2. 新增一个仅开发构建可见、可拖拽吸附的悬浮球，作为开发工具统一入口。
3. 悬浮球与全部工具在生产构建中不存在；发布态看不到入口，直接调用导出命令也会被拒绝。
4. 开发工具复用现有能力，不新增业务接口、不接触解锁/密钥/容器数据。

### 1.2 可判定验收判据

| # | 判据 | 判定方式 |
| --- | --- | --- |
| A1 | 用户界面不存在“日志/诊断导出”按钮 | 源码扫描 + 组件契约测试 |
| A2 | 用户文案不再提示“导出日志” | 源码扫描为零 |
| A3 | 开发构建悬浮球可见、可拖拽、可吸附、位置持久化 | 手动操作清单 |
| A4 | 面板内全部工具可用，错误路径有提示 | 手动操作清单 |
| A5 | 生产构建不含悬浮球组件、标记、chunk | 构建门禁脚本 + 反向注入验证 |
| A6 | 发布态两条导出命令拒绝执行 | 命令内 `cfg!(debug_assertions)` 门 + 发布构建 |
| A7 | 构建、测试、关键路径全部实测通过 | 第 7 节门禁矩阵 |

---

## 2. 范围与非目标

### 2.1 本期范围

- 移除中枢顶栏、更新说明弹窗、更新修复弹窗中的日志/诊断导出入口。
- 移除对应的 props、emits、处理函数、导入与死代码。
- 更新受影响的用户指引文案。
- 新增 DEV-only 悬浮球、拖拽/吸附、面板、工具注册表、首批工具。
- 为两条既有导出命令增加发布态拒绝门。
- 增加生产构建剔除门禁脚本与组件契约测试。

### 2.2 非目标

- 不新增“打开日志目录”“模块直达”“IPC 命令台”“缓存清理”等需要新后端接口或跨组件编排的能力，留待后续单独评审。
- 不改造 `updater/native.rs` 的系统恢复对话框（“打开更新日志并退出”）；它属于启动失败兜底，不是中枢导出入口。若要求用户侧完全无日志访问路径，需单独立项评审。
- 不改造日志导出本身的脱敏、打包、审计链逻辑。
- 不调整中枢布局、视觉主题、模块导航。
- 不引入新的第三方依赖。
- 不做通用插件系统，悬浮球只承载登记在案的工具。

---

## 3. 现状证据

以下为撰写时点的事实，执行前逐项复核：

| 事实 | 证据 |
| --- | --- |
| 中枢顶栏存在日志/诊断图标入口 | `verthys-tauri/src/components/management/ManagementTopBar.vue:79-102`；`updateFailed` prop `:149-150`；emits `:165-168` |
| 事件经管理视图透传 | `verthys-tauri/src/components/views/ManagementView.vue:83, 88-89, 204, 291-293` |
| 安全中心承接导出 | `verthys-tauri/src/components/modules/SecurityCenter.vue:84-86, 264, 326, 792, 850-869` |
| 更新说明弹窗有导出按钮 | `verthys-tauri/src/components/dialogs/UpdaterAvailableDialog.vue:37, 83` |
| 更新修复弹窗有导出按钮 | `verthys-tauri/src/components/dialogs/UpdaterRepairDialog.vue:33, 60` |
| 应用根组件另有修复日志入口 | `verthys-tauri/src/App.vue:51-56, 109, 182, 186-194` |
| 指引文案提示导出日志 | `verthys-tauri/src/lib/updater_error.ts:57, 62, 127, 132, 137, 147, 157, 167, 197, 209` |
| 启动修复系统对话框另有“打开更新日志”入口 | `verthys-tauri/src-tauri/src/updater/native.rs:21-102`（不在本期范围） |
| 两条导出命令注册 | `verthys-tauri/src-tauri/src/lib.rs:653-655` |
| 诊断导出命令实现 | `verthys-tauri/src-tauri/src/controller/diag_controller.rs:31-55` |
| 更新日志导出命令实现 | `verthys-tauri/src-tauri/src/updater/mod.rs:1443-1447` |
| 前端 DEV 判定已有先例 | `verthys-tauri/src/app/feature-flags.ts:92`；`verthys-tauri/src/composables/useSecurityGuard.ts:13-14` |
| 全局层级权威源 | `verthys-tauri/src/styles/tokens.css:84-96` |
| 帧指标快照已存在 | `verthys-tauri/src/core/frame-budget.ts:284-309` |
| 漂浮运动学纯函数已存在 | `verthys-tauri/src/composables/key-tools/floating_physics.ts:44-115` |
| 生产构建已启混淆 | `verthys-tauri/vite.config.ts:17-59` |
| 构建脚本串联前端构建 | `verthys-tauri/package.json:6-11`；`verthys-tauri/src-tauri/tauri.conf.json:6-10` |
| CI 已执行前端生产构建 | `.github/workflows/rust-frontend.yml:183-202` |

---

## 4. 总体设计

### 4.1 三层隔离模型

| 层 | 机制 | 作用 | 验证 |
| --- | --- | --- | --- |
| 构建层 | `import.meta.env.DEV` 条件 + 动态 `import()` | 生产构建静态剔除悬浮球模块与其依赖的 devtools 代码 | 构建产物扫描 |
| 运行层 | 悬浮球只在 DEV 分支挂载；无全局快捷键兜底 | 发布态不存在入口 | 源码审查 + 产物扫描 |
| 命令层 | 两条导出命令入口增加 `cfg!(debug_assertions)` 拒绝门 | 即使 IPC 被直接调用也失败 | 静态扫描 + 发布构建 |

说明：

- 不在 `generate_handler!` 列表中做条件注册。该宏的条目条件编译行为未在本仓库验证，且复制整张命令表会引入巨大重复与漂移风险。采用命令内运行时门，语义确定、改动最小。
- 发布构建使用 release profile，`cfg!(debug_assertions)` 为 false；开发构建为 true。开发期悬浮球正常导出，发布态命令返回错误。
- 不新增任何开发专用后端命令，避免扩大发布态 IPC 面。
- 开发入口的判定维度是 Vite 构建模式，不是 Rust profile：`build_dev.ps1` 走 `npx tauri dev`（Vite dev，DEV=true），悬浮球可见；`npm run build` 生成的 `dist` 永远不含悬浮球，即使随后用 debug Rust 运行也不可见。该组合属于预期隔离，不作为缺陷。

### 4.2 组件拓扑

```
App.vue
  └─ DevDock（仅 import.meta.env.DEV 时动态加载）
       ├─ Orb：拖拽 / 边缘吸附 / 位置持久化 / 点击展开
       ├─ Panel：分组渲染工具注册表 / 点外关闭 / Esc 关闭
       └─ Registry
            ├─ logs：导出诊断日志、导出更新日志
            ├─ runtime：帧指标、空闲档位、复制快照
            ├─ environment：版本、模式、运行环境
            └─ actions：重载界面
```

依赖方向：`DevDock → Registry → tools → 现有 lib/composables`。工具模块不得反向依赖组件；注册表不得直接访问 DOM。

`floating_physics.ts` 是无状态纯函数，跨功能目录复用不构成运行时耦合；本期不迁移目录，避免扩大改动面。

### 4.3 文件布局

新增：

```
verthys-tauri/src/devtools/
  DevDock.vue
  orb_geometry.ts
  useOrbDrag.ts
  registry.ts
  marker.ts
  tools/
    logs.ts
    runtime.ts
    environment.ts
  orb_geometry.spec.ts
  registry.spec.ts
verthys-tauri/scripts/verify-devtools-excluded.mjs
```

修改：

```
verthys-tauri/src/App.vue
verthys-tauri/src/components/management/ManagementTopBar.vue
verthys-tauri/src/components/views/ManagementView.vue
verthys-tauri/src/components/modules/SecurityCenter.vue
verthys-tauri/src/components/dialogs/UpdaterAvailableDialog.vue
verthys-tauri/src/components/dialogs/UpdaterRepairDialog.vue
verthys-tauri/src/lib/updater_error.ts
verthys-tauri/src/components/management/ManagementTopBar.spec.ts
verthys-tauri/src/components/dialogs/UpdaterAvailableDialog.spec.ts
verthys-tauri/src/styles/tokens.css
verthys-tauri/package.json
verthys-tauri/src-tauri/src/controller/diag_controller.rs
verthys-tauri/src-tauri/src/updater/mod.rs
```

### 4.4 悬浮球规格

| 项 | 规格 |
| --- | --- |
| 尺寸 | 主球 56 × 56 px；分组卫星 44 × 44 px |
| 默认位置 | 右下角，右 20 px、底 20 px |
| 安全边距 | 顶部 48 px（避开窗控拖拽区），左右与底部 16 px |
| 拖拽 | Pointer Events + `setPointerCapture`，仅球体接收指针 |
| 点击判定 | 位移 ≤ 6 px 视为点击；超过则进入拖拽，不触发展开 |
| 吸附 | 松手后吸附到最近的左/右边缘；使用现有 `stepSpring` 收敛 |
| 悬浮交互 | 悬浮/聚焦主球时沿“朝向视口中心”的扇区展开四枚分组卫星；移出 140 ms 后收拢 |
| 卫星快捷 | 四枚卫星分别对应日志、运行时、环境、动作分组；点击后按分组定位控制台 |
| 主球动效 | 外环离散弧对准扇区角度、内环落位、四向刻度点亮；按压 0.94 缩放，无波纹与光晕 |
| 无障碍 | 原生 `button`，`aria-expanded`、`aria-controls`、Enter/Space 展开、Esc 关闭；卫星使用 inert 管理隐藏态 |
| 减弱动效 | `prefers-reduced-motion` 下取消弹簧、扇区展开与面板入场动画，直接落位 |
| 持久化 | 键 `Verthys:devtools:orb`；仅接受有限数值，损坏输入回落默认 |
| 视觉 | 引力刻度锚点 + 四枚分组卫星 + 机械控制台；只用细描边、离散刻度与色相变化，无阴影、无发光、无渐变堆积 |
| 层级 | 新增令牌 `--z-devtools: 10020`；高于 10000 级弹窗与 9999 Cosmic 遮罩，低于窗控 10050 与 Toast 100000 |
| 生命周期 | 拖拽期间才启动 rAF；面板关闭后无持续定时器；卸载移除全部监听 |

### 4.5 面板规格

| 项 | 规格 |
| --- | --- |
| 锚定 | 依据球在左/右半屏决定面板向左/右展开；垂直方向夹在安全边距内 |
| 尺寸 | 宽 `min(340px, calc(100vw - 32px))`，高 `min(72vh, 600px)`，内部滚动 |
| 结构 | 机械控制台：编号标题栏 + 四分组跳转轨 + 分组刻度头 + 工具刻度行 + 构建页脚 |
| 关闭 | 点面板外、Esc、再次点击球；点外判定排除球体与面板，监听在打开后的下一帧注册；Esc 在捕获阶段处理并阻止传播，避免同时关闭底层弹窗 |
| 焦点 | 打开时按目标分组聚焦首个动作；关闭时焦点回到球；非模态，不设遮罩 |
| 分组 | 日志与诊断 / 运行时观测 / 环境信息 / 界面动作；跳转轨与滚动位置同步 |
| 工具行 | 左侧序号刻度 + 标签/说明/读数 + 右侧机械键；执行中禁用并显示进行态；info 工具读数每秒刷新 |
| 动效 | 面板裁切入场、分组行错峰落位、工具刻度悬浮延展；无阴影、无发光、无水波纹 |
| 错误 | 统一走现有 Toast 中心；取消保存对话框不提示 |

### 4.6 首批工具

| id | 分组 | 类型 | 行为 | 依赖 | 失败行为 |
| --- | --- | --- | --- | --- | --- |
| `logs.diagnostics` | 日志与诊断 | action | 导出脱敏诊断日志 | `lib/diagnostic_logs.ts` 的 `exportAppLogs` | 非 Tauri 提示；取消静默；错误 Toast |
| `logs.updater` | 日志与诊断 | action | 导出更新事件日志 | `useAppUpdater().exportLogs` | 非 Tauri 提示；取消静默；错误 Toast |
| `runtime.metrics` | 运行时观测 | info | 展示 P50/P95/P99、档位、样本数、draw call、空闲档位 | `frameBudgetMonitor.getMetrics()`；`useGlobalIdleScheduler().level` | 读取异常显示“不可用” |
| `runtime.flags` | 运行时观测 | info | 展示 `perfFlags`；复制 JSON；清除覆盖并重载 | `app/feature-flags.ts` | 清除失败 Toast |
| `runtime.snapshot` | 运行时观测 | action | 将环境 + 指标 + flags 拼成文本写入剪贴板 | `navigator.clipboard` | 权限失败 Toast |
| `environment.info` | 环境信息 | info | 展示版本、构建模式、UA、DPR、视口、是否 Tauri | `import.meta.env`、`isTauri()` | 无 |
| `actions.reload` | 界面动作 | action | 二次确认后重载界面 | `location.reload()` | 无 |

约束：

- 指标轮询仅在面板展开时以 1 s 周期执行，关闭即清理；禁止常驻 rAF。
- `frameBudgetMonitor` 仅在空闲档位 `active` 采样，面板同时显示当前空闲档位，避免把暂停采样误读为性能异常。
- `info` 工具通过 `read()` 返回只读快照，并可携带次级动作按钮；`action` 工具通过 `run()` 执行；附加动作不改变工具类型，避免面板内置特例。
- 导出工具先检查 `isTauri()`，不满足时提示“需在 tauri dev 中运行”，不静默返回。
- 重载与清除覆盖必须二次确认，提示会丢弃未保存的界面状态。
- 所有工具只读或导出本地日志；不调用解锁、密钥、容器、删除、更新安装接口。
- 不提供“打开目录”“任意路径读取”“IPC 控制台”。

---

## 5. 改动面清单

### 5.1 业务界面入口移除

| 文件 | 改动 | 原因 | 影响面 |
| --- | --- | --- | --- |
| `ManagementTopBar.vue` | 删除日志/诊断两个动作节点；删除 `updateFailed` prop 与两个 emit；更新文件头职责说明 | 用户界面零入口 | 仅中枢顶栏 |
| `ManagementView.vue` | 删除 `:update-failed`、两个事件绑定、prop 与 emits | 事件链清理 | 仅管理视图透传 |
| `SecurityCenter.vue` | 删除两个事件绑定、弹窗 `@export`、`exportAppLogs` 导入、`onExportDiagnostics`、`onExportUpdateLogs`，以及不再使用的 `exportLogs` 解构 | 删除用户导出处理与死代码 | 管理界面 + 更新弹窗 |
| `UpdaterAvailableDialog.vue` | 删除“导出日志”按钮与 `export` emit | 用户界面零入口 | 更新说明弹窗 |
| `UpdaterRepairDialog.vue` | 删除“导出日志”按钮与 `export` emit；更新文件头说明 | 用户界面零入口 | 修复弹窗 |
| `App.vue` | 删除修复弹窗 `@export`、`exportUpdateLogs` 解构、`onExportRepairLogs`；改写失败提示 | 删除用户导出处理与死代码 | 启动修复流程 |
| `updater_error.ts` | 10 条含“导出”的指引逐条替换为可执行动作（见下表） | 文案不得指向已不存在的动作 | 错误指引展示 |
| `ManagementTopBar.spec.ts` | 移除 `updateFailed` 夹具；新增“无导出动作节点”断言 | 锁定新契约 | 单测 |
| `UpdaterAvailableDialog.spec.ts` | 新增“无导出日志按钮”断言 | 锁定新契约 | 单测 |

`App.vue:182` 的提示同步改为 `无法启动修复安装器，请重新安装旧版`。

`updater_error.ts` 文案替换清单（行号随编辑漂移，以错误码为准）：

| 行 | 错误码 | 新文案 |
| --- | --- | --- |
| 57 | `E_UPDATER_MANIFEST_INVALID` | 请稍后重试；若持续出现请联系维护人 |
| 62 | `E_UPDATER_MANIFEST_SIG_INVALID` | 已阻止安装；请重新安装或联系维护人 |
| 127 | `E_UPDATER_SIG_INVALID` | 已阻止安装；请重新安装或联系维护人 |
| 132 | `E_UPDATER_SIG_PUBKEY_MISMATCH` | 已阻止安装；请重新安装或联系维护人 |
| 137 | `E_UPDATER_AUTHENTICODE_INVALID` | 已阻止安装；请重新安装或联系维护人 |
| 147 | `E_UPDATER_LOCK_FAILED` | 请重试；若持续失败请重启应用 |
| 157 | `E_UPDATER_INSTALL_FAILED` | 请重试或重新安装旧版 |
| 167 | `E_UPDATER_MARKER_INVALID` | 请运行修复或重新安装旧版 |
| 197 | `E_UPDATER_INTERNAL` | 请重试或重启应用 |
| 209 | 未知错误兜底 | 请重试或重启应用 |

`updater_error.spec.ts` 只校验文案非空，不校验具体措辞，因此替换不会破坏既有断言。

执行后静态扫描预期：

```
rg "导出.{0,4}日志|日志.{0,4}导出|导出诊断|exportDiagnostics|updateFailed" verthys-tauri/src/components verthys-tauri/src/App.vue verthys-tauri/src/lib/updater_error.ts
```

期望零命中。`useAppUpdater.ts` 的 `exportLogs` 方法与 `updater_export_logs` 命令名保留，供开发悬浮球与开发期命令使用。

### 5.2 开发悬浮球

| 文件 | 职责 |
| --- | --- |
| `devtools/marker.ts` | 唯一构建标记常量；必须绑定到根节点属性，不能只放在 console 输出（混淆器会移除 console 调用） |
| `devtools/devdock.css` | 引力刻度锚点、四枚分组卫星与控制台的全部样式；只由 DevDock 导入，随组件剔除 |
| `devtools/orb_geometry.ts` | 纯几何：边界钳制、最近边缘、位置序列化与解析 |
| `devtools/useOrbDrag.ts` | 指针捕获、点击/拖拽分流、松手弹簧收敛、减弱动效分支 |
| `devtools/registry.ts` | 工具类型（action/info）、分组、`run()`/`read()` 契约、注册与启动期校验（唯一 id、非空标签、分组存在） |
| `devtools/tools/logs.ts` | 两个日志导出工具 |
| `devtools/tools/runtime.ts` | 指标、flags、快照复制 |
| `devtools/tools/environment.ts` | 环境信息 |
| `devtools/DevDock.vue` | 球、面板、工具渲染、关闭语义、定时器生命周期 |
| `App.vue` | 仅 DEV 条件动态挂载；生产分支为 null |
| `tokens.css` | 新增 `--z-devtools: 10020`，并补充分层注释 |

挂载形态：

```ts
const DevDock = import.meta.env.DEV
  ? defineAsyncComponent(() => import("./devtools/DevDock.vue"))
  : null;
```

生产构建中该分支为常量 false，动态 import 不进入产物。`DevDock` 自身 `Teleport to body`，不进入 `.app-root` 的空闲治理类。

### 5.3 命令层发布态拒绝

| 文件 | 改动 |
| --- | --- |
| `controller/diag_controller.rs` | `diagnostics_export_logs` 入口增加 `if !cfg!(debug_assertions) { return Err(...) }` |
| `updater/mod.rs` | `updater_export_logs` 入口增加同等拒绝门，返回 `UpdaterError` |

约束：

- 不改命令签名、不改返回类型、不改前端调用方式。
- 拒绝信息不含内部路径或堆栈。
- 开发期行为保持不变；发布态返回明确错误，不执行任何文件读取或打包。

---

## 6. 实施步骤

### Phase 0：基线采集（不改代码）

1. 复核第 3 节全部证据的当前行号与内容。
2. 在 `verthys-tauri` 执行 `npx vue-tsc --noEmit`、`npx vitest run`、`npm run build`。
3. 在 `verthys-tauri/src-tauri` 执行 `cargo test --lib`、`cargo clippy --all-targets -- -D warnings`。
4. 记录输出与失败项；基线不绿则停止，不进入 Phase 1。

退出条件：基线命令全部通过，或存在与本方案无关的既有失败且已记录。

### Phase 1：移除用户入口

1. 按 5.1 清单逐文件删除入口、事件、处理函数、导入与文案。
2. 更新 `ManagementTopBar` 文件头职责说明与 emits 注释。
3. 更新 `UpdaterRepairDialog` 文件头说明，去掉“保留日志导出”。
4. 执行 `npx vue-tsc --noEmit` 与 `npx vitest run`。
5. 执行 5.1 静态扫描，确认产品组件与文案为零。

退出条件：类型检查与单测通过；静态扫描符合预期；用户界面无导出入口。

### Phase 2：悬浮球核心

1. 新增 `marker.ts`、`orb_geometry.ts`、`orb_geometry.spec.ts`。
2. 新增 `useOrbDrag.ts`，复用 `floating_physics.ts` 的 `clampToBounds`、`stepSpring`、`isSettled`。
3. 新增 `DevDock.vue`：球、拖拽、吸附、位置持久化、面板开合、Esc/点外关闭。
4. `App.vue` 增加 DEV 条件动态挂载；`tokens.css` 增加 `--z-devtools`。
5. 执行类型检查与单测；开发构建手动验证球体行为。

退出条件：球可拖拽、吸附、持久化、键盘可达；无持续 rAF；减弱动效分支正确。

### Phase 3：注册表与工具

1. 新增 `registry.ts` 与 `registry.spec.ts`，先锁定唯一 id、分组、非空标签。
2. 新增 `tools/logs.ts`，复用现有导出函数；取消静默、错误 Toast。
3. 新增 `tools/runtime.ts`，实现指标轮询、flags 展示/清除、快照复制；轮询仅在面板展开时运行。
4. 新增 `tools/environment.ts`，只读展示环境信息。
5. `DevDock.vue` 接入注册表与四组渲染。
6. 执行单测与开发构建手动验证全部工具。

退出条件：七个工具逐项可用；错误路径有提示；关闭面板后无定时器残留。

### Phase 4：命令层拒绝门

1. 在两个命令入口增加发布态拒绝门与 Why 注释。
2. 执行 `cargo check`、`cargo test --lib`、`cargo clippy --all-targets -- -D warnings`。
3. 执行静态扫描确认两处拒绝门存在。

退出条件：开发构建导出仍可用；Rust 检查与测试通过；发布态拒绝语义由 `cfg!` 编译期保证。

### Phase 5：生产剔除门禁

1. 新增 `verthys-tauri/scripts/verify-devtools-excluded.mjs`（纯 ASCII）。
2. 脚本校验：
   - `dist` 存在；
   - 任意路径与文件名不含 `DevDock`；
   - 任意 `.js/.mjs/.css/.html/.json/.map` 文本不含 `__VERTHYS_DEV_DOCK__` 或 `DevDock`；
   - `dist/index.html` 不引用悬浮球。
3. `package.json` 的 `build` 串联该脚本：`vue-tsc --noEmit && vite build && node scripts/verify-devtools-excluded.mjs`。
4. 执行 `npm run build`，确认门禁 PASS。
5. 反向注入验证：临时在 `App.vue` 静态导入 `DevDock`，执行 `npm run build`，确认门禁失败；撤销临时代码后再次确认 PASS。反向验证不得提交。

退出条件：正常构建 PASS；反向注入必然失败；工作区无临时残留。

### Phase 6：文档同步与全量复核

1. 先执行 `rg "导出日志|导出更新日志" docs/updater` 全量定位，再逐条改写 `docs/updater/UPDATER_MASTER_PLAN.md` 中仍把“导出日志”列为用户动作的条目（状态表、指引原则与故障处置表）；不扩大文档改动范围。
2. 执行第 7 节全部门禁。
3. 按四视角自审（安全、性能、可维护、接手）逐项复核。
4. 输出验证证据与未覆盖项。

退出条件：门禁全绿；证据可追溯；未覆盖项明确标注。

---

## 7. 验证门禁矩阵

### 7.1 静态与测试

| 门 | 命令（工作目录） | 通过标准 |
| --- | --- | --- |
| 前端类型 | `npx vue-tsc --noEmit`（`verthys-tauri`） | exit 0，零错误 |
| 前端单测 | `npx vitest run`（`verthys-tauri`） | 零失败；新增用例全绿 |
| 前端生产构建 | `npm run build`（`verthys-tauri`） | exit 0；剔除门禁 PASS |
| Rust 单测 | `cargo test --lib`（`verthys-tauri/src-tauri`） | 零失败 |
| Rust 静态 | `cargo clippy --all-targets -- -D warnings` | 零告警 |
| Rust 发布检查 | `cargo check --release`（`verthys-tauri/src-tauri`） | exit 0；拒绝门在 release 下可编译 |
| 体系门禁 | `powershell -ExecutionPolicy Bypass -File ci\run_ci.ps1` | 与本方案相关项全绿；既有基线偏差单独记录 |
| 用户入口扫描 | 第 5.1 节 `rg` 命令 | 产品组件与文案零命中 |
| 发布门扫描 | `rg "cfg!(debug_assertions)"` 两文件 | 两处命中 |

### 7.2 关键路径实测

| # | 操作 | 期望 |
| --- | --- | --- |
| M1 | 开发构建启动 | 悬浮球在右下角出现 |
| M2 | 拖拽到左边缘松手 | 吸附左边缘，无越界；重启后位置保留 |
| M3 | 位移小于 6 px 点击 | 面板展开；不触发拖拽 |
| M4 | Enter/Space 展开、Esc 关闭、点外关闭 | 行为一致，焦点回到球 |
| M5 | 缩小窗口 | 球与面板重新夹取，不越界 |
| M6 | 减弱动效系统设置 | 无弹簧惯性，直接落位 |
| M7 | 导出诊断日志 | 保存对话框；成功 Toast；取消无提示 |
| M8 | 导出更新日志 | 同上 |
| M9 | 指标面板 | 数值每秒刷新；关闭后停止 |
| M10 | flags 清除 | 二次确认后移除 localStorage 覆盖并重载；值回默认 |
| M11 | 复制快照 | 剪贴板内容包含环境 + 指标 + flags |
| M12 | 重载 | 二次确认后界面重载，无重复监听残留 |
| M13 | 中枢/更新弹窗 | 无日志/诊断按钮，指引文案无“导出日志” |
| M14 | 生产构建产物 | 无 `DevDock` 文件、无标记字符串、`index.html` 无引用 |
| M15 | 反向注入 | 构建门禁失败；撤销后恢复 PASS |

### 7.3 未覆盖项声明规则

无法实测的项必须标注“未验证”并说明原因。例如发布态命令拒绝的运行时实测若受环境限制，只能以 `cfg!(debug_assertions)` 编译语义、发布构建成功与静态扫描作为证据，不得宣称已实际调用验证。

---

## 8. 风险与对策

| # | 风险 | 等级 | 对策 |
| --- | --- | --- | --- |
| R1 | 开发代码泄漏到发布包 | 高 | 构建层 DEV 门 + 产物标记/文件名扫描 + 反向注入验证 |
| R2 | 混淆器改写标记字符串导致扫描失效 | 中 | 多信号扫描（文件名、标记、index.html）；反向注入证明门禁有效 |
| R3 | `generate_handler!` 条件注册不可控 | 中 | 不改命令表，采用命令内运行时拒绝门 |
| R4 | 悬浮球遮挡弹窗或窗控 | 中 | 层级 10020；默认右下；顶部 48 px 安全边距；可拖拽；Esc/点外关闭 |
| R5 | 拖拽与点击误判 | 中 | 6 px 位移阈值；指针捕获；拖拽期间 `touch-action: none` |
| R6 | 常驻动画拖累帧预算 | 低 | 拖拽才启动 rAF；面板 1 s 轮询仅展开时运行；无阴影/发光 |
| R7 | 位置持久化损坏导致越界 | 低 | 解析仅接受有限数值；加载后强制钳制；损坏回默认 |
| R8 | 剪贴板权限失败 | 低 | 捕获异常并 Toast，不静默 |
| R9 | 非 Tauri 环境下导出无效 | 低 | 复用 `isTauri()` 短路；开发文档注明需 `tauri dev` |
| R10 | 移除入口后残留死代码 | 中 | 静态扫描 + 类型检查 + 逐文件复核 |
| R11 | 更新弹窗测试因按钮移除失效 | 低 | 先跑基线；仅调整夹具并新增“无导出按钮”断言 |
| R12 | 文档仍指引用户导出日志 | 低 | Phase 6 同步受影响动作表与指引 |
| R13 | 开发工具演变为第二产品面 | 中 | 注册表只收录已评审工具；不新增后端接口；DEV-only |

---

## 9. 回滚方案

| 场景 | 回滚动作 |
| --- | --- |
| Phase 1 后用户界面异常 | 回退 Phase 1 提交；用户入口恢复；开发悬浮球未引入 |
| Phase 2/3 悬浮球异常 | 回退 Phase 2-3 提交；`App.vue` 挂载点移除；产品入口保持已移除状态 |
| Phase 4 命令拒绝门影响开发 | 回退 Phase 4 单个提交；不影响前端 |
| 生产剔除门禁误报 | 先修门禁脚本；不得删除或放宽门禁换取通过 |
| 发布隔离失败 | 整批回退到 Phase 0 基线；重新评审实现路径 |

回滚不涉及数据迁移、不删除用户数据、不改动容器格式。

---

## 10. 人格合规自检

| 条款 | 方案落点 |
| --- | --- |
| 先读后判 | 第 3 节逐项证据；执行前复核行号 |
| 先证后修 | Phase 0 基线；G0 方案评审先行 |
| 最小改动 | 第 5 节文件清单；不做无关重构与格式化 |
| 证据说话 | 第 7 节命令矩阵与手动清单；未实测项明确标注 |
| 宁慢不错 | 未评审不写代码；发布隔离优先于开发便利 |
| 安全底线 | 无凭据、无新增后端接口、工具不接触解锁/密钥/容器 |
| 不可逆操作 | 无删除/迁移/部署；仅代码与文档变更，可回退 |
| 诚实 | 不删测试换通过；不伪造验证；发布态拒绝未实测时明确标注 |
| 验证门禁 | 构建、测试、关键路径三项独立执行 |
| 注释规范 | 新增注释只解释 Why；不写外部文档名、编号、链接 |

四视角自审：

- 安全：DEV-only + 产物门禁 + 命令拒绝门；工具只读本地日志；无提权与绕过。
- 性能：无永久 rAF；指标轮询仅展开时运行；球体动画仅交互期。
- 可维护：注册表统一扩展点；几何纯函数可单测；组件与工具单向依赖。
- 接手：本方案 + 门禁脚本 + 契约测试构成可复现交付链。

### 10.1 方案缺陷自检（本轮已闭环）

| 发现 | 处理 |
| --- | --- |
| 文案替换数量初稿漏计 6 处 | 已按 `updater_error.ts` 全量扫描列出 10 处，并给出逐条替换 |
| 层级 10000 与全屏弹窗同值，DOM 顺序不可控 | 改为 10020，位于弹窗与窗控之间 |
| 点外关闭与开球点击同帧竞争 | 监听在打开后的下一帧注册，并排除球体与面板 |
| 面板窄屏溢出 | 宽度改为 `min(300px, calc(100vw - 32px))` |
| 重载可能丢弃未保存状态 | 重载与清除覆盖均二次确认 |
| 非 Tauri 环境导出静默返回 null | 显式检查 `isTauri()` 并提示 |
| 注册表无法表达“只读指标” | 增加 `kind` 与 `read()` 契约 |
| 产物扫描用泛词 `devtools` 可能误报 | 只扫描 `DevDock` 文件名与标记字符串 |
| 文档仍指引用户导出日志 | Phase 6 定点同步更新动作表 |

---

## 11. 待确认项与默认判断

| # | 待确认 | 默认判断 | 若按默认执行的风险 |
| --- | --- | --- | --- |
| Q1 | 是否同时移除更新说明弹窗与修复弹窗的导出按钮 | 是，用户界面零入口 | 用户失去唯一自助导出通道；但本方案目标即开发专用 |
| Q2 | 发布态隔离采用命令内运行时拒绝，而非编译期删除命令 | 运行时拒绝 | 发布二进制仍含命令名与导出实现；调用必失败，但代码文本存在 |
| Q3 | 首批工具是否限定为 4.6 的 7 项，不新增后端接口 | 是 | “打开目录/模块直达”延后 |
| Q4 | 悬浮球默认右下、层级 10020 | 是 | 弹窗右下角按钮可能被球短暂遮挡；可拖拽规避 |
| Q5 | 引导页/解锁页是否也显示悬浮球 | 是，便于启动期调试 | 会出现在未解锁界面；仅开发构建可见 |
| Q6 | 开发入口仅在 Vite dev / `tauri dev` 可见，debug Rust + production `dist` 组合不提供 | 是 | 若需要打包版开发工具，需另立方案与独立构建模式 |
| Q7 | 是否同步移除 `updater/native.rs` 的“打开更新日志并退出”系统对话框 | 否，保留启动失败兜底 | 用户仍可通过系统对话框打开日志目录；不影响悬浮球的发布隔离 |

确认方式：以上默认全部采纳时回复“按默认执行”；任一调整请指明条目。

---

## 12. 交付物

1. 本方案文档。
2. 代码变更（评审通过后按 Phase 执行）。
3. 验证证据：命令输出、构建门禁结果、手动操作记录。
4. 未覆盖项清单与原因。

---

## 13. 本轮执行记录

### 13.1 基线（Phase 0）

| 门 | 实测结果 |
| --- | --- |
| `npx vue-tsc --noEmit` | 通过，exit 0 |
| `npx vitest run` | 通过，69 文件 / 755 例 |
| `npm run build` | 通过（本轮新增剔除门禁后仍 PASS） |
| `cargo test --lib --quiet` | 559 通过 / 2 忽略 / 0 失败 |
| `cargo check --release` | 通过，exit 0 |
| `cargo clippy --all-targets -- -D warnings` | 未通过：`verthys_controller.rs:1927` 既有 `redundant_closure_call`，与本方案无关；加 `-A clippy::redundant_closure_call` 后通过，确认仅此一处 |

### 13.2 变更与门禁

| 项 | 结果 |
| --- | --- |
| 用户入口移除 | 中枢、更新说明弹窗、修复弹窗、修复流程与 10 条错误指引全部移除或改写；产品 `.vue` 与文案静态扫描零命中 |
| 开发悬浮球 | 引力刻度主球 + 四枚分组卫星 + 机械控制台；`DevDock.spec` 5 例、`orb_geometry.spec` 8 例、`registry.spec` 4 例全绿 |
| 命令层拒绝门 | `diag_controller.rs:43`、`updater/mod.rs:1447` 已加 `cfg!(debug_assertions)` 拒绝 |
| 生产剔除门禁 | `npm run build` 输出 `[devtools-exclusion] PASS` |
| 反向注入验证 | 临时静态导入后构建按预期失败（命中 `index-*.js` 与 `stats.html`）；撤销后重新 PASS |
| 全量前端单测 | 69 文件 / 757 例全绿（含新版悬浮球卫星与控制台契约） |
| Rust 单测与发布检查 | 559 通过 / 2 忽略；`cargo check --release` 通过 |

### 13.3 偏差与未覆盖

| 项 | 说明 |
| --- | --- |
| `cargo clippy` 既有告警 | 位于 `verthys_controller.rs:1927`，非本方案引入；为保持最小改动未修复，交付时如实标注 |
| 开发期视觉与拖拽 | 浏览器开发服务器实测通过：悬浮主球展开「日志/观测/环境/动作」四枚卫星，点击主球打开「开发控制台」并显示四组跳转轨；拖拽手感、吸附动画与多显示器缩放仍仅由几何单测覆盖，未人工拖拽 |
| 版本同步 | 按根 `VERSION` 4.2.5 同步 6 个载体；版本门禁 `-CheckOnly` PASS；版本变更触发 worker 陈旧检查，已重建 worker release 并刷新 externalBin，`cargo check --release` 恢复通过 |
| 体系门禁 `ci\run_ci.ps1` | 版本门禁、锚点门、常量生成门、导出契约门已通过；整体仍阻塞于既有常量消费门：`PHOTO_INDEX_MAX_BYTES` 无消费点（与本方案无关） |
| 发布态命令拒绝 | 由 `cfg!(debug_assertions)` 编译语义、release 编译通过和静态扫描作为证据；未在发布二进制内实际调用 IPC 验证 |
| 并发编辑 | `ModuleKeyRow.vue` 被外部改为“关闭保护时不渲染密钥节点”；其 spec 已按新契约更新并 4/4 通过，未改动生产组件 |

> 本方案已按用户确认执行；最终验收以第 13 节证据为准。
