# 编码规范（CODING_STANDARDS）

> 整合 C 层编码规范并对齐代码现状，给出 C/Rust/TypeScript 的命名、目录、格式、静态检查与提交约定。
>
> Last updated: 2026-09-19 · 维护人：K1Super

本规范整合 `archive/c_layer_coding_spec.md` 并对齐当前代码现状；命名与目录以代码实际符号为准（规范与代码冲突时以代码为事实，差异在文中标注）。提交规范见 [`../CONTRIBUTING.md`](../CONTRIBUTING.md)；刚性底线见 [ENGINEERING_CONSTRAINTS.md](ENGINEERING_CONSTRAINTS.md)。

---

## 1. 适用范围与语言

| 语言 | 位置 | 定位 |
|---|---|---|
| C11 | `core/`（`verthys.dll`） | 安全核心，黑盒封装全部密码/格式/内存逻辑 |
| Rust | `verthys-tauri/src-tauri`、`verthys-tauri/verthys-worker` | 主进程调度 + worker 隔离子进程 |
| TypeScript/Vue3 | `verthys-tauri/src`、`verthys-tauri/src-tauri/src` | 前端 UI（无权限、无密钥能力） |

---

## 2. C 语言规范（core）

### 2.1 命名规范（以代码实际符号为准）

| 类别 | 规则 | 实例 | 来源 |
|---|---|---|---|
| 公共函数 | `Verthys_` + `PascalCase` | `Verthys_Init`、`Verthys_Unlock`、`Verthys_AddRecord` | `core/include/verthys.h` |
| 公共类型 | `Verthys` + `PascalCase`（无 `_t` 后缀） | `VerthysHandle`、`VerthysRecord`、`VerthysResult`、`VerthysSecurityStatus` | `core/include/verthys.h` |
| 公共枚举常量/宏 | `VERTHYS_` + `UPPER_SNAKE` | `VERTHYS_OK`、`VERTHYS_ERR_AUTH`、`VERTHYS_API_VERSION`、`VERTHYS_UNLOCK_FLAG_MINIMAL_FIRST` | `core/include/verthys.h` |
| 内部函数 | `snake_case`，`verthys_` 或组件语义前缀 | `verthys_cng_aead_import_key`、`verthys_lsm_insert`、`vsb_txn_v3_begin`、`memtable_rebuild_locked` | `core/src/**` |
| 内部类型 | `PascalCase`（无 `_t` 后缀） | `VerthysCngAead`、`VsbTxnV3`、`VerthysSuperBlockV3`、`SecureAllocator` | `core/src/**` |
| 内部宏/常量 | `UPPER_SNAKE` | `VERTHYS_V3_SB_MAGIC`、`VERTHYS_KEY_BYTES`、`VERTHYS_V3_REPLICA_FRAME_MAGIC` | `core/src/container/shared/verthys_container_v3.h` |

> 说明：任务线索中曾拟「`模块_组件_名称_t` 类型」命名法，但 `core/include/verthys.h` 与 `core/src` 实际未使用 `_t` 后缀——公开类型统一 `Verthys` 前缀 PascalCase，内部类型组件语义 PascalCase。本规范以代码现状为准，不引入 `_t` 后缀。

命名附加约束（承 `archive/c_layer_coding_spec.md` §4.2）：避免下划线开头标识符（保留给编译器）；循环索引 `i`/`j` 允许，复杂逻辑用有意义名称；全局变量需描述性命名。

### 2.2 目录硬约束（以 core 现状验证）

- **子域 → 功能组件两级拆分**：`core/src/` 下六大域（crypto/container/index/transaction/security/api）+ 31 组件目录，源清单唯一事实源为 `core/CMakeLists.txt` 的 `VERTHYS_SRC_SUBDIRS`。
- **目录全小写蛇形**，示例：`core/src/crypto/keymanager/`、`core/src/security/layer6_closure/`。
- **单个组件目录 3-10 文件、层级 ≤4**（以 `src/` 为基准：域/组件/文件共 3 层）。
- **禁空泛目录名 utils/common/misc/helper**：`core/src` 下无此类目录；`core/src/api/shared/`、`core/src/container/shared/` 为「域内共享契约」组件（承载 `verthys_api_utils.h`、`verthys_container_v3.h` 等契约头），非空泛工具目录。
- **已知偏差（如实记录）**：Rust 侧存在 `verthys-tauri/src-tauri/src/util/`（audit_log/base64/crypto/ffi 等 11 文件）为历史结构，未按 C 层该条约束整改；C 侧文件名 `verthys_api_utils.c` 含 `utils` 为历史遗留命名。

### 2.3 公共/私有头物理隔离

- 公共接口仅 `core/include/verthys.h`（+ 配套 `error_codes.h`），`core/src` 下私有实现头不得被外部 include。
- 包含守卫统一 `#ifndef VERTHYS_XXX_H / #define / #endif`（见 `verthys.h`、`verthys_crypto.h`、`verthys_container_v3.h`）。
- 导出标记：`VERTHYS_API` 为**空宏**（不携带 dllexport/dllimport），导出唯一由 `core/verthys.def` 白名单决定——禁止重新启用 `VERTHYS_EXPORTS` 全量导出（红线，见 [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) ADR-011）。
- C++ 互操作用 `extern "C"` 包裹（`verthys.h` 已有）。

### 2.4 格式化（承 c_layer_coding_spec §4）

- 缩进 4 空格，禁 Tab；行宽建议 ≤80、上限 120；大括号风格 Allman/K&R 二选一且项目内统一（现状以 K&R 为主，见 `verthys_crypto.h`）。
- 二元运算符两侧空格；逗号/分号后空格；关键字后空格（`if (`）；函数名与括号间无空格；指针 `*` 紧贴变量名（`int *ptr`）。
- 每条语句独占一行；空行分隔逻辑块。

### 2.5 内存与错误处理（承 c_layer_coding_spec §5）

- 用 `<stdint.h>` 定宽类型 + `size_t`/`ptrdiff_t`；禁止隐式窄化/符号混算。
- `malloc/calloc/realloc` 与 `free` 成对；`realloc` 结果先赋临时指针；错误路径 `goto cleanup` 释放。
- 敏感数据（密钥/口令）用后立即 `verthys_secure_zero`（`core/src/crypto/cipher/secure_mem.c`），`volatile` 防优化零化。
- 统一错误码：内核返回 `VerthysResult`（`verthys.h`）；C 源内部禁向 stdout/stderr 调试输出（`core/include/error_codes.h` 红线）。

---

## 3. 注释规范（为何而非如何）

- 注释解释「为什么」而非复述「做什么」，拒绝无脑逐行注释（刚性条款 3.7）。
- 复杂算法/核心路径/对外接口必须注释意图与设计；公共函数建议 Doxygen 风格标注参数方向（`[in]/[out]/[in,out]`）、返回/错误码、线程安全、内存所有权。
- 线程安全用统一标注：`MT-Safe / MT-Unsafe / MT-Const / MT-Handle`（`verthys.h` 头部定义）。
- 偏差必须磁盘留痕：无法按规范/方案执行时，在代码头注 + 执行文档记录偏差编号与证据（先例 D-1 `/guard:longjmp`、D-2 `/wd4996`，见 `cmake/VerthysHardening.cmake`）。
- 禁止保留已注释死的代码，及时删除。

---

## 4. 静态检查与编译加固

### 4.1 clang-tidy（`.clang-tidy` 已存在，根目录）

启用方式：`-DVERTHYS_ENABLE_CLANG_TIDY=ON`，`HeaderFilterRegex: 'core/(src|include)/.*\.h$'`（仅项目头，不检 third_party）。规则大类：

| 大类 | 代表规则 |
|---|---|
| UAF 与悬挂指针 | `bugprone-use-after-free`、`bugprone-dangling-handle`、`clang-analyzer-core.UAF` |
| 内部指针对外裸露 | `clang-analyzer-core.StackAddressEscape`、`cppcoreguidelines-owning-memory` |
| 内存分配/释放配对 | `clang-analyzer-unix.Malloc`、`MismatchedDeallocator` |
| 安全编码规范 | `bugprone-suspicious-memset-usage`、`bugprone-swapped-arguments` 等 bugprone-* 集 |
| 性能/现代 C/可读性 | `performance-*`、`modernize-*`、`readability-*`（不阻断） |

**警告即错误门**（三类必须阻断）：`bugprone-use-after-free`、`clang-analyzer-core.UAF`、`clang-analyzer-core.StackAddressEscape`、`clang-analyzer-core.CallAndMessage`、`clang-analyzer-unix.Malloc`、`bugprone-dangling-handle`。

### 4.2 编译器与加固

- 编译基线：`/GS /guard:cf /guard:ehcont /sdl /utf-8 /Zc:inline /FS`（+ `/wd4996` 偏差留痕）；Release `/O2 /GL /Gy /Gw`；链接 `/INCREMENTAL:NO /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT` + x64 `/CETCOMPAT`（`cmake/VerthysHardening.cmake`）。
- ASAN：`-DVERTHYS_ENABLE_ASAN=ON`（CI 门）；fuzz：`-DVERTHYS_ENABLE_FUZZ=ON`（`/fsanitize=fuzzer`，注意 MSVC 下需显式 `address` 与 `fuzzer` 双开关，勿用逗号组合）。
- **clang-format 核实结果：未配置**——根目录无 `.clang-format` 文件，当前格式靠人工约定 + clang-tidy + 编译警告基线约束（如需引入需先评审，避免与既有 4 空格/大括号风格冲突）。

---

## 5. Rust 规范（src-tauri + verthys-worker）

- 包与版本：`verthys-tauri`（lib crate `verthys_tauri_lib`，edition 2021，2.6.1）、`verthys-worker`（bin crate）；依赖显式版本锁定（`=x.y.z`）。
- release profile：`opt-level=3`、`lto=true`、`codegen-units=1`、`panic="abort"`、`strip=true`；dev `incremental=false`（LNK1181 修复，见 Cargo.toml 注释）。
- 模块分域：`controller/`（Tauri command）、`infrastructure/`、`security/`、`security_commands/`、`state/`、`util/`、`worker/`；worker 内 `runtime/`（dispatch/protocol/worker/gmk/ffi_types）。
- 敏感内存：`zeroize`（GMK/密码清零）+ `subtle`（常量时间比较），禁止对敏感值 `Clone` 扩散。
- 与 C 边界：libloading 按名解析 → 错误码镜像 `util/ffi.rs` 与 `error_codes.h` 对齐；本地补丁进 `patches/`（`keyboard-types` 等），升级时复核补丁是否可移除（Cargo.toml 维护说明）。

---

## 6. TypeScript / Vue3 规范

- **ESLint/Prettier 核实结果：未启用**——`verthys-tauri/package.json` 无 eslint/prettier 依赖与脚本，仓库无 `.eslintrc*`/`prettier.*` 配置文件。
- 类型与语法检查由 `vue-tsc --noEmit` + `vite build` 承担（`npm run build` = `vue-tsc && vite build`）。
- 前端入口导出 `verthys.ts`（命令封装）、`src/lib/*.ts`；组件按业务模块拆 `components/modules/`。命名遵循 Vue/TS 社区惯例（PascalCase 组件、camelCase 变量/函数）。
- 敏感逻辑不下沉前端：前端仅经 `invoke` 调 Tauri command，不接触密钥/明文（架构约束）。

---

## 7. 提交规范

- 提交信息、分支策略、PR 流程、代码评审要求见 [`../CONTRIBUTING.md`](../CONTRIBUTING.md)。
- 文档同步是完成定义（DoD）的一部分：接口/目录/构建/配置/安全边界变更须同 PR 更新对应文档（`DOCUMENTATION_CHECKLIST.md` §4）。
- 单一事实来源：版本号以 `CMakeLists.txt`/`Cargo.toml`/`tauri.conf.json` 为准，依赖版本以 `Cargo.toml`/`package.json`/`dep-versions.txt` 为准，文档只引用不抄录。