# 实施进度记录 —— pepper v3 密钥槽改造

> 本文件随时更新，供中断后快速接手。
> 设计与规格见 [IMPL_PEPPER_V3_KEYSET.md](IMPL_PEPPER_V3_KEYSET.md)。
> 时间均为本机本地时间（Asia/Shanghai）。

## 恢复指引（接手时先读这里）

- 当前进度：见下方最新一条【状态=进行中/待办】的条目。
- 构建命令：
  - core：`powershell -ExecutionPolicy Bypass -File scripts\build_core.dev.ps1 -NoPause`（项目根）
  - Rust：`cargo test`（verthys-tauri\src-tauri）
  - 前端：`npm run build`（verthys-tauri）
- 提权重跑：`Start-Process powershell -Verb RunAs -ArgumentList ...` 会弹 UAC，需用户点"是"。
- 关键环境事实：
  - `%APPDATA%\Verthys\pepper.bin` 当前为 v2 格式（旧策略封装）。
  - 事故遗留：机器级密钥容器存在但无用（新策略下不再使用）。
  - 验收 A 前必须删除 pepper.bin（V3-only 无迁移，一次性 rollout 动作）。
- 已失败且勿重试的方案：
  - 提权重跑旧代码测试（失败数不变，已实证）。
  - 在非提权/提权 shell 间切换运行（旧策略下必然漂移）。

## 进度条目

### 2026-09-19 阶段 0：基线确认（完成）

- 描述：确认事故为 pepper 失配而非构建破损；core 编译成功、94 项失败全部 rc=12；
  提权无效；删除 pepper.bin 后非提权 250/0（临时恢复）。
- 证据：非提权日志 `=== Summary: 156 passed, 94 failed ===`；探针日志
  `decrypt(fileLabel)=0x80090027`；恢复后 `250 passed, 0 failed`。
- 附注：临时恢复是删除文件后的重生，非根治；此时 pepper.bin 为 v2 格式。

### 2026-09-19 阶段 1：方案定稿（完成）

- 描述：C1/C2/C3 三档方案对比；用户选定 C3 高标准执行，追加两个约束：
  项目直达 V3 格式（删除全部旧格式兼容内容）；实施期间在 docs 维护进度与实施文档。
- 产物：[IMPL_PEPPER_V3_KEYSET.md](IMPL_PEPPER_V3_KEYSET.md)。

### 2026-09-19 阶段 2：文档先行（完成）

- 描述：撰写实施文档与本进度记录；核对构建体系（对象库双消费 → 存储路径覆盖函数
  必须为常编译内部符号，不能用 `#ifdef` 门控编译——对象库供 DLL 与测试共用）。
- 结论：路径覆盖函数以非导出内部函数落地，发布面不变。

### 2026-09-19 阶段 3：CNG 槽架构重构（完成）

- 文件：`core/src/security/layer3_hw_binding/cng_machine_key.h`、`cng_machine_key.c`
- 完成度：头文件与实现全部重写——4 槽位表（用户级优先、机器级兜底）、
  init 只 Open 不隐式创建机器键、seal 按策略序、unwrap_known 按记录直达、
  destroy 清理 4 槽；DACL/refuse-rebuild/NTE_EXISTS 竞态重开全部保留；
  旧 wrap/unwrap 已删除（调用方仅在 pepper 模块，随阶段 4 一并切换）。
- 未验证：编译（待阶段 5 首次构建）——pepper 模块此时仍在调用已删除的
  wrap/unwrap，构建必失败，属预期中间态。

### 2026-09-19 阶段 4：pepper V3 格式（完成）

- 文件：`core/src/crypto/pepper/verthys_pepper.h`、`verthys_pepper.c`
- 完成度：v3 308B 常量与偏移宏；指纹按 v3 覆盖域（头部 8B ∥ label ∥ cipher）
  重写且改为内部导出（测试构造样本用）；load 重写（尺寸门 → magic/version →
  枚举域 → 指纹 → 按记录级别直达解包，全部失败即来源错误；删除全部
  v1/v2 解析与升级分支）；save 重写（策略序 seal，级别/KSP 随头部持久化）；
  新增 `verthys_pepper_set_storage_path_override`（常编译内部符号）与
  `pepper_file_fingerprint` 声明；头文件注释同步（无外部引用）。
- 残留检查：`cng_machine_key_wrap/unwrap`、`VERTHYS_PEPPER_FILE_V1_BYTES`、
  `is_v1/is_v2` 全库零引用。

### 2026-09-19 阶段 5：测试源与构建登记（完成）

- 新增 `core/tests/crypto/test_pepper_v3.c`（7 用例：首建闭环、密文/指纹
  篡改、封装级伪造、外来尺寸、坏 magic、注入旁路；布局常量测试侧独立
  定义防漂移）；`tests/CMakeLists.txt` 登记源文件；`test_runner.c` 声明
  并编排 pepper_v3 组（keymanager 之后）。

### 2026-09-19 阶段 6：验收 A/B/C（完成）

- 验收 A（非提权）：删除 v2 pepper.bin 后构建，**257 passed / 0 failed**；
  新生成 pepper.bin 实证 308B / ver=3 / key_level=1（用户级）/ provider=2
  （软件 KSP）。
- 验收 B（提权）：UAC 提权全套构建，**257 passed / 0 failed**——
  事故场景（提权导致漂移）回归通过。
- 验收 C（非提权，不删 pepper）：**257 passed / 0 failed**——
  双上下文任意顺序运行稳定。

### 2026-09-19 阶段 7：回归与收尾（完成）

- cargo test：296 passed / 0 failed；npm build：类型检查 + 构建通过
  （vite 5.43s）。
- 改动净范围：`cng_machine_key.h/.c`、`verthys_pepper.h/.c`、
  `core/tests/crypto/test_pepper_v3.c`（新增）、`core/tests/CMakeLists.txt`、
  `core/tests/test_runner.c`、docs 两文件；未触碰任何容器/事务/数据面代码。

## 结项摘要

- 成果：pepper 持久化格式直达 V3（旧格式内容全部删除），CNG 单键全局态
  替换为 4 槽位用户级优先架构，封装级别随文件头持久化、加载直达解包；
  提权/非提权双上下文任意顺序运行全部 257/0。
- 遗留提示：事故期机器级遗留密钥自新策略起不再被使用（自然闲置）。
- 环境现状：`%APPDATA%\Verthys\pepper.bin` = 308B V3（用户级、软件 KSP）。