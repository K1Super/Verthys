# Pepper 持久化 v3 与密钥槽架构 —— 实施文档

> 状态：已实施完成（2026-09-19 全部验收通过）
> 进度与变更明细：[IMPL_PEPPER_V3_PROGRESS.md](IMPL_PEPPER_V3_PROGRESS.md)
> 代码遵循注释自包含规约：所有实现注释仅描述当前代码可验证的行为，不引用本文档或任何外部编号。

## 1. 背景与缺陷

事故现象：core 250 项测试出现 94 项失败，全部为 `Verthys_CreateWithPreset` 在 setup 阶段
返回 `VERTHYS_ERR_PEPPER_SOURCE`（rc=12）；提权运行后失败数不变。逐层探测确认：

- pepper.bin（`%APPDATA%\Verthys\pepper.bin`）存在且格式合法，但封装它的 CNG 密钥已丢失
  （机器密钥文件 mtime 为事故当次运行时间戳，属于旧密钥消失后新建）。
- 同一时刻 Software KSP 的机器级/用户级两把密钥均无法解开该密文（`NTE_INVALID_PARAMETER`），
  即"文件存在但永远解不开"的失配态。
- 失配根源是密钥级别随运行上下文漂移：初始化链为"机器级优先、用户级回退"，
  提权运行打开机器级密钥，非提权运行只能拿到用户级密钥；pepper 文件不记录封装级别，
  换上下文加载时拿错密钥，解包必然失败。

根因三要素：

1. CNG 模块是单键全局态（一把 `s_hKey`），封装与解包共用"当前上下文拿到的唯一密钥"。
2. 初始化期隐式创建密钥——提权环境下会在 init 阶段悄悄产生机器级密钥 K2（事故触发器）。
3. pepper 持久化格式不记录"由哪一级、哪个 KSP 封装"，加载时无直达依据。

## 2. 目标

- pepper 文件自描述封装上下文（级别 + KSP），加载直达，不盲试。
- 封装策略确定：用户级优先（同级别内平台安全边界优先），机器级兜底；不再由运行上下文隐式决定。
- 提权/非提权双上下文任意顺序运行，测试与真机均稳定。
- 格式直达 V3：删除全部旧格式（v1/v2）解析分支，不做迁移。

## 3. pepper 持久化格式 v3（308 字节）

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | magic | `0x50505656`（"VVPP" 小端） |
| 4 | 2 | version | `0x0003` |
| 6 | 2 | source_type | 胡椒获取层级（诊断用） |
| 8 | 1 | key_level | 1=用户级；2=机器级（0 保留） |
| 9 | 1 | key_provider | 1=平台安全边界 KSP；2=软件 KSP（0 保留） |
| 10 | 2 | reserved | 全零 |
| 12 | 8 | fingerprint | HMAC-SHA256（域密钥, version..reserved 8B ∥ label ∥ cipher）前 8 字节 |
| 20 | 32 | label | 系统实例标识哈希（OAEP label） |
| 52 | 256 | cipher | RSA-2048 OAEP 密文 |

校验顺序：长度与 magic/version → key_level/key_provider 枚举合法 → fingerprint → 解包。
任一步失败均返回源错误（`VERTHYS_ERR_PEPPER_SOURCE`），禁止回退到编译内嵌胡椒。

## 4. 密钥槽架构（CNG 模块）

单键全局态替换为 4 槽位表，槽序即封装策略序：

| 槽 | KSP | 级别 | 定位 |
|---|---|---|---|
| 0 | 平台安全边界 KSP | 用户级 | 首选项（TPM 支撑时绑定最强） |
| 1 | 软件 KSP | 用户级 | 常规桌面默认落点 |
| 2 | 平台安全边界 KSP | 机器级 | 兜底（SYSTEM 上下文、无用户配置档） |
| 3 | 软件 KSP | 机器级 | 兜底 |

接口变化：

| 函数 | 语义 |
|---|---|
| `cng_machine_key_init` | 逐槽 Open（provider + 密钥容器），不隐式创建机器级密钥；仅当全部容器不存在时按策略序创建用户级密钥（维持"初始化后密钥可用"的既有契约） |
| `cng_machine_key_is_available` | 至少一个槽的 provider 可打开 |
| `cng_machine_key_seal` | 按策略序取首槽：容器缺失（`NTE_BAD_KEYSET`）才创建，创建失败记入禁止位换下一槽；封装成功输出级别/KSP |
| `cng_machine_key_unwrap_known` | 按文件记录的级别+KSP 直达解包，仅 Open 绝不 Create |
| `cng_machine_key_destroy` | 释放全部 4 槽 |

保留不变：非 `NTE_BAD_KEYSET` 不重建的防线、机器级密钥仅 SYSTEM 的 DACL、
`NTE_EXISTS` 竞态重开、OAEP-SHA256 参数与导出禁用策略。

## 5. 加载与保存语义

- 文件不存在：生成随机胡椒 → `seal`（策略序，记录返回的级别/KSP）→ 原子写出 v3（重试一次；
  仍失败清零内存胡椒并置源错误）。
- 文件存在：按第 3 节顺序校验 → `unwrap_known` 解包 → 进入内存、上锁、可用。
- 保存：恒写 v3；调用仅存在于首建路径，`seal` 的级别/KSP 输出直接写入头部。

## 6. 变更文件清单（函数级）

| 文件 | 变更 |
|---|---|
| `core/src/security/layer3_hw_binding/cng_machine_key.h` | 新增 `CmkKeyLevel`/`CmkKeyProvider` 枚举与 `seal`/`unwrap_known` 声明；删除 `wrap`/`unwrap` 声明 |
| `core/src/security/layer3_hw_binding/cng_machine_key.c` | 槽表 + `init`/`is_available`/`seal`/`unwrap_known`/`destroy` 重写；`set_system_only_dacl` 原样保留 |
| `core/src/crypto/pepper/verthys_pepper.h` | 头注释同步；新增存储路径覆盖函数声明（测试隔离用） |
| `core/src/crypto/pepper/verthys_pepper.c` | v3 常量与偏移宏；`pepper_file_fingerprint` 按 v3 覆盖域重写；`load`/`save` 重写（删除 v1/v2 分支与升级逻辑）；新增 `verthys_pepper_set_storage_path_override` |
| `core/tests/crypto/test_pepper_v3.c` | 新增验收用例（见第 7 节） |
| `core/tests/CMakeLists.txt` | 登记新测试源 |
| `core/tests/test_runner.c` | 声明并编排新测试组 |

## 7. 测试矩阵

| 用例 | 断言 |
|---|---|
| 首建闭环 | 空路径初始化 → 308B 文件、magic/version 正确、级别/KSP 枚举合法 → 重载胡椒一致 |
| 密文篡改 | cipher 翻转 1 位 → 加载失败、源错误置位、胡椒未就绪 |
| 指纹篡改 | fingerprint 翻转 1 位 → 同上 |
| 封装级伪造 | 文件级别字节改为与实际封装相反的级别（指纹同步重算）→ 解包失败、不跨级回退 |
| 外来格式 | 写入 304B 旧格式文件 / 308B 坏 magic → 尺寸与 magic 门拒绝 |
| 注入优先级 | 注入胡椒后初始化不触碰 OS 存储，且存储目录无残留文件 |

测试隔离：全部用例经存储路径覆盖落盘到测试沙箱，不触碰真实 `%APPDATA%` pepper；
用例自备 CNG 初始化（幂等），不依赖测试顺序。

## 8. 实施顺序与验收剧本

1. CNG 槽架构重构（头 + 实现）。
2. pepper v3 格式落地（常量、指纹、load/save、路径覆盖）。
3. 新测试文件 + 构建登记。
4. 验收 A（非提权）：删除现存 v2 pepper.bin（V3-only 无迁移，一次性 rollout 动作）→
   `build_core.dev.ps1` → 250/0。
5. 验收 B（提权）：UAC 提权重跑 250 → 250/0（事故场景回归证明）。
6. 验收 C：再非提权重跑 250 → 250/0（全程不删 pepper，验证双上下文稳定）。
7. 回归：src-tauri cargo test 296/0；前端 `npm run build`；注释纯净校验。

## 9. 回滚

- 回滚代码后，V3 文件（308B）会被旧逻辑按尺寸判为无效 → 返回源错误（安全失败，
  与事故期行为一致）；恢复手段为删除 pepper.bin 重生。无数据损坏风险。
- 改造不触碰容器格式、事务、索引等任何数据面。

## 10. 遗留提示

- 现存机器级遗留密钥（事故期产生）自新策略起不再被封装路径使用，自然闲置，无需清理。
- 存储路径覆盖函数为内部符号，不在 DLL 导出清单中，发布面零变化。

## 11. 验收结果（2026-09-19）

| 场景 | 结果 |
|---|---|
| 验收 A：非提权构建 + 测试（删除 v2 pepper 后首跑） | 257 passed / 0 failed |
| 验收 B：提权构建 + 测试（事故场景回归） | 257 passed / 0 failed |
| 验收 C：再非提权（全程不删 pepper） | 257 passed / 0 failed |
| cargo test | 296 passed / 0 failed |
| 前端 vue-tsc + vite | 构建通过（5.43s） |
| 新生成 pepper.bin | 308B，ver=3，key_level=1（用户级），provider=2（软件 KSP） |

257 = 250 存量 + 7 新增（pepper_v3 组）。