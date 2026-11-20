# 回退锚点生命周期与淘汰治理（生产设计）

> 状态：现行 · 已实施（2026-11-20）
> Last updated: 2026-11-20
> 适用范围：`verthys.dll` 回退锚点（`rollback.state`）、worker/host 锚点管理接口、发布与运维处置
> 权威性：本文与代码冲突时以代码为准，并立即修订本文

---

## 0. 结论摘要

**根因不是容量不足，而是锚点缺少生命周期。** 当前实现只有“登记 / 推进”两条路径，没有“归属 / 失效判定 / 释放 / 回收 / 容量语义”。任何一次测试、迁移或异常退出留下的条目都会永久占位；表满后新建容器在提交阶段失败，却被折叠成 `VERTHYS_E_ROLLBACK`，表现为“检测到文件回退”。

本方案的五条核心决策：

1. **不扩容、不改 `rollback.state` 布局。** 64 条对正常使用足够；问题是占位没有被治理，不是上限太小。
2. **建立五态生命周期。** `ABSENT / ACTIVE / DEAD / TAMPERED / UNKNOWN`，每个状态有明确的判定依据与允许动作。
3. **三级淘汰策略。**
   - 自动回收 `DEAD`（引用的见证密钥确定不存在，锚点已无法通过任何校验）；
   - 用户授权释放 `ACTIVE/TAMPERED`（必须显式确认、审计、告知恢复码后果）；
   - **不自动淘汰有效锚点**（自动 LRU 会把可用容器变成必须恢复码才能打开，属于以可用性换容量）。
4. **容量耗尽必须是独立、可行动的错误。** 新增 `VERTHYS_ERR_ANCHOR_FULL`，UI 提供维护入口，不再误报文件回退。
5. **恢复码在 `DEAD/TAMPERED` 下仍可重设锚点。** 恢复码是显式逃生通道；旧见证已无法证明任何东西，拒绝重设等于让持有恢复码的用户永久失去访问权。实现上仅在恢复路径允许这样做，普通打开仍然 fail-closed。

配套的纵深措施：测试构建强制使用隔离状态目录；发布产物禁止包含测试状态注入字符串；E2E 必须验证隔离目录确实生效。

---

## 1. 事故与现场证据

### 1.1 现象

打开日常容器时返回 `ERR_00000019`，UI 显示“检测到文件回退，已拒绝打开”。口令正确，容器文件本身未损坏。

### 1.2 根因链

1. 历史真实 E2E 未隔离安全状态，创建并首次解锁了大量临时容器。每次临时容器创建收尾的元数据提交都会登记一条锚点，累计达到上限 64 条。
2. 发布收尾时为清理 E2E 污染，把生产 `rollback.state` 替换成了更早的 8 条备份。
3. 日常容器不在该 8 条备份中。`vty_rollback_check` 的规则是：状态存在但该库无条目，且容器 `generation >= 2`，一律按回退拒绝。
4. 因此返回 `VTY_E_ROLLBACK`，UI 显示文件回退。

该次故障是运维性状态替换失误，不是容器格式或加密链路缺陷；但它暴露了锚点表缺少生命周期这一结构性缺陷。

### 1.3 现场数据

| 项目 | 数值 | 说明 |
|---|---|---|
| 错误状态文件条目数 | 8 | 早期备份，缺少目标容器 |
| 发布前实时状态条目数 | 64 | 已达 `VTY_ROLLBACK_MAX_ENTRIES` 上限 |
| 目标容器 UUID | `bd57e2075aebf41ad74d9f4ee97f5aec` | 从容器头偏移 12 读取 |
| 目标容器最新 generation | 767 | 两份 meta 副本中较新的一份 |
| 实时状态中的目标条目 | gen=767，slot=1 | 与容器 generation 完全一致 |
| TPM 见证指纹核对 | 匹配 | 直接导出持久化公钥并计算 SHA-256 比对 |
| 已扫描范围内的日常容器 | 1 个 | 历史测试容器位于 `%TEMP%`，未逐条映射 |

### 1.4 应急处置

1. 备份错误的 8 条状态文件；
2. 恢复发布前实时状态；
3. 校验目标条目 `generation/slot` 与容器一致；
4. 枚举 TPM 持久化见证键，比对状态中的公钥指纹，确认见证存在且匹配；
5. 未改动容器、未删除任何 TPM 键。

### 1.5 教训

- **禁止**用任意旧备份替换 `rollback.state`。状态文件是安全状态，不是普通配置；替换前必须逐条核对目标容器的 UUID、generation 与见证指纹。
- 状态文件损坏或缺失时，唯一受支持的逃生通道是**恢复码**：`vty_vault_open_recovery` 路径会重设锚点并轮换见证。
- 测试污染必须在源头隔离，不能依赖事后手工清理。

---

## 2. 现有机制（代码事实）

### 2.1 状态布局与容量

状态文件位于 `KnownFolder(FOLDERID_LocalAppData)\Verthys\Security\rollback.state`，布局版本 2：

| 区域 | 大小 | 内容 |
|---|---|---|
| header | 16 B | magic `VTRB`、version=2、条目数、保留 |
| entries | 64 × 57 B | `uuid(16) + generation(8) + witnessSlot(1) + witnessFp(32)` |
| MAC | 32 B | HMAC-SHA256，覆盖 header + entries + 设备根 blob |
| device blob | 290 B | 设备根封装的 MAC 密钥 |

关键常量：`VTY_ROLLBACK_MAX_ENTRIES=64`、`RB_ANCHOR_MIN_GENERATION=2`。条目只增不减，没有删除、压缩或淘汰路径。

### 2.2 检查与提交时序

打开容器时：

1. 加载两份 meta 副本，选最新有效副本；
2. 用口令解封槽、打开 body；
3. `vty_rollback_check(uuid, generation)`；
4. `vty_rollback_commit(uuid, generation)`。

保存时：`vty_vault_save_meta` 在落盘后调用 `vty_rollback_commit`。普通创建流程在收尾阶段调用 `vty_module_table_init` + `vty_vault_save_meta`，此时 `generation` 由 1 递增到 2 并提交，因此**创建成功即登记锚点**。只有轮换临时库（`vty_vault_create_from_kc`）设置 `no_rollback_anchor=1` 抑制提交，最终由轮换提交更新同一 UUID 的锚点。

### 2.3 fail-closed 判定矩阵

| 条目 | 见证槽 | 容器 generation | 结果 |
|---|---|---|---|
| 不存在 | — | < 2 且无可用见证 | 首次运行，允许 |
| 不存在 | — | >= 2 或存在可用见证 | `VTY_E_ROLLBACK` |
| 存在 | 有效 | 见证指纹不符 / 缺失 | `VTY_E_ROLLBACK` |
| 存在 | 有效 | 见证匹配且 `gen >= stored` | 允许 |
| 存在 | 有效 | `gen < stored` | `VTY_E_ROLLBACK` |

### 2.4 见证密钥

- 名称：`VerthysWit_<witnessId 32 hex>_A|B`；`witnessId = SHA-256(domain || 设备根哈希 || 容器 UUID)`。
- 每次提交创建另一槽的新 ECC P-256 持久化密钥，写状态，再删除旧键；两槽交替保证崩溃窗口内仍可打开。
- `vty_tpm_witness_exists` 明确区分“不存在（0）”与“平台错误（-1）”，这是本方案自动回收的判定基础。

### 2.5 错误映射链

`VTY_E_ROLLBACK` → `VERTHYS_ERR_ROLLBACK (0x19)` → worker `ERR_00000019` → UI“检测到文件回退”。

容量耗尽发生在 `upsert`：`count >= 64` 返回 `VTY_E_RESOURCE`；`vty_rollback_commit` 把它与状态写失败一起折叠为 `VTY_E_ROLLBACK`，因此**容量问题被误报为回退攻击**。

### 2.6 测试隔离现状

- 生产构建 `VERTHYS_TEST_HOOKS=OFF`，不编译环境变量覆盖路径；开发/测试构建显式 `-DVERTHYS_TEST_HOOKS=ON`，并由 test_runner 设置隔离目录。G0A 预置/缓存提交路径已并入正式实现，不再是独立编译开关。
- E2E 已引入 `E2eStateGuard`，设置 `VERTHYS_TEST_STATE_DIR` 指向临时目录；注释明确“仅测试构建的 DLL 识别该变量”。
- 隔离要求与测试钩子分离：`VERTHYS_TEST_REQUIRE_ISOLATION=ON` 只用于自动化测试构建（`build_test`、CI），缺少隔离目录即拒绝初始化；dev 运行构建（`build_dev`、dev launcher 的 `build/core/Release`）保持测试钩子但不强制隔离，允许回落到生产状态路径，从而可以打开/创建用户真实容器。

### 2.7 生命周期缺口

| 阶段 | 现状 | 缺口 |
|---|---|---|
| 登记 | 创建收尾的元数据提交自动登记 | 无归属、无来源标记 |
| 推进 | 保存时推进 | 正常 |
| 失效 | 无判定 | 见证缺失、指纹不符、平台错误混在一起 |
| 释放 | 无 API | 删除容器、测试清理均无法释放 |
| 回收 | 无 | 表满即永久卡死 |
| 容量 | 折叠为回退 | 不可识别、不可操作 |

### 2.8 正常创建后删除容器的实际行为

1. 创建收尾调用 `vty_module_table_init` + `vty_vault_save_meta`，`generation` 由 1 递增到 2，`vty_rollback_commit` 新增条目并创建见证密钥。
2. 用户在资源管理器中删除 `.verthys` 文件：核心不会收到任何通知，`rollback.state` 条目与 TPM 见证保持不变。
3. 条目仍判定为 `ACTIVE`（见证存在、指纹匹配），不是 `DEAD`，因此自动回收不会处理它。
4. 结果：永久占用 1 个槽位，直到用户通过维护界面的授权释放显式删除条目。

这也是“正常用户创建后删除容器”同样会耗尽锚点表的原因；不是只有测试才会触发。

---

## 3. 问题定义

- **P0 误报与阻塞**：表满时新建容器在创建收尾提交阶段失败，UI 报“文件回退”，用户无法自行恢复。
- **P0 永久占位**：测试、迁移、异常退出产生的条目没有自动释放路径；**正常创建后删除容器同样不会自动释放**——删除文件不会通知核心，条目与 TPM 见证仍然存在，条目保持 `ACTIVE`。已通过维护面板的“扫描容器 + 显式释放”提供治理路径；不做基于文件不存在的自动删除，避免误删离线/归档容器的有效锚点。
- **P1 无可见性**：用户与支持人员看不到锚点数量、状态、对应容器。
- **P1 测试污染**：测试构建缺少强制隔离，历史污染无法防止复发。
- **P2 运维风险**：状态文件替换缺少核对流程，错误替换会直接锁死容器。

---

## 4. 目标、非目标与约束

### 4.1 目标

1. 产品路径不再产生“不可治理”的锚点：正常创建后删除容器可通过维护面板扫描并显式释放；不会自动删除仍可能有效的锚点。
2. 可证明失效的锚点自动回收；不确定或仍有效的锚点绝不自动删除。
3. 容量耗尽返回独立错误，并提供可执行的维护入口。
4. 释放操作有明确授权、审计与恢复路径说明。
5. 不改变容器格式、记录布局、`rollback.state` 布局与 TPM 槽数量。
6. 测试构建与生产状态彻底隔离，并有 CI 门禁防止回归。

### 4.2 非目标

- 不扩容到 64 以上；现场与正常使用均未证明需要。
- 不引入自动 LRU 淘汰有效锚点。
- 不做基于“容器文件不存在”的自动删除：离线磁盘、归档容器、未挂载介质都可能被误判。
- 不改变见证算法、密钥命名或两槽轮换协议。
- 不新增后台常驻服务。

### 4.3 约束

- 状态文件 MAC 只能由设备根解封的密钥计算，外部工具不得直接改写。
- 所有状态修改必须在 `Local\Verthys.RollbackState` 跨进程互斥量下完成。
- 失败必须 fail-closed，不得静默降级为“首次运行”。

---

## 5. 威胁模型与安全不变量

### 5.1 攻击者能力

- 可复制、替换、删除容器文件与 `rollback.state`；
- 可复制旧容器与旧口令，实施回放；
- 可创建大量容器制造容量压力；
- 不能伪造状态 MAC，不能导出 TPM 私钥，不能绕过调用方签名。

### 5.2 不变量

| 编号 | 不变量 |
|---|---|
| INV-1 | 校验通过必须同时满足：条目存在、引用合法见证槽（0/1）、见证指纹匹配、`generation >= stored`；或条目不存在且无见证且 `generation < 2`。字段非法的条目一律 fail-closed。 |
| INV-2 | 自动回收只允许处理“引用见证确定不存在”的条目；平台错误、指纹不符一律不自动处理。 |
| INV-3 | 状态修改必须经过 MAC 认证并原子替换；崩溃后磁盘上只能是旧状态或新状态。 |
| INV-4 | 容量耗尽必须返回独立错误，禁止静默丢弃任何条目。 |
| INV-5 | 自动化测试构建（`VERTHYS_TEST_REQUIRE_ISOLATION=ON`）不得使用生产状态目录；生产产物不得包含测试路径覆盖入口；dev 运行构建允许回落生产路径，测试入口必须自行注入隔离目录。 |
| INV-6 | 释放后当前状态不再引用该条目；见证删除失败必须审计并在后续维护重试，不得伪装成功。 |
| INV-7 | 释放前的授权必须来自显式用户操作；任何自动流程不得释放 `ACTIVE/TAMPERED/UNKNOWN`。 |
| INV-8 | 所有日志、审计、UI 不输出密钥材料、口令、恢复码或见证私钥。 |

---

## 6. 锚点生命周期

### 6.1 状态定义

| 状态 | 判定 | 允许动作 |
|---|---|---|
| `ABSENT` | 状态中无该 UUID 条目 | 首次运行判定；创建收尾提交登记 |
| `ACTIVE` | 条目存在，引用槽密钥存在，指纹匹配 | 正常校验/推进；仅授权释放 |
| `DEAD` | 条目存在，引用槽密钥确定不存在 | 自动回收；无需用户确认 |
| `TAMPERED` | 条目存在，槽密钥存在但指纹不符 | 校验拒绝；仅高级授权释放 |
| `UNKNOWN` | TPM 查询返回平台错误，或条目字段非法 | 不自动处理；维护界面提示重试 |

### 6.2 判定算法

```text
classify(entry):
    if slot >= 2 or fp is all-zero: return UNKNOWN
    probe = witness_probe(wid(uuid), slot, fp)
    switch probe:
        MATCH          -> ACTIVE
        MISSING        -> DEAD
        MISMATCH       -> TAMPERED
        PLATFORM_ERROR -> UNKNOWN
```

约束：

- `DEAD` 只由“确定不存在（MISSING）”得出；平台错误必须保持 `UNKNOWN`。
- `TAMPERED` 只由“键存在但公钥指纹不符（MISMATCH）”得出，不得由平台错误折叠。
- 不得用 `any_usable` 代替单槽判定；两槽轮换期间另一槽可能是预置键或崩溃残留。
- `TAMPERED` 是回退/篡改证据，不自动回收，避免攻击者通过覆盖密钥释放槽位。

### 6.3 状态迁移

| 起点 | 事件 | 终点 |
|---|---|---|
| `ABSENT` | 创建收尾的元数据提交成功（generation=2） | `ACTIVE` |
| `ACTIVE` | 保存推进并轮换见证 | `ACTIVE` |
| `ACTIVE` | 见证被外部删除/TPM 清除 | `DEAD` |
| `ACTIVE` | 状态被旧副本替换且指纹不符 | `TAMPERED` |
| `DEAD` | 自动回收或授权释放 | `ABSENT` |
| `TAMPERED` | 高级授权释放 | `ABSENT` |
| `ACTIVE` | 授权释放 | `ABSENT` |

---

## 7. 淘汰策略

### 7.1 三级策略

**Tier 0：自动回收 `DEAD`（无用户交互）**

- 触发点：`commit`/`reset_anchor` 需要新增条目且 `count == 64`；维护界面“回收失效”调用 `Verthys_RollbackAnchorReclaim`。
- 动作：在锁内压缩条目、`store()` 原子写回；解锁后再尽力删除残留见证键。
- 安全性：`DEAD` 条目在任何情况下都无法通过校验，回收不改变任何容器的可用性。
- 限制：单次最多检查 64 条；`UNKNOWN/TAMPERED` 原样保留。
- 关键顺序：只有状态 `store()` 成功后才会删除见证；状态未落盘时绝不删除任何键。

**Tier 1：授权释放 `ACTIVE/TAMPERED`（显式用户操作）**

- 入口：中枢 → 安全防护 → 回退锚点面板 → 扫描/选择条目 → 释放。
- 前提：用户已完成容器扫描；界面展示 UUID 短名、generation、见证状态、匹配路径。
- 确认：必须二次确认，明确告知“若容器仍存在，之后打开需要恢复码重新建立锚点”。
- 动作：锁内删除条目、`store()`、随后删除两个槽的见证键；写入审计。
- 禁止：任何自动流程、后台任务、测试代码调用该路径。

**Tier 2：不自动淘汰 `ACTIVE`**

- 即使表满，也不得自动删除 `ACTIVE` 条目。
- 理由见 7.2。
- 表满且无可回收 `DEAD` 时，返回 `VERTHYS_ERR_ANCHOR_FULL`，由 UI 引导维护。

### 7.2 为什么不做自动 LRU

1. 删除 `ACTIVE` 条目后，容器仍存在时，下次打开会因“条目缺失且 generation>=2”被 fail-closed 拒绝；唯一恢复路径是恢复码。若用户丢失恢复码，密码正确也无法打开，等同于数据丢失。
2. “长期未使用”不等于“已废弃”。离线磁盘、归档容器、迁移中的容器都会长期不打开。
3. 容量压力来自泄漏，不来自正常使用。先修复泄漏与回收，再评估是否需要淘汰策略。
4. 若未来确有证据需要自动淘汰，正确的前置改造是把 generation 编码进 TPM 见证键名称，使表成为缓存、锚点可从 TPM 重建；在该改造完成前，不引入自动淘汰。

### 7.3 容量策略

| 场景 | 行为 |
|---|---|
| 新增条目（创建收尾提交或恢复码重设）且 `count < 64` | 正常登记 |
| 新增条目且 `count == 64`，存在 `DEAD` | 自动回收后重试一次 |
| 新增条目且 `count == 64`，无可回收条目 | `VTY_E_ANCHOR_FULL` |
| 更新已有条目 | 不受容量影响，始终允许 |
| 恢复码重设已有条目 | 不受容量影响 |
| 恢复码重设缺失条目且表满，存在 `DEAD` | 自动回收后重试一次 |
| 恢复码重设缺失条目且表满，无可回收条目 | `VTY_E_ANCHOR_FULL`，UI 提示先释放锚点 |

`VTY_E_ANCHOR_FULL` 必须在所有路径上与 `VTY_E_ROLLBACK` 分离，禁止折叠。

### 7.4 释放的授权与审计

- 授权模型：本机用户通过已签名应用显式操作；核心层不提供静默调用路径。
- C API 增加 `flags` 参数，调用方必须置位确认位；未置位返回 `VTY_E_INVALID`，防止误调用。
- 审计事件：`RollbackAnchorRelease`，字段为 UUID 哈希、generation、见证状态、结果、失败原因；不记录路径明文。
- 释放失败：状态写失败返回错误且不删除见证；见证删除失败返回成功但审计警告，并在下次维护重试。

### 7.5 释放后的恢复路径

- 容器仍存在时：普通解锁返回 `VTY_E_ROLLBACK`；UI 检测到该 UUID 无锚点后，提示“锚点未登记或已释放”，引导使用恢复码解锁。
- 恢复码解锁成功：`vty_rollback_reset_anchor` 重设锚点并轮换见证；**见证缺失（DEAD）或指纹不符（TAMPERED）时同样允许重设**。恢复码已证明用户持有恢复槽，拒绝重设只会让用户永久失去访问权。
- 重设成功后普通口令可正常打开；非当前槽的残留键由启动清理或本次恢复的 stale 清理删除。
- 恢复码解锁同样受容量约束；表满时先回收/释放。

### 7.6 未来可选的结构性升级（不在本次实施）

若未来容量压力被证明无法通过生命周期治理消除，可考虑：

- 将 generation 编码进 TPM 见证键名称（如 `VerthysWit_<uuid>_<gen>_<slot>`），使锚点可从 TPM 重建；
- 届时 `rollback.state` 退化为缓存，任意条目可安全淘汰；
- 需要迁移全部旧见证键、修改命名与枚举逻辑、重新做崩溃与安全评审，风险显著高于本次方案。

本次明确不实施该升级。

---

## 8. 核心算法与崩溃安全

### 8.1 check（语义不变）

```text
check(uuid, gen):
    init(); lock()
    load_authenticated()
    if missing:
        allow only if any_usable(uuid)==0 and gen < 2
    else:
        idx = find(uuid)
        if idx < 0:
            allow only if any_usable(uuid)==0 and gen < 2
        else:
            if slot not in {0,1}: reject          // 字段非法 fail-closed
            verify witness fingerprint (cache 命中也复核公钥)
            reject if gen < stored
    on success: cleanup stale other slot + schedule pool
    unlock()
```

`check` 不处理容量、不触发回收；校验成功后会清理非当前槽残留键并调度预置池（既有语义）。

### 8.2 commit（增加容量语义）

```text
commit(uuid, gen):
    init(); lock(); load_authenticated()
    idx = find(uuid)
    if idx < 0:
        if any_usable(uuid) != 0: reject
        removed = []
        if count >= 64:
            removed = collect_dead_locked(buf)    // 只改内存，不写盘/不删键
            if removed == 0: unlock(); return ANCHOR_FULL
            invalidate_dead_pool_locked(removed)
        create witness; upsert; store             // 一次原子写
        if store fails: delete new witness; unlock(); return ROLLBACK
        retire old (首次提交无旧键)
    unlock()
    delete_dead_witnesses(removed)                // 状态落盘后才删键
```

关键点：

- 回收只修改内存；只有本次 `store` 成功后才删除 DEAD 条目的见证，避免“状态未落盘却删了真实键”。
- 状态写失败仍返回 `VTY_E_ROLLBACK`，因为无法证明锚点已推进。
- 回收与提交在同一把锁内完成；DEAD 见证删除在解锁后执行，避免长时间占用跨进程互斥量。
- `upsert` 若仍返回容量错误，清理新键并返回 `VTY_E_ANCHOR_FULL`（防御性分支）。

### 8.3 collect_dead_locked / reclaim

```text
collect_dead_locked(buf):
    removed = []; keep = []
    for e in entries:
        if slot valid and witness_exists(slot) == 0:
            removed.push(e.uuid)
        else:
            keep.push(e)
    compact(buf, keep); buf.count = keep.size; zero tail
    return removed                              // 不写盘、不删键

reclaim(flags):
    require CONFIRM
    lock(); load_authenticated()
    removed = collect_dead_locked(buf)
    if removed.empty: unlock(); return OK(0)
    invalidate_dead_pool_locked(removed)
    if store(buf) != OK: unlock(); return IO   // 不删任何见证
    unlock()
    delete_dead_witnesses(removed)             // best-effort，失败计数返回
```

### 8.4 release

```text
release(uuid, flags):
    require CONFIRM
    lock(); load_authenticated()               // 状态缺失时按“条目不存在”处理
    idx = find(uuid)
    invalidate pool for both slots
    if idx >= 0:
        remove entry; count--; zero tail
        if store(buf) != OK: unlock(); return IO   // 条目仍在，见证未动
        released = 1
    unlock()
    delete both witness slots                  // 幂等；失败写 cleanup_failed
    return OK
```

顺序说明：先写状态、后删见证。状态写失败时条目仍在、见证未动；见证删除失败时条目已释放，返回 `cleanup_failed=1`，调用方可对同一 UUID 重试释放（幂等）。

### 8.5 list

```text
list():
    lock(); load_authenticated()
    if missing: unlock(); return 0 + state=ABSENT
    snapshot = copy(entries)                   // 只复制，不做 TPM 探测
    unlock()
    for each snapshot entry: probe -> ACTIVE/DEAD/TAMPERED/UNKNOWN
    return entries + witness_state + count
```

只读；状态缺失与损坏分别以 `state=0` 和 `VTY_E_CORRUPT` 返回；平台错误以 `UNKNOWN` 返回，不中断整个列表。TPM 探测在锁外执行，避免维护面板刷新阻塞打开/保存。

### 8.6 锁与预算

- 全部操作使用现有 `Local\Verthys.RollbackState` 互斥量，超时 5 秒。
- `list` 在锁内只复制快照，锁外最多 64 次 probe（每次 probe 打开一次键并导出公钥）。
- `reclaim` 在锁内压缩 + 一次 `store`，锁外删除见证；`release` 同样锁外删键。
- 不得在持锁期间执行文件扫描、UI 回调或网络操作。

### 8.7 崩溃窗口

| 操作 | 崩溃点 | 磁盘结果 | 后续行为 |
|---|---|---|---|
| 回收 | `store` 前 | 旧状态 | 下次重试 |
| 回收 | `store` 后、删键前 | 新状态，残留键 | 无害；可再次 Reclaim/Release 清理 |
| 释放 | `store` 前 | 旧状态，见证未动 | 操作失败，可重试 |
| 释放 | `store` 后、删键前 | 已释放，残留键 | `cleanup_failed=1`；对同一 UUID 重试释放 |
| 提交 | 建新键后、写状态前 | 旧状态，孤儿新键 | 旧状态仍可打开；孤儿不影响任何锚点判定 |
| 提交 | 写状态后、删旧键前 | 新状态，旧键残留 | 正常；旧键后续删除 |

---

## 9. 接口设计

### 9.1 C API（新增，追加式）

```c
typedef struct VerthysAnchorInfo {
    uint32_t struct_size;        /* 调用方检查；库写出 sizeof(VerthysAnchorInfo) */
    uint8_t  uuid[16];
    uint64_t generation;
    uint32_t witness_state;      /* 0=unknown, 1=active, 2=dead, 3=tampered */
    uint32_t reserved;
} VerthysAnchorInfo;

VERTHYS_API VerthysResult VERTHYS_CALL Verthys_RollbackAnchorList(
    VerthysHandle handle,
    VerthysAnchorInfo *out_anchors,   /* NULL + capacity=0 时仅查数量 */
    uint32_t capacity,
    uint32_t *out_count,
    uint32_t *out_state);             /* 0=absent, 1=ok, 2=corrupt, 3=unknown */

VERTHYS_API VerthysResult VERTHYS_CALL Verthys_RollbackAnchorReclaim(
    VerthysHandle handle,
    uint32_t flags,                   /* bit0=CONFIRM，必须置位 */
    uint32_t *out_removed,
    uint32_t *out_cleanup_failed);

VERTHYS_API VerthysResult VERTHYS_CALL Verthys_RollbackAnchorRelease(
    VerthysHandle handle,
    const uint8_t uuid[16],
    uint32_t flags,                   /* bit0=CONFIRM，必须置位 */
    uint32_t *out_released,           /* 1=删除，0=不存在（幂等） */
    uint32_t *out_cleanup_failed);
```

要求：

- 新符号必须加入 `core/verthys.def` 白名单；
- API 版本递增到 `0x0016`；
- 新接口与其他导出函数一样受发布者签名门约束；未启用签名门的构建不提供虚假授权保证；
- 旧调用方不受影响；新调用方按版本宏判断可用性。

### 9.2 错误码与 ABI

| 层 | 常量 | 值 | 说明 |
|---|---|---|---|
| 内部 | `VTY_E_ANCHOR_FULL` | 枚举尾部（24） | 锚点表满且无可回收条目 |
| 公共 | `VERTHYS_ERR_ANCHOR_FULL` | `0x00000021` | 追加在现有最大码之后 |
| worker | `VERTHYS_ERR_ANCHOR_FULL` | `0x00000021` | 已加入“不折叠为 AUTH”白名单 |
| UI | `E_ANCHOR_FULL` | 对应上述码 | 显示容量与维护入口 |

禁止复用或插入已有值；错误码只允许在枚举尾部追加。

### 9.3 worker 协议

新增 op：

```json
{"op":"rollback_anchor_list"}
{"op":"rollback_anchor_reclaim","anchor_confirm":true}
{"op":"rollback_anchor_release","uuid":"hex32","anchor_confirm":true}
```

说明：锚点确认字段命名为 `anchor_confirm`，与模块删除的字符串 `confirm` 字段分离，避免类型/语义冲突。

响应：

```json
{"ok":true,"op":"rollback_anchor_list","anchors":[{"uuid":"...","generation":767,"witness":"active"}],"anchor_state":1}
{"ok":true,"op":"rollback_anchor_reclaim","anchor_removed":1,"anchor_cleanup_failed":0}
{"ok":true,"op":"rollback_anchor_release","anchor_released":1,"anchor_cleanup_failed":0}
```

约束：

- `uuid` 必须是 32 位十六进制；非法输入返回 `INVALID`；
- `anchor_confirm` 缺失或为 false 时返回 `INVALID`；
- 响应不包含见证指纹、私钥、路径或任何密钥材料；
- `ERR_00000021` 在 worker 错误码白名单中透传，不折叠为 AUTH。

### 9.4 host 命令与扫描

命令（实际注册名）：

- `verthys_rollback_anchor_list`：调用 worker，返回条目与状态；
- `verthys_rollback_anchor_reclaim`：要求 `confirm=true`，调用 worker 回收 DEAD，写审计；
- `verthys_rollback_anchor_release`：要求 `confirm=true` 且 UUID 为 32 位十六进制，调用 worker 释放，写审计；
- `verthys_rollback_anchor_scan`：用户选择根目录后扫描容器，返回 `uuid -> paths`、扫描文件数、是否截断、权限错误数。

扫描规则（已实现）：

- 只读容器头前 76 字节，校验 magic、主版本、`header_len`，从偏移 12 读取 UUID；
- 支持 `.verthys` 与 `.vty`，以文件头 magic 为准；
- 跳过重解析点/符号链接，限制深度 8、文件数 200,000、根目录数 32；返回截断标志；
- 权限错误计数并展示，不视为“文件不存在”；
- 同一 UUID 多个路径时全部展示（每个 UUID 最多 32 条），不自动选择；
- 扫描结果只是证据，不是删除依据；释放必须由用户显式确认。

### 9.5 UI 交互（已实现）

**回退锚点面板（中枢 · 安全防护）**

- 组件：`AnchorManagementPanel.vue` 嵌入 `SecurityDashboard.vue`，位于 `def-board`（动态防护）之后、`flow-rail`（数据流转）之前。
- 顶部读数：`已用 X / 64`、可回收数、见证异常数、状态文件状态。
- 列表：最多 8 条预览；完整列表在 `AnchorManagerDialog.vue`。
- 操作：刷新、扫描与释放、回收失效；面板不直接删除任何锚点。
- 空态：区分“状态文件不存在”“状态文件损坏”“暂无锚点”。

**详情弹窗（`AnchorManagerDialog.vue`）**

- 展示全部锚点、UUID 短名、generation、见证状态、扫描证据；
- 展示扫描摘要：文件数、命中数、权限错误、是否截断；
- 展示“扫描到但未登记 UUID”的独立区块；
- 释放必须勾选条目并二次确认；确认文案明确“容器仍存在时需要恢复码重建锚点”；
- 回收失效仅在存在 DEAD 时可用，并明确 ACTIVE/TAMPERED/UNKNOWN 不会被删除。

**容量错误**

- 创建失败且错误为 `ANCHOR_FULL` 时，前端错误映射显示“本机回退锚点表已满”，引导进入安全防护清理；
- 禁止显示“检测到文件回退”。

**回退错误分流**

- 收到 `E_ROLLBACK` 时，宿主可扫描容器头获取 UUID 并查询锚点状态：
  - 无条目：提示“锚点未登记或已释放”，提供恢复码解锁；
  - 有条目：提示文件回退/见证异常，提供恢复码解锁与支持入口；
  - 状态文件缺失/损坏：单独提示，不伪装成“首次运行”或普通回退。

### 9.6 审计字段

| 事件 | 字段 |
|---|---|
| `RollbackAnchorRelease` | `uuid_hash`（resource_hash）、`released`、`cleanup_failed`、`result` |
| `RollbackAnchorReclaim` | `removed`、`cleanup_failed`、`result` |
| `RollbackAnchorScan` | `files_seen`、`matched`、`truncated`、`permission_errors`、`result` |

不记录：完整路径、见证指纹、恢复码、口令。

说明：自动回收发生在 `commit`/`reset_anchor` 内部，C 层不直接写宿主审计；用户主动触发的 Reclaim/Release 由宿主审计，并把见证清理失败计数写入 detail。自动回收的见证删除为 best-effort；失败只留下不被状态引用的孤儿键，不影响任何锚点判定。

---

## 10. 兼容性与迁移

- **布局不变**：继续使用版本 2 的 64 × 57 B 条目与现有 MAC 布局；无迁移、无降级转换。
- **旧状态兼容**：现有 64 条状态可直接被新代码读取；新增 API 只做判定、压缩与删除。
- **旧见证兼容**：不改密钥命名与两槽轮换；释放时按现有 `witnessId` 计算并删除两槽。
- **ABI**：只追加导出与错误码；API 版本 0x0016；旧调用方忽略新符号即可。
- **降级**：新版本释放过的条目在旧版本中表现为 `ABSENT`；旧版本遇到容量耗尽仍会报 `E_ROLLBACK`。因此发布物必须整体升级（DLL、worker、host、UI 同步），不支持只降级单个组件。
- **释放语义**：条目删除后旧版本表现为 `ABSENT`；释放同时删除两槽见证。状态写失败不会删见证，返回 `VERTHYS_ERR_IO`。
- **状态文件回滚**：旧状态副本缺少新条目时，相关容器会 fail-closed；恢复码是唯一逃生通道。运维禁止手工替换状态文件（见第 15 节）。

---

## 11. 安全分析

### 11.1 攻击场景与响应

| 场景 | 结果 |
|---|---|
| 回放旧容器 | 见证指纹不符或 generation 低于锚点 → 拒绝 |
| 回放旧 `rollback.state` | 条目引用的见证已轮换/删除 → 拒绝；若状态完全未变则与当前状态等价 |
| 删除 `rollback.state` | 见证仍存在或 generation>=2 → 拒绝；恢复码可重设 |
| 删除见证键 | 条目变为 `DEAD`，容器被拒绝；自动回收只释放槽位，不放行容器；恢复码可在 DEAD 下重设锚点 |
| 覆盖见证键伪造指纹 | 条目变为 `TAMPERED`，拒绝且不自动回收；恢复码可显式重设 |
| 填满 64 条制造 DoS | 新容器返回 `ANCHOR_FULL`；用户可扫描并释放废弃条目 |
| 误释放仍存在的容器 | 该容器需恢复码重新建立锚点；不会静默接受回退副本 |
| 释放时状态写失败 | 返回 `ERR_IO`，条目与见证保留 |
| 释放时见证删除失败 | 条目已释放，返回 `cleanup_failed=1`；对同一 UUID 重试释放幂等 |
| 未启用发布者签名门的构建 | 释放/回收 API 不提供强授权保证；生产发布必须开启调用方签名门 |

### 11.2 不变量核对

- INV-1：`check` 的容量无关语义不变；新增“非法见证槽 fail-closed”，缓存命中也复核公钥。
- INV-2：`classify` 只在 `MISSING` 时返回 `DEAD`；`PLATFORM_ERROR` 保持 `UNKNOWN`；`MISMATCH` 返回 `TAMPERED`。
- INV-3：复用 `store()` 的临时文件 + `MoveFileEx` 原子替换；回收与释放均先写状态。
- INV-4：容量错误独立返回；`commit` 不静默丢条目。
- INV-5：自动化测试构建缺少隔离目录时拒绝初始化；dev 运行构建回落生产路径；构建后扫描生产 DLL 的测试状态注入字符串。
- INV-6：释放后状态不再引用；见证删除失败返回 `cleanup_failed`，调用方可重试。
- INV-7：释放只能由显式 API + `CONFIRM` 位触发；自动回收只处理 `DEAD`。
- INV-8：API 与审计不返回密钥材料；UI 只展示 UUID 短名与状态。

### 11.3 残余风险

1. 同一用户会话的恶意进程可删除容器或状态文件；现有 ACL 已记录该边界，本文不扩大。
2. 扫描是有限范围证据；未扫描到的容器可能被误判为废弃。UI 使用“未在扫描范围内找到”的措辞，并要求显式确认。
3. 释放是不可逆的用户操作；恢复码丢失时容器无法恢复。文档与 UI 必须明确告知。
4. TPM 平台错误会阻止自动回收；这是 fail-closed 的有意取舍。
5. 自动回收（commit/reset 内部）的见证删除为 best-effort，失败只留下不被状态引用的孤儿键；用户主动 Reclaim/Release 会返回清理失败计数，可重试。
6. 未启用发布者签名门的构建中，Release/Reclaim 只依赖 CONFIRM 位，不构成强授权边界；生产构建必须开启调用方签名门。
7. 用户主动释放 `TAMPERED` 会删除两槽见证，可能销毁篡改证据；UI 必须在确认文案中明确这一点，并建议先联系支持。
8. **dev 构建/多实例（已发生）**：dev 路径解析曾固定加载 `build/core/Release` 的签名 caller-auth ON DLL，且 `build_dev` 的 CMake 参数未展开导致 test-hooks ON；未签名 dev worker 被拒绝。随后 Debug 宿主又用**生产 DLL 哈希基线**拒绝 `build_dev` DLL（`expected=6168… actual=6667…`），且 worker 解析优先 Release worker。已修复为：Debug 宿主优先 `build_dev/core/Debug`（caller-auth OFF、test-hooks OFF）、dev DLL 跳过生产哈希基线、Debug worker 优先；Release/生产校验保持不变。完整测试使用独立 `build_test`。跨构建状态互读已验证；残余风险是多实例共享同一状态/容器，发布前应增加单实例/状态写者保护。

---

## 12. 可观测性

- 面板展示：条目总数、`DEAD/TAMPERED/UNKNOWN` 数量、状态文件状态；扫描摘要（文件数、命中数、权限错误、截断）在弹窗中展示。
- 诊断接口可返回锚点计数与状态汇总，不返回指纹。
- 审计链沿用现有 HMAC 结构，事件追加不破坏链。
- 发布后首周重点观察：`ANCHOR_FULL` 次数、自动回收条数、释放失败次数、见证清理失败次数。

---

## 13. 测试与验收

### 13.1 单元测试

| 编号 | 场景 | 期望 |
|---|---|---|
| T-01 | 64 条 `ACTIVE`，创建新容器 | `ANCHOR_FULL`，无新条目、无孤儿见证 |
| T-02 | 64 条中 1 条 `DEAD`，创建新容器 | 自动回收后成功，仍为 64 条 |
| T-03 | 1 条 `TAMPERED`，表满 | 不回收，`ANCHOR_FULL` |
| T-04 | TPM 查询返回 `-1` | 视为 `UNKNOWN`，不回收 |
| T-05 | 释放 `ACTIVE` 条目 | 条目删除、两槽见证删除、计数 63 |
| T-06 | 重复释放同一 UUID | 幂等成功，计数不变 |
| T-07 | 释放时状态写失败 | 条目保留，见证保留，返回错误 |
| T-08 | 释放后见证删除失败 | 条目已删除，审计警告，下次重试 |
| T-09 | 恢复码重设已有条目 | 不受容量影响 |
| T-10 | 恢复码重设缺失条目且表满 | `ANCHOR_FULL` |
| T-11 | 状态 MAC 损坏 | 列表/释放/回收均 fail-closed，不修改文件 |
| T-12 | DEAD 条目 + 恢复码 | 恢复码成功重设锚点，之后普通解锁成功 |
| T-13 | TAMPERED 条目 + 恢复码 | 恢复码成功重设锚点，之后普通解锁成功 |
| T-14 | 列表分类 | ACTIVE/DEAD/TAMPERED 分别正确；平台错误为 UNKNOWN |
| T-15 | 释放 ACTIVE | 仅删除选中条目与两槽见证，其他条目/见证保留 |
| T-16 | Reclaim | 只删除 DEAD，ACTIVE 保留 |
| T-17 | 自动化测试构建（`VERTHYS_TEST_REQUIRE_ISOLATION=ON`）无隔离目录 | 初始化返回 `VTY_E_POLICY`，不触碰生产目录；dev 运行构建不在本用例范围 |
| T-18 | 公共错误映射 | 容量耗尽返回 `VERTHYS_ERR_ANCHOR_FULL`，不折叠为 ROLLBACK |
| T-19 | 见证删除失败 | 条目已释放，`cleanup_failed=1`，可重试 |

### 13.2 故障注入

- `store` 前/后终止进程，验证磁盘状态为旧或新，且下次启动行为正确；
- 见证创建后终止，验证孤儿键不影响旧状态打开；
- 见证删除失败注入，验证释放结果与审计；
- 并发两进程同时申请新锚点，验证一个成功、一个 `ANCHOR_FULL`，无重复条目。

### 13.3 E2E

- C 单测通过逻辑容量注入（`vty_rollback_set_max_entries_for_test`）在少量真实 TPM 键下覆盖容量/回收分支；生产逻辑仍使用固定 64 条。
- 真实 64 条现场清理按第 15 节运维规程执行；清理后新建容器验证容量恢复。
- 释放后重新打开该容器，普通解锁返回 `E_ROLLBACK`，恢复码解锁成功并重建锚点。
- `worker_native_staged_smoke_e2e` 在 `v4_create` 后断言隔离目录中生成 `rollback.state`，证明测试钩子真实生效。
- 真实 TPM 上完整执行列表、释放、重开由发布前现场验收覆盖。

### 13.4 UI 与门禁

- 错误映射：`0x21` 不得显示为文件回退；
- `AnchorManagerDialog.spec.ts` 覆盖四种见证状态、勾选 + 二次确认、DEAD 回收门槛、扫描证据与“未在扫描范围内找到”措辞；
- `vue-tsc --noEmit`、`vitest run`、宿主与 worker 全量测试、C 全量测试、文档门禁。
- 构建后门禁：生产 DLL 不得包含 `VERTHYS_TEST_STATE_DIR`；自动化测试构建缺少隔离目录时拒绝初始化；dev 运行构建必须能访问真实状态且不改变生产校验口径。

### 13.5 验收判据

1. 现场 64/64 可被清理到仅保留实际容器；
2. 清理后可成功创建新容器；
3. 任何 `ACTIVE` 条目在无用户确认时数量不减少；
4. 容量耗尽不再出现 `ERR_00000019`；
5. 测试构建未设置隔离目录时拒绝运行，生产产物不含测试覆盖字符串；
6. 全部既有测试通过，无新增 fail-closed 误伤；
7. `DEAD/TAMPERED` 条目持有恢复码时仍可重设锚点。

---

## 14. 实施计划与状态

> 本节是唯一实施状态来源；完成一项即更新状态与证据。

### 14.1 阶段

| 阶段 | 内容 | 状态 |
|---|---|---|
| P0 | 内部/公共错误码、映射、worker 白名单、UI 错误分流 | 已完成 |
| P1 | 四态 probe、生命周期判定、`DEAD` 自动回收、容量预检、DEAD/TAMPERED 恢复 | 已完成 |
| P2 | C API `List/Reclaim/Release`、`.def` 白名单、API 版本递增 0x0016 | 已完成 |
| P3 | worker op、host 命令、扫描器、审计事件 | 已完成 |
| P4 | 中枢安全防护面板、容量错误引导、恢复码分流 | 已完成 |
| P5 | 测试构建强制隔离、发布产物字符串门禁、E2E 隔离断言 | 已完成 |
| P6 | 全量测试、现场清理、发布 | 现场清理完成（64→1）；dev 构建修复完成（Debug DLL + hooks OFF + 独立 build_test）；dev 安全核心启动修复完成（dev DLL 哈希豁免 + Debug worker）；跨构建状态互读已验证；生产发布待执行（建议先加单实例保护） |

### 14.2 文件级改动清单

**C 核心**

- `core/src/crypto/vty_types.h`：追加 `VTY_E_ANCHOR_FULL`
- `core/src/security/tpm/vty_tpm_witness.h/.c`：`vty_tpm_witness_probe` 四态探测、测试注入
- `core/src/security/rollback/vty_rollback.h/.c`：`classify`、`collect_dead_locked`、`reclaim`、`release`、`list`、容量分支、DEAD/TAMPERED 恢复、池作废
- `core/src/api/verthys_api_container.c`、`core/src/api/lifecycle/verthys_api.c`：公共 API 与错误映射
- `core/include/verthys.h`、`core/include/verthys_version.h`、`core/verthys.def`：新 API 与版本
- `core/tests/security/test_rollback.c`、`core/tests/test_runner.c`：T-01..T-19 与故障注入

**worker**

- `verthys-tauri/verthys-worker/src/runtime/ffi_types.rs`：锚点 FFI 结构与函数指针、ABI 布局测试
- `verthys-tauri/verthys-worker/src/runtime/protocol.rs`：`anchor_confirm`、响应字段、0x21 白名单
- `verthys-tauri/verthys-worker/src/runtime/worker.rs`：List/Reclaim/Release FFI 调用
- `verthys-tauri/verthys-worker/src/runtime/dispatch.rs`：新 op 与 UUID 解析

**host**

- `verthys-tauri/src-tauri/src/controller/rollback_anchor_controller.rs`：命令、扫描、审计
- `verthys-tauri/src-tauri/src/infrastructure/path_resolver.rs`：Debug 宿主优先 `build_dev/core/Debug` DLL、dev DLL 跳过生产哈希基线、Debug worker 优先
- `verthys-tauri/src-tauri/src/controller/types.rs`：锚点响应结构
- `verthys-tauri/src-tauri/src/lib.rs`：命令注册
- `verthys-tauri/src-tauri/src/util/audit_log.rs`：锚点审计事件

**前端**

- `verthys-tauri/src/components/management/AnchorManagementPanel.vue`：锚点面板
- `verthys-tauri/src/components/management/AnchorManagerDialog.vue`：扫描、列表、释放/回收确认
- `verthys-tauri/src/components/management/SecurityDashboard.vue`：面板挂载
- `verthys-tauri/src/lib/verthys.ts`、`src/types/verthys.ts`：IPC 包装与类型
- `verthys-tauri/src/utils/verthys-error-i18n.ts`、`src/lib/verthys_error.ts`、`src/key/global-verthys.ts`：`E_ANCHOR_FULL` 与回退分流
- `verthys-tauri/src/components/management/AnchorManagerDialog.spec.ts`：交互契约测试

**CI/发布**

- `build_production.ps1`：构建后扫描生产 DLL 的 `VERTHYS_TEST_STATE_DIR`；显式 `VERTHYS_TEST_REQUIRE_ISOLATION=OFF`
- `ci/release_preflight.ps1`：发布前扫描既有 Release DLL
- `scripts/build/build_core.dev.ps1`：dev 默认 `build_dev`（test-hooks ON、强制隔离 OFF，P2 机器预算旁路必需）；`-TestHooks` 构建 `build_test` 并运行隔离测试（强制隔离 ON）
- `scripts/build/build_core.release.ps1`：`-RequireTestIsolation` 供自动化测试构建使用，必须与 `-TestHooks` 同时开启
- `verthys-tauri/src-tauri/src/worker/e2e_measure.rs`：隔离目录生效断言

### 14.3 风险与回退

| 风险 | 控制 |
|---|---|
| TPM 探测拖慢提交 | 仅在表满时触发；单次上限 64；列表探测在锁外执行 |
| 回收误删有效条目 | 仅 `DEAD`（`exists==0`）；`UNKNOWN/TAMPERED` 不自动处理；状态落盘后才删见证 |
| 释放误操作 | 二次确认、`CONFIRM` 位、审计、恢复码说明；扫描证据仅作参考 |
| 状态写失败 | 复用原子替换；失败不删见证，返回 IO |
| 释放/回收后见证删除失败 | 返回 `cleanup_failed`；对同一 UUID 重试释放幂等 |
| UI 扫描范围误导 | 使用“未在扫描范围内找到”；展示截断与权限错误 |
| 恢复码在 DEAD/TAMPERED 下失效 | 已修复：恢复路径允许忽略旧见证校验并重设锚点 |
| 测试污染 | 开发构建显式启用测试钩子但强制隔离 OFF；自动化测试构建强制隔离 ON，无隔离目录拒绝初始化；生产构建扫描注入字符串 |
| 未开启调用方签名门的构建 | 生产发布必须开启；文档明确 Release/Reclaim 的授权边界 |
| 降级不兼容 | 整包升级；发布说明标注新错误码 0x21 |

---

## 15. 运维手册

### 15.1 本机 64/64 清理（已执行，2026-11-20）

> 现场结果：64 → 1。最终由与桌面应用（`C:\Users\Administrator\Desktop\新建文件夹\Verthys\Verthys.exe`）同设备根密钥的 Debug DLL 执行：回收 63 条 `DEAD`，`cleanup_failed=0`；保留 `bd57e2075aebf41ad74d9f4ee97f5aec`（gen=6594，slot=0，ACTIVE；容器 `C:\Users\Administrator\Desktop\.Verthys.V4\Vault.verthys`，头部最新 generation 同为 6594）。清理前备份：`%LOCALAPPDATA%\Verthys\Security\cleanup-20261120-050053\rollback.state`，SHA-256 `632D6175D48AC6052A7B8BEFCC251E0549D8E91A3A4C092CB99178DA3C407381`。清理后 `rollback.state` 仍为 3986 字节、version=2、count=1。
>
> **事件**：第一次使用签名 Release 维护 worker 写出的状态在隔离目录中由 caller-auth OFF 的 test-hook DLL 读取成功（`list_rc=0, count=1, state=1`），桌面应用（caller-auth ON）随后也成功读写同一状态（gen 6594→6600）。因此**不存在设备根密钥不兼容**；先前 `E_ROLLBACK` 来自同一状态被多个应用实例/旧进程并发使用及状态世代/进程缓存不一致。关闭多余 dev 实例并协调状态后应用恢复；详见第 18 节。维护用临时 worker/DLL 已移除；未替换 `C:\Program Files\Verthys` 下的已安装应用。

1. 完全退出应用，备份 `%LOCALAPPDATA%\Verthys\Security\rollback.state`；
2. 启动新版本，进入中枢 → 安全防护 → 回退锚点；
3. 扫描桌面、文档、下载与容器实际所在目录；
4. 核对实际容器 UUID 与路径；其余条目确认“未在扫描范围内找到”；
5. 先点击“回收失效”，清理所有 `DEAD` 条目；`ACTIVE/TAMPERED/UNKNOWN` 会保留；
6. 对确认废弃的 `ACTIVE` 条目，逐个勾选并阅读后果说明，完成二次确认；
7. 确认状态为：仍在使用中的容器各有 1 条 `ACTIVE`，其余释放；
8. 在临时目录新建一个测试容器（创建成功即验证容量已恢复）；
9. 释放该测试容器锚点，确认计数回到原值；
10. 保存操作前后状态文件副本与审计记录。

> 注意：释放会删除两槽见证键。仅备份 `rollback.state` 无法恢复已释放的锚点；若容器仍在，必须使用恢复码重设锚点。执行前确认恢复码可用。

### 15.2 状态文件恢复（事故流程）

**禁止**直接用任意 `.bak` 覆盖 `rollback.state`。必须完成：

1. 备份当前文件；
2. 校验候选文件：大小 3986、magic `VTRB`、version=2、条目数 ≤ 64；
3. 读取目标容器 UUID（偏移 12）与两份 meta 的最新 generation；
4. 在候选文件中找到同 UUID 条目，要求 `generation >= 容器最新 generation`；
5. 用维护接口确认条目见证状态为 `ACTIVE`（维护接口不返回指纹；禁止用外部工具导出/比对 TPM 私钥）；
6. 任一条件不满足则不得替换；改用恢复码解锁重建锚点；
7. 替换后记录操作人、时间、文件哈希与核对结果。

### 15.3 禁止事项

- 禁止批量删除 `rollback.state` 或 TPM `VerthysWit_*` 键以求“重置”；
- 禁止在测试构建未设置 `VERTHYS_TEST_STATE_DIR` 时运行会创建容器的 E2E；
- 禁止把测试目录、临时容器纳入生产锚点管理范围；
- 禁止在 UI 之外调用释放/回收 API；
- 禁止在未确认恢复码可用时释放 `ACTIVE` 锚点；
- 禁止在未备份与未核对的情况下替换安全状态文件；
- 禁止在未开启调用方签名门的构建中分发锚点维护入口。

---

## 16. 决策记录

| 编号 | 决策 | 理由 | 被否方案 |
|---|---|---|---|
| ADR-RB-01 | 保持 64 条上限 | 正常使用足够；压力来自泄漏 | 扩容到数百条 |
| ADR-RB-02 | 不改变状态布局 | 避免迁移与安全回归 | 版本 3 + 时间戳 + LRU |
| ADR-RB-03 | 不自动淘汰有效锚点 | 会把可用容器变为必须恢复码，可能造成数据丢失 | 自动 LRU/FIFO |
| ADR-RB-04 | 自动回收仅限 `DEAD` | 失效锚点已无法通过任何校验，回收无可用性影响 | 按“未找到文件”自动回收 |
| ADR-RB-05 | 释放必须显式授权并审计 | 安全状态变更需要可追溯 | 后台静默清理 |
| ADR-RB-06 | 容量错误独立于回退错误 | 两者根因与处置完全不同 | 继续折叠为 0x19 |
| ADR-RB-07 | 保留恢复码逃生通道 | 释放、状态丢失、见证清除后的唯一受支持恢复路径 | 取消恢复码 |
| ADR-RB-08 | 恢复码在 `DEAD/TAMPERED` 下允许重设锚点 | 旧见证已无法证明任何东西；拒绝重设等于永久失去访问权 | 要求先释放锚点再恢复 |
| ADR-RB-09 | 新增单槽四态 probe，不用 verify 折叠 | verify 无法区分平台错误与指纹不符，会把平台错误误判为篡改证据 | 复用 verify + exists 组合 |
| ADR-RB-10 | 状态先落盘、见证后删除 | 状态未落盘时删除见证会破坏真实锚点；失败可通过 cleanup_failed 重试 | 先删见证后写状态 |
| ADR-RB-11 | 不基于文件不存在自动删除 | 离线磁盘/归档容器会被误判为废弃；与“真实锚点不误删”冲突 | 扫描后自动释放 ACTIVE |

---

## 17. 附录

### 17.1 错误码对照

| 场景 | 内部 | 公共 | worker | UI |
|---|---|---|---|---|
| 文件回退/见证不符 | `VTY_E_ROLLBACK` | `0x00000019` | `ERR_00000019` | 文件回退 |
| 锚点表满 | `VTY_E_ANCHOR_FULL` | `0x00000021` | `ERR_00000021` | 锚点表已满 |
| TPM 不可用 | `VTY_E_TPM` | `0x00000018` | `ERR_00000018` | 设备安全模块不可用 |
| 状态文件损坏 | `VTY_E_CORRUPT` | `0x00000009` | `ERR_00000009`（锚点维护原样透传） | 状态文件损坏 |
| 状态文件缺失 | — | — | — | 状态文件不存在（首次运行或删除） |
| 状态读写失败 | `VTY_E_IO` | `0x00000008` | `ERR_00000008`（锚点维护原样透传） | 状态文件异常 |
| 调用方未授权 | `VTY_E_CALLER` | `0x00000016` | `ERR_00000016`（锚点维护原样透传） | 调用方未授权 |

### 17.2 实施检查清单

- [x] 错误码只在枚举尾部追加，未复用旧值
- [x] `commit` 容量分支不折叠为 `ROLLBACK`
- [x] `classify` 区分 `DEAD/TAMPERED/UNKNOWN`（四态 probe）
- [x] 回收与释放均先写状态、后删见证
- [x] 释放/回收 API 强制 `CONFIRM`
- [x] `list/reclaim/release` 加入导出白名单并递增 API 版本 0x0016
- [x] worker 白名单保留 `0x21`；锚点维护错误原样透传
- [x] UI 不再把容量问题显示为文件回退
- [x] 恢复码在 `DEAD/TAMPERED` 下可重设锚点
- [x] 测试构建缺隔离目录时拒绝运行
- [x] 生产产物不含 `VERTHYS_TEST_STATE_DIR`
- [x] 全量测试通过（C 327 / worker 127 / 宿主 598 / 前端 853）
- [x] 现场 64/64 清理（2026-11-20，64→1；保留 `bd57e207…`，63 条 `cleanup_failed=0`）
- [x] 跨构建状态互读验证（签名 worker 状态 → caller-auth OFF DLL：`list_rc=0, count=1, state=1`；桌面应用读到 gen 6600）
- [x] dev 构建修复（Debug 宿主优先 `build_dev/core/Debug`；caller-auth OFF、test-hooks ON；`-TestHooks` 独立 `build_test` 327 项通过）
- [x] dev 安全核心启动修复（dev DLL 跳过生产哈希基线；Debug worker 优先；Release/生产校验不变；宿主 598 项通过）
- [x] dev 机器预算 image-auth 修复（`build_dev` test-hooks ON + worker-smoke stderr 排空；定向 create/lock/unlock 与全量 smoke 通过）
- [x] dev 运行构建状态目录策略修复（测试钩子与强制隔离拆分；dev smoke 无隔离目录 `PI-4-SMOKE PASS`；严格测试构建 327 项通过）
- [ ] 单实例/状态写者保护（防止桌面应用、dev 实例与维护工具共享同一状态）
- [ ] 生产发布与现场发布验收（按第 15 节执行）

### 17.3 术语

| 术语 | 含义 |
|---|---|
| 锚点 | `rollback.state` 中某容器的 `generation + 见证槽 + 指纹` 记录 |
| 见证 | TPM 持久化 ECC 密钥，用于证明状态文件不是旧副本 |
| `DEAD` | 引用的见证确定不存在，锚点已无法通过校验 |
| `TAMPERED` | 见证存在但指纹不符，疑似回退或篡改 |
| 释放 | 显式删除锚点条目并删除见证；容器需恢复码重新登记 |
| 回收 | 自动删除 `DEAD` 条目以释放槽位 |

---

## 18. 事件记录：dev 构建启动链路治理（2026-11-20）

- **现象**：dev 版 `verthys-tauri` 报“安全核心启动失败”，无法解锁/创建容器；生产桌面应用正常。
- **根因**：
  1. dev 路径解析最初固定加载 `build/core/Release` 的签名 caller-auth ON DLL；未签名 dev worker 被拒绝（`0x16`）；
  2. `build_core.dev.ps1` 的 CMake 参数未展开，`build_dev` 实际按 test-hooks ON 构建，无隔离目录时拒绝初始化；
  3. Debug 宿主仍用**生产 DLL 哈希基线**校验 `build_dev` DLL：`expected=6168…`、`actual=6667…`，拒绝加载，表现为“安全核心启动失败”；
  4. dev worker 解析优先 `verthys-worker/target/release`，Release worker 使用生产 DLL 哈希基线，与 dev DLL 不匹配；
  5. 多个应用实例曾共享同一 `rollback.state`/容器，放大 `E_ROLLBACK` 与文件占用现象。
- **修复**：
  1. Debug 宿主优先解析 `build_dev/core/Debug/verthys.dll`；Release 宿主仍使用 `build/core/Release`；
  2. Debug 宿主 `verify_dll_integrity` 对 `build_dev` / `build/core/Debug` 的 dev DLL 跳过生产哈希基线；Release 宿主仍强制校验生产 DLL；新增回归 `dev_dll_path_skips_production_hash_baseline_in_debug`；
  3. Debug 宿主优先 `target/debug` worker；Release 宿主优先 `target/release` worker；
  4. `build_core.dev.ps1` 默认 `build_dev`（当时设为 test-hooks OFF，见 §18.1 纠正）；`-TestHooks` 使用独立 `build_test`；CMake 参数加引号。
- **验证**：
  - Debug worker + `build_dev` DLL：`DEV_SPAWN_OK`，`list` 返回 `bd57e207…`、gen=6601、active；
  - `build_dev` DLL 直接读取生产状态：`list_rc=0, count=1, state=1`；
  - `-TestHooks` C 测试 **327 passed / 0 failed**；宿主 **598 passed / 0 failed**；死代码门通过；
  - 生产桌面应用继续正常读写同一状态（gen 6601）。
- **安全边界**：dev 哈希豁免**仅限 Debug 宿主 + `build_dev`/`build/core/Debug` 路径**；Release/生产构建的 DLL 哈希校验与 caller-auth 门保持不变。
- **跨构建兼容性**：签名 worker 写出的状态可被 caller-auth OFF 的 DLL 读取；设备根密钥/状态 MAC 跨构建兼容，**不是**本次根因。
- **残余**：单实例/状态写者保护未实现；生产发布待执行。

### 18.1 事件记录：dev 机器预算 image-auth 拒绝（2026-11-20）

- **现象**：dev 版创建/解锁返回 `ERR_0000000A`，UI 文案为“请求过于频繁”；`v4_create` 与 `lock` 成功，步骤 3 `unlock` 约 3 ms 即失败，创建回滚。
- **根因**：
  1. `build_core.dev.ps1` 默认把 `build_dev` 编成 `VERTHYS_TEST_HOOKS=OFF`（见 §18 第 4 条的当时状态）；
  2. Debug 宿主按 §18 加载 `build_dev/core/Debug/verthys.dll`，该产物不含机器预算旁路 `VERTHYS_TEST_MACHINE_LIMITER_BYPASS`；
  3. 已安装的 `VerthysSecuritySvc` 对未签名 dev worker 执行 image-auth 拒绝，`vty_machine_limiter_check()` 返回 `VTY_E_LOCKED`，经 `VERTHYS_ERR_RATE` 映射为 `0x0A`。
- **证据**：
  - `VerthysSecuritySvc` 事件 3002：`Client request denied ... pid=28920 ... reason=image-auth`（06:17:44，与 unlock 失败同一秒；06:17:26 另一次 pid=40612）；
  - `lockout.state` mtime 停在 05:39:18，未记录新失败，排除失败计数与退避；
  - `vty_keymanager.c` 解锁入口先调用 `vty_machine_limiter_check()`，早于本地熔断与口令校验。
- **修复**：
  1. `build_core.dev.ps1` 的 `build_dev` 恢复 `VERTHYS_TEST_HOOKS=ON`；重建后 DLL 含旁路标记；
  2. `tests/e2e/worker-smoke.ps1` 启动时持续排空 worker stderr：原先只在失败分支读取，4KB 管道写满后 worker 阻塞在日志写入，表现为 PCR 阶段永久挂起。
- **验证**：
  - 定向 create → lock → unlock（Debug worker + 重建 DLL，隔离状态目录）：三步全部 PASS；
  - 全量 `worker-smoke`：`RESULT PI-4-SMOKE PASS`（含 PCR、恢复码轮换、恢复会话重绑、DEK 轮换）；
  - 验证窗口内无新增 `VerthysSecuritySvc` 3002；生产 `rollback.state`（SHA-256 `2F31EC3A…`）与 `lockout.state` mtime 未变化。
- **残余**：6:17 创建失败在 `rollback.state` 留下 `47d9467568ac1b93c3568856e41b6da7`（gen=2）；对应容器路径已不存在，但见证仍存在，实际状态为 `ACTIVE` 而非 `DEAD`。自动回收不会处理，需在维护面板中授权释放。

### 18.2 事件记录：dev 运行构建强制隔离回归（2026-11-20）

- **现象**：dev 宿主（Debug）加载 `build_dev/core/Debug/verthys.dll` 后，创建与打开容器均失败；创建返回 `ERR_00000019`，UI 显示“检测到文件回退”。生产桌面应用不受影响。
- **根因**：`VERTHYS_TEST_HOOKS=ON` 同时承担“机器预算旁路”和“缺少 VERTHYS_TEST_STATE_DIR 即拒绝初始化”两种语义。dev 应用必须使用测试钩子以绕过已安装 P2 服务的 image-auth，但启动时不设置隔离目录；`vty_rollback_init()` 返回 `VTY_E_POLICY`，被 `commit/check` 折叠为 `VTY_E_ROLLBACK`。
- **证据**：
  - 使用 `build_dev` DLL + Debug worker、不注入 `VERTHYS_TEST_STATE_DIR`，定向 `v4_create` 返回 `ERR_00000019`；worker stderr 显示 DLL 加载与 `Verthys_Init` 均成功，失败只发生在创建；
  - Debug worker 无 DLL 哈希基线，排除完整性拒绝；
  - `lockout.state` 现有逻辑在无隔离目录时回落生产路径，只有回退锚点强制拒绝，定位为单一分支问题。
- **修复**：
  1. 新增 `VERTHYS_TEST_REQUIRE_ISOLATION` 编译开关，仅自动化测试构建（`build_test`、CI）开启；`vty_rollback.c` 与 `vty_lockout.c` 只在开启时拒绝缺失隔离目录；
  2. `build_core.dev.ps1`：`build_dev` 为 hooks ON / 隔离 OFF，`-TestHooks` 的 `build_test` 为 hooks ON / 隔离 ON；
  3. `build_core.release.ps1` 新增 `-RequireTestIsolation`（必须与 `-TestHooks` 同用）；CI 测试产物开启，dev launcher 不开启；
  4. `build_production.ps1` 显式写出 `VERTHYS_TEST_REQUIRE_ISOLATION=OFF`，避免 CMake 缓存继承。
- **验证**：
  - Debug worker + `build_dev` DLL、无隔离目录：全量 `worker-smoke` `RESULT PI-4-SMOKE PASS`；测试容器锚点随后通过 `rollback_anchor_release` 释放，`rollback.state` SHA-256 恢复为 `2F31EC3A4FB23B46…`；
  - `build_test`（强制隔离 ON）全量 C 测试 327 passed / 0 failed；`rollback_test_build_requires_isolation` 单独执行通过；
  - `build/core/Release` 以 hooks ON / 隔离 OFF 重建，Release worker 哈希基线同步更新。
- **残余**：单实例/状态写者保护仍未实现；dev 与生产应用不得同时操作同一状态。


