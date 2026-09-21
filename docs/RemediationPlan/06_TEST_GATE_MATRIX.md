# 回归测试与门控矩阵

> 本文档是修复工程的验证中枢：81 项缺陷 → 所属 FIX → 必需测试 → CI 门，逐项映射。
> 用途：验收时逐行核对；新回归发生时反查缺哪一层防线。
> 编号（P0/P1/P2/P3、FIX-x-y）仅存在于本文档，**不得进入代码注释**。

---

## 一、六层防线与职责

| 层 | 载体 | 运行时机 | 覆盖缺陷类型 |
|---|---|---|---|
| L1 单元 | `core/tests/**`、Rust `#[cfg(test)]`、前端 vitest | CI（core.yml / rust-frontend.yml） | 逻辑正确性、边界、失败路径零化 |
| L2 故障注入 | `test_txn_recovery_inject.c`、mock/桩 | CI + 本地 | 崩溃一致性、重试、竞争窗口 |
| L3 模糊 | 5 个 libFuzzer 目标 + 冒烟门 | CI（core.yml fuzz job） | 解析鲁棒性、越界 |
| L4 静态 | clang-tidy（Wave 4 启用）、AST 双引擎、新增零化 grep 门 | CI（Wave 4 新 job） | UAF/越界/红线/未清理提前 return |
| L5 契约 | 命令清单 diff 脚本（Rust ↔ TS） | CI（Wave 4 新 job） | IPC 契约漂移、死命令、幽灵命令 |
| L6 审计 | dep-versions 比对、vendor 哈希、导出面白名单 | CI（既有 + 强化） | 供应链、隐蔽扩面 |

> 注：L4 的"零化 grep 门"规则设计见本文档第三节；L5 的"契约 violet diff"规则设计见第四节。两者均为新增工具化资产，与 Wave 0~4 修复同步开发（Wave 4 合入 CI）。

---

## 二、缺陷 → 测试映射总表

### Wave 0

| 缺陷 | FIX | L1 单元 | L2/L3/L5 配合 | 手工验证 |
|---|---|---|---|---|
| P0-1 导出协议 | FIX-0-1 | vitest：mock writeUserFile 直传断言 | L5 契约门（write_user_file 双端同源） | 三种格式导出落盘 |
| P1-6 超时日志明文 | FIX-0-2 | Rust：脱敏函数三分支单测 | L4 grep 门（无 raw={} 原样日志） | worker 挂起注入后 grep 日志 |
| P1-7 熔断未强制 | FIX-0-3 | Rust：guard 阈值/重置单测；响应码→计数映射单测 | — | 10 次错误口令后端锁定 |
| P1-10 log_fatal 静默 | FIX-0-4 | Rust：命令长度截断单测 | L5 契约门（log_fatal 双侧命中） | 生产构建触发异常落日志 |
| P1-11 README 冲突 | FIX-0-5 | — | L4 grep 门（无冲突标记） | Markdown 渲染 |
| P2-23 响应日志子密钥 | FIX-0-2 | 同 FIX-0-2 | L4 grep 门 | — |

### Wave 1

| 缺陷 | FIX | L1 单元 | L2 故障注入 | L3 模糊 |
|---|---|---|---|---|
| P1-4 SSTable 写穿 | FIX-1-1 | test_v3_lsm 边界预算断言 | 略超容量 flush → extent 区首块不变 | fuzz_sstable 回归 |
| P1-5 delete 多减 | FIX-1-2 | 注入 lsm_delete/extent_release 失败 → refcount/账本净额 | 同上（已并入） | — |
| P1-3 WAL 残留重放 | FIX-1-3 | 换区清零/写头失败不回切 | 第三圈掉电 replay 不 redrive | — |
| P1-2 scan 无锁 | FIX-1-4 | 锁对称性断言 | 双线程 AddRecord+ScanFetch 压力（ASan） | — |
| P1-1 C 层计数 | FIX-1-5 | 跨句柄退避累积断言 | — | — |

### Wave 2

| 缺陷 | FIX | L1 单元 | L4 静态 |
|---|---|---|---|
| P1-8 bin_password | FIX-2-1 | Zeroizing Drop 行为 + 无移出走查 | 零化 grep 门 |
| P1-9 SHM 零化 | FIX-2-2 | PlainBatchGuard Drop 覆写单测 | 零化 grep 门 |
| P1-12 COMPILED pepper | FIX-2-3 | 默认构建失败/受控构建如旧 | 导出面白名单 + 宏门控审查 |
| P2-1 import_key 不清零 | FIX-2-4 | 注入失败 → 缓冲全 0（修复前红） | 零化 grep 门 |
| P3 零化 ×3（栈上 mek/old_mek/integrity_key） | FIX-2-4 | 各失败路径缓冲全 0 | 零化 grep 门 |
| P2-2 provider 竞态 | FIX-2-5 | 并发 init/deinit 句柄数稳定 | — |
| P2-3 rotate 空槽 | FIX-2-6 | 注入 import 失败 → 旧槽可用 | — |
| P2-5 size_t 截断 | FIX-2-7 | ULONG 上界边界单测 | — |
| P2-4 旧 AEAD nonce | FIX-2-10 | 重复 nonce 拒绝 / 调用点清单门 | — |
| P2-19 SecuredString Debug | FIX-2-8 | format 不含明文单测 | grep 门（无 {:?} 打印点） |
| P2-20 GMK 零化 | FIX-2-9 | 中间缓冲覆写单测 | 零化 grep 门 |

### Wave 3

| 缺陷 | FIX | L1 单元 | 手工/注入 |
|---|---|---|---|
| P2-15 max_count OOM | FIX-3-1 | id=1e8 截断断言 | — |
| P2-16 CString panic | FIX-3-2 | NUL 路径返回错误 | — |
| P2-17 read_line 无上限 | FIX-3-3 | 超长流触发上限错误 | — |
| P2-18 SHM CSPRNG | FIX-3-4 | 名称不可预测断言 | — |
| P2-22 FFI catch_unwind | FIX-3-5 | 回调内 panic 不 abort | — |
| P2-21 解锁态闸门 | FIX-3-6 | 未解锁 add_record 被拒 | — |
| P2-32 死命令 | FIX-3-7 | 构建无告警 | L5 契约门 |
| P2-7 路径沙箱 | FIX-3-8 | 系统目录/符号链接拒绝 | — |
| P2-8 defense_closure | FIX-3-9 | 三态断言 | — |
| P2-9 anti_inject 误报 | FIX-3-10 | 解锁后检查无症状 | 注入线程仍检出 |
| P2-10 Deinit 卡死 | FIX-3-11 | 阻塞 preheat 下超时返回 | — |
| P2-12 integrity fail-open | FIX-3-12 | HMAC 失败有遥测且标未完成 | — |
| P2-13 s_hbuf 竞争 | FIX-3-13 | 并发 test_install+verify | — |
| P2-14 system32 前缀 | FIX-3-14 | 伪前缀拒绝 | — |
| P2-6 rekey 双 rotate | FIX-3-15 | 并发压测单次生效 | — |
| P2-11 空口令 | FIX-3-16 | 策略断言（推荐拒绝） | — |
| P2-24 memtable 重建失败 | FIX-3-17 | 注入 create 失败 → put 被拒 | — |
| P2-25 close dirty | FIX-3-18 | close 失败 → reopen 重建全量 | — |
| P2-26 superblock 内容比对 | FIX-3-19 | 同 txid 异内容判不一致 | — |
| P2-27 warmcache 边界 | FIX-3-20 | 非法布局判 miss | fuzz 回归 |
| P2-35 全段 HMAC 缓存 | FIX-3-21 | 二次解锁加速 + 指纹失效重算 | — |

### Wave 4（平台项在 CI 内自证）

| 缺陷 | FIX | 验证方式（门自证） |
|---|---|---|
| P2-28 dep-versions 漂移 | FIX-4-1 | CI 比对 job：故意改坏 → 红 → 还原 |
| P2-29 双 MSVC 机制 | FIX-4-2 | CI 跑 build_production.ps1 验证 job |
| P2-30 AST 门未接入 | FIX-4-3 | 红线违规 PR → 红 → 还原 |
| P2-31 clang-tidy 未启用 | FIX-4-4 | tidy 告警 PR → 红 → 还原（存量豁免表） |
| P2-33 npm 解析漂移 | FIX-4-5 | 本地 npm ci 与 lock 一致 |
| P2-34 lock 被改写 | FIX-4-6 | 构建后 git status 无 lock 变更 + CI lock 比对 |
| Rust 工具链浮动 | FIX-4-7 | runner rustc 版本与本地一致 |
| CI Node 漂移 | FIX-4-8 | 双端同 Node 下 vue-tsc 通过 |
| CONTRIBUTING 悬空 | FIX-4-9 | 文档 Grep |
| CSP 7778 | FIX-4-10 | 配置审查 |
| 混淆吞兜底 | FIX-4-11 | 主通道验证 + 决策留档 |

---

## 三、新增静态门：零化 grep 规则（L4 新资产）

**目的**：把「错误路径零化」纪律工具化，防止 Wave 2 修复的同类缺陷再生。

**规则**（脚本 `ci/check_zeroize_paths.ps1`，Wave 4 接入 CI）：
1. 收集含敏感函数的文件清单（含 `Zeroizing`、`SecureZeroMemory`、`secure_zero`、`memory_guard_secure_zero` 任一调用的 C/Rust 文件）。
2. 对每个函数体：若存在 `Zeroizing`/`secure_zero` 调用，且函数内存在「不经过清理块」的提前 `return`（C）/ `?`（Rust，且 `?` 之后才出现清理调用），则报告。
3. 首版以「扫瞄 + 人工复核清单」落地；稳定后收紧为硬门。
4. 豁免必须显式（`// zeroize-scan: exempt` 注释 + 理由），豁免清单随 CI 资产入库。

**首轮交付物**：Wave 2 完成后全仓扫一遍，清理存量命中（即审计发现的 P1-8/P1-9/A 片/C 片各零化项），此后门开始守增量。

---

## 四、新增契约门：IPC 命令清单 diff（L5 新资产）

**目的**：根除「前端调了后端没有 / 后端注册了前端不用」两类契约漂移（本次 P0-1、P1-10、P2-32 三个真实案例）。

**规则**（脚本 `ci/check_ipc_contract.ps1`，Wave 4 接入 CI）：
1. Rust 侧：解析 `generate_handler!` 宏实参清单（或按 `#[tauri::command]` 函数名，排除生命周期/事件函数）。
2. TS 侧：正则抽取 `ipc<T>("...")` / `invoke("...")` 字符串字面量。
3. 双向差集：
   - TS 有、Rust 无 → 幽灵命令（必须修复，如本次 log_fatal）；
   - Rust 有、TS 无 → 死命令（必须清理或豁免表留据，如本次 5 个）。
4. 首版输出「差集报告 + 人工复核」，稳定后收紧为硬门（豁免表入库）。
5. 注意 Tauri 参数名 camelCase 自动转换不参与比对（只比命令名本体）。

---

## 五、既有门（保持并纳入验收）

- vendor 哈希门（`ci/verify_vendor_hashes.ps1`）——每次 CI 必跑；
- C 导出面白名单门（core.yml dumpbin 比对）——C 层任何改动（尤其 Wave 1/2）必须比对；
- cargo clippy 零告警门（rust-frontend.yml）——Rust 改动必过；
- vite build + vue-tsc + vitest（rust-frontend.yml）——TS 改动必过；
- 5 fuzz 目标冒烟 + 持续门（core.yml fuzz job）。

---

## 六、全工程最终验收清单（逐项打勾）

- [ ] Wave 0 六项完成且验证门全绿（导出落盘 / 日志无明文 / 第 10 次锁定 / FATAL 可达 / README 干净）
- [ ] Wave 1 五项完成；修复前必红测试组（SSTable 越界、delete 重试、WAL 第三圈、跨句柄退避）全部修复后转绿且留档
- [ ] Wave 2 十项完成；「成功+失败」双路径零化走查随 PR 留档；COMPILED 胡椒默认构建不可达
- [ ] Wave 3 二十一项完成；恶意输入注入组全绿；死命令清理决策表入库
- [ ] Wave 4 平台项完成；违规样本 PR 逐一验证 CI 变红后还原；本地干净环境一键构建跑通
- [ ] L4 零化 grep 门上线且扫净首轮存量
- [ ] L5 契约 diff 门上线且当前差集为空（豁免表清零）
- [ ] 全仓 Grep：无冲突标记、无 vcpkg、无 7778、无原样秘密日志
- [ ] 81 项缺陷每条有测试/门/手工验证三选一以上覆盖，台账状态全部「已关闭」或「已决策豁免」
- [ ] `git status` 干净；关键锁文件无意外漂移；版本号仍为 2.6.1 全仓一致

---

## 附：执行顺序速查

T0/T1 前置核查 → Wave 0（01 文档）→ Wave 1（02 文档）→ Wave 2（03 文档）→ Wave 3（04 文档）→ Wave 4 + 门资产正式接入（05 文档 + 本文档第三/四节）→ 季度消化剩余 P3。