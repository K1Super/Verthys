# Wave 2 — 密钥卫生批施行细则

> 目标：封闭「错误路径零化」系统性缺口，治理密码学边界（非重放 nonce、失败路径密钥残留、COMPILED 胡椒兜底）。
> 范围：`core/src/crypto/`、`core/src/security/memory/`、src-tauri/verthys-worker（Rust 零化）。
> 前置：
> - T1 盘点（开工前）：确认存量容器是否存在 COMPILED 胡椒源、pepper V3 头能否区分来源——决定 FIX-2-3 采用硬禁用还是「拒绝新建 + 存量告警」。
> - Wave 0 已交付（FIX-0-2 的日志脱敏设施本批复用；FIX-2-1 与 FIX-0-2 同文件但职责分离）。
> 总纪律（本批核心方法论）：**任何持有敏感缓冲的函数，所有 return 分支必须经过统一清理块；RAII/作用域守卫优先于手工清理**。本批每个 FIX 都要验证「成功路径 + 全部失败路径」两条线。编号（P1-x、P2-x、FIX-x-y）只存在于本文档，**不得进入代码注释**。

---

## FIX-2-1 `bin_password` 与请求串零化（P1-8）

### 现状事实（已核验）

`src-tauri/src/controller/key_controller.rs`（derive 路径 ~189/279-287，verify 路径 ~352/461-466 同构）：
- `bin_password` 是裸 `String`；
- `json!` 中 `"password": *password`、`"bin_password": bin_password` 均把明文**移出** Zeroizing/变量进入 json Value；
- `req_str = req.to_string()` 是含两份明文的普通 String；
- 发送后仅 `drop(password)`（此时 password 内部已被移空，drop 实际零化不到明文）；`bin_password` 与 `req_str` 未零化。

### 修复设计

1. **借用原则**：停机"移出"模式，所有敏感值以借用进入 `json!`，原件保留在 Zeroizing 容器中直到发送后统一销毁。

```rust
// 参数接收后立即遮蔽为 Zeroizing
let bin_password = Zeroizing::new(bin_password);

let req = serde_json::json!({
    "op": "derive_global_key",
    "password": password.as_str(),          /* 借用，不移出 */
    "bin_data": bin_data_b64,
    "bin_password": bin_password.as_str(),  /* 借用，不移出 */
});
let mut req_str = Zeroizing::new(req.to_string());
drop(req);

let resp_json = state
    .send_with_timeout(req_str.as_str(), DERIVE_VERIFY_TIMEOUT)
    ...
// 函数返回：password / bin_password / req_str 三个 Zeroizing 依次 Drop 自动零化
```

2. `send_with_timeout` 若不接受 `&str` 而接受 `&String`，以 `&*req_str`/`req_str.as_str()` 适配；确认其内部不复制存放该串（发送即丢）。若其签名接受 `String`（所有权），改为在调用点 `req_str.as_str().to_owned()` 得到的临时 String 同样有残留风险——**此时应改 `send_with_timeout` 签名为借用**（小范围契约调整，全仓调用点有限）。
3. verify 路径（352/461-466）同法改净；derive/verify 之外全仓扫一遍 `json!({...})` 含 `password`/`bin_password`/`data` 敏感字段的构造点，统一为借用模式（附加清单：导出/导入/改密等所有经 `state.send*` 的请求构造）。
4. `req_str` 变 Zeroizing 后，`log::error!` 超时日志不得引用其值（Wave 0 的 FIX-0-2 已把超时日志改为摘要，天然闭环；若再有新日志点引用 req_str 原文，属违规）。
5. 错误路径 `raw={}`（303/482/669 等）由 FIX-0-2 的脱敏设施处理，本项不再单独改日志。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| Rust 单测 | key_controller 相关测试（若控制器已有测试设施则扩展，否则在 util 层为「借用式 json 构造」建立专门辅助并单测） | 构造含敏感字段请求，断言发送前后 Zeroizing 容器被擦除（drop 后缓冲为 0——测试对 Zeroizing 直接构造场景验证其 Drop 行为；控制器层以「无移出」代码走查 + 编译期约束为准） |
| 手工/工具 | heap dump 或调试器观察 | derive/verify 返回后，控制器堆中口令字节不可见（实施验收时做一次） |

### 验收标准

- `key_controller.rs` 内不存在 `"password": *`、`"bin_password": bin_password` 等移出式 json 构造；三个敏感容器均为 Zeroizing。
- `send_with_timeout`/`send_*` 为借用签名（或等价零拷贝语义）。

---

## FIX-2-2 SHM 写入失败路径统一零化（P1-9）

### 现状事实（已核验）

`verthys-tauri/verthys-worker/src/runtime/worker.rs`：
- 全量拉取 ~399 行：`shm.write_records(&result, exhausted).map_err(|_| 0xFFFFFFFFu32)?;` 失败即 `return Err`，跳过后面的明文 `name/data` 三轮覆写循环（402-415）。
- 摘要拉取 ~610 行同构（零化循环 613-624）。
- 结果容器 `result: Vec<(u64, u32, String, Vec<u8>)>` 中 `name`（String）与 `data`（Vec<u8>）是解密后明文。

### 修复设计

1. **清理提升为 RAII 守卫**（优于手工挪动 `?` 顺序——未来新增 return 也自动覆盖）。该文件内新增：

```rust
/// 持有批量明文的守卫：Drop 时对其内容执行三轮交替覆写后释放。
/// 保证任何提前返回路径（含 SHM 写入失败）都不会跳过明文擦除。
struct PlainBatchGuard {
    rows: Vec<(u64, u32, String, Vec<u8>)>,
}
impl Drop for PlainBatchGuard {
    fn drop(&mut self) {
        for (_, _, name, data) in self.rows.iter_mut() {
            overwrite_bytes(name.as_bytes_mut(), &[0x00, 0xFF, 0x00]);
            overwrite_bytes(data.as_mut_slice(), &[0x00, 0xFF, 0x00]);
        }
    }
}
```

   `overwrite_bytes` 为三轮循环的小助手（把现有 402-415 的覆写代码抽出，语义不变）。
2. 两处调用点：`result` 改由守卫持有（或 `push` 进守卫），`?` 处不再手动 return 前清理——Drop 自动执行；原 402-415 / 613-624 手工循环删除。
3. 检查 `write_records` 成功路径后是否还需要 result 内容（若不用，守卫自然 Drop）；确认 Rust 析构顺序保证 `shm.write_records` 失败时守卫仍被 Drop（函数级局部变量，必然）。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| Rust 单测 | worker 运行时测试模块（如无则新增） | 构造 `PlainBatchGuard` 含已知明文字节，主动提前 `return`/drop，断言缓冲被覆写为 0（抽样检查三段覆写后的终态） |
| 集成 | 构造超 SHM 容量批次（mock shm 返回容量错误） | 错误返回后 result 缓冲已被覆写（可注入检查或依赖守卫单测覆盖） |

### 验收标准

- 两处零化循环消失，代之以 RAII 守卫；worker 错误路径代码走查无"持明文提前返回"。
- 守卫单测覆盖 Drop 覆写。

---

## FIX-2-3 COMPILED 兜底胡椒策略整改（P1-12）

### 现状事实（已核验）

- `core/src/crypto/pepper/verthys_pepper.c:39-44`：`static const uint8_t VERTHYS_PEPPER_COMPILED[32] = {...}`（此处不复述字节值），init 优先级 3 回退（:535-540）。
- 任何拿到 DLL 的人都知道该常量的值 → 走 COMPILED 源的容器离线爆破退化为纯口令熵。

### 修复设计（分步，取决于 T1 盘点结论）

1. **编译期开关（必做，无论 T1 结论）**：该常量的使用路径由编译宏门控，默认（Release）关闭：
```c
#if defined(VERTHYS_ENABLE_COMPILED_PEPPER)   /* 仅测试/调试构建定义 */
static const uint8_t VERTHYS_PEPPER_COMPILED[VERTHYS_KEY_BYTES] = { ... };
#endif
```
   回退逻辑同步门控：默认构建下「OS 托管不可用 + 未注入 + 无 SS 重建」→ 直接 `VERTHYS_ERR_PEPPER_SOURCE` 失败回退错误（不产生 COMPILED 源容器），错误码走 worker 已有的 PEPPER_SOURCE 抛给上层提示"安全源已变更"。
2. **存量兼容（T1 结论为"存在存量 COMPILED 容器"时）**：解锁路径对 COMPILED 源容器**放行但强告警**（当前 g_pepper_source 机制已能记录来源；在 L3/Rust 侧将 PEPPER_SOURCE 响应升级为强制提醒文案），并**拒绝以 COMPILED 源新建**容器。若 T1 结论为"无存量"，直接完全关闭。
3. 文档标注（容器格式说明/安全说明）：COMPILED 源强度等同无胡椒，仅作为受控调试用途存在。
4. 与本批 FIX-2-4 等 C 层零化无关，但与「发布构建不携带可预测兜底」的供应链审计口径一致（导出面白名单门即 Wave 4 的 CI 会顺带盯住新符号）。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 单测 | `core/tests/crypto/test_pepper_v3.c` | mock OS 托管不可用 + 无注入：默认构建下 `verthys_pepper_init` 返回 PEPPER_SOURCE 类失败而非 COMPILED 成功；定义 `VERTHYS_ENABLE_COMPILED_PEPPER` 的构建下行为如旧（受控） |
| 集成 | `verthys_tests.exe` 全量 | 全绿 |

### 验收标准

- Release 构建（默认宏集）不含 COMPILED 兜底路径；`VERHYS_ENABLE_COMPILED_PEPPER` 仅在测试 CMake 目标定义。

---

## FIX-2-4 CNG import_key 失败路径清零调用方 key（P2-1）+ C 层零化三项补漏

### 现状事实（已核验）

- `core/src/crypto/cipher/verthys_crypto_cng.c:163-166`：`verthys_cng_aead_import_key` 失败 return 前不清零调用方 key 缓冲；成功路径（:183）已清。`keymanager_cng.c:278-283` 注释误称"import_key 内部已清"——与实现矛盾。
- 补充三项同性质 P3（评审 C/A 片，同批一并收敛）：
  - `verthys_export_import.c:156-163`：derive 失败仅 zero salt，未 zero 栈上 mek；
  - `verthys_v3_lifecycle.c:756-757`：change_password 旧口令 derive 失败未 zero 栈上 old_mek；
  - `verthys_unlock_pipeline.c:401`（goto fail 路径）：integrity_key 失败分支未 zero 栈上完整性密钥。

### 修复设计

1. `verthys_cng_aead_import_key`：失败 return 前统一 `verthys_secure_zero((void *)key, key_bytes)`（与成功路径同一辅助）；同时**修正** `keymanager_cng.c:278-283` 的注释与实现矛盾——注释改为描述真实契约："失败时 import_key 负责清零调用方 key"（或按另一契约：失败由调用方清，则注释与调用点同步改；二选一后全仓一致，本文档默认前者）。
2. 三个 P3 点：在各失败 `return`/`goto` 前补 `verthys_secure_zero(mek/old_mek/integrity_key, 长度)`。对 `verthys_unlock_pipeline.c` 的 goto fail 结构，在 fail 标签处按"已初始化标志"补清（若 unlock pipeline 采用阶段标志，复用既有模式；实施时以实际控制流为准）。
3. **模式固化**：本项修完即作为"错误路径零化"审查样板；Wave 4 会把 grep 规则门接入 CI（含 Zeroizing/secure_zero 的函数存在未清理提前 return 则红）。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 单测 | `core/tests/crypto/test_cng_kernel.c` / `test_keymanager.c` 扩展 | 注入 `BCryptGenerateSymmetricKey` 失败桩，断言调用方 key 缓冲全 0（修复前红） |
| 单测 | `core/tests/api/test_verthys_export.c` / lifecycle 测试扩展 | derive/改密失败路径后栈缓冲全 0（以确定性失败注入触发） |

### 验收标准

- 四处失败路径均有清零语句，注释与实现一致；单测修复前红后绿。

---

## FIX-2-5 AES-GCM provider 初始化加 once 保护（P2-2）

### 现状事实（已核验）

`verthys_crypto_cng.c:31-78`：共享 AES-GCM provider 以 `InterlockedIncrement(&refs)>1` 判幂等；`open_aes_gcm_provider` 内 `if (s_shared_alg) return` 与 `BCryptOpenAlgorithmProvider` 非原子——并发 init 存在双开句柄泄漏与 refs 失配（deinit 误关在用 provider）。

### 修复设计

1. 以一次性初始化原语保护 open 路径：Windows 用 `INIT_ONCE`（`InitOnceExecuteOnce`），非 Windows 以既有平台抽象（静态 `pthread_once`/原子 CAS 循环）对齐；open 失败时重置 once 状态使下次可重试（若平台 API 不支持重置，改为"失败即降级路径+重开尝试由外层防抖"）。
2. **refs 只做引用计数，不做初始化判据**：open 一律经 once 进入；refs 增减仅决定 deinit 时是否真正 `BCryptCloseAlgorithmProvider`。
3. 全局 deinit 同样经互斥序列化（简化为单点函数），消除"并发方已认为就绪而句柄被关"的竞态。
4. 启动单线程不可达但本项仍实施——理由：DLL 被异步多线程 host（解压缩/预加载）加载时即可能并发，纵深原则成立。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 压力 | `test_cng_kernel.c` 扩展 | 多线程并发 init/deinit 循环 N 轮：BCrypt 句柄数不增长（或经计数断言 refs 恒与句柄一致）、无崩溃 |

### 验收标准

- open 路径 once 化；单测通过。

---

## FIX-2-6 rotate_mek 改「先临时槽后切换」（P2-3）

### 现状事实（已核验）

`keymanager_cng.c:433-439`：先 `BCryptDestroyKey(old)` 再 import 新 MEK；新 import 失败时槽位空（key=NULL, imported=0），不回滚。头文件注明属"已接受降级"，但降级态下所有 unwrap/verify 失败直至重新解锁。

### 修复设计

1. import 新 MEK 到**临时句柄**先验证成功，再原子切换槽位（销毁旧句柄、写入新句柄与标志位）；任一步失败保持旧槽不动。
2. 切换仍存在的极端窗口（destroy 旧句柄成功、写新标志前崩溃——内存操作，进程内无崩溃跨点,故实际无窗口；若实现为两步,两步之间不得有可失败操作）。
3. 保留原有可观测性：失败时记录健康指标并向上层抛 CNG 域错误（不改变外层重试语义）。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 单测 | `test_keymanager.c` 扩展 | 注入新 MEK import 失败：断言旧 MEK 槽依旧有效（unwrap 可用），而非空槽 |

### 验收标准

- 失败后旧槽可用的单测绿。

---

## FIX-2-7 size_t→ULONG 与长度加法溢出守卫（P2-5）

### 现状事实（已核验）

`verthys_crypto_cng.c:202/229/234/283/288` 等处 `(ULONG)plaintext_len` 强转无范围检查；`pt_len + TAG` 相加无溢出守卫（key_separation.c 旧路径同款 383/415/420/483/488）。

### 修复设计

1. 各入口（含旧 key_separation_aead_*）增设：

```c
if (plaintext_len > 0xFFFFFFFFu - VERTHYS_CNG_TAG_BYTES) return VERTHYS_ERR_INVALID;
```

   统一口径：単条明/密文上限 = ULONG_MAX - 16（CNG 参数域）；需要更大的场景由上层分块（当前业务无此场景）。
2. 传 CNG 前以 64 位检查 + 局部 `ULONG len32` 变量承接，避免隐式截断；`ct_len >= pt_len + 16` 类加法全部先做减法形式（`ct_len - pt_len >= 16`）防溢出。
3. 旧 key_separation 路径同法（与 FIX-2-10 的旧路径治理一并审视，若该路径本批决定下线，则此项仅修新 CNG 路径）。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 单测 | `test_crypto.c`/`test_key_separation.c` | 长度为 `0xFFFFFFF0~0xFFFFFFFF` 边界注入：断言返回 INVALID 而非运算错乱（以可构造的最大缓冲或直接以长度参数单测边界判定函数） |

### 验收标准

- 边界单测绿；全仓该文件族无裸 `(ULONG)` 长度强转。

---

## FIX-2-8 SecuredString 手动实现 Debug（P2-19）

### 现状事实（已核验）

`src-tauri/src/util/secured_string.rs:48`：`#[derive(Debug, Default, Clone, PartialEq, Eq, TS)]`；内部 `Zeroizing<String>` 的 Debug 会打印明文，与同文件"不实现 Display 避免打印明文"红线冲突。

### 修复设计

1. 移除 derive 中的 `Debug`，手动实现：

```rust
impl std::fmt::Debug for SecuredString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecuredString")
            .field("len", &self.0.len())     /* 只暴露长度 */
            .field("content", &"<REDACTED>")
            .finish()
    }
}
```

2. 全仓排查：Grep 所有对该类型或其包含结构使用 `{:?}`/`{:#?}`/`dbg!`/`println!` 的日志点，确认无遗漏其它 wrapper（如重命名导出的再包装类型）。
3. Clone/PartialEq/Eq 保留（比较/克隆不打印,风险为时序侧信道,不在本项范围）。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| Rust 单测 | secured_string 测试模块（若有）或新增 | `format!("{:?}", s)` 输出不含明文、含长度；`{:#?}` 同 |

### 验收标准

- 单测绿；全仓无对 SecuredString 内容的调试打印路径。

---

## FIX-2-9 GMK 派生中间量与子密钥零化（P2-20）

### 现状事实（已核验）

`verthys-worker/src/runtime/gmk.rs:98/130-132/264`：HKDF PRK 拷入 `gmk_arr` 后 `gmk` 未显式 zeroize；`okm=[0u8;32]` 派生子密钥 base64 编码后未 zeroize；`worker.rs` password/bin_password 以 `&str` 透传 FFI 后未清（透传层的清理由调用方 Rust String/Zeroizing 负责——本项校准责任链：worker 收到 JSON 里的 password 字段反序列化为 String 后，在请求处理完成后该 String 是否 zeroize）。

### 修复设计

1. `gmk.rs`：PRK 结构体在 extract 用毕后显式 `.zeroize()`（改用 hkdf 输出到 `Zeroizing<[u8;32]>` 或调 crate 的 zeroize 支持——若 crate 不支持，输出到本地数组后 `secure_zero`）；`okm` 用 `Zeroizing<[u8;32]>` 承载，base64 编码读借用。
2. `worker.rs`：梳理"请求 JSON 反序列化 → 字段透传 FFI → 响应回程"整链中的 String 节点；凡含口令/密钥明文的节点改 `Zeroizing<String>`（与 FIX-2-1 的零化模式统一）。
3. Worker 进程结束前的 thread_local GMK 清零路径已有（gmk.rs Drop/clear），保持不变，只补中间量。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| Rust 单测 | gmk 测试模块 | derive 后中间缓冲被覆写；子密钥 base64 输出后 okm 为 0 |

### 验收标准

- 敏感临时数组全部 Zeroizing/显式清零；单测绿。

---

## FIX-2-10 旧版 AEAD nonce 治理（P2-4）

### 现状事实（已核验）

`core/src/security/memory/key_separation.c:371-504`：旧 `key_separation_aead_encrypt/decrypt` 的 12B nonce 完全由调用方外部提供，无内部计数器/重放保护；新版 `VerthysCngAead` 才有 Interlocked 计数器。GCM nonce 复用是灾难性泄漏，防线全依赖调用方纪律。

### 修复设计

1. **先盘点**（实施第一步）：Grep 全仓 `key_separation_aead_` 调用点，输出「调用方 → nonce 来源（随机/计数器/固定）」清单。
2. 按盘点结果二选一：
   - **若调用点已全部迁移到新 CNG 路径**（旧函数无生产调用）→ 旧函数直接下线（删除实现与导出，更新导出面白名单基线）。
   - **若仍有生产调用**→ 短期：在旧路径内部维护「同 key 下已用 nonce 集合」（哈希表 or 单调计数强制覆盖），nonce 非严格递增即拒绝；中期：推动调用方迁移至 `VerthysCngAead` 后下线。
3. 空明文语义（P3，key_separation.c:451 新旧不一致）随本项一并统一：不管选择哪种，把新旧路径对 `ct_len==TAG` 的判定对齐并加一致性单测。

### 回归测试

| 层 | 落点 | 断言 |
|---|---|---|
| 单测 | `test_key_separation.c` | 同一 key 下重复 nonce 第二次加密被拒绝（短期方案）/ 调用点清单为空的静态门（下线方案） |
| 一致性 | 同上 | 新旧路径空明文语义一致 |

### 验收标准

- 调用点清单留档；短期方案下重放防护单测绿；长期（Wave 4 前）旧路径清零下线。

---

## 本批验证门

1. Wave 0 门复跑（Rust/TS 侧）：cargo test × 2、clippy 双零告警、vue-tsc、vitest、npm build
2. Ninja 构建 + `verthys_tests.exe` 全量绿
3. 新增/扩展单测全部绿，其中修复前必红项留档
4. CI（core.yml）通过；导出面白名单与基线一致（本轮 C 改动若增删符号，先评审再更新基线提交，禁止顺带扩面）
5. 每项修复的「成功路径 + 全部失败路径」走查记录随 PR 提交

**git 纪律**：按 FIX 独立提交；本批涉及安全性行为变化（COMPILED 禁用、旧 AEAD 治理）在提交说明中写明行为差异与迁移影响。