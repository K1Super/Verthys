# Shard A 深审发现 — L2 C 核心「密钥生命周期与安全内存」

- 切片范围：`core/src/crypto/{cipher,keymanager,pepper,rekey}` 与 `core/src/security/memory/`，对照 `core/include/verthys.h` FFI。
- 审查方法：沿 unlock→derive→import→wrap→rekey→lock/deinit 调用链逐文件通读，行号均用 Read/Grep 实际定位。
- 红线遵守：未执行破坏性命令、未改源码、未输出任何真实密钥/pepper/口令字节（硬编码项仅报位置与类型）。
- 计数：P0=0，P1=1，P2=6，P3=10。

---

## 一、汇总表

| 级别 | 文件:行 | 问题 | 证据 | 触发 | 影响 | 置信度 | 修复 | 验证 |
|---|---|---|---|---|---|---|---|---|
| P1 | core/src/crypto/pepper/verthys_pepper.c:39-44 | 编译内嵌兜底胡椒为 DLL 内全局固定常量（类型：32B 静态数组，非随机/非机器绑定） | `static const uint8_t VERTHYS_PEPPER_COMPILED[VERTHYS_KEY_BYTES]={...}`；init 优先级 3 回退（:535-540） | OS 托管不可用（无 APPDATA / 非 Windows / 存储路径解析失败）且未 inject/未重建 Shamir 时 | 走 COMPILED 源的容器，pepper 对任意拿到 DLL 的人已知 → 离线口令爆破退化为纯口令熵，pepper 设计价值归零 | 确认缺陷 | 兜底改为编译期开关关闭/仅调试构建启用；或对 COMPILED 源容器在解锁时强制告警并拒绝新建；文档标注其强度等同无 pepper | 单元测试：mock load_from_os=UNAVAILABLE，断言默认构建不产生 COMPILED 源容器 |
| P2 | core/src/crypto/cipher/verthys_crypto_cng.c:163-166（配合 keymanager_cng.c:278-283） | `verthys_cng_aead_import_key` 仅在成功路径（:183）清零调用方 key；失败路径（:165 return）不清零。`verthys_cng_km_verify_mek` 在 import 失败分支注释却称"mek 已被 import_key 内部清零"，与实现不符 | import 失败时 `return VERTHYS_ERR_CNG_UNAVAILABLE` 前无 `verthys_secure_zero`；verify_mek :280 注释与代码矛盾 | BCryptGenerateSymmetricKey 失败（CNG 资源/驱动故障） | 候选 MEK（改密旧口令派生）明文残留在调用方栈/堆，未按契约擦除 | 确认缺陷 | 在 import_key 失败 return 前统一 `verthys_secure_zero((void*)key, ...)`；或修正 verify_mek 注释并由调用方负责 | 注入 BCryptGenerateSymmetricKey 失败桩，memcheck/内存扫描确认调用方 key 缓冲全 0 |
| P2 | core/src/crypto/cipher/verthys_crypto_cng.c:31-56, 58-78 | 共享 AES-GCM 提供者 init 仅靠 `InterlockedIncrement(&s_alg_refs)>1` 判幂等，无锁；`open_aes_gcm_provider` 内 `if(s_shared_alg) return` + BCryptOpenAlgorithmProvider 非原子 | 第二个调用方在首个调用方 open 完成前即返回 OK；open 失败回退把 refs 减回，但并发方已认为就绪 | 多线程同时 verthys_cng_km_init / import_key 内联重检 | 双重 BCryptOpenAlgorithmProvider 句柄泄露；refs 计数与实际句柄失配（全局 deinit 误关仍在用的 provider） | 疑似风险（启动单线程时不可达） | 用 once/InitOnceExecuteOnce 或专用 SRWLOCK 保护 open；refs 仅计数不负责打开 | 多线程并发 init/deinit 压力测试，对比 BCrypt 句柄泄漏 |
| P2 | core/src/crypto/keymanager/keymanager_cng.c:433-439 | `verthys_cng_km_rotate_mek` 先销毁旧 MEK 再 import 新 MEK；新 import 失败时 MEK 槽位置空（key=NULL, imported=0），不回滚旧句柄 | `BCryptDestroyKey(old)` → `handle_count--` → import 失败直接 `return r`，无恢复 | CNG 新 MEK 导入失败（内存/驱动） | 运行中 A/B/C 句柄仍在（读写不中断），但任何后续 unwrap/verify_mek 直到重新导入都失败；属设计上已知的降级态（头文件 :167-168 已说明） | 确认缺陷（已接受设计） | 失败时返回前记录健康指标并提示上层触发重新解锁；或先在临时槽 import 成功再切换，失败不动旧槽 | 故障注入：import 返回失败，断言 MEK 槽状态与上层可观测错误 |
| P2 | core/src/security/memory/key_separation.c:371-504（头文件 :149,167） | 旧版 `key_separation_aead_encrypt/decrypt` 的 12B nonce 由调用方外部提供，无内部单调计数器/重放保护（新版 VerthysCngAead 才有 Interlocked 计数器） | 函数签名直接收 `const uint8_t nonce[12]`；未对同 key 下 nonce 唯一性做任何强制 | 旧调用方在固定 key 下重复 nonce（GCM nonce 复用 → 密钥流/认证崩坏） | GCM nonce 复用灾难性泄漏；强度完全依赖调用方纪律，模块自身无防线 | 疑似风险（取决于旧路径调用方） | 旧路径加同 key nonce 用过集合/计数器；或在头文件强制迁移至 VerthysCngAead 并下线旧 aead | 审计所有 key_separation_aead_* 调用点的 nonce 来源（随机/计数器），加重复断言 |
| P2 | core/src/crypto/cipher/verthys_crypto_cng.c:202,229,234,283,288；core/src/security/memory/key_separation.c:383,415,420,483,488 | `size_t`（64 位）→ `ULONG`（32 位）强制截断无范围检查；容量检查 `pt_len + TAG` 亦无溢出守卫 | `(ULONG)plaintext_len`、`*ciphertext_len < plaintext_len + 16` 直接相加 | 单条明文/密文缓冲 ≥ 4 GiB | 截断后 CNG 按错误长度运算/越界；实际 vault 记录难达 4 GiB，但属未设防 | 确认缺陷 | 入口处 `if (plaintext_len > 0xffffffffu - 16) return INVALID;` 并改用 size_t 长度变量传 CNG（CNG 本就限 ULONG） | 大长度模糊测试边界 |
| P2 | core/src/crypto/rekey/verthys_rekey_auto.c:132-163,182-225 | 自动 rekey 无进行中标志/互斥；`maybe_rotate` 在 MT-Safe 写路径后被调用，24h 防震荡仅看时间不看"已在轮换" | check 仅按时间/txid/FLAG 判定；rotate 无 in-progress 锁 | 两个并发写事务同时跨过 90d/10k 阈值且都通过 24h 闸 | 双线程同时 rotate：重复生成 new_*、双次落 alt 槽、双次 vsb_txn 提交（败者回滚）；靠 vsb_txn 兜底无句柄泄漏，但浪费并可能向用户抛错 | 疑似风险（取决于调用方是否在写锁内） | rotate 入口加 `VERTHYS_CNG_KM_REKEYING` 状态互斥（头文件已有该状态枚举却未在此路径设置） | 并发触发压测，确认单写者假设是否成立 |
| P3 | core/src/crypto/cipher/verthys_crypto.c:112 | `combined_len = pw_len + VERTHYS_KEY_BYTES` 无溢出守卫即 malloc/memcpy | size_t 加法未检 | pw_len 接近 SIZE_MAX（实际用户口令不可达） | 理论上溢出后小缓冲溢出；现实不可达 | 改进建议 | `if (pw_len > SIZE_MAX - VERTHYS_KEY_BYTES) return -1;` | 静态分析/UBSan |
| P3 | core/src/security/memory/secure_allocator.c:331-341（对照头 :110-112） | `secure_allocator_free` 仅按 `data_base==ptr` 查找，未校验登记的 `magic`；头文件声称"含魔数校验失败——双重防伪造" | 循环无 `regions[i].magic == meta->magic` 判断 | 指针伪造（实际需知道真实 data_base） | 文档与实现不符；当前指针比较已防 double-free | 改进建议 | 补 magic 校验或修正头注释 | 单测：传入非本分配器指针返回 INVALID |
| P3 | core/src/security/memory/secure_allocator.c:216-218 vs 333-334 | `destroy` 在 `region_release` 返回 0（VirtualFree 失败）时跳过 `budget_unaccount`；而 `free` 路径无条件 unaccount，口径不一致 | destroy: `if (region_release(...)) budget_unaccount(...)` | VirtualFree 偶发失败 | 全局用量记账偏高（后续 95% 拒绝阈值误判） | 改进建议 | 统一：清零+解锁成功即 unaccount，VirtualFree 失败仅记诊断 | 故障注入 VirtualFree 返回失败 |
| P3 | core/src/crypto/rekey/verthys_rekey_auto.c:198-200,370-394,403-411 | 栈上 `new_wa/new_wb/new_wc`（wrapped 子密钥密文）在成功/失败各路径均未显式清零 | 成功路径只清 ka_*/id_*；wrapped 缓冲不落清零 | 函数返回 | 残留 wrapped 密文+nonce 在栈帧（密文非明文密钥，敏感度低） | 改进建议 | 统一 `verthys_secure_zero(new_wa/b/c, ...)` | 内存扫描栈帧 |
| P3 | core/src/crypto/pepper/verthys_pepper.c:49-53 | `g_pepper/g_pepper_initialized/g_pepper_source_error` 等全局无锁非原子；`verthys_pepper_get` 返回指向全局的借用指针 | static 数组/int 无互斥 | get 与 inject/deinit 并发 | 派生中途被 deinit 清零 → Argon2 读已清零缓冲；实际 unlock/lock 由调用方串行 | 改进建议 | 文档明确 MT-Handle；或加只读 RCU/锁 | 并发 get/deinit 竞态测试 |
| P3 | core/src/crypto/pepper/verthys_pepper.c:391-394 | `hardware_binding_get_hash` 失败时静默用全零 OAEP label | `memset(label,0,...)` | 硬件标识采集失败 | 跨设备迁移保护降级为仅 CNG 机器密钥，label 绑定失效（注释已承认） | 确认缺陷（已承认降级） | label 失败时上升为来源错误而非静默零 label | 故障注入 hardware_binding 失败 |
| P3 | core/src/security/memory/memory_guard.c:94-100 | `regions_cs_ensure` 双重检查锁非原子 | `if(!init){InitializeCriticalSection; init=1;}` | 启动期并发首次调用 | 临界区重复初始化（实践单线程 init） | 改进建议 | InitializeOnce 或编译期初始化 | 启动并发压测 |
| P3 | core/src/security/memory/memory_guard.c:541-545 | 巡逻自重排定时器覆盖 `s_patrol_timer` 未 CloseHandle/Delete | WT_EXECUTEONLYONCE 单次触发后句柄未显式收 | 每次 60s 重排 | 轻微句柄/定时器资源 churn | 改进建议 | 重排前 DeleteTimerQueueTimer 旧句柄 | 长时运行句柄计数 |
| P3 | core/src/crypto/pepper/verthys_pepper.c:102-105 | 硬编码 HMAC 域分离常量 `K_FP_DOMAIN_KEY`（类型：文件完整性 HMAC key，非秘密） | static 32B 数组 | 胡椒文件指纹 | 完整性用途，注释明确非秘密；按要求仅报位置 | 确认（设计内） | 无需改动；保持"非秘密完整性键"定位 | — |
| P3 | core/src/crypto/cipher/verthys_crypto.c:17-21 | `verthys_random_bytes` 返回 void，libsodium `randombytes_buf` 失败不可向上传播 | 无返回值 | 系统熵源致命失败（libsodium 默认会 abort） | 调用方无法感知密钥未真正随机 | 改进建议 | 文档约定默认 RNG 失败即 abort；或返回 int | 单测桩 |
| P3 | core/src/security/memory/key_separation.c:451（对照 verthys_crypto_cng.h:107） | 旧路径 `ct_len <= TAG` 拒绝空明文，新 CNG 路径允许空明文（ct_len==TAG） | 严格 `<=` | 空明文小对象 | 两 AEAD 实现行为不一致，移植易踩 | 改进建议 | 统一空明文语义或在头文件标注差异 | 一致性单测 |

---

## 二、已核对为「非缺陷 / 安全」的重点项（避免误报）

1. **rekey 中 `local_pt = ctx3->ptable` 是否活态别名污染**（verthys_rekey_auto.c:280）：查 `verthys_partition.h:86-90`，`VerthysPartitionTable.entries` 是内联定长数组 `VerthysPartition entries[VERTHYS_PARTITION_MAX]`，结构体按值拷贝 → rewrap 循环改的是栈副本，提交后第 6 步（:359-368）再拷回活态；失败路径栈副本随帧丢弃，活态 ptable 不被污染。**原疑似 P1 不成立。**
2. **`get_u64le`/`put_u64le` 字节序**（rekey_auto.c:45-55）：循环方向看似大小端互逆，实际 round-trip 正确（已用 0x1234 与 0x0102…08 验证），非 bug。
3. **`verthys_cng_aead_import_key` 成功路径清零调用方 key**（crypto_cng.c:183）与 `import_wrapped_role` 二次清零（keymanager_cng.c:107）：双副本双清零，正确。
4. **rekey 密钥材料双副本**（rekey_auto.c:235-240）：ka_wrap 供 wrap（内部清）、ka_imp 供 import（内部清），各消耗一份，符合红线。
5. **`secure_zero` 实现**（secure_mem.c:15-19）：用 `SecureZeroMemory`，不存在被编译器优化消除的风险；`memory_guard_secure_zero` 用 volatile 写，同样抗优化。
6. **`verthys_cng_aead_restore_nonce_counter`**（crypto_cng.c:328-338）：`counter < 当前` 拒绝回退，防 nonce 重放，正确。
7. **pepper 文件原子写**（verthys_pepper.c:433-476）：tmp+fflush/_commit+MoveFileEx(REPLACE|WRITE_THROUGH)，失败清理 tmp，正确。
8. **`verthys_cng_km_rotate_abc` 结构拷贝**（keymanager_cng.c:486-491）：移交后 memset 调用方栈结构，无双 destroy 风险；计数配对正确。

---

## 三、硬编码常量清单（仅位置与类型，不含敏感值）

| 位置 | 类型 | 说明 |
|---|---|---|
| verthys_pepper.c:39-44 | 32B 静态数组（**兜底 pepper 本体**） | 最高敏，见 P1 |
| verthys_pepper.c:102-105 | 32B HMAC 完整性 key | 非秘密域分离 |
| verthys_pepper.c:126 | `0x50505656` 魔数 / `0x0003` 版本 | 文件格式标识 |
| keymanager.c:24-26,222-224,283-284 | HKDF/AAD 域分离字符串常量 | "verthys/...-v1/v2/v3" 域分隔，设计内 |
| keymanager_cng.c:26-29,42-47 | wrap AAD 前缀 / 角色 key_id 常量 | 非敏感诊断标识 |
| verthys_rekey_auto.h:67-75 | 90d/10000ops/24h/FT 换算常量 | 轮换策略参数 |
| verthys_crypto.c:192 / verthys.h | integrity info / 版本字节 | 域分离与 ABI |

## 四、需调用方侧继续确认（越出本切片）

- `maybe_rotate` 是否在写事务锁内调用（决定 P2 并发那条是否真实可达）。
- 旧 `key_separation_aead_*` 的实际生产调用点及其 nonce 来源（决定 P2 GCM nonce 那条的实际暴露面）。
- 旧容器迁移路径：无 pepper.bin 的旧容器在首跑会生成**新随机** OS pepper（verthys_pepper.c:279-296），需确认不会以随机 pepper 解锁历史上用 COMPILED pepper 密封的容器（迁移正确性，非本切片代码缺陷）。
