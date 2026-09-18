# 术语表（GLOSSARY）

> 统一 Verthys 全项目专有名词与标识符的中英文对照与定义，术语均来自真实代码标识符并附出处。
>
> Last updated: 2026-09-19 · 维护人：K1Super

约定：本表术语以代码真实命名为准；「主要出处」以 `core/`、`verthys-tauri/` 为相对根。已废弃旧名（`.vault`、`valt://`、`VALTCORE_*`、`Vault_*`、valtcore.dll）仅允许出现在历史/迁移语境，见 [MIGRATION.md](MIGRATION.md)。

---

## 1. 容器与存储

| 中文术语 | 英文/标识符 | 定义（一句话，可验收/可定位） | 主要出处 |
|---|---|---|---|
| Verthys 容器 | .verthys / V3 container（`VERTHYS_V3_SB_MAGIC` `'V3SB'`） | 唯一现役的 V3 加密容器文件，分区认证 + 内容寻址 Extent + LSM 索引 | `core/src/container/shared/verthys_container_v3.h` |
| 超级块 | superblock / `SuperBlockV3` / `VsbTxnV3` | 3 副本 × 16KB 帧 + 法定人数提交的容器根元数据与事务原语 | `core/src/container/superblock/verthys_superblock_v3.c` |
| 法定人数 | quorum / `VERTHYS_ERR_QUORUM_FAILED` | 超级块写 3 副本 ≥2 成功=提交；读取取 txid 最高且 ≥2 副本一致 | `verthys_container_v3.h` |
| 分区 | partition / `nonce_counter` | 每分区独立 AEAD 密钥 + 12B 单调 nonce 计数器（防 GCM nonce 重用，E-7） | `core/src/container/partition/verthys_partition.c` |
| Extent | extent / 内容寻址（BLAKE2b-256） | 以内容哈希寻址的数据区，同内容去重零重写 + 引用计数 | `core/src/container/extent/verthys_extent.c` |
| WAL | 预写日志 / WAL（`verthys_wal_reset`） | 事务先写日志后提交、崩溃可精确重放的预写日志（环形 960KB） | `core/src/transaction/wal/verthys_wal.c` |
| 事务 v3 | txn v3 / 六 Phase | BEGIN→WRITE→PREPARE→COMMIT→CONFIRM→CLEANUP 六阶段原子提交 | `core/src/transaction/txn/verthys_transaction_v3.c` |
| LSM 索引 | LSM / MemTable / SSTable / Compaction | 跳表 MemTable → 分层 SSTable（Bloom xxHash64）+ 后台压实的日志结构索引 | `core/src/index/lsm/verthys_lsm.c` |
| 墓碑 | tombstone | LSM 删除标记，查询按墓碑感知，压实阶段物理删除 | `core/src/index/lsm/verthys_lsm_memtable.c` |
| 温缓存 | warmcache（`verthys_warmcache_v3`） | V3 温启动缓存，独占句柄写 .tmp → `MoveFileExW` 原子替换 | `core/src/index/warmcache/verthys_warmcache_v3.c` |
| 交换信封 | exchange envelope | 导出/导入用的独立加密文件包（不继承应用胡椒） | `core/src/container/format/verthys_format.c` |
| FlatBuffers | flatcc / schema 驱动 | V3 容器序列化运行时（vendored flatcc，构建期 `flatc -a` codegen） | `core/schema/*.fbs` + `third_party/Flatcc.cmake` |

## 2. 密码与密钥

| 中文术语 | 英文/标识符 | 定义 | 主要出处 |
|---|---|---|---|
| 密钥守卫 / CNG 内核托管 | key_separation / CNG | A/B/C 密钥导 CNG 内核句柄，用户态仅瞬态栈帧 | `core/src/security/memory/key_separation.c` |
| 胡椒 | pepper（`verthys_pepper` / `VERTHYS_ERR_PEPPER_SOURCE`） | Argon2id 混入的应用级胡椒，三层来源 + 来源指纹 + 禁兜底 | `core/src/crypto/pepper/verthys_pepper.c` |
| 域密钥 | domain key（`K_VSEC_DOMAIN_KEY`） | 构建期 `.vsec` 签名域密钥，双侧逐字节一致 | `core/src/security/integrity/integrity.c` |
| 机器绑定 | machine binding / `MachineGuid` | 容器跨设备不可解，CNG RSA-OAEP 包装 + MachineGuid 指纹 | `core/src/security/layer3_hw_binding/hardware_binding.c` |
| 全局主密钥 | GMK（`VERTHYS_GLOBAL_KEY_VERIFIER_v2__`） | 全局主密钥，worker 子进程内 `Zeroizing` 持有，永不出 worker | `verthys-tauri/verthys-worker/src/runtime/gmk.rs` |
| 域分离 | domain separation / HKDF info | 用唯一标签隔离各派生用途，如 `verthys/master-key-v1`、`verthys/module/` | `core/src/crypto/cipher/verthys_crypto.h` |
| Argon2id | Argon2id（校准 `argon2_calibrate`） | 内存硬口令派生，创建期两段式校准选参（目标 ~1.2s） | `core/src/crypto/cipher/verthys_crypto.c` |
| XChaCha20-Poly1305 | XChaCha20-Poly1305（24B nonce） | libsodium AEAD，用于交换信封/兼容路径 | `verthys_crypto.c` |
| CNG | Cryptography Next Generation | Windows 内核态密码服务 API（BCrypt AES-GCM，12B nonce） | `core/src/crypto/cipher/verthys_crypto_cng.c` |
| 恢复卡 | Shamir 分片 | pepper 恢复的 k-of-n 分片方案 | `verthys_pepper.c` |

## 3. 安全防御

| 中文术语 | 英文/标识符 | 定义 | 主要出处 |
|---|---|---|---|
| .vsec | 构建期签名节（magic `'VESC'`） | `.text`/`.rdata` 文件内容 HMAC-SHA256 构建期签名（128B），启动验签 | `core/src/security/integrity/integrity.c` |
| .rhat 运行时哈希 | runtime hash（magic `'VRHT'`） | 32 关键函数 BLAKE2b-256 运行时哈希，失配 = KILL | `core/src/security/integrity/runtime_hash.c` + `core/tools/rhash_gen.c` |
| 解锁管线 | unlock_pipeline / S0-S6 | 解锁 S0-S6 流水线 + 渐进式（`VERTHYS_ERR_PARTIAL_UNLOCK`） | `core/src/api/unlock/verthys_unlock_pipeline.c` |
| 层 1-6 防御 | layer1..6 | 进程守卫/硬件绑定/钩子防御/沙箱/闭环的分层纵深防御 | `core/src/security/layer*_*` |
| 防御闭环 | defense closure / 7 路径 | 7 条攻击路径状态机（BLOCKED/DEGRADED/FAILED） | `core/src/security/layer6_closure/defense_closure.c` |
| 应急分级响应 | emergency / TELEMETRY·DEGRADE·KILL | 三级信号模型，检测与响应解耦 | `core/src/security/emergency/emergency.c` |
| 直接系统调用 | syscall_direct / SSN | SSN 排序法提取 + W^X stub 页，失败优雅降级 | `core/src/security/anti_analysis/syscall_direct.c` |
| 安全分配器 | secure_allocator | 密钥专用 VirtualAlloc 隔离堆 + 全局内存预算记账 | `core/src/security/memory/secure_allocator.c` |
| 渐进式解锁 | progressive unlock / `VERTHYS_ERR_PARTIAL_UNLOCK`(0x11) | 最小可操作优先，索引预热转后台 | `core/include/verthys.h` |

## 4. 进程与工程

| 中文术语 | 英文/标识符 | 定义 | 主要出处 |
|---|---|---|---|
| worker 子进程 | verthys-worker | 加载 DLL + 单线程 FFI 转发，BELOW_NORMAL 优先级 | `verthys-tauri/verthys-worker/src/main.rs` |
| FFI | C ABI / libloading | C DLL 与 Rust 的边界，libloading 按名解析 29 白名单符号 | `verthys-tauri/verthys-worker/Cargo.toml` |
| NSIS | nsis | Tauri Windows 安装包目标 | `verthys-tauri/src-tauri/tauri.conf.json` |
| keyboard-types | keyboard-types（本地补丁） | Rust 键盘事件类型 crate，项目以本地补丁修复 serde 兼容 | `verthys-tauri/src-tauri/Cargo.toml`（[patch.crates-io]） |
| 状态魔法数 | `STATE_MAGIC`（`VERTHYS_STATE`） | 状态文件 magic 前缀（与版本号分离） | `verthys-tauri/src-tauri/src/constants.rs` |
| 进程隔离（双层 Job） | job_isolation | 双层 Job Object + 白名单 DACL（进程守卫） | `core/src/security/layer1_process_guard/job_isolation.c` |