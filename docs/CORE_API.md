# C 核心公开 API（verthys.h）
> C 核心 DLL（verthys.dll）对外标准 C ABI 接口规范，函数签名与语义逐一照源码编写。
>
> Last updated: 2026-09-19 · 维护人：K1Super

本文档是 C 核心动态库对外接口的唯一契约文件，与 `core/include/verthys.h`（公开头文件）、
`core/verthys.def`（导出符号白名单）逐条对齐。所有签名、枚举值、成员语义均照源码编写；
未在源码注释中显式给出的错误码语义已标注“据实现推断”。接口分组以头文件实际声明为准。

---

## 1. 包含方式

```c
#include "verthys.h"          /* 公开 ABI：Verthys_* 接口 + VerthysResult 错误码（唯一错误码体系） */
```

- 头文件仅依赖标准库 `<stdint.h>` / `<stddef.h>`，自包含，无第三方头文件依赖。
- 公开头文件路径：`core/include/verthys.h`；导出白名单：`core/verthys.def`。
- 动态库产物：`verthys.dll`（CMake Release，构建见 `build_production.ps1`）。

## 2. 调用约定与导出宏 `VERTHYS_API`

- 调用约定：`VERTHYS_CALL` 在 Windows 下展开为 `__cdecl`；非 Windows 下为空。
- 导出宏：`VERTHYS_API` 在 Windows 下**恒为空**（不再携带 `__declspec(dllexport/dllimport)`）。
  符号导出**唯一**由链接器 `/DEF:verthys.def` 白名单管控；未列入 `.def` 的接口一律不可达。
  消费方（verthys-worker）经 `libloading` 按名运行时解析，不依赖导入库。
- 版本宏：`VERTHYS_API_VERSION = 0x0014u`，调用方可用 `#if` 做编译期能力判断。
  0x0014 追加：`VerthysSecurityStatus` 原因码/已加固的用户态上限计数/策略位/采样时间，
  以及进程级运行时守卫通知接口 `Verthys_NotifyRuntimeGuards`。

## 3. 不透明句柄 `VerthysHandle`

```c
typedef struct VerthysHandleImpl *VerthysHandle;
```

- 前置声明不完整结构体，内部实现仅源文件可见；外部无法解引用、强转或访问成员。
- 调用方只持有句柄完成指令调用，不接触任何密钥、运行状态等敏感内部数据。
- 句柄由 `Verthys_Init` 分配，必须用 `Verthys_Deinit` 释放；记录数据等多以内部借用指针返回。

## 4. 错误处理统一模式（`VerthysResult`）

所有公开 API 返回 `VerthysResult`（32 位无符号枚举）。成功为 `VERTHYS_OK`（0）。
典型用法：

```c
VerthysHandle h = NULL;
VerthysResult r = Verthys_Init(&h);
if (r != VERTHYS_OK) {
    /* 按错误码分类处理；不要打印/解析内部细节 */
}
```

安全规则：各类认证失败、数据篡改、密码错误在错误码粒度上不做区分（统一返回
`VERTHYS_ERR_AUTH` 等），仅内部日志记录详情，防止攻击者枚举探测。

> 示例来源说明：`core/examples/ffi/` 下仅有 `cng_example.c`，它演示的是 `verthys.h`
> 的 `VerthysResult` 错误码与 CNG 纯函数调用，**并未**调用 `verthys.h` 的 `Verthys_*`
> 公共 API。本仓库暂无调用 `Verthys_*` ABI 的 C 示例文件，上面的 `VerthysResult` 用法为本文档
> 撰写（非取自 `examples/ffi` 实文件）；实际调用范例见 `core/tests/api/`（test_init.c、
> test_verthys_api.c 等）。

## 5. 错误码体系（唯一：`VerthysResult`）

### 5.1 `VerthysResult`（verthys.h，公开 ABI 返回值，u32）

| 枚举 | 值 | 含义 |
|---|---|---|
| `VERTHYS_OK` | `0x00000000` | 成功 |
| `VERTHYS_ERR_INVALID` | `0x00000001` | 入参非法、句柄无效 |
| `VERTHYS_ERR_AUTH` | `0x00000002` | 认证/解密校验未通过（含数据篡改场景统一返回） |
| `VERTHYS_ERR_NOTFOUND` | `0x00000003` | 目标记录不存在 |
| `VERTHYS_ERR_EXISTS` | `0x00000004` | 记录已存在，禁止重复创建 |
| `VERTHYS_ERR_FORMAT` | `0x00000005` | 容器文件格式不符合规范 |
| （缺口） | `0x00000006` | 历史值缺口，未定义 |
| `VERTHYS_ERR_LOCKED` | `0x00000007` | 容器锁定态，无法读写 |
| `VERTHYS_ERR_IO` | `0x00000008` | 磁盘读写 IO 异常 |
| `VERTHYS_ERR_CORRUPT` | `0x00000009` | 数据区块完整性校验失败（区别于认证错误） |
| `VERTHYS_ERR_RATE` | `0x0000000A` | 触发访问限流（暴力破解频次管控） |
| `VERTHYS_ERR_SNAPSHOT` | `0x0000000B` | 扫描游标快照版本过期，需重建游标 |
| `VERTHYS_ERR_PEPPER_SOURCE` | `0x0000000C` | 胡椒来源不可用/来源漂移（区别于密码错误） |
| `VERTHYS_ERR_EXPORT_TOO_MANY` | `0x0000000D` | 导出记录数超 v1 格式上限（65535），拒绝导出 |
| `VERTHYS_ERR_CNG_UNAVAILABLE` | `0x0000000E` | CNG 内核态密码服务不可用（降级链耗尽） |
| `VERTHYS_ERR_RESOURCE_LIMIT` | `0x0000000F` | 全局内存预算耗尽（≈512MB 的 95%） |
| `VERTHYS_ERR_QUORUM_FAILED` | `0x00000010` | 超级块法定人数不满足（3 副本有效 < 2） |
| `VERTHYS_ERR_PARTIAL_UNLOCK` | `0x00000011` | 渐进式解锁：最小可操作态，索引未完全预热 |
| `VERTHYS_ERR_TIMEOUT` | `0x00000012` | 解锁流水线总超时（预算 10s） |
| `VERTHYS_ERR_UNSUPPORTED` | `0x00000013` | 容器格式不支持该操作（显式拒绝） |
| `VERTHYS_ERR_NONCE_EXHAUSTED` | `0x00000014` | 加密层 nonce 计数器耗尽（2^64 计数空间用尽），须密钥轮换 |
| `VERTHYS_ERR_CONTAINER_BUSY` | `0x00000015` | 容器被其他进程独占占用（单写者语义拒绝第二写者），重试需等待持有者退出 |
| `VERTHYS_ERR_UNAUTHORIZED` | `0x00000016` | 宿主或 DLL 缺少有效发布者签名，`Verthys_Init` 在密钥操作前拒绝 |
| `VERTHYS_ERR_POLICY` | `0x00000017` | 策略拒绝：模块未启用/未解锁、恢复会话缺少恢复槽、非恢复会话发起全库轮换等 |
| `VERTHYS_ERR_TPM` | `0x00000018` | TPM/PCR 不可用或 PCR 策略不匹配；调用方应引导恢复码重密封或显式移除 PCR |
| `VERTHYS_ERR_ROLLBACK` | `0x00000019` | 回退锚点拒绝旧副本；调用方应提示文件回退 |
| `VERTHYS_ERR_KEYFILE_REQUIRED` | `0x0000001A` | KEYFILE 标志置位但调用方未提供 keyfile（口令尚未参与判定） |
| `VERTHYS_ERR_KEYFILE_INVALID` | `0x0000001B` | keyfile 不是合法 VKFL v1（长度/magic/version/flags/checksum 不符） |
| `VERTHYS_ERR_ROTATE_PENDING` | `0x0000001C` | 全库 DEK 轮换作业未收敛，源库只读；调用方可稍后重试或先提交/中止 |
| `VERTHYS_ERR_MODULE_LOCKED` | `0x0000001D` | 目标模块未解锁（模块保护已启用且当前会话未持有模块密钥） |
| `VERTHYS_ERR_NO_SPACE` | `0x0000001E` | 数据区/文件系统空间不足（区别于内存预算耗尽） |
| `VERTHYS_ERR_VERIFY` | `0x0000001F` | 完整性复核失败（Merkle/摘要不一致，区别于 AEAD 认证失败） |
| `VERTHYS_ERR_INTERNAL` | `0xFFFFFFFF` | 未归类底层内部异常 |

## 6. 线程安全模型标注规范

| 标注 | 含义 |
|---|---|
| MT-Safe | 全线程安全，内部自带互斥，多线程可并发调用 |
| MT-Unsafe | 非线程安全，同一句柄不可多线程并发执行 |
| MT-Const | 只读安全，只读接口可并发，禁止与写操作并行 |
| MT-Handle | 句柄级安全，不同句柄可并发，同一句柄禁止并发 |

并发度注记（与实现对齐）：记录读取与扫描沿 COW 目录树持共享锁，读者可并行；
写操作经 `api_mutex` 串行化。

## 7. 接口分组总览（扩展分组见 §18；完整导出面以 `verthys.def` 为准）

| # | 功能域 | 函数 |
|---|---|---|
| 1 | 生命周期 | Verthys_Init / Verthys_NotifySandboxAttrs / Verthys_Deinit / Verthys_V4Create / Verthys_V4Unlock / Verthys_V4UnlockKeyfile / Verthys_V4UnlockRecovery / Verthys_Lock / Verthys_Flush |
| 2 | 记录 CRUD | Verthys_AddRecord / Verthys_AddRecords / Verthys_GetRecord / Verthys_DeleteRecord / Verthys_DeleteRecords |
| 3 | 导入导出 / 改密 | Verthys_Export / Verthys_Import / Verthys_ChangePassword |
| 4 | 容器诊断 | Verthys_GetContainerInfo / Verthys_VerifyIntegrity / Verthys_GetDiagnostics / Verthys_GetSecurityStatus |
| 5 | 全量扫描游标 | Verthys_ScanOpen / Verthys_ScanFetch / Verthys_ScanRecordFree / Verthys_ScanClose |
| 6 | 摘要扫描游标 | Verthys_ScanSummaryOpen / Verthys_ScanSummaryFetch / Verthys_ScanSummaryRecordFree / Verthys_GetSummaryCount |
| 7 | 类型探测 | Verthys_HasRecordByType / Verthys_FindFirstLidByType |

---

## 8. 生命周期

### Verthys_Init
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Init(VerthysHandle *out_handle);`
- 参数：`out_handle` — 输出，新创建的句柄（失败时为 NULL）。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID`（out_handle 为 NULL）/ `VERTHYS_ERR_INTERNAL`（上下文分配失败）。（据实现推断）
- 内存：句柄由库内部分配，须以 `Verthys_Deinit` 释放；调用方不 `free`。
- 线程安全：MT-Safe（无全局共享状态，可多线程并行创建多个独立句柄）。

### Verthys_NotifySandboxAttrs
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_NotifySandboxAttrs(uint32_t attrs);`
- 参数：`attrs` — worker 进程已应用的沙盒属性位掩码（与 `process_sandbox` 模块 `SANDBOX_ATTR_*` 对齐）。
- 语义：worker 加载 DLL 后、调用 `Verthys_Init` 之前调用，防御闭环据此识别已生效内核 mitigation policy。
- 返回：`VERTHYS_OK`（实现对任意 attrs 均返回 OK；源码未注释错误分支，据实现推断）。
- 内存：无。
- 线程安全：MT-Safe（Init 前单线程调用）。

### Verthys_Deinit
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Deinit(VerthysHandle handle);`
- 参数：`handle` — 待销毁句柄。
- 语义：销毁上下文，安全擦除内存敏感数据后释放资源。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID`（handle 为 NULL 或非有效句柄）。（据实现推断）
- 内存：释放句柄全部资源；调用方不得再使用该句柄。
- 线程安全：MT-Unsafe（同一句柄不可与其它操作并发销毁）。

### Verthys_V4Unlock
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4Unlock(VerthysHandle handle, const char *verthys_path, const char *password, size_t password_len);`
- 参数：
  - `verthys_path` — 已有容器文件路径；文件不存在返回 IO 错误，**不会**自动创建容器。
  - `password` / `password_len` — 主密码（UTF-8，长度由 `password_len` 指定）。
- 语义：校验 `VRTY` 固定头 → pepper 快速失败 → `.vsec` 验签 → 口令 + 设备根双槽解封 `K_c` →
  元数据与 DataRoot 挂载；全部成功后才进入 UNLOCKED，不存在部分解锁中间态。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_RATE`（限流）/ `VERTHYS_ERR_IO` /
  `VERTHYS_ERR_AUTH`（口令错误）/ `VERTHYS_ERR_PEPPER_SOURCE` / `VERTHYS_ERR_FORMAT`（异种格式）/
  `VERTHYS_ERR_CORRUPT` / `VERTHYS_ERR_CNG_UNAVAILABLE` / `VERTHYS_ERR_TPM` / `VERTHYS_ERR_INTERNAL`。
- 内存：解锁成功后句柄进入可读写就绪态；路径/口令由库内部拷贝使用，调用方可用栈上/临时缓冲。
- 线程安全：MT-Unsafe（同一句柄禁止并发解锁）。

### Verthys_V4Create
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4Create(VerthysHandle handle, const char *verthys_path, const char *password, size_t password_len, char *recovery_text, size_t recovery_cap);`
- 参数：`recovery_text` — 输出恢复码的缓冲区（容量必须 >= 80 字节）；`recovery_cap` — 缓冲区容量。
- 语义：全新创建容器；路径必须不存在（否则返回 `VERTHYS_ERR_EXISTS`）；创建即解锁；预设参数持久写入容器元数据。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_EXISTS` / `VERTHYS_ERR_IO` / `VERTHYS_ERR_PEPPER_SOURCE` / `VERTHYS_ERR_INTERNAL`。
- 内存：同 `Verthys_V4Unlock`；恢复码缓冲区由调用方负责清零。
- 线程安全：MT-Unsafe。

### Verthys_Lock
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Lock(VerthysHandle handle);`
- 语义：锁定容器，清空内存中所有密钥与明文，句柄退回锁定态；碎片整理/全量校验后置为后台异步，本接口仅刷盘 + 敏感内存清零。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED`（已是锁定态）/ `VERTHYS_ERR_INTERNAL`。（据实现推断）
- 内存：敏感缓冲区安全擦除。
- 线程安全：MT-Unsafe。

### Verthys_Flush
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Flush(VerthysHandle handle);`
- 语义：不锁定，主动将内存中缓存的索引事务变更落盘，提升异常崩溃时数据一致性。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_INTERNAL`。（据实现推断）
- 内存：无借用指针影响（**注意**：`GetRecord` 的借用指针在本调用后失效，见下）。
- 线程安全：MT-Safe。

---

## 9. 记录 CRUD

### Verthys_AddRecord
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_AddRecord(VerthysHandle handle, const VerthysRecord *record, uint64_t *out_id);`
- 参数：`record` — 新增记录载体（`type` / `name`(UTF-8，长度由 `name_len` 判定) / `data`(任意二进制，长度 `data_len`)）；`out_id` — 输出系统分配的唯一逻辑 ID。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_INTERNAL`。（据实现推断）
- 内存：`record` 入参由库内部拷贝，调用方可即时释放。
- 线程安全：MT-Safe（内部事务锁保证并发写入安全）。

### Verthys_AddRecords（API 0x0013）
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_AddRecords(VerthysHandle handle, const VerthysRecord *records, uint32_t count, uint64_t *out_ids);`
- 参数：`records` — 记录数组；`count` — 条数（1..`VERTHYS_ADD_RECORDS_MAX`=512）；`out_ids` — 与输入等长的 ID 输出数组。
- 语义：全部记录在**单次事务**中提交，共享一次 DataRoot/元数据落盘；任一条失败整体回滚到调用前的根，`out_ids` 全置 0。大文件导入据此把落盘成本从「记录条数 × 提交」压到「子批 × 提交」。
- 校验：每条按 `Verthys_AddRecord` 同一规则校验；任一非法即整批拒绝且不产生写入。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_FORMAT`（非当前容器格式）/ `VERTHYS_ERR_RESOURCE_LIMIT`（单条载荷超出 IPC 预算）。
- 借用指针：与其他写操作相同，使既有 `Verthys_GetRecord` 借用指针失效。
- 线程安全：MT-Safe。

### Verthys_GetRecord
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetRecord(VerthysHandle handle, uint64_t id, VerthysRecord *out_record);`
- 参数：`id` — 目标记录逻辑 ID；`out_record` — 输出记录。
- 所有权模型：`out_record->data` 与 `out_record->name` 为**内部借用指针**（指向上下文私有缓存
  `last_getrecord_data` / `last_getrecord_name`）。调用方**不持有所有权**，禁止 `free()`、禁止长期保存。
- 失效时机（写操作即失效，继续访问 = Use-After-Free）：`Verthys_AddRecord` / `Verthys_AddRecords` /
  `Verthys_DeleteRecord` / `Verthys_DeleteRecords` / `Verthys_Import` / `Verthys_ChangePassword` / `Verthys_Flush` /
  `Verthys_Lock` / `Verthys_Deinit`；再次调用任意 `Verthys_GetRecord` 也会使上一次借用指针失效（同一时刻最多一组有效）。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_NOTFOUND` / `VERTHYS_ERR_INTERNAL`。（据实现推断，NOTFOUND 对应记录不存在）
- 内存：如上述借用约定；跨写操作保留内容须先深拷贝。
- 线程安全：MT-Unsafe（借用指针不支持跨线程共享）。

### Verthys_DeleteRecord
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_DeleteRecord(VerthysHandle handle, uint64_t id);`
- 语义：单次调用触发一次完整事务提交；大批量删除优先用 `Verthys_DeleteRecords`（合并单事务）。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_INTERNAL`。（据实现推断）
- 线程安全：MT-Safe。

### Verthys_DeleteRecords
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_DeleteRecords(VerthysHandle handle, const uint64_t *ids, size_t count);`
- 语义：多条合并为单次事务提交，仅一次磁盘刷盘，适合大批量清理。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_INTERNAL`。（据实现推断）
- 线程安全：MT-Safe。

---

## 10. 导入导出 / 改密

### Verthys_Export
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Export(VerthysHandle handle, const char *export_path, const char *password, size_t password_len);`
- 语义：导出当前容器为独立加密文件包，可设独立访问密码，不继承应用层胡椒参数；流式分片写入（大数量不爆内存）。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_FORMAT` /
  `VERTHYS_ERR_EXPORT_TOO_MANY`（记录数 > 65535，v1 格式上限）/ `VERTHYS_ERR_INTERNAL`。（据实现推断）
- 线程安全：MT-Safe。

### Verthys_Import
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Import(VerthysHandle handle, const char *import_path, const char *password, size_t password_len);`
- 语义：导入外部加密容器并合并至当前容器；多条记录合并单次事务提交。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_FORMAT` /
  `VERTHYS_ERR_IO` / `VERTHYS_ERR_AUTH`（导入密码错误）/ `VERTHYS_ERR_INTERNAL`。（据实现推断）
- 线程安全：MT-Safe。

### Verthys_ChangePassword
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ChangePassword(VerthysHandle handle, const char *old_pw, size_t old_len, const char *new_pw, size_t new_len);`
- 语义：仅重加密数据密钥（不重加密业务数据）；改密前自动提交未完成事务。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_AUTH`（旧密码错误）/
  `VERTHYS_ERR_FORMAT` / `VERTHYS_ERR_INTERNAL`。
- 线程安全：MT-Safe。---

## 11. 容器诊断

### Verthys_GetContainerInfo
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetContainerInfo(VerthysHandle handle, VerthysContainerInfo *out_info);`
- 语义：读取容器配置/容量/统计只读信息（`api_version`、`fmt_version`、`preset`、`record_count`、`txid`、
  `index_region_size`、`data_region_size`、`data_used_bytes`、`cumulative_write_bytes`、`mount_count`、
  `last_modified_time`、`container_id[16]`、`warm_cache_enabled`、`merkle_pending` 等），不含任何密钥/明文。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_INTERNAL`。（据实现推断）
- 内存：调用方提供结构体，库填充。
- 线程安全：MT-Const。

### Verthys_VerifyIntegrity
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_VerifyIntegrity(VerthysHandle handle, uint64_t *out_failed_lids, uint64_t max_failed, uint64_t *out_failed_count);`
- 语义：遍历全部数据块做 AEAD 标签校验 + Merkle 树哈希校验；输出损坏记录 ID 列表（`out_failed_lids`，
  容量 `max_failed`）与损坏总数（`out_failed_count`）；耗时较长，建议后台低优先级线程；校验期间禁止写入。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_INTERNAL`。（据实现推断）
- 内存：`out_failed_lids` 由调用方分配（至少 `max_failed * sizeof(uint64_t)`）。
- 线程安全：MT-Unsafe。

### Verthys_GetDiagnostics
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetDiagnostics(VerthysHandle handle, VerthysDiagnostics *out_diag);`
- 语义：读取运行性能指标（解锁耗时拆解、缓存命中/淘汰、GC 计数、事务提交/回滚、扫描游标、胡椒来源标记、
  锁等待、持久化缓存加载耗时、磁盘读取字节、页缓存命中率、预热状态、Argon2 漂移监控、索引 mmap 回退计数）。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID`。（据实现推断）
- 内存：调用方提供结构体。
- 线程安全：MT-Const。

### Verthys_GetSecurityStatus
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetSecurityStatus(VerthysHandle handle, VerthysSecurityStatus *out_status);`
- 语义：查询防御闭环 7 攻击路径状态（`VerthysDefensePath`：挂起绕过/内存 Dump/休眠取证/IAT Hook/DLL 劫持/进程读取/跨设备迁移），
  每次调用执行 RUNTIME 级实时复检；进程级事实，锁定态/未挂载态均可查询；FAILED 不改变返回值（诊断查询无处置语义）。
- 字段：`path_state[7]` + 计数/标志为既有 48 字节前缀；0x0014 追加 `path_reason[7]`
  （`VerthysDefenseReason` 0–20）、`limited_count`（已加固的用户态上限项数）、`policy_flags`
  （bit0=心跳 bit1=挂起守卫 bit2=防转储巡检）、`checked_at_unix_ms`（快照采样时间），总 104 字节。
  追加字段位于既有 `reserved[6]` 之后，旧调用方读取前缀布局不受影响。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID`（handle 为 NULL、句柄已注销或 out_status 为 NULL）/ `VERTHYS_ERR_INTERNAL`。
- 内存：调用方提供结构体；库在调用内清零并回填全部字段。
- 线程安全：MT-Safe（registry→句柄快照锁，随后进入检查锁）。

### Verthys_NotifyRuntimeGuards
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_NotifyRuntimeGuards(uint32_t flags);`
- 语义：写入进程级运行时守卫**完整掩码**（非累加 OR）。bit0=worker 心跳已运行，
  bit1=挂起守卫已接线；停止守卫时下发 0。未知位丢弃。
- 返回：`VERTHYS_OK`（无句柄参数；守卫为进程级事实）。
- 线程安全：MT-Safe（原子交换）。
- 版本：API 0x0014。旧 DLL 无此导出时 worker 仅记录一次诊断，不阻断启动。

#### VerthysDefenseReason 原因码

| 值 | 名称 | 语义 |
|---|---|---|
| 0 | NONE | 无附加原因 |
| 1 | NO_RESIDENT_KEY | 无驻留密钥（锁定/未挂载态的正常阻断理由） |
| 2 | V4_KEYS_USER_RESIDENT | 密钥驻留用户态（用户态上限，防护已加固，计入 `limited_count`） |
| 3 | HIBERNATION_ENABLED | 系统休眠启用，休眠镜像可能含密钥 |
| 4 | HIBERNATION_UNKNOWN | 休眠状态不可判定 |
| 5 | SUSPEND_UNPREVENTABLE | 管理员挂起不可阻止（用户态上限，看门狗已生效，计入 `limited_count`） |
| 6 | SUSPEND_GUARD_INACTIVE | 挂起看门狗未接线（可修复降级） |
| 7 | HOOK_SCAN_CLEAN | 挂钩扫描干净 |
| 8 | HOOK_SCAN_UNAVAILABLE | 扫描不可用（ntdll 基线/读取失败） |
| 9 | HOOK_DETECTED | 检测到 IAT/Inline Hook |
| 10 | SANDBOX_VERIFIED | OS 回读全部核心 mitigation 位 |
| 11 | SANDBOX_PARTIAL | 仅部分 mitigation 位可回读 |
| 12 | SANDBOX_UNVERIFIED | 无法回读 mitigation |
| 13 | JOB_ACTIVE | 进程 Job 隔离生效 |
| 14 | DEVICE_BOUND | 设备根/TPM 绑定可用 |
| 15 | NO_SESSION_FACTS | 缺少会话事实 |
| 16 | MODULE_INIT_FAILED | 防御模块初始化失败 |
| 17 | POLICY_DISABLED | 当前策略关闭对应防护 |
| 18 | EVIDENCE_STALE | 扫描证据超过有效期 |
| 19 | ARCH_LIMIT_KERNEL_DEFERRED | 内核态托管暂缓（用户态加固已生效） |
| 20 | HIBERNATION_DISABLED | 系统休眠已禁用 |

---

## 12. 全量扫描游标（完整解密读取）

流程：`Verthys_ScanOpen` → 循环 `Verthys_ScanFetch` → `Verthys_ScanRecordFree` → `Verthys_ScanClose`。
游标绑定事务快照，扫描中不感知新写入，保证遍历一致性。

### Verthys_ScanOpen
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanOpen(VerthysHandle handle, uint64_t start_lid, uint64_t batch_size, VerthysScanCursor **out_cursor);`
- 参数：`start_lid` — 起始遍历 ID；`batch_size` — 单次批量条数；`out_cursor` — 输出游标。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_FORMAT`（v1 容器不含游标能力）。（据实现推断）
- 内存：游标由库分配，须 `Verthys_ScanClose` 释放。
- 线程安全：MT-Unsafe（同一容器句柄不可并发开多个游标）。

### Verthys_ScanFetch
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanFetch(VerthysScanCursor *cursor, VerthysRecord *out_records, uint64_t *out_lids, uint64_t max_count, uint64_t *out_count, uint64_t *out_failed_lids, uint64_t *out_failed_count);`
- 语义：批量拉取完整解密记录；解密失败的损坏条目单独输出失败 ID 列表（不静默丢弃）；拉取前校验快照事务版本，
  容器已修改则返回 `VERTHYS_ERR_SNAPSHOT`（需重建游标）；返回记录为堆深拷贝，须 `Verthys_ScanRecordFree` 释放。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_SNAPSHOT`（快照过期）。（据实现推断）
- 内存：`out_records` 每条需逐条 `Verthys_ScanRecordFree`；不得 `free`。
- 线程安全：MT-Const。

### Verthys_ScanRecordFree
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanRecordFree(VerthysRecord *record);`
- 语义：释放单条扫描记录堆内存并安全擦除。返回 `VERTHYS_OK` / `VERTHYS_ERR_INVALID`。
- 线程安全：MT-Safe。

### Verthys_ScanClose
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanClose(VerthysScanCursor *cursor);`
- 语义：关闭游标，释放迭代器/缓冲区/快照版本资源。返回 `VERTHYS_OK` / `VERTHYS_ERR_INVALID`。
- 线程安全：MT-Unsafe（同一游标禁止并发关闭）。

---

## 13. 摘要扫描游标（仅元数据，不解密数据块）

### Verthys_ScanSummaryOpen
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanSummaryOpen(VerthysHandle handle, uint64_t start_lid, uint64_t batch_size, VerthysScanCursor **out_cursor);`
- 语义：底层同全量扫描，仅跳过数据块读取解密。返回 `VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_FORMAT`。（据实现推断）
- 线程安全：MT-Unsafe。

### Verthys_ScanSummaryFetch
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanSummaryFetch(VerthysScanCursor *cursor, VerthysSummaryRecord *out_records, uint64_t *out_lids, uint64_t max_count, uint64_t *out_count);`
- 语义：批量拉取摘要元数据（`lid`/`type`/`name_len`/`name`/`data_size`/`physical_offset`/`merkle_leaf[32]`/`created_time`/`slot_state`）。仅解密名称，不读记录数据段。
- 类型字段：摘要不读记录密文，`type` 恒为 0（未知）。需要按业务类型取记录 ID 时必须使用 `Verthys_ListIdsByType`（类型盲索引），不得依赖摘要 `type` 过滤。
- `name` 字段为堆拷贝，须 `Verthys_ScanSummaryRecordFree` 释放。返回 `VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_SNAPSHOT`。（据实现推断）
- 线程安全：MT-Const。

### Verthys_ScanSummaryRecordFree
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanSummaryRecordFree(VerthysSummaryRecord *record);`
- 语义：释放摘要记录 `name` 字符串堆内存并安全擦除。返回 `VERTHYS_OK` / `VERTHYS_ERR_INVALID`。
- 线程安全：MT-Safe。

### Verthys_GetSummaryCount
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetSummaryCount(VerthysHandle handle, uint64_t *out_count);`
- 语义：获取已加载摘要索引记录总数，用于判断是否可直接渲染列表。返回 `VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_INTERNAL`。（据实现推断）
- 线程安全：MT-Const。

---

## 14. 类型探测

### Verthys_HasRecordByType
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_HasRecordByType(VerthysHandle handle, uint8_t rtype, uint8_t *out_found);`
- 参数：`rtype` — 目标记录类型；`out_found` — 1=存在，0=不存在。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_FORMAT`（v1 容器不支持摘要索引，out_found=0）。
- 语义：只扫摘要索引不读数据块，典型 < 100ms（v2 容器）。线程安全：MT-Const。

### Verthys_FindFirstLidByType
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_FindFirstLidByType(VerthysHandle handle, uint8_t rtype, uint8_t *out_found, uint64_t *out_lid);`
- 参数：`out_found` — 1=存在；`out_lid` — 匹配记录 lid（found=1 时有效）。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID`（handle/out_found/out_lid 任一 NULL）/ `VERTHYS_ERR_LOCKED`。
- 语义：与 `HasRecordByType` 差异：同时返回 found 标志与 lid（单次遍历）；v1 容器返回 `VERTHYS_OK` + out_found（绝不返回 FORMAT）。线程安全：MT-Const。

### Verthys_ListIdsByType（API 0x0012）
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ListIdsByType(VerthysHandle handle, uint8_t rtype, uint64_t after_id, uint64_t max_count, uint64_t *out_ids, uint64_t *out_count, uint8_t *out_exhausted);`
- 参数：`after_id` — 上一页最后一个 ID，首页传 0；`max_count` — 1..`VERTHYS_TYPE_ID_BATCH_MAX`（4096）。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_LOCKED` / `VERTHYS_ERR_FORMAT`（非当前容器格式）。
- 语义：走类型盲索引 `VTY_KS_TYPE` 分页枚举业务类型 ID，严格升序、跳过墓碑；不读取记录密文，不依赖摘要 `type`。`out_exhausted=1` 表示该类型无更多记录。线程安全：MT-Const。

---

## 15. 关键数据结构（节选）

| 结构体 | 用途 | 内存约定 |
|---|---|---|
| `VerthysRecord` | 单条记录（增/读载体） | `GetRecord` 返回借用指针；`ScanFetch` 返回须 `ScanRecordFree` |
| `VerthysSummaryRecord` | 摘要元数据 | `name` 堆拷贝须 `ScanSummaryRecordFree` |
| `VerthysRecordType` | PHOTO=0x01 / ACCOUNT=0x02 / CERT_MANAGER=0x03 / FILE_VERTHYS=0x04 | — |
| `VerthysSlotState` | FREE=0 / VALID=1 / OBSOLETE=2 / PENDING=3 / CORRUPT=4 | — |
| `VerthysContainerInfo` | 容器只读统计 | 调用方结构体，库填充 |
| `VerthysDiagnostics` | 运行时性能指标 | 调用方结构体，库填充 |
| `VerthysSecurityStatus` | 防御闭环 7 路径状态（104 字节） | `path_state[7]` + 计数 + `path_reason[7]` + `limited_count` + `policy_flags` + `checked_at_unix_ms` |

## 16. 符号前缀与旧符号残留

- 所有公开符号前缀均为 `Verthys_`。全仓源码/头文件中**未发现**旧 `Vault_` 前缀残留
  （历史归档报告中出现 4 处历史记录，非代码）。
- 导出白名单 `core/verthys.def` 共 68 个符号（模块/轮换（含 keyfile 补录）/PCR/keyfile 等扩展已并入，
  0x0014 追加 `Verthys_NotifyRuntimeGuards`），与头文件声明一一对应。
- 名称遗留（供整改参考）：`VerthysRecordType` 中 `VERTHYS_RECORD_FILE_VERTHYS` 语义为“文件保险箱类数据”，
  命名冗余但属源码现状，本文档照实记录，未改代码。

## 17. 交叉引用

- 桥接层命令：见 `TAURI_BRIDGE.md`（Rust 侧经 worker 子进程调用本 DLL）。
- 设计与信任模型：见 `SECURITY_DESIGN.md`。
- 构建/配置：见 `CONFIGURATION.md` 与根 `build_production.ps1`。
- 术语：见 `GLOSSARY.md`。

## 18. 全库 DEK 轮换（API 版本 0x0011）

作业式接口：仅恢复码会话可作为源库；轮换在新文件中全量重建（保留
`vault_uuid`、生成新 K_c、`epoch+1`、恢复槽用同一恢复码 KEK 重封），
构建完成后用 `ReplaceFileW` 单次原子替换源文件（旧库同事务落为备份），
源路径在任一时刻都存在且内容完整。作业期间源库只读，所有写入口返回
`VERTHYS_ERR_ROTATE_PENDING`。

```c
/* 开始：new_path 必须不存在且与源库同目录；flags bit0=移除 PCR 绑定 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateBegin(
    VerthysHandle handle, const char *new_path,
    const char *password, size_t password_len,
    uint32_t flags, VerthysRotateInfo *out_info);

/* 恢复会话补录 keyfile（0x0011）：容器 KEYFILE 启用且会话未持有摘要时，
 * 用当前容器口令 + keyfile 验证 user 槽并缓存摘要；仅解锁态可用。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateAttachKeyfile(
    VerthysHandle handle, const char *keyfile_path,
    const char *password, size_t password_len);

/* 登记已启用模块的模块口令（recovery_code 可选，用于二次校验） */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateUnlockModule(
    VerthysHandle handle, uint32_t module_id,
    const char *password, size_t password_len,
    const char *recovery_code);

/* 全量复制并提供进度；成功后进入 COPIED，失败进入 FAILED（只能 Abort） */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateRun(
    VerthysHandle handle, VerthysRotateProgress progress, void *user);

/* 原子替换并推进回退锚点；keep_old 非 0 保留 .old-* 备份 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateCommit(
    VerthysHandle handle, uint32_t keep_old);

/* 丢弃临时库并释放作业；成功后句柄仍指向原库。
 * 临时库删除失败返回 IO（作业已释放，调用方需提示残留文件）。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateAbort(VerthysHandle handle);
```

`VerthysRotateInfo`：`stage`（1=BEGUN / 2=COPIED / 3=COMMITTED / 4=FAILED）
+ `modules_ready` + `records` / `files` / `chunks` / `bytes` 计数；
`reserved[4]` 必须为 0。进度回调在 Run 内同步调用（持句柄内部锁，
禁止重入 Verthys API），返回非 0 取消本次 Run。

典型调用顺序：

```text
Begin(new_path, password, flags, &info)
  → UnlockModule(module_id, module_password)   // 每个已启用模块一次
  → Run(progress, user)
  → Commit(keep_old)                            // 成功：句柄指向新会话
  → 失败/取消：Abort()
```

边界约定：非恢复码会话返回 `POLICY`；`new_path` 已存在返回 `EXISTS`；
已启用模块未登记口令即 Run 返回 `MODULE_LOCKED`；作业期间写操作返回
`ROTATE_PENDING`；完整性复核失败返回 `VERIFY`。

**PCR 崩溃恢复**：Commit 在覆盖 PCR 密钥前先写入 `<库路径>.vtyrotj`
恢复日志（库 UUID/源代/PCR 策略摘要）。若进程在重封后、原子替换前退出，
下次口令解锁在“日志与当前文件代、PCR 位图、策略摘要完全一致且平台 PCR
仍等于策略摘要”时用口令解出的 `K_c` 重封源库并重新验证；任何一项不匹配
都维持 fail-closed（恢复码仍可打开）。`keep_old=1` 且容器启用 PCR 时，
`.old-*` 备份的普通口令解锁会被 PCR 门拒绝（同名密钥已指向新 `K_c`，属
刻意反回滚设计），备份只能用恢复码打开。

**已删除 fileverthys 模块**：源库 `modules[2]` 处于 `deleted` 时，Run 跳过
文件/分片复制，并要求 `FILE` 键空间只剩墓碑（存在存活叶即 `CORRUPT`）；
记录复制与提交不受影响，新库不重建该模块。

**保真与自检**：复制保留 `record_id` / `created_time` 与源库 `next_id`
水位（已删除的高位 ID 不会被复用）；每条记录与每个分片写入后从新库回读
逐字节比对，不一致返回 `VERIFY`。worker 对 `0x1C` / `0x1D` 保留原错误码，
前端可区分“轮换中只读”与“模块未解锁”。

**取消**：`Verthys_V4RotateRun` 的进度回调返回非 0 即取消本次 Run；
回调在模块/记录/分片/文件边界触发（大文件不会等整文件复制完才响应）。
作业进入 `FAILED`，只能 `Abort`。宿主层（Tauri）通过命名事件把取消请求
跨进程传入 worker，worker 在 Run 前与进度回调中检查（200ms 节流）。
Run 返回后取消通道关闭，后续只能 `Commit` 或 `Abort`。

**口令失败计数**：Begin 的容器口令复核与 AttachKeyfile 的 keyfile+口令
复核共用解锁链路的持久化失败计数/退避窗口；窗口内即使口令正确也返回
`RATE`，成功复核清零计数。