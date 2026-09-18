# C 核心公开 API（verthys.h）
> C 核心 DLL（verthys.dll）对外标准 C ABI 接口规范，函数签名与语义逐一照源码编写。
>
> Last updated: 2026-09-19 · 维护人：K1Super

本文档是 C 核心动态库对外接口的唯一契约文件，与 `core/include/verthys.h`（公开头文件）、
`core/include/error_codes.h`（C/Rust 边界标准错误码）、`core/verthys.def`（导出符号白名单）
逐条对齐。所有签名、枚举值、成员语义均照源码编写；未在源码注释中显式给出的错误码语义已标注
“据实现推断”。接口分组以头文件实际声明为准。

---

## 1. 包含方式

```c
#include "verthys.h"          /* 公开 ABI：Verthys_* 接口 + VerthysResult 错误码 */
#include "error_codes.h"      /* C/Rust FFI 边界标准错误码：VERTHYS_C_*（int） */
```

- 头文件仅依赖标准库 `<stdint.h>` / `<stddef.h>`，自包含，无第三方头文件依赖。
- 公开头文件路径：`core/include/verthys.h`；导出白名单：`core/verthys.def`。
- 动态库产物：`verthys.dll`（CMake Release，构建见 `build_production.ps1`）。

## 2. 调用约定与导出宏 `VERTHYS_API`

- 调用约定：`VERTHYS_CALL` 在 Windows 下展开为 `__cdecl`；非 Windows 下为空。
- 导出宏：`VERTHYS_API` 在 Windows 下**恒为空**（不再携带 `__declspec(dllexport/dllimport)`）。
  符号导出**唯一**由链接器 `/DEF:verthys.def` 白名单管控；未列入 `.def` 的接口一律不可达。
  消费方（verthys-worker）经 `libloading` 按名运行时解析，不依赖导入库。
- 版本宏：`VERTHYS_API_VERSION = 0x000Bu`，调用方可用 `#if` 做编译期能力判断。

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

> 示例来源说明：`core/examples/ffi/` 下仅有 `cng_example.c`，它演示的是 `error_codes.h`
> 的 `VERTHYS_C_*`（int）错误码与 CNG 纯函数调用，**并未**调用 `verthys.h` 的 `Verthys_*`
> 公共 API。本仓库暂无调用 `Verthys_*` ABI 的 C 示例文件，上面的 `VerthysResult` 用法为本文档
> 撰写（非取自 `examples/ffi` 实文件）；实际调用范例见 `core/tests/api/`（test_init.c、
> test_verthys_api.c 等）。

## 5. 错误码体系（两套，勿混淆）

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
| `VERTHYS_ERR_INTERNAL` | `0xFFFFFFFF` | 未归类底层内部异常 |

### 5.2 `VERTHYS_C_*`（error_codes.h，C/Rust FFI 边界标准码，int）

与 Rust 侧 `util/ffi.rs` 的 `c_error_codes` 模块对齐；是 C 源文件内部返回码的规范化标准，
**非** `verthys.h` 公开 API 的返回类型。

| 宏 | 值 | 含义 |
|---|---|---|
| `VERTHYS_C_SUCCESS` | `0` | 成功 |
| `VERTHYS_C_ERR_INVALID` | `-1` | 无效参数 |
| `VERTHYS_C_ERR_LOCKED` | `-2` | 加密库已锁定 |
| `VERTHYS_C_ERR_AUTH` | `-3` | 认证失败（密码错误） |
| `VERTHYS_C_ERR_IO` | `-4` | I/O 错误 |
| `VERTHYS_C_ERR_CORRUPT` | `-5` | 数据损坏 |
| `VERTHYS_C_ERR_FULL` | `-6` | 容器已满 |
| `VERTHYS_C_ERR_NOTFOUND` | `-7` | 记录不存在 |
| `VERTHYS_C_ERR_NOMEM` | `-8` | 内存不足 |
| `VERTHYS_C_ERR_STATE` | `-9` | 状态错误 |
| `VERTHYS_C_ERR_INTERNAL` | `-10` | 通用内部错误 |
| `VERTHYS_C_ERR_ROLLBACK` | `-11` | 检测到回滚攻击 |

## 6. 线程安全模型标注规范

| 标注 | 含义 |
|---|---|
| MT-Safe | 全线程安全，内部自带互斥，多线程可并发调用 |
| MT-Unsafe | 非线程安全，同一句柄不可多线程并发执行 |
| MT-Const | 只读安全，只读接口可并发，禁止与写操作并行 |
| MT-Handle | 句柄级安全，不同句柄可并发，同一句柄禁止并发 |

## 7. 接口分组总览（29 个公开符号，与 `verthys.def` 一致）| # | 功能域 | 函数 |
|---|---|---|
| 1 | 生命周期 | Verthys_Init / Verthys_NotifySandboxAttrs / Verthys_Deinit / Verthys_Unlock / Verthys_RegisterUnlockProgressCallback / Verthys_CreateWithPreset / Verthys_Lock / Verthys_Flush |
| 2 | 记录 CRUD | Verthys_AddRecord / Verthys_GetRecord / Verthys_DeleteRecord / Verthys_DeleteRecords |
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

### Verthys_Unlock
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Unlock(VerthysHandle handle, const char *verthys_path, const char *password, size_t password_len, uint32_t flags);`
- 参数：
  - `verthys_path` — 已有容器文件路径；文件不存在返回 IO 错误，**不会**自动创建容器。
  - `password` / `password_len` — 主密码（UTF-8，非零结尾，长度由 `password_len` 指定）。
  - `flags` — 位域：`VERTHYS_UNLOCK_FLAG_INDEX_PREHEATED (0x01)`（索引已预热，走内存映射）、
    `VERTHYS_UNLOCK_FLAG_ALLOW_CACHE (0x02)`（允许加载持久化缓存）、
    `VERTHYS_UNLOCK_FLAG_MINIMAL_FIRST (0x04)`（渐进式解锁：最小可操作优先）；`flags=0` 为旧版同步读取。
- 返回（源码未逐条注释，据 verthys_api.c 与 unlock pipeline 实现推断）：
  `VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_RATE`（限流）/ `VERTHYS_ERR_IO`（文件不存在或读失败）/
  `VERTHYS_ERR_AUTH`（密码错误）/ `VERTHYS_ERR_PEPPER_SOURCE` / `VERTHYS_ERR_FORMAT` / `VERTHYS_ERR_CORRUPT` /
  `VERTHYS_ERR_CNG_UNAVAILABLE` / `VERTHYS_ERR_QUORUM_FAILED` / `VERTHYS_ERR_PARTIAL_UNLOCK` / `VERTHYS_ERR_TIMEOUT` / `VERTHYS_ERR_INTERNAL`。
- 内存：解锁成功后句柄进入可读写就绪态；路径/密码由库内部拷贝使用，调用方可用栈上/临时缓冲。
- 线程安全：MT-Unsafe（同一句柄禁止并发解锁）。

### Verthys_RegisterUnlockProgressCallback
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_RegisterUnlockProgressCallback(VerthysHandle handle, VerthysUnlockProgressCallback callback, void *user_data);`
- 参数：
  - `callback` — `void (VERTHYS_CALL *)(const VerthysUnlockProgress *progress, void *user_data)`；NULL 取消通知。
  - `user_data` — 原样透传；DLL 不解析其内容。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID`（handle 为 NULL）。
- 语义：注册后对当前句柄的 `Verthys_Unlock` / `Verthys_CreateWithPreset` 各阶段回调进度；
  `message` 为 DLL 内部只读字面量（UTF-8、NULL 终结），仅在回调调用期间有效。
- 内存：`VerthysUnlockProgress` 由 DLL 栈上构造，回调返回后失效；调用方不得保存 `message` 指针。
- 线程安全：MT-Unsafe（同一句柄不可并发注册/解锁）。

### Verthys_CreateWithPreset
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_CreateWithPreset(VerthysHandle handle, const char *verthys_path, const char *password, size_t password_len, VerthysPreset preset);`
- 参数：`preset` — `VERTHYS_PRESET_BALANCED(0) / SECURE(1) / PERFORMANCE(2) / CUSTOM(3)`。
- 语义：全新创建容器；路径必须不存在（否则返回 `VERTHYS_ERR_EXISTS`）；创建即解锁；预设持久写入超级块；唯一合法新建入口。
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID` / `VERTHYS_ERR_EXISTS` /（V3 路径经 `verthys_api_v3_create` 返回 `VERTHYS_ERR_IO` / `VERTHYS_ERR_PEPPER_SOURCE` / `VERTHYS_ERR_INTERNAL`）。（据实现推断）
- 内存：同 `Verthys_Unlock`。
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

### Verthys_GetRecord
`VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetRecord(VerthysHandle handle, uint64_t id, VerthysRecord *out_record);`
- 参数：`id` — 目标记录逻辑 ID；`out_record` — 输出记录。
- 所有权模型：`out_record->data` 与 `out_record->name` 为**内部借用指针**（指向上下文私有缓存
  `last_getrecord_data` / `last_getrecord_name`）。调用方**不持有所有权**，禁止 `free()`、禁止长期保存。
- 失效时机（写操作即失效，继续访问 = Use-After-Free）：`Verthys_AddRecord` / `Verthys_DeleteRecord` /
  `Verthys_DeleteRecords` / `Verthys_Import` / `Verthys_ChangePassword` / `Verthys_Flush` /
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
  `VERTHYS_ERR_FORMAT` / `VERTHYS_ERR_INTERNAL` /（V3 专属：`VERTHYS_ERR_UNSUPPORTED`、`VERTHYS_ERR_PEPPER_SOURCE`，据实现推断）。
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
- 返回：`VERTHYS_OK` / `VERTHYS_ERR_INVALID`（handle 或 out_status 为 NULL）/ `VERTHYS_ERR_INTERNAL`。
- 内存：调用方提供结构体；`out_status->reserved[6]` 调用方须置零。
- 线程安全：MT-Safe（内部串行化锁）。

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
- 语义：批量拉取摘要元数据（`lid`/`type`/`name_len`/`name`/`data_size`/`physical_offset`/`merkle_leaf[32]`/`created_time`/`slot_state`），无解密运算。
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
| `VerthysSecurityStatus` | 防御闭环 7 路径状态 | `path_state[7]` + blocked/degraded/failed 计数 |
| `VerthysUnlockProgress` | 解锁进度 | 栈上构造，回调返回即失效 |

## 16. 符号前缀与旧符号残留

- 所有公开符号前缀均为 `Verthys_`。全仓源码/头文件中**未发现**旧 `Vault_` 前缀残留
  （仅在 `docs/archive/Verthys品牌整改验证交付报告.md` 中出现 4 处历史记录，非代码）。
- 导出白名单 `core/verthys.def` 共 29 个符号，与头文件声明一一对应。
- 名称遗留（供整改参考）：`VerthysRecordType` 中 `VERTHYS_RECORD_FILE_VERTHYS` 语义为“文件保险箱类数据”，
  命名冗余但属源码现状，本文档照实记录，未改代码。

## 17. 交叉引用

- 桥接层命令：见 `TAURI_BRIDGE.md`（Rust 侧经 worker 子进程调用本 DLL）。
- 设计与信任模型：见 `SECURITY_DESIGN.md`。
- 构建/配置：见 `CONFIGURATION.md` 与根 `build_production.ps1`。
- 术语：见 `GLOSSARY.md`。