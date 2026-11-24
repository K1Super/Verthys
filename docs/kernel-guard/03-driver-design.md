# 03 驱动设计

| 项目 | 内容 |
| --- | --- |
| 状态 | 评审稿 |
| 驱动 | `VerthysGuard.sys`，KMDF 非 PnP，x64 |
| 范围 | 受保护进程/线程句柄闸门、状态查询、最小事件缓冲 |
| 关联 | [02-architecture.md](02-architecture.md)、[04-service-and-preset.md](04-service-and-preset.md)、[05-test-and-verification.md](05-test-and-verification.md) |

> Last updated: 2026-11-21

---

## 1. 设计目标

1. 对受保护进程剥离危险句柄权限，让同用户进程无法读内存、注入、挂起、终止、调试附加
2. 驱动只做确定性拒绝，不读文件、不解析容器、不持有密钥、不执行加解密
3. 只接受 SYSTEM 服务的 IOCTL；应用无直接通道
4. 代码量最小、失败显式、可卸载、可审计、HVCI 兼容
5. 无驱动时应用完整可用；驱动故障不损坏数据

---

## 2. 驱动模型

| 项 | 选择 | 理由 |
| --- | --- | --- |
| 框架 | KMDF 非 PnP | 对象生命周期与 IRP 处理更安全；减少样板代码 |
| 类型 | `SERVICE_KERNEL_DRIVER`，按需启动 | 由 P2 服务加载；不进入 boot-start 关键路径 |
| 设备 | `\Device\VerthysGuard` | 固定设备名，服务通过符号链接访问 |
| 符号链接 | `\DosDevices\VerthysGuard` | 仅 SYSTEM 可打开 |
| 设备 ACL | `D:P(A;;GA;;;SY)` | 只允许 LocalSystem；管理员也不直接访问 |
| 缓冲方式 | `METHOD_BUFFERED` | 避免用户指针长期持有 |
| 回调 | `ObRegisterCallbacks`（`PsProcessType`、`PsThreadType`） | 句柄创建前剥离权限 |
| 通知 | `PsSetCreateProcessNotifyRoutineEx`、`PsSetLoadImageNotifyRoutineEx` | 生命周期与映像加载审计；通知类，不阻断 |
| 事件上报 | 固定环形缓冲 + 服务轮询 | 避免内核到用户态回调与阻塞 |

说明：如果目标 WDK/OS 对 KMDF 非 PnP 的生命周期支持不满足验证要求，可在 K0 评审后改为 WDM，但 IOCTL 契约与安全语义不变。该变更必须走 ADR，不得在实现中静默切换。

---

## 3. 组件结构

```text
kernel/
├── CMakeLists.txt 或 .vcxproj      # WDK 工程，独立构建
├── VerthysGuard.inf
├── VerthysGuard.cat                # 生产签名产物
├── include/
│   └── vtg_protocol.h              # 服务/驱动共享协议，定长结构
├── src/
│   ├── driver_main.c               # DriverEntry、设备、队列、卸载
│   ├── vtg_ioctl.c                 # IOCTL 分发、参数校验、状态/统计
│   ├── vtg_registry.c              # 受保护进程登记、路径/创建时间、引用计数
│   ├── vtg_ob.c                    # 进程/线程 Ob 回调与权限剥离
│   ├── vtg_notify.c                # 进程/映像通知、事件环形缓冲
│   ├── vtg_path.c                  # 映像路径查询与规范化
│   └── vtg_util.c                  # 安全字符串、时间、零化
└── tests/
    ├── user_mode_harness/          # 用户态协议/状态机测试
    └── vm/                         # VM 内加载/回归脚本
```

驱动代码估算：1,500–2,200 行 C（含头文件，不含测试与构建脚本）。

---

## 4. 设备与 IOCTL

### 4.1 设备创建

- `WdfDriverCreate` 创建驱动对象；`EvtDriverUnload` 负责清理
- `WdfDeviceInitAssignName` 指定设备名；`WdfDeviceCreate` 创建设备
- 使用 `IoCreateDeviceSecure` 语义的 SDDL，只允许 SYSTEM
- 创建符号链接；卸载时先删除符号链接，再删除设备
- 设备打开使用 `FILE_DEVICE_SECURE_OPEN`，拒绝非 SYSTEM 调用方

### 4.2 协议头

```c
#define VTG_PROTOCOL_MAJOR 1
#define VTG_PROTOCOL_MINOR 0
#define VTG_MAX_IMAGE_PATH_CHARS 520
#define VTG_MAX_PROTECTED_PROCESSES 8
#define VTG_MAX_EVENTS 64

typedef struct _VTG_HEADER {
    UINT32 Size;          /* 整个请求/响应字节数，含头 */
    UINT16 Major;
    UINT16 Minor;
    UINT32 Command;
    UINT32 Flags;
    UINT64 RequestId;
    UINT32 Status;        /* 响应使用；请求填 0 */
    UINT32 Reserved;
} VTG_HEADER;
```

约束：

- 所有结构定长；禁止嵌入用户指针
- `Size` 必须与命令期望长度精确匹配；超长/截断直接拒绝
- 保留字段必须为 0；未知标志位拒绝
- 版本不匹配返回 `VTG_STATUS_VERSION_MISMATCH`，不尝试兼容未知语义

### 4.3 命令

| 命令 | 方向 | 用途 |
| --- | --- | --- |
| `VTG_CMD_PING` | 双向 | 健康检查、版本/能力查询 |
| `VTG_CMD_ARM` | 服务 → 驱动 | 进入受保护模式，登记受保护映像与可信服务身份 |
| `VTG_CMD_DISARM` | 服务 → 驱动 | 退出受保护模式，注销全部进程 |
| `VTG_CMD_REGISTER_PROCESS` | 服务 → 驱动 | 登记具体 worker 进程（PID + 创建时间 + 路径） |
| `VTG_CMD_UNREGISTER_PROCESS` | 服务 → 驱动 | 注销进程，释放引用 |
| `VTG_CMD_QUERY_STATUS` | 双向 | 查询状态、原因、受保护数量、版本 |
| `VTG_CMD_QUERY_STATS` | 双向 | 查询拒绝计数、注册失败、事件丢弃等 |
| `VTG_CMD_QUERY_EVENTS` | 双向 | 拉取环形缓冲事件，服务写审计/事件日志 |

### 4.4 关键结构

```c
typedef struct _VTG_PROCESS_IDENTITY {
    UINT32 ProcessId;
    UINT32 Reserved;
    UINT64 CreationTime;              /* 100ns，进程创建时间 */
    WCHAR  ImagePath[VTG_MAX_IMAGE_PATH_CHARS]; /* NT 路径，NUL 结尾 */
} VTG_PROCESS_IDENTITY;

typedef struct _VTG_ARM_IN {
    VTG_HEADER Header;
    UINT32 Policy;                    /* 1=preferred, 2=required */
    UINT32 Flags;
    VTG_PROCESS_IDENTITY Service;     /* 可信服务进程，允许保留查询/终止 */
    WCHAR  ProtectedImagePath[VTG_MAX_IMAGE_PATH_CHARS];
} VTG_ARM_IN;

typedef struct _VTG_REGISTER_IN {
    VTG_HEADER Header;
    VTG_PROCESS_IDENTITY Process;
    UINT32 Flags;
} VTG_REGISTER_IN;

typedef struct _VTG_STATUS_OUT {
    VTG_HEADER Header;
    UINT32 State;                     /* VTG_STATE_* */
    UINT32 Reason;                    /* VTG_REASON_* */
    UINT16 ProtocolMajor;
    UINT16 ProtocolMinor;
    UINT32 Capabilities;              /* 位图 */
    UINT32 ProtectedCount;
    UINT64 ActiveSince;
    UINT32 LastError;
    UINT32 Reserved;
} VTG_STATUS_OUT;
```

### 4.5 状态与原因

| 状态 | 值 | 含义 |
| --- | --- | --- |
| `VTG_STATE_UNARMED` | 0 | 未进入受保护模式 |
| `VTG_STATE_ARMED` | 1 | 已登记受保护映像，尚未登记进程 |
| `VTG_STATE_ACTIVE` | 2 | 至少一个受保护进程已登记 |
| `VTG_STATE_DEGRADED` | 3 | 部分注册失败或能力受限 |
| `VTG_STATE_LOST` | 4 | 运行中保护丢失 |

| 原因 | 含义 |
| --- | --- |
| `VTG_REASON_NONE` | 正常 |
| `VTG_REASON_NOT_INSTALLED` | 驱动未安装 |
| `VTG_REASON_STOPPED` | 驱动未运行 |
| `VTG_REASON_VERSION_MISMATCH` | 协议/版本不匹配 |
| `VTG_REASON_UNSUPPORTED` | OS/架构不支持 |
| `VTG_REASON_REGISTER_FAILED` | 进程登记失败 |
| `VTG_REASON_PROCESS_EXITED` | 受保护进程退出 |
| `VTG_REASON_DRIVER_UNLOADED` | 驱动卸载/停止 |
| `VTG_REASON_INTERNAL` | 内部错误 |

### 4.6 错误码

| 状态码 | 含义 |
| --- | --- |
| `VTG_STATUS_OK` | 成功 |
| `VTG_STATUS_INVALID_REQUEST` | 结构/长度/保留字段非法 |
| `VTG_STATUS_VERSION_MISMATCH` | 协议版本不匹配 |
| `VTG_STATUS_ACCESS_DENIED` | 调用方不是 SYSTEM 服务 |
| `VTG_STATUS_NOT_ARMED` | 未先 ARM 就注册进程 |
| `VTG_STATUS_CAPACITY_EXCEEDED` | 超过受保护进程上限 |
| `VTG_STATUS_PROCESS_NOT_FOUND` | PID 不存在 |
| `VTG_STATUS_IDENTITY_MISMATCH` | 创建时间/路径不匹配，拒绝登记 |
| `VTG_STATUS_NOT_SUPPORTED` | 命令/能力不支持 |
| `VTG_STATUS_INTERNAL` | 内部错误 |

---

## 5. 受保护进程识别

### 5.1 身份组成

受保护进程不能只用 PID 识别。PID 会被复用，攻击者可以等待 PID 复用后获得错误目标。身份由以下字段组成：

1. 进程对象指针（驱动内部持有引用，用于 Ob 回调快速比较）
2. 进程创建时间（100ns，登记时校验）
3. 映像路径（NT 路径，登记时校验）
4. PID（仅用于日志与查询，不作为唯一键）

### 5.2 登记流程

```text
服务先 ARM 受保护映像路径
  → 父进程创建 worker（挂起）
  → 驱动进程创建通知匹配映像路径，立即加入受保护表
  → 服务 REGISTER 确认具体实例（PID + 创建时间 + 路径）
  → PID 不存在/身份不一致：拒绝确认，不登记
  → 一致：绑定登记项，持有进程引用
```

- ARM 必须在 worker 创建前完成；否则存在“创建后、登记前”的外部窗口
- 驱动在进程创建通知中只做匹配与标记，不在回调中等待或分配大块内存
- REGISTER 用于确认实例身份，防止 PID 复用与路径伪造
- 父进程的创建句柄保留 `PROCESS_SET_QUOTA/PROCESS_TERMINATE` 仅用于 Job 分配，分配后立即关闭；不得在保护生效后重新 `OpenProcess` 取新句柄
- REGISTER 确认失败时，驱动保留创建时标记的保护；状态不升级为 `ACTIVE`，服务按 `DEGRADED` 展示并重试确认
- 受保护映像路径必须位于非管理员可写目录；perMachine 安装是路径信任前提
- 路径比较必须大小写不敏感，并统一为 NT 设备路径
- 路径查询 API 以目标 WDK 文档为准；实现中不得使用未文档化结构
- 登记项使用引用计数 + rundown protection；进程退出时释放
- 受保护进程上限固定（默认 8），超出返回 `CAPACITY_EXCEEDED`，不动态扩容

### 5.3 进程退出

- `PsSetCreateProcessNotifyRoutineEx` 收到退出通知
- 从受保护表移除对应项，释放进程引用
- 生成 `PROCESS_EXITED` 事件；服务决定是否锁定/告警
- 不在通知回调中做阻塞操作；事件入环形缓冲

---

## 6. 句柄权限剥离

### 6.1 注册

- `ObRegisterCallbacks` 注册 `PsProcessType` 与 `PsThreadType`
- 驱动加载即注册；未 ARM 时回调直接放行，不匹配、不剥离任何进程
- 使用固定 altitude，避免与其他安全产品冲突；altitude 在 K0 中确定并记录
- 注册失败即拒绝加载驱动；不允许“无回调但显示 ACTIVE”
- 不在 ARM/DISARM 时反复注册/注销回调，避免与在途进程创建竞态

### 6.2 进程句柄

当目标进程在受保护表中，且调用方不是可信服务进程、不是目标进程自身：

| 权限 | 处理 |
| --- | --- |
| `PROCESS_VM_READ` | 剥离 |
| `PROCESS_VM_WRITE` | 剥离 |
| `PROCESS_VM_OPERATION` | 剥离 |
| `PROCESS_CREATE_THREAD` | 剥离 |
| `PROCESS_SUSPEND_RESUME` | 剥离 |
| `PROCESS_TERMINATE` | 剥离（父进程创建句柄除外，Job 分配后关闭） |
| `PROCESS_DUP_HANDLE` | 剥离 |
| `PROCESS_QUERY_LIMITED_INFORMATION` | 保留（健康检查需要） |
| `PROCESS_SET_QUOTA` | 剥离；父进程创建句柄仅用于 Job 分配，分配后关闭 |

### 6.3 线程句柄

| 权限 | 处理 |
| --- | --- |
| `THREAD_SET_CONTEXT` | 剥离 |
| `THREAD_SUSPEND_RESUME` | 剥离 |
| `THREAD_TERMINATE` | 剥离 |
| `THREAD_SET_INFORMATION` | 剥离 |
| `THREAD_QUERY_LIMITED_INFORMATION` | 保留 |

### 6.4 可信服务

- ARM 时登记可信服务进程身份（PID + 创建时间 + 路径 + 进程对象引用）
- 可信服务保留查询与终止能力，用于健康检查、锁定与应急
- 可信服务身份不能被用户态应用伪造；登记只接受 SYSTEM 服务 IOCTL
- 服务退出/重启后需要重新 ARM，旧引用释放

### 6.5 既有句柄

- Ob 回调只能影响新创建的句柄；已存在的危险句柄无法追溯撤销
- ARM 在 worker 创建前登记受保护映像路径；驱动在进程创建时即标记保护，外部进程的新开句柄从第一刻起被剥离
- 父进程创建句柄保留 `PROCESS_SET_QUOTA/PROCESS_TERMINATE` 仅用于 Job 分配，分配后立即关闭
- 驱动需维护 bootstrap 状态：创建时标记保护，仅允许创建者父进程在 Job 分配前保留上述两项权限；服务 REGISTER 确认后清除 bootstrap；超时未确认则撤销并记录事件
- 父进程在关闭创建句柄前仍拥有完整权限；父进程属于信任边界，被攻陷不在保护范围
- 运行期切入 SECURE 时，只能从此刻起保护；`required` 建议要求先锁定再解锁
- 该限制必须写入 UI 与文档，不能承诺“追溯清除已有句柄”

### 6.6 回调约束

- 回调内只做受保护表查找与位运算
- 不分配内存、不等待、不访问用户态、不写日志、不做文件 I/O
- 使用 `EX_PUSH_LOCK` 保护受保护表；查找路径短小
- 拒绝计数在回调内原子累加，事件在非关键路径生成

---

## 7. 生命周期回调

### 7.1 进程通知

- `PsSetCreateProcessNotifyRoutineEx` 注册
- 未 ARM 时不匹配、不登记任何进程；只处理已登记项的退出清理
- 用途：进程退出清理、异常父进程/子进程审计、事件上报
- 通知类能力，不阻断进程创建
- 回调中只做最小状态更新与事件入队

### 7.2 映像加载通知

- `PsSetLoadImageNotifyRoutineEx` 注册
- 用途：发现未知 DLL 被加载进受保护进程；通知类能力，不能阻断加载
- 受保护进程出现非白名单路径映像时：
  - 记录事件（映像名或哈希前缀、进程、时间）
  - 服务轮询后决定锁定/告警
  - 不在回调中终止进程，避免高 IRQL/死锁风险
- 手动映射不会触发该通知；因此该能力是补充，不是主防线

### 7.3 事件环形缓冲

- 固定 64 条事件，单条定长，覆盖最旧
- 事件包含：类型、时间、PID、创建时间、映像名或哈希前缀、状态/原因
- 服务通过 `QUERY_EVENTS` 拉取；驱动不主动回调用户态
- 事件丢弃计数进入统计；服务发现丢弃时记录告警

---

## 8. 并发与卸载

### 8.1 并发

- 受保护表：`EX_PUSH_LOCK` + 固定数组/链表；不在回调中扩容
- 事件缓冲：`KSPIN_LOCK`；生产者在通知回调，消费者在 IOCTL 线程
- 状态字段：`Interlocked*` 或受锁保护；状态读取返回一致快照
- IOCTL 可并行处理；注册/注销与查询使用同一把锁
- 不在持有锁时调用可能阻塞的 API

### 8.2 卸载

```text
EvtDriverUnload
  → 置 unloading 标志，拒绝新 IOCTL
  → ObUnRegisterCallbacks
  → 等待在途回调计数归零（rundown protection）
  → 注销进程/映像通知
  → 清空受保护表，释放进程引用
  → 删除符号链接
  → 删除设备对象
  → 卸载完成
```

- 卸载过程中不得释放仍在回调中使用的内存
- 使用 `EX_RUNDOWN_REF` 或在途计数 + 事件等待
- 卸载失败时保持设备可用，返回明确错误，不半释放
- 不实现“防卸载”军备竞赛；卸载由服务控制

---

## 9. 安全加固

- 只使用文档化内核 API；禁止 SSDT/IDT Hook、未文档化结构、动态代码
- 编译加固：`/GS`、`/guard:cf`、`/NXCOMPAT`、`/DYNAMICBASE`、`/HIGHENTROPYVA`、`/CETCOMPAT`、`/W4 /WX`
- SAL 注解覆盖所有 IOCTL 缓冲区与锁
- 不映射物理内存、不访问 MSR、不创建可写可执行页
- 设备 ACL 仅 SYSTEM；`FILE_DEVICE_SECURE_OPEN`
- 所有用户输入走 `METHOD_BUFFERED`，逐字段校验长度、版本、保留位
- 驱动不记录密钥、口令、用户数据路径；事件只记录映像名或哈希前缀
- 驱动不加载用户路径 DLL；不使用 `ZwLoadDriver` 等自举
- 驱动不持有文件句柄、不打开容器、不访问注册表用户配置

---

## 10. 兼容性

| 项 | 要求 |
| --- | --- |
| OS | Windows 10 1809+ x64；Windows 11 全版本 |
| 架构 | x64 先行；ARM64 不承诺 |
| HVCI | 必须兼容；禁止动态代码/W+X |
| Secure Boot | 生产签名驱动可加载；测试签名需关闭 Secure Boot |
| KMDF | 版本在 K0 固定；运行库由系统提供 |
| 其他安全产品 | 与常见 AV/EDR/反作弊共存；冲突时状态可见、可禁用 |
| 驱动签名 | 生产由微软签名；开发用测试证书 + TESTSIGNING |

---

## 11. 代码量与结构

| 模块 | 估算行数 |
| --- | --- |
| `driver_main.c` | 250–350 |
| `vtg_ioctl.c` | 250–350 |
| `vtg_registry.c` | 350–500 |
| `vtg_ob.c` | 250–350 |
| `vtg_notify.c` | 200–300 |
| `vtg_path.c` | 150–250 |
| `vtg_util.c` | 100–150 |
| `vtg_protocol.h` | 150–250 |
| 合计 | **1,500–2,200** |

不含 INF、构建脚本、测试与文档。

---

## 12. 待验证项

1. 映像路径与创建时间查询 API 在目标 WDK 的具体签名与可用性
2. KMDF 非 PnP 驱动在 Windows 10 1809 与 Windows 11 的生命周期一致性
3. `ObRegisterCallbacks` altitude 与常见安全产品冲突情况
4. HVCI 开启时的加载与运行验证
5. 驱动卸载时在途回调的等待语义
6. 受保护进程上限与事件缓冲大小是否需要按实测调整

以上项在 K0/K1 验证后更新本文，不得在未验证时写入“已支持”。
