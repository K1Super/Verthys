/*
 * verthys.h — Verthys 核心动态库对外标准C语言ABI接口头文件
 *
 * 模块顶层设计规范：
 *   1. 遵循最小对外暴露接口原则，加密算法、数据存储格式、内存保护、逆向对抗逻辑全部封装于内部实现层，对外完全黑盒化
 *   2. 使用不透明句柄VerthysHandle隔离内部上下文，上层业务无法直接访问密钥、运行状态等敏感内部数据
 *   3. 统一使用32位标准状态码作为返回值，不对外输出内部调试信息、异常详情，规避敏感信息泄露风险
 *   4. 严格遵循标准C调用ABI，保证多语言、不同编译器之间可直接互操作调用
 *
 * 本头文件为DLL与外部调用方唯一接口契约。上层UI、调度模块仅持有句柄完成指令调用，
 * 不包含任何加密运算、密钥处理相关逻辑。
 */
#ifndef VERTHYS_H
#define VERTHYS_H

#include <stdint.h>
#include <stddef.h>
#include "verthys_version.h"

/* ================================================================== *
 * API版本兼容性宏定义
 *
 * VERTHYS_API_VERSION用于标记当前接口集版本号，调用方可通过编译期宏判断
 * 当前库是否具备所需能力接口，实现版本兼容逻辑：
 *   #if VERTHYS_API_VERSION >= 0x0002
 *       // 可使用刷盘、容器信息读取、完整性校验等扩展接口
 *   #endif
 *
 * 常量定义位于 verthys_version.h（与容器格式版本同一事实源）。
 * ================================================================== */

/* ================================================================== *
 * 跨平台调用约定与符号导出控制宏
 *
 * Windows平台x64架构虽统一ABI，但显式指定__cdecl调用约定可保障跨编译器、
 * 跨语言FFI调用时栈布局一致性，避免栈失衡问题。
 *
 * 导出面唯一由 verthys.def 白名单管控。
 *
 * VERTHYS_API 恒为空，不携带 dllexport/dllimport 语义：/DEF: 只追加导出，
 * 若由头文件声明展开 dllexport，实际导出面会变成 .def ∪ 全部头文件声明，
 * “最小导出面”即失效。符号导出唯一由链接器 /DEF:verthys.def 白名单决定，
 * 未列入 .def 的内部接口一律不可达。消费方经 libloading 按名运行时解析，
 * 不依赖导入库；测试目标直接链接对象库。
 * ================================================================== */
#if defined(_WIN32) || defined(__CYGWIN__)
  #define VERTHYS_CALL __cdecl
  #define VERTHYS_API
#else
  #define VERTHYS_CALL
  #if defined(VERTHYS_SHARED_BUILD) && __GNUC__ >= 4
    /* 非 Windows 共享库构建：仅 .def/版本脚本等价物管控时启用默认可见性 */
    #define VERTHYS_API __attribute__((visibility("default")))
  #else
    #define VERTHYS_API
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================== *
 * 不透明安全句柄类型定义
 *
 * 采用前置声明不完整结构体实现强类型隔离，内部实现仅在源文件可见。
 * 外部代码无法对句柄指针做强制转换、成员访问，编译阶段即可拦截非法指针混用，
 * 提升句柄使用的类型安全性，避免句柄误传、野指针等问题。
 * ================================================================== */
typedef struct VerthysHandleImpl *VerthysHandle;

/* ================================================================== *
 * 存储记录业务类型枚举
 *
 * 枚举完整覆盖产品定义的所有存储条目类型，调用方直接使用枚举常量，
 * 不依赖魔法数字硬编码，提升代码可读性与可维护性。
 * ================================================================== */
typedef enum {
    VERTHYS_RECORD_PHOTO        = 0x01,  /* 照片类数据 */
    VERTHYS_RECORD_ACCOUNT      = 0x02,  /* 账号凭证类数据 */
    VERTHYS_RECORD_CERT_MANAGER = 0x03,  /* 证书管理类数据 */
    VERTHYS_RECORD_FILE_VERTHYS   = 0x04   /* 文件保险箱类数据 */
} VerthysRecordType;

/* ================================================================== *
 * 安全策略预设档位枚举
 *
 * 定义三套预设安全策略加自定义策略，对应不同场景下缓存机制、内存清零、
 * 会话超时、数据销毁等底层安全行为配置。
 * ================================================================== */
typedef enum {
    VERTHYS_PRESET_BALANCED     = 0,  /* 均衡模式：开启温缓存、文件监听、休眠影子机制，日常使用推荐 */
    VERTHYS_PRESET_SECURE       = 1,  /* 高安全模式：关闭温缓存，锁定时内存数据强制彻底清零，合规涉密场景使用 */
    VERTHYS_PRESET_PERFORMANCE  = 2,  /* 性能优先模式：延长会话超时时间，放宽温缓存淘汰策略，追求读写速度 */
    VERTHYS_PRESET_CUSTOM       = 3   /* 用户自定义模式：由安全中心组件单独配置各项安全参数 */
} VerthysPreset;

/*
 * 统一32位调用返回状态码
 * 安全设计规则：各类认证失败、数据篡改、密码错误对外返回同一类错误标识，
 * 不在错误码粒度上区分具体失败原因，仅内部日志记录详情，防止攻击者枚举探测。
 * ABI 规则：新错误码只允许在枚举尾部追加，禁止插入或复用已分配值。
 */
typedef enum {
    VERTHYS_OK           = 0x00000000u,
    VERTHYS_ERR_INVALID  = 0x00000001u,  /* 入参非法、句柄无效 */
    VERTHYS_ERR_AUTH     = 0x00000002u,  /* 身份认证、数据解密校验未通过（含数据篡改场景统一返回） */
    VERTHYS_ERR_NOTFOUND = 0x00000003u,  /* 目标记录不存在 */
    VERTHYS_ERR_EXISTS   = 0x00000004u,  /* 记录已存在，禁止重复创建 */
    VERTHYS_ERR_FORMAT   = 0x00000005u,  /* 容器文件格式不符合规范 */
    VERTHYS_ERR_LOCKED   = 0x00000007u,  /* 加密容器当前处于锁定状态，无法执行读写操作 */
    VERTHYS_ERR_IO       = 0x00000008u,  /* 磁盘文件读写IO异常 */
    VERTHYS_ERR_CORRUPT  = 0x00000009u,  /* 数据区块完整性校验失败，文件存在损坏，区别于常规认证错误 */
    VERTHYS_ERR_RATE     = 0x0000000Au,  /* 操作触发访问限流，用于暴力破解访问频次管控 */
    VERTHYS_ERR_SNAPSHOT = 0x0000000Bu,  /* 扫描游标快照版本过期，容器已发生并发事务修改，需重新创建游标 */
    /* 胡椒来源不可用（API 版本 0x0006）：
     * OS 托管 pepper 解包失败、或容器记录的 pepper 来源与
     * 当前生效来源不一致时返回——区别于 VERTHYS_ERR_AUTH（密码错误），
     * 上层应提示"保险库安全源已变更，可能由于系统硬件或安全策略改变"，
     * 而非引导用户重试密码。 */
    VERTHYS_ERR_PEPPER_SOURCE = 0x0000000Cu,
    /* 导出记录数超限（API 版本 0x0006 扩展）：
     * 导出记录数超出 v1 导出格式容量上限（65535），导出被拒绝，
     * 不得静默截断后返回 VERTHYS_OK。 */
    VERTHYS_ERR_EXPORT_TOO_MANY = 0x0000000Du,
    /* （API 版本 0x0007 扩展）：
     * CNG 内核态密码服务不可用（BCrypt 算法提供者打开/密钥导入失败）。
     * 上层按 cng_machine_key 三级降级链处理；此码为降级链耗尽后的
     * 显式顶层错误，区别于 VERTHYS_ERR_INTERNAL 的未归类内部异常。
     */
    VERTHYS_ERR_CNG_UNAVAILABLE = 0x0000000Eu,
    /* （API 版本 0x0007 扩展）：
     * 全局内存预算耗尽（用量达到硬上限 512MB 的 95%）时新操作被拒绝，
     * 避免 OOM。区别于 VERTHYS_ERR_INTERNAL：调用方可触发内存回收后重试。
     */
    VERTHYS_ERR_RESOURCE_LIMIT = 0x0000000Fu,
    /* （API 版本 0x0008 扩展）：
     * 元数据多副本一致性不满足——有效副本数不足，容器一致性无法由
     * 副本多数保证，须触发恢复流程。
     * 区别于 VERTHYS_ERR_CORRUPT（无有效副本，全量损坏）。
     */
    VERTHYS_ERR_QUORUM_FAILED = 0x00000010u,
    /* （API 版本 0x0009 扩展）：
     * 渐进式解锁——容器已进入最小可操作状态（元数据验证 + 密钥导入 +
     * 目录加载完成），但索引尚未完全预热（后台预热进行中）。
     * 上层可正常发起读写，或等待预热完成回调。 */
    VERTHYS_ERR_PARTIAL_UNLOCK = 0x00000011u,
    /* （API 版本 0x0009 扩展）：
     * 解锁流水线总超时（预算 10s）——任一阶段未在预算内完成。
     * 区别于 VERTHYS_ERR_INTERNAL：调用方可安全重试（无部分写入副作用，
     * 事务原子性由提交点保证）。 */
    VERTHYS_ERR_TIMEOUT = 0x00000012u,
    /* （API 版本 0x000A 扩展）：
     * 保留码：当前容器格式不支持调用方请求的操作时使用，
     * 区别于 INTERNAL（未归类异常）与 INVALID（参数非法）。
     */
    VERTHYS_ERR_UNSUPPORTED = 0x00000013u,
    /* （API 版本 0x000C 扩展）：
     * 加密层 nonce 计数器耗尽——同一密钥已消耗全部 2^64 计数空间，
     * 继续加密必然导致 GCM nonce 重用（机密性与真实性双重破坏），
     * 加密操作被拒绝。区别于 VERTHYS_ERR_INTERNAL：此为确定性、
     * 可识别的密钥生命周期终点，上层应触发密钥轮换而非重试。
     */
    VERTHYS_ERR_NONCE_EXHAUSTED = 0x00000014u,
    /* （API 版本 0x000C 扩展）：
     * 容器正被其他进程独占占用——单写者语义下第二个写者被拒绝
     * （文件句柄共享模式或容器元数据区独占锁任一判定命中）。区别于
     * VERTHYS_ERR_IO：不是设备/文件系统故障，等待持有进程退出后重试
     * 即可成功；区别于 VERTHYS_ERR_LOCKED：后者是容器自身密码学锁定态。
     */
    VERTHYS_ERR_CONTAINER_BUSY = 0x00000015u,
    /* 调用方未被授权加载本 DLL（API 版本 0x000E 扩展）：
     * 宿主进程主模块或 verthys.dll 本身缺少有效的发布者 Authenticode
     * 签名，Verthys_Init 在任何密钥/文件操作之前即拒绝。
     */
    VERTHYS_ERR_UNAUTHORIZED = 0x00000016u,
    /* 策略拒绝：模块未启用、模块未解锁、恢复会话缺少 recovery 槽等。
     * 与 AUTH 区分，调用方可给出“先解锁模块/先绑定恢复码”的指引。 */
    VERTHYS_ERR_POLICY = 0x00000017u,
    /* TPM/PCR 不可用或 PCR 策略不匹配。与 AUTH 区分，供调用方
     * 引导恢复码重密封；仍不区分具体槽/TPM 内部状态。 */
    VERTHYS_ERR_TPM = 0x00000018u,
    /* 回退锚点拒绝旧副本。与 CORRUPT 区分，供调用方提示文件回退。 */
    VERTHYS_ERR_ROLLBACK = 0x00000019u,
    /* API 版本 0x000F 扩展：
     * KEYFILE 标志置位但调用方未提供 keyfile（或该操作要求 keyfile）。
     * 与 AUTH 区分：此时口令尚未参与判定，调用方应引导用户选择
     * keyfile 文件后重试，而不是提示“口令错误”。
     */
    VERTHYS_ERR_KEYFILE_REQUIRED = 0x0000001Au,
    /* API 版本 0x000F 扩展：
     * 提供的 keyfile 不是合法 VKFL v1（长度/magic/version/flags/checksum
     * 任一不符）。注意“VKFL 合法但 secret 不对”仍统一返回
     * VERTHYS_ERR_AUTH，不泄露口令/密钥判定细节。
     */
    VERTHYS_ERR_KEYFILE_INVALID = 0x0000001Bu,
    /* API 版本 0x0010 扩展：DEK 全库轮换仍在进行，调用方可稍后重试。
     * 与 CONTAINER_BUSY（外部进程占用）区分：此处是库内轮换事务未收敛。 */
    VERTHYS_ERR_ROTATE_PENDING = 0x0000001Cu,
    /* 目标模块未解锁（模块保护已启用且当前会话未持有该模块密钥）。
     * 与 POLICY 区分：调用方可直接引导“先解锁模块”，而不是检查策略配置。 */
    VERTHYS_ERR_MODULE_LOCKED = 0x0000001Du,
    /* 数据区/文件系统空间不足。与 RESOURCE_LIMIT（内存预算）区分，
     * 调用方可引导用户清理磁盘后重试。 */
    VERTHYS_ERR_NO_SPACE = 0x0000001Eu,
    /* 完整性复核失败（Merkle/摘要不一致）。与 AUTH（AEAD 认证失败）
     * 区分：前者表示结构完整性受损，后者表示密钥/密文不匹配。 */
    VERTHYS_ERR_VERIFY = 0x0000001Fu,
    /* 安全状态目录预检失败：目录/ACL 不可加固、位置不受支持或
     * 重解析点。Init 阶段返回，提示可执行的修复指引而非通用“安全模块不可用”。 */
    VERTHYS_ERR_SECURITY_STATE = 0x00000020u,
    VERTHYS_ERR_INTERNAL = 0xFFFFFFFFu   /* 未归类的底层内部异常 */
} VerthysResult;

/*
 * 单条完整记录数据结构体
 * 用于新增记录入参、读取记录出参载体
 * - name为UTF-8编码字符串，依靠name_len判定长度，不依赖字符串结束符
 * - data承载任意二进制字节流，长度由data_len指定
 * - GetRecord接口返回指针为内部借用指针，在句柄锁定或下一次接口调用前保持有效
 */
typedef struct {
    VerthysRecordType  type;
    const char      *name;
    size_t           name_len;
    const uint8_t   *data;
    size_t           data_len;
} VerthysRecord;

/* ================================================================== *
 * 数据槽位状态枚举
 *
 * 映射底层存储索引条目真实生命周期状态，用于前端展示数据健康度、条目可用性，
 * 与底层存储引擎状态定义保持一一对应。
 * ================================================================== */
typedef enum {
    VERTHYS_SLOT_FREE      = 0x00,  /* 槽位空闲，可写入新数据 */
    VERTHYS_SLOT_VALID     = 0x01,  /* 槽位数据有效，可正常读取使用 */
    VERTHYS_SLOT_OBSOLETE  = 0x02,  /* 数据标记删除，等待垃圾回收物理回收空间 */
    VERTHYS_SLOT_PENDING   = 0x03,  /* 数据写入事务未提交完成，处于中间状态 */
    VERTHYS_SLOT_CORRUPT   = 0x04   /* 槽位数据校验损坏，无法正常解密读取 */
} VerthysSlotState;

/*
 * 记录摘要元数据结构体
 * 仅存储索引元信息，不加载实际业务数据块，用于列表快速渲染，降低IO开销
 * 包含数据唯一编号、类型、存储偏移、完整性哈希、创建时间、槽位健康状态等字段
 * name字段为堆深拷贝内存，调用完成后必须调用专用接口释放
 */
typedef struct {
    uint64_t lid;                 /* 数据逻辑唯一编号 */
    /* 记录业务类型：索引路径直接取得真实值；摘要路径不读记录密文，
     * 固定为 0（未知）。需要按类型取记录 ID 时必须使用
     * Verthys_ListIdsByType（走类型盲索引），不得依赖本字段过滤。 */
    uint8_t  type;
    uint16_t name_len;            /* 名称字节长度 */
    const uint8_t *name;          /* UTF-8名称字符串 */
    uint64_t data_size;           /* 原始二进制数据占用大小 */
    uint64_t physical_offset;     /* 数据在容器文件内物理偏移地址 */
    uint8_t  merkle_leaf[32];     /* Merkle树叶子节点哈希值，用于完整性校验 */
    uint64_t created_time;        /* 记录创建Unix时间戳（秒级） */
    uint8_t  slot_state;          /* 存储槽位运行状态，对应VerthysSlotState枚举 */
} VerthysSummaryRecord;

/* ================================================================== *
 * 容器整体诊断信息结构体
 *
 * 对外暴露容器只读运行统计与配置信息，用于后台运维、安全中心展示，
 * 所有字段均为非敏感元数据，不包含任何密钥、明文内容。
 * ================================================================== */
typedef struct {
    uint32_t api_version;           /* 编译时绑定的接口版本号 */
    uint16_t fmt_version;           /* 容器文件格式版本 */
    uint16_t preset;                /* 当前生效的安全策略预设值 */
    uint64_t record_count;          /* 容器内有效记录总条数 */
    uint64_t txid;                  /* 当前最新事务版本号 */
    uint64_t index_region_size;     /* 索引分区占用字节大小 */
    uint64_t data_region_size;      /* 数据分区总容量 */
    uint64_t data_used_bytes;       /* 数据分区已占用字节（含待回收无效数据） */
    uint64_t cumulative_write_bytes;/* 容器累计写入总字节数，用于防回滚校验 */
    uint32_t mount_count;           /* 容器累计挂载打开次数 */
    uint64_t last_modified_time;    /* 最后一次修改操作时间戳 */
    uint64_t last_fullscan_time;    /* 上一次全量完整性校验执行时间戳 */
    uint8_t  container_id[16];      /* 容器唯一标识ID（非敏感标识） */
    uint8_t  warm_cache_enabled;    /* 保留字段；当前容器恒为 0 */
    uint8_t  merkle_pending;        /* Merkle树是否等待后台重建完成 */
    uint8_t  has_keyfile;           /* keyfile 因子已启用（仅解锁态可读） */
    uint8_t  reserved[6];           /* 预留字节，用于后续版本结构体对齐与扩展 */
} VerthysContainerInfo;

/* ================================================================== *
 * 运行时性能诊断指标结构体
 *
 * 仅包含运行时实际采集的指标：扫描游标打开次数、胡椒来源分类标记、
 * 读写锁平均等待耗时。其余字段为预留，恒为 0。
 *
 * 通过 Verthys_GetDiagnostics() 对外暴露，运维平台可实时采集做瓶颈分析。
 * ================================================================== */
typedef struct {
    /* === 扫描游标运行指标 === */
    uint64_t scan_open_count;       /* 扫描游标创建打开次数 */

    /* === 胡椒注入来源标记 === */
    uint8_t  pepper_source;         /* 胡椒数据来源分类标记 */

    /* === 预留扩展字段（保持 8 字节对齐） === */
    uint8_t  reserved[7];

    /* === 可观测性指标 === */
    /* 读写锁平均等待耗时（毫秒）— 采集 AcquireSRWLockShared/Exclusive 的排队耗时 */
    uint64_t lock_wait_ms;          /* 读写锁平均等待耗时（毫秒） */
    /* 保留字段；当前容器无预热状态，恒为 0 */
    uint32_t preheat_status;        /* 保留字段（恒为 0） */

    /* === 预留对齐字段（确保结构体 8 字节对齐） === */
    uint32_t reserved_v5;
} VerthysDiagnostics;

/* ------------------------------------------------------------------ *
 * 统一线程安全模型标注规范
 *   MT-Safe   — 全线程安全，内部自带互斥锁，多线程可并发调用
 *   MT-Unsafe — 非线程安全，同一操作句柄不可多线程并发执行
 *   MT-Const  — 只读安全，只读接口可并发调用，禁止与写操作并行执行
 *   MT-Handle — 句柄级别安全，不同句柄可并发，同一句柄禁止并发
 * 并发度注记（与实现对齐）：索引读路径（单记录读取、类型探测）内部
 * 以互斥锁串行化读者——调用安全但读者不并行；扫描游标类只读遍历持
 * 共享锁，读者可真正并行。
 * ------------------------------------------------------------------ */

/* ================================================================== *
 * 容器生命周期管理接口组
 * ================================================================== */

/* 初始化创建容器上下文句柄
 * 线程安全：MT-Safe，无全局共享状态，可多线程并行创建多个独立句柄 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Init(VerthysHandle *out_handle);

/* ================================================================== *
 * 通知 DLL 当前 worker 进程已应用的沙盒属性位掩码（保留接口）
 *
 * worker 在加载本 DLL 后、调用 Verthys_Init 之前调用：位掩码与
 * process_sandbox 模块的 SANDBOX_ATTR_* 对齐，动态防护验证据此
 * 识别已生效的内核 mitigation policy。
 *
 * 线程安全：MT-Safe（Init 前单线程调用）
 * ================================================================== */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_NotifySandboxAttrs(uint32_t attrs);
/* 销毁容器上下文，安全擦除内存敏感数据后释放资源
 * 线程安全：MT-Unsafe，同一句柄不可在多线程同时执行销毁与其他操作 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Deinit(VerthysHandle handle);

/* ================================================================== *
 * 容器会话接口
 *
 * 使用“口令 + 设备根”双包裹与 A/B 元数据副本；这些入口只接受
 * magic（VRTY），异种格式文件一律返回 VERTHYS_ERR_FORMAT，不提供
 * 原地迁移。创建成功后句柄即处于解锁态，恢复码只在本次调用返回，
 * 调用方展示并确认后必须自行清零缓冲。
 * ================================================================== */

/* 创建容器；recovery_text 容量必须 >= 80 字节。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4Create(VerthysHandle handle,
                                    const char *verthys_path,
                                    const char *password,
                                    size_t      password_len,
                                    char       *recovery_text,
                                    size_t      recovery_cap);

/* 标准解锁：口令 + 设备根（AND）。仅接受 VRTY 容器文件。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4Unlock(VerthysHandle handle,
                                    const char *verthys_path,
                                    const char *password,
                                    size_t      password_len);

/* 恢复码解锁：仅用于换机/灾难恢复；不撤销旧设备。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4UnlockRecovery(
                                    VerthysHandle handle,
                                    const char *verthys_path,
                                    const char *recovery_text);

/* ================================================================== *
 * keyfile 因子接口（API 版本 0x000F）
 *
 * keyfile 是用户口令槽的 KDF 第二输入（不新增槽、不进入 WebView）：
 *   keyfile_digest = BLAKE3("verthys/v4/keyfile" | secret)
 *   KDF_input      = u32_le(pw_len) | password | u32_le(32) | digest
 * 只接受产品生成的 VKFL v1（72B）文件；keyfile 路径经调用方传入，
 * 文件内容由 C 层在本进程内读取/生成，字节不进入 IPC 载荷。
 *
 * 错误语义：
 *   - KEYFILE 已启用但未传路径：VERTHYS_ERR_KEYFILE_REQUIRED
 *   - 文件不是合法 VKFL：VERTHYS_ERR_KEYFILE_INVALID
 *   - 文件合法但 secret 不对：VERTHYS_ERR_AUTH（与口令错不可区分）
 * ================================================================== */

/* 创建容器并生成 VKFL keyfile 到 keyfile_path（目标必须不存在）。
 * 库创建失败时不留下 keyfile 文件；恢复码只在本次调用返回，处理规则
 * 同 Verthys_V4Create。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4CreateKeyfile(
                                    VerthysHandle handle,
                                    const char *verthys_path,
                                    const char *password,
                                    size_t      password_len,
                                    const char *keyfile_path,
                                    char       *recovery_text,
                                    size_t      recovery_cap);

/* 带 keyfile 解锁：口令 + keyfile + 设备根（AND）。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4UnlockKeyfile(
                                    VerthysHandle handle,
                                    const char *verthys_path,
                                    const char *password,
                                    size_t      password_len,
                                    const char *keyfile_path);

/* 在已解锁库上启用/轮换 keyfile：生成新 VKFL 到 new_keyfile_path，
 * 用当前口令重封用户槽。目标文件已存在返回 VERTHYS_ERR_EXISTS。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4KeyfileEnable(
                                    VerthysHandle handle,
                                    const char *password,
                                    size_t      password_len,
                                    const char *new_keyfile_path);

/* 关闭 keyfile：需当前口令 + 当前 keyfile；成功后恢复“仅口令”解锁。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4KeyfileDisable(
                                    VerthysHandle handle,
                                    const char *password,
                                    size_t      password_len,
                                    const char *keyfile_path);

/* 查询 keyfile 是否启用与当前会话是否为恢复码会话（解锁态）。
 * 恢复会话下可用 Verthys_V4KeyfileEnable/Disable 重绑/关闭 keyfile
 * （keyfile 丢失逃生）；普通会话的 Disable 必须提供当前 keyfile。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4KeyfileStatus(
                                    VerthysHandle handle,
                                    uint32_t   *out_enabled,
                                    uint32_t   *out_recovery_mode);

/* 恢复会话重绑本机设备槽与用户槽（换机恢复后恢复日常解锁）。
 * 仅恢复码会话可用；普通会话返回 POLICY。
 * keyfile_path 仅在容器启用 keyfile 时必填，未启用时忽略。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ResealDevice(
                                    VerthysHandle handle,
                                    const char *password,
                                    size_t      password_len,
                                    const char *keyfile_path);


/* ================================================================== *
 * PCR 策略接口
 *
 * 启用/关闭/重密封都要求恢复码二次认证；恢复会话已由恢复码认证，
 * 可传 NULL/空串。状态查询不需要恢复码。PCR 槽与 K_c 的绑定关系在
 * 会话解锁时由 C 层强制校验，这些入口只变更策略，不返回任何密钥。
 * ================================================================== */

/* 查询 PCR 状态：enabled=1 时 out_select 为 PCR0–23 位图。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4PcrStatus(
    VerthysHandle handle,
    uint32_t *out_enabled,
    uint32_t *out_select);

/* 在已解锁库上启用 PCR 绑定；已启用或 pcr_select 非法返回 POLICY/INVALID。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4PcrEnable(
    VerthysHandle handle,
    uint32_t pcr_select,
    const char *recovery_code);

/* 关闭 PCR 绑定（保留设备根槽）。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4PcrDisable(
    VerthysHandle handle,
    const char *recovery_code);

/* 用当前 PCR 重新绑定；通常在恢复码解锁后、PCR 环境变化时调用。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4PcrReseal(
    VerthysHandle handle,
    const char *recovery_code);

/* ================================================================== *
 * 内容分片 / 清单接口
 *
 * 分片与清单由 C 层用模块 MDEK 直接加密，worker 只转发密文；模块必须
 * 已启用且本会话已解锁，否则返回 POLICY。file_uuid 为 16B 调用方随机/
 * 键控标识；seq < total 且 total > 0。输出缓冲不足返回 RESOURCE_LIMIT，
 * 并把所需长度写入 out_len。
 * ================================================================== */

VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ChunkSeal(
    VerthysHandle handle,
    uint32_t module_id,
    const uint8_t file_uuid[16],
    uint32_t seq,
    uint32_t total,
    const uint8_t *plain,
    size_t plain_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);

VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ChunkOpen(
    VerthysHandle handle,
    uint32_t module_id,
    const uint8_t file_uuid[16],
    uint32_t seq,
    uint32_t total,
    const uint8_t *in,
    size_t in_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len);

/* ================================================================== *
 * 模块 M1 会话接口
 *
 * 模块索引固定：0=photo，1=accounts，2=fileverthys。启用后该模块的
 * MDEK 从 Keyring 移出，只有模块解锁成功后会话才持有；未解锁的
 * 模块记录访问返回 VERTHYS_ERR_POLICY。所有口令/恢复码参数只在本次
 * 调用内使用，调用方负责清零自己的缓冲。
 * ================================================================== */

typedef enum {
    VERTHYS_MODULE_PHOTO = 0,
    VERTHYS_MODULE_ACCOUNTS = 1,
    VERTHYS_MODULE_FILEVERTHYS = 2
} VerthysModuleId;

#define VERTHYS_MODULE_ALL 0xFFFFFFFFu

typedef struct {
    uint32_t enabled;      /* 模块加密已启用 */
    uint32_t unlocked;     /* 本会话已解锁 */
    uint32_t has_recovery; /* 已绑定恢复码槽 */
    uint32_t deleted;      /* 已删除：无 MDEK/无数据，可重新启用重建 */
} VerthysModuleStatus;

/* 启用模块：轮换 MDEK 并单事务重写该模块全部记录。recovery_code 可空；
 * 非空时必须与当前容器恢复码一致，用于同时绑定恢复槽。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ModuleEnable(
    VerthysHandle handle,
    uint32_t module_id,
    const char *password,
    size_t password_len,
    const char *recovery_code);

/* 解锁/锁定模块。Lock 接受 VERTHYS_MODULE_ALL 清除全部模块缓存。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ModuleUnlock(
    VerthysHandle handle,
    uint32_t module_id,
    const char *password,
    size_t password_len);

VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ModuleLock(
    VerthysHandle handle,
    uint32_t module_id);

/* 模块口令轮换：只重封 user 槽，不重写数据。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ModuleRotatePassword(
    VerthysHandle handle,
    uint32_t module_id,
    const char *old_password,
    size_t old_len,
    const char *new_password,
    size_t new_len);

/* 禁用模块：保留 MDEK 与数据，MDEK 回到 body Keyring。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ModuleDisable(
    VerthysHandle handle,
    uint32_t module_id,
    const char *password,
    size_t password_len);

/* 删除模块：密码学销毁 MDEK、清除记录/文件/分片叶，模块进入 deleted 状态并
 * 轮换 UUID；之后可由 ModuleEnable 重建空模块。password 是当前容器口令
 * （不是模块口令）；恢复会话可传 NULL/空串。confirm 必须严格为 "DELETE"。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ModuleDelete(
    VerthysHandle handle,
    uint32_t module_id,
    const char *password,
    size_t password_len,
    const char *confirm);

/* 绑定/更新模块恢复槽：要求模块口令 + 当前容器恢复码。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ModuleBindRecovery(
    VerthysHandle handle,
    uint32_t module_id,
    const char *password,
    size_t password_len,
    const char *recovery_code);

/* 恢复会话中把模块设备槽重绑到当前设备根。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ModuleResealDevice(
    VerthysHandle handle,
    uint32_t module_id,
    const char *password,
    size_t password_len);

/* 查询模块状态；不返回任何密钥。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ModuleStatus(
    VerthysHandle handle,
    uint32_t module_id,
    VerthysModuleStatus *out_status);

/* 查询模块锁剩余秒数（只读；不改变计数/尝试额度）。
 * *out_secs=0 表示当前无模块锁定；返回 VERTHYS_ERR_MODULE_LOCKED 表示
 * 该模块仍处于锁定/最小尝试间隔内，*out_secs>0。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4ModuleLockoutRemaining(
    VerthysHandle handle,
    uint32_t module_id,
    uint32_t *out_secs);

/* 查询库级熔断剩余秒数（只读，无需句柄）。
 * 返回 VERTHYS_OK 时 *out_secs 为建议等待秒数（0=可尝试）；
 * 查询失败返回 *out_secs=0，调用方按既有错误链处理。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetLibLockoutRemaining(
    uint32_t *out_secs);

/* 恢复码轮换：当前口令 + 旧恢复码；新码只在成功时写入 out_recovery，
 * 容量必须 >= 80 字节，调用方展示确认后必须清零。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RecoveryRotate(
    VerthysHandle handle,
    const char *password,
    size_t password_len,
    const char *old_recovery,
    char *out_recovery,
    size_t out_cap);

/* ================================================================== *
 * 全库 DEK 轮换（作业式接口，API 版本 0x0010）
 *
 * 仅恢复码会话可作为源库。轮换在新文件中全量重建：保留 vault_uuid，
 * 生成新 K_c，epoch+1；恢复槽用同一恢复码 KEK 重封（旧恢复码继续
 * 有效），用户/设备槽用调用方重新输入的容器口令重封。新库构建完成
 * 后原子替换源文件。
 *
 * 典型顺序：
 *   Begin(new_path, password, flags, &info)
 *   → 对每个已启用模块调用 RotateUnlockModule（模块口令）
 *   → Run(progress, user)
 *   → Commit(keep_old)    // 成功：句柄指向新会话
 *   → 失败/取消：Abort()
 *
 * 注意：
 *   - new_path 必须不存在且与源库同目录（同卷原子替换）。
 *   - 作业期间源库只读：记录/文件/模块/口令/PCR/keyfile 等写操作返回
 *     VERTHYS_ERR_ROTATE_PENDING。
 *   - KEYFILE 已启用但恢复会话未持有 keyfile 摘要时 Begin 返回 POLICY。
 *   - PCR 绑定：TPM 不可用且 flags 未置 DROP_PCR 时返回 TPM；
 *     显式置位且旧库为高安全模式、无 keyfile 时返回 POLICY。
 * ================================================================== */

#define VERTHYS_V4_ROTATE_STAGE_BEGUN     1u
#define VERTHYS_V4_ROTATE_STAGE_COPIED    2u
#define VERTHYS_V4_ROTATE_STAGE_COMMITTED 3u
#define VERTHYS_V4_ROTATE_STAGE_FAILED    4u

/* Begin flags：允许在 TPM/PCR 不可用时移除 PCR 绑定。 */
#define VERTHYS_V4_ROTATE_FLAG_DROP_PCR   0x00000001u

typedef struct {
    uint32_t stage;          /* VERTHYS_V4_ROTATE_STAGE_* */
    uint32_t modules_ready;  /* 已登记口令的已启用模块数 */
    uint64_t records;        /* 已复制记录数 */
    uint64_t files;          /* 已复制文件数 */
    uint64_t chunks;         /* 已复制分片数 */
    uint64_t bytes;          /* 已复制记录（名称+数据）字节数 */
    uint32_t reserved[4];    /* 预留，必须为 0 */
} VerthysRotateInfo;

/* 进度回调：在 Run 内同步调用（持有句柄内部锁，禁止重入 Verthys API）。
 * 返回非 0 取消本次 Run；作业进入失败态，只能 Abort。 */
typedef int (VERTHYS_CALL *VerthysRotateProgress)(void *user,
                                                  const VerthysRotateInfo *info);

/* 开始轮换：校验恢复会话与容器口令，创建临时新库。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateBegin(
    VerthysHandle handle,
    const char *new_path,
    const char *password,
    size_t password_len,
    uint32_t flags,
    VerthysRotateInfo *out_info);

/* 恢复会话补录 keyfile（API 版本 0x0011）：
 * 容器已启用 KEYFILE 且当前恢复会话未持有 keyfile 摘要时，用当前容器口令
 * + keyfile 路径验证 user 槽；成功后摘要驻留会话（锁定即清零），Begin 可
 * 继续执行。keyfile 字节只由 C 层在 worker 进程内读取，不经过 IPC。
 * 返回：OK / INVALID（入参）/ POLICY（未解锁或容器未启用 keyfile）/
 *       KEYFILE_INVALID（VKFL 非法）/ AUTH（keyfile 或口令不匹配）。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateAttachKeyfile(
    VerthysHandle handle,
    const char *keyfile_path,
    const char *password,
    size_t password_len);

/* 登记一个已启用模块的口令（并解锁源模块）。所有已启用模块都必须
 * 在 Run 前登记；recovery_code 非空时先做一次恢复码二次校验。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateUnlockModule(
    VerthysHandle handle,
    uint32_t module_id,
    const char *password,
    size_t password_len,
    const char *recovery_code);

/* 全量复制并提供进度。成功后才能 Commit。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateRun(
    VerthysHandle handle,
    VerthysRotateProgress progress,
    void *user);

/* 原子替换并推进回退锚点。keep_old 非 0 时保留 .old-* 备份。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateCommit(
    VerthysHandle handle,
    uint32_t keep_old);

/* 丢弃临时库并释放作业；成功后句柄仍指向原库。 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_V4RotateAbort(
    VerthysHandle handle);

/*
 * 运行时切换安全预设档位（BALANCED / SECURE / PERFORMANCE）
 *
 * 切换立即生效：双缓冲原子发布新配置快照，各防护子系统下一次读取
 * 运行时配置时进入新档行为。幂等：切到当前档返回成功。
 * 不涉及容器状态与密钥材料，仅变更进程级运行时防护配置；
 * CUSTOM 档由应用层逐项配置，非本接口合法入参。
 *
 * 返回值：
 *   VERTHYS_OK          — 切换成功
 *   VERTHYS_ERR_INVALID — handle 为 NULL 或 preset 非法
 *
 * 线程安全：MT-Safe（双缓冲 + 原子指针交换，读者无锁）
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_SwitchSecurityPreset(VerthysHandle handle,
                                                                    VerthysPreset preset);

/*
 * 查询当前活跃安全预设档位（0=BALANCED / 1=SECURE / 2=PERFORMANCE）
 *
 * 取自活跃配置快照，供调用方做切档回读校验（切换是否真实生效）。
 * 进程启动后未显式切档时，活跃档位为平衡档基线。
 *
 * 返回值：
 *   VERTHYS_OK          — 查询成功，*out_preset 已填充
 *   VERTHYS_ERR_INVALID — handle / out_preset 为 NULL
 *
 * 线程安全：MT-Safe（快照读取，无锁）
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetSecurityPreset(VerthysHandle handle,
                                                                 uint32_t *out_preset);

/*
 * 查询指定预设档位的特性位投影（跨层特性契约，11 位）
 *
 * 位序（禁止重排）：
 *   0 anti_debug / 1 anti_inject / 2 integrity_check / 3 memory_guard /
 *   4 key_separation（与密钥隔离堆对应的兼容位）/ 5 emergency_response /
 *   6 session_lock_on_idle / 7 module_patrol / 8 clipboard_guard / 9 usb_clone_detect /
 *   10 trace_cleanup
 * 其中 2/6/7/8/9/10 为应用侧策略位（宿主按位执行），其余为 C 层消费能力。
 * 该投影是档位矩阵的唯一权威输出，宿主展示与执行均以此为准。
 *
 * 返回值：
 *   VERTHYS_OK          — 查询成功，*out_bits 已填充
 *   VERTHYS_ERR_INVALID — handle / out_bits 为 NULL 或 preset 非法
 *
 * 线程安全：MT-Safe
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetPresetFeatureBits(VerthysHandle handle,
                                                                    VerthysPreset preset,
                                                                    uint32_t *out_bits);

/*
 * 锁定容器，清空内存中所有密钥与明文数据，句柄退回锁定不可操作状态
 * 耗时较重的碎片整理、全量校验均后置为后台异步任务，本接口仅执行缓存刷盘与敏感内存清零，不阻塞调用线程。
 *
 * 线程安全：MT-Unsafe
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Lock(VerthysHandle handle);

/* ================================================================== *
 * 主动刷盘持久化接口
 *
 * 不执行锁定动作，主动将内存中缓存的索引事务变更落地写入磁盘，
 * 提升程序异常崩溃时数据一致性，供上层缓存同步逻辑调用。
 * 线程安全：MT-Safe
 * ================================================================== */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Flush(VerthysHandle handle);

/* ================================================================== *
 * 单条/批量记录数据操作接口组
 * ================================================================== */

/* 新增一条业务记录，返回系统分配唯一逻辑ID
 * 线程安全：MT-Safe，内部事务锁保证并发写入安全 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_AddRecord(VerthysHandle handle,
                            const VerthysRecord *record,
                            uint64_t *out_id);

/* 批量新增业务记录（API 版本 0x0013）
 *
 * 语义：单次事务提交，全部记录共享一次 DataRoot/元数据落盘；任一条失败
 * 整体回滚到调用前的根（未提交的记录段保持不可达），out_ids 全部置 0。
 * 这是大文件导入的唯一高效写入口：逐条调用 AddRecord 会产生记录条数 ×
 * 提交/fsync 的开销，批量接口把落盘成本压到与批内条数无关的单次提交。
 *
 * 契约：
 *   - count ∈ [1, VERTHYS_ADD_RECORDS_MAX]，records 与 out_ids 必须非 NULL；
 *   - 每条记录按 Verthys_AddRecord 同一规则校验（名称/数据指针、长度上限、
 *     单条 IPC 预算），任一非法即整批拒绝且不产生任何写入；
 *   - 仅当前格式容器可用；其他格式返回 VERTHYS_ERR_FORMAT；
 *   - out_ids[i] 与 records[i] 一一对应，成功时均 > 0；
 *   - 写操作使既有 GetRecord 借用指针失效（与 AddRecord 同一纪律）。
 *
 * 线程安全：MT-Safe，内部事务锁保证并发写入安全。 */
#define VERTHYS_ADD_RECORDS_MAX 512u

VERTHYS_API VerthysResult VERTHYS_CALL Verthys_AddRecords(VerthysHandle handle,
                            const VerthysRecord *records,
                            uint32_t count,
                            uint64_t *out_ids);

/* 按ID读取完整记录数据，返回结构体指针为内部借用内存
 *
 * API 契约加固：指针生命周期契约
 *
 * 1. 所有权模型
 *    out_record->data 与 out_record->name 为【内部借用指针】，指向上下文
 *    私有缓存（last_getrecord_data / last_getrecord_name）。调用方【不持有
 *    所有权】，禁止 free()，禁止长期保存，禁止跨函数传递后继续使用。
 *
 * 2. 失效时机（写操作即失效）
 *    以下任一接口被调用后，本次返回的借用指针【立即失效】（缓存被安全
 *    清零并释放），继续访问将构成 Use-After-Free：
 *      - Verthys_AddRecord       新增记录
 *      - Verthys_AddRecords      批量新增记录
 *      - Verthys_DeleteRecord    删除单条
 *      - Verthys_DeleteRecords   批量删除
 *      - Verthys_Import          导入容器
 *      - Verthys_ChangePassword  修改主密码
 *      - Verthys_Flush           显式刷盘
 *      - Verthys_Lock / Verthys_Deinit  锁定/销毁
 *    上层业务若需跨写操作保留记录内容，必须在写操作前【深拷贝】到自有缓冲。
 *
 * 3. 单次有效原则
 *    再次调用 Verthys_GetRecord（任意 id）也会使上一次返回的借用指针失效
 *    （缓存被新记录覆盖）。同一时刻最多只有一组借用指针有效。
 *
 * 4. 线程安全：MT-Unsafe — 借用指针不支持跨线程共享，避免悬空野指针风险
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetRecord(VerthysHandle handle,
                            uint64_t id,
                            VerthysRecord *out_record);

/*
 * 显式释放 GetRecord 借用缓存。
 *
 * 用途：调用方已把 out_record->name/data 深拷贝到自有缓冲后，立即清零并
 * 释放 C 层缓存，缩短明文在 C 堆中的驻留窗口。
 *
 * 前置条件：handle 必须由 Verthys_Init 创建且尚未 Deinit。
 * 副作用：使上一次 Verthys_GetRecord 返回的借用指针立即失效。
 * 线程安全：MT-Unsafe，与 Verthys_GetRecord 共享同一缓存锁。
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ClearRecordCache(VerthysHandle handle);

/*
 * 删除单条记录接口使用说明
 * 底层执行规则：单次调用触发一次完整事务提交，高频循环逐条删除会产生大量磁盘IO开销；
 * 大批量删除场景优先使用批量删除接口，合并单次事务提交降低IO压力。
 *
 * 线程安全：MT-Safe
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_DeleteRecord(VerthysHandle handle, uint64_t id);

/* 批量删除多条记录，所有条目合并为单次事务提交，仅一次磁盘刷盘，适合大批量清理场景
 * 线程安全：MT-Safe */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_DeleteRecords(VerthysHandle handle, const uint64_t *ids, size_t count);

/* 导出当前容器为独立加密文件包，可设置独立访问密码，不继承应用层胡椒参数
 * 采用流式分片写入机制，大数量记录导出不会造成内存溢出
 * 线程安全：MT-Safe */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Export(VerthysHandle handle,
                         const char *export_path,
                         const char *password,
                         size_t      password_len);

/* 导入外部加密容器，将数据合并至当前打开容器内
 * 导入多条记录合并为单次事务提交，减少多次索引刷新性能损耗
 * 线程安全：MT-Safe */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Import(VerthysHandle handle,
                         const char *import_path,
                         const char *password,
                         size_t      password_len);

/* 修改容器访问主密码，仅重新加密数据密钥，无需全量重加密业务数据，改密前自动提交未完成事务
 * 线程安全：MT-Safe */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ChangePassword(VerthysHandle handle,
                                 const char *old_pw, size_t old_len,
                                 const char *new_pw, size_t new_len);

/* ================================================================== *
 * 容器元数据诊断查询接口
 *
 * 获取容器配置、容量、统计类只读信息，用于状态展示与运维排查，不暴露任何敏感密钥信息。
 * 线程安全：MT-Const，仅只读遍历，可与其他只读接口并发调用
 * ================================================================== */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetContainerInfo(VerthysHandle handle,
                                    VerthysContainerInfo *out_info);

/* ================================================================== *
 * 容器全量数据完整性校验接口
 *
 * 遍历全部数据块执行AEAD标签校验与Merkle树哈希校验，识别损坏数据条目；
 * 耗时较长，建议放置后台低优先级线程执行。可输出损坏记录ID列表与损坏总数。
 * 校验遍历期间禁止执行写入修改操作。
 * 线程安全：MT-Unsafe
 * ================================================================== */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_VerifyIntegrity(VerthysHandle handle,
                                   uint64_t *out_failed_lids,
                                   uint64_t max_failed,
                                   uint64_t *out_failed_count);

/* ================================================================== *
 * 全量数据批量扫描游标接口（完整解密读取）
 * 调用流程规范：打开游标 -> 循环批量拉取 -> 逐条释放记录内存 -> 关闭游标
 * 游标绑定事务快照，扫描过程不会感知中途新写入数据，保证遍历一致性
 * ================================================================== */

/* 扫描游标不透明句柄，内部实现仅在源文件可见 */
typedef struct VerthysScanCursor VerthysScanCursor;

/*
 * 扫描投影：控制游标拉取时对记录数据的处理方式。
 *
 * 列表/索引类调用（只需 id/type/name）应选 INDEX 投影，避免为读取索引而
 * 解密并搬运 MB 级记录数据；确需逐条完整数据的调用才选 FULL。
 */
typedef enum {
    VERTHYS_SCAN_PROJECT_FULL  = 0,  /* 全部记录完整解密并返回数据（Verthys_ScanOpen 的既有行为） */
    VERTHYS_SCAN_PROJECT_INDEX = 1   /* 索引优先：仅对不超过内联阈值的记录解密并返回数据 */
} VerthysScanProject;

/*
 * 创建数据全量扫描游标
 * 指定起始遍历ID与单次批量读取条数，初始化目录树游标并绑定只读快照。
 * 线程安全：MT-Unsafe，同一容器句柄不可并发创建多个扫描游标
 * 等价于 Verthys_ScanOpenEx(handle, start_lid, batch_size, VERTHYS_SCAN_PROJECT_FULL, 0, 0, out_cursor)。
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanOpen(VerthysHandle handle,
                           uint64_t start_lid,
                           uint64_t batch_size,
                           VerthysScanCursor **out_cursor);

/*
 * 创建数据扫描游标（带投影与取批预算）。
 *
 * 参数：
 * - project：投影选择。FULL 完整解密（与 Verthys_ScanOpen 相同）；
 *   INDEX 仅对 plaintext_size <= index_inline_max_bytes 的记录解密并返回
 *   数据，超出阈值的记录仍按序返回条目但 data=NULL/data_len=0（不解密、
 *   不分配数据缓冲），调用方按需经单条读取接口获取。
 * - index_inline_max_bytes：INDEX 投影的内联数据字节阈值，0 表示纯索引
 *   （任何记录都不附带数据）。FULL 投影忽略本参数。
 * - max_batch_bytes：单次 Fetch 输出字节预算（名称 + 数据合计），0 表示
 *   不限。预算为软水位线：累计输出越过预算即收批，本批最多超出预算一条
 *   记录的大小（游标不可回退，"先量后收"会让越预算条目既未输出又已被
 *   消费）。调用方按传输窗口尺寸扣除单条最大记录后设定预算，即可保证
 *   单批载荷不超窗口，避免"整批超限即失败"。
 *
 * 线程安全：MT-Unsafe，同一容器句柄不可并发创建多个扫描游标
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanOpenEx(VerthysHandle handle,
                           uint64_t start_lid,
                           uint64_t batch_size,
                           VerthysScanProject project,
                           uint64_t index_inline_max_bytes,
                           uint64_t max_batch_bytes,
                           VerthysScanCursor **out_cursor);

/*
 * 游标批量拉取完整解密记录
 * 关键使用约束：
 * 1. 解密失败的损坏条目会单独输出失败ID列表，不会静默丢弃
 * 2. 拉取前校验快照事务版本，容器已修改则返回快照过期错误，需重建游标
 * 3. 返回记录内存为堆深拷贝，必须调用专用接口释放，不可直接free释放
 * 4. FULL 投影下本接口完整解密所有二进制数据，CPU与IO开销较高：列表渲染
 *    请改用 INDEX 投影（超阈值记录不解密）或摘要扫描接口
 *
 * 线程安全：MT-Const
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanFetch(VerthysScanCursor *cursor,
                            VerthysRecord *out_records,
                            uint64_t *out_lids,
                            uint64_t max_count,
                            uint64_t *out_count,
                            uint64_t *out_failed_lids,
                            uint64_t *out_failed_count);

/* 释放单条扫描记录堆分配内存，内存区域执行安全擦除后释放
 * 线程安全：MT-Safe */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanRecordFree(VerthysRecord *record);

/* 关闭扫描游标，释放迭代器、缓冲区、快照版本等所有关联资源
 * 线程安全：MT-Unsafe，同一游标禁止并发关闭 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanClose(VerthysScanCursor *cursor);

/* ================================================================== *
 * 轻量摘要扫描游标接口（仅读取元数据，不解密数据块）
 * 仅遍历索引树读取元信息，不访问业务数据区块，加载速度极快，专门用于列表页面快速渲染
 * ================================================================== */

/*
 * 创建摘要信息扫描游标，底层逻辑与全量扫描游标一致，仅跳过数据块读取解密步骤
 * 线程安全：MT-Unsafe
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanSummaryOpen(VerthysHandle handle,
                                   uint64_t start_lid,
                                   uint64_t batch_size,
                                   VerthysScanCursor **out_cursor);

/*
 * 批量拉取记录摘要元数据，仅从索引节点提取基础信息，无解密运算，性能高效
 * name字段为堆拷贝内存，使用完毕必须调用释放接口回收
 * 线程安全：MT-Const
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanSummaryFetch(VerthysScanCursor *cursor,
                                    VerthysSummaryRecord *out_records,
                                    uint64_t *out_lids,
                                    uint64_t max_count,
                                    uint64_t *out_count);

/* 释放摘要记录字符串堆内存，执行安全擦除操作
 * 线程安全：MT-Safe */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanSummaryRecordFree(VerthysSummaryRecord *record);

/* 获取当前已加载摘要索引内记录总条数，上层用于判断是否可直接渲染列表，跳过索引全量遍历
 * 线程安全：MT-Const */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetSummaryCount(VerthysHandle handle, uint64_t *out_count);

/* ================================================================== *
 * 轻量级记录类型存在性检查（只查类型盲索引，不读数据块）
 *
 * 用途：快速判断容器中是否存在指定类型的记录，供启动阶段选择 UI 路径。
 *
 * 性能：只遍历类型盲索引，不访问记录段，不分配 name 堆内存；相比
 * ScanSummaryOpen + Fetch 循环，消除多次 IPC 往返与结构体拷贝开销。
 *
 * 参数：
 *   handle     : 已解锁的 Verthys 句柄
 *   rtype      : 目标记录类型
 *   out_found  : 输出，1=存在匹配类型的记录，0=不存在
 *
 * 返回值：
 *   VERTHYS_OK          — 检查完成（查看 out_found 判断是否存在）
 *   VERTHYS_ERR_INVALID — 参数错误（handle/out_found 为 NULL）
 *   VERTHYS_ERR_LOCKED  — 容器未解锁或应急熔断触发
 *   VERTHYS_ERR_FORMAT  — 非容器格式（out_found=0，调用方回退）
 *
 * 线程安全：MT-Const（只读操作，与其他只读操作并发安全）
 * ================================================================== */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_HasRecordByType(VerthysHandle handle,
                                              uint8_t rtype,
                                              uint8_t *out_found);

/* ================================================================== *
 * 按类型查找首条记录的逻辑 ID
 *
 * 与 Verthys_HasRecordByType 的差异：单次遍历同时返回 found 标志与匹配
 * 记录的 lid，轻量探测、无解密 IO。未找到返回 VERTHYS_OK + out_found=0；
 * 非容器格式返回 VERTHYS_ERR_FORMAT。
 *
 * 参数：
 *   handle     : 已解锁的 Verthys 句柄
 *   rtype      : 目标记录类型
 *   out_found  : 输出，1=存在匹配类型的记录，0=不存在
 *   out_lid    : 输出，匹配记录的逻辑 ID（found=1 时有效）
 *
 * 返回值：
 *   VERTHYS_OK          — 检查完成（查看 out_found 判断是否存在）
 *   VERTHYS_ERR_INVALID — 参数错误（handle/out_found/out_lid 为 NULL）
 *   VERTHYS_ERR_LOCKED  — 容器未解锁或应急熔断触发
 *
 * 线程安全：MT-Const（只读操作，与其他只读操作并发安全）
 * ================================================================== */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_FindFirstLidByType(VerthysHandle handle,
                                                  uint8_t rtype,
                                                  uint8_t *out_found,
                                                  uint64_t *out_lid);

/* ================================================================== *
 * 按类型分页枚举记录 ID（API 版本 0x0012）                             *
 *                                                                    *
 * 权威类型来源：容器的类型盲索引（VTY_KS_TYPE），不读取记录密文，   *
 * 不依赖摘要扫描的 type 字段，跨重启稳定生效。                          *
 *                                                                    *
 * 参数：                                                              *
 *   handle        : 已解锁的 Verthys 句柄                              *
 *   rtype         : 目标记录业务类型                                    *
 *   after_id      : 上一页最后一个 ID；首页传 0                          *
 *   max_count     : 本页上限（1..VERTHYS_TYPE_ID_BATCH_MAX）            *
 *   out_ids       : 调用方缓冲区，至少 max_count 个 uint64              *
 *   out_count     : 本页实际返回条数                                    *
 *   out_exhausted : 1=该类型已无更多记录；0=可能还有下一页              *
 *                                                                    *
 * 返回值：                                                            *
 *   VERTHYS_OK / VERTHYS_ERR_INVALID / VERTHYS_ERR_LOCKED /            *
 *   VERTHYS_ERR_FORMAT（非容器格式）                                   *
 *                                                                    *
 * 线程安全：MT-Const（只读索引游标）                                    *
 * ================================================================== */
#define VERTHYS_TYPE_ID_BATCH_MAX 4096u

VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ListIdsByType(VerthysHandle handle,
                                              uint8_t rtype,
                                              uint64_t after_id,
                                              uint64_t max_count,
                                              uint64_t *out_ids,
                                              uint64_t *out_count,
                                              uint8_t *out_exhausted);



/* ================================================================== *
 * 运行时性能诊断数据获取接口
 *
 * 读取容器运行期实际采集的诊断指标，用于后台监控与问题定位。
 * 线程安全：MT-Const
 * ================================================================== */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetDiagnostics(VerthysHandle handle,
                                  VerthysDiagnostics *out_diag);

/* ================================================================== *
 * （API 版本 0x000B）：
 * 动态防护状态查询接口
 *
 * 防御攻击路径枚举（7 项）。
 * 值域与内部 DefensePath 镜像对齐（编译期契约锁定，同 verthys_api.c）。
 * ================================================================== */
typedef enum {
    VERTHYS_DEFENSE_SUSPEND_BYPASS = 0,  /* 管理员调试挂起绕过 */
    VERTHYS_DEFENSE_MEM_DUMP       = 1,  /* 内存 Dump / 冷启动取证 */
    VERTHYS_DEFENSE_HIBERNATION    = 2,  /* 休眠文件取证 */
    VERTHYS_DEFENSE_IAT_HOOK       = 3,  /* IAT Hook / Inline Hook */
    VERTHYS_DEFENSE_DLL_HIJACK     = 4,  /* DLL 劫持 / 反射注入 */
    VERTHYS_DEFENSE_PROCESS_READ   = 5,  /* 进程打开/读取内存 */
    VERTHYS_DEFENSE_CROSS_DEVICE   = 6,  /* 跨设备迁移解密 */
    VERTHYS_DEFENSE_PATH_COUNT     = 7   /* 路径总数（结构体数组维度） */
} VerthysDefensePath;

/* 防御状态枚举（值域与内部 DefenseState 镜像对齐） */
typedef enum {
    VERTHYS_DEFENSE_NOT_CHECKED = 0,     /* 未校验（校验尚未执行） */
    VERTHYS_DEFENSE_BLOCKED     = 1,     /* 已阻断（关键防御就绪，攻击路径闭合） */
    VERTHYS_DEFENSE_DEGRADED    = 2,     /* 降级（次要防御缺失，业务可继续） */
    VERTHYS_DEFENSE_FAILED      = 3      /* 失败（关键防御缺失，应拒绝启动） */
} VerthysDefenseState;

/* 判定原因码（API 版本 0x0014；值域与内部 DefenseReason 镜像对齐，
 * 调用方按码映射文案，不得解析名称文本） */
typedef enum {
    VERTHYS_DEFENSE_REASON_NONE                      = 0,
    VERTHYS_DEFENSE_REASON_NO_RESIDENT_KEY           = 1,
    VERTHYS_DEFENSE_REASON_V4_KEYS_USER_RESIDENT     = 2,
    VERTHYS_DEFENSE_REASON_HIBERNATION_ENABLED       = 3,
    VERTHYS_DEFENSE_REASON_HIBERNATION_UNKNOWN       = 4,
    VERTHYS_DEFENSE_REASON_SUSPEND_UNPREVENTABLE     = 5,
    VERTHYS_DEFENSE_REASON_SUSPEND_GUARD_INACTIVE    = 6,
    VERTHYS_DEFENSE_REASON_HOOK_SCAN_CLEAN           = 7,
    VERTHYS_DEFENSE_REASON_HOOK_SCAN_UNAVAILABLE     = 8,
    VERTHYS_DEFENSE_REASON_HOOK_DETECTED             = 9,
    VERTHYS_DEFENSE_REASON_SANDBOX_VERIFIED          = 10,
    VERTHYS_DEFENSE_REASON_SANDBOX_PARTIAL           = 11,
    VERTHYS_DEFENSE_REASON_SANDBOX_UNVERIFIED        = 12,
    VERTHYS_DEFENSE_REASON_JOB_ACTIVE                = 13,
    VERTHYS_DEFENSE_REASON_DEVICE_BOUND              = 14,
    VERTHYS_DEFENSE_REASON_NO_SESSION_FACTS          = 15,
    VERTHYS_DEFENSE_REASON_MODULE_INIT_FAILED        = 16,
    VERTHYS_DEFENSE_REASON_POLICY_DISABLED           = 17,
    VERTHYS_DEFENSE_REASON_EVIDENCE_STALE            = 18,
    VERTHYS_DEFENSE_REASON_ARCH_LIMIT_KERNEL_DEFERRED = 19,
    VERTHYS_DEFENSE_REASON_HIBERNATION_DISABLED      = 20
} VerthysDefenseReason;

/* 运行时守卫位（policy_flags） */
#define VERTHYS_DEFENSE_GUARD_HEARTBEAT     0x01u  /* worker 心跳线程已运行 */
#define VERTHYS_DEFENSE_GUARD_SUSPEND_LOCK  0x02u  /* 挂起守卫已接线 */
#define VERTHYS_DEFENSE_POLICY_ANTI_DUMP    0x04u  /* 当前预设启用防转储巡检 */

/*
 * 动态防护状态报告（API 版本 0x000B；0x0014 追加原因码与采样时间）
 *
 * 所有字段均为非敏感运行时状态元数据，不含密钥、句柄或模块内部地址。
 * 追加字段位于既有 reserved[6] 之后：旧调用方按 0x000B 结构读取时
 * 前缀布局不变；新调用方可读取原因码、架构限制计数与采样时间。
 */
typedef struct {
    /* 逐路径防御状态（维度 VERTHYS_DEFENSE_PATH_COUNT，下标 = VerthysDefensePath） */
    VerthysDefenseState path_state[VERTHYS_DEFENSE_PATH_COUNT];
    uint32_t blocked_count;          /* BLOCKED 路径数 */
    uint32_t degraded_count;         /* DEGRADED 路径数 */
    uint32_t failed_count;           /* FAILED 路径数 */
    uint8_t  all_critical_blocked;   /* 1 = 全部 7 条路径 BLOCKED（无 FAILED 且无 DEGRADED） */
    uint8_t  has_degraded;           /* 1 = 存在 DEGRADED 路径 */
    uint8_t  reserved[6];            /* 既有预留（保持不动） */
    /* ---- 追加（API 版本 0x0014） ---- */
    uint32_t path_reason[VERTHYS_DEFENSE_PATH_COUNT]; /* 逐路径判定原因码 */
    uint32_t limited_count;          /* 架构限制导致的 DEGRADED 路径数 */
    uint32_t policy_flags;           /* VERTHYS_DEFENSE_GUARD_* | POLICY_ANTI_DUMP */
    uint32_t reserved2;              /* 预留（调用方忽略） */
    uint64_t checked_at_unix_ms;     /* 本次快照采样时间（Unix 毫秒） */
    uint32_t reserved3[2];           /* 预留（调用方忽略） */
} VerthysSecurityStatus;

/*
 * 查询动态防护状态（7 攻击路径实时复检）
 *
 * 行为契约：
 *   - 每次调用执行 RUNTIME 级实时复检（非上次 BOOT 校验的缓存快照），
 *     反映当前时点的真实防御状态；
 *   - 防御状态为进程级事实，与容器解锁状态无关——锁定态、未挂载态
 *     均可查询（安全中心在解锁前即可展示防护水位）；
 *   - 任一路径 FAILED 不改变本接口返回值（诊断查询不具处置语义），
 *     调用方依据结构体字段决策。
 *
 * 返回值：
 *   VERTHYS_OK          — 查询完成（状态经 out_status 输出）
 *   VERTHYS_ERR_INVALID — handle 或 out_status 为 NULL
 *   VERTHYS_ERR_INTERNAL— 内部校验管线异常（防御性映射）
 *
 * 线程安全：MT-Safe（内部串行化锁保护复检与状态汇总）
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_GetSecurityStatus(
    VerthysHandle handle,
    VerthysSecurityStatus *out_status);

/*
 * 通知运行时守卫状态（API 版本 0x0014）
 *
 * 写入进程级完整掩码（非累加 OR）：bit0=心跳已运行，bit1=挂起守卫已接线。
 * worker 在心跳线程启动后置 bit0，主进程经内部 op 下发 bit1；停止守卫时
 * 下发 0。未知位被丢弃。状态查询中的 policy_flags 同步反映该掩码。
 *
 * 返回值：VERTHYS_OK。无句柄参数——守卫为进程级事实。
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_NotifyRuntimeGuards(uint32_t flags);

/* ================================================================== *
 * 落盘持久化自查接口（API 版本 0x000C）
 *
 * 背景：Windows 字节范围锁为强制锁——会话期内 C 层以独占方式
 * 持有容器元数据区 [0,64KB) 锁。同进程内只有持锁句柄本身可自由读写该
 * 区间，任何"外部新开句柄"（含 Tauri 主进程 std::fs::File::open）
 * 读取该区间都会得到 ERROR_LOCK_VIOLATION。因此落盘校验必须由
 * 持锁进程用持锁句柄自查，不能经外部读路径实现。
 *
 * 本接口幂等、只读、无副作用：仅用会话持锁句柄读取头部与
 * DataRoot 根段，不改变会话状态、不写盘。校验内容：
 *   - 头部 magic 与主版本可读；
 *   - 文件大小覆盖 DataRoot 指向的根段；
 *   - 根段内容摘要与解锁时记录的摘要一致；
 *   - 根段修改时间可读。
 *
 * 线程安全：MT-Const（只读，可与其它只读接口并发）
 * ================================================================== */

/* 落盘自查状态码 */
typedef enum {
    VERTHYS_PERSIST_OK               = 0,  /* 结构完整，落盘有效 */
    VERTHYS_PERSIST_E_HEADER_INVALID = 1,  /* 头部结构校验失败（帧头/长度非法） */
    VERTHYS_PERSIST_E_SIZE_MISMATCH  = 2,  /* 文件大小低于合法容器下限 */
    VERTHYS_PERSIST_E_WAL_REGION     = 3,  /* 保留状态码（无 WAL 区，当前不产生） */
    VERTHYS_PERSIST_E_IO             = 4,  /* 文件读写 IO 异常 */
    VERTHYS_PERSIST_E_INTERNAL       = 5   /* 无可用会话上下文/内部错误 */
} VerPersistStatus;

/* 落盘自查结果（非敏感结构元数据，不含密钥/明文） */
typedef struct {
    VerPersistStatus status;         /* 状态码，对应 VerPersistStatus */
    uint64_t file_size;              /* 容器文件字节大小 */
    uint64_t mtime_ms;               /* 文件修改时间（Unix 毫秒；不可得为 0） */
    uint32_t header_magic;           /* 磁盘头 magic（'VRTY'） */
    uint32_t header_version;         /* 容器格式版本（头部主版本） */
    uint64_t wal_offset;             /* 预留字段（无 WAL 区，恒为 0） */
    char     last_error[256];        /* 失败详情（UTF-8，NULL 终结；成功为空串） */
} VerPersistVerifyResult;

/*
 * 校验当前会话持锁句柄对应的磁盘持久化结构。
 *
 *   handle     : 已解锁的 Verthys 句柄（内部读取会话 DataRoot）
 *   out_result : 输出结果载体（必填，NULL 直接返回 INTERNAL）
 *
 * 返回值：VerPersistStatus（同时写入 out_result->status）。
 *   会话未解锁 / 非容器会话 / 句柄为空 → INTERNAL。
 */
VERTHYS_API VerPersistStatus VERTHYS_CALL Verthys_VerifyPersist(
    VerthysHandle handle,
    VerPersistVerifyResult *out_result);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VERTHYS_H */