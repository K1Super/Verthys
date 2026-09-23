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

/* ================================================================== *
 * API版本兼容性宏定义
 *
 * VERTHYS_API_VERSION用于标记当前接口集版本号，调用方可通过编译期宏判断
 * 当前库是否具备所需能力接口，实现版本兼容逻辑：
 *   #if VERTHYS_API_VERSION >= 0x0002
 *       // 可使用刷盘、容器信息读取、完整性校验等扩展接口
 *   #endif
 *
 * ================================================================== */
#define VERTHYS_API_VERSION 0x000Bu

/* ================================================================== *
 * Verthys_Unlock flags 位域定义（API 版本 0x0005）
 *
 * 上层 Rust 调度层通过 flags 位域将预热状态透传给 C 层，
 * C 层根据标志位分支执行最优路径（内存映射 vs 磁盘同步读取）。
 *
 * 位域定义：
 *   bit 0 (0x01)：索引区已完成预热，C 层可直接 CreateFileMapping
 *                 零拷贝读取索引区，跳过磁盘同步 IO
 *   bit 1 (0x02)：允许加载本地持久化缓存（.verthys.idx_cache）
 *   bit 2 (0x04)：V3（API 版本 0x0009）渐进式
 *                 解锁——最小可操作优先：S0-S4（超块/密钥/分区表）完成后
 *                 立即返回 VERTHYS_ERR_PARTIAL_UNLOCK，索引预热转后台线程
 * ================================================================== */
#define VERTHYS_UNLOCK_FLAG_INDEX_PREHEATED  0x01u  /* 索引区已预热，可走内存映射 */
#define VERTHYS_UNLOCK_FLAG_ALLOW_CACHE      0x02u  /* 允许加载持久化缓存 */
#define VERTHYS_UNLOCK_FLAG_MINIMAL_FIRST    0x04u  /* 渐进式解锁：最小可操作优先 */

/* ================================================================== *
 * 跨平台调用约定与符号导出控制宏
 *
 * Windows平台x64架构虽统一ABI，但显式指定__cdecl调用约定可保障跨编译器、
 * 跨语言FFI调用时栈布局一致性，避免栈失衡问题。
 *
 * 导出面唯一由 verthys.def 白名单管控。
 *
 * 原缺陷：VERTHYS_EXPORTS 使本头文件内所有 VERTHYS_API 声明展开为
 * __declspec(dllexport)，/DEF: 仅追加导出而非白名单——实际导出面 =
 * .def ∪ 全部头文件声明，"最小导出面"承诺失效。
 *
 * 修复：VERTHYS_API 不再携带任何 dllexport/dllimport 语义（恒为空），
 * 符号导出唯一由链接器 /DEF:verthys.def 白名单决定；未列入 .def 的
 * 内部接口（如 Verthys_HasRecordByType 之外的新增内部函数）一律不可达。
 * 消费方（verthys-worker）经 libloading 按名运行时解析，不依赖导入库。
 * 测试目标直接链接对象库，同样不受影响。
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
     * 而非引导用户重试密码。
     * 注：原拟 0x0000000B 与既有 VERTHYS_ERR_SNAPSHOT 冲突，
     *     依 ABI 向后兼容原则顺延至 0x0C。 */
    VERTHYS_ERR_PEPPER_SOURCE = 0x0000000Cu,
    /* 导出记录数超限（API 版本 0x0006 扩展）：
     * 导出记录数超出 v1 导出格式容量上限（65535），导出被拒绝。
     * 原行为：静默截断并返回 VERTHYS_OK——导出不完整且用户不知情。 */
    VERTHYS_ERR_EXPORT_TOO_MANY = 0x0000000Du,
    /* V3 升级（API 版本 0x0007 扩展）：
     * CNG 内核态密码服务不可用（BCrypt 算法提供者打开/密钥导入失败）。
     * 上层按 cng_machine_key 三级降级链处理；此码为降级链耗尽后的
     * 显式顶层错误，区别于 VERTHYS_ERR_INTERNAL 的未归类内部异常。
     * 依 ABI 向后兼容原则在枚举尾部顺延追加。 */
    VERTHYS_ERR_CNG_UNAVAILABLE = 0x0000000Eu,
    /* V3 升级（API 版本 0x0007 扩展）：
     * 全局内存预算耗尽（用量达到硬上限 512MB 的 95%）时新操作被拒绝，
     * 避免 OOM。区别于 VERTHYS_ERR_INTERNAL：调用方可触发内存回收后重试。
     * 依 ABI 向后兼容原则在枚举尾部顺延追加。 */
    VERTHYS_ERR_RESOURCE_LIMIT = 0x0000000Fu,
    /* V3 升级（API 版本 0x0008 扩展）：
     * 超级块法定人数不满足——3 副本中 HMAC 有效副本 < 2（仅 1 副本有效），
     * 容器一致性无法由法定人数保证，须触发恢复流程（WAL 回放）。
     * 区别于 VERTHYS_ERR_CORRUPT（0 有效副本，全量损坏）。
     * 依 ABI 向后兼容原则在枚举尾部顺延追加。 */
    VERTHYS_ERR_QUORUM_FAILED = 0x00000010u,
    /* V3 升级（API 版本 0x0009 扩展）：
     * 渐进式解锁——容器已进入最小可操作状态（超级块验证 + 密钥导入 +
     * 分区表加载完成），但索引尚未完全预热（后台预热进行中）。
     * 上层可正常发起读写（LSM 按需加载 SSTable），或等待预热完成回调。
     * 依 ABI 向后兼容原则在枚举尾部顺延追加。 */
    VERTHYS_ERR_PARTIAL_UNLOCK = 0x00000011u,
    /* V3 升级（API 版本 0x0009 扩展）：
     * 解锁流水线总超时（预算 10s）——S0-S6 任一阶段未在预算内完成。
     * 区别于 VERTHYS_ERR_INTERNAL：调用方可安全重试（无部分写入副作用，
     * 事务原子性由 WAL + 法定人数保证）。 */
    VERTHYS_ERR_TIMEOUT = 0x00000012u,
    /* V3 升级接线收口（API 版本 0x000A 扩展）：
     * 当前容器格式不支持该操作——V3 容器在关联功能尚未迁移至 V3 专属
     * 实现（如改密：依赖 CNG 内核态密钥轮换原语）时显式拒绝，
     * 区别于 INTERNAL（未归类异常）与 INVALID（参数非法）。
     * 依 ABI 向后兼容原则在枚举尾部顺延追加。 */
    VERTHYS_ERR_UNSUPPORTED = 0x00000013u,
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
    uint8_t  type;                /* 记录业务类型 */
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
    uint8_t  warm_cache_enabled;    /* 温缓存策略是否开启 */
    uint8_t  merkle_pending;        /* Merkle树是否等待后台重建完成 */
    uint8_t  reserved[7];           /* 预留字节，用于后续版本结构体对齐与扩展 */
} VerthysContainerInfo;

/* ================================================================== *
 * 运行时性能诊断指标结构体
 *
 * 采集解锁耗时拆解、缓存命中统计、GC回收、事务提交、扫描游标运行等运行指标，
 * 支撑性能排查、运行状态可视化展示。胡椒来源仅做分类标记，不输出原始敏感值。
 *
 * 可观测性指标增强（API 版本 0x0005），新增 5 项指标：
 *   - 页缓存命中率（通过文件句柄信息/高精度计时器估算）
 *   - 读写锁平均等待耗时
 *   - 持久化缓存加载耗时
 *   - 本次解锁磁盘实际读取字节数
 *   - 预热状态枚举（0=未预热 /1=预热中 /2=预热完成 /3=预热失败）
 * 通过 Verthys_GetDiagnostics() 对外暴露，运维平台可实时采集做瓶颈分析。
 * ================================================================== */
typedef struct {
    /* === 最近一次解锁耗时分项统计（单位：毫秒） === */
    uint64_t unlock_total_ms;       /* 解锁整体耗时 */
    uint64_t unlock_read_ms;        /* 文件磁盘读取耗时 */
    uint64_t unlock_derive_ms;      /* 密钥派生计算耗时 */
    uint64_t unlock_index_load_ms;  /* 索引文件加载耗时 */
    uint64_t unlock_summary_load_ms;/* 摘要索引加载耗时 */
    uint64_t unlock_merkle_ms;      /* Merkle树初始化构建耗时 */

    /* === 缓存运行指标 === */
    uint64_t warm_cache_hits;       /* 温缓存命中总次数 */
    uint64_t warm_cache_misses;     /* 温缓存未命中次数 */
    uint64_t warm_cache_evictions;  /* 缓存条目淘汰次数 */

    /* === 事务与垃圾回收指标 === */
    uint64_t gc_trigger_count;      /* 自动垃圾回收触发次数 */
    uint64_t gc_reclaimed_slots;    /* GC总共回收的无效槽位数量 */
    uint64_t commit_count;          /* 事务成功提交总次数 */
    uint64_t rollback_count;        /* 事务回滚次数 */

    /* === 扫描游标运行指标 === */
    uint64_t scan_open_count;       /* 扫描游标创建打开次数 */
    uint64_t scan_snapshot_stale;   /* 快照过期强制重建次数 */

    /* === 胡椒注入来源标记 === */
    uint8_t  pepper_source;         /* 胡椒数据来源分类标记 */

    /* === 预留扩展字段（保持原有 8 字节对齐） === */
    uint8_t  reserved[7];

    /* === 可观测性指标扩展（5 项新增指标） === */
    /* 读写锁平均等待耗时（毫秒）— 采集 AcquireSRWLockShared/Exclusive 的排队耗时 */
    uint64_t lock_wait_ms;          /* 读写锁平均等待耗时（毫秒） */
    /* 持久化缓存加载耗时（毫秒）— .verthys.idx_cache 加载全流程耗时 */
    uint64_t cache_load_ms;         /* 持久化缓存加载耗时（毫秒） */
    /* 本次解锁磁盘实际读取字节数 — 累计真实磁盘 IO 量（不含命中页缓存） */
    uint64_t disk_bytes_read;       /* 本次解锁磁盘实际读取字节数 */
    /* 页缓存命中率（百分比 0~100）— 通过文件句柄信息/高精度计时器估算 */
    uint32_t page_cache_hit_ratio;  /* 页缓存命中率（百分比，0~100） */
    /* 预热状态枚举（0=未预热 /1=预热中 /2=预热完成 /3=预热失败） */
    uint32_t preheat_status;        /* 预热状态枚举 */

    /* === 自适应 Argon2id 漂移监控指标 === */
    /* 基准派生耗时（毫秒）— 容器创建时跑分记录，存入超级块 flags 字段 */
    uint32_t argon2_baseline_ms;    /* 基准派生耗时（毫秒，0=未建立基准） */
    /* 最近一次 Argon2id 派生耗时（毫秒）— 运行时实时采集 */
    uint32_t argon2_last_derive_ms; /* 最近一次 Argon2id 派生耗时（毫秒） */
    /* 连续漂移次数（超基准 30%）— 达到 3 次触发自动降级 */
    uint32_t argon2_drift_count;    /* 连续漂移次数 */
    /* 自动降级标志（0=正常, 1=已降级）— 连续 3 次漂移后置 1 */
    uint32_t argon2_auto_degraded;  /* 自动降级标志 */

    /* === 索引内存映射失败告警指标 ===
     * 累计索引区内存映射失败回退 fread 的次数（跨多次解锁累计）。
     * 每次 prefetch_done=1 但 CreateFileMapping/MapViewOfFile 失败时递增。
     * 通过 Verthys_GetDiagnostics 上报安全中心，运维可据此排查：
     *   - 文件独占锁占用（杀毒软件/备份软件持锁）
     *   - 映射资源耗尽（系统提交上限不足）
     *   - 权限问题（FILE_SHARE_READ 被拒绝）
     * 频繁回退表明预热优化收益受损，需排查环境因素。 */
    uint32_t idx_mmap_fallback_count;  /* 索引内存映射失败回退次数（累计） */

    /* === V5 预留对齐字段（确保结构体 8 字节对齐） === */
    uint8_t  reserved_v5[4];
} VerthysDiagnostics;

/* ------------------------------------------------------------------ *
 * 统一线程安全模型标注规范
 *   MT-Safe   — 全线程安全，内部自带互斥锁，多线程可并发调用
 *   MT-Unsafe — 非线程安全，同一操作句柄不可多线程并发执行
 *   MT-Const  — 只读安全，只读接口可并发调用，禁止与写操作并行执行
 *   MT-Handle — 句柄级别安全，不同句柄可并发，同一句柄禁止并发
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

/*
 * 解锁指定路径加密容器文件
 * 行为规则：文件不存在直接返回IO错误，不会自动创建容器；仅校验解密已有文件，
 * 新建容器必须调用专用创建接口。解锁成功后句柄进入可读写就绪状态。
 *
 * API 版本 0x0005：新增 flags 参数，透传上层预热状态。
 *   - VERTHYS_UNLOCK_FLAG_INDEX_PREHEATED (0x01)：索引区已预热，C 层走内存映射零拷贝路径
 *   - VERTHYS_UNLOCK_FLAG_ALLOW_CACHE (0x02)：允许加载持久化缓存
 *   - flags=0 时行为与旧版完全一致（磁盘同步读取），保证向下兼容
 *
 * 线程安全：MT-Unsafe，同一句柄禁止并发解锁操作
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_Unlock(VerthysHandle handle,
                         const char *verthys_path,
                         const char *password,
                         size_t      password_len,
                         uint32_t    flags);

/* ================================================================== *
 * 解锁进度回调接口（API 版本 0x0004）
 *
 * 解锁流程涉及多个耗时阶段（超级块读取、Argon2id 密钥派生、索引区解密、
 * B+ 树构建、摘要索引加载、Merkle 树创建），总耗时在 SECURE 预设下可达
 * 6~15 秒。前端需向用户展示真实进度，避免面对空白界面产生"卡死"错觉。
 *
 * 设计原则（深模块）：
 *   - 进度回调为单向通知，不影响解锁逻辑流程
 *   - 回调在解锁线程内同步调用，调用方需保证回调函数不阻塞
 *   - 不传递任何敏感数据（密钥/密码/明文），仅传递阶段编号与百分比
 *   - 回调注册后对当前句柄的所有后续 Unlock/CreateWithPreset 调用生效
 *   - 传 NULL 回调可取消进度通知
 *
 * 安全边界：
 *   - message 字段为只读 UTF-8 字符串字面量，不含任何用户数据
 *   - percent 为 0~100 整数，不泄露文件大小/记录数等侧信道信息
 *   - 回调在 DLL 内部线程执行，worker 进程通过 stdout 转发到主进程
 *
 * 线程安全：MT-Unsafe（同一句柄不可并发注册/解锁）
 * ================================================================== */

/* 解锁进度阶段标识 */
typedef enum {
    VERTHYS_UNLOCK_STAGE_READ_SUPERBLOCK  = 1,  /* 超级块已读取（5%） */
    VERTHYS_UNLOCK_STAGE_ARGON2_START     = 2,  /* Argon2id 派生开始（10%） */
    VERTHYS_UNLOCK_STAGE_ARGON2_DONE      = 3,  /* Argon2id 派生完成（50%） */
    VERTHYS_UNLOCK_STAGE_CACHE_CHECK      = 4,  /* 索引缓存检查完成（55%） */
    VERTHYS_UNLOCK_STAGE_BTREE_DECRYPT    = 5,  /* 开始解密索引区（60%） */
    VERTHYS_UNLOCK_STAGE_BTREE_DONE       = 6,  /* B+ 树构建完成（85%） */
    VERTHYS_UNLOCK_STAGE_SUMMARY_DONE     = 7,  /* 摘要索引加载完成（95%） */
    VERTHYS_UNLOCK_STAGE_MERKLE_DONE      = 8,  /* Merkle 树创建完成（100%） */
    /* 索引内存映射失败告警事件阶段（不推进百分比，仅推送告警通知）
     * 索引区内存映射失败回退 fread 时触发，前端可据此展示降级提示。
     * 此阶段为告警性质，不改变主解锁流程，仅通过进度回调异步推送。 */
    VERTHYS_UNLOCK_STAGE_INDEX_MMAP_FALLBACK = 9,  /* 索引内存映射失败回退告警 */
} VerthysUnlockStage;

/* 解锁进度信息（传递给回调函数）
 *
 * 字段说明：
 *   stage       — VerthysUnlockStage 枚举值，标识当前阶段
 *   percent     — 0~100 整数，累计进度百分比
 *   elapsed_ms  — 自解锁开始累计耗时（毫秒）
 *   message     — UTF-8 字符串（只读，DLL 内部字面量，NULL 终结），供前端展示
 *
 * 内存管理：
 *   message 指针仅在回调调用期间有效，调用方不可保存指针或在回调返回后访问。
 *   结构体由 DLL 在栈上构造，回调返回后即失效。
 */
typedef struct {
    uint32_t       stage;       /* VerthysUnlockStage */
    uint32_t       percent;     /* 0~100 */
    uint64_t       elapsed_ms;  /* 累计耗时（毫秒） */
    const char    *message;     /* UTF-8 阶段描述（只读，回调期间有效） */
} VerthysUnlockProgress;

/* 解锁进度回调函数指针类型
 *
 * 签名：void (*)(const VerthysUnlockProgress *progress, void *user_data)
 *
 * 调用约定：__cdecl（与 VERTHYS_CALL 一致）
 * 线程：在执行 Unlock 的线程内同步调用
 * 阻塞：回调函数应快速返回，不可执行耗时操作或阻塞 I/O
 * 异常：回调函数不可抛出 C++ 异常（C ABI 边界）
 */
typedef void (VERTHYS_CALL *VerthysUnlockProgressCallback)(const VerthysUnlockProgress *progress,
                                                          void *user_data);

/*
 * 注册解锁进度回调
 *
 *   handle    : 已初始化的加密库句柄（Verthys_Init 后即可注册）
 *   callback  : 回调函数指针，NULL 表示取消进度通知
 *   user_data : 透传给回调函数的用户数据指针（可为 NULL）
 *
 * 注册后，对该句柄的 Verthys_Unlock / Verthys_CreateWithPreset 调用会在各阶段
 * 通过 callback 通知进度。user_data 原样透传，DLL 不解析其内容。
 *
 * 返回值：
 *   VERTHYS_OK          — 注册成功
 *   VERTHYS_ERR_INVALID — handle 为 NULL
 *
 * 线程安全：MT-Unsafe（同一句柄不可并发注册/解锁）
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_RegisterUnlockProgressCallback(
    VerthysHandle handle,
    VerthysUnlockProgressCallback callback,
    void *user_data);

/*
 * 全新创建加密容器文件
 * 文件路径必须不存在，否则返回已存在错误；创建完成自动完成解锁，安全策略持久写入容器超级块。
 * 是系统唯一合法的容器新建入口。
 *
 * 线程安全：MT-Unsafe
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_CreateWithPreset(VerthysHandle handle,
                                    const char *verthys_path,
                                    const char *password,
                                    size_t      password_len,
                                    VerthysPreset preset);

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
 * 创建数据全量扫描游标
 * 指定起始遍历ID与单次批量读取条数，初始化B+树遍历迭代器并绑定只读事务快照。
 * 线程安全：MT-Unsafe，同一容器句柄不可并发创建多个扫描游标
 */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_ScanOpen(VerthysHandle handle,
                           uint64_t start_lid,
                           uint64_t batch_size,
                           VerthysScanCursor **out_cursor);

/*
 * 游标批量拉取完整解密记录
 * 关键使用约束：
 * 1. 解密失败的损坏条目会单独输出失败ID列表，不会静默丢弃
 * 2. 拉取前校验快照事务版本，容器已修改则返回快照过期错误，需重建游标
 * 3. 返回记录内存为堆深拷贝，必须调用专用接口释放，不可直接free释放
 * 4. 本接口完整解密所有二进制数据，CPU与IO开销较高，列表渲染优先使用摘要扫描接口
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
VERTHYS_API VerthysResult Verthys_GetSummaryCount(VerthysHandle handle, uint64_t *out_count);

/* ================================================================== *
 * 设计：轻量级记录类型存在性检查（只扫摘要索引，不读数据块）     *
 *                                                                    *
 * 用途：快速判断 verthys 中是否存在指定类型的记录（如 TYPE_GLOBAL_KEY），  *
 * 用于启动阶段决定 UI 路径（"初始化密钥" vs "身份验证"）。              *
 *                                                                    *
 * 性能：仅遍历 B+ 树索引节点读取 type 字段，不访问数据区块，            *
 *       不分配 name 字符串堆内存，典型耗时 < 100ms。          *
 *       相比 ScanSummaryOpen+Fetch 循环，消除多次 IPC 往返开销。       *
 *                                                                    *
 * 参数：                                                              *
 *   handle     : 已解锁的 Verthys 句柄                                  *
 *   rtype      : 目标记录类型（如 0x10 = TYPE_GLOBAL_KEY）             *
 *   out_found  : 输出，1=存在匹配类型的记录，0=不存在                   *
 *                                                                    *
 * 返回值：                                                            *
 *   VERTHYS_OK          — 检查完成（查看 out_found 判断是否存在）         *
 *   VERTHYS_ERR_INVALID — 参数错误（handle/out_found 为 NULL）            *
 *   VERTHYS_ERR_LOCKED  — 容器未解锁或应急熔断触发                       *
 *   VERTHYS_ERR_FORMAT  — v1 容器不支持摘要索引（out_found=0，前端回退）  *
 *                                                                    *
 * 线程安全：MT-Const（只读操作，与其他只读操作并发安全）               *
 * ================================================================== */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_HasRecordByType(VerthysHandle handle,
                                              uint8_t rtype,
                                              uint8_t *out_found);

/* ================================================================== *
 * 修复：按类型查找首条记录的逻辑 ID（lid）                    *
 *                                                                    *
 * 与 Verthys_HasRecordByType 的区别：                                   *
 *   - 同时返回 found 标志与匹配记录的 lid（单次遍历完成）             *
 *   - 覆盖 v1 容器路径（线性扫描 ctx->records），消除 v1 假阴性       *
 *                                                                    *
 * 设计目的：将"是否存在全局密钥记录 + 获取 lid"下沉到 worker 的        *
 * verthys_unlock 处理器内进程内执行，结果内联到 unlock 响应，            *
 * 彻底消除 unlock 后 probe IPC 链（verthysHasRecordByType →              *
 * findLidByTypeEarlyStop → verthysGetRecord）及其导致的 UI 卡死。        *
 *                                                                    *
 * 参数：                                                              *
 *   handle     : 已解锁的 Verthys 句柄                                  *
 *   rtype      : 目标记录类型（如 0x10 = TYPE_GLOBAL_KEY）             *
 *   out_found  : 输出，1=存在匹配类型的记录，0=不存在                   *
 *   out_lid    : 输出，匹配记录的逻辑 ID（found=1 时有效）             *
 *                                                                    *
 * 返回值：                                                            *
 *   VERTHYS_OK          — 检查完成（查看 out_found 判断是否存在）         *
 *   VERTHYS_ERR_INVALID — 参数错误（handle/out_found/out_lid 为 NULL）   *
 *   VERTHYS_ERR_LOCKED  — 容器未解锁或应急熔断触发                       *
 *                                                                    *
 * 注意：v1 容器返回 VERTHYS_OK + out_found（绝不返回 VERTHYS_ERR_FORMAT）， *
 *       这是 v1 假阴性 bug 的根治点。                                 *
 *                                                                    *
 * 线程安全：MT-Const（只读操作，与其他只读操作并发安全）               *
 * ================================================================== */
VERTHYS_API VerthysResult VERTHYS_CALL Verthys_FindFirstLidByType(VerthysHandle handle,
                                                  uint8_t rtype,
                                                  uint8_t *out_found,
                                                  uint64_t *out_lid);



/* ================================================================== *
 * 运行时性能诊断数据获取接口
 *
 * 读取容器运行过程中缓存、耗时、GC、事务等全量性能指标，用于后台监控与问题定位。
 * 线程安全：MT-Const
 * ================================================================== */
VERTHYS_API VerthysResult Verthys_GetDiagnostics(VerthysHandle handle,
                                  VerthysDiagnostics *out_diag);

/* ================================================================== *
 * V3 升级（API 版本 0x000B）：
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

/*
 * 动态防护状态报告（API 版本 0x000B）
 *
 * 所有字段均为非敏感运行时状态元数据，不含密钥、句柄或模块内部地址。
 */
typedef struct {
    /* 逐路径防御状态（维度 VERTHYS_DEFENSE_PATH_COUNT，下标 = VerthysDefensePath） */
    VerthysDefenseState path_state[VERTHYS_DEFENSE_PATH_COUNT];
    uint32_t blocked_count;          /* BLOCKED 路径数 */
    uint32_t degraded_count;         /* DEGRADED 路径数 */
    uint32_t failed_count;           /* FAILED 路径数 */
    uint8_t  all_critical_blocked;   /* 1 = 全部 7 条路径 BLOCKED（无 FAILED 且无 DEGRADED） */
    uint8_t  has_degraded;           /* 1 = 存在 DEGRADED 路径 */
    uint8_t  reserved[6];            /* 预留对齐（调用方必须置零传递，回填后忽略） */
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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* VERTHYS_H */