/*
 * verthys_pepper.h — 胡椒安全托管框架（内部模块，不导出）
 *
 * 胡椒的安全托管框架
 *
 * 设计目标：
 *   胡椒的生命周期管理统一接口，解决"依赖外部实现，存在丢失则
 *   数据永久不可恢复"的风险。
 *
 * 三层胡椒来源（按优先级降序）：
 *   1. 注入胡椒：Verthys_Init 时由调度层通过 verthys_pepper_inject() 注入，
 *      胡椒由操作系统密钥存储（TPM/CNG/Keychain）保护，DLL 通过安全
 *      通道获取。最高优先级，部署首选。
 *   2. OS 托管胡椒：verthys_pepper_load_from_os() 从 CNG 持久化密钥
 *      读取（用户级优先、机器级兜底），首次使用时自动生成并持久化。
 *   3. 编译内嵌胡椒：keymanager.c 中的 static 常量，作为兜底默认值，
 *      保证零配置开箱即用（向后兼容）。
 *
 * 胡椒恢复卡（Shamir 秘密共享分片）：
 *   verthys_pepper_export_shamir() 将胡椒拆分为 N 份分片（threshold k-of-n），
 *   每份分片单独存储（不同物理介质/不同保管人），任意 k 份可重建胡椒。
 *   verthys_pepper_reconstruct_shamir() 从 k 份分片重建胡椒。
 *   防止单点丢失导致数据永久不可恢复。
 *
 * 安全约束：
 *   - 胡椒仅驻留于受保护内存（VirtualLock），不通过任何函数返回
 *   - verthys_pepper_get() 返回借用指针，调用方用后不得保留
 *   - 进程退出/Deinit 时安全清零
 *   - Shamir 分片不含原始胡椒，单份分片无意义
 *
 * 深模块：对外仅暴露 7 个函数，隐藏胡椒存储/派生/分片细节。
 */
#ifndef VERTHYS_PEPPER_H
#define VERTHYS_PEPPER_H

#include <stdint.h>
#include <stddef.h>
#include "verthys_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ===================================================================== *
 *                        胡椒生命周期接口                               *
 * ===================================================================== */

/*
 * 初始化胡椒模块（Verthys_Init 时调用，幂等）。
 * 按优先级尝试加载胡椒：
 *   1. 已注入的胡椒（verthys_pepper_inject 优先）
 *   2. OS 托管胡椒（CNG 持久化机器密钥）
 *   3. 编译内嵌胡椒（兜底默认值）
 *
 * 返回 0 成功，非 0 失败（仅当所有来源均失败时）。
 */
int verthys_pepper_init(void);

/*
 * 注入外部胡椒（调度层在 Verthys_Init 前调用）。
 * 胡椒由调度层从 OS 密钥存储（TPM/Keychain）获取后注入。
 * 注入后 verthys_pepper_init 将优先使用此胡椒。
 *
 * 参数：
 *   pepper : 32 字节胡椒（调用方负责注入后清零自己的副本）
 * 返回 0 成功，非 0 失败。
 */
int verthys_pepper_inject(const uint8_t pepper[VERTHYS_KEY_BYTES]);

/*
 * 获取当前生效的胡椒（借用指针，不拷贝）。
 * 调用方使用完毕后不得保留指针，胡椒仅在 verthys_pepper_deinit 前有效。
 *
 * 返回非 NULL 指针成功，NULL 失败（未初始化）。
 */
const uint8_t *verthys_pepper_get(void);

/*
 * 销毁胡椒模块（Verthys_Deinit 时调用）。
 * 安全清零胡椒内存并解锁内存页。
 */
void verthys_pepper_deinit(void);

/* ===================================================================== *
 *                  OS 托管胡椒（CNG 持久化密钥）                        *
 * ===================================================================== */

/*
 * 从 OS 密钥存储加载胡椒。
 * Windows：使用 CNG 持久化密钥（layer3_hw_binding 模块，4 槽位；
 *   用户级优先、机器级兜底，文件头记录封装级别，加载直达解包）。
 *   - 首次调用：生成随机胡椒，用 CNG 密钥加密后持久化到 %APPDATA%
 *   - 后续调用：从持久化存储读取并解密
 *
 * 返回 0 成功，非 0 失败（OS 不支持或密钥不可用）。
 */
int verthys_pepper_load_from_os(void);

/*
 * 将胡椒持久化到 OS 密钥存储（CNG 加密）。
 * 用于首次生成胡椒后持久化，或胡椒轮换后更新存储。
 *
 * 返回 0 成功，非 0 失败。
 */
int verthys_pepper_save_to_os(void);

/*
 * 设置胡椒存储路径覆盖（测试隔离用，内部符号）。
 * path 为 NULL 或空串时恢复默认 %APPDATA% 路径。
 * 该函数不在 DLL 导出清单中，发布面无变化。
 */
void verthys_pepper_set_storage_path_override(const char *path);

/*
 * 计算胡椒持久化文件指纹（内部符号，测试构造样本用）。
 *   meta: 8 字节头部（version||source_type||key_level||key_provider||reserved）
 *   返回 0 成功，非 0 失败。
 */
int pepper_file_fingerprint(const uint8_t meta[8],
                            const uint8_t *label, const uint8_t *cipher,
                            uint8_t out_fp[8]);

/* ===================================================================== *
 *             胡椒恢复卡（Shamir 秘密共享分片）                          *
 * ===================================================================== *
 * 将 32 字节胡椒拆分为 N 份分片，任意 threshold 份可重建。
 * 分片格式：index(1B) || share(32B) = 33 字节/份
 *
 * 算法：基于 GF(2^8) 的 Shamir 秘密共享，与 layer3_hw_binding 一致。
 *   - 生成 threshold-1 个随机系数，构造多项式 f(x)
 *   - f(0) = pepper（秘密）
 *   - 第 i 份分片 = (i, f(i))
 *   - 任意 threshold 份分片通过拉格朗日插值重建 f(0)
 */

/* Shamir 分片结构 */
typedef struct {
    uint8_t index;                      /* 分片索引（1..255，0 保留给秘密本身） */
    uint8_t share[VERTHYS_KEY_BYTES];     /* 分片值 f(index) */
} VerthysPepperShard;

/*
 * 将当前生效的胡椒拆分为 Shamir 分片。
 *
 * 参数：
 *   shards       : 输出分片数组（调用方分配，容量 = total_shards）
 *   total_shards : 分片总数（2..255）
 *   threshold    : 重建所需最少分片数（2..total_shards）
 *
 * 返回 0 成功，非 0 失败。
 */
int verthys_pepper_export_shamir(VerthysPepperShard *shards,
                               uint8_t total_shards,
                               uint8_t threshold);

/*
 * 从 Shamir 分片重建胡椒并注入模块。
 *
 * 参数：
 *   shards    : 分片数组（至少 threshold 份）
 *   count     : 提供的分片数（须 ≥ threshold）
 *   threshold : 重建所需最少分片数
 *
 * 返回 0 成功，非 0 失败（分片不足或校验失败）。
 */
int verthys_pepper_reconstruct_shamir(const VerthysPepperShard *shards,
                                    uint8_t count,
                                    uint8_t threshold);

/* ===================================================================== *
 *                        胡椒来源查询（诊断）                            *
 * ===================================================================== */

/* 胡椒来源枚举（诊断用，不暴露胡椒本身；取值同时用于容器超级块 flags[5]） */
typedef enum {
    VERTHYS_PEPPER_SOURCE_NONE     = 0,  /* 未初始化 */
    VERTHYS_PEPPER_SOURCE_INJECTED = 1,  /* 外部注入 */
    VERTHYS_PEPPER_SOURCE_OS       = 2,  /* OS 托管（CNG/TPM） */
    VERTHYS_PEPPER_SOURCE_COMPILED = 3,  /* 编译内嵌（兜底） */
    VERTHYS_PEPPER_SOURCE_SHAMIR   = 4   /* Shamir 重建 */
} VerthysPepperSource;

/* 查询当前胡椒来源（诊断用，不暴露胡椒值） */
VerthysPepperSource verthys_pepper_get_source(void);

/* 查询 pepper 来源错误状态。
 * 返回 1 = 最近一次 verthys_pepper_init 中 OS 托管 pepper 解包失败
 * （文件存在但机器密钥解不开 / 指纹不匹配），pepper 处于不可用态。
 * 此时容器解锁应返回 VERTHYS_ERR_PEPPER_SOURCE（而非 AUTH/INTERNAL），
 * 提示"保险库安全源已变更"而非"密码错误"。
 */
int verthys_pepper_source_error(void);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_PEPPER_H */
