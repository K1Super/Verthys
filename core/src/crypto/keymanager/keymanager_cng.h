/*
 * keymanager_cng.h — V3 密钥组 CNG 内核托管生命周期（内部模块，不导出）
 *
 * 职责：
 *   1. V3 密钥组（MEK + A/B/C）批量导入：MEK 明文仅在其导入函数栈帧内
 *      短暂存在；A/B/C 以 wrapped 形态（MEK 内核态加密）进入，解包过程
 *      在内核态完成——解包输出缓冲栈上分配 + 立即清零；
 *   2. 句柄生命周期状态机：UNINITIALIZED → KERNEL_RESIDENT →
 *      (REKEYING → KERNEL_RESIDENT)* → DESTROYED；
 *   3. 句柄总数预算：≤ VERTHYS_CNG_MAX_HANDLES。
 *
 * wrapped 子密钥存储格式（V3 超级块承载，域分离标签 v3）：
 *   [12B nonce || 32B ciphertext || 16B tag] = 60 字节
 *   AAD = "verthys/wrap-v3"(16B) || role(1B)，与 V2 标签严格隔离。
 */
#ifndef VERTHYS_KEYMANAGER_CNG_H
#define VERTHYS_KEYMANAGER_CNG_H

#include <stdint.h>
#include <stddef.h>
#include "verthys_crypto_cng.h"

#ifdef __cplusplus
extern "C" {
#endif

/* V3 密钥角色（密钥层次） */
typedef enum {
    VERTHYS_CNG_KEY_MEK = 0,   /* L3 主加密密钥（wrapped 解包的密钥源） */
    VERTHYS_CNG_KEY_A,         /* L4 索引密钥 */
    VERTHYS_CNG_KEY_B,         /* L4 数据密钥 */
    VERTHYS_CNG_KEY_C,         /* L4 超级块密钥 */
    VERTHYS_CNG_KEY_COUNT
} VerthysCngKeyRole;

/* 生命周期状态机 */
typedef enum {
    VERTHYS_CNG_KM_UNINITIALIZED  = 0,  /* init 后，未导入任何密钥 */
    VERTHYS_CNG_KM_DERIVED        = 1,  /* DKM/MEK 在用户态短暂存在（导入中） */
    VERTHYS_CNG_KM_KERNEL_RESIDENT = 2, /* 全部句柄内核态驻留（正常运行） */
    VERTHYS_CNG_KM_REKEYING       = 3,  /* 新旧句柄共存，原子切换中 */
    VERTHYS_CNG_KM_DESTROYED      = 4   /* BCryptDestroyKey 完成，不可恢复 */
} VerthysCngKmState;

/* 句柄总数上限（CNG 句柄预算） */
#define VERTHYS_CNG_MAX_HANDLES 16

/* wrapped 子密钥序列化长度（12B nonce + 32B ct + 16B tag） */
#define VERTHYS_CNG_WRAPPED_BYTES \
    (VERTHYS_CNG_NONCE_BYTES + VERTHYS_CNG_KEY_BYTES + VERTHYS_CNG_TAG_BYTES)

typedef struct VerthysCngKeyManager {
    VerthysCngAead     keys[VERTHYS_CNG_KEY_COUNT];  /* 内核态密钥上下文组 */
    VerthysCngKmState  state;                      /* 生命周期状态 */
    int              handle_count;               /* 活跃内核句柄计数（≤ 上限） */
} VerthysCngKeyManager;

/*
 * 初始化密钥管理器（UNINITIALIZED 状态）。
 * 同时预创建共享 AES-GCM 算法提供者（verthys_cng_init_once，幂等）。
 */
VerthysResult verthys_cng_km_init(VerthysCngKeyManager *km);

/*
 * 批量导入 V3 密钥组：
 *   1. 导入 MEK（仅此一步密钥明文在用户态栈帧，导入后立即清零）；
 *   2. 用 MEK 内核句柄解包 wrapped_a/b/c（解密在内核态完成）；
 *   3. 解包输出（栈上 32B）立即导入对应角色 → 清零。
 *
 * 状态迁移：UNINITIALIZED → KERNEL_RESIDENT（成功）；
 * 失败（解包认证失败/CNG 不可用/预算超限）时销毁全部已导入句柄，
 * 状态回 UNINITIALIZED，返回 VERTHYS_ERR_AUTH / VERTHYS_ERR_CNG_UNAVAILABLE /
 * VERTHYS_ERR_INVALID。
 *
 * wrapped_* 布局见文件头；wrapped_*_len 必须等于 VERTHYS_CNG_WRAPPED_BYTES。
 * 重复调用（KERNEL_RESIDENT 态）：先销毁旧句柄再导入（解锁重入场景）。
 */
__declspec(noinline) VerthysResult verthys_cng_km_import_batch(
    VerthysCngKeyManager *km,
    const uint8_t mek[VERTHYS_CNG_KEY_BYTES],
    const uint8_t *wrapped_a, uint32_t wrapped_a_len,
    const uint8_t *wrapped_b, uint32_t wrapped_b_len,
    const uint8_t *wrapped_c, uint32_t wrapped_c_len
);

/*
 * verthys_v3_lifecycle 创建路径：MEK 内核句柄包装子密钥。
 * 用 MEK 角色上下文（须已导入）对 32B 子密钥明文做内核态加密，产出
 * wrapped 布局 [12B nonce || 32B ct || 16B tag]（60B，与 import_batch
 * 的解包格式互逆），AAD 角色绑定（域分离同 import 路径）。
 * key 明文在函数返回前 SecureZeroMemory（红线：明文仅本栈帧瞬态）。
 * wrapped_out 容量须 ≥ VERTHYS_CNG_WRAPPED_BYTES。
 */
__declspec(noinline) VerthysResult verthys_cng_km_wrap_key(
    VerthysCngKeyManager *km,
    VerthysCngKeyRole role,
    const uint8_t key[VERTHYS_CNG_KEY_BYTES],
    uint8_t *wrapped_out, uint32_t wrapped_out_cap
);

/*
 * verthys_v3_lifecycle 创建路径：生成 V3 密钥组 wrapped 形态。
 * 流程：A/B/C 各 32B 随机（用户态栈帧瞬态）→ MEK 临时导入内核 →
 * 逐角色 wrap（内核态加密，AAD 角色绑定）→ 临时 MEK 句柄销毁 →
 * 状态归还 UNINITIALIZED。产出与 import_batch 互逆：调用方持久化
 * wrapped_a/b/c 到超级块后，再调 import_batch(mek, ...) 完成
 * KERNEL_RESIDENT 正式导入（创建路径同样以解锁态收尾）。
 * wrapped_*_out 容量须 ≥ VERTHYS_CNG_WRAPPED_BYTES（超级块字段恰 60B）。
 * mek 明文不在本函数清零（import_batch 尚需使用，调用方终态清零）。
 * 失败原子性：不留任何句柄，状态回 UNINITIALIZED。
 */
VerthysResult verthys_cng_km_generate_keyset(
    VerthysCngKeyManager *km,
    const uint8_t mek[VERTHYS_CNG_KEY_BYTES],
    uint8_t *wrapped_a_out, uint32_t wrapped_a_cap,
    uint8_t *wrapped_b_out, uint32_t wrapped_b_cap,
    uint8_t *wrapped_c_out, uint32_t wrapped_c_cap
);

/*
 * 获取指定角色的内核态 AEAD 上下文（调用点接线用）。
 * 返回 NULL：参数非法或该角色未导入。
 * 返回的指针生命周期与 km 一致；KERNEL_RESIDENT 态下线程安全
 * （AEAD 运算并发安全，nonce 计数器原子递增）。
 */
VerthysCngAead *verthys_cng_km_get(VerthysCngKeyManager *km, VerthysCngKeyRole role);

/*
 * ChangePassword V3：旧口令派生 MEK 的包裹验证。
 * 临时导入 candidate MEK（唯一句柄，用后即毁）→ 对 wrapped_probe
 * （60B，调用方通常传超级块 wrapped_key_a）执行内核态解包试探：
 * AEAD 认证通过 = 该 MEK 即当前口令派生（VERTHYS_OK）；认证失败 =
 * 口令错误（VERTHYS_ERR_AUTH）。解包输出为栈上 32B 瞬态，验证后清零。
 * 不依赖任何 km 状态（纯静态验证，独立于已驻留密钥组）。
 */
VerthysResult verthys_cng_km_verify_mek(
    const uint8_t mek[VERTHYS_CNG_KEY_BYTES],
    const uint8_t *wrapped_probe, uint32_t wrapped_probe_len);

/*
 * ChangePassword V3：密钥组重包裹（口令变更）。
 * 前置：km 处于 KERNEL_RESIDENT（旧 MEK + A/B/C 内核驻留）。
 * 流程（单栈帧，A/B/C 明文仅瞬态）：
 *   对 role ∈ {A,B,C}：
 *     1. km 内旧 MEK 句柄解包 wrapped_role（超级块现值）→ 栈上 32B；
 *     2. 新 MEK 临时句柄（本函数内导入/销毁）重新加密 → new_wrapped_out；
 *     3. 立即清零栈上明文。
 * km 状态不变（仍为旧 MEK 驻留）——句柄切换由 rotate_mek 在超级块
 * 法定人数提交成功后执行（盘面/内存/km 三态一致的提交顺序约束）。
 * 失败原子性：km 句柄零变更；new_wrapped_* 产物作废由调用方丢弃
 *（超级块事务尚未提交，盘面不受影响）。
 */
VerthysResult verthys_cng_km_rekey(
    VerthysCngKeyManager *km,
    const uint8_t new_mek[VERTHYS_CNG_KEY_BYTES],
    const uint8_t *wrapped_a, uint32_t wrapped_a_len,
    const uint8_t *wrapped_b, uint32_t wrapped_b_len,
    const uint8_t *wrapped_c, uint32_t wrapped_c_len,
    uint8_t *new_wrapped_a_out, uint32_t new_wrapped_a_cap,
    uint8_t *new_wrapped_b_out, uint32_t new_wrapped_b_cap,
    uint8_t *new_wrapped_c_out, uint32_t new_wrapped_c_cap);

/*
 * ChangePassword V3：MEK 句柄轮换（超级块提交成功后收尾）。
 * 前置：KERNEL_RESIDENT。临时槽先行验证：new_mek 先导入独立上下文，
 * 成功后销毁旧 MEK 句柄并整体移交（纯内存操作，无中间窗口）；
 * new_mek 由 import_key 清零契约消耗。A/B/C 句柄不动（明文未变，
 * 仅 wrapped 形态随口令更新）。失败（导入失败）：旧 MEK 槽原样
 * 驻留，零变更上抛——unwrap/verify 语义保持。
 */
VerthysResult verthys_cng_km_rotate_mek(
    VerthysCngKeyManager *km,
    const uint8_t new_mek[VERTHYS_CNG_KEY_BYTES]);

/*
 * 自动密钥轮换：A/B/C 句柄原位切换（超级块提交成功后收尾）。
 * 前置：KERNEL_RESIDENT。new_a/b/c 为调用方已 init + import 的全新
 * 上下文（verthys_rekey_auto_rotate 产物）。消耗语义（调用方在任意
 * 返回路径均不得再 destroy 这三个结构）：
 *   - 成功：三个上下文按值移交 km->keys[A/B/C]（调用方栈结构置零），
 *     km->keys[] 槽位地址不变——wal/txn 借用的 VerthysCngAead 指针
 *     续期有效（原子切换句柄的落地形态）；nonce 计数器
 *     随结构移交（wrap/table 帧已消耗的值不回退）；
 *   - 失败（参数/状态非法）：三个上下文由本函数销毁，km 零变更。
 * MEK 句柄不动（轮换非改密）。handle_count / 进程级总量严格配对
 * （销毁旧 3 + 移交新 3，净值不变）。
 */
__declspec(noinline) VerthysResult verthys_cng_km_rotate_abc(
    VerthysCngKeyManager *km,
    VerthysCngAead *new_a,
    VerthysCngAead *new_b,
    VerthysCngAead *new_c);

/* 防御闭环判据：是否有任一密钥已导入内核（1=是） */
int verthys_cng_km_any_installed(const VerthysCngKeyManager *km);

/*
 * 进程级 CNG 内核句柄总量（本模块全部 VerthysCngKeyManager
 * 实例的活跃句柄之和，原子维护）。defense_closure MEM_DUMP 判据的 V3 分支：
 * > 0 即密钥组已进入内核托管 → 可置 BLOCKED。模块级全局状态与 ctx 解耦，
 * 支持防御闭环在无句柄上下文时查询。
 */
int verthys_cng_km_global_handle_total(void);

/* 当前活跃内核句柄计数 */
int verthys_cng_km_handle_count(const VerthysCngKeyManager *km);

/* 生命周期状态查询 */
VerthysCngKmState verthys_cng_km_state(const VerthysCngKeyManager *km);

/*
 * 销毁全部密钥（锁定/Deinit/紧急熔断）。
 * 对全部 BCRYPT_KEY_HANDLE 调用 BCryptDestroyKey，内核态密钥材料
 * 不可恢复；状态 → DESTROYED。DESTROYED 后须 verthys_cng_km_init 方可
 * 重新导入。幂等。
 */
void verthys_cng_km_destroy_all(VerthysCngKeyManager *km);

#ifdef __cplusplus
}
#endif

#endif /* VERTHYS_KEYMANAGER_CNG_H */
