/*
 * verthys_crypto_cng.c — CNG 内核态 AEAD 封装实现（V3 主密码学路径）
 *
 * GCM 内核母本基于 security/memory/key_separation.c 同源实现改造，
 * 差异点：
 *   1. 单实例上下文（VerthysCngAead）替代模块级三角色槽位数组——可多实例，
 *      由 keymanager_cng 组合出 V3 密钥组；
 *   2. nonce 由封装层内部计数器原子生成（InterlockedIncrement64，
 *      多线程加密下 nonce 唯一性有硬保证），并经 nonce_out 回传持久化；
 *   3. 返回值统一 VerthysResult 错误码（含 VERTHYS_ERR_CNG_UNAVAILABLE 显式
 *      上报 CNG 不可用，三级降级链的顶层错误信号）；
 *   4. 空明文（0 字节）合法（V3 分区元数据等小对象）。
 *
 * 线程安全：BCryptEncrypt/BCryptDecrypt 本身线程安全；nonce_counter 经
 * Interlocked 原子递增，多线程并发加密下 nonce 不重复。
 */
#include "verthys_crypto_cng.h"
#include "verthys_internal.h"  /* verthys_secure_zero / verthys_lock_memory */

#include <string.h>

/* ---------- 模块共享算法提供者（预创建） ---------- */

/*
 * 提供者生命周期（并发安全）：
 *   s_alg_lock 串行化 open/close 与引用计数增减——首次打开、失败重试、
 *   deinit 关闭全部经锁互斥，杜绝双开句柄泄漏与"并发方已认为就绪而
 *   句柄被关"的竞态。s_alg_refs 仅做引用计数（init/deinit 配对），
 *   不充当初始化判据；open 失败不改变状态（保持未打开），下次
 *   init_once 可重试。deinit 须与 init_once 严格配对，且不得与
 *   密钥导入并发（关闭前提：已导入句柄先行销毁，契约见头文件）。
 */
static BCRYPT_ALG_HANDLE s_shared_alg = NULL;
static volatile LONG s_alg_refs = 0;   /* 引用计数（init/deinit 配对） */
static SRWLOCK s_alg_lock = SRWLOCK_INIT;

/* ---------- 测试注入（只被测试 exe 使用，对象直链的内部符号；
 * 不在 DLL 导出清单中，发布面零变化） ---------- */

/* one-shot 标志：令下一次内核密钥导入确定性失败（模拟 BCrypt 调用失败，
 * 走真实失败分支——用于验证导入失败路径的调用方密钥清零契约） */
static volatile LONG s_test_import_fail_once = 0;

/* ntstatus.h 的 STATUS_UNSUCCESSFUL（精简头未引入，就地补定义） */
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

void verthys_cng_test_inject_import_failure(void)
{
    InterlockedExchange(&s_test_import_fail_once, 1);
}

/* 当前共享提供者引用计数观测（并发 init/deinit 压力测试的终态断言） */
LONG verthys_cng_test_alg_refs(void)
{
    return s_alg_refs;
}

/*
 * 打开 AES 算法提供者并切换至 GCM 链模式。
 * 调用方须持有 s_alg_lock 独占锁；失败时 s_shared_alg 保持 NULL
 * （状态不变，下次可重试）。返回 0 成功，非 0 失败。
 */
static int open_aes_gcm_provider_locked(void)
{
    NTSTATUS st = BCryptOpenAlgorithmProvider(&s_shared_alg,
                                              BCRYPT_AES_ALGORITHM,
                                              NULL,
                                              0);
    if (!BCRYPT_SUCCESS(st)) {
        s_shared_alg = NULL;
        return -1;
    }

    st = BCryptSetProperty(s_shared_alg,
                           BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           sizeof(BCRYPT_CHAIN_MODE_GCM),
                           0);
    if (!BCRYPT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(s_shared_alg, 0);
        s_shared_alg = NULL;
        return -1;
    }

    return 0;
}

VerthysResult verthys_cng_init_once(void)
{
    VerthysResult r = VERTHYS_OK;

    AcquireSRWLockExclusive(&s_alg_lock);
    if (s_shared_alg != NULL) {
        /* 已就绪：仅计数（持锁增减，与 deinit 的关闭判定互斥） */
        s_alg_refs++;
    } else if (open_aes_gcm_provider_locked() == 0) {
        s_alg_refs = 1;             /* 首个引用由打开者持有 */
    } else {
        r = VERTHYS_ERR_CNG_UNAVAILABLE;   /* 状态不变，下次可重试 */
    }
    ReleaseSRWLockExclusive(&s_alg_lock);
    return r;
}

void verthys_cng_global_deinit(void)
{
    AcquireSRWLockExclusive(&s_alg_lock);
    if (s_alg_refs > 0) {
        s_alg_refs--;
    }
    if (s_alg_refs == 0 && s_shared_alg != NULL) {
        /* 末位引用释放：真正关闭（未配对的额外 deinit 在 refs 已为 0 时
         * 为幂等空转，不产生负漂移） */
        BCryptCloseAlgorithmProvider(s_shared_alg, 0);
        s_shared_alg = NULL;
    }
    ReleaseSRWLockExclusive(&s_alg_lock);
}

/* ---------- GCM 认证模式信息（母本迁移） ---------- */

/*
 * 初始化 BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO 结构（AES-GCM 专用）。
 *   auth_info : 输出结构（调用方栈分配）
 *   nonce     : 12 字节 Nonce
 *   ad        : 关联数据（可为 NULL）
 *   ad_len    : 关联数据字节数（调用方入口已完成 ULONG 域守卫，无损收窄）
 *   tag       : 标签缓冲（加密时为输出，解密时为输入）
 *   tag_len   : 标签字节数（必须为 VERTHYS_CNG_TAG_BYTES）
 */
static void init_gcm_auth_info(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *auth_info,
                               const uint8_t nonce[VERTHYS_CNG_NONCE_BYTES],
                               const uint8_t *ad, ULONG ad_len,
                               uint8_t *tag, ULONG tag_len)
{
    BCRYPT_INIT_AUTH_MODE_INFO(*auth_info);

    auth_info->pbNonce      = (PUCHAR)nonce;
    auth_info->cbNonce      = VERTHYS_CNG_NONCE_BYTES;
    auth_info->pbAuthData   = (ad_len > 0) ? (PUCHAR)ad : NULL;
    auth_info->cbAuthData   = ad_len;
    auth_info->pbTag        = (tag_len > 0) ? (PUCHAR)tag : NULL;
    auth_info->cbTag        = tag_len;
}

/*
 * 计数器编码为 12 字节大端 nonce（96 位单调计数器）。
 * counter 为 uint64（< 2^96），高 4 字节恒零。
 */
static void encode_nonce(uint8_t nonce[VERTHYS_CNG_NONCE_BYTES], uint64_t counter)
{
    for (int i = 0; i < (int)VERTHYS_CNG_NONCE_BYTES; i++) {
        int shift = (int)(VERTHYS_CNG_NONCE_BYTES - 1 - (size_t)i) * 8;
        nonce[i] = (uint8_t)((shift >= 64) ? 0 : (counter >> shift));
    }
}

uint64_t verthys_cng_nonce_decode_counter(
    const uint8_t nonce[VERTHYS_CNG_NONCE_BYTES])
{
    uint64_t v = 0;
    for (size_t i = 4; i < VERTHYS_CNG_NONCE_BYTES; i++) {
        v = (v << 8) | (uint64_t)nonce[i];
    }
    return v;
}

/* ---------- 公共接口 ---------- */

VerthysResult verthys_cng_aead_init(VerthysCngAead *aead)
{
    if (aead == NULL) return VERTHYS_ERR_INVALID;

    /*
     * 红线：init 仅做内存消毒，绝不感知内核句柄——未初始化内存中
     *   的垃圾字段（imported/key 任意组合）无法与合法句柄区分，对垃圾值
     *   调用 BCryptDestroyKey 即 0xC0000005。已导入上下文须先 destroy
     *   再 init（契约见头文件）。
     */
    memset(aead, 0, sizeof(*aead));
    return VERTHYS_OK;
}

VerthysResult verthys_cng_aead_import_key(
    VerthysCngAead *aead,
    const uint8_t key[VERTHYS_CNG_KEY_BYTES],
    const uint8_t key_id[VERTHYS_CNG_KEY_ID_BYTES])
{
    NTSTATUS st;

    /*
     * 清零契约（const 消耗语义）：key 非 NULL 的所有返回路径——
     *   成功、内核导入失败、提供者不可用、上下文非法——一律清零
     *   调用方缓冲。调用方无法区分成败，零化责任全部在本函数。
     */
    if (key == NULL) return VERTHYS_ERR_INVALID;
    if (aead == NULL) {
        verthys_secure_zero((void *)key, VERTHYS_CNG_KEY_BYTES);
        return VERTHYS_ERR_INVALID;
    }

    /* 确保共享算法提供者就绪（幂等；调用方通常已 init_once）。
     * 防御路径经 init_once 获取的引用不配对释放——提供者随进程存活，
     * 消除"导入成功而提供者被并发 deinit 关闭"的窗口 */
    if (s_shared_alg == NULL) {
        VerthysResult r = verthys_cng_init_once();
        if (r != VERTHYS_OK) {
            verthys_secure_zero((void *)key, VERTHYS_CNG_KEY_BYTES);
            return r;
        }
    }

    /*
     * 重复导入：仅当 imported 标志置位时销毁旧句柄，避免内核句柄泄露。
     * 防御守卫：imported=0 时 key 必为无效值（未初始化垃圾或 NULL），
     *   绝不对其调用 BCryptDestroyKey（野句柄 → 0xC0000005）。
     */
    if (aead->imported && aead->key != NULL) {
        BCryptDestroyKey(aead->key);
        aead->key = NULL;
    }

    if (InterlockedExchange(&s_test_import_fail_once, 0) != 0) {
        st = STATUS_UNSUCCESSFUL;   /* 测试注入：模拟内核导入失败，走真实失败分支 */
    } else {
        st = BCryptGenerateSymmetricKey(s_shared_alg,
                                        &aead->key,
                                        NULL,
                                        0,
                                        (PUCHAR)key,
                                        VERTHYS_CNG_KEY_BYTES,
                                        0);
    }
    if (!BCRYPT_SUCCESS(st)) {
        aead->key = NULL;
        verthys_secure_zero((void *)key, VERTHYS_CNG_KEY_BYTES);
        return VERTHYS_ERR_CNG_UNAVAILABLE;
    }

    aead->alg           = s_shared_alg;
    aead->imported      = 1;
    aead->nonce_counter = 0;

    if (key_id != NULL) {
        memcpy(aead->key_id, key_id, VERTHYS_CNG_KEY_ID_BYTES);
    } else {
        memset(aead->key_id, 0, VERTHYS_CNG_KEY_ID_BYTES);
    }

    /*
     * 红线：密钥明文仅允许在本函数栈帧内短暂存在。
     * 内核已持有独立副本，立即清零调用方传入的用户态副本。
     * const 契约同 key_separation_install。
     */
    verthys_secure_zero((void *)key, VERTHYS_CNG_KEY_BYTES);

    return VERTHYS_OK;
}

VerthysResult verthys_cng_aead_encrypt(
    VerthysCngAead *aead,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t *ciphertext_len,
    uint8_t *nonce_out)
{
    ULONG pt_len32;
    ULONG ad_len32;

    if (aead == NULL || ciphertext == NULL || ciphertext_len == NULL ||
        nonce_out == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (plaintext == NULL && plaintext_len != 0) return VERTHYS_ERR_INVALID;
    if (aad == NULL && aad_len != 0) return VERTHYS_ERR_INVALID;
    /* 长度域守卫：单条明文上限 = ULONG_MAX - TAG（密文 = 明文+16 须在
     * CNG 的 32 位参数域内可表示；更大场景由上层分块，当前业务无此场景） */
    if (plaintext_len > 0xFFFFFFFFu - VERTHYS_CNG_TAG_BYTES) {
        return VERTHYS_ERR_INVALID;
    }
    if (aad_len > 0xFFFFFFFFu) return VERTHYS_ERR_INVALID;
    /* 缓冲容量校验（明文已受限域，加法无溢出）：ciphertext 需容纳 pt_len + 16B 标签 */
    if (*ciphertext_len < plaintext_len + VERTHYS_CNG_TAG_BYTES) {
        return VERTHYS_ERR_INVALID;
    }
    if (aead->key == NULL || !aead->imported) return VERTHYS_ERR_LOCKED;

    /* 域守卫后无损收窄（杜绝隐式截断进入内核调用） */
    pt_len32 = (ULONG)plaintext_len;
    ad_len32 = (ULONG)aad_len;

    /* nonce 计数器原子递增（多线程下 nonce 唯一性硬保证）；防回退/防重用 */
    uint64_t counter = (uint64_t)InterlockedIncrement64(
        (volatile LONG64 *)&aead->nonce_counter);
    if (counter == 0) {
        /* 2^64 回绕：理论上不可达，防御性拒绝而非静默重用 nonce */
        InterlockedDecrement64((volatile LONG64 *)&aead->nonce_counter);
        return VERTHYS_ERR_INTERNAL;
    }

    uint8_t nonce[VERTHYS_CNG_NONCE_BYTES];
    encode_nonce(nonce, counter);

    /* 标签写入位置：ciphertext 末尾 16 字节，布局 [ct || tag] */
    uint8_t *tag = ciphertext + plaintext_len;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    init_gcm_auth_info(&auth_info, nonce, aad, ad_len32,
                       tag, VERTHYS_CNG_TAG_BYTES);

    ULONG result_len = 0;
    NTSTATUS st = BCryptEncrypt(aead->key,
                                (PUCHAR)plaintext,
                                pt_len32,
                                &auth_info,
                                NULL,
                                0,
                                ciphertext,
                                pt_len32,
                                &result_len,
                                0);
    if (!BCRYPT_SUCCESS(st)) {
        /* 失败时清零输出缓冲，防止残留半成品密文与标签 */
        verthys_secure_zero(ciphertext, plaintext_len + VERTHYS_CNG_TAG_BYTES);
        return VERTHYS_ERR_INTERNAL;
    }

    /* GCM 流式加密：result_len 应等于 plaintext_len（不含标签） */
    if (result_len != pt_len32) {
        verthys_secure_zero(ciphertext, plaintext_len + VERTHYS_CNG_TAG_BYTES);
        return VERTHYS_ERR_INTERNAL;
    }

    memcpy(nonce_out, nonce, VERTHYS_CNG_NONCE_BYTES);
    *ciphertext_len = plaintext_len + VERTHYS_CNG_TAG_BYTES;
    return VERTHYS_OK;
}

VerthysResult verthys_cng_aead_decrypt(
    const VerthysCngAead *aead,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *nonce,
    uint8_t *plaintext, size_t *plaintext_len)
{
    ULONG ct_pt_len32;
    ULONG ad_len32;

    if (aead == NULL || ciphertext == NULL || plaintext == NULL ||
        plaintext_len == NULL || nonce == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (aad == NULL && aad_len != 0) return VERTHYS_ERR_INVALID;
    /* 输入至少包含标签（空明文合法：ct_len == 16） */
    if (ciphertext_len < VERTHYS_CNG_TAG_BYTES) return VERTHYS_ERR_INVALID;
    /* 长度域守卫：单条密文上限 = ULONG_MAX（对应加密侧明文上限
     * ULONG_MAX - 16；更大场景由上层分块） */
    if (ciphertext_len > 0xFFFFFFFFu) return VERTHYS_ERR_INVALID;
    if (aad_len > 0xFFFFFFFFu) return VERTHYS_ERR_INVALID;

    size_t expected_pt_len = ciphertext_len - VERTHYS_CNG_TAG_BYTES;
    if (*plaintext_len < expected_pt_len) return VERTHYS_ERR_INVALID;
    if (aead->key == NULL || !aead->imported) return VERTHYS_ERR_LOCKED;

    /* 域守卫后无损收窄（杜绝隐式截断进入内核调用） */
    ct_pt_len32 = (ULONG)expected_pt_len;
    ad_len32 = (ULONG)aad_len;

    /* 标签读取位置：ciphertext 末尾 16 字节 */
    const uint8_t *tag = ciphertext + expected_pt_len;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    init_gcm_auth_info(&auth_info, nonce, aad, ad_len32,
                       (uint8_t *)tag, VERTHYS_CNG_TAG_BYTES);

    ULONG result_len = 0;
    NTSTATUS st = BCryptDecrypt(aead->key,
                                (PUCHAR)ciphertext,
                                ct_pt_len32,
                                &auth_info,
                                NULL,
                                0,
                                plaintext,
                                ct_pt_len32,
                                &result_len,
                                0);
    if (!BCRYPT_SUCCESS(st)) {
        /* 认证失败（STATUS_AUTH_TAG_MISMATCH）或内核错误：
         * 清零输出缓冲，防止残留部分明文 */
        verthys_secure_zero(plaintext, expected_pt_len);
        return VERTHYS_ERR_AUTH;
    }

    if (result_len != ct_pt_len32) {
        verthys_secure_zero(plaintext, expected_pt_len);
        return VERTHYS_ERR_INTERNAL;
    }

    *plaintext_len = expected_pt_len;
    return VERTHYS_OK;
}

void verthys_cng_aead_destroy(VerthysCngAead *aead)
{
    if (aead == NULL) return;

    if (aead->key != NULL) {
        /* 内核释放密钥材料；句柄值失效，后续 AEAD 调用返回 INVALID_HANDLE */
        BCryptDestroyKey(aead->key);
        aead->key = NULL;
    }
    aead->alg           = NULL;
    aead->imported      = 0;
    aead->nonce_counter = 0;
    memset(aead->key_id, 0, sizeof(aead->key_id));
}

uint64_t verthys_cng_aead_nonce_counter(const VerthysCngAead *aead)
{
    if (aead == NULL || !aead->imported) return 0;
    return aead->nonce_counter;
}

VerthysResult verthys_cng_aead_restore_nonce_counter(VerthysCngAead *aead,
                                                 uint64_t counter)
{
    if (aead == NULL || !aead->imported) return VERTHYS_ERR_INVALID;
    /* 防回退：恢复值必须大于当前计数器（历史已用 nonce 不得复用） */
    if (counter < aead->nonce_counter) return VERTHYS_ERR_INVALID;

    InterlockedExchange64((volatile LONG64 *)&aead->nonce_counter,
                          (LONG64)counter);
    return VERTHYS_OK;
}

int verthys_cng_aead_is_imported(const VerthysCngAead *aead)
{
    return (aead != NULL && aead->imported && aead->key != NULL) ? 1 : 0;
}
