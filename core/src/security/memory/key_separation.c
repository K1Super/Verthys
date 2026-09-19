/*
 * key_separation.c — 三权分立密钥 CNG 内核托管实现
 *
 *
 * CNG 内核托管实现要点：
 *   1. 共享算法提供者：BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM) +
 *      BCryptSetProperty(BCRYPT_CHAIN_MODE_GCM)，模块全局唯一 s_hAlgorithm。
 *   2. 密钥导入内核：BCryptGenerateSymmetricKey 将 32 字节密钥明文导入内核，
 *      返回 BCRYPT_KEY_HANDLE。调用后立即 verthys_secure_zero 入参，密钥字节
 *      从此只存在于内核地址空间。
 *   3. 句柄数组隔离：三个角色的 BCRYPT_KEY_HANDLE 存于 s_slots[3] 数组，
 *      VirtualLock 锁定该数组页（仅保护句柄值与状态标志，不保护密钥本体）。
 *   4. 内核态 AEAD：BCryptEncrypt/BCryptDecrypt 携带
 *      BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO（pbNonce/pbAuthData/pbTag），
 *      在内核态完成 AES-256-GCM 运算，密钥字节永不返回用户态。
 *   5. C 密钥休眠：active 标志实现逻辑休眠；CNG 句柄无 PAGE_NOACCESS 等价，
 *      AEAD 路径强制校验 active 状态，休眠态调用立即返回失败。
 *   6. 紧急销毁：BCryptDestroyKey 销毁内核句柄（内核释放密钥材料），
 *      BCryptCloseAlgorithmProvider 关闭算法提供者。无需多轮覆写用户态堆页。
 *
 * 算法参数：AES-256-GCM
 *   - 密钥：32 字节（BCRYPT_AES_256_KEY_SIZE = 32）
 *   - Nonce：12 字节（NIST SP 800-38D 推荐）
 *   - 认证标签：16 字节（GCM 最大强度）
 *   - 密文布局：[ciphertext || tag]（与 libsodium XChaCha20-Poly1305 兼容布局，
 *     便于上层封装统一处理）
 *
 * 注意：本模块非线程安全，调用方（事务提交路径）保证单线程串行访问。
 * 如需多线程访问，需在 s_slots 上加锁——但当前架构中 AEAD 运算均在
 * 单线程事务上下文内完成，无需引入锁开销。
 */
#include "key_separation.h"
#include "verthys_internal.h"  /* verthys_secure_zero / verthys_lock_memory / verthys_unlock_memory */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <string.h>

/* ---------- CNG 常量 ---------- */

/* BCRYPT_KEY_DATA_BLOB 导出格式头部：12 字节（MAGIC 4B + VERSION 4B + cbKey 4B）
 * 后跟密钥字节。用于 key_separation_acquire 向后兼容导出。 */
#define KEYSEP_EXPORT_HEADER_BYTES 12u

/* ---------- 模块状态 ---------- */

/*
 * 每个角色的密钥槽：CNG 内核句柄 + 安装/激活标志。
 * 密钥本体驻留内核地址空间，本结构仅持有句柄值（一个指针大小的整数）。
 * s_slots 数组整体被 VirtualLock 锁定，防止句柄值与状态标志被换出到磁盘
 * 残留（虽不致命，但避免信息泄露）。
 */
typedef struct {
    BCRYPT_KEY_HANDLE hKey;      /* CNG 内核密钥句柄（NULL=未安装） */
    int               installed; /* 密钥已安装标志（0=未安装，1=已安装） */
    int               active;    /* 激活状态（仅 KEY_ROLE_COMMIT 使用：0=休眠，1=激活） */
} KeySlot;

static KeySlot s_slots[KEY_ROLE_COUNT];
static BCRYPT_ALG_HANDLE s_hAlgorithm = NULL;  /* 共享 AES-GCM 算法提供者 */
static int     s_initialized = 0;

/* ---------- 辅助函数 ---------- */

/*
 * 打开 AES 算法提供者并切换至 GCM 链模式。
 * 模块全局唯一 s_hAlgorithm，三个角色共用，避免重复打开的开销。
 * 返回 0 成功，非 0 失败。
 */
static int open_aes_gcm_provider(void)
{
    if (s_hAlgorithm != NULL) return 0;  /* 已打开，幂等 */

    NTSTATUS st = BCryptOpenAlgorithmProvider(&s_hAlgorithm,
                                              BCRYPT_AES_ALGORITHM,
                                              NULL,
                                              0);
    if (!BCRYPT_SUCCESS(st)) {
        s_hAlgorithm = NULL;
        return -1;
    }

    /* 切换至 GCM 链模式（BCRYPT_CHAIN_MODE_GCM） */
    st = BCryptSetProperty(s_hAlgorithm,
                           BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           sizeof(BCRYPT_CHAIN_MODE_GCM),
                           0);
    if (!BCRYPT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(s_hAlgorithm, 0);
        s_hAlgorithm = NULL;
        return -1;
    }

    return 0;
}

/*
 * 初始化 BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO 结构（AES-GCM 专用）。
 *   auth_info : 输出结构（调用方栈分配）
 *   nonce     : 12 字节 Nonce
 *   ad        : 关联数据（可为 NULL）
 *   ad_len    : 关联数据字节数
 *   tag       : 标签缓冲（加密时为输出，解密时为输入）
 *   tag_len   : 标签字节数（必须为 KEYSEP_AEAD_TAG_BYTES）
 */
static void init_gcm_auth_info(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *auth_info,
                               const uint8_t nonce[KEYSEP_AEAD_NONCE_BYTES],
                               const uint8_t *ad, size_t ad_len,
                               uint8_t *tag, size_t tag_len)
{
    /* BCRYPT_INIT_AUTH_MODE_INFO 是 bcrypt.h 提供的标准宏，
     * 将 cbSize 与 dwInfoVersion 设为正确值，其余字段置零。 */
    BCRYPT_INIT_AUTH_MODE_INFO(*auth_info);

    auth_info->pbNonce      = (PUCHAR)nonce;
    auth_info->cbNonce      = KEYSEP_AEAD_NONCE_BYTES;
    auth_info->pbAuthData   = (ad_len > 0) ? (PUCHAR)ad : NULL;
    auth_info->cbAuthData   = (ULONG)ad_len;
    auth_info->pbTag        = (tag_len > 0) ? (PUCHAR)tag : NULL;
    auth_info->cbTag        = (ULONG)tag_len;

    /* pbMacContext / cbMacContext 仅用于分块流式运算，单次调用置 NULL/0 即可。 */
}

/* ===================================================================== *
 *                           公共接口                                    *
 * ===================================================================== */

int key_separation_init(void)
{
    if (s_initialized) return 0;  /* 幂等 */

    /* 重置槽位状态 */
    for (int r = 0; r < (int)KEY_ROLE_COUNT; r++) {
        s_slots[r].hKey      = NULL;
        s_slots[r].installed = 0;
        s_slots[r].active    = 0;
    }

    /* 打开共享 AES-GCM 算法提供者 */
    if (open_aes_gcm_provider() != 0) {
        return -1;
    }

    /*
     * 锁定 s_slots 数组所在内存页，防止句柄值与状态标志被换出到磁盘
     * （密钥本体在内核，但句柄值泄露仍可能被攻击者用于调用 BCryptDecrypt）。
     * VirtualLock 失败不阻断初始化（与 verthys_lock_memory 既有约定一致）。
     */
    verthys_lock_memory(s_slots, sizeof(s_slots));

    s_initialized = 1;
    return 0;
}

int key_separation_install(KeyRole role, const uint8_t key[KEYSEP_KEY_BYTES])
{
    if (!s_initialized) {
        if (key_separation_init() != 0) return -1;
    }
    if (role < 0 || role >= KEY_ROLE_COUNT) return -1;
    if (key == NULL) return -1;

    KeySlot *slot = &s_slots[role];

    /* 若该角色已有旧句柄，先销毁（避免句柄泄露） */
    if (slot->hKey != NULL) {
        BCryptDestroyKey(slot->hKey);
        slot->hKey = NULL;
    }

    /*
     * BCryptGenerateSymmetricKey 将 32 字节密钥明文导入内核，生成
     * BCRYPT_KEY_HANDLE。调用后密钥字节只存在于内核地址空间，
     * 用户态仅持有句柄值。
     *
     * 参数：
     *   s_hAlgorithm : 共享 AES-GCM 提供者
     *   &slot->hKey  : 输出内核句柄
     *   NULL, 0      : 让 CNG 自行分配密钥对象内存
     *   key, 32      : 密钥明文（导入后内核拷贝，用户态副本需调用方擦除）
     *   0            : flags
     */
    NTSTATUS st = BCryptGenerateSymmetricKey(s_hAlgorithm,
                                             &slot->hKey,
                                             NULL,
                                             0,
                                             (PUCHAR)key,
                                             KEYSEP_KEY_BYTES,
                                             0);
    if (!BCRYPT_SUCCESS(st)) {
        slot->hKey = NULL;
        return -1;
    }

    slot->installed = 1;

    if (role == KEY_ROLE_COMMIT) {
        /*
         * C 密钥安装后立即休眠：active=0，AEAD 路径将拒绝放行。
         * 必须经 key_separation_activate_commit 唤醒后方可使用。
         */
        slot->active = 0;
    } else {
        /* A/B 密钥安装后立即可用 */
        slot->active = 1;
    }

    /*
     * 清零调用方传入的密钥明文副本。参数虽声明为 const，但调用方栈/堆
     * 副本必须在此销毁，避免明文密钥在调用方上下文残留被后续溢出读取。
     * 此时内核已持有密钥独立副本，清零用户态副本不影响后续 AEAD 运算。
     * cast away const 为本模块明确的安全契约。
     */
    verthys_secure_zero((void *)key, KEYSEP_KEY_BYTES);

    return 0;
}

int key_separation_acquire(KeyRole role, uint8_t out_key[KEYSEP_KEY_BYTES])
{
    if (!s_initialized) return -1;
    if (role < 0 || role >= KEY_ROLE_COUNT) return -1;
    if (out_key == NULL) return -1;

    KeySlot *slot = &s_slots[role];
    if (slot->hKey == NULL) return -1;
    if (!slot->installed) return -1;  /* 密钥未安装 */

    /*
     * C 密钥非提交期间保持休眠：必须先 activate_commit 激活方可导出。
     * 这是为了保持与旧版（PAGE_NOACCESS 物理隔离）等价的逻辑隔离强度。
     */
    if (role == KEY_ROLE_COMMIT && !slot->active) {
        return -1;
    }

    /*
     * BCryptExportKey(BCRYPT_KEY_DATA_BLOB) 从内核句柄导出密钥字节。
     * 输出格式：[MAGIC(4B) || VERSION(4B) || cbKey(4B) || key bytes]
     * 总长度 = 12 + 32 = 44 字节。
     *
     * 注意：本接口使密钥字节短暂返回用户态，仅供仍使用
     * XChaCha20-Poly1305 的旧调用方过渡使用。新代码应使用
     * key_separation_aead_*，密钥字节永不离开内核。
     */
    uint8_t blob[KEYSEP_EXPORT_HEADER_BYTES + KEYSEP_KEY_BYTES];
    ULONG blob_len = 0;
    NTSTATUS st = BCryptExportKey(slot->hKey,
                                  NULL,
                                  BCRYPT_KEY_DATA_BLOB,
                                  blob,
                                  sizeof(blob),
                                  &blob_len,
                                  0);
    if (!BCRYPT_SUCCESS(st)) {
        verthys_secure_zero(blob, sizeof(blob));
        return -1;
    }

    /* 校验导出长度与头部格式 */
    if (blob_len != sizeof(blob)) {
        verthys_secure_zero(blob, sizeof(blob));
        return -1;
    }

    /* 跳过 12 字节头部，提取密钥字节到调用方缓冲 */
    memcpy(out_key, blob + KEYSEP_EXPORT_HEADER_BYTES, KEYSEP_KEY_BYTES);
    verthys_secure_zero(blob, sizeof(blob));

    return 0;
}

int key_separation_any_installed(void)
{
    if (!s_initialized) return 0;
    for (int r = 0; r < (int)KEY_ROLE_COUNT; r++) {
        if (s_slots[r].hKey != NULL && s_slots[r].installed) {
            return 1;
        }
    }
    return 0;
}

void key_separation_release(uint8_t key[KEYSEP_KEY_BYTES])
{
    if (key == NULL) return;
    /* 清零调用方栈缓冲区，防止明文密钥在栈上残留被后续溢出读取 */
    verthys_secure_zero(key, KEYSEP_KEY_BYTES);
}

int key_separation_activate_commit(void)
{
    if (!s_initialized) return -1;

    KeySlot *slot = &s_slots[KEY_ROLE_COMMIT];
    if (slot->hKey == NULL) return -1;
    if (!slot->installed) return -1;  /* 未安装无法激活 */

    /*
     * 激活 C 密钥：标记 active=1，允许 AEAD 运算与 acquire 导出。
     * 与旧版差异：CNG 句柄无 PAGE_NOACCESS 等价，此处仅做逻辑激活。
     * BCRYPT_KEY_HANDLE 一直驻留内核，但 AEAD 路径强制校验 active 状态，
     * 休眠态调用将立即返回失败，等价于"逻辑不可访问"。
     */
    slot->active = 1;
    return 0;
}

int key_separation_deactivate_commit(void)
{
    if (!s_initialized) return -1;

    KeySlot *slot = &s_slots[KEY_ROLE_COMMIT];
    if (slot->hKey == NULL) return -1;

    /*
     * 休眠 C 密钥：标记 active=0，AEAD 路径与 acquire 将拒绝放行。
     * 缩小 C 密钥暴露窗口，与旧版 PAGE_NOACCESS 等价的逻辑隔离。
     */
    slot->active = 0;
    return 0;
}

void key_separation_purge_all(void)
{
    if (!s_initialized) return;

    /*
     * 紧急销毁 / 熔断：对三个 BCRYPT_KEY_HANDLE 调用 BCryptDestroyKey。
     * 句柄值失效后，内核中密钥材料随之释放——
     * 后续任何 BCryptEncrypt/Decrypt 调用将返回 STATUS_INVALID_HANDLE。
     *
     * 与旧版差异：不再需要多轮覆写用户态堆页（密钥从未进入用户态），
     * BCryptDestroyKey 即等价于"内核态密钥销毁"。这比 HeapDestroy 更彻底，
     * 因为内核密钥材料所在内存由内核对象管理器统一回收，用户态无任何路径可达。
     */
    for (int r = 0; r < (int)KEY_ROLE_COUNT; r++) {
        KeySlot *slot = &s_slots[r];
        if (slot->hKey != NULL) {
            BCryptDestroyKey(slot->hKey);
            slot->hKey = NULL;
        }
        slot->installed = 0;
        slot->active    = 0;
    }

    /*
     * 关闭算法提供者（模块可能不再使用，释放 CNG 内部资源）。
     * 下次 init 会重新打开。
     */
    if (s_hAlgorithm != NULL) {
        BCryptCloseAlgorithmProvider(s_hAlgorithm, 0);
        s_hAlgorithm = NULL;
    }

    /* 解锁 s_slots 数组页 */
    verthys_unlock_memory(s_slots, sizeof(s_slots));

    s_initialized = 0;  /* 重置为未初始化，允许后续重新 init */
}

/* ===================================================================== *
 *                  CNG 内核态 AEAD 接口实现                              *
 * ===================================================================== */

int key_separation_aead_encrypt(KeyRole role,
                                const uint8_t nonce[KEYSEP_AEAD_NONCE_BYTES],
                                const uint8_t *ad, size_t ad_len,
                                const uint8_t *plaintext, size_t pt_len,
                                uint8_t *ciphertext, size_t *ct_len)
{
    if (!s_initialized) return -1;
    if (role < 0 || role >= KEY_ROLE_COUNT) return -1;
    if (nonce == NULL || plaintext == NULL || ciphertext == NULL || ct_len == NULL) {
        return -1;
    }
    /* 缓冲容量校验：ciphertext 需容纳 pt_len + 16B 标签 */
    if (*ct_len < pt_len + KEYSEP_AEAD_TAG_BYTES) return -1;
    if (ad == NULL && ad_len != 0) return -1;

    KeySlot *slot = &s_slots[role];
    if (slot->hKey == NULL || !slot->installed) return -1;

    /* C 密钥休眠态拒绝运算 */
    if (role == KEY_ROLE_COMMIT && !slot->active) return -1;

    /*
     * 标签写入位置：ciphertext 末尾 16 字节。
     * 密文布局 [ciphertext || tag] 与 libsodium XChaCha20-Poly1305 兼容，
     * 便于上层封装统一处理。
     */
    uint8_t *tag = ciphertext + pt_len;

    /* 初始化 GCM 认证模式信息 */
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    init_gcm_auth_info(&auth_info, nonce, ad, ad_len, tag, KEYSEP_AEAD_TAG_BYTES);

    /*
     * BCryptEncrypt 在内核态完成 AES-256-GCM 运算：
     *   - 明文从用户态传入，内核读取后加密，密文写回用户态 ciphertext 缓冲
     *   - 标签写入 auth_info.pbTag（即 ciphertext + pt_len）
     *   - pbIV=NULL, cbIV=0：GCM 的 Nonce 已在 auth_info 中指定
     *   - dwFlags=0：不使用 BCRYPT_BLOCK_PADDING（GCM 是流式 AEAD，无需填充）
     *
     * 密钥字节全程驻留内核，用户态仅见证明文→密文的转换。
     */
    ULONG result_len = 0;
    NTSTATUS st = BCryptEncrypt(slot->hKey,
                                (PUCHAR)plaintext,
                                (ULONG)pt_len,
                                &auth_info,
                                NULL,
                                0,
                                ciphertext,
                                (ULONG)pt_len,
                                &result_len,
                                0);
    if (!BCRYPT_SUCCESS(st)) {
        /* 失败时清零输出缓冲，防止残留半成品密文 */
        verthys_secure_zero(ciphertext, pt_len + KEYSEP_AEAD_TAG_BYTES);
        return -1;
    }

    /* GCM 流式加密：result_len 应等于 pt_len（不含标签） */
    if (result_len != pt_len) {
        verthys_secure_zero(ciphertext, pt_len + KEYSEP_AEAD_TAG_BYTES);
        return -1;
    }

    *ct_len = pt_len + KEYSEP_AEAD_TAG_BYTES;
    return 0;
}

int key_separation_aead_decrypt(KeyRole role,
                                const uint8_t nonce[KEYSEP_AEAD_NONCE_BYTES],
                                const uint8_t *ad, size_t ad_len,
                                const uint8_t *ciphertext, size_t ct_len,
                                uint8_t *plaintext, size_t *pt_len)
{
    if (!s_initialized) return -1;
    if (role < 0 || role >= KEY_ROLE_COUNT) return -1;
    if (nonce == NULL || ciphertext == NULL || plaintext == NULL || pt_len == NULL) {
        return -1;
    }
    /* 输入必须大于标签长度（至少有 1 字节密文 + 16 字节标签） */
    if (ct_len <= KEYSEP_AEAD_TAG_BYTES) return -1;
    /* 输出缓冲容量校验 */
    size_t expected_pt_len = ct_len - KEYSEP_AEAD_TAG_BYTES;
    if (*pt_len < expected_pt_len) return -1;
    if (ad == NULL && ad_len != 0) return -1;

    KeySlot *slot = &s_slots[role];
    if (slot->hKey == NULL || !slot->installed) return -1;

    /* C 密钥休眠态拒绝运算 */
    if (role == KEY_ROLE_COMMIT && !slot->active) return -1;

    /*
     * 标签读取位置：ciphertext 末尾 16 字节。
     * CNG 在内核态校验标签，认证失败返回 STATUS_AUTH_TAG_MISMATCH。
     */
    const uint8_t *tag = ciphertext + expected_pt_len;

    /* 初始化 GCM 认证模式信息 */
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    init_gcm_auth_info(&auth_info, nonce, ad, ad_len, (uint8_t *)tag, KEYSEP_AEAD_TAG_BYTES);

    /*
     * BCryptDecrypt 在内核态完成 AES-256-GCM 运算：
     *   - 输入 ct_len 字节（密文+标签），但 BCryptDecrypt 的 pbInput 长度
     *     应为"纯密文长度"（不含标签），标签通过 auth_info.pbTag 传入
     *   - 内核校验标签通过后写回明文到 plaintext 缓冲
     *   - 认证失败返回非 0，明文缓冲不写入有效数据
     */
    ULONG result_len = 0;
    NTSTATUS st = BCryptDecrypt(slot->hKey,
                                (PUCHAR)ciphertext,
                                (ULONG)expected_pt_len,
                                &auth_info,
                                NULL,
                                0,
                                plaintext,
                                (ULONG)expected_pt_len,
                                &result_len,
                                0);
    if (!BCRYPT_SUCCESS(st)) {
        /* 认证失败或内核错误：清零输出缓冲防止残留 */
        verthys_secure_zero(plaintext, expected_pt_len);
        return -1;
    }

    if (result_len != expected_pt_len) {
        verthys_secure_zero(plaintext, expected_pt_len);
        return -1;
    }

    *pt_len = expected_pt_len;
    return 0;
}
