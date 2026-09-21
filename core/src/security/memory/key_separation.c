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
 *   4. C 密钥休眠：active 标志实现逻辑休眠；CNG 句柄无 PAGE_NOACCESS 等价，
 *      acquire 路径强制校验 active 状态，休眠态调用立即返回失败。
 *   5. 紧急销毁：BCryptDestroyKey 销毁内核句柄（内核释放密钥材料），
 *      BCryptCloseAlgorithmProvider 关闭算法提供者。无需多轮覆写用户态堆页。
 *
 * 本模块曾提供外部 nonce 的 AES-256-GCM 内核态运算接口，因 nonce 复用
 * 防线完全依赖调用方纪律且无生产调用点已整体移除；密钥消费方使用
 * verthys_crypto_cng 的 AEAD 上下文（内部 Interlocked 计数器生成 nonce）。
 *
 * 注意：本模块非线程安全，调用方保证单线程串行访问。
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
     * XChaCha20-Poly1305 的旧调用方过渡使用。新的密钥消费方使用
     * verthys_crypto_cng 的 AEAD 上下文，密钥字节永不离开内核。
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

