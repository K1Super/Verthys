/*
 * cng_machine_key.c — CNG 机器密钥防导出加固实现
 *
 * 实现要点：
 *   1. NCryptOpenStorageProvider（Platform → Software 回退链，见下）
 *   2. NCryptCreatePersistedKey(RSA, NCRYPT_MACHINE_KEY_FLAG)
 *   3. NCryptSetProperty(NCRYPT_EXPORT_POLICY, 0) —— 禁用导出
 *   4. NCryptSetProperty(Security Descriminator) —— 仅 SYSTEM 可访问
 *   5. NCryptEncrypt / NCryptDecrypt（OAEP padding）
 *
 * 链接：ncrypt.lib
 *
 * ★ WP-11 修复：Provider 回退链（生产级可用性）。
 *   原实现硬编码 MS_PLATFORM_KEY_STORAGE_PROVIDER——该 Provider 的
 *   持久化密钥依赖平台安全能力（TPM/虚拟安全平台），在无 TPM 的
 *   物理机与 VM 上 NCryptCreatePersistedKey 恒返回 NTE_BAD_KEYSET，
 *   导致跨设备防御路径（defense_closure P7）永久 DEGRADED、pepper
 *   包装静默失效。
 *   修复：按强度降序尝试两个 Provider——
 *     1) MS_PLATFORM_KEY_STORAGE_PROVIDER —— TPM 支撑时密钥材料
 *        由平台安全边界保护（最强）
 *     2) MS_KEY_STORAGE_PROVIDER（Software KSP）—— 密钥材料由
 *        CNG 密钥隔离服务（KeyIso，SYSTEM 隔离进程）托管，持久化
 *        于用户/机器密钥容器，满足 v5.0 §5"内核托管不可导出"契约
 *   每个 Provider 内部再按 机器级 → 用户级 回退。
 *
 * 优雅降级策略：
 *   机器级密钥要求 SYSTEM 权限，普通用户进程无法创建。
 *   为避免阻塞 Verthys_Init，本模块采用回退链全部耗尽后降级：
 *     1) 机器级密钥（NCRYPT_MACHINE_KEY_FLAG）—— 最强绑定，需 SYSTEM
 *     2) 用户级密钥（无 flag）—— 用户密钥容器，绑定当前用户
 *     3) 优雅降级 —— 密钥不可用但 Verthys_Init 继续，defense_closure
 *        通过 cng_machine_key_is_available() 报告 DEGRADED 状态
 *
 *   s_initialized     —— 已执行过 init（幂等保护）
 *   s_key_available   —— 密钥实际可用（wrap/unwrap 可调用）
 */
#include "cng_machine_key.h"
#include "verthys_internal.h"
#include "verthys_diag.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <ncrypt.h>
#include <string.h>
#include <stdio.h>

/* 机器密钥名称 */
static const WCHAR K_KEY_NAME[] = L"Verthys_GMK_Wrap_Key_v1";

/* NCRYPT 常量辅助 */
#ifndef NCRYPT_MACHINE_KEY_FLAG
#define NCRYPT_MACHINE_KEY_FLAG 0x00000020
#endif

/* ★ 方案 4.3（P0-1 修复）：仅当密钥确实不存在时才允许创建。
 * NTE_BAD_KEYSET (0x80090029) = 密钥容器不存在；其他 OpenKey 失败
 * （权限不足、TPM 忙、profile 未加载等瞬时/环境性错误）一律不得重建，
 * 否则会静默销毁既有持久化密钥，导致此前被其包装的 pepper 永久无法解包。 */
#ifndef NTE_BAD_KEYSET
#define NTE_BAD_KEYSET ((SECURITY_STATUS)0x80090029L)
#endif

/* AT_KEYEXCHANGE 在 WIN32_LEAN_AND_MEAN 下未被 windows.h 自动包含，
 * wincrypt.h 中定义为 1，此处手动定义避免引入整个 wincrypt.h */
#ifndef AT_KEYEXCHANGE
#define AT_KEYEXCHANGE 1
#endif

/* SHA256 算法标识（BCRYPT_OAEP_PADDING_INFO.pszAlgId 需要宽字符串） */
#ifndef BCRYPT_SHA256_ALGORITHM
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#endif

/* ---------- 诊断日志 ---------- */

/* [CNG-DBG] 诊断日志（P2-5 修复）：
 *   由 VERTHYS_DIAG 编译门统一控制（cmake -DVERTHYS_DIAG=ON），
 *   生产构建默认关闭（宏为空操作），DLL 对调试器/DebugView 静默。
 *   诊断构建开启时经 VERTHYS_DIAG_LOG（OutputDebugStringA）输出。 */
#ifdef VERTHYS_DIAG
#define CNG_DBG(fmt, ...) do { \
    char _cng_buf[256]; \
    _snprintf_s(_cng_buf, sizeof(_cng_buf), _TRUNCATE, \
                "[CNG-DBG] " fmt "\n", ##__VA_ARGS__); \
    VERTHYS_DIAG_LOG(_cng_buf); \
} while (0)
#else
#define CNG_DBG(fmt, ...) ((void)0)
#endif

/* NCRYPT 状态码转字符串（用于日志） */
static const char *cng_status_name(SECURITY_STATUS st)
{
    switch (st) {
        case (SECURITY_STATUS)0x00000000L: return "ERROR_SUCCESS";
        case (SECURITY_STATUS)0x80090029L: return "NTE_BAD_KEYSET (密钥容器不存在/权限不足)";
        case (SECURITY_STATUS)0x80090016L: return "NTE_BAD_KEY_STATE";
        case (SECURITY_STATUS)0x8009000FL: return "NTE_EXISTS";
        case (SECURITY_STATUS)0x80070005L: return "E_ACCESSDENIED";
        default: return "OTHER";
    }
}

/* ---------- 模块状态 ---------- */

static NCRYPT_PROV_HANDLE s_hProvider = 0;
static NCRYPT_KEY_HANDLE  s_hKey = 0;
static int s_initialized = 0;       /* init 已执行（幂等保护） */
static int s_key_available = 0;     /* 密钥实际可用（wrap/unwrap 可调用） */

/* ---------- DACL 构建：仅 SYSTEM ---------- */

static int set_system_only_dacl(NCRYPT_HANDLE hObject)
{
    /* 构建 only-SYSTEM 的安全描述符，应用到密钥容器 */
    SECURITY_DESCRIPTOR sd;
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
        return -1;
    }

    BYTE aclBuf[256];
    ACL *pAcl = (ACL *)aclBuf;
    DWORD aclSize = sizeof(aclBuf);
    if (!InitializeAcl(pAcl, aclSize, ACL_REVISION)) {
        return -2;
    }

    /* DENY Everyone 所有权限 */
    PSID pEveryone = NULL;
    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&worldAuth, 1, SECURITY_WORLD_RID,
                                   0, 0, 0, 0, 0, 0, 0, &pEveryone)) {
        return -3;
    }
    /* NCRYPT_GENERIC_READ | NCRYPT_GENERIC_WRITE | NCRYPT_GENERIC_EXECUTE | DELETE */
    DWORD denyMask = 0xF001F;  /* 全部权限 */
    if (!AddAccessDeniedAce(pAcl, ACL_REVISION, denyMask, pEveryone)) {
        FreeSid(pEveryone);
        return -4;
    }
    FreeSid(pEveryone);

    /* ALLOW SYSTEM 完全控制 */
    PSID pSystem = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                                   0, 0, 0, 0, 0, 0, 0, &pSystem)) {
        return -5;
    }
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, 0xF001F, pSystem)) {
        FreeSid(pSystem);
        return -6;
    }
    FreeSid(pSystem);

    if (!SetSecurityDescriptorDacl(&sd, TRUE, pAcl, FALSE)) {
        return -7;
    }

    /* 应用到 NCRYPT 对象 */
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    /* NCRYPT 通过 Security Descriptor 属性设置（NCRYPT_SECURITY_DESCR_PROPERTY） */
    DWORD secDescSize = sizeof(SECURITY_DESCRIPTOR);
    SECURITY_STATUS st = NCryptSetProperty(
        hObject, NCRYPT_SECURITY_DESCR_PROPERTY,
        (PBYTE)&sd, secDescSize, 0);
    if (st != ERROR_SUCCESS) {
        return -8;
    }
    return 0;
}

/* ---------- 内部：尝试以指定 flag 打开或创建密钥 ----------
 *
 * hProv    —— 已打开的存储 Provider 句柄（由调用方管理生命周期）
 * flags:
 *   NCRYPT_MACHINE_KEY_FLAG —— 机器级密钥（需 SYSTEM 权限）
 *   0                        —— 用户级密钥（绑定当前用户）
 *
 * 返回 0 成功，非 0 失败。
 * 成功时 s_hKey 已指向打开/创建的密钥句柄。
 */
static int try_open_or_create_key(NCRYPT_PROV_HANDLE hProv, DWORD flags,
                                  const char *level_name)
{
    SECURITY_STATUS st;

    /* 1. 尝试打开已存在的密钥 */
    CNG_DBG("NCryptOpenKey(name=%ls, %s) ...", K_KEY_NAME, level_name);
    st = NCryptOpenKey(hProv, &s_hKey, K_KEY_NAME,
                       AT_KEYEXCHANGE, flags);
    CNG_DBG("NCryptOpenKey status=0x%08X (%s)", st, cng_status_name(st));

    if (st == ERROR_SUCCESS) {
        return 0;  /* 密钥已存在，直接使用 */
    }

    /*
     * ★ 方案 4.3（P0-1 根治）：创建路径仅由 NTE_BAD_KEYSET 触发。
     *
     * 原缺陷：任何 OpenKey 失败都以 NCRYPT_OVERWRITE_KEY_FLAG 重建持久化密钥，
     * 瞬时性错误（keyset 权限抖动 / TPM 忙 / profile 未加载）也会删除既有密钥，
     * 此前被其 RSA 包装的 pepper 永久无法解包 → OS 托管金库全部无法解锁。
     *
     * 修复：仅 NTE_BAD_KEYSET（密钥确实不存在）进入创建分支；
     * 其他错误原样上报，由上层优雅降级（defense_closure 报 DEGRADED）。
     * 且创建不再携带 NCRYPT_OVERWRITE_KEY_FLAG —— 若竞态下密钥已被并行创建，
     * 返回 NTE_EXISTS 并判定为"已存在可打开"重试一次打开，绝不覆盖。
     */
    if (st != NTE_BAD_KEYSET) {
        CNG_DBG("NCryptOpenKey failed with non-BAD_KEYSET status 0x%08X — refuse to rebuild", st);
        s_hKey = 0;
        return -1;
    }

    /* 2. 密钥确实不存在，创建持久化密钥（无 OVERWRITE 语义） */
    CNG_DBG("NCryptCreatePersistedKey(RSA, %ls) ...", K_KEY_NAME);
    st = NCryptCreatePersistedKey(
        hProv, &s_hKey, NCRYPT_RSA_ALGORITHM,
        K_KEY_NAME, AT_KEYEXCHANGE,
        flags);
    if (st == (SECURITY_STATUS)0x8009000FL /* NTE_EXISTS：竞态下已被并行创建 */) {
        CNG_DBG("NCryptCreatePersistedKey NTE_EXISTS — key was created concurrently, retry open");
        st = NCryptOpenKey(hProv, &s_hKey, K_KEY_NAME,
                           AT_KEYEXCHANGE, flags);
        if (st == ERROR_SUCCESS) {
            return 0;
        }
        CNG_DBG("NCryptOpenKey(retry after NTE_EXISTS) status=0x%08X (%s)", st, cng_status_name(st));
        s_hKey = 0;
        return -1;
    }
    CNG_DBG("NCryptCreatePersistedKey status=0x%08X (%s)", st, cng_status_name(st));

    if (st != ERROR_SUCCESS) {
        s_hKey = 0;
        return -1;
    }

    /* 3. 设置 2048-bit 密钥长度 */
    DWORD keyLength = 2048;
    st = NCryptSetProperty(s_hKey, NCRYPT_LENGTH_PROPERTY,
                           (PBYTE)&keyLength, sizeof(keyLength), 0);
    if (st != ERROR_SUCCESS) {
        CNG_DBG("NCryptSetProperty(LENGTH) failed: 0x%08X", st);
        NCryptDeleteKey(s_hKey, 0);
        s_hKey = 0;
        return -2;
    }

    /* 4. 禁用导出策略（NCRYPT_EXPORT_POLICY = 0 表示完全禁用导出） */
    DWORD exportPolicy = 0;
    NCryptSetProperty(s_hKey, NCRYPT_EXPORT_POLICY_PROPERTY,
                      (PBYTE)&exportPolicy, sizeof(exportPolicy), 0);

    /* 5. 仅机器级密钥应用 only-SYSTEM DACL
     *    用户级密钥不能应用 only-SYSTEM ACL，否则用户自己也无权访问 */
    if (flags & NCRYPT_MACHINE_KEY_FLAG) {
        set_system_only_dacl(s_hKey);
    }

    /* 6. Finalize 持久化 */
    st = NCryptFinalizeKey(s_hKey, 0);
    if (st != ERROR_SUCCESS) {
        CNG_DBG("NCryptFinalizeKey failed: 0x%08X (%s)", st, cng_status_name(st));
        NCryptDeleteKey(s_hKey, 0);
        s_hKey = 0;
        return -3;
    }

    CNG_DBG("%s 密钥创建并持久化成功", level_name);
    return 0;
}

/* ---------- 公共接口 ---------- */

/*
 * ★ WP-11：Provider 回退链初始化。
 *
 * 依次尝试（前序成功即止）：
 *   1. MS_PLATFORM_KEY_STORAGE_PROVIDER（TPM/平台安全支撑，最强）
 *      a. 机器级（需 SYSTEM）  b. 用户级
 *   2. MS_KEY_STORAGE_PROVIDER（Software KSP，KeyIso 内核隔离托管）
 *      a. 机器级（需 SYSTEM）  b. 用户级
 *
 * 全部失败 → 优雅降级（s_key_available=0，init 仍返回 0），
 * defense_closure P7（CROSS_DEVICE）据此报 DEGRADED。
 * 任一成功 → s_hProvider/s_hKey 指向该级句柄，进程生命周期内持有。
 */
int cng_machine_key_init(void)
{
    if (s_initialized) return 0;

    static const struct {
        LPCWSTR     provider;
        const char *label;
    } chain[] = {
        { MS_PLATFORM_KEY_STORAGE_PROVIDER, "platform-KSP" },
        { MS_KEY_STORAGE_PROVIDER,          "software-KSP" },
    };
    const size_t chain_len = sizeof(chain) / sizeof(chain[0]);

    s_key_available = 0;

    for (size_t p = 0; p < chain_len && !s_key_available; p++) {
        NCRYPT_PROV_HANDLE hProv = 0;
        SECURITY_STATUS st = NCryptOpenStorageProvider(&hProv,
                                                       chain[p].provider, 0);
        if (st != ERROR_SUCCESS) {
            CNG_DBG("NCryptOpenStorageProvider(%s) failed: 0x%08X (%s) — try next",
                    chain[p].label, st, cng_status_name(st));
            continue;
        }

        /* 机器级优先（最强绑定，需 SYSTEM 权限） */
        if (try_open_or_create_key(hProv, NCRYPT_MACHINE_KEY_FLAG,
                                   chain[p].label) == 0) {
            s_hProvider     = hProv;
            s_key_available = 1;
            s_initialized   = 1;
            return 0;
        }

        /* 机器级失败，回退用户级 */
        CNG_DBG("%s machine-level failed, falling back to user-level",
                chain[p].label);
        if (try_open_or_create_key(hProv, 0, chain[p].label) == 0) {
            s_hProvider     = hProv;
            s_key_available = 1;
            s_initialized   = 1;
            return 0;
        }

        /* 本 Provider 两级均失败 → 关闭句柄，尝试下一 Provider
         * ncrypt.dll 不导出 NCryptCloseStorageProvider（仅头文件声明），
         * NCryptFreeObject 是关闭 provider 句柄的正确 API */
        CNG_DBG("%s both levels failed — try next provider", chain[p].label);
        NCryptFreeObject(hProv);
    }

    /* 回退链全部耗尽 —— 优雅降级：密钥不可用但 Verthys_Init 继续，
     * cross-device 绑定降级为 DEGRADED（defense_closure 经
     * cng_machine_key_is_available() 查询） */
    CNG_DBG("all providers failed —— degrade gracefully");
    s_hProvider   = 0;
    s_hKey        = 0;
    s_initialized = 1;
    s_key_available = 0;
    return 0;
}

int cng_machine_key_is_available(void)
{
    return s_key_available;
}

int cng_machine_key_wrap(const uint8_t salt[CMK_GMK_SALT_BYTES],
                          uint8_t cipher[CMK_RSA_CIPHER_BYTES],
                          const uint8_t label[CMK_OAEP_LABEL_BYTES])
{
    if (!s_initialized) return -1;
    if (!s_key_available) return -2;  /* 优雅降级：密钥不可用 */

    /* 构建 BCRYPT_OAEP_PADDING_INFO */
    BCRYPT_OAEP_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    paddingInfo.pbLabel = (PUCHAR)label;
    paddingInfo.cbLabel = CMK_OAEP_LABEL_BYTES;

    /* NCryptEncrypt */
    DWORD cbResult = 0;
    SECURITY_STATUS st = NCryptEncrypt(
        s_hKey,
        (PBYTE)salt, CMK_GMK_SALT_BYTES,
        &paddingInfo,
        cipher, CMK_RSA_CIPHER_BYTES,
        &cbResult,
        NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS || cbResult != CMK_RSA_CIPHER_BYTES) {
        return -3;
    }

    /* 加密后立即清零临时盐值缓冲（不修改调用方原始数据） */
    return 0;
}

int cng_machine_key_unwrap(const uint8_t cipher[CMK_RSA_CIPHER_BYTES],
                            uint8_t salt[CMK_GMK_SALT_BYTES],
                            const uint8_t label[CMK_OAEP_LABEL_BYTES])
{
    if (!s_initialized) return -1;
    if (!s_key_available) return -2;  /* 优雅降级：密钥不可用 */

    BCRYPT_OAEP_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    paddingInfo.pbLabel = (PUCHAR)label;
    paddingInfo.cbLabel = CMK_OAEP_LABEL_BYTES;

    DWORD cbResult = 0;
    SECURITY_STATUS st = NCryptDecrypt(
        s_hKey,
        (PBYTE)cipher, CMK_RSA_CIPHER_BYTES,
        &paddingInfo,
        salt, CMK_GMK_SALT_BYTES,
        &cbResult,
        NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS || cbResult != CMK_GMK_SALT_BYTES) {
        /* 机器不匹配 / OAEP label 不一致 → 解密失败 */
        return -3;
    }
    return 0;
}

void cng_machine_key_destroy(void)
{
    if (s_hKey) {
        /* 注意：仅销毁句柄，不删除持久化密钥
         * （持久化密钥用于下次会话恢复）
         * 仅在应急销毁时调用 NCryptDeleteKey */
        NCryptFreeObject(s_hKey);
        s_hKey = 0;
    }
    if (s_hProvider) {
        /* ncrypt.dll 不导出 NCryptCloseStorageProvider，使用 NCryptFreeObject */
        NCryptFreeObject(s_hProvider);
        s_hProvider = 0;
    }
    s_initialized = 0;
    s_key_available = 0;
}
