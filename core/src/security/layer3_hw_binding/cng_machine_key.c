/*
 * cng_machine_key.c — CNG 机器密钥防导出加固实现
 *
 * 实现要点：
 *   1. NCryptOpenStorageProvider（平台安全边界 → 软件 KSP 两个 Provider）
 *   2. NCryptCreatePersistedKey(RSA)（仅在 seal 期、容器确实缺失时）
 *   3. NCryptSetProperty(NCRYPT_EXPORT_POLICY, 0) —— 禁用导出
 *   4. NCryptSetProperty(Security Descriptor) —— 机器级容器仅 SYSTEM 可访问
 *   5. NCryptEncrypt / NCryptDecrypt（OAEP padding）
 *
 * 链接：ncrypt.lib
 *
 * 密钥槽位（4 槽）：
 *   单键全局态替换为槽位表，槽序即封装策略序——
 *     0) 平台安全边界 KSP · 用户级（TPM 支撑时绑定最强，优先）
 *     1) 软件 KSP · 用户级（常规桌面默认落点）
 *     2) 平台安全边界 KSP · 机器级（兜底：SYSTEM 上下文、无用户配置档）
 *     3) 软件 KSP · 机器级（兜底）
 *   策略意义：初始化与封装优先用户级，机器级仅在用户级不可用（SYSTEM
 *   上下文）时兜底，密钥级别不再随调用方运行权限上下漂移。
 *
 * 优雅降级策略：
 *   各槽位逐级尝试后全部失败时降级为不可用，不阻塞 Verthys_Init；
 *   调用方应通过 cng_machine_key_is_available() 查询实际可用性。
 *
 *   s_initialized —— 已执行过 init（幂等保护）
 *   CmkSlot.key_open / prov_open —— 槽位容器 / provider 实际可打开
 *   CmkSlot.create_blocked —— 本进程内创建尝试已失败（不再重试）
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

/* 密钥容器名称（用户级与机器级同名，由打开级别旗标区分作用域） */
static const WCHAR K_KEY_NAME[] = L"Verthys_GMK_Wrap_Key_v1";

/* NCRYPT 常量辅助 */
#ifndef NCRYPT_MACHINE_KEY_FLAG
#define NCRYPT_MACHINE_KEY_FLAG 0x00000020
#endif

/* ★ 仅当容器确实不存在时才允许创建。
 * NTE_BAD_KEYSET (0x80090029) = 密钥容器不存在；其他 OpenKey 失败
 * （权限不足、TPM 忙、profile 未加载等瞬时/环境性错误）一律不得重建，
 * 否则会静默销毁既有持久化密钥，导致此前被其包装的胡椒永久无法解包。 */
#ifndef NTE_BAD_KEYSET
#define NTE_BAD_KEYSET ((SECURITY_STATUS)0x80090029L)
#endif

/* NTE_EXISTS：创建时容器已被并行创建（竞态） */
#ifndef NTE_EXISTS
#define NTE_EXISTS ((SECURITY_STATUS)0x8009000FL)
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

/* [CNG-DBG] 诊断日志：
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

/* ---------- 模块状态：4 槽位表 ---------- */

typedef struct {
    LPCWSTR          provider;       /* KSP 全名 */
    int              provider_id;    /* CmkKeyProvider 取值 */
    int              level_id;       /* CmkKeyLevel 取值 */
    NCRYPT_PROV_HANDLE hProv;
    NCRYPT_KEY_HANDLE  hKey;
    int              prov_open;      /* provider 可打开 */
    int              key_open;       /* 密钥容器可打开 */
    int              create_blocked; /* 本进程内创建失败（不可重试） */
} CmkSlot;

/* 槽序 = 封装策略序：用户级优先（同级别内平台安全边界优先），机器级兜底 */
static CmkSlot s_slots[4] = {
    { MS_PLATFORM_KEY_STORAGE_PROVIDER, CMK_PROVIDER_PLATFORM_KSP, CMK_KEY_LEVEL_USER,    0, 0, 0, 0, 0 },
    { MS_KEY_STORAGE_PROVIDER,          CMK_PROVIDER_SOFTWARE_KSP, CMK_KEY_LEVEL_USER,    0, 0, 0, 0, 0 },
    { MS_PLATFORM_KEY_STORAGE_PROVIDER, CMK_PROVIDER_PLATFORM_KSP, CMK_KEY_LEVEL_MACHINE, 0, 0, 0, 0, 0 },
    { MS_KEY_STORAGE_PROVIDER,          CMK_PROVIDER_SOFTWARE_KSP, CMK_KEY_LEVEL_MACHINE, 0, 0, 0, 0, 0 },
};

static int s_initialized = 0;        /* init 已执行（幂等保护） */

/* 槽位对应的打开级别旗标 */
static DWORD slot_level_flag(const CmkSlot *s)
{
    return (s->level_id == CMK_KEY_LEVEL_MACHINE) ? NCRYPT_MACHINE_KEY_FLAG : 0;
}

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

/* ---------- 槽位创建（仅容器缺失时，加固规则） ---------- */

/*
 * 在槽位 Provider 内创建 RSA 密钥容器。
 *
 * 加固规则：
 *   1. 创建不携带 NCRYPT_OVERWRITE_KEY_FLAG —— 若竞态下容器已被并行
 *      创建，返回 NTE_EXISTS 并重开一次，绝不覆盖。
 *   2. 2048-bit 密钥长度。
 *   3. 导出策略置 0（完全禁用导出）。
 *   4. 机器级容器应用 only-SYSTEM DACL；用户级不应用（否则用户自身
 *      也无权访问）。
 *   5. Finalize 持久化，任一步失败删除刚建容器。
 */
static int slot_create_key(CmkSlot *s)
{
    SECURITY_STATUS st;

    CNG_DBG("NCryptCreatePersistedKey(RSA, %s)", s->provider);
    st = NCryptCreatePersistedKey(
        s->hProv, &s->hKey, NCRYPT_RSA_ALGORITHM,
        K_KEY_NAME, AT_KEYEXCHANGE,
        slot_level_flag(s));
    if (st == NTE_EXISTS) {
        CNG_DBG("NCryptCreatePersistedKey NTE_EXISTS — key was created concurrently, retry open");
        st = NCryptOpenKey(s->hProv, &s->hKey, K_KEY_NAME,
                           AT_KEYEXCHANGE, slot_level_flag(s));
        if (st == ERROR_SUCCESS) {
            s->key_open = 1;
            return 0;
        }
        CNG_DBG("NCryptOpenKey(retry after NTE_EXISTS) status=0x%08X (%s)", st, cng_status_name(st));
        s->hKey = 0;
        return -1;
    }
    CNG_DBG("NCryptCreatePersistedKey status=0x%08X (%s)", st, cng_status_name(st));

    if (st != ERROR_SUCCESS) {
        s->hKey = 0;
        return -1;
    }

    /* 设置 2048-bit 密钥长度 */
    DWORD keyLength = 2048;
    st = NCryptSetProperty(s->hKey, NCRYPT_LENGTH_PROPERTY,
                           (PBYTE)&keyLength, sizeof(keyLength), 0);
    if (st != ERROR_SUCCESS) {
        CNG_DBG("NCryptSetProperty(LENGTH) failed: 0x%08X", st);
        NCryptDeleteKey(s->hKey, 0);
        s->hKey = 0;
        return -2;
    }

    /* 禁用导出策略（NCRYPT_EXPORT_POLICY = 0 表示完全禁用导出） */
    DWORD exportPolicy = 0;
    NCryptSetProperty(s->hKey, NCRYPT_EXPORT_POLICY_PROPERTY,
                      (PBYTE)&exportPolicy, sizeof(exportPolicy), 0);

    /* 仅机器级容器应用 only-SYSTEM DACL */
    if (slot_level_flag(s) & NCRYPT_MACHINE_KEY_FLAG) {
        set_system_only_dacl(s->hKey);
    }

    /* Finalize 持久化 */
    st = NCryptFinalizeKey(s->hKey, 0);
    if (st != ERROR_SUCCESS) {
        CNG_DBG("NCryptFinalizeKey failed: 0x%08X (%s)", st, cng_status_name(st));
        NCryptDeleteKey(s->hKey, 0);
        s->hKey = 0;
        return -3;
    }

    s->key_open = 1;
    return 0;
}

/* ---------- 槽位打开（仅 Open，绝不 Create） ---------- */

/* 打开槽位 provider 与密钥容器；失败仅置位标记，不阻塞其他槽位 */
static void slot_open(CmkSlot *s)
{
    SECURITY_STATUS st = NCryptOpenStorageProvider(&s->hProv, s->provider, 0);
    if (st != ERROR_SUCCESS) {
        CNG_DBG("NCryptOpenStorageProvider(%s) failed: 0x%08X (%s)",
                s->provider, st, cng_status_name(st));
        return;
    }
    s->prov_open = 1;

    st = NCryptOpenKey(s->hProv, &s->hKey, K_KEY_NAME,
                       AT_KEYEXCHANGE, slot_level_flag(s));
    if (st == ERROR_SUCCESS) {
        s->key_open = 1;
    }
}

/* 按级别 + KSP 定位槽位；未命中返回 NULL */
static CmkSlot *find_slot(int key_level, int key_provider)
{
    for (int i = 0; i < 4; i++) {
        if (s_slots[i].level_id == key_level &&
            s_slots[i].provider_id == key_provider) {
            return &s_slots[i];
        }
    }
    return NULL;
}

/* ---------- OAEP 包装/解包（槽位句柄） ---------- */

static int wrap_via_slot(CmkSlot *s,
                         const uint8_t salt[CMK_GMK_SALT_BYTES],
                         uint8_t cipher[CMK_RSA_CIPHER_BYTES],
                         const uint8_t label[CMK_OAEP_LABEL_BYTES])
{
    BCRYPT_OAEP_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    paddingInfo.pbLabel = (PUCHAR)label;
    paddingInfo.cbLabel = CMK_OAEP_LABEL_BYTES;

    DWORD cbResult = 0;
    SECURITY_STATUS st = NCryptEncrypt(
        s->hKey,
        (PBYTE)salt, CMK_GMK_SALT_BYTES,
        &paddingInfo,
        cipher, CMK_RSA_CIPHER_BYTES,
        &cbResult,
        NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS || cbResult != CMK_RSA_CIPHER_BYTES) {
        return -3;
    }
    return 0;
}

static int unwrap_via_slot(CmkSlot *s,
                           const uint8_t cipher[CMK_RSA_CIPHER_BYTES],
                           uint8_t salt[CMK_GMK_SALT_BYTES],
                           const uint8_t label[CMK_OAEP_LABEL_BYTES])
{
    BCRYPT_OAEP_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    paddingInfo.pbLabel = (PUCHAR)label;
    paddingInfo.cbLabel = CMK_OAEP_LABEL_BYTES;

    DWORD cbResult = 0;
    SECURITY_STATUS st = NCryptDecrypt(
        s->hKey,
        (PBYTE)cipher, CMK_RSA_CIPHER_BYTES,
        &paddingInfo,
        salt, CMK_GMK_SALT_BYTES,
        &cbResult,
        NCRYPT_PAD_OAEP_FLAG);
    if (st != ERROR_SUCCESS || cbResult != CMK_GMK_SALT_BYTES) {
        /* 密钥不匹配 / OAEP label 不一致 → 解密失败 */
        return -3;
    }
    return 0;
}

/* ---------- 公共接口 ---------- */

int cng_machine_key_init(void)
{
    if (s_initialized) return 0;

    for (int i = 0; i < 4; i++) {
        s_slots[i].hProv = 0;
        s_slots[i].hKey  = 0;
        s_slots[i].prov_open = 0;
        s_slots[i].key_open = 0;
        s_slots[i].create_blocked = 0;
        slot_open(&s_slots[i]);
    }

    /* 全部容器不可用（首启）→ 按策略序创建首个用户级密钥；
     * 机器级绝不隐式创建（隐式创建会把封装级别拖进运行权限上下文） */
    int any_key = 0;
    for (int i = 0; i < 4; i++) {
        if (s_slots[i].key_open) { any_key = 1; break; }
    }
    if (!any_key) {
        for (int i = 0; i < 4; i++) {
            CmkSlot *s = &s_slots[i];
            if (!s->prov_open) continue;
            SECURITY_STATUS st = NCryptOpenKey(s->hProv, &s->hKey, K_KEY_NAME,
                                               AT_KEYEXCHANGE, slot_level_flag(s));
            if (st == NTE_BAD_KEYSET) {
                if (slot_create_key(s) == 0) break;
                s->create_blocked = 1;
                CNG_DBG("slot %d create failed — try next", i);
            } else if (st == ERROR_SUCCESS) {
                s->key_open = 1;
                break;
            }
            /* 其他错误：不创建，换下一槽 */
        }
    }

    s_initialized = 1;
    return 0;
}

int cng_machine_key_is_available(void)
{
    if (!s_initialized) return 0;
    for (int i = 0; i < 4; i++) {
        if (s_slots[i].prov_open) return 1;
    }
    return 0;
}

int cng_machine_key_seal(const uint8_t salt[CMK_GMK_SALT_BYTES],
                         uint8_t cipher[CMK_RSA_CIPHER_BYTES],
                         const uint8_t label[CMK_OAEP_LABEL_BYTES],
                         int *out_level, int *out_provider)
{
    if (!s_initialized) return -1;

    for (int i = 0; i < 4; i++) {
        CmkSlot *s = &s_slots[i];
        if (!s->prov_open || s->create_blocked) continue;

        if (!s->key_open) {
            SECURITY_STATUS st = NCryptOpenKey(s->hProv, &s->hKey, K_KEY_NAME,
                                               AT_KEYEXCHANGE, slot_level_flag(s));
            if (st == NTE_BAD_KEYSET) {
                if (slot_create_key(s) != 0) {
                    s->create_blocked = 1;
                    continue;
                }
            } else if (st == ERROR_SUCCESS) {
                s->key_open = 1;
            } else {
                /* 非缺失类错误：不创建，换下一槽 */
                continue;
            }
        }

        if (wrap_via_slot(s, salt, cipher, label) != 0) {
            continue;
        }
        if (out_level)    *out_level    = s->level_id;
        if (out_provider) *out_provider = s->provider_id;
        return 0;
    }
    return -4;
}

int cng_machine_key_unwrap_known(const uint8_t cipher[CMK_RSA_CIPHER_BYTES],
                                 uint8_t salt[CMK_GMK_SALT_BYTES],
                                 const uint8_t label[CMK_OAEP_LABEL_BYTES],
                                 int key_level, int key_provider)
{
    if (!s_initialized) return -1;

    CmkSlot *s = find_slot(key_level, key_provider);
    if (s == NULL || !s->prov_open) return -2;

    /* 仅打开，绝不创建：容器缺失原样报错（不跨级回退） */
    if (!s->key_open) {
        SECURITY_STATUS st = NCryptOpenKey(s->hProv, &s->hKey, K_KEY_NAME,
                                           AT_KEYEXCHANGE, slot_level_flag(s));
        if (st != ERROR_SUCCESS) return -2;
        s->key_open = 1;
    }

    return unwrap_via_slot(s, cipher, salt, label);
}

void cng_machine_key_destroy(void)
{
    for (int i = 0; i < 4; i++) {
        CmkSlot *s = &s_slots[i];
        /* 注意：仅销毁句柄，不删除持久化密钥
         * （持久化密钥用于下次会话恢复）
         * 仅在应急销毁时调用 NCryptDeleteKey */
        if (s->hKey) {
            NCryptFreeObject(s->hKey);
            s->hKey = 0;
        }
        if (s->hProv) {
            /* ncrypt.dll 不导出 NCryptCloseStorageProvider，使用 NCryptFreeObject */
            NCryptFreeObject(s->hProv);
            s->hProv = 0;
        }
        s->prov_open = 0;
        s->key_open = 0;
        s->create_blocked = 0;
    }
    s_initialized = 0;
}