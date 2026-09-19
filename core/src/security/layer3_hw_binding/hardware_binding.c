/*
 * hardware_binding.c — MachineGuid 机器实例指纹实现
 *
 * ★ 弃用 CPUID/SMBIOS/UEFI 路径（缺陷依据同头注）。
 *
 * 指纹构造：
 *   1. RegGetValueW 读取 HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
 *      （KEY_WOW64_64KEY 显式 64 位视图；KEY_QUERY_VALUE 权限，普通用户可读）；
 *   2. fingerprint = HMAC-SHA256(domain_key, MachineGuid UTF-8)；
 *      域分离密钥为固定常量（完整性用途，非秘密）——绑定的安全性来自
 *      MachineGuid 的唯一性与 OAEP label 绑定，不依赖密钥保密。
 *
 * 注意：MachineGuid 在重装系统时重新生成——这正是"绑定"语义：
 * 重装后需经授权迁移流程恢复；跨设备复制 .verthys 无法解出 OS 托管 pepper。
 */
#include "hardware_binding.h"
#include "verthys_internal.h"   /* verthys_secure_zero */
#include "verthys_crypto.h"     /* verthys_hmac_sha256 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>

/* ---------- 模块状态 ---------- */

static uint8_t s_instance_hash[HW_INSTANCE_HASH_BYTES];
static HwBindMode s_mode = HW_BIND_MACHINE_GUID;
static int s_initialized = 0;

/* 域分离密钥（固定常量，仅完整性用途） */
static const uint8_t K_HB_DOMAIN_KEY[VERTHYS_KEY_BYTES] = {
    'v', 'e', 'r', 't', 'h', 'y', 's', '/', 'm', 'a', 'c', 'h', 'i', 'n', 'e',
    '-', 'b', 'i', 'n', 'd', '-', 'v', '2', 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* ---------- MachineGuid 读取 ---------- */

/*
 * 读取注册表 MachineGuid（UTF-8 输出，截断保护）。
 * 返回 0 成功，非 0 失败。
 */
static int read_machine_guid(char *out, size_t cap)
{
    if (out == NULL || cap == 0) return -1;

    LSTATUS st = RegGetValueW(HKEY_LOCAL_MACHINE,
                              L"SOFTWARE\\Microsoft\\Cryptography",
                              L"MachineGuid",
                              RRF_RT_REG_SZ,
                              NULL,
                              NULL,
                              NULL);
    /* RegGetValueW 第一次调用探测大小失败并不必要：直接按固定容量读取 */
    (void)st;

    wchar_t guid_w[128];
    DWORD cb = sizeof(guid_w);
    st = RegGetValueW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Cryptography",
                      L"MachineGuid",
                      RRF_RT_REG_SZ | KEY_WOW64_64KEY,
                      NULL,
                      (PVOID)guid_w,
                      &cb);
    if (st != ERROR_SUCCESS || cb < sizeof(wchar_t)) {
        return -1;
    }
    guid_w[127] = L'\0';

    int n = WideCharToMultiByte(CP_UTF8, 0, guid_w, -1,
                                out, (int)cap, NULL, NULL);
    verthys_secure_zero(guid_w, sizeof(guid_w));
    if (n <= 0) return -1;
    return 0;
}

/* ---------- 公共接口 ---------- */

int hardware_binding_init(void)
{
    if (s_initialized) return 0;

    char guid_utf8[256];
    if (read_machine_guid(guid_utf8, sizeof(guid_utf8)) != 0) {
        return -1;
    }

    uint8_t mac[VERTHYS_HMAC_BYTES];
    int rc = verthys_hmac_sha256(mac, K_HB_DOMAIN_KEY,
                               (const uint8_t *)guid_utf8, strlen(guid_utf8));
    verthys_secure_zero(guid_utf8, sizeof(guid_utf8));
    if (rc != 0) {
        return -1;
    }

    memcpy(s_instance_hash, mac, HW_INSTANCE_HASH_BYTES);
    verthys_secure_zero(mac, sizeof(mac));

    s_mode = HW_BIND_MACHINE_GUID;
    s_initialized = 1;
    return 0;
}

int hardware_binding_get_hash(uint8_t hash[HW_INSTANCE_HASH_BYTES])
{
    if (!s_initialized) {
        /* 惰性初始化（Verthys_Init 已调用，此处兜底） */
        if (hardware_binding_init() != 0) return -1;
    }
    memcpy(hash, s_instance_hash, HW_INSTANCE_HASH_BYTES);
    return 0;
}

HwBindMode hardware_binding_get_mode(void)
{
    return s_mode;
}

int hardware_binding_verify(const uint8_t expected[HW_INSTANCE_HASH_BYTES])
{
    if (!s_initialized) return -1;
    /* 常量时间比较，防止侧信道 */
    uint8_t diff = 0;
    for (size_t i = 0; i < HW_INSTANCE_HASH_BYTES; i++) {
        diff |= (uint8_t)(s_instance_hash[i] ^ expected[i]);
    }
    return diff == 0 ? 0 : -1;
}
