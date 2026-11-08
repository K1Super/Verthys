/* 调用方签名校验实现。
 *
 * 判定顺序：
 *   1) 本 DLL 自身签名（防止替换未签名的 verthys.dll 绕过宿主校验）；
 *   2) 宿主进程主模块签名。
 * 两者都必须是「有效 Authenticode + 发布者证书 SHA-256 指纹等于构建期注入值」。
 *
 * 使用 CurrentUser/LocalMachine 信任链，不做吊销联网检查（离线环境可用）；
 * 指纹固定比对比信任链更严格：中间 CA 被攻破也不会放行非发布者证书。
 */
#include "vty_caller_auth.h"
#include "vty_types.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <string.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

#if defined(VERTHYS_REQUIRE_CALLER_SIG) && VERTHYS_REQUIRE_CALLER_SIG
#ifndef VERTHYS_PUBLISHER_SHA256
#error "VERTHYS_REQUIRE_CALLER_SIG requires VERTHYS_PUBLISHER_SHA256"
#endif
#endif

/* 未注入时为空串：即便误开开关也只会在运行时 fail-closed，不会放行 */
#ifndef VERTHYS_PUBLISHER_SHA256
#define VERTHYS_PUBLISHER_SHA256 ""
#endif

#define CALLER_PATH_CHARS 32768

/* 取自身模块句柄的锚点：按地址定位，DLL 被改名（多实例/私有部署）也能
 * 正确识别，不依赖 "verthys.dll" 这个文件名。 */
static const int k_module_anchor = 0;

/* 去掉 ':' / '-' / 空格等分隔符，统一成 64 位小写十六进制串。
 * 允许运维用带分隔符的指纹配置，避免“格式不同 → 全部拒绝”的误伤。 */
static int normalize_fingerprint(const char *in, char out[65])
{
    size_t n = 0;
    if (in == NULL) return 0;
    for (const char *p = in; *p != '\0'; ++p) {
        char c = *p;
        if (c == ':' || c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
        if (n >= 64) return 0;
        out[n++] = c;
    }
    if (n != 64) return 0;
    out[64] = '\0';
    return 1;
}

static int digest_to_hex(const BYTE *digest, DWORD len, char out[65])
{
    static const char k_hex[] = "0123456789abcdef";
    if (len != 32) return 0;
    for (DWORD i = 0; i < len; ++i) {
        out[i * 2] = k_hex[digest[i] >> 4];
        out[i * 2 + 1] = k_hex[digest[i] & 0x0f];
    }
    out[64] = '\0';
    return 1;
}

/* 验签并取出签名者证书指纹；任何一步失败都返回 0（fail-closed）。 */
static int verify_module_pinned(const wchar_t *path)
{
    char pinned[65];
    char actual[65];
    int ok = 0;

    SecureZeroMemory(pinned, sizeof(pinned));
    SecureZeroMemory(actual, sizeof(actual));
    if (!normalize_fingerprint(VERTHYS_PUBLISHER_SHA256, pinned)) {
        SecureZeroMemory(pinned, sizeof(pinned));
        return 0;
    }

    WINTRUST_FILE_INFO file_info;
    memset(&file_info, 0, sizeof(file_info));
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path;

    WINTRUST_DATA trust_data;
    memset(&trust_data, 0, sizeof(trust_data));
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policy, &trust_data);

    if (status == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA *prov =
            WTHelperProvDataFromStateData(trust_data.hWVTStateData);
        if (prov != NULL) {
            CRYPT_PROVIDER_SGNR *sgnr =
                WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
            if (sgnr != NULL && sgnr->csCertChain > 0 && sgnr->pasCertChain != NULL) {
                PCCERT_CONTEXT cert = sgnr->pasCertChain[0].pCert;
                BYTE digest[32];
                DWORD digest_len = sizeof(digest);
                if (cert != NULL &&
                    CryptHashCertificate(0, CALG_SHA_256, 0,
                                         cert->pbCertEncoded, cert->cbCertEncoded,
                                         digest, &digest_len)) {
                    if (digest_to_hex(digest, digest_len, actual)) {
                        ok = (memcmp(actual, pinned, 64) == 0);
                    }
                    SecureZeroMemory(digest, sizeof(digest));
                }
            }
        }
    }

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policy, &trust_data);

    /* 指纹属于信任根数据：无论成功或失败都不留在栈上 */
    SecureZeroMemory(pinned, sizeof(pinned));
    SecureZeroMemory(actual, sizeof(actual));
    return ok;
}

int vty_caller_auth_required(void)
{
#if defined(VERTHYS_REQUIRE_CALLER_SIG) && VERTHYS_REQUIRE_CALLER_SIG
    return 1;
#else
    return 0;
#endif
}

int vty_caller_auth_check(void)
{
    if (!vty_caller_auth_required()) return VTY_OK;

    wchar_t path[CALLER_PATH_CHARS];

    /* 自身模块优先：未签名的 DLL 被合法宿主加载时也拒绝 */
    HMODULE self = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)&k_module_anchor, &self) ||
        self == NULL) {
        return VTY_E_CALLER;
    }
    DWORD n = GetModuleFileNameW(self, path, CALLER_PATH_CHARS);
    if (n == 0 || n >= CALLER_PATH_CHARS) return VTY_E_CALLER;
    if (!verify_module_pinned(path)) return VTY_E_CALLER;

    n = GetModuleFileNameW(NULL, path, CALLER_PATH_CHARS);
    if (n == 0 || n >= CALLER_PATH_CHARS) return VTY_E_CALLER;
    if (!verify_module_pinned(path)) return VTY_E_CALLER;

    SecureZeroMemory(path, sizeof(path));
    return VTY_OK;
}
