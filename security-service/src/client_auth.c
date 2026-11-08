/*
 * client_auth.c — Authenticode 发布者钉扎、PID/SID 派生与模块校验
 */
#include "client_auth.h"
#include "state_crypto.h"
#include "service_util.h"

#include <psapi.h>
#include <softpub.h>
#include <string.h>
#include <wintrust.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "crypt32.lib")

#define VTY_AUTH_MODULE_SLOTS 512u

static int normalize_expected_hex(const wchar_t *input, wchar_t out[65])
{
    size_t i;
    size_t len;

    if (input == NULL || out == NULL) return -1;
    len = wcslen(input);
    if (len != 64u) return -1;
    for (i = 0; i < 64u; i++) {
        wchar_t c = input[i];
        if (c >= L'A' && c <= L'F') {
            c = (wchar_t)(c - L'A' + L'a');
        }
        if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) {
            return -1;
        }
        out[i] = c;
    }
    out[64] = L'\0';
    return 0;
}

static void hash_to_hex(const uint8_t hash[32], wchar_t out[65])
{
    static const wchar_t hex[] = L"0123456789abcdef";
    size_t i;

    for (i = 0; i < 32u; i++) {
        out[i * 2u] = hex[(hash[i] >> 4) & 0x0Fu];
        out[i * 2u + 1u] = hex[hash[i] & 0x0Fu];
    }
    out[64] = L'\0';
}

static int extract_signer_hash(void *state_data, uint8_t hash[32])
{
    CRYPT_PROVIDER_DATA *provider;
    CRYPT_PROVIDER_SGNR *signer;
    CRYPT_PROVIDER_CERT *cert;

    if (state_data == NULL) return -1;
    provider = WTHelperProvDataFromStateData(state_data);
    if (provider == NULL) return -1;
    signer = WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
    if (signer == NULL) return -1;
    cert = WTHelperGetProvCertFromChain(signer, 0);
    if (cert == NULL || cert->pCert == NULL ||
        cert->pCert->pbCertEncoded == NULL ||
        cert->pCert->cbCertEncoded == 0) {
        return -1;
    }
    return vty_sha256(cert->pCert->pbCertEncoded, cert->pCert->cbCertEncoded,
                      hash);
}

int vty_auth_verify_authenticode(const wchar_t *path,
                                 const wchar_t *expected_sha256)
{
    WINTRUST_FILE_INFO file_info;
    WINTRUST_DATA data;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    wchar_t expected[65];
    wchar_t actual[65];
    uint8_t hash[32];
    int ok = 0;
    LONG status;

    if (path == NULL || expected_sha256 == NULL ||
        normalize_expected_hex(expected_sha256, expected) != 0) {
        return -1;
    }
    if (!vty_path_exists(path)) return -1;

    memset(&file_info, 0, sizeof(file_info));
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path;

    memset(&data, 0, sizeof(data));
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file_info;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    status = WinVerifyTrust(NULL, &action, &data);
    if (status == ERROR_SUCCESS) {
        memset(hash, 0, sizeof(hash));
        if (extract_signer_hash(data.hWVTStateData, hash) == 0) {
            hash_to_hex(hash, actual);
            if (wcscmp(actual, expected) == 0) {
                ok = 1;
            }
        }
        vty_secure_zero(hash, sizeof(hash));
    }

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)WinVerifyTrust(NULL, &action, &data);
    return ok ? 0 : -1;
}

int vty_auth_client_process(HANDLE pipe, const wchar_t *expected_sha256,
                            int verify_image, VtyClientIdentity *identity,
                            HANDLE *process)
{
    DWORD pid = 0;
    DWORD token_user_len = 0;
    HANDLE local_process = NULL;
    HANDLE token = NULL;
    BYTE token_buf[VTY_SID_BUF_BYTES];
    PSID sid = NULL;
    int rc = -1;

    if (pipe == NULL || identity == NULL || process == NULL) return -1;
    memset(identity, 0, sizeof(*identity));
    *process = NULL;

    /* 远程客户端在本机没有 PID；GetNamedPipeClientProcessId 失败即拒绝。 */
    if (pipe == NULL || !GetNamedPipeClientProcessId(pipe, &pid) || pid == 0) {
        return -1;
    }
    identity->pid = pid;
    if (pid == GetCurrentProcessId()) {
        return -1;
    }
    local_process = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (local_process == NULL) return -1;

    if (vty_get_process_image_path(local_process, identity->image_path,
                                   VTY_PATH_MAX) != 0) {
        goto done;
    }
    if (verify_image &&
        vty_auth_verify_authenticode(identity->image_path, expected_sha256) !=
            0) {
        goto done;
    }

    if (!OpenProcessToken(local_process, TOKEN_QUERY, &token)) goto done;
    if (!GetTokenInformation(token, TokenUser, token_buf, sizeof(token_buf),
                             &token_user_len)) {
        goto done;
    }
    sid = ((TOKEN_USER *)token_buf)->User.Sid;
    if (sid == NULL || vty_sid_hash(sid, identity->sid_hash) != 0) goto done;

    *process = local_process;
    local_process = NULL;
    rc = 0;

done:
    if (token != NULL) CloseHandle(token);
    if (local_process != NULL) CloseHandle(local_process);
    vty_secure_zero(token_buf, sizeof(token_buf));
    if (rc != 0) {
        *process = NULL;
    }
    return rc;
}

int vty_auth_check_module(HANDLE process, const wchar_t *expected_sha256)
{
    HMODULE modules[VTY_AUTH_MODULE_SLOTS];
    DWORD needed = 0;
    DWORD count;
    DWORD i;
    int found = 0;

    if (process == NULL || expected_sha256 == NULL ||
        expected_sha256[0] == L'\0') {
        return -1;
    }
    memset(modules, 0, sizeof(modules));
    if (!EnumProcessModulesEx(process, modules, (DWORD)sizeof(modules),
                              &needed, LIST_MODULES_ALL)) {
        return -1;
    }
    count = needed / (DWORD)sizeof(HMODULE);
    if (count > VTY_AUTH_MODULE_SLOTS) count = VTY_AUTH_MODULE_SLOTS;

    for (i = 0; i < count; i++) {
        wchar_t module_path[VTY_PATH_MAX];
        const wchar_t *base;

        if (modules[i] == NULL) continue;
        if (GetModuleFileNameExW(process, modules[i], module_path,
                                 VTY_PATH_MAX) == 0) {
            continue;
        }
        module_path[VTY_PATH_MAX - 1u] = L'\0';
        base = wcsrchr(module_path, L'\\');
        base = (base != NULL) ? base + 1 : module_path;
        if (_wcsicmp(base, L"verthys.dll") != 0) continue;
        found = 1;
        if (vty_auth_verify_authenticode(module_path, expected_sha256) != 0) {
            return -1;
        }
    }
    return found ? 0 : -1;
}

void vty_auth_log_denied(const VtyClientIdentity *identity,
                         const wchar_t *reason)
{
    wchar_t sid_hex[VTY_SID_LOG_HEX_CHARS + 1u];
    wchar_t detail[256];
    DWORD pid = 0;
    const wchar_t *why = reason != NULL ? reason : L"unspecified";

    sid_hex[0] = L'\0';
    if (identity != NULL) {
        pid = identity->pid;
        (void)vty_sid_hash_log_hex(identity->sid_hash, sid_hex);
    }
    if (swprintf_s(detail, 256, L"client denied pid=%lu sid8=%s reason=%s",
                   (unsigned long)pid, sid_hex, why) < 0) {
        return;
    }
    vty_event_log(EVENTLOG_ERROR_TYPE, 3002, detail);
}
