/*
 * cng_example.c — 示例 C 函数实现
 *
 *
 * C 语言端职责：
 *   - 提供纯函数，接收输入/输出缓冲区指针及长度
 *   - 执行具体的系统 API 调用（如 BCryptEncrypt）
 *   - 所有 C 函数返回标准化错误码（int）
 *   - C 源码内部严格禁止向 stdout/stderr 输出任何调试信息
 *   - 禁止调用 Windows 事件日志 API
 *   - 错误反馈仅通过返回值传递
 *
 * CI 红线：
 *   - 本文件不得包含 printf / fprintf / OutputDebugString
 *   - 所有函数返回值必须为 error_codes.h 定义的错误码常量
 */

#include "error_codes.h"

/* Windows CNG (Cryptography Next Generation) */
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

#include <string.h>

/* ------------------------------------------------------------------ *
 * 示例：CNG 加密函数                                                  *
 *                                                                    *
 * 纯函数模式：                                                        *
 *   - 接收输入缓冲区、输出缓冲区指针及长度                            *
 *   - 执行 BCryptEncrypt 系统调用                                     *
 *   - 返回标准化错误码                                                *
 *   - 无任何输出操作                                                  *
 * ------------------------------------------------------------------ */
int verthys_cng_encrypt(
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *ciphertext,
    size_t *ciphertext_len,
    const unsigned char *key,
    const unsigned char *nonce)
{
#ifdef _WIN32
    if (plaintext == NULL || ciphertext == NULL ||
        ciphertext_len == NULL || key == NULL || nonce == NULL) {
        return VERTHYS_C_ERR_INVALID;
    }

    /* 检查输出缓冲区容量（XChaCha20-Poly1305: 明文 + 16字节 MAC） */
    size_t required = plaintext_len + 16;
    if (*ciphertext_len < required) {
        return VERTHYS_C_ERR_INVALID;
    }

    BCRYPT_ALG_HANDLE alg_handle = NULL;
    BCRYPT_KEY_HANDLE key_handle = NULL;
    NTSTATUS status;

    /* 打开算法提供者 */
    status = BCryptOpenAlgorithmProvider(
        &alg_handle,
        BCRYPT_AES_GCM_ALGORITHM,
        NULL,
        0);
    if (!BCRYPT_SUCCESS(status)) {
        return VERTHYS_C_ERR_INTERNAL;
    }

    /* 生成对称密钥 */
    status = BCryptGenerateSymmetricKey(
        alg_handle,
        &key_handle,
        NULL,
        0,
        (PUCHAR)key,
        32,
        0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        return VERTHYS_C_ERR_INTERNAL;
    }

    /* 初始化 GCM IV（12 字节 Nonce） */
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = (PUCHAR)nonce;
    auth_info.cbNonce = 12;

    /* 执行加密 */
    DWORD encrypted_len = 0;
    status = BCryptEncrypt(
        key_handle,
        (PUCHAR)plaintext,
        (ULONG)plaintext_len,
        &auth_info,
        NULL,
        0,
        ciphertext,
        (ULONG)*ciphertext_len,
        &encrypted_len,
        0);

    /* 清理资源 */
    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg_handle, 0);

    if (!BCRYPT_SUCCESS(status)) {
        return VERTHYS_C_ERR_INTERNAL;
    }

    *ciphertext_len = encrypted_len;
    return VERTHYS_C_SUCCESS;
#else
    /* 非 Windows 平台：返回内部错误（实际项目使用 libsodium 替代） */
    (void)plaintext;
    (void)plaintext_len;
    (void)ciphertext;
    (void)ciphertext_len;
    (void)key;
    (void)nonce;
    return VERTHYS_C_ERR_INTERNAL;
#endif
}

/* ------------------------------------------------------------------ *
 * 示例：CNG 解密函数                                                  *
 * ------------------------------------------------------------------ */
int verthys_cng_decrypt(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    unsigned char *plaintext,
    size_t *plaintext_len,
    const unsigned char *key,
    const unsigned char *nonce)
{
#ifdef _WIN32
    if (ciphertext == NULL || plaintext == NULL ||
        plaintext_len == NULL || key == NULL || nonce == NULL) {
        return VERTHYS_C_ERR_INVALID;
    }

    /* GCM 密文 = 明文 + 16字节 MAC */
    if (ciphertext_len < 16) {
        return VERTHYS_C_ERR_CORRUPT;
    }
    size_t plain_len = ciphertext_len - 16;
    if (*plaintext_len < plain_len) {
        return VERTHYS_C_ERR_INVALID;
    }

    BCRYPT_ALG_HANDLE alg_handle = NULL;
    BCRYPT_KEY_HANDLE key_handle = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(
        &alg_handle,
        BCRYPT_AES_GCM_ALGORITHM,
        NULL,
        0);
    if (!BCRYPT_SUCCESS(status)) {
        return VERTHYS_C_ERR_INTERNAL;
    }

    status = BCryptGenerateSymmetricKey(
        alg_handle,
        &key_handle,
        NULL,
        0,
        (PUCHAR)key,
        32,
        0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(alg_handle, 0);
        return VERTHYS_C_ERR_INTERNAL;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = (PUCHAR)nonce;
    auth_info.cbNonce = 12;

    DWORD decrypted_len = 0;
    status = BCryptDecrypt(
        key_handle,
        (PUCHAR)ciphertext,
        (ULONG)ciphertext_len,
        &auth_info,
        NULL,
        0,
        plaintext,
        (ULONG)*plaintext_len,
        &decrypted_len,
        0);

    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg_handle, 0);

    if (!BCRYPT_SUCCESS(status)) {
        /* 认证失败 */
        return VERTHYS_C_ERR_AUTH;
    }

    *plaintext_len = decrypted_len;
    return VERTHYS_C_SUCCESS;
#else
    (void)ciphertext;
    (void)ciphertext_len;
    (void)plaintext;
    (void)plaintext_len;
    (void)key;
    (void)nonce;
    return VERTHYS_C_ERR_INTERNAL;
#endif
}

/* ------------------------------------------------------------------ *
 * 示例：创建不可继承的文件句柄                                        *
 *                                                                    *
 *    "不可继承强制"                               *
 * 安全属性中 bInheritHandle 设为 FALSE                                *
 * ------------------------------------------------------------------ */
int verthys_create_non_inheritable_file(
    const char *path,
    void **out_handle)
{
#ifdef _WIN32
    if (path == NULL || out_handle == NULL) {
        return VERTHYS_C_ERR_INVALID;
    }

    /* 安全属性：bInheritHandle = FALSE */
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;

    /* 转换路径为宽字符 */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    if (wlen == 0) {
        return VERTHYS_C_ERR_INVALID;
    }
    wchar_t *wpath = (wchar_t *)HeapAlloc(
        GetProcessHeap(), 0, wlen * sizeof(wchar_t));
    if (wpath == NULL) {
        return VERTHYS_C_ERR_NOMEM;
    }
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, wlen);

    HANDLE hFile = CreateFileW(
        wpath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        &sa,               /* bInheritHandle = FALSE */
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    HeapFree(GetProcessHeap(), 0, wpath);

    if (hFile == INVALID_HANDLE_VALUE) {
        return VERTHYS_C_ERR_IO;
    }

    *out_handle = (void *)hFile;
    return VERTHYS_C_SUCCESS;
#else
    (void)path;
    (void)out_handle;
    return VERTHYS_C_ERR_INTERNAL;
#endif
}
