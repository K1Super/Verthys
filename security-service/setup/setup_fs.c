/*
 * setup_fs.c — 目录删除、SHA-256、根证书导入/删除、目录归档
 */

#include "setup_internal.h"

static void delete_tree_inner(const wchar_t *path)
{
    wchar_t pattern[VTY_PATH_MAX];
    WIN32_FIND_DATAW fd;
    HANDLE find;

    if (vty_path_join(pattern, VTY_PATH_MAX, path, L"*") != 0) {
        RemoveDirectoryW(path);
        return;
    }
    find = FindFirstFileW(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE) {
        RemoveDirectoryW(path);
        return;
    }
    do {
        wchar_t full[VTY_PATH_MAX];
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0) {
            continue;
        }
        if (vty_path_join(full, VTY_PATH_MAX, path, fd.cFileName) != 0) continue;
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                RemoveDirectoryW(full);
            } else {
                delete_tree_inner(full);
            }
        } else {
            SetFileAttributesW(full, FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(full);
        }
    } while (FindNextFileW(find, &fd));
    FindClose(find);
    RemoveDirectoryW(path);
}

void delete_tree(const wchar_t *path)
{
    if (path == NULL || !vty_path_exists(path)) return;
    (void)vty_acl_force_admin_full(path);
    delete_tree_inner(path);
}

static void hash_to_hex(const uint8_t hash[VTY_HASH_BYTES], wchar_t out[65])
{
    for (size_t i = 0; i < VTY_HASH_BYTES; i++) {
        out[i * 2u] = (wchar_t)(L"0123456789abcdef"[(hash[i] >> 4) & 0x0Fu]);
        out[i * 2u + 1u] =
            (wchar_t)(L"0123456789abcdef"[hash[i] & 0x0Fu]);
    }
    out[64] = L'\0';
}

int sha256_file_hex(const wchar_t *path, wchar_t out[65])
{
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD size = 0;
    DWORD read = 0;
    uint8_t *data = NULL;
    uint8_t hash[VTY_HASH_BYTES];
    int rc = -1;

    if (path == NULL || out == NULL) return -1;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    size = GetFileSize(file, NULL);
    if (size == 0 || size > 65536u) goto done;
    data = (uint8_t *)malloc(size);
    if (data == NULL) goto done;
    if (!ReadFile(file, data, size, &read, NULL) || read != size) goto done;
    if (vty_sha256(data, size, hash) != 0) goto done;
    hash_to_hex(hash, out);
    rc = 0;

done:
    if (data != NULL) {
        vty_secure_zero(data, size);
        free(data);
    }
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return rc;
}

int root_ca_pin_matches(const wchar_t *sha_hex)
{
    const char *pin = VERTHYS_ROOT_CA_SHA256;
    if (pin == NULL || pin[0] == '\0') return 1;
    if (sha_hex == NULL) return 0;
    for (size_t i = 0; i < 64u; i++) {
        if ((char)sha_hex[i] != pin[i]) return 0;
    }
    return pin[64] == '\0';
}

int delete_root_cert_by_sha256(const wchar_t *sha_hex)
{
    HCERTSTORE store = NULL;
    PCCERT_CONTEXT cert = NULL;
    int rc = 0;

    if (sha_hex == NULL || sha_hex[0] == L'\0') return 0;
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                          CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");
    if (store == NULL) return -1;
    while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL) {
        uint8_t hash[VTY_HASH_BYTES];
        wchar_t hex[65];
        if (vty_sha256(cert->pbCertEncoded, cert->cbCertEncoded, hash) != 0) {
            continue;
        }
        hash_to_hex(hash, hex);
        if (_wcsicmp(hex, sha_hex) == 0) {
            if (!CertDeleteCertificateFromStore(cert)) rc = -1;
            cert = NULL;
            break;
        }
    }
    CertCloseStore(store, 0);
    return rc;
}

void remove_parent_if_empty(const wchar_t *security_dir)
{
    wchar_t parent[VTY_PATH_MAX];
    const wchar_t *slash;

    if (security_dir == NULL) return;
    slash = wcsrchr(security_dir, L'\\');
    if (slash == NULL || (size_t)(slash - security_dir) >= VTY_PATH_MAX) return;
    memcpy(parent, security_dir, (size_t)(slash - security_dir));
    parent[slash - security_dir] = L'\0';
    (void)RemoveDirectoryW(parent);
}

int fail_with_ca(PCCERT_CONTEXT *ctx, int newly_added, int code)
{
    if (ctx != NULL && *ctx != NULL) {
        if (newly_added) {
            (void)CertDeleteCertificateFromStore(*ctx);
        } else {
            CertFreeCertificateContext(*ctx);
        }
        *ctx = NULL;
    }
    return code;
}

int archive_security_dir(const wchar_t *security_dir, const wchar_t *suffix)
{
    wchar_t parent[VTY_PATH_MAX];
    wchar_t target[VTY_PATH_MAX];
    wchar_t stamp[64];
    size_t len;
    const wchar_t *slash;

    if (!vty_path_exists(security_dir)) return 0;
    len = wcslen(security_dir);
    slash = wcsrchr(security_dir, L'\\');
    if (slash == NULL) return -1;
    if ((size_t)(slash - security_dir) >= VTY_PATH_MAX) return -1;
    memcpy(parent, security_dir, (size_t)(slash - security_dir));
    parent[slash - security_dir] = L'\0';
    if (swprintf_s(stamp, 64, L"%llu", (unsigned long long)vty_utc_now_100ns()) <
        0) {
        return -1;
    }
    if (swprintf_s(target, VTY_PATH_MAX, L"%ls\\%ls-%ls", parent, suffix, stamp) <
        0) {
        return -1;
    }
    (void)vty_acl_force_admin_full(security_dir);
    if (!MoveFileExW(security_dir, target, 0)) {
        return -1;
    }
    return 0;
}

int import_bundled_root_ca(const wchar_t *setup_dir,
                                  wchar_t root_sha[65],
                                  PCCERT_CONTEXT *added_ctx,
                                  int *newly_added)
{
    wchar_t cer_path[VTY_PATH_MAX];
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD size = 0;
    DWORD read = 0;
    uint8_t *data = NULL;
    uint8_t hash[VTY_HASH_BYTES];
    HCERTSTORE store = NULL;
    PCCERT_CONTEXT cert = NULL;
    PCCERT_CONTEXT existing = NULL;
    PCCERT_CONTEXT stored = NULL;
    int rc = -1;

    if (root_sha != NULL) root_sha[0] = L'\0';
    if (added_ctx != NULL) *added_ctx = NULL;
    if (newly_added != NULL) *newly_added = 0;
    if (vty_path_join(cer_path, VTY_PATH_MAX, setup_dir,
                      L"VerthysRootCA.cer") != 0) {
        return -1;
    }
    /* 公网 CA 签发时无需随包根证书；文件缺失按“已受信”处理。 */
    if (!vty_path_exists(cer_path)) return 0;

    file = CreateFileW(cer_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return -1;
    size = GetFileSize(file, NULL);
    if (size == 0 || size > 65536u) goto done;
    data = (uint8_t *)malloc(size);
    if (data == NULL) goto done;
    if (!ReadFile(file, data, size, &read, NULL) || read != size) goto done;
    if (vty_sha256(data, size, hash) != 0) goto done;
    if (root_sha != NULL) hash_to_hex(hash, root_sha);
    if (!root_ca_pin_matches(root_sha)) {
        setup_print(L"[setup] bundled root CA fingerprint mismatch\n");
        goto done;
    }

    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                          CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");
    if (store == NULL) goto done;
    cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        data, size);
    if (cert == NULL) goto done;

    existing = CertFindCertificateInStore(
        store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_EXISTING,
        cert, NULL);
    if (existing != NULL) {
        CertFreeCertificateContext(existing);
        existing = NULL;
        rc = 0;
        goto done;
    }
    if (!CertAddCertificateContextToStore(store, cert, CERT_STORE_ADD_NEW,
                                          &stored)) {
        existing = CertFindCertificateInStore(
            store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_EXISTING, cert, NULL);
        if (existing == NULL) goto done;
        CertFreeCertificateContext(existing);
        existing = NULL;
        stored = NULL;
        rc = 0;
        goto done;
    }
    if (added_ctx != NULL) *added_ctx = stored;
    if (newly_added != NULL) *newly_added = 1;
    stored = NULL;
    rc = 0;

done:
    if (stored != NULL) CertFreeCertificateContext(stored);
    if (cert != NULL) CertFreeCertificateContext(cert);
    if (store != NULL) CertCloseStore(store, 0);
    if (data != NULL) {
        vty_secure_zero(data, size);
        free(data);
    }
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return rc;
}
