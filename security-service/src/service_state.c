/*
 * service_state.c — 路径解析、目录加固、注册表锚点与启动引导
 *
 * 启动引导严格区分三类结果，任何“未知来源状态”都不会被静默采纳：
 *   - 首次运行（无锚点、无文件）才允许初始化；
 *   - 锚点存在但状态/密钥缺失或损坏 → 运行但 fail-closed；
 *   - ACL 放宽、重解析点、签名私钥丢失且公钥仍存在 → 拒绝启动。
 */
#include "service_state.h"
#include "state_crypto.h"

#include <stdio.h>
#include <string.h>

#ifndef VERTHYS_SERVICE_PUBLISHER_SHA256
#define VERTHYS_SERVICE_PUBLISHER_SHA256 ""
#endif

#define VTY_SERVICE_DUMMY_KEY_BYTES 32u

static void copy_ascii_to_wide(const char *src, wchar_t *dst, size_t cap)
{
    size_t i = 0;

    if (dst == NULL || cap == 0) return;
    if (src != NULL) {
        while (src[i] != '\0' && i + 1u < cap) {
            dst[i] = (wchar_t)src[i];
            i++;
        }
    }
    dst[i] = L'\0';
}

static int file_exists(const wchar_t *path)
{
    return vty_path_exists(path) && !vty_path_is_directory(path);
}

static int fill_security_paths(VtyServicePaths *paths)
{
    if (vty_path_join(paths->state_file, VTY_PATH_MAX, paths->security_dir,
                      VTY_MS_STATE_FILE_NAME) != 0 ||
        vty_path_join(paths->state_key_file, VTY_PATH_MAX,
                      paths->security_dir, VTY_MS_KEY_FILE_NAME) != 0 ||
        vty_path_join(paths->signing_key_file, VTY_PATH_MAX,
                      paths->security_dir, VTY_SIGNING_KEY_FILE_NAME) != 0 ||
        vty_path_join(paths->temp_file, VTY_PATH_MAX, paths->security_dir,
                      VTY_MS_TEMP_FILE_NAME) != 0) {
        return -1;
    }
    return 0;
}

int vty_service_paths_resolve(VtyServicePaths *paths)
{
    if (paths == NULL) return -1;
    memset(paths, 0, sizeof(*paths));
    if (vty_known_folder(&FOLDERID_ProgramData, paths->programdata,
                         VTY_PATH_MAX) != 0) {
        return -1;
    }
    if (vty_path_join(paths->parent_dir, VTY_PATH_MAX, paths->programdata,
                      L"Verthys") != 0) {
        return -1;
    }
    if (vty_path_join(paths->security_dir, VTY_PATH_MAX, paths->parent_dir,
                      L"Security") != 0) {
        return -1;
    }
    return fill_security_paths(paths);
}

/* 测试模式：把状态目录重定向到调用方指定的临时目录。 */
static int override_test_state_dir(VtyServicePaths *paths, const wchar_t *dir)
{
    if (paths == NULL || dir == NULL || dir[0] == L'\0') return -1;
    if (vty_wide_copy(paths->parent_dir, VTY_PATH_MAX, dir) != 0) return -1;
    if (vty_wide_copy(paths->security_dir, VTY_PATH_MAX, dir) != 0) return -1;
    return fill_security_paths(paths);
}

int vty_service_paths_resolve_install(VtyServicePaths *paths)
{
    if (paths == NULL) return -1;
    if (vty_known_folder(&FOLDERID_ProgramFiles, paths->program_files,
                         VTY_PATH_MAX) != 0) {
        return -1;
    }
    if (vty_path_join(paths->install_dir, VTY_PATH_MAX, paths->program_files,
                      VTY_SERVICE_INSTALL_SUFFIX) != 0) {
        return -1;
    }
    if (vty_path_join(paths->service_exe, VTY_PATH_MAX, paths->install_dir,
                      VTY_SERVICE_EXE_NAME) != 0) {
        return -1;
    }
    return 0;
}

static int ensure_dir(const wchar_t *path, VtyAclProfile profile,
                      int test_mode)
{
    if (path == NULL) return -1;
    if (!CreateDirectoryW(path, NULL) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        return -1;
    }
    if (!vty_path_is_directory(path) || !vty_path_has_reparse(path, 0)) {
        return -1;
    }
    if (!test_mode && vty_acl_apply_path(path, profile) != 0) {
        return -1;
    }
    return 0;
}

int vty_service_paths_ensure_dirs(const VtyServicePaths *paths, int test_mode)
{
    if (paths == NULL) return -1;
    if (ensure_dir(paths->parent_dir, VTY_ACL_PROFILE_PARENT, test_mode) != 0) {
        return -1;
    }
    if (ensure_dir(paths->security_dir, VTY_ACL_PROFILE_SECURITY_DIR,
                   test_mode) != 0) {
        return -1;
    }
    return 0;
}

int vty_service_paths_verify_dirs(const VtyServicePaths *paths, int test_mode)
{
    if (paths == NULL) return -1;
    if (!vty_path_is_directory(paths->parent_dir) ||
        !vty_path_has_reparse(paths->parent_dir, 0) ||
        !vty_path_is_directory(paths->security_dir) ||
        !vty_path_has_reparse(paths->security_dir, 0)) {
        return -1;
    }
    if (!test_mode) {
        if (vty_acl_verify_path(paths->parent_dir,
                                VTY_ACL_PROFILE_PARENT) == 0) {
            return -1;
        }
        if (vty_acl_verify_path(paths->security_dir,
                                VTY_ACL_PROFILE_SECURITY_DIR) == 0) {
            return -1;
        }
    }
    return 0;
}

int vty_service_paths_harden_files(const VtyServicePaths *paths, int test_mode)
{
    const wchar_t *files[3];
    size_t i;

    if (paths == NULL) return -1;
    if (test_mode) return 0;
    files[0] = paths->state_file;
    files[1] = paths->state_key_file;
    files[2] = paths->signing_key_file;
    for (i = 0; i < 3u; i++) {
        if (!file_exists(files[i])) continue;
        if (vty_acl_apply_path(files[i], VTY_ACL_PROFILE_STATE_FILE) != 0) {
            return -1;
        }
    }
    if (file_exists(paths->temp_file)) {
        (void)DeleteFileW(paths->temp_file);
    }
    return 0;
}

void vty_service_registry_location_production(VtyRegistryLocation *location)
{
    if (location == NULL) return;
    memset(location, 0, sizeof(*location));
    location->hive = HKEY_LOCAL_MACHINE;
    (void)vty_wide_copy(location->root, VTY_REGISTRY_TEXT_MAX,
                        VTY_SVC_REGISTRY_KEY);
    location->view = KEY_WOW64_64KEY;
}

void vty_service_registry_location_test(VtyRegistryLocation *location,
                                        const wchar_t *root)
{
    if (location == NULL) return;
    memset(location, 0, sizeof(*location));
    location->hive = HKEY_CURRENT_USER;
    if (root != NULL && root[0] != L'\0') {
        (void)vty_wide_copy(location->root, VTY_REGISTRY_TEXT_MAX, root);
    } else {
        (void)vty_wide_copy(location->root, VTY_REGISTRY_TEXT_MAX,
                            L"Software\\VerthysTest\\SecurityService");
    }
    location->view = 0;
}

int vty_service_registry_open(const VtyRegistryLocation *location, int create,
                              PHKEY key_out)
{
    HKEY key = NULL;
    LONG rc;
    DWORD disposition = 0;

    if (location == NULL || key_out == NULL || location->root[0] == L'\0') {
        return -1;
    }
    *key_out = NULL;
    if (create) {
        rc = RegCreateKeyExW(location->hive, location->root, 0, NULL,
                             REG_OPTION_NON_VOLATILE,
                             KEY_ALL_ACCESS | location->view, NULL, &key,
                             &disposition);
    } else {
        rc = RegOpenKeyExW(location->hive, location->root, 0,
                           KEY_ALL_ACCESS | location->view, &key);
    }
    if (rc != ERROR_SUCCESS) return -1;
    *key_out = key;
    return 0;
}

int vty_service_registry_harden(HKEY key)
{
    if (key == NULL) return -1;
    return vty_acl_apply_registry(key, VTY_ACL_PROFILE_REGISTRY);
}

int vty_service_anchors_read(HKEY key, VtyServiceAnchors *anchors)
{
    DWORD value = 0;
    uint64_t qvalue = 0;
    DWORD pub_len = 0;

    if (key == NULL || anchors == NULL) return -1;
    memset(anchors, 0, sizeof(*anchors));
    if (vty_registry_read_dword(key, VTY_SVC_REG_INSTALLED, &value) == 0) {
        anchors->installed_present = 1;
        anchors->installed = value;
    }
    if (vty_registry_read_dword(key, VTY_SVC_REG_STATE_INITIALIZED, &value) == 0) {
        anchors->state_initialized_present = 1;
        anchors->state_initialized = value;
    }
    if (vty_registry_read_dword(key, VTY_SVC_REG_STATE_GENERATION, &value) == 0) {
        anchors->generation_present = 1;
        anchors->generation = value;
    }
    if (vty_registry_read_dword(key, VTY_SVC_REG_PROTOCOL_VERSION, &value) == 0) {
        anchors->protocol_present = 1;
        anchors->protocol = value;
    }
    if (vty_registry_read_qword(key, VTY_SVC_REG_STATE_CREATED, &qvalue) == 0) {
        anchors->created_present = 1;
        anchors->created_utc = qvalue;
    }
    pub_len = VTY_ECC_BLOB_MAX;
    if (vty_registry_read_binary(key, VTY_SVC_REG_SERVER_PUBKEY, anchors->pubkey,
                                 VTY_ECC_BLOB_MAX, &pub_len) == 0 &&
        pub_len > 0) {
        anchors->pubkey_present = 1;
        anchors->pubkey_len = pub_len;
    }
    return 0;
}

int vty_service_write_pubkey(HKEY key, const uint8_t *blob, DWORD len)
{
    if (key == NULL || blob == NULL || len == 0 || len > VTY_ECC_BLOB_MAX) {
        return -1;
    }
    return vty_registry_write_binary(key, VTY_SVC_REG_SERVER_PUBKEY, blob, len);
}

int vty_service_write_initial_anchors(HKEY key, const uint8_t *pubkey,
                                      DWORD pubkey_len, uint64_t created_utc)
{
    if (key == NULL || pubkey == NULL || pubkey_len == 0) return -1;
    if (vty_registry_write_dword(key, VTY_SVC_REG_STATE_GENERATION,
                                 VTY_STATE_GENERATION_CURRENT) != 0) {
        return -1;
    }
    if (vty_registry_write_qword(key, VTY_SVC_REG_STATE_CREATED, created_utc) !=
        0) {
        return -1;
    }
    if (vty_registry_write_dword(key, VTY_SVC_REG_PROTOCOL_VERSION,
                                 VTY_SVC_PROTOCOL_VERSION) != 0) {
        return -1;
    }
    if (vty_service_write_pubkey(key, pubkey, pubkey_len) != 0) return -1;
    /* 锚点最后写：其它值全部落盘后才声明“状态已初始化”。 */
    return vty_registry_write_dword(key, VTY_SVC_REG_STATE_INITIALIZED, 1u);
}

void vty_service_runtime_config_production(VtyServiceRuntimeConfig *cfg)
{
    if (cfg == NULL) return;
    memset(cfg, 0, sizeof(*cfg));
    (void)vty_wide_copy(cfg->pipe_name, 128, VTY_SVC_PIPE_NAME);
    (void)vty_wide_copy(cfg->registry_root, VTY_REGISTRY_TEXT_MAX,
                        VTY_SVC_REGISTRY_KEY);
    copy_ascii_to_wide(VERTHYS_SERVICE_PUBLISHER_SHA256, cfg->publisher_sha256,
                       65u);
}

static void fill_dummy_key(uint8_t key[32])
{
    size_t i;

    for (i = 0; i < 32u; i++) {
        key[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }
}

/* 初始化机器状态结构并以 fail-closed 标记运行（用于状态不可判定场景）。 */
static void init_fail_closed_state(VtyServiceContext *ctx)
{
    uint8_t dummy[32];

    fill_dummy_key(dummy);
    if (vty_machine_state_init(&ctx->state, ctx->paths.security_dir, dummy,
                               1) == 0) {
        InterlockedExchange(&ctx->state.fail_closed, 1);
    }
    vty_secure_zero(dummy, sizeof(dummy));
}

static int load_machine_state(VtyServiceContext *ctx)
{
    uint8_t key[32];

    if (!file_exists(ctx->paths.state_key_file)) {
        vty_event_log(EVENTLOG_ERROR_TYPE, 3001,
                      L"state HMAC key missing; fail-closed");
        return -1;
    }
    if (vty_read_file_exact(ctx->paths.state_key_file, key, 32u, 32u) != 0) {
        vty_event_log(EVENTLOG_ERROR_TYPE, 3001,
                      L"state HMAC key unreadable; fail-closed");
        return -1;
    }
    if (vty_machine_state_init(&ctx->state, ctx->paths.security_dir, key,
                               1) != 0) {
        vty_secure_zero(key, sizeof(key));
        return -1;
    }
    vty_secure_zero(key, sizeof(key));
    if (vty_machine_state_load(&ctx->state) != 0) {
        return -1;
    }
    return 0;
}

static int import_signing_key(VtyServiceContext *ctx, const uint8_t *priv,
                              DWORD priv_len)
{
    DWORD pub_len = 0;

    if (vty_ecc_load_private(priv, priv_len, &ctx->signing_key) != 0) {
        return -1;
    }
    if (vty_ecc_public_from_private(priv, priv_len, ctx->signing_pub_blob,
                                    &pub_len, VTY_ECC_BLOB_MAX) != 0) {
        return -1;
    }
    ctx->signing_pub_len = pub_len;
    return 0;
}

static int generate_signing_key(VtyServiceContext *ctx, HKEY registry)
{
    uint8_t priv[VTY_ECC_BLOB_MAX];
    uint8_t pub[VTY_ECC_BLOB_MAX];
    DWORD priv_len = 0;
    DWORD pub_len = 0;
    int rc = -1;

    if (vty_ecc_generate_keypair(priv, &priv_len, VTY_ECC_BLOB_MAX, pub,
                                 &pub_len, VTY_ECC_BLOB_MAX) != 0) {
        goto done;
    }
    if (vty_write_file_atomic(ctx->paths.security_dir,
                              VTY_SIGNING_KEY_FILE_NAME, priv, priv_len) != 0) {
        goto done;
    }
    if (vty_service_write_pubkey(registry, pub, pub_len) != 0) goto done;
    if (import_signing_key(ctx, priv, priv_len) != 0) goto done;
    rc = 0;

done:
    vty_secure_zero(priv, sizeof(priv));
    if (rc != 0) {
        vty_ecc_free_key(&ctx->signing_key);
        ctx->signing_pub_len = 0;
    }
    return rc;
}

/*
 * 加载签名私钥：
 *   - 私钥存在：导入并派生公钥；注册表公钥存在时必须逐字节一致。
 *   - 私钥缺失但公钥存在：拒绝启动（需管理员 /repair-keys）。
 *   - 私钥与公钥都缺失：生成新密钥对并写回公钥（状态不受影响）。
 */
static int load_signing_key(VtyServiceContext *ctx, HKEY registry,
                            const VtyServiceAnchors *anchors)
{
    uint8_t priv[VTY_ECC_BLOB_MAX];
    DWORD priv_len = 0;

    if (file_exists(ctx->paths.signing_key_file)) {
        if (vty_read_file_any(ctx->paths.signing_key_file, priv, sizeof(priv),
                              &priv_len) != 0) {
            vty_event_log(EVENTLOG_ERROR_TYPE, 3003,
                          L"signing key unreadable; refuse start");
            return -1;
        }
        if (import_signing_key(ctx, priv, priv_len) != 0) {
            vty_secure_zero(priv, sizeof(priv));
            vty_event_log(EVENTLOG_ERROR_TYPE, 3003,
                          L"signing key import failed; refuse start");
            return -1;
        }
        vty_secure_zero(priv, sizeof(priv));
        if (anchors->pubkey_present) {
            if (ctx->signing_pub_len != anchors->pubkey_len ||
                memcmp(ctx->signing_pub_blob, anchors->pubkey,
                       anchors->pubkey_len) != 0) {
                vty_event_log(EVENTLOG_ERROR_TYPE, 3003,
                              L"signing key does not match pinned public key");
                vty_ecc_free_key(&ctx->signing_key);
                ctx->signing_pub_len = 0;
                return -1;
            }
        } else if (vty_service_write_pubkey(registry, ctx->signing_pub_blob,
                                            ctx->signing_pub_len) != 0) {
            return -1;
        }
        return 0;
    }

    if (anchors->pubkey_present) {
        vty_event_log(EVENTLOG_ERROR_TYPE, 3003,
                      L"signing private key missing while public key exists");
        return -1;
    }
    return generate_signing_key(ctx, registry);
}

static int first_initialize(VtyServiceContext *ctx, HKEY registry)
{
    uint8_t key[32];
    uint64_t now = vty_utc_now_100ns();
    int rc = -1;

    if (vty_random_bytes(key, sizeof(key)) != 0) return -1;
    if (vty_write_file_atomic(ctx->paths.security_dir, VTY_MS_KEY_FILE_NAME,
                              key, (DWORD)sizeof(key)) != 0) {
        vty_secure_zero(key, sizeof(key));
        return -1;
    }
    if (vty_machine_state_init(&ctx->state, ctx->paths.security_dir, key,
                               1) != 0) {
        vty_secure_zero(key, sizeof(key));
        return -1;
    }
    vty_secure_zero(key, sizeof(key));
    if (vty_machine_state_create_new(&ctx->state) != 0) {
        return -1;
    }
    if (generate_signing_key(ctx, registry) != 0) {
        return -1;
    }
    if (vty_service_write_initial_anchors(registry, ctx->signing_pub_blob,
                                          ctx->signing_pub_len, now) != 0) {
        return -1;
    }
    vty_event_log(EVENTLOG_INFORMATION_TYPE, 1002,
                  L"machine state initialized");
    rc = 0;
    return rc;
}

VtyServiceInitResult vty_service_context_init(VtyServiceContext *ctx,
                                              const VtyServiceRuntimeConfig *cfg)
{
    HKEY registry = NULL;
    int anchor_state = 0;
    int any_file = 0;
    int fail_closed = 0;
    VtyServiceInitResult result = VTY_SERVICE_INIT_REFUSE;

    if (ctx == NULL || cfg == NULL) return VTY_SERVICE_INIT_REFUSE;
    memset(ctx, 0, sizeof(*ctx));
    ctx->cfg = *cfg;
    ctx->fail_closed = 1;
    ctx->stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ctx->stop_event == NULL) return VTY_SERVICE_INIT_REFUSE;

    if (vty_service_paths_resolve(&ctx->paths) != 0) goto done;
    if (cfg->test_mode && cfg->test_state_dir[0] != L'\0') {
        if (override_test_state_dir(&ctx->paths, cfg->test_state_dir) != 0) {
            goto done;
        }
    }
    if (vty_service_paths_ensure_dirs(&ctx->paths, cfg->test_mode) != 0) {
        goto done;
    }
    if (vty_service_paths_verify_dirs(&ctx->paths, cfg->test_mode) != 0) {
        goto done;
    }

    if (cfg->test_mode) {
        VtyRegistryLocation test_location;
        vty_service_registry_location_test(&test_location,
                                           cfg->registry_root);
        ctx->registry = test_location;
    } else {
        vty_service_registry_location_production(&ctx->registry);
    }
    if (vty_service_registry_open(&ctx->registry, 1, &registry) != 0) goto done;
    if (!cfg->test_mode && vty_service_registry_harden(registry) != 0) {
        goto done;
    }
    if (vty_service_anchors_read(registry, &ctx->anchors) != 0) goto done;

    anchor_state = ctx->anchors.state_initialized_present &&
                   ctx->anchors.state_initialized == 1u;
    any_file = file_exists(ctx->paths.state_file) ||
               file_exists(ctx->paths.state_key_file) ||
               file_exists(ctx->paths.signing_key_file);

    if (vty_service_paths_harden_files(&ctx->paths, cfg->test_mode) != 0) {
        goto done;
    }

    if (anchor_state) {
        if (!ctx->anchors.generation_present ||
            ctx->anchors.generation != VTY_STATE_GENERATION_CURRENT) {
            vty_event_log(EVENTLOG_ERROR_TYPE, 3001,
                          L"state generation mismatch; fail-closed");
            fail_closed = 1;
        }
        if (!ctx->anchors.protocol_present ||
            ctx->anchors.protocol != VTY_SVC_PROTOCOL_VERSION) {
            vty_event_log(EVENTLOG_ERROR_TYPE, 3001,
                          L"protocol version mismatch; fail-closed");
            fail_closed = 1;
        }
        if (!ctx->anchors.created_present) {
            vty_event_log(EVENTLOG_ERROR_TYPE, 3001,
                          L"state creation anchor missing; fail-closed");
            fail_closed = 1;
        }
        if (load_signing_key(ctx, registry, &ctx->anchors) != 0) goto done;
        if (load_machine_state(ctx) != 0) {
            init_fail_closed_state(ctx);
            fail_closed = 1;
        }
#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
        vty_machine_state_set_test_offsets(&ctx->state,
                                           cfg->test_utc_offset_100ns,
                                           cfg->test_ms_offset);
        if (cfg->test_ignore_user_quota) {
            vty_machine_state_set_test_ignore_user_quota(&ctx->state, 1);
        }
#endif
        if (fail_closed) {
            InterlockedExchange(&ctx->fail_closed, 1);
            result = VTY_SERVICE_INIT_FAIL_CLOSED;
        } else {
            InterlockedExchange(&ctx->fail_closed, 0);
            result = VTY_SERVICE_INIT_OK;
        }
        goto done;
    }

    if (any_file) {
        /* 无锚点但存在文件：不采纳未知来源状态，也不自动重建。 */
        vty_event_log(EVENTLOG_ERROR_TYPE, 3001,
                      L"state files exist without initialization anchor");
        if (load_signing_key(ctx, registry, &ctx->anchors) != 0) goto done;
        init_fail_closed_state(ctx);
        InterlockedExchange(&ctx->fail_closed, 1);
        result = VTY_SERVICE_INIT_FAIL_CLOSED;
        goto done;
    }

    /* 首次运行：只有此时允许生成密钥与初始状态。 */
    if (first_initialize(ctx, registry) != 0) goto done;
#if defined(VERTHYS_SERVICE_TEST_HOOKS) && VERTHYS_SERVICE_TEST_HOOKS
    vty_machine_state_set_test_offsets(&ctx->state, cfg->test_utc_offset_100ns,
                                       cfg->test_ms_offset);
    if (cfg->test_ignore_user_quota) {
        vty_machine_state_set_test_ignore_user_quota(&ctx->state, 1);
    }
#endif
    InterlockedExchange(&ctx->fail_closed, 0);
    result = VTY_SERVICE_INIT_OK;

done:
    if (registry != NULL) {
        RegCloseKey(registry);
    }
    if (result == VTY_SERVICE_INIT_REFUSE) {
        vty_ecc_free_key(&ctx->signing_key);
        ctx->signing_pub_len = 0;
        InterlockedExchange(&ctx->fail_closed, 1);
    }
    return result;
}

void vty_service_context_cleanup(VtyServiceContext *ctx)
{
    if (ctx == NULL) return;
    vty_ecc_free_key(&ctx->signing_key);
    ctx->signing_pub_len = 0;
    vty_machine_state_destroy(&ctx->state);
    vty_secure_zero(ctx->signing_pub_blob, sizeof(ctx->signing_pub_blob));
    if (ctx->stop_event != NULL) {
        CloseHandle(ctx->stop_event);
        ctx->stop_event = NULL;
    }
}

int vty_service_context_is_fail_closed(VtyServiceContext *ctx)
{
    if (ctx == NULL) return 1;
    if (InterlockedCompareExchange(&ctx->fail_closed, 0, 0) != 0) return 1;
    return vty_machine_state_is_fail_closed(&ctx->state);
}
