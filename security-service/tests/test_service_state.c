/*
 * test_service_state.c — 启动引导：首次初始化 / 缺失 / 篡改 / 密钥修复
 *
 * 全部使用 HKCU 测试键与临时状态目录，不触碰真实 %ProgramData%\Verthys。
 */
#include "test_common.h"
#include "service_state.h"
#include "service_util.h"

#include <stdio.h>
#include <string.h>

static wchar_t g_dir[VTY_PATH_MAX];
static wchar_t g_root[VTY_REGISTRY_TEXT_MAX];

static int prepare(void)
{
    if (test_make_temp_dir(g_dir, VTY_PATH_MAX) != 0) return -1;
    if (swprintf_s(g_root, VTY_REGISTRY_TEXT_MAX,
                   L"Software\\VerthysTest\\svc-unit-%lu-%llu",
                   (unsigned long)GetCurrentProcessId(),
                   (unsigned long long)GetTickCount64()) < 0) {
        return -1;
    }
    return 0;
}

static void fill_cfg(VtyServiceRuntimeConfig *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    (void)vty_wide_copy(cfg->pipe_name, 128,
                        L"\\\\.\\pipe\\VerthysSecuritySvcTestUnit");
    (void)vty_wide_copy(cfg->registry_root, VTY_REGISTRY_TEXT_MAX, g_root);
    (void)vty_wide_copy(cfg->test_state_dir, VTY_PATH_MAX, g_dir);
    cfg->test_mode = 1;
}

static void cleanup(VtyServiceContext *ctx)
{
    vty_service_context_cleanup(ctx);
    RegDeleteTreeW(HKEY_CURRENT_USER, g_root);
    test_remove_tree(g_dir);
}

static int delete_reg_value(const wchar_t *name)
{
    HKEY key = NULL;
    LONG rc;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, g_root, 0,
                      KEY_READ | KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
        return -1;
    }
    rc = RegDeleteValueW(key, name);
    RegCloseKey(key);
    return (rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND) ? 0 : -1;
}

static int read_anchors(VtyServiceAnchors *anchors)
{
    VtyRegistryLocation location;
    HKEY key = NULL;
    int rc;

    vty_service_registry_location_test(&location, g_root);
    if (vty_service_registry_open(&location, 0, &key) != 0) return -1;
    rc = vty_service_anchors_read(key, anchors);
    RegCloseKey(key);
    return rc;
}

static void test_first_init_and_reload(void)
{
    VtyServiceContext ctx;
    VtyServiceContext ctx2;
    VtyServiceRuntimeConfig cfg;
    VtyServiceAnchors anchors;
    VtyMachineStateFields fields;
    VtyMachineDecision decision;
    uint8_t sid[32];
    wchar_t path[VTY_PATH_MAX];
    size_t i;

    printf("[ STATE ] first initialization and reload\n");
    if (prepare() != 0) {
        CHECK(0);
        return;
    }
    fill_cfg(&cfg);
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_OK);
    CHECK(ctx.signing_key != NULL);
    CHECK(ctx.signing_pub_len > 0);
    CHECK_EQ_INT(vty_service_context_is_fail_closed(&ctx), 0);
    CHECK_EQ_INT(read_anchors(&anchors), 0);
    CHECK_EQ_INT(anchors.state_initialized_present, 1);
    CHECK_EQ_U64(anchors.state_initialized, 1u);
    CHECK_EQ_INT(anchors.pubkey_present, 1);
    CHECK_EQ_INT(anchors.protocol_present, 1);
    CHECK_EQ_U64(anchors.protocol, VTY_SVC_PROTOCOL_VERSION);

    CHECK_EQ_INT(vty_path_join(path, VTY_PATH_MAX, g_dir,
                               VTY_MS_STATE_FILE_NAME),
                 0);
    CHECK(vty_path_exists(path));
    CHECK_EQ_INT(vty_path_join(path, VTY_PATH_MAX, g_dir,
                               VTY_MS_KEY_FILE_NAME),
                 0);
    CHECK(vty_path_exists(path));
    CHECK_EQ_INT(vty_path_join(path, VTY_PATH_MAX, g_dir,
                               VTY_SIGNING_KEY_FILE_NAME),
                 0);
    CHECK(vty_path_exists(path));

    for (i = 0; i < 32u; i++) sid[i] = (uint8_t)(i + 1u);
    CHECK_EQ_INT(vty_machine_state_record_failure(&ctx.state, sid, &decision),
                 0);
    CHECK_EQ_INT(decision.status, VTY_SVC_STATUS_OK);
    vty_machine_state_snapshot(&ctx.state, &fields);
    CHECK_EQ_U64(fields.tokens, VTY_MS_CAPACITY - 1u);
    vty_service_context_cleanup(&ctx);

    memset(&ctx2, 0, sizeof(ctx2));
    CHECK_EQ_INT((int)vty_service_context_init(&ctx2, &cfg),
                 (int)VTY_SERVICE_INIT_OK);
    vty_machine_state_snapshot(&ctx2.state, &fields);
    CHECK_EQ_U64(fields.tokens, VTY_MS_CAPACITY - 1u);
    CHECK_EQ_INT(read_anchors(&anchors), 0);
    CHECK_EQ_INT(anchors.pubkey_present, 1);
    CHECK_EQ_U64(anchors.pubkey_len, ctx2.signing_pub_len);
    CHECK(memcmp(anchors.pubkey, ctx2.signing_pub_blob,
                 ctx2.signing_pub_len) == 0);
    cleanup(&ctx2);
}

static void test_missing_state_file(void)
{
    VtyServiceContext ctx;
    VtyServiceRuntimeConfig cfg;
    wchar_t path[VTY_PATH_MAX];

    printf("[ STATE ] anchor with missing state file -> fail-closed\n");
    if (prepare() != 0) {
        CHECK(0);
        return;
    }
    fill_cfg(&cfg);
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_OK);
    vty_service_context_cleanup(&ctx);
    CHECK_EQ_INT(vty_path_join(path, VTY_PATH_MAX, g_dir,
                               VTY_MS_STATE_FILE_NAME),
                 0);
    CHECK(DeleteFileW(path));
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_FAIL_CLOSED);
    CHECK_EQ_INT(vty_service_context_is_fail_closed(&ctx), 1);
    CHECK(ctx.signing_key != NULL);
    cleanup(&ctx);
}

static void test_missing_hmac_key(void)
{
    VtyServiceContext ctx;
    VtyServiceRuntimeConfig cfg;
    wchar_t path[VTY_PATH_MAX];

    printf("[ STATE ] anchor with missing HMAC key -> fail-closed\n");
    if (prepare() != 0) {
        CHECK(0);
        return;
    }
    fill_cfg(&cfg);
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_OK);
    vty_service_context_cleanup(&ctx);
    CHECK_EQ_INT(vty_path_join(path, VTY_PATH_MAX, g_dir,
                               VTY_MS_KEY_FILE_NAME),
                 0);
    CHECK(DeleteFileW(path));
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_FAIL_CLOSED);
    CHECK_EQ_INT(vty_service_context_is_fail_closed(&ctx), 1);
    cleanup(&ctx);
}

static void test_tampered_state(void)
{
    VtyServiceContext ctx;
    VtyServiceRuntimeConfig cfg;
    wchar_t path[VTY_PATH_MAX];
    uint8_t blob[96];

    printf("[ STATE ] tampered state -> fail-closed\n");
    if (prepare() != 0) {
        CHECK(0);
        return;
    }
    fill_cfg(&cfg);
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_OK);
    vty_service_context_cleanup(&ctx);
    CHECK_EQ_INT(vty_path_join(path, VTY_PATH_MAX, g_dir,
                               VTY_MS_STATE_FILE_NAME),
                 0);
    CHECK_EQ_INT(test_read_file(path, blob, sizeof(blob)),
                 (int)sizeof(blob));
    blob[70] ^= 0x01u;
    CHECK_EQ_INT(vty_write_file_atomic(g_dir, VTY_MS_STATE_FILE_NAME, blob,
                                       sizeof(blob)),
                 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_FAIL_CLOSED);
    CHECK_EQ_INT(vty_service_context_is_fail_closed(&ctx), 1);
    cleanup(&ctx);
}

static void test_missing_anchor_with_files(void)
{
    VtyServiceContext ctx;
    VtyServiceRuntimeConfig cfg;

    printf("[ STATE ] files without anchor -> fail-closed\n");
    if (prepare() != 0) {
        CHECK(0);
        return;
    }
    fill_cfg(&cfg);
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_OK);
    vty_service_context_cleanup(&ctx);
    CHECK_EQ_INT(delete_reg_value(VTY_SVC_REG_STATE_INITIALIZED), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_FAIL_CLOSED);
    CHECK_EQ_INT(vty_service_context_is_fail_closed(&ctx), 1);
    cleanup(&ctx);
}

static void test_repair_keys(void)
{
    VtyServiceContext ctx;
    VtyServiceRuntimeConfig cfg;
    VtyServiceAnchors anchors;
    VtyMachineStateFields fields;
    wchar_t path[VTY_PATH_MAX];

    printf("[ STATE ] repair keys when private and public are both missing\n");
    if (prepare() != 0) {
        CHECK(0);
        return;
    }
    fill_cfg(&cfg);
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_OK);
    vty_machine_state_snapshot(&ctx.state, &fields);
    vty_service_context_cleanup(&ctx);
    CHECK_EQ_INT(vty_path_join(path, VTY_PATH_MAX, g_dir,
                               VTY_SIGNING_KEY_FILE_NAME),
                 0);
    CHECK(DeleteFileW(path));
    CHECK_EQ_INT(delete_reg_value(VTY_SVC_REG_SERVER_PUBKEY), 0);
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_OK);
    CHECK(ctx.signing_key != NULL);
    CHECK_EQ_INT(read_anchors(&anchors), 0);
    CHECK_EQ_INT(anchors.pubkey_present, 1);
    CHECK_EQ_U64(anchors.pubkey_len, ctx.signing_pub_len);
    vty_machine_state_snapshot(&ctx.state, &fields);
    CHECK_EQ_U64(fields.tokens, VTY_MS_CAPACITY);
    cleanup(&ctx);
}

static void test_missing_private_with_public(void)
{
    VtyServiceContext ctx;
    VtyServiceRuntimeConfig cfg;
    wchar_t path[VTY_PATH_MAX];

    printf("[ STATE ] private key missing while public exists -> refuse\n");
    if (prepare() != 0) {
        CHECK(0);
        return;
    }
    fill_cfg(&cfg);
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_OK);
    vty_service_context_cleanup(&ctx);
    CHECK_EQ_INT(vty_path_join(path, VTY_PATH_MAX, g_dir,
                               VTY_SIGNING_KEY_FILE_NAME),
                 0);
    CHECK(DeleteFileW(path));
    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT((int)vty_service_context_init(&ctx, &cfg),
                 (int)VTY_SERVICE_INIT_REFUSE);
    CHECK(ctx.signing_key == NULL);
    cleanup(&ctx);
}

int test_service_state_run(void)
{
    test_first_init_and_reload();
    test_missing_state_file();
    test_missing_hmac_key();
    test_tampered_state();
    test_missing_anchor_with_files();
    test_repair_keys();
    test_missing_private_with_public();
    return g_test_failures;
}
