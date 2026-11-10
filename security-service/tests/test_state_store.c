/*
 * test_state_store.c — 状态 HMAC、原子写入与 schema 校验
 */
#include "test_common.h"
#include "machine_state.h"
#include "service_util.h"
#include "state_crypto.h"

#include <string.h>

static uint8_t g_key[32];
static wchar_t g_dir[VTY_PATH_MAX];

static int store_setup(void)
{
    size_t i;

    for (i = 0; i < 32u; i++) {
        g_key[i] = (uint8_t)(i * 11u + 0x5Au);
    }
    return test_make_temp_dir(g_dir, VTY_PATH_MAX);
}

static void store_teardown(void)
{
    test_remove_tree(g_dir);
}

static void write_state_blob(VtyMachineState *st, const uint8_t *payload64)
{
    uint8_t mac[32];
    uint8_t blob[96];

    CHECK_EQ_INT(vty_hmac_sha256(st->hmac_key, payload64, 64u, mac), 0);
    memcpy(blob, payload64, 64u);
    memcpy(blob + 64, mac, 32u);
    CHECK_EQ_INT(vty_write_file_atomic(st->dir, VTY_MS_STATE_FILE_NAME, blob,
                                       96u),
                 0);
    vty_secure_zero(mac, sizeof(mac));
}

static void build_payload(uint8_t payload[64], uint32_t magic,
                          uint16_t version, uint32_t capacity,
                          uint32_t tokens, uint64_t created,
                          uint64_t last_write)
{
    memset(payload, 0, 64u);
    vty_svc_put_u32le(payload + 0, magic);
    vty_svc_put_u16le(payload + 4, version);
    vty_svc_put_u16le(payload + 6, 0);
    vty_svc_put_u32le(payload + 8, capacity);
    vty_svc_put_u32le(payload + 12, tokens);
    vty_svc_put_u64le(payload + 16, created);
    vty_svc_put_u64le(payload + 48, created);
    vty_svc_put_u64le(payload + 56, last_write);
}

static void test_hmac_and_missing(void)
{
    VtyMachineState st;
    VtyMachineState st2;
    uint8_t key2[32];
    wchar_t path[VTY_PATH_MAX];
    uint8_t blob[96];
    long got;
    size_t i;

    printf("[ U7 ] state HMAC and missing-state fail-closed\n");
    if (store_setup() != 0) {
        CHECK(0);
        return;
    }
    CHECK_EQ_INT(vty_machine_state_init(&st, g_dir, g_key, 0), 0);
    CHECK_EQ_INT(vty_machine_state_create_new(&st), 0);
    CHECK(vty_machine_state_is_fail_closed(&st) == 0);

    if (vty_path_join(path, VTY_PATH_MAX, g_dir, VTY_MS_STATE_FILE_NAME) != 0) {
        CHECK(0);
        vty_machine_state_destroy(&st);
        store_teardown();
        return;
    }
    got = test_read_file(path, blob, sizeof(blob));
    CHECK_EQ_INT(got, (int)sizeof(blob));

    for (i = 0; i < 32u; i++) {
        key2[i] = (uint8_t)(g_key[i] ^ 0xFFu);
    }
    CHECK_EQ_INT(vty_machine_state_init(&st2, g_dir, key2, 0), 0);
    CHECK(vty_machine_state_load(&st2) != 0);
    CHECK_EQ_INT(vty_machine_state_is_fail_closed(&st2), 1);
    vty_machine_state_destroy(&st2);

    blob[64] ^= 0x01u;
    CHECK_EQ_INT(vty_write_file_atomic(g_dir, VTY_MS_STATE_FILE_NAME, blob,
                                       sizeof(blob)),
                 0);
    CHECK_EQ_INT(vty_machine_state_init(&st2, g_dir, g_key, 0), 0);
    CHECK(vty_machine_state_load(&st2) != 0);
    CHECK_EQ_INT(vty_machine_state_is_fail_closed(&st2), 1);
    vty_machine_state_destroy(&st2);

    CHECK(DeleteFileW(path));
    CHECK_EQ_INT(vty_machine_state_init(&st2, g_dir, g_key, 0), 0);
    CHECK(vty_machine_state_load(&st2) != 0);
    CHECK_EQ_INT(vty_machine_state_is_fail_closed(&st2), 1);
    vty_machine_state_destroy(&st2);
    vty_machine_state_destroy(&st);
    store_teardown();
}

static void test_atomic_write(void)
{
    VtyMachineState st;
    wchar_t temp_path[VTY_PATH_MAX];
    uint8_t first[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t second[8] = {9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t readback[8];
    HANDLE stale;

    printf("[ U8 ] atomic write survives stale temp file\n");
    if (store_setup() != 0) {
        CHECK(0);
        return;
    }
    CHECK_EQ_INT(vty_machine_state_init(&st, g_dir, g_key, 0), 0);
    CHECK_EQ_INT(vty_write_file_atomic(g_dir, L"atomic.bin", first,
                                       sizeof(first)),
                 0);
    CHECK_EQ_INT(vty_path_join(temp_path, VTY_PATH_MAX, g_dir,
                               L"atomic.bin"),
                 0);
    CHECK_EQ_INT(test_read_file(temp_path, readback, sizeof(readback)),
                 (int)sizeof(readback));
    CHECK(memcmp(readback, first, sizeof(first)) == 0);

    memset(temp_path, 0, sizeof(temp_path));
    CHECK_EQ_INT(vty_path_join(temp_path, VTY_PATH_MAX, g_dir,
                               L"atomic.bin.tmp"),
                 0);
    stale = CreateFileW(temp_path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(stale != INVALID_HANDLE_VALUE);
    if (stale != INVALID_HANDLE_VALUE) {
        WriteFile(stale, "stale", 5u, NULL, NULL);
        CloseHandle(stale);
    }
    CHECK_EQ_INT(vty_write_file_atomic(g_dir, L"atomic.bin", second,
                                       sizeof(second)),
                 0);
    memset(readback, 0, sizeof(readback));
    CHECK_EQ_INT(vty_path_join(temp_path, VTY_PATH_MAX, g_dir,
                               L"atomic.bin"),
                 0);
    CHECK_EQ_INT(test_read_file(temp_path, readback, sizeof(readback)),
                 (int)sizeof(readback));
    CHECK(memcmp(readback, second, sizeof(second)) == 0);
    vty_machine_state_destroy(&st);
    store_teardown();
}

static void test_schema(void)
{
    VtyMachineState st;
    uint8_t payload[64];
    uint64_t now = vty_utc_now_100ns();

    printf("[ U11 ] state schema rejects incompatible layouts\n");
    if (store_setup() != 0) {
        CHECK(0);
        return;
    }
    CHECK_EQ_INT(vty_machine_state_init(&st, g_dir, g_key, 0), 0);

    build_payload(payload, VTY_MS_MAGIC, (uint16_t)VTY_MS_VERSION,
                  VTY_MS_CAPACITY + 1u, VTY_MS_CAPACITY, now, now);
    write_state_blob(&st, payload);
    CHECK(vty_machine_state_load(&st) != 0);

    vty_machine_state_destroy(&st);
    CHECK_EQ_INT(vty_machine_state_init(&st, g_dir, g_key, 0), 0);
    build_payload(payload, VTY_MS_MAGIC, (uint16_t)VTY_MS_VERSION + 1u,
                  VTY_MS_CAPACITY, VTY_MS_CAPACITY, now, now);
    write_state_blob(&st, payload);
    CHECK(vty_machine_state_load(&st) != 0);

    vty_machine_state_destroy(&st);
    CHECK_EQ_INT(vty_machine_state_init(&st, g_dir, g_key, 0), 0);
    build_payload(payload, VTY_MS_MAGIC, (uint16_t)VTY_MS_VERSION,
                  VTY_MS_CAPACITY, VTY_MS_CAPACITY + 1u, now, now);
    write_state_blob(&st, payload);
    CHECK(vty_machine_state_load(&st) != 0);

    vty_machine_state_destroy(&st);
    CHECK_EQ_INT(vty_machine_state_init(&st, g_dir, g_key, 0), 0);
    build_payload(payload, VTY_MS_MAGIC ^ 1u, (uint16_t)VTY_MS_VERSION,
                  VTY_MS_CAPACITY, 0u, now, now);
    write_state_blob(&st, payload);
    CHECK(vty_machine_state_load(&st) != 0);

    vty_machine_state_destroy(&st);
    store_teardown();
}

int test_state_store_run(void)
{
    test_hmac_and_missing();
    test_atomic_write();
    test_schema();
    return g_test_failures;
}
