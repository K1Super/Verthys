/*
 * vty_g0a2_crash.c — G0-A2 崩溃注入宿主（仅隔离原型 + 测试钩子构建）
 *
 * 在真实容器上执行批量导入会话，并在指定阶段 TerminateProcess：
 *   import : Begin + 3 次新增后直接退出（锚点仍停在 Begin 前的代）
 *   limit  : 31 次推迟保存后，第 32 次触发上限提交，在“新键已建、
 *            状态未写”处崩溃（VTY_RB_CRASH_AFTER_NEW_KEY）
 *   commit : Begin + 2 次新增后调用 BulkImportCommit，在“状态已写、
 *            旧键未退役”处崩溃（VTY_RB_CRASH_AFTER_STORE）
 *
 * 用法：vty_g0a2_crash <container> <state_path> <import|limit|commit>
 * 退出码：0xC0DE0002 / 0xC0DE0003 崩溃点；0xC0DE0011 导入中主动退出；
 *         10 参数非法；11 回滚状态路径注入失败；12 回滚初始化失败；
 *         13 容器创建失败；14 会话 Begin 失败；15 写入失败；
 *         16 UUID 文件写入失败；20+rc 未触发崩溃的失败。
 */
#include "verthys.h"
#include "verthys_internal.h"
#include "vty_keymanager.h"
#include "vty_rollback.h"
#include "vty_types.h"

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define G0A2_HOST_PW "g0a2-pw"

static int host_add(VerthysHandle h, unsigned i)
{
    VerthysRecord r;
    uint64_t id = 0;
    char name[32];

    snprintf(name, sizeof(name), "h%u", i);
    memset(&r, 0, sizeof(r));
    r.type = VERTHYS_RECORD_PHOTO;
    r.name = name;
    r.name_len = strlen(name);
    r.data = (const uint8_t *)"x";
    r.data_len = 1u;
    return Verthys_AddRecord(h, &r, &id);
}

static int host_write_uuid(const char *container,
                           const uint8_t uuid[VTY_UUID_BYTES])
{
    static const char digits[] = "0123456789abcdef";
    char path[MAX_PATH];
    char hex[VTY_UUID_BYTES * 2u + 1u];
    FILE *f;
    int i;

    if (sprintf_s(path, sizeof(path), "%s.uuid", container) < 0) return 1;
    for (i = 0; i < (int)VTY_UUID_BYTES; i++) {
        hex[i * 2] = digits[(uuid[i] >> 4) & 0x0fu];
        hex[i * 2 + 1] = digits[uuid[i] & 0x0fu];
    }
    hex[VTY_UUID_BYTES * 2u] = '\0';
    f = fopen(path, "wb");
    if (f == NULL) return 1;
    if (fwrite(hex, 1, VTY_UUID_BYTES * 2u, f) != VTY_UUID_BYTES * 2u) {
        fclose(f);
        return 1;
    }
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    VerthysHandle h = NULL;
    char recovery[128];
    unsigned i;
    int rc;

    if (argc != 4) return 10;
    if (vty_rollback_set_path_for_test(argv[2]) != VTY_OK) return 11;
    vty_rollback_set_enabled(1);
    if (vty_rollback_init() != VTY_OK) return 12;

    remove(argv[1]);
    memset(recovery, 0, sizeof(recovery));
    if (Verthys_Init(&h) != VERTHYS_OK) return 13;
    if (Verthys_V4Create(h, argv[1], G0A2_HOST_PW, strlen(G0A2_HOST_PW),
                         recovery, sizeof(recovery)) != VERTHYS_OK) {
        return 13;
    }

    {
        struct VerthysContext *ctx = (struct VerthysContext *)h;
        if (ctx->vault == NULL ||
            host_write_uuid(argv[1], ctx->vault->header.vault_uuid) != 0) {
            return 16;
        }
    }

    if (Verthys_BulkImportBegin(h) != VERTHYS_OK) return 14;

    if (strcmp(argv[3], "import") == 0) {
        for (i = 0; i < 3u; i++) {
            if (host_add(h, i) != VERTHYS_OK) return 15;
        }
        /* 模拟导入进程被杀：不调用 Commit/Deinit（Deinit 会收口锚点），
         * 锚点保持 Begin 前的代。 */
        TerminateProcess(GetCurrentProcess(), 0xC0DE0011u);
    }

    if (strcmp(argv[3], "limit") == 0) {
        for (i = 0; i < VTY_ANCHOR_DEFER_MAX_GENS - 1u; i++) {
            if (host_add(h, i) != VERTHYS_OK) return 15;
        }
        vty_rollback_set_crash_point_for_test(VTY_RB_CRASH_AFTER_NEW_KEY);
        rc = host_add(h, i);
        return 20 + (rc & 0xFF);
    }

    if (strcmp(argv[3], "commit") == 0) {
        for (i = 0; i < 2u; i++) {
            if (host_add(h, i) != VERTHYS_OK) return 15;
        }
        vty_rollback_set_crash_point_for_test(VTY_RB_CRASH_AFTER_STORE);
        rc = Verthys_BulkImportCommit(h);
        return 20 + (rc & 0xFF);
    }

    return 10;
}
