/*
 * vty_mem_host.c — A8 内存零残留测试宿主
 *
 * 角色：
 *   hold  <vault>  从 stdin 读取口令，建库→保存→轮换→解锁，把密钥材料
 *                  （hex）回传给父进程用于转储扫描；收到 LOCK 后释放并清零
 *                  自身所有副本，收到 EXIT 退出。
 *   crash <vault>  同上解锁并回传密钥，收到 CRASH 后制造访问违例，供父进程
 *                  检查 WER/崩溃转储是否残留明文。
 *   dump  <pid> <file>  用 MiniDumpWriteDump 生成完整内存转储（不依赖 procdump）。
 *
 * 该工具与其它测试一样直接链接核心对象库（不走 DLL 边界），口令只经
 * stdin 传递，不进入命令行，避免 argv 中的明文让 A8-3 产生假阳性。
 */
#include "vty_keymanager_v4.h"
#include "vty_v4_types.h"
#include "vty_rollback.h"
#include "vty_util.h"

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_line(char *buf, size_t cap)
{
    size_t len;

    if (fgets(buf, (int)cap, stdin) == NULL) return 0;
    len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }
    return 1;
}

static wchar_t *to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w;

    if (n <= 0) return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (w == NULL) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

static void hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char *digits = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 0x0fu];
    }
    out[len * 2] = '\0';
}

static char *secret_line(const char *label, const uint8_t *key)
{
    char hex[VTY_KEY_BYTES * 2 + 1];
    size_t need;

    hex_encode(key, VTY_KEY_BYTES, hex);
    need = strlen("SECRET ") + strlen(label) + 1 + strlen(hex) + 1;
    {
        char *line = (char *)malloc(need);
        if (line == NULL) return NULL;
        sprintf_s(line, need, "SECRET %s %s", label, hex);
        return line;
    }
}

static void emit_secrets(VtyVault *v)
{
    char *kc = secret_line("kc", v->kc);
    uint32_t i;

    if (kc != NULL) { puts(kc); }
    for (i = 0; i < v->keyring.count; i++) {
        if (v->keyring.entries[i].kind != VTY_KEYKIND_MDEK) continue;
        {
            char label[32];
            char *line;
            sprintf_s(label, sizeof(label), "mdek%u", (unsigned)i);
            line = secret_line(label, v->keyring.entries[i].key);
            if (line != NULL) {
                puts(line);
                vty_secure_zero(line, strlen(line));
                free(line);
            }
        }
    }
    /* 临时副本用完即清；父进程已通过管道拿到内容 */
    if (kc != NULL) { vty_secure_zero(kc, strlen(kc)); free(kc); }

    fflush(stdout);
}

static int run_hold(const char *vault_path)
{
    char pw[256];
    char pw2[300];
    char code[VTY_RECOVERY_TEXT_BUF];
    char order[64];
    VtyVault *v = NULL;
    int rc;

    if (!read_line(pw, sizeof(pw))) return 2;
    sprintf_s(pw2, sizeof(pw2), "%s-2", pw);

    rc = vty_vault_create(vault_path, pw, &v, code, sizeof(code));
    if (rc != VTY_OK) {
        printf("ERROR create %d\n", rc);
        return 3;
    }
    rc = vty_vault_save(v);
    /* 改密不再轮换恢复码；原码继续作为独立凭据被 A8 扫描。 */
    if (rc == VTY_OK) rc = vty_vault_rotate_password(v, pw2);
    vty_vault_free(v);
    v = NULL;
    if (rc != VTY_OK) {
        printf("ERROR rotate %d\n", rc);
        return 4;
    }

    rc = vty_vault_open(vault_path, pw2, &v);
    if (rc != VTY_OK) {
        printf("ERROR open %d\n", rc);
        return 5;
    }

    printf("SECRET password %s\n", pw2);
    printf("SECRET recovery %s\n", code);
    emit_secrets(v);
    printf("READY %lu\n", (unsigned long)GetCurrentProcessId());
    fflush(stdout);

    while (read_line(order, sizeof(order))) {
        if (strcmp(order, "LOCK") == 0) {
            vty_vault_free(v);
            v = NULL;
            vty_secure_zero(pw, sizeof(pw));
            vty_secure_zero(pw2, sizeof(pw2));
            vty_secure_zero(code, sizeof(code));
            puts("LOCKED");
            fflush(stdout);
        } else if (strcmp(order, "EXIT") == 0) {
            break;
        }
    }
    if (v != NULL) vty_vault_free(v);
    vty_secure_zero(pw, sizeof(pw));
    vty_secure_zero(pw2, sizeof(pw2));
    vty_secure_zero(code, sizeof(code));
    return 0;
}

static int run_crash(const char *vault_path)
{
    char pw[256];
    char order[64];
    VtyVault *v = NULL;
    int rc;

    if (!read_line(pw, sizeof(pw))) return 2;
    rc = vty_vault_open(vault_path, pw, &v);
    if (rc != VTY_OK) {
        printf("ERROR open %d\n", rc);
        return 5;
    }
    printf("SECRET password %s\n", pw);
    emit_secrets(v);
    printf("READY %lu\n", (unsigned long)GetCurrentProcessId());
    fflush(stdout);

    if (!read_line(order, sizeof(order))) return 6;
    if (strcmp(order, "CRASH") == 0) {
        /* 制造未处理访问违例：用于验证 WER 转储不留明文 */
        volatile int *p = (volatile int *)0;
        *p = 1;
    }
    vty_vault_free(v);
    return 0;
}

static int run_dump(DWORD pid, const char *path)
{
    wchar_t *wpath = to_wide(path);
    HANDLE process;
    HANDLE file;
    MINIDUMP_TYPE type;
    BOOL ok;

    if (wpath == NULL) return 2;
    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process == NULL) {
        printf("ERROR openprocess %lu\n", (unsigned long)GetLastError());
        free(wpath);
        return 3;
    }
    file = CreateFileW(wpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);
    if (file == INVALID_HANDLE_VALUE) {
        printf("ERROR createfile %lu\n", (unsigned long)GetLastError());
        CloseHandle(process);
        return 4;
    }
    type = (MINIDUMP_TYPE)(MiniDumpWithFullMemory |
                           MiniDumpWithHandleData |
                           MiniDumpWithPrivateReadWriteMemory |
                           MiniDumpIgnoreInaccessibleMemory);
    ok = MiniDumpWriteDump(process, pid, file, type, NULL, NULL, NULL);
    CloseHandle(file);
    CloseHandle(process);
    if (!ok) {
        printf("ERROR dump %lu\n", (unsigned long)GetLastError());
        return 5;
    }
    puts("DUMP OK");
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    /* 测试宿主只操作沙箱库：关闭回退锚点，避免污染真实用户目录，
     * 也避免锚点状态把同一临时库的重复用例串成误报。 */
    vty_rollback_set_enabled(0);
    if (argc >= 3 && strcmp(argv[1], "hold") == 0) return run_hold(argv[2]);
    if (argc >= 3 && strcmp(argv[1], "crash") == 0) return run_crash(argv[2]);
    if (argc >= 4 && strcmp(argv[1], "dump") == 0) {
        DWORD pid = (DWORD)strtoul(argv[2], NULL, 10);
        return run_dump(pid, argv[3]);
    }
    printf("usage: vty_mem_host <hold|crash> <vault> | dump <pid> <file>\n");
    return 1;
}
