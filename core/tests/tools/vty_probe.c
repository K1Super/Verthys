/*
 * vty_probe.c — v4 安全核心攻击探针（仅测试用，不进入生产 DLL 导出面）
 *
 * 用途：让 tests/attack/run.ps1 能以独立进程直接驱动 v4 原语，
 * 为 A5/A6b/A7/A10/A11/A13/A14/A15 生成可复核证据。
 *
 * 输出契约：单行 `RESULT <id> PASS|FAIL <detail>`，退出码 0=PASS。
 * 所有工件写入调用方给出的临时目录，绝不触碰活动库。
 */
#include "verthys_crypto.h"
#include "vty_v4_types.h"
#include "vty_keymanager_v4.h"
#include "vty_module_v4.h"
#include "vty_record_v4.h"
#include "vty_chunk_v4.h"
#include "vty_recovery.h"
#include "vty_format_v4.h"
#include "vty_keyslot_v4.h"
#include "vty_lockout.h"
#include "vty_rollback.h"
#include "vty_tpm_witness.h"
#include "vty_device_root.h"
#include "vty_blake3.h"
#include "vty_util.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void mkpath(char *out, size_t cap, const char *dir, const char *name)
{
    snprintf(out, cap, "%s\\%s", dir, name);
}

static int probe_read(const char *path, uint8_t *buf, size_t cap, size_t *len)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (f == NULL) return 1;
    n = fread(buf, 1, cap, f);
    fclose(f);
    *len = n;
    return 0;
}

static int probe_write(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t n;
    if (f == NULL) return 1;
    n = fwrite(buf, 1, len, f);
    fclose(f);
    return n == len ? 0 : 1;
}

static int contains(const uint8_t *hay, size_t hay_len, const char *needle)
{
    size_t nlen = strlen(needle);
    size_t i;
    if (nlen == 0 || nlen > hay_len) return 0;
    for (i = 0; i + nlen <= hay_len; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

static int report(const char *id, int pass, const char *detail)
{
    printf("RESULT %s %s %s\n", id, pass ? "PASS" : "FAIL", detail);
    return pass ? 0 : 1;
}

/* A5：v4 分片文件不得泄露明文，且不能按旧格式解析成功 */
static int cmd_a5(const char *dir)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    const char *marker = "A5_MARKER_5EC7_PLAINTEXT";
    uint8_t pt[65536];
    uint8_t *ct = NULL, *mct = NULL;
    size_t ct_len = 0, mct_len = 0;
    uint8_t ids[VTY_HASH_BYTES];
    uint8_t *out = NULL;
    size_t out_len = 0;
    uint8_t pt_hash[VTY_HASH_BYTES];
    char cpath[1024], mpath[1024];
    uint8_t *file = NULL;
    size_t file_len = 0;
    uint32_t total = 0;

    memset(mdek, 0x21, sizeof(mdek));
    memset(uuid, 0x22, sizeof(uuid));
    memset(pt, 'A', sizeof(pt));
    memcpy(pt, marker, strlen(marker));
    memset(pt_hash, 0x23, sizeof(pt_hash));

    if (vty_chunk_seal(mdek, uuid, 0, 1, 1, pt, sizeof(pt), &ct, &ct_len)
        != VTY_OK) return report("A5", 0, "chunk_seal");
    if (vty_chunk_id(mdek, uuid, 0, ids) != VTY_OK) {
        vty_free(ct, ct_len);
        return report("A5", 0, "chunk_id");
    }
    if (vty_manifest_seal(mdek, uuid, 1, pt_hash, 1, ids, &mct, &mct_len)
        != VTY_OK) {
        vty_free(ct, ct_len);
        return report("A5", 0, "manifest_seal");
    }

    mkpath(cpath, sizeof(cpath), dir, "a5_chunk.bin");
    mkpath(mpath, sizeof(mpath), dir, "a5_manifest.bin");
    if (probe_write(cpath, ct, ct_len) || probe_write(mpath, mct, mct_len)) {
        vty_free(ct, ct_len); vty_free(mct, mct_len);
        return report("A5", 0, "write");
    }

    file = (uint8_t *)vty_alloc(1 << 20);
    if (file == NULL) {
        vty_free(ct, ct_len); vty_free(mct, mct_len);
        return report("A5", 0, "alloc");
    }

    if (probe_read(cpath, file, 1 << 20, &file_len) ||
        contains(file, file_len, marker) ||
        (file_len >= 4 && file[0] == 'V' && file[1] == '3' &&
         file[2] == 'S' && file[3] == 'B')) {
        vty_free(file, 1 << 20); vty_free(ct, ct_len); vty_free(mct, mct_len);
        return report("A5", 0, "chunk 文件泄露标记或出现 V3SB 头");
    }
    /* 用错误的 seq/total 与旧格式入口都不能“还原”出该分片 */
    if (vty_chunk_open(mdek, uuid, 1, 1, 1, file, file_len, &out, &out_len)
        == VTY_OK) {
        vty_free(file, 1 << 20); vty_free(ct, ct_len); vty_free(mct, mct_len);
        return report("A5", 0, "错误 seq 仍被接受");
    }
    if (probe_read(mpath, file, 1 << 20, &file_len) ||
        contains(file, file_len, marker) ||
        vty_manifest_open(mdek, uuid, 2, file, file_len,
                          pt_hash, &total, &out) == VTY_OK) {
        vty_free(file, 1 << 20); vty_free(ct, ct_len); vty_free(mct, mct_len);
        return report("A5", 0, "manifest 可被错误 epoch/明文还原");
    }

    vty_free(file, 1 << 20);
    vty_free(ct, ct_len);
    vty_free(mct, mct_len);
    return report("A5", 1, "无明文泄露；错误 seq/epoch 还原失败");
}

/* A6b：同机错误模块口令达到阈值后熔断；A14：设备槽破坏后 fail-closed */
static int cmd_a6b(const char *dir, int break_device)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    char vpath[1024], mpath[1024], spath[1024];
    uint8_t uuid0[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    int rc, pass = 1;
    int i;

    mkpath(vpath, sizeof(vpath), dir, "a6b.verthys");
    mkpath(mpath, sizeof(mpath), dir, "a6b.mod");
    mkpath(spath, sizeof(spath), dir, "a6b.state");
    remove(vpath); remove(mpath); remove(spath);

    vty_lockout_set_enabled(1);
    if (vty_lockout_set_path(spath) != VTY_OK || vty_lockout_init() != VTY_OK ||
        vty_lockout_reset() != VTY_OK) return report("A6b", 0, "lockout init");

    if (vty_vault_create(vpath, "probe-vault-pass", &v, code, sizeof(code)) != VTY_OK)
        return report("A6b", 0, "vault create");
    if (vty_vault_module_uuid(v, 0, uuid0) != VTY_OK)
        return report("A6b", 0, "module uuid");
    if (vty_module_create(mpath, v, uuid0, "module-pass",
                          VTY_ARGON2_MEM_KIB_MIN, 3, 1) != VTY_OK)
        return report("A6b", 0, "module create");
    if (vty_module_unlock(mpath, v, uuid0, "module-pass", mdek) != VTY_OK)
        return report("A6b", 0, "correct unlock");

    if (break_device) {
        uint8_t *buf = (uint8_t *)vty_alloc(1 << 20);
        size_t len = 0;
        uint8_t hash[VTY_HASH_BYTES];
        if (buf == NULL || probe_read(mpath, buf, 1 << 20, &len) != 0 ||
            len < 32 + 273) {
            vty_free(buf, 1 << 20);
            return report("A14", 0, "module read");
        }
        buf[272] ^= 0x01u;   /* 设备槽 RSA 密文 */
        vty_blake3_32(buf, len - 32, hash);
        memcpy(buf + len - 32, hash, sizeof(hash));
        (void)probe_write(mpath, buf, len);
        vty_free(buf, 1 << 20);
        rc = vty_module_unlock(mpath, v, uuid0, "module-pass", mdek);
        vty_vault_free(v);
        vty_lockout_set_enabled(0);
        return report("A14", rc == VTY_E_TPM,
                      rc == VTY_E_TPM ? "设备槽破坏 → E_TPM"
                                      : "设备槽破坏后仍返回成功");
    }

    for (i = 0; i < 5; i++) {
        rc = vty_module_unlock(mpath, v, uuid0, "wrong-pass", mdek);
        if (rc != VTY_E_KEY_INVALID) {
            pass = 0;
            break;
        }
    }
    if (pass) {
        rc = vty_module_unlock(mpath, v, uuid0, "module-pass", mdek);
        pass = (rc == VTY_E_LOCKED);
    }
    vty_vault_free(v);
    vty_lockout_set_enabled(0);
    return report("A6b", pass, pass ? "5 次错误后正确口令仍被熔断"
                                     : "未按阈值熔断");
}

/* A7：跨进程持久化熔断（phase1 制造锁定，phase2 新进程复核） */
static int cmd_a7(const char *state, const char *phase)
{
    int locked;
    int i;

    vty_lockout_set_enabled(1);
    if (vty_lockout_set_path(state) != VTY_OK || vty_lockout_init() != VTY_OK)
        return report("A7", 0, "lockout init");

    if (strcmp(phase, "phase1") == 0) {
        (void)vty_lockout_reset();
        for (i = 0; i < VTY_LOCKOUT_MAX_FAILURES; i++) {
            (void)vty_lockout_record_failure();
        }
        locked = (vty_lockout_check() == VTY_E_LOCKED);
        return report("A7", locked, locked ? "阈值后锁定" : "阈值后未锁定");
    }

    /* 新进程只读状态 */
    locked = (vty_lockout_check() == VTY_E_LOCKED);
    {
        uint8_t id[VTY_UUID_BYTES];
        if (vty_tpm_witness_id_from_string(state, id) == VTY_OK) {
            (void)vty_tpm_witness_delete_all(id);
        }
    }
    return report("A7", locked, locked ? "重启后仍锁定" : "重启后可绕过");
}

/* A10：同一明文重复封装不得复用 nonce/密文 */
static int cmd_a10(const char *dir)
{
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t *blobs[256];
    size_t lens[256];
    const char *pt = "same-plaintext-for-nonce-check";
    uint32_t i, j, dup = 0;

    memset(mdek, 0x31, sizeof(mdek));
    memset(uuid, 0x32, sizeof(uuid));

    for (i = 0; i < 256; i++) {
        uint8_t *b = NULL;
        size_t n = 0;
        if (vty_record_seal(mdek, uuid, i, 1, (const uint8_t *)pt, strlen(pt),
                            (const uint8_t *)pt, strlen(pt), &b, &n) != VTY_OK) {
            return report("A10", 0, "record seal");
        }
        blobs[i] = b; lens[i] = n;
    }
    for (i = 0; i < 256 && dup == 0; i++) {
        for (j = i + 1; j < 256; j++) {
            if (lens[i] == lens[j] && memcmp(blobs[i], blobs[j], lens[i]) == 0) {
                dup = 1;
                break;
            }
        }
    }
    for (i = 0; i < 256; i++) vty_free(blobs[i], lens[i]);
    (void)dir;
    return report("A10", dup == 0, dup ? "出现重复封装" : "256 次封装无重复");
}

/* A11：槽序进入 AAD；跨模块记录不可重放 */
static int cmd_a11(void)
{
    VtyV4Header h;
    VtySlot s;
    uint8_t key[VTY_KEY_BYTES];
    uint8_t back[VTY_KEY_BYTES];
    uint8_t mdek_a[VTY_KEY_BYTES], mdek_b[VTY_KEY_BYTES];
    uint8_t ua[VTY_UUID_BYTES], ub[VTY_UUID_BYTES];
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    uint8_t *name = NULL, *data = NULL;
    size_t name_len = 0, data_len = 0;
    int pass = 1;

    memset(&h, 0, sizeof(h));
    memset(key, 0x41, sizeof(key));
    memset(h.vault_uuid, 0x42, sizeof(h.vault_uuid));
    h.epoch = 3;
    if (vty_slot_seal_argon2id(&s, VTY_SLOT_USER_PASSWORD,
                               VTY_SLOT_FLAG_REQUIRED, (const uint8_t *)"pw", 2,
                               key, &h, 0, VTY_ARGON2_MEM_KIB_MIN, 3, 1) != VTY_OK)
        return report("A11", 0, "slot seal");
    /* 槽 0 的密文拿到槽 1 解包：AAD 下标不同必须失败 */
    if (vty_slot_open_argon2id(&s, (const uint8_t *)"pw", 2, &h, 1, back)
        == VTY_OK) pass = 0;

    memset(mdek_a, 0x51, sizeof(mdek_a));
    memset(mdek_b, 0x52, sizeof(mdek_b));
    memset(ua, 0x53, sizeof(ua));
    memset(ub, 0x54, sizeof(ub));
    if (vty_record_seal(mdek_a, ua, 1, 3, (const uint8_t *)"n", 1,
                        (const uint8_t *)"d", 1, &blob, &blob_len) != VTY_OK)
        return report("A11", 0, "record seal");
    if (vty_record_open(mdek_b, ub, 3, blob, blob_len,
                        &name, &name_len, &data, &data_len) == VTY_OK) pass = 0;
    vty_free(blob, blob_len);
    return report("A11", pass, pass ? "槽换位/跨模块重放均失败"
                                    : "重放被接受");
}

/* A13：明文回退开关必须被显式拒绝 */
static int cmd_a13(void)
{
    int r0 = vty_record_reject_plaintext(0);
    int r1 = vty_record_reject_plaintext(1);
    int pass = (r0 == VTY_E_PLAINTEXT_FORBIDDEN) && (r1 == VTY_OK);
    return report("A13", pass, pass ? "encrypted=0 → PLAINTEXT_FORBIDDEN"
                                    : "明文回退未被拒绝");
}

/* A15：恢复码正向成功、错误恢复码拒绝 */
static int cmd_a15(const char *dir)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    char other[VTY_RECOVERY_TEXT_BUF];
    uint8_t raw[VTY_RECOVERY_CODE_BYTES];
    char vpath[1024];
    int pass = 1;

    mkpath(vpath, sizeof(vpath), dir, "a15.verthys");
    remove(vpath);
    if (vty_vault_create(vpath, "recovery-pass", &v, code, sizeof(code)) != VTY_OK)
        return report("A15", 0, "create");
    vty_vault_free(v);

    if (vty_vault_open_recovery(vpath, code, &re) != VTY_OK) pass = 0;
    if (re != NULL) vty_vault_free(re);
    re = NULL;

    if (vty_recovery_generate(raw, other, sizeof(other)) != VTY_OK) pass = 0;
    if (vty_vault_open_recovery(vpath, other, &re) == VTY_OK) pass = 0;
    if (re != NULL) vty_vault_free(re);
    return report("A15", pass, pass ? "正确恢复码成功、错误恢复码拒绝"
                                    : "恢复码流程异常");
}

/* A12：整体还原旧库文件 → 外部锚点拒绝；恢复码可重设锚点；锚点篡改 fail-closed */
static int cmd_a12(const char *dir)
{
    VtyVault *v = NULL;
    VtyVault *re = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    char vpath[1024], opath[1024], spath[1024];
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t old_copy[65536];
    uint8_t state[4096];
    size_t old_len = 0;
    size_t state_len = 0;
    int pass = 1;
    int rc;
    const char *detail = "旧副本被锚点拒绝；恢复码重设锚点；锚点篡改 fail-closed";

    mkpath(vpath, sizeof(vpath), dir, "a12.verthys");
    mkpath(opath, sizeof(opath), dir, "a12_old.verthys");
    mkpath(spath, sizeof(spath), dir, "a12.state");
    remove(vpath); remove(opath); remove(spath);

    /* 该探针只用正确口令：关掉熔断，避免任何失败路径写状态 */
    vty_lockout_set_enabled(0);
    vty_rollback_set_enabled(1);
    if (vty_rollback_set_path(spath) != VTY_OK || vty_rollback_init() != VTY_OK) {
        vty_rollback_set_enabled(0);
        return report("A12", 0, "rollback init");
    }

    if (vty_vault_create(vpath, "a12-pass", &v, code, sizeof(code)) != VTY_OK) {
        vty_rollback_set_enabled(0);
        return report("A12", 0, "create");
    }
    memcpy(uuid, v->header.vault_uuid, VTY_UUID_BYTES);
    if (vty_vault_save(v) != VTY_OK ||
        probe_read(vpath, old_copy, sizeof(old_copy), &old_len) != 0 ||
        old_len == 0 ||
        vty_vault_save(v) != VTY_OK) {
        vty_vault_free(v);
        vty_rollback_set_enabled(0);
        return report("A12", 0, "prepare old copy");
    }
    vty_vault_free(v);

    v = NULL;
    if (vty_vault_open(vpath, "a12-pass", &v) != VTY_OK) {
        vty_rollback_set_enabled(0);
        return report("A12", 0, "最新副本打开失败");
    }
    vty_vault_free(v);

    if (probe_write(opath, old_copy, old_len) != 0) {
        vty_rollback_set_enabled(0);
        return report("A12", 0, "write old copy");
    }
    v = NULL;
    rc = vty_vault_open(opath, "a12-pass", &v);
    if (rc != VTY_E_ROLLBACK) {
        pass = 0;
        detail = "旧副本未被拒绝";
    }
    if (v != NULL) vty_vault_free(v);

    /* 恢复码是逃生通道：允许回退并把锚点重设到旧版本 */
    if (pass) {
        if (vty_vault_open_recovery(opath, code, &re) != VTY_OK) {
            pass = 0;
            detail = "恢复码无法打开旧副本";
        } else {
            vty_vault_free(re);
            re = NULL;
            v = NULL;
            if (vty_vault_open(opath, "a12-pass", &v) != VTY_OK) {
                pass = 0;
                detail = "锚点未随恢复码重设";
            }
            if (v != NULL) vty_vault_free(v);
        }
    }

    /* 锚点文件被篡改：必须 fail-closed，而不是当作首次运行 */
    if (pass) {
        if (probe_read(spath, state, sizeof(state), &state_len) != 0 ||
            state_len == 0) {
            pass = 0;
            detail = "锚点文件缺失";
        } else {
            state[0] ^= 0x01u;
            if (probe_write(spath, state, state_len) != 0) {
                pass = 0;
                detail = "锚点文件写入失败";
            } else {
                v = NULL;
                rc = vty_vault_open(vpath, "a12-pass", &v);
                if (rc != VTY_E_ROLLBACK) {
                    pass = 0;
                    detail = "锚点篡改后仍可打开";
                }
                if (v != NULL) vty_vault_free(v);
            }
        }
    }

    vty_rollback_set_enabled(0);
    (void)vty_tpm_witness_delete_all(uuid);
    return report("A12", pass, detail);
}

/* 设备槽当前 level/provider：封一次临时密钥读取头部字段（不含密钥内容） */
static void probe_device_slot(int *level, int *provider)
{
    uint8_t key[VTY_KEY_BYTES];
    uint8_t blob[VTY_DEVICE_BLOB_BYTES];
    size_t blob_len = sizeof(blob);
    int i;
    *level = -1;
    *provider = -1;
    for (i = 0; i < VTY_KEY_BYTES; i++) key[i] = (uint8_t)i;
    if (vty_device_root_init() != VTY_OK) return;
    if (vty_device_key_seal(key, blob, &blob_len) != VTY_OK) return;
    *level = (int)blob[0];
    *provider = (int)blob[1];
    vty_secure_zero(key, sizeof(key));
}

/* 明文扫描：模块/库文件中不得出现口令原文（ASCII 与 UTF-16LE 两种表示） */
static int probe_plaintext_hits(const char *path)
{
    uint8_t *buf;
    size_t len = 0;
    int hits = 0;

    buf = (uint8_t *)vty_alloc(1 << 20);
    if (buf == NULL) return -1;
    if (probe_read(path, buf, 1 << 20, &len) != 0) {
        /* 读不到就不能宣称“0 命中”，否则会把 IO 故障当成干净 */
        hits = -1;
    } else {
        if (contains(buf, len, "probe-vault-pass")) hits++;
        if (contains(buf, len, "module-pass")) hits++;
        /* UTF-16LE：只需检查高字节为 0 的相邻字节对 */
        {
            size_t i;
            const char *needles[2] = { "probe-vault-pass", "module-pass" };
            for (int n = 0; n < 2; n++) {
                size_t nlen = strlen(needles[n]);
                for (i = 0; i + nlen * 2 <= len; i++) {
                    size_t j;
                    int match = 1;
                    for (j = 0; j < nlen; j++) {
                        if (buf[i + j * 2] != (uint8_t)needles[n][j] ||
                            buf[i + j * 2 + 1] != 0) { match = 0; break; }
                    }
                    if (match) { hits++; break; }
                }
            }
        }
    }
    vty_free(buf, 1 << 20);
    return hits;
}

/* A6：源机建库/建模块并做正控（离机复核由 a6run 完成） */
static int cmd_a6(const char *dir)
{
    VtyVault *v = NULL;
    char code[VTY_RECOVERY_TEXT_BUF];
    char vpath[1024], mpath[1024];
    uint8_t uuid0[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    int rc_open, rc_mod, rc_create, level, provider, hits;

    mkpath(vpath, sizeof(vpath), dir, "a6.verthys");
    mkpath(mpath, sizeof(mpath), dir, "a6.mod");
    remove(vpath);
    remove(mpath);

    /* A6 验证设备根绑定，与回滚锚点无关，避免两个模块互相干扰 */
    vty_rollback_set_enabled(0);

    rc_create = vty_vault_create(vpath, "probe-vault-pass", &v, code, sizeof(code));
    if (rc_create != VTY_OK) return report("A6", 0, "vault create failed");

    if (vty_vault_module_uuid(v, 0, uuid0) != VTY_OK) {
        vty_vault_free(v);
        return report("A6", 0, "module uuid failed");
    }
    if (vty_module_create(mpath, v, uuid0, "module-pass",
                          VTY_ARGON2_MEM_KIB_MIN, 3, 1) != VTY_OK) {
        vty_vault_free(v);
        return report("A6", 0, "module create failed");
    }
    rc_mod = vty_module_unlock(mpath, v, uuid0, "module-pass", mdek);
    vty_vault_free(v);
    v = NULL;

    rc_open = vty_vault_open(vpath, "probe-vault-pass", &v);
    if (v != NULL) vty_vault_free(v);

    probe_device_slot(&level, &provider);
    hits = probe_plaintext_hits(vpath);
    if (hits >= 0) {
        int mh = probe_plaintext_hits(mpath);
        hits = mh < 0 ? -1 : hits + mh; /* 任一文件读失败都不能报告 0 命中 */
    }

    printf("A6 device_level=%d device_provider=%d vault_open=%d module_unlock=%d plaintext_hits=%d\n",
           level, provider, rc_open, rc_mod, hits);
    return report("A6", rc_mod == VTY_OK && rc_open == VTY_OK && hits == 0,
                  rc_mod == VTY_OK && rc_open == VTY_OK
                      ? "源机正控：设备根可用，模块解锁/库打开成功，无明文泄漏"
                      : "源机正控失败");
}

/* A6 离机复核：只报告返回码，由 offmachine/run.ps1 判定
 * （异机期望 vault_open=E_TPM 且无法取得模块密钥）。 */
static int cmd_a6run(const char *dir)
{
    VtyVault *v = NULL;
    char vpath[1024], mpath[1024];
    uint8_t uuid0[VTY_UUID_BYTES];
    uint8_t mdek[VTY_KEY_BYTES];
    uint8_t filebuf[4096];
    size_t flen = 0;
    int rc_open, rc_mod = -1, level, provider, hits = 0;

    mkpath(vpath, sizeof(vpath), dir, "a6.verthys");
    mkpath(mpath, sizeof(mpath), dir, "a6.mod");

    vty_rollback_set_enabled(0);

    /* 模块文件头：uuid(16)@8、module_uuid(16)@24，不依赖解锁状态 */
    if (probe_read(mpath, filebuf, sizeof(filebuf), &flen) != 0 || flen < 40) {
        printf("A6RUN FAIL module_missing\n");
        return 2;
    }
    memcpy(uuid0, filebuf + 24, VTY_UUID_BYTES);

    rc_open = vty_vault_open(vpath, "probe-vault-pass", &v);
    if (rc_open == VTY_OK && v != NULL) {
        rc_mod = vty_module_unlock(mpath, v, uuid0, "module-pass", mdek);
        vty_vault_free(v);
    }

    probe_device_slot(&level, &provider);
    hits = probe_plaintext_hits(vpath);
    if (hits >= 0) {
        int mh = probe_plaintext_hits(mpath);
        hits = mh < 0 ? -1 : hits + mh;
    }

    printf("A6RUN device_level=%d device_provider=%d vault_open=%d module_unlock=%d plaintext_hits=%d\n",
           level, provider, rc_open, rc_mod, hits);
    return 0;
}

int main(int argc, char **argv)
{
    if (verthys_crypto_init() != 0) {
        printf("RESULT INIT FAIL crypto_init\n");
        return 2;
    }
    /* 探针默认不写用户目录：回退锚点只在 A12 用例里显式开启并注入沙箱路径，
     * 与测试进程“副作用模块默认关闭”的约定一致。 */
    vty_rollback_set_enabled(0);
    if (argc < 3) {
        printf("usage: vty_probe <a5|a6|a6run|a6b|a7|a10|a11|a12|a13|a14|a15> <dir|path> [...]\n");
        return 2;
    }

    if (strcmp(argv[1], "a5") == 0) return cmd_a5(argv[2]);
    if (strcmp(argv[1], "a6") == 0) return cmd_a6(argv[2]);
    if (strcmp(argv[1], "a6run") == 0) return cmd_a6run(argv[2]);
    if (strcmp(argv[1], "a6b") == 0) return cmd_a6b(argv[2], 0);
    if (strcmp(argv[1], "a14") == 0) return cmd_a6b(argv[2], 1);
    if (strcmp(argv[1], "a7") == 0 && argc >= 4) return cmd_a7(argv[2], argv[3]);
    if (strcmp(argv[1], "a10") == 0) return cmd_a10(argv[2]);
    if (strcmp(argv[1], "a11") == 0) return cmd_a11();
    if (strcmp(argv[1], "a12") == 0) return cmd_a12(argv[2]);
    if (strcmp(argv[1], "a13") == 0) return cmd_a13();
    if (strcmp(argv[1], "a15") == 0) return cmd_a15(argv[2]);

    printf("RESULT UNKNOWN FAIL unsupported command\n");
    return 2;
}
