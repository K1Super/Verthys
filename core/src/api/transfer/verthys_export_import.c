/*
 * verthys_export_import.c — 导出 / 导入 / 修改主密码模块
 *
 * 包含以下公共 API 与其内部辅助函数：
 *   - Verthys_Export()        ：流式导出（v1 交换格式，跨设备兼容）
 *   - Verthys_Import()        ：导入合并到当前加密库
 *   - Verthys_ChangePassword()：修改主密码
 *
 * 三个 API 的实现：
 *   - Export      ：记录 ID 快照 + 逐条记录段解密流式写入
 *                   （内存峰值与记录数解耦）；
 *   - Import      ：逐条写仓库，末尾一次 DataRoot/元数据提交；
 *   - ChangePassword：口令槽重派生 + 密钥环重包裹 + 原子提交。
 */
#include "verthys_api_utils.h"
#include "verthys_internal.h"
#include "verthys.h"
#include "verthys_format.h"            /* v1 交换格式读写器（跨设备契约） */
#include "verthys_crypto.h"
#include "keymanager.h"
#include "anti_debug.h"   /* 高危入口反调试检测 */
#include "runtime_hash.h"   /* 写路径周期运行时函数哈希校验 */
#include "vty_repo.h"    /* 记录仓库（导出/导入/计数） */
#include "vty_record.h"  /* 单条明文上限 */
#include "verthys_api_container.h" /* 错误码映射与改密适配 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#ifdef _WIN32
/*
 * 导出/导入目标路径纵深防御（C 层，Windows）。
 *
 * 背景：worker 端（Rust）已在 CString 层拒绝内嵌 NUL 的路径，但 C 层仍需
 * 独立校验，杜绝导出/导入被诱导写入或读取系统关键目录 / 符号链接 / 目录穿越
 * 路径。返回 0=允许，-1=拒绝（调用方映射为 VERTHYS_ERR_INVALID）。
 */

/* 判断单一路径段是否等于 "." 或 ".."（目录穿越段） */
static int is_dot_segment(const char *seg, size_t len)
{
    if (len == 1 && seg[0] == '.') return 1;
    if (len == 2 && seg[0] == '.' && seg[1] == '.') return 1;
    return 0;
}

/* 检查路径任意位置是否含 '.'/'..' 目录段（'\\' 与 '/' 均视为分隔符） */
static int path_has_dot_segment(const char *path)
{
    const char *p = path;
    while (*p != '\0') {
        const char *seg_start = p;
        while (*p != '\0' && *p != '\\' && *p != '/') p++;
        if (is_dot_segment(seg_start, (size_t)(p - seg_start))) return 1;
        if (*p != '\0') p++;  /* 跳过分隔符 */
    }
    return 0;
}

/* 判断规范化路径是否位于给定目录前缀内。分隔符边界：前缀后紧跟的字符
 * 必须是 '\\'、'/' 或字符串结尾，避免 "C:\\WindowsFoo" 误命中 "C:\\Windows"。 */
static int path_under_dir(const char *dir, const char *path)
{
    size_t dlen = strlen(dir);
    if (dlen == 0) return 0;
    if (_strnicmp(path, dir, dlen) != 0) return 0;
    char next = path[dlen];
    return (next == '\0' || next == '\\' || next == '/');
}

/* 探测目标是否为重解析点（符号链接 / 挂载点）。返回 1=是，0=否或不可判定。 */
static int path_is_reparse_point(const char *path)
{
    HANDLE h = CreateFileA(path, 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING,
                           FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                           NULL);
    if (h == INVALID_HANDLE_VALUE) {
        /* 目标不存在或不可访问：非重解析点，由后续实际打开再裁决 */
        return 0;
    }
    BY_HANDLE_FILE_INFORMATION info;
    int is_reparse = 0;
    if (GetFileInformationByHandle(h, &info)) {
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            is_reparse = 1;
        }
    }
    CloseHandle(h);
    return is_reparse;
}

static int verthys_validate_transfer_path(const char *path)
{
    char full[MAX_PATH];
    char win_dir[MAX_PATH];
    char sys_dir[MAX_PATH];
    DWORD n;

    if (path == NULL || path[0] == '\0') return -1;

    /* 1. 原始路径目录穿越段复检（在规范化前拦截字面 '.'/'..'） */
    if (path_has_dot_segment(path)) return -1;

    /* 2. 规范化（折叠相对段与重复分隔符），失败即拒绝 */
    n = GetFullPathNameA(path, MAX_PATH, full, NULL);
    if (n == 0 || n >= MAX_PATH) return -1;

    /* 3. 规范化结果再复检目录穿越段（防御性，规范化后理论上不应残留） */
    if (path_has_dot_segment(full)) return -1;

    /* 4. 系统关键目录前缀黑名单（拿不到黑名单目录即拒绝，宁严勿宽） */
    if (GetWindowsDirectoryA(win_dir, MAX_PATH) == 0) return -1;
    if (GetSystemDirectoryA(sys_dir, MAX_PATH) == 0) return -1;
    if (path_under_dir(win_dir, full)) return -1;
    if (path_under_dir(sys_dir, full)) return -1;

    /* 5. 重解析点（符号链接 / 挂载点）探测 */
    if (path_is_reparse_point(full)) return -1;

    return 0;
}
#else
static int verthys_validate_transfer_path(const char *path)
{
    (void)path;
    return 0;  /* 非 Windows：无系统目录 / 重解析点语义，不校验 */
}
#endif /* _WIN32 */

/* 8. 导出（v1 交换格式，跨设备兼容） */
/*
 * 流式导出：元数据（type/名称/尺寸）单遍收集，数据不预载——get_data
 * 回调按 record_id 重新读取并解密单条记录。
 *
 * 内存峰值 = max(单条记录大小) + 固定缓冲 + 元数据数组大小，与记录
 * 总数解耦，万级照片库导出不 OOM。
 *
 * 原子性：流式写入过程中任一步骤失败 → 关闭并删除半成品文件，返回错误。
 * 安全性：明文数据用完即刻 verthys_secure_zero 清零释放，最小化明文驻留窗口。
 */
typedef struct {
    VtyVault *v;
    const uint64_t *ids;
    uint16_t count;
} VerthysExportCtx;

static int verthys_export_get_data(uint16_t idx,
                                      uint8_t **out_data, size_t *out_size,
                                      void *user_data)
{
    VerthysExportCtx *sc = (VerthysExportCtx *)user_data;
    VtyRepoRecord rec;
    int rc;

    if (sc == NULL || out_data == NULL || out_size == NULL ||
        idx >= sc->count) {
        return -1;
    }
    memset(&rec, 0, sizeof(rec));
    rc = vty_repo_get(sc->v, sc->ids[idx], &rec);
    if (rc != VTY_OK) return -1;
    if (rec.name != NULL) {
        vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
    }
    if (rec.data_len == 0) {
        uint8_t *dummy = (uint8_t *)calloc(1, 1);
        if (dummy == NULL) return -1;
        *out_data = dummy;
        *out_size = 0;
    } else {
        *out_data = rec.data;
        *out_size = rec.data_len;
    }
    return 0;
}

static void verthys_export_release_data(uint16_t idx,
                                           uint8_t *data, size_t size,
                                           void *user_data)
{
    (void)idx;
    (void)user_data;
    if (data == NULL) return;
    if (size > 0) verthys_secure_zero(data, size);
    free(data);
}

static VerthysResult verthys_export_locked(struct VerthysContext *ctx,
                                              const char *export_path,
                                              const char *password,
                                              size_t password_len)
{
    VtyVault *v = ctx->vault;
    VtyRepoIter *it = NULL;
    VerthysFmtRecord *fmt_recs = NULL;
    uint64_t *ids = NULL;
    uint64_t total = 0;
    uint16_t count = 0;
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES];
    VerthysExportCtx sc;
    int rc;

    memset(salt, 0, sizeof(salt));
    memset(mek, 0, sizeof(mek));
    memset(dek, 0, sizeof(dek));
    if (v == NULL || !v->unlocked || v->store == NULL) return VERTHYS_ERR_LOCKED;

    rc = vty_repo_count(v, &total);
    if (rc != VTY_OK) return verthys_api_container_map(rc);
    if (total > 65535u) return VERTHYS_ERR_EXPORT_TOO_MANY;

    if (total > 0) {
        fmt_recs = (VerthysFmtRecord *)calloc((size_t)total, sizeof(VerthysFmtRecord));
        ids = (uint64_t *)calloc((size_t)total, sizeof(uint64_t));
        if (fmt_recs == NULL || ids == NULL) {
            free(fmt_recs);
            free(ids);
            return VERTHYS_ERR_INTERNAL;
        }
    }

    rc = vty_repo_iter_open(v, 0, &it);
    if (rc != VTY_OK) {
        free(fmt_recs);
        free(ids);
        return verthys_api_container_map(rc);
    }
    for (;;) {
        VtyRepoLeaf leaf;
        VtyRepoRecord rec;
        int done = 0;

        rc = vty_repo_iter_next(it, &leaf, &done);
        if (rc != VTY_OK) break;
        if (done) break;
        if (count >= total) { rc = VTY_E_CORRUPT; break; }

        memset(&rec, 0, sizeof(rec));
        rc = vty_repo_read(v, &leaf, &rec);
        if (rc != VTY_OK) break;

        fmt_recs[count].type = rec.type;
        fmt_recs[count].name_len = (uint16_t)rec.name_len;
        fmt_recs[count].name =
            (uint8_t *)malloc(rec.name_len > 0 ? rec.name_len : 1u);
        if (fmt_recs[count].name == NULL) {
            vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
            vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);
            rc = VTY_E_RESOURCE;
            break;
        }
        if (rec.name_len > 0) memcpy(fmt_recs[count].name, rec.name, rec.name_len);
        fmt_recs[count].data_size = (uint32_t)rec.data_len;
        fmt_recs[count].data = NULL;
        ids[count] = leaf.record_id;

        vty_free(rec.name, rec.name_len != 0 ? rec.name_len : 1u);
        vty_free(rec.data, rec.data_len != 0 ? rec.data_len : 1u);
        count++;
    }
    vty_repo_iter_close(it);

    if (rc != VTY_OK || count != (uint16_t)total) {
        VerthysResult err = (rc != VTY_OK)
            ? verthys_api_container_map(rc) : VERTHYS_ERR_CORRUPT;
        for (uint16_t i = 0; i < count; i++) {
            if (fmt_recs[i].name != NULL) {
                verthys_secure_zero(fmt_recs[i].name, fmt_recs[i].name_len);
                free(fmt_recs[i].name);
            }
        }
        free(fmt_recs);
        free(ids);
        return err;
    }

    verthys_random_bytes(salt, sizeof salt);
    if (keymanager_derive_master_export(mek, (const uint8_t *)password,
                                        password_len, salt) != 0) {
        for (uint16_t i = 0; i < count; i++) {
            if (fmt_recs[i].name != NULL) {
                verthys_secure_zero(fmt_recs[i].name, fmt_recs[i].name_len);
                free(fmt_recs[i].name);
            }
        }
        free(fmt_recs);
        free(ids);
        verthys_secure_zero(mek, sizeof mek);
        verthys_secure_zero(salt, sizeof salt);
        return VERTHYS_ERR_INTERNAL;
    }
    keymanager_generate_dek(dek);

    sc.v = v;
    sc.ids = ids;
    sc.count = count;
    rc = vfmt_write_streaming(salt, v->mem_kib, v->iters, v->parallel,
                              mek, dek, fmt_recs, count,
                              verthys_export_get_data,
                              verthys_export_release_data,
                              &sc, export_path);

    for (uint16_t i = 0; i < count; i++) {
        if (fmt_recs[i].name != NULL) {
            verthys_secure_zero(fmt_recs[i].name, fmt_recs[i].name_len);
            free(fmt_recs[i].name);
        }
    }
    free(fmt_recs);
    free(ids);
    verthys_secure_zero(salt, sizeof salt);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);
    return rc == 0 ? VERTHYS_OK : (rc < 0 ? VERTHYS_ERR_INTERNAL : VERTHYS_ERR_IO);
}

VerthysResult Verthys_Export(VerthysHandle handle,
                         const char *export_path,
                         const char *password,
                         size_t      password_len)
{
    struct VerthysContext *ctx;

    if (handle == NULL || export_path == NULL) return VERTHYS_ERR_INVALID;
    if (password == NULL && password_len != 0) return VERTHYS_ERR_INVALID;

    /* 导出路径纵深防御校验（目录穿越 / 系统目录 / 符号链接） */
    if (verthys_validate_transfer_path(export_path) != 0) {
        return VERTHYS_ERR_INVALID;
    }

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    /* 导出属高危入口，执行反调试检测（命中即 KILL 上报） */
    if (anti_debug_check() != DBG_THREAT_NONE) {
        return VERTHYS_ERR_INTERNAL;
    }

    /* 递归互斥锁保护，防止并发重入 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif

    /* v1 交换格式流式导出（记录段解密按需进行） */
    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        VerthysResult rc_vault = verthys_export_locked(ctx, export_path,
                                                     password, password_len);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        return rc_vault;
    }

    /* 非容器格式无导出路径 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
    return VERTHYS_ERR_FORMAT;
}

/* 9. 导入（v1 交换格式文件，合并到当前加密库）
 *
 * 逐条写仓库，末尾一次 DataRoot/元数据提交；导入原子性由仓库层的
 * 事务提交保证。前置校验：名称长度 ≤ VERTHYS_NAME_MAX_BYTES，
 * 预检将坏文件挡在写入前（FORMAT 拒绝，零副作用）。
 * api_mutex 已由公共入口独占持有。
 */

/* 导入：逐条写仓库，末尾一次 DataRoot/元数据提交。 */
static VerthysResult verthys_api_container_import(struct VerthysContext *ctx,
                                           const VerthysFmtRecord *fmt_recs,
                                           uint16_t count)
{
    VtyRepoInput *in = NULL;
    uint16_t i;
    int rc;

    if (ctx->vault == NULL || !ctx->vault->unlocked || ctx->vault->store == NULL) {
        return VERTHYS_ERR_LOCKED;
    }
    if (count == 0) return VERTHYS_OK;
    for (i = 0; i < count; i++) {
        if (fmt_recs[i].name_len > VERTHYS_NAME_MAX_BYTES) {
            return VERTHYS_ERR_FORMAT;
        }
        /* 记录层单条明文上限：超过即拒绝（格式层 u32 允许更大，但
         * 记录 AEAD 预算不允许），避免半途失败被映射成 NOTFOUND。 */
        if (fmt_recs[i].data_size >= (uint64_t)VTY_RECORD_MAX_DATA) {
            return VERTHYS_ERR_FORMAT;
        }
    }

    in = (VtyRepoInput *)calloc(count, sizeof(VtyRepoInput));
    if (in == NULL) return VERTHYS_ERR_INTERNAL;
    for (i = 0; i < count; i++) {
        in[i].type = fmt_recs[i].type;
        in[i].name = fmt_recs[i].name;
        in[i].name_len = fmt_recs[i].name_len;
        in[i].data = fmt_recs[i].data;
        in[i].data_len = fmt_recs[i].data_size;
    }
    rc = vty_repo_add_many(ctx->vault, in, count, NULL);
    free(in);
    return verthys_api_container_map(rc);
}

VerthysResult Verthys_Import(VerthysHandle handle,
                         const char *import_path,
                         const char *password,
                         size_t      password_len)
{
    struct VerthysContext *ctx;
    uint8_t *blob = NULL;
    size_t   blob_size = 0;
    uint8_t  mek[VERTHYS_KEY_BYTES];
    uint8_t  dek[VERTHYS_KEY_BYTES];
    VerthysFmtMeta meta;
    VerthysFmtRecord *fmt_recs = NULL;
    uint16_t count = 0;
    VerthysResult import_rc;

    if (handle == NULL || import_path == NULL) return VERTHYS_ERR_INVALID;
    if (password == NULL && password_len != 0) return VERTHYS_ERR_INVALID;

    /* 导入路径纵深防御校验（目录穿越 / 系统目录 / 符号链接） */
    if (verthys_validate_transfer_path(import_path) != 0) {
        return VERTHYS_ERR_INVALID;
    }

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    /* 递归互斥锁保护 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockExclusive(ctx->api_mutex);
#endif

    /* 写操作入口统一失效查询缓存，防止 UAF */
    ctx_free_getrecord_cache(ctx);
    /* 写路径周期运行时哈希校验（30min 门控） */
    runtime_hash_verify_periodic();

    /* 导入文件始终是 v1 交换格式（与 Export 输出对称） */
    if (read_file(import_path, &blob, &blob_size) != 0) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_IO;
    }

    if (vfmt_parse_header(blob, blob_size, &meta) != 0) {
        free(blob);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_FORMAT;
    }

    if (keymanager_derive_master_export(mek, (const uint8_t *)password,
                                        password_len, meta.salt) != 0) {
        free(blob);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_INTERNAL;
    }

    if (vfmt_decrypt_meta(blob, blob_size, mek, &meta) != 0) {
        verthys_secure_zero(mek, sizeof mek);
        free(blob);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_AUTH;
    }

    if (keymanager_unwrap_dek(dek, meta.wrapped_dek, meta.dek_wrap_nonce, mek) != 0) {
        verthys_secure_zero(mek, sizeof mek);
        free(blob);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_AUTH;
    }

    if (vfmt_decrypt_records(blob, blob_size, &meta, dek,
                             &fmt_recs, &count) != 0) {
        verthys_secure_zero(mek, sizeof mek);
        verthys_secure_zero(dek, sizeof dek);
        free(blob);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
        return VERTHYS_ERR_AUTH;
    }

    free(blob);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);

    /* 单次提交批量 */
    import_rc = (ctx->fmt_version == VERTHYS_FMT_CONTAINER)
        ? verthys_api_container_import(ctx, fmt_recs, count)
        : VERTHYS_ERR_FORMAT;

    vfmt_free_records(fmt_recs, count);
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
    return import_rc;
}

/* 10. 修改主密码
 *
 * 口令槽重派生 + 密钥环重包裹 + DataRoot/元数据原子提交；
 * 单调用原子语义见 verthys_api_container_change_password。
 */
VerthysResult Verthys_ChangePassword(VerthysHandle handle,
                                 const char *old_pw, size_t old_len,
                                 const char *new_pw, size_t new_len)
{
    struct VerthysContext *ctx;
    VerthysResult rc;

    if (handle == NULL) return VERTHYS_ERR_INVALID;
    if (old_pw == NULL && old_len != 0) return VERTHYS_ERR_INVALID;
    if (new_pw == NULL && new_len != 0) return VERTHYS_ERR_INVALID;
    /* 空口令策略（禁止）：旧口令按解锁入口同拒；新口令若为空会造出
     * 空口令容器——解锁入口已拒空口令，改密到空口令即永久锁死，
     * 此处显式拒绝防自锁。 */
    if (old_len == 0 || new_len == 0) return VERTHYS_ERR_INVALID;

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    /* 改密属高危入口，执行反调试检测（命中即 KILL 上报） */
    if (anti_debug_check() != DBG_THREAT_NONE) {
        return VERTHYS_ERR_INTERNAL;
    }

    /* 递归互斥锁保护，防止并发重入 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) {
        AcquireSRWLockExclusive(ctx->api_mutex);
    }
#endif

    /* 写操作入口统一失效查询缓存，防止 UAF
     * 改密会重新派生口令槽并重包裹密钥环，旧密钥下解密的数据缓存
     * 必须立即失效，否则上层持有的旧借用指针将指向已释放的明文数据。 */
    ctx_free_getrecord_cache(ctx);
    /* 写路径周期运行时哈希校验（30min 门控） */
    runtime_hash_verify_periodic();

    if (ctx->fmt_version == VERTHYS_FMT_CONTAINER) {
        rc = verthys_api_container_change_password(ctx, old_pw, old_len,
                                            new_pw, new_len);
    } else {
        rc = VERTHYS_ERR_FORMAT;
    }
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
    return rc;
}
