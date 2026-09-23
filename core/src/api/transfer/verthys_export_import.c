/*
 * verthys_export_import.c — 导出 / 导入 / 修改主密码 模块（V3-only）
 *
 * 从 verthys_api.c 拆分而来（export / import / changepassword 模块）。
 * 包含以下公共 API 与其内部辅助函数：
 *   - Verthys_Export()        ：流式导出（v1 交换格式，跨设备兼容）
 *   - Verthys_Import()        ：导入合并到当前加密库
 *   - Verthys_ChangePassword()：修改主密码
 *
 *
 * 三个 API 的 V3 实现：
 *   - Export      ：LSM 快照迭代器两遍式收集（精确容量）+ Extent 内核态
 *                   按需解密流式写入（内存峰值与记录数解耦）；
 *   - Import      ：单事务批量（BEGIN → 逐条 WRITE_EXTENT + UPDATE_INDEX →
 *                   PREPARE/COMMIT/CONFIRM 收口，磁盘写入量 O(1) 重写）；
 *   - ChangePassword：VsbTxnV3 超级块事务保护 + CNG 密钥组重包裹（A/B/C
 *                   明文不变仅换 MEK 包装）+ MEK 句柄轮换 + 温缓存失效广播
 *                   （verthys_v3_change_password 完整实现）。
 */
#include "verthys_api_utils.h"
#include "verthys_internal.h"
#include "verthys.h"
#include "verthys_v3_lifecycle.h"      /* V3 上下文 + 事务收口 + 改密 */
#include "verthys_container_v3.h"      /* VsbTxnV3 / 超级块事务原语 */
#include "verthys_format.h"            /* v1 交换格式读写器（跨设备契约） */
#include "verthys_crypto.h"
#include "keymanager.h"
#include "anti_debug_v2.h"   /* 高危入口反调试检测 */
#include "runtime_hash.h"   /* 写路径周期运行时函数哈希校验 */

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
 * 流式分片写入修复（V3 迁移）
 *
 * 元数据快照（name/type/尺寸 + Extent 寻址字段）单遍收集，数据块明文
 * 不预载——get_data 回调逐条从 Extent 分区解密，release 回调清零释放。
 *
 * 内存峰值 = max(单条记录大小) + 16KB + 元数据数组大小，与记录总数
 * 解耦，万级照片库导出不 OOM。
 *
 * 原子性：流式写入过程中任一步骤失败 → 关闭并删除半成品文件，返回错误。
 * 安全性：明文数据用完即刻 verthys_secure_zero 清零释放，最小化明文驻留窗口。
 */

/* v3 导出条目快照：LSM 迭代器单遍收集的 Extent 寻址字段
 *（get_data 回调按需解密的最小集；name/type 等元数据在 fmt_recs 中） */
typedef struct {
    uint8_t  hash[VERTHYS_EXTENT_HASH_BYTES];  /* 内容寻址键 */
    uint64_t plaintext_size;                  /* Extent 明文长度（解密缓冲容量） */
} VerthysV3ExportEntry;

/* v3 流式导出回调上下文 */
typedef struct {
    struct VerthysContext *ctx;
    const VerthysV3ExportEntry *entries;  /* 条目快照（按导出顺序） */
    uint16_t count;                      /* 实际记录数 */
} VerthysV3ExportStreamCtx;

/* v3 流式导出 get_data 回调：按 idx 从 Extent 分区内核态解密单条记录明文
 *（一次一条，release 回调用完即清零释放——内存峰值 = max(单条记录) + 16KB） */
static int verthys_export_v3_get_data(uint16_t idx,
                                    uint8_t **out_data, size_t *out_size,
                                    void *user_data)
{
    VerthysV3ExportStreamCtx *sc = (VerthysV3ExportStreamCtx *)user_data;
    struct VerthysContext *ctx;
    VerthysContextV3 *v;
    uint8_t *data;
    size_t cap;
    VerthysResult r;

    if (sc == NULL || sc->ctx == NULL || idx >= sc->count) return -1;
    ctx = sc->ctx;
    v = ctx->v3;
    if (v == NULL || !v->subsystems_open) return -1;

    /* 解密缓冲（extent_get 契约：pt 非 NULL；空记录走 1 字节哑缓冲，
     * 成功后按实际长度 0 返回） */
    cap = (sc->entries[idx].plaintext_size > 0)
              ? (size_t)sc->entries[idx].plaintext_size : 1u;
    data = (uint8_t *)malloc(cap);
    if (data == NULL) return -1;

    r = verthys_extent_get(v->f, v->txn.extent_part, v->ext_idx,
                         sc->entries[idx].hash, data, &cap);
    if (r != VERTHYS_OK || cap != (size_t)sc->entries[idx].plaintext_size) {
        /* 解密失败 / 长度交叉不一致：上层整体失败，保证导出完整性 */
        verthys_secure_zero(data, cap);
        free(data);
        return -1;
    }
    *out_data = data;
    *out_size = cap;
    return 0;
}

/* v3 流式导出 release_data 回调：清零并释放单条记录明文 */
static void verthys_export_v3_release_data(uint16_t idx,
                                         uint8_t *data, size_t size,
                                         void *user_data)
{
    (void)idx;
    (void)user_data;
    if (data == NULL) return;
    if (size > 0) verthys_secure_zero(data, size);
    free(data);
}

VerthysResult Verthys_Export(VerthysHandle handle,
                         const char *export_path,
                         const char *password,
                         size_t      password_len)
{
    struct VerthysContext *ctx;
    VerthysContextV3 *v;
    VerthysLsmScanIter *it = NULL;
    VerthysV3ExportEntry *snap = NULL;
    VerthysFmtRecord *fmt_recs = NULL;
    uint64_t total = 0;
    uint16_t count = 0;
    uint8_t salt[VERTHYS_SALT_BYTES], mek[VERTHYS_KEY_BYTES], dek[VERTHYS_KEY_BYTES];
    int rc;

    if (handle == NULL || export_path == NULL) return VERTHYS_ERR_INVALID;
    if (password == NULL && password_len != 0) return VERTHYS_ERR_INVALID;

    /* 导出路径纵深防御校验（目录穿越 / 系统目录 / 符号链接） */
    if (verthys_validate_transfer_path(export_path) != 0) {
        return VERTHYS_ERR_INVALID;
    }

    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;

    if (ctx->fmt_version != VERTHYS_FMT_V3) return VERTHYS_ERR_FORMAT;

    /* 导出属高危入口，执行反调试检测（命中即 KILL 上报） */
    if (anti_debug_v2_check() != DBG_THREAT_NONE) {
        return VERTHYS_ERR_INTERNAL;
    }

    /* 递归互斥锁保护，防止并发重入 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) AcquireSRWLockShared(ctx->api_mutex);
#endif

    /* 导出始终使用 v1 交换格式（独立派生密钥，跨设备迁移） */
    verthys_random_bytes(salt, sizeof salt);
    if (keymanager_derive_master_export(mek, (const uint8_t *)password,
                                        password_len, salt) != 0) {
        /* 派生中途失败可能已写入部分密钥材料，一并清零 */
        verthys_secure_zero(mek, sizeof mek);
        verthys_secure_zero(salt, sizeof salt);
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        return VERTHYS_ERR_INTERNAL;
    }
    keymanager_generate_dek(dek);

    /* V3 路径 — LSM 快照迭代 + Extent 内核态按需解密流式写入。
     *
     * 容量控制（两遍式）：第一遍迭代器计数（含 65535 容量硬顶判定——
     * v1 导出格式 u16 计数，超出整体拒绝），第二遍精确分配收集。
     * estimate_records 为估算值（同 lid 多版本未 compaction 时偏高），
     * 不用作容量依据——两遍迭代保证数组精确、无截断风险。
     *
     * 迭代器契约：open/next 持 lsm 独占锁；两遍迭代先于流式写入完成并
     * close（回调期 extent_get 不触碰 lsm，无锁交叉）。 */
    v = ctx->v3;

    /* 就绪断言（渐进式解锁的最小可操作态同样可导出——subsystems_open
     * 已就绪；EXTENT 分区与索引均可随机访问） */
    if (v == NULL || !v->subsystems_open) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        verthys_secure_zero(salt, sizeof salt);
        verthys_secure_zero(mek, sizeof mek);
        verthys_secure_zero(dek, sizeof dek);
        return VERTHYS_ERR_LOCKED;
    }

    /* 第一遍：快照迭代计数（墓碑自动跳过——迭代器语义） */
    rc = verthys_lsm_scan_open(v->lsm, &it);
    if (rc != VERTHYS_OK) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        verthys_secure_zero(salt, sizeof salt);
        verthys_secure_zero(mek, sizeof mek);
        verthys_secure_zero(dek, sizeof dek);
        return (rc == VERTHYS_ERR_INTERNAL) ? VERTHYS_ERR_INTERNAL : rc;
    }
    {
        VerthysLsmEntry e;
        uint8_t name_buf[VERTHYS_NAME_MAX_BYTES];
        size_t name_len = 0;
        while ((rc = verthys_lsm_scan_next(it, &e, name_buf,
                                         sizeof(name_buf),
                                         &name_len)) == VERTHYS_OK) {
            total++;
        }
    }
    verthys_lsm_scan_close(it);
    it = NULL;
    if (rc != VERTHYS_ERR_NOTFOUND) {
        /* 迭代器中途损坏（AUTH/CORRUPT/INTERNAL 收敛）——导出整体拒绝，
         * 杜绝静默不完整导出（完整性红线） */
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        verthys_secure_zero(salt, sizeof salt);
        verthys_secure_zero(mek, sizeof mek);
        verthys_secure_zero(dek, sizeof dek);
        return rc;
    }

    /* v1 导出格式容量硬顶（拒绝而非静默截断） */
    if (total > 65535) {
#ifdef _WIN32
        if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
        verthys_secure_zero(salt, sizeof salt);
        verthys_secure_zero(mek, sizeof mek);
        verthys_secure_zero(dek, sizeof dek);
        return VERTHYS_ERR_EXPORT_TOO_MANY;
    }

    /* 第二遍：精确分配 + 元数据收集（name 深拷贝防回调期修改） */
    if (total > 0) {
        snap = (VerthysV3ExportEntry *)calloc((size_t)total,
                                            sizeof(VerthysV3ExportEntry));
        fmt_recs = (VerthysFmtRecord *)calloc((size_t)total,
                                            sizeof(VerthysFmtRecord));
        if (snap == NULL || fmt_recs == NULL) {
            if (snap) free(snap);
            if (fmt_recs) free(fmt_recs);
#ifdef _WIN32
            if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
            verthys_secure_zero(salt, sizeof salt);
            verthys_secure_zero(mek, sizeof mek);
            verthys_secure_zero(dek, sizeof dek);
            return VERTHYS_ERR_INTERNAL;
        }

        rc = verthys_lsm_scan_open(v->lsm, &it);
        if (rc != VERTHYS_OK) {
            free(snap);
            free(fmt_recs);
#ifdef _WIN32
            if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
            verthys_secure_zero(salt, sizeof salt);
            verthys_secure_zero(mek, sizeof mek);
            verthys_secure_zero(dek, sizeof dek);
            return rc;
        }
        {
            VerthysLsmEntry e;
            uint8_t name_buf[VERTHYS_NAME_MAX_BYTES];
            size_t name_len = 0;
            while ((rc = verthys_lsm_scan_next(it, &e, name_buf,
                                             sizeof(name_buf),
                                             &name_len)) == VERTHYS_OK) {
                if (count >= total) {
                    /* 快照窗口不一致（两遍间出现新条目——api_mutex 独占 +
                     * 单写者纪律下不可达的防御路径）：拒绝，杜绝截断导出 */
                    rc = VERTHYS_ERR_CORRUPT;
                    break;
                }
                fmt_recs[count].type = (uint8_t)e.type;
                fmt_recs[count].name_len = (uint16_t)e.name_len;
                fmt_recs[count].name =
                    (uint8_t *)malloc(e.name_len > 0 ? e.name_len : 1);
                if (fmt_recs[count].name == NULL) {
                    for (uint16_t k = 0; k < count; k++) {
                        if (fmt_recs[k].name) {
                            free(fmt_recs[k].name);
                            fmt_recs[k].name = NULL;
                        }
                    }
                    verthys_lsm_scan_close(it);
                    free(snap);
                    free(fmt_recs);
#ifdef _WIN32
                    if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
                    verthys_secure_zero(salt, sizeof salt);
                    verthys_secure_zero(mek, sizeof mek);
                    verthys_secure_zero(dek, sizeof dek);
                    return VERTHYS_ERR_INTERNAL;
                }
                if (e.name_len > 0) {
                    memcpy(fmt_recs[count].name, name_buf, e.name_len);
                }
                fmt_recs[count].data_size = e.data_size;
                fmt_recs[count].data = NULL;   /* 流式：回调按需解密 */

                memcpy(snap[count].hash, e.hash, VERTHYS_EXTENT_HASH_BYTES);
                snap[count].plaintext_size = e.plaintext_size;
                count++;
            }
        }
        verthys_lsm_scan_close(it);
        it = NULL;
        if (rc != VERTHYS_ERR_NOTFOUND) {
            for (uint16_t k = 0; k < count; k++) {
                if (fmt_recs[k].name) free(fmt_recs[k].name);
            }
            free(snap);
            free(fmt_recs);
#ifdef _WIN32
            if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
            verthys_secure_zero(salt, sizeof salt);
            verthys_secure_zero(mek, sizeof mek);
            verthys_secure_zero(dek, sizeof dek);
            return rc;
        }
    }

    /* 配置流式回调上下文 */
    VerthysV3ExportStreamCtx sc;
    sc.ctx = ctx;
    sc.entries = snap;
    sc.count = count;

    /* 流式写入：全程不预载明文，按需 Extent 解密单条记录 */
    rc = vfmt_write_streaming(salt, v->sb.argon2_mem_kib, v->sb.argon2_iters,
                              v->sb.argon2_parallel, mek, dek,
                              fmt_recs, count,
                              verthys_export_v3_get_data,
                              verthys_export_v3_release_data,
                              &sc, export_path);

    /* 释放元数据数组（name 为记录名明文，secure_zero 后释放） */
    if (fmt_recs) {
        for (uint16_t i = 0; i < count; i++) {
            if (fmt_recs[i].name) {
                verthys_secure_zero(fmt_recs[i].name, fmt_recs[i].name_len);
                free(fmt_recs[i].name);
            }
        }
        free(fmt_recs);
    }
    if (snap) {
        verthys_secure_zero(snap, (size_t)count * sizeof(VerthysV3ExportEntry));
        free(snap);
    }
    verthys_secure_zero(salt, sizeof salt);
    verthys_secure_zero(mek, sizeof mek);
    verthys_secure_zero(dek, sizeof dek);
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockShared(ctx->api_mutex);
#endif
    return rc == 0 ? VERTHYS_OK : (rc < 0 ? VERTHYS_ERR_INTERNAL : VERTHYS_ERR_IO);
}

/* 9. 导入（v1 交换格式文件，合并到当前加密库） */
/*
 * 单事务批量合并修复（V3 迁移）——BEGIN → 逐条
 * verthys_v3_add_record_in_txn（WRITE_EXTENT 内容寻址去重 +
 * UPDATE_INDEX，LID 顺序分配）→ PREPARE/COMMIT/CONFIRM 收口
 * （verthys_v3_txn_finish）。磁盘写入量与条目数解耦（法定人数提交 +
 * 索引/分区表覆写各一次）；任一条目失败 → verthys_v3_txn_abort 整体回滚
 * （MemTable/WAL 精确撤销 + Extent 引用还原），导入原子性。
 *
 * 前置校验：名称长度 ≤ VERTHYS_NAME_MAX_BYTES（LSM 条目约束，AddRecord
 * 同口径）——预检将坏文件挡在 BEGIN 前（FORMAT 拒绝，零副作用），
 * 杜绝半途回滚的无谓开销。api_mutex 已由公共入口独占持有。
 */
static VerthysResult verthys_api_v3_import(struct VerthysContext *ctx,
                                        const VerthysFmtRecord *fmt_recs,
                                        uint16_t count)
{
    VerthysContextV3 *v;
    VerthysResult rc;
    uint16_t i;

    if (ctx->v3 == NULL || !ctx->v3->subsystems_open) return VERTHYS_ERR_LOCKED;
    v = ctx->v3;

    for (i = 0; i < count; i++) {
        if (fmt_recs[i].name_len > VERTHYS_NAME_MAX_BYTES) {
            return VERTHYS_ERR_FORMAT;
        }
    }

    /* 空导入：无副作用直返（不产生空事务） */
    if (count == 0) return VERTHYS_OK;

    rc = verthys_txn_v3_begin(&v->txn);
    if (rc != VERTHYS_OK) return rc;

    for (i = 0; i < count; i++) {
        rc = verthys_v3_add_record_in_txn(v, (uint8_t)fmt_recs[i].type,
                                        fmt_recs[i].name,
                                        (size_t)fmt_recs[i].name_len,
                                        fmt_recs[i].data,
                                        (size_t)fmt_recs[i].data_size,
                                        NULL);
        if (rc != VERTHYS_OK) {
            verthys_v3_txn_abort(v);
            return rc;
        }
    }

    /* PREPARE → COMMIT → CONFIRM（COMMIT 后不可回滚，
     * confirm 失败由下次 open 的崩溃恢复幂等收尾——错误直接上抛） */
    return verthys_v3_txn_finish(v);
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

    if (ctx->fmt_version != VERTHYS_FMT_V3) return VERTHYS_ERR_FORMAT;

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

    /* 单事务批量导入（六阶段收口，原子性由 abort 路径保证） */
    import_rc = verthys_api_v3_import(ctx, fmt_recs, count);

    vfmt_free_records(fmt_recs, count);
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
    return import_rc;
}

/* 10. 修改主密码（V3-only） */
/*
 * 重派生 + 重包裹 + 法定人数原子提交。
 *
 * v1/v2 时代的"派生候选 MEK + memcmp 驻留密钥"验证范式对 V3 不适用
 * （密钥全部 CNG 内核态驻留，用户态无 MEK 可比）：旧口令验证走
 * wrapped_key_a 内核态解包试探（verthys_cng_km_verify_mek）。
 * 单调用原子语义 + 盘面/内存/km 三态一致的提交顺序约束见
 * verthys_v3_change_password（verthys_v3_lifecycle.c）。
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

    if (ctx->fmt_version != VERTHYS_FMT_V3) return VERTHYS_ERR_FORMAT;

    /* 改密属高危入口，执行反调试检测（命中即 KILL 上报） */
    if (anti_debug_v2_check() != DBG_THREAT_NONE) {
        return VERTHYS_ERR_INTERNAL;
    }

    /* 递归互斥锁保护，防止并发重入 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) {
        AcquireSRWLockExclusive(ctx->api_mutex);
    }
#endif

    /* 写操作入口统一失效查询缓存，防止 UAF
     * 改密操作会重新加密超级块（KEK+DEK 双层结构），旧密钥下解密的数据
     * 缓存必须立即失效，否则上层持有的旧借用指针将指向已释放的明文数据。 */
    ctx_free_getrecord_cache(ctx);
    /* 写路径周期运行时哈希校验（30min 门控） */
    runtime_hash_verify_periodic();

    rc = (ctx->v3 == NULL)
        ? VERTHYS_ERR_LOCKED
        : verthys_v3_change_password(ctx->v3, old_pw, old_len,
                                   new_pw, new_len);
#ifdef _WIN32
    if (ctx->api_mutex != NULL) ReleaseSRWLockExclusive(ctx->api_mutex);
#endif
    return rc;
}
