/*
 * verthys_api.c — 句柄生命周期与容器会话门面
 *
 *
 * 状态机：
 *   UNINIT  ──Unlock──→ UNLOCKED
 *   LOCKED  ──Unlock──→ UNLOCKED
 *   UNLOCKED──Lock────→ LOCKED
 *   任何非 UNLOCKED 状态下的增/查/删 → VERTHYS_ERR_LOCKED
 *
 * 内存安全：
 *   - 三密钥仅在 UNLOCKED 时驻留，Lock/Deinit 即刻 verthys_secure_zero
 *   - 目录树/记录段/Merkle 树同理
 *   - 局部密钥变量用后即擦
 */
#include "verthys_internal.h"

/* 内部模块头 */
#include "verthys_api_utils.h"      /* 共享底层工具 */
#include "vty_secure_state.h"       /* N2：安全状态目录预检 */
#include "vty_keymanager.h"       /* 会话（A/B 元数据 + 数据区） */
#include "vty_rotate.h"           /* 全库 DEK 轮换作业 */
#include "vty_secure_delete.h"    /* 代际派生文件零写删除 */
#include "vty_repo.h"             /* 待擦墓碑补偿 */
#include "verthys_api_container.h"          /* 记录/计数/校验/改密适配 */
#include "vty_caller_auth.h"        /* 调用方签名门（锚点维护接口） */

#include "vty_rollback.h"         /* 最后一个上下文注销时停止预置线程 */

/* 项目头 */
#include "verthys_crypto.h"
#include "vty_util.h"            /* vty_secure_zero */
#include "verthys_pepper.h"
#include "anti_debug.h"
#include "tls_loader.h"
#include "secure_allocator.h"   /* ctx 隔离堆生命周期 */
#include "job_isolation.h"
#include "cng_machine_key.h"
#include "system32_loader.h"
#include "hardware_binding.h"
#include "emergency.h"
#include "anti_inject.h"
#include "memory_guard.h"
#include "integrity.h"         /* 解锁入口 .vsec 验签 */
#include "runtime_hash.h"      /* 解锁后 + 周期运行时函数哈希校验 */
#include "hook_scan.h"         /* ntdll 导出基线/Hook 扫描（BOOT 判据） */
#include "verthys_security_runtime.h"  /* 周期巡检/句柄注册表/应急处理器 */
#include "vty_machine_limiter.h"
#include "defense_closure.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>            /* _fstat64 / st_mtime（落盘自查文件元数据） */

#include "verthys_diag.h"

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>               /* _O_RDWR/_O_BINARY */
#else
#include <unistd.h>
#endif

/* 1. 创建未初始化的加密库上下文 */
VerthysResult Verthys_Init(VerthysHandle *out_handle)
{
    if (out_handle == NULL) return VERTHYS_ERR_INVALID;
    /* 调用方签名校验必须先于任何初始化副作用。
     * 否则未授权进程仍可通过 Init 触发环境探测/防御模块初始化，
     * 把“拒绝”变成“拒绝但已泄漏宿主信息”。 */
    if (vty_caller_auth_check() != 0) return VERTHYS_ERR_UNAUTHORIZED;
    /* 先确认注册表有空位，避免分配完成后无法登记而泄漏上下文 */
    if (!verthys_ctx_registry_has_capacity()) return VERTHYS_ERR_RESOURCE_LIMIT;

    /* N2：安全状态目录预检必须先于任何状态相关副作用。失败返回专用错误码，
     * 避免运行期把“目录不可加固”折叠成通用的“安全模块不可用”。 */
    if (vty_secure_state_preflight() != VTY_OK) return VERTHYS_ERR_SECURITY_STATE;

    /* AVX2 软性检测：仅设置全局标志，不拒绝启动。
     * 密码库内部自动选择最优指令集路径，项目层不做硬性要求。 */
#ifdef _WIN32
    g_has_avx2 = verthys_check_avx2_support();
    if (g_has_avx2) {
        VERTHYS_DIAG_LOG("[VERTHYS] AVX2 detected: crypto operations will use AVX2-accelerated paths");
    } else {
        VERTHYS_DIAG_LOG("[VERTHYS] AVX2 not detected: falling back to SSE4.2/generic paths (libsodium handles runtime selection)");
    }
#else
    g_has_avx2 = 0;  /* 非 Windows 平台暂不支持 AVX2 检测 */
#endif

    if (verthys_crypto_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    /*
     * TLS 标志验证必须在 LoaderLock 释放后执行（tls_loader_init 不进入
     * DllMain，避免加载锁死锁）；本调用仅验证 TLS 回调标志（加载路径
     * 完整性）。
     */
    if (tls_loader_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    if (anti_debug_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    if (anti_debug_check() != 0) {
        /* 检测到调试器（高置信度）：KILL 信号已在 check 内部上报，
         * 此处不再作为初始化失败——应急体系将接管进程处置 */
        return VERTHYS_ERR_INTERNAL;
    }

    /*
     * Windows 加密 Worker 安全设计 — 动态防护初始化
     *
     * 加载顺序：
     *   1. TLS 回调（已在 DLL 加载时触发）→ 设置 g_tls_init_marker
     *   2. DllMain(DLL_PROCESS_ATTACH)（已在 DLL 加载时触发）→ DisableThreadLibraryCalls
     *   3. 此处 Verthys_Init → 防御模块 init + 闭环验证
     *
     * 失败处理：
     *   - 关键防御模块 init 失败 → 立即返回 VERTHYS_ERR_INTERNAL，Worker 拒绝启动
     *   - defense_closure_check 失败（有 FAILED 路径）→ 返回 VERTHYS_ERR_INTERNAL
     *
     * 注意：process_sandbox 必须由 Worker 进程本身在加载本 DLL 之前应用，
     *       此处不调用 process_sandbox_init（mitigation policy 是进程级，已应用即生效）。
     */
    /* Layer 1: 进程不可触碰化 */
    if (job_isolation_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    /* Layer 3: 固件与硬件绑定 */
    if (cng_machine_key_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    if (system32_loader_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    if (hardware_binding_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    /* Layer 4: Hook/注入对抗基线（TLS 标志已在上方验证） */
    /* 防注入基线：在所有模块与内部线程就绪之后采样，避免早期线程
     * 尚未建立时把基线记小。 */
    if (anti_inject_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }

    /* Layer 6: 最终闭环防御能力验证（BOOT 模式 — 任一关键路径 FAILED 即拒绝启动） */
    /* Hook 基线必须在 BOOT 闭环之前完成解析与首次扫描：闭环读取的是
     * 真实扫描结论，而不是"模块已加载"的名义状态。初始化/首次扫描
     * 失败只降级为 UNAVAILABLE，不拒绝启动。 */
    (void)hook_scan_init();
    (void)hook_scan_run_once();
    if (defense_closure_init() != 0) {
        return VERTHYS_ERR_INTERNAL;
    }
    if (defense_closure_check(DEFENSE_CHECK_BOOT, NULL) != 0) {
        /* 存在 FAILED 攻击路径，关键防御模块缺失，拒绝启动 */
        return VERTHYS_ERR_INTERNAL;
    }
    /* BOOT 闭环通过后启动 60s 周期扫描；启动失败只降级，不拒绝启动。 */
    (void)hook_scan_start_periodic();
    /* 反调试 60s / 反注入 300s 周期巡检（BOOT 成功后启动）。 */
    verthys_security_periodic_start();

    struct VerthysContext *ctx = (struct VerthysContext *)calloc(1, sizeof(struct VerthysContext));
    if (ctx == NULL) return VERTHYS_ERR_INTERNAL;
    ctx->state = VERTHYS_STATE_UNINIT;
    /* 分配并初始化 SRWLOCK 读写锁
     * 读操作以共享模式进入，写操作以独占模式进入，允许多个读取并发执行。
     * SRWLOCK 零初始化即可使用，无需 InitializeCriticalSection。 */
#ifdef _WIN32
    ctx->api_mutex = (SRWLOCK *)malloc(sizeof(SRWLOCK));
    if (ctx->api_mutex == NULL) {
        verthys_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return VERTHYS_ERR_INTERNAL;
    }
    InitializeSRWLock(ctx->api_mutex);
#endif

    /* 初始化胡椒托管框架
     * 按优先级加载胡椒：注入 > OS 托管(CNG/TPM) > 编译内嵌兜底。
     * 胡椒内存受 VirtualLock 保护，Deinit 时安全清零。
     * 失败不阻塞 Init（keymanager_derive_master 会再次尝试懒加载）。 */
    verthys_pepper_init();

    /* 密钥相关结构专用安全分配器的进程级预算。
     * 分配器实例由密钥对象经 secure_allocator_shared 懒创建：
     * 会话生命周期可能跨越 Deinit，不能绑定到单个上下文。 */
    (void)secure_allocator_budget_init(SECURE_ALLOC_DEFAULT_BUDGET_BYTES,
                                       NULL, NULL);

    /* 注册应急 DEGRADE 降级处理器。
     * 应急体系判定降级（如中置信度远程内存读取、窗口内重复信号）时，
     * 回调 verthys_emergency_lock_all：清空全部句柄密钥并锁定容器，
     * 进程保持存活，用户重新解锁即可恢复。 */
    emergency_set_degrade_handler(verthys_emergency_lock_all);

    /* 登记活动句柄（应急 DEGRADE 处理器寻址基础） */
    verthys_ctx_registry_add(ctx);

    *out_handle = (VerthysHandle)ctx;  /* 显式 cast（VerthysHandleImpl* ← VerthysContext*） */
    return VERTHYS_OK;
}

/* 2. 销毁上下文 */


VerthysResult Verthys_Deinit(VerthysHandle handle)
{
    if (handle == NULL) return VERTHYS_ERR_INVALID;
    struct VerthysContext *ctx = (struct VerthysContext *)handle;

    /* 先原子注销：只有成功移除的调用方才拥有释放权。
     *
     * 重复 Deinit 的入参已不在注册表，禁止继续解引用或释放；
     * 否则会形成双重释放/堆破坏。 */
    if (!verthys_ctx_registry_remove(ctx)) return VERTHYS_ERR_INVALID;
    /* 停止防转储低频巡逻 */
    memory_guard_patrol_stop();
    /* 停止 Hook 周期扫描（等待在途回调退出） */
    hook_scan_stop_periodic();
    /* 停止反调试/反注入周期巡检（等待在途回调退出） */
    verthys_security_periodic_stop();


    /* 会话收口：先释放轮换作业（其持有库引用），再清零并释放会话。 */
    if (ctx->rotate != NULL) {
        vty_rotate_abort(ctx->rotate);
        ctx->rotate = NULL;
    }
    /* Deinit 无法返回错误：尽力推进锚点，失败只输出固定诊断串
     * （不含路径/UUID/密钥），下次解锁补推进。 */
    if (ctx->vault != NULL && vty_vault_bulk_active(ctx->vault)) {
        if (vty_vault_bulk_commit(ctx->vault) != VTY_OK) {
            VERTHYS_DIAG_LOG("verthys: bulk anchor commit failed on deinit");
        }
    }
    vault_session_detach(ctx);

    if (ctx->state == VERTHYS_STATE_UNLOCKED) {
        ctx_zero_sensitive(ctx);
    }
    free(ctx->file_path);
    ctx->file_path = NULL;

    /* 销毁 SRWLOCK 读写锁
     * SRWLOCK 无需 DeleteCriticalSection，直接释放堆内存即可。 */
#ifdef _WIN32
    if (ctx->api_mutex != NULL) {
        free(ctx->api_mutex);
        ctx->api_mutex = NULL;
    }
#endif

    verthys_secure_zero(ctx, sizeof(*ctx));
    free(ctx);

    /* 最后一个上下文已注销：停止预置线程并清空进程内缓存，
     * 保证 DLL 卸载后不再有 TPM 调用。 */
    if (verthys_ctx_registry_empty()) {
        vty_rollback_shutdown();
    }
    return VERTHYS_OK;
}


/* 公共 API 接受显式长度；本层按 NUL 终结串取口令，长度不符时复制一份，
 * 避免调用方传入的长度与内存内容不一致导致越界或截断语义漂移。 */
static char *password_copy(const char *password, size_t len)
{
    char *copy;

    if (password == NULL || len == 0) return NULL;
    copy = (char *)malloc(len + 1u);
    if (copy == NULL) return NULL;
    memcpy(copy, password, len);
    copy[len] = '\0';
    return copy;
}

static void password_free(char *copy, size_t len)
{
    if (copy == NULL) return;
    verthys_secure_zero(copy, len + 1u);
    free(copy);
}

/* 解锁后统一维护：无论口令、keyfile、恢复码还是新建路径都经过 adopt，
 * 因此派生文件清理与待擦墓碑补偿不会因解锁方式不同而遗漏。
 *
 * 维护有界且不阻断解锁：失败项保留，下次解锁重试。 */
static int verthys_api_container_maintain(VtyVault *v, const char *path)
{
    uint64_t deleted = 0;
    uint64_t failed = 0;

    if (path != NULL) {
        /* 维护内部有时间预算，残留文件不会阻断解锁。 */
        (void)vty_secure_delete_maintain(path, &deleted, &failed);
    }
    if (v != NULL && v->unlocked && v->store != NULL) {
        (void)vty_repo_maintain_pending_scrub(v, 4096u, NULL, NULL);
        /* 待擦维护完成后再重建空闲区：仍带定位符的墓碑保持占用，
         * 其余不可达字节标为空闲，后续写入即可复用。失败时退回追加
         * 模式，不影响本次会话的可读性与删除语义。 */
        (void)vty_repo_space_sync(v);
    }
    /* 维护内的元数据提交失败会锁定会话；此时绝不能把句柄置为已解锁，
     * 否则用户看到解锁成功但所有操作返回 LOCKED。 */
    if (v != NULL && !v->unlocked) return VTY_E_POLICY;
    return VTY_OK;
}

static VerthysResult verthys_api_container_adopt(struct VerthysContext *ctx,
                                         const char *path, VtyVault *v)
{
    char *new_path;
    /* 旧会话若仍有轮换作业，先释放作业再释放库，避免悬空引用。 */
    if (ctx->rotate != NULL) {
        vty_rotate_abort(ctx->rotate);
        ctx->rotate = NULL;
    }
    /* 先准备新路径再替换会话：路径分配失败时旧会话保持完整，不出现
     * "库已释放但挂载点未更新"的中间态。 */
    new_path = dup_string(path);
    if (new_path == NULL) {
        vty_vault_free(v);
        return VERTHYS_ERR_RESOURCE_LIMIT;
    }
    {
        int mrc = verthys_api_container_maintain(v, path);

        if (mrc != VTY_OK || v == NULL || !v->unlocked) {
            free(new_path);
            if (v != NULL) vty_vault_free(v);
            return verthys_api_map_vty(mrc != VTY_OK ? mrc : VTY_E_POLICY);
        }
    }
    free(ctx->file_path);
    ctx->file_path = new_path;
    vault_session_attach(ctx, v);
    ctx->fmt_version = VERTHYS_FMT_CONTAINER;
    ctx->preset = VERTHYS_PRESET_BALANCED;
    ctx->warm_cache_enabled = 0;
    ctx->state = VERTHYS_STATE_UNLOCKED;
    return VERTHYS_OK;
}

/* 容器专用入口必须先确认 magic：把异种格式文件交给解析器会产生
 * 误导性的槽错误，而且不利于把“拒绝旧格式”作为独立攻击面验证。 */
static VerthysResult verthys_api_container_require_magic(const char *path)
{
    FILE *peek;
    uint8_t header[8];
    size_t n;

    if (path == NULL) return VERTHYS_ERR_INVALID;
    peek = fopen(path, "rb");
    if (peek == NULL) return VERTHYS_ERR_IO;
    n = fread(header, 1, sizeof(header), peek);
    fclose(peek);
    if (n < sizeof(header)) return VERTHYS_ERR_FORMAT;
    if (detect_format(header, n) != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;
    return VERTHYS_OK;
}

static VerthysResult verthys_api_container_unlock(struct VerthysContext *ctx,
                                           const char *path,
                                           const char *password, size_t len,
                                           const char *keyfile_path)
{
    VtyVault *v = NULL;
    char *pw;
    int rc;

    if (password == NULL || len == 0) return VERTHYS_ERR_INVALID;
    /* 公共契约只保证 password 指向 len 字节，不保证 NUL 终结；
     * 本层按 NUL 串取口令，必须先复制再调用，避免越界读。 */
    pw = password_copy(password, len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;
    /* keyfile 由 C 层在本进程内读取；路径只是入参，字节不进入调用方。 */
    rc = (keyfile_path != NULL)
             ? vty_vault_open_keyfile(path, pw, keyfile_path, &v)
             : vty_vault_open(path, pw, &v);
    password_free(pw, len);
    if (rc != VTY_OK) return verthys_api_map_vty(rc);
    return verthys_api_container_adopt(ctx, path, v);
}

/*
 * 解锁入口二进制验签。
 * 构建期 .vsec 基准比对：进程内按自身文件元数据指纹缓存结论，
 * 指纹不变直接回放（解锁热路径零节 I/O），指纹变化（自更新/篡改）
 * 强制重算。未配置（开发构建）时为空操作；验签失败 = 二进制被篡改
 * （高置信度）→ KILL 级上报已发出，返回 CORRUPT 拒绝解锁。
 */
static VerthysResult verthys_api_unlock_integrity_precheck(void)
{
    if (integrity_verify_startup() != 0) return VERTHYS_ERR_CORRUPT;
    return VERTHYS_OK;
}

/*
 * 解锁成功后的进程级安全钩子：
 * 运行时函数级哈希全量校验（.rhat 真表，防内存补丁注入跳转）。
 * 失配 = 进程内存被篡改（高置信度）→ KILL 级应急（进程终止，
 * 绝不带着已解锁密钥继续运行）。置于信号复位之前：篡改态不做任何
 * "恢复性"钩子。
 */
static void verthys_api_unlock_post_hooks(void)
{
    runtime_hash_verify();
    emergency_clear_signals();
    /* 解锁后一次完整注入巡检（线程/APC/窗口钩子/模块白名单）。 */
    (void)anti_inject_check_all();
    (void)hook_scan_run_once();   /* 解锁后立即刷新 Hook 证据 */
    memory_guard_patrol_start();
}

/* 新建：只创建容器。恢复码在创建响应里
 * 一次性返回，调用方确认后必须清零自己的副本。 */
VerthysResult Verthys_V4Create(VerthysHandle handle,
                               const char *verthys_path,
                               const char *password,
                               size_t password_len,
                               char *recovery_text,
                               size_t recovery_cap)
{
    struct VerthysContext *ctx;
    VtyVault *v = NULL;
    char *pw = NULL;
    FILE *probe;
    int rc;

    if (handle == NULL || verthys_path == NULL || password == NULL ||
        recovery_text == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (password_len == 0 || recovery_cap < VTY_RECOVERY_TEXT_BUF) {
        return VERTHYS_ERR_INVALID;
    }
    ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;

    probe = fopen(verthys_path, "rb");
    if (probe != NULL) {
        fclose(probe);
        return VERTHYS_ERR_EXISTS;
    }

    /* 同 Unlock：显式长度参数不保证 NUL 终结，统一复制后再进入下层。 */
    pw = password_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;
    rc = vty_vault_create(verthys_path, pw, &v, recovery_text, recovery_cap);
    password_free(pw, password_len);
    if (rc != VTY_OK) return verthys_api_map_vty(rc);
    return verthys_api_container_adopt(ctx, verthys_path, v);
}

VerthysResult Verthys_V4CreateKeyfile(VerthysHandle handle,
                                      const char *verthys_path,
                                      const char *password,
                                      size_t password_len,
                                      const char *keyfile_path,
                                      char *recovery_text,
                                      size_t recovery_cap)
{
    struct VerthysContext *ctx;
    VtyVault *v = NULL;
    char *pw = NULL;
    FILE *probe;
    int rc;

    if (handle == NULL || verthys_path == NULL || password == NULL ||
        keyfile_path == NULL || recovery_text == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    if (password_len == 0 || recovery_cap < VTY_RECOVERY_TEXT_BUF) {
        return VERTHYS_ERR_INVALID;
    }
    ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;

    /* 库路径先做快速失败：避免先落一个 keyfile 再发现库已存在。 */
    probe = fopen(verthys_path, "rb");
    if (probe != NULL) {
        fclose(probe);
        return VERTHYS_ERR_EXISTS;
    }

    pw = password_copy(password, password_len);
    if (pw == NULL) return VERTHYS_ERR_RESOURCE_LIMIT;
    rc = vty_vault_create_keyfile_file(verthys_path, pw, keyfile_path, &v,
                                       recovery_text, recovery_cap);
    password_free(pw, password_len);
    if (rc != VTY_OK) return verthys_api_map_vty(rc);
    return verthys_api_container_adopt(ctx, verthys_path, v);
}

/* 口令解锁共用路径：V4Unlock 与 V4UnlockKeyfile 仅 keyfile 参数不同。
 * 锁序与钩子顺序保持：整段解锁（含成功后置钩子）在 api_mutex 独占锁内完成。 */
static VerthysResult verthys_api_unlock_with_password(struct VerthysContext *ctx,
                                                      const char *verthys_path,
                                                      const char *password,
                                                      size_t password_len,
                                                      const char *keyfile_path)
{
    VerthysResult rc;

    verthys_ctx_lock_exclusive(ctx);
    rc = verthys_api_container_require_magic(verthys_path);
    if (rc == VERTHYS_OK) {
        rc = verthys_api_container_unlock(ctx, verthys_path, password, password_len,
                                          keyfile_path);
        if (rc == VERTHYS_OK) {
            verthys_api_unlock_post_hooks();
        }
    }
    verthys_ctx_unlock_exclusive(ctx);
    return rc;
}

VerthysResult Verthys_V4Unlock(VerthysHandle handle,
                               const char *verthys_path,
                               const char *password,
                               size_t password_len)
{
    struct VerthysContext *ctx;
    VerthysResult ir;

    if (handle == NULL || verthys_path == NULL || password == NULL ||
        password_len == 0) {
        return VERTHYS_ERR_INVALID;
    }
    ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;

    ir = verthys_api_unlock_integrity_precheck();
    if (ir != VERTHYS_OK) return ir;

    /* SECURE = preferred：解锁前尝试内核保护，失败不阻断用户态解锁。 */
    vty_machine_limiter_kernel_guard_apply_preset();

    return verthys_api_unlock_with_password(ctx, verthys_path, password,
                                            password_len, NULL);
}

VerthysResult Verthys_V4UnlockKeyfile(VerthysHandle handle,
                                      const char *verthys_path,
                                      const char *password,
                                      size_t password_len,
                                      const char *keyfile_path)
{
    struct VerthysContext *ctx;
    VerthysResult ir;

    if (handle == NULL || verthys_path == NULL || password == NULL ||
        keyfile_path == NULL || password_len == 0) {
        return VERTHYS_ERR_INVALID;
    }
    ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;

    ir = verthys_api_unlock_integrity_precheck();
    if (ir != VERTHYS_OK) return ir;

    /* SECURE = preferred：解锁前尝试内核保护，失败不阻断用户态解锁。 */
    vty_machine_limiter_kernel_guard_apply_preset();

    return verthys_api_unlock_with_password(ctx, verthys_path, password,
                                            password_len, keyfile_path);
}

VerthysResult Verthys_V4UnlockRecovery(VerthysHandle handle,
                                       const char *verthys_path,
                                       const char *recovery_text)
{
    struct VerthysContext *ctx;
    VtyVault *v = NULL;
    VerthysResult rc;
    VerthysResult ir;
    int vrc;

    if (handle == NULL || verthys_path == NULL || recovery_text == NULL) {
        return VERTHYS_ERR_INVALID;
    }
    ctx = (struct VerthysContext *)handle;
    if (ctx->state == VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_INVALID;

    ir = verthys_api_unlock_integrity_precheck();
    if (ir != VERTHYS_OK) return ir;

    /* SECURE = preferred：解锁前尝试内核保护，失败不阻断用户态解锁。 */
    vty_machine_limiter_kernel_guard_apply_preset();

    verthys_ctx_lock_exclusive(ctx);
    rc = verthys_api_container_require_magic(verthys_path);
    if (rc == VERTHYS_OK) {
        vrc = vty_vault_open_recovery(verthys_path, recovery_text, &v);
        rc = (vrc == VTY_OK) ? verthys_api_container_adopt(ctx, verthys_path, v)
                             : verthys_api_map_vty(vrc);
        if (rc == VERTHYS_OK) {
            verthys_api_unlock_post_hooks();
        }
    }
    verthys_ctx_unlock_exclusive(ctx);
    return rc;
}

/* 4. 锁定 */
/*
 * Lock 同步路径只做必要操作：释放轮换作业、会话释放（密钥与明文清零）、
 * 借用指针缓存释放。耗时任务（全盘校验）不在此路径，由独立完整性
 * 校验接口按需执行。
 */
VerthysResult Verthys_Lock(VerthysHandle handle)
{
    struct VerthysContext *ctx;
    VerthysResult commit_rc = VERTHYS_OK;

    if (handle == NULL) return VERTHYS_ERR_INVALID;
    ctx = (struct VerthysContext *)handle;
    if (ctx->state != VERTHYS_STATE_UNLOCKED) return VERTHYS_ERR_LOCKED;
    if (ctx->file_path == NULL) return VERTHYS_ERR_INVALID;
    if (ctx->fmt_version != VERTHYS_FMT_CONTAINER) return VERTHYS_ERR_FORMAT;

    /* 锁定路径：
     *   1. 释放轮换作业（其持有库引用）；
     *   2. 会话释放（密钥与明文清零）；
     *   3. GetRecord 借用指针缓存释放。 */
    verthys_ctx_lock_exclusive(ctx);

    if (ctx->rotate != NULL) {
        vty_rotate_abort(ctx->rotate);
        ctx->rotate = NULL;
    }
    if (verthys_bulk_defer_active(ctx)) {
        int rc = vty_vault_bulk_commit(ctx->vault);
        if (rc != VTY_OK) commit_rc = verthys_api_map_vty(rc);
    }
    vault_session_detach(ctx);
    ctx_free_getrecord_cache(ctx);
    ctx->state = VERTHYS_STATE_LOCKED;

    verthys_ctx_unlock_exclusive(ctx);

    /* 密钥清零后解除内核保护；失败只影响耗时，不影响锁定结果。 */
    vty_machine_limiter_kernel_guard_release();
    /* 锚点提交失败不影响密钥清零；返回错误让调用方提示
     * “回退锚点未推进”，下次解锁会补推进。 */
    return commit_rc;
}
