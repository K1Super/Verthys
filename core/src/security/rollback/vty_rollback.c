/*
 * vty_rollback.c — 库文件版本回退检测实现
 *
 * 状态布局（版本字段 2）：header(16) + N×{uuid(16), generation(8), witnessSlot(1),
 * witnessFp(32)} + MAC(32) + 设备根 blob(290)。
 *
 * MAC 密钥由设备根封装，覆盖 header、条目与 blob——篡改任意字节或把状态
 * 文件拷到其它机器都会解封/比对失败，从而 fail-closed。
 *
 * 见证身份：SHA-256(domain || 设备根哈希 || 容器 UUID)，与状态文件路径无关。
 *
 * 状态文件固定落在 KnownFolder\Verthys\Security；旧布局与旧路径一律按
 * 损坏 fail-closed，不做迁移。
 * 状态缺失时：见证域仍有密钥，或容器 generation >= 2（已建立锚点），
 * 均按回退拒绝；只有 generation < 2 且无见证才视为首次运行。
 */
#include "vty_rollback.h"
#include "vty_secure_state.h"
#include "vty_util.h"
#include "vty_kdf.h"
#include "vty_device_root.h"
#include "vty_tpm_witness.h"
#include "vty_witness_pool.h"
#include "vty_rollback_internal.h"

#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>  /* sprintf_s */


/* 测试隔离钩子：仅 VERTHYS_TEST_HOOKS=1 的攻击回归构建编译。
 * 生产构建不包含此代码，状态路径不可由环境变量改写。 */
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
static int g_test_env_hook = 0;
#endif

char g_state_path[VTY_SECURE_STATE_PATH_BYTES];
int g_test_path = 0;
int g_initialized = 0;
int g_enabled = 1;

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
static uint32_t g_test_max_entries = 0;
int g_crash_point = 0;
static int g_test_env_checked = 0;
static int g_test_explicit_enable = 0;
#endif

/* 逻辑容量：生产固定 64；测试构建可缩小以覆盖容量分支。
 * 状态文件的物理布局始终按 VTY_ROLLBACK_MAX_ENTRIES 解释。 */
uint32_t vty_rb_max_entries(void)
{
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    if (g_test_max_entries > 0 &&
        g_test_max_entries <= VTY_ROLLBACK_MAX_ENTRIES) {
        return g_test_max_entries;
    }
#endif
    return VTY_ROLLBACK_MAX_ENTRIES;
}

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
/* 攻击回归在没有 PCP 见证的 runner 上仍需验证非见证攻击面：允许测试
 * 入口显式关闭回滚锚点。只编译进测试钩子构建，生产 DLL 不识别该变量；
 * 调用方显式 set_enabled(1) 优先于环境开关。 */
void vty_rb_apply_test_disable(void)
{
    char value[8];
    DWORD n;

    if (g_test_env_checked) return;
    g_test_env_checked = 1;
    if (g_test_explicit_enable) return;
    n = GetEnvironmentVariableA("VERTHYS_TEST_ROLLBACK_DISABLED", value,
                                sizeof(value));
    if (n == 1 && value[0] == '1') g_enabled = 0;
}
#else
#define vty_rb_apply_test_disable() ((void)0)
#endif

void vty_rollback_set_enabled(int enabled)
{
    g_enabled = enabled ? 1 : 0;
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    if (enabled) g_test_explicit_enable = 1;
#endif
}

int vty_rollback_enabled(void)
{
    return g_enabled;
}


static int resolve_paths(void)
{
    int rc;

    if (g_state_path[0] != '\0') return VTY_OK;
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    {
        char test_dir[VTY_SECURE_STATE_PATH_BYTES];
        DWORD test_len = GetEnvironmentVariableA("VERTHYS_TEST_STATE_DIR",
                                                 test_dir, sizeof(test_dir));
        if (test_len > 0 && test_len < sizeof(test_dir)) {
            if (sprintf_s(g_state_path, sizeof(g_state_path),
                          "%s\\rollback.state", test_dir) < 0) {
                return VTY_E_INVALID;
            }
            g_test_path = 1;
            g_test_env_hook = 1;
            return VTY_OK;
        }
#if defined(VERTHYS_TEST_REQUIRE_ISOLATION) && VERTHYS_TEST_REQUIRE_ISOLATION
        /* 自动化测试构建缺少隔离目录时拒绝运行：绝不回落到生产状态目录。 */
        return VTY_E_POLICY;
#else
        /* dev 构建的测试钩子只用于机器预算旁路，同时必须能操作用户真实
         * 容器；测试入口自行注入隔离目录，因此这里允许回落到生产路径。 */
#endif
    }
#endif
    rc = vty_secure_state_file_path("rollback.state", g_state_path,
                                    sizeof(g_state_path));
    if (rc != VTY_OK) return rc;
    return VTY_OK;
}

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
int vty_rollback_set_path_for_test(const char *path)
{
    size_t len;

    if (path == NULL) return VTY_E_INVALID;
    len = strlen(path);
    if (len == 0 || len >= sizeof(g_state_path)) return VTY_E_INVALID;
    memcpy(g_state_path, path, len + 1);
    g_test_path = 1;
    g_test_env_hook = 0;
    /* 切换状态文件时清除测试注入，避免容量/崩溃点泄漏到后续用例。 */
    g_test_max_entries = 0;
    g_crash_point = 0;
    return VTY_OK;
}
#else
/* 生产构建保留同名桩：测试工具仍可链接，但任何路径覆盖都被拒绝，
 * 生产 DLL 不能在运行期被改写状态目录。 */
int vty_rollback_set_path_for_test(const char *path)
{
    (void)path;
    return VTY_E_POLICY;
}
#endif

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
/* 若测试环境在首次默认解析之后才注入状态目录，把已解析的默认路径
 * 丢弃并重新按注入目录解析；显式 set_path_for_test 不受影响。 */
static void maybe_apply_test_dir(void)
{
    char dir[VTY_SECURE_STATE_PATH_BYTES];
    DWORD n;

    if (g_test_env_hook || g_test_path) return;
    n = GetEnvironmentVariableA("VERTHYS_TEST_STATE_DIR", dir, sizeof(dir));
    if (n == 0 || n >= sizeof(dir)) return;
    g_state_path[0] = '\0';
    (void)resolve_paths();
}
#endif

int vty_rollback_init(void)
{
    int rc = vty_device_root_init();

    if (rc != VTY_OK) return rc;
    vty_rb_apply_test_disable();
#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
    maybe_apply_test_dir();
#endif
    rc = resolve_paths();
    if (rc != VTY_OK) return rc;
    g_initialized = 1;
    return VTY_OK;
}

int vty_rb_witness_id(const uint8_t vault_uuid[VTY_UUID_BYTES],
                      uint8_t id[VTY_UUID_BYTES])
{
    /* 见证身份始终绑定设备根 + 容器 UUID；测试隔离只改状态目录，
     * 不改身份，否则同一次运行内创建/保存会落到不同见证域。 */
    return vty_secure_state_identity_rollback(vault_uuid, id);
}

HANDLE vty_rb_lock_state(void)
{
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"Local\\Verthys.RollbackState");
    if (mutex == NULL) return NULL;
    if (WaitForSingleObject(mutex, 5000) != WAIT_OBJECT_0) {
        CloseHandle(mutex);
        return NULL;
    }
    return mutex;
}

void vty_rb_unlock_state(HANDLE mutex)
{
    if (mutex == NULL) return;
    ReleaseMutex(mutex);
    CloseHandle(mutex);
}

/* 只在持有 RollbackState 互斥量时访问。 */
rb_verified_entry g_verified[RB_G0A_VERIFIED_MAX];
uint8_t g_dirty[RB_G0A_DIRTY_MAX][VTY_UUID_BYTES];
int g_dirty_used[RB_G0A_DIRTY_MAX];

HANDLE vty_rollback_lock_state(void)
{
    return vty_rb_lock_state();
}

void vty_rollback_unlock_state(void *mutex)
{
    vty_rb_unlock_state((HANDLE)mutex);
}

#if defined(VERTHYS_TEST_HOOKS) && VERTHYS_TEST_HOOKS
void vty_rollback_set_max_entries_for_test(uint32_t max_entries)
{
    g_test_max_entries =
        (max_entries > 0 && max_entries <= VTY_ROLLBACK_MAX_ENTRIES)
            ? max_entries
            : 0;
}

void vty_rollback_reset_path_for_test(void)
{
    g_state_path[0] = '\0';
    g_test_path = 0;
    g_initialized = 0;
    g_test_env_hook = 0;
}
#endif

void vty_rollback_shutdown(void)
{
    HANDLE lock;

    /* 先停止后台线程（其可能正在建键），再清空进程内状态。 */
    vty_witness_pool_shutdown();
    /* 与在途提交串行化；取不到锁（进程收尾异常）时仍清空，
     * 避免把缓存与脏标记留在进程内存里。 */
    lock = vty_rb_lock_state();
    vty_rb_cache_clear();
    vty_secure_zero(g_dirty, sizeof(g_dirty));
    memset(g_dirty_used, 0, sizeof(g_dirty_used));
    if (lock != NULL) vty_rb_unlock_state(lock);
}
