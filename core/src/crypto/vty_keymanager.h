/*
 * vty_keymanager.h — 库创建、解锁与会话（内部，不导出）
 *
 * 双包裹采用“异或分享”实现真正的 AND：口令槽只解出一半，设备槽
 * 解出另一半；任一单边都不足以还原容器 DEK。恢复槽独立承载完整
 * Keyring，仅用于换机与灾难恢复。
 */
#ifndef VTY_KEYMANAGER_H
#define VTY_KEYMANAGER_H

#include "vty_types.h"
#include "vty_keyfile.h"
#include "vty_format.h"
#include "vty_keyslot.h"
#include "vty_recovery.h"
#include "vty_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 模块会话状态。MDEK 只在已启用且解锁后驻留；未启用模块的 MDEK
 * 仍在 body Keyring 中，不复制到这里，避免出现两份可读密钥。 */
typedef struct {
    uint8_t uuid[VTY_UUID_BYTES];
    uint8_t enabled;                /* 描述符 bit0；与模块表一致 */
    uint8_t unlocked;               /* 仅本会话；锁定/释放必须清零 */
    uint8_t has_recovery;           /* 描述符 slot_count=3 */
    uint8_t deleted;                /* 描述符 bit1；无 MDEK/无数据 */
    uint8_t mdek[VTY_KEY_BYTES];    /* 仅 unlocked=1 时有效 */
} VtyModuleState;

typedef struct VtyVault {
    VtyHeader header;
    VtySlot slots[VTY_MAX_SLOTS];
    uint32_t slot_count;
    char path[1024];          /* 库文件路径，保存时只覆盖非活动元数据副本 */
    uint8_t kc[VTY_KEY_BYTES];
    VtyKeyring keyring;
    VtyDataRootLocator data_root;  /* 与 Keyring kind 4 同源 */
    uint8_t data_root_hash[VTY_HASH_BYTES];
    VtyStore *store;               /* 解锁期间持有的数据区会话（可写） */
    VtyModuleState modules[VTY_MODULE_COUNT];
    uint8_t k_recovery[VTY_KEY_BYTES]; /* 仅恢复会话驻留的恢复 KEK */
    uint8_t recovery_mode;             /* 1=本次会话由恢复码打开 */
    uint8_t keyfile_digest[VTY_KEY_BYTES]; /* KEYFILE 会话缓存的 KDF 第二输入摘要 */
    uint8_t keyfile_digest_set;            /* 1=keyfile_digest 有效；锁定/释放清零 */
    uint32_t active_copy;          /* 已认证且代最高的副本下标 */
    uint8_t no_rollback_anchor;    /* 1=保存不推进回退锚点（轮换临时库构建） */
    uint8_t rotate_pending;        /* 1=本会话正作为轮换源库（拒绝写操作） */
    int unlocked;
    uint32_t mem_kib;
    uint32_t iters;
    uint32_t parallel;
} VtyVault;

/* 绑定事实（非敏感）：供防御状态查询使用，不含任何密钥材料。 */
typedef struct {
    uint32_t unlocked;      /* 1=会话已解锁 */
    uint32_t device_bound;  /* 1=设备根槽存在 */
    uint32_t pcr_bound;     /* 1=PCR 槽存在 */
} VtyVaultBindingInfo;

/* 读取会话绑定事实（纯读）。v 为 NULL 时返回 VTY_E_INVALID 并清零输出。 */
int vty_vault_binding_info(const VtyVault *v, VtyVaultBindingInfo *out);

/* 创建：默认 Argon2id 参数（64 MiB / 3 / 1），生成恢复码文本 */
__declspec(noinline) int vty_vault_create(const char *path, const char *password,
                     VtyVault **out,
                     char *recovery_text, size_t recovery_cap);

/* 创建：自定义 KDF 参数；低于下限直接 VTY_E_KDF_WEAK */
int vty_vault_create_ex(const char *path, const char *password,
                        uint32_t mem_kib, uint32_t iters, uint32_t parallel,
                        VtyVault **out,
                        char *recovery_text, size_t recovery_cap);

/* 创建：额外启用 PCR 绑定（pcr_select 为 PCR0–23 位图，需 TPM 可用）。
 * 无 TPM/PCR 不可读时返回 VTY_E_TPM，且不留下半成品库。 */
int vty_vault_create_pcr(const char *path, const char *password,
                         uint32_t pcr_select,
                         VtyVault **out,
                         char *recovery_text, size_t recovery_cap);

/* 创建：附带 keyfile 因子（VKFL v1 blob）。keyfile 只进入用户槽 KDF 输入，
 * 不写独立槽、不落盘到容器；blob 缺失时等价标准创建。 */
int vty_vault_create_keyfile(const char *path, const char *password,
                             const uint8_t *keyfile_blob, size_t keyfile_len,
                             VtyVault **out,
                             char *recovery_text, size_t recovery_cap);

/* 创建：生成 VKFL v1 文件并以其作为 KDF 第二输入。keyfile_path 必须
 * 不存在（独占新建）；库创建失败时不留下 keyfile 文件。 */
int vty_vault_create_keyfile_file(const char *path, const char *password,
                                  const char *keyfile_path, VtyVault **out,
                                  char *recovery_text, size_t recovery_cap);

/* 轮换：以恢复会话的 K_recovery 与源库槽参数重建一个新库文件。
 * 前置：src->unlocked && src->recovery_mode，且 K_recovery 非零。
 * 保留 vault_uuid；epoch = src->epoch + 1；generation = src->generation + 1；
 * 恢复槽复用源槽 salt/Argon2id 参数、换新 nonce 并用 K_recovery 重封新
 * K_c，使旧恢复码继续有效。用户/设备槽按 password（可选 keyfile 摘要）
 * 重封到当前设备根。临时库构建期间不推进回退锚点。
 * flags 必须已由调用方剔除 VTY_FLAG_PCR / VTY_FLAG_MODULE_M1；
 * KEYFILE 标志置位时 keyfile_digest_or_null 必须非空。 */
int vty_vault_create_from_kc(const VtyVault *src, const char *path,
                             const char *password,
                             const uint8_t kc[VTY_KEY_BYTES],
                             uint16_t flags,
                             const uint8_t *keyfile_digest_or_null,
                             VtyVault **out);

/* 构造 PCR 槽：创建/覆盖该库 PCR 密钥 → measure → 用当前 K_c 密封。
 * 只构造槽，不改会话与磁盘；失败时删除刚创建的密钥。供 PCR 启用与
 * 轮换提交阶段复用，避免两处实现漂移。 */
int vty_vault_pcr_slot_prepare(VtyVault *v, uint32_t pcr_select,
                               VtySlot *slot);

/* 在已解锁库上启用 PCR 绑定。调用方必须先完成恢复码二次认证；
 * 本函数只负责密码学操作，不承担用户确认职责。 */
int vty_vault_pcr_enable(VtyVault *v, uint32_t pcr_select);

/* 关闭 PCR 绑定（保留设备根槽）。调用方必须先完成口令 + 恢复码二次认证。 */
int vty_vault_pcr_disable(VtyVault *v);

/* 用当前 PCR 重新绑定：供恢复码解锁后、设备环境已变化时使用。
 * 成功后才更新槽并落盘；失败时槽保持旧值，需再次用恢复码重试。 */
int vty_vault_pcr_reseal(VtyVault *v);

/* 轮换提交崩溃安全：PCR 密钥名按库 UUID 派生，重封会覆盖旧私钥。提交在
 * 覆盖后、原子替换前被杀时，源库口令解锁会卡在 PCR 门；因此覆盖前必须
 * 先在 <库路径>.vtyrotj 落盘恢复日志（库 UUID/源代/PCR 策略摘要）。
 * start 成功后 token 持有排他句柄：并发进程既读不到也删不掉日志，进程
 * 退出时句柄由系统释放。end 关闭句柄，delete_file=1 时删除日志。
 * 日志不是密钥材料，不含任何可直接解锁库的机密。 */
int vty_vault_rotate_journal_start(const VtyVault *v, void **token);
void vty_vault_rotate_journal_end(void **token, int delete_file);

/* 恢复判定：日志存在且与当前文件严格匹配（UUID、代、PCR 位图、策略摘要
 * 一致，且当前平台 PCR 仍等于策略摘要）时返回 1。只有在这种情况下才允许
 * 把 PCR 门推迟到会话建立后用当前 K_c 重封；平台状态变化时不得自动重绑，
 * 否则等于绕过 PCR 策略。 */
int vty_vault_rotate_journal_match(const VtyVault *v);

/* 陈旧判定：日志 UUID 匹配但源代严格小于当前文件代时返回 1。用于“替换
 * 已完成、日志未删除”的崩溃残留：此时重封已无意义，原文件才是最新状态，
 * 可直接清理日志；源代等于或大于文件代时不清理（可能是回退现场）。 */
int vty_vault_rotate_journal_stale(const VtyVault *v);

/* 删除陈旧日志（尽力而为）。正在提交的进程持有排他句柄时删除会失败，
 * 不影响其流程。 */
void vty_vault_rotate_journal_clear(const VtyVault *v);

/* 标准解锁：口令 + 设备根（AND），失败不产生任何持久副作用 */
__declspec(noinline) int vty_vault_open(const char *path, const char *password, VtyVault **out);

/* 带 keyfile 解锁：KEYFILE 标志置位时必须提供 VKFL 文件路径；
 * 标志未置位时忽略 keyfile_path，保持标准口令路径。 */
__declspec(noinline) int vty_vault_open_keyfile(const char *path, const char *password,
                           const char *keyfile_path, VtyVault **out);

/* 已解锁会话：启用/轮换 keyfile（只重封用户槽，不重写数据）。 */
int vty_vault_keyfile_enable(VtyVault *v, const char *password,
                             const uint8_t *new_blob, size_t new_len);

/* 已解锁会话：生成新的 VKFL 到 new_keyfile_path 并启用/轮换 keyfile。
 * 新文件独占创建；重封失败时删除刚生成的文件。 */
int vty_vault_keyfile_enable_file(VtyVault *v, const char *password,
                                  const char *new_keyfile_path);

/* 已解锁会话：关闭 keyfile（校验当前 keyfile 后重封用户槽、清标志）。 */
int vty_vault_keyfile_disable(VtyVault *v, const char *password,
                              const char *keyfile_path);

/* 恢复解锁：仅恢复码 */
__declspec(noinline) int vty_vault_open_recovery(const char *path, const char *recovery_text,
                            VtyVault **out);

/* 恢复会话重绑容器 user/device 槽。
 * 前置：v->unlocked && v->recovery_mode。
 * keyfile_digest_or_null：
 *   - 容器 KEYFILE 标志置位时必须提供；
 *   - 未置位时必须为 NULL。
 * 成功：重封 user/device 槽 + 自检 + save_meta；失败：v->unlocked=0。 */
int vty_vault_reseal_device(VtyVault *v, const char *password,
                            const uint8_t *keyfile_digest_or_null);

/* 同上，但从 keyfile_path 读取 VKFL 摘要；容器未启用 keyfile 时忽略路径。 */
int vty_vault_reseal_device_file(VtyVault *v, const char *password,
                                 const char *keyfile_path);

/* 轮换补录：恢复会话未持有 keyfile 摘要时，用当前容器口令 + keyfile 验证
 * user 槽，成功后缓存摘要供后续轮换使用。仅 KEYFILE 标志置位的已解锁库
 * 可用；失败不修改会话（摘要不会部分写入）。VKFL 格式错误返回
 * VTY_E_KEYFILE_INVALID；keyfile/口令不匹配返回 VTY_E_AUTH。 */
int vty_vault_attach_keyfile(VtyVault *v, const char *keyfile_path,
                             const char *password);

/* 轮换口令：epoch 不变，只重封口令/设备槽；不轮换恢复码。 */
int vty_vault_rotate_password(VtyVault *v, const char *new_password);

/* 恢复码轮换：当前口令 + 旧码，重封恢复槽与全部已启用模块的 recovery 槽；
 * new_text 只在成功时写入，容量必须 >= VTY_RECOVERY_TEXT_BUF。 */
int vty_vault_recovery_rotate(VtyVault *v,
                              const char *password,
                              const char *old_recovery_text,
                              char *new_text, size_t new_cap);

/* 校验当前口令（改密前的旧口令确认）。不改变会话状态。 */
int vty_vault_verify_password(VtyVault *v, const char *password);

/* 落盘：只写非活动 A/B 副本，回读并认证成功后推进回退锚点；
 * 锁定时拒绝。 */
int vty_vault_save(VtyVault *v);

/* 仅验证 user 槽（不依赖设备根）：删除等根级操作要求当前容器口令。 */
int vty_vault_verify_user_password(const VtyVault *v, const char *password);

/* 仅验证恢复码：打开恢复槽并确认解出的 K_c 与当前会话一致。
 * 失败不改变会话；用于 PCR 启停/重密封前的二次认证。 */
int vty_vault_verify_recovery(const VtyVault *v, const char *recovery_text);

/* 查询 PCR 绑定状态与位图；不需要恢复码。 */
int vty_vault_pcr_info(const VtyVault *v,
                       uint32_t *out_enabled, uint32_t *out_select);

/* 取模块 MDEK：未启用从 Keyring kind 3 读；已启用且未解锁返回 E_POLICY；
 * 已删除模块返回 E_POLICY。系统记录域的保留 UUID 在本函数内改取系统密钥，
 * 使安全/密钥管理记录不依赖任何可启用模块。 */
int vty_vault_module_key(const VtyVault *v, const uint8_t module_uuid[VTY_UUID_BYTES],
                         uint8_t key_out[VTY_KEY_BYTES]);

/* 系统记录域密钥：SK = HKDF-SHA256(K_c, "verthys/v4/system-record")。
 * 仅用于安全/密钥管理记录；容器解锁即可派生，不落盘，调用方用后清零。 */
int vty_vault_system_key(const VtyVault *v, uint8_t key_out[VTY_KEY_BYTES]);

/* 系统记录域的保留模块 UUID：ASCII "VTYSYSTEM" + 8 字节零填充，
 * 不进入模块表，不可启用、不可删除。 */
extern const uint8_t vty_system_module_uuid[VTY_UUID_BYTES];

/* 按 module_index 取 MDEK，策略同 vty_vault_module_key。 */
int vty_vault_module_key_index(const VtyVault *v, uint32_t index,
                               uint8_t key_out[VTY_KEY_BYTES]);

/* 取第 index 个模块 UUID；越界返回 VTY_E_INVALID */
int vty_vault_module_uuid(const VtyVault *v, uint32_t index,
                          uint8_t out[VTY_UUID_BYTES]);

/* 提交数据区并同步 DataRoot/locator；不写元数据。 */
int vty_vault_commit_store(VtyVault *v);

/* 落盘自查结果（结构元数据，不含密钥/明文）。 */
typedef struct {
    uint64_t file_size;
    uint64_t mtime_ms;
    uint32_t header_magic;
    uint32_t header_version;
} VtyPersistCheck;

/* 校验会话的 DataRoot 根段仍在盘上且摘要一致；不做全树遍历。 */
int vty_vault_verify_persist(const VtyVault *v, VtyPersistCheck *out);

/* 元数据提交：假设调用方已完成 vty_vault_commit_store，不再重复提交
 * 数据区；用于模块事务保证“一次数据提交 + 一次元数据提交”。 */
int vty_vault_save_meta(VtyVault *v);

void vty_vault_lock(VtyVault *v);
void vty_vault_free(VtyVault *v);

#ifdef __cplusplus
}
#endif

#endif /* VTY_KEYMANAGER_H */
