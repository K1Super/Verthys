/*
 * key_separation.h — 三权分立密钥 CNG 内核托管（内部模块，不导出）
 *
 *
 *   CNG 托管设计的优势：密钥原始字节自始至终不进入用户态内存，用户态仅持有
 *   BCRYPT_KEY_HANDLE 句柄值。即使完整 Dump 进程内存，拿到的只是
 *   0x00000000ABCD1234 这样的句柄 ID，在内核地址空间之外无任何映射意义。
 *
 *   三份密钥（A/B/C）各自调用 BCryptGenerateSymmetricKey 生成内核句柄，
 *   存入 HANDLE 数组。解密调用时，C 层调用 BCryptDecrypt 在内核态完成运算，
 *   返回明文。敏感内存页保护（VirtualLock）仅需保护句柄数组和中间态密文，
 *   不再需要保护密钥本体。紧急熔断时，调用 BCryptDestroyKey 销毁内核句柄，
 *   而非 HeapDestroy 覆写用户态堆页。
 *
 *   收益：密钥材料在用户态的内存驻留时间从"始终存在"降为"从未存在"，
 *   攻击面收缩了一个数量级。
 *
 * 算法选择：AES-256-GCM（CNG 原生支持）。
 *   - 密钥：32 字节（BCRYPT_AES_256_KEY_SIZE）
 *   本模块仅承担密钥的内核托管与生命周期（安装/休眠/销毁）；AEAD
 *   运算由 verthys_crypto_cng 的 AEAD 上下文完成（nonce 由内部
 *   Interlocked 计数器生成，不依赖调用方纪律）。acquire 仅供仍需
 *   原始密钥字节的过渡调用方使用，应尽快迁移。
 *
 * 角色定义（与旧版保持兼容）：
 *   A 密钥（索引解密）：赋予扫描模块及索引读取模块，仅能解密头部映射表，
 *                       无权限读取实体数据块。
 *   B 密钥（数据解密）：赋予文件预览和导出模块，仅能解密数据区内容，
 *                       无法修改容器索引和超级块。
 *   C 密钥（超级块提交）：仅由事务原子提交模块持有，非提交期间保持休眠。
 */
#ifndef VERTHYS_KEY_SEPARATION_H
#define VERTHYS_KEY_SEPARATION_H

#include <stdint.h>
#include <stddef.h>

/* 密钥用途枚举（与旧版保持二进制兼容） */
typedef enum {
    KEY_ROLE_INDEX   = 0,  /* A 密钥：索引解密（头部映射表） */
    KEY_ROLE_DATA    = 1,  /* B 密钥：数据解密（文件内容） */
    KEY_ROLE_COMMIT  = 2,  /* C 密钥：超级块提交（事务原子提交） */
    KEY_ROLE_COUNT
} KeyRole;

/* ---------- CNG AES-256-GCM 参数 ---------- */
#define KEYSEP_KEY_BYTES        32u   /* AES-256 密钥长度 */

/*
 * 初始化三权分立密钥模块（CNG 内核托管）。
 * 打开共享 AES-GCM 算法提供者（BCryptOpenAlgorithmProvider +
 * BCRYPT_CHAIN_MODE_GCM），初始化三个空槽位的 BCRYPT_KEY_HANDLE。
 * 返回 0 成功，非 0 失败。
 * 幂等：重复调用返回 0。
 */
int key_separation_init(void);

/*
 * 安装指定角色的密钥（导入到 CNG 内核句柄）。
 *   role: 密钥用途
 *   key:  32 字节密钥明文（调用后调用方应清零自己的副本；本函数内部
 *         也会 verthys_secure_zero 入参，确保明文不留调用方栈/堆）
 * 调用 BCryptGenerateSymmetricKey 将密钥字节导入内核，用户态仅持有
 * BCRYPT_KEY_HANDLE 句柄。密钥原始字节随即从用户态内存消失。
 *
 * 对 C 角色（KEY_ROLE_COMMIT）：安装后立即进入休眠（active=0），
 * 必须经 key_separation_activate_commit 唤醒后方可导出。
 */
int key_separation_install(KeyRole role, const uint8_t key[KEYSEP_KEY_BYTES]);

/*
 * 获取指定角色的密钥（向后兼容：从 CNG 句柄导出原始密钥字节）。
 *   role: 密钥用途
 *   out_key: 输出 32 字节明文密钥（写入调用方栈缓冲区）
 * 返回 0 成功，非 0 失败（密钥未安装 / C 角色休眠 / 导出失败）。
 *
 * ★ 过渡期声明：
 *   本接口使密钥字节返回用户态，与"CNG 内核托管"承诺相悖。
 *   当前仓库中无任何调用点；全量接线（V3 容器密文迁移）时删除。
 *   新的密钥消费方一律使用 verthys_crypto_cng 的 AEAD 上下文。
 * 调用方（如存在）使用后必须立即 key_separation_release(out_key) 清零。
 */
int key_separation_acquire(KeyRole role, uint8_t out_key[KEYSEP_KEY_BYTES]);

/*
 * 防御闭环判据：查询是否有任一角色已安装内核密钥。
 * 返回 1 = 至少一个角色已安装；0 = 全部未安装。
 * defense_closure 的 MEM_DUMP 路径据此区分 BLOCKED/DEGRADED。
 */
int key_separation_any_installed(void);

/*
 * 释放（清零）借用的密钥副本。
 * 调用方使用完密钥后必须调用此函数清零栈缓冲区。
 */
void key_separation_release(uint8_t key[KEYSEP_KEY_BYTES]);

/*
 * 激活 C 密钥（超级块提交）。
 * 仅在事务提交时调用，提交完成后调用 key_separation_deactivate_commit()。
 * 非提交期间 C 密钥保持休眠状态（active=0，acquire 导出拒绝放行）。
 *
 * 与旧版差异：CNG 句柄本身无 PAGE_NOACCESS 等价语义，此处以 active 标志
 * 实现逻辑休眠；BCRYPT_KEY_HANDLE 仍驻留内核，但本模块在 acquire 路径上
 * 强制校验 active 状态，休眠态调用将立即返回失败。
 */
int key_separation_activate_commit(void);

/*
 * 停用 C 密钥（恢复休眠）。
 * 事务提交完成后立即调用。
 */
int key_separation_deactivate_commit(void);

/*
 * 销毁全部密钥（紧急零化 / 熔断）。
 * 对三个 BCRYPT_KEY_HANDLE 调用 BCryptDestroyKey 销毁内核句柄，
 * 关闭算法提供者。句柄值失效后，内核中密钥材料随之释放。
 *
 * 与旧版差异：不再需要多轮覆写用户态堆页（密钥从未进入用户态），
 * BCryptDestroyKey 即等价于"内核态密钥销毁"。
 */
void key_separation_purge_all(void);

#endif /* VERTHYS_KEY_SEPARATION_H */
