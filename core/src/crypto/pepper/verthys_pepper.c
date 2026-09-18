/*
 * verthys_pepper.c — 胡椒安全托管框架实现
 *
 * ★ Comprehensive_optimization 第八部分 一.2：胡椒的安全托管框架
 *
 * 实现要点：
 *   - 胡椒内存受 VirtualLock 保护，防止换页泄露
 *   - OS 托管：CNG 机器密钥 RSA-OAEP 加密后持久化到 %APPDATA%
 *   - Shamir 秘密共享：GF(2^8) 多项式拆分/重建，支持胡椒恢复卡
 *   - 编译内嵌胡椒兜底：保证零配置开箱即用
 *   - 胡椒永不通过函数返回，仅返回借用指针
 *
 * 三层胡椒来源（按优先级降序）：
 *   1. 注入胡椒（verthys_pepper_inject）
 *   2. OS 托管胡椒（CNG 持久化机器密钥）
 *   3. 编译内嵌胡椒（keymanager.c static 常量，兜底）
 */
#include "verthys_pepper.h"
#include "verthys_internal.h"  /* verthys_secure_zero, verthys_lock_memory */
#include "cng_machine_key.h"
#include "hardware_binding.h"  /* system_instance 标识 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlobj.h>  /* SHGetFolderPath */
#endif

/* ===================================================================== *
 *                编译内嵌胡椒（兜底默认值，与 keymanager.c 一致）         *
 *                                                                    *
 *   当 OS 托管不可用且未注入外部胡椒时，回退到此常量。                   *
 *   保证零配置场景向后兼容，不破坏已存在的 .verthys 文件。                 *
 * ===================================================================== */
static const uint8_t VERTHYS_PEPPER_COMPILED[VERTHYS_KEY_BYTES] = {
    0x9c, 0x4d, 0xa2, 0xb8, 0x5f, 0xe1, 0x73, 0x6a,
    0xd7, 0x0c, 0x4b, 0x9e, 0xa8, 0x21, 0xf5, 0x3c,
    0x6e, 0x87, 0x10, 0xd4, 0x2a, 0xb9, 0xc5, 0x7f,
    0xe3, 0x08, 0x91, 0x4d, 0xa6, 0x2c, 0xb7, 0x5e
};

/* ===================================================================== *
 *                        胡椒模块状态                                    *
 * ===================================================================== */
static int g_pepper_initialized = 0;
static int g_pepper_locked = 0;              /* 内存是否已 VirtualLock */
static int g_pepper_source_error = 0;        /* ★ §4.2：来源失败标志（禁止兜底回退） */
static uint8_t g_pepper[VERTHYS_KEY_BYTES];    /* 当前生效的胡椒（受保护内存） */
static VerthysPepperSource g_pepper_source = VERTHYS_PEPPER_SOURCE_NONE;

#define VERTHYS_PEPPER_FILE_VERSION  0x0002u
#define VERTHYS_PEPPER_FILE_V1_BYTES (4 + 2 + 2 + CMK_OAEP_LABEL_BYTES + CMK_RSA_CIPHER_BYTES)
#define VERTHYS_PEPPER_FILE_BYTES    (4 + 2 + 2 + 8 + CMK_OAEP_LABEL_BYTES + CMK_RSA_CIPHER_BYTES)
#define VERTHYS_PEPPER_FP_BYTES      8u

/* verthys_pepper_load_from_os 返回码 */
#define VERTHYS_PEPPER_LOAD_OK          0    /* 成功 */
#define VERTHYS_PEPPER_LOAD_UNAVAILABLE (-1) /* 来源不可用（无文件/CNG 不可用）→ 允许兜底 */
#define VERTHYS_PEPPER_LOAD_SOURCE_ERR  (-2) /* 来源失败（文件存在但解不开/指纹不符）→ 禁止兜底 */

/* ---------- 来源指纹计算（方案 §4.2） ---------- */

/*
 * source_fingerprint = HMAC-SHA256(domain_key, label || cipher) 前 8 字节。
 * 域分离密钥为固定常量（完整性用途，非秘密）——指纹用于自检/交叉验证，
 * 防篡改本身由 CNG 机器密钥解包（认证失败即拒绝）保障。
 */
static int pepper_file_fingerprint(const uint8_t *label, const uint8_t *cipher,
                                   uint8_t out_fp[VERTHYS_PEPPER_FP_BYTES])
{
    static const uint8_t K_FP_DOMAIN_KEY[VERTHYS_KEY_BYTES] = {
        'v', 'e', 'r', 't', 'h', 'y', 's', '/', 'p', 'e', 'p', 'p', 'e', 'r', '-',
        'f', 'p', '-', 'v', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    uint8_t mac[VERTHYS_HMAC_BYTES];

    /* 拼接 label||cipher 到连续缓冲后单次 HMAC */
    uint8_t material[CMK_OAEP_LABEL_BYTES + CMK_RSA_CIPHER_BYTES];
    memcpy(material, label, CMK_OAEP_LABEL_BYTES);
    memcpy(material + CMK_OAEP_LABEL_BYTES, cipher, CMK_RSA_CIPHER_BYTES);

    int rc = verthys_hmac_sha256(mac, K_FP_DOMAIN_KEY,
                               material, sizeof(material));
    verthys_secure_zero(material, sizeof(material));
    if (rc != 0) {
        return -1;
    }
    memcpy(out_fp, mac, VERTHYS_PEPPER_FP_BYTES);
    verthys_secure_zero(mac, sizeof(mac));
    return 0;
}

/* OS 托管胡椒持久化文件魔数与版本 */
#define VERTHYS_PEPPER_FILE_MAGIC    0x50505656u  /* "VVPP" 小端 */
/*
 * ★ 方案 §4.2（P0-B 根治）：v2 头部新增 source_type 与 source_fingerprint。
 *   v2 布局（304B）：magic(4) + version(2) + source_type(2) +
 *                   fingerprint(8) + label(32) + cipher(256)
 *   - source_type：生成时的胡椒来源（VerthysPepperSource 取值）
 *   - source_fingerprint：HMAC-SHA256(domain_key, label||cipher) 前 8 字节，
 *     与机器密钥解包结果交叉验证，检测文件损坏/篡改/错拿
 *   v1（296B）：magic + version=1 + reserved(2) + label + cipher；
 *   v1 文件解包成功后自动升级为 v2（补写指纹，方案 §9 pepper 迁移）。
 */
/* ===================================================================== *
 *                GF(2^8) 运算（Shamir 秘密共享）                        *
 *                                                                    *
 *   不可约多项式：x^8 + x^4 + x^3 + x + 1 = 0x11B                     *
 *   加法/减法 = XOR                                                   *
 *   乘法 = Russian Peasant + 规约                                     *
 *   逆元 = 费马小定理 a^254（因 |GF(2^8)*| = 255，a^255 = 1）         *
 * ===================================================================== */

/* GF(2^8) 乘法 */
static uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;  /* 规约：x^8 = x^4 + x^3 + x + 1 */
        b >>= 1;
    }
    return p;
}

/* GF(2^8) 幂运算（快速幂） */
static uint8_t gf256_pow(uint8_t a, uint8_t e)
{
    uint8_t r = 1;
    uint8_t base = a;
    while (e > 0) {
        if (e & 1) r = gf256_mul(r, base);
        base = gf256_mul(base, base);
        e >>= 1;
    }
    return r;
}

/* GF(2^8) 乘法逆元：a^254（费马小定理，a^255 = 1 for a != 0） */
static uint8_t gf256_inv(uint8_t a)
{
    if (a == 0) return 0;  /* 0 无逆元，返回 0（调用方须保证 a != 0） */
    return gf256_pow(a, 0xFE);  /* 254 = 255 - 1 */
}

/* GF(2^8) 多项式求值：f(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[deg]*x^deg
 * coeffs[0] = 秘密（f(0)），degree = threshold - 1 */
static uint8_t gf256_poly_eval(const uint8_t *coeffs, uint8_t deg, uint8_t x)
{
    /* Horner 法则：f(x) = ((...((coeffs[deg]*x + coeffs[deg-1])*x + ...) + coeffs[0]) */
    uint8_t result = coeffs[deg];
    for (int i = (int)deg - 1; i >= 0; i--) {
        result = gf256_mul(result, x) ^ coeffs[i];
    }
    return result;
}

/* ===================================================================== *
 *                    胡椒内存保护                                        *
 * ===================================================================== */
static void pepper_lock_memory(void)
{
#ifdef _WIN32
    if (!g_pepper_locked) {
        if (verthys_lock_memory(g_pepper, sizeof(g_pepper)) == 0) {
            g_pepper_locked = 1;
        }
        /* 锁定失败不致命：胡椒仍在内存中，仅换页风险增加 */
    }
#endif
}

static void pepper_unlock_memory(void)
{
#ifdef _WIN32
    if (g_pepper_locked) {
        verthys_unlock_memory(g_pepper, sizeof(g_pepper));
        g_pepper_locked = 0;
    }
#endif
}

/* ===================================================================== *
 *                    OS 托管胡椒持久化路径                                *
 * ===================================================================== */
static int pepper_get_storage_path(char *out_path, size_t path_cap)
{
#ifdef _WIN32
    char appdata[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata) != S_OK) {
        return -1;
    }
    int n = snprintf(out_path, path_cap, "%s\\Verthys", appdata);
    if (n < 0 || (size_t)n >= path_cap) return -1;

    /* 确保 Verthys 目录存在 */
    CreateDirectoryA(out_path, NULL);
    /* ERROR_ALREADY_EXISTS 是正常情况，不视为错误 */

    n = snprintf(out_path, path_cap, "%s\\Verthys\\pepper.bin", appdata);
    if (n < 0 || (size_t)n >= path_cap) return -1;
    return 0;
#else
    const char *home = getenv("HOME");
    if (home == NULL) return -1;
    int n = snprintf(out_path, path_cap, "%s/.verthys/pepper.bin", home);
    if (n < 0 || (size_t)n >= path_cap) return -1;
    return 0;
#endif
}

/* ===================================================================== *
 *                    OS 托管胡椒加载/保存（CNG）                         *
 * ===================================================================== */
int verthys_pepper_load_from_os(void)
{
    if (g_pepper_initialized) {
        /* 已初始化，不覆盖（除非来源优先级更高，由 init 协调） */
        return VERTHYS_PEPPER_LOAD_OK;
    }
#ifdef _WIN32
    char path[MAX_PATH];
    if (pepper_get_storage_path(path, sizeof(path)) != 0) {
        return VERTHYS_PEPPER_LOAD_UNAVAILABLE;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        /* 文件不存在：首次使用，生成新胡椒并持久化 */
        verthys_random_bytes(g_pepper, VERTHYS_KEY_BYTES);
        pepper_lock_memory();
        g_pepper_source = VERTHYS_PEPPER_SOURCE_OS;
        g_pepper_initialized = 1;
        /* 持久化到 OS 存储（P1-1 修复：重试一次抗瞬时故障，
         * 仍失败置来源错误态——禁止静默降级到编译内嵌胡椒。
         * 内存中的随机胡椒即被清零丢弃，避免"高熵胡椒未持久化
         * 却被零熵常量替换"的安全性浪费；上层以 VERTHYS_ERR_
         * PEPPER_SOURCE 明确报错，用户修复环境后重试即可。） */
        if (verthys_pepper_save_to_os() != 0 &&
            verthys_pepper_save_to_os() != 0) {
            verthys_secure_zero(g_pepper, sizeof(g_pepper));
            g_pepper_source = VERTHYS_PEPPER_SOURCE_NONE;
            g_pepper_initialized = 0;
            g_pepper_source_error = 1;
            return VERTHYS_PEPPER_LOAD_SOURCE_ERR;
        }
        return VERTHYS_PEPPER_LOAD_OK;
    }

    uint8_t buf[VERTHYS_PEPPER_FILE_BYTES];
    size_t rd = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    int is_v1 = (rd == VERTHYS_PEPPER_FILE_V1_BYTES);
    int is_v2 = (rd == VERTHYS_PEPPER_FILE_BYTES);
    if (!is_v1 && !is_v2) {
        verthys_secure_zero(buf, sizeof(buf));
        return VERTHYS_PEPPER_LOAD_SOURCE_ERR;
    }

    /* 校验魔数与版本 */
    uint32_t magic = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
                     ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    if (magic != VERTHYS_PEPPER_FILE_MAGIC) {
        verthys_secure_zero(buf, sizeof(buf));
        return VERTHYS_PEPPER_LOAD_SOURCE_ERR;
    }
    uint16_t ver = (uint16_t)buf[4] | ((uint16_t)buf[5] << 8);
    if (is_v1 && ver != 0x0001u) {
        verthys_secure_zero(buf, sizeof(buf));
        return VERTHYS_PEPPER_LOAD_SOURCE_ERR;
    }
    if (is_v2 && ver != VERTHYS_PEPPER_FILE_VERSION) {
        verthys_secure_zero(buf, sizeof(buf));
        return VERTHYS_PEPPER_LOAD_SOURCE_ERR;
    }

    /* 提取 label / cipher（v1 无 source_type/fingerprint 字段） */
    const uint8_t *label;
    const uint8_t *cipher;
    if (is_v2) {
        /* ★ §4.2：先验指纹 HMAC(label||cipher)，与机器密钥解包交叉验证 */
        const uint8_t *fp_stored = buf + 8;
        label  = buf + 8 + VERTHYS_PEPPER_FP_BYTES;
        cipher = label + CMK_OAEP_LABEL_BYTES;

        uint8_t fp_calc[VERTHYS_PEPPER_FP_BYTES];
        if (pepper_file_fingerprint(label, cipher, fp_calc) != 0 ||
            memcmp(fp_stored, fp_calc, VERTHYS_PEPPER_FP_BYTES) != 0) {
            verthys_secure_zero(fp_calc, sizeof(fp_calc));
            verthys_secure_zero(buf, sizeof(buf));
            return VERTHYS_PEPPER_LOAD_SOURCE_ERR;
        }
        verthys_secure_zero(fp_calc, sizeof(fp_calc));
    } else {
        label  = buf + 8;
        cipher = buf + 8 + CMK_OAEP_LABEL_BYTES;
    }

    /*
     * CNG 解密：校验 system_instance label 一致性（防跨设备迁移）。
     * ★ §4.2：文件存在但解包失败（机器密钥丢失/被重建/硬件指纹变更）
     * → 来源错误，禁止静默兜底（原 P0-B 缺陷的根治点）。
     */
    if (!cng_machine_key_is_available()) {
        verthys_secure_zero(buf, sizeof(buf));
        return VERTHYS_PEPPER_LOAD_SOURCE_ERR;
    }
    uint8_t pepper[VERTHYS_KEY_BYTES];
    if (cng_machine_key_unwrap(cipher, pepper, label) != 0) {
        verthys_secure_zero(buf, sizeof(buf));
        verthys_secure_zero(pepper, sizeof(pepper));
        return VERTHYS_PEPPER_LOAD_SOURCE_ERR;
    }

    memcpy(g_pepper, pepper, VERTHYS_KEY_BYTES);
    verthys_secure_zero(pepper, sizeof(pepper));
    verthys_secure_zero(buf, sizeof(buf));
    pepper_lock_memory();
    g_pepper_source = VERTHYS_PEPPER_SOURCE_OS;
    g_pepper_initialized = 1;
    g_pepper_source_error = 0;

    /* v1 → v2 原地升级：补写 source_type + 指纹（best-effort，失败不阻断） */
    if (is_v1) {
        (void)verthys_pepper_save_to_os();
    }
    return VERTHYS_PEPPER_LOAD_OK;
#else
    /* 非 Windows 平台：OS 托管不可用，回退 */
    return VERTHYS_PEPPER_LOAD_UNAVAILABLE;
#endif
}

int verthys_pepper_save_to_os(void)
{
#ifdef _WIN32
    if (!g_pepper_initialized) return -1;
    if (!cng_machine_key_is_available()) return -1;

    char path[MAX_PATH];
    if (pepper_get_storage_path(path, sizeof(path)) != 0) return -1;

    /* 获取 system_instance 标识作为 OAEP label（绑定机器） */
    uint8_t label[CMK_OAEP_LABEL_BYTES];
    if (hardware_binding_get_hash(label) != 0) {
        /* 获取失败：用全零 label（降级，但仍 CNG 加密） */
        memset(label, 0, sizeof(label));
    }

    /* CNG 加密胡椒 */
    uint8_t cipher[CMK_RSA_CIPHER_BYTES];
    if (cng_machine_key_wrap(g_pepper, cipher, label) != 0) {
        return -1;
    }

    /* ★ §4.2：计算来源指纹 HMAC(label||cipher) 前 8 字节 */
    uint8_t fp[VERTHYS_PEPPER_FP_BYTES];
    if (pepper_file_fingerprint(label, cipher, fp) != 0) {
        verthys_secure_zero(cipher, sizeof(cipher));
        return -1;
    }

    /* 序列化到文件（v2 布局，304B） */
    uint8_t buf[VERTHYS_PEPPER_FILE_BYTES];
    buf[0] = (uint8_t)(VERTHYS_PEPPER_FILE_MAGIC & 0xFF);
    buf[1] = (uint8_t)((VERTHYS_PEPPER_FILE_MAGIC >> 8) & 0xFF);
    buf[2] = (uint8_t)((VERTHYS_PEPPER_FILE_MAGIC >> 16) & 0xFF);
    buf[3] = (uint8_t)((VERTHYS_PEPPER_FILE_MAGIC >> 24) & 0xFF);
    buf[4] = (uint8_t)(VERTHYS_PEPPER_FILE_VERSION & 0xFF);
    buf[5] = (uint8_t)((VERTHYS_PEPPER_FILE_VERSION >> 8) & 0xFF);
    buf[6] = (uint8_t)((uint32_t)g_pepper_source & 0xFF);   /* source_type */
    buf[7] = 0;                                             /* 高字节保留 */
    memcpy(buf + 8, fp, VERTHYS_PEPPER_FP_BYTES);             /* fingerprint */
    memcpy(buf + 8 + VERTHYS_PEPPER_FP_BYTES, label, CMK_OAEP_LABEL_BYTES);
    memcpy(buf + 8 + VERTHYS_PEPPER_FP_BYTES + CMK_OAEP_LABEL_BYTES, cipher, CMK_RSA_CIPHER_BYTES);
    verthys_secure_zero(fp, sizeof(fp));

    /* 原子写入：临时文件 + rename */
    char tmp_path[MAX_PATH];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
        verthys_secure_zero(buf, sizeof(buf));
        verthys_secure_zero(cipher, sizeof(cipher));
        return -1;
    }

    FILE *f = fopen(tmp_path, "wb");
    if (f == NULL) {
        verthys_secure_zero(buf, sizeof(buf));
        verthys_secure_zero(cipher, sizeof(cipher));
        return -1;
    }
    if (fwrite(buf, 1, sizeof(buf), f) != sizeof(buf)) {
        fclose(f);
        remove(tmp_path);
        verthys_secure_zero(buf, sizeof(buf));
        verthys_secure_zero(cipher, sizeof(cipher));
        return -1;
    }
    fflush(f);
#ifdef _WIN32
    _commit(_fileno(f));
#endif
    fclose(f);

    /* 原子替换 */
#ifdef _WIN32
    if (!MoveFileExA(tmp_path, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        remove(tmp_path);
        verthys_secure_zero(buf, sizeof(buf));
        verthys_secure_zero(cipher, sizeof(cipher));
        return -1;
    }
#else
    if (rename(tmp_path, path) != 0) {
        remove(tmp_path);
        verthys_secure_zero(buf, sizeof(buf));
        verthys_secure_zero(cipher, sizeof(cipher));
        return -1;
    }
#endif

    verthys_secure_zero(buf, sizeof(buf));
    verthys_secure_zero(cipher, sizeof(cipher));
    return 0;
#else
    return -1;
#endif
}

/* ===================================================================== *
 *                    胡椒生命周期接口                                    *
 * ===================================================================== */

int verthys_pepper_inject(const uint8_t pepper[VERTHYS_KEY_BYTES])
{
    if (pepper == NULL) return -1;

    /* 若已有胡椒，先安全清零旧值 */
    if (g_pepper_initialized) {
        verthys_secure_zero(g_pepper, sizeof(g_pepper));
    }

    memcpy(g_pepper, pepper, VERTHYS_KEY_BYTES);
    pepper_lock_memory();
    g_pepper_source = VERTHYS_PEPPER_SOURCE_INJECTED;
    g_pepper_source_error = 0;  /* ★ 审查修正：注入解除历史来源错误态 */
    g_pepper_initialized = 1;
    return 0;
}

int verthys_pepper_init(void)
{
    if (g_pepper_initialized) return 0;

    /* 优先级 1：已注入（verthys_pepper_inject 优先调用）*/
    if (g_pepper_source == VERTHYS_PEPPER_SOURCE_INJECTED) {
        g_pepper_initialized = 1;
        return 0;
    }

    /* 优先级 2：OS 托管胡椒（CNG/TPM）*/
    int rc = verthys_pepper_load_from_os();
    if (rc == VERTHYS_PEPPER_LOAD_OK) {
        g_pepper_source_error = 0;
        return 0;
    }
    if (rc == VERTHYS_PEPPER_LOAD_SOURCE_ERR) {
        /* ★ 方案 §4.2（P0-B 根治）：来源失败禁止静默兜底。
         * 原缺陷：解包失败静默回退编译内嵌常量 → 解锁以错误 pepper 派生
         * MEK → key_a/b 解包失败 → 用户看到"密码错误"，无从诊断。
         * 现行为：置来源错误标志（verthys_pepper_source_error 查询），
         * 解锁路径返回 VERTHYS_ERR_PEPPER_SOURCE，前端提示"保险库安全源
         * 已变更"。 */
        g_pepper_source_error = 1;
        return -1;
    }

    /* 优先级 3：编译内嵌胡椒（兜底默认值；来源确定性，随容器记录可校验）*/
    memcpy(g_pepper, VERTHYS_PEPPER_COMPILED, VERTHYS_KEY_BYTES);
    pepper_lock_memory();
    g_pepper_source = VERTHYS_PEPPER_SOURCE_COMPILED;
    g_pepper_source_error = 0;
    g_pepper_initialized = 1;
    return 0;
}

const uint8_t *verthys_pepper_get(void)
{
    if (!g_pepper_initialized) return NULL;
    return g_pepper;
}

void verthys_pepper_deinit(void)
{
    if (!g_pepper_initialized) return;
    pepper_unlock_memory();
    verthys_secure_zero(g_pepper, sizeof(g_pepper));
    g_pepper_initialized = 0;
    g_pepper_source = VERTHYS_PEPPER_SOURCE_NONE;
}

/* ===================================================================== *
 *            胡椒恢复卡（Shamir 秘密共享分片）                            *
 * ===================================================================== *
 * 将 32 字节胡椒按字节独立拆分，每个字节用独立的 GF(2^8) 多项式。
 *   f_byte(x) = pepper[byte] + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)
 * 第 i 份分片的 share[byte] = f_byte(i)
 *
 * 重建时对每个字节独立拉格朗日插值求 f_byte(0) = pepper[byte]
 */

int verthys_pepper_export_shamir(VerthysPepperShard *shards,
                               uint8_t total_shards,
                               uint8_t threshold)
{
    if (shards == NULL) return -1;
    if (!g_pepper_initialized) return -1;
    if (total_shards < 2 || total_shards > 255) return -1;
    if (threshold < 2 || threshold > total_shards) return -1;

    /* degree = threshold - 1，多项式系数 = secret + (threshold-1) 个随机值 */
    uint8_t deg = (uint8_t)(threshold - 1);
    uint8_t coeffs[256];  /* 最多 256 系数（threshold ≤ 255） */

    for (uint8_t s = 0; s < total_shards; s++) {
        shards[s].index = (uint8_t)(s + 1);  /* 索引 1..total_shards，0 保留给秘密 */
    }

    /* 对胡椒的每个字节独立构造多项式并求值 */
    for (size_t byte = 0; byte < VERTHYS_KEY_BYTES; byte++) {
        coeffs[0] = g_pepper[byte];  /* f(0) = 秘密 */
        /* 生成 deg 个随机系数 */
        if (deg > 0) {
            verthys_random_bytes(coeffs + 1, deg);
        }

        /* 对每份分片求值：share = f(index) */
        for (uint8_t s = 0; s < total_shards; s++) {
            uint8_t x = (uint8_t)(s + 1);
            shards[s].share[byte] = gf256_poly_eval(coeffs, deg, x);
        }
    }

    verthys_secure_zero(coeffs, sizeof(coeffs));
    return 0;
}

int verthys_pepper_reconstruct_shamir(const VerthysPepperShard *shards,
                                    uint8_t count,
                                    uint8_t threshold)
{
    if (shards == NULL) return -1;
    if (count < threshold) return -1;
    if (threshold < 2) return -1;

    uint8_t deg = (uint8_t)(threshold - 1);
    uint8_t pepper[VERTHYS_KEY_BYTES];

    /* 使用前 threshold 份分片（多余的忽略） */
    /* 对每个字节独立拉格朗日插值求 f(0) */
    for (size_t byte = 0; byte < VERTHYS_KEY_BYTES; byte++) {
        /* 拉格朗日插值：f(0) = Σ y_i * L_i(0)
         * L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j)
         *        = Π_{j≠i} x_j / (x_i ⊕ x_j)   （GF(2^8) 中减法=XOR） */
        uint8_t secret = 0;
        for (uint8_t i = 0; i < threshold; i++) {
            uint8_t xi = shards[i].index;
            uint8_t yi = shards[i].share[byte];

            /* 计算 L_i(0) = Π_{j≠i} x_j * inv(x_i ⊕ x_j) */
            uint8_t num = 1;   /* 分子：Π x_j */
            uint8_t denom = 1; /* 分母：Π (x_i ⊕ x_j) */
            for (uint8_t j = 0; j < threshold; j++) {
                if (j == i) continue;
                uint8_t xj = shards[j].index;
                /* 0 - x_j = x_j（GF(2^8) 减法 = XOR，0 XOR x = x） */
                num = gf256_mul(num, xj);
                /* x_i - x_j = x_i XOR x_j */
                uint8_t diff = xi ^ xj;
                if (diff == 0) {
                    /* 两个分片索引相同：无法重建 */
                    verthys_secure_zero(pepper, sizeof(pepper));
                    return -1;
                }
                denom = gf256_mul(denom, diff);
            }
            /* L_i(0) = num * inv(denom) */
            uint8_t li = gf256_mul(num, gf256_inv(denom));
            /* 累加 y_i * L_i(0) */
            secret ^= gf256_mul(yi, li);
        }
        pepper[byte] = secret;
    }

    /* 注入重建的胡椒 */
    if (g_pepper_initialized) {
        verthys_secure_zero(g_pepper, sizeof(g_pepper));
    }
    memcpy(g_pepper, pepper, VERTHYS_KEY_BYTES);
    verthys_secure_zero(pepper, sizeof(pepper));
    pepper_lock_memory();
    g_pepper_source = VERTHYS_PEPPER_SOURCE_SHAMIR;
    g_pepper_source_error = 0;  /* ★ 审查修正：重建解除历史来源错误态 */
    g_pepper_initialized = 1;
    return 0;
}

/* ===================================================================== *
 *                        胡椒来源查询（诊断）                            *
 * ===================================================================== */
VerthysPepperSource verthys_pepper_get_source(void)
{
    return g_pepper_source;
}

/* ★ 方案 §4.2：来源错误状态查询（见 verthys_pepper.h 契约） */
int verthys_pepper_source_error(void)
{
    return g_pepper_source_error ? 1 : 0;
}
