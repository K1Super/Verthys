/*
 * integrity.c — 惰性关键段完整性校验 + 分散式校验锚点实现
 *
 *
 * 技术要点：
 *   - HMAC-SHA256（libsodium 经 verthys_crypto.h 封装）计算各区段摘要
 *   - 每个锚点拥有独立 32 字节基准哈希（post-build 工具经 integrity_set_baseline 注入）
 *   - 基准全零 = 未配置 = 跳过校验（返回 0=通过），避免开发期阻断
 *   - 校验失败（哈希不匹配）返回非零，调用方据此触发应急流程（同 emergency.h）
 *   - 计算用临时哈希缓冲区用毕立即 verthys_secure_zero 清零，避免内存残留
 *
 * 区段覆盖（分散式，无单点）：
 *   ANCHOR_STARTUP         DLL .text 全段 + EXE 前 1MB（组合哈希）
 *   ANCHOR_OPEN_SETTINGS   DLL .rdata 段
 *   ANCHOR_SWITCH_TREE     DLL .text 后半段
 *   ANCHOR_EXPORT_FILE     EXE PE 头 + 数据目录表（SizeOfHeaders 区块）
 *   ANCHOR_IMPORT_FILE     DLL 导出表（IMAGE_DIRECTORY_ENTRY_EXPORT）
 *   ANCHOR_CHANGE_PASSWORD DLL .text 前半段
 *   ANCHOR_UNLOCK          EXE .text 段抽样（固定步长，低开销）
 *
 * 安全策略：
 *   - 域分离密钥为非秘密固定常量（仅完整性用途，与机密性无关）
 *   - 与 anti_debug.c 的 check_integrity() 使用不同域标签，避免跨模块哈希碰撞
 *   - PE 解析失败 / HMAC 计算失败时返回 0（不阻断），仅哈希不匹配返回非零
 *     —— 与 anti_debug.c 一致，避免基础设施异常导致误报
 */
#include "integrity.h"
#include "verthys_crypto.h"
#include "verthys_internal.h"  /* verthys_secure_zero */
#include "emergency.h"       /* 验签失败 KILL 级上报 */
#include <sodium.h>          /* crypto_auth_hmacsha256_state（流式 HMAC） */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string.h>
#include <stdio.h>

/* ---------- 常量 ---------- */

/* 主 EXE 头部校验区段大小：1 MiB（integrity.h 要求） */
#define INTEGRITY_EXE_HEAD_BYTES  (1024u * 1024u)

/* ANCHOR_UNLOCK 抽样参数：固定步长抽取 NUM_SAMPLES 个 SAMPLE_BYTES 字节块 */
#define UNLOCK_SAMPLE_COUNT  32u
#define UNLOCK_SAMPLE_BYTES  64u

/*
 * 域分离密钥（非秘密，仅完整性校验用途）。
 * 标签 "VltIntgrAnchor" + 零填充至 32 字节，与 anti_debug.c 的 "IntegrityCheck"
 * 标签不同，确保两套校验输出互不碰撞。
 */
static const uint8_t s_integrity_key[VERTHYS_KEY_BYTES] = {
    0x56, 0x6c, 0x74, 0x49, 0x6e, 0x74, 0x67, 0x72,  /* "VltIntgr"       */
    0x41, 0x6e, 0x63, 0x68, 0x6f, 0x72, 0x00, 0x00,  /* "Anchor\0\0"     */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* ---------- 模块状态 ---------- */

/*
 * 各锚点基准哈希存储。BSS 段默认全零 = 未配置 = 跳过校验。
 * post-build 工具通过 integrity_set_baseline() 注入实际基准值。
 * 运行时只读（set_baseline 仅在初始化阶段调用），无需加锁。
 */
static uint8_t s_baseline[ANCHOR_COUNT][VERTHYS_HMAC_BYTES];

static int s_initialized = 0;

/* ---------- 辅助函数 ---------- */

/* 判断指定锚点的基准是否为全零（未配置）。 */
static int baseline_is_zero(IntegrityAnchor anchor)
{
    static const uint8_t zero[VERTHYS_HMAC_BYTES] = {0};
    return memcmp(s_baseline[anchor], zero, VERTHYS_HMAC_BYTES) == 0;
}

/*
 * 将计算出的哈希与指定锚点基准比对。
 *   返回 0=通过（未配置或匹配），1=校验失败（哈希不匹配）。
 * 注意：本函数不负责清零 computed 缓冲，由调用方用毕 verthys_secure_zero。
 */
static int verify_against_baseline(IntegrityAnchor anchor,
                                   const uint8_t computed[VERTHYS_HMAC_BYTES])
{
    if (baseline_is_zero(anchor)) {
        return 0;  /* 未配置，跳过 = 通过 */
    }
    return (memcmp(s_baseline[anchor], computed, VERTHYS_HMAC_BYTES) != 0) ? 1 : 0;
}

/*
 * 计算 data[0..len) 的 HMAC-SHA256 并与指定锚点基准比对。
 *   返回 0=通过，1=校验失败；HMAC 计算失败时返回 0（不阻断，与 anti_debug.c 一致）。
 * 临时哈希缓冲用毕立即清零。
 */
static int hash_and_verify(IntegrityAnchor anchor,
                           const uint8_t *data, size_t len)
{
    uint8_t hash[VERTHYS_HMAC_BYTES];

    if (data == NULL || len == 0) {
        return 0;  /* 无数据可校验，不阻断 */
    }

    if (verthys_hmac_sha256(hash, s_integrity_key, data, len) != 0) {
        verthys_secure_zero(hash, sizeof hash);
        return 0;  /* HMAC 计算失败，不阻断 */
    }

    int result = verify_against_baseline(anchor, hash);
    verthys_secure_zero(hash, sizeof hash);
    return result;
}

/* 获取包含本模块（DLL）的模块句柄。基于本文件内函数地址定位。 */
static HMODULE get_self_module(void)
{
    HMODULE h = NULL;
    BOOL ok = GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)&integrity_init,
        &h);
    if (!ok || h == NULL) return NULL;
    return h;
}

/* 获取主 EXE 模块句柄。GetModuleHandleW(NULL) 返回当前进程主 EXE 基址。 */
static HMODULE get_exe_module(void)
{
    return GetModuleHandleW(NULL);
}

/*
 * 在指定模块内按名称查找 PE 区段。
 *   hMod       模块句柄
 *   name       区段名（如 ".text"、".rdata"）
 *   out_size   输出区段 VirtualSize
 * 返回区段在内存中的起始指针（base + VirtualAddress），未找到返回 NULL。
 */
static const BYTE *find_section(HMODULE hMod, const char *name, size_t *out_size)
{
    if (hMod == NULL || name == NULL || out_size == NULL) return NULL;

    const BYTE *base = (const BYTE *)hMod;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    const IMAGE_NT_HEADERS *nt =
        (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    /* 防御性：e_lfanew 越界检查（粗略） */
    if (dos->e_lfanew <= 0 ||
        (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > nt->OptionalHeader.SizeOfImage) {
        return NULL;
    }

    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        /* 区段名为 8 字节，不足 8 字节时以 0 填充。拷贝到临时缓冲比较。 */
        char buf[IMAGE_SIZEOF_SHORT_NAME + 1];
        memcpy(buf, sec[i].Name, IMAGE_SIZEOF_SHORT_NAME);
        buf[IMAGE_SIZEOF_SHORT_NAME] = '\0';
        if (strcmp(buf, name) == 0) {
            DWORD vsize = sec[i].Misc.VirtualSize;
            if (vsize == 0) return NULL;
            *out_size = vsize;
            return base + sec[i].VirtualAddress;
        }
    }
    return NULL;
}

/*
 * 解析 EXE 模块的 NT 头。
 * 成功返回 base 指针与 nt 指针，失败返回 NULL。
 */
static const IMAGE_NT_HEADERS *get_nt_headers(HMODULE hMod, const BYTE **out_base)
{
    if (hMod == NULL) return NULL;
    const BYTE *base = (const BYTE *)hMod;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    const IMAGE_NT_HEADERS *nt =
        (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (out_base) *out_base = base;
    return nt;
}

/* ---------- 各锚点校验实现 ---------- */

/*
 * ANCHOR_STARTUP：DLL .text 全段 + EXE 前 1MB（组合哈希）。
 * 组合方式：h1=HMAC(DLL .text)，h2=HMAC(EXE 前1MB)，
 *           final=HMAC(h1||h2)，与基准比对。
 * EXE 前 1MB 区段以 SizeOfImage 为上界钳制，避免读越界。
 * 中间哈希 h1/h2 在合并后立即清零。
 */
static int check_anchor_startup(void)
{
    HMODULE self = get_self_module();
    HMODULE exe  = get_exe_module();
    if (self == NULL || exe == NULL) return 0;

    /* DLL .text 段 */
    size_t text_size = 0;
    const BYTE *text = find_section(self, ".text", &text_size);
    if (text == NULL || text_size == 0) return 0;

    /* EXE 前 1MB（钳制到 SizeOfImage） */
    const BYTE *exe_base = NULL;
    const IMAGE_NT_HEADERS *nt = get_nt_headers(exe, &exe_base);
    if (nt == NULL || exe_base == NULL) return 0;
    DWORD image_size = nt->OptionalHeader.SizeOfImage;
    size_t exe_head = INTEGRITY_EXE_HEAD_BYTES;
    if (image_size != 0 && exe_head > image_size) {
        exe_head = image_size;
    }
    if (exe_head == 0) return 0;

    uint8_t h1[VERTHYS_HMAC_BYTES];
    uint8_t h2[VERTHYS_HMAC_BYTES];
    uint8_t combined[2 * VERTHYS_HMAC_BYTES];
    uint8_t final_hash[VERTHYS_HMAC_BYTES];
    int result = 0;

    /* h1 = HMAC(DLL .text) */
    if (verthys_hmac_sha256(h1, s_integrity_key, text, text_size) != 0) {
        verthys_secure_zero(h1, sizeof h1);
        return 0;  /* 计算失败，不阻断 */
    }
    /* h2 = HMAC(EXE 前 1MB) */
    if (verthys_hmac_sha256(h2, s_integrity_key, exe_base, exe_head) != 0) {
        verthys_secure_zero(h1, sizeof h1);
        verthys_secure_zero(h2, sizeof h2);
        return 0;  /* 计算失败，不阻断 */
    }

    /* 合并 h1||h2，合并后立即清零中间哈希 */
    memcpy(combined, h1, VERTHYS_HMAC_BYTES);
    memcpy(combined + VERTHYS_HMAC_BYTES, h2, VERTHYS_HMAC_BYTES);
    verthys_secure_zero(h1, sizeof h1);
    verthys_secure_zero(h2, sizeof h2);

    /* final = HMAC(combined) */
    if (verthys_hmac_sha256(final_hash, s_integrity_key,
                          combined, sizeof combined) != 0) {
        verthys_secure_zero(combined, sizeof combined);
        verthys_secure_zero(final_hash, sizeof final_hash);
        return 0;  /* 计算失败，不阻断 */
    }
    verthys_secure_zero(combined, sizeof combined);

    result = verify_against_baseline(ANCHOR_STARTUP, final_hash);
    verthys_secure_zero(final_hash, sizeof final_hash);
    return result;
}

/*
 * ANCHOR_OPEN_SETTINGS：DLL .rdata 段。
 */
static int check_anchor_open_settings(void)
{
    HMODULE self = get_self_module();
    if (self == NULL) return 0;

    size_t rdata_size = 0;
    const BYTE *rdata = find_section(self, ".rdata", &rdata_size);
    if (rdata == NULL || rdata_size == 0) return 0;

    return hash_and_verify(ANCHOR_OPEN_SETTINGS, rdata, rdata_size);
}

/*
 * ANCHOR_SWITCH_TREE：DLL .text 后半段。
 */
static int check_anchor_switch_tree(void)
{
    HMODULE self = get_self_module();
    if (self == NULL) return 0;

    size_t text_size = 0;
    const BYTE *text = find_section(self, ".text", &text_size);
    if (text == NULL || text_size == 0) return 0;

    size_t half = text_size / 2;
    if (half == 0) return 0;

    /* 后半段：[text+half, text+text_size) */
    return hash_and_verify(ANCHOR_SWITCH_TREE, text + half, text_size - half);
}

/*
 * ANCHOR_EXPORT_FILE：EXE PE 头 + 入口表（数据目录）。
 * 校验 SizeOfHeaders 区块，涵盖 DOS 头、NT 头、区段表与数据目录数组
 *（含入口点地址、导入/导出/资源等目录描述符）。
 */
static int check_anchor_export_file(void)
{
    HMODULE exe = get_exe_module();
    if (exe == NULL) return 0;

    const BYTE *base = NULL;
    const IMAGE_NT_HEADERS *nt = get_nt_headers(exe, &base);
    if (nt == NULL || base == NULL) return 0;

    DWORD headers_size = nt->OptionalHeader.SizeOfHeaders;
    if (headers_size == 0) return 0;

    return hash_and_verify(ANCHOR_EXPORT_FILE, base, headers_size);
}

/*
 * ANCHOR_IMPORT_FILE：DLL 导出表。
 * 通过 IMAGE_DIRECTORY_ENTRY_EXPORT 定位导出目录区段并计算 HMAC。
 *（DLL 暴露内部接口，导出表是注入/Hook 攻击的高价值目标。）
 */
static int check_anchor_import_file(void)
{
    HMODULE self = get_self_module();
    if (self == NULL) return 0;

    const BYTE *base = NULL;
    const IMAGE_NT_HEADERS *nt = get_nt_headers(self, &base);
    if (nt == NULL || base == NULL) return 0;

    const IMAGE_DATA_DIRECTORY *exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir->VirtualAddress == 0 || exp_dir->Size == 0) return 0;

    const BYTE *export_data = base + exp_dir->VirtualAddress;
    DWORD export_size = exp_dir->Size;

    return hash_and_verify(ANCHOR_IMPORT_FILE, export_data, export_size);
}

/*
 * ANCHOR_CHANGE_PASSWORD：DLL .text 前半段。
 */
static int check_anchor_change_password(void)
{
    HMODULE self = get_self_module();
    if (self == NULL) return 0;

    size_t text_size = 0;
    const BYTE *text = find_section(self, ".text", &text_size);
    if (text == NULL || text_size == 0) return 0;

    size_t half = text_size / 2;
    if (half == 0) return 0;

    /* 前半段：[text, text+half) */
    return hash_and_verify(ANCHOR_CHANGE_PASSWORD, text, half);
}

/*
 * ANCHOR_UNLOCK：EXE .text 段抽样校验。
 * 以固定步长抽取 UNLOCK_SAMPLE_COUNT 个 UNLOCK_SAMPLE_BYTES 字节块，
 * 拼接后计算 HMAC。低开销、覆盖面广，适合高频“解锁”路径。
 * .text 过小时直接全段校验。
 */
static int check_anchor_unlock(void)
{
    HMODULE exe = get_exe_module();
    if (exe == NULL) return 0;

    size_t text_size = 0;
    const BYTE *text = find_section(exe, ".text", &text_size);
    if (text == NULL || text_size == 0) return 0;

    /* .text 不足抽样总量时直接全段校验 */
    if (text_size < (size_t)(UNLOCK_SAMPLE_COUNT * UNLOCK_SAMPLE_BYTES)) {
        return hash_and_verify(ANCHOR_UNLOCK, text, text_size);
    }

    uint8_t sample_buf[UNLOCK_SAMPLE_COUNT * UNLOCK_SAMPLE_BYTES];
    size_t stride = text_size / UNLOCK_SAMPLE_COUNT;
    if (stride < UNLOCK_SAMPLE_BYTES) stride = UNLOCK_SAMPLE_BYTES;

    for (size_t i = 0; i < UNLOCK_SAMPLE_COUNT; i++) {
        size_t off = i * stride;
        /* 末尾样本越界保护：确保最后一个样本完整落在 .text 内 */
        if (off + UNLOCK_SAMPLE_BYTES > text_size) {
            off = text_size - UNLOCK_SAMPLE_BYTES;
        }
        memcpy(sample_buf + i * UNLOCK_SAMPLE_BYTES,
               text + off,
               UNLOCK_SAMPLE_BYTES);
    }

    int result = hash_and_verify(ANCHOR_UNLOCK,
                                 sample_buf, sizeof sample_buf);
    verthys_secure_zero(sample_buf, sizeof sample_buf);
    return result;
}

/* ===================================================================== *
 *                           公共接口                                    *
 * ===================================================================== */

int integrity_init(void)
{
    if (s_initialized) return 0;

    /* 确保密码库可用（HMAC-SHA256 依赖 libsodium） */
    if (verthys_crypto_init() != 0) {
        return -1;
    }

    /*
     * 准备各锚点基准哈希存储：默认全零（=未配置=跳过）。
     * BSS 段已为零，此处显式清零以防御动态加载场景下的脏页复用。
     */
    for (int i = 0; i < (int)ANCHOR_COUNT; i++) {
        memset(s_baseline[i], 0, VERTHYS_HMAC_BYTES);
    }

    s_initialized = 1;
    return 0;
}

void integrity_set_baseline(IntegrityAnchor anchor, const uint8_t hash[32])
{
    if (anchor < 0 || anchor >= ANCHOR_COUNT) return;
    if (hash == NULL) return;

    memcpy(s_baseline[anchor], hash, VERTHYS_HMAC_BYTES);
}

int integrity_check_startup(void)
{
    if (!s_initialized) {
        if (integrity_init() != 0) return 0;  /* 初始化失败，不阻断 */
    }
    return check_anchor_startup();
}

int integrity_check_anchor(IntegrityAnchor anchor)
{
    if (!s_initialized) {
        if (integrity_init() != 0) return 0;  /* 初始化失败，不阻断 */
    }

    if (anchor < 0 || anchor >= ANCHOR_COUNT) return 0;

    switch (anchor) {
        case ANCHOR_STARTUP:
            return check_anchor_startup();
        case ANCHOR_OPEN_SETTINGS:
            return check_anchor_open_settings();
        case ANCHOR_SWITCH_TREE:
            return check_anchor_switch_tree();
        case ANCHOR_EXPORT_FILE:
            return check_anchor_export_file();
        case ANCHOR_IMPORT_FILE:
            return check_anchor_import_file();
        case ANCHOR_CHANGE_PASSWORD:
            return check_anchor_change_password();
        case ANCHOR_UNLOCK:
            return check_anchor_unlock();
        default:
            return 0;  /* 未知锚点，不阻断 */
    }
}

/* ===================================================================== *
 *        ★ 构建期签名 + 一次性验签（.vsec 机制）实现          *
 * ===================================================================== *
 *
 * .vsec 节布局（128 字节，只读节，由构建脚本在链接后补丁）：
 *   [0..3]   magic   = 0x43534556 ('VESV' 小端)
 *   [4..5]   version = 0x0002（v2：新增 .rhat 第三槽）
 *   [6..7]   flags   = 0（预留）
 *   [8..39]  HMAC(.text 文件内容)
 *   [40..71] HMAC(.rdata 文件内容)
 *   [72..103] HMAC(.rhat 文件内容)（运行时哈希表防文件级篡改）
 *   [104..127] 保留全零
 *
 * 全零节 = 未配置（开发构建）→ 验签跳过。构建脚本以相同域密钥补丁本节。
 * 版本兼容：version==1 仅校验 text+rdata（旧脚本产物）；version>=2 追加
 * .rhat 槽——.rhat 节缺失（理论上不可达，runtime_hash.c 恒编入）按
 * 基础设施异常跳过该槽，text/rdata 槽照常校验。
 */

/* .vsec 固定大小 */
#define VSEC_BLOB_BYTES   128u
#define VSEC_MAGIC        0x43534556u
#define VSEC_VERSION_2    0x0002u
#define VSEC_TEXT_HMAC_OFF    8u
#define VSEC_RDATA_HMAC_OFF  40u
#define VSEC_RHAT_HMAC_OFF   72u

/* .vsec 节定义（只读；verify_startup 引用其地址以保留符号防 /OPT:REF 剪除） */
#pragma section(".vsec", read)
__declspec(allocate(".vsec"))
const uint8_t g_vsec_blob[VSEC_BLOB_BYTES] = { 0 };

/* 域密钥：与 build_core.release.ps1 中的补丁密钥保持逐字节一致（非秘密） */
static const uint8_t K_VSEC_DOMAIN_KEY[VERTHYS_KEY_BYTES] = {
    'v', 'e', 'r', 't', 'h', 'y', 's', '/', 'v', 's', 'e', 'c', '-', 'v', '1', '/',
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15,
    0xbf, 0x61, 0x83, 0xd2, 0x55, 0x0a, 0x34, 0x6c
};

/* 从 PE 文件读取节表，输出指定节的文件偏移与原始大小 */
static int vsec_find_section(FILE *f, const char *name,
                             long *out_raw_ptr, DWORD *out_raw_size)
{
    uint8_t dos[64], nt[24], opt20[20];
    if (fread(dos, 1, sizeof(dos), f) != sizeof(dos)) return -1;
    if (dos[0] != 'M' || dos[1] != 'Z') return -1;

    long e_lfanew = (long)dos[0x3C] | ((long)dos[0x3D] << 8) |
                    ((long)dos[0x3E] << 16) | ((long)dos[0x3F] << 24);
    if (e_lfanew <= 0 || fseek(f, e_lfanew, SEEK_SET) != 0) return -1;
    if (fread(nt, 1, sizeof(nt), f) != sizeof(nt)) return -1;
    if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0) return -1;

    WORD nsections = (WORD)(nt[6] | (nt[7] << 8));
    WORD opt_size  = (WORD)(nt[20] | (nt[21] << 8));

    long opt_start = e_lfanew + 4 + 20;
    long sec_start = opt_start + opt_size;
    if (fseek(f, sec_start, SEEK_SET) != 0) return -1;

    for (WORD i = 0; i < nsections; i++) {
        uint8_t sh[40];
        if (fread(sh, 1, sizeof(sh), f) != sizeof(sh)) return -1;
        if (memcmp(sh, name, strlen(name)) == 0 && sh[strlen(name)] == '\0') {
            *out_raw_ptr = (long)((uint32_t)sh[20] | ((uint32_t)sh[21] << 8) |
                                  ((uint32_t)sh[22] << 16) | ((uint32_t)sh[23] << 24));
            *out_raw_size = (DWORD)((uint32_t)sh[16] | ((uint32_t)sh[17] << 8) |
                                    ((uint32_t)sh[18] << 16) | ((uint32_t)sh[19] << 24));
            return 0;
        }
        (void)opt20; (void)opt_start;
    }
    return -1;
}

/* 计算文件中 [raw_ptr, raw_ptr+raw_size) 的 HMAC-SHA256 */
static int vsec_hash_file_region(FILE *f, long raw_ptr, DWORD raw_size,
                                 uint8_t out[VERTHYS_HMAC_BYTES])
{
    if (raw_ptr <= 0 || raw_size == 0) return -1;
    if (fseek(f, raw_ptr, SEEK_SET) != 0) return -1;

    /* 流式 HMAC：分块读取（crypto_auth_hmacsha256 无流式接口，
     * 使用 crypto_auth_hmacsha256_state） */
    crypto_auth_hmacsha256_state st;
    if (crypto_auth_hmacsha256_init(&st, K_VSEC_DOMAIN_KEY, VERTHYS_KEY_BYTES) != 0) {
        return -1;
    }

    uint8_t buf[65536];
    DWORD remaining = raw_size;
    while (remaining > 0) {
        size_t chunk = (remaining > sizeof(buf)) ? sizeof(buf) : (size_t)remaining;
        if (fread(buf, 1, chunk, f) != chunk) {
            verthys_secure_zero(buf, sizeof(buf));
            return -1;
        }
        crypto_auth_hmacsha256_update(&st, buf, chunk);
        remaining -= (DWORD)chunk;
    }
    verthys_secure_zero(buf, sizeof(buf));

    if (crypto_auth_hmacsha256_final(&st, out) != 0) {
        return -1;
    }
    return 0;
}

int integrity_verify_startup(void)
{
    /* 常量时间引用 .vsec（防止 /OPT:REF 剪除只读节） */
    volatile const uint8_t *blob_ref = g_vsec_blob;
    (void)blob_ref;

    /* 1. 定位自身 DLL 文件路径 */
    HMODULE hSelf = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)&integrity_verify_startup, &hSelf) ||
        hSelf == NULL) {
        return 0;  /* 无法定位自身模块：不阻断（基础设施异常不误报原则） */
    }
    wchar_t self_path[MAX_PATH];
    if (GetModuleFileNameW(hSelf, self_path, MAX_PATH) == 0) {
        return 0;
    }

    /* 2. 读取 .vsec 基准（从文件读取，保持与签名阶段同一字节源） */
    FILE *f = NULL;
    if (_wfopen_s(&f, self_path, L"rb") != 0 || f == NULL) {
        return 0;  /* 文件打开失败：不阻断 */
    }

    long vsec_ptr = 0; DWORD vsec_size = 0;
    uint8_t baseline[VSEC_BLOB_BYTES];
    memset(baseline, 0, sizeof(baseline));
    int have_vsec = (vsec_find_section(f, ".vsec", &vsec_ptr, &vsec_size) == 0 &&
                     vsec_size >= VSEC_BLOB_BYTES &&
                     fseek(f, vsec_ptr, SEEK_SET) == 0 &&
                     fread(baseline, 1, VSEC_BLOB_BYTES, f) == VSEC_BLOB_BYTES);
    if (!have_vsec) {
        fclose(f);
        return 0;  /* 无 .vsec（开发构建）：跳过 */
    }

    uint32_t magic = (uint32_t)baseline[0] | ((uint32_t)baseline[1] << 8) |
                     ((uint32_t)baseline[2] << 16) | ((uint32_t)baseline[3] << 24);
    uint16_t vsec_version = (uint16_t)((uint16_t)baseline[4] |
                                       ((uint16_t)baseline[5] << 8));
    uint8_t all_zero = 0;
    for (size_t i = 0; i < VSEC_BLOB_BYTES; i++) all_zero |= baseline[i];
    if (magic != VSEC_MAGIC || all_zero == 0) {
        verthys_secure_zero(baseline, sizeof(baseline));
        fclose(f);
        return 0; /* 未配置（全零占位）或魔法不符：跳过 */
    }

    /* 3. 重算 .text / .rdata（v2：+ .rhat）文件内容 HMAC */
    uint8_t text_mac[VERTHYS_HMAC_BYTES];
    uint8_t rdata_mac[VERTHYS_HMAC_BYTES];
    uint8_t rhat_mac[VERTHYS_HMAC_BYTES];
    long t_ptr = 0, r_ptr = 0, h_ptr = 0;
    DWORD t_size = 0, r_size = 0, h_size = 0;
    int have_rhat = 0;
    int ok = (vsec_find_section(f, ".text", &t_ptr, &t_size) == 0 &&
              vsec_find_section(f, ".rdata", &r_ptr, &r_size) == 0 &&
              vsec_hash_file_region(f, t_ptr, t_size, text_mac) == 0 &&
              vsec_hash_file_region(f, r_ptr, r_size, rdata_mac) == 0);
    if (ok && vsec_version >= VSEC_VERSION_2) {
        /* .rhat 节缺失/HMAC 计算失败：基础设施异常 → 跳过该槽不误报
         *（节被整体移除的场景必然改变其余节布局，已由 .text/.rdata 检出） */
        have_rhat = (vsec_find_section(f, ".rhat", &h_ptr, &h_size) == 0 &&
                     vsec_hash_file_region(f, h_ptr, h_size, rhat_mac) == 0);
    }
    fclose(f);

    if (!ok) {
        verthys_secure_zero(baseline, sizeof(baseline));
        return 0; /* 节解析失败：基础设施异常不误报 */
    }

    /* 4. 常量时间比对（v2：追加 .rhat 槽） */
    uint8_t diff = 0;
    for (size_t i = 0; i < VERTHYS_HMAC_BYTES; i++) {
        diff |= (uint8_t)(text_mac[i] ^ baseline[VSEC_TEXT_HMAC_OFF + i]);
        diff |= (uint8_t)(rdata_mac[i] ^ baseline[VSEC_RDATA_HMAC_OFF + i]);
        if (have_rhat) {
            diff |= (uint8_t)(rhat_mac[i] ^ baseline[VSEC_RHAT_HMAC_OFF + i]);
        }
    }
    verthys_secure_zero(text_mac, sizeof(text_mac));
    verthys_secure_zero(rdata_mac, sizeof(rdata_mac));
    verthys_secure_zero(rhat_mac, sizeof(rhat_mac));
    verthys_secure_zero(baseline, sizeof(baseline));

    if (diff != 0) {
        /* 分发二进制被篡改（高置信度）→ KILL 级上报 + 拒绝解锁 */
        emergency_report(EMERG_LEVEL_KILL, EMERG_SIG_INTEGRITY_FAIL);
        return (int)VERTHYS_ERR_CORRUPT;
    }
    return 0;
}
