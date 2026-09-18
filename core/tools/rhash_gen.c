/*
 * rhash_gen.c — 构建期 .rhat 运行时哈希表生成器（V3 升级 WP-8）
 *
 * 用法：rhash_gen --patch <binary> [--map <mapfile>]
 *   <binary>  链接完成的 PE（verthys.dll / verthys_tests.exe）
 *   <mapfile> 链接器 map（缺省 = <binary> 同目录同名 .map，/MAP 产物）
 *
 * 流程（v5.0 §9.3 构建期步骤）：
 *   1. 解析 PE：节表（RVA↔文件偏移换算）、.pdata（函数精确边界）、
 *      .reloc（重定位槽位——掩码归一化的文件视角）；
 *   2. 解析 map "Publics by Value"：符号名 → RVA（Rva+Base 列为首选
 *      派生，节号+偏移为交叉校验——两路独立推导必须一致）；
 *   3. 对 X 清单（runtime_hash.h VERTHYS_RUNTIME_HASH_FUNCS）每个函数：
 *      文件字节拷贝 → 掩码重定位槽位 → BLAKE2b-256（libsodium
 *      crypto_generichash，无密钥 + 域标签前缀，与运行期逐字节一致）；
 *   4. 补丁 .rhat 节（VerthysRhatBlob 布局，runtime_hash.h 单一事实源）。
 *
 * 与运行期（runtime_hash.c scan）的一致性契约：
 *   - 哈希输入 = VERTHYS_RHAT_LABEL ‖ (函数字节 ∧ 重定位槽位清零)；
 *   - 重定位槽位宽度：DIR64=8 / HIGHLOW=4 / HIGH=LOW=2（部分相交取交集）；
 *   - 函数边界：.pdata RUNTIME_FUNCTION 精确 Begin/End；.pdata 无对应
 *      （无展开信息的叶子函数）→ 回退"同节下一符号起点"。
 *
 * 退出码：0 成功；1 失败（X 符号缺失/边界异常/节缺失 → 构建 fail-fast，
 * 禁静默降级——§3 完整落地红线）。
 *
 * 校验门（构建期硬失败条件）：
 *   - 任一 X 符号在 map 缺失 / RVA 双路推导不一致；
 *   - 函数尺寸为 0 或超 VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES；
 *   - .rhat 节缺失或原始尺寸 < 16 + 48×N；
 *   - 两路 RVA 派生（Rva+Base 列 vs 节表换算）不一致。
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "runtime_hash.h"     /* X 清单 + 布局 + 标签 + 常量（单一事实源） */
#include <sodium.h>           /* crypto_generichash（BLAKE2b-256） */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

/* X 清单函数名展开（字符串数组，序号即 x_index） */
static const char *s_x_names[] = {
#define X(fn) #fn,
    VERTHYS_RUNTIME_HASH_FUNCS(X)
#undef X
};
#define X_FUNC_COUNT (sizeof(s_x_names) / sizeof(s_x_names[0]))

/* ---------- PE 解析结果 ---------- */

typedef struct PeSection {
    char     name[9];    /* 8 字节 + NUL */
    uint32_t va;         /* VirtualAddress（RVA） */
    uint32_t vsize;      /* VirtualSize */
    uint32_t raw_ptr;    /* PointerToRawData（文件偏移） */
    uint32_t raw_size;   /* SizeOfRawData */
} PeSection;

typedef struct PeInfo {
    uint8_t       *bytes;      /* 整个文件（内存中） */
    size_t         size;
    uint64_t       image_base;
    uint32_t       image_size;
    PeSection     *secs;
    uint32_t       sec_count;
    /* 数据目录（文件偏移，0 = 无） */
    size_t         reloc_off, reloc_size;
    size_t         pdata_off, pdata_size;
    /* .rhat 节（索引 -1 = 缺失） */
    int            rhat_index;
} PeInfo;

/* ---------- map 符号 ---------- */

typedef struct MapSym {
    char     name[256];
    uint32_t rva;          /* 首选派生（Rva+Base - ImageBase）或节表换算 */
    uint32_t section;      /* map 节号（1 基） */
    uint32_t offset;       /* 节内偏移 */
    int      has_rvabase;
    uint64_t rvabase;      /* map Rva+Base 列原值 */
} MapSym;

static MapSym *s_syms = NULL;
static size_t  s_sym_count = 0;

/* ---------- 工具函数 ---------- */

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[rhash_gen] ERROR: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static int is_hex_digit(int c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
           (c >= 'a' && c <= 'f');
}

/* ---------- PE 解析 ---------- */

static void pe_parse(PeInfo *pe, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) die("无法打开二进制: %s", path);
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0) die("空文件: %s", path);
    pe->size = (size_t)len;
    pe->bytes = (uint8_t *)malloc(pe->size);
    if (!pe->bytes || fread(pe->bytes, 1, pe->size, f) != pe->size) {
        die("读取失败: %s", path);
    }
    fclose(f);

    if (pe->size < sizeof(IMAGE_DOS_HEADER)) die("PE 过小");
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)pe->bytes;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) die("DOS 签名不符");
    size_t nt_off = (size_t)dos->e_lfanew;
    if (nt_off + sizeof(IMAGE_NT_HEADERS) > pe->size) die("NT 头越界");
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(pe->bytes + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) die("PE 签名不符");
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        die("仅支持 x64 映像");
    }

    pe->image_base = nt->OptionalHeader.ImageBase;
    pe->image_size = nt->OptionalHeader.SizeOfImage;
    pe->sec_count  = nt->FileHeader.NumberOfSections;
    if (pe->sec_count == 0 || pe->sec_count > 96) die("节数量异常");

    size_t sec_off = nt_off + offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
                     nt->FileHeader.SizeOfOptionalHeader;
    pe->secs = (PeSection *)calloc(pe->sec_count, sizeof(PeSection));
    if (!pe->secs) die("内存不足");
    if (sec_off + pe->sec_count * sizeof(IMAGE_SECTION_HEADER) > pe->size) {
        die("节表越界");
    }

    const IMAGE_SECTION_HEADER *sh =
        (const IMAGE_SECTION_HEADER *)(pe->bytes + sec_off);
    pe->rhat_index = -1;
    for (uint32_t i = 0; i < pe->sec_count; i++) {
        memcpy(pe->secs[i].name, sh[i].Name, IMAGE_SIZEOF_SHORT_NAME);
        pe->secs[i].name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
        pe->secs[i].va        = sh[i].VirtualAddress;
        pe->secs[i].vsize     = sh[i].Misc.VirtualSize;
        pe->secs[i].raw_ptr   = sh[i].PointerToRawData;
        pe->secs[i].raw_size  = sh[i].SizeOfRawData;
        if (strcmp(pe->secs[i].name, ".rhat") == 0) pe->rhat_index = (int)i;
    }
    if (pe->rhat_index < 0) {
        die("'.rhat' 节缺失（runtime_hash.c 未编译入或被 /OPT:REF 剪除）");
    }

    /* 数据目录 → 文件偏移（RVA 换算） */
    const IMAGE_DATA_DIRECTORY *reloc_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    const IMAGE_DATA_DIRECTORY *pdata_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    pe->reloc_size = reloc_dir->Size;
    pe->pdata_size = pdata_dir->Size;
    pe->reloc_off = pe->pdata_off = 0;
    if (reloc_dir->VirtualAddress != 0 && pe->reloc_size != 0) {
        pe->reloc_off = (size_t)-1; /* rva_to_file 在下方初始化后回填 */
    }
    if (pdata_dir->VirtualAddress != 0 && pe->pdata_size != 0) {
        pe->pdata_off = (size_t)-1;
    }

    /* RVA → 文件偏移函数（内部宏式实现，供下方与主流程共用） */
#define RVA_TO_FILE(rva_, out_)                                            \
    do {                                                                    \
        (out_) = (size_t)-1;                                                \
        uint32_t _r = (uint32_t)(rva_);                                     \
        for (uint32_t _i = 0; _i < pe->sec_count; _i++) {                   \
            uint32_t _span = pe->secs[_i].vsize > pe->secs[_i].raw_size    \
                                 ? pe->secs[_i].vsize : pe->secs[_i].raw_size; \
            if (_r >= pe->secs[_i].va && _r < pe->secs[_i].va + _span) {   \
                size_t _delta = _r - pe->secs[_i].va;                      \
                if (_delta < pe->secs[_i].raw_size) {                      \
                    (out_) = pe->secs[_i].raw_ptr + _delta;                \
                }                                                           \
                break;                                                      \
            }                                                               \
        }                                                                   \
    } while (0)

    if (pe->reloc_off == (size_t)-1) {
        RVA_TO_FILE(reloc_dir->VirtualAddress, pe->reloc_off);
    }
    if (pe->pdata_off == (size_t)-1) {
        RVA_TO_FILE(pdata_dir->VirtualAddress, pe->pdata_off);
    }
#undef RVA_TO_FILE

    /* .rhat 节容量校验（16 头 + 48×N ≤ 原始尺寸） */
    size_t need = sizeof(VerthysRhatBlob);
    if ((size_t)pe->secs[pe->rhat_index].raw_size < need) {
        die(".rhat 节过小: %u < %zu", pe->secs[pe->rhat_index].raw_size, need);
    }
}

/* ---------- map 解析 ---------- */

/*
 * 解析 "Publics by Value" 区符号行：
 *   格式（MSVC VS2015+）：' SSSS:OOOOOOOO  name  [Rva+Base]  [lib:obj]'
 *   - Rva+Base 列存在 → RVA = 列值 - ImageBase（首选派生）；
 *   - 无该列 → RVA = 节表[SSSS-1].va + OOOOOOOO（回退派生）。
 *   两路可用时强制一致（不一致 = 解析歧义 → 硬失败）。
 *   顶层 "Start Length Name Class" 贡献表与 "Static symbols" 区跳过
 *   （X 清单全部为非 static 外部符号）。
 */
static void map_parse(const PeInfo *pe, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) die("无法打开 map: %s（链接器需启用 /MAP）", path);

    char line[1024];
    int in_publics = 0;
    size_t cap = 4096;
    s_syms = (MapSym *)malloc(cap * sizeof(MapSym));
    if (!s_syms) die("内存不足");
    s_sym_count = 0;

    while (fgets(line, sizeof(line), f)) {
        /* 区切换：进入 Publics by Value；遇 Static symbols / 其他区头退出 */
        if (strstr(line, "Publics by Value")) { in_publics = 1; continue; }
        if (!in_publics) continue;
        if (strncmp(line, " Static symbols", 15) == 0) break;
        if (strstr(line, "Line numbers for")) { in_publics = 0; continue; }

        /* 符号行首 token: SSSS:OOOOOOOO */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char *tok1 = p;
        char *colon = strchr(p, ':');
        if (colon == NULL || colon == tok1) continue;

        /* 校验节号与偏移均为十六进制且长度合法（4 + 8） */
        size_t seclen = (size_t)(colon - tok1);
        if (seclen != 4) continue;
        int ok = 1;
        for (size_t i = 0; i < seclen; i++) {
            if (!is_hex_digit((unsigned char)tok1[i])) { ok = 0; break; }
        }
        if (!ok) continue;
        char *offstart = colon + 1;
        size_t offlen = 0;
        while (is_hex_digit((unsigned char)offstart[offlen])) offlen++;
        if (offlen != 8) continue;

        /* 名称 token（Rva+Base 前一列） */
        char *p2 = offstart + offlen;
        while (*p2 == ' ' || *p2 == '\t') p2++;
        if (*p2 == '\r' || *p2 == '\n' || *p2 == '\0') continue;
        char *name = p2;
        while (*p2 && *p2 != ' ' && *p2 != '\t' && *p2 != '\r' && *p2 != '\n') {
            p2++;
        }
        size_t namelen = (size_t)(p2 - name);
        if (namelen == 0 ||
            namelen >= sizeof(((MapSym *)0)->name)) continue; /* 长度越界防误报 */

        /* 可选第三列：Rva+Base
         * x64 默认 ImageBase=0x140000000 → Rva+Base 典型为 10 位十六进制
         * （0000000140003A40，含前导零时 16 位）。取 8~16 位窗口做候选，
         * 由下方 [image_base, image_base+SizeOfImage) 区间校验最终裁决
         * （单字符 "f"/"i" 标志列与 obj 文件名列均被窗口 + 区间双重排除）。 */
        char *p3 = p2;
        while (*p3 == ' ' || *p3 == '\t') p3++;
        int has_rvabase = 0;
        uint64_t rvabase = 0;
        if (is_hex_digit((unsigned char)*p3)) {
            char *e = p3;
            uint64_t v = 0;
            int digits = 0;
            while (is_hex_digit((unsigned char)*e) && digits < 17) {
                int d;
                char c = *e;
                if (c >= '0' && c <= '9') d = c - '0';
                else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                else d = c - 'a' + 10;
                v = (v << 4) | (uint64_t)d;
                e++;
                digits++;
            }
            if (digits >= 8 && digits <= 16) {
                has_rvabase = 1;
                rvabase = v;
            }
        }

        if (s_sym_count == cap) {
            cap *= 2;
            MapSym *grown = (MapSym *)realloc(s_syms, cap * sizeof(MapSym));
            if (!grown) die("内存不足");
            s_syms = grown;
        }

        MapSym *s = &s_syms[s_sym_count];
        memset(s, 0, sizeof(*s));
        memcpy(s->name, name, namelen);
        s->name[namelen] = '\0';
        s->section = (uint32_t)strtoul(tok1, NULL, 16);
        s->offset  = (uint32_t)strtoul(offstart, NULL, 16);
        s->has_rvabase = has_rvabase;
        s->rvabase = rvabase;

        /* 双路 RVA 派生 + 一致性校验 */
        uint32_t rva_sec = 0, rva_base = 0;
        int have_sec = 0, have_base = 0;
        if (s->section >= 1 && s->section <= pe->sec_count) {
            rva_sec = pe->secs[s->section - 1].va + s->offset;
            have_sec = 1;
        }
        if (has_rvabase) {
            uint64_t rb = rvabase;
            if (rb >= pe->image_base && rb - pe->image_base < pe->image_size) {
                rva_base = (uint32_t)(rb - pe->image_base);
                have_base = 1;
            }
        }
        if (have_base && have_sec && rva_base != rva_sec) {
            die("符号 %s 双路 RVA 派生不一致（Rva+Base=%08X vs 节表=%08X）",
                s->name, rva_base, rva_sec);
        }
        if (have_base)       s->rva = rva_base;
        else if (have_sec)   s->rva = rva_sec;
        else                 continue; /* 无可用派生：跳过该符号 */

        s_sym_count++;
    }
    fclose(f);
    if (!in_publics && s_sym_count == 0) {
        die("map 未找到 Publics by Value 区（非 MSVC /MAP 产物?）: %s", path);
    }
}

/* ---------- .pdata / 符号尺寸 ---------- */

/* 返回 .pdata 中 BeginAddress == rva 的函数尺寸；0 = 无精确边界 */
static uint32_t pdata_size_of(const PeInfo *pe, uint32_t rva)
{
    if (pe->pdata_off == 0 || pe->pdata_size < 12) return 0;
    size_t count = pe->pdata_size / 12;
    if (pe->pdata_off + count * 12 > pe->size) return 0;
    for (size_t i = 0; i < count; i++) {
        const uint8_t *e = pe->bytes + pe->pdata_off + i * 12;
        uint32_t begin = rd32(e);
        uint32_t end   = rd32(e + 4);
        if (begin == rva && end > begin) return end - begin;
    }
    return 0;
}

/* 符号名查找（精确匹配，重复符号取首个） */
static const MapSym *find_sym(const char *name)
{
    for (size_t i = 0; i < s_sym_count; i++) {
        if (strcmp(s_syms[i].name, name) == 0) return &s_syms[i];
    }
    return NULL;
}

/* 按节内偏移排序（供"下一符号起点"尺寸回退） */
static int sym_cmp(const void *a, const void *b)
{
    uint32_t ra = ((const MapSym *)a)->rva;
    uint32_t rb = ((const MapSym *)b)->rva;
    return (ra < rb) ? -1 : (ra > rb) ? 1 : 0;
}

/*
 * 计算函数尺寸：.pdata 精确边界优先；回退 = 同节下一更大 RVA 符号起点
 * （含尾部对齐填充——填充字节两侧一致，额外覆盖无害）。
 */
static uint32_t func_size_of(const PeInfo *pe, const MapSym *sym)
{
    uint32_t rva = sym->rva;

    uint32_t via_pdata = pdata_size_of(pe, rva);
    if (via_pdata != 0) {
        if (via_pdata > VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES) {
            die("%s 尺寸 %u 超上限 %u", sym->name, via_pdata,
                (uint32_t)VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES);
        }
        return via_pdata;
    }

    /* 回退：排序符号表中下一更大 RVA */
    uint32_t next = 0;
    int have_next = 0;
    for (size_t i = 0; i < s_sym_count; i++) {
        if (s_syms[i].rva > rva &&
            (!have_next || s_syms[i].rva < next)) {
            next = s_syms[i].rva;
            have_next = 1;
        }
    }
    /* 上界：所在节的 VA+VSize */
    uint32_t sec_end = pe->image_size;
    if (sym->section >= 1 && sym->section <= pe->sec_count) {
        uint32_t e = pe->secs[sym->section - 1].va + pe->secs[sym->section - 1].vsize;
        if (e < sec_end) sec_end = e;
    }
    uint32_t end = have_next && next < sec_end ? next : sec_end;
    uint32_t size = end - rva;
    if (size == 0) {
        die("%s 尺寸为 0（无 .pdata 边界且无后续符号）", sym->name);
    }
    if (size > VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES) {
        die("%s 尺寸 %u 超上限 %u", sym->name, size,
            (uint32_t)VERTHYS_RUNTIME_HASH_MAX_FUNC_BYTES);
    }
    return size;
}

/* ---------- 重定位槽位（文件视角） ---------- */

typedef struct FileSpot {
    uint32_t rva;
    uint8_t  width;
} FileSpot;

static FileSpot *s_spots = NULL;
static size_t    s_spot_count = 0;

static void collect_file_spots(const PeInfo *pe)
{
    if (pe->reloc_off == 0 || pe->reloc_size == 0) {
        s_spot_count = 0; /* 固定基址映像：无重定位 */
        return;
    }
    size_t cap = 4096;
    s_spots = (FileSpot *)malloc(cap * sizeof(FileSpot));
    if (!s_spots) die("内存不足");

    const uint8_t *p    = pe->bytes + pe->reloc_off;
    const uint8_t *pend = p + pe->reloc_size;
    while (p + 8 <= pend) {
        uint32_t page_rva   = rd32(p);
        uint32_t block_size = rd32(p + 4);
        if (block_size < 8 || p + block_size > pend) {
            die(".reloc 块边界异常（page=%08X size=%u）", page_rva, block_size);
        }
        for (uint32_t off = 8; off + 2 <= block_size; off += 2) {
            uint16_t e = rd16(p + off);
            uint16_t type = (uint16_t)(e >> 12);
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            uint8_t width;
            if (type == IMAGE_REL_BASED_DIR64)        width = 8;
            else if (type == IMAGE_REL_BASED_HIGHLOW) width = 4;
            else if (type == IMAGE_REL_BASED_HIGH ||
                     type == IMAGE_REL_BASED_LOW)      width = 2;
            else die("未知重定位类型 %u（无法与运行期归一化）", type);

            if (s_spot_count == cap) {
                cap *= 2;
                FileSpot *grown = (FileSpot *)realloc(s_spots,
                                                      cap * sizeof(FileSpot));
                if (!grown) die("内存不足");
                s_spots = grown;
            }
            s_spots[s_spot_count].rva   = page_rva + (e & 0x0FFF);
            s_spots[s_spot_count].width = width;
            s_spot_count++;
        }
        p += block_size;
    }

    /* 升序排序（.reloc 天然有序，防御异常映像） */
    qsort(s_spots, s_spot_count, sizeof(FileSpot), sym_cmp);
}

/* ---------- 掩码哈希（与 runtime_hash.c masked_hash 逐字节一致） ---------- */

static int masked_hash(const PeInfo *pe, uint32_t rva, uint32_t size,
                       uint8_t out[32])
{
    /* RVA → 文件偏移 */
    size_t foff = (size_t)-1;
    for (uint32_t i = 0; i < pe->sec_count; i++) {
        if (rva >= pe->secs[i].va && rva < pe->secs[i].va + pe->secs[i].vsize) {
            size_t delta = rva - pe->secs[i].va;
            if (delta >= pe->secs[i].raw_size ||
                pe->secs[i].raw_ptr + delta + size > pe->size) {
                return -1;
            }
            foff = pe->secs[i].raw_ptr + delta;
            break;
        }
    }
    if (foff == (size_t)-1) return -1;

    /* 输入缓冲：标签 ‖ 掩码后字节 */
    static const uint8_t label[] = VERTHYS_RHASH_LABEL;
    const size_t label_len = sizeof(label) - 1u;
    size_t total = label_len + size;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return -1;
    memcpy(buf, label, label_len);
    memcpy(buf + label_len, pe->bytes + foff, size);

    /* 掩码：与 [rva, rva+size) 相交槽位清零（交集裁剪，与运行期一致） */
    uint64_t end = (uint64_t)rva + size;
    for (size_t i = 0; i < s_spot_count; i++) {
        uint64_t s_start = s_spots[i].rva;
        uint64_t s_end   = s_start + s_spots[i].width;
        if (s_start >= end) break; /* 升序 */
        uint64_t o_lo = (s_start > rva) ? s_start : rva;
        uint64_t o_hi = (s_end < end) ? s_end : end;
        if (o_hi > o_lo) {
            memset(buf + label_len + (size_t)(o_lo - rva), 0,
                   (size_t)(o_hi - o_lo));
        }
    }

    int rc = crypto_generichash(out, 32, buf, (unsigned long long)total,
                                NULL, 0);
    free(buf);
    return rc == 0 ? 0 : -1;
}

/* ---------- 主流程 ---------- */

int main(int argc, char **argv)
{
    const char *bin_path = NULL;
    const char *map_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--patch") == 0 && i + 1 < argc) {
            bin_path = argv[++i];
        } else if (strcmp(argv[i], "--map") == 0 && i + 1 < argc) {
            map_path = argv[++i];
        } else {
            fprintf(stderr, "用法: rhash_gen --patch <binary> [--map <map>]\n");
            return 1;
        }
    }
    if (!bin_path) {
        fprintf(stderr, "用法: rhash_gen --patch <binary> [--map <map>]\n");
        return 1;
    }

    /* map 缺省路径：<binary> 同名 .map */
    char default_map[1024];
    if (!map_path) {
        size_t n = strlen(bin_path);
        if (n >= sizeof(default_map)) die("路径过长");
        strcpy(default_map, bin_path);
        char *dot = strrchr(default_map, '.');
        strcpy(dot ? dot : default_map + n, ".map");
        map_path = default_map;
    }

    if (sodium_init() < 0) die("libsodium 初始化失败");

    PeInfo pe;
    memset(&pe, 0, sizeof(pe));
    pe_parse(&pe, bin_path);
    map_parse(&pe, map_path);
    qsort(s_syms, s_sym_count, sizeof(MapSym), sym_cmp); /* 尺寸回退前提 */
    collect_file_spots(&pe);

    /* X 清单全量命中（红线：缺一即失败） */
    if (X_FUNC_COUNT > VERTHYS_RUNTIME_HASH_MAX) {
        die("X 清单 %zu 超表容量 %u", X_FUNC_COUNT, VERTHYS_RUNTIME_HASH_MAX);
    }

    VerthysRhatBlob blob;
    memset(&blob, 0, sizeof(blob));
    blob.magic[0] = VERTHYS_RHAT_MAGIC0;
    blob.magic[1] = VERTHYS_RHAT_MAGIC1;
    blob.magic[2] = VERTHYS_RHAT_MAGIC2;
    blob.magic[3] = VERTHYS_RHAT_MAGIC3;
    blob.version  = VERTHYS_RHAT_VERSION;
    blob.count    = (uint16_t)X_FUNC_COUNT;

    size_t total_bytes = 0;
    for (size_t xi = 0; xi < X_FUNC_COUNT; xi++) {
        const char *name = s_x_names[xi];
        const MapSym *sym = find_sym(name);
        if (!sym) die("X 清单符号缺失于 map: %s（禁静默降级）", name);

        uint32_t size = func_size_of(&pe, sym);
        uint8_t hash[32];
        if (masked_hash(&pe, sym->rva, size, hash) != 0) {
            die("%s 哈希计算失败（RVA=%08X size=%u）", name, sym->rva, size);
        }

        blob.entry[xi].rva     = sym->rva;
        blob.entry[xi].size    = size;
        blob.entry[xi].x_index = (uint32_t)xi;
        memcpy(blob.entry[xi].hash, hash, 32);
        total_bytes += size;

        printf("  [rhat] %-32s rva=%08X size=%5u hash=%02X%02X%02X%02X...\n",
               name, sym->rva, size, hash[0], hash[1], hash[2], hash[3]);
    }

    /* 补丁 .rhat（文件内原位写 16+48×N 字节） */
    {
        const PeSection *rhat = &pe.secs[pe.rhat_index];
        FILE *f = fopen(bin_path, "r+b");
        if (!f) die("无法写打开二进制: %s", bin_path);
        if (fseek(f, (long)rhat->raw_ptr, SEEK_SET) != 0 ||
            fwrite(&blob, 1, sizeof(blob), f) != sizeof(blob)) {
            die(".rhat 补丁写入失败（raw=%u size=%u）",
                rhat->raw_ptr, rhat->raw_size);
        }
        fclose(f);
    }

    printf("[rhat] .rhat 补丁完成: %s（%zu 函数 / %zu 字节 / %zu 重定位槽位）\n",
           bin_path, X_FUNC_COUNT, total_bytes, s_spot_count);

    free(pe.bytes);
    free(pe.secs);
    free(s_syms);
    free(s_spots);
    return 0;
}
