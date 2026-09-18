/*
 * @file infrastructure/path_resolver.rs
 * @brief 路径解析与完整性校验基础设施
 *
 * 本模块负责解析 verthys-worker.exe 和 verthys.dll 的运行时路径，
 * 并提供 DLL 完整性校验能力（SHA-256 比对编译时嵌入哈希）。
 * 路径解析策略优先使用开发环境最新构建产物，生产环境回退至 Tauri 资源目录。
 * 完整性校验为非阻塞性安全审计手段，哈希不匹配仅记录警告而不阻断启动，
 * 以规避因构建顺序、代码签名等导致的误报。
 *
 * 依赖：
 *   - dll_hash：编译时由 build.rs 嵌入的 DLL 哈希
 *   - sha2：用于 SHA-256 计算
 *   - tauri::AppHandle：用于资源路径解析
 *
 * 安全约束：
 *   - DLL 校验仅用于日志审计，不作为严格安全门禁
 *   - 路径解析结果需经 sanitize_path 脱敏后记录日志，避免泄露本地文件结构
 */

use crate::dll_hash;
use crate::util::path::sanitize_path;
use tauri::Manager;

/// 校验 verthys.dll 的 SHA-256 哈希是否与编译时嵌入值一致
///
/// 该函数在进程启动时调用，用于检测 DLL 是否被意外替换。
/// 校验失败仅记录安全警告日志，不阻断启动流程，原因如下：
/// - 增量编译、代码签名、构建顺序可能导致实际哈希与嵌入值不一致
/// - 严格阻断会造成生产环境不可用，违背可用性优先原则
/// - 运维人员应通过日志审计发现异常，而非依赖运行时阻断
///
/// # 参数
/// - `dll_path`：DLL 文件绝对路径
///
/// # 返回
/// - `Ok(())`：校验通过或跳过（文件不存在、未嵌入哈希等）
/// - 不返回错误，所有异常情况均以日志记录并静默通过
pub fn verify_dll_integrity(dll_path: &str) -> Result<(), String> {
    use sha2::{Digest, Sha256};

    let embedded_hash = dll_hash::DLL_HASH;
    if embedded_hash.is_none() {
        log::warn!("[DLL 校验] 编译时未嵌入 DLL 哈希，跳过校验（可能构建顺序异常）");
        return Ok(());
    }

    let expected = embedded_hash.unwrap();
    let data = match std::fs::read(dll_path) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("[DLL 校验] 读取 DLL 失败，跳过校验: {}", e);
            return Ok(());
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let actual = format!("{:x}", hasher.finalize());

    if actual != expected {
        // ★ 企业级根治：dev 环境哈希不匹配强制阻断（根治 worker 0xC0000005 崩溃）
        //
        // 原缺陷：哈希不匹配仅 warn 不阻断（return Ok），导致过期 DLL 被加载。
        //   典型场景：path_resolver 因路径深度错误回退到 target/debug/verthys.dll
        //   （7/30 构建，VerthysSummaryRecord 80 字节布局，无 slot_state），而 worker
        //   exe 为最新（88 字节布局，含 slot_state）。FFI 布局不匹配导致
        //   Verthys_ScanSummaryFetch 返回的结构体字段错位 → rec.name 指针读到垃圾值
        //   → std::slice::from_raw_parts 解引用 0x0 → worker 0xC0000005 崩溃 →
        //   后续 verthys_derive_global_key/verthys_verify_global_key IPC 全部失败 →
        //   用户看到"无法初始化密钥/无法身份验证"。
        //
        // 根治策略（分层阻断）：
        //   - dev 环境（debug_assertions）：哈希不匹配返回 Err，worker_controller
        //     返回 IntegrityViolation 明确错误，前端展示通用提示，引导重建/同步
        //     DLL，而非静默加载过期副本导致 worker 崩溃。build.rs 编译时计算
        //     build/core/Release/verthys.dll 哈希嵌入 exe，dev 环境加载该 DLL
        //     哈希必然匹配，不匹配即说明加载了过期/错误副本，必须阻断。
        //   - 生产环境（release）：保持 warn 不阻断。代码签名、构建顺序可能导致
        //     哈希漂移，严格阻断会造成生产不可用，违背可用性优先原则。
        if cfg!(debug_assertions) {
            log::error!(
                "[DLL 校验] DLL 哈希不匹配（dev 环境强制阻断）expected={} actual={} — \
                 拒绝加载，防止 FFI 布局不匹配导致 worker 崩溃",
                expected, actual
            );
            // 返回脱敏错误（不含哈希值，符合"禁止输出错误具体信息"约束）
            return Err(
                "DLL 完整性校验失败：加载的加密核心与编译时不一致，请重新编译或同步 Release 版本".into(),
            );
        }
        log::warn!(
            "[DLL 校验] DLL 哈希不匹配（安全警告）expected={} actual={} — 已记录，继续启动",
            expected, actual
        );
        return Ok(());
    }

    log::info!("[DLL 校验] DLL 哈希校验通过: {}", expected);
    Ok(())
}

/// 获取编译时嵌入的 DLL SHA-256 哈希前缀（前 16 字符）
///
/// 该哈希前缀用于诊断信息（如 DiagInfo），便于区分不同版本，
/// 同时不泄露完整哈希值，降低哈希碰撞攻击风险。
/// 若编译时未嵌入哈希，返回空字符串。
pub fn get_dll_hash_prefix() -> String {
    dll_hash::DLL_HASH
        .map(|h| h.chars().take(16).collect())
        .unwrap_or_default()
}

/// 检查 VC++ 运行库依赖是否存在（仅 Windows）
///
/// 在 Windows 平台检查 System32 目录下是否存在 vcruntime140.dll 等
/// 常见 VC++ 运行库文件，用于提前预判子进程能否正常启动。
/// 缺失时返回包含具体缺失文件的错误信息，引导用户安装 Redistributable。
/// 非 Windows 平台静默跳过。
pub fn check_dll_dependencies(_dll_path: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let system32 = std::env::var("SystemRoot")
            .unwrap_or_else(|_| r"C:\Windows".into());
        let system32_dir = std::path::Path::new(&system32).join("System32");

        let required_runtimes = [
            "vcruntime140.dll",
            "msvcp140.dll",
            "vcruntime140_1.dll",
        ];

        let mut missing = Vec::new();
        for dll in &required_runtimes {
            let full_path = system32_dir.join(dll);
            if !full_path.exists() {
                missing.push(dll.to_string());
            }
        }

        if !missing.is_empty() {
            return Err(format!(
                "缺少 VC++ 运行库依赖: {} — 请安装 Microsoft Visual C++ Redistributable",
                missing.join(", ")
            ));
        }

        log::info!("[DLL 依赖] VC++ 运行库依赖检查通过");
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = dll_path;
    }

    Ok(())
}

/* ------------------------------------------------------------------ *
 * PE 架构校验（企业级前置门禁）                                       *
 *                                                                    *
 * 背景：                                                             *
 *   verthys-worker.exe 若为 32-bit（x86）而 verthys.dll 为 64-bit，   *
 *   Windows 加载器会在 main() 执行前终止子进程（exit code 0、零输出、*
 *   "file not found"）。此类失败无法通过就绪超时准确诊断：           *
 *     - stderr 为空（main 从未运行，panic hook 未触发）              *
 *     - 退出码为 0（加载器失败，非应用退出码）                       *
 *   表现为"安全子进程就绪超时"，误导排查方向。                       *
 *                                                                    *
 * 方案：                                                             *
 *   在 spawn 子进程之前，通过解析 PE 头的 Machine 字段主动校验       *
 *   worker exe 与 DLL 架构一致且为 x86_64（与主进程一致），          *
 *   不匹配时立即返回明确错误，避免进入静默加载器失败路径。           *
 *                                                                    *
 * 实现：                                                             *
 *   - 纯 Rust 解析 PE 头（无外部依赖）                               *
 *   - 仅读文件头部 < 1KB，不加载整个文件                             *
 *   - 解析失败返回 Err，绝不 panic                                   *
 * ------------------------------------------------------------------ */

/// PE 文件机器类型（架构）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArch {
    /// 0x014C — IMAGE_FILE_MACHINE_I386（32-bit）
    X86,
    /// 0x8664 — IMAGE_FILE_MACHINE_AMD64（64-bit）
    X64,
    /// 0xAA64 — IMAGE_FILE_MACHINE_ARM64
    Arm64,
    /// 未知机器类型（保留原始值用于诊断）
    Unknown(u16),
}

impl PeArch {
    /// 用户可读的架构名称（用于日志，不含敏感信息）
    pub fn as_str(&self) -> &'static str {
        match self {
            PeArch::X86 => "x86(32-bit)",
            PeArch::X64 => "x86_64(64-bit)",
            PeArch::Arm64 => "arm64",
            PeArch::Unknown(_) => "unknown",
        }
    }
}

/// 读取 PE 文件的机器类型（架构）
///
/// 解析流程：DOS 头 e_lfanew（偏移 0x3C）→ PE 签名 → COFF Machine 字段。
/// 仅读取文件头部，不加载整个文件到内存，对任意路径安全。
///
/// # 参数
/// - `path`：PE 文件（exe/dll）绝对路径
///
/// # 返回
/// - `Ok(PeArch)`：成功解析
/// - `Err(String)`：文件无法打开、非 PE 镜像、头部损坏等
pub fn detect_pe_architecture(path: &str) -> Result<PeArch, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut f = std::fs::File::open(path).map_err(|e| format!("open: {}", e))?;

    // DOS 头：前 64 字节足够读取 e_lfanew（偏移 0x3C，4 字节）
    let mut dos = [0u8; 64];
    f.read_exact(&mut dos).map_err(|e| format!("read dos header: {}", e))?;
    if dos[0] != b'M' || dos[1] != b'Z' {
        return Err("not a PE/DOS image (missing MZ signature)".into());
    }
    let e_lfanew = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as u64;
    // e_lfanew 合法范围：>= 64（DOS 头之后），<= 0x1000（PE 头不会离 DOS 头太远）
    if !(64..=0x1000).contains(&e_lfanew) {
        return Err(format!("invalid e_lfanew: 0x{:X}", e_lfanew));
    }

    f.seek(SeekFrom::Start(e_lfanew))
        .map_err(|e| format!("seek to PE header: {}", e))?;
    // PE 签名 (4B "PE\0\0") + COFF 头 (20B)：Machine 字段在偏移 +4
    let mut pe = [0u8; 24];
    f.read_exact(&mut pe).map_err(|e| format!("read PE/COFF header: {}", e))?;
    if pe[0] != b'P' || pe[1] != b'E' || pe[2] != 0 || pe[3] != 0 {
        return Err("missing PE signature".into());
    }
    let machine = u16::from_le_bytes([pe[4], pe[5]]);

    Ok(match machine {
        0x014C => PeArch::X86,
        0x8664 => PeArch::X64,
        0xAA64 => PeArch::Arm64,
        other => PeArch::Unknown(other),
    })
}

/// 校验 worker exe 与 verthys.dll 架构一致且为 x86_64
///
/// 企业级安全前置门禁：在 spawn 子进程之前，确认 worker 二进制与
/// verthys.dll 架构匹配（均为 x86_64），避免 32-bit worker 加载
/// 64-bit DLL 导致的静默加载器失败。
///
/// 此类失败无法通过就绪超时准确诊断（stderr 为空、退出码为 0），
/// 必须在 spawn 前通过 PE 头解析主动检测。
///
/// # 参数
/// - `worker_exe`：verthys-worker.exe 绝对路径
/// - `dll_path`：verthys.dll 绝对路径
///
/// # 返回
/// - `Ok(())`：两者均为 x86_64 且一致
/// - `Err(String)`：架构不匹配或不符合 x86_64 要求（错误信息已脱敏，仅含架构名）
pub fn verify_binary_architecture(worker_exe: &str, dll_path: &str) -> Result<(), String> {
    let worker_arch = detect_pe_architecture(worker_exe)
        .map_err(|e| format!("worker exe 架构解析失败: {}", e))?;
    let dll_arch = detect_pe_architecture(dll_path)
        .map_err(|e| format!("dll 架构解析失败: {}", e))?;

    log::info!(
        "[arch_check] worker={} dll={}",
        worker_arch.as_str(),
        dll_arch.as_str()
    );

    if worker_arch != dll_arch {
        return Err(format!(
            "架构不匹配: worker={} dll={}",
            worker_arch.as_str(),
            dll_arch.as_str()
        ));
    }

    // 强制要求 x86_64：主进程为 64-bit，worker 与 DLL 必须同架构
    if worker_arch != PeArch::X64 {
        return Err(format!(
            "架构不符合要求（需 x86_64）: worker={}",
            worker_arch.as_str()
        ));
    }

    Ok(())
}

/* ------------------------------------------------------------------ *
 * PE 导入表解析（企业级依赖预检）                                     *
 *                                                                    *
 * 背景：                                                             *
 *   check_dll_dependencies 仅校验 VC++ 运行库是否存在于 System32，   *
 *   无法发现 worker exe / verthys.dll 的其它导入依赖缺失。          *
 *   加载器级失败（exit code 0 + 零 stderr）的根因往往是某个导入      *
 *   DLL 在搜索路径中不可达（如应用级 DLL 未随包发布、系统级 DLL     *
 *   在精简版 Windows 中缺失）。                                      *
 *                                                                    *
 * 方案：                                                             *
 *   解析 PE Import Directory Table，提取所有被导入的 DLL 名称，      *
 *   按 Windows 加载器搜索顺序逐一确认可访问：                        *
 *     1. exe 同级目录（应用级 DLL，如 verthys.dll）                 *
 *     2. System32（64-bit 进程的系统 DLL 目录）                      *
 *     3. Windows 目录                                                *
 *     4. PATH 环境变量                                               *
 *   缺失任一依赖即返回明确错误，避免进入静默加载器失败路径。         *
 * ------------------------------------------------------------------ */

/// 解析 PE 文件的导入表，返回所有被导入的 DLL 名称（去重、小写）
///
/// 解析流程：
///   DOS 头 e_lfanew → PE 签名 → COFF 头（Machine/NumberOfSections/
///   SizeOfOptionalHeader）→ Optional Header magic（PE32/PE32+）→
///   Data Directory[1]（Import Directory RVA/Size）→ Section Headers →
///   RVA→File Offset 映射 → 遍历 IMPORT 描述符数组读取 Name 字符串。
///
/// 仅读取必要的字节，不加载整个文件到内存。对任意 PE 路径安全，
/// 解析失败返回 Err，绝不 panic。
///
/// # 参数
/// - `path`：PE 文件（exe/dll）绝对路径
///
/// # 返回
/// - `Ok(Vec<String>)`：去重后的导入 DLL 名称列表（小写，含扩展名）
/// - `Err(String)`：文件无法打开、非 PE 镜像、头部损坏等
pub fn parse_pe_imports(path: &str) -> Result<Vec<String>, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut f = std::fs::File::open(path).map_err(|e| format!("open: {}", e))?;

    // ---- DOS 头：读取 e_lfanew（偏移 0x3C）----
    let mut dos = [0u8; 64];
    f.read_exact(&mut dos)
        .map_err(|e| format!("read dos header: {}", e))?;
    if dos[0] != b'M' || dos[1] != b'Z' {
        return Err("not a PE/DOS image (missing MZ signature)".into());
    }
    let e_lfanew = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as u64;
    if !(64..=0x1000).contains(&e_lfanew) {
        return Err(format!("invalid e_lfanew: 0x{:X}", e_lfanew));
    }

    // ---- PE 签名 (4B) + COFF 头 (20B) ----
    f.seek(SeekFrom::Start(e_lfanew))
        .map_err(|e| format!("seek to PE header: {}", e))?;
    let mut pe_coff = [0u8; 24];
    f.read_exact(&mut pe_coff)
        .map_err(|e| format!("read PE/COFF header: {}", e))?;
    if pe_coff[0] != b'P' || pe_coff[1] != b'E' || pe_coff[2] != 0 || pe_coff[3] != 0 {
        return Err("missing PE signature".into());
    }

    // COFF 头字段
    let num_sections = u16::from_le_bytes([pe_coff[6], pe_coff[7]]) as u64;
    let size_of_optional_header = u16::from_le_bytes([pe_coff[20], pe_coff[21]]) as u64;
    if num_sections == 0 || num_sections > 96 {
        return Err(format!("invalid NumberOfSections: {}", num_sections));
    }

    // ---- Optional Header：判定 PE32 / PE32+ 以定位 Data Directories ----
    let opt_off = e_lfanew + 24;
    f.seek(SeekFrom::Start(opt_off))
        .map_err(|e| format!("seek to optional header: {}", e))?;
    let mut opt_magic = [0u8; 2];
    f.read_exact(&mut opt_magic)
        .map_err(|e| format!("read optional header magic: {}", e))?;

    // Data Directories 起始偏移（相对 Optional Header 起点）：
    //   PE32  (0x010B)：标准字段 28B + Windows 特定字段 68B = 96B
    //   PE32+ (0x020B)：标准字段 24B + Windows 特定字段 88B = 112B
    let data_dir_off = match opt_magic {
        [0x0B, 0x01] => opt_off + 96,  // PE32
        [0x0B, 0x02] => opt_off + 112, // PE32+
        _ => {
            return Err(format!(
                "unknown optional header magic: 0x{:02X}{:02X}",
                opt_magic[1], opt_magic[0]
            ));
        }
    };

    // Import Directory = Data Directory[1]（每条 8B：RVA + Size）
    if size_of_optional_header < 112 + 8 * 2 {
        return Err("optional header too small for import directory entry".into());
    }
    let import_dir_entry_off = data_dir_off + 8; // 跳过 Export Directory[0]
    f.seek(SeekFrom::Start(import_dir_entry_off))
        .map_err(|e| format!("seek to import dir entry: {}", e))?;
    let mut import_dir = [0u8; 8];
    f.read_exact(&mut import_dir)
        .map_err(|e| format!("read import dir entry: {}", e))?;
    let import_rva =
        u32::from_le_bytes([import_dir[0], import_dir[1], import_dir[2], import_dir[3]]) as u64;
    let import_size =
        u32::from_le_bytes([import_dir[4], import_dir[5], import_dir[6], import_dir[7]]) as u64;

    if import_rva == 0 || import_size == 0 {
        // 无导入表（罕见，如纯静态链接二进制）
        return Ok(Vec::new());
    }

    // ---- Section Headers（每条 40B）：构造 RVA → File Offset 映射 ----
    let sections_off = opt_off + size_of_optional_header;
    f.seek(SeekFrom::Start(sections_off))
        .map_err(|e| format!("seek to section headers: {}", e))?;
    let mut sections_buf = vec![0u8; (num_sections * 40) as usize];
    f.read_exact(&mut sections_buf)
        .map_err(|e| format!("read section headers: {}", e))?;

    // RVA → File Offset 转换：查找包含该 RVA 的区段
    let rva_to_offset = |rva: u64| -> Option<u64> {
        for i in 0..num_sections as usize {
            let base = i * 40;
            let virtual_size = u32::from_le_bytes([
                sections_buf[base + 8],
                sections_buf[base + 9],
                sections_buf[base + 10],
                sections_buf[base + 11],
            ]) as u64;
            let virtual_addr = u32::from_le_bytes([
                sections_buf[base + 12],
                sections_buf[base + 13],
                sections_buf[base + 14],
                sections_buf[base + 15],
            ]) as u64;
            let ptr_raw = u32::from_le_bytes([
                sections_buf[base + 20],
                sections_buf[base + 21],
                sections_buf[base + 22],
                sections_buf[base + 23],
            ]) as u64;
            if virtual_size == 0 {
                continue;
            }
            if rva >= virtual_addr && rva < virtual_addr + virtual_size {
                return Some(ptr_raw + (rva - virtual_addr));
            }
        }
        None
    };

    // ---- 遍历 IMPORT 描述符数组（每条 20B，末尾全零终止）----
    let import_file_off = rva_to_offset(import_rva)
        .ok_or_else(|| format!("import RVA 0x{:X} not in any section", import_rva))?;

    let mut imports: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut buf = [0u8; 20];
    let mut cur = import_file_off;
    // 上限保护：导入描述符数量不会超过区段大小 / 20 + 8
    let max_descriptors = (import_size as usize / 20) + 8;
    for _ in 0..max_descriptors {
        f.seek(SeekFrom::Start(cur))
            .map_err(|e| format!("seek to import descriptor: {}", e))?;
        if f.read_exact(&mut buf).is_err() {
            break; // 文件结束
        }
        // Name RVA 在描述符偏移 +12
        let name_rva = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as u64;
        if name_rva == 0 {
            break; // 终止符
        }
        let name_off = match rva_to_offset(name_rva) {
            Some(o) => o,
            None => {
                // 名称 RVA 无法映射，跳过此条（不致命）
                cur += 20;
                continue;
            }
        };
        f.seek(SeekFrom::Start(name_off))
            .map_err(|e| format!("seek to dll name: {}", e))?;
        // 读取以 null 结尾的 ASCII 字符串
        let mut name = Vec::with_capacity(32);
        let mut b = [0u8; 1];
        loop {
            if f.read_exact(&mut b).is_err() {
                break;
            }
            if b[0] == 0 {
                break;
            }
            name.push(b[0]);
            if name.len() > 256 {
                break; // 防止损坏的字符串导致无限读取
            }
        }
        if let Ok(s) = String::from_utf8(name) {
            let lower = s.to_lowercase();
            if seen.insert(lower.clone()) {
                imports.push(lower);
            }
        }
        cur += 20;
    }

    Ok(imports)
}

/// Windows 加载器搜索顺序中查找指定 DLL
///
/// 搜索顺序（简化版 SafeDllSearchMode，与 Windows 加载器一致）：
///   1. exe 同级目录（应用级 DLL，如 verthys.dll）
///   2. System32（64-bit 进程系统 DLL 目录）
///   3. Windows 目录（SystemRoot 根）
///   4. PATH 环境变量中的目录
///
/// 返回首个命中目录的字符串（用于日志），未命中返回 None。
fn find_dll_in_search_paths(dll_name: &str, exe_dir: &std::path::Path) -> Option<String> {
    // 1. exe 同级目录
    if exe_dir.join(dll_name).exists() {
        return Some("exe_dir".to_string());
    }

    // 2. System32 / 3. Windows 目录
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let system32 = std::path::Path::new(&system_root).join("System32");
    if system32.join(dll_name).exists() {
        return Some("System32".to_string());
    }
    if std::path::Path::new(&system_root).join(dll_name).exists() {
        return Some("Windows".to_string());
    }

    // 4. PATH 环境变量
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(';') {
            if dir.is_empty() {
                continue;
            }
            if std::path::Path::new(dir).join(dll_name).exists() {
                return Some("PATH".to_string());
            }
        }
    }

    None
}

/// 校验 worker exe 与 verthys.dll 的全部导入依赖可访问（企业级预检）
///
/// 在 spawn 子进程之前，解析两个 PE 文件的导入表，对每个被导入的
/// DLL 按 Windows 加载器搜索顺序确认可访问。缺失任一依赖将导致
/// 加载器级失败（exit code 0 + 零 stderr），无法通过就绪超时诊断，
/// 必须在此主动拦截。
///
/// 此函数在 `check_dll_dependencies`（VC++ 运行库基础检查）之上扩展：
///   - VC++ 运行库：vcruntime140 / msvcp140 / vcruntime140_1 / ucrtbase
///   - 应用级 DLL：verthys.dll（worker 导入它）等
///   - 系统 DLL：kernel32 / user32 / advapi32 等（缺失视为系统损坏）
///
/// # 参数
/// - `worker_exe`：verthys-worker.exe 绝对路径
/// - `dll_path`：verthys.dll 绝对路径
///
/// # 返回
/// - `Ok(())`：全部导入依赖可访问
/// - `Err(String)`：缺失依赖列表（错误信息已脱敏，仅含 DLL 名称）
pub fn check_binary_dependencies(worker_exe: &str, dll_path: &str) -> Result<(), String> {
    // 1. 基础检查：VC++ 运行库（保持与 check_dll_dependencies 一致的行为）
    check_dll_dependencies(dll_path)?;

    // 2. 确定 exe 同级目录（应用级 DLL 搜索基准）
    let exe_dir = std::path::Path::new(worker_exe)
        .parent()
        .ok_or_else(|| "无法解析 worker exe 所在目录".to_string())?;

    // 3. 解析 worker exe 与 verthys.dll 的导入表
    let worker_imports = parse_pe_imports(worker_exe)
        .map_err(|e| format!("worker exe 导入表解析失败: {}", e))?;
    let dll_imports = parse_pe_imports(dll_path)
        .map_err(|e| format!("verthys.dll 导入表解析失败: {}", e))?;

    log::debug!(
        "[dep_check] worker 导入 {} 项, dll 导入 {} 项",
        worker_imports.len(),
        dll_imports.len()
    );

    // 4. 合并去重，逐一校验可访问性
    let mut all_imports = std::collections::HashSet::new();
    for imp in worker_imports.iter().chain(dll_imports.iter()) {
        all_imports.insert(imp.clone());
    }

    let mut missing: Vec<String> = Vec::new();
    for imp in &all_imports {
        if find_dll_in_search_paths(imp, exe_dir).is_none() {
            missing.push(imp.clone());
        }
    }

    if !missing.is_empty() {
        // 已脱敏：仅含 DLL 文件名，不含路径
        return Err(format!(
            "缺失导入依赖: {} — 请确认依赖 DLL 已随包发布或系统运行库已安装",
            missing.join(", ")
        ));
    }

    log::info!(
        "[dep_check] 导入依赖校验通过（共 {} 项）",
        all_imports.len()
    );
    Ok(())
}

/// 解析 verthys-worker.exe 的绝对路径
///
/// 路径搜索顺序：
/// 1. 开发环境：当前 exe 位于 `target/{debug,release}` 下时，
///    优先查找 `../../../verthys-worker/target/{release,debug}/verthys-worker.exe`
///    保证使用最新构建产物。
/// 2. 生产环境：依次尝试 Tauri 资源目录（`binaries/`、根目录）、
///    可执行文件同级目录（包括 `binaries/`、`resources/binaries/` 等）。
/// 3. 兜底：当前工作目录下的相对路径。
///
/// 所有搜索到的路径均会经 `sanitize_path` 脱敏后记录日志。
/// 若所有策略均失败，返回包含已尝试范围的错误信息。
pub fn resolve_worker_path(app: &tauri::AppHandle) -> Result<String, String> {
    let exe_name = if cfg!(target_os = "windows") {
        "verthys-worker.exe"
    } else {
        "verthys-worker"
    };

    // 1. 开发环境优先
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let exe_dir_str = exe_dir.display().to_string().replace('/', "\\");
            let is_dev = exe_dir_str.ends_with("\\target\\debug")
                || exe_dir_str.ends_with("\\target\\release");

            if is_dev {
                for profile in &["release", "debug"] {
                    let p = exe_dir
                        .join(format!("../../../verthys-worker/target/{}/{}", profile, exe_name));
                    if p.exists() {
                        let abs = p.canonicalize().map_err(|e| e.to_string())?;
                        log::info!("[resolve_worker] 开发环境命中: {}", sanitize_path(&abs.display().to_string()));
                        return Ok(abs.display().to_string());
                    }
                }
            }
        }
    }

    // 2. Tauri 资源目录
    let resource_candidates = [
        "binaries/verthys-worker".to_string(),
        "verthys-worker".to_string(),
    ];
    for rel in &resource_candidates {
        if let Ok(path) = app.path().resolve(rel, tauri::path::BaseDirectory::Resource) {
            let exe = if cfg!(target_os = "windows") {
                format!("{}.exe", path.display())
            } else {
                path.display().to_string()
            };
            if std::path::Path::new(&exe).exists() {
                log::info!("[resolve_worker] 资源路径命中: {}", sanitize_path(&exe));
                return Ok(exe);
            }
        }
    }

    // 3. 可执行文件同级目录
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let exe_based = [
                exe_dir.join(format!("binaries/{}", exe_name)),
                exe_dir.join(exe_name),
                exe_dir.join(format!("resources/binaries/{}", exe_name)),
                exe_dir.join(format!("resources/{}", exe_name)),
            ];
            for p in &exe_based {
                if p.exists() {
                    let abs = p.canonicalize().map_err(|e| e.to_string())?;
                    log::info!("[resolve_worker] exe 同级命中: {}", sanitize_path(&abs.display().to_string()));
                    return Ok(abs.display().to_string());
                }
            }
        }
    }

    // 4. 当前工作目录相对路径（兜底）
    let dev_candidates = [
        "../verthys-worker/target/release/verthys-worker.exe",
        "../verthys-worker/target/debug/verthys-worker.exe",
        "../../verthys-worker/target/release/verthys-worker.exe",
        "../../verthys-worker/target/debug/verthys-worker.exe",
    ];
    for c in &dev_candidates {
        if std::path::Path::new(c).exists() {
            let abs = std::fs::canonicalize(c).map_err(|e| e.to_string())?;
            log::info!("[resolve_worker] CWD 相对命中: {}", sanitize_path(&abs.display().to_string()));
            return Ok(abs.display().to_string());
        }
    }

    Err(format!(
        "verthys-worker ({}) 未找到。已尝试：开发目录、资源目录(binaries/|根)、exe同级、CWD相对",
        exe_name
    ))
}

/// 解析 verthys.dll 的绝对路径
///
/// 搜索策略与 `resolve_worker_path` 类似，但针对 DLL 文件：
/// 1. 开发环境：当前 exe 在 `target/{debug,release}` 下时，
///    查找 `../../../../build/core/Release/verthys.dll`。
/// 2. 生产环境：Tauri 资源目录、可执行文件同级（含 `resources/`、`_up_/` 嵌套路径）。
/// 3. 兜底：当前工作目录及向上递归查找 `build/core/Release/`。
///
/// 路径匹配成功后将通过 `sanitize_path` 脱敏后记录日志。
///
/// ★ 企业级根治：dev-env 相对路径深度修正（根治 worker 0xC0000005 崩溃）
///
/// 原缺陷：原路径 `../../../build/core/Release/verthys.dll` 仅上溯 3 级，
///   从 `verthys-tauri/src-tauri/target/{debug,release}` 出发落到
///   `verthys-tauri/build/`（不存在）。build/ 实际位于仓库根 `Verthys/build/`，
///   需上溯 4 级。对比 resolve_worker_path 用 `../../../verthys-worker/...` 是
///   正确的——因为 verthys-worker/ 挂在 verthys-tauri/ 下（3 级即可命中），而
///   build/ 挂在 Verthys/ 下（需 4 级）。
///
///   步骤 1 因深度错误失败后，回退到步骤 2（Tauri 资源目录），命中
///   `src-tauri/target/debug/verthys.dll` 或 `src-tauri/verthys.dll` ——
///   这两份是 7/30 的过期拷贝，早于 C 端 VerthysSummaryRecord 引入 slot_state
///   字段。固定后的 Rust worker（sizeof=88）读取旧 DLL 写入的 80 字节记录，
///   name 指针字段错位读到垃圾值 → 解引用空指针 → worker 0xC0000005 at 0x0
///   崩溃 → 后续 verthys_derive_global_key/verthys_verify_global_key 报
///   "worker 子进程已退出" → 用户看到"无法初始化密钥/无法身份验证"。
///
/// 修复：上溯深度 3→4，确保 dev 环境优先命中 build/core/Release/verthys.dll
///   （与 worker 同源、与 Rust FFI 布局严格对齐的 Release 构建）。
pub fn resolve_dll_path(app: &tauri::AppHandle) -> Result<String, String> {
    // 1. 开发环境优先
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let exe_dir_str = exe_dir.display().to_string().replace('/', "\\");
            let is_dev = exe_dir_str.ends_with("\\target\\debug")
                || exe_dir_str.ends_with("\\target\\release");

            if is_dev {
                // ★ 企业级根治：4 级上溯抵达仓库根 Verthys/build/core/Release/
                //   exe_dir = Verthys/verthys-tauri/src-tauri/target/{debug,release}
                //   ../../../../ → Verthys/  → build/core/Release/verthys.dll ✓
                //   （原 ../../../ 仅到 verthys-tauri/，build/ 不在此层 → 回退到过期 DLL）
                let p = exe_dir.join("../../../../build/core/Release/verthys.dll");
                if p.exists() {
                    let abs = p.canonicalize().map_err(|e| e.to_string())?;
                    log::info!("[resolve_dll] 开发环境命中: {}", sanitize_path(&abs.display().to_string()));
                    return Ok(abs.display().to_string());
                }
            }
        }
    }

    // 2. Tauri 资源目录
    if let Ok(path) = app.path().resolve("verthys.dll", tauri::path::BaseDirectory::Resource) {
        if path.exists() {
            log::info!("[resolve_dll] 资源路径命中: {}", sanitize_path(&path.display().to_string()));
            return Ok(path.display().to_string());
        }
    }

    // 3. 可执行文件同级目录（含 resources/、_up_/ 等嵌套）
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let exe_based = [
                exe_dir.join("verthys.dll"),
                exe_dir.join("resources/verthys.dll"),
                exe_dir.join("_up_/_up_/build/core/Release/verthys.dll"),
                exe_dir.join("_up_/build/core/Release/verthys.dll"),
            ];
            for p in &exe_based {
                if p.exists() {
                    let abs = p.canonicalize().map_err(|e| e.to_string())?;
                    log::info!("[resolve_dll] exe 同级命中: {}", sanitize_path(&abs.display().to_string()));
                    return Ok(abs.display().to_string());
                }
            }
        }
    }

    // 4. 当前工作目录相对路径
    let candidates = [
        "../../build/core/Release/verthys.dll",
        "../../../build/core/Release/verthys.dll",
        "../build/core/Release/verthys.dll",
        "build/core/Release/verthys.dll",
    ];

    for c in &candidates {
        if std::path::Path::new(c).exists() {
            let abs = std::fs::canonicalize(c).map_err(|e| e.to_string())?;
            log::info!("[resolve_dll] CWD 相对命中: {}", sanitize_path(&abs.display().to_string()));
            return Ok(abs.display().to_string());
        }
    }

    // 5. 向上递归查找
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            for depth in 1..=5 {
                let p = exe_dir
                    .join("../".repeat(depth))
                    .join("build/core/Release/verthys.dll");
                if p.exists() {
                    return Ok(p.canonicalize().map_err(|e| e.to_string())?.display().to_string());
                }
            }
        }
    }

    // 6. 当前工作目录根
    if std::path::Path::new("verthys.dll").exists() {
        return Ok(std::fs::canonicalize("verthys.dll")
            .map_err(|e| e.to_string())?
            .display()
            .to_string());
    }

    Err("verthys.dll 未找到。已尝试：资源目录、exe同级、开发目录".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 解析当前测试二进制自身的 PE 头，验证架构检测返回已知值。
    /// 测试二进制由 cargo 编译生成，必为合法 PE 镜像。
    #[test]
    fn test_detect_pe_architecture_on_self() {
        let exe = std::env::current_exe().expect("current_exe");
        let arch = detect_pe_architecture(&exe.display().to_string());
        assert!(arch.is_ok(), "detect_pe_architecture 应成功: {:?}", arch);
        let arch = arch.unwrap();
        // 测试二进制架构应为主机架构之一（Windows 上通常为 X64）
        assert!(
            arch == PeArch::X64 || arch == PeArch::X86 || arch == PeArch::Arm64,
            "意外架构: {:?}",
            arch
        );
    }

    /// 非 PE 文件应返回错误，绝不 panic
    #[test]
    fn test_detect_pe_architecture_non_pe() {
        // 创建临时文件，内容非 MZ
        let tmp = std::env::temp_dir().join("verthys_pe_test_nonpe.bin");
        std::fs::write(&tmp, b"NOT_A_PE_FILE_CONTENT").expect("write temp");
        let r = detect_pe_architecture(tmp.to_str().unwrap());
        assert!(r.is_err(), "非 PE 文件应返回错误");
        let _ = std::fs::remove_file(&tmp);
    }

    /// 不存在的文件应返回错误
    #[test]
    fn test_detect_pe_architecture_missing_file() {
        let r = detect_pe_architecture("Z:\\nonexistent\\file.exe");
        assert!(r.is_err());
    }

    /// 解析当前测试二进制的导入表，验证：
    ///   - 返回非空列表（任何 PE 都至少导入一个 DLL）
    ///   - kernel32.dll 必在其中（Windows 必备依赖）
    #[test]
    fn test_parse_pe_imports_on_self() {
        let exe = std::env::current_exe().expect("current_exe");
        let imports = parse_pe_imports(&exe.display().to_string());
        assert!(imports.is_ok(), "parse_pe_imports 应成功: {:?}", imports);
        let imports = imports.unwrap();
        assert!(!imports.is_empty(), "测试二进制应至少导入一个 DLL");

        // 全部应为小写
        for imp in &imports {
            assert_eq!(imp.to_lowercase(), *imp, "导入名应已小写化: {}", imp);
        }

        // Windows 测试二进制必然导入 kernel32.dll
        #[cfg(target_os = "windows")]
        {
            assert!(
                imports.iter().any(|s| s == "kernel32.dll"),
                "kernel32.dll 应在导入表中: {:?}",
                imports
            );
        }
    }

    /// 非 PE 文件解析导入表应返回错误
    #[test]
    fn test_parse_pe_imports_non_pe() {
        let tmp = std::env::temp_dir().join("verthys_pe_imports_nonpe.bin");
        std::fs::write(&tmp, b"RANDOM_BYTES_NOT_PE").expect("write temp");
        let r = parse_pe_imports(tmp.to_str().unwrap());
        assert!(r.is_err());
        let _ = std::fs::remove_file(&tmp);
    }

    /// 不存在的文件解析导入表应返回错误
    #[test]
    fn test_parse_pe_imports_missing_file() {
        let r = parse_pe_imports("Z:\\nonexistent\\missing.dll");
        assert!(r.is_err());
    }

    /// find_dll_in_search_paths 对系统核心 DLL 应命中 System32
    #[test]
    #[cfg(target_os = "windows")]
    fn test_find_dll_system32() {
        let exe_dir = std::env::temp_dir();
        let hit = find_dll_in_search_paths("kernel32.dll", &exe_dir);
        assert!(hit.is_some(), "kernel32.dll 应在搜索路径中找到");
    }

    /// find_dll_in_search_paths 对虚构 DLL 应返回 None
    #[test]
    fn test_find_dll_missing() {
        let exe_dir = std::env::temp_dir();
        let hit = find_dll_in_search_paths("zzz_nonexistent_dll_12345.dll", &exe_dir);
        assert!(hit.is_none(), "虚构 DLL 不应在搜索路径中");
    }

    /// check_dll_dependencies 在 Windows 上应通过（测试机必装 VC++ 运行库）
    #[test]
    #[cfg(target_os = "windows")]
    fn test_check_dll_dependencies_passes() {
        // 传入一个占位路径，函数实际只检查 System32
        let r = check_dll_dependencies("dummy.dll");
        assert!(r.is_ok(), "VC++ 运行库检查应通过: {:?}", r);
    }

    /// check_binary_dependencies 对当前 exe 应通过
    /// （当前测试二进制的所有导入依赖在测试环境中均可达）
    #[test]
    fn test_check_binary_dependencies_on_self() {
        let exe = std::env::current_exe().expect("current_exe");
        let exe_str = exe.display().to_string();
        // 用自身同时作为 worker 与 dll（仅验证导入表解析 + 搜索路径逻辑，
        // 不验证架构一致性，因为此处不关心 dll 架构）
        let r = check_binary_dependencies(&exe_str, &exe_str);
        assert!(
            r.is_ok(),
            "当前二进制依赖检查应通过: {:?}",
            r
        );
    }
}