/*
 * @file infrastructure/path_resolver/pe.rs
 * @brief PE 头解析：机器类型（架构）与导入表
 *
 * 纯 Rust 解析 PE 头，无外部依赖；仅读文件头部，不加载整个文件。
 * 解析失败返回 Err，绝不 panic。
 */

/* ------------------------------------------------------------------ *
 * PE 架构校验（前置门禁）                                       *
 *                                                                    *
 * 背景：                                                             *
 *   verthys-worker.exe 若为 32-bit（x86）而 verthys.dll 为 64-bit，   *
 *   Windows 加载器会在 main() 执行前终止子进程（exit code 0、零输出、*
 *   "file not found"）。此类失败无法通过就绪超时准确诊断：           *
 *     - stderr 为空（main 从未运行，panic hook 未触发）              *
 *     - 退出码为 0（加载器失败，非应用退出码）                       *
 *   表现为"安全子进程就绪超时"，误导排查方向。                       *
 *                                                                    *
 * 做法：                                                             *
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
    f.read_exact(&mut dos)
        .map_err(|e| format!("read dos header: {}", e))?;
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
    f.read_exact(&mut pe)
        .map_err(|e| format!("read PE/COFF header: {}", e))?;
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
/// 安全前置门禁：在 spawn 子进程之前，确认 worker 二进制与
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
    let dll_arch =
        detect_pe_architecture(dll_path).map_err(|e| format!("dll 架构解析失败: {}", e))?;

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
 * PE 导入表解析（依赖预检）                                     *
 *                                                                    *
 * 背景：                                                             *
 *   check_dll_dependencies 仅校验 VC++ 运行库是否存在于 System32，   *
 *   无法发现 worker exe / verthys.dll 的其它导入依赖缺失。          *
 *   加载器级失败（exit code 0 + 零 stderr）的根因往往是某个导入      *
 *   DLL 在搜索路径中不可达（如应用级 DLL 未随包发布、系统级 DLL     *
 *   在精简版 Windows 中缺失）。                                      *
 *                                                                    *
 * 做法：                                                             *
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
