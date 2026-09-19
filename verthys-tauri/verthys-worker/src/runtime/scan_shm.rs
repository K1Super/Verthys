/* scan_shm.rs — 共享内存传输层（Windows 专用）+ 非windows空壳
 *
 * 职责：游标批量扫描的零拷贝数据传输（VirtualLock + 随机名称 + 安全擦除）。
 *
 * 原 runtime.rs 中为 `#[cfg(windows)] mod scan_shm { ... }` 内嵌模块。
 * 拆分后本文件替代该内嵌模块：windows 内容封装于私有 windows_impl 模块并 glob 重导出，
 * 非 windows 平台提供一个不做事的 ScanShm 空壳存根（worker.rs 仅在 #[cfg(windows)]
 * 上下文引用 ScanShm，故存根在非 windows 不会被实际构造）。
 *
 * 安全特性：
 *   - VirtualLock 锁定物理内存，禁止换页
 *   - 每次传输后随机字节覆写擦除
 *   - 随机不可猜测名称，防止同用户进程探测
 *   - 固定大小，防止共享内存膨胀成为侧信道
 */

#[cfg(windows)]
pub(crate) use windows_impl::*;

#[cfg(windows)]
mod windows_impl {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, VirtualLock, VirtualUnlock,
        MEMORY_MAPPED_VIEW_ADDRESS, FILE_MAP_ALL_ACCESS, FILE_MAP_READ, FILE_MAP_WRITE,
        PAGE_READWRITE,
    };

    /// 共享内存魔数 "VSMM"（全量扫描）
    pub const SHM_MAGIC: u32 = 0x56534D4D;
    pub const SHM_VERSION: u32 = 1;
    /// 头部 64 字节
    pub const SHM_HEADER_SIZE: usize = 64;
    /// 每条全量记录索引 40 字节
    pub const SHM_ENTRY_SIZE: usize = 40;
    /// 默认共享内存大小 8MB
    pub const SHM_DEFAULT_SIZE: usize = 8 * 1024 * 1024;

    /* ===== 摘要扫描专用常量（轻量元数据，无数据块）===== */
    /// 摘要扫描共享内存魔数 "VSUM"（区别于全量扫描 VSMM，reader 据此选择解析路径）
    pub const SHM_SUMMARY_MAGIC: u32 = 0x5653554D;
    /// 每条摘要记录索引 80 字节（8 字节对齐）：
    ///   [0..8]   lid: u64
    ///   [8..12]  rtype: u32
    ///   [12..16] name_len: u32
    ///   [16..24] data_size: u64
    ///   [24..32] physical_offset: u64
    ///   [32..40] name_offset: u64
    ///   [40..72] merkle_leaf: [u8; 32]
    ///   [72..80] created_time: u64
    pub const SHM_SUMMARY_ENTRY_SIZE: usize = 80;
    /// 摘要扫描默认共享内存大小 4MB（元数据体积极小，4MB 足够上万条）
    pub const SHM_SUMMARY_DEFAULT_SIZE: usize = 4 * 1024 * 1024;

    /// 摘要记录元组（writer 侧构造 → SHM 传输）：
    /// (lid, rtype, name, data_size, physical_offset, merkle_leaf, created_time)
    ///
    /// worker.rs 的 fetch_summary_into_shm 与本模块 write_summary_records 共用，
    /// 避免复杂元组类型在多处重复书写（clippy::type_complexity）。
    pub type SummaryRecord = (u64, u8, String, u64, u64, [u8; 32], u64);

    /*
     * 头部布局（64 字节）：
     *   [0..4]   magic: u32
     *   [4..8]   version: u32
     *   [8..16]  record_count: u64
     *   [16..24] total_name_bytes: u64
     *   [24..32] total_data_bytes: u64
     *   [32..36] exhausted: u32
     *   [36..40] error_code: u32
     *   [40..64] reserved
     *
     * 索引条目布局（40 字节/条）：
     *   [0..8]   lid: u64
     *   [8..12]  rtype: u32
     *   [12..16] name_len: u32
     *   [16..24] data_len: u64
     *   [24..32] name_offset: u64  (相对共享内存起始的绝对偏移)
     *   [32..40] data_offset: u64
     */

    pub struct ScanShm {
        handle: HANDLE,
        view: MEMORY_MAPPED_VIEW_ADDRESS,
        ptr: *mut u8,
        size: usize,
        name: String,
        locked: bool,
    }

    impl ScanShm {
        /// 创建共享内存段，VirtualLock 锁定物理内存
        /// 安全描述符：仅当前用户可读写，其他进程无访问权限
        pub fn create(size: usize) -> Result<Self, &'static str> {
            let name = format!("verthys_scan_{}", random_hex_name());
            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0u16)).collect();

            // ---- 构建受限安全描述符：仅当前用户 SID 可读写 ----
            // 获取当前进程 token → 提取用户 SID → 构建 ACL → 设置 DACL
            // 失败时退化为 NULL 安全描述符（继承进程默认 DACL）
            let sec_ctx = build_restricted_security_attributes();
            let sa_ptr = match &sec_ctx {
                Some(ctx) => &ctx.sa as *const SECURITY_ATTRIBUTES,
                None => std::ptr::null(),
            };

            let handle = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    sa_ptr,
                    PAGE_READWRITE,
                    ((size >> 32) & 0xFFFFFFFF) as u32,
                    (size & 0xFFFFFFFF) as u32,
                    wide.as_ptr(),
                )
            };
            if handle.is_null() {
                return Err("CreateFileMappingW failed");
            }
            // 安全描述符已被 CreateFileMappingW 复制到对象安全描述符中，
            // sec_ctx 可在函数返回时释放
            drop(sec_ctx);

            let view = unsafe {
                MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, size)
            };
            let ptr = view.Value as *mut u8;
            if ptr.is_null() {
                unsafe { CloseHandle(handle) };
                return Err("MapViewOfFile failed");
            }

            // VirtualLock：锁定物理内存页，禁止换出到 pagefile
            let locked = unsafe { VirtualLock(ptr as *const std::ffi::c_void, size) } != 0;

            // 初始清零
            unsafe { std::ptr::write_bytes(ptr, 0, size) };

            Ok(ScanShm {
                handle,
                view,
                ptr,
                size,
                name,
                locked,
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn size(&self) -> usize {
            self.size
        }

        #[allow(dead_code)]
        pub fn ptr(&self) -> *mut u8 {
            self.ptr
        }

        /// 共享内存覆写擦除：随机字节覆写（防残留数据被恶意读取）
        /// 每次传输完成后发送方立即将数据区全部写为随机字节
        pub fn wipe(&mut self) {
            unsafe {
                let slice = std::slice::from_raw_parts_mut(self.ptr, self.size);
                fill_random_bytes(slice);
            }
        }

        /// 将记录写入共享内存缓冲区
        /// 返回写入的记录数，或在数据超出缓冲区时返回错误
        pub fn write_records(
            &mut self,
            records: &[(u64, u32, String, Vec<u8>)],
            exhausted: bool,
        ) -> Result<usize, &'static str> {
            let entry_table_size = records.len() * SHM_ENTRY_SIZE;
            let total_name_bytes: usize = records.iter().map(|r| r.2.len()).sum();
            let total_data_bytes: usize = records.iter().map(|r| r.3.len()).sum();
            let needed = SHM_HEADER_SIZE + entry_table_size + total_name_bytes + total_data_bytes;

            if needed > self.size {
                return Err("data exceeds shared memory size");
            }

            // 写入前先擦除旧数据
            self.wipe();

            let base = self.ptr;
            unsafe {
                *(base as *mut u32) = SHM_MAGIC;
                *((base.add(4)) as *mut u32) = SHM_VERSION;
                *((base.add(8)) as *mut u64) = records.len() as u64;
                *((base.add(16)) as *mut u64) = total_name_bytes as u64;
                *((base.add(24)) as *mut u64) = total_data_bytes as u64;
                *((base.add(32)) as *mut u32) = if exhausted { 1 } else { 0 };
                *((base.add(36)) as *mut u32) = 0;
            }

            let entries_start = unsafe { base.add(SHM_HEADER_SIZE) };
            let names_start = unsafe { entries_start.add(entry_table_size) };
            let data_start = unsafe { names_start.add(total_name_bytes) };

            // 关键：entry 表中存储的是相对 base 的偏移（不是绝对指针），
            // reader 端通过 base.add(offset) 读取数据。
            // 若写入绝对指针，reader 端 base.add(absolute_ptr) 会越界 → segfault。
            let mut name_off_abs = names_start;       // 绝对指针，用于实际写入
            let mut data_off_abs = data_start;         // 绝对指针，用于实际写入
            let mut name_off_rel = SHM_HEADER_SIZE + entry_table_size;  // 相对偏移，存入 entry
            let mut data_off_rel = SHM_HEADER_SIZE + entry_table_size + total_name_bytes;

            for (i, (lid, rtype, name, data)) in records.iter().enumerate() {
                let entry_ptr = unsafe { entries_start.add(i * SHM_ENTRY_SIZE) };
                unsafe {
                    *(entry_ptr as *mut u64) = *lid;
                    *((entry_ptr.add(8)) as *mut u32) = *rtype;
                    *((entry_ptr.add(12)) as *mut u32) = name.len() as u32;
                    *((entry_ptr.add(16)) as *mut u64) = data.len() as u64;
                    *((entry_ptr.add(24)) as *mut u64) = name_off_rel as u64;
                    *((entry_ptr.add(32)) as *mut u64) = data_off_rel as u64;
                }
                if !name.is_empty() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(name.as_ptr(), name_off_abs, name.len());
                    }
                }
                name_off_abs = unsafe { name_off_abs.add(name.len()) };
                name_off_rel += name.len();
                if !data.is_empty() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(data.as_ptr(), data_off_abs, data.len());
                    }
                }
                data_off_abs = unsafe { data_off_abs.add(data.len()) };
                data_off_rel += data.len();
            }

            Ok(records.len())
        }

        /// 将摘要记录写入共享内存缓冲区（轻量元数据，无数据块）
        ///
        /// ★ 摘要记录元组增加 created_time 字段
        /// 元组：(lid, rtype, name, data_size, physical_offset, merkle_leaf, created_time)
        ///
        /// 与全量 write_records 的区别：
        ///   - 写入 SHM_SUMMARY_MAGIC 而非 SHM_MAGIC（reader 据此区分解析路径）
        ///   - 每条 80 字节索引条目（含 data_size/physical_offset/merkle_leaf/created_time，无 data_offset）
        ///   - total_data_bytes 恒为 0（无数据块传输）
        ///
        /// 返回写入的记录数，或在数据超出缓冲区时返回错误
        pub fn write_summary_records(
            &mut self,
            records: &[SummaryRecord],
            exhausted: bool,
        ) -> Result<usize, &'static str> {
            let entry_table_size = records.len() * SHM_SUMMARY_ENTRY_SIZE;
            let total_name_bytes: usize = records.iter().map(|r| r.2.len()).sum();
            // 摘要扫描无独立数据区（merkle_leaf 内联在索引条目中）
            let total_data_bytes: usize = 0;
            let needed = SHM_HEADER_SIZE + entry_table_size + total_name_bytes + total_data_bytes;

            if needed > self.size {
                return Err("summary data exceeds shared memory size");
            }

            // 写入前先擦除旧数据
            self.wipe();

            let base = self.ptr;
            unsafe {
                *(base as *mut u32) = SHM_SUMMARY_MAGIC;
                *((base.add(4)) as *mut u32) = SHM_VERSION;
                *((base.add(8)) as *mut u64) = records.len() as u64;
                *((base.add(16)) as *mut u64) = total_name_bytes as u64;
                *((base.add(24)) as *mut u64) = total_data_bytes as u64;
                *((base.add(32)) as *mut u32) = if exhausted { 1 } else { 0 };
                *((base.add(36)) as *mut u32) = 0;
            }

            let entries_start = unsafe { base.add(SHM_HEADER_SIZE) };
            let names_start = unsafe { entries_start.add(entry_table_size) };

            // entry 表中 name_offset 存储相对 base 的偏移（reader 端通过 base.add(offset) 读取）
            let mut name_off_abs = names_start;
            let mut name_off_rel = SHM_HEADER_SIZE + entry_table_size;

            for (i, (lid, rtype, name, data_size, physical_offset, merkle_leaf, created_time)) in records.iter().enumerate() {
                let entry_ptr = unsafe { entries_start.add(i * SHM_SUMMARY_ENTRY_SIZE) };
                unsafe {
                    *(entry_ptr as *mut u64) = *lid;
                    *((entry_ptr.add(8)) as *mut u32) = *rtype as u32;
                    *((entry_ptr.add(12)) as *mut u32) = name.len() as u32;
                    *((entry_ptr.add(16)) as *mut u64) = *data_size;
                    *((entry_ptr.add(24)) as *mut u64) = *physical_offset;
                    *((entry_ptr.add(32)) as *mut u64) = name_off_rel as u64;
                    // merkle_leaf 32 字节内联拷贝
                    std::ptr::copy_nonoverlapping(
                        merkle_leaf.as_ptr(),
                        entry_ptr.add(40),
                        32,
                    );
                    // ★ created_time 写入偏移 72
                    *((entry_ptr.add(72)) as *mut u64) = *created_time;
                }
                if !name.is_empty() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(name.as_ptr(), name_off_abs, name.len());
                    }
                }
                name_off_abs = unsafe { name_off_abs.add(name.len()) };
                name_off_rel += name.len();
            }

            Ok(records.len())
        }

        /// 销毁：擦除 → 解锁 → 取消映射 → 关闭句柄
        pub fn destroy(mut self) {
            self.wipe();
            if self.locked {
                unsafe {
                    VirtualUnlock(self.ptr as *const std::ffi::c_void, self.size);
                }
            }
            if !self.ptr.is_null() {
                unsafe { UnmapViewOfFile(self.view) };
            }
            if !self.handle.is_null() {
                unsafe { CloseHandle(self.handle) };
            }
        }
    }

    /// 生成 16 字符随机十六进制名称（不可猜测）
    fn random_hex_name() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            ^ (std::process::id() as u64).rotate_left(17);
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut hex = String::with_capacity(16);
        for _ in 0..16 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let nibble = ((state >> 56) & 0xF) as u8;
            let c = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            };
            hex.push(c as char);
        }
        hex
    }

    /// 生成随机字节填充缓冲区（用于共享内存覆写擦除）
    /// 使用 xorshift64* PRNG，避免依赖系统 RNG 的性能开销
    fn fill_random_bytes(buf: &mut [u8]) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let mut state = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        // 避免 state=0 退化
        if state == 0 { state = 0xDEADBEEFCAFEBABE; }
        for byte in buf.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state >> 56) as u8;
        }
    }

    /// 构建受限安全属性：仅当前用户 SID 可读写共享内存
    ///
    /// 流程：
    ///   1. OpenProcessToken → 获取当前进程 token
    ///   2. GetTokenInformation(TokenUser) → 提取用户 SID
    ///   3. InitializeAcl + AddAccessAllowedAce → 构建 ACL（当前用户 FILE_MAP_READ|WRITE）
    ///   4. InitializeSecurityDescriptor + SetSecurityDescriptorDacl → 设置 DACL
    ///   5. 返回 SecurityContext（持有所有缓冲区 + SECURITY_ATTRIBUTES）
    ///
    /// 安全性：Vec 的堆分配地址在 move 后不变，lpSecurityDescriptor 指向堆数据，
    /// 因此 SecurityContext 可以安全地按值返回。
    fn build_restricted_security_attributes() -> Option<SecurityContext> {
        use windows_sys::Win32::Security::{
            AddAccessAllowedAce, GetTokenInformation, InitializeAcl,
            InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
            ACL, SECURITY_DESCRIPTOR,
            ACL_REVISION, TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows_sys::Win32::Foundation::CloseHandle;

        // 1. 获取当前进程 token
        let mut token: HANDLE = std::ptr::null_mut();
        unsafe {
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
        }

        // 2. 查询 token 大小（TokenUser = 1）
        let mut buf_len: u32 = 0;
        unsafe {
            GetTokenInformation(token, 1i32, std::ptr::null_mut(), 0, &mut buf_len);
        }

        // 3. 获取 TOKEN_USER（含 SID）
        let mut token_buf: Vec<u8> = vec![0u8; buf_len as usize];
        let ok = unsafe {
            GetTokenInformation(token, 1i32, token_buf.as_mut_ptr() as *mut _, buf_len, &mut buf_len)
        };
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return None;
        }

        let token_user = unsafe { &*(token_buf.as_ptr() as *const TOKEN_USER) };
        let sid = token_user.User.Sid;

        // 4. 构建 ACL：当前用户 FILE_MAP_READ | FILE_MAP_WRITE
        let acl_size = std::mem::size_of::<ACL>() + std::mem::size_of::<u32>() * 4 + 64;
        let mut acl_buf: Vec<u8> = vec![0u8; acl_size];
        let acl = acl_buf.as_mut_ptr() as *mut ACL;
        unsafe {
            if InitializeAcl(acl, acl_size as u32, ACL_REVISION) == 0 {
                return None;
            }
            if AddAccessAllowedAce(acl, ACL_REVISION, FILE_MAP_READ | FILE_MAP_WRITE, sid) == 0 {
                return None;
            }
        }

        // 5. 构建安全描述符
        let mut sd_buf: Vec<u8> = vec![0u8; std::mem::size_of::<SECURITY_DESCRIPTOR>()];
        let sd = sd_buf.as_mut_ptr() as *mut std::ffi::c_void;
        unsafe {
            if InitializeSecurityDescriptor(sd, 1) == 0 {
                return None;
            }
            if SetSecurityDescriptorDacl(sd, 1, acl, 0) == 0 {
                return None;
            }
        }

        // 6. 构建 SECURITY_ATTRIBUTES
        // lpSecurityDescriptor 指向 sd_buf 的堆数据（Vec 堆地址在 move 后不变）
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd_buf.as_mut_ptr() as *mut _,
            bInheritHandle: 0,
        };

        Some(SecurityContext {
            sa,
            _acl_buf: acl_buf,
            _sd_buf: sd_buf,
            _token_buf: token_buf,
        })
    }

    /// 持有安全属性相关的缓冲区
    /// Vec 的堆分配在 move 后地址不变，确保 lpSecurityDescriptor 始终有效
    struct SecurityContext {
        sa: SECURITY_ATTRIBUTES,
        _acl_buf: Vec<u8>,
        _sd_buf: Vec<u8>,
        _token_buf: Vec<u8>,
    }
}

/* 非 Windows 平台：ScanShm 空壳存根。
 * worker.rs 仅在 #[cfg(windows)] 上下文引用 ScanShm，故此存根不会被实际构造。 */
#[cfg(not(windows))]
#[allow(dead_code)]
pub(crate) struct ScanShm;
