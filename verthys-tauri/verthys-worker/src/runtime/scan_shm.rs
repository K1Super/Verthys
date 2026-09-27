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

    /// SHM 协议契约（与主进程同源）：经 include! 引入仓库根共享契约文件，
    /// 常量/结构体布局与主进程编译期同源——改根文件后两端同步重编译，
    /// 杜绝历史"双份常量人工同步"导致的协议漂移（如 88/80 条目错位）。
    /// dead_code 压降：worker 仅消费常量子集，未使用条目按契约文件约定
    /// 在本 include 站点统一豁免。
    #[allow(dead_code)]
    mod shm_contract {
        include!("../../../shm_schema.rs");
    }
    pub use shm_contract::{
        SCAN_BATCH_MAX_BYTES, SHM_AUTH_BLOCK_LEN, SHM_DEFAULT_SIZE, SHM_ENTRY_SIZE,
        SHM_HEADER_SIZE, SHM_MAGIC, SHM_SUMMARY_DEFAULT_SIZE, SHM_SUMMARY_ENTRY_SIZE,
        SHM_SUMMARY_MAGIC, SHM_VERSION,
    };

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
            auth_key: Option<&[u8]>,
        ) -> Result<usize, &'static str> {
            // 尺寸推导全部 checked 运算：记录数/名称长度来自上游 C 层，
            // 溢出必须显式失败（返回受控错误），禁止回绕后越界写
            let entry_table_size = records
                .len()
                .checked_mul(SHM_ENTRY_SIZE)
                .ok_or("entry table size overflow")?;
            let total_name_bytes: usize = records
                .iter()
                .try_fold(0usize, |acc, r| acc.checked_add(r.2.len()))
                .ok_or("name bytes overflow")?;
            let total_data_bytes: usize = records
                .iter()
                .try_fold(0usize, |acc, r| acc.checked_add(r.3.len()))
                .ok_or("data bytes overflow")?;
            let needed = SHM_HEADER_SIZE
                .checked_add(entry_table_size)
                .and_then(|v| v.checked_add(total_name_bytes))
                .and_then(|v| v.checked_add(total_data_bytes))
                .ok_or("size computation overflow")?;

            if needed > self.size {
                return Err("data exceeds shared memory size");
            }

            // 认证块（可选）：提供密钥时须为尾部 32 字节 HMAC 标签预留空间
            if auth_key.is_some()
                && needed
                    .checked_add(SHM_AUTH_BLOCK_LEN)
                    .ok_or("auth block overflow")?
                    > self.size
            {
                return Err("auth block overflow");
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

            // 认证块：对 [0, needed) 全部字节计算 HMAC-SHA256，把 32 字节标签写到 needed 偏移处
            if let Some(key) = auth_key {
                let data_slice = unsafe { std::slice::from_raw_parts(base, needed) };
                let tag = hmac_sha256(key, data_slice);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        tag.as_ptr(),
                        base.add(needed),
                        SHM_AUTH_BLOCK_LEN,
                    );
                }
            }

            Ok(records.len())
        }

        /// 将摘要记录写入共享内存缓冲区（轻量元数据，无数据块）
        ///
        /// 摘要记录元组增加 created_time 字段
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
            auth_key: Option<&[u8]>,
        ) -> Result<usize, &'static str> {
            // 尺寸推导全部 checked 运算（同 write_records：上游输入溢出必须显式失败）
            let entry_table_size = records
                .len()
                .checked_mul(SHM_SUMMARY_ENTRY_SIZE)
                .ok_or("entry table size overflow")?;
            let total_name_bytes: usize = records
                .iter()
                .try_fold(0usize, |acc, r| acc.checked_add(r.2.len()))
                .ok_or("name bytes overflow")?;
            // 摘要扫描无独立数据区（merkle_leaf 内联在索引条目中）
            let total_data_bytes: usize = 0;
            let needed = SHM_HEADER_SIZE
                .checked_add(entry_table_size)
                .and_then(|v| v.checked_add(total_name_bytes))
                .and_then(|v| v.checked_add(total_data_bytes))
                .ok_or("size computation overflow")?;

            if needed > self.size {
                return Err("summary data exceeds shared memory size");
            }

            // 认证块（可选）：提供密钥时须为尾部 32 字节 HMAC 标签预留空间
            if auth_key.is_some()
                && needed
                    .checked_add(SHM_AUTH_BLOCK_LEN)
                    .ok_or("auth block overflow")?
                    > self.size
            {
                return Err("auth block overflow");
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
                    // created_time 写入偏移 72
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

            // 认证块：对 [0, needed) 全部字节计算 HMAC-SHA256，把 32 字节标签写到 needed 偏移处
            if let Some(key) = auth_key {
                let data_slice = unsafe { std::slice::from_raw_parts(base, needed) };
                let tag = hmac_sha256(key, data_slice);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        tag.as_ptr(),
                        base.add(needed),
                        SHM_AUTH_BLOCK_LEN,
                    );
                }
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
    ///
    /// 熵源为操作系统 CSPRNG（Windows 经 getrandom 走 BCryptGenRandom 家族）。
    /// 名称不可预测性决定同用户进程对共享内存段的探测难度，
    /// 墙钟/进程号派生种子可被重现，此处禁止。
    /// pub(super)：供本模块测试直接验证随机性契约。
    pub(super) fn random_hex_name() -> String {
        let mut raw = [0u8; 8]; /* 8 字节熵 → 16 字符十六进制 */
        fill_random_bytes(&mut raw);
        let mut hex = String::with_capacity(16);
        for b in &raw {
            hex.push_str(&format!("{:02x}", b));
        }
        hex
    }

    /// 生成随机字节填充缓冲区（用于共享内存覆写擦除）
    ///
    /// 直接取操作系统 CSPRNG（BCryptGenRandom 家族），逐字节 xorshift
    /// 的 64 位状态空间与墙钟种子不满足密码学安全要求。
    /// CSPRNG 不可用（极罕见）时整体填零——不泄露旧数据，
    /// 且擦除后立即解锁/取消映射，失败方向保守。
    /// pub(super)：供本模块测试直接验证随机性契约。
    pub(super) fn fill_random_bytes(buf: &mut [u8]) {
        if getrandom::getrandom(buf).is_err() {
            for byte in buf.iter_mut() {
                *byte = 0;
            }
        }
    }

    /// 标准 HMAC-SHA256（用 sha2 原语手写 HMAC 结构）
    ///
    /// worker 未直接依赖 hmac crate，此处用 sha2 实现同一算法，输出与主进程
    /// hmac crate 逐字节一致。密钥长度超过分组大小先哈希再使用，精确对齐
    /// 标准 HMAC 密钥预处理。
    /// pub(super)：供本模块测试重算认证标签比对。
    pub(super) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        const BLOCK: usize = 64;
        let mut k = [0u8; BLOCK];
        if key.len() > BLOCK {
            let d = Sha256::digest(key);
            k[..32].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }

        let mut inner = Sha256::new();
        inner.update(ipad);
        inner.update(data);
        let inner_hash = inner.finalize();

        let mut outer = Sha256::new();
        outer.update(opad);
        outer.update(inner_hash);
        let out = outer.finalize();

        let mut tag = [0u8; 32];
        tag.copy_from_slice(&out);
        tag
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

/* ------------------------------------------------------------------ *
 * CSPRNG 路径测试（Windows）                                          *
 *                                                                    *
 * 随机名为共享内存段的探测难度关键：名称必须不可预测。                *
 * 擦除填充不可全零（残余明文风险）；两次调用不可重复。                *
 * ------------------------------------------------------------------ */
#[cfg(all(test, windows))]
mod tests {
    use super::windows_impl::{fill_random_bytes, random_hex_name};
    use super::windows_impl::{
        hmac_sha256, ScanShm, SHM_AUTH_BLOCK_LEN, SHM_ENTRY_SIZE, SHM_HEADER_SIZE,
    };

    #[test]
    fn random_name_is_hex_and_unique() {
        // 线程随机源（wasi 等特例无关）：批量生成 64 个名称，
        // 断言全部 16 字符十六进制且两两不同（碰撞概率可忽略）。
        let names: Vec<String> = (0..64).map(|_| random_hex_name()).collect();
        for n in &names {
            assert_eq!(n.len(), 16);
            assert!(n.chars().all(|c| c.is_ascii_hexdigit()));
        }
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 64, "随机名出现碰撞（CSPRNG 失效或仍为 PRNG）");
    }

    #[test]
    fn fill_random_overwrites_and_differs() {
        let mut a = [0x5Au8; 128];
        let mut b = [0x5Au8; 128];
        fill_random_bytes(&mut a);
        fill_random_bytes(&mut b);
        assert!(!a.iter().all(|&x| x == 0), "CSPRNG 不可用导致全零");
        // 两次输出逐字节必需有差异（128 字节全同概率 2^-1024）
        assert_ne!(&a[..], &b[..], "两次 CSPRNG 输出完全一致（熵源失效）");
    }

    #[test]
    fn write_records_with_auth_writes_correct_tag() {
        let key = [0x42u8; 32];
        let mut shm = ScanShm::create(8 * 1024 * 1024).expect("create");
        let records = [(1u64, 2u32, "name".to_string(), vec![0xAAu8, 0xBB, 0xCC])];
        let written = shm.write_records(&records, false, Some(&key)).expect("write");
        assert_eq!(written, 1);

        // 头部 64 + 1 条 40 字节条目 + 名称 4 + 数据 3
        let needed = SHM_HEADER_SIZE + SHM_ENTRY_SIZE + 4 + 3;
        let base = shm.ptr();
        unsafe {
            let data = std::slice::from_raw_parts(base, needed);
            let expected = hmac_sha256(&key, data);
            let tag = std::slice::from_raw_parts(base.add(needed), SHM_AUTH_BLOCK_LEN);
            assert_eq!(tag, &expected[..], "认证块应等于重算的 HMAC 标签");
        }
        shm.destroy();
    }

    #[test]
    fn tampered_shm_auth_tag_mismatch() {
        let key = [0x37u8; 32];
        let mut shm = ScanShm::create(8 * 1024 * 1024).expect("create");
        let records = [(9u64, 1u32, "tamper".to_string(), vec![1u8, 2, 3, 4])];
        shm.write_records(&records, false, Some(&key)).expect("write");

        // 头部 64 + 1 条 40 字节条目 + 名称 6 + 数据 4
        let needed = SHM_HEADER_SIZE + SHM_ENTRY_SIZE + 6 + 4;
        let base = shm.ptr();
        unsafe {
            let stored_tag = std::slice::from_raw_parts(base.add(needed), SHM_AUTH_BLOCK_LEN).to_vec();
            // 篡改载荷区首字节（magic）
            *base ^= 0xFF;
            let data = std::slice::from_raw_parts(base, needed);
            let recomputed = hmac_sha256(&key, data);
            assert_ne!(recomputed.as_slice(), stored_tag.as_slice(), "篡改后重算标签应与原标签不同");
        }
        shm.destroy();
    }
}
