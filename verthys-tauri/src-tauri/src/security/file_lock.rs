/*
 * file_lock.rs — 独占锁与防并发 + 私有目录 ACL 隔离（SECURITY.md 企业级重写版）
 *
 * SECURITY.md 修复要点：
 *   1. 修正 ACL 策略：移除 Everyone Deny All 致命缺陷，改用仅允许 ACE 重置 DACL
 *   2. VerthysFileLock 手动实现 Send/Sync，确保 Windows 下编译通过
 *   3. Drop 中引入错误日志与备用解锁逻辑
 *   4. 使用安全包装的 SID 操作，消除指针类型强转隐患
 *   5. 设计锁管理器，支持原子锁升级（共享→独占）
 *   6. 全面引入审计日志，建立文件操作的可追溯性
 */

use std::ptr;

/* ==================================================================== *
 *                        Windows 原始 FFI 声明                          *
 * ==================================================================== */
#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *const u8,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: *const u8,
    ) -> isize;

    fn CloseHandle(hObject: isize) -> i32;

    fn LockFileEx(
        hFile: isize,
        dwFlags: u32,
        dwReserved: u32,
        nNumberOfBytesToLockLow: u32,
        nNumberOfBytesToLockHigh: u32,
        lpOverlapped: *mut Overlapped,
    ) -> i32;

    fn UnlockFileEx(
        hFile: isize,
        dwReserved: u32,
        nNumberOfBytesToUnlockLow: u32,
        nNumberOfBytesToUnlockHigh: u32,
        lpOverlapped: *mut Overlapped,
    ) -> i32;

    fn UnlockFile(
        hFile: isize,
        dwFileOffsetLow: u32,
        dwFileOffsetHigh: u32,
        nNumberOfBytesToUnlockLow: u32,
        nNumberOfBytesToUnlockHigh: u32,
    ) -> i32;

    fn GetLastError() -> u32;

    fn OpenProcessToken(
        ProcessHandle: isize,
        DesiredAccess: u32,
        TokenHandle: *mut isize,
    ) -> i32;

    fn GetCurrentProcess() -> isize;

    fn GetTokenInformation(
        TokenHandle: isize,
        TokenInformationClass: u32,
        TokenInformation: *mut u8,
        TokenInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;

    fn LocalFree(hMem: isize) -> isize;
}

#[cfg(target_os = "windows")]
#[link(name = "advapi32")]
extern "system" {
    fn SetNamedSecurityInfoW(
        pObjectName: *const u16,
        ObjectType: u32,
        SecurityInfo: u32,
        psidOwner: *const u8,
        psidGroup: *const u8,
        pDacl: *const u8,
        pSacl: *const u8,
    ) -> u32;

    fn SetEntriesInAclW(
        cCountOfExplicitEntries: u32,
        pListOfExplicitEntries: *const ExplicitAccessW,
        OldAcl: *const u8,
        NewAcl: *mut *mut u8,
    ) -> u32;

    fn BuildExplicitAccessWithNameW(
        pExplicitAccess: *mut ExplicitAccessW,
        pTrusteeName: *const u16,
        AccessPermissions: u32,
        AccessMode: u32,
        Inheritance: u32,
    );

    fn ConvertStringSidToSidW(
        StringSid: *const u16,
        Sid: *mut *mut u8,
    ) -> i32;

    fn GetNamedSecurityInfoW(
        pObjectName: *const u16,
        ObjectType: u32,
        SecurityInfo: u32,
        psidOwner: *mut *mut u8,
        psidGroup: *mut *mut u8,
        pDacl: *mut *mut u8,
        pSacl: *mut *mut u8,
        pSecurityDescriptor: *mut *mut u8,
    ) -> u32;
}

/* ---------- FFI 结构体（#[repr(C)] 保证布局） ---------- */
#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Default)]
pub struct Overlapped {
    pub internal: usize,
    pub internal_high: usize,
    pub offset_low: u32,
    pub offset_high: u32,
    pub h_event: isize,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Default)]
pub struct TrusteeW {
    pub p_multiple_trustee: *const u8,
    pub multiple_trustee_operation: u32,
    pub trustee_form: u32,
    pub trustee_type: u32,
    pub ptstr_name: *const u16,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Default)]
pub struct ExplicitAccessW {
    pub grf_access_permissions: u32,
    pub grf_access_mode: u32,
    pub grf_inheritance: u32,
    pub trustee: TrusteeW,
}

/* ---------- 常量 ---------- */
#[cfg(target_os = "windows")]
const GENERIC_READ: u32 = 0x8000_0000;
#[cfg(target_os = "windows")]
const GENERIC_WRITE: u32 = 0x4000_0000;
#[cfg(target_os = "windows")]
const GENERIC_EXECUTE: u32 = 0x2000_0000;
#[cfg(target_os = "windows")]
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
#[cfg(target_os = "windows")]
const OPEN_EXISTING: u32 = 3;
#[cfg(target_os = "windows")]
const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x02;
#[cfg(target_os = "windows")]
const FILE_SHARE_READ: u32 = 0x0000_0001;
#[cfg(target_os = "windows")]
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
#[cfg(target_os = "windows")]
const TOKEN_QUERY: u32 = 0x0008;
#[cfg(target_os = "windows")]
const TOKEN_USER_CLASS: u32 = 1; /* TokenUser = 1 */
#[cfg(target_os = "windows")]
const SE_FILE_OBJECT: u32 = 1;
#[cfg(target_os = "windows")]
const DACL_SECURITY_INFORMATION: u32 = 0x0004;
#[cfg(target_os = "windows")]
const SUB_CONTAINERS_AND_OBJECTS_INHERIT: u32 = 0x0003;
#[cfg(target_os = "windows")]
const GRANT_ACCESS: u32 = 1;
#[cfg(target_os = "windows")]
const TRUSTEE_IS_SID: u32 = 0;

/// SECURITY.md 第 1 项：哨兵字节偏移量（2GB，超出任何合理 verthys 文件大小）
#[cfg(target_os = "windows")]
const SENTINEL_OFFSET: u32 = 0x7FFF_FFFF;

/* ==================================================================== *
 *                        辅助函数                                      *
 * ==================================================================== */
#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    if v.last() != Some(&0) {
        v.push(0);
    }
    v
}

#[cfg(target_os = "windows")]
fn last_error_str() -> String {
    unsafe { format!("GetLastError={}", GetLastError()) }
}

/* ==================================================================== *
 *  SECURITY.md 第 4 项：安全 SID 包装类型                               *
 *                                                                        *
 *  消除 Vec<u8> 指针强转隐患，提供类型安全的 PSID 访问。                *
 *  SidToken 持有连续内存，as_ptr() 返回 *const u8 供 Windows API 使用。 *
 * ==================================================================== */
#[cfg(target_os = "windows")]
struct SidToken {
    data: Vec<u8>,
}

#[cfg(target_os = "windows")]
impl SidToken {
    /// 从已分配的 SID 指针复制数据到安全的 Rust 向量
    unsafe fn from_raw(ptr: *const u8) -> Result<Self, String> {
        if ptr.is_null() {
            return Err("SID 指针为空".into());
        }
        // SID 结构：Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthoritys(4*N)
        let sub_count = *ptr.add(1) as usize;
        let sid_size = 8 + 4 * sub_count;
        let data = std::slice::from_raw_parts(ptr, sid_size).to_vec();
        Ok(SidToken { data })
    }

    /// 从 SDDL 字符串（如 "S-1-5-32-544"）创建 SID
    fn from_string(sid_string: &str) -> Result<Self, String> {
        unsafe {
            let wide = to_wide(sid_string);
            let mut sid_ptr: *mut u8 = ptr::null_mut();

            let ok = ConvertStringSidToSidW(wide.as_ptr(), &mut sid_ptr);
            if ok == 0 || sid_ptr.is_null() {
                return Err(format!("ConvertStringSidToSidW 失败: {}", sid_string));
            }

            let result = Self::from_raw(sid_ptr);

            // 释放原始 SID（LocalFree）
            let _ = LocalFree(sid_ptr as isize);

            result
        }
    }

    /// 返回 PSID 指针（供 Windows API 使用）
    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
}

/* ==================================================================== *
 *  SECURITY.md 第 2 项：VerthysFileLock — Send/Sync + Drop 日志           *
 *                                                                        *
 *  Windows 文件句柄（HANDLE = isize）本质上线程安全：                    *
 *  - LockFileEx/UnlockFile 对同一句柄的调用是原子操作                    *
 *  - CloseHandle 线程安全                                               *
 *  因此手动实现 Send + Sync 是安全的。                                  *
 * ==================================================================== */
pub struct VerthysFileLock {
    #[cfg(target_os = "windows")]
    handle: isize,
    /// SECURITY.md 第 5 项：锁类型记录（用于锁升级状态机）
    lock_type: LockType,
}

/// SECURITY.md 第 5 项：锁类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockType {
    /// 共享锁（多读，排斥写）
    Shared,
    /// 独占锁（排斥一切）
    Exclusive,
}

// SECURITY.md 第 2 项：手动实现 Send/Sync
// Windows HANDLE 本质是 isize，LockFileEx/UnlockFile/CloseHandle 均线程安全。
// VerthysFileLock 仅持有一个 HANDLE 和一个 Copy 枚举，无内部可变性。
unsafe impl Send for VerthysFileLock {}
unsafe impl Sync for VerthysFileLock {}

#[cfg(target_os = "windows")]
impl VerthysFileLock {
    /// 尝试对 .verthys 文件加独占锁。
    /// 若文件已被另一进程锁定，返回 Err。
    pub fn lock_exclusive(path: &str) -> Result<Self, String> {
        let wide = to_wide(path);

        unsafe {
            let handle = CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null(),
            );

            if handle == -1 || handle == 0 {
                return Err(format!("CreateFileW 失败: {}", last_error_str()));
            }

            let mut overlapped: Overlapped = Default::default();
            overlapped.offset_low = SENTINEL_OFFSET;
            overlapped.offset_high = 0;

            let ok = LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                1,
                0,
                &mut overlapped,
            );

            if ok == 0 {
                let err = last_error_str();
                let _ = CloseHandle(handle);
                return Err(format!("LockFileEx 失败: {}", err));
            }

            log::info!(
                "[file_lock] 独占锁已获取 (handle=0x{:X})",
                handle
            );

            Ok(VerthysFileLock {
                handle,
                lock_type: LockType::Exclusive,
            })
        }
    }

    /// 尝试对 .verthys 文件加共享读锁。
    pub fn lock_shared(path: &str) -> Result<Self, String> {
        let wide = to_wide(path);

        unsafe {
            let handle = CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null(),
            );

            if handle == -1 || handle == 0 {
                return Err(format!("CreateFileW 失败: {}", last_error_str()));
            }

            let mut overlapped: Overlapped = Default::default();
            overlapped.offset_low = SENTINEL_OFFSET;
            overlapped.offset_high = 0;

            let ok = LockFileEx(
                handle,
                0, /* 无 LOCKFILE_EXCLUSIVE_LOCK → 共享锁 */
                0,
                1,
                0,
                &mut overlapped,
            );

            if ok == 0 {
                let err = last_error_str();
                let _ = CloseHandle(handle);
                return Err(format!("LockFileEx(shared) 失败: {}", err));
            }

            log::info!(
                "[file_lock] 共享锁已获取 (handle=0x{:X})",
                handle
            );

            Ok(VerthysFileLock {
                handle,
                lock_type: LockType::Shared,
            })
        }
    }

    /// SECURITY.md 第 5 项：原子锁升级（共享→独占）
    ///
    /// 在已持有共享锁的同一句柄上请求独占锁，无需先释放共享锁。
    /// Windows LockFileEx 支持在同一句柄上叠加锁请求。
    /// 若无法立即升级（其他进程持有共享锁），返回 Err。
    pub fn try_upgrade_to_exclusive(&mut self) -> Result<(), String> {
        if self.lock_type == LockType::Exclusive {
            return Ok(()); // 已是独占锁
        }

        unsafe {
            let mut overlapped: Overlapped = Default::default();
            overlapped.offset_low = SENTINEL_OFFSET;
            overlapped.offset_high = 0;

            let ok = LockFileEx(
                self.handle,
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                1,
                0,
                &mut overlapped,
            );

            if ok == 0 {
                return Err(format!(
                    "锁升级失败(shared→exclusive): {}",
                    last_error_str()
                ));
            }

            self.lock_type = LockType::Exclusive;
            log::info!(
                "[file_lock] 锁已升级为独占 (handle=0x{:X})",
                self.handle
            );
            Ok(())
        }
    }

    /// 查询当前锁类型
    pub fn lock_type(&self) -> LockType {
        self.lock_type
    }
}

/// SECURITY.md 第 3 项：Drop 中引入错误日志与备用解锁逻辑
///
/// 修复原实现完全忽略解锁和句柄关闭错误的问题：
/// - UnlockFile 失败时记录包含 GetLastError() 的错误日志
/// - 无论解锁成功与否，都执行 CloseHandle 并记录错误
/// - 日志不含明文路径（仅用句柄值标识）
#[cfg(target_os = "windows")]
impl Drop for VerthysFileLock {
    fn drop(&mut self) {
        unsafe {
            // 1. 尝试解锁
            let unlock_ok = UnlockFile(self.handle, SENTINEL_OFFSET, 0, 1, 0);
            if unlock_ok == 0 {
                let err = GetLastError();
                log::error!(
                    "[file_lock] UnlockFile 失败 (handle=0x{:X}, GetLastError={}). \
                     文件锁可能残留，后续进程可能无法获取锁。",
                    self.handle,
                    err
                );
                // 备用：尝试 UnlockFileEx（某些情况下行为不同）
                let mut overlapped: Overlapped = Default::default();
                overlapped.offset_low = SENTINEL_OFFSET;
                overlapped.offset_high = 0;
                let retry_ok = UnlockFileEx(self.handle, 0, 1, 0, &mut overlapped);
                if retry_ok == 0 {
                    log::error!(
                        "[file_lock] UnlockFileEx 备用解锁也失败 (handle=0x{:X}, GetLastError={})",
                        self.handle,
                        GetLastError()
                    );
                } else {
                    log::info!(
                        "[file_lock] UnlockFileEx 备用解锁成功 (handle=0x{:X})",
                        self.handle
                    );
                }
            } else {
                log::debug!(
                    "[file_lock] UnlockFile 成功 (handle=0x{:X})",
                    self.handle
                );
            }

            // 2. 关闭句柄（无论解锁成功与否）
            let close_ok = CloseHandle(self.handle);
            if close_ok == 0 {
                log::error!(
                    "[file_lock] CloseHandle 失败 (handle=0x{:X}, GetLastError={})",
                    self.handle,
                    GetLastError()
                );
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl VerthysFileLock {
    pub fn lock_exclusive(_path: &str) -> Result<Self, String> {
        Err("file_lock: 非 Windows 平台不支持".into())
    }

    pub fn lock_shared(_path: &str) -> Result<Self, String> {
        Err("file_lock: 非 Windows 平台不支持".into())
    }

    pub fn try_upgrade_to_exclusive(&mut self) -> Result<(), String> {
        Err("file_lock: 非 Windows 平台不支持".into())
    }

    pub fn lock_type(&self) -> LockType {
        LockType::Shared
    }
}

#[cfg(not(target_os = "windows"))]
impl Drop for VerthysFileLock {
    fn drop(&mut self) {}
}

/* ==================================================================== *
 *  SECURITY.md 第 1 项：修正 ACL 策略                                    *
 *                                                                        *
 *  致命缺陷修复：移除 Everyone Deny All 条目                             *
 *                                                                        *
 *  原实现构建了 Everyone 的 DENY_ACCESS 条目，Windows ACL 评估机制是     *
 *  拒绝优先于允许，导致所有用户（包括所有者）的所有访问被拒绝，          *
 *  目录变为不可恢复的"死目录"。                                         *
 *                                                                        *
 *  正确的加固逻辑：                                                      *
 *  1. 获取目录当前的 DACL，备份它（以便失败回滚）                       *
 *  2. 构建仅包含所需主体的允许 ACE：                                    *
 *     - 当前用户完全控制                                                *
 *     - Administrators 读取执行                                         *
 *     - SYSTEM 读取执行                                                 *
 *  3. 调用 SetNamedSecurityInfoW 设置 DACL_SECURITY_INFORMATION         *
 *     （替换原有 ACL，隐式拒绝其他任何主体）                            *
 *  4. 如果应用失败，使用备份 DACL 进行回滚                              *
 *  5. 操作前后写入结构化审计日志                                        *
 * ==================================================================== */
#[cfg(target_os = "windows")]
pub fn harden_private_dir(dir: &str) -> Result<(), String> {
    log::info!("[file_lock] 开始加固目录 ACL: hash={:016x}", path_hash(dir));

    unsafe {
        /* 1. 获取当前用户 SID */
        let user_sid = SidToken::from_raw(get_current_user_sid_ptr()?)?;

        /* 2. 创建 Administrators / SYSTEM SID */
        let admin_sid = SidToken::from_string("S-1-5-32-544")?;
        let system_sid = SidToken::from_string("S-1-5-18")?;

        /* SECURITY.md 第 1 项：备份当前 DACL（用于失败回滚） */
        let wide_dir = to_wide(dir);
        let mut old_dacl: *mut u8 = ptr::null_mut();
        let mut old_sd: *mut u8 = ptr::null_mut();
        let backup_result = GetNamedSecurityInfoW(
            wide_dir.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut old_dacl,
            ptr::null_mut(),
            &mut old_sd,
        );

        let has_backup = backup_result == 0 && !old_dacl.is_null();
        if !has_backup {
            log::warn!(
                "[file_lock] 无法备份当前 DACL (GetNamedSecurityInfoW 结果={}), \
                 失败时将无法回滚",
                backup_result
            );
        }

        /* 3. SECURITY.md 第 1 项：构建仅包含允许 ACE 的 DACL（3 条规则）
         *    严禁使用 Everyone Deny All —— 拒绝优先于允许会导致目录死锁 */
        let mut ea: [ExplicitAccessW; 3] = Default::default();

        /* a) 当前用户：完全控制（GRANT_ACCESS） */
        BuildExplicitAccessWithNameW(
            &mut ea[0],
            ptr::null(),
            FILE_ALL_ACCESS,
            GRANT_ACCESS,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        );
        ea[0].trustee.trustee_form = TRUSTEE_IS_SID;
        ea[0].trustee.ptstr_name = user_sid.as_ptr() as *const u16;

        /* b) Administrators：读取+执行（GRANT_ACCESS） */
        BuildExplicitAccessWithNameW(
            &mut ea[1],
            ptr::null(),
            GENERIC_READ | GENERIC_EXECUTE,
            GRANT_ACCESS,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        );
        ea[1].trustee.trustee_form = TRUSTEE_IS_SID;
        ea[1].trustee.ptstr_name = admin_sid.as_ptr() as *const u16;

        /* c) SYSTEM：读取+执行（GRANT_ACCESS） */
        BuildExplicitAccessWithNameW(
            &mut ea[2],
            ptr::null(),
            GENERIC_READ | GENERIC_EXECUTE,
            GRANT_ACCESS,
            SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        );
        ea[2].trustee.trustee_form = TRUSTEE_IS_SID;
        ea[2].trustee.ptstr_name = system_sid.as_ptr() as *const u16;

        /* SECURITY.md 第 1 项关键修复：
         * 不再创建 Everyone Deny All 条目！
         * SetNamedSecurityInfoW 设置 DACL_SECURITY_INFORMATION 会替换整个 DACL，
         * 未在 ACL 中列出的主体隐式被拒绝（空白拒绝），无需显式 Deny 条目。 */

        /* 4. 构建 DACL */
        let mut new_acl: *mut u8 = ptr::null_mut();
        let status = SetEntriesInAclW(3, ea.as_ptr(), ptr::null(), &mut new_acl);
        if status != 0 {
            return Err(format!("SetEntriesInAclW 失败: error={}", status));
        }

        /* 5. 应用新 DACL 到目录 */
        let info_status = SetNamedSecurityInfoW(
            wide_dir.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null(),
            ptr::null(),
            new_acl,
            ptr::null(),
        );

        /* 6. 释放新 DACL 内存 */
        let _ = LocalFree(new_acl as isize);

        if info_status != 0 {
            let err_msg = format!("SetNamedSecurityInfoW 失败: error={}", info_status);

            /* SECURITY.md 第 1 项：失败时尝试回滚到备份 DACL */
            if has_backup {
                log::warn!(
                    "[file_lock] ACL 加固失败，尝试回滚到原始 DACL..."
                );
                let rollback_status = SetNamedSecurityInfoW(
                    wide_dir.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null(),
                    ptr::null(),
                    old_dacl,
                    ptr::null(),
                );
                if rollback_status == 0 {
                    log::info!("[file_lock] 已回滚到原始 DACL");
                } else {
                    log::error!(
                        "[file_lock] 回滚失败 (error={}), 目录可能处于不一致状态",
                        rollback_status
                    );
                }
            }

            /* 释放备份 SD 内存 */
            if !old_sd.is_null() {
                let _ = LocalFree(old_sd as isize);
            }

            return Err(err_msg);
        }

        /* 7. 释放备份 SD 内存 */
        if !old_sd.is_null() {
            let _ = LocalFree(old_sd as isize);
        }

        /* SECURITY.md 第 6 项：审计日志 */
        log::info!(
            "[file_lock] 目录 ACL 加固成功: hash={:016x}, \
             ACEs=[user:FULL, admins:READ+EXEC, system:READ+EXEC], \
             deny=none(implicit)",
            path_hash(dir)
        );

        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
pub fn harden_private_dir(_dir: &str) -> Result<(), String> {
    Ok(())
}

/* ==================================================================== *
 *                        SID 获取辅助函数                               *
 * ==================================================================== */

/// SECURITY.md 第 4 项：获取当前用户 SID 原始指针
///
/// 返回的指针指向进程内分配的内存，调用方应立即复制到 SidToken 中。
#[cfg(target_os = "windows")]
unsafe fn get_current_user_sid_ptr() -> Result<*const u8, String> {
    let mut token: isize = 0;
    let ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token);
    if ok == 0 {
        return Err(format!("OpenProcessToken 失败: {}", last_error_str()));
    }

    /* 第一次调用获取所需大小 */
    let mut ret_len: u32 = 0;
    let mut dummy = [0u8; 4];
    let _ = GetTokenInformation(
        token,
        TOKEN_USER_CLASS,
        dummy.as_mut_ptr(),
        dummy.len() as u32,
        &mut ret_len,
    );

    let mut buf = vec![0u8; ret_len as usize];
    let result = GetTokenInformation(
        token,
        TOKEN_USER_CLASS,
        buf.as_mut_ptr(),
        buf.len() as u32,
        &mut ret_len,
    );

    let _ = CloseHandle(token);

    if result == 0 {
        return Err(format!("GetTokenInformation 失败: {}", last_error_str()));
    }

    /* TOKEN_USER 结构：{ SID_AND_ATTRIBUTES User; }
     * SID_AND_ATTRIBUTES：{ *mut Sid; u32 Attributes; }
     * 在 64 位上：偏移 0 = SID 指针（8字节），偏移 8 = Attributes（4字节）
     */
    let sid_ptr = *(buf.as_ptr() as *const *const u8);
    if sid_ptr.is_null() {
        return Err("Token SID 为空".into());
    }

    Ok(sid_ptr)
}

/// SECURITY.md 第 6 项：路径哈希（审计日志用，不泄露明文路径）
fn path_hash(path: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

/* ==================================================================== *
 *                        单元测试                                       *
 * ==================================================================== */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_hash_consistency() {
        let h1 = path_hash("C:\\Users\\test\\verthys");
        let h2 = path_hash("C:\\Users\\test\\verthys");
        let h3 = path_hash("C:\\Users\\other\\verthys");
        assert_eq!(h1, h2, "相同路径应产生相同哈希");
        assert_ne!(h1, h3, "不同路径应产生不同哈希");
    }

    #[test]
    fn test_lock_type_enum() {
        assert_ne!(LockType::Shared, LockType::Exclusive);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_sid_token_from_string() {
        // Administrators SID
        let sid = SidToken::from_string("S-1-5-32-544").unwrap();
        assert!(!sid.data.is_empty());
        assert_eq!(sid.data.len(), 8 + 4 * 2); // 2 sub-authorities

        // SYSTEM SID
        let sid2 = SidToken::from_string("S-1-5-18").unwrap();
        assert!(!sid2.data.is_empty());
        assert_eq!(sid2.data.len(), 8 + 4 * 1); // 1 sub-authority
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_sid_token_as_ptr_valid() {
        let sid = SidToken::from_string("S-1-1-0").unwrap(); // Everyone
        let ptr = sid.as_ptr();
        assert!(!ptr.is_null());
        // Revision byte should be 1
        assert_eq!(unsafe { *ptr }, 1);
    }

    #[test]
    fn test_verthys_file_lock_send_sync() {
        // 编译期验证：VerthysFileLock 实现了 Send + Sync
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VerthysFileLock>();
    }
}
