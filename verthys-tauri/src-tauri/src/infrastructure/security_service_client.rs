//! security_service_client.rs — 宿主侧 P2 安全服务 IPC 客户端
//!
//! 只用于内核生命周期命令：宿主在创建 worker 之前 ARM 同目录 worker 路径，
//! worker 挂起创建后提交 PID + 创建时间完成 REGISTER。
//!
//! 安全约束：
//!   - 只连接固定管道名，请求 64 字节、响应 128 字节，全部定长；
//!   - 公钥只从 HKLM 服务键读取，缺失或类型不符即失败；
//!   - 响应必须通过 ECDSA P-256 验签，任何字段不符按失败处理；
//!   - 所有错误只返回固定描述，不输出路径、内部状态或堆栈；
//!   - 失败不阻断用户态解锁：调用方按 `preferred` 记录并继续。

#[cfg(target_os = "windows")]
mod imp {
    use sha2::{Digest, Sha256};
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, HANDLE, ERROR_IO_PENDING, ERROR_PIPE_BUSY,
        WAIT_OBJECT_0,
    };
    use windows::Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptDestroyKey, BCryptImportKeyPair,
        BCryptOpenAlgorithmProvider, BCryptVerifySignature, BCRYPT_ALG_HANDLE,
        BCRYPT_FLAGS, BCRYPT_KEY_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::{
        SetNamedPipeHandleState, WaitNamedPipeW, NAMED_PIPE_MODE, PIPE_READMODE_MESSAGE,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        KEY_WOW64_64KEY, REG_BINARY, REG_DWORD, REG_VALUE_TYPE,
    };
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
    use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

    const SERVICE_KEY: &str = r"SOFTWARE\Verthys\SecurityService";
    const PUBKEY_VALUE: &str = "ServerPubKey";
    const INSTALLED_VALUE: &str = "Installed";
    const PIPE_NAME: &str = r"\\.\pipe\VerthysSecuritySvc.v1";

    const REQUEST_BYTES: usize = 64;
    const RESPONSE_BYTES: usize = 128;
    const RESPONSE_HEADER_BYTES: usize = 64;
    const SIGNATURE_BYTES: usize = 64;
    const REQUEST_MAGIC: u32 = 0x5153_5456;
    const RESPONSE_MAGIC: u32 = 0x5253_5456;
    const PROTOCOL_VERSION: u16 = 1;

    const CMD_KERNEL_ARM: u16 = 6;
    const CMD_KERNEL_REGISTER: u16 = 7;
    const CMD_KERNEL_DISARM: u16 = 8;

    const STATUS_OK: u16 = 0;
    const STATUS_MAX: u16 = 5;

    const ARM_MODE_HOST_PREARM: u32 = 1;

    const PUBKEY_MAX: usize = 256;
    const CONNECT_TIMEOUT_MS: u32 = 250;
    const IO_TIMEOUT_MS: u32 = 1000;

    /// worker 映像白名单选择器，与服务侧派生规则一一对应。
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum WorkerImage {
        Default,
        Sidecar,
    }

    impl WorkerImage {
        fn selector(self) -> u32 {
            match self {
                WorkerImage::Default => 0,
                WorkerImage::Sidecar => 1,
            }
        }
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn put_u16(raw: &mut [u8], off: usize, value: u16) {
        raw[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(raw: &mut [u8], off: usize, value: u32) {
        raw[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(raw: &mut [u8], off: usize, value: u64) {
        raw[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn get_u16(raw: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([raw[off], raw[off + 1]])
    }

    fn get_u32(raw: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
    }

    fn get_u64(raw: &[u8], off: usize) -> u64 {
        u64::from_le_bytes([
            raw[off],
            raw[off + 1],
            raw[off + 2],
            raw[off + 3],
            raw[off + 4],
            raw[off + 5],
            raw[off + 6],
            raw[off + 7],
        ])
    }

    /// 构造内核生命周期请求。返回 (请求字节, request_id, nonce_lo, nonce_hi)。
    fn build_kernel_request(
        command: u16,
        payload: Option<(u32, u32, u32, u64)>,
        request_id: u32,
        nonce_lo: u64,
        nonce_hi: u64,
    ) -> [u8; REQUEST_BYTES] {
        let mut raw = [0u8; REQUEST_BYTES];
        put_u32(&mut raw, 0, REQUEST_MAGIC);
        put_u16(&mut raw, 4, PROTOCOL_VERSION);
        put_u16(&mut raw, 6, command);
        put_u32(&mut raw, 8, request_id);
        put_u64(&mut raw, 16, nonce_lo);
        put_u64(&mut raw, 24, nonce_hi);
        if let Some((mode, worker_image, target_pid, target_creation)) = payload {
            if command == CMD_KERNEL_ARM {
                put_u32(&mut raw, 32, mode);
                put_u32(&mut raw, 36, worker_image);
            } else if command == CMD_KERNEL_REGISTER {
                put_u32(&mut raw, 32, target_pid);
                put_u64(&mut raw, 36, target_creation);
            }
        }
        raw
    }

    /// 校验响应头（签名之前的结构校验）。返回内核状态码。
    fn decode_kernel_response(
        raw: &[u8; RESPONSE_BYTES],
        expected_request_id: u32,
        expected_nonce_lo: u64,
        expected_nonce_hi: u64,
    ) -> Result<(u16, u32), &'static str> {
        if get_u32(raw, 0) != RESPONSE_MAGIC
            || get_u16(raw, 4) != PROTOCOL_VERSION
            || get_u32(raw, 8) != expected_request_id
            || get_u64(raw, 16) != expected_nonce_lo
            || get_u64(raw, 24) != expected_nonce_hi
            || get_u32(raw, 36) != 0
        {
            return Err("安全服务响应格式无效");
        }
        let status = get_u16(raw, 6);
        if status > STATUS_MAX {
            return Err("安全服务响应状态无效");
        }
        Ok((status, get_u32(raw, 48)))
    }

    fn random_bytes(buf: &mut [u8]) -> Result<(), String> {
        use windows::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };
        if unsafe { BCryptGenRandom(None, buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }.is_ok() {
            Ok(())
        } else {
            Err("安全服务随机数生成失败".to_string())
        }
    }

    fn read_registry_value(name: &str, buf: &mut [u8], want_type: REG_VALUE_TYPE) -> Result<u32, String> {
        let key_path = wide(SERVICE_KEY);
        let value_name = wide(name);
        let mut key = HKEY::default();
        if unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR::from_raw(key_path.as_ptr()),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut key,
            )
        }
        .is_err()
        {
            return Err("安全服务未安装或不可读取".to_string());
        }

        let mut value_type = REG_VALUE_TYPE::default();
        let mut size = buf.len() as u32;
        let read = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR::from_raw(value_name.as_ptr()),
                None,
                Some(&mut value_type),
                Some(buf.as_mut_ptr()),
                Some(&mut size),
            )
        };
        unsafe {
            let _ = RegCloseKey(key);
        }
        if read.is_err() {
            return Err("安全服务注册表值读取失败".to_string());
        }
        if value_type != want_type || size == 0 || size as usize > buf.len() {
            return Err("安全服务注册表值类型或长度无效".to_string());
        }
        Ok(size)
    }

    fn service_ready() -> Result<Vec<u8>, String> {
        let mut installed = [0u8; 4];
        read_registry_value(INSTALLED_VALUE, &mut installed, REG_DWORD)?;
        if u32::from_le_bytes(installed) != 1 {
            return Err("安全服务未安装".to_string());
        }
        let mut pubkey = vec![0u8; PUBKEY_MAX];
        let len = read_registry_value(PUBKEY_VALUE, &mut pubkey, REG_BINARY)?;
        pubkey.truncate(len as usize);
        Ok(pubkey)
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    fn connect_pipe() -> Result<OwnedHandle, String> {
        let name = wide(PIPE_NAME);
        let open = || unsafe {
            CreateFileW(
                PCWSTR::from_raw(name.as_ptr()),
                (windows::Win32::Foundation::GENERIC_READ
                    | windows::Win32::Foundation::GENERIC_WRITE)
                    .0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            )
        };
        let handle = match open() {
            Ok(h) => h,
            Err(_) if unsafe { GetLastError() } == ERROR_PIPE_BUSY => {
                unsafe {
                    let _ = WaitNamedPipeW(
                        PCWSTR::from_raw(name.as_ptr()),
                        CONNECT_TIMEOUT_MS,
                    );
                }
                open().map_err(|_| "安全服务管道连接失败".to_string())?
            }
            Err(_) => return Err("安全服务管道连接失败".to_string()),
        };
        let owned = OwnedHandle(handle);
        let mode: NAMED_PIPE_MODE = PIPE_READMODE_MESSAGE;
        unsafe { SetNamedPipeHandleState(owned.0, Some(&mode), None, None) }
            .map_err(|_| "安全服务管道模式设置失败".to_string())?;
        Ok(owned)
    }

    fn overlapped_io(pipe: HANDLE, write: bool, buf: &mut [u8]) -> Result<usize, String> {
        let event = unsafe { CreateEventW(None, true, false, None) }
            .map_err(|_| "安全服务 I/O 事件创建失败".to_string())?;
        let event = OwnedHandle(event);
        let mut ov = OVERLAPPED::default();
        ov.hEvent = event.0;
        let mut transferred: u32 = 0;
        let result = unsafe {
            if write {
                WriteFile(pipe, Some(buf), Some(&mut transferred), Some(&mut ov))
            } else {
                ReadFile(pipe, Some(buf), Some(&mut transferred), Some(&mut ov))
            }
        };
        match result {
            Ok(()) => Ok(transferred as usize),
            Err(_) if unsafe { GetLastError() } == ERROR_IO_PENDING => {
                if unsafe { WaitForSingleObject(event.0, IO_TIMEOUT_MS) } != WAIT_OBJECT_0 {
                    unsafe {
                        let _ = CancelIoEx(pipe, Some(&ov));
                        let _ = WaitForSingleObject(event.0, 100);
                    }
                    return Err("安全服务 I/O 超时".to_string());
                }
                let mut done: u32 = 0;
                unsafe { GetOverlappedResult(pipe, &ov, &mut done, false) }
                    .map_err(|_| "安全服务 I/O 完成失败".to_string())?;
                Ok(done as usize)
            }
            Err(_) => Err("安全服务 I/O 失败".to_string()),
        }
    }

    fn verify_signature(pubkey: &[u8], response: &[u8; RESPONSE_BYTES]) -> Result<(), String> {
        let mut hasher = Sha256::new();
        hasher.update(&response[..RESPONSE_HEADER_BYTES]);
        let hash = hasher.finalize();

        let mut alg = BCRYPT_ALG_HANDLE::default();
        if unsafe {
            BCryptOpenAlgorithmProvider(
                &mut alg,
                w!("ECDSA_P256"),
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
        }
        .is_err()
        {
            return Err("安全服务验签初始化失败".to_string());
        }
        let alg = OwnedAlg(alg);
        let mut key = BCRYPT_KEY_HANDLE::default();
        if unsafe {
            BCryptImportKeyPair(
                alg.0,
                BCRYPT_KEY_HANDLE::default(),
                w!("ECCPUBLICBLOB"),
                &mut key,
                pubkey,
                0,
            )
        }
        .is_err()
        {
            return Err("安全服务公钥无效".to_string());
        }
        let key = OwnedKey(key);
        if unsafe {
            BCryptVerifySignature(
                key.0,
                None,
                &hash,
                &response[RESPONSE_HEADER_BYTES..RESPONSE_HEADER_BYTES + SIGNATURE_BYTES],
                BCRYPT_FLAGS(0),
            )
        }
        .is_err()
        {
            return Err("安全服务响应签名校验失败".to_string());
        }
        Ok(())
    }

    struct OwnedAlg(BCRYPT_ALG_HANDLE);

    impl Drop for OwnedAlg {
        fn drop(&mut self) {
            unsafe {
                let _ = BCryptCloseAlgorithmProvider(self.0, 0);
            }
        }
    }

    struct OwnedKey(BCRYPT_KEY_HANDLE);

    impl Drop for OwnedKey {
        fn drop(&mut self) {
            unsafe {
                let _ = BCryptDestroyKey(self.0);
            }
        }
    }

    fn request_kernel(
        command: u16,
        payload: Option<(u32, u32, u32, u64)>,
    ) -> Result<(), String> {
        let pubkey = service_ready()?;
        let pipe = connect_pipe()?;

        let mut random = [0u8; 20];
        random_bytes(&mut random)?;
        let request_id = u32::from_le_bytes([random[0], random[1], random[2], random[3]]);
        let nonce_lo = u64::from_le_bytes([
            random[4], random[5], random[6], random[7], random[8], random[9],
            random[10], random[11],
        ]);
        let nonce_hi = u64::from_le_bytes([
            random[12], random[13], random[14], random[15], random[16], random[17],
            random[18], random[19],
        ]);

        let mut request = build_kernel_request(command, payload, request_id, nonce_lo, nonce_hi);
        if overlapped_io(pipe.0, true, &mut request)? != REQUEST_BYTES {
            return Err("安全服务请求写入不完整".to_string());
        }

        let mut response = [0u8; RESPONSE_BYTES];
        if overlapped_io(pipe.0, false, &mut response)? != RESPONSE_BYTES {
            return Err("安全服务响应长度无效".to_string());
        }
        let (status, _kernel_state) =
            decode_kernel_response(&response, request_id, nonce_lo, nonce_hi)?;
        verify_signature(&pubkey, &response)?;
        if status != STATUS_OK {
            return Err(format!("安全服务拒绝内核命令（状态 {}）", status));
        }
        Ok(())
    }

    pub fn kernel_arm_host(image: WorkerImage) -> Result<(), String> {
        request_kernel(
            CMD_KERNEL_ARM,
            Some((ARM_MODE_HOST_PREARM, image.selector(), 0, 0)),
        )
    }

    pub fn kernel_register(pid: u32, creation: u64) -> Result<(), String> {
        if pid == 0 || creation == 0 {
            return Err("worker 身份无效".to_string());
        }
        request_kernel(CMD_KERNEL_REGISTER, Some((0, 0, pid, creation)))
    }

    pub fn kernel_disarm() -> Result<(), String> {
        request_kernel(CMD_KERNEL_DISARM, None)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows::Win32::Security::Cryptography::{
            BCryptExportKey, BCryptFinalizeKeyPair, BCryptGenerateKeyPair, BCryptSignHash,
        };

        #[test]
        fn signature_verification_accepts_valid_and_rejects_tampered() {
            unsafe {
                let mut alg = BCRYPT_ALG_HANDLE::default();
                assert!(BCryptOpenAlgorithmProvider(
                    &mut alg,
                    w!("ECDSA_P256"),
                    None,
                    BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0)
                )
                .is_ok());
                let alg = OwnedAlg(alg);

                let mut key = BCRYPT_KEY_HANDLE::default();
                assert!(BCryptGenerateKeyPair(alg.0, &mut key, 256, 0).is_ok());
                let key = OwnedKey(key);
                assert!(BCryptFinalizeKeyPair(key.0, 0).is_ok());

                let mut blob = [0u8; 256];
                let mut blob_len: u32 = 0;
                assert!(BCryptExportKey(
                    key.0,
                    BCRYPT_KEY_HANDLE::default(),
                    w!("ECCPUBLICBLOB"),
                    Some(&mut blob),
                    &mut blob_len,
                    0
                )
                .is_ok());
                let pubkey = &blob[..blob_len as usize];

                let mut response = [0u8; RESPONSE_BYTES];
                put_u32(&mut response, 0, RESPONSE_MAGIC);
                put_u16(&mut response, 4, PROTOCOL_VERSION);
                put_u16(&mut response, 6, STATUS_OK);

                let hash = Sha256::digest(&response[..RESPONSE_HEADER_BYTES]);
                let mut signature = [0u8; SIGNATURE_BYTES];
                let mut signature_len: u32 = 0;
                assert!(BCryptSignHash(
                    key.0,
                    None,
                    &hash,
                    Some(&mut signature),
                    &mut signature_len,
                    BCRYPT_FLAGS(0)
                )
                .is_ok());
                assert_eq!(signature_len as usize, SIGNATURE_BYTES);
                response[RESPONSE_HEADER_BYTES..].copy_from_slice(&signature);

                verify_signature(pubkey, &response).expect("合法签名必须通过");
                let mut tampered = response;
                tampered[8] ^= 1;
                assert!(verify_signature(pubkey, &tampered).is_err());
            }
        }

        #[test]
        fn kernel_arm_request_layout() {
            let raw = build_kernel_request(
                CMD_KERNEL_ARM,
                Some((ARM_MODE_HOST_PREARM, 1, 0, 0)),
                0x11223344,
                0x0102030405060708,
                0x1112131415161718,
            );
            assert_eq!(get_u32(&raw, 0), REQUEST_MAGIC);
            assert_eq!(get_u16(&raw, 4), PROTOCOL_VERSION);
            assert_eq!(get_u16(&raw, 6), CMD_KERNEL_ARM);
            assert_eq!(get_u32(&raw, 8), 0x11223344);
            assert_eq!(get_u32(&raw, 32), ARM_MODE_HOST_PREARM);
            assert_eq!(get_u32(&raw, 36), 1);
            assert_eq!(raw[40..].iter().all(|b| *b == 0), true);
        }

        #[test]
        fn kernel_register_request_layout() {
            let raw = build_kernel_request(
                CMD_KERNEL_REGISTER,
                Some((0, 0, 0x1234, 0x0102030405060708)),
                7,
                8,
                9,
            );
            assert_eq!(get_u32(&raw, 32), 0x1234);
            assert_eq!(get_u64(&raw, 36), 0x0102030405060708);
            assert_eq!(raw[44..].iter().all(|b| *b == 0), true);
        }

        #[test]
        fn disarm_request_has_no_payload() {
            let raw = build_kernel_request(CMD_KERNEL_DISARM, None, 1, 2, 3);
            assert_eq!(raw[32..].iter().all(|b| *b == 0), true);
        }

        #[test]
        fn response_header_rejects_tampering() {
            let mut raw = [0u8; RESPONSE_BYTES];
            put_u32(&mut raw, 0, RESPONSE_MAGIC);
            put_u16(&mut raw, 4, PROTOCOL_VERSION);
            put_u16(&mut raw, 6, STATUS_OK);
            put_u32(&mut raw, 8, 7);
            put_u64(&mut raw, 16, 8);
            put_u64(&mut raw, 24, 9);
            assert_eq!(decode_kernel_response(&raw, 7, 8, 9), Ok((0, 0)));

            let mut bad = raw;
            bad[0] ^= 0xFF;
            assert!(decode_kernel_response(&bad, 7, 8, 9).is_err());

            let mut bad = raw;
            put_u32(&mut bad, 8, 8);
            assert!(decode_kernel_response(&bad, 7, 8, 9).is_err());

            let mut bad = raw;
            put_u32(&mut bad, 36, 1);
            assert!(decode_kernel_response(&bad, 7, 8, 9).is_err());

            let mut bad = raw;
            put_u16(&mut bad, 6, STATUS_MAX + 1);
            assert!(decode_kernel_response(&bad, 7, 8, 9).is_err());
        }
    }
}

#[cfg(target_os = "windows")]
pub use imp::{kernel_arm_host, kernel_disarm, kernel_register, WorkerImage};

#[cfg(not(target_os = "windows"))]
mod imp {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum WorkerImage {
        Default,
        Sidecar,
    }

    pub fn kernel_arm_host(_image: WorkerImage) -> Result<(), String> {
        Err("非 Windows 平台不支持内核防护".to_string())
    }

    pub fn kernel_register(_pid: u32, _creation: u64) -> Result<(), String> {
        Err("非 Windows 平台不支持内核防护".to_string())
    }

    pub fn kernel_disarm() -> Result<(), String> {
        Err("非 Windows 平台不支持内核防护".to_string())
    }
}

#[cfg(not(target_os = "windows"))]
pub use imp::{kernel_arm_host, kernel_disarm, kernel_register, WorkerImage};
