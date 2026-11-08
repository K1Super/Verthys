/*
 * controller/verthys_controller/preheat.rs — 容器预热（页缓存预读）
 *
 * 职责边界：
 *   用户选定容器后，在后台把解锁首批读入的元数据区预读进系统页缓存，
 *   缩短解锁首次读取延迟。本模块只做文件 I/O，不加载 DLL、不解密、
 *   不接触密钥，也不签发任何凭证。
 *
 * 约束：
 *   - 预读长度固定（A/B 元数据副本上界），不随容器体积放大，恶意文件
 *     无法借预热放大磁盘 I/O。
 *   - 预热失败只记录日志，不影响后续解锁。
 *   - 只接受当前容器 magic（VRTY）；其它格式不预热。
 */
use crate::controller::types::VerthysResponse;
use crate::util::path::sanitize_path;
use tauri::State;

/// 预热 .verthys 文件元数据区到 OS 页缓存。
///
/// 用户选择文件后调用，后台以 FILE_FLAG_SEQUENTIAL_SCAN 预读元数据区。
/// 预热失败仅记录日志，不阻塞后续解锁。
///
/// 安全边界：纯文件 I/O，不涉及 DLL、不解密、不接触密钥。
#[tauri::command]
pub async fn verthys_preheat(
    _state: State<'_, crate::state::AppState>,
    verthys_path: String,
) -> Result<VerthysResponse, String> {
    log::info!(
        "[verthys_preheat] 启动预热: path={}",
        sanitize_path(&verthys_path)
    );

    if !std::path::Path::new(&verthys_path).exists() {
        return Ok(VerthysResponse::ok("preheat"));
    }

    let path = verthys_path.clone();
    let preheat_result = tokio::task::spawn_blocking(move || verthys_preheat_blocking(&path)).await;
    match preheat_result {
        Ok(Ok(())) => log::info!("[verthys_preheat] 预热完成"),
        Ok(Err(e)) => log::warn!("[verthys_preheat] 预热失败: {}（解锁走磁盘读取）", e),
        Err(e) => log::warn!("[verthys_preheat] spawn_blocking 异常: {}", e),
    }

    Ok(VerthysResponse::ok("preheat"))
}

/// 实际执行预热的同步函数，在 blocking 线程中运行。
fn verthys_preheat_blocking(verthys_path: &str) -> Result<(), String> {
    use std::io::Read;

    let mut header = [0u8; 8];
    {
        let mut file = std::fs::File::open(verthys_path).map_err(|e| {
            log::warn!(
                "[verthys_preheat] 打开文件失败: {} | {}",
                sanitize_path(verthys_path),
                e
            );
            format!("打开文件失败: {}", e)
        })?;
        file.read_exact(&mut header).map_err(|e| {
            log::warn!("[verthys_preheat] 读取头部失败: {}", e);
            format!("读取头部失败: {}", e)
        })?;
    }

    if header[0..4] != *b"VRTY" {
        log::warn!("[verthys_preheat] 非当前容器帧头，跳过预热");
        return Err("非当前容器帧头".to_string());
    }

    // A/B 元数据副本共 128 KiB；预读该区间即覆盖解锁首批读段。
    const METADATA_PREHEAT_BYTES: u64 = 128 * 1024;
    preheat_range_sequential(verthys_path, 0, METADATA_PREHEAT_BYTES);
    log::info!(
        "[verthys_preheat] 元数据区预热完成: path={}",
        sanitize_path(verthys_path)
    );
    Ok(())
}

/// 以顺序扫描方式预读文件的指定范围，触发 OS 预读相邻页到缓存。
fn preheat_range_sequential(path: &str, off: u64, size: u64) {
    use std::io::{Read, Seek, SeekFrom};

    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x08000000)
            .open(path)
        {
            Ok(f) => f,
            Err(e) => {
                log::warn!("[verthys_preheat] SEQUENTIAL 打开失败: {}", e);
                return;
            }
        }
    };
    #[cfg(not(windows))]
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            log::warn!("[verthys_preheat] 打开失败: {}", e);
            return;
        }
    };

    let mut reader = std::io::BufReader::with_capacity(1024 * 1024, file);
    if let Err(e) = reader.seek(SeekFrom::Start(off)) {
        log::warn!("[verthys_preheat] seek 失败 off={}: {}", off, e);
        return;
    }

    let mut sink = std::io::sink();
    if let Err(e) = std::io::copy(&mut reader.take(size), &mut sink) {
        log::warn!("[verthys_preheat] 预读元数据区失败: {}", e);
    }
}
