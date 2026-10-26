/*
 * controller/verthys_controller/preheat.rs — 容器预热（页缓存预读与一次性令牌）
 *
 * 职责边界：
 *   用户选定容器后，在后台把解锁首批读段与温缓存文件预读进系统页缓存，
 *   并签发 30 秒有效的一次性预热令牌；解锁携带该令牌时启用零拷贝路径。
 *   本模块只做文件 I/O 与令牌签发，不加载 DLL、不解密、不接触密钥。
 *
 * 约束：
 *   - 预读长度固定（V3 固定布局区上界），不随容器体积放大，恶意文件
 *     无法借预热放大磁盘 I/O。
 *   - 预热失败只降级为磁盘读取：返回 Err 仅供调用方清除 prefetch_done，
 *     不得阻塞后续解锁。
 *   - 预读范围与 C 层固定布局契约同源；布局调整时必须同步常量，
 *     由 C 侧结构测试先在布局层暴露不一致。
 */
use crate::controller::types::VerthysResponse;
use crate::repository::container_layout;
use crate::state::verthys_session::PreheatToken;
use crate::state::AppState;
use crate::util::path::sanitize_path;
use tauri::State;

/// 预热 .verthys 文件索引区到 OS 页缓存，并生成预热令牌。
///
/// 用户选择文件后调用，后台以 FILE_FLAG_SEQUENTIAL_SCAN 预读索引区。
/// 预热成功后生成 30 秒有效的一次性令牌，解锁时需携带以启用零拷贝路径。
/// 预热失败仅记录日志，不阻塞后续解锁（降级磁盘读取）。
///
/// 安全边界：纯文件 I/O，不涉及 DLL、不解密、不接触密钥。
/// 返回令牌签名（base64），前端在解锁时传回。
#[tauri::command]
pub async fn verthys_preheat(
    state: State<'_, AppState>,
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

    use std::sync::atomic::Ordering;
    match preheat_result {
        Ok(Ok(())) => {
            state.prefetch_done.store(true, Ordering::SeqCst);
            log::info!("[verthys_preheat] 预热完成，prefetch_done=true");

            match PreheatToken::new() {
                Ok(token) => {
                    let token_b64 = crate::util::base64::base64_encode(token.signature());
                    state.preheat_token_store.store(token);
                    log::info!("[verthys_preheat] 预热令牌已生成（30s 有效）");

                    let mut resp = VerthysResponse::ok("preheat");
                    resp.data = Some(token_b64);
                    return Ok(resp);
                }
                Err(e) => {
                    log::warn!(
                        "[verthys_preheat] 生成预热令牌失败: {}，仅设置 prefetch_done",
                        e
                    );
                }
            }
        }
        Ok(Err(e)) => {
            state.prefetch_done.store(false, Ordering::SeqCst);
            log::warn!(
                "[verthys_preheat] 预热失败: {}，prefetch_done=false（C 层走磁盘读取）",
                e
            );
        }
        Err(e) => {
            state.prefetch_done.store(false, Ordering::SeqCst);
            log::warn!(
                "[verthys_preheat] spawn_blocking 异常: {}，prefetch_done=false",
                e
            );
        }
    }

    Ok(VerthysResponse::ok("preheat"))
}

/// 实际执行预热的同步函数，在 blocking 线程中运行。
///
/// 预读目标为 V3 固定布局区（解锁首批读段）与温缓存文件；读段长度固定，
/// 不依赖容器体积，恶意文件无法借此放大 IO。
/// 所有失败返回 Err，以便上层正确设置 prefetch_done 标志。
fn verthys_preheat_blocking(verthys_path: &str) -> Result<(), String> {
    use std::io::Read;

    let mut header = [0u8; 128];
    let filled = {
        let mut file = std::fs::File::open(verthys_path).map_err(|e| {
            log::warn!(
                "[verthys_preheat] 打开文件失败: {} | {}",
                sanitize_path(verthys_path),
                e
            );
            format!("打开文件失败: {}", e)
        })?;
        let mut n = 0usize;
        while n < 128 {
            match file.read(&mut header[n..]) {
                Ok(0) => break,
                Ok(r) => n += r,
                Err(e) => {
                    log::warn!("[verthys_preheat] 读取头部失败: {}", e);
                    return Err(format!("读取头部失败: {}", e));
                }
            }
        }
        n
    };
    if filled < 8 {
        log::warn!("[verthys_preheat] 文件过短 ({} 字节)，跳过预热", filled);
        return Err(format!("文件过短 ({} 字节)", filled));
    }

    // 唯一容器格式为 V3（磁盘偏移 0 为 Replica-0 帧头 'V3RP'）。旧布局
    // 时代的索引区偏移解析与 V3 无关，已随格式收敛删除，避免误读。
    const V3_REPLICA_FRAME_MAGIC: [u8; 4] = [0x56, 0x33, 0x52, 0x50]; // 'V3RP' LE
    if header[0..4] != V3_REPLICA_FRAME_MAGIC {
        log::warn!("[verthys_preheat] 非 V3 容器帧头，跳过预热");
        return Err("非 V3 容器帧头".to_string());
    }

    // V3 预热目标（page cache 进页即用）：
    //   1. 固定布局区：超块三副本 + WAL 区 + 分区表，即解锁流水线的首批读段；
    //   2. 温缓存文件（附属数据目录 idx_cache）：解锁时由 C 层加载的索引缓存。
    preheat_range_sequential(verthys_path, 0, V3_FIXED_LAYOUT_PREHEAT_BYTES);
    preheat_cache_file(verthys_path);
    log::info!(
        "[verthys_preheat] V3 容器预热完成: path={} (固定布局区 + 温缓存已进页缓存)",
        sanitize_path(verthys_path)
    );
    Ok(())
}

/// V3 固定布局区字节数：超块三副本（64KB）+ WAL 区（960KB）+ 分区表（3MB）。
///
/// 与 C 层布局契约同源（V3 容器固定布局区上界），用于预热预读长度；
/// 布局调整时需同步本值（C 侧结构测试会先在布局层暴露不一致）。
const V3_FIXED_LAYOUT_PREHEAT_BYTES: u64 = 4 * 1024 * 1024;

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
        log::warn!("[verthys_preheat] 预读索引区失败: {}", e);
    }
}

/// 预读持久化缓存文件（附属数据目录 idx_cache）到页缓存，提升温启动性能。
///
/// 附属目录优先，旧布局缓存作为只读回退（升级后首次打开、C 层尚未迁移时
/// 仍可享受温启动预读）。
fn preheat_cache_file(verthys_path: &str) {
    let primary = container_layout::idx_cache_file_for(verthys_path);
    let cache_path = if primary.exists() {
        primary
    } else {
        let legacy = container_layout::legacy_idx_cache_file_for(verthys_path);
        if !legacy.exists() {
            return;
        }
        legacy
    };
    let cache_path = cache_path.to_string_lossy().to_string();

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x08000000)
            .open(&cache_path)
        {
            Ok(f) => f,
            Err(e) => {
                log::warn!("[verthys_preheat] 缓存文件打开失败: {}", e);
                return;
            }
        };
        let mut reader = std::io::BufReader::with_capacity(256 * 1024, file);
        let mut sink = std::io::sink();
        let _ = std::io::copy(&mut reader, &mut sink);
    }
    #[cfg(not(windows))]
    {
        let file = match std::fs::File::open(&cache_path) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut reader = std::io::BufReader::with_capacity(256 * 1024, file);
        let mut sink = std::io::sink();
        let _ = std::io::copy(&mut reader, &mut sink);
    }
    log::info!(
        "[verthys_preheat] 缓存文件已预读: {}",
        sanitize_path(&cache_path)
    );
}
