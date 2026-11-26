use super::WorkerSession;

#[cfg(target_os = "windows")]
use std::sync::{Arc, Mutex as StdMutex};
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use super::host_env::{dev_machine_limiter_bypass, prearm_image, worker_image_for_name};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::CloseHandle;

#[cfg(target_os = "windows")]
#[test]
fn prearm_accepts_only_whitelisted_sibling_worker() {
    use crate::infrastructure::security_service_client::WorkerImage;

    assert_eq!(
        worker_image_for_name("verthys-worker.exe"),
        Some(WorkerImage::Default)
    );
    assert_eq!(
        worker_image_for_name("Verthys-Worker.EXE"),
        Some(WorkerImage::Default)
    );
    assert_eq!(
        worker_image_for_name("verthys-worker-x86_64-pc-windows-msvc.exe"),
        Some(WorkerImage::Sidecar)
    );
    assert_eq!(worker_image_for_name("other.exe"), None);
    assert_eq!(worker_image_for_name("verthys-worker-other.exe"), None);

    let host = std::env::current_exe().expect("current_exe");
    let dir = host.parent().expect("host dir");
    let sibling = dir.join("verthys-worker.exe");
    assert_eq!(
        prearm_image(&sibling.to_string_lossy()),
        Some(WorkerImage::Default)
    );
    let foreign = dir.join("missing-subdir").join("verthys-worker.exe");
    assert_eq!(prearm_image(&foreign.to_string_lossy()), None);
    let other = dir.join("other.exe");
    assert_eq!(prearm_image(&other.to_string_lossy()), None);
}

/// 验证 WorkerSession::spawn 在无 tokio 运行时上下文时返回错误
#[test]
fn test_spawn_requires_runtime() {
    // 不在 tokio 运行时上下文中
    let result = WorkerSession::spawn("nonexistent.exe", "nonexistent.dll");
    // 用 match 避免 unwrap_err() 要求 WorkerSession: Debug
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("spawn 应在无运行时上下文时失败"),
    };
    assert!(
        err.contains("tokio runtime"),
        "错误信息应提及 tokio runtime，实际: {}",
        err
    );
}

/// 验证 debug（测试）构建会向 worker 子进程注入机器预算旁路。
///
/// 未签名开发客户端会被已安装的 VerthysSecuritySvc 以 image-auth 拒绝，
/// 若旁路未进环境块，创建自检解锁会 fail-closed 并回滚整个创建。
#[cfg(target_os = "windows")]
#[test]
fn dev_machine_limiter_bypass_is_injected_into_child_env() {
    let (key, value) = dev_machine_limiter_bypass().expect("debug 构建必须注入旁路变量");
    assert_eq!(key, "VERTHYS_TEST_MACHINE_LIMITER_BYPASS");
    assert_eq!(value, "1");

    // 无控制台宿主下 cmd.exe 会自建可见控制台窗口，测试进程显式禁用窗口
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut cmd = std::process::Command::new("cmd");
    cmd.arg("/C").arg(format!("echo %{}%", key));
    cmd.env(key, value);
    cmd.creation_flags(CREATE_NO_WINDOW);
    let output = cmd.output().expect("spawn cmd 失败");
    assert!(
        output.status.success(),
        "cmd 退出异常: {:?}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim(),
        "1",
        "子进程未读到旁路变量，stdout={:?}",
        stdout
    );
}

/// worker 挂起看门狗端到端用例：真实 worker + 心跳 + 挂起看门狗。
///
/// 由 tests/attack/a18-suspend.ps1 设置 VERTHYS_A18=1 后驱动；常规
/// `cargo test` 不执行进程级实验，避免无产物环境下的偶发失败。
///
/// 判定：健康期不得误杀；挂起全部线程后 3s 级触发处置并终止 worker。
#[cfg(target_os = "windows")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspend_watchdog_terminates_suspended_worker() {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    if std::env::var("VERTHYS_A18").ok().as_deref() != Some("1") {
        eprintln!("A18S 跳过：未设置 VERTHYS_A18=1");
        return;
    }

    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("无法定位仓库根目录");
    let worker = std::env::var("VERTHYS_A18_WORKER")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            repo.join("verthys-tauri/verthys-worker/target/release/verthys-worker.exe")
        });
    let dll = std::env::var("VERTHYS_A18_DLL")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.join("build/core/Release/verthys.dll"));
    assert!(
        worker.is_file(),
        "A18S 缺少 worker 产物: {}",
        worker.display()
    );
    assert!(dll.is_file(), "A18S 缺少 DLL 产物: {}", dll.display());

    /// 挂起目标进程的全部线程并保持挂起，返回成功挂起的线程数。
    fn suspend_all_threads(pid: u32) -> usize {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
            TH32CS_SNAPTHREAD,
        };
        use windows::Win32::System::Threading::{
            OpenThread, SuspendThread, THREAD_SUSPEND_RESUME,
        };

        let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) } {
            Ok(h) => h,
            Err(_) => return 0,
        };
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        if unsafe { Thread32First(snapshot, &mut entry) }.is_err() {
            let _ = unsafe { CloseHandle(snapshot) };
            return 0;
        }
        let mut suspended = 0usize;
        loop {
            if entry.th32OwnerProcessID == pid {
                if let Ok(thread) =
                    unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) }
                {
                    if unsafe { SuspendThread(thread) } != u32::MAX {
                        suspended += 1;
                    }
                    let _ = unsafe { CloseHandle(thread) };
                }
            }
            if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
        let _ = unsafe { CloseHandle(snapshot) };
        suspended
    }

    let session = WorkerSession::spawn(
        &worker.to_string_lossy(),
        &dll.to_string_lossy(),
    )
    .expect("spawn worker 失败");
    session.wait_for_ready_signal().expect("worker 就绪失败");
    session.arm_heartbeat().expect("启用心跳失败");

    let fired = Arc::new(AtomicBool::new(false));
    let suspended_at = Arc::new(StdMutex::new(None::<Instant>));
    let elapsed_ms = Arc::new(AtomicU64::new(0));
    let handler_session = session.clone();
    let handler_fired = fired.clone();
    let handler_at = suspended_at.clone();
    let handler_elapsed = elapsed_ms.clone();
    session
        .start_suspend_watchdog(Arc::new(move || {
            let ms = handler_at
                .lock()
                .ok()
                .and_then(|t| *t)
                .map(|t| t.elapsed().as_millis() as u64)
                .unwrap_or(0);
            handler_elapsed.store(ms, Ordering::SeqCst);
            handler_fired.store(true, Ordering::SeqCst);
            handler_session.kill();
        }))
        .expect("启动挂起看门狗失败");

    // 健康期观察：心跳正常时看门狗不得触发。
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        !fired.load(Ordering::SeqCst),
        "健康 worker 被看门狗误杀"
    );

    let suspended = suspend_all_threads(session.pid());
    assert!(suspended > 0, "未能挂起 worker 线程");
    if let Ok(mut slot) = suspended_at.lock() {
        *slot = Some(Instant::now());
    }

    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline && !fired.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        fired.load(Ordering::SeqCst),
        "worker 挂起 3s 后看门狗未触发处置"
    );
    let measured = elapsed_ms.load(Ordering::SeqCst);
    println!("A18S_ELAPSED_MS={}", measured);
    assert!(
        (2000..=5000).contains(&measured),
        "处置延迟越界: {}ms（期望 3s 级）",
        measured
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && session.is_alive() {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!session.is_alive(), "看门狗触发后 worker 未终止");
}
