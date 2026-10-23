/*
 * updater/transport.rs — 安装包下载传输
 *
 * 插件下载接口只提供“读取直到结束”，无法在超限时立即中止、无法按会话取消，
 * 也不暴露重定向策略。本模块自行执行 HTTP 传输，把总时限、连接时限、空闲
 * 时限、字节上限、取消与重定向白名单集中到一处，避免安全判定分散在回调里。
 */

use super::UpdaterError;
use futures_util::StreamExt;
use reqwest::redirect::Policy;
use reqwest::Url;
use std::sync::Once;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// 建立连接的上限；连接阶段卡住时不必等到总时限。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 两个数据块之间的最长等待；网络静默视为失败。
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// 最多跟随的重定向次数。
const MAX_REDIRECTS: usize = 5;
/// 初始预分配上限；安装包较大时仍按实际增长，避免一次性占满内存。
const PREALLOC_CAP: u64 = 8 * 1024 * 1024;

static CRYPTO_INIT: Once = Once::new();

/// 一次下载所需的全部策略；由清单校验结果构造，不在传输层重新解释业务。
pub struct DownloadSpec {
    pub url: Url,
    pub expected_size: u64,
    /// 是否允许明文 HTTP；仅本机回环渠道为真。
    pub allow_http: bool,
    /// 是否允许任意回环地址；仅本机渠道为真。
    pub allow_loopback: bool,
    /// 允许的重定向目标主机（小写）；初始主机已由调用方加入。
    pub allowed_hosts: Vec<String>,
    /// 本机回环渠道绕过系统代理，避免代理把回环请求转出本机。
    pub no_proxy: bool,
}

/// 下载安装包：成功返回完整字节，失败返回可映射到用户文案的错误。
///
/// 取消通过 `CancellationToken` 生效；一旦触发，连接与缓冲区立即释放。
/// 进度回调只报告块长度，不包含任何业务判定。
pub async fn download<F>(
    spec: &DownloadSpec,
    cancel: &CancellationToken,
    total_timeout: Duration,
    mut on_chunk: F,
) -> Result<Vec<u8>, UpdaterError>
where
    F: FnMut(usize, Option<u64>),
{
    install_crypto_provider();

    let allowed_hosts: Vec<String> = spec
        .allowed_hosts
        .iter()
        .map(|host| host.to_ascii_lowercase())
        .collect();
    let allow_http = spec.allow_http;
    let allow_loopback = spec.allow_loopback;
    if !redirect_target_allowed(&spec.url, allow_http, allow_loopback, &allowed_hosts) {
        return Err(UpdaterError::new(
            "E_UPDATER_MANIFEST_INVALID",
            "下载地址不在允许范围",
            false,
        ));
    }
    let redirect = Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.stop();
        }
        if redirect_target_allowed(attempt.url(), allow_http, allow_loopback, &allowed_hosts) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });

    let mut builder = reqwest::Client::builder()
        .user_agent("Verthys-Updater")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(total_timeout)
        .redirect(redirect);
    if spec.no_proxy {
        builder = builder.no_proxy();
    }
    let client = builder.build().map_err(|error| {
        UpdaterError::new(
            "E_UPDATER_NETWORK",
            format!("无法创建下载客户端: {error}"),
            true,
        )
    })?;

    let response = tokio::select! {
        _ = cancel.cancelled() => return Err(cancelled_error()),
        response = client.get(spec.url.clone()).send() => response.map_err(network_error)?,
    };

    if !response.status().is_success() {
        return Err(http_status_error(response.status()));
    }
    if let Some(length) = response.content_length() {
        if length != spec.expected_size {
            return Err(size_error());
        }
    }

    let mut stream = response.bytes_stream();
    let prealloc = usize::try_from(spec.expected_size.min(PREALLOC_CAP)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(prealloc);
    let started = Instant::now();

    loop {
        let remaining = total_timeout
            .checked_sub(started.elapsed())
            .unwrap_or_default();
        if remaining.is_zero() {
            return Err(UpdaterError::new(
                "E_UPDATER_NETWORK",
                "下载总时长超限",
                true,
            ));
        }

        let next = tokio::select! {
            _ = cancel.cancelled() => return Err(cancelled_error()),
            next = tokio::time::timeout(IDLE_TIMEOUT.min(remaining), stream.next()) => next,
        };

        match next {
            Err(_) => return Err(UpdaterError::new("E_UPDATER_NETWORK", "下载空闲超时", true)),
            Ok(None) => break,
            Ok(Some(Err(error))) => return Err(network_error(error)),
            Ok(Some(Ok(chunk))) => {
                let total = bytes.len() as u64 + chunk.len() as u64;
                if total > spec.expected_size {
                    return Err(size_error());
                }
                bytes.extend_from_slice(&chunk);
                on_chunk(chunk.len(), Some(spec.expected_size));
            }
        }
    }

    if bytes.len() as u64 != spec.expected_size {
        return Err(size_error());
    }
    Ok(bytes)
}

/// 回环判定：主机名形式与 IPv4 回环段都接受，IPv6 仅接受 `::1`。
pub(crate) fn is_loopback_host(host: &str) -> bool {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn redirect_target_allowed(
    url: &Url,
    allow_http: bool,
    allow_loopback: bool,
    allowed_hosts: &[String],
) -> bool {
    let scheme_ok = url.scheme() == "https" || (allow_http && url.scheme() == "http");
    if !scheme_ok {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    if allow_loopback && is_loopback_host(host) {
        return true;
    }
    allowed_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host))
}

fn install_crypto_provider() {
    CRYPTO_INIT.call_once(|| {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

fn network_error(error: reqwest::Error) -> UpdaterError {
    UpdaterError::new("E_UPDATER_NETWORK", format!("下载请求失败: {error}"), true)
}

fn http_status_error(status: reqwest::StatusCode) -> UpdaterError {
    if status == reqwest::StatusCode::NOT_FOUND
        || status == reqwest::StatusCode::GONE
        || status == reqwest::StatusCode::FORBIDDEN
    {
        return UpdaterError::new(
            "E_UPDATER_PACKAGE_MISSING",
            format!("更新物料不可访问: HTTP {status}"),
            false,
        );
    }
    let retryable = status.is_server_error()
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
    UpdaterError::new(
        "E_UPDATER_NETWORK",
        format!("下载请求返回 HTTP {status}"),
        retryable,
    )
}

fn size_error() -> UpdaterError {
    UpdaterError::new(
        "E_UPDATER_SIZE_MISMATCH",
        "下载字节数与清单声明不一致",
        false,
    )
}

fn cancelled_error() -> UpdaterError {
    UpdaterError::new("E_UPDATER_CANCELLED", "更新已取消", false)
}

#[cfg(test)]
mod tests {
    use super::{download, is_loopback_host, redirect_target_allowed, DownloadSpec};
    use reqwest::Url;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    fn spec(url: String, expected: u64) -> DownloadSpec {
        DownloadSpec {
            url: Url::parse(&url).expect("test url"),
            expected_size: expected,
            allow_http: true,
            allow_loopback: true,
            allowed_hosts: vec!["127.0.0.1".to_string()],
            no_proxy: true,
        }
    }

    async fn spawn_server(response: &'static [u8]) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                // 先消费请求头再回写，避免服务端提前关闭触发 TCP 重置。
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;
                let _ = socket.write_all(response).await;
                let _ = socket.shutdown().await;
            }
        });
        (format!("http://{addr}/installer.exe"), handle)
    }

    #[tokio::test]
    async fn downloads_exact_bytes_and_rejects_length_mismatch() {
        let (url, server) =
            spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest")
                .await;
        let bytes = download(
            &spec(url, 4),
            &CancellationToken::new(),
            Duration::from_secs(5),
            |_, _| {},
        )
        .await
        .unwrap();
        assert_eq!(bytes, b"test");
        server.await.unwrap();

        let (url, server) =
            spawn_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\ntest")
                .await;
        let error = download(
            &spec(url, 4),
            &CancellationToken::new(),
            Duration::from_secs(5),
            |_, _| {},
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "E_UPDATER_SIZE_MISMATCH");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_aborts_in_flight_download() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Ok((_socket, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        let token = CancellationToken::new();
        let cancel = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel.cancel();
        });

        let error = download(
            &spec(format!("http://{addr}/installer.exe"), 10),
            &token,
            Duration::from_secs(5),
            |_, _| {},
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "E_UPDATER_CANCELLED");
        server.abort();
    }

    #[test]
    fn loopback_detection_covers_names_and_ipv4_range() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.10.0.9"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("example.com"));
        assert!(!is_loopback_host("10.0.0.1"));
    }

    #[test]
    fn redirect_policy_requires_scheme_host_and_limit() {
        let allowed = vec!["updates.example.com".to_string()];
        let url = |value: &str| Url::parse(value).expect("test url");

        assert!(redirect_target_allowed(
            &url("https://updates.example.com/file"),
            false,
            false,
            &allowed
        ));
        assert!(!redirect_target_allowed(
            &url("http://updates.example.com/file"),
            false,
            false,
            &allowed
        ));
        assert!(redirect_target_allowed(
            &url("http://127.0.0.2/file"),
            true,
            true,
            &allowed
        ));
        assert!(!redirect_target_allowed(
            &url("https://other.example.com/file"),
            false,
            false,
            &allowed
        ));
    }
}
