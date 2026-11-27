//! 管道请求：普通请求、路径授权、流式进度与就绪握手。

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use super::block_on_with_handle;
use crate::worker::protocol::{
    ActorRequest, RotateProgress, DEFAULT_IPC_TIMEOUT, READY_CHECK_TIMEOUT,
};
use super::WorkerSession;

/// 路径授权签发超时：本地进程内往返，超时即视为失败关闭。
const PATH_AUTH_TIMEOUT: Duration = Duration::from_secs(5);

impl WorkerSession {
    /// 发送 JSON 请求并等待 JSON 响应（默认 15 秒超时）
    pub fn send_json(&self, json: &str) -> Result<String, String> {
        self.send_json_with_timeout(json, DEFAULT_IPC_TIMEOUT)
    }

    /// 签发一次性路径授权。
    ///
    /// `target_op` 限定消费该授权的操作，`mode` 限定读写方向；
    /// worker 只接受与规范化路径完全匹配且未过期的授权。
    pub fn authorize_path(&self, target_op: &str, mode: &str, path: &str) -> Result<(), String> {
        let request = serde_json::json!({
            "op": "authorize_path",
            "path": path,
            "mode": mode,
            "target_op": target_op,
        })
        .to_string();
        let response = self.send_json_with_timeout(&request, PATH_AUTH_TIMEOUT)?;
        let value: serde_json::Value =
            serde_json::from_str(&response).map_err(|e| format!("路径授权响应解析失败: {}", e))?;
        if value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
            Ok(())
        } else {
            Err(value
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("路径授权失败")
                .to_string())
        }
    }

    /// 发送 JSON 请求并等待 JSON 响应（自定义超时）
    ///
    /// 使用 tokio::time::timeout 包裹 read_line()，不轮询管道状态。
    pub fn send_json_with_timeout(&self, json: &str, timeout: Duration) -> Result<String, String> {
        let json_owned = json.to_string();
        let request_tx = self
            .inner
            .clone_sender()
            .ok_or_else(|| "worker actor 已退出（通道已关闭）".to_string())?;
        let runtime_handle = self.inner.runtime_handle.clone();

        block_on_with_handle(&runtime_handle, async move {
            let (reply_tx, reply_rx) = oneshot::channel();

            request_tx
                .send(ActorRequest::Send {
                    json: json_owned,
                    timeout,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| "worker actor 已退出（通道发送失败）".to_string())?;

            reply_rx
                .await
                .map_err(|_| "worker actor 通道关闭（任务已终止）".to_string())?
        })
    }


    /// 发送全库轮换请求并流式接收进度（v4_rotate_run 专用）
    ///
    /// 与解锁流式协议同构：worker 在 Run 阻塞期间写多条
    /// `{"op":"v4_rotate_progress",...}` 进度行，FFI 返回后写最终响应行。
    /// - `json`：v4_rotate_run 请求 JSON
    /// - `progress_cb`：每收到一条轮换进度行时调用
    ///
    /// 返回最终响应行的原始 JSON 字符串。
    pub fn send_json_with_rotate_progress(
        &self,
        json: &str,
        progress_cb: &dyn Fn(&RotateProgress),
    ) -> Result<String, String> {
        let json_owned = json.to_string();
        let request_tx = self
            .inner
            .clone_sender()
            .ok_or_else(|| "worker actor 已退出（通道已关闭）".to_string())?;
        let runtime_handle = self.inner.runtime_handle.clone();

        block_on_with_handle(&runtime_handle, async move {
            let (reply_tx, mut reply_rx) = oneshot::channel();
            let (progress_tx, mut progress_rx) = mpsc::channel::<RotateProgress>(64);

            request_tx
                .send(ActorRequest::SendStreamingRotate {
                    json: json_owned,
                    reply: reply_tx,
                    progress_tx,
                })
                .await
                .map_err(|_| "worker actor 已退出（通道发送失败）".to_string())?;

            loop {
                tokio::select! {
                    result = &mut reply_rx => {
                        /* 与解锁流一致：最终响应就绪后先排空已入队进度，
                         * 保证前端收到最后一条统计后再看到完成响应。 */
                        while let Ok(p) = progress_rx.try_recv() {
                            progress_cb(&p);
                        }
                        return match result {
                            Ok(r) => r,
                            Err(_) => Err("worker actor 通道关闭（任务已终止）".to_string()),
                        };
                    }
                    progress = progress_rx.recv() => {
                        if let Some(p) = progress {
                            progress_cb(&p);
                        }
                    }
                }
            }
        })
    }

    /// 就绪检测：等待 worker 主动推送的 ready 信号
    ///
    /// worker 在进入主循环前会主动写入 {"ok":true,"op":"ready"} 到 stdout。
    /// 此方法读取该信号，无需发送 ping，避免协议失步（ping 响应与 ready 信号混淆）。
    ///
    /// 诊断价值：
    ///   - 收到 ready 信号 → DLL 加载成功、Verthys_Init 成功、主循环已启动
    ///   - 超时 + stderr 有内容 → 可判断 worker 卡在哪一步（DLL 加载/Verthys_Init）
    ///   - 超时 + stderr 为空 → worker 使用旧版本二进制（无 eprintln 诊断）
    pub fn wait_for_ready_signal(&self) -> Result<(), String> {
        let request_tx = self
            .inner
            .clone_sender()
            .ok_or_else(|| "worker actor 已退出（通道已关闭）".to_string())?;
        let runtime_handle = self.inner.runtime_handle.clone();

        block_on_with_handle(&runtime_handle, async move {
            let (reply_tx, reply_rx) = oneshot::channel();

            request_tx
                .send(ActorRequest::WaitReady {
                    timeout: READY_CHECK_TIMEOUT,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| "worker actor 已退出（通道发送失败）".to_string())?;

            reply_rx
                .await
                .map_err(|_| "worker actor 通道关闭（任务已终止）".to_string())?
        })
    }
}
