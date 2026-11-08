/*
 * workers/worker-rpc.ts — Web Worker 侧的记录加解密 RPC 客户端
 *
 * 职责：把工作线程中的每次记录加解密请求封装为一次主线程 RPC。密钥与
 * 派生过程都在 Tauri worker 进程内完成，本线程只搬运 base64 载荷。
 *
 * 协议：请求 { __verthysRpc: true, rpcId, call }；结果
 *       { __verthysRpcResult: true, rpcId, ok, result?, error? }。
 * 结果消息只由本客户端消费，任务消息由宿主 dispatch 处理。
 */

/** 单次 RPC 调用（与 Tauri module_seal/module_open 参数同形） */
export interface WorkerRpcCall {
  op: "seal" | "open";
  module: "photo" | "file";
  kind: string;
  data: string;
  salt?: string;
  fileHash?: string;
  seq?: number;
  total?: number;
  iterations?: number;
  wrappedKey?: string;
  password?: string;
}

/** RPC 成功结果 */
export interface WorkerRpcSuccess {
  dataB64: string;
  seq?: number;
  total?: number;
}

export interface WorkerRpcRequestMessage {
  __verthysRpc: true;
  rpcId: number;
  call: WorkerRpcCall;
}

export interface WorkerRpcResultMessage {
  __verthysRpcResult: true;
  rpcId: number;
  ok: boolean;
  result?: WorkerRpcSuccess;
  error?: string;
}

interface PendingRpc {
  resolve: (result: WorkerRpcSuccess) => void;
  reject: (error: Error) => void;
}

/** 判定结果消息（宿主 dispatch 不应处理这类消息） */
function isWorkerRpcResult(data: unknown): data is WorkerRpcResultMessage {
  return (
    typeof data === "object" &&
    data !== null &&
    (data as { __verthysRpcResult?: unknown }).__verthysRpcResult === true
  );
}

/**
 * 工作线程 RPC 客户端。
 *
 * @param post 向主线程发送消息的函数（Worker 内为 postMessage）
 */
export class WorkerRpcClient {
  private nextId = 1;
  private readonly pending = new Map<number, PendingRpc>();

  constructor(private readonly post: (message: WorkerRpcRequestMessage) => void) {}

  /** 发起一次 RPC；主线程返回失败时以 Error 拒绝 */
  request(call: WorkerRpcCall): Promise<WorkerRpcSuccess> {
    const rpcId = this.nextId++;
    return new Promise<WorkerRpcSuccess>((resolve, reject) => {
      this.pending.set(rpcId, { resolve, reject });
      try {
        this.post({ __verthysRpc: true, rpcId, call });
      } catch (e) {
        this.pending.delete(rpcId);
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  /**
   * 消费一条结果消息。
   *
   * @returns true 表示该消息属于 RPC（已消费），false 表示应交给任务分发
   */
  handleMessage(data: unknown): boolean {
    if (!isWorkerRpcResult(data)) return false;
    const pending = this.pending.get(data.rpcId);
    if (!pending) return true;
    this.pending.delete(data.rpcId);
    if (data.ok && data.result) {
      pending.resolve(data.result);
    } else {
      pending.reject(new Error(data.error || "内容加解密 RPC 失败"));
    }
    return true;
  }
}
