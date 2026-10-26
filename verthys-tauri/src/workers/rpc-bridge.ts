/*
 * workers/rpc-bridge.ts — Web Worker 加解密 RPC 的主线程桥
 *
 * 职责：接收工作线程发出的记录加解密请求，调用 Tauri 侧的模块密钥命令，
 * 并把结果回投给同一 Worker。桥只处理显式标记的 RPC 消息，其余消息
 * 原样交给任务分发函数，避免与任务响应协议混淆。
 *
 * 并发：RPC 响应按 rpcId 关联，多个 Worker 可并行发起；单次调用失败
 * 以 ok=false 回投，由工作线程按任务失败处理。
 */
import {
  ModuleCryptoError,
  openRecord,
  sealRecord,
  type CryptoModule,
} from "../lib/module_crypto";
import type {
  WorkerRpcRequestMessage,
  WorkerRpcResultMessage,
  WorkerRpcSuccess,
} from "./worker-rpc";

/** RPC 结果回投所需的最小能力（真实 Worker 与测试替身都满足） */
export interface RpcPostTarget {
  postMessage(message: unknown): void;
}

/** RPC 桥挂载所需的消息入口能力 */
export interface RpcHostWorker extends RpcPostTarget {
  onmessage: ((e: MessageEvent<unknown>) => void) | null;
}

/** 判定 RPC 请求（仅工作线程发往主线程） */
export function isWorkerRpcRequest(data: unknown): data is WorkerRpcRequestMessage {
  return (
    typeof data === "object" &&
    data !== null &&
    (data as { __verthysRpc?: unknown }).__verthysRpc === true
  );
}

/** 执行一次 RPC 并把结果回投给发起方 */
export async function handleWorkerRpc(
  worker: RpcPostTarget,
  request: WorkerRpcRequestMessage,
): Promise<void> {
  const { call } = request;
  const module = call.module as CryptoModule;
  try {
    const result: WorkerRpcSuccess =
      call.op === "seal"
        ? {
            dataB64: await sealRecord(module, call.kind, call.data, {
              salt: call.salt,
              fileHash: call.fileHash,
              seq: call.seq,
              total: call.total,
              iterations: call.iterations,
              wrappedKey: call.wrappedKey,
              password: call.password,
            }),
          }
        : await openRecord(module, call.kind, call.data, {
            salt: call.salt,
            fileHash: call.fileHash,
            seq: call.seq,
            total: call.total,
            iterations: call.iterations,
            wrappedKey: call.wrappedKey,
            password: call.password,
          });
    const message: WorkerRpcResultMessage = {
      __verthysRpcResult: true,
      rpcId: request.rpcId,
      ok: true,
      result,
    };
    worker.postMessage(message);
  } catch (e) {
    const code = e instanceof ModuleCryptoError ? e.code : "";
    const message: WorkerRpcResultMessage = {
      __verthysRpcResult: true,
      rpcId: request.rpcId,
      ok: false,
      error: `${e instanceof Error ? e.message : String(e)}${code ? `（${code}）` : ""}`,
    };
    worker.postMessage(message);
  }
}

/**
 * 把 RPC 桥挂到 Worker 的消息入口。
 *
 * @param worker 目标 Worker
 * @param dispatchTask 非 RPC 消息的任务分发函数（原有 onmessage 逻辑）
 */
export function attachRpcBridge(
  worker: RpcHostWorker,
  dispatchTask: (data: unknown) => void,
): void {
  worker.onmessage = (e: MessageEvent<unknown>) => {
    if (isWorkerRpcRequest(e.data)) {
      void handleWorkerRpc(worker, e.data);
      return;
    }
    dispatchTask(e.data);
  };
}
