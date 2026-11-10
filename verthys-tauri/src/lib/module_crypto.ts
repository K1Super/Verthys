/*
 * lib/module_crypto.ts — 内容层加密前端入口
 *
 * 职责：把 Tauri 侧的模块密钥/记录加解密命令收敛为稳定 API，供业务代码与
 * Web Worker 的 RPC 桥复用。本模块只传递模块名、公开参数与 base64 载荷，
 * 不派生、不缓存任何密钥。
 *
 * 密钥不在前端保存：内容密钥只存在于 worker/C 层会话内，前端只传递公开
 * 参数（文件盐、迭代次数与布局种类）。瘦身布局仅保留读取兼容，不再新建
 * 包裹文件密钥。
 *
 * 错误语义：worker 失败统一抛 ModuleCryptoError，保留 worker 错误码字符串
 * （ERR_XXXXXXXX），调用方可据 LOCKED / AUTH 分支处理，不做文案匹配。
 */
import {
  verthysModuleKeyLock,
  verthysModuleOpen,
  verthysModuleProbeOuter,
  verthysModuleSeal,
  type ModuleCryptParams,
  type VerthysResponse,
} from "./verthys";
import { SALT_LEN, PBKDF2_ITER } from "../constants/crypto_const";
import { bytesToBase64 } from "../utils/binary_codec";

/** 内容层模块标识（与 worker 白名单一致） */
export type CryptoModule = "photo" | "file";

/** worker 错误码：认证失败（口令/密钥不匹配或数据被篡改） */
export const MODULE_ERR_AUTH = "ERR_00000002";
/** worker 错误码：模块密钥未解锁或已清除 */
export const MODULE_ERR_LOCKED = "ERR_00000007";
/** 文件块 v2 的 KDF 公开参数（与记录同形，可落盘） */
export interface FileKdf {
  /** KDF 版本标识 */
  version: number;
  /** 文件盐 base64 */
  saltB64: string;
  /** PBKDF2 迭代次数 */
  iterations: number;
}

export class ModuleCryptoError extends Error {
  /** worker 错误码字符串（可能为空） */
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "ModuleCryptoError";
    this.code = code;
  }
}

function ensureOk(resp: VerthysResponse, action: string): VerthysResponse {
  if (!resp.ok) {
    const code = resp.error_code ?? resp.error ?? "";
    throw new ModuleCryptoError(`${action}失败`, code);
  }
  return resp;
}

/** 清除模块密钥（不传 module 表示全部清除） */
export async function lockModuleKey(module?: CryptoModule): Promise<void> {
  ensureOk(await verthysModuleKeyLock(module), "清除模块密钥");
}

/** 生成文件块 v2 的随机 KDF 参数（盐是公开数据） */
export function createFileKdf(): FileKdf {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  return { version: 2, saltB64: bytesToBase64(salt), iterations: PBKDF2_ITER };
}

/** 加密单条内容记录，返回 base64 密文 */
export async function sealRecord(
  module: CryptoModule,
  kind: string,
  dataB64: string,
  opts: Omit<ModuleCryptParams, "module" | "kind" | "data"> = {},
): Promise<string> {
  const r = ensureOk(
    await verthysModuleSeal({ module, kind, data: dataB64, ...opts }),
    `加密记录(${kind})`,
  );
  if (r.data === undefined) {
    throw new ModuleCryptoError("加密响应缺失密文", "");
  }
  return r.data;
}

/** 解密单条内容记录；返回明文 base64 与（记录型块的）位置信息 */
export async function openRecord(
  module: CryptoModule,
  kind: string,
  dataB64: string,
  opts: Omit<ModuleCryptParams, "module" | "kind" | "data"> = {},
): Promise<{ dataB64: string; seq?: number; total?: number }> {
  const r = ensureOk(
    await verthysModuleOpen({ module, kind, data: dataB64, ...opts }),
    `解密记录(${kind})`,
  );
  return { dataB64: r.data ?? "", seq: r.seq, total: r.total };
}

/**
 * 探测内容记录的外层信封（模块密钥层）是否完整。
 *
 * 供损坏扫描使用：不需要文件口令、不校验布局种类标签。
 * 返回 true=外层可解封；false=外层认证失败（确定损坏）；
 * 模块锁定/超时等无法判定的情况抛出 `ModuleCryptoError`，由调用方跳过。
 */
export async function probeOuterRecord(
  module: CryptoModule,
  dataB64: string,
): Promise<boolean> {
  const resp = await verthysModuleProbeOuter({ module, data: dataB64 });
  if (resp.ok) return true;
  const code = resp.error_code ?? resp.error ?? "";
  if (code === MODULE_ERR_AUTH) return false;
  throw new ModuleCryptoError("探测内容外层失败", code);
}

/** 生成文件块 v2 的口令校验块（口令是每个文件独立的用户输入） */
export async function buildModuleCheck(
  module: CryptoModule,
  kdf: FileKdf,
  password: string,
): Promise<string> {
  return sealRecord(module, "v2_check", "", {
    salt: kdf.saltB64,
    iterations: kdf.iterations,
    password,
  });
}

/** 校验文件块 v2 口令校验块；认证失败返回 false，其余故障抛出 */
export async function verifyModuleCheck(
  module: CryptoModule,
  kdf: FileKdf,
  password: string,
  checkB64: string,
): Promise<boolean> {
  const r = await verthysModuleOpen({
    module,
    kind: "v2_check",
    data: checkB64,
    salt: kdf.saltB64,
    iterations: kdf.iterations,
    password,
  });
  if (r.ok) return true;
  const code = r.error_code ?? r.error ?? "";
  if (code === MODULE_ERR_AUTH) return false;
  throw new ModuleCryptoError("校验口令校验块失败", code);
}
