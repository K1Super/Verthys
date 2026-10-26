/*
 * lib/module_crypto.ts — 内容层加密前端入口
 *
 * 职责：把 Tauri 侧的模块密钥/记录加解密命令收敛为稳定 API，供业务代码与
 * Web Worker 的 RPC 桥复用。本模块只传递模块名、公开参数与 base64 载荷，
 * 不派生、不缓存任何密钥。
 *
 * 文件密钥不在前端保存：瘦身布局的随机文件密钥只在首次创建时由 worker
 * 生成并立即包裹，后续每次加解密由 worker 用包裹态密钥一次性解封；
 * 文件块 v2 的盐与迭代次数是公开参数，随每次请求携带。
 *
 * 错误语义：worker 失败统一抛 ModuleCryptoError，保留 worker 错误码字符串
 * （ERR_XXXXXXXX），调用方可据 LOCKED / AUTH 分支处理，不做文案匹配。
 */
import {
  verthysModuleFileKey,
  verthysModuleKeyLock,
  verthysModuleKeyUnlock,
  verthysModuleOpen,
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
/** worker 错误码：参数非法 */
export const MODULE_ERR_INVALID = "ERR_00000001";

/** 文件块 v2 的 KDF 公开参数（与记录同形，可落盘） */
export interface FileKdfV2 {
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

/** 判断是否为认证失败（密文损坏/密钥不匹配） */
export function isModuleAuthError(e: unknown): boolean {
  return e instanceof ModuleCryptoError && e.code === MODULE_ERR_AUTH;
}

/** 判断是否需要重新解锁模块（worker 重启或锁定后） */
export function isModuleLockedError(e: unknown): boolean {
  return e instanceof ModuleCryptoError && e.code === MODULE_ERR_LOCKED;
}

function ensureOk(resp: VerthysResponse, action: string): VerthysResponse {
  if (!resp.ok) {
    const code = resp.error_code ?? resp.error ?? "";
    throw new ModuleCryptoError(`${action}失败`, code);
  }
  return resp;
}

/** 文件级密钥组（索引瘦身布局）：盐与包裹态密钥都是公开数据 */
export interface SlimFileKeys {
  /** 文件盐 base64 */
  saltB64: string;
  /** 包裹态文件密钥 base64（可随索引长期保存） */
  wrappedFileKey: string;
}

/** 把模块口令一次性交付 worker；前端不再持有该口令 */
export async function unlockModuleKey(module: CryptoModule, key: string): Promise<void> {
  ensureOk(await verthysModuleKeyUnlock(module, key), "解锁模块密钥");
}

/** 清除模块密钥（不传 module 表示全部清除） */
export async function lockModuleKey(module?: CryptoModule): Promise<void> {
  ensureOk(await verthysModuleKeyLock(module), "清除模块密钥");
}

/** 创建索引瘦身布局的文件级密钥组（随机文件密钥只在 worker 内生成并包裹） */
export async function createSlimFileKeys(module: CryptoModule = "photo"): Promise<SlimFileKeys> {
  const r = ensureOk(
    await verthysModuleFileKey({ module, kind: "slim_create" }),
    "创建文件密钥",
  );
  if (!r.salt || !r.wrapped_key) {
    throw new ModuleCryptoError("创建文件密钥响应缺少盐或包裹密钥", "");
  }
  return { saltB64: r.salt, wrappedFileKey: r.wrapped_key };
}

/** 生成文件块 v2 的随机 KDF 参数（盐是公开数据） */
export function createFileKdfV2(): FileKdfV2 {
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

/** 生成文件块 v2 的口令校验块（口令是每个文件独立的用户输入） */
export async function buildV2Check(
  module: CryptoModule,
  kdf: FileKdfV2,
  password: string,
): Promise<string> {
  return sealRecord(module, "v2_check", "", {
    salt: kdf.saltB64,
    iterations: kdf.iterations,
    password,
  });
}

/** 校验文件块 v2 口令校验块；认证失败返回 false，其余故障抛出 */
export async function verifyV2Check(
  module: CryptoModule,
  kdf: FileKdfV2,
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
