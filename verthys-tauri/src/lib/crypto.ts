/*
 * crypto.ts — 前端独立加密层（XChaCha20-Poly1305 + BLAKE3）
 *
 * 设计原则（对照用户提供的加密存储设计）：
 *   - 机密性：原始文件名、类型、大小、缩略图均加密，外部无法获取明文
 *   - 完整性：每个块独立附加 Poly1305 认证标签（AEAD 内置）
 *   - Nonce 唯一：每块 24 字节随机 Nonce（CSPRNG），碰撞概率可忽略
 *   - 块顺序绑定：块序号 + 总块数 + 文件哈希 作为 AEAD 附加数据（AD）
 *   - 密钥派生：PBKDF2-SHA256(150000) → 主密钥；HKDF-SHA256 → 文件子密钥
 *   - 内存安全：密钥使用后立即 fill(0) 清零（Zeroize 等价）
 *
 * 记录类型约定（verthys record type）：
 *   0x01 — 照片元数据（加密的 JSON：名称/MIME/大小/缩略图/块ID/哈希）
 *   0x05 — 照片数据块（加密的原始图片块）
 *
 * 数据块格式（base64 解码后）：
 *   [salt(16)] [seq(4 大端)] [total(4 大端)] [nonce(24)] [ciphertext+tag(变长)]
 *   AD = "VERTHYSPHOTO_CHUNK_v1" || seq(4) || total(4) || fileHash(32)
 *
 * 元数据格式（base64 解码后）：
 *   [salt(16)] [nonce(24)] [ciphertext+tag(变长)]
 *   AD = "VERTHYSPHOTO_META_v1"
 *   明文 = JSON { name, mime, size, thumbB64, chunkIds, fileHash, createdAt }
 *
 * 分层架构：
 *   constants/crypto_const.ts  ← 常量集中定义
 *   types/crypto.ts            ← 类型接口抽离
 *   utils/binary_codec.ts      ← 二进制编解码工具
 *   lib/crypto_error.ts        ← 标准化错误封装
 *   lib/crypto.ts              ← 加密层主逻辑（本文件）
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { blake3 } from "@noble/hashes/blake3";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToBase64, base64ToBytes, hexToBytes, bytesToHex, isValidHex, toArrayBuffer } from "../utils/binary_codec";

import {
  PBKDF2_ITER, KEY_LEN, SALT_LEN, NONCE_LEN, TAG_LEN,
  SEQ_LEN, TOTAL_LEN, CHUNK_SIZE, FILE_HASH_LEN,
  META_AD_TEXT, CHUNK_AD_PREFIX_TEXT, FILE_KEY_INFO_TEXT,
  THUMB_AD_TEXT, FILE_KEY_WRAP_AD_TEXT, CHUNK_SET_AD_TEXT,
  PHOTO_FMT_SLIM,
  VENC_MAGIC_TEXT, VENC_VERSION,
  VENC_OUTER_HEADER_BYTES, VENC_WRAPPED_KEY_BYTES, VENC_FRAME_HEADER_BYTES,
  VENC_TRAILER_PAYLOAD_BYTES,
  VENC_KDF_ID_PBKDF2_SHA256,
  VENC_FRAME_TYPE_LIGHT_META, VENC_FRAME_TYPE_CHUNK, VENC_FRAME_TYPE_TRAILER,
  PARSE_MAX_FRAME_COUNT, PARSE_MAX_FRAME_BYTES, PARSE_MAX_CONTAINER_BYTES,
  TYPE_PHOTO_META, TYPE_PHOTO_CHUNK,
} from "../constants/crypto_const";
import type { PhotoMeta, LightMeta, VencPhotoSpecV2, SlimChunkSet } from "../types/crypto";
import { PHOTO_INDEX_MAX_BYTES } from "../constants/photo_budget.generated";
import {
  CryptoError, CryptoErrorKind,
  invalidInput, formatCorrupted, unsupportedVersion, wrapAsCryptoError,
} from "./crypto_error";

/* ------------------------------------------------------------------ *
 * 模块级预计算常量（AD 字节序列，避免重复编码）                       *
 * ------------------------------------------------------------------ */

const META_AD = new TextEncoder().encode(META_AD_TEXT);
const CHUNK_AD_PREFIX = new TextEncoder().encode(CHUNK_AD_PREFIX_TEXT);
const FILE_KEY_INFO = new TextEncoder().encode(FILE_KEY_INFO_TEXT);
const THUMB_AD = new TextEncoder().encode(THUMB_AD_TEXT);
const FILE_KEY_WRAP_AD = new TextEncoder().encode(FILE_KEY_WRAP_AD_TEXT);
const CHUNK_SET_AD = new TextEncoder().encode(CHUNK_SET_AD_TEXT);
const VENC_MAGIC = new TextEncoder().encode(VENC_MAGIC_TEXT);

/* ------------------------------------------------------------------ *
 * 密钥派生（公共函数，消除两处 PBKDF2 重复逻辑）                      *
 * ------------------------------------------------------------------ */

/**
 * 通用 PBKDF2-SHA256 密钥派生（公共函数）
 *
 * 统一 deriveMasterKey 与 encryptExportFile/decryptExportFile 中
 * 重复的 PBKDF2 逻辑：导入 baseKey → deriveBits。
 *
 * @param password 用户密码或令牌
 * @param salt 盐值（长度不限，由调用方保证）
 * @param iterations 迭代次数（默认 150000，与后端一致）
 * @param keyLengthBits 派生密钥位数（默认 256）
 * @returns 派生密钥的 ArrayBuffer
 * @throws CryptoError(INVALID_INPUT) 密码为空或盐值非法
 * @throws CryptoError(KEY_DERIVATION_FAILED) Web Crypto API 派生失败
 */
async function derivePBKDF2Bits(
  password: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITER,
  keyLengthBits: number = KEY_LEN * 8,
): Promise<ArrayBuffer> {
  if (!password || password.length === 0) {
    throw invalidInput("密码/令牌不能为空");
  }
  if (!salt || salt.length === 0) {
    throw invalidInput("盐值不能为空");
  }

  try {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]
    );
    return await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: toArrayBuffer(salt), iterations, hash: "SHA-256" },
      baseKey, keyLengthBits
    );
  } catch (e) {
    throw wrapAsCryptoError(e, CryptoErrorKind.KEY_DERIVATION_FAILED, "PBKDF2 密钥派生失败");
  }
}

/**
 * 从用户密码派生主密钥（PBKDF2-SHA256，150000 迭代）
 *
 * 与 verthys.ts 的 deriveFieldKey 不同：此处用于照片文件级主密钥。
 */
async function deriveMasterKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const bits = await derivePBKDF2Bits(password, salt);
  return new Uint8Array(bits);
}

/**
 * 从主密钥派生文件子密钥（HKDF-SHA256）
 * 每个文件独立的密钥，防止跨文件密钥重用
 */
function deriveFileKey(masterKey: Uint8Array, fileSalt: Uint8Array): Uint8Array {
  // HKDF: extract + expand
  const ikm = masterKey;
  const salt = fileSalt;
  const info = FILE_KEY_INFO;
  return hkdf(sha256, ikm, salt, info, KEY_LEN);
}

/* ------------------------------------------------------------------ *
 * 文件子密钥缓存（每文件一次 PBKDF2）                                 *
 *                                                                    *
 * 密文布局里 salt 随块携带：同一文件的块若共用 salt（新写入路径），     *
 * 逐块重复 PBKDF2（150k 迭代）是纯粹的重复计算；不同 salt 之间不会     *
 * 互相复用。此处按 salt 缓存派生结果，使"每文件一次派生"在读取侧        *
 * 自动成立，且对存量"每块独立 salt"的设备数据无影响（互不命中）。       *
 *                                                                    *
 * 安全边界：缓存只持有派生结果（子密钥），容量受限，淘汰与显式清理时     *
 * 一律零填充；模块密钥失效必须调用 clearFileKeyCache。                  *
 * ------------------------------------------------------------------ */

/** 缓存条目上限（超出淘汰最旧条目并零填充其子密钥） */
const FILE_KEY_CACHE_MAX = 8;

/** salt → 派生中的文件子密钥（键含口令指纹，见 deriveCacheKey） */
const fileKeyCache = new Map<string, Promise<Uint8Array>>();

/**
 * 派生缓存键：口令指纹 + 盐。
 *
 * Why 键控口令：仅按盐缓存时，同一盐在不同口令下会误命中（口令错误却拿到
 * 正确口令派生的子密钥，掩盖认证失败并让"换钥后仍可解旧数据"的风险外溢）。
 * 此处以口令与盐的 BLAKE3 短摘要作为键——摘要仅用于内存查表，不落盘、
 * 不入日志；口令明文不进入键字符串（字符串不可清零）。
 */
function deriveCacheKey(password: string, salt: Uint8Array): string {
  const pwBytes = new TextEncoder().encode(password);
  const buf = new Uint8Array(pwBytes.length + 1 + salt.length);
  buf.set(pwBytes, 0);
  buf.set(salt, pwBytes.length + 1);
  const digest = blake3(buf, { dkLen: 16 });
  const key = bytesToHex(digest);
  zeroize(buf);
  zeroize(digest);
  return key;
}

/** 按口令与盐取文件子密钥（命中缓存则复用，未命中执行一次 PBKDF2 + HKDF）。
 *  返回缓存主副本的拷贝：调用方用毕自行零填充，缓存淘汰/清空时销毁主副本，
 *  两侧互不影响——避免"缓存淘汰打断在途解密"的竞态。 */
async function deriveFileKeyCached(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const cacheKey = deriveCacheKey(password, salt);
  const hit = fileKeyCache.get(cacheKey);
  if (hit) return (await hit).slice();

  const pending = (async (): Promise<Uint8Array> => {
    const masterKey = await deriveMasterKey(password, salt);
    const fileKey = deriveFileKey(masterKey, salt);
    zeroize(masterKey);
    return fileKey;
  })();
  fileKeyCache.set(cacheKey, pending);

  if (fileKeyCache.size > FILE_KEY_CACHE_MAX) {
    const oldestKey = fileKeyCache.keys().next().value as string | undefined;
    if (oldestKey !== undefined) {
      const oldest = fileKeyCache.get(oldestKey);
      fileKeyCache.delete(oldestKey);
      // 淘汰即销毁：派生失败时无可销毁内容
      void oldest?.then((k) => zeroize(k)).catch(() => { /* 派生失败无需清理 */ });
    }
  }
  // 未命中路径同样返回拷贝：调用方零填充自己的副本，缓存主副本不受影响
  return (await pending).slice();
}

/** 清空文件子密钥缓存（模块密钥失效/登出时调用，逐条零填充） */
export function clearFileKeyCache(): void {
  for (const pending of fileKeyCache.values()) {
    void pending.then((k) => zeroize(k)).catch(() => { /* 派生失败无需清理 */ });
  }
  fileKeyCache.clear();
}

/** 当前缓存条目数（观测与断言用：条目数即"不同盐的派生次数"上界） */
export function getFileKeyCacheSize(): number {
  return fileKeyCache.size;
}

/* ------------------------------------------------------------------ *
 * 内存安全                                                            *
 * ------------------------------------------------------------------ */

/** 安全清零（Zeroize 等价） */
function zeroize(buf: Uint8Array): void {
  buf.fill(0);
}

/* ------------------------------------------------------------------ *
 * 哈希                                                                *
 * ------------------------------------------------------------------ */

/** 计算 BLAKE3 文件哈希（32 字节，用于完整性 + AD 绑定） */
export function computeFileHash(data: Uint8Array): Uint8Array {
  if (!data || data.length === 0) {
    throw invalidInput("待哈希数据不能为空");
  }
  return blake3(data, { dkLen: FILE_HASH_LEN });
}

/* ------------------------------------------------------------------ *
 * 元数据加密/解密                                                     *
 * ------------------------------------------------------------------ */

/** 加密元数据，返回 base64 串 */
export async function encryptMeta(meta: PhotoMeta, password: string): Promise<string> {
  if (!password || password.length === 0) {
    throw invalidInput("密码不能为空");
  }
  if (!meta || typeof meta !== "object") {
    throw invalidInput("元数据对象非法");
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const fileKey = await deriveFileKeyCached(password, salt);

  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify(meta));

  const cipher = xchacha20poly1305(fileKey, nonce, META_AD);
  const ciphertext = cipher.encrypt(plaintext);  // 末尾含 16 字节 tag

  // 组合: salt(16) | nonce(24) | ciphertext+tag
  const combined = new Uint8Array(SALT_LEN + NONCE_LEN + ciphertext.length);
  combined.set(salt, 0);
  combined.set(nonce, SALT_LEN);
  combined.set(ciphertext, SALT_LEN + NONCE_LEN);

  zeroize(fileKey);
  return bytesToBase64(combined);
}

/** 解密元数据，返回 PhotoMeta */
export async function decryptMeta(b64: string, password: string): Promise<PhotoMeta> {
  if (!password || password.length === 0) {
    throw invalidInput("密码不能为空");
  }
  if (!b64 || b64.length === 0) {
    throw invalidInput("密文 base64 不能为空");
  }

  const combined = base64ToBytes(b64);
  if (combined.length < SALT_LEN + NONCE_LEN) {
    throw formatCorrupted(`元数据密文过短（${combined.length} < ${SALT_LEN + NONCE_LEN}）`);
  }

  const salt = combined.slice(0, SALT_LEN);
  const nonce = combined.slice(SALT_LEN, SALT_LEN + NONCE_LEN);
  const ciphertext = combined.slice(SALT_LEN + NONCE_LEN);

  const fileKey = await deriveFileKeyCached(password, salt);

  const cipher = xchacha20poly1305(fileKey, nonce, META_AD);
  let plaintext: Uint8Array;
  try {
    plaintext = cipher.decrypt(ciphertext);  // 验证 tag，失败抛错
  } catch (e) {
    throw wrapAsCryptoError(e, CryptoErrorKind.TAG_VERIFICATION_FAILED, "元数据标签校验失败（密码错误或数据被篡改）");
  }
  zeroize(fileKey);

  const dec = new TextDecoder();

  let meta: PhotoMeta;
  try {
    meta = JSON.parse(dec.decode(plaintext)) as PhotoMeta;
  } catch (e) {
    throw formatCorrupted("解密后的元数据 JSON 解析失败", e);
  }
  return meta;
}

/* ------------------------------------------------------------------ *
 * 数据块加密/解密                                                     *
 * ------------------------------------------------------------------ */

/** 构造块 AD: "VERTHYSPHOTO_CHUNK_v1" || seq(4) || total(4) || fileHash(32) */
function buildChunkAD(seq: number, total: number, fileHashBytes: Uint8Array): Uint8Array {
  const ad = new Uint8Array(CHUNK_AD_PREFIX.length + SEQ_LEN + TOTAL_LEN + FILE_HASH_LEN);
  ad.set(CHUNK_AD_PREFIX, 0);
  const view = new DataView(ad.buffer);
  view.setUint32(CHUNK_AD_PREFIX.length, seq, false);     // 大端
  view.setUint32(CHUNK_AD_PREFIX.length + SEQ_LEN, total, false);
  ad.set(fileHashBytes, CHUNK_AD_PREFIX.length + SEQ_LEN + TOTAL_LEN);
  return ad;
}

/**
 * 加密单个数据块
 * 返回组合后的 Uint8Array: salt(16) | seq(4) | total(4) | nonce(24) | ciphertext+tag
 *
 * @param saltOverride 指定文件级盐：同一文件的多块复用同一盐可使读取侧只派生一次
 *   （派生结果按盐缓存）；不传则每块独立随机盐（旧行为，读取侧逐块派生）。
 *   盐随块携带，布局不变，两种形态并存可解。
 */
export async function encryptChunk(
  plaintext: Uint8Array,
  password: string,
  seq: number,
  total: number,
  fileHashHex: string,
  saltOverride?: Uint8Array,
): Promise<Uint8Array> {
  if (!password || password.length === 0) {
    throw invalidInput("密码不能为空");
  }
  if (!plaintext || plaintext.length === 0) {
    throw invalidInput("待加密数据块不能为空");
  }
  if (!isValidHex(fileHashHex)) {
    throw invalidInput(`文件哈希 hex 非法: 长度=${fileHashHex?.length ?? 0}`);
  }
  if (fileHashHex.length !== FILE_HASH_LEN * 2) {
    throw invalidInput(`文件哈希长度不符（期望 ${FILE_HASH_LEN * 2} 字符，实际 ${fileHashHex.length}）`);
  }
  if (!Number.isInteger(seq) || seq < 0) {
    throw invalidInput(`块序号非法: ${seq}`);
  }
  if (!Number.isInteger(total) || total <= 0) {
    throw invalidInput(`总块数非法: ${total}`);
  }

  const salt = saltOverride ?? crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const fileKey = await deriveFileKeyCached(password, salt);

  // 文件哈希 hex → bytes（用于 AD 绑定，防重放）
  const fileHashBytes = hexToBytes(fileHashHex);
  const ad = buildChunkAD(seq, total, fileHashBytes);

  const cipher = xchacha20poly1305(fileKey, nonce, ad);
  const ciphertext = cipher.encrypt(plaintext);  // 含 tag

  // 组合: salt(16) | seq(4) | total(4) | nonce(24) | ciphertext+tag
  const combined = new Uint8Array(SALT_LEN + SEQ_LEN + TOTAL_LEN + NONCE_LEN + ciphertext.length);
  combined.set(salt, 0);
  const view = new DataView(combined.buffer);
  view.setUint32(SALT_LEN, seq, false);
  view.setUint32(SALT_LEN + SEQ_LEN, total, false);
  combined.set(nonce, SALT_LEN + SEQ_LEN + TOTAL_LEN);
  combined.set(ciphertext, SALT_LEN + SEQ_LEN + TOTAL_LEN + NONCE_LEN);

  zeroize(fileKey);
  zeroize(ad);
  return combined;
}

/** 解密单个数据块，返回明文 Uint8Array */
export async function decryptChunk(
  combinedB64: string,
  password: string,
  fileHashHex: string
): Promise<{ plaintext: Uint8Array; seq: number; total: number }> {
  if (!password || password.length === 0) {
    throw invalidInput("密码不能为空");
  }
  if (!combinedB64 || combinedB64.length === 0) {
    throw invalidInput("密文 base64 不能为空");
  }
  if (!isValidHex(fileHashHex)) {
    throw invalidInput(`文件哈希 hex 非法: 长度=${fileHashHex?.length ?? 0}`);
  }
  if (fileHashHex.length !== FILE_HASH_LEN * 2) {
    throw invalidInput(`文件哈希长度不符（期望 ${FILE_HASH_LEN * 2} 字符，实际 ${fileHashHex.length}）`);
  }

  const combined = base64ToBytes(combinedB64);
  const minLen = SALT_LEN + SEQ_LEN + TOTAL_LEN + NONCE_LEN;
  if (combined.length < minLen) {
    throw formatCorrupted(`数据块密文过短（${combined.length} < ${minLen}）`);
  }

  const salt = combined.slice(0, SALT_LEN);
  const view = new DataView(combined.buffer, combined.byteOffset);
  const seq = view.getUint32(SALT_LEN, false);
  const total = view.getUint32(SALT_LEN + SEQ_LEN, false);
  const nonce = combined.slice(SALT_LEN + SEQ_LEN + TOTAL_LEN, SALT_LEN + SEQ_LEN + TOTAL_LEN + NONCE_LEN);
  const ciphertext = combined.slice(SALT_LEN + SEQ_LEN + TOTAL_LEN + NONCE_LEN);

  const fileKey = await deriveFileKeyCached(password, salt);

  const fileHashBytes = hexToBytes(fileHashHex);
  const ad = buildChunkAD(seq, total, fileHashBytes);

  const cipher = xchacha20poly1305(fileKey, nonce, ad);
  let plaintext: Uint8Array;
  try {
    plaintext = cipher.decrypt(ciphertext);  // 验证 tag + 序号
  } catch (e) {
    throw wrapAsCryptoError(e, CryptoErrorKind.TAG_VERIFICATION_FAILED, "数据块标签校验失败（密码错误、哈希不匹配或数据被篡改）");
  }

  zeroize(fileKey);
  zeroize(ad);
  return { plaintext, seq, total };
}

/* ------------------------------------------------------------------ *
 * 索引瘦身布局原语                                                     *
 *                                                                    *
 * 与既有布局并存：既有布局每条记录自包含（索引携带缩略图、块携带 salt    *
 * 与序号）；本布局把缩略图拆为独立记录、随机文件密钥以包裹态存入索引，   *
 * 块密文只保留 nonce 与密文。读取侧按索引内的布局标记分流。              *
 *                                                                    *
 * 密钥层级：fileSalt(16) → wrapKey（PBKDF2+HKDF，按盐缓存）→           *
 *   包裹随机 fileKey｜缩略图用 wrapKey、块用 fileKey；索引密文头部复用   *
 *   同一 fileSalt，使一次派生同时覆盖索引、缩略图与密钥解封。            *
 * ------------------------------------------------------------------ */

/** 索引瘦身布局的文件级密钥组 */
export interface SlimFileKeys {
  /** 文件盐（索引密文头部与包裹密钥共用） */
  fileSalt: Uint8Array;
  /** 随机文件密钥（块级 AEAD 直接使用；调用方用毕必须清零） */
  fileKey: Uint8Array;
  /** 包裹态文件密钥 base64（存入索引 JSON，非机密，可随记录长期保存） */
  wrappedFileKey: string;
}

/** 缩略图 AD：标识文本 + 文件哈希（绑定缩略图归属，防跨照片换用） */
function buildThumbAD(fileHashBytes: Uint8Array): Uint8Array {
  return buildFileBoundAD(THUMB_AD, fileHashBytes);
}

/** 块集 AD：标识文本 + 文件哈希（绑定块集归属，防跨照片换用） */
function buildChunkSetAD(fileHashBytes: Uint8Array): Uint8Array {
  return buildFileBoundAD(CHUNK_SET_AD, fileHashBytes);
}

/** 文件绑定 AD 构造：标识文本 + 文件哈希（缩略图 / 块集共用） */
function buildFileBoundAD(prefix: Uint8Array, fileHashBytes: Uint8Array): Uint8Array {
  const ad = new Uint8Array(prefix.length + FILE_HASH_LEN);
  ad.set(prefix, 0);
  ad.set(fileHashBytes, prefix.length);
  return ad;
}

/** 校验文件哈希 hex（长度与字符集），返回字节形式；非法即抛错 */
function requireFileHashBytes(fileHashHex: string): Uint8Array {
  if (!isValidHex(fileHashHex) || fileHashHex.length !== FILE_HASH_LEN * 2) {
    throw invalidInput(`文件哈希 hex 非法: 长度=${fileHashHex?.length ?? 0}`);
  }
  return hexToBytes(fileHashHex);
}

/**
 * 用包裹密钥加密记录载荷（缩略图 / 块集共用）：nonce(24) ‖ 密文+tag。
 *
 * 用包裹密钥而非块级文件密钥：这些记录在读取侧与索引共用同一文件盐，
 * 解封它们的密钥即索引解密已派生的同一把密钥（派生命中缓存，零额外 PBKDF2）。
 */
async function sealWithWrapKey(
  payload: Uint8Array,
  password: string,
  fileSalt: Uint8Array,
  ad: Uint8Array,
): Promise<Uint8Array> {
  if (!payload || payload.length === 0) {
    throw invalidInput("记录载荷不能为空");
  }
  const wrapKey = await deriveFileKeyCached(password, fileSalt);
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const ciphertext = xchacha20poly1305(wrapKey, nonce, ad).encrypt(payload);
  zeroize(wrapKey);

  const out = new Uint8Array(NONCE_LEN + ciphertext.length);
  out.set(nonce, 0);
  out.set(ciphertext, NONCE_LEN);
  return out;
}

/**
 * 解封记录载荷（缩略图 / 块集共用）：盐取自包裹态文件密钥（与索引同盐）。
 *
 * @param label 失败时的定位文案（区分缩略图 / 块集，便于排查）
 */
async function openWithWrapKey(
  combinedB64: string,
  password: string,
  wrappedFileKeyB64: string,
  ad: Uint8Array,
  label: string,
): Promise<Uint8Array> {
  if (!combinedB64 || combinedB64.length === 0) {
    throw invalidInput(`${label}密文不能为空`);
  }
  const fileSalt = extractSlimFileSalt(wrappedFileKeyB64);
  const combined = base64ToBytes(combinedB64);
  if (combined.length < NONCE_LEN + TAG_LEN) {
    throw formatCorrupted(`${label}密文过短（${combined.length}）`);
  }
  const nonce = combined.slice(0, NONCE_LEN);
  const ciphertext = combined.slice(NONCE_LEN);

  const wrapKey = await deriveFileKeyCached(password, fileSalt);
  try {
    const plaintext = xchacha20poly1305(wrapKey, nonce, ad).decrypt(ciphertext);
    zeroize(wrapKey);
    return plaintext;
  } catch (e) {
    zeroize(wrapKey);
    throw wrapAsCryptoError(
      e, CryptoErrorKind.TAG_VERIFICATION_FAILED,
      `${label}标签校验失败（密码不匹配或数据被篡改）`,
    );
  }
}

/**
 * 创建索引瘦身布局的文件级密钥组（随机盐 + 随机文件密钥 + 包裹态密钥）。
 *
 * @param password 照片模块独立密钥
 * @returns 文件盐、随机文件密钥与包裹态文件密钥（base64）
 */
export async function createSlimFileKeys(password: string): Promise<SlimFileKeys> {
  if (!password || password.length === 0) {
    throw invalidInput("密码不能为空");
  }
  const fileSalt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const wrapKey = await deriveFileKeyCached(password, fileSalt);
  const fileKey = crypto.getRandomValues(new Uint8Array(KEY_LEN));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const cipher = xchacha20poly1305(wrapKey, nonce, FILE_KEY_WRAP_AD);
  const wrapped = cipher.encrypt(fileKey);

  const combined = new Uint8Array(SALT_LEN + NONCE_LEN + wrapped.length);
  combined.set(fileSalt, 0);
  combined.set(nonce, SALT_LEN);
  combined.set(wrapped, SALT_LEN + NONCE_LEN);

  zeroize(wrapKey);
  return { fileSalt, fileKey, wrappedFileKey: bytesToBase64(combined) };
}

/**
 * 取出包裹态文件密钥内的文件盐（结构校验后返回盐副本）。
 *
 * 用途：写入侧在加密索引前需要知道盐（索引密文盐必须与包裹态密钥同盐，
 * 读取侧一次派生即可覆盖索引与缩略图）；此处只解析盐，不接触密钥材料。
 */
export function extractSlimFileSalt(wrappedFileKeyB64: string): Uint8Array {
  if (!wrappedFileKeyB64) {
    throw invalidInput("包裹态文件密钥不能为空");
  }
  const combined = base64ToBytes(wrappedFileKeyB64);
  if (combined.length < SALT_LEN + NONCE_LEN + TAG_LEN) {
    throw formatCorrupted(`包裹态文件密钥过短（${combined.length}）`);
  }
  return combined.slice(0, SALT_LEN);
}

/**
 * 解封包裹态文件密钥，返回块级文件密钥。
 *
 * @param wrappedFileKeyB64 包裹态文件密钥 base64（内含盐与 nonce）
 * @param password 照片模块独立密钥
 * @returns 随机文件密钥（调用方用毕必须清零）
 * @throws CryptoError(TAG_VERIFICATION_FAILED) 密码不匹配或包裹被篡改
 */
export async function unwrapSlimFileKey(
  wrappedFileKeyB64: string,
  password: string,
): Promise<Uint8Array> {
  const fileSalt = extractSlimFileSalt(wrappedFileKeyB64);
  const combined = base64ToBytes(wrappedFileKeyB64);
  const nonce = combined.slice(SALT_LEN, SALT_LEN + NONCE_LEN);
  const ciphertext = combined.slice(SALT_LEN + NONCE_LEN);

  const wrapKey = await deriveFileKeyCached(password, fileSalt);
  const cipher = xchacha20poly1305(wrapKey, nonce, FILE_KEY_WRAP_AD);
  let fileKey: Uint8Array;
  try {
    fileKey = cipher.decrypt(ciphertext);
  } catch (e) {
    zeroize(wrapKey);
    throw wrapAsCryptoError(
      e, CryptoErrorKind.TAG_VERIFICATION_FAILED,
      "文件密钥解封失败（密码不匹配或数据被篡改）",
    );
  }
  zeroize(wrapKey);
  if (fileKey.length !== KEY_LEN) {
    zeroize(fileKey);
    throw formatCorrupted(`文件密钥长度不符（${fileKey.length} ≠ ${KEY_LEN}）`);
  }
  return fileKey;
}

/**
 * 用指定文件盐加密索引（布局二）。
 *
 * 密文布局与既有索引一致（salt|nonce|密文），区别仅在盐由调用方给定：
 * 索引盐须与包裹态密钥同盐，读取侧一次派生即同时得到缩略图与密钥解封所需
 * 的密钥材料（同一 wrapKey），无需为缩略图重复派生。
 */
export async function encryptSlimMeta(
  meta: PhotoMeta,
  password: string,
  fileSalt: Uint8Array,
): Promise<string> {
  if (!password || password.length === 0) {
    throw invalidInput("密码不能为空");
  }
  if (!meta || typeof meta !== "object") {
    throw invalidInput("元数据对象非法");
  }
  if (!fileSalt || fileSalt.length !== SALT_LEN) {
    throw invalidInput(`文件盐长度不符（${fileSalt?.length ?? 0} ≠ ${SALT_LEN}）`);
  }
  if (!meta.wrappedFileKey) {
    throw invalidInput("索引瘦身布局的索引必须携带包裹态文件密钥");
  }
  // 预算边界（生成常量断言其密文可被扫描缓存承载）：索引超出预算即
  // 列表缓存失效、逐张回退 IPC，属结构性退化，此处前置拒绝而非静默写入
  const plaintext = new TextEncoder().encode(JSON.stringify(meta));
  if (plaintext.length > PHOTO_INDEX_MAX_BYTES) {
    throw invalidInput(
      `索引明文 ${plaintext.length} 字节超出预算 ${PHOTO_INDEX_MAX_BYTES} 字节`,
    );
  }

  const wrapKey = await deriveFileKeyCached(password, fileSalt);
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const cipher = xchacha20poly1305(wrapKey, nonce, META_AD);
  const ciphertext = cipher.encrypt(plaintext);

  const combined = new Uint8Array(SALT_LEN + NONCE_LEN + ciphertext.length);
  combined.set(fileSalt, 0);
  combined.set(nonce, SALT_LEN);
  combined.set(ciphertext, SALT_LEN + NONCE_LEN);

  zeroize(wrapKey);
  return bytesToBase64(combined);
}

/**
 * 加密单个负载块（布局二）：nonce(24) | 密文+tag，AD 绑定 seq/total/fileHash。
 *
 * 与既有布局共用同一 AD 构造，故块顺序与归属校验语义完全一致；
 * 差异仅在块密文不再携带 salt/seq/total（fileKey 由索引内包裹态密钥解封）。
 */
export function encryptSlimChunk(
  plaintext: Uint8Array,
  fileKey: Uint8Array,
  seq: number,
  total: number,
  fileHashHex: string,
): Uint8Array {
  if (!fileKey || fileKey.length !== KEY_LEN) {
    throw invalidInput(`文件密钥长度不符（${fileKey?.length ?? 0} ≠ ${KEY_LEN}）`);
  }
  if (!plaintext || plaintext.length === 0) {
    throw invalidInput("待加密数据块不能为空");
  }
  if (!isValidHex(fileHashHex) || fileHashHex.length !== FILE_HASH_LEN * 2) {
    throw invalidInput(`文件哈希 hex 非法: 长度=${fileHashHex?.length ?? 0}`);
  }
  if (!Number.isInteger(seq) || seq < 0 || !Number.isInteger(total) || total <= 0) {
    throw invalidInput(`块序号/总数非法: seq=${seq} total=${total}`);
  }

  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const ad = buildChunkAD(seq, total, hexToBytes(fileHashHex));
  const ciphertext = xchacha20poly1305(fileKey, nonce, ad).encrypt(plaintext);
  zeroize(ad);

  const out = new Uint8Array(NONCE_LEN + ciphertext.length);
  out.set(nonce, 0);
  out.set(ciphertext, NONCE_LEN);
  return out;
}

/**
 * 解密单个负载块（布局二）。
 *
 * 序号与总数由调用方按块在列表中的位置给出（密文不携带），与 AD 绑定值
 * 一致才能通过认证：错位、重复或跨文件拼接都会被拒绝。
 */
export function decryptSlimChunk(
  combinedB64: string,
  fileKey: Uint8Array,
  fileHashHex: string,
  seq: number,
  total: number,
): Uint8Array {
  if (!fileKey || fileKey.length !== KEY_LEN) {
    throw invalidInput(`文件密钥长度不符（${fileKey?.length ?? 0} ≠ ${KEY_LEN}）`);
  }
  if (!combinedB64 || combinedB64.length === 0) {
    throw invalidInput("密文 base64 不能为空");
  }
  if (!isValidHex(fileHashHex) || fileHashHex.length !== FILE_HASH_LEN * 2) {
    throw invalidInput(`文件哈希 hex 非法: 长度=${fileHashHex?.length ?? 0}`);
  }
  if (!Number.isInteger(seq) || seq < 0 || !Number.isInteger(total) || total <= 0) {
    throw invalidInput(`块序号/总数非法: seq=${seq} total=${total}`);
  }

  const combined = base64ToBytes(combinedB64);
  if (combined.length < NONCE_LEN + TAG_LEN) {
    throw formatCorrupted(`数据块密文过短（${combined.length}）`);
  }
  const nonce = combined.slice(0, NONCE_LEN);
  const ciphertext = combined.slice(NONCE_LEN);

  const ad = buildChunkAD(seq, total, hexToBytes(fileHashHex));
  try {
    const plaintext = xchacha20poly1305(fileKey, nonce, ad).decrypt(ciphertext);
    zeroize(ad);
    return plaintext;
  } catch (e) {
    zeroize(ad);
    throw wrapAsCryptoError(
      e, CryptoErrorKind.TAG_VERIFICATION_FAILED,
      `第 ${seq + 1}/${total} 块标签校验失败（文件密钥不匹配或数据被篡改）`,
    );
  }
}

/**
 * 加密缩略图记录载荷（布局二）：nonce(24) | 密文+tag，AD 绑定文件哈希。
 *
 * 用包裹密钥（而非块级文件密钥）加密：缩略图读取（列表路径）只需索引解密
 * 已派生的同一把密钥，无需为缩略图额外解封文件密钥。
 */
export async function encryptSlimThumb(
  rawThumb: Uint8Array,
  password: string,
  fileSalt: Uint8Array,
  fileHashHex: string,
): Promise<Uint8Array> {
  const ad = buildThumbAD(requireFileHashBytes(fileHashHex));
  const out = await sealWithWrapKey(rawThumb, password, fileSalt, ad);
  zeroize(ad);
  return out;
}

/**
 * 解密缩略图记录载荷（布局二），返回原始缩略图字节（JPEG）。
 *
 * 文件盐从包裹态文件密钥中取出（与索引密文同盐）→ 派生命中缓存时，
 * 索引解密后的缩略图解密不再产生第二次密钥派生。
 */
export async function decryptSlimThumb(
  combinedB64: string,
  password: string,
  wrappedFileKeyB64: string,
  fileHashHex: string,
): Promise<Uint8Array> {
  const ad = buildThumbAD(requireFileHashBytes(fileHashHex));
  try {
    return await openWithWrapKey(combinedB64, password, wrappedFileKeyB64, ad, "缩略图");
  } finally {
    zeroize(ad);
  }
}

/** 块集记录载荷（解密后）：逐块记录 ID 与逐块密文哈希，按序一一对应 */
export type { SlimChunkSet } from "../types/crypto";

/**
 * 加密块集记录载荷（布局二）：nonce(24) | 密文+tag，AD 绑定文件哈希。
 *
 * 逐块引用与逐块哈希随分块数线性增长，放入本记录后索引体积与照片大小解耦；
 * 加密规格与缩略图一致（同一包裹密钥、同一文件盐），读取侧共用一次派生。
 */
export async function encryptSlimChunkSet(
  set: SlimChunkSet,
  password: string,
  fileSalt: Uint8Array,
  fileHashHex: string,
): Promise<Uint8Array> {
  if (!set || !Array.isArray(set.ids) || !Array.isArray(set.hashes)) {
    throw invalidInput("块集结构非法");
  }
  if (set.ids.length === 0 || set.ids.length !== set.hashes.length) {
    throw invalidInput(
      `块集项数不一致（id=${set.ids.length}，hash=${set.hashes.length}）`,
    );
  }
  for (const id of set.ids) {
    if (!Number.isInteger(id) || id <= 0) {
      throw invalidInput(`块集包含非法记录 ID: ${id}`);
    }
  }
  for (const h of set.hashes) {
    if (!isValidHex(h)) {
      throw invalidInput("块集包含非法块哈希");
    }
  }

  const ad = buildChunkSetAD(requireFileHashBytes(fileHashHex));
  const payload = new TextEncoder().encode(JSON.stringify(set));
  try {
    return await sealWithWrapKey(payload, password, fileSalt, ad);
  } finally {
    zeroize(ad);
    zeroize(payload);
  }
}

/**
 * 解密块集记录载荷（布局二），并做结构校验（id/hash 等长、id 为正整数）。
 *
 * 结构来自本机写入，但读取侧仍按外部输入对待：任何不满足不变式的载荷
 * 直接判损坏，避免把错位的块序号带入后续 AD 校验造成误判。
 */
export async function decryptSlimChunkSet(
  combinedB64: string,
  password: string,
  wrappedFileKeyB64: string,
  fileHashHex: string,
): Promise<SlimChunkSet> {
  const ad = buildChunkSetAD(requireFileHashBytes(fileHashHex));
  let plaintext: Uint8Array;
  try {
    plaintext = await openWithWrapKey(combinedB64, password, wrappedFileKeyB64, ad, "块集");
  } finally {
    zeroize(ad);
  }
  try {
    const raw = JSON.parse(new TextDecoder().decode(plaintext)) as SlimChunkSet;
    if (!raw || !Array.isArray(raw.ids) || !Array.isArray(raw.hashes)) {
      throw formatCorrupted("块集结构非法");
    }
    if (raw.ids.length === 0 || raw.ids.length !== raw.hashes.length) {
      throw formatCorrupted(
        `块集项数不一致（id=${raw.ids.length}，hash=${raw.hashes.length}）`,
      );
    }
    for (const id of raw.ids) {
      if (!Number.isInteger(id) || id <= 0) {
        throw formatCorrupted(`块集包含非法记录 ID: ${id}`);
      }
    }
    for (const h of raw.hashes) {
      if (!isValidHex(h)) {
        throw formatCorrupted("块集包含非法块哈希");
      }
    }
    return raw;
  } finally {
    zeroize(plaintext);
  }
}

/* ------------------------------------------------------------------ *
 * .venc v2 容器（自描述信封 + 内容密钥封装 + 逐帧 AEAD）              *
 *                                                                    *
 * 布局：                                                              *
 *   [Outer Header 42B 明文]：magic(4) version(2) flags(2) kdf_id(2)   *
 *                            iterations(4) salt(16) iv(12)           *
 *   [Wrapped Content Key 48B]：AES-256-GCM 加密 content_key(32)，     *
 *      密钥 = PBKDF2(token, salt, iterations)，nonce = iv，           *
 *      AD = Outer Header 全字节（头部被篡改即解封失败）               *
 *   [Frame]*：帧头 [type(1) seq(4 大端) len(4 大端)] +                *
 *             [nonce(24)] + [ciphertext+tag]                          *
 *      帧密钥 = content_key（XChaCha20-Poly1305），                   *
 *      帧 AD = type|seq|len（大端）                                    *
 *   [Trailer 帧]：frame_count(u32) + body_bytes(u64) 交叉校验         *
 *                                                                    *
 * 帧类型：1=轻量头（明文 JSON 结构，经内容密钥逐帧加密）、             *
 *         2=加密块负载（保持模块密钥加密态原样搬运）、                 *
 *         3=尾部校验帧                                                *
 *                                                                    *
 * KDF 参数自描述：iterations 写入头部，解密端按读取值执行派生，       *
 * 提升迭代次数不会使历史文件永久不可解。                               *
 * ------------------------------------------------------------------ */

/** 把本地存储元数据投影为容器轻量头（不携带内联块负载） */
export function toLightMeta(local: PhotoMeta): LightMeta {
  return {
    name: local.name,
    mime: local.mime,
    size: local.size,
    thumbB64: local.thumbB64,
    fileHash: local.fileHash,
    createdAt: local.createdAt,
    chunkCount: local.chunkDataB64?.length ?? 0,
    chunkHashes: local.chunkHashes ?? [],
    // 来源布局与包裹态密钥随容器携带：接收端按同一布局分流；
    // 既有布局两项为空（JSON 序列化时被省略，不改变既有容器结构）
    fmt: local.fmt,
    wrappedFileKey: local.wrappedFileKey,
  };
}

/** 计算加密块 base64 数组的逐块 BLAKE3 hex（容器打包与完整性校验用） */
export function computeChunkHashesForB64(chunkB64List: string[]): string[] {
  return chunkB64List.map((cb) =>
    bytesToHex(blake3(base64ToBytes(cb), { dkLen: FILE_HASH_LEN })),
  );
}

/** 帧头 / 帧 AD 编码：type(1) + seq(4 大端) + len(4 大端)，两者同型 */
function encodeFrameHeader(type: number, seq: number, len: number): Uint8Array {
  const buf = new Uint8Array(VENC_FRAME_HEADER_BYTES);
  buf[0] = type;
  const view = new DataView(buf.buffer);
  view.setUint32(1, seq, false);
  view.setUint32(5, len, false);
  return buf;
}

/** 逐帧加密：帧头 + nonce + ciphertext+tag 拼装，AD 绑定 type/seq/len */
function encryptFrame(
  contentKey: Uint8Array,
  type: number,
  seq: number,
  payload: Uint8Array,
): Uint8Array {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const ad = encodeFrameHeader(type, seq, payload.length);
  const cipher = xchacha20poly1305(contentKey, nonce, ad);
  const ct = cipher.encrypt(payload); // 末尾含 16B tag

  const out = new Uint8Array(VENC_FRAME_HEADER_BYTES + NONCE_LEN + ct.length);
  out.set(encodeFrameHeader(type, seq, payload.length), 0);
  out.set(nonce, VENC_FRAME_HEADER_BYTES);
  out.set(ct, VENC_FRAME_HEADER_BYTES + NONCE_LEN);
  zeroize(ad);
  return out;
}

/** 容器照片输入的结构前置校验（打包侧防御，避免容量字段自相矛盾或发出即损坏） */
function assertVencPhotoShape(photo: VencPhotoSpecV2): void {
  const lm = photo.lightMeta;
  if (!lm || !photo.chunkBytes) {
    throw invalidInput("照片容器数据字段缺失");
  }
  if (lm.chunkCount !== photo.chunkBytes.length || lm.chunkHashes.length !== photo.chunkBytes.length) {
    throw invalidInput(
      `照片 "${lm.name}" 块数字段不一致: chunkCount=${lm.chunkCount}, ` +
        `chunkHashes=${lm.chunkHashes.length}, 实际块=${photo.chunkBytes.length}`,
    );
  }
  // 打包前逐块校验哈希声明：写入容器的 chunkHashes 必须是负载的真实摘要，
  // 否则接收端必然拒绝——fail-fast 避免产出「注定无法解析」的文件
  for (let i = 0; i < photo.chunkBytes.length; i++) {
    const actual = bytesToHex(blake3(photo.chunkBytes[i], { dkLen: FILE_HASH_LEN }));
    if (actual !== lm.chunkHashes[i]) {
      throw invalidInput(
        `照片 "${lm.name}" 第 ${i + 1} 块哈希声明不符: ` +
          `期望 ${lm.chunkHashes[i]}，实际 ${actual}`,
      );
    }
  }
}

/** 轻量头形状校验（解包侧防御，结构来自外部输入） */
function assertLightMetaShape(lm: LightMeta): void {
  if (typeof lm !== "object" || lm === null) {
    throw formatCorrupted("轻量头结构非法");
  }
  if (typeof lm.name !== "string" || typeof lm.mime !== "string" || typeof lm.thumbB64 !== "string") {
    throw formatCorrupted("轻量头字段类型非法");
  }
  if (!Number.isFinite(lm.size) || lm.size < 0 || lm.size > PARSE_MAX_CONTAINER_BYTES) {
    throw formatCorrupted(`轻量头 size 非法: ${lm.size}`);
  }
  if (!Number.isInteger(lm.chunkCount) || lm.chunkCount < 0 || lm.chunkCount > PARSE_MAX_FRAME_COUNT) {
    throw formatCorrupted(`轻量头 chunkCount 非法: ${lm.chunkCount}`);
  }
  if (!Array.isArray(lm.chunkHashes) || lm.chunkHashes.length !== lm.chunkCount) {
    throw formatCorrupted("轻量头 chunkHashes 数组长度与 chunkCount 不一致");
  }
  if (!isValidHex(lm.fileHash) || lm.fileHash.length !== FILE_HASH_LEN * 2) {
    throw formatCorrupted("轻量头 fileHash 非法");
  }
  // 布局标记与包裹态密钥必须成对出现：索引瘦身布局的块密文只能按包裹密钥
  // 解封，缺失即无法导入，此处前置拒绝（避免产出"注定无法解析"的中间态）
  if (lm.fmt === PHOTO_FMT_SLIM) {
    if (typeof lm.wrappedFileKey !== "string" || lm.wrappedFileKey.length === 0) {
      throw formatCorrupted("轻量头声明索引瘦身布局但缺少包裹态文件密钥");
    }
  } else if (lm.wrappedFileKey !== undefined) {
    throw formatCorrupted("轻量头携带包裹态文件密钥但未声明索引瘦身布局");
  }
}

/** 逐块完整性校验：块帧负载的 BLAKE3 与轻量头声明的 chunkHashes 逐一比对 */
function assertChunkHashesMatched(photo: { lightMeta: LightMeta; chunkBytes: Uint8Array[] }): void {
  for (let i = 0; i < photo.chunkBytes.length; i++) {
    const actual = bytesToHex(blake3(photo.chunkBytes[i], { dkLen: FILE_HASH_LEN }));
    if (actual !== photo.lightMeta.chunkHashes[i]) {
      throw formatCorrupted(
        `照片 "${photo.lightMeta.name}" 第 ${i + 1} 块哈希不符: ` +
          `期望 ${photo.lightMeta.chunkHashes[i]}，实际 ${actual}`,
      );
    }
  }
}

/**
 * 将照片容器数据打包为 .venc v2 加密文件。
 *
 * 收集全部输出段后一次性拼接返回；大文件单文件导出应改用
 * {@link packVencV2Streamed} 流式产出以压低内存峰值。
 *
 * @param photos 照片容器数据（轻量头 + 加密块字节）
 * @param token 导出令牌（外层内容密钥封装的凭据）
 * @returns .venc v2 完整字节（头部 + 封装密钥 + 帧序列 + 尾部校验帧）
 */
export async function packVencV2(
  photos: VencPhotoSpecV2[],
  token: string,
): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  await packVencV2Internal(photos, token, async (part) => {
    parts.push(part);
  });
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/**
 * 将照片容器数据流式打包为 .venc v2 加密文件，逐段交给写入回调。
 *
 * 与 {@link packVencV2} 共享同一打包核心：不缓存帧序列，每产生一段
 * （首段为头部 + 封装密钥，其后为单个加密帧，末尾为尾部校验帧）即
 * `await emit(part)`，由调用方决定落盘 / 拼接策略；回调返回 Promise
 * 以支持背压（如流式追加落盘）。回调抛错即中止打包并向上传播。
 *
 * @param photos 照片容器数据（轻量头 + 加密块字节）
 * @param token 导出令牌（外层内容密钥封装的凭据）
 * @param emit 分段写出回调（按容器字节顺序调用）
 */
export async function packVencV2Streamed(
  photos: VencPhotoSpecV2[],
  token: string,
  emit: (part: Uint8Array) => Promise<void>,
): Promise<void> {
  await packVencV2Internal(photos, token, emit);
}

/**
 * 预估 .venc v2 容器总字节数（打包前进度分母）。
 *
 * 逐段合计：容器前缀 + 每个轻量头帧 / 块帧（帧头 + nonce + 负载 + tag）
 * + 尾部校验帧，与打包核心的实际产出逐字节一致，误差仅在深层异常时
 * 出现（异常路径进度不生效）。供流式导出进度换算使用。
 */
export function estimateVencTotalBytes(photos: VencPhotoSpecV2[]): number {
  const frameOverhead = VENC_FRAME_HEADER_BYTES + NONCE_LEN + TAG_LEN;
  let total = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
  for (const photo of photos) {
    const lmBytes = new TextEncoder().encode(JSON.stringify(photo.lightMeta)).length;
    total += frameOverhead + lmBytes;
    for (const chunk of photo.chunkBytes) {
      total += frameOverhead + chunk.length;
    }
  }
  return total + frameOverhead + VENC_TRAILER_PAYLOAD_BYTES;
}

/**
 * 打包核心（packVencV2 / packVencV2Streamed 共用）：外层头部 + 内容密钥
 * 封装 + 逐帧 AEAD + 尾部校验帧，全程逐段向 `emit` 产出，不缓存帧序列。
 */
async function packVencV2Internal(
  photos: VencPhotoSpecV2[],
  token: string,
  emit: (part: Uint8Array) => Promise<void>,
): Promise<void> {
  if (!photos || photos.length === 0) {
    throw invalidInput("照片数据列表不能为空");
  }
  if (!token || token.length === 0) {
    throw invalidInput("加密令牌不能为空");
  }
  for (const photo of photos) assertVencPhotoShape(photo);

  // 1. 外层头部（明文，42B）
  const header = new Uint8Array(VENC_OUTER_HEADER_BYTES);
  header.set(VENC_MAGIC, 0);
  const hv = new DataView(header.buffer);
  hv.setUint16(4, VENC_VERSION, false);
  hv.setUint16(6, 0, false); // flags 保留
  hv.setUint16(8, VENC_KDF_ID_PBKDF2_SHA256, false);
  hv.setUint32(10, PBKDF2_ITER, false);
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  header.set(salt, 14);
  header.set(iv, 30);

  // 2. 随机内容密钥（帧负载加密钥，仅封装后落盘）
  const contentKey = crypto.getRandomValues(new Uint8Array(KEY_LEN));

  // 3. 封装内容密钥：AES-256-GCM，AD 绑定完整头部字节
  const kebBits = await derivePBKDF2Bits(token, salt);
  const kek = await crypto.subtle.importKey(
    "raw", kebBits, { name: "AES-GCM", length: 256 }, false, ["encrypt"],
  );
  let wrappedBuf: ArrayBuffer;
  try {
    wrappedBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: toArrayBuffer(header) },
      kek,
      toArrayBuffer(contentKey),
    );
  } catch (e) {
    zeroize(contentKey);
    throw wrapAsCryptoError(e, CryptoErrorKind.KEY_DERIVATION_FAILED, "内容密钥封装失败");
  }

  try {
    // 首段：外层头部 + 封装密钥（容器前 90 字节，明密结合无帧头）
    const prefix = new Uint8Array(VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES);
    prefix.set(header, 0);
    prefix.set(new Uint8Array(wrappedBuf), VENC_OUTER_HEADER_BYTES);
    await emit(prefix);

    // 4. 帧序列：每张照片一个轻量头帧 + 逐块一个块帧，全局 seq 单调递增
    let seq = 0;
    let frameCount = 0;
    let bodyBytes = 0;
    for (const photo of photos) {
      const lmBytes = new TextEncoder().encode(JSON.stringify(photo.lightMeta));
      await emit(encryptFrame(contentKey, VENC_FRAME_TYPE_LIGHT_META, seq++, lmBytes));
      frameCount += 1;
      bodyBytes += lmBytes.length;
      for (const chunk of photo.chunkBytes) {
        await emit(encryptFrame(contentKey, VENC_FRAME_TYPE_CHUNK, seq++, chunk));
        frameCount += 1;
        bodyBytes += chunk.length;
      }
    }

    // 5. 尾部校验帧：frame_count(u32) + body_bytes(u64) 交叉校验
    const trailerPayload = new Uint8Array(VENC_TRAILER_PAYLOAD_BYTES);
    const tv = new DataView(trailerPayload.buffer);
    tv.setUint32(0, frameCount, false);
    tv.setBigUint64(4, BigInt(bodyBytes), false);
    await emit(encryptFrame(contentKey, VENC_FRAME_TYPE_TRAILER, seq, trailerPayload));
  } finally {
    zeroize(contentKey);
  }
}

/**
 * 解包 .venc v2 加密文件并完成全链路校验。
 *
 * 校验链（任一步失败即以分类错误拒绝，不产出部分结果）：
 *   1. 容器大小上限与最小长度；
 *   2. 魔数 / 版本 / KDF 标识 / 迭代次数（头部自描述）；
 *   3. 内容密钥解封（AEAD 标签校验，AD 绑定完整头部 → 头部篡改即失败）；
 *   4. 逐帧解析：帧序严格递增、帧类型合法、帧负载上限、标签校验；
 *   5. 尾部帧交叉校验：frame_count 与 body_bytes 与实解数据一致；
 *   6. 逐块完整性：块帧负载 BLAKE3 与轻量头 chunkHashes 逐一比对；
 *   7. 尾部无残留数据、容器内至少一张照片。
 *
 * @param encoded .venc v2 完整字节
 * @param token 导出令牌
 * @returns 照片容器数据数组（轻量头 + 加密块字节）
 */
export async function unpackVencV2(
  encoded: Uint8Array,
  token: string,
): Promise<VencPhotoSpecV2[]> {
  if (!encoded || encoded.length === 0) {
    throw formatCorrupted("venc 数据为空");
  }
  if (encoded.length > PARSE_MAX_CONTAINER_BYTES) {
    throw formatCorrupted(`容器超过大小上限（${encoded.length} > ${PARSE_MAX_CONTAINER_BYTES}）`);
  }
  const minLen = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES + VENC_FRAME_HEADER_BYTES + NONCE_LEN + 16;
  if (encoded.length < minLen) {
    throw formatCorrupted(`venc 数据过短（${encoded.length} < ${minLen}）`);
  }

  const view = new DataView(encoded.buffer, encoded.byteOffset, encoded.byteLength);

  // 1. 外层头部校验
  const magic = new TextDecoder().decode(encoded.slice(0, VENC_MAGIC.length));
  if (magic !== VENC_MAGIC_TEXT) {
    throw formatCorrupted(`venc 魔数不匹配（期望 "${VENC_MAGIC_TEXT}"，实际 "${magic}"）`);
  }
  const version = view.getUint16(4, false);
  if (version !== VENC_VERSION) {
    throw unsupportedVersion(`不支持的容器版本: ${version}（当前支持 ${VENC_VERSION}）`);
  }
  const kdfId = view.getUint16(8, false);
  if (kdfId !== VENC_KDF_ID_PBKDF2_SHA256) {
    throw unsupportedVersion(`不支持的密钥派生算法标识: ${kdfId}`);
  }
  const iterations = view.getUint32(10, false);
  if (iterations < 10_000) {
    throw formatCorrupted(`头部迭代次数非法: ${iterations}`);
  }
  const salt = encoded.slice(14, 14 + SALT_LEN);
  const iv = encoded.slice(30, 30 + 12);
  const header = encoded.slice(0, VENC_OUTER_HEADER_BYTES);

  // 2. 内容密钥解封（AD = 头部全字节）
  const kebBits = await derivePBKDF2Bits(token, salt, iterations);
  const kek = await crypto.subtle.importKey(
    "raw", kebBits, { name: "AES-GCM", length: 256 }, false, ["decrypt"],
  );
  const wrapped = encoded.slice(VENC_OUTER_HEADER_BYTES, VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES);
  let contentKey: Uint8Array;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: toArrayBuffer(header) },
      kek,
      toArrayBuffer(wrapped),
    );
    contentKey = new Uint8Array(pt);
  } catch (e) {
    throw wrapAsCryptoError(e, CryptoErrorKind.TAG_VERIFICATION_FAILED, "内容密钥解封失败（令牌错误或文件被篡改）");
  }
  if (contentKey.length !== KEY_LEN) {
    zeroize(contentKey);
    throw formatCorrupted(`内容密钥长度非法: ${contentKey.length}`);
  }

  // 3. 逐帧解析
  try {
    let offset = VENC_OUTER_HEADER_BYTES + VENC_WRAPPED_KEY_BYTES;
    const photos: { lightMeta: LightMeta; chunkBytes: Uint8Array[] }[] = [];
    let cur: { lightMeta: LightMeta; chunkBytes: Uint8Array[] } | null = null;
    let expectSeq = 0;
    let frameCount = 0;
    let bodyBytes = 0;
    let trailer: { frameCount: number; bodyBytes: number } | null = null;

    while (offset < encoded.length) {
      if (offset + VENC_FRAME_HEADER_BYTES > encoded.length) {
        throw formatCorrupted("帧头越界");
      }
      const type = encoded[offset];
      const seq = view.getUint32(offset + 1, false);
      const len = view.getUint32(offset + 5, false);
      if (type !== VENC_FRAME_TYPE_LIGHT_META && type !== VENC_FRAME_TYPE_CHUNK && type !== VENC_FRAME_TYPE_TRAILER) {
        throw formatCorrupted(`未知帧类型: ${type}`);
      }
      if (seq !== expectSeq) {
        throw formatCorrupted(`帧序号不连续: seq=${seq}，期望 ${expectSeq}`);
      }
      if (len > PARSE_MAX_FRAME_BYTES) {
        throw formatCorrupted(`帧负载超过上限: ${len}`);
      }
      const frameTotal = VENC_FRAME_HEADER_BYTES + NONCE_LEN + len + TAG_LEN;
      if (offset + frameTotal > encoded.length) {
        throw formatCorrupted(`帧负载越界（offset=${offset}, len=${len}）`);
      }
      const nonce = encoded.slice(offset + VENC_FRAME_HEADER_BYTES, offset + VENC_FRAME_HEADER_BYTES + NONCE_LEN);
      const ct = encoded.slice(offset + VENC_FRAME_HEADER_BYTES + NONCE_LEN, offset + frameTotal);
      const ad = encodeFrameHeader(type, seq, len);
      const cipher = xchacha20poly1305(contentKey, nonce, ad);
      let payload: Uint8Array;
      try {
        payload = cipher.decrypt(ct);
      } catch (e) {
        throw wrapAsCryptoError(e, CryptoErrorKind.TAG_VERIFICATION_FAILED, `帧 ${seq} 标签校验失败（数据被篡改）`);
      } finally {
        zeroize(ad);
      }
      offset += frameTotal;
      expectSeq += 1;

      if (type === VENC_FRAME_TYPE_TRAILER) {
        if (offset !== encoded.length) {
          throw formatCorrupted("尾部校验帧之后存在未识别数据");
        }
        if (payload.length < 12) {
          throw formatCorrupted("尾部校验帧负载过短");
        }
        const tv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
        trailer = {
          frameCount: tv.getUint32(0, false),
          bodyBytes: Number(tv.getBigUint64(4, false)),
        };
        break;
      }

      frameCount += 1;
      bodyBytes += payload.length;
      if (frameCount > PARSE_MAX_FRAME_COUNT) {
        throw formatCorrupted(`帧数超过上限（${frameCount} > ${PARSE_MAX_FRAME_COUNT}）`);
      }

      if (type === VENC_FRAME_TYPE_LIGHT_META) {
        if (cur) {
          // 上一张照片收尾：逐块哈希校验
          assertChunkHashesMatched(cur);
          photos.push(cur);
        }
        let lightMeta: unknown;
        try {
          lightMeta = JSON.parse(new TextDecoder().decode(payload));
        } catch (e) {
          throw formatCorrupted("轻量头 JSON 解析失败", e);
        }
        assertLightMetaShape(lightMeta as LightMeta);
        cur = { lightMeta: lightMeta as LightMeta, chunkBytes: [] };
      } else {
        if (!cur) {
          throw formatCorrupted("块帧先于轻量头出现");
        }
        cur.chunkBytes.push(payload);
      }
    }

    if (!trailer) {
      throw formatCorrupted("缺少尾部校验帧");
    }
    if (cur) {
      assertChunkHashesMatched(cur);
      photos.push(cur);
    }
    if (photos.length === 0) {
      throw formatCorrupted("容器内无照片");
    }
    // 尾部交叉校验：实解帧数与字节数必须与 trailer 声明一致
    if (trailer.frameCount !== frameCount) {
      throw formatCorrupted(`尾部帧数校验不符: 声明 ${trailer.frameCount}，实际 ${frameCount}`);
    }
    if (trailer.bodyBytes !== bodyBytes) {
      throw formatCorrupted(`尾部字节数校验不符: 声明 ${trailer.bodyBytes}，实际 ${bodyBytes}`);
    }
    return photos.map((p) => ({ lightMeta: p.lightMeta, chunkBytes: p.chunkBytes }));
  } finally {
    zeroize(contentKey);
  }
}

/** 生成随机令牌（默认 32 bytes hex） */
export function generateRandomToken(bytes: number = 32): string {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw invalidInput(`令牌字节数非法: ${bytes}`);
  }
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}

/* ------------------------------------------------------------------ *
 * 独立密码加密层（per-field AES-GCM）                                  *
 *                                                                    *
 * 与 DLL 的加密库主加密相互独立：                                      *
 *   - DLL 负责 verthys 级别的整体加密（主密码派生）                      *
 *   - 此层为单条密码追加的细粒度加密，需用户独立密钥才能解密           *
 *   - encKey 不存储明文，仅存 salt + iv + ciphertext                  *
 *                                                                    *
 * 从 verthys.ts 迁移至此，verthys.ts 仅保留纯 IPC 调用                    *
 * ------------------------------------------------------------------ */

/** 从用户密钥派生 AES-GCM 密钥 */
async function deriveFieldKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: toArrayBuffer(salt), iterations: PBKDF2_ITER, hash: "SHA-256" },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

/** 加密单个密码字段，返回 { salt, iv, ct } 的 base64 组合串 */
export async function encryptPasswordField(plain: string, passphrase: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveFieldKey(passphrase, salt);
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plain));
  // 组合格式: salt(16) | iv(12) | ct
  const combined = new Uint8Array(salt.length + iv.length + ct.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ct), salt.length + iv.length);
  return bytesToBase64(combined);
}

/** 解密单个密码字段 */
export async function decryptPasswordField(b64: string, passphrase: string): Promise<string> {
  const combined = base64ToBytes(b64);
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ct = combined.slice(28);
  const key = await deriveFieldKey(passphrase, salt);
  const dec = new TextDecoder();
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return dec.decode(pt);
}

/* ------------------------------------------------------------------ *
 * 再导出（保持原有 API 完全不变）                                     *
 *                                                                    *
 * 上层组件（PhotoAlbum.vue 等）通过 `from "../../lib/crypto"` 导入   *
 * 常量与类型，此处再导出确保无需修改调用方。                          *
 * ------------------------------------------------------------------ */

export { CHUNK_SIZE, TYPE_PHOTO_META, TYPE_PHOTO_CHUNK };
export { bytesToHex };
export type { PhotoMeta, LightMeta, VencPhotoSpecV2 };
