/*
 * crypto/password_field.ts — 独立密码字段加密层（per-field AES-GCM）与随机令牌生成。
 *
 * 与 DLL 的加密库主加密相互独立：
 *   - DLL 负责 verthys 级别的整体加密（主密码派生）
 *   - 此层为单条密码追加的细粒度加密，需用户独立密钥才能解密
 *   - encKey 不存储明文，仅存 salt + iv + ciphertext
 */
import { bytesToBase64, base64ToBytes, bytesToHex, toArrayBuffer } from "../../utils/codec/binary_codec";
import { PBKDF2_ITER } from "../../constants/crypto_const";
import { invalidInput } from "../util/crypto_error";
import { zeroize } from "./venc_common";

/** 生成随机令牌（默认 32 bytes hex） */
export function generateRandomToken(bytes: number = 32): string {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw invalidInput(`令牌字节数非法: ${bytes}`);
  }
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  const token = bytesToHex(arr);
  zeroize(arr);
  return token;
}

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
