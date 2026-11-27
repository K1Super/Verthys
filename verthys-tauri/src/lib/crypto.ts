/*
 * crypto.ts — 前端剩余密码学能力（VENC 备份容器 + 字段密码 + BLAKE3）
 *
 * 职责边界：
 *   - VENC 备份容器：用户导出令牌 → PBKDF2 → 封装内容密钥 → 逐帧 XChaCha20-Poly1305
 *   - 独立密码字段：per-field AES-GCM（清单密码等既有记录）
 *   - BLAKE3 完整性校验与公开结构解析（包裹态密钥盐等）
 *
 * 照片/文件记录的内容加密不在本文件：已下沉到 Tauri worker 的 module_crypto 模块。
 * 本文件不执行模块密钥派生，也不持有模块密钥或文件密钥。
 *
 * 容器布局（导出文件）：
 *   外层头 42B（magic/version/flags/kdf/iterations/salt/iv）+ 包裹内容密钥 48B + 逐帧
 *   帧 AD = type(1) || seq(4 大端) || len(4 大端) || salt(16)
 *
 * 本文件仅为重导出入口，实现按域拆分在 crypto/ 目录：
 *   - crypto/venc_common.ts：共享常量、密钥派生、清零、帧头/AD、清单契约
 *   - crypto/venc_pack.ts：容器打包与体积预估
 *   - crypto/venc_unpack.ts：容器解包、流式解码与预览
 *   - crypto/password_field.ts：字段密码与随机令牌
 */
export { extractSlimFileSalt, toLightMeta } from "./crypto/venc_common";
export {
  packVenc,
  packVencStreamed,
  packVencStreamedLazy,
  estimateVencTotalBytes,
  VENC_CONTAINER_FIXED_BYTES,
  vencPhotoFramesBytes,
} from "./crypto/venc_pack";
export {
  unpackVencStream,
  unpackVencPreview,
  unpackVenc,
  type VencStreamHandlers,
  type VencPreview,
} from "./crypto/venc_unpack";
export {
  generateRandomToken,
  encryptPasswordField,
  decryptPasswordField,
} from "./crypto/password_field";

/* ------------------------------------------------------------------ *
 * 再导出                                                              *
 *                                                                    *
 * 上层组件（PhotoAlbum.vue 等）通过 `from "../../lib/crypto"` 导入     *
 * 常量与类型。                                                        *
 * ------------------------------------------------------------------ */

export { CHUNK_SIZE, TYPE_PHOTO_META, TYPE_PHOTO_CHUNK } from "../constants/crypto_const";
export { bytesToHex } from "../utils/codec/binary_codec";
export type { PhotoMeta, LightMeta, VencPhotoSpec } from "../types/crypto";
